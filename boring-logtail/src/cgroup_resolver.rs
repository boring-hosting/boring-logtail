// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolve kernel cgroup IDs to container-runtime IDs off the capture path.
//!
//! The eBPF event gives us a numeric cgroup ID, not a Kubernetes name. A
//! background scan walks cgroup v2, extracts exact 64-hex container IDs from
//! recognized directory forms, and asks the kernel for the same numeric ID
//! eBPF reports. Capture then performs only a snapshot lookup.

use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, bail};
use blt_model::ContainerId;
use log::{info, warn};
use tokio::{sync::watch, time::Instant};

use crate::enrichment::CgroupSnapshot;

pub const DEFAULT_HOST_CGROUP_ROOT: &str = "/host/sys/fs/cgroup";

pub const NATIVE_CGROUP_ROOT: &str = "/sys/fs/cgroup";

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

const TOMBSTONE_TTL: Duration = Duration::from_secs(5 * 60);

const MAX_CGROUP_DIRECTORIES: usize = 250_000;

#[repr(C)]

struct FileHandle {
    handle_bytes: libc::c_uint,
    handle_type: libc::c_int,
    bytes: [u8; 128],
}

pub fn spawn_cgroup_cache(root: PathBuf) -> watch::Receiver<Arc<CgroupSnapshot>> {
    let (sender, receiver) = watch::channel(Arc::new(CgroupSnapshot::default()));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);

        let mut previous = HashMap::<u64, Vec<ContainerId>>::new();

        let mut tombstones = HashMap::<u64, (Instant, Vec<ContainerId>)>::new();

        let mut announced_count = None;

        loop {
            interval.tick().await;

            let scan_root = root.clone();

            match tokio::task::spawn_blocking(move || scan_cgroups(&scan_root)).await {
                Ok(Ok(current)) => {
                    let now = Instant::now();

                    for (cgroup_id, containers) in &previous {
                        // A process can write after its cgroup directory has
                        // disappeared. Tombstones keep that late event
                        // attributable for a bounded grace period.
                        if !current.contains_key(cgroup_id) {
                            tombstones
                                .insert(*cgroup_id, (now + TOMBSTONE_TTL, containers.clone()));
                        }
                    }

                    tombstones.retain(|_, (expires, _)| *expires > now);

                    let mut combined = current.clone();

                    for (cgroup_id, (_, containers)) in &tombstones {
                        combined
                            .entry(*cgroup_id)
                            .or_insert_with(|| containers.clone());
                    }

                    if announced_count != Some(current.len()) {
                        info!(
                            "indexed {} container cgroups under {}",
                            current.len(),
                            root.display()
                        );

                        announced_count = Some(current.len());
                    }

                    previous = current;

                    sender.send_replace(Arc::new(CgroupSnapshot {
                        containers: combined,
                    }));
                }
                Ok(Err(error)) => {
                    warn!(
                        "cgroup enrichment refresh failed under {}: {error:#}",
                        root.display()
                    )
                }
                Err(error) => warn!("cgroup enrichment refresh task failed: {error}"),
            }
        }
    });

    receiver
}

fn scan_cgroups(root: &Path) -> anyhow::Result<HashMap<u64, Vec<ContainerId>>> {
    if !root.join("cgroup.controllers").is_file() {
        bail!("{} is not a cgroup-v2 hierarchy", root.display());
    }

    let mut result = HashMap::<u64, Vec<ContainerId>>::new();

    let mut pending = vec![root.to_owned()];

    let mut visited = 0usize;

    while let Some(directory) = pending.pop() {
        visited += 1;

        if visited > MAX_CGROUP_DIRECTORIES {
            bail!("cgroup hierarchy exceeds {MAX_CGROUP_DIRECTORIES} directories");
        }

        for entry in fs::read_dir(&directory)
            .with_context(|| format!("read cgroup directory {}", directory.display()))?
        {
            let entry = entry?;

            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }

        let Some(container_id) = container_id_from_path(&directory) else {
            continue;
        };

        let cgroup_id = cgroup_id_from_handle(&directory)
            .with_context(|| format!("resolve cgroup ID for {}", directory.display()))?;

        let containers = result.entry(cgroup_id).or_default();

        if !containers.contains(&container_id) {
            containers.push(container_id);
        }
    }

    Ok(result)
}

fn cgroup_id_from_handle(path: &Path) -> anyhow::Result<u64> {
    // cgroup v2 exposes the cgroup ID in its file handle. This asks the kernel
    // for the value that matches bpf_get_current_cgroup_id().
    let path = CString::new(path.as_os_str().as_bytes()).context("cgroup path contains NUL")?;

    let mut handle = FileHandle {
        handle_bytes: 128,
        handle_type: 0,
        bytes: [0; 128],
    };

    let mut mount_id = 0;

    // SAFETY: both C pointers refer to initialized storage for this synchronous
    // call. `handle_bytes` advertises the 128-byte tail of our repr(C) buffer.
    let result = unsafe {
        libc::name_to_handle_at(
            libc::AT_FDCWD,
            path.as_ptr(),
            (&mut handle as *mut FileHandle).cast(),
            &mut mount_id,
            0,
        )
    };

    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if handle.handle_bytes < 8 {
        bail!("cgroup file handle is only {} bytes", handle.handle_bytes);
    }

    Ok(u64::from_ne_bytes(handle.bytes[..8].try_into().unwrap()))
}

fn container_id_from_path(path: &Path) -> Option<ContainerId> {
    // Walk leaf-to-root and accept only a complete runtime-specific token. A
    // random short hex-looking directory must never become guessed identity.
    path.components().rev().find_map(|component| {
        let component = component.as_os_str().to_str()?;

        if let Some(candidate) = component
            .strip_prefix("cri-containerd-")
            .and_then(|value| value.strip_suffix(".scope"))
        {
            return format!("containerd://{candidate}").parse().ok();
        }

        if let Some(candidate) = component
            .strip_prefix("crio-")
            .and_then(|value| value.strip_suffix(".scope"))
        {
            return format!("cri-o://{candidate}").parse().ok();
        }

        format!("containerd://{component}").parse().ok()
    })
}

#[cfg(test)]

mod tests {

    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]

    fn decodes_measured_containerd_cgroup_layouts() {
        let systemd = PathBuf::from(format!(
            "/kubepods.slice/kubepods-burstable.slice/cri-containerd-{ID}.scope"
        ));

        let cgroupfs = PathBuf::from(format!("/kubepods/burstable/pod-uid/{ID}"));

        assert_eq!(container_id_from_path(&systemd).unwrap().id, ID);

        assert_eq!(container_id_from_path(&cgroupfs).unwrap().id, ID);
    }

    #[test]

    fn recognizes_crio_systemd_scope_without_guessing_containerd() {
        let path = PathBuf::from(format!(
            "/kubepods.slice/kubepods-burstable.slice/crio-{ID}.scope"
        ));

        let container = container_id_from_path(&path).unwrap();

        assert_eq!(container.runtime, "cri-o");

        assert_eq!(container.id, ID);
    }

    #[test]

    fn rejects_partial_and_unrelated_path_tokens() {
        assert!(container_id_from_path(Path::new("/kubepods/cri-containerd-abc.scope")).is_none());

        assert!(container_id_from_path(Path::new("/system.slice/sshd.service")).is_none());
    }

    #[test]

    fn cgroup_file_handle_exposes_the_kernel_cgroup_inode_id() {
        let root = Path::new("/sys/fs/cgroup");

        if !root.join("cgroup.controllers").is_file() {
            return;
        }

        let handle_id = cgroup_id_from_handle(root).unwrap();

        let inode_id = root.metadata().unwrap().ino();

        assert_eq!(handle_id, inode_id);
    }
}
