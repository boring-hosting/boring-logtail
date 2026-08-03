// SPDX-License-Identifier: GPL-3.0-or-later

//! Node-local kubelet log topology to Kubernetes identity snapshots.

use crate::{
    cri_log::identity_from_link,
    directory_watch::DirectoryWatch,
    enrichment::{ContainerId, KubernetesIdentity, PodSnapshot},
};
use anyhow::{Context as _, bail};
use log::{info, warn};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

pub const DEFAULT_CONTAINER_LOG_ROOT: &str = "/var/log/containers";
const TOMBSTONE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CONTAINER_LOG_ENTRIES: usize = 250_000;
const TOMBSTONE_TICK_MS: libc::c_int = 60_000;

#[derive(Default)]
struct MetadataCache {
    live: HashMap<ContainerId, Vec<KubernetesIdentity>>,
    tombstones: HashMap<ContainerId, (Instant, Vec<KubernetesIdentity>)>,
}

impl MetadataCache {
    fn replace(
        &mut self,
        current: HashMap<ContainerId, Vec<KubernetesIdentity>>,
        now: Instant,
    ) -> PodSnapshot {
        for (container_id, identities) in &self.live {
            if !current.contains_key(container_id) {
                let mut removed = identities.clone();
                for identity in &mut removed {
                    identity.tombstone = true;
                }
                self.tombstones
                    .insert(container_id.clone(), (now + TOMBSTONE_TTL, removed));
            }
        }
        self.snapshot(current, now)
    }

    fn snapshot(
        &mut self,
        current: HashMap<ContainerId, Vec<KubernetesIdentity>>,
        now: Instant,
    ) -> PodSnapshot {
        self.tombstones.retain(|_, (expires, _)| *expires > now);
        let mut combined = current.clone();
        for (container_id, (_, identities)) in &self.tombstones {
            combined
                .entry(container_id.clone())
                .or_insert_with(|| identities.clone());
        }
        self.live = current;
        PodSnapshot {
            identities: combined,
            stale: false,
        }
    }
}

pub fn spawn_metadata_cache(
    container_log_root: PathBuf,
    node: String,
) -> watch::Receiver<Arc<PodSnapshot>> {
    let (sender, receiver) = watch::channel(Arc::new(PodSnapshot::default()));
    let thread_name = "boring-logtail-node-metadata";
    let spawn = std::thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            let mut cache = MetadataCache::default();
            let mut announced_count = None;
            refresh_cache(
                &container_log_root,
                &node,
                &sender,
                &mut cache,
                &mut announced_count,
            );
            let mut inotify = match DirectoryWatch::new([container_log_root.as_path()]) {
                Ok(inotify) => inotify,
                Err(error) => {
                    warn!("node-local metadata watch disabled: {error:#}");
                    return;
                }
            };
            loop {
                let ready = match inotify.wait(Duration::from_millis(TOMBSTONE_TICK_MS as u64)) {
                    Ok(ready) => ready,
                    Err(error) => {
                        warn!("node-local metadata watch failed: {error:#}");
                        return;
                    }
                };
                if !ready {
                    let live = cache.live.clone();
                    let snapshot = cache.snapshot(live, Instant::now());
                    sender.send_replace(Arc::new(snapshot));
                    continue;
                }
                refresh_cache(
                    &container_log_root,
                    &node,
                    &sender,
                    &mut cache,
                    &mut announced_count,
                );
            }
        });
    if let Err(error) = spawn {
        warn!("cannot start {thread_name} thread: {error}");
    }
    receiver
}

fn refresh_cache(
    root: &Path,
    node: &str,
    sender: &watch::Sender<Arc<PodSnapshot>>,
    cache: &mut MetadataCache,
    announced_count: &mut Option<usize>,
) {
    match scan_metadata(root, node) {
        Ok(current) => {
            if *announced_count != Some(current.len()) {
                info!(
                    "indexed {} node-local container log identities under {}",
                    current.len(),
                    root.display()
                );
                *announced_count = Some(current.len());
            }
            sender.send_replace(Arc::new(cache.replace(current, Instant::now())));
        }
        Err(error) => warn!(
            "node-local metadata refresh failed under {}: {error:#}",
            root.display()
        ),
    }
}

fn scan_metadata(
    root: &Path,
    node: &str,
) -> anyhow::Result<HashMap<ContainerId, Vec<KubernetesIdentity>>> {
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }
    let mut identities = HashMap::<ContainerId, Vec<KubernetesIdentity>>::new();
    for (count, entry) in fs::read_dir(root)
        .with_context(|| format!("read container log directory {}", root.display()))?
        .enumerate()
    {
        if count >= MAX_CONTAINER_LOG_ENTRIES {
            bail!("container log directory exceeds {MAX_CONTAINER_LOG_ENTRIES} entries");
        }
        let entry = entry?;
        if !entry.file_type()?.is_symlink() {
            continue;
        }
        let target = fs::read_link(entry.path())
            .with_context(|| format!("read container log link {}", entry.path().display()))?;
        match identity_from_log_link(&entry.path(), &target, node) {
            Ok(identity) => identities
                .entry(identity.container_id.clone())
                .or_default()
                .push(identity),
            Err(error) => warn!(
                "ignoring unsupported container log link {}: {error:#}",
                entry.path().display()
            ),
        }
    }
    Ok(identities)
}

fn identity_from_log_link(
    link: &Path,
    target: &Path,
    node: &str,
) -> anyhow::Result<KubernetesIdentity> {
    let parsed = identity_from_link(link, target, target.to_path_buf(), node)?;
    // The legacy cgroup join currently supports containerd only. The new
    // registered-file path keeps the opaque ID runtime-neutral instead.
    let container_id: ContainerId =
        format!("containerd://{}", parsed.opaque_container_id).parse()?;

    Ok(KubernetesIdentity {
        node: parsed.node,
        namespace: parsed.namespace,
        pod_name: parsed.pod_name,
        pod_uid: parsed.pod_uid,
        container_name: parsed.container_name,
        container_id,
        restart_count: parsed.attempt,
        tombstone: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::symlink, time::SystemTime};

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn decodes_exact_identity_from_kubelet_log_topology() {
        let link = PathBuf::from(format!(
            "/var/log/containers/checkout-abc_payments_checkout-{ID}.log"
        ));
        let target = Path::new("/var/log/pods/payments_checkout-abc_pod-uid/checkout/2.log");
        let identity = identity_from_log_link(&link, target, "worker-1").unwrap();
        assert_eq!(identity.namespace, "payments");
        assert_eq!(identity.pod_name, "checkout-abc");
        assert_eq!(identity.pod_uid, "pod-uid");
        assert_eq!(identity.container_name, "checkout");
        assert_eq!(identity.container_id.id, ID);
        assert_eq!(identity.restart_count, 2);
        assert_eq!(identity.node, "worker-1");
    }

    #[test]
    fn rejects_disagreement_between_link_and_target() {
        let link = PathBuf::from(format!(
            "/var/log/containers/checkout-abc_payments_checkout-{ID}.log"
        ));
        let wrong_target = Path::new("/var/log/pods/other_checkout-abc_pod-uid/checkout/0.log");
        assert!(identity_from_log_link(&link, wrong_target, "worker-1").is_err());
    }

    #[test]
    fn rejects_partial_container_ids_and_malformed_paths() {
        let short = Path::new("/var/log/containers/pod_ns_container-abc.log");
        let target = Path::new("/var/log/pods/ns_pod_uid/container/0.log");
        assert!(identity_from_log_link(short, target, "worker-1").is_err());
        assert!(identity_from_log_link(Path::new("not-a-log"), target, "worker-1").is_err());
    }

    #[test]
    fn scans_a_kubelet_log_fixture_without_following_the_log() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "boring-logtail-node-metadata-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let link = root.join(format!("checkout-abc_payments_checkout-{ID}.log"));
        symlink(
            "/var/log/pods/payments_checkout-abc_pod-uid/checkout/0.log",
            &link,
        )
        .unwrap();

        let snapshot = scan_metadata(&root, "worker-1").unwrap();
        let identity = snapshot.values().flatten().next().unwrap();
        assert_eq!(identity.pod_uid, "pod-uid");
        assert_eq!(identity.container_id.id, ID);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removed_metadata_is_bounded_by_tombstone_expiry() {
        let identity = identity_from_log_link(
            &PathBuf::from(format!(
                "/var/log/containers/checkout-abc_payments_checkout-{ID}.log"
            )),
            Path::new("/var/log/pods/payments_checkout-abc_pod-uid/checkout/0.log"),
            "worker-1",
        )
        .unwrap();
        let now = Instant::now();
        let mut cache = MetadataCache::default();
        cache.replace(
            HashMap::from([(identity.container_id.clone(), vec![identity])]),
            now,
        );
        let removed = cache.replace(HashMap::new(), now + Duration::from_secs(1));
        assert!(
            removed
                .identities
                .values()
                .flatten()
                .next()
                .unwrap()
                .tombstone
        );
        let expired = cache.replace(HashMap::new(), now + TOMBSTONE_TTL + Duration::from_secs(2));
        assert!(expired.identities.is_empty());
    }
}
