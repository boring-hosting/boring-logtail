// SPDX-License-Identifier: GPL-3.0-or-later

//! Node-local CRI-file discovery and kernel-map-independent registration state.

use crate::{
    cri_log::{CriLogIdentity, identity_from_link},
    directory_watch::DirectoryWatch,
};
use anyhow::{Context as _, bail};
use boring_logtail_common::{
    RegisteredFileKey, RegisteredWriteTargetKey, RegisteredWriteTargetValue,
};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

pub const MAX_REGISTERED_LOG_FILES: usize = 16_384;
const MAX_DISCOVERY_ENTRIES: usize = 250_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredLogFile {
    pub key: RegisteredFileKey,
    pub identity: CriLogIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredWriteTarget {
    pub key: RegisteredWriteTargetKey,
    pub file_key: RegisteredFileKey,
    pub identity: CriLogIdentity,
}

pub fn scan_registered_log_files(
    container_log_root: &Path,
    node: &str,
) -> anyhow::Result<Vec<DiscoveredLogFile>> {
    if !container_log_root.is_dir() {
        bail!("{} is not a directory", container_log_root.display());
    }

    let mut discovered = Vec::new();
    for (count, entry) in fs::read_dir(container_log_root)
        .with_context(|| {
            format!(
                "read container log directory {}",
                container_log_root.display()
            )
        })?
        .enumerate()
    {
        if count >= MAX_DISCOVERY_ENTRIES {
            bail!("container log directory exceeds {MAX_DISCOVERY_ENTRIES} entries");
        }
        let entry = entry?;
        if !entry.file_type()?.is_symlink() {
            continue;
        }
        let link_path = entry.path();
        let target = fs::read_link(&link_path)
            .with_context(|| format!("read container log link {}", link_path.display()))?;
        let unresolved = if target.is_absolute() {
            target.clone()
        } else {
            link_path
                .parent()
                .context("container log link has no parent")?
                .join(&target)
        };
        let resolved = fs::canonicalize(&unresolved)
            .with_context(|| format!("resolve container log target {}", unresolved.display()))?;
        let metadata = fs::metadata(&resolved)
            .with_context(|| format!("stat resolved container log {}", resolved.display()))?;
        if !metadata.is_file() {
            continue;
        }
        let device = metadata.dev();
        let key = RegisteredFileKey {
            device_major: libc::major(device),
            device_minor: libc::minor(device),
            inode: metadata.ino(),
        };
        let identity = identity_from_link(&link_path, &target, resolved, node)?;
        discovered.push(DiscoveredLogFile { key, identity });
    }
    Ok(discovered)
}

pub fn scan_registered_write_targets(
    proc_root: &Path,
    files: &[DiscoveredLogFile],
) -> anyhow::Result<Vec<DiscoveredWriteTarget>> {
    let mut by_file = HashMap::<RegisteredFileKey, Vec<&DiscoveredLogFile>>::new();
    for file in files {
        by_file.entry(file.key).or_default().push(file);
    }

    let mut targets = Vec::new();
    for (process_count, process) in fs::read_dir(proc_root)
        .with_context(|| format!("read proc root {}", proc_root.display()))?
        .enumerate()
    {
        if process_count >= MAX_DISCOVERY_ENTRIES {
            bail!("proc root exceeds {MAX_DISCOVERY_ENTRIES} entries");
        }
        let process = process?;
        let Some(tgid) = process
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != 0)
        else {
            continue;
        };
        let descriptors = process.path().join("fd");
        let Ok(descriptors) = fs::read_dir(descriptors) else {
            continue;
        };
        for descriptor in descriptors.take(MAX_DISCOVERY_ENTRIES) {
            let descriptor = match descriptor {
                Ok(descriptor) => descriptor,
                Err(_) => continue,
            };
            let Some(fd) = descriptor
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(metadata) = fs::metadata(descriptor.path()) else {
                continue;
            };
            let device = metadata.dev();
            let file_key = RegisteredFileKey {
                device_major: libc::major(device),
                device_minor: libc::minor(device),
                inode: metadata.ino(),
            };
            let Some(files) = by_file.get(&file_key) else {
                continue;
            };
            for file in files {
                targets.push(DiscoveredWriteTarget {
                    key: RegisteredWriteTargetKey { tgid, fd },
                    file_key,
                    identity: file.identity.clone(),
                });
            }
        }
    }
    Ok(targets)
}

pub fn spawn_registered_write_target_discovery(
    container_log_root: std::path::PathBuf,
    proc_root: std::path::PathBuf,
    node: String,
) -> watch::Receiver<Arc<Vec<DiscoveredWriteTarget>>> {
    let (sender, receiver) = watch::channel(Arc::new(Vec::new()));
    let thread_name = "boring-logtail-cri-file-discovery";
    let spawn = std::thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            loop {
                let files = match scan_registered_log_files(&container_log_root, &node) {
                    Ok(files) => files,
                    Err(error) => {
                        log::warn!(
                            "CRI-file discovery failed under {}: {error:#}",
                            container_log_root.display()
                        );
                        return;
                    }
                };
                let targets = match scan_registered_write_targets(&proc_root, &files) {
                    Ok(targets) => targets,
                    Err(error) => {
                        log::warn!(
                            "CRI write-target discovery failed under {}: {error:#}",
                            proc_root.display()
                        );
                        return;
                    }
                };
                sender.send_replace(Arc::new(targets));

                let mut paths = HashSet::from([container_log_root.clone()]);
                paths.extend(
                    files
                        .iter()
                        .filter_map(|file| file.identity.log_path.parent().map(Path::to_path_buf)),
                );
                let mut watcher = match DirectoryWatch::new(paths.iter().map(PathBuf::as_path)) {
                    Ok(watcher) => watcher,
                    Err(error) => {
                        log::warn!("CRI-file lifecycle watch disabled: {error:#}");
                        return;
                    }
                };
                loop {
                    match watcher.wait(Duration::from_secs(60)) {
                        Ok(true) => break,
                        Ok(false) => continue,
                        Err(error) => {
                            log::warn!("CRI-file lifecycle watch failed: {error:#}");
                            return;
                        }
                    }
                }
            }
        });
    if let Err(error) = spawn {
        log::warn!("cannot start {thread_name} thread: {error}");
    }
    receiver
}

pub trait RegistrationMap {
    type Error: fmt::Display;

    fn insert(
        &mut self,
        key: RegisteredWriteTargetKey,
        value: RegisteredWriteTargetValue,
    ) -> Result<(), Self::Error>;
    fn remove(&mut self, key: &RegisteredWriteTargetKey) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationPhase {
    Registered,
    Draining,
    Tombstone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleSnapshot {
    pub identity: CriLogIdentity,
    pub phase: RegistrationPhase,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegistrationCounters {
    pub inserted: u64,
    pub already_current: u64,
    pub draining: u64,
    pub revived: u64,
    pub removed: u64,
    pub ambiguous: u64,
    pub map_failures: u64,
    pub unknown_handle: u64,
}

#[derive(Clone, Debug)]
struct ActiveRegistration {
    handle: u64,
    identity: CriLogIdentity,
    drain_at: Option<Duration>,
}

#[derive(Clone, Debug)]
struct Tombstone {
    identity: CriLogIdentity,
    expires_at: Duration,
}

pub struct RegistrationTable<M> {
    map: M,
    active: HashMap<RegisteredWriteTargetKey, ActiveRegistration>,
    tombstones: HashMap<u64, Tombstone>,
    next_handle: u64,
    drain_grace: Duration,
    tombstone_ttl: Duration,
    counters: RegistrationCounters,
}

impl<M: RegistrationMap> RegistrationTable<M> {
    pub fn new(map: M, drain_grace: Duration, tombstone_ttl: Duration) -> Self {
        Self {
            map,
            active: HashMap::new(),
            tombstones: HashMap::new(),
            next_handle: 1,
            drain_grace,
            tombstone_ttl,
            counters: RegistrationCounters::default(),
        }
    }

    pub fn reconcile(&mut self, discovered: Vec<DiscoveredWriteTarget>, now: Duration) {
        self.expire(now);

        let mut desired = HashMap::<RegisteredWriteTargetKey, DiscoveredWriteTarget>::new();
        let mut ambiguous = HashSet::new();
        for file in discovered {
            match desired.get(&file.key) {
                Some(existing) if existing.identity != file.identity => {
                    ambiguous.insert(file.key);
                }
                Some(_) => {}
                None => {
                    desired.insert(file.key, file);
                }
            }
        }
        for key in &ambiguous {
            desired.remove(key);
            self.counters.ambiguous += 1;
        }

        for (key, file) in &desired {
            if let Some(active) = self.active.get_mut(key) {
                if active.identity == file.identity {
                    if active.drain_at.take().is_some() {
                        self.counters.revived += 1;
                    } else {
                        self.counters.already_current += 1;
                    }
                } else {
                    self.counters.ambiguous += 1;
                }
                continue;
            }

            let Some(handle) = self.allocate_handle() else {
                self.counters.map_failures += 1;
                continue;
            };
            let registration = ActiveRegistration {
                handle,
                identity: file.identity.clone(),
                drain_at: None,
            };
            self.active.insert(*key, registration);
            if self
                .map
                .insert(*key, RegisteredWriteTargetValue { handle })
                .is_err()
            {
                self.active.remove(key);
                self.counters.map_failures += 1;
                continue;
            }
            self.counters.inserted += 1;
        }

        for (key, registration) in &mut self.active {
            if !desired.contains_key(key) && registration.drain_at.is_none() {
                registration.drain_at = Some(now + self.drain_grace);
                self.counters.draining += 1;
            }
        }
    }

    pub fn snapshot(&mut self, handle: u64) -> Option<HandleSnapshot> {
        if let Some(active) = self.active.values().find(|entry| entry.handle == handle) {
            return Some(HandleSnapshot {
                identity: active.identity.clone(),
                phase: if active.drain_at.is_some() {
                    RegistrationPhase::Draining
                } else {
                    RegistrationPhase::Registered
                },
            });
        }
        if let Some(tombstone) = self.tombstones.get(&handle) {
            return Some(HandleSnapshot {
                identity: tombstone.identity.clone(),
                phase: RegistrationPhase::Tombstone,
            });
        }
        self.counters.unknown_handle += 1;
        None
    }

    pub fn counters(&self) -> RegistrationCounters {
        self.counters
    }

    pub fn snapshots(&self) -> HashMap<u64, HandleSnapshot> {
        let mut snapshots = HashMap::new();
        for registration in self.active.values() {
            snapshots.insert(
                registration.handle,
                HandleSnapshot {
                    identity: registration.identity.clone(),
                    phase: if registration.drain_at.is_some() {
                        RegistrationPhase::Draining
                    } else {
                        RegistrationPhase::Registered
                    },
                },
            );
        }
        for (handle, tombstone) in &self.tombstones {
            snapshots.insert(
                *handle,
                HandleSnapshot {
                    identity: tombstone.identity.clone(),
                    phase: RegistrationPhase::Tombstone,
                },
            );
        }
        snapshots
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    pub fn into_map(self) -> M {
        self.map
    }

    fn expire(&mut self, now: Duration) {
        self.tombstones.retain(|_, value| value.expires_at > now);
        let expired: Vec<_> = self
            .active
            .iter()
            .filter_map(|(key, registration)| {
                registration
                    .drain_at
                    .filter(|deadline| *deadline <= now)
                    .map(|_| *key)
            })
            .collect();
        for key in expired {
            let Some(registration) = self.active.remove(&key) else {
                continue;
            };
            if self.map.remove(&key).is_err() {
                self.active.insert(key, registration);
                self.counters.map_failures += 1;
                continue;
            }
            self.tombstones.insert(
                registration.handle,
                Tombstone {
                    identity: registration.identity,
                    expires_at: now + self.tombstone_ttl,
                },
            );
            self.counters.removed += 1;
        }
    }

    fn allocate_handle(&mut self) -> Option<u64> {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1)?;
        (handle != 0).then_some(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Default)]
    struct FakeMap(HashMap<RegisteredWriteTargetKey, RegisteredWriteTargetValue>);

    impl RegistrationMap for FakeMap {
        type Error = Infallible;

        fn insert(
            &mut self,
            key: RegisteredWriteTargetKey,
            value: RegisteredWriteTargetValue,
        ) -> Result<(), Self::Error> {
            self.0.insert(key, value);
            Ok(())
        }

        fn remove(&mut self, key: &RegisteredWriteTargetKey) -> Result<(), Self::Error> {
            self.0.remove(key);
            Ok(())
        }
    }

    fn target(key: RegisteredWriteTargetKey, pod_uid: &str) -> DiscoveredWriteTarget {
        DiscoveredWriteTarget {
            key,
            file_key: RegisteredFileKey {
                device_major: 8,
                device_minor: 1,
                inode: 42,
            },
            identity: CriLogIdentity {
                node: "worker-1".into(),
                namespace: "payments".into(),
                pod_name: "checkout".into(),
                pod_uid: pod_uid.into(),
                container_name: "app".into(),
                opaque_container_id: ID.into(),
                attempt: 0,
                log_path: PathBuf::from("/var/log/pods/x/app/0.log"),
            },
        }
    }

    #[test]
    fn resolves_only_descriptors_that_point_to_discovered_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "boring-logtail-proc-fixture-{}-{unique}",
            std::process::id()
        ));
        let proc_root = root.join("proc");
        let fd_root = proc_root.join("4242/fd");
        fs::create_dir_all(&fd_root).unwrap();
        let log = root.join("0.log");
        let unrelated = root.join("unrelated");
        fs::write(&log, b"CRI bytes").unwrap();
        fs::write(&unrelated, b"nope").unwrap();
        symlink(&log, fd_root.join("17")).unwrap();
        symlink(&unrelated, fd_root.join("18")).unwrap();
        let metadata = fs::metadata(&log).unwrap();
        let device = metadata.dev();
        let file = DiscoveredLogFile {
            key: RegisteredFileKey {
                device_major: libc::major(device),
                device_minor: libc::minor(device),
                inode: metadata.ino(),
            },
            identity: target(RegisteredWriteTargetKey { tgid: 1, fd: 1 }, "uid-1").identity,
        };

        let found = scan_registered_write_targets(&proc_root, &[file]).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].key,
            RegisteredWriteTargetKey { tgid: 4242, fd: 17 }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scans_symlinks_into_canonical_file_keys_without_reading_payloads() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "boring-logtail-registered-files-{}-{unique}",
            std::process::id()
        ));
        let containers = root.join("containers");
        let pod_dir = root.join("pods/payments_checkout_pod-uid/checkout");
        fs::create_dir_all(&containers).unwrap();
        fs::create_dir_all(&pod_dir).unwrap();
        let log = pod_dir.join("0.log");
        fs::write(&log, b"payload must not be read").unwrap();
        let link = containers.join(format!("checkout_payments_checkout-{ID}.log"));
        symlink(&log, &link).unwrap();

        let found = scan_registered_log_files(&containers, "worker-1").unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].identity.log_path, fs::canonicalize(&log).unwrap());
        assert_eq!(found[0].identity.pod_uid, "pod-uid");
        assert_eq!(found[0].key.inode, fs::metadata(&log).unwrap().ino());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registers_drains_tombstones_and_forgets_in_order() {
        let key = RegisteredWriteTargetKey { tgid: 42, fd: 7 };
        let mut table = RegistrationTable::new(
            FakeMap::default(),
            Duration::from_secs(5),
            Duration::from_secs(10),
        );
        table.reconcile(vec![target(key, "uid-1")], Duration::ZERO);
        assert_eq!(table.active_len(), 1);
        assert_eq!(
            table.snapshot(1).unwrap().phase,
            RegistrationPhase::Registered
        );

        table.reconcile(Vec::new(), Duration::from_secs(1));
        assert_eq!(
            table.snapshot(1).unwrap().phase,
            RegistrationPhase::Draining
        );
        table.reconcile(Vec::new(), Duration::from_secs(6));
        assert_eq!(table.active_len(), 0);
        assert_eq!(
            table.snapshot(1).unwrap().phase,
            RegistrationPhase::Tombstone
        );
        table.reconcile(Vec::new(), Duration::from_secs(17));
        assert!(table.snapshot(1).is_none());
        assert_eq!(table.counters().removed, 1);
        assert_eq!(table.into_map().0.len(), 0);
    }

    #[test]
    fn refuses_two_identities_for_one_kernel_file_key() {
        let key = RegisteredWriteTargetKey { tgid: 42, fd: 7 };
        let mut table = RegistrationTable::new(
            FakeMap::default(),
            Duration::from_secs(5),
            Duration::from_secs(10),
        );
        table.reconcile(
            vec![target(key, "uid-1"), target(key, "uid-2")],
            Duration::ZERO,
        );

        assert_eq!(table.active_len(), 0);
        assert_eq!(table.counters().ambiguous, 1);
    }
}
