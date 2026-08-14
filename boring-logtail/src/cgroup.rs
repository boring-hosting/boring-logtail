// SPDX-License-Identifier: GPL-3.0-or-later

//! Find the collector's own cgroup so eBPF can ignore self-generated logs.
//!
//! `/proc/self/cgroup` is namespace-aware. We resolve its unified-v2 membership
//! against the process-visible mount and hold the directory open, giving Aya a
//! stable kernel object rather than comparing fragile path strings.

use std::{
    fs::File,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, bail};

const SELF_CGROUP: &str = "/proc/self/cgroup";

const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";

/// The cgroup that contains the collector itself.
///
/// Keeping the directory open gives Aya a stable FD to place in the eBPF
/// cgroup array. The kernel, not a namespace-relative PID, then decides whether
/// a write belongs to us.

pub struct CollectorCgroup {
    directory: File,
    path: PathBuf,
}

impl CollectorCgroup {
    /// Discover and open this process's unified cgroup-v2 directory.

    pub fn discover() -> anyhow::Result<Self> {
        let membership = std::fs::read_to_string(SELF_CGROUP)
            .with_context(|| format!("read collector cgroup membership from {SELF_CGROUP}"))?;

        Self::from_membership(Path::new(CGROUP2_MOUNT), &membership)
    }

    fn from_membership(mount: &Path, membership: &str) -> anyhow::Result<Self> {
        let relative = cgroup2_membership(membership)?;

        let path = safe_cgroup_path(mount, relative)?;

        let directory = File::open(&path)
            .with_context(|| format!("open collector cgroup {}", path.display()))?;

        if !directory
            .metadata()
            .with_context(|| format!("inspect collector cgroup {}", path.display()))?
            .is_dir()
        {
            bail!("collector cgroup is not a directory: {}", path.display());
        }

        Ok(Self { directory, path })
    }

    pub fn directory(&self) -> &File {
        &self.directory
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn cgroup2_membership(contents: &str) -> anyhow::Result<&str> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');

            let hierarchy = fields.next()?;

            let controllers = fields.next()?;

            let path = fields.next()?;

            (hierarchy == "0" && controllers.is_empty()).then_some(path)
        })
        .next()
        .filter(|path| path.starts_with('/'))
        .context("no valid cgroup-v2 membership in /proc/self/cgroup")
}

fn safe_cgroup_path(mount: &Path, membership: &str) -> anyhow::Result<PathBuf> {
    // `/proc` is kernel input, but still reject traversal before joining it to
    // a filesystem root. This also documents the path shape we rely on.
    let relative = membership
        .strip_prefix('/')
        .context("cgroup-v2 membership path is not absolute")?;

    let relative = Path::new(relative);

    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
        && !relative.as_os_str().is_empty()
    {
        bail!("unsafe cgroup-v2 membership path: {membership}");
    }

    Ok(mount.join(relative))
}

#[cfg(test)]

mod tests {

    use super::*;

    #[test]

    fn finds_unified_membership_among_legacy_entries() {
        let membership = "11:memory:/legacy\n0::/system.slice/boring-logtail\n";

        assert_eq!(
            cgroup2_membership(membership).unwrap(),
            "/system.slice/boring-logtail"
        );
    }

    #[test]

    fn accepts_a_private_cgroup_namespace_root() {
        assert_eq!(
            safe_cgroup_path(Path::new("/sys/fs/cgroup"), "/").unwrap(),
            Path::new("/sys/fs/cgroup")
        );
    }

    #[test]

    fn rejects_legacy_only_membership() {
        assert!(cgroup2_membership("11:memory:/legacy\n").is_err());
    }

    #[test]

    fn rejects_relative_and_traversing_paths() {
        assert!(safe_cgroup_path(Path::new("/sys/fs/cgroup"), "relative").is_err());

        assert!(safe_cgroup_path(Path::new("/sys/fs/cgroup"), "/../escape").is_err());
    }
}
