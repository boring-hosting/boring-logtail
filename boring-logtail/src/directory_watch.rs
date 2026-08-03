// SPDX-License-Identifier: GPL-3.0-or-later

//! Small Linux inotify wrapper shared by node-local discovery loops.

use anyhow::Context as _;
use std::{
    ffi::CString,
    fs,
    io::Read as _,
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::ffi::OsStrExt as _,
    },
    path::Path,
    time::Duration,
};

pub(crate) struct DirectoryWatch {
    file: fs::File,
}

impl DirectoryWatch {
    pub(crate) fn new<'a>(paths: impl IntoIterator<Item = &'a Path>) -> anyhow::Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("create inotify instance");
        }
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_ATTRIB;
        let mut count = 0;
        for path in paths {
            let encoded =
                CString::new(path.as_os_str().as_bytes()).context("inotify path contains NUL")?;
            if unsafe { libc::inotify_add_watch(file.as_raw_fd(), encoded.as_ptr(), mask) } < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("watch directory {}", path.display()));
            }
            count += 1;
        }
        anyhow::ensure!(count > 0, "inotify requires at least one directory");
        Ok(Self { file })
    }

    /// Waits for a lifecycle event. `false` is a normal timeout.
    pub(crate) fn wait(&mut self, timeout: Duration) -> anyhow::Result<bool> {
        let milliseconds = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("poll inotify");
            }
            if ready == 0 {
                return Ok(false);
            }
            let mut buffer = [0u8; 64 * 1024];
            match self.file.read(&mut buffer) {
                Ok(0) => return Ok(false),
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("read inotify events"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn observes_directory_lifecycle_without_reading_file_content() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "boring-logtail-inotify-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let mut watch = DirectoryWatch::new([root.as_path()]).unwrap();
        fs::write(root.join("created.log"), b"not consumed by the watch").unwrap();

        assert!(watch.wait(Duration::from_secs(1)).unwrap());
        fs::remove_dir_all(root).unwrap();
    }
}
