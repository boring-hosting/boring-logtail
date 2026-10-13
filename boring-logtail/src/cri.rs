// SPDX-License-Identifier: GPL-3.0-or-later

//! Kubernetes CRI log records, without pretending they are application writes.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Identity encoded by one path below `/var/log/pods`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CriSource {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub container_name: String,
    pub restart: u32,
}

impl CriSource {
    pub fn from_relative_path(path: &Path) -> Result<Self, InvalidCriPath> {
        let mut components = path.components();
        let pod = utf8_component(components.next(), path)?;
        let container_name = utf8_component(components.next(), path)?;
        let file = utf8_component(components.next(), path)?;

        if components.next().is_some() || container_name.is_empty() {
            return Err(InvalidCriPath(path.display().to_string()));
        }

        let mut pod_parts = pod.splitn(3, '_');
        let namespace = pod_parts.next().unwrap_or_default();
        let pod_name = pod_parts.next().unwrap_or_default();
        let pod_uid = pod_parts.next().unwrap_or_default();

        let restart = file
            .strip_suffix(".log")
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| InvalidCriPath(path.display().to_string()))?;

        if namespace.is_empty() || pod_name.is_empty() || pod_uid.is_empty() {
            return Err(InvalidCriPath(path.display().to_string()));
        }

        Ok(Self {
            namespace: namespace.to_owned(),
            pod_name: pod_name.to_owned(),
            pod_uid: pod_uid.to_owned(),
            container_name: container_name.to_owned(),
            restart,
        })
    }
}

fn utf8_component<'a>(
    component: Option<std::path::Component<'a>>,
    path: &Path,
) -> Result<&'a str, InvalidCriPath> {
    component
        .and_then(|part| part.as_os_str().to_str())
        .ok_or_else(|| InvalidCriPath(path.display().to_string()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidCriPath(String);

impl fmt::Display for InvalidCriPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid CRI log path {}", self.0)
    }
}

impl std::error::Error for InvalidCriPath {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CriStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CriTag {
    Partial,
    Full,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CriFragment<'a> {
    pub timestamp: jiff::Timestamp,
    pub stream: CriStream,
    pub tag: CriTag,
    /// Payload without the CRI file record's terminating newline.
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidCriRecord {
    MissingField,
    InvalidTimestamp,
    InvalidStream,
    InvalidTag,
    MissingTerminator,
}

impl fmt::Display for InvalidCriRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingField => "CRI record is missing a field",
            Self::InvalidTimestamp => "CRI record has an invalid timestamp",
            Self::InvalidStream => "CRI record has an invalid stream",
            Self::InvalidTag => "CRI record has an invalid tag",
            Self::MissingTerminator => "CRI record has no terminating newline",
        })
    }
}

impl std::error::Error for InvalidCriRecord {}

pub fn parse_record(line: &[u8]) -> Result<CriFragment<'_>, InvalidCriRecord> {
    let line = line
        .strip_suffix(b"\n")
        .ok_or(InvalidCriRecord::MissingTerminator)?;
    let (timestamp, rest) = split_field(line)?;
    let (stream, rest) = split_field(rest)?;
    let (tag, payload) = split_field(rest)?;

    let timestamp = std::str::from_utf8(timestamp)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(InvalidCriRecord::InvalidTimestamp)?;
    let stream = match stream {
        b"stdout" => CriStream::Stdout,
        b"stderr" => CriStream::Stderr,
        _ => return Err(InvalidCriRecord::InvalidStream),
    };
    let tag = match tag {
        b"P" => CriTag::Partial,
        b"F" => CriTag::Full,
        _ => return Err(InvalidCriRecord::InvalidTag),
    };

    Ok(CriFragment {
        timestamp,
        stream,
        tag,
        payload,
    })
}

fn split_field(bytes: &[u8]) -> Result<(&[u8], &[u8]), InvalidCriRecord> {
    let index = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(InvalidCriRecord::MissingField)?;

    Ok((&bytes[..index], &bytes[index + 1..]))
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PartialKey {
    source: CriSource,
    stream: CriStream,
}

#[derive(Debug)]
struct Pending {
    timestamp: jiff::Timestamp,
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CriRecord {
    pub source: CriSource,
    pub timestamp: jiff::Timestamp,
    pub stream: CriStream,
    pub bytes: Arc<[u8]>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JoinError {
    PartialLaneCapacity,
}

impl fmt::Display for JoinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CRI partial lane capacity reached")
    }
}

impl std::error::Error for JoinError {}

/// Bounded reconstruction for CRI `P` fragments.
pub struct CriJoiner {
    max_record_bytes: usize,
    max_partial_lanes: usize,
    partials: HashMap<PartialKey, Pending>,
}

impl CriJoiner {
    pub fn new(max_record_bytes: usize, max_partial_lanes: usize) -> Self {
        assert!(max_record_bytes > 0);
        assert!(max_partial_lanes > 0);

        Self {
            max_record_bytes,
            max_partial_lanes,
            partials: HashMap::new(),
        }
    }

    pub fn accept(
        &mut self,
        source: CriSource,
        fragment: CriFragment<'_>,
    ) -> Result<Option<CriRecord>, JoinError> {
        let key = PartialKey {
            source: source.clone(),
            stream: fragment.stream,
        };

        if fragment.tag == CriTag::Partial {
            if !self.partials.contains_key(&key) && self.partials.len() == self.max_partial_lanes {
                return Err(JoinError::PartialLaneCapacity);
            }

            let pending = self.partials.entry(key).or_insert_with(|| Pending {
                timestamp: fragment.timestamp,
                bytes: Vec::new(),
                truncated: false,
            });
            append_bounded(
                &mut pending.bytes,
                fragment.payload,
                self.max_record_bytes,
                &mut pending.truncated,
            );

            return Ok(None);
        }

        let mut pending = self.partials.remove(&key).unwrap_or_else(|| Pending {
            timestamp: fragment.timestamp,
            bytes: Vec::new(),
            truncated: false,
        });
        append_bounded(
            &mut pending.bytes,
            fragment.payload,
            self.max_record_bytes,
            &mut pending.truncated,
        );
        append_bounded(
            &mut pending.bytes,
            b"\n",
            self.max_record_bytes,
            &mut pending.truncated,
        );

        Ok(Some(CriRecord {
            source,
            timestamp: pending.timestamp,
            stream: fragment.stream,
            bytes: pending.bytes.into(),
            truncated: pending.truncated,
        }))
    }

    pub fn pending_lanes(&self) -> usize {
        self.partials.len()
    }

    pub fn pending_bytes(&self) -> usize {
        self.partials
            .values()
            .map(|pending| pending.bytes.len())
            .sum()
    }
}

fn append_bounded(bytes: &mut Vec<u8>, next: &[u8], limit: usize, truncated: &mut bool) {
    let available = limit.saturating_sub(bytes.len());
    let accepted = available.min(next.len());

    bytes.extend_from_slice(&next[..accepted]);
    *truncated |= accepted < next.len();
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct TrackedFile {
    path: PathBuf,
    source: CriSource,
    file: File,
    pending: Vec<u8>,
    current: bool,
    drained_polls: u8,
    dropping_oversized: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CriFileEvent {
    Line { source: CriSource, bytes: Vec<u8> },
    OversizedLine { source: CriSource },
}

/// Open CRI files and their in-memory offsets.
///
/// Reconciliation is deliberately separate from reading. An outer loop may
/// trigger it from narrowly scoped lifecycle notifications without putting
/// filesystem discovery on the record path.
pub struct CriFileSet {
    root: PathBuf,
    max_line_bytes: usize,
    initialized: bool,
    files: HashMap<FileIdentity, TrackedFile>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CriFileStats {
    pub tracked_files: usize,
    pub pending_bytes: usize,
}

impl CriFileSet {
    pub fn new(root: PathBuf, max_line_bytes: usize) -> Self {
        assert!(max_line_bytes > 0);

        Self {
            root,
            max_line_bytes,
            initialized: false,
            files: HashMap::new(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn reconcile(&mut self) -> std::io::Result<()> {
        for tracked in self.files.values_mut() {
            tracked.current = false;
        }

        for path in discover_log_files(&self.root)? {
            let metadata = fs::metadata(&path)?;
            let identity = FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            };

            if let Some(tracked) = self.files.get_mut(&identity) {
                tracked.current = true;
                tracked.drained_polls = 0;
                continue;
            }

            let relative = path
                .strip_prefix(&self.root)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let Ok(source) = CriSource::from_relative_path(relative) else {
                continue;
            };
            let mut file = File::open(&path)?;

            if !self.initialized {
                file.seek(SeekFrom::End(0))?;
            }

            self.files.insert(
                identity,
                TrackedFile {
                    path,
                    source,
                    file,
                    pending: Vec::new(),
                    current: true,
                    drained_polls: 0,
                    dropping_oversized: false,
                },
            );
        }

        self.initialized = true;
        Ok(())
    }

    pub fn read_available(&mut self) -> std::io::Result<Vec<CriFileEvent>> {
        self.read_matching(|_| true)
    }

    /// Read changed current paths plus old inodes waiting to drain after rotation.
    pub fn read_changed(
        &mut self,
        changed: &HashSet<PathBuf>,
    ) -> std::io::Result<Vec<CriFileEvent>> {
        self.read_matching(|tracked| !tracked.current || changed.contains(&tracked.path))
    }

    pub fn stats(&self) -> CriFileStats {
        CriFileStats {
            tracked_files: self.files.len(),
            pending_bytes: self
                .files
                .values()
                .map(|tracked| tracked.pending.len())
                .sum(),
        }
    }

    fn read_matching(
        &mut self,
        mut selected: impl FnMut(&TrackedFile) -> bool,
    ) -> std::io::Result<Vec<CriFileEvent>> {
        let mut events = Vec::new();
        let mut remove = Vec::new();

        for (identity, tracked) in &mut self.files {
            if !selected(tracked) {
                continue;
            }

            let mut read_any = false;
            let mut chunk = [0_u8; 8 * 1024];

            loop {
                let read = tracked.file.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                read_any = true;
                consume_file_bytes(tracked, &chunk[..read], self.max_line_bytes, &mut events);
            }

            if tracked.current || read_any {
                tracked.drained_polls = 0;
            } else {
                tracked.drained_polls = tracked.drained_polls.saturating_add(1);
                if tracked.drained_polls >= 2 {
                    remove.push(*identity);
                }
            }
        }

        for identity in remove {
            self.files.remove(&identity);
        }

        Ok(events)
    }
}

fn consume_file_bytes(
    tracked: &mut TrackedFile,
    mut bytes: &[u8],
    max_line_bytes: usize,
    events: &mut Vec<CriFileEvent>,
) {
    while !bytes.is_empty() {
        if tracked.dropping_oversized {
            if let Some(pos) = bytes.iter().position(|&b| b == b'\n') {
                tracked.dropping_oversized = false;
                bytes = &bytes[pos + 1..];
            } else {
                break;
            }
            continue;
        }

        if let Some(pos) = bytes.iter().position(|&b| b == b'\n') {
            let line_chunk = &bytes[..=pos];
            bytes = &bytes[pos + 1..];

            let total_len = tracked.pending.len() + line_chunk.len();
            if total_len > max_line_bytes {
                tracked.pending.clear();
                events.push(CriFileEvent::OversizedLine {
                    source: tracked.source.clone(),
                });
            } else if tracked.pending.is_empty() {
                events.push(CriFileEvent::Line {
                    source: tracked.source.clone(),
                    bytes: line_chunk.to_vec(),
                });
            } else {
                tracked.pending.extend_from_slice(line_chunk);
                events.push(CriFileEvent::Line {
                    source: tracked.source.clone(),
                    bytes: std::mem::take(&mut tracked.pending),
                });
            }
        } else {
            let total_len = tracked.pending.len() + bytes.len();
            if total_len >= max_line_bytes {
                tracked.pending.clear();
                tracked.dropping_oversized = true;
                events.push(CriFileEvent::OversizedLine {
                    source: tracked.source.clone(),
                });
            } else {
                tracked.pending.extend_from_slice(bytes);
            }
            break;
        }
    }
}

fn discover_log_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for pod in read_directories(root)? {
        for container in read_directories(&pod)? {
            for entry in fs::read_dir(container)? {
                let entry = entry?;
                if entry.file_type()?.is_file()
                    && entry.path().extension().is_some_and(|value| value == "log")
                {
                    files.push(entry.path());
                }
            }
        }
    }

    files.sort();
    Ok(files)
}

fn read_directories(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut directories = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            directories.push(entry.path());
        }
    }

    directories.sort();
    Ok(directories)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn source(container: &str) -> CriSource {
        source_restart(container, 2)
    }

    fn source_restart(container: &str, restart: u32) -> CriSource {
        CriSource {
            namespace: "games".into(),
            pod_name: "palworld-0".into(),
            pod_uid: "0123-4567".into(),
            container_name: container.into(),
            restart,
        }
    }

    #[test]
    fn parses_cri_path_identity() {
        let parsed =
            CriSource::from_relative_path(Path::new("games_palworld-0_0123-4567/server/2.log"))
                .unwrap();

        assert_eq!(parsed, source("server"));
        assert!(CriSource::from_relative_path(Path::new("games_pod/0.log")).is_err());
        assert!(CriSource::from_relative_path(Path::new("games_pod_uid/server/nope.log")).is_err());
    }

    #[test]
    fn parses_opaque_full_record() {
        let parsed = parse_record(b"2026-08-15T17:03:00.123456789Z stderr F hi \xff\n").unwrap();

        assert_eq!(parsed.stream, CriStream::Stderr);
        assert_eq!(parsed.tag, CriTag::Full);
        assert_eq!(parsed.payload, b"hi \xff");
        assert_eq!(
            parsed.timestamp.to_string(),
            "2026-08-15T17:03:00.123456789Z"
        );
    }

    #[test]
    fn rejects_malformed_record_headers() {
        assert_eq!(
            parse_record(b"nope stdout F hello\n").unwrap_err(),
            InvalidCriRecord::InvalidTimestamp
        );
        assert_eq!(
            parse_record(b"2026-08-15T17:03:00Z wat F hello\n").unwrap_err(),
            InvalidCriRecord::InvalidStream
        );
        assert_eq!(
            parse_record(b"2026-08-15T17:03:00Z stdout X hello\n").unwrap_err(),
            InvalidCriRecord::InvalidTag
        );
        assert_eq!(
            parse_record(b"2026-08-15T17:03:00Z stdout F hello").unwrap_err(),
            InvalidCriRecord::MissingTerminator
        );
    }

    #[test]
    fn joins_partial_records_without_physical_newlines() {
        let mut joiner = CriJoiner::new(64, 4);
        let first = parse_record(b"2026-08-15T17:03:00Z stdout P pretty \n").unwrap();
        let final_part = parse_record(b"2026-08-15T17:03:01Z stdout F json\n").unwrap();

        assert_eq!(joiner.accept(source("server"), first).unwrap(), None);
        assert_eq!(joiner.pending_bytes(), b"pretty ".len());
        let record = joiner
            .accept(source("server"), final_part)
            .unwrap()
            .unwrap();

        assert_eq!(&*record.bytes, b"pretty json\n");
        assert_eq!(joiner.pending_bytes(), 0);
        assert_eq!(record.timestamp.to_string(), "2026-08-15T17:03:00Z");
        assert!(!record.truncated);
    }

    #[test]
    fn keeps_streams_and_containers_in_separate_lanes() {
        let mut joiner = CriJoiner::new(64, 4);

        joiner
            .accept(
                source("server"),
                parse_record(b"2026-08-15T17:03:00Z stdout P server-\n").unwrap(),
            )
            .unwrap();
        joiner
            .accept(
                source("sidecar"),
                parse_record(b"2026-08-15T17:03:00Z stdout P sidecar-\n").unwrap(),
            )
            .unwrap();

        let sidecar = joiner
            .accept(
                source("sidecar"),
                parse_record(b"2026-08-15T17:03:01Z stdout F done\n").unwrap(),
            )
            .unwrap()
            .unwrap();
        let server = joiner
            .accept(
                source("server"),
                parse_record(b"2026-08-15T17:03:01Z stdout F done\n").unwrap(),
            )
            .unwrap()
            .unwrap();

        assert_eq!(&*sidecar.bytes, b"sidecar-done\n");
        assert_eq!(&*server.bytes, b"server-done\n");
    }

    #[test]
    fn truncates_at_the_record_bound() {
        let mut joiner = CriJoiner::new(5, 1);
        let partial = parse_record(b"2026-08-15T17:03:00Z stdout P 1234\n").unwrap();
        let full = parse_record(b"2026-08-15T17:03:01Z stdout F 56\n").unwrap();

        joiner.accept(source("server"), partial).unwrap();
        let record = joiner.accept(source("server"), full).unwrap().unwrap();

        assert_eq!(&*record.bytes, b"12345");
        assert!(record.truncated);
    }

    #[test]
    fn rejects_a_new_partial_lane_at_capacity() {
        let mut joiner = CriJoiner::new(64, 1);
        let partial = || parse_record(b"2026-08-15T17:03:00Z stdout P x\n").unwrap();

        joiner.accept(source("one"), partial()).unwrap();

        assert_eq!(
            joiner.accept(source("two"), partial()).unwrap_err(),
            JoinError::PartialLaneCapacity
        );
    }

    fn create_log(root: &Path, restart: u32, bytes: &[u8]) -> PathBuf {
        let directory = root.join("games_palworld-0_0123-4567/server");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{restart}.log"));
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn starts_existing_files_at_eof_then_reads_appends() {
        let directory = tempfile::tempdir().unwrap();
        let path = create_log(directory.path(), 0, b"old\n");
        let mut files = CriFileSet::new(directory.path().to_owned(), 64);

        files.reconcile().unwrap();
        assert!(files.read_available().unwrap().is_empty());

        File::options()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(b"new\n")
            .unwrap();

        assert_eq!(
            files.read_available().unwrap(),
            vec![CriFileEvent::Line {
                source: source_restart("server", 0),
                bytes: b"new\n".to_vec(),
            }]
        );
    }

    #[test]
    fn reads_only_notified_current_files() {
        let directory = tempfile::tempdir().unwrap();
        let first = create_log(directory.path(), 0, b"");
        let second = create_log(directory.path(), 1, b"");
        let mut files = CriFileSet::new(directory.path().to_owned(), 64);
        files.reconcile().unwrap();

        File::options()
            .append(true)
            .open(&first)
            .unwrap()
            .write_all(b"first\n")
            .unwrap();
        File::options()
            .append(true)
            .open(&second)
            .unwrap()
            .write_all(b"second\n")
            .unwrap();

        assert_eq!(
            files
                .read_changed(&HashSet::from([first]))
                .unwrap()
                .into_iter()
                .map(|event| match event {
                    CriFileEvent::Line { bytes, .. } => bytes,
                    CriFileEvent::OversizedLine { .. } => unreachable!(),
                })
                .collect::<Vec<_>>(),
            vec![b"first\n".to_vec()]
        );
        assert_eq!(files.read_available().unwrap().len(), 1);
    }

    #[test]
    fn reads_new_files_from_zero_and_drains_a_rotated_inode() {
        let directory = tempfile::tempdir().unwrap();
        let path = create_log(directory.path(), 0, b"ignored\n");
        let mut files = CriFileSet::new(directory.path().to_owned(), 64);
        files.reconcile().unwrap();

        let rotated = path.with_extension("log.old");
        fs::rename(&path, &rotated).unwrap();
        File::options()
            .append(true)
            .open(&rotated)
            .unwrap()
            .write_all(b"old-inode\n")
            .unwrap();
        fs::write(&path, b"new-inode\n").unwrap();

        files.reconcile().unwrap();
        let events = files.read_available().unwrap();

        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| matches!(
            event,
            CriFileEvent::Line { bytes, .. } if bytes == b"old-inode\n"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            CriFileEvent::Line { bytes, .. } if bytes == b"new-inode\n"
        )));
    }

    #[test]
    fn bounds_unterminated_physical_lines_and_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let mut files = CriFileSet::new(directory.path().to_owned(), 4);
        files.reconcile().unwrap();
        create_log(directory.path(), 0, b"12345\nok\n");
        files.reconcile().unwrap();

        assert_eq!(
            files.read_available().unwrap(),
            vec![
                CriFileEvent::OversizedLine {
                    source: source_restart("server", 0),
                },
                CriFileEvent::Line {
                    source: source_restart("server", 0),
                    bytes: b"ok\n".to_vec(),
                },
            ]
        );
    }
}
