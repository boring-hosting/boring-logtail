// SPDX-License-Identifier: GPL-3.0-or-later

//! Turns raw kernel capture events into complete application log records.
//!
//! Keep the stages separate: their boundaries are different and must not be
//! inferred from one another.
//!
//! ```text
//! WriteEvent chunks
//!     |  group by (cgroup_id, pid, tid, operation_id)
//!     v
//! WriteOperation                         one completed write syscall
//! ```
//!
//! Build this incrementally:
//!
//! `WriteAssembler` owns a map of incomplete operations. It accepts one
//!    `WriteEvent` at a time and returns `None` until the last chunk arrives.
//!    It then validates offsets and produces one `WriteOperation` containing
//!    the joined bytes. Missing, duplicate, truncated, and expired operations
//!    must be reported rather than silently discarded.
//!
//! Process lookup, stream framing, and kubernetes identity belong after this
//! boundary. They must not leak into syscall reconstruction.

use boring_logtail_common::WriteEvent;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub enum JoinWriteError {
    NoChunks,
    MissingFirstChunk,
    MissingLastChunk,
    MixedWrites,
    MixedMetadata,
    WrongOffset { expected: u32, actual: u32 },
    ChunkAfterLast,
}

impl fmt::Display for JoinWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoChunks => write!(formatter, "write has no chunks"),
            Self::MissingFirstChunk => write!(formatter, "write does not start with a first chunk"),
            Self::MissingLastChunk => write!(formatter, "write does not end with a last chunk"),
            Self::MixedWrites => write!(formatter, "chunks belong to different writes"),
            Self::MixedMetadata => write!(formatter, "chunks disagree about write metadata"),
            Self::WrongOffset { expected, actual } => {
                write!(
                    formatter,
                    "expected chunk at offset {expected}, got {actual}"
                )
            }
            Self::ChunkAfterLast => write!(formatter, "found another chunk after the last chunk"),
        }
    }
}

impl Error for JoinWriteError {}

/// One reconstructed write syscall, still carrying the identity needed by
/// later framing and enrichment stages.
#[derive(Debug, Eq, PartialEq)]
pub struct WriteOperation {
    pub capture_source: u16,
    pub operation_kind: u16,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub operation_id: u64,
    pub source_id: u64,
    pub result: Option<i64>,
    pub pid: u32,
    pub tid: u32,
    pub fd: Option<u32>,
    pub requested_len: u32,
    pub truncated: bool,
    pub read_failed: bool,
    pub bytes: Vec<u8>,
}

fn assemble_write(chunks: &[WriteEvent]) -> Result<WriteOperation, JoinWriteError> {
    let Some(first) = chunks.first() else {
        return Err(JoinWriteError::NoChunks);
    };
    if !first.is_first_chunk() {
        return Err(JoinWriteError::MissingFirstChunk);
    }

    let mut bytes = Vec::new();
    let mut reached_last = false;
    for chunk in chunks {
        if reached_last {
            return Err(JoinWriteError::ChunkAfterLast);
        }
        if WriteKey::from(chunk) != WriteKey::from(first) {
            return Err(JoinWriteError::MixedWrites);
        }
        if chunk.timestamp_ns != first.timestamp_ns
            || chunk.capture_source != first.capture_source
            || chunk.operation_kind != first.operation_kind
            || chunk.source_id != first.source_id
            || chunk.fd() != first.fd()
            || chunk.requested_len != first.requested_len
            || chunk.result() != first.result()
        {
            return Err(JoinWriteError::MixedMetadata);
        }

        let expected = bytes.len() as u32;
        if chunk.data_offset != expected {
            return Err(JoinWriteError::WrongOffset {
                expected,
                actual: chunk.data_offset,
            });
        }

        bytes.extend_from_slice(chunk.payload());
        reached_last = chunk.is_last_chunk() || chunk.is_truncated();
    }

    if !reached_last {
        return Err(JoinWriteError::MissingLastChunk);
    }
    Ok(WriteOperation {
        capture_source: first.capture_source,
        operation_kind: first.operation_kind,
        timestamp_ns: first.timestamp_ns,
        cgroup_id: first.cgroup_id,
        operation_id: first.operation_id,
        source_id: first.source_id,
        result: first.result(),
        pid: first.pid,
        tid: first.tid,
        fd: first.fd(),
        requested_len: first.requested_len,
        truncated: chunks.iter().any(WriteEvent::is_truncated),
        read_failed: chunks
            .iter()
            .any(|chunk| chunk.has_flag(boring_logtail_common::FLAG_READ_FAILED)),
        bytes,
    })
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct WriteKey {
    capture_source: u16,
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    operation_id: u64,
}

impl From<&WriteEvent> for WriteKey {
    fn from(event: &WriteEvent) -> Self {
        Self {
            capture_source: event.capture_source,
            cgroup_id: event.cgroup_id,
            pid: event.pid,
            tid: event.tid,
            operation_id: event.operation_id,
        }
    }
}

impl fmt::Display for WriteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={}/cgroup={}/pid={}/tid={}/operation={}",
            self.capture_source, self.cgroup_id, self.pid, self.tid, self.operation_id,
        )
    }
}

#[derive(Default, Debug)]
pub struct WriteAssembler {
    incomplete: HashMap<WriteKey, Vec<WriteEvent>>,
}

impl WriteAssembler {
    pub fn new() -> Self {
        Self {
            incomplete: HashMap::new(),
        }
    }

    pub fn accept(&mut self, event: WriteEvent) -> Result<Option<WriteOperation>, JoinWriteError> {
        let is_terminal = event.is_last_chunk() || event.is_truncated();
        let key = WriteKey::from(&event);

        self.incomplete.entry(key).or_default().push(event);

        if !is_terminal {
            return Ok(None);
        }

        let chunks = self
            .incomplete
            .remove(&key)
            .expect("entry was inserted immediately above");
        assemble_write(&chunks).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use boring_logtail_common::{
        CAPTURE_SOURCE_APPLICATION_SYSCALL, FLAG_FD_KNOWN, FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK,
        OPERATION_WRITE, OPERATION_WRITEV, WRITE_CHUNK_SIZE, WRITE_EVENT_VERSION,
    };

    use super::*;

    fn write_chunks(bytes: &[u8]) -> Vec<WriteEvent> {
        let chunk_count = bytes.len().div_ceil(WRITE_CHUNK_SIZE);
        bytes
            .chunks(WRITE_CHUNK_SIZE)
            .enumerate()
            .map(|(number, chunk)| {
                let mut data = [0; WRITE_CHUNK_SIZE];
                data[..chunk.len()].copy_from_slice(chunk);
                let mut flags = FLAG_FD_KNOWN;
                if number == 0 {
                    flags |= FLAG_FIRST_CHUNK;
                }
                if number + 1 == chunk_count {
                    flags |= FLAG_LAST_CHUNK;
                }
                WriteEvent {
                    abi_version: WRITE_EVENT_VERSION,
                    flags,
                    capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
                    operation_kind: OPERATION_WRITE,
                    timestamp_ns: 1,
                    cgroup_id: 456,
                    operation_id: 789,
                    source_id: 0,
                    result: bytes.len() as i64,
                    pid: 123,
                    tid: 124,
                    fd: 1,
                    requested_len: bytes.len() as u32,
                    data_offset: (number * WRITE_CHUNK_SIZE) as u32,
                    captured_len: chunk.len() as u32,
                    data,
                }
            })
            .collect()
    }

    #[test]
    fn joins_and_deconstructs_json_spread_across_chunks() {
        let source = serde_json::json!({
            "level": "info",
            "service": "checkout",
            "message": "a deliberately long structured log that crosses the eBPF chunk boundary",
            "customer": {
                "id": 42,
                "name": "Ada Lovelace",
                "labels": ["early-adopter", "priority", "likes-very-long-json-documents"]
            },
            "cart": (0..20)
                .map(|id| serde_json::json!({ "product_id": id, "quantity": id % 3 + 1 }))
                .collect::<Vec<_>>()
        });
        let encoded = serde_json::to_vec(&source).unwrap();
        assert!(encoded.len() > WRITE_CHUNK_SIZE * 2);

        let chunks = write_chunks(&encoded);
        let mut assembler = WriteAssembler::new();
        let mut operation = None;
        for chunk in chunks {
            operation = assembler.accept(chunk).unwrap().or(operation);
        }
        let operation = operation.unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&operation.bytes).unwrap();

        assert_eq!(decoded["service"], "checkout");
        assert_eq!(decoded["customer"]["id"], 42);
        assert_eq!(decoded["customer"]["labels"][1], "priority");
        assert_eq!(decoded["cart"][17]["product_id"], 17);
        assert_eq!(decoded, source);
        assert_eq!(operation.cgroup_id, 456);
        assert_eq!(operation.pid, 123);
        assert_eq!(operation.fd, Some(1));
        assert!(!operation.truncated);
    }

    #[test]
    fn refuses_a_write_with_a_missing_middle_chunk() {
        let encoded = vec![b'x'; WRITE_CHUNK_SIZE * 3];
        let mut chunks = write_chunks(&encoded);
        chunks.remove(1);

        let mut assembler = WriteAssembler::new();
        assert!(assembler.accept(chunks.remove(0)).unwrap().is_none());
        assert_eq!(
            assembler.accept(chunks.remove(0)),
            Err(JoinWriteError::WrongOffset {
                expected: WRITE_CHUNK_SIZE as u32,
                actual: (WRITE_CHUNK_SIZE * 2) as u32,
            })
        );
    }

    #[test]
    fn emits_truncated_writes_with_an_integrity_marker() {
        let mut chunks = write_chunks(&vec![b'x'; WRITE_CHUNK_SIZE * 2]);
        let final_chunk = chunks.last_mut().unwrap();
        final_chunk.flags &= !FLAG_LAST_CHUNK;
        final_chunk.flags |= boring_logtail_common::FLAG_TRUNCATED;

        let mut assembler = WriteAssembler::new();
        assert!(assembler.accept(chunks.remove(0)).unwrap().is_none());
        let operation = assembler.accept(chunks.remove(0)).unwrap().unwrap();

        assert!(operation.truncated);
        assert_eq!(operation.bytes.len(), WRITE_CHUNK_SIZE * 2);
    }

    #[test]
    fn joins_writev_segments_in_logical_iovec_order() {
        let segments: [&[u8]; 4] = [b"abc", b"", b"defgh", b"\n"];
        let expected = segments.concat();
        let mut offset = 0u32;
        let mut events = Vec::new();
        for (index, segment) in segments.iter().filter(|part| !part.is_empty()).enumerate() {
            let mut data = [0; WRITE_CHUNK_SIZE];
            data[..segment.len()].copy_from_slice(segment);
            let mut flags = FLAG_FD_KNOWN;
            if index == 0 {
                flags |= FLAG_FIRST_CHUNK;
            }
            if offset as usize + segment.len() == expected.len() {
                flags |= FLAG_LAST_CHUNK;
            }
            events.push(WriteEvent {
                abi_version: WRITE_EVENT_VERSION,
                flags,
                capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
                operation_kind: OPERATION_WRITEV,
                timestamp_ns: 1,
                cgroup_id: 456,
                operation_id: 790,
                source_id: 0,
                result: expected.len() as i64,
                pid: 123,
                tid: 124,
                fd: 2,
                requested_len: expected.len() as u32,
                data_offset: offset,
                captured_len: segment.len() as u32,
                data,
            });
            offset += segment.len() as u32;
        }

        let mut assembler = WriteAssembler::new();
        let mut operation = None;
        for event in events {
            operation = assembler.accept(event).unwrap().or(operation);
        }
        let operation = operation.unwrap();
        assert_eq!(operation.operation_kind, OPERATION_WRITEV);
        assert_eq!(operation.fd, Some(2));
        assert_eq!(operation.bytes, expected);
    }
}
