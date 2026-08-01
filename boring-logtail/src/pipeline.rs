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
//!     |  append bytes to (cgroup_id, stdout/stderr)
//!     v
//! StreamState                            bytes retained across syscalls
//!     |  split using newline/JSON/multiline framing
//!     v
//! LogRecord                              one application-level record
//! ```
//!
//! Build this incrementally:
//!
//! 1. `WriteAssembler` owns a map of incomplete operations. It accepts one
//!    `WriteEvent` at a time and returns `None` until the last chunk arrives.
//!    It then validates offsets and produces one `WriteOperation` containing
//!    the joined bytes. Missing, duplicate, truncated, and expired operations
//!    must be reported rather than silently discarded.
//! 2. `ProcessResolver` enriches a completed operation with process metadata.
//!    Preserve the numeric PID even when `/proc/<pid>` cannot be resolved, and
//!    cache successful lookups instead of resolving every chunk.
//! 3. `StreamAssembler` owns state keyed initially by `(cgroup_id, stream)`,
//!    where fd 1 is stdout and fd 2 is stderr. It appends bytes from completed
//!    writes because one record may span several syscalls and one syscall may
//!    contain several records.
//! 4. `RecordFramer` extracts `LogRecord`s from a stream. Start with newline
//!    framing; JSON, multiline, and protocol-specific framing can be added
//!    without changing capture or write assembly.
//!
//! The smallest useful first milestone is only stage 1: accept events and emit
//! complete `WriteOperation`s. Do not make Kubernetes or container-name lookup
//! part of this module yet; that is later enrichment keyed by `cgroup_id`.

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
    WrongOffset { expected: u32, actual: u32 },
    ChunkAfterLast,
    Truncated,
}

impl fmt::Display for JoinWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoChunks => write!(formatter, "write has no chunks"),
            Self::MissingFirstChunk => write!(formatter, "write does not start with a first chunk"),
            Self::MissingLastChunk => write!(formatter, "write does not end with a last chunk"),
            Self::MixedWrites => write!(formatter, "chunks belong to different writes"),
            Self::WrongOffset { expected, actual } => {
                write!(
                    formatter,
                    "expected chunk at offset {expected}, got {actual}"
                )
            }
            Self::ChunkAfterLast => write!(formatter, "found another chunk after the last chunk"),
            Self::Truncated => write!(formatter, "write was truncated by the capture limit"),
        }
    }
}

impl Error for JoinWriteError {}

/// Put the ordered chunks from one syscall back into its original byte stream.
pub fn join_write_chunks(chunks: &[WriteEvent]) -> Result<Vec<u8>, JoinWriteError> {
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
        if chunk.operation_id != first.operation_id {
            return Err(JoinWriteError::MixedWrites);
        }
        if chunk.is_truncated() {
            return Err(JoinWriteError::Truncated);
        }

        let expected = bytes.len() as u32;
        if chunk.data_offset != expected {
            return Err(JoinWriteError::WrongOffset {
                expected,
                actual: chunk.data_offset,
            });
        }

        bytes.extend_from_slice(chunk.payload());
        reached_last = chunk.is_last_chunk();
    }

    if !reached_last {
        return Err(JoinWriteError::MissingLastChunk);
    }
    Ok(bytes)
}

// WriteKey is pretty much: cgroup, pid, tid, operation_id
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct WriteKey {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    operation_id: u64,
}

impl fmt::Display for WriteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cgroup={}/pid={}/tid={}/operation={}",
            self.cgroup_id, self.pid, self.tid, self.operation_id,
        )
    }
}

// Reconstructs the events.
#[derive(Default, Debug)]
pub struct ChunkChunker {
    incomplete: HashMap<WriteKey, Vec<WriteEvent>>,
}

impl ChunkChunker {
    pub fn new() -> Self {
        Self {
            incomplete: HashMap::new(),
        }
    }

    pub fn accept(&mut self, event: WriteEvent) -> Result<Option<Vec<u8>>, JoinWriteError> {
        let is_last = event.is_last_chunk();
        let key = WriteKey {
            cgroup_id: event.cgroup_id,
            pid: event.pid,
            tid: event.tid,
            operation_id: event.operation_id,
        };

        self.incomplete.entry(key).or_default().push(event);

        if !is_last {
            return Ok(None);
        }

        let chunks = self
            .incomplete
            .remove(&key)
            .expect("entry was inserted immediately above");
        join_write_chunks(&chunks).map(Some)
    }
}

// // The actual representation of the damn log. After so many hoops.
// struct LogRecord {
//     timestamp_ns: u64,
//     cgroup_id: u64,
//     pid: u32,
//     tid: u32,
//     process: Option<String>,
//     stream: OutputStream,
//     bytes: Vec<u8>,
//     integrity: Integrity,
// }

#[cfg(test)]
mod tests {
    use boring_logtail_common::{
        FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK, SYSCALL_WRITE, WRITE_CHUNK_SIZE, WRITE_EVENT_VERSION,
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
                let mut flags = 0;
                if number == 0 {
                    flags |= FLAG_FIRST_CHUNK;
                }
                if number + 1 == chunk_count {
                    flags |= FLAG_LAST_CHUNK;
                }
                WriteEvent {
                    abi_version: WRITE_EVENT_VERSION,
                    flags,
                    syscall: SYSCALL_WRITE,
                    timestamp_ns: 1,
                    cgroup_id: 456,
                    operation_id: 789,
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
        let joined = join_write_chunks(&chunks).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&joined).unwrap();

        assert_eq!(decoded["service"], "checkout");
        assert_eq!(decoded["customer"]["id"], 42);
        assert_eq!(decoded["customer"]["labels"][1], "priority");
        assert_eq!(decoded["cart"][17]["product_id"], 17);
        assert_eq!(decoded, source);
    }

    #[test]
    fn refuses_a_write_with_a_missing_middle_chunk() {
        let encoded = vec![b'x'; WRITE_CHUNK_SIZE * 3];
        let mut chunks = write_chunks(&encoded);
        chunks.remove(1);

        assert_eq!(
            join_write_chunks(&chunks),
            Err(JoinWriteError::WrongOffset {
                expected: WRITE_CHUNK_SIZE as u32,
                actual: (WRITE_CHUNK_SIZE * 2) as u32,
            })
        );
    }
}

struct OutputStream {
    lines: Vec<String>,
}

#[derive(Debug)]
enum ProcessorError {
    Unreconstrcutable(String),
}

impl fmt::Display for ProcessorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err = match self {
            Self::Unreconstrcutable(s) => {
                format!("Unreconstructable {s}")
            }
        };
        write!(f, "Pipeline errored: {err}")
    }
}

impl Error for ProcessorError {}

// trait Processor {
//     type HashMap;

//     fn pipeline(&self, event: &WriteEvent) -> Result<Option<LogRecord>, ProcessorError>;
// }
