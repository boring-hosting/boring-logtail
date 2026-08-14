// SPDX-License-Identifier: GPL-3.0-or-later

//! Coordinates decoded kernel events into enriched, framed records.
//!
//! Keep the stages separate: their boundaries are different and must not be
//! inferred from one another.
//!
//! ```text
//! WriteEvent chunks
//!     |  group by (cgroup_id, pid, tid, operation_id)
//!     v
//! WriteOperation                         one completed write syscall
//!     |  enrich, classify descriptor, frame
//!     v
//! LogRecord batch                        zero or more pipeline outputs
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
//! Kubernetes identity belongs after syscall reconstruction. Stream framing
//! follows because one write syscall is not necessarily one log record.

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    sync::Arc,
};

use blt_abi::WriteEvent;
use blt_model::{Enrichment, LogRecord, StreamFileDescriptor};

use crate::{config::CaptureConfig, enrichment::Enricher, framing::RecordFramer};

#[derive(Debug, Eq, PartialEq)]

pub enum JoinWriteError {
    NoChunks,
    MissingFirstChunk,
    MissingLastChunk,
    MixedWrites,
    MixedMetadata,
    WrongOffset { expected: u32, actual: u32 },
    ChunkAfterLast,
    CapacityEvicted,
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
            Self::CapacityEvicted => {
                write!(
                    formatter,
                    "incomplete write evicted at the assembly memory bound"
                )
            }
        }
    }
}

impl Error for JoinWriteError {}

/// One reconstructed write syscall, still carrying the identity needed by
/// later framing and enrichment stages.
#[derive(Debug, Clone, Eq, PartialEq)]

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
    pub capture_gaps: Vec<usize>,
    pub bytes: Vec<u8>,
}

/// A complete write after identity lookup and stdout/stderr classification,
/// ready for record framing.
#[derive(Clone, Debug, Eq, PartialEq)]

pub struct ProcessedWrite {
    pub operation: WriteOperation,
    pub enrichment: Enrichment,
    pub stream: StreamFileDescriptor,
}

fn assemble_write(chunks: &[WriteEvent]) -> Result<WriteOperation, JoinWriteError> {
    let Some(first) = chunks.first() else {
        return Err(JoinWriteError::NoChunks);
    };

    if !first.is_first_chunk() {
        return Err(JoinWriteError::MissingFirstChunk);
    }

    let mut bytes = Vec::new();

    let mut capture_gaps = Vec::new();

    let mut reached_last = false;

    let mut expected_offset = 0u32;

    for (index, chunk) in chunks.iter().enumerate() {
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

        if chunk.data_offset != expected_offset {
            return Err(JoinWriteError::WrongOffset {
                expected: expected_offset,
                actual: chunk.data_offset,
            });
        }

        let read_failed = chunk.has_flag(blt_abi::FLAG_READ_FAILED);

        if read_failed {
            // A failed user-memory read advances the logical syscall offset but
            // contributes no bytes. Remember the seam so framing cannot invent
            // one apparently continuous line around the hole.
            capture_gaps.push(bytes.len());
        }

        bytes.extend_from_slice(chunk.payload());

        expected_offset = if read_failed {
            let logical_end = chunks.get(index + 1).map_or_else(
                || {
                    chunk
                        .result()
                        .and_then(|result| u32::try_from(result).ok())
                        .unwrap_or(chunk.requested_len)
                },
                |next| next.data_offset,
            );

            if logical_end <= chunk.data_offset {
                return Err(JoinWriteError::WrongOffset {
                    expected: chunk.data_offset.saturating_add(1),
                    actual: logical_end,
                });
            }

            logical_end
        } else {
            chunk
                .data_offset
                .checked_add(chunk.payload().len() as u32)
                .ok_or(JoinWriteError::MixedMetadata)?
        };

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
            .any(|chunk| chunk.has_flag(blt_abi::FLAG_READ_FAILED)),
        capture_gaps,
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

const ASSEMBLY_EVENT_CHARGE: usize = std::mem::size_of::<WriteEvent>() * 2 + 64;

const ASSEMBLY_OPERATION_CHARGE: usize = 256;

/// Bounded join table for fixed-size chunks emitted by the eBPF side.
///
/// The full key includes capture source, cgroup, task, and operation id because
/// syscalls from different tasks can interleave freely in the ring buffer.
#[derive(Debug)]

pub struct WriteAssembler {
    incomplete: HashMap<WriteKey, Vec<WriteEvent>>,
    order: VecDeque<WriteKey>,
    bytes: usize,
    max_operations: usize,
    max_bytes: usize,
}

impl WriteAssembler {
    #[cfg(test)]

    pub fn new() -> Self {
        Self::with_limits(4_096, 64 * 1024 * 1024)
    }

    fn with_limits(max_operations: usize, max_bytes: usize) -> Self {
        assert!(max_operations > 0 && max_bytes >= ASSEMBLY_EVENT_CHARGE);

        Self {
            incomplete: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_operations,
            max_bytes,
        }
    }

    pub fn accept(&mut self, event: WriteEvent) -> Result<Option<WriteOperation>, JoinWriteError> {
        let is_terminal = event.is_last_chunk() || event.is_truncated();

        let key = WriteKey::from(&event);

        let new_operation = !self.incomplete.contains_key(&key);

        let charge = ASSEMBLY_EVENT_CHARGE + usize::from(new_operation) * ASSEMBLY_OPERATION_CHARGE;

        if (new_operation && self.incomplete.len() == self.max_operations)
            || self.bytes.saturating_add(charge) > self.max_bytes
        {
            // An incomplete operation is useless after any of its chunks are
            // discarded. Remove the whole thing and report the loss honestly.
            if new_operation {
                self.evict_oldest();
            } else {
                self.remove(&key);
            }

            return Err(JoinWriteError::CapacityEvicted);
        }

        if new_operation {
            self.order.push_back(key);
        }

        self.incomplete.entry(key).or_default().push(event);

        self.bytes += charge;

        if !is_terminal {
            return Ok(None);
        }

        let chunks = self
            .remove(&key)
            .expect("entry was inserted immediately above");

        assemble_write(&chunks).map(Some)
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self.order.front().copied() {
            self.remove(&key);
        }
    }

    fn remove(&mut self, key: &WriteKey) -> Option<Vec<WriteEvent>> {
        let chunks = self.incomplete.remove(key)?;

        self.order.retain(|candidate| candidate != key);

        self.bytes -= ASSEMBLY_OPERATION_CHARGE + chunks.len() * ASSEMBLY_EVENT_CHARGE;

        Some(chunks)
    }
}

#[cfg(test)]

impl Default for WriteAssembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of feeding one kernel event through the pipeline.
/// `Pending` is normal: a chunk or partial line may need more input.
#[derive(Debug, Eq, PartialEq)]

pub enum PipelineDecision {
    Pending,
    Records(Vec<Arc<LogRecord>>),
}

/// Stateful node half of capture: join, enrich, and frame complete records.

pub struct Pipeline {
    assembler: WriteAssembler,
    enricher: Enricher,
    framer: RecordFramer,
}

impl Pipeline {
    pub fn new(enricher: Enricher, limits: CaptureConfig) -> Self {
        Self {
            assembler: WriteAssembler::with_limits(
                limits.assembly_operations,
                limits.assembly_bytes,
            ),
            enricher,
            framer: RecordFramer::with_limits(
                limits.max_record_bytes,
                limits.framing_lanes,
                limits.framing_bytes,
            ),
        }
    }

    pub fn accept(&mut self, event: WriteEvent) -> Result<PipelineDecision, JoinWriteError> {
        let Some(operation) = self.assembler.accept(event)? else {
            return Ok(PipelineDecision::Pending);
        };

        let enrichment = self.enricher.enrich(&operation);

        let stream = StreamFileDescriptor::from(operation.fd);

        let records = self.framer.accept(ProcessedWrite {
            operation,
            enrichment,
            stream,
        });

        if records.is_empty() {
            return Ok(PipelineDecision::Pending);
        }

        Ok(Self::records(records))
    }

    pub fn flush(&mut self) -> PipelineDecision {
        let records = self.framer.flush();

        if records.is_empty() {
            PipelineDecision::Pending
        } else {
            Self::records(records)
        }
    }

    fn records(records: Vec<LogRecord>) -> PipelineDecision {
        PipelineDecision::Records(records.into_iter().map(Arc::new).collect())
    }
}

#[cfg(test)]

mod tests {

    use std::{collections::HashMap, sync::Arc};

    use blt_abi::{
        CAPTURE_SOURCE_APPLICATION_SYSCALL, FLAG_FD_KNOWN, FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK,
        OPERATION_WRITE, OPERATION_WRITEV, WRITE_CHUNK_SIZE, WRITE_EVENT_VERSION,
    };
    use blt_model::{ContainerId, KubernetesIdentity, WorkloadResolution};
    use tokio::sync::watch;

    use super::*;
    use crate::enrichment::{CgroupSnapshot, PodSnapshot};

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

    fn pipeline(cgroups: CgroupSnapshot, pods: PodSnapshot) -> Pipeline {
        let (_, cgroups) = watch::channel(Arc::new(cgroups));

        let (_, pods) = watch::channel(Arc::new(pods));

        Pipeline::new(Enricher { cgroups, pods }, CaptureConfig::default())
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

    fn incomplete_write_assembly_is_bounded() {
        let mut assembler =
            WriteAssembler::with_limits(1, ASSEMBLY_OPERATION_CHARGE + ASSEMBLY_EVENT_CHARGE);

        let mut first = write_chunks(&vec![b'a'; WRITE_CHUNK_SIZE * 2]).remove(0);

        first.operation_id = 1;

        assert!(assembler.accept(first).unwrap().is_none());

        let mut second = write_chunks(&vec![b'b'; WRITE_CHUNK_SIZE * 2]).remove(0);

        second.operation_id = 2;

        assert_eq!(
            assembler.accept(second),
            Err(JoinWriteError::CapacityEvicted)
        );

        assert!(assembler.incomplete.is_empty());

        assert_eq!(assembler.bytes, 0);
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

        final_chunk.flags |= blt_abi::FLAG_TRUNCATED;

        let mut assembler = WriteAssembler::new();

        assert!(assembler.accept(chunks.remove(0)).unwrap().is_none());

        let operation = assembler.accept(chunks.remove(0)).unwrap().unwrap();

        assert!(operation.truncated);

        assert_eq!(operation.bytes.len(), WRITE_CHUNK_SIZE * 2);
    }

    #[test]

    fn preserves_read_failure_gaps_instead_of_rejecting_later_chunks() {
        let mut chunks = write_chunks(&vec![b'x'; WRITE_CHUNK_SIZE * 2]);

        chunks[0].flags |= blt_abi::FLAG_READ_FAILED;

        chunks[0].captured_len = 0;

        let mut assembler = WriteAssembler::new();

        assert!(assembler.accept(chunks.remove(0)).unwrap().is_none());

        let operation = assembler.accept(chunks.remove(0)).unwrap().unwrap();

        assert!(operation.read_failed);

        assert_eq!(operation.capture_gaps, vec![0]);

        assert_eq!(operation.bytes.len(), WRITE_CHUNK_SIZE);

        let mut terminal = write_chunks(b"lost").remove(0);

        terminal.flags |= blt_abi::FLAG_READ_FAILED;

        terminal.captured_len = 0;

        let operation = WriteAssembler::new().accept(terminal).unwrap().unwrap();

        assert!(operation.bytes.is_empty());

        assert_eq!(operation.capture_gaps, vec![0]);
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

    #[test]

    fn keeps_unresolved_writes_and_their_bytes_visible() {
        let mut pipeline = pipeline(CgroupSnapshot::default(), PodSnapshot::default());

        let event = write_chunks(b"still here\n").remove(0);

        let PipelineDecision::Records(emitted) = pipeline.accept(event).unwrap() else {
            panic!()
        };

        let [record] = emitted.as_slice() else {
            panic!()
        };

        assert_eq!(record.enrichment, Enrichment::UnresolvedCgroup);

        assert_eq!(record.sample_percent, 100);

        assert_eq!(record.bytes(), b"still here\n");
    }

    #[test]

    fn carries_stale_kubernetes_enrichment_without_node_policy() {
        const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let container: ContainerId = format!("containerd://{ID}").parse().unwrap();

        let identity = KubernetesIdentity {
            node: "worker-1".into(),
            namespace: "payments".into(),
            pod_name: "checkout".into(),
            pod_uid: "pod-uid".into(),
            container_name: "checkout".into(),
            container_id: container.clone(),
            workload: WorkloadResolution::NoController,
        };

        let cgroups = CgroupSnapshot {
            containers: HashMap::from([(456, vec![container.clone()])]),
        };

        let pods = PodSnapshot {
            identities: HashMap::from([(container, vec![identity.clone()])]),
            stale: true,
            ..Default::default()
        };

        let mut emitted = pipeline(cgroups, pods);

        let PipelineDecision::Records(records) = emitted
            .accept(write_chunks(b"visible\n").remove(0))
            .unwrap()
        else {
            panic!()
        };

        assert_eq!(records[0].enrichment, Enrichment::Stale(identity));
    }
}
