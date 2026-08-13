// SPDX-License-Identifier: GPL-3.0-or-later

//! Byte-preserving log records and bounded newline framing.

use crate::{
    enrichment::{ContainerId, Enrichment, WorkloadResolution},
    pipeline::{ProcessedWrite, StreamFileDescriptor},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

pub const DEFAULT_MAX_RECORD_BYTES: usize = 64 * 1024;
pub(crate) const FRAMING_LANE_CHARGE: usize = 2_048;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum FramingKey {
    Kubernetes {
        namespace: String,
        pod_uid: String,
        container_id: ContainerId,
        workload: WorkloadResolution,
        stream: StreamFileDescriptor,
    },
    Unresolved {
        capture_source: u16,
        cgroup_id: u64,
        stream: StreamFileDescriptor,
    },
}

impl FramingKey {
    fn from_write(write: &ProcessedWrite) -> Self {
        match &write.enrichment {
            Enrichment::Enriched(identity) | Enrichment::Stale(identity) => Self::Kubernetes {
                namespace: identity.namespace.clone(),
                pod_uid: identity.pod_uid.clone(),
                container_id: identity.container_id.clone(),
                workload: identity.workload.clone(),
                stream: write.stream,
            },
            Enrichment::UnresolvedCgroup
            | Enrichment::UnresolvedContainer(_)
            | Enrichment::AmbiguousCgroup
            | Enrichment::AmbiguousContainer(_) => Self::Unresolved {
                capture_source: write.operation.capture_source,
                cgroup_id: write.operation.cgroup_id,
                stream: write.stream,
            },
        }
    }

    pub(crate) fn sampling_seed(&self) -> u64 {
        let mut state = 0xcbf2_9ce4_8422_2325;
        let mut add = |bytes: &[u8]| {
            for byte in bytes {
                state ^= u64::from(*byte);
                state = state.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        match self {
            Self::Kubernetes {
                namespace,
                pod_uid,
                container_id,
                workload,
                stream,
            } => {
                add(namespace.as_bytes());
                add(pod_uid.as_bytes());
                add(container_id.runtime.as_bytes());
                add(container_id.id.as_bytes());
                match workload {
                    WorkloadResolution::Resolved(workload) => {
                        add(&[0]);
                        add(workload.api_version.as_bytes());
                        add(workload.kind.as_bytes());
                        add(workload.name.as_bytes());
                        add(workload.uid.as_bytes());
                    }
                    WorkloadResolution::NoController => add(&[1]),
                    WorkloadResolution::UnresolvedReplicaSet(workload) => {
                        add(&[2]);
                        add(workload.uid.as_bytes());
                    }
                    WorkloadResolution::UnsupportedOwner(workload) => {
                        add(&[3]);
                        add(workload.api_version.as_bytes());
                        add(workload.kind.as_bytes());
                        add(workload.uid.as_bytes());
                    }
                }
                add(&stream.sampling_bytes());
            }
            Self::Unresolved {
                capture_source,
                cgroup_id,
                stream,
            } => {
                add(&capture_source.to_le_bytes());
                add(&cgroup_id.to_le_bytes());
                add(&stream.sampling_bytes());
            }
        }
        state
    }

    const fn stream(&self) -> StreamFileDescriptor {
        match self {
            Self::Kubernetes { stream, .. } | Self::Unresolved { stream, .. } => *stream,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordIntegrity {
    pub capture_truncated: bool,
    pub payload_read_failed: bool,
    pub max_size_split: bool,
    pub capacity_split: bool,
    pub capture_gap: bool,
    pub unterminated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Severity {
    #[default]
    Unknown,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "unknown",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LogRecord {
    pub(crate) observed_at: jiff::Timestamp,
    pub(crate) sampling_seed: u64,
    pub(crate) stream: StreamFileDescriptor,
    pub(crate) enrichment: Enrichment,
    pub(crate) first_timestamp_ns: u64,
    pub(crate) last_timestamp_ns: u64,
    pub(crate) first_operation_id: u64,
    pub(crate) last_operation_id: u64,
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) integrity: RecordIntegrity,
    pub(crate) sample_percent: u8,
    pub(crate) severity: Severity,
}

impl LogRecord {
    pub fn observed_at(&self) -> jiff::Timestamp {
        self.observed_at
    }
    pub fn stream(&self) -> StreamFileDescriptor {
        self.stream
    }

    pub fn enrichment(&self) -> &Enrichment {
        &self.enrichment
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn integrity(&self) -> RecordIntegrity {
        self.integrity
    }

    pub fn sample_percent(&self) -> u8 {
        self.sample_percent
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn first_timestamp_ns(&self) -> u64 {
        self.first_timestamp_ns
    }

    pub fn last_timestamp_ns(&self) -> u64 {
        self.last_timestamp_ns
    }

    pub fn first_operation_id(&self) -> u64 {
        self.first_operation_id
    }

    pub fn last_operation_id(&self) -> u64 {
        self.last_operation_id
    }
}

#[derive(Debug)]
struct PendingRecord {
    enrichment: Enrichment,
    first_timestamp_ns: u64,
    last_timestamp_ns: u64,
    first_operation_id: u64,
    last_operation_id: u64,
    bytes: Vec<u8>,
    integrity: RecordIntegrity,
}

impl PendingRecord {
    fn new(write: &ProcessedWrite) -> Self {
        Self {
            enrichment: write.enrichment.clone(),
            first_timestamp_ns: write.operation.timestamp_ns,
            last_timestamp_ns: write.operation.timestamp_ns,
            first_operation_id: write.operation.operation_id,
            last_operation_id: write.operation.operation_id,
            bytes: Vec::new(),
            integrity: RecordIntegrity::default(),
        }
    }

    fn observe(&mut self, write: &ProcessedWrite) {
        self.last_timestamp_ns = write.operation.timestamp_ns;
        self.last_operation_id = write.operation.operation_id;
        self.integrity.capture_truncated |= write.operation.truncated;
        self.integrity.payload_read_failed |= write.operation.read_failed;
    }

    fn finish(
        mut self,
        framing_key: FramingKey,
        max_size_split: bool,
        capacity_split: bool,
        capture_gap: bool,
        unterminated: bool,
    ) -> LogRecord {
        self.integrity.max_size_split = max_size_split;
        self.integrity.capacity_split = capacity_split;
        self.integrity.capture_gap = capture_gap;
        self.integrity.unterminated = unterminated;
        LogRecord {
            observed_at: jiff::Timestamp::now(),
            sampling_seed: framing_key.sampling_seed(),
            stream: framing_key.stream(),
            enrichment: self.enrichment,
            first_timestamp_ns: self.first_timestamp_ns,
            last_timestamp_ns: self.last_timestamp_ns,
            first_operation_id: self.first_operation_id,
            last_operation_id: self.last_operation_id,
            bytes: self.bytes.into(),
            integrity: self.integrity,
            sample_percent: 100,
            severity: Severity::Unknown,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RecordFramer {
    max_record_bytes: usize,
    max_pending_lanes: usize,
    max_pending_bytes: usize,
    pending_bytes: usize,
    pending: HashMap<FramingKey, PendingRecord>,
    pending_order: VecDeque<FramingKey>,
}

impl RecordFramer {
    #[cfg(test)]
    pub fn new(max_record_bytes: usize) -> Self {
        Self::with_limits(max_record_bytes, 4_096, 64 * 1024 * 1024)
    }

    pub(crate) fn with_limits(
        max_record_bytes: usize,
        max_pending_lanes: usize,
        max_pending_bytes: usize,
    ) -> Self {
        assert!(max_record_bytes > 0, "record byte limit must be non-zero");
        assert!(max_pending_lanes > 0, "pending lane limit must be non-zero");
        assert!(
            max_pending_bytes >= max_record_bytes,
            "pending byte limit must fit one record"
        );
        assert!(
            max_pending_bytes >= max_record_bytes + FRAMING_LANE_CHARGE,
            "pending byte limit must fit one lane and record"
        );
        Self {
            max_record_bytes,
            max_pending_lanes,
            max_pending_bytes,
            pending_bytes: 0,
            pending: HashMap::new(),
            pending_order: VecDeque::new(),
        }
    }

    pub(crate) fn accept(&mut self, write: ProcessedWrite) -> Vec<LogRecord> {
        let lane = FramingKey::from_write(&write);
        let mut records = Vec::new();
        let mut offset = 0;
        for gap in write.operation.capture_gaps.iter().copied() {
            let gap = gap.min(write.operation.bytes.len());
            records.extend(self.accept_bytes(&write, &lane, &write.operation.bytes[offset..gap]));
            records.push(self.flush_gap(&write, &lane));
            offset = gap;
        }
        records.extend(self.accept_bytes(&write, &lane, &write.operation.bytes[offset..]));
        if write.operation.truncated && write.operation.capture_gaps.is_empty() {
            records.push(self.flush_gap(&write, &lane));
        }
        records
    }

    fn accept_bytes(
        &mut self,
        write: &ProcessedWrite,
        lane: &FramingKey,
        mut input: &[u8],
    ) -> Vec<LogRecord> {
        let mut records = Vec::new();

        while !input.is_empty() {
            let new_lane = !self.pending.contains_key(lane);
            if new_lane && self.pending.len() == self.max_pending_lanes {
                records.push(self.flush_oldest_capacity());
            }
            while new_lane
                && self.pending_bytes.saturating_add(FRAMING_LANE_CHARGE) > self.max_pending_bytes
            {
                records.push(self.flush_oldest_capacity());
            }
            if new_lane {
                self.pending_order.push_back(lane.clone());
                self.pending_bytes += FRAMING_LANE_CHARGE;
            }
            let pending = self
                .pending
                .entry(lane.clone())
                .or_insert_with(|| PendingRecord::new(write));
            pending.observe(write);

            let allocation_room = self.max_pending_bytes - self.pending_bytes;
            let spare_capacity = pending.bytes.capacity() - pending.bytes.len();
            let available = (self.max_record_bytes - pending.bytes.len())
                .min(allocation_room.saturating_add(spare_capacity));
            let window = &input[..input.len().min(available)];
            let newline = window.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(window.len(), |position| position + 1);
            let old_capacity = pending.bytes.capacity();
            pending.bytes.extend_from_slice(&input[..consumed]);
            self.pending_bytes += pending.bytes.capacity() - old_capacity;
            input = &input[consumed..];

            let complete_line = newline.is_some();
            let reached_limit = pending.bytes.len() == self.max_record_bytes;
            if complete_line || reached_limit {
                let pending = self.remove_pending(lane);
                records.push(pending.finish(lane.clone(), !complete_line, false, false, false));
            } else {
                while self.pending_bytes > self.max_pending_bytes {
                    records.push(self.flush_oldest_capacity());
                }
            }
        }

        records
    }

    fn remove_pending(&mut self, lane: &FramingKey) -> PendingRecord {
        let pending = self
            .pending
            .remove(lane)
            .expect("pending record exists until it is emitted");
        self.pending_bytes -= pending.bytes.capacity() + FRAMING_LANE_CHARGE;
        self.pending_order.retain(|candidate| candidate != lane);
        pending
    }

    fn flush_gap(&mut self, write: &ProcessedWrite, lane: &FramingKey) -> LogRecord {
        let mut pending = if self.pending.contains_key(lane) {
            self.remove_pending(lane)
        } else {
            PendingRecord::new(write)
        };
        pending.observe(write);
        pending.finish(lane.clone(), false, false, true, true)
    }

    fn flush_oldest_capacity(&mut self) -> LogRecord {
        let lane = self
            .pending_order
            .front()
            .cloned()
            .expect("capacity is consumed only by a pending source");
        self.remove_pending(&lane)
            .finish(lane, false, true, false, true)
    }

    pub(crate) fn flush(&mut self) -> Vec<LogRecord> {
        self.pending_bytes = 0;
        self.pending_order.clear();
        self.pending
            .drain()
            .map(|(lane, pending)| pending.finish(lane, false, false, false, true))
            .collect()
    }
}

#[cfg(test)]
impl Default for RecordFramer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RECORD_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enrichment::{ContainerId, KubernetesIdentity, WorkloadIdentity},
        pipeline::WriteOperation,
    };
    use boring_logtail_common::{CAPTURE_SOURCE_APPLICATION_SYSCALL, OPERATION_WRITE};

    fn write(number: u64, bytes: &[u8]) -> ProcessedWrite {
        write_from_source(number, 7, bytes)
    }

    fn write_from_source(number: u64, source: u64, bytes: &[u8]) -> ProcessedWrite {
        ProcessedWrite {
            operation: WriteOperation {
                capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
                operation_kind: OPERATION_WRITE,
                timestamp_ns: number,
                cgroup_id: source,
                operation_id: number,
                source_id: 0,
                result: Some(bytes.len() as i64),
                pid: 1,
                tid: 1,
                fd: Some(1),
                requested_len: bytes.len() as u32,
                truncated: false,
                read_failed: false,
                capture_gaps: Vec::new(),
                bytes: bytes.to_vec(),
            },
            enrichment: Enrichment::UnresolvedCgroup,
            stream: StreamFileDescriptor::Stdout,
        }
    }

    #[test]
    fn frames_across_writes_and_emits_many_lines() {
        let mut framer = RecordFramer::new(64);
        assert!(framer.accept(write(1, b"hel")).is_empty());
        let records = framer.accept(write(2, b"lo\none\ntwo"));
        assert_eq!(records.len(), 2);
        assert_eq!(&*records[0].bytes, b"hello\n");
        assert_eq!(&*records[1].bytes, b"one\n");
        assert_eq!(records[0].first_operation_id, 1);
        assert_eq!(records[0].last_operation_id, 2);
        let flushed = framer.flush();
        assert_eq!(&*flushed[0].bytes, b"two");
        assert!(flushed[0].integrity.unterminated);
    }

    #[test]
    fn preserves_non_utf8_and_splits_at_the_bound() {
        let mut framer = RecordFramer::new(4);
        let records = framer.accept(write(1, &[0xff, b'a', b'b', b'c', b'd', b'\n']));
        assert_eq!(records.len(), 2);
        assert_eq!(&*records[0].bytes, &[0xff, b'a', b'b', b'c']);
        assert!(records[0].integrity.max_size_split);
        assert_eq!(&*records[1].bytes, b"d\n");
        assert!(!records[1].integrity.max_size_split);
    }

    #[test]
    fn carries_capture_integrity_to_the_record() {
        let mut damaged = write(1, b"bad\n");
        damaged.operation.truncated = true;
        damaged.operation.read_failed = true;
        let record = RecordFramer::new(64).accept(damaged).remove(0);
        assert!(record.integrity.capture_truncated);
        assert!(record.integrity.payload_read_failed);
    }

    #[test]
    fn capture_gaps_split_lines_and_zero_byte_failures_stay_visible() {
        let mut damaged = write(1, b"beforeafter\n");
        damaged.operation.read_failed = true;
        damaged.operation.capture_gaps = vec![6];
        let records = RecordFramer::new(64).accept(damaged);
        assert_eq!(records.len(), 2);
        assert_eq!(&*records[0].bytes, b"before");
        assert!(records[0].integrity.capture_gap);
        assert_eq!(&*records[1].bytes, b"after\n");

        let mut empty = write(2, b"");
        empty.operation.read_failed = true;
        empty.operation.capture_gaps = vec![0];
        let record = RecordFramer::new(64).accept(empty).remove(0);
        assert!(record.bytes.is_empty());
        assert!(record.integrity.capture_gap);
        assert!(record.integrity.payload_read_failed);
    }

    #[test]
    fn pending_source_and_byte_pressure_flush_explicit_fragments() {
        let mut source_limited = RecordFramer::with_limits(8, 2, FRAMING_LANE_CHARGE * 2 + 16);
        assert!(
            source_limited
                .accept(write_from_source(1, 1, b"aaa"))
                .is_empty()
        );
        assert!(
            source_limited
                .accept(write_from_source(2, 2, b"bbb"))
                .is_empty()
        );
        let flushed = source_limited.accept(write_from_source(3, 3, b"c"));
        assert_eq!(&*flushed[0].bytes, b"aaa");
        assert!(flushed[0].integrity.capacity_split);

        let mut byte_limited = RecordFramer::with_limits(8, 4, FRAMING_LANE_CHARGE + 8);
        assert!(
            byte_limited
                .accept(write_from_source(1, 1, b"aaa"))
                .is_empty()
        );
        let flushed = byte_limited.accept(write_from_source(2, 2, b"bb"));
        assert_eq!(&*flushed[0].bytes, b"aaa");
        assert!(flushed[0].integrity.capacity_split);
    }

    #[test]
    fn pending_byte_accounting_tracks_retained_vector_capacity() {
        let mut framer = RecordFramer::with_limits(8, 8, FRAMING_LANE_CHARGE + 8);
        for source in 0..8 {
            let records = framer.accept(write_from_source(source, source, b"line\nx"));
            assert!(!records.is_empty());
            assert!(framer.pending_bytes <= FRAMING_LANE_CHARGE + 8);
            assert_eq!(
                framer.pending_bytes,
                framer.pending.len() * FRAMING_LANE_CHARGE
                    + framer
                        .pending
                        .values()
                        .map(|pending| pending.bytes.capacity())
                        .sum::<usize>()
            );
        }
    }

    #[test]
    fn workload_resolution_change_never_joins_one_fake_line() {
        let container_id = ContainerId {
            runtime: "containerd".into(),
            id: "a".repeat(64),
        };
        let identity = |workload| KubernetesIdentity {
            node: "node".into(),
            namespace: "games".into(),
            pod_name: "server-a".into(),
            pod_uid: "pod-a".into(),
            container_name: "server".into(),
            container_id: container_id.clone(),
            workload,
        };
        let unresolved_owner = WorkloadIdentity {
            api_version: "apps/v1".into(),
            kind: "ReplicaSet".into(),
            name: "server-rs".into(),
            uid: "rs-uid".into(),
        };
        let deployment = WorkloadIdentity {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            name: "server".into(),
            uid: "deployment-uid".into(),
        };
        let mut first = write(1, b"before");
        first.enrichment = Enrichment::Enriched(identity(
            WorkloadResolution::UnresolvedReplicaSet(unresolved_owner),
        ));
        let mut second = write(2, b"after\n");
        second.enrichment =
            Enrichment::Enriched(identity(WorkloadResolution::Resolved(deployment)));

        let mut framer = RecordFramer::new(64);
        assert!(framer.accept(first).is_empty());
        let resolved = framer.accept(second);
        assert_eq!(resolved[0].bytes(), b"after\n");
        assert_eq!(resolved[0].severity(), Severity::Unknown);
        let unresolved = framer.flush();
        assert_eq!(unresolved[0].bytes(), b"before");
        assert!(unresolved[0].integrity().unterminated);
    }
}
