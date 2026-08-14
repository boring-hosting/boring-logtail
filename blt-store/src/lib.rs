// SPDX-License-Identifier: GPL-3.0-or-later

//! The bounded in-memory log database.
//!
//! `LogStore` owns the records. Share one `Arc<LogStore>` between ingestion and
//! readers; the bounded transport queue belongs before the database, not inside
//! it. Queries, clearing, and continuous streams operate on that same value.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    sync::{Arc, RwLock},
    time::Duration,
};

use blt_model::{Enrichment, KubernetesIdentity, LogRecord, WorkloadResolution};
use serde::{Deserialize, Deserializer};
use tokio::{sync::broadcast, time::Instant};

const RECORD_CHARGE: usize = 256;
const WORKLOAD_CHARGE: usize = 2_048;
const QUEUE_CHARGE: usize = 64;
const MAX_SELECTOR_BYTES: usize = 1_024;
const MAX_STREAM_BACKLOG: usize = 128;
const MIN_MEMORY: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 64 * 1024;
pub const FRAMING_LANE_CHARGE: usize = 2_048;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(deserialize_with = "deserialize_bytes")]
    pub max_memory: usize,
    pub max_logs: usize,
    #[serde(deserialize_with = "deserialize_duration")]
    pub retention: Duration,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_memory: 128 * 1024 * 1024,
            max_logs: 500,
            retention: Duration::from_secs(60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StoreLimits {
    pub retained_bytes: usize,
    pub assembly_bytes: usize,
    pub assembly_operations: usize,
    pub framing_bytes: usize,
    pub framing_lanes: usize,
    pub max_record_bytes: usize,
    workload_capacity: usize,
    ingress_bytes: usize,
    ingress_records: usize,
    stream_records: usize,
    headroom_bytes: usize,
}

impl StoreConfig {
    pub fn limits(&self) -> Result<StoreLimits, &'static str> {
        if self.max_memory < MIN_MEMORY {
            return Err("store max_memory must be at least 32MiB");
        }
        if self.max_logs == 0 {
            return Err("store max_logs must be non-zero");
        }
        if self.retention.is_zero() {
            return Err("store retention must be non-zero");
        }

        let part = |percent| self.max_memory / 100 * percent;
        let retained_bytes = part(80);
        let assembly_bytes = part(2);
        let framing_bytes = part(3);
        let ingress_bytes = part(5);
        let headroom_bytes =
            self.max_memory - retained_bytes - assembly_bytes - framing_bytes - ingress_bytes;
        let one = DEFAULT_MAX_RECORD_BYTES + RECORD_CHARGE + QUEUE_CHARGE;

        if framing_bytes < DEFAULT_MAX_RECORD_BYTES + FRAMING_LANE_CHARGE
            || ingress_bytes < one
            || [retained_bytes, assembly_bytes, framing_bytes, ingress_bytes]
                .into_iter()
                .any(|value| value > u32::MAX as usize)
        {
            return Err("store max_memory is too small for internal record buffers");
        }

        Ok(StoreLimits {
            retained_bytes,
            assembly_bytes,
            assembly_operations: (assembly_bytes / WORKLOAD_CHARGE).max(1),
            framing_bytes,
            framing_lanes: (framing_bytes / (DEFAULT_MAX_RECORD_BYTES + FRAMING_LANE_CHARGE))
                .max(1),
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            workload_capacity: (retained_bytes / WORKLOAD_CHARGE).max(1),
            ingress_bytes,
            ingress_records: (ingress_bytes / QUEUE_CHARGE).max(1),
            stream_records: (headroom_bytes / one).clamp(1, MAX_STREAM_BACKLOG),
            headroom_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.limits().map(|_| ())
    }

    pub fn derived_limits_summary(&self) -> Result<String, &'static str> {
        let limits = self.limits()?;
        Ok(format!(
            "retained={} assembly={} framing={} ingress={} headroom={} workload_capacity={} assembly_operations={} framing_lanes={} ingress_records={} stream_backlog={}",
            limits.retained_bytes,
            limits.assembly_bytes,
            limits.framing_bytes,
            limits.ingress_bytes,
            limits.headroom_bytes,
            limits.workload_capacity,
            limits.assembly_operations,
            limits.framing_lanes,
            limits.ingress_records,
            limits.stream_records,
        ))
    }
}

fn deserialize_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<usize, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(usize),
        Text(String),
    }

    match Value::deserialize(deserializer)? {
        Value::Number(value) => Ok(value),
        Value::Text(text) => parse_bytes(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid byte size {text:?}"))),
    }
}

fn deserialize_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_duration(&text)
        .ok_or_else(|| serde::de::Error::custom(format!("invalid duration {text:?}")))
}

fn parse_duration(value: &str) -> Option<Duration> {
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    if value == 0 {
        return None;
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        _ => return None,
    };
    value.checked_mul(multiplier).map(Duration::from_secs)
}

fn parse_bytes(value: &str) -> Option<usize> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let number: usize = value[..split].parse().ok()?;
    let multiplier = match &value[split..] {
        "" | "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        _ => return None,
    };
    number.checked_mul(multiplier)
}

pub type StoreSequence = u64;

#[derive(Debug)]
pub struct StoredRecord {
    sequence: StoreSequence,
    record: Arc<LogRecord>,
    accounted_bytes: usize,
    retained_at: Instant,
}

impl StoredRecord {
    pub fn sequence(&self) -> StoreSequence {
        self.sequence
    }

    pub fn record(&self) -> &LogRecord {
        &self.record
    }

    pub fn accounted_bytes(&self) -> usize {
        self.accounted_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Selector {
    PodUid(String),
    WorkloadUid(String),
    Namespace(String),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TryAppendError {
    RecordTooLarge,
}

impl fmt::Display for TryAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "store append rejected: {self:?}")
    }
}

impl std::error::Error for TryAppendError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    SelectorTooLarge,
    Lagged(u64),
    Closed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreStats {
    pub accepted_records: u64,
    pub per_workload_evictions: u64,
    pub global_budget_evictions: u64,
    pub retention_evictions: u64,
    pub workload_limit_rejections: u64,
    pub unresolved_workload_rejections: u64,
    pub retained_record_rejections: u64,
    pub retained_records: usize,
    pub retained_bytes: usize,
    pub workloads: usize,
    pub pods: usize,
}

type PodLogs = VecDeque<StoreSequence>;

#[derive(Default)]
struct WorkloadLogs {
    pods: HashMap<String, PodLogs>,
    records: usize,
}

#[derive(Default)]
struct NamespaceLogs {
    workloads: HashMap<String, WorkloadLogs>,
}

struct StoreData {
    config: StoreConfig,
    limits: StoreLimits,
    next: StoreSequence,
    retained_bytes: usize,
    namespaces: HashMap<String, NamespaceLogs>,
    records: BTreeMap<StoreSequence, Arc<StoredRecord>>,
    stats: StoreStats,
}

pub struct LogStore {
    state: RwLock<StoreData>,
    notifications: broadcast::Sender<Arc<StoredRecord>>,
}

impl LogStore {
    pub fn new(config: StoreConfig) -> Self {
        let limits = config.limits().expect("invalid log-store configuration");
        let (notifications, _) = broadcast::channel(limits.stream_records);
        Self {
            state: RwLock::new(StoreData {
                config,
                limits,
                next: 0,
                retained_bytes: 0,
                namespaces: HashMap::new(),
                records: BTreeMap::new(),
                stats: StoreStats::default(),
            }),
            notifications,
        }
    }

    pub fn try_append<R>(&self, record: R) -> Result<(), TryAppendError>
    where
        R: Into<Arc<LogRecord>>,
    {
        let record = record.into();
        let mut state = self.state.write().expect("log store lock poisoned");
        if record.bytes().len() > state.limits.max_record_bytes {
            return Err(TryAppendError::RecordTooLarge);
        }
        if let Some(stored) = state.append(record, Instant::now()) {
            let _ = self.notifications.send(stored);
        }
        Ok(())
    }

    pub fn query(&self, selector: &Selector) -> Result<Vec<Arc<StoredRecord>>, StreamError> {
        validate_selector(selector)?;
        let mut state = self.state.write().expect("log store lock poisoned");
        state.expire(Instant::now());
        Ok(state.query(selector))
    }

    pub fn stream(&self, selector: Selector) -> Result<LogStream, StreamError> {
        validate_selector(&selector)?;
        let receiver = self.notifications.subscribe();
        let mut state = self.state.write().expect("log store lock poisoned");
        state.expire(Instant::now());
        let through = state.next;
        let retained = state.query(&selector).into();
        Ok(LogStream {
            selector,
            through,
            retained,
            receiver,
        })
    }

    pub fn flush(&self) {
        let mut state = self.state.write().expect("log store lock poisoned");
        state.namespaces.clear();
        state.records.clear();
        state.retained_bytes = 0;
        state.refresh_stats();
    }

    pub fn stats(&self) -> StoreStats {
        let mut state = self.state.write().expect("log store lock poisoned");
        state.expire(Instant::now());
        state.refresh_stats();
        state.stats.clone()
    }
}

pub struct LogStream {
    selector: Selector,
    through: StoreSequence,
    retained: VecDeque<Arc<StoredRecord>>,
    receiver: broadcast::Receiver<Arc<StoredRecord>>,
}

impl LogStream {
    pub fn through(&self) -> StoreSequence {
        self.through
    }

    pub async fn recv(&mut self) -> Result<Arc<StoredRecord>, StreamError> {
        if let Some(record) = self.retained.pop_front() {
            return Ok(record);
        }
        loop {
            match self.receiver.recv().await {
                Ok(record)
                    if record.sequence > self.through
                        && matches(&self.selector, record.record()) =>
                {
                    return Ok(record);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    return Err(StreamError::Lagged(skipped));
                }
                Err(broadcast::error::RecvError::Closed) => return Err(StreamError::Closed),
            }
        }
    }
}

impl StoreData {
    fn append(
        &mut self,
        record: Arc<LogRecord>,
        retained_at: Instant,
    ) -> Option<Arc<StoredRecord>> {
        self.expire(retained_at);
        let Some(identity) = identity(&record) else {
            self.stats.unresolved_workload_rejections += 1;
            return None;
        };
        let workload = match workload_uid(identity) {
            Some(workload) => workload,
            None => {
                self.stats.unresolved_workload_rejections += 1;
                return None;
            }
        };
        let namespace = identity.namespace.clone();
        let pod = identity.pod_uid.clone();
        let new_workload = !self
            .namespaces
            .get(&namespace)
            .is_some_and(|logs| logs.workloads.contains_key(&workload));
        let charge = record_bytes(&record);

        if charge + usize::from(new_workload) * WORKLOAD_CHARGE > self.limits.retained_bytes {
            self.stats.retained_record_rejections += 1;
            return None;
        }
        if new_workload && self.workload_count() >= self.limits.workload_capacity {
            self.stats.workload_limit_rejections += 1;
            return None;
        }

        self.next += 1;
        let stored = Arc::new(StoredRecord {
            sequence: self.next,
            record,
            accounted_bytes: charge,
            retained_at,
        });
        let workload_logs = self
            .namespaces
            .entry(namespace)
            .or_default()
            .workloads
            .entry(workload.clone())
            .or_default();
        workload_logs
            .pods
            .entry(pod)
            .or_default()
            .push_back(self.next);
        workload_logs.records += 1;
        self.records.insert(self.next, stored.clone());
        self.retained_bytes += charge + usize::from(new_workload) * WORKLOAD_CHARGE;

        while self.workload_records(&workload) > self.config.max_logs {
            self.evict_oldest_workload(&workload, EvictionReason::PerWorkload);
        }
        while self.retained_bytes > self.limits.retained_bytes {
            let Some(sequence) = self
                .records
                .first_key_value()
                .map(|(sequence, _)| *sequence)
            else {
                break;
            };
            self.evict(sequence, EvictionReason::GlobalBudget);
        }
        self.stats.accepted_records += 1;
        self.refresh_stats();
        Some(stored)
    }

    fn query(&self, selector: &Selector) -> Vec<Arc<StoredRecord>> {
        self.records
            .values()
            .filter(|record| matches(selector, record.record()))
            .cloned()
            .collect()
    }

    fn workload_records(&self, workload: &str) -> usize {
        self.namespaces
            .values()
            .filter_map(|namespace| namespace.workloads.get(workload))
            .map(|logs| logs.records)
            .sum()
    }

    fn workload_count(&self) -> usize {
        self.namespaces
            .values()
            .map(|namespace| namespace.workloads.len())
            .sum()
    }

    fn evict_oldest_workload(&mut self, workload: &str, reason: EvictionReason) {
        let oldest = self
            .namespaces
            .values()
            .filter_map(|namespace| namespace.workloads.get(workload))
            .flat_map(|logs| logs.pods.values())
            .filter_map(VecDeque::front)
            .min()
            .copied();
        if let Some(sequence) = oldest {
            self.evict(sequence, reason);
        }
    }

    fn evict(&mut self, sequence: StoreSequence, reason: EvictionReason) {
        let Some(record) = self.records.remove(&sequence) else {
            return;
        };
        let Some(identity) = identity(record.record()) else {
            return;
        };
        let Some(workload) = workload_uid(identity) else {
            return;
        };
        let namespace_name = identity.namespace.clone();
        let pod_name = identity.pod_uid.clone();
        let mut remove_namespace = false;

        if let Some(namespace) = self.namespaces.get_mut(&namespace_name) {
            let mut remove_workload = false;
            if let Some(logs) = namespace.workloads.get_mut(&workload) {
                let mut remove_pod = false;
                if let Some(pod) = logs.pods.get_mut(&pod_name) {
                    if pod.front() == Some(&sequence) {
                        pod.pop_front();
                    } else if let Some(position) = pod.iter().position(|item| *item == sequence) {
                        pod.remove(position);
                    }
                    remove_pod = pod.is_empty();
                }
                if remove_pod {
                    logs.pods.remove(&pod_name);
                }
                logs.records -= 1;
                remove_workload = logs.records == 0;
            }
            if remove_workload {
                namespace.workloads.remove(&workload);
                self.retained_bytes -= WORKLOAD_CHARGE;
            }
            remove_namespace = namespace.workloads.is_empty();
        }
        if remove_namespace {
            self.namespaces.remove(&namespace_name);
        }

        self.retained_bytes -= record.accounted_bytes;
        match reason {
            EvictionReason::PerWorkload => self.stats.per_workload_evictions += 1,
            EvictionReason::GlobalBudget => self.stats.global_budget_evictions += 1,
            EvictionReason::Retention => self.stats.retention_evictions += 1,
        }
        self.refresh_stats();
    }

    fn expire(&mut self, now: Instant) {
        loop {
            let expired = self
                .records
                .first_key_value()
                .and_then(|(sequence, record)| {
                    (now.saturating_duration_since(record.retained_at) >= self.config.retention)
                        .then_some(*sequence)
                });
            let Some(sequence) = expired else {
                break;
            };
            self.evict(sequence, EvictionReason::Retention);
        }
    }

    fn refresh_stats(&mut self) {
        self.stats.retained_records = self.records.len();
        self.stats.retained_bytes = self.retained_bytes;
        self.stats.workloads = self.workload_count();
        self.stats.pods = self
            .namespaces
            .values()
            .flat_map(|namespace| namespace.workloads.values())
            .map(|workload| workload.pods.len())
            .sum();
    }
}

#[derive(Clone, Copy)]
enum EvictionReason {
    PerWorkload,
    GlobalBudget,
    Retention,
}

fn validate_selector(selector: &Selector) -> Result<(), StreamError> {
    let length = match selector {
        Selector::PodUid(value) | Selector::WorkloadUid(value) | Selector::Namespace(value) => {
            value.len()
        }
    };
    if length > MAX_SELECTOR_BYTES {
        Err(StreamError::SelectorTooLarge)
    } else {
        Ok(())
    }
}

fn identity(record: &LogRecord) -> Option<&KubernetesIdentity> {
    match record.enrichment() {
        Enrichment::Enriched(identity) | Enrichment::Stale(identity) => Some(identity),
        _ => None,
    }
}

fn workload_uid(identity: &KubernetesIdentity) -> Option<String> {
    match &identity.workload {
        WorkloadResolution::Resolved(workload) => Some(workload.uid.clone()),
        WorkloadResolution::NoController => Some(identity.pod_uid.clone()),
        WorkloadResolution::UnresolvedReplicaSet(_) | WorkloadResolution::UnsupportedOwner(_) => {
            None
        }
    }
}

fn matches(selector: &Selector, record: &LogRecord) -> bool {
    identity(record).is_some_and(|identity| match selector {
        Selector::PodUid(uid) => &identity.pod_uid == uid,
        Selector::WorkloadUid(uid) => workload_uid(identity).as_ref() == Some(uid),
        Selector::Namespace(namespace) => &identity.namespace == namespace,
    })
}

fn record_bytes(record: &LogRecord) -> usize {
    record
        .bytes()
        .len()
        .saturating_add(RECORD_CHARGE)
        .saturating_add(match identity(record) {
            Some(identity) => {
                let workload = match &identity.workload {
                    WorkloadResolution::Resolved(workload)
                    | WorkloadResolution::UnresolvedReplicaSet(workload)
                    | WorkloadResolution::UnsupportedOwner(workload) => {
                        workload.api_version.len()
                            + workload.kind.len()
                            + workload.name.len()
                            + workload.uid.len()
                    }
                    WorkloadResolution::NoController => 0,
                };
                identity.node.len()
                    + identity.namespace.len()
                    + identity.pod_uid.len()
                    + identity.pod_name.len()
                    + identity.container_name.len()
                    + identity.container_id.runtime.len()
                    + identity.container_id.id.len()
                    + workload
            }
            None => 0,
        })
}

#[cfg(test)]
mod tests {
    use blt_model::{
        ContainerId, RecordIntegrity, Severity, StreamFileDescriptor, WorkloadIdentity,
    };

    use super::*;

    fn config() -> StoreConfig {
        StoreConfig {
            max_memory: 32 * 1024 * 1024,
            max_logs: 2,
            retention: Duration::from_secs(60 * 60),
        }
    }

    fn record(namespace: &str, workload_uid: &str, pod_uid: &str, size: usize) -> LogRecord {
        LogRecord {
            observed_at: "2026-08-12T18:00:00Z".parse().unwrap(),
            sampling_seed: 1,
            stream: StreamFileDescriptor::Stdout,
            enrichment: Enrichment::Enriched(KubernetesIdentity {
                node: "node-1".into(),
                namespace: namespace.into(),
                pod_name: format!("pod-{pod_uid}"),
                pod_uid: pod_uid.into(),
                container_name: "server".into(),
                container_id: ContainerId {
                    runtime: "containerd".into(),
                    id: "a".repeat(64),
                },
                workload: WorkloadResolution::Resolved(WorkloadIdentity {
                    api_version: "apps/v1".into(),
                    kind: "Deployment".into(),
                    name: "game".into(),
                    uid: workload_uid.into(),
                }),
            }),
            first_timestamp_ns: 0,
            last_timestamp_ns: 0,
            first_operation_id: 0,
            last_operation_id: 0,
            bytes: Arc::from(vec![b'x'; size]),
            integrity: RecordIntegrity::default(),
            sample_percent: 100,
            severity: Severity::Unknown,
        }
    }

    fn sequences(records: &[Arc<StoredRecord>]) -> Vec<u64> {
        records.iter().map(|record| record.sequence()).collect()
    }

    #[test]
    fn parses_config_and_derives_one_bounded_envelope() {
        let config: StoreConfig =
            serde_yaml::from_str("max_memory: 128MiB\nmax_logs: 500\nretention: 15m").unwrap();
        let limits = config.limits().unwrap();
        assert_eq!(config.retention, Duration::from_secs(15 * 60));
        assert!(
            limits.retained_bytes
                + limits.assembly_bytes
                + limits.framing_bytes
                + limits.ingress_bytes
                + limits.headroom_bytes
                <= config.max_memory
        );
        assert!(limits.ingress_records >= 512);
    }

    #[test]
    fn hierarchy_keeps_workload_limit_across_pods_and_namespaces_separate() {
        let store = LogStore::new(config());
        store
            .try_append(record("games", "workload-1", "pod-a", 8))
            .unwrap();
        store
            .try_append(record("games", "workload-1", "pod-b", 8))
            .unwrap();
        store
            .try_append(record("games", "workload-1", "pod-a", 8))
            .unwrap();
        store
            .try_append(record("tools", "workload-2", "pod-c", 8))
            .unwrap();

        assert_eq!(
            sequences(
                &store
                    .query(&Selector::WorkloadUid("workload-1".into()))
                    .unwrap()
            ),
            vec![2, 3]
        );
        assert_eq!(
            sequences(&store.query(&Selector::PodUid("pod-b".into())).unwrap()),
            vec![2]
        );
        assert_eq!(
            sequences(&store.query(&Selector::Namespace("tools".into())).unwrap()),
            vec![4]
        );
        assert_eq!(store.stats().per_workload_evictions, 1);
    }

    #[test]
    fn flush_clears_retention_without_replacing_the_database() {
        let store = Arc::new(LogStore::new(config()));
        let reader = Arc::clone(&store);
        store
            .try_append(record("games", "workload-1", "pod-a", 8))
            .unwrap();
        store.flush();
        assert!(
            reader
                .query(&Selector::Namespace("games".into()))
                .unwrap()
                .is_empty()
        );
        assert_eq!(reader.stats().retained_records, 0);
    }

    #[tokio::test]
    async fn stream_is_retained_history_then_new_matching_records() {
        let store = Arc::new(LogStore::new(config()));
        store
            .try_append(record("games", "workload-1", "pod-a", 8))
            .unwrap();
        let mut stream = store
            .stream(Selector::WorkloadUid("workload-1".into()))
            .unwrap();
        store
            .try_append(record("other", "workload-2", "pod-b", 8))
            .unwrap();
        store
            .try_append(record("games", "workload-1", "pod-c", 8))
            .unwrap();

        assert_eq!(stream.through(), 1);
        assert_eq!(stream.recv().await.unwrap().sequence(), 1);
        assert_eq!(stream.recv().await.unwrap().sequence(), 3);
    }

    #[test]
    fn expiry_and_global_eviction_keep_indexes_coherent() {
        let mut config = config();
        config.retention = Duration::from_secs(10);
        let mut state = StoreData {
            limits: config.limits().unwrap(),
            config,
            next: 0,
            retained_bytes: 0,
            namespaces: HashMap::new(),
            records: BTreeMap::new(),
            stats: StoreStats::default(),
        };
        let now = Instant::now();
        state.append(
            record("games", "workload-1", "pod-old", 8).into(),
            now - Duration::from_secs(11),
        );
        state.append(
            record("games", "workload-1", "pod-young", 8).into(),
            now - Duration::from_secs(9),
        );
        state.expire(now);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.stats.retention_evictions, 1);
        assert_eq!(state.stats.pods, 1);
    }

    #[test]
    fn retained_memory_never_exceeds_derived_budget() {
        let mut config = config();
        config.max_logs = 1_000;
        let limit = config.limits().unwrap().retained_bytes;
        let store = LogStore::new(config);
        for operation in 0..512 {
            store
                .try_append(record(
                    "games",
                    &format!("workload-{}", operation % 2),
                    &format!("pod-{}", operation % 4),
                    64 * 1024,
                ))
                .unwrap();
        }
        let stats = store.stats();
        assert!(stats.retained_bytes <= limit);
        assert!(stats.global_budget_evictions > 0);
    }
}
