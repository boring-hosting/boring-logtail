// SPDX-License-Identifier: GPL-3.0-or-later

//! Workload-owned bounded retention and gap-free replay/live handoff.

use crate::enrichment::{Enrichment, KubernetesIdentity, WorkloadResolution};
use crate::record::{FRAMING_LANE_CHARGE, LogRecord};
use serde::{Deserialize, Deserializer};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    sync::Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

const RECORD_CHARGE: usize = 256;
const WORKLOAD_CHARGE: usize = 2_048;
const QUEUE_CHARGE: usize = 64;
const MAX_SELECTOR_BYTES: usize = 1_024;
const MAX_SUBSCRIBERS: usize = 8;
const MAX_LIVE_RECORDS_PER_SUBSCRIBER: usize = 128;
const MIN_MEMORY: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(deserialize_with = "deserialize_bytes")]
    pub max_memory: usize,
    pub max_workloads: usize,
    pub max_logs: usize,
    #[serde(deserialize_with = "deserialize_bytes")]
    pub max_record_bytes: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_memory: 128 * 1024 * 1024,
            max_workloads: 128,
            max_logs: 500,
            max_record_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StoreLimits {
    pub(crate) retained_bytes: usize,
    pub(crate) assembly_bytes: usize,
    pub(crate) assembly_operations: usize,
    pub(crate) framing_bytes: usize,
    pub(crate) framing_lanes: usize,
    ingress_bytes: usize,
    ingress_records: usize,
    replay_bytes: usize,
    subscriber_bytes: usize,
    subscriber_records: usize,
    headroom_bytes: usize,
}

impl StoreConfig {
    pub(crate) fn limits(&self) -> Result<StoreLimits, &'static str> {
        if self.max_memory < MIN_MEMORY {
            return Err("store max_memory must be at least 32MiB");
        }
        if self.max_workloads == 0 || self.max_logs == 0 || self.max_record_bytes == 0 {
            return Err("store counts and max_record_bytes must be non-zero");
        }
        let part = |percent| self.max_memory / 100 * percent;
        let limits = StoreLimits {
            retained_bytes: part(40),
            assembly_bytes: part(2),
            framing_bytes: part(3),
            ingress_bytes: part(5),
            replay_bytes: part(40),
            subscriber_bytes: part(5) / MAX_SUBSCRIBERS,
            headroom_bytes: self.max_memory - part(95),
            framing_lanes: self.max_workloads.saturating_mul(8).clamp(1, 4_096),
            assembly_operations: self.max_workloads.saturating_mul(8).clamp(1, 4_096),
            ingress_records: self.max_workloads.saturating_mul(4).clamp(16, 8_192),
            subscriber_records: 0,
        };
        let one = self.max_record_bytes + RECORD_CHARGE + QUEUE_CHARGE;
        let limits = StoreLimits {
            subscriber_records: (limits.subscriber_bytes / one)
                .clamp(1, MAX_LIVE_RECORDS_PER_SUBSCRIBER),
            ..limits
        };
        let total = limits.retained_bytes
            + limits.assembly_bytes
            + limits.framing_bytes
            + limits.ingress_bytes
            + limits.replay_bytes
            + limits.subscriber_bytes * MAX_SUBSCRIBERS
            + limits.headroom_bytes;
        if limits.framing_lanes == 0
            || total > self.max_memory
            || limits.framing_bytes < self.max_record_bytes + FRAMING_LANE_CHARGE
            || limits.ingress_bytes < one
            || limits.replay_bytes < one
            || limits.subscriber_bytes < one
            || [
                limits.assembly_bytes,
                limits.framing_bytes,
                limits.ingress_bytes,
                limits.replay_bytes,
                limits.subscriber_bytes,
                limits.retained_bytes,
            ]
            .into_iter()
            .any(|n| n > u32::MAX as usize)
        {
            return Err("store max_memory is too small for max_record_bytes and internal buffers");
        }
        Ok(limits)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.limits().map(|_| ())
    }

    pub fn derived_limits_summary(&self) -> Result<String, &'static str> {
        let limits = self.limits()?;
        Ok(format!(
            "retained={} assembly={} framing={} ingress={} replay={} live_total={} headroom={} assembly_operations={} framing_lanes={} ingress_records={} subscribers={} live_records_per_subscriber={}",
            limits.retained_bytes,
            limits.assembly_bytes,
            limits.framing_bytes,
            limits.ingress_bytes,
            limits.replay_bytes,
            limits.subscriber_bytes * MAX_SUBSCRIBERS,
            limits.headroom_bytes,
            limits.assembly_operations,
            limits.framing_lanes,
            limits.ingress_records,
            MAX_SUBSCRIBERS,
            limits.subscriber_records,
        ))
    }
}

fn deserialize_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(usize),
        Text(String),
    }
    match Value::deserialize(d)? {
        Value::Number(n) => Ok(n),
        Value::Text(text) => parse_bytes(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid byte size {text:?}"))),
    }
}
fn parse_bytes(value: &str) -> Option<usize> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
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
}
impl StoredRecord {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriberTerminal {
    Active,
    SubscriberLagged,
    StoreClosed,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TryAppendError {
    IngressFull,
    IngressByteLimit,
    StoreClosed,
    RecordTooLarge,
}
impl fmt::Display for TryAppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store append rejected: {self:?}")
    }
}
impl std::error::Error for TryAppendError {}
#[derive(Debug, Eq, PartialEq)]
pub enum SubscribeError {
    SubscriberLimit,
    ReplayByteLimit,
    SelectorTooLarge,
    StoreClosed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreStats {
    pub accepted_records: u64,
    pub per_workload_evictions: u64,
    pub global_budget_evictions: u64,
    pub workload_limit_rejections: u64,
    pub unresolved_workload_rejections: u64,
    pub retained_record_rejections: u64,
    pub replay_admission_rejections: u64,
    pub subscriber_limit_rejections: u64,
    pub subscriber_lagged: u64,
    pub retained_records: usize,
    pub retained_bytes: usize,
    pub workloads: usize,
    pub pods: usize,
    pub subscribers: usize,
    pub pinned_replay_bytes: usize,
}

pub struct ReplayRecord {
    stored: Arc<StoredRecord>,
    _reservation: Arc<ReplayReservation>,
}
impl ReplayRecord {
    pub fn sequence(&self) -> u64 {
        self.stored.sequence
    }
    pub fn record(&self) -> &LogRecord {
        &self.stored.record
    }
}
struct ReplayReservation {
    _permit: OwnedSemaphorePermit,
}
pub struct ReplaySession {
    pub through: u64,
    pub replay: Vec<ReplayRecord>,
    pub live: LiveReceiver,
}
pub struct LiveReceiver {
    receiver: mpsc::Receiver<LiveRecord>,
    terminal: watch::Receiver<SubscriberTerminal>,
    _slot: OwnedSemaphorePermit,
}
impl LiveReceiver {
    pub async fn recv(&mut self) -> Option<LiveRecord> {
        self.receiver.recv().await
    }
    pub fn terminal(&self) -> SubscriberTerminal {
        *self.terminal.borrow()
    }
    pub async fn terminal_changed(&mut self) -> SubscriberTerminal {
        let _ = self.terminal.changed().await;
        *self.terminal.borrow()
    }
}
pub struct LiveRecord {
    stored: Arc<StoredRecord>,
    _permit: OwnedSemaphorePermit,
}
impl LiveRecord {
    pub fn sequence(&self) -> u64 {
        self.stored.sequence
    }
    pub fn record(&self) -> &LogRecord {
        &self.stored.record
    }
}

#[derive(Clone)]
pub struct LogStore {
    commands: mpsc::Sender<Command>,
    ingress: Arc<Semaphore>,
    ingress_bytes: usize,
    max_record_bytes: usize,
    stats: watch::Receiver<StoreStats>,
}
impl LogStore {
    pub fn spawn(config: StoreConfig) -> Self {
        let limits = config.limits().expect("invalid log-store configuration");
        let (commands, receiver) = mpsc::channel(limits.ingress_records);
        let ingress = Arc::new(Semaphore::new(limits.ingress_bytes));
        let (stats_sender, stats) = watch::channel(StoreStats::default());
        let store = Self {
            commands,
            ingress: ingress.clone(),
            ingress_bytes: limits.ingress_bytes,
            max_record_bytes: config.max_record_bytes,
            stats,
        };
        tokio::spawn(run(State::new(config, limits, stats_sender), receiver));
        store
    }
    pub fn try_append(&self, record: LogRecord) -> Result<(), TryAppendError> {
        if record.bytes().len() > self.max_record_bytes {
            return Err(TryAppendError::RecordTooLarge);
        }
        let charge = record_bytes(&record) + QUEUE_CHARGE;
        if charge > self.ingress_bytes {
            return Err(TryAppendError::RecordTooLarge);
        }
        let permit = self
            .ingress
            .clone()
            .try_acquire_many_owned(charge as u32)
            .map_err(|_| TryAppendError::IngressByteLimit)?;
        self.commands
            .try_send(Command::Append(Box::new(record), permit))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Closed(_) => TryAppendError::StoreClosed,
                mpsc::error::TrySendError::Full(_) => TryAppendError::IngressFull,
            })
    }
    pub async fn subscribe(&self, selector: Selector) -> Result<ReplaySession, SubscribeError> {
        if selector_len(&selector) > MAX_SELECTOR_BYTES {
            return Err(SubscribeError::SelectorTooLarge);
        }
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Subscribe(selector, tx))
            .await
            .map_err(|_| SubscribeError::StoreClosed)?;
        rx.await.unwrap_or(Err(SubscribeError::StoreClosed))
    }
    pub fn stats(&self) -> StoreStats {
        self.stats.borrow().clone()
    }
    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        if self.commands.send(Command::Shutdown(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

enum Command {
    Append(Box<LogRecord>, OwnedSemaphorePermit),
    Subscribe(
        Selector,
        oneshot::Sender<Result<ReplaySession, SubscribeError>>,
    ),
    Shutdown(oneshot::Sender<()>),
}
struct WorkloadRing {
    records: VecDeque<Arc<StoredRecord>>,
}
struct Subscriber {
    selector: Selector,
    sender: mpsc::Sender<LiveRecord>,
    bytes: Arc<Semaphore>,
    terminal: watch::Sender<SubscriberTerminal>,
}
struct State {
    config: StoreConfig,
    limits: StoreLimits,
    next: u64,
    retained_bytes: usize,
    workloads: HashMap<String, WorkloadRing>,
    global: BTreeMap<u64, (String, Arc<StoredRecord>)>,
    pod_counts: HashMap<String, usize>,
    subscribers: Vec<Subscriber>,
    replay: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    stats: StoreStats,
    stats_sender: watch::Sender<StoreStats>,
}
impl State {
    fn new(
        config: StoreConfig,
        limits: StoreLimits,
        stats_sender: watch::Sender<StoreStats>,
    ) -> Self {
        Self {
            config,
            limits,
            next: 0,
            retained_bytes: 0,
            workloads: HashMap::new(),
            global: BTreeMap::new(),
            pod_counts: HashMap::new(),
            subscribers: vec![],
            replay: Arc::new(Semaphore::new(limits.replay_bytes)),
            slots: Arc::new(Semaphore::new(MAX_SUBSCRIBERS)),
            stats: StoreStats::default(),
            stats_sender,
        }
    }
    fn append(&mut self, record: LogRecord) {
        let Some((workload, pod)) =
            identity(&record).and_then(|id| workload_uid(id).map(|w| (w, id.pod_uid.clone())))
        else {
            self.stats.unresolved_workload_rejections += 1;
            return;
        };
        let new = !self.workloads.contains_key(&workload);
        let charge = record_bytes(&record);
        if charge + usize::from(new) * WORKLOAD_CHARGE > self.limits.retained_bytes {
            self.stats.retained_record_rejections += 1;
            return;
        }
        if new && self.workloads.len() >= self.config.max_workloads {
            self.stats.workload_limit_rejections += 1;
            return;
        }
        self.next += 1;
        let stored = Arc::new(StoredRecord {
            sequence: self.next,
            record: Arc::new(record),
            accounted_bytes: charge,
        });
        if new {
            self.workloads.insert(
                workload.clone(),
                WorkloadRing {
                    records: VecDeque::new(),
                },
            );
            self.retained_bytes += WORKLOAD_CHARGE;
        }
        self.retained_bytes += charge;
        *self.pod_counts.entry(pod).or_default() += 1;
        self.workloads
            .get_mut(&workload)
            .unwrap()
            .records
            .push_back(stored.clone());
        self.global
            .insert(self.next, (workload.clone(), stored.clone()));
        while self.workloads[&workload].records.len() > self.config.max_logs {
            self.evict(&workload, true);
        }
        while self.retained_bytes > self.limits.retained_bytes {
            let Some(workload) = self.global.first_key_value().map(|(_, (w, _))| w.clone()) else {
                break;
            };
            self.evict(&workload, false);
        }
        self.stats.accepted_records += 1;
        self.publish(stored);
    }
    fn evict(&mut self, workload: &str, per_workload: bool) {
        let removed = self
            .workloads
            .get_mut(workload)
            .and_then(|r| r.records.pop_front());
        if let Some(record) = removed {
            self.global.remove(&record.sequence);
            self.retained_bytes -= record.accounted_bytes;
            if let Some(id) = identity(&record.record)
                && let Some(count) = self.pod_counts.get_mut(&id.pod_uid)
            {
                *count -= 1;
                if *count == 0 {
                    self.pod_counts.remove(&id.pod_uid);
                }
            }
            if per_workload {
                self.stats.per_workload_evictions += 1
            } else {
                self.stats.global_budget_evictions += 1
            }
        }
        if self
            .workloads
            .get(workload)
            .is_some_and(|r| r.records.is_empty())
        {
            self.workloads.remove(workload);
            self.retained_bytes -= WORKLOAD_CHARGE;
        }
    }
    fn subscribe(&mut self, selector: Selector) -> Result<ReplaySession, SubscribeError> {
        self.subscribers.retain(|s| !s.sender.is_closed());
        let slot = self.slots.clone().try_acquire_owned().map_err(|_| {
            self.stats.subscriber_limit_rejections += 1;
            SubscribeError::SubscriberLimit
        })?;
        let records: Vec<_> = self
            .global
            .values()
            .filter(|(_, r)| matches(&selector, &r.record))
            .map(|(_, r)| r.clone())
            .collect();
        let bytes = records.iter().map(|r| r.accounted_bytes).sum::<usize>();
        let permit = self
            .replay
            .clone()
            .try_acquire_many_owned(bytes as u32)
            .map_err(|_| {
                self.stats.replay_admission_rejections += 1;
                SubscribeError::ReplayByteLimit
            })?;
        let reservation = Arc::new(ReplayReservation { _permit: permit });
        let replay = records
            .into_iter()
            .map(|stored| ReplayRecord {
                stored,
                _reservation: reservation.clone(),
            })
            .collect();
        let (sender, receiver) = mpsc::channel(self.limits.subscriber_records);
        let (terminal, terminal_rx) = watch::channel(SubscriberTerminal::Active);
        self.subscribers.push(Subscriber {
            selector,
            sender,
            bytes: Arc::new(Semaphore::new(self.limits.subscriber_bytes)),
            terminal,
        });
        Ok(ReplaySession {
            through: self.next,
            replay,
            live: LiveReceiver {
                receiver,
                terminal: terminal_rx,
                _slot: slot,
            },
        })
    }
    fn publish(&mut self, record: Arc<StoredRecord>) {
        self.subscribers.retain_mut(|s| {
            if !matches(&s.selector, &record.record) {
                return true;
            }
            let charge = record.accounted_bytes + QUEUE_CHARGE;
            let Ok(permit) = s.bytes.clone().try_acquire_many_owned(charge as u32) else {
                self.stats.subscriber_lagged += 1;
                let _ = s.terminal.send(SubscriberTerminal::SubscriberLagged);
                return false;
            };
            match s.sender.try_send(LiveRecord {
                stored: record.clone(),
                _permit: permit,
            }) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats.subscriber_lagged += 1;
                    let _ = s.terminal.send(SubscriberTerminal::SubscriberLagged);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
    }
    fn publish_stats(&mut self) {
        self.stats.retained_records = self.global.len();
        self.stats.retained_bytes = self.retained_bytes;
        self.stats.workloads = self.workloads.len();
        self.stats.pods = self.pod_counts.len();
        self.stats.subscribers = MAX_SUBSCRIBERS - self.slots.available_permits();
        self.stats.pinned_replay_bytes = self.limits.replay_bytes - self.replay.available_permits();
        self.stats_sender.send_replace(self.stats.clone());
    }
}

async fn run(mut state: State, mut rx: mpsc::Receiver<Command>) {
    let mut replies = vec![];
    while let Some(command) = rx.recv().await {
        match command {
            Command::Append(record, _permit) => state.append(*record),
            Command::Subscribe(s, tx) => {
                let _ = tx.send(state.subscribe(s));
            }
            Command::Shutdown(tx) => {
                replies.push(tx);
                rx.close();
                break;
            }
        }
        state.publish_stats();
    }
    while let Some(command) = rx.recv().await {
        match command {
            Command::Append(record, _) => state.append(*record),
            Command::Subscribe(_, tx) => {
                let _ = tx.send(Err(SubscribeError::StoreClosed));
            }
            Command::Shutdown(tx) => replies.push(tx),
        }
    }
    for s in state.subscribers.drain(..) {
        let _ = s.terminal.send(SubscriberTerminal::StoreClosed);
    }
    state.publish_stats();
    for tx in replies {
        let _ = tx.send(());
    }
}

fn identity(record: &LogRecord) -> Option<&KubernetesIdentity> {
    match &record.enrichment {
        Enrichment::Enriched(id) | Enrichment::Stale(id) => Some(id),
        _ => None,
    }
}
fn workload_uid(id: &KubernetesIdentity) -> Option<String> {
    match &id.workload {
        WorkloadResolution::Resolved(w) => Some(w.uid.clone()),
        WorkloadResolution::NoController => Some(id.pod_uid.clone()),
        WorkloadResolution::UnresolvedReplicaSet(_) | WorkloadResolution::UnsupportedOwner(_) => {
            None
        }
    }
}
fn matches(selector: &Selector, record: &LogRecord) -> bool {
    identity(record).is_some_and(|id| match selector {
        Selector::PodUid(uid) => &id.pod_uid == uid,
        Selector::WorkloadUid(uid) => workload_uid(id).as_ref() == Some(uid),
        Selector::Namespace(ns) => &id.namespace == ns,
    })
}
fn selector_len(s: &Selector) -> usize {
    match s {
        Selector::PodUid(v) | Selector::WorkloadUid(v) | Selector::Namespace(v) => v.len(),
    }
}
fn record_bytes(record: &LogRecord) -> usize {
    record
        .bytes()
        .len()
        .saturating_add(RECORD_CHARGE)
        .saturating_add(match identity(record) {
            Some(id) => {
                let workload = match &id.workload {
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
                id.node.len()
                    + id.namespace.len()
                    + id.pod_uid.len()
                    + id.pod_name.len()
                    + id.container_name.len()
                    + id.container_id.runtime.len()
                    + id.container_id.id.len()
                    + workload
            }
            None => 0,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enrichment::{ContainerId, WorkloadIdentity},
        pipeline::StreamFileDescriptor,
        record::{RecordIntegrity, Severity},
    };
    use std::{sync::Arc, time::Instant};

    fn config() -> StoreConfig {
        StoreConfig {
            max_memory: 32 * 1024 * 1024,
            max_workloads: 4,
            max_logs: 2,
            max_record_bytes: 64 * 1024,
        }
    }

    fn record(workload_uid: &str, pod_uid: &str, size: usize) -> LogRecord {
        let container_id = ContainerId {
            runtime: "containerd".into(),
            id: "a".repeat(64),
        };
        LogRecord {
            sampling_seed: 1,
            stream: StreamFileDescriptor::Stdout,
            enrichment: Enrichment::Enriched(KubernetesIdentity {
                node: "node-1".into(),
                namespace: "games".into(),
                pod_name: format!("pod-{pod_uid}"),
                pod_uid: pod_uid.into(),
                container_name: "server".into(),
                container_id,
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

    fn sequences(session: &ReplaySession) -> Vec<u64> {
        session.replay.iter().map(ReplayRecord::sequence).collect()
    }

    #[test]
    fn sizes_and_defaults() {
        let c: StoreConfig = serde_yaml::from_str(
            "max_memory: 128MiB\nmax_workloads: 128\nmax_logs: 500\nmax_record_bytes: 64KiB",
        )
        .unwrap();
        assert_eq!(c.max_memory, 128 << 20);
        assert_eq!(c.max_logs, 500);
        for removed in [
            "retained_bytes: 4",
            "records_per_source: 4",
            "framer_pending_bytes: 4",
            "max_subscribers: 4",
        ] {
            assert!(serde_yaml::from_str::<StoreConfig>(removed).is_err());
        }
    }
    #[test]
    fn derivation_fits_envelope() {
        let c = StoreConfig::default();
        let l = c.limits().unwrap();
        assert!(
            l.retained_bytes
                + l.framing_bytes
                + l.assembly_bytes
                + l.ingress_bytes
                + l.replay_bytes
                + l.subscriber_bytes * MAX_SUBSCRIBERS
                + l.headroom_bytes
                <= c.max_memory
        );
        assert!(
            StoreConfig {
                max_memory: 1024,
                ..c
            }
            .limits()
            .is_err()
        );
    }

    #[tokio::test]
    async fn workload_limit_is_shared_across_historical_pods() {
        let store = LogStore::spawn(config());
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        store.try_append(record("workload-1", "pod-b", 8)).unwrap();
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();

        let workload = store
            .subscribe(Selector::WorkloadUid("workload-1".into()))
            .await
            .unwrap();
        assert_eq!(sequences(&workload), vec![2, 3]);
        assert_eq!(store.stats().per_workload_evictions, 1);
        drop(workload);

        let old_replica = store
            .subscribe(Selector::PodUid("pod-b".into()))
            .await
            .unwrap();
        assert_eq!(sequences(&old_replica), vec![2]);
        let current_replica = store
            .subscribe(Selector::PodUid("pod-a".into()))
            .await
            .unwrap();
        assert_eq!(sequences(&current_replica), vec![3]);
    }

    #[tokio::test]
    async fn standalone_pod_is_its_own_workload() {
        let store = LogStore::spawn(config());
        let mut standalone = record("ignored", "solo-pod", 8);
        let Enrichment::Enriched(identity) = &mut standalone.enrichment else {
            unreachable!()
        };
        identity.workload = WorkloadResolution::NoController;
        store.try_append(standalone).unwrap();

        let replay = store
            .subscribe(Selector::WorkloadUid("solo-pod".into()))
            .await
            .unwrap();
        assert_eq!(sequences(&replay), vec![1]);
    }

    #[tokio::test]
    async fn unresolved_workload_is_rejected_without_guessing() {
        let store = LogStore::spawn(config());
        let mut unresolved = record("ignored", "pod-a", 8);
        let Enrichment::Enriched(identity) = &mut unresolved.enrichment else {
            unreachable!()
        };
        identity.workload = WorkloadResolution::UnresolvedReplicaSet(WorkloadIdentity {
            api_version: "apps/v1".into(),
            kind: "ReplicaSet".into(),
            name: "missing".into(),
            uid: "rs-uid".into(),
        });
        store.try_append(unresolved).unwrap();

        let replay = store
            .subscribe(Selector::Namespace("games".into()))
            .await
            .unwrap();
        assert!(replay.replay.is_empty());
        assert_eq!(store.stats().unresolved_workload_rejections, 1);
    }

    #[tokio::test]
    async fn workload_admission_limit_fails_closed() {
        let store = LogStore::spawn(StoreConfig {
            max_workloads: 1,
            ..config()
        });
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        store.try_append(record("workload-2", "pod-b", 8)).unwrap();

        let replay = store
            .subscribe(Selector::Namespace("games".into()))
            .await
            .unwrap();
        assert_eq!(sequences(&replay), vec![1]);
        assert_eq!(store.stats().workload_limit_rejections, 1);
    }

    #[tokio::test]
    async fn subscriber_consumption_never_drains_retention() {
        let store = LogStore::spawn(config());
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        let mut session = store
            .subscribe(Selector::WorkloadUid("workload-1".into()))
            .await
            .unwrap();
        assert_eq!(sequences(&session), vec![1]);

        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        assert_eq!(session.live.recv().await.unwrap().sequence(), 2);
        assert_eq!(store.stats().retained_records, 2);
        assert_eq!(sequences(&session), vec![1]);
    }

    #[tokio::test]
    async fn replay_live_watermark_has_no_gap_or_duplicate() {
        let store = LogStore::spawn(config());
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        let mut session = store
            .subscribe(Selector::WorkloadUid("workload-1".into()))
            .await
            .unwrap();
        store.try_append(record("workload-1", "pod-b", 8)).unwrap();

        assert_eq!(session.through, 1);
        assert_eq!(sequences(&session), vec![1]);
        assert_eq!(session.live.recv().await.unwrap().sequence(), 2);
    }

    #[tokio::test]
    async fn retained_memory_never_exceeds_derived_budget() {
        let mut cfg = config();
        cfg.max_logs = 1_000;
        let retained_limit = cfg.limits().unwrap().retained_bytes;
        let store = LogStore::spawn(cfg);
        for _ in 0..256 {
            store
                .try_append(record("workload-1", "pod-a", 64 * 1024))
                .unwrap();
            tokio::task::yield_now().await;
        }
        let replay = store
            .subscribe(Selector::WorkloadUid("workload-1".into()))
            .await
            .unwrap();
        let stats = store.stats();
        assert!(stats.retained_bytes <= retained_limit);
        assert!(stats.retained_records < 256);
        assert_eq!(replay.replay.len(), stats.retained_records);
    }

    #[tokio::test]
    async fn shutdown_drains_an_append_accepted_behind_it() {
        let store = LogStore::spawn(config());
        let (reply, acknowledged) = oneshot::channel();
        store.commands.try_send(Command::Shutdown(reply)).unwrap();
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        acknowledged.await.unwrap();
        assert_eq!(store.stats().accepted_records, 1);
    }

    #[tokio::test]
    async fn one_lagging_subscriber_does_not_close_a_healthy_subscriber() {
        let store = LogStore::spawn(config());
        let mut lagging = store
            .subscribe(Selector::Namespace("games".into()))
            .await
            .unwrap();
        let mut healthy = store
            .subscribe(Selector::Namespace("games".into()))
            .await
            .unwrap();

        for sequence in 1..=8 {
            store
                .try_append(record("workload-1", "pod-a", 64 * 1024))
                .unwrap();
            assert_eq!(healthy.live.recv().await.unwrap().sequence(), sequence);
        }
        assert_eq!(
            lagging.live.terminal_changed().await,
            SubscriberTerminal::SubscriberLagged
        );
        assert_eq!(healthy.live.terminal(), SubscriberTerminal::Active);
    }

    #[tokio::test]
    async fn global_eviction_preserves_pod_counts_for_remaining_records() {
        let mut cfg = config();
        cfg.max_logs = 1_000;
        let store = LogStore::spawn(cfg);
        for operation in 0..256 {
            loop {
                match store.try_append(record(
                    &format!("workload-{}", operation % 2),
                    &format!("pod-{}", operation % 4),
                    64 * 1024,
                )) {
                    Ok(()) => break,
                    Err(TryAppendError::IngressFull | TryAppendError::IngressByteLimit) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("append failed: {error}"),
                }
            }
        }
        let replay = store
            .subscribe(Selector::Namespace("games".into()))
            .await
            .unwrap();
        let stats = store.stats();
        assert!(stats.global_budget_evictions > 0);
        assert_eq!(stats.pods, 4);
        assert_eq!(replay.replay.len(), stats.retained_records);
        assert!(replay.replay[0].sequence() > 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "manual release benchmark matrix"]
    async fn benchmark_workload_store_matrix() {
        const OPERATIONS: usize = 10_000;
        for payload_bytes in [64, 1_024, 16_384] {
            for workloads in [1, 32, 128] {
                let store = LogStore::spawn(StoreConfig {
                    max_memory: 128 * 1024 * 1024,
                    max_workloads: workloads,
                    max_logs: 500,
                    max_record_bytes: 64 * 1024,
                });
                let started = Instant::now();
                let mut latencies = Vec::with_capacity(OPERATIONS);
                for operation in 0..OPERATIONS {
                    let append_started = Instant::now();
                    loop {
                        match store.try_append(record(
                            &format!("workload-{}", operation % workloads),
                            &format!("pod-{}", operation % (workloads * 2)),
                            payload_bytes,
                        )) {
                            Ok(()) => break,
                            Err(TryAppendError::IngressFull | TryAppendError::IngressByteLimit) => {
                                tokio::task::yield_now().await
                            }
                            Err(error) => panic!("benchmark append failed: {error}"),
                        }
                    }
                    latencies.push(append_started.elapsed().as_nanos());
                }
                let barrier = store
                    .subscribe(Selector::Namespace("games".into()))
                    .await
                    .unwrap();
                latencies.sort_unstable();
                let elapsed = started.elapsed();
                println!(
                    "payload={} workloads={} records_per_sec={:.0} p50_append_ns={} p99_append_ns={} retained_records={} retained_bytes={} vm_hwm_kib={}",
                    payload_bytes,
                    workloads,
                    OPERATIONS as f64 / elapsed.as_secs_f64(),
                    latencies[OPERATIONS / 2],
                    latencies[OPERATIONS * 99 / 100],
                    store.stats().retained_records,
                    store.stats().retained_bytes,
                    vm_hwm_kib(),
                );
                drop(barrier);
                store.shutdown().await;
            }
        }
    }

    fn vm_hwm_kib() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmHWM:")?
                        .split_whitespace()
                        .next()?
                        .parse()
                        .ok()
                })
            })
            .unwrap_or(0)
    }
}
