// SPDX-License-Identifier: GPL-3.0-or-later

//! Workload-owned bounded retention and gap-free replay/live handoff.

use crate::enrichment::{Enrichment, KubernetesIdentity, WorkloadResolution};
use crate::record::{DEFAULT_MAX_RECORD_BYTES, FRAMING_LANE_CHARGE, LogRecord};
use serde::{Deserialize, Deserializer};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    time::{Instant, MissedTickBehavior},
};

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
pub(crate) struct StoreLimits {
    pub(crate) retained_bytes: usize,
    pub(crate) assembly_bytes: usize,
    pub(crate) assembly_operations: usize,
    pub(crate) framing_bytes: usize,
    pub(crate) framing_lanes: usize,
    pub(crate) max_record_bytes: usize,
    workload_capacity: usize,
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
        if self.max_logs == 0 {
            return Err("store max_logs must be non-zero");
        }
        if self.retention.is_zero() {
            return Err("store retention must be non-zero");
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
            framing_lanes: (part(3) / (DEFAULT_MAX_RECORD_BYTES + FRAMING_LANE_CHARGE)).max(1),
            assembly_operations: (part(2) / WORKLOAD_CHARGE).max(1),
            ingress_records: 0,
            subscriber_records: 0,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            workload_capacity: (part(40) / WORKLOAD_CHARGE).max(1),
        };
        let one = DEFAULT_MAX_RECORD_BYTES + RECORD_CHARGE + QUEUE_CHARGE;
        let limits = StoreLimits {
            ingress_records: (limits.ingress_bytes / one).max(1),
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
            || limits.framing_bytes < DEFAULT_MAX_RECORD_BYTES + FRAMING_LANE_CHARGE
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
            return Err("store max_memory is too small for internal record and delivery buffers");
        }
        Ok(limits)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.limits().map(|_| ())
    }

    pub fn derived_limits_summary(&self) -> Result<String, &'static str> {
        let limits = self.limits()?;
        Ok(format!(
            "retained={} assembly={} framing={} ingress={} replay={} live_total={} headroom={} workload_capacity={} assembly_operations={} framing_lanes={} ingress_records={} subscribers={} live_records_per_subscriber={}",
            limits.retained_bytes,
            limits.assembly_bytes,
            limits.framing_bytes,
            limits.ingress_bytes,
            limits.replay_bytes,
            limits.subscriber_bytes * MAX_SUBSCRIBERS,
            limits.headroom_bytes,
            limits.workload_capacity,
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

fn deserialize_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(d)?;
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
    retained_at: Instant,
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
    pub retention_evictions: u64,
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
            max_record_bytes: limits.max_record_bytes,
            stats,
        };
        tokio::spawn(run(State::new(config, limits, stats_sender), receiver));
        store
    }
    pub fn try_append<R>(&self, record: R) -> Result<(), TryAppendError>
    where
        R: Into<Arc<LogRecord>>,
    {
        let record = record.into();
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
            .try_send(Command::Append(record, permit))
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
    Append(Arc<LogRecord>, OwnedSemaphorePermit),
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
    fn append(&mut self, record: Arc<LogRecord>) {
        self.expire(Instant::now());
        self.append_at(record, Instant::now());
    }

    fn append_at(&mut self, record: Arc<LogRecord>, retained_at: Instant) {
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
        if new && self.workloads.len() >= self.limits.workload_capacity {
            self.stats.workload_limit_rejections += 1;
            return;
        }
        self.next += 1;
        let stored = Arc::new(StoredRecord {
            sequence: self.next,
            record,
            accounted_bytes: charge,
            retained_at,
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
            self.evict(&workload, EvictionReason::PerWorkload);
        }
        while self.retained_bytes > self.limits.retained_bytes {
            let Some(workload) = self.global.first_key_value().map(|(_, (w, _))| w.clone()) else {
                break;
            };
            self.evict(&workload, EvictionReason::GlobalBudget);
        }
        self.stats.accepted_records += 1;
        self.publish(stored);
    }
    fn evict(&mut self, workload: &str, reason: EvictionReason) {
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
            match reason {
                EvictionReason::PerWorkload => self.stats.per_workload_evictions += 1,
                EvictionReason::GlobalBudget => self.stats.global_budget_evictions += 1,
                EvictionReason::Retention => self.stats.retention_evictions += 1,
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

    fn expire(&mut self, now: Instant) {
        loop {
            let expired = self
                .global
                .first_key_value()
                .filter(|(_, (_, record))| {
                    now.saturating_duration_since(record.retained_at) >= self.config.retention
                })
                .map(|(_, (workload, _))| workload.clone());
            let Some(workload) = expired else {
                break;
            };
            self.evict(&workload, EvictionReason::Retention);
        }
    }

    fn subscribe(&mut self, selector: Selector) -> Result<ReplaySession, SubscribeError> {
        self.expire(Instant::now());
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

#[derive(Clone, Copy)]
enum EvictionReason {
    PerWorkload,
    GlobalBudget,
    Retention,
}

async fn run(mut state: State, mut rx: mpsc::Receiver<Command>) {
    let mut replies = vec![];
    let cadence = state.config.retention.min(Duration::from_secs(1));
    let mut expiry = tokio::time::interval(cadence);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Skip);
    expiry.tick().await;
    loop {
        let command = tokio::select! {
            command = rx.recv() => command,
            _ = expiry.tick() => {
                state.expire(Instant::now());
                state.publish_stats();
                continue;
            }
        };
        let Some(command) = command else {
            break;
        };
        match command {
            Command::Append(record, _permit) => state.append(record),
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
            Command::Append(record, _) => state.append(record),
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
    use std::sync::Arc;

    fn config() -> StoreConfig {
        StoreConfig {
            max_memory: 32 * 1024 * 1024,
            max_logs: 2,
            retention: Duration::from_secs(60 * 60),
        }
    }

    fn record(workload_uid: &str, pod_uid: &str, size: usize) -> LogRecord {
        let container_id = ContainerId {
            runtime: "containerd".into(),
            id: "a".repeat(64),
        };
        LogRecord {
            observed_at: "2026-08-12T18:00:00Z".parse().unwrap(),
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
        let c: StoreConfig =
            serde_yaml::from_str("max_memory: 128MiB\nmax_logs: 500\nretention: 15m").unwrap();
        assert_eq!(c.max_memory, 128 << 20);
        assert_eq!(c.max_logs, 500);
        assert_eq!(c.retention, Duration::from_secs(15 * 60));
        for (text, expected) in [
            ("1s", Duration::from_secs(1)),
            ("12m", Duration::from_secs(12 * 60)),
            ("3h", Duration::from_secs(3 * 60 * 60)),
        ] {
            let parsed: StoreConfig = serde_yaml::from_str(&format!("retention: {text}")).unwrap();
            assert_eq!(parsed.retention, expected);
        }
        for invalid in [
            "0s",
            "1",
            "1d",
            "1H",
            "1.5h",
            "1h30m",
            " 1h",
            "18446744073709551615h",
        ] {
            assert!(
                serde_yaml::from_str::<StoreConfig>(&format!("retention: {invalid:?}")).is_err()
            );
        }
        for removed in [
            "max_workloads: 128",
            "max_record_bytes: 64KiB",
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
    async fn workload_capacity_is_derived_from_memory() {
        let small = config().limits().unwrap().workload_capacity;
        let large = StoreConfig {
            max_memory: 64 * 1024 * 1024,
            ..config()
        }
        .limits()
        .unwrap()
        .workload_capacity;
        assert!(small > 1);
        assert!((small * 2..=small * 2 + 1).contains(&large));
    }

    #[test]
    fn retention_expires_mixed_ages_and_cleans_identity_accounting() {
        let mut config = config();
        config.retention = Duration::from_secs(10);
        let limits = config.limits().unwrap();
        let (stats_sender, _) = watch::channel(StoreStats::default());
        let mut state = State::new(config, limits, stats_sender);
        let now = Instant::now();
        state.append_at(
            record("workload-1", "pod-old", 8).into(),
            now - Duration::from_secs(11),
        );
        state.append_at(
            record("workload-1", "pod-young", 8).into(),
            now - Duration::from_secs(9),
        );

        state.expire(now);

        assert_eq!(state.global.len(), 1);
        assert_eq!(state.stats.retention_evictions, 1);
        assert!(!state.pod_counts.contains_key("pod-old"));
        assert_eq!(state.pod_counts["pod-young"], 1);
        state.expire(now + Duration::from_secs(1));
        assert!(state.global.is_empty());
        assert!(state.workloads.is_empty());
        assert!(state.pod_counts.is_empty());
        assert_eq!(state.stats.retention_evictions, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_actor_expires_history_but_existing_replay_refs_survive() {
        let store = LogStore::spawn(StoreConfig {
            retention: Duration::from_secs(2),
            ..config()
        });
        store.try_append(record("workload-1", "pod-a", 8)).unwrap();
        tokio::task::yield_now().await;
        let replay = store
            .subscribe(Selector::WorkloadUid("workload-1".into()))
            .await
            .unwrap();
        assert_eq!(replay.replay.len(), 1);

        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        let fresh = store
            .subscribe(Selector::WorkloadUid("workload-1".into()))
            .await
            .unwrap();

        assert!(fresh.replay.is_empty());
        assert_eq!(replay.replay[0].record().bytes(), &[b'x'; 8]);
        assert_eq!(store.stats().retention_evictions, 1);
        store.shutdown().await;
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
            loop {
                match store.try_append(record("workload-1", "pod-a", 64 * 1024)) {
                    Ok(()) => break,
                    Err(TryAppendError::IngressFull | TryAppendError::IngressByteLimit) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("append failed: {error}"),
                }
            }
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
                    max_logs: 500,
                    retention: Duration::from_secs(60 * 60),
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
