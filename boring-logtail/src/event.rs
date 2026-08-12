// SPDX-License-Identifier: GPL-3.0-or-later

//! Precompiled event recognition on accepted, framed log bytes.

use crate::{config::Config, enrichment::Enrichment, record::LogRecord};
use regex::bytes::RegexSet;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Info,
    Warning,
    Error,
}

impl fmt::Display for EventType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDefinition {
    pub name: Arc<str>,
    pub kind: EventType,
    pub message: Arc<str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaughtEvent {
    pub definition: Arc<EventDefinition>,
    pub record: Arc<LogRecord>,
}

#[derive(Clone)]
pub struct EmitterSender {
    pub(crate) sender: mpsc::Sender<CaughtEvent>,
}

struct CompiledCatcher {
    definition: Arc<EventDefinition>,
    emitters: Vec<EmitterSender>,
}

pub struct EventCatcher {
    expressions: RegexSet,
    catchers: Vec<CompiledCatcher>,
    stats: Arc<AtomicCatcherStats>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventCatcherStats {
    pub caught: u64,
    pub queue_full: u64,
    pub emitter_closed: u64,
}

#[derive(Default)]
struct AtomicCatcherStats {
    caught: AtomicU64,
    queue_full: AtomicU64,
    emitter_closed: AtomicU64,
}

#[derive(Debug)]
pub enum CompileEventCatchersError {
    Regex(regex::Error),
    MissingEmitter(String),
}

impl fmt::Display for CompileEventCatchersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regex(error) => write!(formatter, "compile event catchers: {error}"),
            Self::MissingEmitter(name) => {
                write!(formatter, "event emitter {name:?} is not running")
            }
        }
    }
}

impl std::error::Error for CompileEventCatchersError {}

impl EventCatcher {
    pub fn compile(
        config: &Config,
        senders: &BTreeMap<String, EmitterSender>,
    ) -> Result<Self, CompileEventCatchersError> {
        let expressions = RegexSet::new(
            config
                .event_catchers
                .iter()
                .map(|catcher| catcher.regex.as_str()),
        )
        .map_err(CompileEventCatchersError::Regex)?;
        let catchers = config
            .event_catchers
            .iter()
            .map(|catcher| {
                let definition = &config.events[&catcher.event];
                let emitters = catcher
                    .emitters
                    .iter()
                    .map(|name| {
                        senders
                            .get(name)
                            .cloned()
                            .ok_or_else(|| CompileEventCatchersError::MissingEmitter(name.clone()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CompiledCatcher {
                    definition: Arc::new(EventDefinition {
                        name: Arc::from(catcher.event.as_str()),
                        kind: definition.kind,
                        message: Arc::from(definition.message.as_str()),
                    }),
                    emitters,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            expressions,
            catchers,
            stats: Arc::new(AtomicCatcherStats::default()),
        })
    }

    pub fn stats(&self) -> EventCatcherStats {
        EventCatcherStats {
            caught: self.stats.caught.load(Ordering::Relaxed),
            queue_full: self.stats.queue_full.load(Ordering::Relaxed),
            emitter_closed: self.stats.emitter_closed.load(Ordering::Relaxed),
        }
    }

    pub fn catch(&self, record: Arc<LogRecord>) {
        if !matches!(
            record.enrichment(),
            Enrichment::Enriched(_) | Enrichment::Stale(_)
        ) {
            return;
        }
        for index in self.expressions.matches(record.bytes()).iter() {
            self.stats.caught.fetch_add(1, Ordering::Relaxed);
            let catcher = &self.catchers[index];
            let event = CaughtEvent {
                definition: catcher.definition.clone(),
                record: record.clone(),
            };
            for emitter in &catcher.emitters {
                match emitter.sender.try_send(event.clone()) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.stats.queue_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.stats.emitter_closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enrichment::{ContainerId, KubernetesIdentity, WorkloadResolution},
        pipeline::StreamFileDescriptor,
        record::{RecordIntegrity, Severity},
    };

    #[test]
    fn compiles_all_expressions_together_and_rejects_invalid_regex() {
        let mut config: Config = serde_yaml::from_str(
            "events: {joined: {type: info, message: Joined!}}\n\
             event_catchers: [{regex: '(?i)joined', event: joined, emitters: [discord]}]\n\
             event_emitters: {discord: {channel_id: '1', secret_from_env: TOKEN}}\n",
        )
        .unwrap();
        config.validate().unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        let senders = BTreeMap::from([("discord".into(), EmitterSender { sender })]);
        assert!(EventCatcher::compile(&config, &senders).is_ok());
        config.event_catchers[0].regex = "[".into();
        assert!(matches!(
            EventCatcher::compile(&config, &senders),
            Err(CompileEventCatchersError::Regex(_))
        ));
    }

    #[test]
    fn one_catcher_can_fan_out_to_stdout_and_discord() {
        let mut config: Config = serde_yaml::from_str(
            "events: {joined: {type: info, message: Joined!}}\n\
             event_catchers: [{regex: joined, event: joined, emitters: [stdout, discord]}]\n\
             event_emitters:\n  stdout: {}\n  discord: {channel_id: '1', secret_from_env: TOKEN}\n",
        )
        .unwrap();
        config.validate().unwrap();
        let (stdout, _stdout_rx) = mpsc::channel(1);
        let (discord, _discord_rx) = mpsc::channel(1);
        let senders = BTreeMap::from([
            ("discord".into(), EmitterSender { sender: discord }),
            ("stdout".into(), EmitterSender { sender: stdout }),
        ]);
        let catcher = EventCatcher::compile(&config, &senders).unwrap();
        assert_eq!(catcher.catchers[0].emitters.len(), 2);
    }

    #[test]
    fn caught_event_shares_the_exact_matched_record_bytes() {
        let mut config: Config = serde_yaml::from_str(
            "events: {error: {type: error, message: An error occurred!}}\n\
             event_catchers: [{regex: failed, event: error, emitters: [stdout]}]\n\
             event_emitters: {stdout: {}}\n",
        )
        .unwrap();
        config.validate().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let catcher = EventCatcher::compile(
            &config,
            &BTreeMap::from([("stdout".into(), EmitterSender { sender })]),
        )
        .unwrap();
        let bytes: Arc<[u8]> = Arc::from(&b"database failed\n"[..]);
        let record = Arc::new(LogRecord {
            sampling_seed: 1,
            stream: StreamFileDescriptor::Stderr,
            enrichment: Enrichment::Enriched(KubernetesIdentity {
                node: "node".into(),
                namespace: "games".into(),
                pod_name: "game-1".into(),
                pod_uid: "pod-1".into(),
                container_name: "game".into(),
                container_id: ContainerId {
                    runtime: "containerd".into(),
                    id: "a".repeat(64),
                },
                workload: WorkloadResolution::NoController,
            }),
            first_timestamp_ns: 1,
            last_timestamp_ns: 1,
            first_operation_id: 1,
            last_operation_id: 1,
            bytes: bytes.clone(),
            integrity: RecordIntegrity::default(),
            sample_percent: 100,
            severity: Severity::Unknown,
        });

        catcher.catch(record.clone());

        let event = receiver.try_recv().unwrap();
        assert!(Arc::ptr_eq(&event.record, &record));
        assert_eq!(event.record.bytes(), b"database failed\n");
    }
}
