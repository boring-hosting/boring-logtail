// SPDX-License-Identifier: GPL-3.0-or-later

//! Collector-owned admission policy and event recognition.
//!
//! The node sends every honest framed record. This module is deliberately on
//! the cluster side: operators can change filtering, sampling, and alerts
//! without changing what the DaemonSet captures.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use blt_emitter::EmitterSender;
use blt_model::{CaughtEvent, Enrichment, EventDefinition, LogRecord};
use regex::bytes::RegexSet;

use crate::CollectorConfig;

struct Catcher {
    definition: Arc<EventDefinition>,
    emitters: Vec<EmitterSender>,
}

/// Immutable hot-path policy compiled once during collector startup.
pub struct Policy {
    sample_percent: u8,
    namespaces: Option<BTreeSet<String>>,
    expressions: RegexSet,
    catchers: Vec<Catcher>,
    stats: PolicyCounters,
}

#[derive(Default)]

struct PolicyCounters {
    filtered: AtomicU64,
    sampled: AtomicU64,
    caught: AtomicU64,
    emitter_full: AtomicU64,
    emitter_closed: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]

pub struct PolicyStats {
    pub filtered: u64,
    pub sampled: u64,
    pub caught: u64,
    pub emitter_full: u64,
    pub emitter_closed: u64,
}

impl Policy {
    pub fn compile(
        config: &CollectorConfig,
        senders: &BTreeMap<String, EmitterSender>,
    ) -> anyhow::Result<Self> {
        let expressions = RegexSet::new(
            config
                .event_catchers
                .iter()
                .map(|catcher| catcher.regex.as_str()),
        )?;

        let catchers = config
            .event_catchers
            .iter()
            .map(|catcher| {
                let event = &config.events[&catcher.event];

                let emitters = catcher
                    .emitters
                    .iter()
                    .map(|name| {
                        senders
                            .get(name)
                            .cloned()
                            .ok_or_else(|| anyhow::anyhow!("event emitter {name:?} is not running"))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;

                Ok(Catcher {
                    definition: Arc::new(EventDefinition {
                        name: Arc::from(catcher.event.as_str()),
                        kind: event.kind,
                        message: Arc::from(event.message.as_str()),
                    }),
                    emitters,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        Ok(Self {
            sample_percent: config.sampling.percent,
            namespaces: config
                .filters
                .namespaces
                .as_ref()
                .map(|filter| filter.include.iter().cloned().collect()),
            expressions,
            catchers,
            stats: PolicyCounters::default(),
        })
    }

    /// Return a shareable record only when collector policy admits it.
    pub fn admit(&self, mut record: LogRecord) -> Option<Arc<LogRecord>> {
        if !self.namespace_allowed(&record) {
            self.stats.filtered.fetch_add(1, Ordering::Relaxed);

            return None;
        }

        record.sample_percent = self.sample_percent;

        if !sampled_in(&record, self.sample_percent) {
            self.stats.sampled.fetch_add(1, Ordering::Relaxed);

            return None;
        }

        let record = Arc::new(record);

        self.catch(&record);

        Some(record)
    }

    pub fn stats(&self) -> PolicyStats {
        PolicyStats {
            filtered: self.stats.filtered.load(Ordering::Relaxed),
            sampled: self.stats.sampled.load(Ordering::Relaxed),
            caught: self.stats.caught.load(Ordering::Relaxed),
            emitter_full: self.stats.emitter_full.load(Ordering::Relaxed),
            emitter_closed: self.stats.emitter_closed.load(Ordering::Relaxed),
        }
    }

    fn namespace_allowed(&self, record: &LogRecord) -> bool {
        let Some(namespaces) = &self.namespaces else {
            return true;
        };

        match record.enrichment() {
            Enrichment::Enriched(identity) | Enrichment::Stale(identity) => {
                namespaces.contains(&identity.namespace)
            }
            _ => false,
        }
    }

    fn catch(&self, record: &Arc<LogRecord>) {
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
                match emitter.try_send(event.clone()) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        self.stats.emitter_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        self.stats.emitter_closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

fn sampled_in(record: &LogRecord, percent: u8) -> bool {
    match percent {
        0 => false,
        100 => true,
        percent => {
            let mut value = record.sampling_seed()
                ^ record.first_timestamp_ns().rotate_left(7)
                ^ record.last_timestamp_ns().rotate_left(13)
                ^ record.first_operation_id().rotate_left(17)
                ^ record.last_operation_id().rotate_left(29)
                ^ (record.bytes().len() as u64).rotate_left(41);

            value ^= value >> 30;

            value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);

            value ^= value >> 27;

            value = value.wrapping_mul(0x94d0_49bb_1331_11eb);

            (value ^ (value >> 31)) % 100 < u64::from(percent)
        }
    }
}
