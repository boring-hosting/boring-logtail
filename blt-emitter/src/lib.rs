// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded asynchronous delivery for caught events.
//!
//! Plain version: capture drops a notification into a small mailbox and keeps
//! moving. A destination worker owns the slow stdout or HTTP work. If Discord
//! stalls, it can fill only its own bounded queue; it cannot make eBPF capture
//! wait for the internet.
//!
//! Destination rendering lives in one file per emitter. Configuration parsing
//! and secret lookup stay in the host application. See `learn/workspace.org`
//! and `learn/boring-logtail.org`.

mod discord;
mod stdout;

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use blt_model::CaughtEvent;
use tokio::{sync::mpsc, task::JoinHandle};

const QUEUE_CAPACITY: usize = 128;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Aggregate destination outcomes. Queue-full drops belong to catcher stats.
#[derive(Clone, Debug, Default, Eq, PartialEq)]

pub struct EmitterStats {
    pub delivered: u64,
    pub delivery_failed: u64,
}

#[derive(Default)]

struct AtomicEmitterStats {
    delivered: AtomicU64,
    delivery_failed: AtomicU64,
}

impl AtomicEmitterStats {
    fn delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }

    fn failed(&self) {
        self.delivery_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> EmitterStats {
        EmitterStats {
            delivered: self.delivered.load(Ordering::Relaxed),
            delivery_failed: self.delivery_failed.load(Ordering::Relaxed),
        }
    }
}

/// Cheap cloneable handle used by catchers for nonblocking delivery attempts.
#[derive(Clone)]

pub struct EmitterSender {
    sender: mpsc::Sender<CaughtEvent>,
}

impl EmitterSender {
    /// Wraps a bounded channel when assembling or testing the catcher graph.

    pub fn new(sender: mpsc::Sender<CaughtEvent>) -> Self {
        Self { sender }
    }

    /// Attempts delivery immediately; it never awaits destination I/O.

    pub fn try_send(
        &self,
        event: CaughtEvent,
    ) -> Result<(), mpsc::error::TrySendError<CaughtEvent>> {
        self.sender.try_send(event)
    }
}

/// Runtime Discord destination with the already-resolved bot secret.
///
/// `Debug` redacts the secret. Environment-variable lookup belongs to the host
/// so this reusable crate never depends on the application's YAML shape.

pub struct DiscordConfig {
    channel_id: String,
    secret: String,
    api: String,
}

impl DiscordConfig {
    pub fn new(channel_id: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            channel_id: channel_id.into(),
            secret: secret.into(),
            api: discord::DISCORD_API.to_owned(),
        }
    }

    #[cfg(test)]

    fn with_api(mut self, api: impl Into<String>) -> Self {
        self.api = api.into();

        self
    }
}

impl fmt::Debug for DiscordConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscordConfig")
            .field("channel_id", &self.channel_id)
            .field("secret", &"[redacted]")
            .field("api", &self.api)
            .finish()
    }
}

/// Runtime destinations selected by the host after configuration validation.
#[derive(Debug, Default)]

pub struct EmittersConfig {
    pub discord: Option<DiscordConfig>,
    pub stdout: bool,
}

/// Owns destination workers and their shared delivery counters.

pub struct EventEmitters {
    tasks: Vec<JoinHandle<()>>,
    stats: Arc<AtomicEmitterStats>,
}

impl EventEmitters {
    /// Starts one bounded worker for each configured destination.

    pub fn spawn(config: EmittersConfig) -> (BTreeMap<String, EmitterSender>, Self) {
        let stats = Arc::new(AtomicEmitterStats::default());

        let mut senders = BTreeMap::new();

        let mut tasks = Vec::new();

        if let Some(config) = config.discord {
            let (sender, task) = discord::spawn(config, stats.clone());

            senders.insert("discord".into(), EmitterSender { sender });

            tasks.push(task);
        }

        if config.stdout {
            let (sender, task) = stdout::spawn(stats.clone());

            senders.insert("stdout".into(), EmitterSender { sender });

            tasks.push(task);
        }

        (senders, Self { tasks, stats })
    }

    /// Returns a relaxed, diagnostic snapshot of aggregate outcomes.

    pub fn stats(&self) -> EmitterStats {
        self.stats.snapshot()
    }

    /// Waits briefly for accepted events to drain, then abandons stuck workers.

    pub async fn shutdown(self) {
        for task in self.tasks {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, task).await;
        }
    }
}

fn channel() -> (mpsc::Sender<CaughtEvent>, mpsc::Receiver<CaughtEvent>) {
    mpsc::channel(QUEUE_CAPACITY)
}
