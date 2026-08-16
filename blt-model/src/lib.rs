// SPDX-License-Identifier: GPL-3.0-or-later

//! Durable userspace facts shared by storage, APIs, and emitters.
//!
//! Plain version: once capture has turned CRI bytes into a real log record,
//! everybody should pass around that same record instead of inventing a lossy
//! copy for each destination. This crate owns those stable nouns and behavior
//! intrinsic to them; it owns no watchers, queues, storage, or network clients.
//!
//! [`LogRecord`] is a complete userspace record, and [`CaughtEvent`] is a
//! configured match carrying that same record. See `learn/workspace.org`.

mod caught;
mod identity;
mod record;

pub use caught::{CaughtEvent, EventDefinition, EventType};
pub use identity::{
    ContainerId, Enrichment, InvalidContainerId, KubernetesIdentity, WorkloadIdentity,
    WorkloadResolution,
};
pub use record::{LogRecord, RecordIntegrity, Severity, StreamFileDescriptor};
