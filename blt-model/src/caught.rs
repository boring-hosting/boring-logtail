// SPDX-License-Identifier: GPL-3.0-or-later

//! Values created when a configured pattern matches a complete log record.
//!
//! Catching and delivery are separate jobs. The application compiles regexes
//! and creates these values; emitters only decide how to render and deliver
//! them. Keeping the values here prevents either side from owning the other.

use std::{fmt, sync::Arc};

use serde::Deserialize;

use crate::LogRecord;

/// Configured meaning of an event, independent of captured stream severity.
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

/// One named event from configuration, compiled once and shared by matches.
///
/// `Arc<str>` keeps each caught notification cheap: a burst of matches shares
/// the immutable name and message instead of allocating them repeatedly.
#[derive(Clone, Debug, Eq, PartialEq)]

pub struct EventDefinition {
    pub name: Arc<str>,
    pub kind: EventType,
    pub message: Arc<str>,
}

/// A configured event match plus the exact immutable record that matched.
///
/// The record is an `Arc`, not a reduced alert payload. Storage, ordinary
/// output, and every emitter therefore observe identical bytes and metadata.
#[derive(Clone, Debug, Eq, PartialEq)]

pub struct CaughtEvent {
    pub definition: Arc<EventDefinition>,
    pub record: Arc<LogRecord>,
}
