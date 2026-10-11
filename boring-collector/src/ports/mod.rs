// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage contracts used by collector ingress and trusted readers.

mod logs;
mod metrics;

use std::fmt;

pub use logs::{LogEntry, LogReader, LogSink, PortLogStream, ReadError, ReadRequest, ReadSelector};
pub use metrics::MetricsSink;

/// Why a complete OTLP batch was not accepted by a storage adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportError {
    Retryable(String),
    Rejected(String),
}

impl ExportError {
    pub fn retryable(message: impl Into<String>) -> Self {
        Self::Retryable(message.into())
    }

    pub fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected(message.into())
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retryable(message) | Self::Rejected(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ExportError {}
