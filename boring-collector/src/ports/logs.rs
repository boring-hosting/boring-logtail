// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage ports shared by collector ingress and trusted log readers.

use std::{fmt, pin::Pin};

use async_trait::async_trait;
use futures_core::Stream;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};

const MAX_SELECTOR_BYTES: usize = 1_024;

/// One complete log entry returned by a storage adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEntry {
    pub timestamp_unix_nano: u64,
    pub line: Vec<u8>,
    pub namespace: String,
    pub workload_kind: String,
    pub workload: String,
    pub pod: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadSelector {
    Namespace(String),
    Workload(String),
    Pod(String),
}

impl ReadSelector {
    fn value(&self) -> &str {
        match self {
            Self::Namespace(value) | Self::Workload(value) | Self::Pod(value) => value,
        }
    }
}

/// A typed retained/live read. Adapters own the history-to-follow handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    pub selector: ReadSelector,
    pub follow: bool,
    pub tail_lines: u32,
}

impl ReadRequest {
    pub fn new(selector: ReadSelector, follow: bool, tail_lines: u32) -> Result<Self, ReadError> {
        let value = selector.value();
        if value.is_empty() {
            return Err(ReadError::InvalidRequest("selector must not be empty"));
        }
        if value.len() > MAX_SELECTOR_BYTES {
            return Err(ReadError::InvalidRequest("selector is too large"));
        }

        Ok(Self {
            selector,
            follow,
            tail_lines,
        })
    }
}

use super::ExportError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadError {
    InvalidRequest(&'static str),
    Unavailable(String),
    Lagged(u64),
    Protocol(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => formatter.write_str(message),
            Self::Unavailable(message) | Self::Protocol(message) => formatter.write_str(message),
            Self::Lagged(count) => write!(formatter, "log stream lagged by {count} entries"),
        }
    }
}

impl std::error::Error for ReadError {}

pub type PortLogStream = Pin<Box<dyn Stream<Item = Result<LogEntry, ReadError>> + Send + 'static>>;

/// Bulk write port. One call is one complete OTLP export request.
#[async_trait]
pub trait LogSink: Send + Sync {
    async fn export(
        &self,
        batch: ExportLogsServiceRequest,
    ) -> Result<ExportLogsServiceResponse, ExportError>;
}

/// Retained/live read port. Implementations hide the handoff mechanism.
#[async_trait]
pub trait LogReader: Send + Sync {
    async fn stream(&self, request: ReadRequest) -> Result<PortLogStream, ReadError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_request_owns_selector_validation() {
        assert_eq!(
            ReadRequest::new(ReadSelector::Pod(String::new()), false, 10),
            Err(ReadError::InvalidRequest("selector must not be empty"))
        );
    }
}
