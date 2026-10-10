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

/// Why a complete OTLP batch was not accepted by the storage adapter.
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use opentelemetry_proto::tonic::{
        collector::logs::v1::{ExportLogsServiceRequest, ExportLogsServiceResponse},
        common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        resource::v1::Resource,
    };
    use tokio::sync::broadcast;
    use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};

    use super::*;

    /// Deliberately tiny test adapter. Production retention belongs to Loki.
    struct MemoryLogStore {
        entries: Mutex<Vec<LogEntry>>,
        inserted: broadcast::Sender<LogEntry>,
    }

    impl MemoryLogStore {
        fn new() -> Self {
            let (inserted, _) = broadcast::channel(16);
            Self {
                entries: Mutex::new(Vec::new()),
                inserted,
            }
        }

        fn insert(&self, entry: LogEntry) {
            self.entries.lock().unwrap().push(entry.clone());
            let _ = self.inserted.send(entry);
        }
    }

    #[async_trait]
    impl LogSink for MemoryLogStore {
        async fn export(
            &self,
            batch: ExportLogsServiceRequest,
        ) -> Result<ExportLogsServiceResponse, ExportError> {
            let mut entries = Vec::new();
            for resource_logs in batch.resource_logs {
                let resource = resource_logs
                    .resource
                    .ok_or_else(|| ExportError::rejected("resource is required"))?;
                let attributes = text_attributes(&resource.attributes);
                for record in resource_logs
                    .scope_logs
                    .into_iter()
                    .flat_map(|scope| scope.log_records)
                {
                    entries.push(memory_entry(&attributes, record)?);
                }
            }

            {
                let mut retained = self.entries.lock().unwrap();
                retained.extend(entries.iter().cloned());
            }
            for entry in entries {
                let _ = self.inserted.send(entry);
            }

            Ok(ExportLogsServiceResponse::default())
        }
    }

    #[async_trait]
    impl LogReader for MemoryLogStore {
        async fn stream(&self, request: ReadRequest) -> Result<PortLogStream, ReadError> {
            let retained = self
                .entries
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| matches_entry(&request.selector, entry))
                .cloned()
                .collect::<Vec<_>>();
            let skip = retained.len().saturating_sub(request.tail_lines as usize);
            let retained = tokio_stream::iter(retained.into_iter().skip(skip).map(Ok));

            if !request.follow {
                return Ok(Box::pin(retained));
            }

            let selector = request.selector;
            let live = BroadcastStream::new(self.inserted.subscribe()).filter_map(move |result| {
                match result {
                    Ok(entry) if matches_entry(&selector, &entry) => Some(Ok(entry)),
                    Ok(_) => None,
                    Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(
                        count,
                    )) => Some(Err(ReadError::Lagged(count))),
                }
            });

            Ok(Box::pin(retained.chain(live)))
        }
    }

    fn matches_entry(selector: &ReadSelector, entry: &LogEntry) -> bool {
        match selector {
            ReadSelector::Namespace(value) => entry.namespace == *value,
            ReadSelector::Workload(value) => entry.workload == *value,
            ReadSelector::Pod(value) => entry.pod == *value,
        }
    }

    fn text_attributes(attributes: &[KeyValue]) -> HashMap<&str, &str> {
        attributes
            .iter()
            .filter_map(
                |attribute| match attribute.value.as_ref()?.value.as_ref()? {
                    any_value::Value::StringValue(value) => {
                        Some((attribute.key.as_str(), value.as_str()))
                    }
                    _ => None,
                },
            )
            .collect()
    }

    fn memory_entry(
        attributes: &HashMap<&str, &str>,
        record: LogRecord,
    ) -> Result<LogEntry, ExportError> {
        let line = match record.body.and_then(|body| body.value) {
            Some(any_value::Value::StringValue(value)) => value.into_bytes(),
            Some(any_value::Value::BytesValue(value)) => value,
            _ => return Err(ExportError::rejected("log body must be text or bytes")),
        };
        let (workload_kind, workload) = [
            ("Deployment", "k8s.deployment.name"),
            ("StatefulSet", "k8s.statefulset.name"),
            ("DaemonSet", "k8s.daemonset.name"),
            ("Job", "k8s.job.name"),
            ("CronJob", "k8s.cronjob.name"),
            ("ReplicaSet", "k8s.replicaset.name"),
        ]
        .into_iter()
        .find_map(|(kind, key)| attributes.get(key).map(|value| (kind, *value)))
        .unwrap_or(("Pod", attributes.get("k8s.pod.name").copied().unwrap_or("")));

        Ok(LogEntry {
            timestamp_unix_nano: record.time_unix_nano.max(record.observed_time_unix_nano),
            line,
            namespace: attributes
                .get("k8s.namespace.name")
                .copied()
                .unwrap_or("")
                .to_owned(),
            workload_kind: workload_kind.to_owned(),
            workload: workload.to_owned(),
            pod: attributes
                .get("k8s.pod.name")
                .copied()
                .unwrap_or("")
                .to_owned(),
        })
    }

    fn entry(line: &[u8]) -> LogEntry {
        LogEntry {
            timestamp_unix_nano: 1,
            line: line.to_vec(),
            namespace: "games".into(),
            workload_kind: "StatefulSet".into(),
            workload: "valheim".into(),
            pod: "valheim-0".into(),
        }
    }

    fn batch(lines: &[&str]) -> ExportLogsServiceRequest {
        let attributes = [
            ("k8s.namespace.name", "games"),
            ("k8s.statefulset.name", "valheim"),
            ("k8s.pod.name", "valheim-0"),
        ]
        .into_iter()
        .map(|(key, value)| KeyValue {
            key: key.into(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(value.into())),
            }),
            ..KeyValue::default()
        })
        .collect();

        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes,
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope::default()),
                    log_records: lines
                        .iter()
                        .enumerate()
                        .map(|(index, line)| LogRecord {
                            observed_time_unix_nano: index as u64 + 1,
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue((*line).into())),
                            }),
                            ..LogRecord::default()
                        })
                        .collect(),
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    #[tokio::test]
    async fn private_adapter_obeys_retained_then_live_contract() {
        let store = Arc::new(MemoryLogStore::new());
        store.insert(entry(b"old-one"));
        store.insert(entry(b"old-two"));

        let mut stream = store
            .stream(ReadRequest::new(ReadSelector::Workload("valheim".into()), true, 1).unwrap())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().line, b"old-two");

        store.insert(entry(b"new"));
        assert_eq!(stream.next().await.unwrap().unwrap().line, b"new");
    }

    #[tokio::test]
    async fn private_adapter_accepts_a_complete_bulk_export() {
        let store = MemoryLogStore::new();
        store.export(batch(&["one", "two"])).await.unwrap();

        let mut stream = store
            .stream(ReadRequest::new(ReadSelector::Workload("valheim".into()), false, 10).unwrap())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().line, b"one");
        assert_eq!(stream.next().await.unwrap().unwrap().line, b"two");
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn read_request_owns_selector_validation() {
        assert_eq!(
            ReadRequest::new(ReadSelector::Pod(String::new()), false, 10),
            Err(ReadError::InvalidRequest("selector must not be empty"))
        );
    }
}
