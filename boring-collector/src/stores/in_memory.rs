// SPDX-License-Identifier: GPL-3.0-or-later

//! Small in-memory log adapter for tests and local experiments.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use opentelemetry_proto::tonic::{
    collector::logs::v1::{ExportLogsServiceRequest, ExportLogsServiceResponse},
    common::v1::{KeyValue, any_value},
    logs::v1::LogRecord,
};
use tokio::sync::broadcast;
use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};

use crate::ports::{
    ExportError, LogEntry, LogReader, LogSink, PortLogStream, ReadError, ReadRequest, ReadSelector,
};

pub struct InMemoryLogStore {
    entries: Mutex<Vec<LogEntry>>,
    inserted: broadcast::Sender<LogEntry>,
}

impl Default for InMemoryLogStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryLogStore {
    pub fn new() -> Self {
        let (inserted, _) = broadcast::channel(1_024);
        Self {
            entries: Mutex::new(Vec::new()),
            inserted,
        }
    }

    pub fn insert(&self, entry: LogEntry) {
        self.entries.lock().unwrap().push(entry.clone());
        let _ = self.inserted.send(entry);
    }
}

#[async_trait]
impl LogSink for InMemoryLogStore {
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
                entries.push(log_entry(&attributes, record)?);
            }
        }

        self.entries.lock().unwrap().extend(entries.iter().cloned());
        for entry in entries {
            let _ = self.inserted.send(entry);
        }
        Ok(ExportLogsServiceResponse::default())
    }
}

#[async_trait]
impl LogReader for InMemoryLogStore {
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
        let live =
            BroadcastStream::new(self.inserted.subscribe()).filter_map(
                move |result| match result {
                    Ok(entry) if matches_entry(&selector, &entry) => Some(Ok(entry)),
                    Ok(_) => None,
                    Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(
                        count,
                    )) => Some(Err(ReadError::Lagged(count))),
                },
            );
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

fn log_entry(attributes: &HashMap<&str, &str>, record: LogRecord) -> Result<LogEntry, ExportError> {
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

#[cfg(test)]
mod tests {
    use opentelemetry_proto::tonic::{
        collector::logs::v1::ExportLogsServiceRequest,
        common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        resource::v1::Resource,
    };

    use super::*;

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
                    ..Resource::default()
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
                    ..ScopeLogs::default()
                }],
                ..ResourceLogs::default()
            }],
        }
    }

    #[tokio::test]
    async fn yields_retained_then_live_entries() {
        let store = InMemoryLogStore::new();
        store.insert(entry(b"old"));
        let mut stream = store
            .stream(ReadRequest::new(ReadSelector::Workload("valheim".into()), true, 1).unwrap())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().line, b"old");
        store.insert(entry(b"new"));
        assert_eq!(stream.next().await.unwrap().unwrap().line, b"new");
    }

    #[tokio::test]
    async fn accepts_a_complete_bulk_export() {
        let store = InMemoryLogStore::new();
        store.export(batch(&["one", "two"])).await.unwrap();
        let mut stream = store
            .stream(ReadRequest::new(ReadSelector::Workload("valheim".into()), false, 10).unwrap())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().line, b"one");
        assert_eq!(stream.next().await.unwrap().unwrap().line, b"two");
        assert!(stream.next().await.is_none());
    }
}
