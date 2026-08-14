// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded OTLP Logs ingestion for the cluster-wide collector.
//!
//! The receiver accepts only the versioned BLT mapping, reconstructs the exact
//! internal record, and hands it to the same bounded store contract already
//! proven in-process. Filtering, sampling, and event delivery happen here,
//! after decoding and before store admission.

mod policy;

use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use blt_model::EventType;
use blt_otel::decode_record;
use blt_store::{LogStore, StoreConfig};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
pub use policy::{Policy, PolicyStats};
use prost::Message as _;
use serde::Deserialize;

pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Collector configuration. Retention remains a first-class public contract.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorConfig {
    pub listen: SocketAddr,
    pub max_request_bytes: usize,
    pub store: StoreConfig,
    pub sampling: SamplingConfig,
    pub filters: FilterConfig,
    pub events: BTreeMap<String, EventConfig>,
    pub event_catchers: Vec<EventCatcherConfig>,
    pub event_emitters: EventEmittersConfig,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:4318".parse().expect("static address is valid"),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            store: StoreConfig::default(),
            sampling: SamplingConfig::default(),
            filters: FilterConfig::default(),
            events: BTreeMap::new(),
            event_catchers: Vec::new(),
            event_emitters: EventEmittersConfig::default(),
        }
    }
}

impl CollectorConfig {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut config = match path {
            Some(path) => serde_yaml::from_slice(&std::fs::read(path)?)?,
            None => Self::default(),
        };

        config.validate()?;

        Ok(config)
    }

    pub fn validate(&mut self) -> anyhow::Result<()> {
        self.store.validate().map_err(anyhow::Error::msg)?;

        if self.max_request_bytes == 0 {
            anyhow::bail!("collector max_request_bytes must be non-zero");
        }

        if self.sampling.percent > 100 {
            anyhow::bail!("sampling percent must be in 0..=100");
        }

        if let Some(filter) = &mut self.filters.namespaces {
            if filter.include.is_empty() || filter.include.len() > 64 {
                anyhow::bail!("namespace include must contain 1..=64 names");
            }

            let mut seen = HashSet::new();

            for namespace in &mut filter.include {
                *namespace = namespace.trim().to_owned();

                if namespace.is_empty() || !seen.insert(namespace.clone()) {
                    anyhow::bail!("namespace includes must be non-empty and unique");
                }
            }
        }

        for catcher in &self.event_catchers {
            if !self.events.contains_key(&catcher.event) {
                anyhow::bail!("event catcher references unknown event {:?}", catcher.event);
            }

            if catcher.emitters.is_empty() {
                anyhow::bail!("event catcher {:?} has no emitters", catcher.event);
            }

            let mut emitters = HashSet::new();

            for emitter in &catcher.emitters {
                if !emitters.insert(emitter) {
                    anyhow::bail!("event catcher repeats emitter {emitter:?}");
                }

                let exists = match emitter.as_str() {
                    "stdout" => self.event_emitters.stdout.is_some(),
                    "discord" => self.event_emitters.discord.is_some(),
                    _ => false,
                };

                if !exists {
                    anyhow::bail!("event catcher references unknown emitter {emitter:?}");
                }
            }
        }

        for (name, event) in &self.events {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !name.as_bytes()[0].is_ascii_lowercase()
            {
                anyhow::bail!("invalid event name {name:?}");
            }

            if event.message.trim().is_empty() {
                anyhow::bail!("event {name:?} message must not be empty");
            }
        }

        if let Some(discord) = &mut self.event_emitters.discord {
            discord.channel_id = discord.channel_id.trim().to_owned();

            discord.secret_from_env = discord.secret_from_env.trim().to_owned();

            if discord.channel_id.is_empty() || discord.secret_from_env.is_empty() {
                anyhow::bail!("Discord channel and secret environment name must be non-empty");
            }
        }

        regex::bytes::RegexSet::new(self.event_catchers.iter().map(|item| &item.regex))?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamplingConfig {
    pub percent: u8,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self { percent: 100 }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    pub namespaces: Option<NamespaceFilterConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFilterConfig {
    pub include: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventConfig {
    #[serde(rename = "type")]
    pub kind: EventType,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCatcherConfig {
    pub regex: String,
    pub event: String,
    pub emitters: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventEmittersConfig {
    pub stdout: Option<StdoutEmitterConfig>,
    pub discord: Option<DiscordEmitterConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdoutEmitterConfig {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordEmitterConfig {
    pub channel_id: String,
    pub secret_from_env: String,
}

#[derive(Clone)]

struct ReceiverState {
    store: Arc<LogStore>,
    // Constructed here to make the collector the sole API composition root.
    // An external transport awaits its own authenticated protocol ADR.
    policy: Arc<Policy>,
}

pub fn router(store: Arc<LogStore>, policy: Arc<Policy>, max_request_bytes: usize) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/logs", post(receive_logs))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(ReceiverState {
            store,
            policy,
        })
}

async fn receive_logs(State(state): State<ReceiverState>, body: Bytes) -> Response {
    let request = match ExportLogsServiceRequest::decode(body) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid OTLP protobuf: {error}"),
            )
                .into_response();
        }
    };

    let response = ingest(request, &state.store, &state.policy);

    if let Some(partial) = &response.partial_success {
        log::warn!(
            "OTLP partial success: rejected_records={} reasons={}",
            partial.rejected_log_records,
            partial.error_message
        );
    }

    otlp_response(response)
}

/// Admit every independently valid record and report rejected records using
/// OTLP partial-success semantics.
pub fn ingest(
    request: ExportLogsServiceRequest,
    store: &LogStore,
    policy: &Policy,
) -> ExportLogsServiceResponse {
    let mut rejected = 0i64;

    let mut reasons = std::collections::BTreeMap::<String, i64>::new();

    for resource_logs in request.resource_logs {
        let Some(resource) = resource_logs.resource else {
            let count = resource_logs
                .scope_logs
                .iter()
                .map(|scope| scope.log_records.len() as i64)
                .sum::<i64>();

            rejected += count;

            *reasons.entry("missing-resource".into()).or_default() += count;

            continue;
        };

        for log in resource_logs
            .scope_logs
            .into_iter()
            .flat_map(|scope| scope.log_records)
        {
            match decode_record(&resource, &log) {
                Ok(record) => {
                    if let Some(record) = policy.admit(record)
                        && let Err(error) = store.try_append(record)
                    {
                        rejected += 1;

                        *reasons.entry(format!("store:{error:?}")).or_default() += 1;
                    }
                }
                Err(error) => {
                    rejected += 1;

                    *reasons.entry(format!("decode:{error:?}")).or_default() += 1;
                }
            }
        }
    }

    ExportLogsServiceResponse {
        partial_success: (rejected > 0).then(|| ExportLogsPartialSuccess {
            rejected_log_records: rejected,
            error_message: reasons
                .into_iter()
                .map(|(reason, count)| format!("{reason}={count}"))
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

fn otlp_response(response: ExportLogsServiceResponse) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-protobuf")],
        response.encode_to_vec(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use blt_model::{
        ContainerId, Enrichment, KubernetesIdentity, LogRecord, RecordIntegrity, Severity,
        StreamFileDescriptor, WorkloadIdentity, WorkloadResolution,
    };
    use blt_otel::{ExportConfig, ExportContext, OtlpExporter, export_request};
    use blt_store::Selector;

    use super::*;

    fn policy() -> Policy {
        Policy::compile(&CollectorConfig::default(), &Default::default()).unwrap()
    }

    fn record() -> LogRecord {
        LogRecord {
            observed_at: "2026-08-13T18:10:52.313Z".parse().unwrap(),
            sampling_seed: 7,
            stream: StreamFileDescriptor::Stderr,
            enrichment: Enrichment::Enriched(KubernetesIdentity {
                node: "worker-1".into(),
                namespace: "flux-system".into(),
                pod_name: "controller-abc".into(),
                pod_uid: "pod-uid".into(),
                container_name: "manager".into(),
                container_id: ContainerId {
                    runtime: "cri-o".into(),
                    id: "a".repeat(64),
                },
                workload: WorkloadResolution::Resolved(WorkloadIdentity {
                    api_version: "apps/v1".into(),
                    kind: "Deployment".into(),
                    name: "controller".into(),
                    uid: "deployment-uid".into(),
                }),
            }),
            first_timestamp_ns: 1,
            last_timestamp_ns: 2,
            first_operation_id: 3,
            last_operation_id: 4,
            bytes: Arc::from(&b"{\"level\":\"error\"}\n"[..]),
            integrity: RecordIntegrity::default(),
            sample_percent: 100,
            severity: Severity::Error,
        }
    }

    fn context() -> ExportContext {
        ExportContext {
            cluster_uid: Some("cluster-uid".into()),
            agent_instance: "worker-1/agent".into(),
            agent_version: "0.1.0".into(),
        }
    }

    #[tokio::test]

    async fn valid_otlp_record_enters_collector_store() {
        let store = Arc::new(LogStore::new(StoreConfig {
            max_memory: 32 * 1024 * 1024,
            max_logs: 10,
            retention: std::time::Duration::from_secs(60),
        }));

        let response = ingest(export_request(&record(), &context()), &store, &policy());

        assert!(response.partial_success.is_none());

        let replay = store
            .query(&Selector::Namespace("flux-system".into()))
            .unwrap();

        assert_eq!(replay.len(), 1);

        assert_eq!(store.stats().accepted_records, 1);
    }

    #[tokio::test]

    async fn malformed_record_is_partial_success_not_whole_request_failure() {
        let store = Arc::new(LogStore::new(StoreConfig {
            max_memory: 32 * 1024 * 1024,
            max_logs: 10,
            retention: std::time::Duration::from_secs(60),
        }));

        let mut request = export_request(&record(), &context());

        let log = &mut request.resource_logs[0].scope_logs[0].log_records[0];

        log.attributes
            .retain(|attribute| attribute.key != "blt.mapping.version");

        let response = ingest(request, &store, &policy());

        assert_eq!(response.partial_success.unwrap().rejected_log_records, 1);

        assert_eq!(store.stats().accepted_records, 0);
    }

    #[test]

    fn config_keeps_retention_and_request_bounds_explicit() {
        let mut config: CollectorConfig = serde_yaml::from_str(
            "listen: 127.0.0.1:4318\nmax_request_bytes: 2097152\nstore:\n  max_memory: 32MiB\n  max_logs: 99\n  retention: 15m\n",
        )
        .unwrap();

        assert!(config.validate().is_ok());
    }

    #[tokio::test]

    async fn collector_owns_filter_sampling_and_catcher_policy() {
        let mut config: CollectorConfig = serde_yaml::from_str(
            "sampling: {percent: 100}\n\
             filters: {namespaces: {include: [flux-system]}}\n\
             events: {failed: {type: error, message: Reconciliation failed}}\n\
             event_catchers: [{regex: leader.changed, event: failed, emitters: [stdout]}]\n\
             event_emitters: {stdout: {}}\n",
        )
        .unwrap();

        config.validate().unwrap();

        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

        let senders = std::collections::BTreeMap::from([(
            "stdout".to_owned(),
            blt_emitter::EmitterSender::new(sender),
        )]);

        let policy = Policy::compile(&config, &senders).unwrap();

        let mut matching = record();

        matching.bytes = Arc::from(&b"{\"error\":\"leader changed\"}\n"[..]);

        let admitted = policy.admit(matching).unwrap();

        let caught = receiver.try_recv().unwrap();

        assert!(Arc::ptr_eq(&admitted, &caught.record));

        let mut excluded = record();

        if let Enrichment::Enriched(identity) = &mut excluded.enrichment {
            identity.namespace = "default".into();
        }

        assert!(policy.admit(excluded).is_none());

        assert_eq!(policy.stats().filtered, 1);

        assert_eq!(policy.stats().caught, 1);

        config.sampling.percent = 0;

        let policy = Policy::compile(&config, &senders).unwrap();

        assert!(policy.admit(record()).is_none());

        assert_eq!(policy.stats().sampled, 1);
    }

    #[tokio::test]

    async fn agent_shutdown_flush_reaches_collector_replay() {
        let store = Arc::new(LogStore::new(StoreConfig {
            max_memory: 32 * 1024 * 1024,
            max_logs: 10,
            retention: std::time::Duration::from_secs(60),
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();

        let (stop, stopped) = tokio::sync::oneshot::channel();

        let server_store = store.clone();

        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(server_store, Arc::new(policy()), DEFAULT_MAX_REQUEST_BYTES),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
        });

        let exporter = OtlpExporter::spawn(
            ExportConfig {
                endpoint: format!("http://{address}/v1/logs"),
                queue_records: 8,
                queue_bytes: 1024 * 1024,
                batch_records: 8,
                batch_bytes: 1024 * 1024,
                flush_interval: std::time::Duration::from_secs(60),
                retry_max_elapsed: std::time::Duration::from_secs(1),
                request_timeout: std::time::Duration::from_secs(1),
            },
            context(),
        );

        exporter.sender().try_send(&record()).unwrap();

        // The long timer proves shutdown, rather than the periodic tick, flushes.
        let stats = exporter.shutdown().await;

        assert_eq!(stats.exported_records, 1);

        let replay = store
            .query(&Selector::Namespace("flux-system".into()))
            .unwrap();

        assert_eq!(replay.len(), 1);

        stop.send(()).unwrap();

        server.await.unwrap();
    }
}
