// SPDX-License-Identifier: GPL-3.0-or-later

//! Loki-backed implementation of the collector log storage ports.

use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_core::Stream;
use futures_util::StreamExt as _;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use prost::Message as _;
use reqwest::{StatusCode, Url, header};
use serde::Deserialize;
use tokio::{sync::Semaphore, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::{connect_async, tungstenite::Message as WebSocketMessage};

use crate::{
    ExportError, LogEntry, LogReader, LogSink, PortLogStream, ReadError, ReadRequest, ReadSelector,
};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_CONCURRENT_EXPORTS: usize = 16;
const DEFAULT_HANDOFF_BUFFER: usize = 1_024;

#[derive(Clone, Debug)]
pub struct LokiConfig {
    pub endpoint: String,
    pub request_timeout: Duration,
    pub max_concurrent_exports: usize,
    pub handoff_buffer: usize,
}

impl LokiConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            request_timeout: Duration::from_secs(10),
            max_concurrent_exports: DEFAULT_MAX_CONCURRENT_EXPORTS,
            handoff_buffer: DEFAULT_HANDOFF_BUFFER,
        }
    }

    fn validate(&self) -> Result<Url, &'static str> {
        let endpoint = Url::parse(self.endpoint.trim()).map_err(|_| "invalid Loki endpoint")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.cannot_be_a_base()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("Loki endpoint must be an HTTP base URL without query or fragment");
        }
        if self.request_timeout.is_zero() {
            return Err("Loki request timeout must be non-zero");
        }
        if self.max_concurrent_exports == 0 {
            return Err("Loki concurrent export limit must be non-zero");
        }
        if self.handoff_buffer == 0 {
            return Err("Loki handoff buffer must be non-zero");
        }

        Ok(endpoint)
    }
}

pub struct LokiLogStore {
    endpoint: Url,
    client: reqwest::Client,
    export_slots: Semaphore,
    handoff_buffer: usize,
}

impl LokiLogStore {
    pub fn new(config: LokiConfig) -> Result<Self, &'static str> {
        let endpoint = config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| "failed to build Loki HTTP client")?;

        Ok(Self {
            endpoint,
            client,
            export_slots: Semaphore::new(config.max_concurrent_exports),
            handoff_buffer: config.handoff_buffer,
        })
    }

    fn url(&self, path: &str) -> Url {
        self.endpoint.join(path).expect("static Loki path is valid")
    }

    async fn query_retained(
        &self,
        request: &ReadRequest,
        end_exclusive: Option<u64>,
    ) -> Result<Vec<LogEntry>, ReadError> {
        if request.tail_lines == 0 {
            return Ok(Vec::new());
        }

        let mut url = self.url("/loki/api/v1/query_range");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("query", &logql(&request.selector));
            query.append_pair("limit", &request.tail_lines.to_string());
            query.append_pair("direction", "backward");
            if let Some(end) = end_exclusive {
                query.append_pair("end", &end.to_string());
            }
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| ReadError::Unavailable(format!("query Loki: {error}")))?;
        if !response.status().is_success() {
            return Err(ReadError::Unavailable(format!(
                "Loki query returned HTTP {}",
                response.status()
            )));
        }

        let response: QueryResponse = response
            .json()
            .await
            .map_err(|error| ReadError::Protocol(format!("decode Loki query response: {error}")))?;
        if response.status != "success" || response.data.result_type != "streams" {
            return Err(ReadError::Protocol(
                "Loki returned a non-stream query response".into(),
            ));
        }

        let mut entries = response
            .data
            .result
            .into_iter()
            .flat_map(entries_from_stream)
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.timestamp_unix_nano);

        let skip = entries.len().saturating_sub(request.tail_lines as usize);
        Ok(entries.into_iter().skip(skip).collect())
    }

    async fn connect_tail(
        &self,
        selector: &ReadSelector,
        start: u64,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        ReadError,
    > {
        let mut url = self.url("/loki/api/v1/tail");
        url.set_scheme(match url.scheme() {
            "https" => "wss",
            _ => "ws",
        })
        .map_err(|_| ReadError::Protocol("invalid Loki WebSocket URL".into()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("query", &logql(selector));
            query.append_pair("start", &start.to_string());
        }

        connect_async(url.as_str())
            .await
            .map(|(stream, _)| stream)
            .map_err(|error| ReadError::Unavailable(format!("connect Loki tail: {error}")))
    }
}

#[async_trait]
impl LogSink for LokiLogStore {
    async fn export(
        &self,
        batch: ExportLogsServiceRequest,
    ) -> Result<ExportLogsServiceResponse, ExportError> {
        let _slot = self
            .export_slots
            .try_acquire()
            .map_err(|_| ExportError::retryable("Loki export concurrency is full"))?;
        let response = self
            .client
            .post(self.url("/otlp/v1/logs"))
            .header(header::CONTENT_TYPE, "application/x-protobuf")
            .body(batch.encode_to_vec())
            .send()
            .await
            .map_err(|error| ExportError::retryable(format!("export to Loki: {error}")))?;
        let status = response.status();

        if !status.is_success() {
            let message = format!("Loki export returned HTTP {status}");
            return if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                Err(ExportError::retryable(message))
            } else {
                Err(ExportError::rejected(message))
            };
        }

        if response
            .content_length()
            .is_some_and(|size| size as usize > MAX_RESPONSE_BYTES)
        {
            return Err(ExportError::retryable("Loki export response is too large"));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| ExportError::retryable(format!("read Loki response: {error}")))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ExportError::retryable("Loki export response is too large"));
        }
        if body.is_empty() {
            return Ok(ExportLogsServiceResponse::default());
        }

        ExportLogsServiceResponse::decode(body)
            .map_err(|error| ExportError::retryable(format!("decode Loki response: {error}")))
    }
}

#[async_trait]
impl LogReader for LokiLogStore {
    async fn stream(&self, request: ReadRequest) -> Result<PortLogStream, ReadError> {
        if !request.follow {
            return Ok(Box::pin(tokio_stream::iter(
                self.query_retained(&request, None)
                    .await?
                    .into_iter()
                    .map(Ok),
            )));
        }

        let tail_start = unix_nanos()?;
        let socket = self.connect_tail(&request.selector, tail_start).await?;
        let handoff = unix_nanos()?;
        let (sender, receiver) = tokio::sync::mpsc::channel(self.handoff_buffer);
        let task = tokio::spawn(read_tail(socket, sender, handoff));
        let retained = match self
            .query_retained(&request, Some(handoff.saturating_add(1)))
            .await
        {
            Ok(entries) => entries,
            Err(error) => {
                task.abort();
                return Err(error);
            }
        };
        let retained = tokio_stream::iter(retained.into_iter().map(Ok));
        let live = AbortOnDropStream {
            receiver: ReceiverStream::new(receiver),
            task,
        };

        Ok(Box::pin(retained.chain(live)))
    }
}

fn unix_nanos() -> Result<u64, ReadError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReadError::Protocol("system clock is before the Unix epoch".into()))?
        .as_nanos();
    u64::try_from(nanos).map_err(|_| ReadError::Protocol("system clock is out of range".into()))
}

async fn read_tail<S>(
    mut socket: tokio_tungstenite::WebSocketStream<S>,
    sender: tokio::sync::mpsc::Sender<Result<LogEntry, ReadError>>,
    after: u64,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(message) = socket.next().await {
        let result = match message {
            Ok(WebSocketMessage::Text(text)) => tail_entries(text.as_str(), after),
            Ok(WebSocketMessage::Binary(bytes)) => std::str::from_utf8(&bytes)
                .map_err(|error| ReadError::Protocol(format!("Loki tail is not UTF-8: {error}")))
                .and_then(|text| tail_entries(text, after)),
            Ok(WebSocketMessage::Close(_)) => {
                let _ = sender
                    .send(Err(ReadError::Unavailable("Loki tail closed".into())))
                    .await;
                return;
            }
            Ok(WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_)) => continue,
            Ok(_) => continue,
            Err(error) => Err(ReadError::Unavailable(format!("read Loki tail: {error}"))),
        };

        let entries = match result {
            Ok(entries) => entries,
            Err(error) => {
                let _ = sender.send(Err(error)).await;
                return;
            }
        };
        for entry in entries {
            match sender.try_send(Ok(entry)) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    let _ = sender.send(Err(ReadError::Lagged(1))).await;
                    return;
                }
            }
        }
    }

    let _ = sender
        .send(Err(ReadError::Unavailable("Loki tail ended".into())))
        .await;
}

fn tail_entries(text: &str, after: u64) -> Result<Vec<LogEntry>, ReadError> {
    let response: TailResponse = serde_json::from_str(text)
        .map_err(|error| ReadError::Protocol(format!("decode Loki tail response: {error}")))?;
    if !response.dropped_entries.is_empty() {
        return Err(ReadError::Lagged(response.dropped_entries.len() as u64));
    }

    response
        .streams
        .into_iter()
        .flat_map(entries_from_stream)
        .collect::<Result<Vec<_>, _>>()
        .map(|entries| {
            entries
                .into_iter()
                .filter(|entry| entry.timestamp_unix_nano > after)
                .collect()
        })
}

fn entries_from_stream(stream: LokiStream) -> impl Iterator<Item = Result<LogEntry, ReadError>> {
    let namespace = label(&stream.stream, &["k8s_namespace_name", "service_namespace"]);
    let workload = label(&stream.stream, &["service_name"]);
    let pod = label(&stream.stream, &["k8s_pod_name"]);
    let workload_kind = workload_kind(&stream.stream);

    stream.values.into_iter().map(move |value| {
        if value.len() < 2 {
            return Err(ReadError::Protocol(
                "Loki stream entry has fewer than two values".into(),
            ));
        }
        let timestamp_unix_nano = value[0]
            .parse()
            .map_err(|error| ReadError::Protocol(format!("invalid Loki timestamp: {error}")))?;
        Ok(LogEntry {
            timestamp_unix_nano,
            line: value[1].as_bytes().to_vec(),
            namespace: namespace.clone(),
            workload_kind: workload_kind.clone(),
            workload: workload.clone(),
            pod: pod.clone(),
        })
    })
}

fn label(labels: &HashMap<String, String>, candidates: &[&str]) -> String {
    candidates
        .iter()
        .find_map(|name| labels.get(*name))
        .cloned()
        .unwrap_or_default()
}

fn workload_kind(labels: &HashMap<String, String>) -> String {
    [
        ("Deployment", "k8s_deployment_name"),
        ("StatefulSet", "k8s_statefulset_name"),
        ("DaemonSet", "k8s_daemonset_name"),
        ("Job", "k8s_job_name"),
        ("CronJob", "k8s_cronjob_name"),
        ("ReplicaSet", "k8s_replicaset_name"),
    ]
    .into_iter()
    .find_map(|(kind, name)| labels.contains_key(name).then(|| kind.to_owned()))
    .unwrap_or_else(|| "Pod".into())
}

fn logql(selector: &ReadSelector) -> String {
    let (label, value) = match selector {
        ReadSelector::Namespace(value) => ("k8s_namespace_name", value),
        ReadSelector::Workload(value) => ("service_name", value),
        ReadSelector::Pod(value) => ("k8s_pod_name", value),
    };
    let value = serde_json::to_string(value).expect("a Rust string always serializes");
    format!("{{{label}={value}}}")
}

#[derive(Deserialize)]
struct QueryResponse {
    status: String,
    data: QueryData,
}

#[derive(Deserialize)]
struct QueryData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<LokiStream>,
}

#[derive(Deserialize)]
struct LokiStream {
    stream: HashMap<String, String>,
    values: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct TailResponse {
    #[serde(default)]
    streams: Vec<LokiStream>,
    #[serde(default)]
    dropped_entries: Vec<serde_json::Value>,
}

struct AbortOnDropStream {
    receiver: ReceiverStream<Result<LogEntry, ReadError>>,
    task: JoinHandle<()>,
}

impl Stream for AbortOnDropStream {
    type Item = Result<LogEntry, ReadError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(context)
    }
}

impl Drop for AbortOnDropStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        body::Bytes,
        extract::{State, WebSocketUpgrade, ws::Message},
        http::StatusCode as AxumStatus,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use opentelemetry_proto::tonic::{
        collector::logs::v1::ExportLogsServiceRequest,
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    };
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Default)]
    struct FixtureState {
        export_calls: AtomicUsize,
        exported_records: Mutex<Vec<usize>>,
    }

    async fn export_fixture(State(state): State<Arc<FixtureState>>, body: Bytes) -> Response {
        state.export_calls.fetch_add(1, Ordering::Relaxed);
        let request = ExportLogsServiceRequest::decode(body).unwrap();
        let count = request
            .resource_logs
            .iter()
            .flat_map(|resource| &resource.scope_logs)
            .map(|scope| scope.log_records.len())
            .sum();
        state.exported_records.lock().unwrap().push(count);
        (
            AxumStatus::OK,
            ExportLogsServiceResponse::default().encode_to_vec(),
        )
            .into_response()
    }

    async fn query_fixture() -> Json<serde_json::Value> {
        Json(json!({
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [{
                    "stream": {
                        "k8s_namespace_name": "games",
                        "k8s_pod_name": "valheim-0",
                        "k8s_statefulset_name": "valheim",
                        "service_name": "valheim"
                    },
                    "values": [["2", "old-two"], ["1", "old-one"]]
                }]
            }
        }))
    }

    async fn tail_fixture(upgrade: WebSocketUpgrade) -> Response {
        upgrade.on_upgrade(|mut socket| async move {
            let timestamp = unix_nanos().unwrap().saturating_add(1_000_000_000);
            let response = json!({
                "streams": [{
                    "stream": {
                        "k8s_namespace_name": "games",
                        "k8s_pod_name": "valheim-0",
                        "k8s_statefulset_name": "valheim",
                        "service_name": "valheim"
                    },
                    "values": [[timestamp.to_string(), "live"]]
                }],
                "dropped_entries": []
            });
            let _ = socket
                .send(Message::Text(response.to_string().into()))
                .await;
        })
    }

    async fn fixture() -> (LokiLogStore, Arc<FixtureState>, JoinHandle<()>) {
        let state = Arc::new(FixtureState::default());
        let app = Router::new()
            .route("/otlp/v1/logs", post(export_fixture))
            .route("/loki/api/v1/query_range", get(query_fixture))
            .route("/loki/api/v1/tail", get(tail_fixture))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = LokiLogStore::new(LokiConfig::new(format!("http://{address}"))).unwrap();
        (store, state, task)
    }

    fn bulk_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: (0..2)
                .map(|_| ResourceLogs {
                    scope_logs: (0..2)
                        .map(|_| ScopeLogs {
                            log_records: vec![LogRecord::default(), LogRecord::default()],
                            ..ScopeLogs::default()
                        })
                        .collect(),
                    ..ResourceLogs::default()
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn one_otlp_batch_is_one_loki_request() {
        let (store, state, task) = fixture().await;

        store.export(bulk_request()).await.unwrap();

        assert_eq!(state.export_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*state.exported_records.lock().unwrap(), vec![8]);
        task.abort();
    }

    #[tokio::test]
    async fn finite_read_is_chronological_and_bounded() {
        let (store, _, task) = fixture().await;
        let mut stream = store
            .stream(ReadRequest::new(ReadSelector::Workload("valheim".into()), false, 1).unwrap())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().line, b"old-two");
        assert!(stream.next().await.is_none());
        task.abort();
    }

    #[tokio::test]
    async fn following_yields_history_before_live_entries() {
        let (store, _, task) = fixture().await;
        let mut stream = store
            .stream(ReadRequest::new(ReadSelector::Workload("valheim".into()), true, 2).unwrap())
            .await
            .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().line, b"old-one");
        assert_eq!(stream.next().await.unwrap().unwrap().line, b"old-two");
        assert_eq!(stream.next().await.unwrap().unwrap().line, b"live");
        task.abort();
    }

    #[test]
    fn logql_escapes_selector_values() {
        assert_eq!(
            logql(&ReadSelector::Pod("a\"b\\c".into())),
            r#"{k8s_pod_name="a\"b\\c"}"#
        );
    }
}
