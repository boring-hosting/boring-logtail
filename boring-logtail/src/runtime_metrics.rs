// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded process metrics and lifecycle HTTP endpoints.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::Response,
    routing::get,
};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

type Labels = [(&'static str, &'static str); 1];

#[derive(Clone)]
pub struct RuntimeMetrics(Arc<Inner>);

struct Inner {
    registry: Registry,
    alive: AtomicBool,
    ready: AtomicBool,
    tracked_files: Gauge,
    buffered_file_bytes: Gauge,
    partial_lanes: Gauge,
    partial_bytes: Gauge,
    identities: Gauge,
    queue_records: Gauge,
    queue_bytes: Gauge,
    captured_records: Counter,
    exported_records: Counter,
    integrity_records: Family<Labels, Counter>,
    dropped_records: Family<Labels, Counter>,
    export_batches: Counter,
    export_retries: Counter,
    export_failures: Counter,
    watcher_overflows: Counter,
    reconcile_duration: Histogram,
    export_duration: Histogram,
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let tracked_files = Gauge::default();
        let buffered_file_bytes = Gauge::default();
        let partial_lanes = Gauge::default();
        let partial_bytes = Gauge::default();
        let identities = Gauge::default();
        let queue_records = Gauge::default();
        let queue_bytes = Gauge::default();
        let captured_records = Counter::default();
        let exported_records = Counter::default();
        let integrity_records = Family::default();
        let dropped_records = Family::default();
        let export_batches = Counter::default();
        let export_retries = Counter::default();
        let export_failures = Counter::default();
        let watcher_overflows = Counter::default();
        let reconcile_duration = Histogram::new([0.001, 0.005, 0.025, 0.1, 0.5, 2.0]);
        let export_duration = Histogram::new([0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0]);

        registry.register(
            prometheus_name("boring.logtail.cri.files"),
            "Tracked CRI files",
            tracked_files.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.cri.file.buffer.size"),
            "Bytes buffered while reading CRI files",
            buffered_file_bytes.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.cri.partial.lanes"),
            "Pending partial CRI record lanes",
            partial_lanes.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.cri.partial.buffer.size"),
            "Pending partial CRI record bytes",
            partial_bytes.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.k8s.identities"),
            "Known Kubernetes container identities",
            identities.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.otlp.queue.depth"),
            "Records held by the OTLP exporter",
            queue_records.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.otlp.queue.size"),
            "Bytes held by the OTLP exporter",
            queue_bytes.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.records.captured"),
            "Complete enriched records admitted for export",
            captured_records.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.records.exported"),
            "Records accepted by the collector",
            exported_records.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.records.integrity"),
            "Records carrying an integrity condition",
            integrity_records.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.records.dropped"),
            "Records dropped before collector acceptance",
            dropped_records.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.export.batches"),
            "OTLP batches accepted by the collector",
            export_batches.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.export.retries"),
            "OTLP export retries",
            export_retries.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.export.failures"),
            "OTLP batches that exhausted delivery",
            export_failures.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.watcher.overflows"),
            "Filesystem watcher channel overflows",
            watcher_overflows.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.reconcile.duration"),
            "CRI filesystem reconciliation duration",
            reconcile_duration.clone(),
        );
        registry.register(
            prometheus_name("boring.logtail.export.duration"),
            "OTLP batch export duration",
            export_duration.clone(),
        );

        Self(Arc::new(Inner {
            registry,
            alive: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            tracked_files,
            buffered_file_bytes,
            partial_lanes,
            partial_bytes,
            identities,
            queue_records,
            queue_bytes,
            captured_records,
            exported_records,
            integrity_records,
            dropped_records,
            export_batches,
            export_retries,
            export_failures,
            watcher_overflows,
            reconcile_duration,
            export_duration,
        }))
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/metrics", get(metrics))
            .route("/healthz", get(health))
            .route("/readyz", get(ready))
            .with_state(self.clone())
    }

    pub fn set_ready(&self, ready: bool) {
        self.0.ready.store(ready, Ordering::Release);
    }
    pub fn critical_task_stopped(&self) {
        self.0.ready.store(false, Ordering::Release);
        self.0.alive.store(false, Ordering::Release);
    }
    pub fn observe_capture_state(
        &self,
        files: usize,
        file_bytes: usize,
        lanes: usize,
        partial_bytes: usize,
        identities: usize,
    ) {
        self.0.tracked_files.set(to_i64(files));
        self.0.buffered_file_bytes.set(to_i64(file_bytes));
        self.0.partial_lanes.set(to_i64(lanes));
        self.0.partial_bytes.set(to_i64(partial_bytes));
        self.0.identities.set(to_i64(identities));
    }
    pub fn queue_add(&self, records: usize, bytes: usize) {
        self.0.queue_records.inc_by(to_i64(records));
        self.0.queue_bytes.inc_by(to_i64(bytes));
    }
    pub fn queue_remove(&self, records: usize, bytes: usize) {
        self.0.queue_records.dec_by(to_i64(records));
        self.0.queue_bytes.dec_by(to_i64(bytes));
    }
    pub fn captured(&self) {
        self.0.captured_records.inc();
    }
    pub fn exported(&self, records: u64) {
        self.0.exported_records.inc_by(records);
        self.0.export_batches.inc();
    }
    pub fn integrity(&self, reason: &'static str) {
        self.0
            .integrity_records
            .get_or_create(&[("reason", reason)])
            .inc();
    }
    pub fn dropped(&self, reason: &'static str) {
        self.0
            .dropped_records
            .get_or_create(&[("reason", reason)])
            .inc();
    }
    pub fn export_retry(&self) {
        self.0.export_retries.inc();
    }
    pub fn export_failure(&self) {
        self.0.export_failures.inc();
    }
    pub fn watcher_overflow(&self) {
        self.0.watcher_overflows.inc();
    }
    pub fn observe_reconcile(&self, seconds: f64) {
        self.0.reconcile_duration.observe(seconds);
    }
    pub fn observe_export(&self, seconds: f64) {
        self.0.export_duration.observe(seconds);
    }

    fn encode(&self) -> String {
        let mut output = String::new();
        encode(&mut output, &self.0.registry).expect("encoding metrics into a String cannot fail");
        output
    }
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn prometheus_name(otel_name: &str) -> String {
    otel_name.replace('.', "_")
}

async fn metrics(State(state): State<RuntimeMetrics>) -> Response {
    Response::builder()
        .header(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Body::from(state.encode()))
        .unwrap()
}
async fn health(State(state): State<RuntimeMetrics>) -> StatusCode {
    if state.0.alive.load(Ordering::Acquire) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn ready(State(state): State<RuntimeMetrics>) -> StatusCode {
    if state.0.alive.load(Ordering::Acquire) && state.0.ready.load(Ordering::Acquire) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exposes_bounded_metric_contract_and_lifecycle() {
        let metrics = RuntimeMetrics::new();
        metrics.observe_capture_state(2, 3, 4, 5, 6);
        metrics.dropped("queue_full");
        metrics.observe_export(0.1);
        let text = metrics.encode();
        assert!(text.contains("boring_logtail_cri_files 2"));
        assert!(text.contains("boring_logtail_records_dropped_total{reason=\"queue_full\"} 1"));
        assert!(text.contains("boring_logtail_export_duration_count 1"));
        assert!(text.len() < 64 * 1024);
        assert!(!metrics.0.ready.load(Ordering::Acquire));
        assert_eq!(
            ready(State(metrics.clone())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(health(State(metrics.clone())).await, StatusCode::NO_CONTENT);
        metrics.set_ready(true);
        assert_eq!(ready(State(metrics.clone())).await, StatusCode::NO_CONTENT);
        metrics.critical_task_stopped();
        assert_eq!(
            health(State(metrics)).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
