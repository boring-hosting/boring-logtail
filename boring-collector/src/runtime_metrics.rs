// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded collector metrics and lifecycle HTTP endpoints.

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
    loki_inflight: Gauge,
    otlp_requests: Family<Labels, Counter>,
    otlp_records: Family<Labels, Counter>,
    otlp_metric_points: Family<Labels, Counter>,
    loki_saturation: Counter,
    loki_failures: Family<Labels, Counter>,
    loki_duration: Histogram,
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let loki_inflight = Gauge::default();
        let otlp_requests = Family::default();
        let otlp_records = Family::default();
        let otlp_metric_points = Family::default();
        let loki_saturation = Counter::default();
        let loki_failures = Family::default();
        let loki_duration = Histogram::new([0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0]);
        registry.register(
            prometheus_name("boring.collector.loki.exports.inflight"),
            "Current Loki export requests",
            loki_inflight.clone(),
        );
        registry.register(
            prometheus_name("boring.collector.otlp.requests"),
            "OTLP log requests by result",
            otlp_requests.clone(),
        );
        registry.register(
            prometheus_name("boring.collector.otlp.records"),
            "OTLP log records by result",
            otlp_records.clone(),
        );
        registry.register(
            prometheus_name("boring.collector.otlp.metric.points"),
            "OTLP metric data points by result",
            otlp_metric_points.clone(),
        );
        registry.register(
            prometheus_name("boring.collector.loki.saturation"),
            "Exports rejected by the Loki concurrency bound",
            loki_saturation.clone(),
        );
        registry.register(
            prometheus_name("boring.collector.loki.failures"),
            "Loki export failures by bounded class",
            loki_failures.clone(),
        );
        registry.register(
            prometheus_name("boring.collector.loki.export.duration"),
            "Loki export request duration",
            loki_duration.clone(),
        );
        Self(Arc::new(Inner {
            registry,
            alive: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            loki_inflight,
            otlp_requests,
            otlp_records,
            otlp_metric_points,
            loki_saturation,
            loki_failures,
            loki_duration,
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
    pub fn otlp_result(&self, result: &'static str, records: usize) {
        let labels = [("result", result)];
        self.0.otlp_requests.get_or_create(&labels).inc();
        self.0
            .otlp_records
            .get_or_create(&labels)
            .inc_by(records as u64);
    }
    pub fn otlp_metrics_result(&self, result: &'static str, points: usize) {
        self.0
            .otlp_metric_points
            .get_or_create(&[("result", result)])
            .inc_by(points as u64);
    }
    pub fn loki_started(&self) {
        self.0.loki_inflight.inc();
    }
    pub fn loki_finished(&self, seconds: f64) {
        self.0.loki_inflight.dec();
        self.0.loki_duration.observe(seconds);
    }
    pub fn loki_saturated(&self) {
        self.0.loki_saturation.inc();
    }
    pub fn loki_failed(&self, class: &'static str) {
        self.0
            .loki_failures
            .get_or_create(&[("class", class)])
            .inc();
    }
    fn encode(&self) -> String {
        let mut output = String::new();
        encode(&mut output, &self.0.registry).expect("String encoding cannot fail");
        output
    }
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
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
    async fn exposes_bounded_otlp_loki_and_lifecycle_contract() {
        let metrics = RuntimeMetrics::new();
        metrics.otlp_result("accepted", 3);
        metrics.otlp_metrics_result("accepted", 4);
        metrics.loki_saturated();
        metrics.loki_failed("retryable");
        metrics.loki_started();
        metrics.loki_finished(0.1);
        let text = metrics.encode();
        assert!(text.contains("boring_collector_otlp_records_total{result=\"accepted\"} 3"));
        assert!(text.contains("boring_collector_otlp_metric_points_total{result=\"accepted\"} 4"));
        assert!(text.contains("boring_collector_loki_exports_inflight 0"));
        assert!(text.len() < 64 * 1024);
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
