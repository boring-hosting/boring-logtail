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
    snapshot_pods: Gauge,
    snapshot_containers: Gauge,
    last_success_timestamp: Gauge,
    reconciles: Family<Labels, Counter>,
    kubelet_read_duration: Histogram,
    prometheus_push_duration: Histogram,
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let snapshot_pods = Gauge::default();
        let snapshot_containers = Gauge::default();
        let last_success_timestamp = Gauge::default();
        let reconciles = Family::default();
        let kubelet_read_duration = Histogram::new([0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]);
        let prometheus_push_duration = Histogram::new([0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]);
        registry.register(
            prometheus_name("boring.probe.snapshot.pods"),
            "Pods in the latest kubelet snapshot",
            snapshot_pods.clone(),
        );
        registry.register(
            prometheus_name("boring.probe.snapshot.containers"),
            "Containers in the latest kubelet snapshot",
            snapshot_containers.clone(),
        );
        registry.register(
            prometheus_name("boring.probe.reconcile.last.success.timestamp"),
            "Unix time of the last successful reconcile",
            last_success_timestamp.clone(),
        );
        registry.register(
            prometheus_name("boring.probe.reconciles"),
            "Probe reconciles by result",
            reconciles.clone(),
        );
        registry.register(
            prometheus_name("boring.probe.kubelet.read.duration"),
            "Kubelet snapshot read duration",
            kubelet_read_duration.clone(),
        );
        registry.register(
            prometheus_name("boring.probe.prometheus.push.duration"),
            "Prometheus remote-write duration",
            prometheus_push_duration.clone(),
        );
        Self(Arc::new(Inner {
            registry,
            alive: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            snapshot_pods,
            snapshot_containers,
            last_success_timestamp,
            reconciles,
            kubelet_read_duration,
            prometheus_push_duration,
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
    pub fn snapshot(&self, pods: usize, containers: usize) {
        self.0.snapshot_pods.set(to_i64(pods));
        self.0.snapshot_containers.set(to_i64(containers));
    }
    pub fn result(&self, result: &'static str) {
        self.0.reconciles.get_or_create(&[("result", result)]).inc();
    }
    pub fn read_duration(&self, seconds: f64) {
        self.0.kubelet_read_duration.observe(seconds);
    }
    pub fn push_duration(&self, seconds: f64) {
        self.0.prometheus_push_duration.observe(seconds);
    }
    pub fn successful(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.0
            .last_success_timestamp
            .set(i64::try_from(now).unwrap_or(i64::MAX));
        self.result("success");
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
    async fn exposes_fixed_results_snapshot_gauges_and_lifecycle() {
        let metrics = RuntimeMetrics::new();
        metrics.snapshot(2, 5);
        metrics.result("read_error");
        metrics.read_duration(0.1);
        let text = metrics.encode();
        assert!(text.contains("boring_probe_snapshot_pods 2"));
        assert!(text.contains("boring_probe_reconciles_total{result=\"read_error\"} 1"));
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
