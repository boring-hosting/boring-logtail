// SPDX-License-Identifier: GPL-3.0-or-later

//! Stateless OTLP ingress and trusted log reads backed by storage ports.

pub mod grpc;
pub mod otlp;
pub mod ports;
pub mod runtime_metrics;
pub mod stores;

use std::{net::SocketAddr, path::Path, time::Duration};

use serde::Deserialize;
use stores::{LokiConfig, LokiLogStore, PrometheusConfig, PrometheusMetricsStore};

pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorConfig {
    pub otlp_grpc_listen: SocketAddr,
    pub reader_grpc_listen: SocketAddr,
    pub health_listen: SocketAddr,
    pub max_request_bytes: usize,
    pub loki: LokiStoreConfig,
    pub prometheus: PrometheusStoreConfig,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            otlp_grpc_listen: "0.0.0.0:4317".parse().expect("static address is valid"),
            reader_grpc_listen: "0.0.0.0:50051".parse().expect("static address is valid"),
            health_listen: "0.0.0.0:13133".parse().expect("static address is valid"),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            loki: LokiStoreConfig::default(),
            prometheus: PrometheusStoreConfig::default(),
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
        if self.max_request_bytes == 0 {
            anyhow::bail!("collector max_request_bytes must be non-zero");
        }
        self.loki.endpoint = self.loki.endpoint.trim().to_owned();
        self.prometheus.otlp_endpoint = self.prometheus.otlp_endpoint.trim().to_owned();
        LokiLogStore::new(self.loki_config())
            .map(|_| ())
            .map_err(anyhow::Error::msg)?;
        PrometheusMetricsStore::new(self.prometheus_config())
            .map(|_| ())
            .map_err(anyhow::Error::msg)
    }

    pub fn loki_config(&self) -> LokiConfig {
        let mut config = LokiConfig::new(self.loki.endpoint.clone());
        config.request_timeout = Duration::from_millis(self.loki.request_timeout_ms);
        config.max_concurrent_exports = self.loki.max_concurrent_exports;
        config.handoff_buffer = self.loki.handoff_buffer;
        config
    }

    pub fn prometheus_config(&self) -> PrometheusConfig {
        let mut config = PrometheusConfig::new(self.prometheus.otlp_endpoint.clone());
        config.request_timeout = Duration::from_millis(self.prometheus.request_timeout_ms);
        config
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrometheusStoreConfig {
    pub otlp_endpoint: String,
    pub request_timeout_ms: u64,
}

impl Default for PrometheusStoreConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint:
                "http://prometheus-server.observability.svc.cluster.local/api/v1/otlp/v1/metrics"
                    .into(),
            request_timeout_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LokiStoreConfig {
    pub endpoint: String,
    pub request_timeout_ms: u64,
    pub max_concurrent_exports: usize,
    pub handoff_buffer: usize,
}

impl Default for LokiStoreConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://loki.observability.svc.cluster.local:3100".into(),
            request_timeout_ms: 10_000,
            max_concurrent_exports: 16,
            handoff_buffer: 1_024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_small_collector_contract() {
        let config: CollectorConfig = serde_yaml::from_str(
            "otlp_grpc_listen: 127.0.0.1:4317\n\
             reader_grpc_listen: 127.0.0.1:50051\n\
             health_listen: 127.0.0.1:13133\n\
             max_request_bytes: 2097152\n\
             loki:\n  endpoint: http://loki:3100\n  max_concurrent_exports: 8\n\
             prometheus:\n  otlp_endpoint: http://prometheus:9090/api/v1/otlp/v1/metrics\n",
        )
        .unwrap();

        assert_eq!(config.otlp_grpc_listen.port(), 4317);
        assert_eq!(config.reader_grpc_listen.port(), 50051);
        assert_eq!(config.health_listen.port(), 13133);
        assert_eq!(config.loki.max_concurrent_exports, 8);
        assert_eq!(config.prometheus.request_timeout_ms, 5_000);
    }

    #[test]
    fn rejects_removed_memory_and_catcher_configuration() {
        for yaml in [
            "store: {retention: 1h}\n",
            "sampling: {percent: 10}\n",
            "filters: {}\n",
            "events: {}\n",
            "event_catchers: []\n",
            "event_emitters: {}\n",
        ] {
            assert!(serde_yaml::from_str::<CollectorConfig>(yaml).is_err());
        }
    }

    #[test]
    fn validates_prometheus_endpoints_and_timeout() {
        for yaml in [
            "prometheus: {otlp_endpoint: not-a-url}\n",
            "prometheus: {request_timeout_ms: 0}\n",
        ] {
            let mut config: CollectorConfig = serde_yaml::from_str(yaml).unwrap();
            assert!(config.validate().is_err());
        }
        assert!(
            serde_yaml::from_str::<CollectorConfig>("prometheus: {removed_option: true}\n")
                .is_err()
        );
    }
}
