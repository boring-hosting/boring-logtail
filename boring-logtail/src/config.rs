// SPDX-License-Identifier: GPL-3.0-or-later

//! Small node-agent configuration for collector delivery.

use std::{fs, path::Path, time::Duration};

use anyhow::Context as _;
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub collector: CollectorExportConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorExportConfig {
    pub endpoint: String,
    pub queue_records: usize,
    pub queue_bytes: usize,
    pub batch_records: usize,
    pub batch_bytes: usize,
    pub flush_interval_ms: u64,
    pub retry_max_elapsed_ms: u64,
    pub request_timeout_ms: u64,
}

impl Default for CollectorExportConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://boring-collector:4318/v1/logs".to_owned(),
            queue_records: 1_024,
            queue_bytes: 8 * 1024 * 1024,
            batch_records: 512,
            batch_bytes: 1024 * 1024,
            flush_interval_ms: 1_000,
            retry_max_elapsed_ms: 30_000,
            request_timeout_ms: 10_000,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut config = match path {
            Some(path) => serde_yaml::from_slice(
                &fs::read(path)
                    .with_context(|| format!("read node-agent config {}", path.display()))?,
            )
            .with_context(|| format!("parse node-agent config {}", path.display()))?,
            None => Self::default(),
        };

        config.validate()?;

        Ok(config)
    }

    pub fn validate(&mut self) -> anyhow::Result<()> {
        self.collector.endpoint = self.collector.endpoint.trim().to_owned();

        blt_otel::ExportConfig {
            endpoint: self.collector.endpoint.clone(),
            queue_records: self.collector.queue_records,
            queue_bytes: self.collector.queue_bytes,
            batch_records: self.collector.batch_records,
            batch_bytes: self.collector.batch_bytes,
            flush_interval: Duration::from_millis(self.collector.flush_interval_ms),
            retry_max_elapsed: Duration::from_millis(self.collector.retry_max_elapsed_ms),
            request_timeout: Duration::from_millis(self.collector.request_timeout_ms),
        }
        .validate()
        .map_err(anyhow::Error::msg)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]

    fn defaults_describe_delivery() {
        let config = Config::load(None).unwrap();

        assert!(config.collector.endpoint.ends_with("/v1/logs"));
    }

    #[test]

    fn rejects_old_collector_side_policy() {
        for yaml in [
            "sampling: {percent: 10}\n",
            "store: {retention: 1h}\n",
            "filters: {}\n",
            "events: {}\n",
            "event_emitters: {}\n",
        ] {
            assert!(
                serde_yaml::from_str::<Config>(yaml).is_err(),
                "accepted {yaml}"
            );
        }
    }
}
