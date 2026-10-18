// SPDX-License-Identifier: GPL-3.0-or-later

//! Strict deployment configuration for the probe.

use std::{error::Error, fmt, net::SocketAddr, time::Duration};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_http_listen")]
    pub http_listen: SocketAddr,
    pub runtime: RuntimeConfig,
    pub kubelet: KubeletConfig,
    pub collector: CollectorConfig,
}

fn default_http_listen() -> SocketAddr {
    "0.0.0.0:9090".parse().expect("static address is valid")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KubeletConfig {
    pub endpoint: String,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub endpoint: String,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Config {
    pub fn resolve_node_name(&mut self, node_name: Option<&str>) -> Result<(), ConfigError> {
        const TOKEN: &str = "{node_name}";
        let occurrences = self.kubelet.endpoint.matches(TOKEN).count();
        if occurrences == 0 {
            return Ok(());
        }
        if occurrences != 1 {
            return Err(ConfigError(
                "kubelet.endpoint must contain at most one {node_name}",
            ));
        }

        let node_name = node_name
            .filter(|name| !name.is_empty())
            .ok_or(ConfigError("BORING_PROBE_NODE_NAME is required"))?;
        self.kubelet.endpoint = self.kubelet.endpoint.replace(TOKEN, node_name);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.runtime.interval.is_zero()
            || self.kubelet.timeout.is_zero()
            || self.collector.timeout.is_zero()
        {
            return Err(ConfigError("durations must be non-zero"));
        }

        validate_endpoint("kubelet.endpoint", &self.kubelet.endpoint)?;
        validate_endpoint("collector.endpoint", &self.collector.endpoint)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ConfigError(&'static str);

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid probe configuration: {}", self.0)
    }
}

impl Error for ConfigError {}

fn validate_endpoint(name: &'static str, endpoint: &str) -> Result<(), ConfigError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| ConfigError(name))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConfigError(name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
http_listen: 0.0.0.0:9090
runtime:
  interval: 15s
kubelet:
  endpoint: https://node-name:10250/stats/summary
  timeout: 5s
collector:
  endpoint: http://boring-collector:4317
  timeout: 5s
"#;

    #[test]
    fn parses_the_configured_boundaries() {
        let config: Config = serde_yaml::from_str(YAML).unwrap();
        config.validate().unwrap();
        assert_eq!(config.runtime.interval, Duration::from_secs(15));
        assert_eq!(config.kubelet.timeout, Duration::from_secs(5));
        assert_eq!(config.collector.timeout, Duration::from_secs(5));
        assert_eq!(config.http_listen.port(), 9090);
    }

    #[test]
    fn defaults_the_runtime_http_listener_for_rolling_upgrades() {
        let config: Config =
            serde_yaml::from_str(&YAML.replace("http_listen: 0.0.0.0:9090\n", "")).unwrap();
        assert_eq!(config.http_listen, default_http_listen());
    }

    #[test]
    fn rejects_unknown_keys_and_zero_durations() {
        let zero: Config =
            serde_yaml::from_str(&YAML.replace("interval: 15s", "interval: 0s")).unwrap();
        assert!(zero.validate().is_err());
        assert!(serde_yaml::from_str::<Config>(&format!("{YAML}\nnope: true\n")).is_err());
    }

    #[test]
    fn resolves_exactly_one_node_name_token_before_validation() {
        let mut config: Config =
            serde_yaml::from_str(&YAML.replace("node-name", "{node_name}")).unwrap();

        assert!(config.resolve_node_name(None).is_err());
        config.resolve_node_name(Some("worker-a")).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.kubelet.endpoint,
            "https://worker-a:10250/stats/summary"
        );
    }

    #[test]
    fn rejects_more_than_one_node_name_token() {
        let mut config: Config = serde_yaml::from_str(&YAML.replace(
            "https://node-name:10250/stats/summary",
            "https://{node_name}:10250/{node_name}",
        ))
        .unwrap();

        assert!(config.resolve_node_name(Some("worker-a")).is_err());
    }
}
