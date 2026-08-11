// SPDX-License-Identifier: GPL-3.0-or-later

//! Versioned, immutable process configuration.

use crate::{sampling::SamplePercent, store::StoreConfig};
use anyhow::{Context as _, bail};
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path};

pub const MAX_INCLUDED_NAMESPACES: usize = 64;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    #[serde(default)]
    pub sampling: SamplingConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub filters: Vec<FilterConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingConfig {
    #[serde(default = "default_percent")]
    pub percent: u8,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self { percent: 100 }
    }
}

const fn default_percent() -> u8 {
    100
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FilterConfig {
    KubernetesNamespace { include: Vec<String> },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            sampling: SamplingConfig::default(),
            store: StoreConfig::default(),
            filters: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };

        let bytes = fs::read(path).with_context(|| format!("read config {}", path.display()))?;
        let mut config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&mut self) -> anyhow::Result<()> {
        if self.version != 1 {
            bail!("unsupported config version {}", self.version);
        }
        SamplePercent::try_from(self.sampling.percent)?;
        self.store.validate().map_err(anyhow::Error::msg)?;
        for filter in &mut self.filters {
            let FilterConfig::KubernetesNamespace { include } = filter;
            if include.is_empty() {
                bail!("kubernetes namespace include must not be empty");
            }
            if include.len() > MAX_INCLUDED_NAMESPACES {
                bail!("kubernetes namespace include exceeds {MAX_INCLUDED_NAMESPACES}");
            }
            let mut unique = HashSet::new();
            for namespace in include {
                *namespace = namespace.trim().to_owned();
                if !valid_dns_label(namespace) {
                    bail!("invalid Kubernetes namespace {namespace:?}");
                }
                if !unique.insert(namespace.clone()) {
                    bail!("duplicate Kubernetes namespace {namespace}");
                }
            }
        }
        Ok(())
    }
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> anyhow::Result<Config> {
        let mut config: Config = serde_yaml::from_str(value)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn defaults_are_admit_all_and_full_sample() {
        let config = Config::load(None).unwrap();
        assert!(config.filters.is_empty());
        assert_eq!(config.sampling.percent, 100);
        assert_eq!(config.store.max_logs, 500);
        assert_eq!(config.store.max_record_bytes, 64 * 1024);
        assert_eq!(parse("version: 1\n").unwrap().sampling.percent, 100);
    }

    #[test]
    fn trims_and_accepts_exact_namespaces() {
        let config = parse("version: 1\nsampling: { percent: 7 }\nfilters:\n- type: kubernetes-namespace\n  include: [' game-servers ', kube-system]\n").unwrap();
        let FilterConfig::KubernetesNamespace { include } = &config.filters[0];
        assert_eq!(include, &["game-servers", "kube-system"]);
    }

    #[test]
    fn rejects_bad_contracts() {
        for yaml in [
            "version: 2\n",
            "version: 1\nsampling: { percent: 101 }\n",
            "version: 1\nstore: { max_logs: 0 }\n",
            "version: 1\nstore: { max_memory: 1MiB }\n",
            "version: 1\nfilters: [{type: nope}]\n",
            "version: 1\nfilters: [{type: kubernetes-namespace, include: []}]\n",
            "version: 1\nfilters: [{type: kubernetes-namespace, include: [foo, foo]}]\n",
            "version: 1\nfilters: [{type: kubernetes-namespace, include: ['Bad_Name']}]\n",
        ] {
            assert!(parse(yaml).is_err(), "accepted {yaml}");
        }
        let names = (0..65)
            .map(|n| format!("n{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            parse(&format!(
                "version: 1\nfilters: [{{type: kubernetes-namespace, include: [{names}]}}]\n"
            ))
            .is_err()
        );
    }
}
