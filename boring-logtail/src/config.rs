// SPDX-License-Identifier: GPL-3.0-or-later

//! Small, immutable process configuration.

use crate::{event::EventType, sampling::SamplePercent, store::StoreConfig};
use anyhow::{Context as _, bail};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
};

pub const MAX_INCLUDED_NAMESPACES: usize = 64;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub sampling: SamplingConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub filters: FilterConfig,
    #[serde(default)]
    pub events: BTreeMap<String, EventConfig>,
    #[serde(default)]
    pub event_catchers: Vec<EventCatcherConfig>,
    #[serde(default)]
    pub event_emitters: EventEmittersConfig,
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
    pub discord: Option<DiscordEmitterConfig>,
    pub stdout: Option<StdoutEmitterConfig>,
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
        SamplePercent::try_from(self.sampling.percent)?;
        self.store.validate().map_err(anyhow::Error::msg)?;
        if let Some(filter) = &mut self.filters.namespaces {
            let include = &mut filter.include;
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
        for (name, event) in &self.events {
            if !valid_event_name(name) {
                bail!("invalid event name {name:?}");
            }
            if event.message.trim().is_empty() {
                bail!("event {name:?} message must not be empty");
            }
        }
        for catcher in &self.event_catchers {
            if catcher.regex.is_empty() {
                bail!("event catcher regex must not be empty");
            }
            if !self.events.contains_key(&catcher.event) {
                bail!("event catcher references unknown event {:?}", catcher.event);
            }
            if catcher.emitters.is_empty() {
                bail!("event catcher for {:?} has no emitters", catcher.event);
            }
            let mut unique = HashSet::new();
            for emitter in &catcher.emitters {
                if !unique.insert(emitter) {
                    bail!(
                        "event catcher for {:?} repeats emitter {emitter:?}",
                        catcher.event
                    );
                }
                let configured = match emitter.as_str() {
                    "discord" => self.event_emitters.discord.is_some(),
                    "stdout" => self.event_emitters.stdout.is_some(),
                    _ => false,
                };
                if !configured {
                    bail!("event catcher references unknown emitter {emitter:?}");
                }
            }
        }
        regex::bytes::RegexSet::new(
            self.event_catchers
                .iter()
                .map(|catcher| catcher.regex.as_str()),
        )
        .context("compile event catcher regex")?;
        if let Some(discord) = &mut self.event_emitters.discord {
            discord.channel_id = discord.channel_id.trim().to_owned();
            discord.secret_from_env = discord.secret_from_env.trim().to_owned();
            if discord.channel_id.is_empty() {
                bail!("discord channel_id must not be empty");
            }
            if discord.secret_from_env.is_empty() {
                bail!("discord secret_from_env must not be empty");
            }
        }
        Ok(())
    }
}

fn valid_event_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
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
        assert_eq!(config.sampling.percent, 100);
        assert_eq!(config.store.max_logs, 500);
        assert!(config.filters.namespaces.is_none());
        assert_eq!(parse("{}\n").unwrap().sampling.percent, 100);
    }

    #[test]
    fn trims_and_accepts_exact_namespaces() {
        let config = parse("sampling: { percent: 7 }\nfilters:\n  namespaces:\n    include: [' game-servers ', kube-system]\n").unwrap();
        let include = &config.filters.namespaces.as_ref().unwrap().include;
        assert_eq!(include, &["game-servers", "kube-system"]);
    }

    #[test]
    fn rejects_bad_contracts() {
        for yaml in [
            "version: 1\n",
            "sampling: { percent: 101 }\n",
            "store: { max_logs: 0 }\n",
            "store: { max_memory: 1MiB }\n",
            "store: { max_workloads: 12 }\n",
            "store: { max_record_bytes: 64KiB }\n",
            "filters: {kubernetes-namespace: {include: [foo]}}\n",
            "filters: {namespaces: {include: []}}\n",
            "filters: {namespaces: {include: [foo, foo]}}\n",
            "filters: {namespaces: {include: ['Bad_Name']}}\n",
            "event_emitters: {stdout: {nope: true}}\n",
            "events: {joined: {type: info, message: hi}}\nevent_catchers: [{regex: hi, event: joined, emitters: [stdout]}]\n",
        ] {
            assert!(parse(yaml).is_err(), "accepted {yaml}");
        }
        let names = (0..65)
            .map(|n| format!("n{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            parse(&format!(
                "filters: {{namespaces: {{include: [{names}]}}}}\n"
            ))
            .is_err()
        );
    }
}
