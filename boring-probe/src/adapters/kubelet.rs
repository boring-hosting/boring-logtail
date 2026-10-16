// SPDX-License-Identifier: GPL-3.0-or-later

//! Kubelet Summary API adapter.

use std::{error::Error, fmt, path::PathBuf, time::SystemTime};

use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    config::KubeletConfig,
    ports::{
        ContainerStats, CpuStats, MemoryStats, NodeStats, PersistentVolumeClaimReference,
        PodReference, PodStats, StatsReadError, StatsSnapshot, StatsSource, VolumeStats,
    },
};

const SERVICE_ACCOUNT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

pub struct KubeletStatsAdapter {
    client: reqwest::Client,
    endpoint: String,
    token_file: PathBuf,
    timeout: std::time::Duration,
}

impl KubeletStatsAdapter {
    pub fn new(config: &KubeletConfig) -> Result<Self, KubeletAdapterBuildError> {
        Self::with_service_account(config, SERVICE_ACCOUNT_CA, SERVICE_ACCOUNT_TOKEN)
    }

    fn with_service_account(
        config: &KubeletConfig,
        ca_file: impl Into<PathBuf>,
        token_file: impl Into<PathBuf>,
    ) -> Result<Self, KubeletAdapterBuildError> {
        let ca_file = ca_file.into();
        let certificate = std::fs::read(&ca_file)
            .map_err(|error| build_error(format!("read {}: {error}", ca_file.display())))?;
        let certificate = reqwest::Certificate::from_pem(&certificate)
            .map_err(|error| build_error(format!("decode {}: {error}", ca_file.display())))?;
        let client = reqwest::Client::builder()
            .add_root_certificate(certificate)
            .build()
            .map_err(|error| build_error(format!("build kubelet HTTP client: {error}")))?;

        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
            token_file: token_file.into(),
            timeout: config.timeout,
        })
    }
}

#[async_trait]
impl StatsSource for KubeletStatsAdapter {
    async fn snapshot(&self) -> Result<StatsSnapshot, StatsReadError> {
        let token = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|error| unavailable(format!("read service-account token: {error}")))?;
        let response = self
            .client
            .get(&self.endpoint)
            .bearer_auth(token.trim())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|error| unavailable(format!("request kubelet summary: {error}")))?;

        if !response.status().is_success() {
            return Err(unavailable(format!(
                "kubelet summary returned HTTP {}",
                response.status()
            )));
        }

        let body = response
            .bytes()
            .await
            .map_err(|error| unavailable(format!("read kubelet summary: {error}")))?;
        decode_summary(&body)
    }
}

#[derive(Debug)]
pub struct KubeletAdapterBuildError(String);

impl fmt::Display for KubeletAdapterBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for KubeletAdapterBuildError {}

fn build_error(message: String) -> KubeletAdapterBuildError {
    KubeletAdapterBuildError(message)
}

fn unavailable(message: String) -> StatsReadError {
    StatsReadError::Unavailable(message)
}

fn decode_summary(bytes: &[u8]) -> Result<StatsSnapshot, StatsReadError> {
    let summary: WireSummary = serde_json::from_slice(bytes)
        .map_err(|error| StatsReadError::InvalidSnapshot(error.to_string()))?;
    summary.try_into()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireSummary {
    node: WireNodeStats,
    #[serde(default)]
    pods: Vec<WirePodStats>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireNodeStats {
    node_name: String,
    start_time: String,
    cpu: Option<WireCpuStats>,
    memory: Option<WireMemoryStats>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WirePodStats {
    pod_ref: WirePodReference,
    start_time: String,
    cpu: Option<WireCpuStats>,
    memory: Option<WireMemoryStats>,
    #[serde(default, rename = "volume")]
    volumes: Vec<WireVolumeStats>,
    #[serde(default)]
    containers: Vec<WireContainerStats>,
}

#[derive(Deserialize)]
struct WirePodReference {
    name: String,
    namespace: String,
    uid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireContainerStats {
    name: String,
    start_time: String,
    cpu: Option<WireCpuStats>,
    memory: Option<WireMemoryStats>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCpuStats {
    time: String,
    usage_nano_cores: Option<u64>,
    usage_core_nano_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireMemoryStats {
    time: String,
    available_bytes: Option<u64>,
    usage_bytes: Option<u64>,
    working_set_bytes: Option<u64>,
    rss_bytes: Option<u64>,
    page_faults: Option<u64>,
    major_page_faults: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireVolumeStats {
    time: String,
    name: String,
    pvc_ref: Option<WirePersistentVolumeClaimReference>,
    available_bytes: Option<u64>,
    capacity_bytes: Option<u64>,
    used_bytes: Option<u64>,
    inodes_free: Option<u64>,
    inodes: Option<u64>,
    inodes_used: Option<u64>,
}

#[derive(Deserialize)]
struct WirePersistentVolumeClaimReference {
    name: String,
    namespace: String,
}

impl TryFrom<WireSummary> for StatsSnapshot {
    type Error = StatsReadError;

    fn try_from(summary: WireSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            node: summary.node.try_into()?,
            pods: summary
                .pods
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<WireNodeStats> for NodeStats {
    type Error = StatsReadError;

    fn try_from(stats: WireNodeStats) -> Result<Self, Self::Error> {
        Ok(Self {
            name: stats.node_name,
            start_time: parse_time(&stats.start_time)?,
            cpu: stats.cpu.map(TryInto::try_into).transpose()?,
            memory: stats.memory.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<WirePodStats> for PodStats {
    type Error = StatsReadError;

    fn try_from(stats: WirePodStats) -> Result<Self, Self::Error> {
        Ok(Self {
            reference: PodReference {
                name: stats.pod_ref.name,
                namespace: stats.pod_ref.namespace,
                uid: stats.pod_ref.uid,
            },
            start_time: parse_time(&stats.start_time)?,
            cpu: stats.cpu.map(TryInto::try_into).transpose()?,
            memory: stats.memory.map(TryInto::try_into).transpose()?,
            volumes: stats
                .volumes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            containers: stats
                .containers
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<WireVolumeStats> for VolumeStats {
    type Error = StatsReadError;

    fn try_from(stats: WireVolumeStats) -> Result<Self, Self::Error> {
        Ok(Self {
            name: stats.name,
            persistent_volume_claim: stats.pvc_ref.map(|reference| {
                PersistentVolumeClaimReference {
                    name: reference.name,
                    namespace: reference.namespace,
                }
            }),
            observed_at: parse_time(&stats.time)?,
            available_bytes: stats.available_bytes,
            capacity_bytes: stats.capacity_bytes,
            used_bytes: stats.used_bytes,
            inodes_free: stats.inodes_free,
            inodes: stats.inodes,
            inodes_used: stats.inodes_used,
        })
    }
}

impl TryFrom<WireContainerStats> for ContainerStats {
    type Error = StatsReadError;

    fn try_from(stats: WireContainerStats) -> Result<Self, Self::Error> {
        Ok(Self {
            name: stats.name,
            start_time: parse_time(&stats.start_time)?,
            cpu: stats.cpu.map(TryInto::try_into).transpose()?,
            memory: stats.memory.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<WireCpuStats> for CpuStats {
    type Error = StatsReadError;

    fn try_from(stats: WireCpuStats) -> Result<Self, Self::Error> {
        Ok(Self {
            observed_at: parse_time(&stats.time)?,
            usage_nano_cores: stats.usage_nano_cores,
            usage_core_nano_seconds: stats.usage_core_nano_seconds,
        })
    }
}

impl TryFrom<WireMemoryStats> for MemoryStats {
    type Error = StatsReadError;

    fn try_from(stats: WireMemoryStats) -> Result<Self, Self::Error> {
        Ok(Self {
            observed_at: parse_time(&stats.time)?,
            available_bytes: stats.available_bytes,
            usage_bytes: stats.usage_bytes,
            working_set_bytes: stats.working_set_bytes,
            rss_bytes: stats.rss_bytes,
            page_faults: stats.page_faults,
            major_page_faults: stats.major_page_faults,
        })
    }
}

fn parse_time(value: &str) -> Result<SystemTime, StatsReadError> {
    value
        .parse::<jiff::Timestamp>()
        .map(SystemTime::from)
        .map_err(|error| StatsReadError::InvalidSnapshot(format!("invalid timestamp: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_selected_summary_fields() {
        let snapshot = decode_summary(
            br#"{
              "node": {
                "nodeName": "worker-a",
                "startTime": "2026-10-11T10:00:00Z",
                "cpu": {"time":"2026-10-11T10:01:00Z","usageNanoCores":250000000,"usageCoreNanoSeconds":9000000000},
                "memory": {"time":"2026-10-11T10:01:00Z","workingSetBytes":1024}
              },
              "pods": [{
                "podRef":{"name":"game-0","namespace":"games","uid":"pod-1"},
                "startTime":"2026-10-11T10:00:10Z",
                "volume":[{
                  "time":"2026-10-11T10:01:00Z",
                  "availableBytes":4096,
                  "capacityBytes":8192,
                  "usedBytes":3072,
                  "inodesFree":90,
                  "inodes":100,
                  "inodesUsed":10,
                  "name":"data",
                  "pvcRef":{"name":"game-data","namespace":"games"}
                }],
                "containers":[{
                  "name":"server",
                  "startTime":"2026-10-11T10:00:11Z",
                  "memory":{"time":"2026-10-11T10:01:00Z","usageBytes":2048}
                }]
              }]
            }"#,
        )
        .unwrap();

        assert_eq!(snapshot.node.name, "worker-a");
        assert_eq!(
            snapshot.node.cpu.unwrap().usage_nano_cores,
            Some(250_000_000)
        );
        assert_eq!(snapshot.pods[0].reference.uid, "pod-1");
        assert_eq!(snapshot.pods[0].volumes[0].name, "data");
        assert_eq!(snapshot.pods[0].volumes[0].capacity_bytes, Some(8192));
        assert_eq!(
            snapshot.pods[0].volumes[0]
                .persistent_volume_claim
                .as_ref()
                .unwrap()
                .name,
            "game-data"
        );
        assert_eq!(
            snapshot.pods[0].containers[0]
                .memory
                .as_ref()
                .unwrap()
                .usage_bytes,
            Some(2048)
        );
    }

    #[test]
    fn preserves_missing_measurements() {
        let snapshot = decode_summary(
            br#"{
              "node":{"nodeName":"worker-a","startTime":"2026-10-11T10:00:00Z"},
              "pods":[]
            }"#,
        )
        .unwrap();
        assert_eq!(snapshot.node.cpu, None);
        assert_eq!(snapshot.node.memory, None);
    }
}
