// SPDX-License-Identifier: GPL-3.0-or-later

//! Resource-statistics source port and application-owned snapshot.

use std::{error::Error, fmt, time::SystemTime};

use async_trait::async_trait;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatsSnapshot {
    pub node: NodeStats,
    pub pods: Vec<PodStats>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStats {
    pub name: String,
    pub start_time: SystemTime,
    pub cpu: Option<CpuStats>,
    pub memory: Option<MemoryStats>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodStats {
    pub reference: PodReference,
    pub start_time: SystemTime,
    pub cpu: Option<CpuStats>,
    pub memory: Option<MemoryStats>,
    pub volumes: Vec<VolumeStats>,
    pub containers: Vec<ContainerStats>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodReference {
    pub name: String,
    pub namespace: String,
    pub uid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerStats {
    pub name: String,
    pub start_time: SystemTime,
    pub cpu: Option<CpuStats>,
    pub memory: Option<MemoryStats>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeStats {
    pub name: String,
    pub persistent_volume_claim: Option<PersistentVolumeClaimReference>,
    pub observed_at: SystemTime,
    pub available_bytes: Option<u64>,
    pub capacity_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub inodes_free: Option<u64>,
    pub inodes: Option<u64>,
    pub inodes_used: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentVolumeClaimReference {
    pub name: String,
    pub namespace: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuStats {
    pub observed_at: SystemTime,
    pub usage_nano_cores: Option<u64>,
    pub usage_core_nano_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryStats {
    pub observed_at: SystemTime,
    pub available_bytes: Option<u64>,
    pub usage_bytes: Option<u64>,
    pub working_set_bytes: Option<u64>,
    pub rss_bytes: Option<u64>,
    pub page_faults: Option<u64>,
    pub major_page_faults: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatsReadError {
    Unavailable(String),
    InvalidSnapshot(String),
}

impl fmt::Display for StatsReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "statistics unavailable: {message}"),
            Self::InvalidSnapshot(message) => {
                write!(formatter, "invalid statistics snapshot: {message}")
            }
        }
    }
}

impl Error for StatsReadError {}

#[async_trait]
pub trait StatsSource: Send + Sync {
    async fn snapshot(&self) -> Result<StatsSnapshot, StatsReadError>;
}
