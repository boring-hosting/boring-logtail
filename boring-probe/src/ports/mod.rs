// SPDX-License-Identifier: GPL-3.0-or-later

//! Application-owned boundaries for reading and publishing resource metrics.

mod metrics_sink;
mod stats_source;

pub use metrics_sink::{MetricsPushError, MetricsSink};
pub use stats_source::{
    ContainerStats, CpuStats, MemoryStats, NodeStats, PersistentVolumeClaimReference, PodReference,
    PodStats, StatsReadError, StatsSnapshot, StatsSource, VolumeStats,
};
