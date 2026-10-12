// SPDX-License-Identifier: GPL-3.0-or-later

//! Concrete adapters for the probe ports.

mod kubelet;
mod prometheus;

pub use kubelet::{KubeletAdapterBuildError, KubeletStatsAdapter};
pub use prometheus::PrometheusRemoteWriteAdapter;
