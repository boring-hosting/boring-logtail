// SPDX-License-Identifier: GPL-3.0-or-later

//! Concrete adapters for the probe ports.

mod kubelet;
mod otlp;

pub use kubelet::{KubeletAdapterBuildError, KubeletStatsAdapter};
pub use otlp::OtlpMetricsAdapter;
