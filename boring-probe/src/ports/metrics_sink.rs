// SPDX-License-Identifier: GPL-3.0-or-later

//! Resource-metrics sink port.

use std::{error::Error, fmt};

use async_trait::async_trait;

use super::StatsSnapshot;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricsPushError {
    Unavailable(String),
    Rejected(String),
}

impl fmt::Display for MetricsPushError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "metrics sink unavailable: {message}"),
            Self::Rejected(message) => write!(formatter, "metrics snapshot rejected: {message}"),
        }
    }
}

impl Error for MetricsPushError {}

#[async_trait]
pub trait MetricsSink: Send + Sync {
    async fn push(&self, snapshot: StatsSnapshot) -> Result<(), MetricsPushError>;
}
