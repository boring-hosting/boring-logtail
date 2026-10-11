// SPDX-License-Identifier: GPL-3.0-or-later

//! Metrics storage contract.

use async_trait::async_trait;
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};

use super::ExportError;

/// Bulk write port. One call is one complete OTLP export request.
#[async_trait]
pub trait MetricsSink: Send + Sync {
    async fn export(
        &self,
        batch: ExportMetricsServiceRequest,
    ) -> Result<ExportMetricsServiceResponse, ExportError>;
}
