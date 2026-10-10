// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage ports shared by collector ingress and trusted log readers.

use async_trait::async_trait;
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};

use crate::ExportError;

/// Bulk write port. One call is one complete OTLP export request.
#[async_trait]
trait _MetricsSink: Send + Sync {
    async fn export(
        &self,
        batch: ExportMetricsServiceRequest,
    ) -> Result<ExportMetricsServiceResponse, ExportError>;
}
