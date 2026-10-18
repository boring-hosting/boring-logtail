// SPDX-License-Identifier: GPL-3.0-or-later

//! Prometheus-backed implementation of the collector metrics storage port.

use std::time::Duration;

use async_trait::async_trait;
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use prost::Message as _;
use reqwest::{StatusCode, Url, header::CONTENT_TYPE};

use crate::ports::{ExportError, MetricsSink};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
#[derive(Clone, Debug)]
pub struct PrometheusConfig {
    pub otlp_endpoint: String,
    pub request_timeout: Duration,
}

impl PrometheusConfig {
    pub fn new(otlp_endpoint: impl Into<String>) -> Self {
        Self {
            otlp_endpoint: otlp_endpoint.into(),
            request_timeout: Duration::from_secs(5),
        }
    }

    fn validate(&self) -> Result<Url, &'static str> {
        if self.request_timeout.is_zero() {
            return Err("Prometheus request timeout must be non-zero");
        }
        endpoint(&self.otlp_endpoint)
    }
}

pub struct PrometheusMetricsStore {
    otlp_endpoint: Url,
    client: reqwest::Client,
}

impl PrometheusMetricsStore {
    pub fn new(config: PrometheusConfig) -> Result<Self, &'static str> {
        let otlp_endpoint = config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| "failed to build Prometheus HTTP client")?;
        Ok(Self {
            otlp_endpoint,
            client,
        })
    }

    async fn response(
        response: reqwest::Response,
    ) -> Result<ExportMetricsServiceResponse, ExportError> {
        let status = response.status();
        if !status.is_success() {
            return Err(http_error(status));
        }
        if response
            .content_length()
            .is_some_and(|size| size as usize > MAX_RESPONSE_BYTES)
        {
            return Err(ExportError::retryable(
                "Prometheus OTLP response is too large",
            ));
        }
        let body = response.bytes().await.map_err(|error| {
            ExportError::retryable(format!("read Prometheus response: {error}"))
        })?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ExportError::retryable(
                "Prometheus OTLP response is too large",
            ));
        }
        if body.is_empty() {
            return Ok(ExportMetricsServiceResponse::default());
        }
        ExportMetricsServiceResponse::decode(body).map_err(|error| {
            ExportError::retryable(format!("decode Prometheus OTLP response: {error}"))
        })
    }
}

#[async_trait]
impl MetricsSink for PrometheusMetricsStore {
    async fn export(
        &self,
        batch: ExportMetricsServiceRequest,
    ) -> Result<ExportMetricsServiceResponse, ExportError> {
        let response = self
            .client
            .post(self.otlp_endpoint.clone())
            .header(CONTENT_TYPE, "application/x-protobuf")
            .body(batch.encode_to_vec())
            .send()
            .await
            .map_err(|error| ExportError::retryable(format!("export OTLP metrics: {error}")))?;
        Self::response(response).await
    }
}

fn endpoint(value: &str) -> Result<Url, &'static str> {
    let endpoint = Url::parse(value.trim()).map_err(|_| "invalid Prometheus endpoint")?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.cannot_be_a_base()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("Prometheus endpoint must be an HTTP URL without query or fragment");
    }
    Ok(endpoint)
}

fn http_error(status: StatusCode) -> ExportError {
    let message = format!("Prometheus returned HTTP {status}");
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        ExportError::retryable(message)
    } else {
        ExportError::rejected(message)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Router, body::Bytes, extract::State, http::HeaderMap, routing::post};
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;

    #[derive(Debug)]
    struct CapturedRequest {
        headers: HeaderMap,
        body: Bytes,
    }

    async fn capture_otlp(
        State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        requests
            .lock()
            .unwrap()
            .push(CapturedRequest { headers, body });
        StatusCode::NO_CONTENT
    }

    async fn serve(router: Router) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn forwards_otlp_without_changing_the_request() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            .route("/otlp", post(capture_otlp))
            .with_state(requests.clone());
        let (base, task) = serve(router).await;
        let store =
            PrometheusMetricsStore::new(PrometheusConfig::new(format!("{base}/otlp"))).unwrap();
        let batch = ExportMetricsServiceRequest::default();

        store.export(batch.clone()).await.unwrap();

        let captured = requests.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].body.as_ref(), batch.encode_to_vec());
        assert_eq!(captured[0].headers[CONTENT_TYPE], "application/x-protobuf");
        task.abort();
    }

    #[tokio::test]
    async fn classifies_prometheus_http_failures() {
        for (status, retryable) in [
            (StatusCode::TOO_MANY_REQUESTS, true),
            (StatusCode::INTERNAL_SERVER_ERROR, true),
            (StatusCode::BAD_REQUEST, false),
        ] {
            let router = Router::new().fallback(move || async move { status });
            let (base, task) = serve(router).await;
            let store =
                PrometheusMetricsStore::new(PrometheusConfig::new(format!("{base}/otlp"))).unwrap();

            let otlp = store
                .export(ExportMetricsServiceRequest::default())
                .await
                .unwrap_err();
            assert_eq!(otlp.is_retryable(), retryable);
            task.abort();
        }
    }
}
