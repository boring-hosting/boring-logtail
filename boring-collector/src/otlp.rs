// SPDX-License-Identifier: GPL-3.0-or-later

use std::{future::Future, sync::Arc};

use crate::{
    ports::{ExportError, LogSink},
    runtime_metrics::RuntimeMetrics,
};
use tonic_reflection::server::Builder as ReflectionBuilder;

use opentelemetry_proto::tonic::{
    collector::{
        logs::v1::{
            ExportLogsServiceRequest, ExportLogsServiceResponse,
            logs_service_server::{LogsService, LogsServiceServer},
        },
        metrics::v1::{
            ExportMetricsServiceRequest, ExportMetricsServiceResponse,
            metrics_service_server::{MetricsService, MetricsServiceServer},
        },
    },
    metrics::v1::metric,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Server};

const OTLP_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("otlp_descriptor");

#[derive(Clone)]
struct OtlpLogsService {
    sink: Arc<dyn LogSink>,
    metrics: RuntimeMetrics,
}

#[derive(Clone)]
struct OtlpMetricsService {}

#[tonic::async_trait]
impl MetricsService for OtlpMetricsService {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        let request = request.into_inner();

        let data_points: usize = request
            .resource_metrics
            .iter()
            .flat_map(|resource| &resource.scope_metrics)
            .flat_map(|scope| &scope.metrics)
            .map(|metric| match &metric.data {
                Some(metric::Data::Gauge(gauge)) => gauge.data_points.len(),
                Some(metric::Data::Sum(sum)) => sum.data_points.len(),
                Some(metric::Data::Histogram(histogram)) => histogram.data_points.len(),
                Some(metric::Data::ExponentialHistogram(histogram)) => histogram.data_points.len(),
                Some(metric::Data::Summary(summary)) => summary.data_points.len(),
                None => 0,
            })
            .sum();

        println!("received {data_points} metric data points");

        let metrics_resp = ExportMetricsServiceResponse::default();

        let resp = Response::new(metrics_resp);
        Ok(resp)
    }
}

#[tonic::async_trait]
impl LogsService for OtlpLogsService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let request = request.into_inner();
        let records = request
            .resource_logs
            .iter()
            .flat_map(|resource| &resource.scope_logs)
            .map(|scope| scope.log_records.len())
            .sum();
        match self.sink.export(request).await {
            Ok(response) => {
                self.metrics.otlp_result("accepted", records);
                Ok(Response::new(response))
            }
            Err(error) => {
                let result = if error.is_retryable() {
                    "retryable"
                } else {
                    "rejected"
                };
                self.metrics.otlp_result(result, records);
                Err(export_status(error))
            }
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    log_sink: Arc<dyn LogSink>,
    max_request_bytes: usize,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    serve_observed(
        listener,
        log_sink,
        max_request_bytes,
        RuntimeMetrics::new(),
        shutdown,
    )
    .await
}

pub async fn serve_observed(
    listener: TcpListener,
    log_sink: Arc<dyn LogSink>,
    max_request_bytes: usize,
    metrics: RuntimeMetrics,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    let service = LogsServiceServer::new(OtlpLogsService {
        sink: log_sink,
        metrics,
    })
    .max_decoding_message_size(max_request_bytes);

    // TODO: evaluate wtf the options are.
    let metrics_service = MetricsServiceServer::new(OtlpMetricsService {})
        .max_decoding_message_size(max_request_bytes);

    let reflection = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(OTLP_DESCRIPTOR_SET)
        .build_v1()
        .expect("OTLP reflection descriptors are valid");

    Server::builder()
        .add_service(service)
        .add_service(metrics_service)
        .add_service(reflection)
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}

fn export_status(error: ExportError) -> Status {
    match error {
        ExportError::Retryable(message) => Status::unavailable(message),
        ExportError::Rejected(message) => Status::invalid_argument(message),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use opentelemetry_proto::tonic::{
        collector::logs::v1::{
            ExportLogsServiceRequest, ExportLogsServiceResponse,
            logs_service_client::LogsServiceClient,
        },
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    };
    use tonic_reflection::pb::v1::{
        ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
        server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
    };

    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        records: Mutex<Vec<usize>>,
    }

    #[tonic::async_trait]
    impl LogSink for RecordingSink {
        async fn export(
            &self,
            batch: ExportLogsServiceRequest,
        ) -> Result<ExportLogsServiceResponse, ExportError> {
            let count = batch
                .resource_logs
                .iter()
                .flat_map(|resource| &resource.scope_logs)
                .map(|scope| scope.log_records.len())
                .sum();
            self.records.lock().unwrap().push(count);
            Ok(ExportLogsServiceResponse::default())
        }
    }

    #[tokio::test]
    async fn standard_otlp_client_crosses_one_bulk_sink_call() {
        let sink = Arc::new(RecordingSink::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let server_sink: Arc<dyn LogSink> = sink.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_sink, 1024 * 1024, async move {
                while stopped.changed().await.is_ok() {
                    if *stopped.borrow() {
                        break;
                    }
                }
            })
            .await
        });
        let mut client = LogsServiceClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord::default(), LogRecord::default()],
                    ..ScopeLogs::default()
                }],
                ..ResourceLogs::default()
            }],
        };

        client.export(request).await.unwrap();
        assert_eq!(*sink.records.lock().unwrap(), vec![2]);

        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reflection_lists_otlp_logs_and_metrics() {
        let sink: Arc<dyn LogSink> = Arc::new(RecordingSink::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(async move {
            serve(listener, sink, 1024 * 1024, async move {
                while stopped.changed().await.is_ok() {
                    if *stopped.borrow() {
                        break;
                    }
                }
            })
            .await
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = ServerReflectionClient::new(channel);
        let requests = tokio_stream::iter([ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::ListServices(String::new())),
        }]);
        let mut responses = client
            .server_reflection_info(requests)
            .await
            .unwrap()
            .into_inner();
        let response = responses.message().await.unwrap().unwrap();
        let MessageResponse::ListServicesResponse(services) = response.message_response.unwrap()
        else {
            panic!("reflection did not return a service list");
        };
        let names: Vec<_> = services
            .service
            .into_iter()
            .map(|service| service.name)
            .collect();

        assert!(names.iter().any(|name| name.ends_with("LogsService")));
        assert!(names.iter().any(|name| name.ends_with("MetricsService")));

        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
