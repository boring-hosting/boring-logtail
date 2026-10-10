// SPDX-License-Identifier: GPL-3.0-or-later

use std::{future::Future, sync::Arc};

use blt_store::{ExportError, LogSink};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Server};

#[derive(Clone)]
struct OtlpLogsService {
    sink: Arc<dyn LogSink>,
}

#[tonic::async_trait]
impl LogsService for OtlpLogsService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        self.sink
            .export(request.into_inner())
            .await
            .map(Response::new)
            .map_err(export_status)
    }
}

pub async fn serve(
    listener: TcpListener,
    sink: Arc<dyn LogSink>,
    max_request_bytes: usize,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    let service = LogsServiceServer::new(OtlpLogsService { sink })
        .max_decoding_message_size(max_request_bytes);
    Server::builder()
        .add_service(service)
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
}
