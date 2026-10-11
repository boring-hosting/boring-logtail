// SPDX-License-Identifier: GPL-3.0-or-later

mod stream_logs;

use std::{future::Future, sync::Arc};

use crate::ports::LogReader;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

pub use stream_logs::LogService;

pub mod proto {
    tonic::include_proto!("boring_logtail.v1");
}

use proto::log_service_server::LogServiceServer;

pub async fn serve(
    listener: TcpListener,
    reader: Arc<dyn LogReader>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .add_service(LogServiceServer::new(LogService::new(reader)))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::ports::{LogEntry, PortLogStream, ReadError, ReadRequest, ReadSelector};

    use super::{
        proto::{
            StreamLogsRequest, log_service_client::LogServiceClient,
            stream_logs_request::Selector as ProtoSelector,
        },
        *,
    };

    #[derive(Default)]
    struct MemoryReader {
        requests: Mutex<Vec<ReadRequest>>,
    }

    #[tonic::async_trait]
    impl LogReader for MemoryReader {
        async fn stream(&self, request: ReadRequest) -> Result<PortLogStream, ReadError> {
            self.requests.lock().unwrap().push(request);
            Ok(Box::pin(tokio_stream::iter([Ok(LogEntry {
                timestamp_unix_nano: 1_234_567_890,
                line: b"ready".to_vec(),
                namespace: "games".into(),
                workload_kind: "StatefulSet".into(),
                workload: "valheim".into(),
                pod: "valheim-0".into(),
            })])))
        }
    }

    #[tokio::test]
    async fn reader_protocol_is_stable_over_the_new_port() {
        let reader = Arc::new(MemoryReader::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let server_reader: Arc<dyn LogReader> = reader.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_reader, async move {
                while stopped.changed().await.is_ok() {
                    if *stopped.borrow() {
                        break;
                    }
                }
            })
            .await
        });
        let mut client = LogServiceClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        let mut stream = client
            .stream_logs(StreamLogsRequest {
                selector: Some(ProtoSelector::Workload("valheim".into())),
                follow: true,
                tail_lines: 100,
            })
            .await
            .unwrap()
            .into_inner();

        let response = stream.message().await.unwrap().unwrap();
        assert_eq!(response.line, b"ready");
        assert_eq!(response.sequence, 0);
        assert_eq!(response.timestamp.unwrap().nanos, 234_567_890);
        assert_eq!(
            *reader.requests.lock().unwrap(),
            vec![ReadRequest::new(ReadSelector::Workload("valheim".into()), true, 100).unwrap()]
        );

        drop(stream);
        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
