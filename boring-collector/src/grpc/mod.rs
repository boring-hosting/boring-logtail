// SPDX-License-Identifier: GPL-3.0-or-later

mod stream_logs;

use std::{future::Future, sync::Arc};

use blt_store::LogStore;
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
    store: Arc<LogStore>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .add_service(LogServiceServer::new(LogService::new(store)))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use blt_model::{
        ContainerId, Enrichment, KubernetesIdentity, LogRecord, RecordIntegrity, Severity,
        StreamFileDescriptor, WorkloadIdentity, WorkloadResolution,
    };
    use blt_store::StoreConfig;

    use super::{
        proto::{
            StreamLogsRequest, log_service_client::LogServiceClient,
            stream_logs_request::Selector as ProtoSelector,
        },
        *,
    };

    fn record(
        namespace: &str,
        workload_name: &str,
        workload_uid: &str,
        pod_name: &str,
        body: &'static [u8],
    ) -> LogRecord {
        LogRecord {
            observed_at: "2026-08-15T06:30:00.123456789Z".parse().unwrap(),
            sampling_seed: 1,
            stream: StreamFileDescriptor::Stdout,
            enrichment: Enrichment::Enriched(KubernetesIdentity {
                node: "node-1".into(),
                namespace: namespace.into(),
                pod_name: pod_name.into(),
                pod_uid: format!("{pod_name}-uid"),
                container_name: "game".into(),
                container_id: ContainerId {
                    runtime: "containerd".into(),
                    id: "a".repeat(64),
                },
                workload: WorkloadResolution::Resolved(WorkloadIdentity {
                    api_version: "apps/v1".into(),
                    kind: "StatefulSet".into(),
                    name: workload_name.into(),
                    uid: workload_uid.into(),
                }),
            }),
            first_timestamp_ns: 0,
            last_timestamp_ns: 0,
            first_operation_id: 0,
            last_operation_id: 0,
            bytes: body.into(),
            integrity: RecordIntegrity::default(),
            sample_percent: 100,
            severity: Severity::Unknown,
        }
    }

    #[tokio::test]
    async fn real_client_gets_retained_tail_then_matching_inserts() {
        let store = Arc::new(LogStore::new(StoreConfig::default()));
        store
            .try_append(record(
                "games",
                "factorio-owner-server",
                "workload-1",
                "factorio-0",
                b"old-one\n",
            ))
            .unwrap();
        store
            .try_append(record(
                "other",
                "noise",
                "workload-2",
                "noise-0",
                b"ignore\n",
            ))
            .unwrap();
        store
            .try_append(record(
                "games",
                "factorio-owner-server",
                "workload-1",
                "factorio-1",
                b"old-two\n",
            ))
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let server_store = Arc::clone(&store);
        let server = tokio::spawn(async move {
            serve(listener, server_store, async move {
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
                selector: Some(ProtoSelector::Workload("factorio-owner-server".into())),
                follow: true,
                tail_lines: 1,
            })
            .await
            .unwrap()
            .into_inner();

        let retained = stream.message().await.unwrap().unwrap();
        assert_eq!(retained.sequence, 3);
        assert_eq!(retained.line, b"old-two\n");
        assert_eq!(retained.namespace, "games");
        assert_eq!(retained.workload_kind, "StatefulSet");
        assert_eq!(retained.workload, "factorio-owner-server");
        assert_eq!(retained.pod, "factorio-1");
        assert_eq!(retained.timestamp.unwrap().nanos, 123_456_789);

        store
            .try_append(record(
                "games",
                "different",
                "workload-3",
                "different-0",
                b"ignore-live\n",
            ))
            .unwrap();
        store
            .try_append(record(
                "games",
                "factorio-owner-server",
                "workload-1",
                "factorio-2",
                b"new\xffline\n",
            ))
            .unwrap();

        let live = stream.message().await.unwrap().unwrap();
        assert_eq!(live.sequence, 5);
        assert_eq!(live.line, b"new\xffline\n");
        drop(stream);

        let mut finite = client
            .stream_logs(StreamLogsRequest {
                selector: Some(ProtoSelector::Pod("factorio-2".into())),
                follow: false,
                tail_lines: 1,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(finite.message().await.unwrap().unwrap().sequence, 5);
        assert!(finite.message().await.unwrap().is_none());

        drop(finite);
        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
