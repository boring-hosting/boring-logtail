// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;

use blt_model::{Enrichment, KubernetesIdentity, WorkloadResolution};
use blt_store::{LogStore, Selector, StoredRecord, StreamError};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::proto::{
    StreamLogsRequest, StreamLogsResponse, log_service_server::LogService as LogServiceRoute,
    stream_logs_request::Selector as ProtoSelector,
};

const STREAM_BUFFER: usize = 32;

#[derive(Clone)]
pub struct LogService {
    store: Arc<LogStore>,
}

impl LogService {
    pub fn new(store: Arc<LogStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl LogServiceRoute for LogService {
    type StreamLogsStream = ReceiverStream<Result<StreamLogsResponse, Status>>;

    async fn stream_logs(
        &self,
        request: Request<StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let request = request.into_inner();
        let selector = selector(request.selector)?;
        let tail_lines = request.tail_lines as usize;
        let (sender, receiver) = mpsc::channel(STREAM_BUFFER);

        if request.follow {
            let mut records = self
                .store
                .stream(selector, tail_lines)
                .map_err(stream_status)?;

            tokio::spawn(async move {
                loop {
                    let response = match records.recv().await {
                        Ok(record) => response(&record),
                        Err(error) => Err(stream_status(error)),
                    };
                    let terminal = response.is_err();

                    if sender.send(response).await.is_err() || terminal {
                        break;
                    }
                }
            });
        } else {
            let retained = self.store.query(&selector).map_err(stream_status)?;
            let skip = retained.len().saturating_sub(tail_lines);

            tokio::spawn(async move {
                for record in retained.into_iter().skip(skip) {
                    if sender.send(response(&record)).await.is_err() {
                        break;
                    }
                }
            });
        }

        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

fn selector(selector: Option<ProtoSelector>) -> Result<Selector, Status> {
    let selector = match selector {
        Some(ProtoSelector::Namespace(value)) => Selector::Namespace(value),
        Some(ProtoSelector::Workload(value)) => Selector::Workload(value),
        Some(ProtoSelector::Pod(value)) => Selector::Pod(value),
        None => return Err(Status::invalid_argument("one selector is required")),
    };

    let empty = match &selector {
        Selector::Namespace(value) | Selector::Workload(value) | Selector::Pod(value) => {
            value.is_empty()
        }
    };
    if empty {
        Err(Status::invalid_argument("selector must not be empty"))
    } else {
        Ok(selector)
    }
}

fn response(record: &StoredRecord) -> Result<StreamLogsResponse, Status> {
    let log = record.record();
    let identity = identity(log.enrichment()).ok_or_else(|| {
        Status::internal("the store returned a record without Kubernetes identity")
    })?;
    let (workload_kind, workload) = match &identity.workload {
        WorkloadResolution::Resolved(workload) => (workload.kind.clone(), workload.name.clone()),
        WorkloadResolution::NoController => ("Pod".into(), identity.pod_name.clone()),
        WorkloadResolution::UnresolvedReplicaSet(_) | WorkloadResolution::UnsupportedOwner(_) => {
            return Err(Status::internal(
                "the store returned a record without resolved workload identity",
            ));
        }
    };
    let total_nanos = log.observed_at().as_nanosecond();
    let seconds = i64::try_from(total_nanos.div_euclid(1_000_000_000))
        .map_err(|_| Status::internal("record timestamp is outside protobuf range"))?;
    let nanos = i32::try_from(total_nanos.rem_euclid(1_000_000_000))
        .expect("nanosecond remainder fits in i32");

    Ok(StreamLogsResponse {
        timestamp: Some(prost_types::Timestamp { seconds, nanos }),
        sequence: record.sequence(),
        line: log.bytes().to_vec(),
        namespace: identity.namespace.clone(),
        workload_kind,
        workload,
        pod: identity.pod_name.clone(),
    })
}

fn identity(enrichment: &Enrichment) -> Option<&KubernetesIdentity> {
    match enrichment {
        Enrichment::Enriched(identity) | Enrichment::Stale(identity) => Some(identity),
        Enrichment::UnresolvedCgroup
        | Enrichment::UnresolvedContainer(_)
        | Enrichment::AmbiguousCgroup
        | Enrichment::AmbiguousContainer(_) => None,
    }
}

fn stream_status(error: StreamError) -> Status {
    match error {
        StreamError::SelectorTooLarge => Status::invalid_argument("selector is too large"),
        StreamError::Lagged(skipped) => {
            Status::resource_exhausted(format!("log stream lagged by {skipped} records"))
        }
        StreamError::Closed => Status::unavailable("log store closed"),
    }
}
