// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;

use crate::ports::{LogEntry, LogReader, ReadError, ReadRequest, ReadSelector};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};

use super::proto::{
    StreamLogsRequest, StreamLogsResponse, log_service_server::LogService as LogServiceRoute,
    stream_logs_request::Selector as ProtoSelector,
};

const STREAM_BUFFER: usize = 32;

#[derive(Clone)]
pub struct LogService {
    reader: Arc<dyn LogReader>,
}

impl LogService {
    pub fn new(reader: Arc<dyn LogReader>) -> Self {
        Self { reader }
    }
}

#[tonic::async_trait]
impl LogServiceRoute for LogService {
    type StreamLogsStream = ReceiverStream<Result<StreamLogsResponse, Status>>;

    async fn stream_logs(
        &self,
        request: Request<StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let request = read_request(request.into_inner())?;
        let mut records = self.reader.stream(request).await.map_err(read_status)?;
        let (sender, receiver) = mpsc::channel(STREAM_BUFFER);

        tokio::spawn(async move {
            while let Some(record) = records.next().await {
                let response = record.and_then(response).map_err(read_status);
                let terminal = response.is_err();
                if sender.send(response).await.is_err() || terminal {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

fn read_request(request: StreamLogsRequest) -> Result<ReadRequest, Status> {
    let selector = match request.selector {
        Some(ProtoSelector::Namespace(value)) => ReadSelector::Namespace(value),
        Some(ProtoSelector::Workload(value)) => ReadSelector::Workload(value),
        Some(ProtoSelector::Pod(value)) => ReadSelector::Pod(value),
        None => return Err(Status::invalid_argument("one selector is required")),
    };
    ReadRequest::new(selector, request.follow, request.tail_lines).map_err(read_status)
}

fn response(record: LogEntry) -> Result<StreamLogsResponse, ReadError> {
    let seconds = i64::try_from(record.timestamp_unix_nano / 1_000_000_000)
        .map_err(|_| ReadError::Protocol("record timestamp is outside protobuf range".into()))?;
    let nanos = i32::try_from(record.timestamp_unix_nano % 1_000_000_000)
        .expect("nanosecond remainder fits i32");

    Ok(StreamLogsResponse {
        timestamp: Some(prost_types::Timestamp { seconds, nanos }),
        sequence: 0,
        line: record.line,
        namespace: record.namespace,
        workload_kind: record.workload_kind,
        workload: record.workload,
        pod: record.pod,
    })
}

fn read_status(error: ReadError) -> Status {
    match error {
        ReadError::InvalidRequest(message) => Status::invalid_argument(message),
        ReadError::Lagged(skipped) => {
            Status::resource_exhausted(format!("log stream lagged by {skipped} records"))
        }
        ReadError::Unavailable(message) => Status::unavailable(message),
        ReadError::Protocol(message) => Status::internal(message),
    }
}
