// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded OTLP/gRPC batching kept away from the capture loop.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use blt_model::LogRecord;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse, logs_service_client::LogsServiceClient,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
    time::Instant,
};
use tonic::{Code, Request, transport::Endpoint};

use crate::{ExportContext, encoded_len, export_request};

#[derive(Clone, Debug)]
pub struct ExportConfig {
    pub endpoint: String,
    pub queue_records: usize,
    pub queue_bytes: usize,
    pub batch_records: usize,
    pub batch_bytes: usize,
    pub flush_interval: Duration,
    pub retry_max_elapsed: Duration,
    pub request_timeout: Duration,
}

impl ExportConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.endpoint.is_empty() {
            return Err("OTLP endpoint must not be empty");
        }

        if Endpoint::from_shared(self.endpoint.clone()).is_err() {
            return Err("OTLP endpoint must be a valid gRPC URI");
        }

        if self.queue_records == 0
            || self.queue_bytes == 0
            || self.batch_records == 0
            || self.batch_bytes == 0
            || self.flush_interval.is_zero()
            || self.request_timeout.is_zero()
            || self.queue_bytes > u32::MAX as usize
        {
            return Err("OTLP queue, batch, flush, and timeout bounds must be non-zero");
        }

        if self.batch_bytes > self.queue_bytes {
            return Err("OTLP batch_bytes must fit queue_bytes");
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportStats {
    pub queued_records: u64,
    pub queue_full: u64,
    pub queue_byte_limit: u64,
    pub exported_batches: u64,
    pub exported_records: u64,
    pub rejected_records: u64,
    pub failed_batches: u64,
    pub retries: u64,
}

#[derive(Default)]
struct AtomicStats {
    queued_records: AtomicU64,
    queue_full: AtomicU64,
    queue_byte_limit: AtomicU64,
    exported_batches: AtomicU64,
    exported_records: AtomicU64,
    rejected_records: AtomicU64,
    failed_batches: AtomicU64,
    retries: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TryExportError {
    RecordTooLarge,
    QueueByteLimit,
    QueueFull,
    Closed,
}

impl fmt::Display for TryExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OTLP export rejected: {self:?}")
    }
}

impl std::error::Error for TryExportError {}

struct Item {
    request: ExportLogsServiceRequest,
    bytes: usize,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub struct OtlpSender {
    sender: mpsc::Sender<Item>,
    bytes: Arc<Semaphore>,
    max_bytes: usize,
    context: Arc<ExportContext>,
    stats: Arc<AtomicStats>,
}

impl OtlpSender {
    /// Queue a record without awaiting network or queue capacity.
    pub fn try_send(&self, record: &LogRecord) -> Result<(), TryExportError> {
        let request = export_request(record, &self.context);

        let bytes = encoded_len(&request);

        if bytes > self.max_bytes || bytes > u32::MAX as usize {
            return Err(TryExportError::RecordTooLarge);
        }

        let permit = self
            .bytes
            .clone()
            .try_acquire_many_owned(bytes as u32)
            .map_err(|_| {
                self.stats.queue_byte_limit.fetch_add(1, Ordering::Relaxed);

                TryExportError::QueueByteLimit
            })?;

        self.sender
            .try_send(Item {
                request,
                bytes,
                _permit: permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    self.stats.queue_full.fetch_add(1, Ordering::Relaxed);

                    TryExportError::QueueFull
                }
                mpsc::error::TrySendError::Closed(_) => TryExportError::Closed,
            })?;

        self.stats.queued_records.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    pub fn stats(&self) -> ExportStats {
        ExportStats {
            queued_records: self.stats.queued_records.load(Ordering::Relaxed),
            queue_full: self.stats.queue_full.load(Ordering::Relaxed),
            queue_byte_limit: self.stats.queue_byte_limit.load(Ordering::Relaxed),
            exported_batches: self.stats.exported_batches.load(Ordering::Relaxed),
            exported_records: self.stats.exported_records.load(Ordering::Relaxed),
            rejected_records: self.stats.rejected_records.load(Ordering::Relaxed),
            failed_batches: self.stats.failed_batches.load(Ordering::Relaxed),
            retries: self.stats.retries.load(Ordering::Relaxed),
        }
    }
}

pub struct OtlpExporter {
    sender: Option<OtlpSender>,
    task: JoinHandle<()>,
}

impl OtlpExporter {
    pub fn spawn(config: ExportConfig, context: ExportContext) -> Self {
        config
            .validate()
            .expect("invalid OTLP export configuration");

        let (sender, receiver) = mpsc::channel(config.queue_records);

        let bytes = Arc::new(Semaphore::new(config.queue_bytes));

        let stats = Arc::new(AtomicStats::default());

        let sender = OtlpSender {
            sender,
            bytes,
            max_bytes: config.queue_bytes,
            context: Arc::new(context),
            stats: stats.clone(),
        };

        let task = tokio::spawn(run(config, receiver, stats));

        Self {
            sender: Some(sender),
            task,
        }
    }

    pub fn sender(&self) -> OtlpSender {
        self.sender.as_ref().expect("exporter is running").clone()
    }

    pub fn stats(&self) -> ExportStats {
        self.sender.as_ref().expect("exporter is running").stats()
    }

    /// Close admission and wait for the actor to flush all accepted records.
    pub async fn shutdown(mut self) -> ExportStats {
        let sender = self.sender.take().expect("exporter is running");

        let stats = sender.stats.clone();

        drop(sender);

        let _ = self.task.await;

        snapshot(&stats)
    }
}

async fn run(config: ExportConfig, mut receiver: mpsc::Receiver<Item>, stats: Arc<AtomicStats>) {
    let channel = Endpoint::from_shared(config.endpoint.clone())
        .expect("validated OTLP endpoint")
        .timeout(config.request_timeout)
        .connect_lazy();
    let mut client = LogsServiceClient::new(channel);

    let mut batch = Vec::new();

    let mut batch_bytes = 0usize;

    let timer = tokio::time::sleep(config.flush_interval);

    tokio::pin!(timer);

    loop {
        tokio::select! {
            item = receiver.recv() => {
                let Some(item) = item else { break };
                if !batch.is_empty()
                    && (batch.len() == config.batch_records
                        || batch_bytes.saturating_add(item.bytes) > config.batch_bytes)
                {
                    flush(&mut client, &config, &stats, std::mem::take(&mut batch)).await;
                    batch_bytes = 0;
                }
                batch_bytes += item.bytes;
                batch.push(item);
                if batch.len() == config.batch_records || batch_bytes >= config.batch_bytes {
                    flush(&mut client, &config, &stats, std::mem::take(&mut batch)).await;
                    batch_bytes = 0;
                }
                timer.as_mut().reset(Instant::now() + config.flush_interval);
            }
            () = &mut timer, if !batch.is_empty() => {
                flush(&mut client, &config, &stats, std::mem::take(&mut batch)).await;
                batch_bytes = 0;
                timer.as_mut().reset(Instant::now() + config.flush_interval);
            }
        }
    }

    if !batch.is_empty() {
        flush(&mut client, &config, &stats, batch).await;
    }
}

async fn flush(
    client: &mut LogsServiceClient<tonic::transport::Channel>,
    config: &ExportConfig,
    stats: &AtomicStats,
    items: Vec<Item>,
) {
    let record_count = items.len() as u64;

    let request = ExportLogsServiceRequest {
        resource_logs: items
            .iter()
            .flat_map(|item| item.request.resource_logs.iter().cloned())
            .collect(),
    };

    let started = Instant::now();

    let mut delay = Duration::from_millis(100);

    loop {
        match send(client, request.clone(), config.request_timeout).await {
            SendResult::Accepted(rejected) => {
                stats.exported_batches.fetch_add(1, Ordering::Relaxed);

                stats
                    .exported_records
                    .fetch_add(record_count - rejected.min(record_count), Ordering::Relaxed);

                stats
                    .rejected_records
                    .fetch_add(rejected, Ordering::Relaxed);

                return;
            }
            SendResult::PermanentFailure => {
                stats.failed_batches.fetch_add(1, Ordering::Relaxed);

                return;
            }
            SendResult::RetryableFailure => {
                if started.elapsed().saturating_add(delay) > config.retry_max_elapsed {
                    stats.failed_batches.fetch_add(1, Ordering::Relaxed);

                    return;
                }

                stats.retries.fetch_add(1, Ordering::Relaxed);

                tokio::time::sleep(delay).await;

                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
}

enum SendResult {
    Accepted(u64),
    RetryableFailure,
    PermanentFailure,
}

async fn send(
    client: &mut LogsServiceClient<tonic::transport::Channel>,
    batch: ExportLogsServiceRequest,
    timeout: Duration,
) -> SendResult {
    let mut request = Request::new(batch);
    request.set_timeout(timeout);
    match client.export(request).await {
        Ok(response) => {
            let response: ExportLogsServiceResponse = response.into_inner();
            let rejected = response
                .partial_success
                .map_or(0, |partial| partial.rejected_log_records.max(0) as u64);

            SendResult::Accepted(rejected)
        }
        Err(status)
            if matches!(
                status.code(),
                Code::Aborted
                    | Code::Cancelled
                    | Code::DeadlineExceeded
                    | Code::ResourceExhausted
                    | Code::Unavailable
                    | Code::Unknown
            ) =>
        {
            SendResult::RetryableFailure
        }
        Err(_) => SendResult::PermanentFailure,
    }
}

fn snapshot(stats: &AtomicStats) -> ExportStats {
    ExportStats {
        queued_records: stats.queued_records.load(Ordering::Relaxed),
        queue_full: stats.queue_full.load(Ordering::Relaxed),
        queue_byte_limit: stats.queue_byte_limit.load(Ordering::Relaxed),
        exported_batches: stats.exported_batches.load(Ordering::Relaxed),
        exported_records: stats.exported_records.load(Ordering::Relaxed),
        rejected_records: stats.rejected_records.load(Ordering::Relaxed),
        failed_batches: stats.failed_batches.load(Ordering::Relaxed),
        retries: stats.retries.load(Ordering::Relaxed),
    }
}
