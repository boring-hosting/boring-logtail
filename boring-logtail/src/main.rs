// SPDX-License-Identifier: GPL-3.0-or-later

//! Process wiring for the only user-facing binary.
//!
//! Tail node-local CRI files, enrich records, and ship them to the collector.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context as _;
use blt_model::LogRecord;
use blt_otel::{ExportConfig, ExportContext, OtlpExporter, OtlpSender, TryExportError};
use boring_logtail::{
    config::Config,
    cri::{CriFileEvent, CriFileSet, CriJoiner, CriStream, parse_record},
    enrichment::PodSnapshot,
    k8s_watch::spawn_kubernetes_cache,
};
use log::{debug, info, warn};
use notify::{Event, EventKind, RecursiveMode, Watcher as _, event::ModifyKind};
use tokio::{
    signal::{self, unix::SignalKind},
    sync::{oneshot, watch},
    task::JoinHandle,
};

const MAX_RECORD_BYTES: usize = 64 * 1024;

struct LogTailApplication {
    event_task: Option<JoinHandle<anyhow::Result<()>>>,
    event_shutdown: Option<oneshot::Sender<()>>,
    exporter: Option<OtlpExporter>,
}

#[derive(Debug, Default)]

struct RecordIntegrityTotals {
    capacity_splits: u64,
    capture_gaps: u64,
    unterminated_flushes: u64,
}

#[tokio::main]

async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let application = LogTailApplication::start().await?;

    info!("capture is live; waiting for a shutdown signal");

    shutdown_signal().await?;

    info!("shutting down");

    application.shutdown().await;

    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = signal::unix::signal(SignalKind::terminate())?;

    tokio::select! {
        result = signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }

    Ok(())
}

impl LogTailApplication {
    async fn start() -> anyhow::Result<Self> {
        let config_path = std::env::var_os("BORING_LOGTAIL_CONFIG").map(PathBuf::from);

        let config = Config::load(config_path.as_deref()).context("configure boring-logtail")?;

        info!(
            "configuration: collector_endpoint={}",
            config.collector.endpoint,
        );

        let exporter = OtlpExporter::spawn(export_config(&config), export_context());

        let pods = pod_cache().await;
        let root = std::env::var_os("BORING_LOGTAIL_CRI_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/log/pods"));
        let (event_task, event_shutdown) =
            spawn_cri_loop(root, MAX_RECORD_BYTES, pods, exporter.sender())?;

        info!("capture source is userspace CRI files");

        Ok(Self {
            event_task: Some(event_task),
            event_shutdown: Some(event_shutdown),
            exporter: Some(exporter),
        })
    }

    async fn shutdown(mut self) {
        if let Some(event_shutdown) = self.event_shutdown.take() {
            let _ = event_shutdown.send(());
        }

        if let Some(event_task) = self.event_task.take() {
            match event_task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!("capture task stopped with an error: {error:#}"),
                Err(error) => warn!("capture task failed: {error}"),
            }
        }

        if let Some(exporter) = self.exporter.take() {
            info!("final OTLP export stats: {:?}", exporter.shutdown().await);
        }
    }
}

async fn pod_cache() -> watch::Receiver<Arc<PodSnapshot>> {
    match std::env::var("BORING_LOGTAIL_NODE_NAME") {
        Ok(node) if !node.is_empty() => match spawn_kubernetes_cache(node).await {
            Ok(receiver) => receiver,
            Err(error) => {
                warn!("Kubernetes Pod watch disabled: {error:#}");
                watch::channel(Arc::new(PodSnapshot::default())).1
            }
        },
        _ => {
            warn!("node-local enrichment disabled: BORING_LOGTAIL_NODE_NAME is not set");
            watch::channel(Arc::new(PodSnapshot::default())).1
        }
    }
}

fn spawn_cri_loop(
    root: PathBuf,
    max_record_bytes: usize,
    mut pods: watch::Receiver<Arc<PodSnapshot>>,
    exporter: OtlpSender,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, oneshot::Sender<()>)> {
    let mut files = CriFileSet::new(root, max_record_bytes + 1024);
    files
        .reconcile()
        .context("discover initial CRI log files")?;
    let (file_events, mut file_event_receiver) = tokio::sync::mpsc::channel(8192);
    let notification_overflow = Arc::new(AtomicBool::new(false));
    let overflow = Arc::clone(&notification_overflow);
    let mut watcher = notify::recommended_watcher(move |event| {
        if file_events.try_send(event).is_err() {
            overflow.store(true, Ordering::Relaxed);
        }
    })
    .context("create CRI filesystem watcher")?;
    watcher
        .watch(files.root(), RecursiveMode::Recursive)
        .context("watch CRI log directory")?;
    let mut joiner = CriJoiner::new(max_record_bytes, 4096);
    let (shutdown, mut shutdown_receiver) = oneshot::channel();

    let task = tokio::spawn(async move {
        let _watcher = watcher;
        let mut reconcile_tick = tokio::time::interval(Duration::from_millis(500));
        let mut repair_tick = tokio::time::interval(Duration::from_secs(30));
        let mut report_tick = tokio::time::interval(Duration::from_secs(60));
        let mut reconcile_requested = false;
        let mut last_reconcile = tokio::time::Instant::now();
        const RECONCILE_COOLDOWN: Duration = Duration::from_secs(5);
        let mut identities = cri_identity_index(&pods.borrow());
        let mut ingress_drops = StdHashMap::<TryExportError, u64>::new();
        let mut integrity_totals = RecordIntegrityTotals::default();

        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => break,
                _ = reconcile_tick.tick() => {
                    if (reconcile_requested || notification_overflow.swap(false, Ordering::Relaxed))
                        && last_reconcile.elapsed() >= RECONCILE_COOLDOWN
                    {
                        reconcile_requested = false;
                        last_reconcile = tokio::time::Instant::now();
                        match files.reconcile().and_then(|_| files.read_available()) {
                            Ok(events) => process_cri_events(events, &mut joiner, &identities, &exporter, &mut ingress_drops, &mut integrity_totals)?,
                            Err(error) => warn!("CRI file reconciliation failed: {error}"),
                        }
                    }
                }
                _ = repair_tick.tick() => {
                    last_reconcile = tokio::time::Instant::now();
                    match files.reconcile().and_then(|_| files.read_available()) {
                        Ok(events) => process_cri_events(events, &mut joiner, &identities, &exporter, &mut ingress_drops, &mut integrity_totals)?,
                        Err(error) => warn!("CRI repair reconciliation failed: {error}"),
                    }
                }
                _ = report_tick.tick() => {
                    let file_stats = files.stats();
                    let partial_lanes = joiner.pending_lanes();
                    let partial_bytes = joiner.pending_bytes();
                    let export_stats = exporter.stats();
                    let identity_count: usize = identities.values().map(|c| c.len()).sum();
                    info!("cri_files={file_stats:?} cri_partial_lanes={partial_lanes} cri_partial_bytes={partial_bytes} identities={identity_count} export_ingress_drops={ingress_drops:?} export_stats={export_stats:?}");
                }
                _ = pods.changed() => {
                    identities = cri_identity_index(&pods.borrow_and_update());
                }
                event = file_event_receiver.recv() => {
                    let Some(event) = event else {
                        anyhow::bail!("CRI filesystem watcher stopped");
                    };
                    let mut changed = HashSet::new();
                    let mut needs_reconcile = false;

                    let mut handle_event = |event: Result<Event, notify::Error>| {
                        match event {
                            Ok(event) if requests_reconciliation(&event) => needs_reconcile = true,
                            Ok(event) => {
                                changed.extend(event.paths);
                            }
                            Err(error) => {
                                warn!("CRI filesystem notification failed: {error}");
                                needs_reconcile = true;
                            }
                        }
                    };

                    handle_event(event);
                    while let Ok(event) = file_event_receiver.try_recv() {
                        handle_event(event);
                    }

                    if needs_reconcile {
                        reconcile_requested = true;
                    }

                    if !changed.is_empty() {
                        let events = files.read_changed(&changed)?;
                        process_cri_events(events, &mut joiner, &identities, &exporter, &mut ingress_drops, &mut integrity_totals)?;
                    }
                }
            }
        }

        Ok(())
    });

    Ok((task, shutdown))
}

fn requests_reconciliation(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
    )
}

fn process_cri_events(
    events: Vec<CriFileEvent>,
    joiner: &mut CriJoiner,
    identities: &StdHashMap<String, StdHashMap<String, blt_model::KubernetesIdentity>>,
    exporter: &OtlpSender,
    ingress_drops: &mut StdHashMap<TryExportError, u64>,
    integrity_totals: &mut RecordIntegrityTotals,
) -> anyhow::Result<()> {
    for event in events {
        let CriFileEvent::Line { source, bytes } = event else {
            warn!("discarding oversized CRI physical record");
            continue;
        };
        let fragment = match parse_record(&bytes) {
            Ok(fragment) => fragment,
            Err(error) => {
                debug!("discarding malformed CRI record: {error}");
                continue;
            }
        };
        let Some(record) = joiner.accept(source, fragment)? else {
            continue;
        };
        let Some(identity) = identities
            .get(&record.source.pod_uid)
            .and_then(|containers| containers.get(&record.source.container_name))
            .cloned()
        else {
            debug!(
                "CRI record has no current Pod identity: {}/{}",
                record.source.namespace, record.source.pod_name
            );
            continue;
        };
        let stream = match record.stream {
            CriStream::Stdout => blt_model::StreamFileDescriptor::RuntimeStdout,
            CriStream::Stderr => blt_model::StreamFileDescriptor::RuntimeStderr,
        };
        let log_record = LogRecord::new(
            record.timestamp,
            cri_sampling_seed(&record.source),
            stream,
            blt_model::Enrichment::Enriched(identity),
            0,
            0,
            0,
            0,
            record.bytes,
            blt_model::RecordIntegrity {
                capture_truncated: record.truncated,
                ..Default::default()
            },
            100,
            blt_model::Severity::Unknown,
        );
        publish_record(&log_record, exporter, ingress_drops, integrity_totals);
    }

    Ok(())
}

fn cri_identity_index(
    snapshot: &PodSnapshot,
) -> StdHashMap<String, StdHashMap<String, blt_model::KubernetesIdentity>> {
    let mut index: StdHashMap<String, StdHashMap<String, blt_model::KubernetesIdentity>> =
        StdHashMap::new();
    for identity in snapshot.identities.values().flatten() {
        index
            .entry(identity.pod_uid.clone())
            .or_default()
            .insert(identity.container_name.clone(), identity.clone());
    }
    index
}

fn cri_sampling_seed(source: &boring_logtail::cri::CriSource) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for byte in source
        .pod_uid
        .bytes()
        .chain(source.container_name.bytes())
        .chain(source.restart.to_le_bytes())
    {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    state
}

fn export_config(config: &Config) -> ExportConfig {
    ExportConfig {
        endpoint: config.collector.endpoint.clone(),
        queue_records: config.collector.queue_records,
        queue_bytes: config.collector.queue_bytes,
        batch_records: config.collector.batch_records,
        batch_bytes: config.collector.batch_bytes,
        flush_interval: Duration::from_millis(config.collector.flush_interval_ms),
        retry_max_elapsed: Duration::from_millis(config.collector.retry_max_elapsed_ms),
        request_timeout: Duration::from_millis(config.collector.request_timeout_ms),
    }
}

fn export_context() -> ExportContext {
    let node = std::env::var("BORING_LOGTAIL_NODE_NAME").unwrap_or_else(|_| "unknown-node".into());

    let pod = std::env::var("BORING_LOGTAIL_POD_NAME").unwrap_or_else(|_| "unknown-agent".into());

    ExportContext {
        cluster_uid: std::env::var("BORING_LOGTAIL_CLUSTER_UID").ok(),
        agent_instance: format!("{node}/{pod}"),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

fn publish_record(
    record: &LogRecord,
    exporter: &OtlpSender,
    ingress_drops: &mut StdHashMap<TryExportError, u64>,
    integrity_totals: &mut RecordIntegrityTotals,
) {
    let integrity = record.integrity();

    integrity_totals.capacity_splits += u64::from(integrity.capacity_split);

    integrity_totals.capture_gaps += u64::from(integrity.capture_gap);

    integrity_totals.unterminated_flushes += u64::from(integrity.unterminated);

    if let Err(reason) = exporter.try_send(record) {
        *ingress_drops.entry(reason).or_default() += 1;
    }
}
