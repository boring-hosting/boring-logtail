// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context as _;
use aya::{
    Ebpf,
    maps::{CgroupArray, HashMap, ProgramArray, RingBuf},
    programs::TracePoint,
};
use boring_logtail::{
    cgroup_resolver::{DEFAULT_HOST_CGROUP_ROOT, NATIVE_CGROUP_ROOT, spawn_cgroup_cache},
    config::Config,
    decode_event,
    emitter::EventEmitters,
    enrichment::{Enricher, PodSnapshot},
    event::EventCatcher,
    filter::{DropReason, FilterPlan},
    k8s_watch::spawn_kubernetes_cache,
    pipeline::{Pipeline, PipelineDecision},
    sampling::OutputPolicy,
    store::{LogStore, TryAppendError},
};
use log::{debug, info, warn};
use std::{collections::HashMap as StdHashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    signal::{self, unix::SignalKind},
    sync::{oneshot, watch},
    task::JoinHandle,
};

mod cgroup;

use cgroup::CollectorCgroup;

struct LogTailApplication {
    // Keeping Ebpf alive keeps its programs, links, and maps alive.
    _ebpf: Ebpf,
    // The task owns the ring buffer because tokio::spawn requires 'static data.
    event_task: Option<JoinHandle<anyhow::Result<()>>>,
    event_shutdown: Option<oneshot::Sender<()>>,
    store: LogStore,
    emitters: Option<EventEmitters>,
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
        raise_memlock_limit();

        let config_path = std::env::var_os("BORING_LOGTAIL_CONFIG").map(PathBuf::from);
        let config = Config::load(config_path.as_deref()).context("configure boring-logtail")?;
        let (emitter_senders, emitters) = EventEmitters::spawn(&config)?;
        let event_catcher = EventCatcher::compile(&config, &emitter_senders)?;
        let filter_plan = FilterPlan::compile(&config);
        let output_policy = OutputPolicy::WithSample(config.sampling.percent.try_into()?);
        info!(
            "configuration: sample_percent={} pod_watch={:?} max_logs={} retention={:?} max_memory={} derived_limits=\"{}\"",
            config.sampling.percent,
            filter_plan.pod_watch,
            config.store.max_logs,
            config.store.retention,
            config.store.max_memory,
            config
                .store
                .derived_limits_summary()
                .map_err(anyhow::Error::msg)?,
        );
        let store = LogStore::spawn(config.store.clone());

        let collector_cgroup = CollectorCgroup::discover()?;

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/boring-logtail"
        )))?;

        info!("capture source is application write/writev");
        configure_collector_filter(&mut ebpf, &collector_cgroup)?;
        configure_application_fds(&mut ebpf)?;
        configure_chunk_worker(&mut ebpf)?;
        load_exit_program(&mut ebpf)?;
        load_enter_program(&mut ebpf)?;
        load_enter_writev_program(&mut ebpf)?;

        // Attach exit first so no entry can be recorded without its matching
        // exit handler already being available.
        let cgroup_root = std::env::var_os("BORING_LOGTAIL_HOST_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(default_cgroup_root);
        let cgroups = spawn_cgroup_cache(cgroup_root);
        let pods = match std::env::var("BORING_LOGTAIL_NODE_NAME") {
            Ok(node) if !node.is_empty() => {
                match spawn_kubernetes_cache(node, filter_plan.pod_watch.clone()).await {
                    Ok(receiver) => receiver,
                    Err(error) => {
                        warn!("Kubernetes Pod watch disabled: {error:#}");
                        let (_, receiver) = watch::channel(Arc::new(PodSnapshot::default()));
                        receiver
                    }
                }
            }
            _ => {
                warn!("node-local enrichment disabled: BORING_LOGTAIL_NODE_NAME is not set");
                let (_, receiver) = watch::channel(Arc::new(PodSnapshot::default()));
                receiver
            }
        };
        attach_exit_program(&mut ebpf)?;
        attach_enter_program(&mut ebpf)?;
        attach_enter_writev_program(&mut ebpf)?;
        let enricher = Enricher { cgroups, pods };
        let (event_task, event_shutdown) = spawn_capture_loop(
            &mut ebpf,
            Pipeline::new(enricher, output_policy, filter_plan.writes, &config.store)
                .with_event_catcher(event_catcher),
            store.clone(),
        )?;

        Ok(Self {
            _ebpf: ebpf,
            event_task: Some(event_task),
            event_shutdown: Some(event_shutdown),
            store,
            emitters: Some(emitters),
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
        self.store.shutdown().await;
        if let Some(emitters) = self.emitters.take() {
            emitters.shutdown().await;
        }
    }
}

fn default_cgroup_root() -> PathBuf {
    let mounted = PathBuf::from(DEFAULT_HOST_CGROUP_ROOT);
    if mounted.join("cgroup.controllers").is_file() {
        mounted
    } else {
        PathBuf::from(NATIVE_CGROUP_ROOT)
    }
}

// I still don't really understand this.
fn raise_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn configure_collector_filter(
    ebpf: &mut Ebpf,
    collector_cgroup: &CollectorCgroup,
) -> anyhow::Result<()> {
    let collector_map = ebpf
        .map_mut("COLLECTOR_CGROUP")
        .context("eBPF map COLLECTOR_CGROUP is missing")?;
    let mut ignored_cgroups = CgroupArray::try_from(collector_map)?;
    let collector_fd = collector_cgroup
        .directory()
        .try_clone()
        .context("clone collector cgroup file descriptor")?;
    ignored_cgroups.set(0, collector_fd, 0)?;
    debug!(
        "ignoring collector cgroup {}",
        collector_cgroup.path().display()
    );

    Ok(())
}

fn configure_application_fds(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let allowed_fd_map = ebpf
        .map_mut("ALLOWED_FDS")
        .context("eBPF map ALLOWED_FDS is missing")?;
    let mut allowed_fds = HashMap::<_, u32, u8>::try_from(allowed_fd_map)?;
    allowed_fds.insert(1, 1, 0)?;
    allowed_fds.insert(2, 1, 0)?;
    Ok(())
}

fn configure_chunk_worker(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    for (name, map_name) in [
        ("boring_logtail_send_write_chunk", "WRITE_WORKER"),
        ("boring_logtail_send_writev_chunk", "WRITEV_WORKER"),
    ] {
        let worker: &mut TracePoint = ebpf
            .program_mut(name)
            .with_context(|| format!("eBPF program {name} is missing"))?
            .try_into()?;
        worker.load().with_context(|| format!("load {name}"))?;
        let worker_fd = worker.fd()?.try_clone()?;
        let worker_map = ebpf
            .map_mut(map_name)
            .with_context(|| format!("eBPF map {map_name} is missing"))?;
        ProgramArray::try_from(worker_map)?.set(0, &worker_fd, 0)?;
    }
    Ok(())
}

fn spawn_capture_loop(
    ebpf: &mut Ebpf,
    mut pipeline: Pipeline,
    store: LogStore,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, oneshot::Sender<()>)> {
    let event_map = ebpf
        .take_map("EVENTS")
        .context("eBPF map EVENTS is missing")?;
    let ring_buf = RingBuf::try_from(event_map)?;
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let (shutdown, mut shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut drops = StdHashMap::<DropReason, u64>::new();
        let mut ingress_drops = StdHashMap::<TryAppendError, u64>::new();
        let mut integrity_totals = RecordIntegrityTotals::default();
        let mut report = tokio::time::interval(Duration::from_secs(60));

        loop {
            let mut guard = tokio::select! {
                guard = ring_buf.readable_mut() => guard?,
                _ = &mut shutdown_receiver => break,
                _ = report.tick() => {
                    let stats = store.stats();
                    info!("pipeline_drops={drops:?} store_ingress_drops={ingress_drops:?} record_integrity={integrity_totals:?} store_stats={stats:?}");
                    continue;
                }
            };

            while let Some(item) = guard.get_inner_mut().next() {
                match decode_event(&item) {
                    Ok(event) => match pipeline.accept(event) {
                        Ok(PipelineDecision::Records { emitted, sampled }) => {
                            *drops.entry(DropReason::Sampled).or_default() += sampled as u64;
                            publish_records(
                                emitted,
                                &store,
                                &mut ingress_drops,
                                &mut integrity_totals,
                            );
                        }
                        Ok(PipelineDecision::Pending) => {}
                        Ok(PipelineDecision::Dropped(reason)) => {
                            *drops.entry(reason).or_default() += 1;
                        }
                        Err(error) => {
                            warn!("discarding write that cannot be reconstructed: {error}")
                        }
                    },
                    Err(error) => debug!("discarding malformed ring-buffer record: {error}"),
                }
            }
            guard.clear_ready();
        }

        if let PipelineDecision::Records { emitted, sampled } = pipeline.flush() {
            *drops.entry(DropReason::Sampled).or_default() += sampled as u64;
            publish_records(emitted, &store, &mut ingress_drops, &mut integrity_totals);
        }

        if !drops.is_empty()
            || !ingress_drops.is_empty()
            || integrity_totals.capacity_splits > 0
            || integrity_totals.capture_gaps > 0
            || integrity_totals.unterminated_flushes > 0
        {
            info!(
                "final pipeline_drops={drops:?} store_ingress_drops={ingress_drops:?} record_integrity={integrity_totals:?}"
            );
        }
        Ok(())
    });
    Ok((task, shutdown))
}

fn publish_records(
    records: Vec<Arc<boring_logtail::record::LogRecord>>,
    store: &LogStore,
    ingress_drops: &mut StdHashMap<TryAppendError, u64>,
    integrity_totals: &mut RecordIntegrityTotals,
) {
    for record in records {
        let integrity = record.integrity();
        integrity_totals.capacity_splits += u64::from(integrity.capacity_split);
        integrity_totals.capture_gaps += u64::from(integrity.capture_gap);
        integrity_totals.unterminated_flushes += u64::from(integrity.unterminated);
        if let Err(reason) = store.try_append(record) {
            *ingress_drops.entry(reason).or_default() += 1;
        }
    }
}

fn load_enter_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let enter_program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_enter")
        .context("eBPF program boring_logtail_enter is missing")?
        .try_into()?;
    enter_program.load().context("load boring_logtail_enter")?;
    Ok(())
}

fn attach_enter_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let enter_program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_enter")
        .context("eBPF program boring_logtail_enter is missing")?
        .try_into()?;
    enter_program.attach("syscalls", "sys_enter_write")?;
    Ok(())
}

fn load_enter_writev_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_enter_writev")
        .context("eBPF program boring_logtail_enter_writev is missing")?
        .try_into()?;
    program.load().context("load boring_logtail_enter_writev")?;
    Ok(())
}

fn attach_enter_writev_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_enter_writev")
        .context("eBPF program boring_logtail_enter_writev is missing")?
        .try_into()?;
    program.attach("syscalls", "sys_enter_writev")?;
    Ok(())
}

fn load_exit_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let exit_program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_exit")
        .context("eBPF program boring_logtail_exit is missing")?
        .try_into()?;
    exit_program.load().context("load boring_logtail_exit")?;
    Ok(())
}

fn attach_exit_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let exit_program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_exit")
        .context("eBPF program boring_logtail_exit is missing")?
        .try_into()?;
    exit_program.attach("syscalls", "sys_exit_write")?;
    let writev_exit: &mut TracePoint = ebpf
        .program_mut("boring_logtail_exit_writev")
        .context("eBPF program boring_logtail_exit_writev is missing")?
        .try_into()?;
    writev_exit
        .load()
        .context("load boring_logtail_exit_writev")?;
    writev_exit.attach("syscalls", "sys_exit_writev")?;
    Ok(())
}
