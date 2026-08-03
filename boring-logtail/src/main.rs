// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context as _;
use aya::{
    Ebpf,
    maps::{CgroupArray, HashMap, ProgramArray, RingBuf},
    programs::TracePoint,
};
use boring_logtail::{
    cgroup_resolver::{DEFAULT_HOST_CGROUP_ROOT, NATIVE_CGROUP_ROOT, spawn_cgroup_cache},
    cri_metadata::{CriEndpoint, CriSnapshot, DEFAULT_CRI_RECONCILE_INTERVAL, spawn_cri_cache},
    decode_event,
    enrichment::{Enricher, PodSnapshot, StreamCandidate},
    k8s_watch::{spawn_kubernetes_cache, spawn_merged_cache},
    pipeline::WriteAssembler,
    sampling::{OutputPolicy, SamplingCounters},
};
use log::{debug, info, warn};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    signal::{self, unix::SignalKind},
    sync::watch,
    task::JoinHandle,
};

mod cgroup;

use cgroup::CollectorCgroup;

fn payload_for_humans(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

struct LogTailApplication {
    // Keeping Ebpf alive keeps its programs, links, and maps alive.
    _ebpf: Ebpf,
    // The task owns the ring buffer because tokio::spawn requires 'static data.
    event_task: Option<JoinHandle<anyhow::Result<()>>>,
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

        let collector_cgroup = CollectorCgroup::discover()?;
        let cri_snapshot = configure_cri_cache()?;

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
        attach_exit_program(&mut ebpf)?;
        attach_enter_program(&mut ebpf)?;
        attach_enter_writev_program(&mut ebpf)?;
        let cgroup_root = std::env::var_os("BORING_LOGTAIL_HOST_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(default_cgroup_root);
        let cgroups = spawn_cgroup_cache(cgroup_root);
        let pods = match std::env::var("BORING_LOGTAIL_NODE_NAME") {
            Ok(node) if !node.is_empty() => {
                let kubernetes = match spawn_kubernetes_cache(node.clone()).await {
                    Ok(receiver) => receiver,
                    Err(error) => {
                        warn!("Kubernetes Pod watch disabled: {error:#}");
                        let (_, receiver) = watch::channel(Arc::new(PodSnapshot::default()));
                        receiver
                    }
                };
                let cri = cri_snapshot.unwrap_or_else(|| {
                    let (_, receiver) = watch::channel(Arc::new(CriSnapshot::default()));
                    receiver
                });
                spawn_merged_cache(node, cri, kubernetes)
            }
            _ => {
                warn!("node-local enrichment disabled: BORING_LOGTAIL_NODE_NAME is not set");
                let (_, receiver) = watch::channel(Arc::new(PodSnapshot::default()));
                receiver
            }
        };
        let enricher = Enricher::new(cgroups, pods);
        let sample_config = std::env::var("BORING_LOGTAIL_SAMPLE_PERCENT").ok();
        let output_policy = OutputPolicy::from_config(sample_config.as_deref())
            .context("configure BORING_LOGTAIL_SAMPLE_PERCENT")?;
        let sampling_counters = Arc::new(SamplingCounters::default());
        info!(
            "incoming-log output sample is {} percent",
            output_policy.sample_percent().get()
        );
        spawn_pipeline_diagnostics(
            enricher.counters(),
            Arc::clone(&sampling_counters),
            output_policy,
        );
        let event_task = spawn_capture_loop(&mut ebpf, enricher, output_policy, sampling_counters)?;

        Ok(Self {
            _ebpf: ebpf,
            event_task: Some(event_task),
        })
    }

    async fn shutdown(mut self) {
        if let Some(event_task) = self.event_task.take() {
            event_task.abort();
            let _ = event_task.await;
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

fn configure_cri_cache() -> anyhow::Result<Option<watch::Receiver<Arc<CriSnapshot>>>> {
    let Some(runtime) = std::env::var_os("BORING_LOGTAIL_CRI_RUNTIME") else {
        info!("CRI metadata cache disabled: BORING_LOGTAIL_CRI_RUNTIME is not set");
        return Ok(None);
    };
    let runtime = runtime
        .to_str()
        .context("BORING_LOGTAIL_CRI_RUNTIME is not UTF-8")?;
    let socket = std::env::var_os("BORING_LOGTAIL_CRI_SOCKET")
        .map(PathBuf::from)
        .context("BORING_LOGTAIL_CRI_SOCKET is required when CRI metadata is enabled")?;
    let endpoint = CriEndpoint::configured(runtime, socket)?;
    info!(
        "CRI metadata cache enabled runtime={} socket={}",
        endpoint.runtime.scheme(),
        endpoint.socket.display()
    );
    let (snapshot, counters) = spawn_cri_cache(endpoint, DEFAULT_CRI_RECONCILE_INTERVAL);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            info!(
                "cri_cache_counts attempts={} successes={} failures={} containers={}",
                counters.attempts.load(std::sync::atomic::Ordering::Relaxed),
                counters
                    .successes
                    .load(std::sync::atomic::Ordering::Relaxed),
                counters.failures.load(std::sync::atomic::Ordering::Relaxed),
                counters
                    .containers
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
        }
    });
    Ok(Some(snapshot))
}

fn spawn_pipeline_diagnostics(
    counters: Arc<boring_logtail::enrichment::EnrichmentCounters>,
    sampling: Arc<SamplingCounters>,
    policy: OutputPolicy,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let snapshot = counters.snapshot();
            let samples = sampling.snapshot();
            info!(
                "pipeline_counts sample_percent={} observed={} emitted={} dropped_by_policy={} enriched={} unresolved_cgroup={} unresolved_container={} ambiguous={} tombstone_hit={}",
                policy.sample_percent().get(),
                samples.observed,
                samples.emitted,
                samples.dropped_by_policy,
                snapshot.enriched,
                snapshot.unresolved_cgroup,
                snapshot.unresolved_container,
                snapshot.ambiguous,
                snapshot.tombstone_hit,
            );
        }
    });
}

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
    enricher: Enricher,
    output_policy: OutputPolicy,
    sampling_counters: Arc<SamplingCounters>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let event_map = ebpf
        .take_map("EVENTS")
        .context("eBPF map EVENTS is missing")?;
    let ring_buf = RingBuf::try_from(event_map)?;
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let mut assembler = WriteAssembler::new();

    Ok(tokio::spawn(async move {
        loop {
            let mut guard = ring_buf.readable_mut().await?;
            while let Some(item) = guard.get_inner_mut().next() {
                match decode_event(&item) {
                    Ok(event) => {
                        match assembler.accept(event) {
                            Ok(operation) => {
                                let Some(operation) = operation else {
                                    continue;
                                };
                                let emit = output_policy.should_emit(&operation);
                                sampling_counters.record(emit);
                                if !emit {
                                    continue;
                                }
                                let source = enricher.enrich(&operation).source();
                                let stream = operation.fd.map(StreamCandidate::from).map_or_else(
                                    || "unknown".to_owned(),
                                    |stream| stream.to_string(),
                                );
                                info!(
                                    "incoming_log sample_percent={} source=\"{}\" stream={} cgroup={} pid={} tid={} bytes={} truncated={} read_failed={} payload={:?}",
                                    output_policy.sample_percent().get(),
                                    source,
                                    stream,
                                    operation.cgroup_id,
                                    operation.pid,
                                    operation.tid,
                                    operation.bytes.len(),
                                    operation.truncated,
                                    operation.read_failed,
                                    payload_for_humans(&operation.bytes),
                                );
                            }
                            Err(err) => {
                                warn!("discarding write that cannot be reconstructed: {err}")
                            }
                        };
                    }
                    Err(error) => debug!("discarding malformed ring-buffer record: {error}"),
                }
            }
            guard.clear_ready();
        }
    }))
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

#[cfg(test)]
mod tests {
    use super::payload_for_humans;

    #[test]
    fn makes_invalid_utf8_readable_without_touching_the_bytes() {
        let bytes = [0xff, b'a'];
        assert_eq!(payload_for_humans(&bytes), "�a");
        assert_eq!(bytes, [0xff, b'a']);
    }
}
