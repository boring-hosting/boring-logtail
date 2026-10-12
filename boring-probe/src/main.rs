use std::{env, fs::File, time::Duration};

use anyhow::{Context, Result};
use boring_probe::{
    adapters::{KubeletStatsAdapter, PrometheusRemoteWriteAdapter},
    config::Config,
    ports::{MetricsSink, StatsSource},
};
use log::{error, info};
use tokio::{
    signal::{self, unix::SignalKind},
    sync::oneshot,
    task::JoinHandle,
};

fn load_config() -> Result<Config> {
    let file = env::var("BORING_PROBE_CONFIG").context("BORING_PROBE_CONFIG is required")?;

    let config_file = File::open(&file).with_context(|| format!("open probe config {file}"))?;
    let mut config: Config = serde_yaml::from_reader(config_file)
        .with_context(|| format!("parse probe config {file}"))?;
    config.resolve_node_name(env::var("BORING_PROBE_NODE_NAME").ok().as_deref())?;
    config.validate()?;

    Ok(config)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = load_config().context("load probe configuration")?;

    let kubelet = KubeletStatsAdapter::new(&config.kubelet)?;
    let prometheus = PrometheusRemoteWriteAdapter::new(&config.prometheus);

    let (task, shutdown) = run(config.runtime.interval, kubelet, prometheus).await?;

    info!("capture is live; waiting for a shutdown signal");

    shutdown_signal().await?;
    info!("shutting down");

    let _ = shutdown.send(());
    task.await?;

    Ok(())
}

async fn run<S, P>(
    interval: Duration,
    stats_source: S,
    metrics_sink: P,
) -> Result<(JoinHandle<()>, oneshot::Sender<()>)>
where
    S: StatsSource + 'static,
    P: MetricsSink + 'static,
{
    let (shutdown, mut shutdown_receiver) = oneshot::channel();
    let mut reconcile_tick = tokio::time::interval(interval);

    let task = tokio::spawn(async move {
        info!("running application");

        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => {
                    break;
                }
                _ = reconcile_tick.tick() => {
                    if let Err(err) = reconcile(&stats_source, &metrics_sink).await {
                        error!("failed to reconcile: {err}");
                    }
                }
            }
        }

        info!("application stopped");
    });

    Ok((task, shutdown))
}

async fn reconcile<T: StatsSource, P: MetricsSink>(kubelet: &T, prom: &P) -> anyhow::Result<()> {
    let snapshot = kubelet.snapshot().await?;

    prom.push(snapshot).await?;

    info!("snapshot pushed");
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::SystemTime,
    };

    use async_trait::async_trait;
    use boring_probe::ports::{MetricsPushError, NodeStats, StatsReadError, StatsSnapshot};

    use super::*;

    struct FlakySource(Arc<AtomicUsize>);

    #[async_trait]
    impl StatsSource for FlakySource {
        async fn snapshot(&self) -> Result<StatsSnapshot, StatsReadError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(StatsReadError::Unavailable("first read".to_owned()));
            }
            Ok(StatsSnapshot {
                node: NodeStats {
                    name: "worker-a".to_owned(),
                    start_time: SystemTime::UNIX_EPOCH,
                    cpu: None,
                    memory: None,
                },
                pods: Vec::new(),
            })
        }
    }

    struct CountingSink(Arc<AtomicUsize>);

    #[async_trait]
    impl MetricsSink for CountingSink {
        async fn push(&self, _snapshot: StatsSnapshot) -> Result<(), MetricsPushError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_failure_does_not_stop_the_next_interval() {
        let reads = Arc::new(AtomicUsize::new(0));
        let pushes = Arc::new(AtomicUsize::new(0));
        let (task, shutdown) = run(
            Duration::from_secs(15),
            FlakySource(Arc::clone(&reads)),
            CountingSink(Arc::clone(&pushes)),
        )
        .await
        .unwrap();

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(15)).await;
        tokio::task::yield_now().await;

        assert!(reads.load(Ordering::SeqCst) >= 2);
        assert!(pushes.load(Ordering::SeqCst) >= 1);
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }
}
