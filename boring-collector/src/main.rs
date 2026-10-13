// SPDX-License-Identifier: GPL-3.0-or-later

use std::{path::PathBuf, sync::Arc};

use boring_collector::{
    CollectorConfig, grpc, otlp,
    ports::{LogReader, LogSink},
    runtime_metrics::RuntimeMetrics,
    stores::LokiLogStore,
};
use log::info;
use tokio::{net::TcpListener, task::JoinSet};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let path = std::env::var_os("BORING_COLLECTOR_CONFIG").map(PathBuf::from);
    let config = CollectorConfig::load(path.as_deref())?;
    let metrics = RuntimeMetrics::new();
    let store = Arc::new(
        LokiLogStore::with_metrics(config.loki_config(), metrics.clone())
            .map_err(anyhow::Error::msg)?,
    );
    let log_sink: Arc<dyn LogSink> = store.clone();
    let reader: Arc<dyn LogReader> = store;
    let otlp_listener = TcpListener::bind(config.otlp_grpc_listen).await?;

    let reader_listener = TcpListener::bind(config.reader_grpc_listen).await?;
    let health_listener = TcpListener::bind(config.health_listen).await?;

    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut tasks = JoinSet::new();

    info!("OTLP/gRPC listening on {}", config.otlp_grpc_listen);
    let otlp_stopped = stopped.clone();
    let otlp_metrics = metrics.clone();
    tasks.spawn(async move {
        otlp::serve_observed(
            otlp_listener,
            log_sink,
            config.max_request_bytes,
            otlp_metrics,
            wait_for_stop(otlp_stopped),
        )
        .await
        .map_err(anyhow::Error::from)
    });

    info!("reader gRPC listening on {}", config.reader_grpc_listen);
    let reader_stopped = stopped.clone();
    tasks.spawn(async move {
        grpc::serve(reader_listener, reader, wait_for_stop(reader_stopped))
            .await
            .map_err(anyhow::Error::from)
    });

    info!("health listening on {}", config.health_listen);
    let health_metrics = metrics.clone();
    tasks.spawn(async move {
        axum::serve(health_listener, health_metrics.router())
            .with_graceful_shutdown(wait_for_stop(stopped))
            .await
            .map_err(anyhow::Error::from)
    });

    metrics.set_ready(true);

    tokio::select! {
        _ = shutdown_signal() => {}
        result = tasks.join_next() => {
            metrics.critical_task_stopped();
            result.ok_or_else(|| anyhow::anyhow!("collector server set is empty"))???;
        }
    }

    metrics.set_ready(false);
    let _ = stop.send(true);
    while let Some(result) = tasks.join_next().await {
        result??;
    }

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn wait_for_stop(mut stopped: tokio::sync::watch::Receiver<bool>) {
    if *stopped.borrow() {
        return;
    }
    while stopped.changed().await.is_ok() {
        if *stopped.borrow() {
            return;
        }
    }
}
