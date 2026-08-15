// SPDX-License-Identifier: GPL-3.0-or-later

use std::{path::PathBuf, sync::Arc};

use blt_emitter::{DiscordConfig, EmittersConfig, EventEmitters};
use blt_store::LogStore;
use boring_collector::{CollectorConfig, Policy, grpc, router};
use log::info;

#[tokio::main]

async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let path = std::env::var_os("BORING_COLLECTOR_CONFIG").map(PathBuf::from);

    let config = CollectorConfig::load(path.as_deref())?;

    let discord = config
        .event_emitters
        .discord
        .as_ref()
        .map(|discord| {
            let secret = std::env::var(&discord.secret_from_env)?;

            if secret.is_empty() {
                anyhow::bail!(
                    "Discord secret environment variable {} is empty",
                    discord.secret_from_env
                );
            }

            Ok::<_, anyhow::Error>(DiscordConfig::new(&discord.channel_id, secret))
        })
        .transpose()?;

    let (senders, emitters) = EventEmitters::spawn(EmittersConfig {
        stdout: config.event_emitters.stdout.is_some(),
        discord,
    });

    let policy = Arc::new(Policy::compile(&config, &senders)?);
    let store = Arc::new(LogStore::new(config.store.clone()));
    let http_listener = tokio::net::TcpListener::bind(config.listen).await?;
    let grpc_listener = tokio::net::TcpListener::bind(config.grpc_listen).await?;

    info!("boring-collector OTLP/HTTP listening on {}", config.listen);
    info!("boring-collector gRPC listening on {}", config.grpc_listen);

    let (stop, stopped) = tokio::sync::watch::channel(false);
    let http_router = router(store.clone(), policy.clone(), config.max_request_bytes);
    let http_stopped = stopped.clone();
    let http = async move {
        axum::serve(http_listener, http_router)
            .with_graceful_shutdown(wait_for_stop(http_stopped))
            .await
            .map_err(anyhow::Error::from)
    };
    let grpc = async move {
        grpc::serve(grpc_listener, store, wait_for_stop(stopped))
            .await
            .map_err(anyhow::Error::from)
    };
    tokio::pin!(http, grpc);

    tokio::select! {
        result = &mut http => return result,
        result = &mut grpc => return result,
        () = shutdown_signal() => {}
    }

    let _ = stop.send(true);
    let (_, _) = tokio::try_join!(http, grpc)?;

    info!("final collector policy stats: {:?}", policy.stats());

    emitters.shutdown().await;

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
