// SPDX-License-Identifier: GPL-3.0-or-later

use std::{path::PathBuf, sync::Arc};

use blt_emitter::{DiscordConfig, EmittersConfig, EventEmitters};
use blt_store::LogStore;
use boring_collector::{CollectorConfig, Policy, router};
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
    let listener = tokio::net::TcpListener::bind(config.listen).await?;

    info!("boring-collector listening on {}", config.listen);

    axum::serve(
        listener,
        router(store.clone(), policy.clone(), config.max_request_bytes),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("final collector policy stats: {:?}", policy.stats());

    emitters.shutdown().await;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
