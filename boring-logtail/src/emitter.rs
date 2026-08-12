// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded asynchronous delivery for caught events.

use crate::{
    config::{Config, DiscordEmitterConfig},
    event::{CaughtEvent, EmitterSender},
};
use anyhow::{Context as _, bail};
use reqwest::{Client, StatusCode, header::AUTHORIZATION};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt as _, BufWriter},
    sync::mpsc,
    task::JoinHandle,
};

const EMITTER_QUEUE_CAPACITY: usize = 128;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const DISCORD_API: &str = "https://discord.com/api/v10";
const DISCORD_CONTENT_CHARS: usize = 2_000;
const TRUNCATED: &str = "...[truncated]";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EmitterStats {
    pub delivered: u64,
    pub delivery_failed: u64,
}

#[derive(Default)]
struct AtomicEmitterStats {
    delivered: AtomicU64,
    delivery_failed: AtomicU64,
}

pub struct EventEmitters {
    tasks: Vec<JoinHandle<()>>,
    stats: Arc<AtomicEmitterStats>,
}

impl EventEmitters {
    pub fn spawn(config: &Config) -> anyhow::Result<(BTreeMap<String, EmitterSender>, Self)> {
        let stats = Arc::new(AtomicEmitterStats::default());
        let mut senders = BTreeMap::new();
        let mut tasks = Vec::new();
        if let Some(discord) = &config.event_emitters.discord {
            let secret = std::env::var(&discord.secret_from_env).with_context(|| {
                format!(
                    "read Discord bot secret from environment variable {}",
                    discord.secret_from_env
                )
            })?;
            if secret.is_empty() {
                bail!(
                    "Discord bot secret environment variable {} is empty",
                    discord.secret_from_env
                );
            }
            let (sender, task) = spawn_discord(
                discord.clone(),
                secret,
                DISCORD_API.to_owned(),
                stats.clone(),
            );
            senders.insert("discord".into(), EmitterSender { sender });
            tasks.push(task);
        }
        if config.event_emitters.stdout.is_some() {
            let (sender, task) = spawn_stdout(stats.clone());
            senders.insert("stdout".into(), EmitterSender { sender });
            tasks.push(task);
        }
        Ok((senders, Self { tasks, stats }))
    }

    pub fn stats(&self) -> EmitterStats {
        EmitterStats {
            delivered: self.stats.delivered.load(Ordering::Relaxed),
            delivery_failed: self.stats.delivery_failed.load(Ordering::Relaxed),
        }
    }

    pub async fn shutdown(self) {
        for task in self.tasks {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, task).await;
        }
    }
}

fn spawn_stdout(stats: Arc<AtomicEmitterStats>) -> (mpsc::Sender<CaughtEvent>, JoinHandle<()>) {
    spawn_stdout_writer(BufWriter::new(tokio::io::stdout()), stats)
}

fn spawn_stdout_writer<W>(
    writer: W,
    stats: Arc<AtomicEmitterStats>,
) -> (mpsc::Sender<CaughtEvent>, JoinHandle<()>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut receiver) = mpsc::channel::<CaughtEvent>(EMITTER_QUEUE_CAPACITY);
    let task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(event) = receiver.recv().await {
            let line = render_stdout(&event);
            if let Err(error) = writer.write_all(line.as_bytes()).await {
                stats.delivery_failed.fetch_add(1, Ordering::Relaxed);
                log::warn!("stdout event delivery failed: {error}");
                break;
            }
            if let Err(error) = writer.flush().await {
                stats.delivery_failed.fetch_add(1, Ordering::Relaxed);
                log::warn!("stdout event delivery failed: {error}");
                break;
            }
            stats.delivered.fetch_add(1, Ordering::Relaxed);
        }
    });
    (sender, task)
}

fn render_stdout(event: &CaughtEvent) -> String {
    format!(
        "event={:?} type={} message={:?} {}\n",
        &*event.definition.name,
        event.definition.kind,
        &*event.definition.message,
        render_record(&event.record),
    )
}

fn render_record(record: &crate::record::LogRecord) -> String {
    format!(
        "identity={:?} stream={:?} severity={} first_timestamp_ns={} last_timestamp_ns={} first_operation_id={} last_operation_id={} sample_percent={} integrity={:?} log={}",
        record.enrichment().description(),
        record.stream(),
        record.severity(),
        record.first_timestamp_ns(),
        record.last_timestamp_ns(),
        record.first_operation_id(),
        record.last_operation_id(),
        record.sample_percent(),
        record.integrity(),
        quote_bytes(record.bytes()),
    )
}

fn quote_bytes(bytes: &[u8]) -> String {
    let mut quoted = String::from("\"");
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                for character in text.chars() {
                    quoted.extend(character.escape_debug());
                }
                break;
            }
            Err(error) => {
                let valid = &remaining[..error.valid_up_to()];
                for character in std::str::from_utf8(valid)
                    .expect("prefix before UTF-8 error is valid")
                    .chars()
                {
                    quoted.extend(character.escape_debug());
                }
                let invalid = error
                    .error_len()
                    .unwrap_or(remaining.len() - error.valid_up_to());
                for byte in &remaining[error.valid_up_to()..error.valid_up_to() + invalid] {
                    use std::fmt::Write as _;
                    write!(quoted, "\\x{byte:02x}").expect("writing to String cannot fail");
                }
                remaining = &remaining[error.valid_up_to() + invalid..];
            }
        }
    }
    quoted.push('"');
    quoted
}

fn discord_content(event: &CaughtEvent) -> String {
    let content = format!(
        "{}\n{}",
        event.definition.message,
        render_record(&event.record)
    );
    if content.chars().count() <= DISCORD_CONTENT_CHARS {
        return content;
    }
    let keep = DISCORD_CONTENT_CHARS - TRUNCATED.chars().count();
    let mut truncated = content.chars().take(keep).collect::<String>();
    truncated.push_str(TRUNCATED);
    truncated
}

fn spawn_discord(
    config: DiscordEmitterConfig,
    secret: String,
    api: String,
    stats: Arc<AtomicEmitterStats>,
) -> (mpsc::Sender<CaughtEvent>, JoinHandle<()>) {
    let (sender, mut receiver) = mpsc::channel::<CaughtEvent>(EMITTER_QUEUE_CAPACITY);
    let task = tokio::spawn(async move {
        let client = Client::new();
        let endpoint = format!(
            "{}/channels/{}/messages",
            api.trim_end_matches('/'),
            config.channel_id
        );
        let authorization = format!("Bot {secret}");
        while let Some(event) = receiver.recv().await {
            let content = discord_content(&event);
            let response = client
                .post(&endpoint)
                .header(AUTHORIZATION, &authorization)
                .json(&DiscordMessage { content: &content })
                .send()
                .await;
            match response {
                Ok(response) if discord_success(response.status()) => {
                    stats.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Ok(response) => {
                    stats.delivery_failed.fetch_add(1, Ordering::Relaxed);
                    log::warn!(
                        "Discord event delivery failed with status {}",
                        response.status()
                    );
                }
                Err(error) => {
                    stats.delivery_failed.fetch_add(1, Ordering::Relaxed);
                    log::warn!("Discord event delivery failed: {error}");
                }
            }
        }
    });
    (sender, task)
}

fn discord_success(status: StatusCode) -> bool {
    status.is_success()
}

#[derive(Serialize)]
struct DiscordMessage<'a> {
    content: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enrichment::{ContainerId, Enrichment, KubernetesIdentity, WorkloadResolution},
        event::{EventDefinition, EventType},
        pipeline::StreamFileDescriptor,
        record::{LogRecord, RecordIntegrity, Severity},
    };
    use std::sync::Arc;
    use tokio::{io::AsyncReadExt as _, net::TcpListener};

    #[tokio::test]
    async fn discord_actor_posts_to_a_fake_endpoint_without_exposing_the_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4_096];
            let count = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("POST /channels/42/messages HTTP/1.1"));
            assert!(request.contains("authorization: Bot hush"));
            assert!(request.contains("Someone joined!\\nidentity="));
            assert!(request.contains(r#"log=\"database failed\""#));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let stats = Arc::new(AtomicEmitterStats::default());
        let (sender, task) = spawn_discord(
            DiscordEmitterConfig {
                channel_id: "42".into(),
                secret_from_env: "unused".into(),
            },
            "hush".into(),
            format!("http://{address}"),
            stats.clone(),
        );
        sender
            .send(CaughtEvent {
                definition: Arc::new(EventDefinition {
                    name: Arc::from("joined"),
                    kind: EventType::Info,
                    message: Arc::from("Someone joined!"),
                }),
                record: test_record(&b"database failed"[..]),
            })
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();
        server.await.unwrap();
        assert_eq!(stats.delivered.load(Ordering::Relaxed), 1);
        assert_eq!(stats.delivery_failed.load(Ordering::Relaxed), 0);
    }

    fn caught(kind: EventType, message: &str) -> CaughtEvent {
        CaughtEvent {
            definition: Arc::new(EventDefinition {
                name: Arc::from("joined\nnot-a-field"),
                kind,
                message: Arc::from(message),
            }),
            record: test_record(&b"actual error\n\xff"[..]),
        }
    }

    fn test_record(bytes: &[u8]) -> Arc<LogRecord> {
        Arc::new(LogRecord {
            sampling_seed: 1,
            stream: StreamFileDescriptor::Stderr,
            enrichment: Enrichment::Enriched(KubernetesIdentity {
                node: "node-1".into(),
                namespace: "games".into(),
                pod_name: "game-1".into(),
                pod_uid: "pod-1".into(),
                container_name: "server".into(),
                container_id: ContainerId {
                    runtime: "containerd".into(),
                    id: "a".repeat(64),
                },
                workload: WorkloadResolution::NoController,
            }),
            first_timestamp_ns: 10,
            last_timestamp_ns: 11,
            first_operation_id: 20,
            last_operation_id: 21,
            bytes: Arc::from(bytes),
            integrity: RecordIntegrity::default(),
            sample_percent: 100,
            severity: Severity::Unknown,
        })
    }

    #[test]
    fn stdout_rendering_is_stable_and_always_one_physical_line() {
        let rendered = render_stdout(&caught(EventType::Warning, "quote=\" slash=\\\nnext\r\0"));
        assert!(rendered.contains("event=\"joined\\nnot-a-field\" type=warning"));
        assert!(rendered.contains("identity=\"k8s=games/game-1/server pod_uid=pod-1"));
        assert!(rendered.contains("stream=Stderr severity=unknown"));
        assert!(rendered.contains("first_timestamp_ns=10 last_timestamp_ns=11"));
        assert!(rendered.ends_with("log=\"actual error\\n\\xff\"\n"));
        for kind in [EventType::Info, EventType::Warning, EventType::Error] {
            let rendered = render_stdout(&caught(kind, "hello"));
            assert_eq!(rendered.lines().count(), 1);
            assert!(rendered.contains(&format!("type={kind}")));
        }
    }

    #[tokio::test]
    async fn stdout_actor_delivers_and_counts_writer_failure() {
        let stats = Arc::new(AtomicEmitterStats::default());
        let (writer, mut reader) = tokio::io::duplex(4_096);
        let (sender, task) = spawn_stdout_writer(writer, stats.clone());
        sender.send(caught(EventType::Info, "hello")).await.unwrap();
        drop(sender);
        task.await.unwrap();
        let mut output = String::new();
        reader.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("event=\"joined\\nnot-a-field\" type=info message=\"hello\""));
        assert!(output.ends_with("log=\"actual error\\n\\xff\"\n"));
        assert_eq!(stats.delivered.load(Ordering::Relaxed), 1);

        let failed = Arc::new(AtomicEmitterStats::default());
        let (writer, reader) = tokio::io::duplex(1);
        drop(reader);
        let (sender, task) = spawn_stdout_writer(writer, failed.clone());
        sender.send(caught(EventType::Error, "nope")).await.unwrap();
        drop(sender);
        task.await.unwrap();
        assert_eq!(failed.delivery_failed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn discord_content_includes_the_log_and_marks_truncation() {
        let event = caught(EventType::Error, "An error occurred!");
        let content = discord_content(&event);
        assert!(content.starts_with("An error occurred!\nidentity="));
        assert!(content.ends_with("log=\"actual error\\n\\xff\""));
        let oversized = CaughtEvent {
            record: test_record(&vec![b'x'; DISCORD_CONTENT_CHARS * 2]),
            ..event
        };
        let content = discord_content(&oversized);
        assert_eq!(content.chars().count(), DISCORD_CONTENT_CHARS);
        assert!(content.ends_with(TRUNCATED));
    }
}
