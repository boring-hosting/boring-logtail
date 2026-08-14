// SPDX-License-Identifier: GPL-3.0-or-later

//! Compact, bounded Discord alerts.
//!
//! Discord is an alert surface, not a raw record dump. The renderer includes
//! only useful identity, neutralizes markdown fences and mentions, and truncates
//! before Discord's embed limit. HTTP remains entirely inside this worker.

use std::sync::Arc;

use blt_model::{CaughtEvent, Enrichment, EventType, StreamFileDescriptor};
use reqwest::{Client, header::AUTHORIZATION};
use serde::Serialize;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{AtomicEmitterStats, DiscordConfig, channel};

pub(super) const DISCORD_API: &str = "https://discord.com/api/v10";

const DESCRIPTION_CHARS: usize = 4_096;

const TRUNCATED: &str = "...[truncated]";

const INFO_COLOR: u32 = 0x3b82f6;

const WARNING_COLOR: u32 = 0xf59e0b;

const ERROR_COLOR: u32 = 0xef4444;

pub(super) fn spawn(
    config: DiscordConfig,
    stats: Arc<AtomicEmitterStats>,
) -> (mpsc::Sender<CaughtEvent>, JoinHandle<()>) {
    let (sender, mut receiver) = channel();

    let task = tokio::spawn(async move {
        let client = Client::new();

        let endpoint = format!(
            "{}/channels/{}/messages",
            config.api.trim_end_matches('/'),
            config.channel_id,
        );

        let authorization = format!("Bot {}", config.secret);

        while let Some(event) = receiver.recv().await {
            let response = client
                .post(&endpoint)
                .header(AUTHORIZATION, &authorization)
                .json(&render(&event))
                .send()
                .await;

            match response {
                Ok(response) if response.status().is_success() => stats.delivered(),
                Ok(response) => {
                    stats.failed();

                    log::warn!(
                        "Discord event delivery failed with status {}",
                        response.status()
                    );
                }
                Err(error) => {
                    stats.failed();

                    log::warn!("Discord event delivery failed: {error}");
                }
            }
        }
    });

    (sender, task)
}

fn render(event: &CaughtEvent) -> DiscordMessage {
    let record = &event.record;

    let rendered_log = render_log(record.bytes());

    // Replace backticks before adding our own fence. Otherwise captured text
    // could close the code block and turn the rest into active Discord markup.
    let mut log = rendered_log.replace('`', "ˋ");

    let wrapper_chars = "```text\n\n```".chars().count();

    let available = DESCRIPTION_CHARS - wrapper_chars;

    if log.chars().count() > available {
        let keep = available - TRUNCATED.chars().count();

        log = log.chars().take(keep).collect();

        log.push_str(TRUNCATED);
    }

    let mut fields = Vec::with_capacity(4);

    match record.enrichment() {
        Enrichment::Enriched(identity) | Enrichment::Stale(identity) => {
            fields.push(DiscordField::inline("Namespace", &identity.namespace));

            fields.push(DiscordField::inline("Pod", &identity.pod_name));

            fields.push(DiscordField::inline("Container", &identity.container_name));
        }
        enrichment => fields.push(DiscordField::inline("Source", enrichment.description())),
    }

    fields.push(DiscordField::inline(
        "Stream",
        match record.stream() {
            StreamFileDescriptor::Stdout => "stdout".to_owned(),
            StreamFileDescriptor::Stderr => "stderr".to_owned(),
            StreamFileDescriptor::Other(fd) => format!("fd {fd}"),
            StreamFileDescriptor::Unknown => "unknown".to_owned(),
        },
    ));

    DiscordMessage {
        embeds: vec![DiscordEmbed {
            title: event.definition.message.to_string(),
            description: format!("```text\n{log}\n```"),
            color: match event.definition.kind {
                EventType::Info => INFO_COLOR,
                EventType::Warning => WARNING_COLOR,
                EventType::Error => ERROR_COLOR,
            },
            fields,
            timestamp: record.observed_at().to_string(),
        }],
        // Never let captured application text ping users, roles, or everyone.
        allowed_mentions: AllowedMentions { parse: Vec::new() },
    }
}

/// Render structured application logs as structured text without changing the
/// stored bytes. The fallback keeps arbitrary bytes exact and visible.

fn render_log(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let text = text.trim_end_matches(['\r', '\n']);

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            return serde_json::to_string_pretty(&json)
                .expect("a parsed JSON value always serializes");
        }
    }

    let quoted = super::stdout::quote_bytes(bytes);

    quoted[1..quoted.len() - 1].to_owned()
}

#[derive(Debug, Serialize)]

struct DiscordMessage {
    embeds: Vec<DiscordEmbed>,
    allowed_mentions: AllowedMentions,
}

#[derive(Debug, Serialize)]

struct DiscordEmbed {
    title: String,
    description: String,
    color: u32,
    fields: Vec<DiscordField>,
    timestamp: String,
}

#[derive(Debug, Serialize)]

struct DiscordField {
    name: &'static str,
    value: String,
    inline: bool,
}

impl DiscordField {
    fn inline(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            value: value.into(),
            inline: true,
        }
    }
}

#[derive(Debug, Serialize)]

struct AllowedMentions {
    parse: Vec<String>,
}

#[cfg(test)]

mod tests {

    use blt_model::{
        ContainerId, EventDefinition, KubernetesIdentity, LogRecord, RecordIntegrity, Severity,
        WorkloadResolution,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::*;

    fn caught(kind: EventType, bytes: &[u8], enrichment: Enrichment) -> CaughtEvent {
        CaughtEvent {
            definition: Arc::new(EventDefinition {
                name: Arc::from("joined"),
                kind,
                message: Arc::from("Someone joined!"),
            }),
            record: Arc::new(LogRecord::new(
                "2026-08-12T18:00:00Z".parse().unwrap(),
                1,
                StreamFileDescriptor::Stderr,
                enrichment,
                10,
                11,
                20,
                21,
                Arc::from(bytes),
                RecordIntegrity::default(),
                100,
                Severity::Unknown,
            )),
        }
    }

    fn identity() -> Enrichment {
        Enrichment::Enriched(KubernetesIdentity {
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
        })
    }

    #[test]

    fn embed_is_compact_safe_and_bounded() {
        let message = render(&caught(EventType::Error, b"actual error\n\xff", identity()));

        let embed = &message.embeds[0];

        assert_eq!(embed.color, ERROR_COLOR);

        assert_eq!(embed.timestamp, "2026-08-12T18:00:00Z");

        assert_eq!(
            embed
                .fields
                .iter()
                .map(|field| field.name)
                .collect::<Vec<_>>(),
            ["Namespace", "Pod", "Container", "Stream"]
        );

        assert!(embed.description.contains("actual error\\n\\xff"));

        let json = serde_json::to_string(&message).unwrap();

        for forbidden in ["pod_uid", "container_id", "workload", "operation_id"] {
            assert!(!json.contains(forbidden), "Discord leaked {forbidden}");
        }

        assert!(json.contains(r#""parse":[]"#));

        let oversized = caught(
            EventType::Info,
            &vec![b'x'; DESCRIPTION_CHARS * 2],
            Enrichment::UnresolvedCgroup,
        );

        let description = &render(&oversized).embeds[0].description;

        assert_eq!(description.chars().count(), DESCRIPTION_CHARS);

        assert!(description.contains(TRUNCATED));

        assert!(description.ends_with("\n```"));

        assert_eq!(
            render(&caught(EventType::Warning, b"x", identity())).embeds[0].color,
            WARNING_COLOR
        );

        assert_eq!(
            render(&caught(EventType::Info, b"`@everyone`", identity())).embeds[0].color,
            INFO_COLOR
        );

        assert!(
            !render(&caught(EventType::Info, b"`@everyone`", identity())).embeds[0]
                .description
                .contains("`@everyone`")
        );
    }

    #[test]

    fn json_is_readable_while_non_json_bytes_remain_escaped() {
        let bytes = br#"{"level":"error","message":"leader changed"}
"#;

        let event = caught(EventType::Error, bytes, identity());

        let description = &render(&event).embeds[0].description;

        assert!(description.contains("\n  \"level\": \"error\","));

        assert!(!description.contains("\\\"level\\\""));

        assert_eq!(event.record.bytes(), bytes);

        assert_eq!(render_log(b"bad\n\xff"), "bad\\n\\xff");
    }

    #[test]

    fn runtime_config_debug_redacts_the_secret() {
        let debug = format!("{:?}", DiscordConfig::new("42", "hush"));

        assert!(debug.contains("[redacted]"));

        assert!(!debug.contains("hush"));
    }

    #[tokio::test]

    async fn actor_posts_to_a_fake_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut request = Vec::new();

            let mut chunk = [0; 1_024];

            loop {
                let count = stream.read(&mut chunk).await.unwrap();

                assert_ne!(count, 0);

                request.extend_from_slice(&chunk[..count]);

                let Some(headers_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                else {
                    continue;
                };

                let headers = String::from_utf8_lossy(&request[..headers_end]);

                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;

                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap();

                if request.len() >= headers_end + 4 + content_length {
                    break;
                }
            }

            let request = String::from_utf8_lossy(&request);

            assert!(request.contains("authorization: Bot hush"));

            assert!(request.contains(r#""title":"Someone joined!""#));

            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let stats = Arc::new(AtomicEmitterStats::default());

        let config = DiscordConfig::new("42", "hush").with_api(format!("http://{address}"));

        let (sender, task) = spawn(config, stats.clone());

        sender
            .send(caught(EventType::Info, b"database failed", identity()))
            .await
            .unwrap();

        drop(sender);

        task.await.unwrap();

        server.await.unwrap();

        assert_eq!(stats.snapshot().delivered, 1);
    }
}
