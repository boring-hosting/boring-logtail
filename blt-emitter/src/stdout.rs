// SPDX-License-Identifier: GPL-3.0-or-later

//! Diagnostic one-line delivery to standard output.
//!
//! The whole record is rendered into one owned buffer before one write/flush
//! cycle. Quoting turns newlines, controls, and invalid UTF-8 into visible
//! escapes so captured bytes cannot forge a second physical log line.

use std::sync::Arc;

use blt_model::{CaughtEvent, LogRecord};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt as _, BufWriter},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{AtomicEmitterStats, channel};

pub(super) fn spawn(stats: Arc<AtomicEmitterStats>) -> (mpsc::Sender<CaughtEvent>, JoinHandle<()>) {
    spawn_writer(BufWriter::new(tokio::io::stdout()), stats)
}

fn spawn_writer<W>(
    writer: W,
    stats: Arc<AtomicEmitterStats>,
) -> (mpsc::Sender<CaughtEvent>, JoinHandle<()>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut receiver) = channel();

    let task = tokio::spawn(async move {
        let mut writer = writer;

        while let Some(event) = receiver.recv().await {
            let line = render(&event);

            if let Err(error) = writer.write_all(line.as_bytes()).await {
                stats.failed();

                log::warn!("stdout event delivery failed: {error}");

                break;
            }

            if let Err(error) = writer.flush().await {
                stats.failed();

                log::warn!("stdout event delivery failed: {error}");

                break;
            }

            stats.delivered();
        }
    });

    (sender, task)
}

fn render(event: &CaughtEvent) -> String {
    format!(
        "event={:?} type={} message={:?} {}\n",
        &*event.definition.name,
        event.definition.kind,
        &*event.definition.message,
        render_record(&event.record),
    )
}

fn render_record(record: &LogRecord) -> String {
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

pub(super) fn quote_bytes(bytes: &[u8]) -> String {
    // Walk valid UTF-8 in chunks. On an invalid sequence, preserve its exact
    // bytes as \xNN and resume after it; lossy replacement would destroy the
    // evidence this diagnostic emitter is meant to expose.
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

#[cfg(test)]

mod tests {

    use std::sync::Arc;

    use blt_model::{
        CaughtEvent, Enrichment, EventDefinition, EventType, LogRecord, RecordIntegrity, Severity,
        StreamFileDescriptor,
    };
    use tokio::io::AsyncReadExt as _;

    use super::*;

    fn caught(kind: EventType, message: &str) -> CaughtEvent {
        CaughtEvent {
            definition: Arc::new(EventDefinition {
                name: Arc::from("joined\nnot-a-field"),
                kind,
                message: Arc::from(message),
            }),
            record: Arc::new(LogRecord::new(
                "2026-08-12T18:00:00Z".parse().unwrap(),
                1,
                StreamFileDescriptor::Stderr,
                Enrichment::UnresolvedCgroup,
                10,
                11,
                20,
                21,
                Arc::from(&b"actual error\n\xff"[..]),
                RecordIntegrity::default(),
                100,
                Severity::Unknown,
            )),
        }
    }

    #[test]

    fn rendering_is_stable_and_always_one_physical_line() {
        let rendered = render(&caught(EventType::Warning, "quote=\" slash=\\\nnext\r\0"));

        assert!(rendered.contains("event=\"joined\\nnot-a-field\" type=warning"));

        assert!(rendered.contains("stream=Stderr severity=unknown"));

        assert!(rendered.contains("first_timestamp_ns=10 last_timestamp_ns=11"));

        assert!(rendered.ends_with("log=\"actual error\\n\\xff\"\n"));

        assert_eq!(rendered.lines().count(), 1);
    }

    #[tokio::test]

    async fn actor_delivers_and_counts_writer_failure() {
        let stats = Arc::new(AtomicEmitterStats::default());

        let (writer, mut reader) = tokio::io::duplex(4_096);

        let (sender, task) = spawn_writer(writer, stats.clone());

        sender.send(caught(EventType::Info, "hello")).await.unwrap();

        drop(sender);

        task.await.unwrap();

        let mut output = String::new();

        reader.read_to_string(&mut output).await.unwrap();

        assert!(output.contains("type=info message=\"hello\""));

        assert_eq!(stats.snapshot().delivered, 1);

        let failed = Arc::new(AtomicEmitterStats::default());

        let (writer, reader) = tokio::io::duplex(1);

        drop(reader);

        let (sender, task) = spawn_writer(writer, failed.clone());

        sender.send(caught(EventType::Error, "nope")).await.unwrap();

        drop(sender);

        task.await.unwrap();

        assert_eq!(failed.snapshot().delivery_failed, 1);
    }
}
