// SPDX-License-Identifier: GPL-3.0-or-later

//! The immutable userspace record shared after framing completes.
//!
//! A syscall write is not necessarily one log line. The application first
//! reconstructs writes and frames bytes; only then does it construct
//! [`LogRecord`]. Storage, matching, APIs, and emitters share that finished
//! value through `Arc` and never rewrite its bytes.

use std::{fmt, sync::Arc};

use crate::Enrichment;

/// Best-known meaning of the descriptor observed during capture.
///
/// `Stdout` and `Stderr` mean fd 1/2 candidates, not durable pipe identity;
/// redirection can make those numbers lie. The display spelling keeps that
/// caveat visible in diagnostic output.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]

pub enum StreamFileDescriptor {
    Stdout,
    Stderr,
    Other(u32),
    Unknown,
}

impl From<Option<u32>> for StreamFileDescriptor {
    fn from(fd: Option<u32>) -> Self {
        match fd {
            Some(1) => Self::Stdout,
            Some(2) => Self::Stderr,
            Some(other) => Self::Other(other),
            None => Self::Unknown,
        }
    }
}

impl fmt::Display for StreamFileDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => formatter.write_str("stdout-candidate"),
            Self::Stderr => formatter.write_str("stderr-candidate"),
            Self::Other(fd) => write!(formatter, "fd-{fd}"),
            Self::Unknown => formatter.write_str("unknown-candidate"),
        }
    }
}

impl StreamFileDescriptor {
    pub const fn sampling_bytes(self) -> [u8; 5] {
        match self {
            Self::Stdout => [0, 0, 0, 0, 1],
            Self::Stderr => [0, 0, 0, 0, 2],
            Self::Other(fd) => {
                let bytes = fd.to_le_bytes();

                [1, bytes[0], bytes[1], bytes[2], bytes[3]]
            }
            Self::Unknown => [2, 0, 0, 0, 0],
        }
    }
}

/// Explicit evidence that a record is incomplete or was split by a bound.
///
/// A `false` field means that particular loss was not observed; it is not a
/// universal proof that every upstream boundary was lossless.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]

pub struct RecordIntegrity {
    pub capture_truncated: bool,
    pub payload_read_failed: bool,
    pub max_size_split: bool,
    pub capacity_split: bool,
    pub capture_gap: bool,
    pub unterminated: bool,
}

/// Semantic severity when known. Capture alone normally leaves this `Unknown`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]

pub enum Severity {
    #[default]
    Unknown,
    Info,
    Warn,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "unknown",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        })
    }
}

// DO not do private/public and getters. just make them public.
/// One byte-preserving framed log record plus its capture/source facts.
///
/// Fields are public data rather than active resources. In normal operation a
/// record is finalized and immediately placed in `Arc`, making shared reads
/// cheap while the store, catchers, and emitters retain independent references.
#[derive(Debug, Eq, PartialEq)]

pub struct LogRecord {
    pub observed_at: jiff::Timestamp,
    pub sampling_seed: u64,
    pub stream: StreamFileDescriptor,
    pub enrichment: Enrichment,
    // In case we need to figure out delay/freshness
    pub first_timestamp_ns: u64,
    pub last_timestamp_ns: u64,

    // Some additional metadata regarding construction.
    pub first_operation_id: u64,
    pub last_operation_id: u64,

    pub bytes: Arc<[u8]>,
    pub integrity: RecordIntegrity,
    pub sample_percent: u8,
    pub severity: Severity,
}

// I really dislike getters and setters.
impl LogRecord {
    #[allow(clippy::too_many_arguments)]

    pub fn new(
        observed_at: jiff::Timestamp,
        sampling_seed: u64,
        stream: StreamFileDescriptor,
        enrichment: Enrichment,
        first_timestamp_ns: u64,
        last_timestamp_ns: u64,
        first_operation_id: u64,
        last_operation_id: u64,
        bytes: Arc<[u8]>,
        integrity: RecordIntegrity,
        sample_percent: u8,
        severity: Severity,
    ) -> Self {
        Self {
            observed_at,
            sampling_seed,
            stream,
            enrichment,
            first_timestamp_ns,
            last_timestamp_ns,
            first_operation_id,
            last_operation_id,
            bytes,
            integrity,
            sample_percent,
            severity,
        }
    }

    pub fn observed_at(&self) -> jiff::Timestamp {
        self.observed_at
    }

    pub fn sampling_seed(&self) -> u64 {
        self.sampling_seed
    }

    pub fn stream(&self) -> StreamFileDescriptor {
        self.stream
    }

    pub fn enrichment(&self) -> &Enrichment {
        &self.enrichment
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn integrity(&self) -> RecordIntegrity {
        self.integrity
    }

    pub fn sample_percent(&self) -> u8 {
        self.sample_percent
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn first_timestamp_ns(&self) -> u64 {
        self.first_timestamp_ns
    }

    pub fn last_timestamp_ns(&self) -> u64 {
        self.last_timestamp_ns
    }

    pub fn first_operation_id(&self) -> u64 {
        self.first_operation_id
    }

    pub fn last_operation_id(&self) -> u64 {
        self.last_operation_id
    }
}
