// SPDX-License-Identifier: GPL-3.0-or-later

//! Bulk log storage ports and the Loki adapter which implements them.

mod loki;
mod ports;

pub use loki::{LokiConfig, LokiLogStore};
pub use ports::{
    ExportError, LogEntry, LogReader, LogSink, PortLogStream, ReadError, ReadRequest, ReadSelector,
};
