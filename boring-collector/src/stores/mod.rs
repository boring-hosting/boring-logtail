// SPDX-License-Identifier: GPL-3.0-or-later

//! Concrete storage adapters.

mod in_memory;
mod loki;

pub use in_memory::InMemoryLogStore;
pub use loki::{LokiConfig, LokiLogStore};
