// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]

//! Empty host-checkable target for the eBPF package.
//!
//! The real program is `main.rs` and is compiled for the BPF target through
//! Aya's `build-std` path. Cargo still needs this tiny library target so normal
//! workspace metadata and lint commands can inspect the package without trying
//! to link a `no_std` kernel program as a host executable.
