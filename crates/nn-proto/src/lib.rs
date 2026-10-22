//! `nn-proto` — the admin protocol, the signed payloads, the quorum, the
//! shutdown marker, the watchdog hold, and the core/worker IPC.
//!
//! Why a crate of its own: shared with the watchdog and nn-admin. `common`'s
//! admin_protocol, admin_signed_payload, admin_quorum, shutdown_marker and
//! watchdog_hold move here in R03.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]
