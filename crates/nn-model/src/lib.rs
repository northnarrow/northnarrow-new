//! `nn-model` — the vocabulary: events, verdicts, response actions and
//! outcomes, ProcessKey, PostureKind, log escaping, network addresses, the OCSF
//! mapping.
//!
//! Why a crate of its own: shared by nn-proto, the export, the server, nn-admin
//! and the watchdog, which need no engine. `common`'s model, posture_types,
//! netaddr, log_escape and the std types of `wire` move here in R02.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]
