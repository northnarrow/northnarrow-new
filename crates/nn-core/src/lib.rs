//! `nn-core` — detection, posture, correlation, the COMBAT and response
//! policies, signed content, the sensor contract and the bus types.
//!
//! Why a crate of its own: the common core: no OS call, no tokio, built for six
//! targets (the CI job `portable-core`). The content lists move here in R07,
//! the logic in R08.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]
