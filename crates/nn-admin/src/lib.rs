//! `nn-admin` — the operator client's library.
//!
//! Why a crate of its own: the `nn-admin` binary stays a three-line shim in the
//! agent package (`CARGO_BIN_EXE_nn-admin`, the SBOMs, the release). admin_cli
//! and the logic of `bin/nn_admin.rs` move here in R10.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

/// The agent's identity on disk, read and never minted (R10, lab PR 259:
/// from nn-linux's `agent_id`).
pub mod agent_id;
/// What nn-admin needs of the host it runs on and of the agent it
/// administers, which the agent binds (R10, lab PR 259).
pub mod host;
