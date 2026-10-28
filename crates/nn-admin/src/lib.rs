//! `nn-admin` — the operator client's library.
//!
//! Why a crate of its own: the operator's client signs requests, reads and
//! verifies the chains, sets overlays and the per-rule policy, restores
//! quarantine; it needs the admin protocol (nn-proto), the chains'
//! verification (nn-evidence), the content and policy rules (nn-core) and
//! the vocabulary (nn-model), not the engine's host, not the agent. What it
//! reads of the Linux host and of the agent goes through [`host::AdminHost`],
//! which the agent implements; the `nn-admin` binary stays a three-line
//! shim in the agent package (`CARGO_BIN_EXE_nn-admin`, the SBOMs, the
//! release) that passes the agent's host to [`main`].
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs. R10 (lab PR 259): the agent's
//! `admin_cli` and the logic of its `bin/nn_admin.rs` ([`cli`]) moved here.

#![forbid(unsafe_code)]

use std::process::ExitCode;

/// The library half of the command line: the transport, the signed
/// requests, the readers and verifiers (was the agent's `admin_cli`).
pub mod admin_cli;
/// The agent's identity on disk, read and never minted (R10, lab PR 259:
/// from nn-linux's `agent_id`).
pub mod agent_id;
/// The command line: clap's dispatcher, the rendering, the exit codes (was
/// the agent's `bin/nn_admin.rs`).
pub mod cli;
/// What nn-admin needs of the host it runs on and of the agent it
/// administers, which the agent binds (R10, lab PR 259).
pub mod host;

// R10 (lab PR 259; plan §4.1 rule 2, removed in R17): the paths the moved
// code names keep resolving — the chains' readers and verifiers and the OS
// CSPRNG are nn-evidence's, the overlays' content and signature file
// nn-core's, as they were through the agent's shims.
pub(crate) use nn_core::config;
pub(crate) use nn_evidence::{audit, os_rng, verify_lines};

/// `nn-admin`: the command line on `host` (the agent's, from the binary).
pub fn main<H: host::AdminHost>(host: &H) -> ExitCode {
    cli::run(host)
}
