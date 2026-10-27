//! `nn-core` — detection, posture, correlation, the COMBAT and response
//! policies, signed content, the sensor contract and the bus types.
//!
//! Why a crate of its own: the common core: no OS call, no tokio, built for six
//! targets (the CI job `portable-core`). The content lists move here in R07,
//! the logic in R08. What the content code needs from the OS is a trait the
//! host implements ([`content_host::ContentHost`], R07, lab PR 247; the
//! agent's is `LinuxHost`).
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

/// What the content lists need from their host: an open that follows no
/// final symlink and blocks on no FIFO.
pub mod content_host;

/// Configuration content (R07, lab PR 247): the generic `.v1` + `.local`
/// list loader and what the loaders take from the signed-overlay gate (was
/// the agent's `config::overlay` and part of its `config::overlay_auth`).
pub mod config {
    /// The shipped `.v1` defaults and the operator's `.local` overlay of a
    /// flat list, merged.
    pub mod overlay;
    /// The verified overlay content, its hash, the bounded read.
    pub mod overlay_auth;
}

/// The agent's anti-tamper content (R07, lab PR 247): the COMBAT management
/// carve-out (was the agent's `anti_tamper::combat_allow`).
pub mod anti_tamper {
    /// The CIDRs COMBAT's isolation spares (`combat-allow.cidrs`).
    pub mod combat_allow;
}
