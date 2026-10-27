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

/// The bounded buffer of recent events the posture's triggers count over
/// (R08a, lab PR 250; was the agent's `correlation`).
pub mod correlation;

/// The per-(rule, uid) budget of logging and storing detections (R08a, lab
/// PR 250; was the agent's `detection_budget`, without its reporter task).
pub mod detection_budget;

/// The adaptive defensive posture (R08a, lab PR 250; was the agent's
/// `posture`).
pub mod posture {
    /// The corroboration ledger: the escalation signals of each actor's
    /// scope, recent enough to vouch for a blunt heuristic.
    pub mod corroboration;
    /// The operator's escalation allowlist: process × destination tuples
    /// the exfiltration and lateral-movement counts leave out.
    pub mod escalation_allow;
    /// The operator's carve-out of the mass-write arm.
    pub mod mass_write_overlay;
    /// The live state, with its monotonic timestamps.
    pub mod state;
    /// The transitions: a trigger's level, the decay.
    pub mod transitions;
}

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

/// Deception content (R07, lab PR 247): the credential canaries' renderer
/// (was the agent's `canary::templates`).
pub mod canary {
    /// The five credential families' decoys, rendered from a seed.
    pub mod templates;
}

/// FIM content (R07, lab PR 247): the watched paths (was the agent's
/// `fim::paths_config`).
pub mod fim {
    /// The shipped `fim-paths.v1` and the operator's `fim-paths.local`.
    pub mod paths_config;
}

/// The agent's anti-tamper content (R07, lab PR 247): the COMBAT management
/// carve-out (was the agent's `anti_tamper::combat_allow`).
pub mod anti_tamper {
    /// The CIDRs COMBAT's isolation spares (`combat-allow.cidrs`).
    pub mod combat_allow;
}
