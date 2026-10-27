//! `nn-core` — detection, posture, correlation, the COMBAT and response
//! policies, signed content, the sensor contract and the bus types.
//!
//! Why a crate of its own: the common core: no OS call, no tokio, built for six
//! targets (the CI job `portable-core`). The content lists move here in R07,
//! the logic in R08. What the content code needs from the OS is a trait the
//! host implements ([`content_host::ContentHost`], R07, lab PR 247; the
//! agent's is `LinuxHost`); so is what the posture reads from its host — the
//! process table, the host's files, the clocks — and what it consults in the
//! agent's other modules until they move here ([`posture::host`], R08a, lab
//! PR 250).
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

/// What the content lists need from their host: an open that follows no
/// final symlink and blocks on no FIFO.
pub mod content_host;

// The bounded buffer of recent events the posture's triggers count over
// (R08a, lab PR 250; was the agent's `correlation`). No outer doc comment on
// a moved module: rustdoc would resolve its own `//!` links from here.
pub mod correlation;

// The per-(rule, uid) budget of logging and storing detections (R08a, lab
// PR 250; was the agent's `detection_budget`, without its reporter task).
pub mod detection_budget;

/// The decision engine (R08b, lab PR 251): what it does on its host
/// (`decision::host`, the agent's `LinuxHost`).
pub mod decision {
    /// The host's calls the engine makes: the package database's `rpm`, the
    /// work kept off the async runtime, the host's view of a path, the
    /// trusted-installer window, the kernel's map of the security tools.
    pub mod host;
}

/// The ransomware signal (R08b, lab PR 251): the entropy of what a burst
/// left behind (cut from the agent's `impact::entropy`).
pub mod impact {
    /// What a sampling found, what samples, the measure, the containers.
    pub mod entropy;
}

// The adaptive defensive posture (R08a, lab PR 250; was the agent's
// `posture`): the state machine, its triggers, the corroboration ledger, the
// lineage, the stack exemption, the operator's two overlays, and what it
// needs from its host (`posture::host`).
pub mod posture;

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
/// (was the agent's `canary::templates`); R08a (lab PR 250): the readers a
/// File or Credential canary spares (was the agent's `canary::readers`).
pub mod canary {
    // The programs whose read of a File or Credential canary is recorded,
    // not killed: judged on what the kernel executed (R08a, lab PR 250).
    pub mod readers;
    /// The five credential families' decoys, rendered from a seed.
    pub mod templates;
}

// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the path the
// moved lineage names, so it compiles as it was in the agent.
/// `crate::path_text::…`, the open sensor's path text (nn-model's).
use nn_model::path_text;

/// The network state the rules read (R08b, lab PR 251): the operator's
/// blocklists, the DNS cache, the host's configured DNS resolvers (were the
/// agent's `net::blocklist`, the state of its `net::dns_cache` and its
/// `net::resolvers`).
pub mod net {
    // The operator's NetFlow and JA3 blocklists (Tappa 10, N6).
    pub mod blocklist;
    // The PID-keyed DNS query cache: a connect's name, a forwarded query's
    // originator (Tappa 10, N4).
    pub mod dns_cache;
    // The `nameserver`s of the host's `resolv.conf`, re-read when they
    // change (lab PR 224).
    pub mod resolvers;
}

/// FIM content (R07, lab PR 247): the watched paths (was the agent's
/// `fim::paths_config`); R08b (lab PR 251): the anti-tamper baits.
pub mod fim {
    /// The anti-tamper baits: each path with its template (R08b, lab PR 251;
    /// cut from the agent's `fim::honeypot`).
    pub mod baits;
    /// The shipped `fim-paths.v1` and the operator's `fim-paths.local`.
    pub mod paths_config;
}

/// The agent's anti-tamper content (R07, lab PR 247): the COMBAT management
/// carve-out (was the agent's `anti_tamper::combat_allow`); R08b (lab PR
/// 251): the trusted-installer window's vocabulary.
pub mod anti_tamper {
    /// The CIDRs COMBAT's isolation spares (`combat-allow.cidrs`).
    pub mod combat_allow;
    /// The trusted-installer window's vocabulary: the agent's own units, a
    /// window's grant (R08b, lab PR 251).
    pub mod trusted_installer;
}
