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
//! PR 250). R08b (lab PR 251) moves the decision engine here — its rules,
//! the multi-match combination, the signed per-rule policy, the network
//! state the rules read, the ransomware and security-tool judges, the
//! canary detector — and what they do on their host is a trait the host
//! implements too ([`decision::host`], [`canary::host`]).
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

// The decision engine (R08b, lab PR 251; was the agent's `decision`): the
// rules, the multi-match combination, the signed per-rule policy, the held
// responses, the replay, the ATT&CK mapping and the rule catalogue's table,
// the chain rules' correlation state, and what the engine does on its host
// (`decision::host`).
pub mod decision;

// The ransomware signal (R08b, lab PR 251; was the agent's `impact`, without
// its sampler of the host's files): the tracker the NN-L-IMP rules and the
// posture share.
pub mod impact;

// Defences switched off (R08b, lab PR 251; was the agent's `impair`): the
// security-tool detector the NN-L-EVA rules and the posture share, and its
// shipped list.
pub mod impair;

// The adaptive defensive posture (R08a, lab PR 250; was the agent's
// `posture`): the state machine, its triggers, the corroboration ledger, the
// lineage, the stack exemption, the operator's two overlays, and what it
// needs from its host (`posture::host`).
pub mod posture;

/// Configuration content (R07, lab PR 247): the generic `.v1` + `.local`
/// list loader and what the loaders take from the signed-overlay gate (was
/// the agent's `config::overlay` and part of its `config::overlay_auth`);
/// R08b (lab PR 251): the comm allowlists (were the agent's
/// `config::comm_allowlist`).
pub mod config {
    // The process and network comm allowlists (Tappa 10.5, D1; R08b, lab PR
    // 251, with the rules that judge on them).
    pub mod comm_allowlist;
    /// The shipped `.v1` defaults and the operator's `.local` overlay of a
    /// flat list, merged.
    pub mod overlay;
    /// The verified overlay content, its hash, the bounded read.
    pub mod overlay_auth;
}

/// Deception content (R07, lab PR 247): the credential canaries' renderer
/// (was the agent's `canary::templates`); R08a (lab PR 250): the readers a
/// File or Credential canary spares (was the agent's `canary::readers`);
/// R08b (lab PR 251): the canary detector (was the agent's
/// `canary::detector`) and the network canaries' addresses (from the
/// agent's `canary::network`).
pub mod canary {
    // The programs whose read of a File or Credential canary is recorded,
    // not killed: judged on what the kernel executed (R08a, lab PR 250).
    pub mod readers;
    /// The five credential families' decoys, rendered from a seed.
    pub mod templates;
    // R08b (lab PR 251): the inline filter that turns an access to a
    // deployed canary into its trip (Tappa 9.5 K3), what it does on its host
    // (`canary::host`), and the network canaries' addresses it matches a
    // connect on.
    pub mod detector;
    pub mod host;
    pub mod network;
}

// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the path the
// moved lineage names, so it compiles as it was in the agent.
/// `crate::path_text::…`, the open sensor's path text (nn-model's).
use nn_model::path_text;

// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the path the
// moved engine names for the parts of a detection record it reads.
/// `crate::detection_payload::…`, nn-evidence's.
use nn_evidence::detection_payload;

/// The network state the rules read (R08b, lab PR 251): the operator's
/// blocklists, the DNS cache, the flow tracker, the netflow pacing, the
/// host's configured DNS resolvers (were the agent's `net::blocklist`, the
/// state of its `net::dns_cache`, its `net::flow_tracker`, `net::limiter`
/// and `net::resolvers`).
pub mod net {
    // The operator's NetFlow and JA3 blocklists (Tappa 10, N6).
    pub mod blocklist;
    // The PID-keyed DNS query cache: a connect's name, a forwarded query's
    // originator (Tappa 10, N4).
    pub mod dns_cache;
    // The TCP connect → close tracker, the flow id, the open-flow snapshots
    // (Tappa 10, N3).
    pub mod flow_tracker;
    // The netflow rows handed to the rules, paced per uid (external audit
    // NET-019).
    pub mod limiter;
    // The `nameserver`s of the host's `resolv.conf`, re-read when they
    // change (lab PR 224).
    pub mod resolvers;
}

/// FIM content (R07, lab PR 247): the watched paths (was the agent's
/// `fim::paths_config`); R08b (lab PR 251): the anti-tamper baits, the
/// drift's classification and the FIM rules (were the agent's
/// `fim::rules` and part of its `fim::drain`).
pub mod fim {
    /// The anti-tamper baits: each path with its template (R08b, lab PR 251;
    /// cut from the agent's `fim::honeypot`).
    pub mod baits;
    /// The drift's provisional severity, its classifier and the per-tier
    /// token bucket (R08b, lab PR 251; cut from the agent's `fim::drain`).
    pub mod drift;
    /// The shipped `fim-paths.v1` and the operator's `fim-paths.local`.
    pub mod paths_config;
    // The FIM, credential-read and file-capability rules (Tappa 9; R08b,
    // lab PR 251, with the engine).
    pub mod rules;
}

/// The COMBAT ladder (R08c, lab PR 252): who it acts against, as its
/// signed rows name them (was the agent's `combat::offender`).
pub mod combat {
    /// An offender's identity as the ladder captured it: pid, starts,
    /// executable, cgroup, how it joined the episode.
    pub mod offender;
}

/// The agent's anti-tamper content (R07, lab PR 247): the COMBAT management
/// carve-out (was the agent's `anti_tamper::combat_allow`); R08b (lab PR
/// 251): the trusted-installer window's vocabulary; R08c (lab PR 252): the
/// isolation's read-back vocabulary.
pub mod anti_tamper {
    /// The CIDRs COMBAT's isolation spares (`combat-allow.cidrs`).
    pub mod combat_allow;
    /// An IP family and what an isolation found in its table, read back
    /// (R08c, lab PR 252; cut from the agent's
    /// `anti_tamper::network_isolate`).
    pub mod network_isolate;
    /// The trusted-installer window's vocabulary: the agent's own units, a
    /// window's grant (R08b, lab PR 251).
    pub mod trusted_installer;
}
