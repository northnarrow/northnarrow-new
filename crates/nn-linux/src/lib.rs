//! `nn-linux` — the Linux adapters: the eBPF loader and sensors, /proc, the
//! actuators, self-defence, systemd, the KeyStore and the sandbox.
//!
//! Why a crate of its own: the one place for aya, /proc, cgroups, netfilter,
//! systemd and keys on disk; another OS would be a sibling crate. The adapters
//! move here in R09. R09a (lab PR 253) moves the actuators — the executor and
//! its actions (kill, quarantine, the egress block, the throttle, the
//! containment and its release), the COMBAT ladder's production actuator,
//! host-critical guard and stale chain's compatibility line —, the
//! self-defence (`anti_tamper`: the LSM deny hooks and their kernel maps, the
//! BPF guard, the BTF revalidation, the fail-open counters, the network
//! isolator, the trusted-installer window, the admin key set), the agent's
//! signing key, and the utilities they stand on. With the key goes the
//! agent's Linux host, [`LinuxHost`](chain_host_linux::LinuxHost): the key's
//! chains are written on it, and the implementations of nn-core's and
//! nn-evidence's host traits on it go with it (a trait of another crate on a
//! type of another crate is implemented in neither the agent nor nn-core) —
//! the chains', the content lists', the posture's, the decision engine's,
//! the canary detector's and the COMBAT ladder's — with what they name: the
//! canary registry and access log, the interface addresses and the
//! read-forward set, the sampler of the host's files, the DNS pump's ingest.
//!
//! The only crate of the layout where `unsafe` is allowed (no
//! `#![forbid(unsafe_code)]`, R01): its blocks moved verbatim, each with its
//! `SAFETY` comment.
//!
//! The moved modules carry no outer doc comment here: rustdoc would resolve
//! their own `//!` links from this file (nn-core's way, lab PR 250).
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

// The per-install agent identity (`/var/lib/northnarrow/agent_id`), read
// once at boot (R09a, lab PR 253; was the agent's `agent_id`).
pub mod agent_id;

// A log's directory held open, so its path resolves through the descriptor
// taken at start (R09a; was the agent's `anchored`).
pub mod anchored;

// The agent's self-defence (Tappa 7): the LSM deny hooks and the kernel
// maps they read, the BPF guard, the BTF revalidation, the fail-open
// counters, the COMBAT network isolator, the trusted-installer window, the
// admin key set and its challenge (R09a; was the agent's `anti_tamper`; its
// COMBAT carve-out is nn-core's, `anti_tamper::combat_allow`).
pub mod anti_tamper;

// A raw descriptor in tokio's reactor (R09a; was the agent's `async_fd`).
pub mod async_fd;

// Replacing a file the agent protects, without following a planted link
// (R09a; was the agent's `atomic_file`, the path of `antitamper-bpf`'s).
pub mod atomic_file;

// An external command with a deadline (R09a; was the agent's
// `bounded_cmd`).
pub mod bounded_cmd;

/// Deception (R09a, lab PR 253): the stores of the canary detector's host —
/// the signed registry of deployed canaries and their access log, this
/// host's interface addresses, the read-forward set the FIM drain consults
/// (were the agent's `canary::{registry, access_log, network,
/// read_forward}`; the detector is nn-core's, the decoys' path policy
/// R09b's).
pub mod canary {
    // The chained log of canary accesses (Tappa 9.5 K3).
    pub mod access_log;
    // What a Network canary covers and its deploy check; this host's
    // addresses (lab PR 163).
    pub mod network;
    // The canaries' inodes whose read the FIM drain forwards (lab PR 178).
    pub mod read_forward;
    // The chained registry of deployed canaries (Tappa 9.5 K2).
    pub mod registry;

    // R09a shim (plan §4.1 rule 2, removed in R17): the path the moved
    // stores name for the canary chains' line reader.
    /// `crate::canary::chain_lines::…`, nn-evidence's.
    use nn_evidence::chain_lines;
}

// The Linux host of the canary detector (nn-core's `CanaryHost`; R09a; was
// the agent's `canary_host_linux`).
pub mod canary_host_linux;

// The Linux host of the signed chains, the agent's host type (R09a; was the
// agent's `chain_host_linux`).
pub mod chain_host_linux;

/// The COMBAT ladder's Linux parts (R09a, lab PR 253): its production
/// actuator, its host-critical guard and the stale chain's compatibility
/// line (were the agent's `combat::{actuator, protected, reconcile}`; the
/// ladder is nn-core's).
pub mod combat {
    // `SystemActuator`: the executor's kill, quarantine and per-PID egress
    // block, the isolator, `/proc`.
    pub mod actuator;
    // `SystemProtectedProcs`: the host-critical identities read from the
    // live `/proc`.
    pub mod protected;
    // The stale chain's unsigned compatibility line: the anchored
    // `O_NOFOLLOW` open, the mode, the state directory's dance.
    pub mod reconcile;

    // R09a shim (plan §4.1 rule 2, removed in R17): the path the moved
    // actuator and guard name for the offenders' identity.
    /// `super::offender::…`, nn-core's.
    use nn_core::combat::offender;
}

// The Linux host of the COMBAT ladder (nn-core's `CombatHost`; R09a; was
// the agent's `combat_host_linux`).
pub mod combat_host_linux;

// The Linux host of the content lists (nn-core's `ContentHost`; R09a; was
// the agent's `content_host_linux`).
pub mod content_host_linux;

// The Linux host of the decision engine (nn-core's `DecisionHost`; R09a;
// was the agent's `decision_host_linux`).
pub mod decision_host_linux;

/// FIM (R09a, lab PR 253): the helpers the self-defence and the canary
/// registry name, cut from the agent's `fim::attach` (the FIM's attach,
/// drain, baseline, honeypot and recompute are R09b's).
pub mod fim {
    /// The kernel's form of a `stat(2)` device number, a path's `InodeKey`.
    pub mod attach;

    // R09a shim (plan §4.1 rule 2, removed in R17): the path the isolator's
    // tests name for the shipped FIM list.
    /// `crate::fim::paths_config::…`, nn-core's.
    #[cfg(test)]
    pub(crate) use nn_core::fim::paths_config;
}

// The filesystems the agent's files live on, by identity (R09a; was the
// agent's `fs_type`).
pub mod fs_type;

/// The ransomware signal's Linux part (R09a, lab PR 253): the production
/// sampler of the host's files (was the agent's `impact::entropy`; the
/// signal is nn-core's).
pub mod impact {
    // `FsSampler`: `O_NOFOLLOW`, the owners and mode bits, `/proc/1/root`.
    pub mod entropy;
}

/// Defences switched off (R09a, lab PR 253): the kernel map of the
/// security tools' processes the decision engine's host fills (cut from
/// the agent's `impair`; the detector is nn-core's).
pub mod impair {
    /// The kernel map of the tools' processes
    /// ([`DefenseDetector::attach_map`](nn_core::impair::DefenseDetector::attach_map)).
    pub type DefenderMap = aya::maps::HashMap<aya::maps::MapData, u32, u8>;
}

// The agent's signing key and its files (R09a; was the agent's `keys`).
pub mod keys;

/// Network (R09a, lab PR 253): the DNS pump's ingest, and the DNS cache
/// carrying it (were the agent's `net::dns_ingest` and `net::dns_cache`;
/// the cache's state is nn-core's).
pub mod net {
    // How far the DNS pump has read its ring, and how a lookup waits for
    // it (lab PR 229).
    pub mod dns_ingest;

    /// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the DNS
    /// cache's state is nn-core's, with the rules that read it; the agent's
    /// cache carries the DNS pump's ingest ([`dns_ingest`], lab PR 229), and
    /// the reply parsers keep the path R06 (lab PR 242) left them. R09a (lab
    /// PR 253): moved here from the agent's `net` with the ingest.
    pub mod dns_cache {
        pub use nn_core::net::dns_cache::*;

        pub use crate::net::dns_ingest::{monotonic_ns, DnsIngest, IngestClaim, INGEST_WAIT};

        /// [`nn_core::net::dns_cache::DnsCache`] with the DNS pump's ingest.
        pub type DnsCache = nn_core::net::dns_cache::DnsCache<DnsIngest>;

        // ── DNS reply parser (nn-parse) ─────────────────────────────────
        //
        // R06 of the Wave 4 restructure (lab PR 242): the reply parser and its
        // tests moved to nn-parse's `dns_records`. Re-exported here for the
        // paths the fuzz targets and `fuzz_api` name (until R17).
        pub use nn_parse::dns_records::{parse_a_records, parse_aaaa_records};
    }
}

// The OS CSPRNG as an infallible generator (R09a; was the agent's
// `os_rng`).
pub mod os_rng;

// The Linux host of the posture (nn-core's `PostureHost` and
// `PostureAgent`; R09a; was the agent's `posture_host_linux`).
pub mod posture_host_linux;

// The executor and its actions (Tappa 3, Tappa 5): kill, quarantine, the
// egress block, the throttle, the containment and its release, the
// capability preflight, the pidfd capture of a process (R09a; was the
// agent's `response`; its configuration and policy are nn-core's).
pub mod response;

// Blocking work kept off the async runtime's worker threads (R09a; was the
// agent's `runtime`).
pub mod runtime;

/// The self-integrity watcher's pieces the self-defence and the actuators
/// name (R09a, lab PR 253; cut from the agent's `self_integrity`, R09c's).
pub mod self_integrity;

// The system directories' binaries, never `$PATH` (R09a; was the agent's
// `trusted_bin`).
pub mod trusted_bin;

// R09a shims (lab PR 253; plan §4.1 rule 2, removed in R17): the paths the
// moved code names for what is nn-evidence's and nn-core's, as the agent's
// shims of the same names give them, so the files moved as they were.

/// `crate::audit::…`: nn-evidence's audit chain, the agent's key under it,
/// the writer signing with that key unless told otherwise.
pub(crate) mod audit {
    pub use nn_evidence::audit::*;

    pub use crate::keys::AgentSigningKey;

    /// [`nn_evidence::audit::AuditLog`], signed by the agent's key unless
    /// another is named.
    pub type AuditLog<K = AgentSigningKey> = nn_evidence::audit::AuditLog<K>;
}

/// `crate::chain_anchor::…`, nn-evidence's.
use nn_evidence::chain_anchor;

/// `crate::chain_host::…`, nn-evidence's.
use nn_evidence::chain_host;

/// `crate::chain_tail::…`, nn-evidence's (the Linux host's tests).
#[cfg(test)]
use nn_evidence::chain_tail;

/// `crate::chainlog::…`: nn-evidence's rotating chains, the writer signing
/// with the agent's key unless told otherwise.
pub(crate) mod chainlog {
    pub use nn_evidence::chainlog::*;

    /// [`nn_evidence::chainlog::RotatingChainLog`], signed by the agent's
    /// key unless another is named (the Linux host's tests).
    #[cfg(test)]
    pub type RotatingChainLog<P, K = crate::keys::AgentSigningKey> =
        nn_evidence::chainlog::RotatingChainLog<P, K>;
}

/// `crate::decision::…`, nn-core's (the exemption facts' trait).
use nn_core::decision;

/// `crate::posture::…`: nn-core's posture, and the stack exemption on the
/// Linux host (the agent's alias).
pub(crate) mod posture {
    pub use nn_core::posture::*;

    /// [`nn_core::posture::exempt::ExemptPids`] on the Linux host.
    pub type ExemptPids = nn_core::posture::exempt::ExemptPids<crate::chain_host_linux::LinuxHost>;
}
