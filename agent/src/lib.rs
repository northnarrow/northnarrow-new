//! NorthNarrow agent library.
//!
//! - [`sensors`]   — eBPF-driven event sources.
//! - [`decision`]  — deterministic rule engine (Tappa 2).
//! - [`response`]  — concrete executors (Tappa 3 + Tappa 5).
//! - [`posture`]   — the defensive posture and its COMBAT ladder.
//! - [`correlation`] — bounded buffer of recent events the posture
//!   triggers read.
//!
//! Detection is deterministic: rules, correlation, posture and COMBAT.
//! The on-host LLM advisor of Tappa 6 (ADE, its RAG knowledge base and
//! XAI explanations) was removed in Wave 4 (lab PR 214).

pub mod admin_cli;
pub mod admin_socket;
pub mod agent_id;
pub mod anchored;
pub mod anti_tamper;
pub mod async_fd;
pub mod atomic_file;
/// R05 shim (lab PR 241; plan §4.1 rule 2, removed in R17): the audit chain
/// is nn-evidence's. The agent's key and its files (`keys`) keep their names
/// here, and the writer signs with that key unless told otherwise.
pub mod audit {
    pub use nn_evidence::audit::*;

    pub use crate::keys::{
        read_signing_key, read_verifying_key, verifying_key_path, AgentSigningKey,
        DEFAULT_SIGNING_KEY_PATH,
    };

    /// [`nn_evidence::audit::AuditLog`], signed by the agent's key unless
    /// another is named.
    pub type AuditLog<K = AgentSigningKey> = nn_evidence::audit::AuditLog<K>;
}
/// The audit log's writability before the attach (from `audit`, R04a, lab
/// PR 241).
pub mod audit_preflight;
/// Lab PR 218: the start as typed phases, the BPF LSM gate, the deny
/// self-test, the degradations, the trust level and the capability manifest.
pub mod boot;
pub mod bounded_cmd;
/// The binary's version, cargo features and BPF guard mode (from `audit`,
/// R04a, lab PR 241).
pub mod build_info;
pub mod canary;
/// R05 shim: the chains' completeness checks are nn-evidence's (the agent's
/// own chains, their paths and tasks, are [`chains`]).
pub mod chain_anchor {
    pub use nn_evidence::chain_anchor::*;

    /// [`nn_evidence::chain_anchor::Anchor`], signed by the agent's key
    /// unless another is named.
    pub type Anchor<K = crate::keys::AgentSigningKey> = nn_evidence::chain_anchor::Anchor<K>;
}
/// R05 shim: what the signed chains need from their host (R04a), nn-evidence's.
pub use nn_evidence::chain_host;
/// The Linux host of the signed chains (R04a, lab PR 241).
pub mod chain_host_linux;
/// R05 shim: the newest-first tail reader of the admin read verbs.
pub use nn_evidence::chain_tail;
/// R05 shim: the rotating, signed chains are nn-evidence's; the writer signs
/// with the agent's key unless told otherwise.
pub mod chainlog {
    pub use nn_evidence::chainlog::*;

    /// [`nn_evidence::chainlog::RotatingChainLog`], signed by the agent's
    /// key unless another is named.
    pub type RotatingChainLog<P, K = crate::keys::AgentSigningKey> =
        nn_evidence::chainlog::RotatingChainLog<P, K>;
}
/// The agent's chains: paths, checks, anchoring tasks (from `chain_anchor`,
/// R04a, lab PR 241).
pub mod chains;
pub mod combat;
pub mod config;
/// The Linux host of the content lists: the open of nn-core's
/// `ContentHost` (R07, lab PR 247).
pub mod content_host_linux;
pub mod correlation;
/// Lab PR 222: copy on first write (ransomware rollback, EXPERIMENTAL).
pub mod cow;
pub mod decision;
pub mod detection_budget;
/// The detection log's records (from `detection_store`, R04a, lab PR 241).
pub mod detection_payload;
pub mod detection_store;
pub mod execpol;
pub mod execq;
pub mod fim;
pub mod fs_type;
#[doc(hidden)]
pub mod fuzz_api;
pub mod host_hardening;
pub mod impact;
pub mod impair;
pub mod install_manifest;
/// The agent's signing key (from `audit`, R04a, lab PR 241).
pub mod keys;
pub mod loop_progress;
pub mod net;
pub mod os_rng;
/// The text of the open sensor's paths (from `sensors::open_sensor`, R04b,
/// lab PR 241).
pub mod path_text;
pub mod posture;
pub mod process_hardening;
pub mod removed_settings;
pub mod response;
pub(crate) mod runtime;
pub mod sd_notify;
pub mod self_integrity;
/// Tappa 10.9 step 0, lab builds only (`--sensor-feasibility`).
#[cfg(feature = "test-privileged")]
pub mod sensor_feasibility;
pub mod sensors;
pub mod shutdown_marker;
pub mod systemd_state;
pub mod telemetry_probe;
pub mod trusted_bin;
pub mod upgrade_rollback;
/// Lab builds only (`--verifier-check`): every program of the embedded
/// eBPF object through the kernel's verifier.
#[cfg(feature = "debug-trigger")]
pub mod verifier_check;
/// R05 shim: the full verifiers' line reader.
pub use nn_evidence::verify_lines;
