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
/// R09a shim (lab PR 253; plan §4.1 rule 2, removed in R17): the agent's
/// identity on disk is nn-linux's.
pub use nn_linux::agent_id;
/// The agent reads its identity once: a scan of `main.rs` (R09a, lab PR
/// 253: from `agent_id`'s tests).
#[cfg(test)]
mod agent_id_tests;
/// R09a shim: the anchor of a log's directory is nn-linux's.
pub use nn_linux::anchored;
/// R09a shim: the self-defence (the LSM deny hooks and their kernel maps,
/// the BPF guard, the BTF revalidation, the network isolator, the
/// trusted-installer window, the admin key set) is nn-linux's.
pub use nn_linux::anti_tamper;
/// R09a shim: the async file descriptor is nn-linux's.
pub use nn_linux::async_fd;
/// R09a shim: the atomic replace of a protected file is nn-linux's.
pub use nn_linux::atomic_file;
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
/// R09a shim: the external commands with a deadline are nn-linux's.
pub use nn_linux::bounded_cmd;
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
/// R05 shim: the newest-first tail reader of the admin read verbs.
pub use nn_evidence::chain_tail;
/// R09a shim: the Linux host of the canary detector — the signed registry
/// and access log, the interface addresses, the read-forward set,
/// `stat(2)`, `/proc` (nn-core's `CanaryHost`, R08b, lab PR 251) — is
/// nn-linux's.
pub use nn_linux::canary_host_linux;
/// R09a shim: the Linux host of the signed chains (R04a, lab PR 241) and the
/// agent's host type, [`chain_host_linux::LinuxHost`], are nn-linux's.
pub use nn_linux::chain_host_linux;
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
/// R09a shim: the Linux host of the COMBAT ladder — its capture of a
/// process, a pidfd (nn-core's `CombatHost`, R08c, lab PR 252) — is
/// nn-linux's.
pub use nn_linux::combat_host_linux;
pub mod config;
/// R09a shim: the Linux host of the content lists — the open of nn-core's
/// `ContentHost` (R07, lab PR 247) — is nn-linux's.
pub use nn_linux::content_host_linux;
/// What is Linux about the content reads, through the agent's loaders and
/// renderer (R09a, lab PR 253: from `content_host_linux`'s tests).
#[cfg(test)]
mod content_host_tests;
/// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the buffer of
/// recent events the posture's triggers read is nn-core's.
pub use nn_core::correlation;
/// Lab PR 222: copy on first write (ransomware rollback, EXPERIMENTAL).
pub mod cow;
pub mod decision;
/// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the detection
/// budget is nn-core's; its reporter task is [`detection_report`].
pub use nn_core::detection_budget;
/// R09a shim: the Linux host of the decision engine — the package
/// database's `rpm`, the work kept off the async runtime, the host's view of
/// a path, the trusted-installer window, `DEFENDER_PIDS` (nn-core's
/// `DecisionHost`, R08b, lab PR 251) — is nn-linux's.
pub use nn_linux::decision_host_linux;
/// The detection log's records (from `detection_store`, R04a, lab PR 241).
pub mod detection_payload;
/// The detection budget's reporter task (from `detection_budget`, R08a, lab
/// PR 250).
pub mod detection_report;
pub mod detection_store;
/// The exploit guard's `off` is a weakening the agent reports (R09b, lab PR
/// 254: from `sensors::epg`'s tests).
#[cfg(test)]
mod epg_tests;
/// The exec guards' kernel configuration the eBPF loader writes (R09b, lab
/// PR 254: from `sensors::multiplexer`).
pub mod exec_guards;
pub mod execpol;
pub mod execq;
/// R09b shim (lab PR 254): file integrity monitoring — the observers'
/// attach, the drain and its drift log, the baseline, the honeypot baits,
/// the recompute, the watched paths' loader on the Linux host — is
/// nn-linux's (its rules and list nn-core's).
pub use nn_linux::fim;
/// R09a shim: the filesystems' identity is nn-linux's.
pub use nn_linux::fs_type;
#[doc(hidden)]
pub mod fuzz_api;
pub mod host_hardening;
pub mod impact;
pub mod impair;
pub mod install_manifest;
/// R09a shim: the agent's signing key (from `audit`, R04a, lab PR 241) is
/// nn-linux's.
pub use nn_linux::keys;
pub mod loop_progress;
pub mod net;
/// R09a shim: the OS CSPRNG is nn-linux's.
pub use nn_linux::os_rng;
/// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the text of the
/// open sensor's paths (from `sensors::open_sensor`, R04b, lab PR 241) is
/// nn-model's, the crate the module map names; the posture reads it.
pub use nn_model::path_text;
pub mod posture;
/// R09a shim: the Linux host of the posture — the process table, the host's
/// files and the clocks of nn-core's `PostureHost` (R08a, lab PR 250) — is
/// nn-linux's.
pub use nn_linux::posture_host_linux;
pub mod process_hardening;
pub mod removed_settings;
/// R09a shim: the executor and its actions (kill, quarantine, the egress
/// block, the throttle, the containment and its release) are nn-linux's.
pub use nn_linux::response;
/// R09a shim: the work kept off the async runtime is nn-linux's.
pub(crate) use nn_linux::runtime;
pub mod sd_notify;
pub mod self_integrity;
/// Tappa 10.9 step 0, lab builds only (`--sensor-feasibility`).
#[cfg(feature = "test-privileged")]
pub mod sensor_feasibility;
pub mod sensors;
pub mod shutdown_marker;
pub mod systemd_state;
pub mod telemetry_probe;
/// R09a shim: the system directories' binaries are nn-linux's.
pub use nn_linux::trusted_bin;
pub mod upgrade_rollback;
/// Lab builds only (`--verifier-check`): every program of the embedded
/// eBPF object through the kernel's verifier.
#[cfg(feature = "debug-trigger")]
pub mod verifier_check;
/// R05 shim: the full verifiers' line reader.
pub use nn_evidence::verify_lines;
