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
pub mod audit;
/// Lab PR 218: the start as typed phases, the BPF LSM gate, the deny
/// self-test, the degradations, the trust level and the capability manifest.
pub mod boot;
pub mod bounded_cmd;
pub mod canary;
pub mod chain_anchor;
pub(crate) mod chain_tail;
pub mod chainlog;
pub mod combat;
pub mod config;
pub mod correlation;
pub mod decision;
pub mod detection_budget;
pub mod detection_store;
pub mod fim;
pub mod fs_type;
#[doc(hidden)]
pub mod fuzz_api;
pub mod host_hardening;
pub mod install_manifest;
pub mod loop_progress;
pub mod net;
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
/// Lab builds only (`--verifier-check`): every program of the embedded
/// eBPF object through the kernel's verifier.
#[cfg(feature = "debug-trigger")]
pub mod verifier_check;
pub mod verify_lines;
