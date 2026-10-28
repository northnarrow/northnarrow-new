//! R08c shim (Wave 4 restructure, lab PR 252; plan §4.1 rule 2, removed in
//! R17): the COMBAT ladder is nn-core's — its stages and state machine, its
//! worker, the actuator's and the host-critical guard's traits and the
//! outcomes they report, the signed evidence it writes, the offenders'
//! identity, the stale chain's record (`nn_core::combat`).
//!
//! The agent keeps the paths it had. nn-core's ladder takes its host as a
//! type parameter — the host's capture of a process (`nn_core::combat::host`);
//! the agent's is [`LinuxHost`] (`combat_host_linux`: a pidfd and the start
//! of the process, `response::proc_ref::ProcRef`). Here the ladder and its
//! neutralize hook are aliases on it (an alias without a parameter: one with
//! a default would not apply where a value is built), the evidence signs
//! with the agent's key, and `ProcRef` keeps its name. Callers, `main.rs`,
//! the admin socket and the posture's golden replay are unchanged; the
//! replay's actuator implements the trait on the agent's host.
//!
//! What is Linux is nn-linux's since R09a (lab PR 253), under its paths
//! here: the production actuator ([`actuator::SystemActuator`]: the
//! executor's kill, quarantine and per-PID egress block, the isolator,
//! `/proc`), the production guard ([`protected::SystemProtectedProcs`]:
//! `/proc`), the stale chain's compatibility line ([`reconcile`]), and the
//! host itself (`nn_linux::chain_host_linux::LinuxHost`, named here by its
//! crate as those are). The ladder's tests that wire the agent's signing
//! key, its audit log, its posture or a real process stay here
//! (`host_tests`, `evidence_tests`).

use nn_linux::chain_host_linux::LinuxHost;

pub use nn_core::combat::*;

/// [`nn_core::combat::CombatLadder`] on the agent's host.
pub type CombatLadder = nn_core::combat::CombatLadder<LinuxHost>;

/// [`nn_core::combat::NeutralizeHook`] on the agent's host.
pub type NeutralizeHook = nn_core::combat::NeutralizeHook<LinuxHost>;

/// [`nn_core::combat::AuditEvidence`], into an audit log the agent's key
/// signs.
pub type AuditEvidence = nn_core::combat::AuditEvidence<crate::audit::AgentSigningKey>;

/// The ladder's capture of a process on the agent's host: a pidfd and the
/// start of the process (`response::proc_ref::ProcRef`).
pub type ProcRef = <LinuxHost as CombatHost>::Proc;

/// The ladder's Linux parts (R09a, lab PR 253): nn-linux's.
pub use nn_linux::combat::{actuator, protected, reconcile};

pub use actuator::SystemActuator;
pub use protected::SystemProtectedProcs;

/// The evidence's tests, which sign with the agent's key (R08c, lab PR
/// 252).
#[cfg(test)]
mod evidence_tests;
/// The ladder's tests that need the agent's other modules (R08c, lab PR
/// 252).
#[cfg(test)]
mod host_tests;
