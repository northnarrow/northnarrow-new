//! Decision engine (Tappa 2).
//!
//! Hardcoded rules examine each [`Event`] and emit a [`Verdict`] when
//! they match. Tappa 2 is observation-only: the agent logs the verdict
//! but executes nothing. Tappa 3 wires real responses (KillProcess
//! first) on top of these verdicts.
//!
//! Design rules of thumb for this layer:
//!
//! - Rules are pure functions of the event. No I/O, no clocks, no
//!   filesystem reads — that keeps them trivially testable.
//! - Each rule has a stable, immutable id (`R<NNN>_Name`). Once an id
//!   ships it never changes meaning; a deprecated rule keeps the slot
//!   and is retired in code only.
//! - Every rule judges every event (lab PR 236, multi-match): the decision
//!   is computed from all the matches under the signed per-rule policy
//!   ([`combine`], [`rule_policy`]). It used to be the first match. (Tappa 6
//!   fed what no rule matched to an on-host LLM advisor; it was removed in
//!   Wave 4, lab PR 214, and detection stays deterministic.)

use nn_model::{Event, Verdict};

pub mod catalogue;
pub mod combine;
pub mod engine;
pub mod replay;
pub mod response_policy;
pub mod rule_policy;
pub mod rules;

pub use engine::RuleEngine;

// R08b shims (lab PR 251; plan §4.1 rule 2, removed in R17): the engine's
// foundations are nn-core's — the ATT&CK mapping, the bounded structures,
// the flow ledger, and the chain rules' correlation store and ancestry
// tree, which read the process table through their host (the agent's
// `LinuxHost` here).
pub use nn_core::decision::{attack, bounded, flow_ledger};

/// The chain rules' correlation state: nn-core's, on the agent's host.
pub mod correlation {
    pub use nn_core::decision::correlation::*;

    /// [`nn_core::decision::correlation::CorrelationStore`] on the agent's
    /// host.
    pub type CorrelationStore =
        nn_core::decision::correlation::CorrelationStore<crate::chain_host_linux::LinuxHost>;

    /// [`nn_core::decision::correlation::AncestryTree`] on the agent's host.
    pub type AncestryTree =
        nn_core::decision::correlation::AncestryTree<crate::chain_host_linux::LinuxHost>;

    /// The ancestry tree, on the agent's host.
    pub mod ancestry {
        pub use nn_core::decision::correlation::ancestry::*;

        /// [`nn_core::decision::correlation::AncestryTree`] on the agent's
        /// host.
        pub type AncestryTree = super::AncestryTree;
    }
}

/// Contract every rule implements.
///
/// Implementations are stateless and `Send + Sync` so the engine can
/// be shared across tasks without locking.
pub trait Rule: Send + Sync {
    /// Stable identifier — `R<NNN>_PascalCase`. Never changes after
    /// shipping; used in telemetry, alert dedup, and correlation.
    fn id(&self) -> &'static str;

    /// Human-readable rule name for dashboards and CLI output.
    fn name(&self) -> &'static str;

    /// Coarse category — `"execution"`, `"lateral_movement"`,
    /// `"privilege_escalation"`, etc. Used for grouping in the UI and
    /// for future correlation passes.
    fn category(&self) -> &'static str;

    /// Lab PR 221 (capability C16): the MITRE ATT&CK tactics and
    /// techniques the rule's detection is evidence of, as data — ids of
    /// ATT&CK Enterprise [`attack::ATTACK_VERSION`]. A detection record
    /// carries them in its `mitre` field. Every shipped rule declares at
    /// least one (`decision/catalogue` tests); a rule wrapping another
    /// returns the inner rule's.
    fn attack(&self) -> &'static [attack::AttackRef];

    /// Returns `Some(verdict)` if the rule fires, `None` otherwise.
    /// Implementations must keep this hot-path cheap — no allocations
    /// in the negative case where possible.
    fn evaluate(&self, event: &Event) -> Option<Verdict>;
}

/// Lab PR 228: the golden replay of recorded event streams.
#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod validation_registry;
