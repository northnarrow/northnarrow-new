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
//!
//! R08b (lab PR 251): moved from the agent to nn-core. What the engine
//! reads and asks of the machine it runs on is its host's, a type parameter
//! of its types ([`host::DecisionHost`] on the posture's
//! [`crate::posture::host::PostureAgent`]; the agent's is `LinuxHost`). The
//! golden replay of recorded streams, the rule catalogue's renderer and the
//! validation registry's checks, which name the agent's records and the
//! rules decided outside the engine, stay in the agent.

use nn_model::{Event, Verdict};

pub mod attack;
pub mod bounded;
pub mod catalogue;
pub mod combine;
pub mod correlation;
pub mod engine;
pub mod flow_ledger;
pub mod host;
pub mod replay;
pub mod response_policy;
pub mod rule_policy;
pub mod rules;

pub use engine::RuleEngine;

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

#[cfg(test)]
mod tests;
