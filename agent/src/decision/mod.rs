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
//! - The first matching rule wins for now. Tappa 6 will introduce a
//!   second pass that aggregates across multiple matches and feeds
//!   ambiguity into the LLM.

use common::{Event, Verdict};

pub mod engine;
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

    /// Returns `Some(verdict)` if the rule fires, `None` otherwise.
    /// Implementations must keep this hot-path cheap — no allocations
    /// in the negative case where possible.
    fn evaluate(&self, event: &Event) -> Option<Verdict>;
}

#[cfg(test)]
mod tests;
