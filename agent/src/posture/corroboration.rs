//! COMBAT escalation corroboration (BUG-032).
//!
//! A NeedsCorroboration COMBAT-tier trigger (the blunt network/file
//! heuristics) escalates to ENGAGED on its own and reaches COMBAT only
//! with a SECOND distinct escalation signal within
//! [`CORROBORATION_WINDOW`]. Decisive triggers (kernel-adjudicated,
//! [`common::posture_types::Confidence::Decisive`]) bypass this and
//! reach COMBAT immediately. This makes the FSM ladder
//! (Observing→Alerted→Engaged→Combat) mean what it says, instead of a
//! single blunt heuristic jumping straight to locked isolation.
//!
//! ## Documented beta limit — single-vector
//!
//! With [`SUSTAINED_SAME_TYPE_PROMOTES`] = `false` (default), a
//! single-vector attack — even sustained (pure massive exfil with no
//! other distinct signal) — tops out at ENGAGED (alert), never
//! auto-isolates. This is a deliberate precision-over-autonomous-
//! completeness choice for beta: the operator sees the alert and acts.
//! The sustained knob exists if single-vector autonomy is later
//! required. (BUG-032.)

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use common::posture_types::TriggerType;

/// Calibration knob (NOT a fixed constant — tune on the VM). Window in
/// which a second distinct escalation signal corroborates a blunt
/// COMBAT-tier heuristic.
pub const CORROBORATION_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Defensive bound on ledger size vs a trigger flood. The time window
/// is the primary prune; this caps a burst.
const LEDGER_CAP: usize = 64;

/// Single-vector knob — OFF by default. When `true`, the SAME trigger
/// firing >= [`SUSTAINED_SAME_TYPE_MIN`] times in-window self-
/// corroborates (covers a pure single-vector attack at the cost of more
/// false positives). See the module-level note on the beta limit.
pub const SUSTAINED_SAME_TYPE_PROMOTES: bool = false;
const SUSTAINED_SAME_TYPE_MIN: usize = 2;

#[derive(Clone, Copy)]
struct LedgerEntry {
    trigger: TriggerType,
    at: Instant,
}

/// Bounded, in-memory record of recent escalation signals (ENGAGED-tier
/// and above), used to decide whether a blunt COMBAT-tier signal has
/// independent corroboration. Lives in `PostureMachine::Inner` and is
/// only ever touched inside `observe()`'s state-write critical section.
#[derive(Default)]
pub struct CorroborationLedger {
    entries: VecDeque<LedgerEntry>,
}

impl CorroborationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop entries older than the window, then cap the size. Call
    /// before every query/record.
    pub fn prune(&mut self, now: Instant) {
        while self
            .entries
            .front()
            .is_some_and(|e| now.saturating_duration_since(e.at) > CORROBORATION_WINDOW)
        {
            self.entries.pop_front();
        }
        while self.entries.len() > LEDGER_CAP {
            self.entries.pop_front();
        }
    }

    /// Is there a DISTINCT escalation signal already in the ledger
    /// (corroborating `current`)? With the sustained knob on, a
    /// sufficiently-repeated SAME signal also corroborates.
    ///
    /// Caller must [`prune`](Self::prune) first.
    pub fn corroborated(&self, current: TriggerType) -> bool {
        if self.entries.iter().any(|e| e.trigger != current) {
            return true;
        }
        SUSTAINED_SAME_TYPE_PROMOTES
            && self.entries.iter().filter(|e| e.trigger == current).count() + 1
                >= SUSTAINED_SAME_TYPE_MIN
    }

    /// Record an escalation signal. The caller records only signals
    /// whose `target_level() >= Engaged` (ALERTED-tier recon/DNS is too
    /// noisy to count as corroboration).
    pub fn record(&mut self, trigger: TriggerType, at: Instant) {
        self.entries.push_back(LedgerEntry { trigger, at });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lone_signal_is_not_corroborated() {
        let l = CorroborationLedger::new();
        // empty ledger: nothing corroborates the first firing.
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern));
    }

    #[test]
    fn distinct_prior_signal_corroborates() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::LateralMovement, now);
        // a DIFFERENT escalation signal is present → corroborated.
        assert!(l.corroborated(TriggerType::ExfiltrationPattern));
    }

    #[test]
    fn same_type_repeat_not_corroborated_with_knob_off() {
        // Default SUSTAINED_SAME_TYPE_PROMOTES = false: a repeated SAME
        // signal does NOT promote (the documented single-vector limit).
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ExfiltrationPattern, now);
        assert_eq!(SUSTAINED_SAME_TYPE_PROMOTES, false, "guard: knob default");
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern));
    }

    #[test]
    fn prune_drops_out_of_window_entries() {
        let base = Instant::now();
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::LateralMovement, base);
        // Advance well past the window.
        let later = base + CORROBORATION_WINDOW + Duration::from_secs(1);
        l.prune(later);
        assert_eq!(l.len(), 0, "stale entry pruned");
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern));
    }

    #[test]
    fn ledger_capped_against_flood() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        for _ in 0..(LEDGER_CAP + 50) {
            l.record(TriggerType::ExfiltrationPattern, now);
        }
        l.prune(now);
        assert!(l.len() <= LEDGER_CAP, "size cap holds under a flood");
    }
}
