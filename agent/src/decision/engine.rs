//! Rule engine: holds a sequence of [`Rule`]s and routes events
//! through them.

use std::sync::Arc;

use common::{Event, Verdict};
use parking_lot::Mutex;

use super::rules::net::DnsBurstWindow;
use super::rules::{default_rules, default_rules_with_net};
use super::Rule;
use crate::config::comm_allowlist::CommAllowlist;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};

/// Owns the active rule set and dispatches events to it.
///
/// Order matters: rules are evaluated in insertion order and the first
/// match wins. Place high-confidence, high-severity rules earlier so a
/// cheap obvious match short-circuits the rest.
pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    /// Empty engine. Useful for tests that pin a single rule.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Engine pre-loaded with the Tappa 2 rule set (R001..=R010).
    pub fn with_default_rules() -> Self {
        let mut e = Self::new();
        for r in default_rules() {
            e.add_rule(r);
        }
        e
    }

    /// Tappa 10 N9 — engine pre-loaded with the full Tappa 2 +
    /// FIM (Tappa 9) + canary (Tappa 9.5) + NN-L-NET (Tappa 10)
    /// rule set, with operator-loaded blocklists threaded into
    /// the 9 net rules. Production `main.rs` calls this once at
    /// boot after reading the blocklist files from disk.
    pub fn with_default_rules_and_net(
        blocklist: Arc<NetBlocklist>,
        ja3_blocklist: Arc<Ja3Blocklist>,
        burst_window: Arc<Mutex<DnsBurstWindow>>,
        process_allowlist: Arc<CommAllowlist>,
    ) -> Self {
        let mut e = Self::new();
        for r in default_rules_with_net(blocklist, ja3_blocklist, burst_window, process_allowlist) {
            e.add_rule(r);
        }
        e
    }

    /// Engine pre-loaded with the Tappa 5 demo rules (R901..=R904)
    /// FIRST, then R001..=R010. Demo rules win over the production
    /// rules so a `/tmp/payload.block-outbound` exec triggers
    /// `R901` (BlockOutbound) instead of being killed by `R001`.
    /// This ordering only ships in the `demo-tappa5` build; the
    /// regression demo (`/tmp/nn-test-payload`) still goes through
    /// R001 → KillProcess because its filename has no demo suffix.
    #[cfg(feature = "demo-tappa5")]
    pub fn with_default_rules_and_demo_tappa5() -> Self {
        let mut e = Self::new();
        for r in super::rules::demo_tappa5_rules() {
            e.add_rule(r);
        }
        for r in super::rules::default_rules() {
            e.add_rule(r);
        }
        e
    }

    /// Append a rule. Order is preserved.
    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Number of rules currently registered.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// First-match wins. Returns the verdict from the earliest rule
    /// that fires, or `None` if every rule abstains.
    pub fn evaluate(&self, event: &Event) -> Option<Verdict> {
        for rule in &self.rules {
            if let Some(v) = rule.evaluate(event) {
                return Some(v);
            }
        }
        None
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}
