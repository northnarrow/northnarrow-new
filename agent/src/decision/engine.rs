//! Rule engine: holds a sequence of [`Rule`]s and routes events
//! through them.

use std::sync::Arc;

use common::{Event, Verdict};
use parking_lot::Mutex;

use super::attack::AttackRef;
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

    /// Engine pre-loaded with [`default_rules`]: the production
    /// composition over empty operator state (external audit PROC-014).
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
    #[allow(clippy::too_many_arguments)]
    pub fn with_default_rules_and_net(
        blocklist: Arc<NetBlocklist>,
        ja3_blocklist: Arc<Ja3Blocklist>,
        burst_window: Arc<Mutex<DnsBurstWindow>>,
        process_allowlist: Arc<CommAllowlist>,
        netflow_comm_allowlist: Arc<CommAllowlist>,
        beacon_window: Arc<Mutex<super::rules::net::BeaconWindow>>,
        dns_cache: Arc<crate::net::dns_cache::DnsCache>,
        // FIM-009 self-upgrade (§15.1): the trusted-installer override
        // the NN-L-FIM-009 rule reads (armed by the admin dispatcher).
        installer_override: Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>,
        // Review 49: the shared process-lineage cache the FIM rules'
        // package-manager carve-out reads.
        lineage: crate::posture::lineage::AuthSessionTracker,
        // External audit DEC-005: the readers the File / Credential canary
        // rules record instead of killing.
        canary_readers: crate::canary::readers::CanaryReaders,
        // External audit NET-019: the chain rules' correlation store, which
        // the netflow limiter reads too.
        correlation: Arc<Mutex<super::correlation::CorrelationStore>>,
    ) -> Self {
        let mut e = Self::new();
        for r in default_rules_with_net(
            blocklist,
            ja3_blocklist,
            burst_window,
            process_allowlist,
            netflow_comm_allowlist,
            beacon_window,
            dns_cache,
            installer_override,
            lineage,
            canary_readers,
            correlation,
        ) {
            e.add_rule(r);
        }
        e
    }

    /// This engine with the Tappa 5 demo rules (R901..=R904) put FIRST.
    /// Demo rules win over the production rules so a
    /// `/tmp/payload.block-outbound` exec triggers `R901` (BlockOutbound)
    /// instead of being killed by `R001`. This ordering only ships in the
    /// `demo-tappa5` build; the regression demo (`/tmp/nn-test-payload`)
    /// still goes through R001 → KillProcessTree because its filename has
    /// no demo suffix.
    ///
    /// External audit PROC-015 / PROC-014: `main.rs` puts them ahead of
    /// the production engine ([`Self::with_default_rules_and_net`]), so a
    /// demo build keeps the operator's blocklists and allowlists; it used
    /// to run them over [`default_rules`], which has neither. Such a build
    /// enforces only under [`demo_rules_gate`].
    #[cfg(feature = "demo-tappa5")]
    pub fn with_demo_tappa5_first(self) -> Self {
        let mut e = Self::new();
        for r in super::rules::demo_tappa5_rules() {
            e.add_rule(r);
        }
        e.rules.extend(self.rules);
        e
    }

    /// The ids of the registered rules, in evaluation order (a rule
    /// registered twice appears twice).
    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.rules.iter().map(|r| r.id()).collect()
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
        self.evaluate_with_attack(event).map(|(v, _)| v)
    }

    /// [`Self::evaluate`], with the ATT&CK references of the rule that
    /// fired ([`Rule::attack`]) for its detection record (lab PR 221).
    pub fn evaluate_with_attack(&self, event: &Event) -> Option<(Verdict, &'static [AttackRef])> {
        for rule in &self.rules {
            if let Some(v) = rule.evaluate(event) {
                return Some((v, rule.attack()));
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

/// External audit PROC-015 (NN-AUD-302): the variable that lets a
/// `demo-tappa5` build enforce. It is a weakening variable
/// (`self_integrity::WEAKENING_ENV`): set to `1` in such a build, it is a
/// signed `integrity_drift`.
pub const ALLOW_DEMO_RULES_ENV: &str = "NN_ALLOW_DEMO_RULES";

/// `true` when this binary carries the demo rules R901..=R904 (the
/// `demo-tappa5` feature).
pub const DEMO_RULES_BUILD: bool = cfg!(feature = "demo-tappa5");

/// Does this value of [`ALLOW_DEMO_RULES_ENV`] weaken the agent? Only
/// `1`, and only in a build whose demo rules it releases: elsewhere
/// nothing reads it.
pub fn allow_demo_rules_weakens(value: &str) -> bool {
    DEMO_RULES_BUILD && value == "1"
}

/// External audit PROC-015 (NN-AUD-302): may this agent start? A
/// `demo-tappa5` build (`demo_build`) puts R901..=R904 ahead of every
/// production rule; they block a process's outbound traffic, quarantine
/// its file or throttle it on a filename suffix any user chooses. Such a
/// build starts in detect-only, where no verdict is executed, or with
/// [`ALLOW_DEMO_RULES_ENV`]`=1` (`allow`, the variable's value), the
/// operator's explicit consent; in enforcement without it the agent
/// refuses to start, with the reason. Any other build always starts.
pub fn demo_rules_gate(
    demo_build: bool,
    detect_only: bool,
    allow: Option<&str>,
) -> Result<(), String> {
    if !demo_build || detect_only || allow == Some("1") {
        return Ok(());
    }
    Err(format!(
        "this agent was built with the demo-tappa5 feature: the demo rules R901..R904 \
         block, quarantine or throttle any process whose file name ends in a demo suffix, \
         ahead of every production rule (external audit PROC-015). Refusing to start in \
         enforcement: run it with --detect-only, set {ALLOW_DEMO_RULES_ENV}=1 to enforce \
         them on a lab host, or install a release build (`northnarrow-agent \
         --build-features` prints `none`)"
    ))
}
