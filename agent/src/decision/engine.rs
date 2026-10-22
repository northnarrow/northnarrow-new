//! Rule engine: holds a sequence of [`Rule`]s and routes events
//! through them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use nn_model::telemetry::FlowPhase;
use nn_model::{Event, Verdict};
use parking_lot::Mutex;

use super::attack::AttackRef;
use super::combine::{self, Decision};
use super::flow_ledger::{self, FlowLedger};
use super::response_policy;
use super::rule_policy::{self, ActorFacts, PolicyHandle, ProcFacts};

use super::rules::net::DnsBurstWindow;
use super::rules::{default_rules, default_rules_with_net};
use super::Rule;
use crate::config::comm_allowlist::CommAllowlist;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};

/// Owns the active rule set and dispatches events to it.
///
/// Lab PR 236 (multi-match): every rule is evaluated, in insertion order,
/// and the decision is computed from all the matches ([`combine`]) under
/// the per-rule policy ([`rule_policy`]). The order is the last tie-break
/// of the primary rule: place the more specific rule earlier.
pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
    /// Lab PR 224 (CM-02): the rules that already answered each open flow
    /// ([`flow_ledger`]).
    flow_ledger: Mutex<FlowLedger>,
    /// Lab PR 236: the per-rule policy this engine reads (production: the
    /// agent's [`rule_policy::global`]).
    policy: PolicyHandle,
    /// What an exemption check reads about a process.
    facts: Arc<dyn ActorFacts>,
}

/// Lab PR 224: verdicts given to a flow at its connect, since boot.
static CONNECT_VERDICTS: AtomicU64 = AtomicU64::new(0);

/// Lab PR 224 (CM-02): verdicts given to a TCP flow at its connect, while
/// it was open, by any engine since boot (status surface).
pub fn connect_verdicts_total() -> u64 {
    CONNECT_VERDICTS.load(Ordering::Relaxed)
}

impl RuleEngine {
    /// Empty engine. Useful for tests that pin a single rule.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            flow_ledger: Mutex::new(FlowLedger::default()),
            policy: PolicyHandle::default(),
            facts: Arc::new(ProcFacts::default()),
        }
    }

    /// This engine reading the policy `handle` (production: the agent's
    /// [`rule_policy::global`], swapped by `nn-admin policy set`).
    pub fn with_policy(mut self, handle: PolicyHandle) -> Self {
        self.policy = handle;
        self
    }

    /// This engine reading exemption facts from `facts` (the golden replay
    /// and `nn-admin policy test`: an empty `/proc`).
    pub fn with_facts(mut self, facts: Arc<dyn ActorFacts>) -> Self {
        self.facts = facts;
        self
    }

    /// The policy this engine reads.
    pub fn policy(&self) -> &PolicyHandle {
        &self.policy
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
        // Lab PR 224: the configured resolvers and the fan-out thresholds.
        net_config: super::rules::net::NetRuleConfig,
        // Lab PR 225: shared with the posture.
        ransom: Arc<crate::impact::RansomTracker>,
        defense: Arc<crate::impair::DefenseDetector>,
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
            net_config,
            ransom,
            defense,
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
        e.policy = self.policy;
        e.facts = self.facts;
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

    /// The decision's verdict ([`Self::decide`]): the primary rule's, with
    /// the strongest allowed action and the highest severity of every
    /// match, or `None` if every rule abstains.
    pub fn evaluate(&self, event: &Event) -> Option<Verdict> {
        self.decide(event).map(|d| d.verdict)
    }

    /// [`Self::evaluate`], with the ATT&CK references of every matched
    /// rule ([`Rule::attack`], the primary's first) for its detection
    /// record (lab PR 221).
    pub fn evaluate_with_attack(&self, event: &Event) -> Option<(Verdict, Vec<AttackRef>)> {
        self.decide(event).map(|d| {
            let attack = d.attack();
            (d.verdict, attack)
        })
    }

    /// Lab PR 236 (multi-match): every rule judges the event, and the
    /// decision is computed from all the matches ([`combine::combine`])
    /// after the per-rule policy ([`combine::apply_policy`]), under the
    /// legacy ceiling — without `enforce`, no response runs that the
    /// first-match engine would not have run on the event; every rule's
    /// state (chains, windows, the correlation store) sees the event.
    ///
    /// Lab PR 224 (CM-02): a flow is judged in each of its phases (the
    /// connect, the open-flow snapshots, the close); a rule that already
    /// answered the flow in an earlier phase is skipped, and a flow gets
    /// chain verdicts in one phase only ([`flow_ledger`]). A verdict on an
    /// open flow, or on a refused connect, says so in its reasoning.
    pub fn decide(&self, event: &Event) -> Option<Decision> {
        let flow = match event {
            Event::NetFlow(nf) => Some(nf),
            _ => None,
        };
        let key = flow.map(|nf| (nf.pid, nf.start_ns));
        let fired = key.and_then(|k| self.flow_ledger.lock().fired(&k));
        let policy = self.policy.current();
        // The event's actor, for a uid exemption (read once, if asked).
        let principal = std::cell::OnceCell::new();
        let mut matched: Vec<&'static str> = Vec::new();
        let mut matches = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if fired
                .as_deref()
                .is_some_and(|f| flow_ledger::excluded(rule.id(), f))
            {
                continue;
            }
            response_policy::take_held();
            let Some(v) = rule.evaluate(event) else {
                continue;
            };
            let held = response_policy::take_held();
            matched.push(rule.id());
            let facts = &*self.facts;
            let exempt = |v: &Verdict| {
                let p = principal
                    .get_or_init(|| crate::detection_payload::Principal::from_event(event));
                let uid = (p.pid == v.event_pid).then_some(p.uid);
                rule_policy::exempt(policy.exemptions(rule.id()), v.event_pid, uid, facts)
            };
            matches.push(combine::apply_policy(
                index,
                rule.id(),
                rule.attack(),
                v,
                held,
                &policy,
                exempt,
            ));
        }
        let mut decision = combine::combine(matches);
        match (flow, key) {
            (Some(nf), Some(key)) => {
                let mut ledger = self.flow_ledger.lock();
                match nf.phase {
                    // The flow is over: nothing more will name it.
                    FlowPhase::Closed => ledger.forget(&key),
                    FlowPhase::Connect | FlowPhase::Snapshot => {
                        for id in &matched {
                            ledger.record(key, id);
                        }
                    }
                    // No flow follows a refused connect.
                    FlowPhase::Denied => {}
                }
                if nf.phase == FlowPhase::Connect && decision.is_some() {
                    CONNECT_VERDICTS.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Review 70: a chain completed by a precursor processed after
            // its egress names that egress (pid, connect time): its later
            // phases get no second chain verdict.
            _ => {
                if let Some(d) = &decision {
                    for m in &d.matches {
                        if m.rule_id.starts_with("NN-L-CHAIN-") && m.verdict.timestamp_ns != 0 {
                            self.flow_ledger
                                .lock()
                                .record((m.verdict.event_pid, m.verdict.timestamp_ns), m.rule_id);
                        }
                    }
                }
            }
        }
        if let (Some(nf), Some(d)) = (flow, decision.as_mut()) {
            d.verdict = flow_ledger::annotate(d.verdict.clone(), nf);
        }
        decision
    }

    /// Flows the engine remembers a verdict for (tests, metrics).
    pub fn open_flows_with_verdicts(&self) -> usize {
        self.flow_ledger.lock().len()
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
