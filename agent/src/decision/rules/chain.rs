//! Tappa 10.5 (D5) — chain / correlation detection rules
//! NN-L-CHAIN-001..003. Tappa 10.6 D3 re-homed the correlation state
//! onto the shared [`CorrelationStore`].
//!
//! Two-event, same-PID correlation rules in the **stateful
//! single-trigger** shape (design §13 Q2 / §3.5-A): each rule records a
//! typed precursor into the shared store and queries it behind the
//! single-event `Rule::evaluate` trait (`Arc<Mutex<_>>` interior
//! mutability — the NN-L-NET-005 `DnsBurstWindow` precedent). The
//! single-pass engine is unchanged (§13 Q3); the N-event + cross-PID
//! machinery lives in the store (D3) + ancestry tree (D4).
//!
//! ## How a single-trigger chain rule works
//!
//! Each rule watches for TWO event kinds across successive
//! `evaluate` calls:
//!
//! 1. A **precursor** event (a credential-store FIM access / a `/tmp`
//!    exec / a canary trip). On a precursor the rule RECORDS its typed
//!    [`PrecursorKind`] for the PID and returns `None` — so the event
//!    falls through to the precursor's own rule (FIM-015..017 / R001 /
//!    NN-L-CANARY-*), which fires as usual.
//! 2. A **trigger** event — an outbound `Event::NetFlow`. On a flow
//!    the rule LOOKS UP its precursor kind for the same PID within
//!    the [`CORRELATION_WINDOW_NS`] lookback. A hit means "this process
//!    accessed credentials / ran from /tmp / tripped a canary AND is
//!    now talking to the network" — a Critical exfiltration / C2
//!    indicator. It fires `KillProcessTree` → posture COMBAT.
//!
//! ## Engine ordering requirement
//!
//! The chain rules MUST be registered FIRST in the engine
//! ([`crate::decision::rules::default_rules`] /
//! [`default_rules_with_net`] prepend them) for two reasons:
//!
//! - To OBSERVE precursor events before a higher-priority rule
//!   consumes them. The engine is first-match-wins; a chain rule
//!   returns `None` on a precursor (recording only), so the event
//!   still falls through to FIM-015 / R001 / the canary rule. But if
//!   the chain rule sat AFTER those, the firing rule would
//!   short-circuit the scan and the precursor would never be
//!   recorded.
//! - So a correlated flow surfaces the Critical chain verdict before
//!   any lower-severity net rule (e.g. NN-L-NET-008) matches the same
//!   flow.
//!
//! ## Correlation state (Tappa 10.6 D3)
//!
//! The per-rule `ChainCorrelationBuffer` is replaced by one shared
//! [`CorrelationStore`] (`crate::decision::correlation`) injected into
//! every chain rule. Each records a typed [`PrecursorKind`] and queries
//! it by PID within [`CORRELATION_WINDOW_NS`] — same-PID,
//! single-precursor behaviour (CHAIN-001..003) is preserved bit-for-bit.
//! D4 wires the ancestry tree, and D6 adds the cross-PID
//! (`has_recent_in_ancestors`) + N-event (`has_sequence`) chains
//! CHAIN-004..008 over the same shared store.
//!
//! ## Retention per precursor kind (external audit NETR-014, lab PR 213)
//!
//! A credential read and a canary trip are kept 30 minutes
//! ([`crate::decision::correlation::LONG_RETENTION_NS`]); a staging-directory exec and a `sudo`/`su`
//! stay at [`CORRELATION_WINDOW_NS`] (300 s). CHAIN-001/003/004/006 grade
//! the correlation by age ([`ChainAge`]): an egress within 300 s of the
//! precursor is the Critical `KillProcessTree` verdict, unchanged; past
//! 300 s and within 30 minutes it is one **High `Log`** record, once per
//! precursor, with no response and no COMBAT. Waiting out five minutes no
//! longer hides the chain from the analyst, and a long-lived process that
//! opens a credential store and talks to the network much later (a backup
//! client, an agent-style helper) is not killed for it. CHAIN-002/005/008
//! (staging exec, `sudo`/`su`) and the three-step CHAIN-007 (its first step
//! is the staging exec) keep the 300 s window; so do the late completions
//! below.
//!
//! ## Late precursors (review 70, lab PRs 235 and 244)
//!
//! A precursor and its egress come through different rings and pumps, so
//! the precursor can reach the engine after an egress it preceded in kernel
//! time. CHAIN-007 notes every flow it sees that completes no chain
//! ([`CorrelationStore::note_egress`]); a late precursor completes the chain
//! with the noted egress on the kernel timestamps and the verdict names that
//! egress: a credential read completes CHAIN-007 or CHAIN-001 (review 70), a
//! staging exec CHAIN-007 (lab PR 235) or CHAIN-002 (lab PR 244). A two-step
//! chain (CHAIN-001, CHAIN-002), in order or late, claims the egress, naming
//! its precursor, and a late two-step completion needs an unclaimed one. The
//! three-step CHAIN-007 takes the egress (it is removed): a late read one
//! unclaimed or claimed by CHAIN-002, a late exec one unclaimed or claimed.
//! So a flow gets at most two chain verdicts, the two-step one first and
//! then CHAIN-007, and the flow ledger keeps the flow's later phases from a
//! third.
//!
//! ## Rate limiting (§13 Q4)
//!
//! All chain rules are Critical and fire the deterministic
//! `KillProcessTree` unconditionally — never throttled. The §6.5
//! netflow pacing (external audit NET-019, `net::limiter`) never holds
//! back a flow of a process that holds, or whose ancestors hold, a
//! precursor in the store, and notes the flows it holds back as egresses
//! for a precursor processed later.
//!
//! The one exception is NN-L-CHAIN-008 (sudo/su then egress): it is
//! informational (`Medium` + `Log`) and is registered LAST in the
//! engine through [`ChainRuleSet::tail`], so its Log verdict never
//! shadows a blocking rule on the same flow. See its docs.

use std::net::IpAddr;
use std::sync::Arc;

use nn_model::telemetry::FlowPhase;
use nn_model::{CanaryAccessKind, Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::correlation::{
    retention_ns, ChainAge, CorrelationStore, EgressNote, PrecursorKind, ProcKey,
    CORRELATION_WINDOW_NS,
};
use crate::decision::Rule;
use crate::fim::rules::is_credential_store_access;
use crate::net::resolvers::HostResolvers;
use crate::posture::lineage::AuthSessionTracker;

// ── verdict helper ───────────────────────────────────────────────────

/// Build a Critical chain Verdict from the triggering `NetFlowEvent`.
fn chain_verdict(
    rule: &dyn Rule,
    nf: &nn_model::telemetry::NetFlowEvent,
    reasoning: &str,
) -> Verdict {
    chain_verdict_with(
        rule,
        nf,
        ResponseAction::KillProcessTree,
        Severity::Critical,
        reasoning,
    )
}

/// External audit NETR-014 (lab PR 213): the record of a chain whose
/// precursor is older than [`CORRELATION_WINDOW_NS`] and within its 30-minute
/// retention — High, `Log`: no response, no COMBAT. `what` says what the
/// process (or its ancestor) did; the age is in minutes.
fn aged_chain_verdict(
    rule: &dyn Rule,
    nf: &nn_model::telemetry::NetFlowEvent,
    age_ns: u64,
    kind: PrecursorKind,
    what: &str,
    technique: &str,
) -> Verdict {
    let kept = match kind {
        PrecursorKind::CredRead => "credential read",
        PrecursorKind::CanaryTrip => "canary trip",
        PrecursorKind::TmpExec | PrecursorKind::PrivEsc => "precursor",
    };
    chain_verdict_with(
        rule,
        nf,
        ResponseAction::Log,
        Severity::High,
        &format!(
            "{what} {} min before this outbound flow — past the {} s window that \
             kills the process tree, within the {} min a {kept} is kept: recorded \
             for the analyst, no response, once per precursor ({technique}; external \
             audit NETR-014)",
            age_ns / 60_000_000_000,
            CORRELATION_WINDOW_NS / 1_000_000_000,
            retention_ns(kind) / 60_000_000_000,
        ),
    )
}

/// Review 70: the verdict of a chain completed by a precursor processed
/// after the egress it preceded; it names the egress, as the in-order
/// verdict does.
fn late_chain_verdict(rule: &dyn Rule, egress: &EgressNote, reasoning: &str) -> Verdict {
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action: ResponseAction::KillProcessTree,
        severity: Severity::Critical,
        reasoning: reasoning.to_string(),
        event_pid: egress.pid,
        event_filename: egress.comm.clone(),
        timestamp_ns: egress.start_ns,
    }
}

/// Chain Verdict with an explicit action and severity (the
/// informational NN-L-CHAIN-008 uses `Log` + `Medium`).
fn chain_verdict_with(
    rule: &dyn Rule,
    nf: &nn_model::telemetry::NetFlowEvent,
    action: ResponseAction,
    severity: Severity,
    reasoning: &str,
) -> Verdict {
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity,
        reasoning: reasoning.to_string(),
        event_pid: nf.pid,
        event_filename: nf.comm.clone(),
        timestamp_ns: nf.start_ns,
    }
}

/// `true` when a flow's destination never leaves the host: loopback
/// (`127.0.0.0/8`, `::1`, IPv4-mapped `::ffff:127.0.0.0/104`) or the
/// unspecified address. Such a flow is local IPC, not egress.
///
/// Only NN-L-CHAIN-008 applies it. The other chains keep loopback
/// triggers on purpose: their precursors (credential read, `/tmp`
/// exec, canary trip) are rare and high-confidence, and handing data
/// to a local proxy (`127.0.0.1:9050`) is a real exfiltration path.
fn is_on_host(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// External audit NETR-008: the review-49 carve-out for the staging chains
/// (CHAIN-002/005/007), now that their precursor covers `/var/tmp` (where
/// package transactions stage scriptlets). A process of a package
/// transaction gets no chain verdict; its flow falls through to the
/// network rules (NN-L-NET-008 records it), so no blocking rule is
/// shadowed by a downgraded one.
///
/// Lab PR 175: the transaction of NN-L-NET-008 and the FIM rules
/// ([`AuthSessionTracker::in_package_transaction`]: a package manager
/// proper executed by root whose run covers `event_ns`), no longer any
/// `mandb` or package manager in the lineage. The same predicate at the
/// same time as NN-L-NET-008, so a flow a chain leaves alone is the flow
/// NN-L-NET-008 records.
fn package_mediated(lineage: Option<&AuthSessionTracker>, pid: u32, event_ns: u64) -> bool {
    lineage.is_some_and(|l| l.in_package_transaction(pid, event_ns))
}

// ── NN-L-CHAIN-001 — credential read → egress ────────────────────────

/// Credential-store FIM access (NN-L-FIM-015/016/017 path hit)
/// followed by a same-PID outbound flow within the window. MITRE
/// T1555 (Credentials from Password Stores) → T1041 (Exfiltration
/// Over C2 Channel). Critical + KillProcessTree → COMBAT.
pub struct NnLChain001CredReadThenEgress {
    buf: Arc<Mutex<CorrelationStore>>,
}

impl NnLChain001CredReadThenEgress {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
    }
}

impl Rule for NnLChain001CredReadThenEgress {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-001_CredReadThenEgress"
    }
    fn name(&self) -> &'static str {
        "Credential-store access followed by network egress"
    }
    fn category(&self) -> &'static str {
        "chain_exfiltration"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CredentialAccess, "T1555.003"),
            AttackRef::new(Tactic::CredentialAccess, "T1555.005"),
            AttackRef::new(Tactic::CredentialAccess, "T1552.004"),
            AttackRef::new(Tactic::Exfiltration, "T1041"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Precursor: record + fall through (FIM-015/016/017 fires).
            // External audit NETR-001: not a wide-coverage open (any home's
            // keyring, browser or password store, Tappa 10.9). The owner
            // application opens those too — so does a backup — and
            // review 54 decided they are reported, never acted on; here
            // they fed a KillProcessTree. FIM-015/017 still log them.
            Event::Fim(fe) if is_credential_store_access(fe) && !fe.wide_coverage => {
                let mut store = self.buf.lock();
                store.record_for_pid(fe.modifier_pid, PrecursorKind::CredRead, fe.timestamp_ns);
                // Review 70: the read happened before an egress of the same
                // process that was processed first (another ring). Lab PR
                // 235: claimed, so a `/tmp` exec processed later still
                // completes CHAIN-007 with it.
                let key = store.current_key(fe.modifier_pid);
                let egress =
                    store.claim_egress_after(key, fe.timestamp_ns, CORRELATION_WINDOW_NS)?;
                Some(late_chain_verdict(
                    self,
                    &egress,
                    "Process accessed a credential store and then opened an \
                     outbound flow within the correlation window (the read was \
                     processed after the flow, in kernel order before it) — \
                     credential exfiltration (T1555 → T1041); kill the process \
                     tree + posture → COMBAT",
                ))
            }
            // Trigger: same-PID egress after a recorded cred access.
            // External audit NETR-014: graded by the read's age. Lab PR
            // 224: any phase of the flow (the connect, an open-flow
            // snapshot, the close), not a connect the kernel refused.
            Event::NetFlow(nf) if nf.phase != FlowPhase::Denied => {
                let mut store = self.buf.lock();
                match store.chain_age_for_pid(nf.pid, PrecursorKind::CredRead, nf.start_ns)? {
                    ChainAge::Fresh => {}
                    ChainAge::Aged { age_ns } => {
                        return Some(aged_chain_verdict(
                            self,
                            nf,
                            age_ns,
                            PrecursorKind::CredRead,
                            "Process accessed a credential store",
                            "T1555 → T1041",
                        ))
                    }
                }
                // Review 70: completed in order; no late precursor may reuse
                // it for a two-step chain.
                let key = store.current_key(nf.pid);
                store.claim_egress(key, nf.start_ns, PrecursorKind::CredRead);
                Some(chain_verdict(
                    self,
                    nf,
                    "Process accessed a credential store and then opened an \
                     outbound flow within the correlation window — \
                     credential exfiltration (T1555 → T1041); kill the \
                     process tree + posture → COMBAT",
                ))
            }
            _ => None,
        }
    }
}

// ── NN-L-CHAIN-002 — /tmp exec → C2 egress ───────────────────────────

/// A process executed from a staging directory (`/tmp/`, `/var/tmp/`,
/// `/dev/shm/`; R001–R003 shape) followed by a
/// same-PID outbound flow to a non-DNS port within the window. MITRE
/// T1059 (Command and Scripting Interpreter) → T1571 (Non-Standard
/// Port) — a dropper calling home. Critical + KillProcessTree →
/// COMBAT.
///
/// "C2 flow" is read as any same-PID outbound to a port other than
/// 53: restricting to a specific C2 port set would miss the common
/// C2-over-443 case, while excluding DNS avoids the benign resolver
/// call. The `/tmp`-exec precursor is the high-confidence half; the
/// egress correlation is what escalates it to Critical.
///
/// Lab PR 244: an exec record processed after the egress it preceded
/// completes the chain with the noted egress (module docs, "Late
/// precursors"), the resolver exemption, the package carve-out and the
/// port-53 hold judged on the egress's own destination and time.
pub struct NnLChain002TmpExecThenEgress {
    buf: Arc<Mutex<CorrelationStore>>,
    lineage: Option<AuthSessionTracker>,
    resolvers: Arc<HostResolvers>,
}

impl NnLChain002TmpExecThenEgress {
    /// With no configured resolver: every port-53 flow is an egress.
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self {
            buf,
            lineage: None,
            resolvers: HostResolvers::none(),
        }
    }

    /// With the package-manager carve-out ([`package_mediated`]).
    pub fn with_lineage(mut self, lineage: Option<AuthSessionTracker>) -> Self {
        self.lineage = lineage;
        self
    }

    /// Lab PR 224 (CM-02 d, research defect D1): a `/tmp` binary doing
    /// plain name resolution at a resolver the host is configured with is
    /// not the egress that matters; any other flow is — TCP/53 to its own
    /// server included. The exemption used to be any flow to port 53.
    pub fn with_resolvers(mut self, resolvers: Arc<HostResolvers>) -> Self {
        self.resolvers = resolvers;
        self
    }
}

impl Rule for NnLChain002TmpExecThenEgress {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-002_TmpExecThenEgress"
    }
    fn name(&self) -> &'static str {
        "/tmp exec followed by network egress"
    }
    fn category(&self) -> &'static str {
        "chain_c2"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Execution, "T1059"),
            AttackRef::new(Tactic::CommandAndControl, "T1571"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Every spawn feeds the shared ancestry tree (D4) — this is
            // the one chain rule that sees `Event::ProcessSpawn`, so it
            // hosts lineage observation for the whole store. A `/tmp`
            // image additionally records the TmpExec precursor (R001
            // shape).
            // External audit NETR-009: keyed with the process's own start
            // (POS-003), not `parent_start_ns` (the parent's start: since
            // lab PR 238 its thread-group leader's, the forking thread's
            // before).
            Event::ProcessSpawn {
                pid,
                ppid,
                filename,
                timestamp_ns,
                start_ns,
                exe,
                ..
            } => {
                let mut store = self.buf.lock();
                store.observe_spawn(*pid, *ppid, *start_ns);
                // Review 61: the file the kernel executed. External audit
                // NETR-008: any staging directory, not `/tmp/` alone.
                if !crate::decision::rules::is_staging_path(exe.path_or(filename)) {
                    return None;
                }
                let key = ProcKey {
                    pid: *pid,
                    start_ns: *start_ns,
                };
                store.record(key, PrecursorKind::TmpExec, *timestamp_ns);
                // Lab PR 244: the exec was processed after an egress it
                // preceded (the exec ring's pump behind the connect's, as in
                // lab PR 235), so the egress was judged without it. The
                // chain is judged on the kernel timestamps, flow by flow as
                // in order: the earliest unclaimed egress of this process
                // within the window after the exec that is not a lookup at a
                // configured resolver nor a package transaction's. On a miss
                // the exec is only recorded, as before.
                let candidates =
                    store.exec_egresses(*pid, *start_ns, *timestamp_ns, CORRELATION_WINDOW_NS);
                drop(store);
                let egress = candidates.into_iter().find(|n| {
                    !crate::net::resolvers::is_resolver_destination(
                        &n.dst_addr,
                        n.dst_port,
                        &self.resolvers,
                    ) && !package_mediated(self.lineage.as_ref(), *pid, n.start_ns)
                })?;
                // Claimed: no late precursor completes a two-step chain with
                // it again; a late credential read can still complete
                // CHAIN-007 with it.
                self.buf
                    .lock()
                    .claim_exec_egress(*pid, *start_ns, egress.start_ns);
                Some(crate::decision::response_policy::hold_port_53_to(
                    egress.dst_port,
                    late_chain_verdict(
                        self,
                        &egress,
                        "Process executed from a staging directory (/tmp, /var/tmp, \
                         /dev/shm) then opened an outbound flow (other than a lookup at a \
                         configured resolver) within the correlation window (the exec was \
                         processed after the flow, in kernel order before it) — dropper C2 \
                         (T1059 → T1571); kill the process tree + posture → COMBAT",
                    ),
                ))
            }
            // Trigger: same-PID egress other than a lookup at a configured
            // resolver (lab PR 224: in any phase of the flow but a refused
            // connect).
            Event::NetFlow(nf)
                if nf.phase != FlowPhase::Denied
                    && !crate::net::resolvers::is_resolver_flow(nf, &self.resolvers) =>
            {
                if !self.buf.lock().has_recent_for_pid(
                    nf.pid,
                    PrecursorKind::TmpExec,
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) || package_mediated(self.lineage.as_ref(), nf.pid, nf.start_ns)
                {
                    return None;
                }
                // Lab PR 244: completed in order; no late precursor completes
                // a two-step chain with it again (a second staging exec of the
                // process, a credential read for CHAIN-001), a late read can
                // still complete CHAIN-007 with it.
                let mut store = self.buf.lock();
                let key = store.current_key(nf.pid);
                store.claim_egress(key, nf.start_ns, PrecursorKind::TmpExec);
                drop(store);
                Some(crate::decision::response_policy::hold_port_53(
                    nf,
                    chain_verdict(
                        self,
                        nf,
                        "Process executed from a staging directory (/tmp, /var/tmp, \
                         /dev/shm) then opened an outbound flow (other than a lookup at a \
                         configured resolver) within the correlation window — \
                         dropper C2 (T1059 → T1571); kill the process tree + \
                         posture → COMBAT",
                    ),
                ))
            }
            _ => None,
        }
    }
}

// ── NN-L-CHAIN-003 — canary trip → egress ────────────────────────────

/// A canary trip (any NN-L-CANARY-* deception trap) followed by a
/// same-PID outbound flow within the window. MITRE deception → T1041
/// (Exfiltration Over C2 Channel) — the process that touched a
/// decoy is now talking to the network. Critical + KillProcessTree →
/// COMBAT.
///
/// The connection a network canary trip is (NN-L-CANARY-003, a connect to
/// the decoy destination) is not an egress after it: the engine's flow
/// ledger owns every row of it from the trip on, in any order the rows
/// arrive (lab PR 163, lab PR 246), and the trip drops a note of it taken
/// earlier ([`CorrelationStore::drop_trip_egress`]). Any other flow of the
/// process completes this chain.
pub struct NnLChain003CanaryThenEgress {
    buf: Arc<Mutex<CorrelationStore>>,
}

impl NnLChain003CanaryThenEgress {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
    }
}

impl Rule for NnLChain003CanaryThenEgress {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-003_CanaryThenEgress"
    }
    fn name(&self) -> &'static str {
        "Canary trip followed by network egress"
    }
    fn category(&self) -> &'static str {
        "chain_exfiltration"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Exfiltration, "T1041")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Precursor: any canary trip, keyed on the accessor PID.
            Event::CanaryTripped {
                access_kind,
                accessor_pid,
                timestamp_ns,
                ..
            } => {
                let mut store = self.buf.lock();
                store.record_for_pid(*accessor_pid, PrecursorKind::CanaryTrip, *timestamp_ns);
                // Lab PR 246: a network trip is a connect; that connection is
                // the trip's, not an egress after it (the engine's flow
                // ledger keeps every rule off its rows from now on). A row
                // of it judged before the trip leaves no egress for a late
                // precursor to complete a chain with.
                if *access_kind == CanaryAccessKind::NetworkConnect {
                    store.drop_trip_egress(*accessor_pid, *timestamp_ns);
                }
                None
            }
            // Trigger: same-PID egress after the trip. External audit
            // NETR-014: graded by the trip's age.
            Event::NetFlow(nf) if nf.phase != FlowPhase::Denied => {
                let age = self.buf.lock().chain_age_for_pid(
                    nf.pid,
                    PrecursorKind::CanaryTrip,
                    nf.start_ns,
                )?;
                if let ChainAge::Aged { age_ns } = age {
                    return Some(aged_chain_verdict(
                        self,
                        nf,
                        age_ns,
                        PrecursorKind::CanaryTrip,
                        "Process tripped a deception canary",
                        "deception → T1041",
                    ));
                }
                Some(chain_verdict(
                    self,
                    nf,
                    "Process tripped a deception canary and then opened an \
                     outbound flow within the correlation window — \
                     deception → exfiltration (T1041); kill the process \
                     tree + posture → COMBAT",
                ))
            }
            _ => None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Tappa 10.6 D6 — CHAIN-004..008: cross-PID + N-event kill chains
// ════════════════════════════════════════════════════════════════════
//
// These build on the shared store (D3) + ancestry tree (D4). The
// cross-PID rules (004/005/006/008) use `has_recent_in_ancestors`
// (strictly an ancestor, not self) so they NEVER shadow the same-PID
// CHAIN-001..003; CHAIN-007 uses the N-event `has_sequence`. All fire
// Critical + KillProcessTree, like the originals.

/// `sudo`/`su` comms — the privilege-escalation precursor for CHAIN-008.
const PRIVESC_TOOLS: &[&str] = &["sudo", "su"];

/// NN-L-CHAIN-004 — credential read by an **ancestor**, then a
/// descendant egresses. The cross-PID form of CHAIN-001 (T1555 →
/// T1041): e.g. a parent reads `~/.aws/credentials`, the child it
/// spawned exfiltrates. Reuses the `CredRead` precursor recorded by
/// CHAIN-001 in the shared store.
pub struct NnLChain004CrossPidCredExfil {
    buf: Arc<Mutex<CorrelationStore>>,
}

impl NnLChain004CrossPidCredExfil {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
    }
}

impl Rule for NnLChain004CrossPidCredExfil {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-004_CrossPidCredExfil"
    }
    fn name(&self) -> &'static str {
        "Ancestor credential read followed by descendant egress"
    }
    fn category(&self) -> &'static str {
        "chain_exfiltration"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CredentialAccess, "T1555.003"),
            AttackRef::new(Tactic::CredentialAccess, "T1555.005"),
            AttackRef::new(Tactic::CredentialAccess, "T1552.004"),
            AttackRef::new(Tactic::Exfiltration, "T1041"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if nf.phase == FlowPhase::Denied {
            return None;
        }
        // External audit NETR-014: graded by the read's age.
        let age =
            self.buf
                .lock()
                .chain_age_in_ancestors(nf.pid, PrecursorKind::CredRead, nf.start_ns)?;
        if let ChainAge::Aged { age_ns } = age {
            return Some(aged_chain_verdict(
                self,
                nf,
                age_ns,
                PrecursorKind::CredRead,
                "A process ancestor read a credential store",
                "T1555 → T1041, cross-PID",
            ));
        }
        Some(chain_verdict(
            self,
            nf,
            "A process ancestor read a credential store and a descendant \
             then opened an outbound flow — cross-PID credential \
             exfiltration (T1555 → T1041); kill the process tree + \
             posture → COMBAT",
        ))
    }
}

/// NN-L-CHAIN-005 — `/tmp` exec by an **ancestor**, then a descendant
/// egresses to a non-DNS port. Cross-PID form of CHAIN-002 (T1059 →
/// T1571): a dropper spawns a child that calls home. Reuses `TmpExec`.
pub struct NnLChain005CrossPidTmpC2 {
    buf: Arc<Mutex<CorrelationStore>>,
    lineage: Option<AuthSessionTracker>,
    resolvers: Arc<HostResolvers>,
}

impl NnLChain005CrossPidTmpC2 {
    /// With no configured resolver: every port-53 flow is an egress.
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self {
            buf,
            lineage: None,
            resolvers: HostResolvers::none(),
        }
    }

    /// With the package-manager carve-out ([`package_mediated`]).
    pub fn with_lineage(mut self, lineage: Option<AuthSessionTracker>) -> Self {
        self.lineage = lineage;
        self
    }

    /// Lab PR 224: as [`NnLChain002TmpExecThenEgress::with_resolvers`].
    pub fn with_resolvers(mut self, resolvers: Arc<HostResolvers>) -> Self {
        self.resolvers = resolvers;
        self
    }
}

impl Rule for NnLChain005CrossPidTmpC2 {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-005_CrossPidTmpC2"
    }
    fn name(&self) -> &'static str {
        "Ancestor /tmp exec followed by descendant egress"
    }
    fn category(&self) -> &'static str {
        "chain_c2"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Execution, "T1059"),
            AttackRef::new(Tactic::CommandAndControl, "T1571"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if nf.phase == FlowPhase::Denied
            || crate::net::resolvers::is_resolver_flow(nf, &self.resolvers)
        {
            return None;
        }
        if !self.buf.lock().has_recent_in_ancestors(
            nf.pid,
            PrecursorKind::TmpExec,
            nf.start_ns,
            CORRELATION_WINDOW_NS,
        ) || package_mediated(self.lineage.as_ref(), nf.pid, nf.start_ns)
        {
            return None;
        }
        Some(crate::decision::response_policy::hold_port_53(
            nf,
            chain_verdict(
                self,
                nf,
                "A process ancestor executed from a staging directory and a descendant then \
             opened an outbound flow (other than a lookup at a configured resolver) — cross-PID \
             dropper C2 (T1059 → T1571); kill the process tree + \
             posture → COMBAT",
            ),
        ))
    }
}

/// NN-L-CHAIN-006 — canary trip by an **ancestor**, then a descendant
/// egresses. Cross-PID form of CHAIN-003 (deception → T1041). Reuses
/// the `CanaryTrip` precursor.
pub struct NnLChain006CrossPidCanaryExfil {
    buf: Arc<Mutex<CorrelationStore>>,
}

impl NnLChain006CrossPidCanaryExfil {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
    }
}

impl Rule for NnLChain006CrossPidCanaryExfil {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-006_CrossPidCanaryExfil"
    }
    fn name(&self) -> &'static str {
        "Ancestor canary trip followed by descendant egress"
    }
    fn category(&self) -> &'static str {
        "chain_exfiltration"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Exfiltration, "T1041")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if nf.phase == FlowPhase::Denied {
            return None;
        }
        // External audit NETR-014: graded by the trip's age.
        let age = self.buf.lock().chain_age_in_ancestors(
            nf.pid,
            PrecursorKind::CanaryTrip,
            nf.start_ns,
        )?;
        if let ChainAge::Aged { age_ns } = age {
            return Some(aged_chain_verdict(
                self,
                nf,
                age_ns,
                PrecursorKind::CanaryTrip,
                "A process ancestor tripped a deception canary",
                "deception → T1041, cross-PID",
            ));
        }
        Some(chain_verdict(
            self,
            nf,
            "A process ancestor tripped a deception canary and a \
             descendant then opened an outbound flow — cross-PID \
             deception → exfiltration (T1041); kill the process tree + \
             posture → COMBAT",
        ))
    }
}

/// NN-L-CHAIN-007 — three-step same-PID kill chain: `/tmp` exec **then**
/// credential read **then** egress, all on one process within the
/// window (T1059 → T1555 → T1041). Uses the D3 N-event
/// [`CorrelationStore::has_sequence`]. Registered BEFORE CHAIN-001/002
/// so this richer 3-step verdict wins over the 2-step ones for the same
/// flow (the §13 Q10 specific-before-catch-all ordering).
pub struct NnLChain007TmpCredExfilSequence {
    buf: Arc<Mutex<CorrelationStore>>,
    lineage: Option<AuthSessionTracker>,
}

impl NnLChain007TmpCredExfilSequence {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf, lineage: None }
    }

    /// With the package-manager carve-out ([`package_mediated`]).
    pub fn with_lineage(mut self, lineage: Option<AuthSessionTracker>) -> Self {
        self.lineage = lineage;
        self
    }
}

impl Rule for NnLChain007TmpCredExfilSequence {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-007_TmpCredExfilSequence"
    }
    fn name(&self) -> &'static str {
        "/tmp exec then credential read then egress (3-step)"
    }
    fn category(&self) -> &'static str {
        "chain_exfiltration"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Execution, "T1059"),
            AttackRef::new(Tactic::CredentialAccess, "T1555.003"),
            AttackRef::new(Tactic::CredentialAccess, "T1555.005"),
            AttackRef::new(Tactic::CredentialAccess, "T1552.004"),
            AttackRef::new(Tactic::Exfiltration, "T1041"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            Event::NetFlow(nf) if nf.phase != FlowPhase::Denied => {
                let mut store = self.buf.lock();
                let key = store.current_key(nf.pid);
                if !store.has_sequence(
                    key,
                    &[PrecursorKind::TmpExec, PrecursorKind::CredRead],
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    // Review 70: this rule sees every flow first; keep it
                    // for a precursor processed after it.
                    store.note_egress(key, EgressNote::of(nf));
                    return None;
                }
                drop(store);
                if package_mediated(self.lineage.as_ref(), nf.pid, nf.start_ns) {
                    return None;
                }
                Some(chain_verdict(
                    self,
                    nf,
                    "Process executed from a staging directory, then read a credential store, \
                     then opened an outbound flow — three-step dropper → \
                     credential-access → exfil chain (T1059 → T1555 → T1041); \
                     kill the process tree + posture → COMBAT",
                ))
            }
            // Review 70: the credential read of the chain was processed after
            // the egress (the open sensor's or FIM's ring, behind the
            // network drain), though it happened before it. Recorded here
            // too: this verdict ends the rule pass before CHAIN-001 runs.
            // External audit NETR-001: wide-coverage opens excluded, as in
            // CHAIN-001.
            Event::Fim(fe) if is_credential_store_access(fe) && !fe.wide_coverage => {
                let mut store = self.buf.lock();
                let key = store.current_key(fe.modifier_pid);
                if !store.has_recent(
                    key,
                    PrecursorKind::TmpExec,
                    fe.timestamp_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    return None;
                }
                if package_mediated(self.lineage.as_ref(), fe.modifier_pid, fe.timestamp_ns) {
                    return None;
                }
                let egress =
                    store.take_egress_after(key, fe.timestamp_ns, CORRELATION_WINDOW_NS)?;
                store.record(key, PrecursorKind::CredRead, fe.timestamp_ns);
                Some(late_chain_verdict(
                    self,
                    &egress,
                    "Process executed from a staging directory, then read a credential store, \
                     then opened an outbound flow (the read was processed after \
                     the flow, in kernel order before it) — three-step dropper → \
                     credential-access → exfil chain (T1059 → T1555 → T1041); \
                     kill the process tree + posture → COMBAT",
                ))
            }
            // Lab PR 235: the staging exec of the chain was processed after
            // the credential read and the egress (the exec ring's pump behind
            // the open sensor's or FIM's and the connect pump), though it
            // happened before both: the CI flake of 22/10/2026, where
            // CHAIN-001 fired on the egress and this rule never did. The
            // chain is judged on the kernel timestamps. On a hit the exec is
            // observed and its `TmpExec` recorded here, as CHAIN-002 would,
            // and the egress is taken: CHAIN-002, which judges the exec after
            // this rule, completes no two-step chain with it (lab PR 244). On
            // a miss nothing changes here.
            Event::ProcessSpawn {
                pid,
                ppid,
                filename,
                exe,
                timestamp_ns,
                start_ns,
                ..
            } if crate::decision::rules::is_staging_path(exe.path_or(filename)) => {
                let egress = self.buf.lock().exec_sequence_egress(
                    *pid,
                    *start_ns,
                    *timestamp_ns,
                    CORRELATION_WINDOW_NS,
                )?;
                if package_mediated(self.lineage.as_ref(), *pid, *timestamp_ns) {
                    return None;
                }
                self.buf.lock().complete_exec_sequence(
                    *pid,
                    *ppid,
                    *start_ns,
                    *timestamp_ns,
                    egress.start_ns,
                );
                Some(late_chain_verdict(
                    self,
                    &egress,
                    "Process executed from a staging directory, then read a credential store, \
                     then opened an outbound flow (the exec was processed after \
                     the read and the flow, in kernel order before them) — three-step \
                     dropper → credential-access → exfil chain (T1059 → T1555 → T1041); \
                     kill the process tree + posture → COMBAT",
                ))
            }
            _ => None,
        }
    }
}

/// NN-L-CHAIN-008 — `sudo`/`su` by an **ancestor**, then a descendant
/// opens an off-host flow (T1548 → T1041). Records the `PrivEsc`
/// precursor on the sudo/su spawn itself (returns None — falls through
/// to any process rule), and triggers cross-PID on a later descendant
/// flow.
///
/// **Informational: `Medium` + `Log`, registered LAST.** Running sudo
/// or su and then reaching the network is the routine admin workflow.
/// In the lab (2026-10-11) `sudo apt-get update` drew this verdict on
/// apt's `http` method, and a loopback benchmark run under sudo drew
/// 499 of them. As a Critical `KillProcessTree` it killed package
/// updates, configuration management (`become: sudo`) and any sudo'd
/// tool that touched the network for the whole correlation window,
/// while an attacker who already holds sudo sidesteps it trivially
/// (wait out the window, `systemd-run`). So it stays a correlation
/// signal only:
///
/// - loopback and unspecified destinations are ignored
///   ([`is_on_host`]);
/// - the verdict is `Medium` + `Log`;
/// - the rule sits at the END of the engine ([`ChainRuleSet::tail`]),
///   so its Log verdict never shadows a blocking rule on the same flow
///   (a sudo'd shell calling port 4444 still gets NN-L-NET-010's kill).
///
/// A sharper trigger (sudo/su invoked from a service context rather
/// than a login session, or the design's module-load → outbound
/// sequence) is an open review item.
pub struct NnLChain008CrossPidPrivEscExfil {
    buf: Arc<Mutex<CorrelationStore>>,
}

impl NnLChain008CrossPidPrivEscExfil {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
    }
}

impl Rule for NnLChain008CrossPidPrivEscExfil {
    fn id(&self) -> &'static str {
        "NN-L-CHAIN-008_CrossPidPrivEscExfil"
    }
    fn name(&self) -> &'static str {
        "Ancestor sudo/su privesc followed by descendant egress"
    }
    fn category(&self) -> &'static str {
        "chain_exfiltration"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::PrivilegeEscalation, "T1548"),
            AttackRef::new(Tactic::Exfiltration, "T1041"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Precursor: a sudo/su exec — record PrivEsc on its PID.
            Event::ProcessSpawn {
                pid,
                comm,
                timestamp_ns,
                start_ns,
                ..
            } if PRIVESC_TOOLS.contains(&comm.as_str()) => {
                let key = ProcKey {
                    pid: *pid,
                    start_ns: *start_ns,
                };
                self.buf
                    .lock()
                    .record(key, PrecursorKind::PrivEsc, *timestamp_ns);
                None
            }
            // Trigger: a descendant of the sudo/su process leaves the
            // host. Loopback is local IPC, not egress.
            // Lab PR 224: a record (Medium Log), judged once, on the closed
            // flow, as the network family's other records.
            Event::NetFlow(nf) if nf.phase == FlowPhase::Closed && !is_on_host(&nf.dst_addr) => {
                if !self.buf.lock().has_recent_in_ancestors(
                    nf.pid,
                    PrecursorKind::PrivEsc,
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    return None;
                }
                Some(chain_verdict_with(
                    self,
                    nf,
                    ResponseAction::Log,
                    Severity::Medium,
                    "A descendant of a sudo/su process opened an off-host \
                     flow within the correlation window — privilege use → \
                     network (T1548 → T1041). Routine for admin tooling, so \
                     logged for correlation only; blocking rules on the \
                     same flow are evaluated first",
                ))
            }
            _ => None,
        }
    }
}

// ── Factory ──────────────────────────────────────────────────────────

/// The NN-L-CHAIN rules over **one shared** [`CorrelationStore`], split
/// by the engine position each one needs.
pub struct ChainRuleSet {
    /// Registered FIRST: they record precursors before a first-match
    /// short-circuit, and their Critical verdicts win over lower net
    /// rules on the same flow (module docs).
    pub head: Vec<Box<dyn Rule>>,
    /// Registered LAST: informational chains whose `Log` verdict must
    /// never shadow a blocking rule on the same event (NN-L-CHAIN-008).
    pub tail: Vec<Box<dyn Rule>>,
}

/// Build the NN-L-CHAIN rules over **one shared** [`CorrelationStore`]
/// (Tappa 10.6 D3). Unlike the net blocklists / comm allowlists, the
/// store is PRIVATE runtime state (not operator config), so it's
/// constructed here rather than threaded from `main.rs` — the
/// `Arc<Mutex<_>>` lives for the engine's lifetime, cloned into each
/// rule. Sharing (vs the old per-rule buffers) is what lets D6's
/// multi-precursor chains correlate across rule kinds; per-rule
/// isolation is preserved by the typed [`PrecursorKind`]. The engine
/// MUST register [`ChainRuleSet::head`] FIRST and
/// [`ChainRuleSet::tail`] LAST (see the module docs); the
/// `default_rules*` builders do both.
pub fn chain_rule_set() -> ChainRuleSet {
    chain_rule_set_with(None)
}

/// [`chain_rule_set`] with the lineage cache for the staging chains'
/// package-manager carve-out (external audit NETR-008). Production passes
/// the shared tracker.
pub fn chain_rule_set_with(lineage: Option<AuthSessionTracker>) -> ChainRuleSet {
    chain_rule_set_over(Arc::new(Mutex::new(CorrelationStore::new())), lineage)
}

/// [`chain_rule_set_with`] over a store the caller also holds: production
/// passes the one the netflow limiter reads (external audit NET-019 — a
/// process with a precursor in it always has its flows evaluated).
pub fn chain_rule_set_over(
    store: Arc<Mutex<CorrelationStore>>,
    lineage: Option<AuthSessionTracker>,
) -> ChainRuleSet {
    chain_rule_set_full(store, lineage, HostResolvers::none())
}

/// [`chain_rule_set_over`] with the host's configured resolvers (lab PR
/// 224), whose DNS port the staging chains leave to a staged image.
pub fn chain_rule_set_full(
    store: Arc<Mutex<CorrelationStore>>,
    lineage: Option<AuthSessionTracker>,
    resolvers: Arc<HostResolvers>,
) -> ChainRuleSet {
    ChainRuleSet {
        head: vec![
            // CHAIN-007 (3-step same-PID) first: the richest verdict wins
            // first-match over the 2-step CHAIN-001/002 for the same flow.
            Box::new(
                NnLChain007TmpCredExfilSequence::new(Arc::clone(&store))
                    .with_lineage(lineage.clone()),
            ),
            // Same-PID 2-step originals.
            Box::new(NnLChain001CredReadThenEgress::new(Arc::clone(&store))),
            Box::new(
                NnLChain002TmpExecThenEgress::new(Arc::clone(&store))
                    .with_lineage(lineage.clone())
                    .with_resolvers(Arc::clone(&resolvers)),
            ),
            Box::new(NnLChain003CanaryThenEgress::new(Arc::clone(&store))),
            // Cross-PID variants (strict ancestor — never shadow the above).
            Box::new(NnLChain004CrossPidCredExfil::new(Arc::clone(&store))),
            Box::new(
                NnLChain005CrossPidTmpC2::new(Arc::clone(&store))
                    .with_lineage(lineage)
                    .with_resolvers(resolvers),
            ),
            Box::new(NnLChain006CrossPidCanaryExfil::new(Arc::clone(&store))),
        ],
        tail: vec![Box::new(NnLChain008CrossPidPrivEscExfil::new(Arc::clone(
            &store,
        )))],
    }
}

/// Every chain rule in engine order (head, then tail) over one shared
/// store — the flat view the unit tests use.
pub fn chain_rules() -> Vec<Box<dyn Rule>> {
    let ChainRuleSet { mut head, tail } = chain_rule_set();
    head.extend(tail);
    head
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_model::telemetry::{FimEvent, FimOp, NetFlowEvent};
    use std::net::{IpAddr, Ipv4Addr};

    const SEC: u64 = 1_000_000_000;

    fn cred_fim(pid: u32, ts_ns: u64) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: ts_ns,
            path: "/home/u/.gnupg/private-keys-v1.d/abc.key".to_string(),
            op: FimOp::Opened,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 1000,
            modifier_comm: "exfil".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    fn tmp_spawn(pid: u32, ts_ns: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "dropper".to_string(),
            filename: "/tmp/dropper".to_string(),
            timestamp_ns: ts_ns,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn canary_trip(pid: u32, ts_ns: u64) -> Event {
        Event::CanaryTripped {
            canary_id: "deadbeef".to_string(),
            canary_name: "decoy-aws".to_string(),
            canary_type: nn_model::CanaryTypeTag::Credential,
            access_kind: nn_model::CanaryAccessKind::FileOpen,
            accessor_pid: pid,
            accessor_uid: 1000,
            accessor_comm: "thief".to_string(),
            accessor_exe: None,
            timestamp_ns: ts_ns,
            first_trip: true,
        }
    }

    fn flow(pid: u32, dst_port: u16, ts_ns: u64) -> Event {
        Event::NetFlow(NetFlowEvent {
            start_ns: ts_ns,
            end_ns: ts_ns + 1_000,
            family: 2,
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            src_port: 54321,
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            dst_port,
            proto: 6,
            pid,
            uid: 1000,
            comm: "evilbin".to_string(),
            exe: Some("/usr/bin/evilbin".to_string()),
            proc_start_ns: 0,
            bytes_sent: 1024,
            bytes_recv: 2048,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
            phase: Default::default(),
            observed_ns: 0,
        })
    }

    // ── NN-L-CHAIN-001 bespoke pairs ────────────────────────────────

    fn chain001() -> NnLChain001CredReadThenEgress {
        NnLChain001CredReadThenEgress::new(Arc::new(Mutex::new(CorrelationStore::new())))
    }

    #[test]
    fn chain001_fires_on_cred_read_then_egress() {
        let r = chain001();
        assert!(
            r.evaluate(&cred_fim(42, 10 * SEC)).is_none(),
            "precursor records, no fire"
        );
        let v = r
            .evaluate(&flow(42, 443, 10 * SEC + 5 * SEC))
            .expect("egress after cred read must fire");
        assert_eq!(v.rule_id, "NN-L-CHAIN-001_CredReadThenEgress");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// External audit NETR-001: a wide-coverage credential open (the owner
    /// application, a backup) is reported by the FIM rules, never acted
    /// on; it no longer arms the chain's KillProcessTree — in either
    /// order of processing.
    #[test]
    fn chain001_ignores_wide_coverage_reads() {
        let wide = |pid, ts| match cred_fim(pid, ts) {
            Event::Fim(mut fe) => {
                fe.wide_coverage = true;
                Event::Fim(fe)
            }
            _ => unreachable!(),
        };
        let r = chain001();
        assert!(r.evaluate(&wide(42, 10 * SEC)).is_none());
        assert!(r.evaluate(&flow(42, 443, 15 * SEC)).is_none());
        // the read processed after the flow (review 70)
        let r = chain001();
        assert!(r.evaluate(&flow(43, 443, 20 * SEC)).is_none());
        assert!(r.evaluate(&wide(43, 19 * SEC)).is_none());
        // the same read off the wide-coverage path still arms it
        let r = chain001();
        assert!(r.evaluate(&cred_fim(44, 30 * SEC)).is_none());
        assert!(r.evaluate(&flow(44, 443, 31 * SEC)).is_some());
    }

    #[test]
    fn chain001_does_not_fire_without_precursor() {
        let r = chain001();
        assert!(r.evaluate(&flow(42, 443, 100 * SEC)).is_none());
    }

    /// External audit NETR-014 (lab PR 213): past the 300 s window the
    /// correlation no longer kills — it is one High record, no response —
    /// and nothing past the 30-minute retention (it used to be nothing past
    /// 300 s).
    #[test]
    fn chain001_does_not_kill_after_the_window() {
        let r = chain001();
        r.evaluate(&cred_fim(42, 10 * SEC));
        // Egress 6 minutes later: recorded, not killed.
        let v = r
            .evaluate(&flow(42, 443, 10 * SEC + 360 * SEC))
            .expect("an aged correlation is recorded");
        assert_eq!(v.rule_id, "NN-L-CHAIN-001_CredReadThenEgress");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning.contains("6 min before") && v.reasoning.contains("no response"),
            "{}",
            v.reasoning
        );
        let r = chain001();
        r.evaluate(&cred_fim(43, 10 * SEC));
        assert!(r
            .evaluate(&flow(43, 443, 10 * SEC + 31 * 60 * SEC))
            .is_none());
    }

    /// External audit NETR-014: the triage's pin — a credential read at t0
    /// and an egress at t0 + 20 min give CHAIN-001 (the record), at
    /// t0 + 31 min nothing; within 300 s it is still the Critical kill.
    #[test]
    fn a_cred_read_correlates_for_thirty_minutes() {
        let t0 = 100 * SEC;
        let r = chain001();
        r.evaluate(&cred_fim(42, t0));
        let v = r
            .evaluate(&flow(42, 443, t0 + 20 * 60 * SEC))
            .expect("CHAIN-001");
        assert_eq!(
            (v.severity, v.action),
            (Severity::High, ResponseAction::Log)
        );
        let r = chain001();
        r.evaluate(&cred_fim(42, t0));
        assert!(r.evaluate(&flow(42, 443, t0 + 31 * 60 * SEC)).is_none());
        let r = chain001();
        r.evaluate(&cred_fim(42, t0));
        let v = r
            .evaluate(&flow(42, 443, t0 + 299 * SEC))
            .expect("CHAIN-001");
        assert_eq!(
            (v.severity, v.action),
            (Severity::Critical, ResponseAction::KillProcessTree),
            "unchanged within 300 s"
        );
    }

    /// External audit NETR-014: one record per read — a backup client that
    /// read its credentials and then makes a hundred connections is one
    /// record, not a hundred; a new read is a new record (and a fresh one
    /// is the kill again).
    #[test]
    fn an_aged_read_is_recorded_once() {
        let t0 = 100 * SEC;
        let r = chain001();
        r.evaluate(&cred_fim(42, t0));
        let fired = (0..100)
            .filter_map(|i| r.evaluate(&flow(42, 443, t0 + 400 * SEC + i * SEC)))
            .count();
        assert_eq!(fired, 1);
        r.evaluate(&cred_fim(42, t0 + 600 * SEC));
        let v = r
            .evaluate(&flow(42, 443, t0 + 1000 * SEC))
            .expect("the new read");
        assert_eq!(v.severity, Severity::High);
        r.evaluate(&cred_fim(42, t0 + 1100 * SEC));
        let v = r
            .evaluate(&flow(42, 443, t0 + 1110 * SEC))
            .expect("a fresh read");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn chain001_does_not_fire_cross_pid() {
        let r = chain001();
        r.evaluate(&cred_fim(42, 10 * SEC));
        // Egress from a DIFFERENT pid — no correlation (Q2 per-PID).
        assert!(r.evaluate(&flow(99, 443, 10 * SEC + SEC)).is_none());
    }

    #[test]
    fn chain001_ignores_non_cred_fim_precursor() {
        let r = chain001();
        let benign = Event::Fim(FimEvent {
            timestamp_ns: 10 * SEC,
            path: "/etc/hosts".to_string(),
            op: FimOp::Modified,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "x".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        });
        assert!(r.evaluate(&benign).is_none());
        assert!(
            r.evaluate(&flow(42, 443, 10 * SEC + SEC)).is_none(),
            "non-cred FIM must not seed the chain"
        );
    }

    // ── NN-L-CHAIN-002 bespoke pairs ────────────────────────────────

    fn chain002() -> NnLChain002TmpExecThenEgress {
        NnLChain002TmpExecThenEgress::new(Arc::new(Mutex::new(CorrelationStore::new())))
    }

    #[test]
    fn chain002_fires_on_tmp_exec_then_nondns_egress() {
        let r = chain002();
        assert!(r.evaluate(&tmp_spawn(42, 10 * SEC)).is_none());
        let v = r
            .evaluate(&flow(42, 4444, 10 * SEC + SEC))
            .expect("non-DNS egress after /tmp exec must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lab PR 224: a lookup at a configured resolver is the carve-out —
    /// the flow helper's destination 203.0.113.9 stands in for one.
    #[test]
    fn chain002_does_not_fire_on_a_lookup_at_a_configured_resolver() {
        let r = chain002().with_resolvers(HostResolvers::fixed([IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 9,
        ))]));
        r.evaluate(&tmp_spawn(42, 10 * SEC));
        assert!(r.evaluate(&flow(42, 53, 10 * SEC + SEC)).is_none());
    }

    /// Lab PR 224 (research defect D1): port 53 to a server the host is not
    /// configured with is C2 like any other port — the starting tree let
    /// every port-53 flow through. A new match: Critical, recorded, its kill
    /// held behind the per-rule policy.
    #[test]
    fn chain002_fires_on_port_53_to_a_server_that_is_no_configured_resolver() {
        let r = chain002().with_resolvers(HostResolvers::fixed([IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 53,
        ))]));
        r.evaluate(&tmp_spawn(42, 10 * SEC));
        let v = r
            .evaluate(&flow(42, 53, 10 * SEC + SEC))
            .expect("TCP/53 to its own server is the dropper's C2");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning.contains("configured resolver") && v.reasoning.contains("[held back: "),
            "{}",
            v.reasoning
        );
        // Another port: the kill, as before lab PR 224.
        let r = chain002();
        r.evaluate(&tmp_spawn(43, 10 * SEC));
        let v = r.evaluate(&flow(43, 4444, 10 * SEC + SEC)).expect("C2");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn chain002_does_not_fire_without_tmp_precursor() {
        let r = chain002();
        // Non-/tmp spawn doesn't seed.
        let non_tmp = Event::ProcessSpawn {
            pid: 42,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "ls".to_string(),
            filename: "/usr/bin/ls".to_string(),
            timestamp_ns: 10 * SEC,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        r.evaluate(&non_tmp);
        assert!(r.evaluate(&flow(42, 4444, 10 * SEC + SEC)).is_none());
    }

    fn staged_spawn(pid: u32, filename: &str, ts_ns: u64) -> Event {
        let mut e = tmp_spawn(pid, ts_ns);
        if let Event::ProcessSpawn { filename: f, .. } = &mut e {
            *f = filename.to_string();
        }
        e
    }

    /// External audit NETR-008: the precursor covers every staging
    /// directory, not `/tmp/` alone; `/run/user` stays out.
    #[test]
    fn chain_002_records_var_tmp() {
        for (i, path) in ["/var/tmp/stage", "/dev/shm/stage", "/tmp/stage"]
            .iter()
            .enumerate()
        {
            let r = chain002();
            let pid = 50 + i as u32;
            r.evaluate(&staged_spawn(pid, path, 10 * SEC));
            let v = r
                .evaluate(&flow(pid, 443, 11 * SEC))
                .unwrap_or_else(|| panic!("{path} then egress fires"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
        }
        let r = chain002();
        r.evaluate(&staged_spawn(60, "/run/user/1000/app", 10 * SEC));
        assert!(r.evaluate(&flow(60, 443, 11 * SEC)).is_none());
    }

    /// External audit NETR-008: a package transaction's process staged in
    /// /var/tmp gets no chain verdict (its flow falls through to the net
    /// rules); anything else still does.
    #[test]
    fn chain_002_spares_a_package_transaction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        lineage.ingest_spawn(700, 1, "/usr/bin/rpm", 1);
        lineage.ingest_spawn(701, 700, "/var/tmp/rpm-tmp.x", 2);
        let r = NnLChain002TmpExecThenEgress::new(Arc::new(Mutex::new(CorrelationStore::new())))
            .with_lineage(Some(lineage));
        r.evaluate(&staged_spawn(701, "/var/tmp/rpm-tmp.x", 10 * SEC));
        r.evaluate(&staged_spawn(702, "/var/tmp/stage2", 10 * SEC));
        assert!(r.evaluate(&flow(701, 443, 11 * SEC)).is_none());
        assert!(r.evaluate(&flow(702, 443, 11 * SEC)).is_some());
    }

    /// Lab PR 175: the carve-out is NN-L-NET-008's package transaction
    /// (root's package manager, while its run covers the flow). A program
    /// from `/tmp` a user's `mandb` forked (`LD_PRELOAD`; not set-id) drew
    /// no chain verdict; now CHAIN-002 and CHAIN-005 judge it. A root
    /// transaction's staged scriptlet still falls through to the net rules.
    #[test]
    fn chains_judge_a_staged_process_forked_under_a_users_mandb() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // the user's mandb (710, running) → /tmp/payload (711) → its child (712)
        lineage.ingest_exec(710, 700, "/usr/bin/mandb", &[], SEC, SEC, 1000);
        lineage.ingest_exec(711, 710, "/tmp/payload", &[], 10 * SEC, 10 * SEC, 1000);
        lineage.ingest_exec(712, 711, "/usr/bin/curl", &[], 10 * SEC, 10 * SEC, 1000);
        // root's rpm (720, running) → its scriptlet (721)
        lineage.ingest_exec(720, 1, "/usr/bin/rpm", &[], SEC, SEC, 0);
        lineage.ingest_exec(721, 720, "/var/tmp/rpm-tmp.x", &[], 10 * SEC, 10 * SEC, 0);
        for pid in ["710", "720"] {
            std::fs::create_dir_all(tmp.path().join(pid)).unwrap();
        }
        let store = Arc::new(Mutex::new(CorrelationStore::new()));
        let c002 =
            NnLChain002TmpExecThenEgress::new(store.clone()).with_lineage(Some(lineage.clone()));
        let c005 = NnLChain005CrossPidTmpC2::new(store).with_lineage(Some(lineage));
        c002.evaluate(&spawn_at(711, 710, "/tmp/payload", 10 * SEC));
        c002.evaluate(&spawn_at(712, 711, "/usr/bin/curl", 10 * SEC + 1));
        c002.evaluate(&spawn_at(721, 720, "/var/tmp/rpm-tmp.x", 10 * SEC));
        let v = c002.evaluate(&flow(711, 443, 11 * SEC)).expect("CHAIN-002");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        let v = c005.evaluate(&flow(712, 443, 11 * SEC)).expect("CHAIN-005");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(c002.evaluate(&flow(721, 443, 11 * SEC)).is_none());
    }

    #[test]
    fn chain002_does_not_fire_cross_pid_or_ttl() {
        let r = chain002();
        r.evaluate(&tmp_spawn(42, 10 * SEC));
        assert!(
            r.evaluate(&flow(99, 4444, 10 * SEC + SEC)).is_none(),
            "cross-pid"
        );
        assert!(
            r.evaluate(&flow(42, 4444, 10 * SEC + 360 * SEC)).is_none(),
            "ttl-expired"
        );
    }

    // ── NN-L-CHAIN-003 bespoke pairs ────────────────────────────────

    fn chain003() -> NnLChain003CanaryThenEgress {
        NnLChain003CanaryThenEgress::new(Arc::new(Mutex::new(CorrelationStore::new())))
    }

    #[test]
    fn chain003_fires_on_canary_then_egress() {
        let r = chain003();
        assert!(r.evaluate(&canary_trip(42, 10 * SEC)).is_none());
        let v = r
            .evaluate(&flow(42, 443, 10 * SEC + SEC))
            .expect("egress after canary trip must fire");
        assert_eq!(v.rule_id, "NN-L-CHAIN-003_CanaryThenEgress");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// External audit NETR-014: a canary trip is kept 30 minutes too —
    /// past 300 s, one High record.
    #[test]
    fn chain003_records_an_aged_trip_without_killing() {
        let r = chain003();
        r.evaluate(&canary_trip(42, 10 * SEC));
        let v = r
            .evaluate(&flow(42, 443, 10 * SEC + 12 * 60 * SEC))
            .expect("an aged trip is recorded");
        assert_eq!(v.rule_id, "NN-L-CHAIN-003_CanaryThenEgress");
        assert_eq!(
            (v.severity, v.action),
            (Severity::High, ResponseAction::Log)
        );
        assert!(
            v.reasoning.contains("canary trip is kept"),
            "{}",
            v.reasoning
        );
        assert!(r
            .evaluate(&flow(42, 443, 10 * SEC + 13 * 60 * SEC))
            .is_none());
        let r = chain003();
        r.evaluate(&canary_trip(42, 10 * SEC));
        assert!(r
            .evaluate(&flow(42, 443, 10 * SEC + 31 * 60 * SEC))
            .is_none());
    }

    #[test]
    fn chain003_does_not_fire_without_precursor_or_cross_pid() {
        let r = chain003();
        assert!(
            r.evaluate(&flow(42, 443, 100 * SEC)).is_none(),
            "no precursor"
        );
        r.evaluate(&canary_trip(42, 10 * SEC));
        assert!(
            r.evaluate(&flow(99, 443, 10 * SEC + SEC)).is_none(),
            "cross-pid"
        );
    }

    // ── factory ─────────────────────────────────────────────────────

    #[test]
    fn chain_rules_builder_returns_eight_rules() {
        let rules = chain_rules();
        assert_eq!(rules.len(), 8);
        let ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            vec![
                // CHAIN-007 first (specific 3-step before the 2-step pair).
                "NN-L-CHAIN-007_TmpCredExfilSequence",
                "NN-L-CHAIN-001_CredReadThenEgress",
                "NN-L-CHAIN-002_TmpExecThenEgress",
                "NN-L-CHAIN-003_CanaryThenEgress",
                "NN-L-CHAIN-004_CrossPidCredExfil",
                "NN-L-CHAIN-005_CrossPidTmpC2",
                "NN-L-CHAIN-006_CrossPidCanaryExfil",
                "NN-L-CHAIN-008_CrossPidPrivEscExfil",
            ]
        );
    }

    /// D3 shared-store regression: the 3 rules now share one
    /// `CorrelationStore`. A credential-read precursor must trigger
    /// ONLY NN-L-CHAIN-001 on the subsequent egress — the `/tmp` and
    /// canary rules stay isolated by `PrecursorKind` despite the shared
    /// memory.
    #[test]
    fn shared_store_isolates_precursor_kinds_across_rules() {
        let rules = chain_rules();
        let cred = cred_fim(42, 10 * SEC);
        for r in &rules {
            assert!(
                r.evaluate(&cred).is_none(),
                "precursor records, never fires"
            );
        }
        let egress = flow(42, 443, 10 * SEC + SEC);
        let fired: Vec<String> = rules
            .iter()
            .filter_map(|r| r.evaluate(&egress))
            .map(|v| v.rule_id)
            .collect();
        assert_eq!(
            fired,
            vec!["NN-L-CHAIN-001_CredReadThenEgress".to_string()],
            "only the cred-read chain fires; /tmp + canary kinds isolated"
        );
    }

    // ── D6 CHAIN-004..008 ───────────────────────────────────────────

    fn proc_spawn(pid: u32, ppid: u32, comm: &str, filename: &str, ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 1000,
            gid: 1000,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// Feed an event to every rule (no first-match short-circuit) and
    /// return the rule_ids that fired.
    fn fire_ids(rules: &[Box<dyn Rule>], event: &Event) -> Vec<String> {
        rules
            .iter()
            .filter_map(|r| r.evaluate(event))
            .map(|v| v.rule_id)
            .collect()
    }

    #[test]
    fn chain004_cross_pid_cred_exfil_fires() {
        let rules = chain_rules();
        // parent 100 spawns child 200 (CHAIN-002 records the ancestry edge).
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        // parent 100 reads a credential store.
        fire_ids(&rules, &cred_fim(100, 11 * SEC));
        // child 200 egresses → cross-PID credential exfil.
        let fired = fire_ids(&rules, &flow(200, 443, 12 * SEC));
        assert!(
            fired.contains(&"NN-L-CHAIN-004_CrossPidCredExfil".to_string()),
            "{fired:?}"
        );
        // Same-PID CHAIN-001 must NOT fire — the cred read was the parent's.
        assert!(!fired.contains(&"NN-L-CHAIN-001_CredReadThenEgress".to_string()));
    }

    #[test]
    fn chain005_cross_pid_tmp_c2_fires() {
        let rules = chain_rules();
        // parent 100 ran from /tmp (records TmpExec) and spawned child 200.
        fire_ids(
            &rules,
            &proc_spawn(100, 1, "dropper", "/tmp/dropper", 10 * SEC),
        );
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 11 * SEC),
        );
        let fired = fire_ids(&rules, &flow(200, 4444, 12 * SEC));
        assert!(
            fired.contains(&"NN-L-CHAIN-005_CrossPidTmpC2".to_string()),
            "{fired:?}"
        );
        // Lab PR 224: port 53 to a server that is no configured resolver
        // (the flow helper's 203.0.113.9; `chain_rules` knows none) is an
        // egress.
        let dns = fire_ids(&rules, &flow(200, 53, 13 * SEC));
        assert!(dns.contains(&"NN-L-CHAIN-005_CrossPidTmpC2".to_string()));
        // A lookup at a configured one is the carve-out.
        let store = Arc::new(Mutex::new(CorrelationStore::new()));
        let r = NnLChain005CrossPidTmpC2::new(Arc::clone(&store)).with_resolvers(
            HostResolvers::fixed([IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]),
        );
        let spawns = NnLChain002TmpExecThenEgress::new(Arc::clone(&store));
        spawns.evaluate(&proc_spawn(100, 1, "dropper", "/tmp/dropper", 10 * SEC));
        spawns.evaluate(&proc_spawn(200, 100, "bash", "/usr/bin/bash", 11 * SEC));
        assert!(r.evaluate(&flow(200, 53, 13 * SEC)).is_none());
        assert!(r.evaluate(&flow(200, 4444, 13 * SEC)).is_some());
    }

    /// A spawn carrying the process's own start (POS-003).
    fn spawn_at(pid: u32, ppid: u32, filename: &str, start: u64) -> Event {
        let mut e = proc_spawn(pid, ppid, "p", filename, start);
        if let Event::ProcessSpawn { start_ns, .. } = &mut e {
            *start_ns = start;
        }
        e
    }

    /// External audit NETR-009: with starts on the wire, a cross-PID chain
    /// still completes through the real parent.
    #[test]
    fn chain005_fires_with_incarnations() {
        let rules = chain_rules();
        fire_ids(&rules, &spawn_at(100, 1, "/tmp/dropper", 10 * SEC));
        fire_ids(&rules, &spawn_at(200, 100, "/usr/bin/bash", 11 * SEC));
        let fired = fire_ids(&rules, &flow(200, 4444, 12 * SEC));
        assert!(
            fired.contains(&"NN-L-CHAIN-005_CrossPidTmpC2".to_string()),
            "{fired:?}"
        );
    }

    /// External audit NETR-009: a harmless process takes the PID of an
    /// exited process that ran from /tmp; its child's flow is no chain.
    #[test]
    fn a_recycled_tmp_pid_gives_its_new_holder_no_chain() {
        let rules = chain_rules();
        fire_ids(&rules, &spawn_at(100, 1, "/tmp/dropper", 10 * SEC));
        // 100 exits; the PID goes to a harmless process, which forks 200.
        fire_ids(&rules, &spawn_at(100, 1, "/usr/bin/make", 20 * SEC));
        fire_ids(&rules, &spawn_at(200, 100, "/usr/bin/cc", 21 * SEC));
        let fired = fire_ids(&rules, &flow(200, 4444, 22 * SEC));
        assert!(fired.is_empty(), "{fired:?}");
        let fired = fire_ids(&rules, &flow(100, 4444, 22 * SEC));
        assert!(fired.is_empty(), "{fired:?}");
    }

    #[test]
    fn chain004_multi_level_ancestry() {
        let rules = chain_rules();
        // 100 → 200 → 300; cred read by the grandparent reaches the
        // grandchild's egress.
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        fire_ids(
            &rules,
            &proc_spawn(300, 200, "curl", "/usr/bin/curl", 11 * SEC),
        );
        fire_ids(&rules, &cred_fim(100, 12 * SEC));
        let fired = fire_ids(&rules, &flow(300, 443, 13 * SEC));
        assert!(
            fired.contains(&"NN-L-CHAIN-004_CrossPidCredExfil".to_string()),
            "{fired:?}"
        );
    }

    /// External audit NETR-014: the cross-PID chains grade by age too — an
    /// ancestor's read 10 minutes old is one High record for a descendant's
    /// egress; a fresh read in any ancestor is the kill, before an aged one
    /// in a nearer ancestor. The staging chains keep 300 s.
    #[test]
    fn cross_pid_chains_grade_by_age() {
        let c004 = "NN-L-CHAIN-004_CrossPidCredExfil";
        let verdict_of = |rules: &[Box<dyn Rule>], e: &Event, id: &str| {
            rules
                .iter()
                .filter_map(|r| r.evaluate(e))
                .find(|v| v.rule_id == id)
        };
        let rules = chain_rules();
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        fire_ids(
            &rules,
            &proc_spawn(300, 200, "curl", "/usr/bin/curl", 11 * SEC),
        );
        fire_ids(&rules, &cred_fim(100, 12 * SEC));
        let v = verdict_of(&rules, &flow(300, 443, 12 * SEC + 600 * SEC), c004)
            .expect("an aged ancestor read is recorded");
        assert_eq!(
            (v.severity, v.action),
            (Severity::High, ResponseAction::Log)
        );
        assert!(verdict_of(&rules, &flow(300, 443, 12 * SEC + 601 * SEC), c004).is_none());
        // aged in the parent (200), fresh in the grandparent (100)
        let rules = chain_rules();
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        fire_ids(
            &rules,
            &proc_spawn(300, 200, "curl", "/usr/bin/curl", 11 * SEC),
        );
        fire_ids(&rules, &cred_fim(200, 12 * SEC));
        fire_ids(&rules, &cred_fim(100, 700 * SEC));
        let v = verdict_of(&rules, &flow(300, 443, 710 * SEC), c004).expect("CHAIN-004");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // CHAIN-006: an ancestor's canary trip
        let rules = chain_rules();
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        fire_ids(&rules, &canary_trip(100, 12 * SEC));
        let v = verdict_of(
            &rules,
            &flow(200, 443, 12 * SEC + 900 * SEC),
            "NN-L-CHAIN-006_CrossPidCanaryExfil",
        )
        .expect("CHAIN-006 record");
        assert_eq!(v.severity, Severity::High);
        // CHAIN-005 (staging exec) still ends at 300 s
        let rules = chain_rules();
        fire_ids(
            &rules,
            &proc_spawn(100, 1, "dropper", "/tmp/dropper", 10 * SEC),
        );
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 11 * SEC),
        );
        let fired = fire_ids(&rules, &flow(200, 4444, 10 * SEC + 360 * SEC));
        assert!(fired.is_empty(), "{fired:?}");
    }

    /// External audit NETR-014: the three-step chain's first step is the
    /// staging exec, kept 300 s — CHAIN-007 does not stretch; the read alone
    /// still gives CHAIN-001's record.
    #[test]
    fn chain007_keeps_the_five_minute_window() {
        let rules = chain_rules();
        fire_ids(&rules, &tmp_spawn(42, 10 * SEC));
        fire_ids(&rules, &cred_fim(42, 11 * SEC));
        let v = first_verdict(&rules, &flow(42, 443, 10 * SEC + 400 * SEC)).expect("a verdict");
        assert_eq!(v.rule_id, C001, "not CHAIN-007");
        assert_eq!(v.action, ResponseAction::Log);
    }

    #[test]
    fn chain004_does_not_fire_for_unrelated_process() {
        let rules = chain_rules();
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        fire_ids(&rules, &cred_fim(100, 11 * SEC));
        // 999 is not a descendant of 100.
        let fired = fire_ids(&rules, &flow(999, 443, 12 * SEC));
        assert!(!fired.contains(&"NN-L-CHAIN-004_CrossPidCredExfil".to_string()));
    }

    #[test]
    fn chain007_three_step_sequence_fires() {
        let rules = chain_rules();
        // Same PID: /tmp exec → cred read → egress.
        fire_ids(&rules, &tmp_spawn(42, 10 * SEC));
        fire_ids(&rules, &cred_fim(42, 11 * SEC));
        let fired = fire_ids(&rules, &flow(42, 443, 12 * SEC));
        assert!(
            fired.contains(&"NN-L-CHAIN-007_TmpCredExfilSequence".to_string()),
            "{fired:?}"
        );
        // CHAIN-007 is registered first, so it wins first-match in the
        // engine (it heads the fired list here).
        assert_eq!(
            fired.first().map(String::as_str),
            Some("NN-L-CHAIN-007_TmpCredExfilSequence")
        );
    }

    #[test]
    fn chain007_does_not_fire_without_full_sequence() {
        let rules = chain_rules();
        // Only the cred read (no prior /tmp exec) → 007 misses, 001 fires.
        fire_ids(&rules, &cred_fim(42, 10 * SEC));
        let fired = fire_ids(&rules, &flow(42, 443, 11 * SEC));
        assert!(!fired.contains(&"NN-L-CHAIN-007_TmpCredExfilSequence".to_string()));
        assert!(fired.contains(&"NN-L-CHAIN-001_CredReadThenEgress".to_string()));
    }

    const C007: &str = "NN-L-CHAIN-007_TmpCredExfilSequence";
    const C001: &str = "NN-L-CHAIN-001_CredReadThenEgress";
    const C002: &str = "NN-L-CHAIN-002_TmpExecThenEgress";

    /// The verdict the engine keeps for `event`: the first rule that fires.
    fn first_verdict(rules: &[Box<dyn Rule>], event: &Event) -> Option<Verdict> {
        rules.iter().find_map(|r| r.evaluate(event))
    }

    /// Review 70: the credential read went through the open sensor's ring
    /// and was processed after the egress it preceded (lab, Ubuntu 22.04:
    /// CHAIN-002 fired and CHAIN-007 never did). The read now completes
    /// CHAIN-007, naming the egress, and only once.
    #[test]
    fn chain007_completes_when_the_read_is_processed_after_the_egress() {
        let rules = chain_rules();
        fire_ids(&rules, &tmp_spawn(42, 10 * SEC));
        let on_flow = first_verdict(&rules, &flow(42, 443, 12 * SEC)).expect("CHAIN-002");
        assert_eq!(on_flow.rule_id, C002);
        let on_read = first_verdict(&rules, &cred_fim(42, 11 * SEC)).expect("late CHAIN-007");
        assert_eq!(on_read.rule_id, C007);
        assert_eq!(
            (on_read.event_pid, on_read.timestamp_ns),
            (42, 12 * SEC),
            "the verdict names the egress"
        );
        assert_eq!(on_read.action, ResponseAction::KillProcessTree);
        let again = fire_ids(&rules, &cred_fim(42, 11 * SEC + 5));
        assert!(
            !again.iter().any(|id| id == C007 || id == C001),
            "{again:?}"
        );
    }

    /// Review 70 without the `/tmp` exec: the late read completes CHAIN-001.
    #[test]
    fn chain001_completes_when_the_read_is_processed_after_the_egress() {
        let rules = chain_rules();
        assert!(first_verdict(&rules, &flow(42, 443, 12 * SEC)).is_none());
        let on_read = first_verdict(&rules, &cred_fim(42, 11 * SEC)).expect("late CHAIN-001");
        assert_eq!(on_read.rule_id, C001);
        assert_eq!(on_read.timestamp_ns, 12 * SEC);
    }

    /// An egress a chain completed in order is claimed: a read that also
    /// preceded it but is processed later completes nothing more.
    #[test]
    fn an_egress_completed_in_order_is_not_completed_again() {
        let rules = chain_rules();
        fire_ids(&rules, &cred_fim(42, 10 * SEC));
        assert_eq!(
            first_verdict(&rules, &flow(42, 443, 12 * SEC)).map(|v| v.rule_id),
            Some(C001.to_string())
        );
        let late = fire_ids(&rules, &cred_fim(42, 11 * SEC));
        assert!(!late.iter().any(|id| id == C007 || id == C001), "{late:?}");
    }

    /// A read that happened after the egress (kernel time) completes no
    /// chain with it; nor does another process's read.
    #[test]
    fn a_read_after_the_egress_or_by_another_process_completes_nothing() {
        let rules = chain_rules();
        fire_ids(&rules, &flow(42, 443, 12 * SEC));
        let after = fire_ids(&rules, &cred_fim(42, 13 * SEC));
        assert!(
            !after.iter().any(|id| id == C007 || id == C001),
            "{after:?}"
        );
        let other = fire_ids(&rules, &cred_fim(43, 11 * SEC));
        assert!(
            !other.iter().any(|id| id == C007 || id == C001),
            "{other:?}"
        );
    }

    /// A `/tmp` exec of the process started at `start_ns`, as the exec
    /// sensor reports it (the start known).
    fn tmp_exec_started(pid: u32, start_ns: u64, ts_ns: u64) -> Event {
        let mut e = tmp_spawn(pid, ts_ns);
        if let Event::ProcessSpawn { start_ns: s, .. } = &mut e {
            *s = start_ns;
        }
        e
    }

    /// Lab PR 235: the `/tmp` exec of the chain was processed after the
    /// credential read and the egress (CI, Ubuntu 22.04, 22/10/2026:
    /// CHAIN-001 fired on the egress, CHAIN-007 never did). The exec now
    /// completes CHAIN-007 on the kernel timestamps, naming the egress,
    /// once; the exec is observed and its `TmpExec` kept.
    #[test]
    fn chain007_completes_when_the_exec_is_processed_after_the_read_and_the_egress() {
        let rules = chain_rules();
        assert!(first_verdict(&rules, &cred_fim(42, 11 * SEC)).is_none());
        let on_flow = first_verdict(&rules, &flow(42, 443, 12 * SEC)).expect("CHAIN-001");
        assert_eq!(on_flow.rule_id, C001);
        let on_exec = first_verdict(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC))
            .expect("late CHAIN-007");
        assert_eq!(on_exec.rule_id, C007);
        assert_eq!(
            (on_exec.event_pid, on_exec.timestamp_ns),
            (42, 12 * SEC),
            "the verdict names the egress"
        );
        assert_eq!(on_exec.action, ResponseAction::KillProcessTree);
        assert_eq!(on_exec.severity, Severity::Critical);
        // The egress is spent; a re-exec of the same process completes
        // nothing more, and the exec was recorded for the flows to come.
        let again = first_verdict(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC + 5));
        assert!(again.is_none(), "{again:?}");
        assert_eq!(
            first_verdict(&rules, &flow(42, 443, 13 * SEC)).map(|v| v.rule_id),
            Some(C007.to_string()),
            "in order now: exec, read, egress"
        );
    }

    /// Lab PR 235 with the read processed last as well: egress, read
    /// (CHAIN-001 late), then the exec (CHAIN-007).
    #[test]
    fn chain007_completes_when_the_egress_comes_first_and_the_exec_last() {
        let rules = chain_rules();
        assert!(first_verdict(&rules, &flow(42, 443, 12 * SEC)).is_none());
        assert_eq!(
            first_verdict(&rules, &cred_fim(42, 11 * SEC)).map(|v| v.rule_id),
            Some(C001.to_string())
        );
        // the read's late CHAIN-001 claimed the egress: no second one
        assert!(first_verdict(&rules, &cred_fim(42, 11 * SEC + 5)).is_none());
        let on_exec = first_verdict(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC))
            .expect("late CHAIN-007");
        assert_eq!(on_exec.rule_id, C007);
        assert_eq!(on_exec.timestamp_ns, 12 * SEC);
    }

    /// Lab PR 235: a late exec completes nothing out of kernel order — a
    /// read before the exec, an egress before the read, a read of another
    /// process, an exec outside the staging directories, an exec whose
    /// start is unknown.
    #[test]
    fn a_late_exec_completes_only_the_ordered_sequence() {
        let late_exec = |cred_ts: u64, cred_pid: u32, flow_ts: u64, exec: Event| {
            let rules = chain_rules();
            fire_ids(&rules, &cred_fim(cred_pid, cred_ts));
            fire_ids(&rules, &flow(42, 443, flow_ts));
            fire_ids(&rules, &exec)
        };
        let staged = tmp_exec_started(42, 9 * SEC, 10 * SEC);
        for (what, fired) in [
            (
                "read before the exec",
                late_exec(9 * SEC + 5, 42, 12 * SEC, staged.clone()),
            ),
            (
                "egress before the read",
                late_exec(11 * SEC, 42, 10 * SEC + 5, staged.clone()),
            ),
            (
                "another process read",
                late_exec(11 * SEC, 43, 12 * SEC, staged.clone()),
            ),
            (
                "egress past the window",
                late_exec(
                    11 * SEC,
                    42,
                    10 * SEC + CORRELATION_WINDOW_NS + 1,
                    staged.clone(),
                ),
            ),
            ("start unknown", {
                late_exec(11 * SEC, 42, 12 * SEC, tmp_exec_started(42, 0, 10 * SEC))
            }),
        ] {
            assert!(!fired.iter().any(|id| id == C007), "{what}: {fired:?}");
        }
        let mut not_staged = tmp_exec_started(42, 9 * SEC, 10 * SEC);
        if let Event::ProcessSpawn { filename, .. } = &mut not_staged {
            *filename = "/usr/bin/dropper".to_string();
        }
        let fired = late_exec(11 * SEC, 42, 12 * SEC, not_staged);
        assert!(!fired.iter().any(|id| id == C007), "not staged: {fired:?}");
    }

    // ── Lab PR 244: NN-L-CHAIN-002 completed by a late exec ─────────

    /// Every chain verdict on `event` (no first-match short-circuit).
    fn verdicts(rules: &[Box<dyn Rule>], event: &Event) -> Vec<Verdict> {
        rules.iter().filter_map(|r| r.evaluate(event)).collect()
    }

    /// The CI ordering of the e2e, deterministically: the `/tmp` exec
    /// record (its own ring and pump) is processed after the egress it
    /// preceded, which was judged without it. CHAIN-002 completes on the
    /// kernel timestamps, naming the egress, once; the exec is recorded for
    /// the flows that follow.
    #[test]
    fn chain002_completes_when_the_exec_is_processed_after_the_egress() {
        let rules = chain_rules();
        assert!(fire_ids(&rules, &flow(42, 443, 12 * SEC)).is_empty());
        let on_exec = verdicts(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC));
        assert_eq!(on_exec.len(), 1, "{on_exec:?}");
        let v = &on_exec[0];
        assert_eq!(v.rule_id, C002);
        assert_eq!(
            (v.event_pid, v.timestamp_ns),
            (42, 12 * SEC),
            "the verdict names the egress"
        );
        assert_eq!(
            (v.severity, v.action.clone()),
            (Severity::Critical, ResponseAction::KillProcessTree)
        );
        assert!(
            v.reasoning
                .contains("the exec was processed after the flow"),
            "{}",
            v.reasoning
        );
        // Once: a re-exec of the process completes nothing more.
        let again = fire_ids(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC + 5));
        assert!(again.is_empty(), "{again:?}");
        // The exec was recorded: the next egress is CHAIN-002's in order.
        assert_eq!(fire_ids(&rules, &flow(42, 443, 13 * SEC)), [C002]);
    }

    /// The CI ordering of lab PR 235 — the exec processed after the read
    /// and the egress: CHAIN-001 on the egress, CHAIN-007 on the late exec,
    /// never CHAIN-002 as well — and the egress first, the exec, then the
    /// read: CHAIN-002 on the late exec, CHAIN-007 on the late read. Either
    /// way the flow gets the two-step chain first, then the longer one, and
    /// nothing completes it a third time.
    #[test]
    fn a_flow_gets_at_most_the_two_step_chain_then_chain007() {
        let rules = chain_rules();
        assert!(fire_ids(&rules, &cred_fim(42, 11 * SEC)).is_empty());
        assert_eq!(fire_ids(&rules, &flow(42, 443, 12 * SEC)), [C001]);
        assert_eq!(
            fire_ids(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC)),
            [C007]
        );
        assert!(fire_ids(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC + 5)).is_empty());
        assert!(fire_ids(&rules, &cred_fim(42, 11 * SEC + 5)).is_empty());

        let rules = chain_rules();
        assert!(fire_ids(&rules, &flow(43, 443, 12 * SEC)).is_empty());
        assert_eq!(
            fire_ids(&rules, &tmp_exec_started(43, 9 * SEC, 10 * SEC)),
            [C002]
        );
        let on_read = verdicts(&rules, &cred_fim(43, 11 * SEC));
        assert_eq!(
            on_read
                .iter()
                .map(|v| (v.rule_id.as_str(), v.timestamp_ns))
                .collect::<Vec<_>>(),
            [(C007, 12 * SEC)],
            "the read is the step CHAIN-002 lacked"
        );
        assert!(fire_ids(&rules, &cred_fim(43, 11 * SEC + 5)).is_empty());
        assert!(fire_ids(&rules, &tmp_exec_started(43, 9 * SEC, 10 * SEC + 5)).is_empty());
    }

    /// An egress CHAIN-002 answered in order is claimed: a second staging
    /// exec of the process (execve keeps its start) stamped before the
    /// egress but processed after it completes no second CHAIN-002.
    #[test]
    fn an_egress_chain002_answered_in_order_is_not_completed_again() {
        let rules = chain_rules();
        assert!(fire_ids(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC)).is_empty());
        assert_eq!(fire_ids(&rules, &flow(42, 443, 12 * SEC)), [C002]);
        let again = fire_ids(&rules, &tmp_exec_started(42, 9 * SEC, 11 * SEC));
        assert!(again.is_empty(), "{again:?}");
    }

    /// CHAIN-002 over a store CHAIN-007 notes the flows in, with `resolvers`
    /// configured.
    fn chain002_with_resolvers(resolvers: &[IpAddr]) -> Vec<Box<dyn Rule>> {
        let store = Arc::new(Mutex::new(CorrelationStore::new()));
        vec![
            Box::new(NnLChain007TmpCredExfilSequence::new(Arc::clone(&store))),
            Box::new(
                NnLChain002TmpExecThenEgress::new(store)
                    .with_resolvers(HostResolvers::fixed(resolvers.iter().copied())),
            ),
        ]
    }

    /// The resolver exemption holds for a late exec: a lookup at a
    /// configured resolver is no egress (the exec then names the C2 flow
    /// after it); port 53 of another server is, its kill held as in order.
    #[test]
    fn a_late_exec_keeps_the_resolver_exemption_and_the_port_53_hold() {
        let resolver = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));
        let rules = chain002_with_resolvers(&[resolver]);
        fire_ids(&rules, &flow_to(42, resolver, 53, 11 * SEC));
        let fired = fire_ids(&rules, &tmp_exec_started(42, 9 * SEC, 10 * SEC));
        assert!(fired.is_empty(), "a lookup at the resolver: {fired:?}");

        let rules = chain002_with_resolvers(&[resolver]);
        fire_ids(&rules, &flow_to(43, resolver, 53, 11 * SEC));
        fire_ids(&rules, &flow(43, 4444, 12 * SEC));
        let v = verdicts(&rules, &tmp_exec_started(43, 9 * SEC, 10 * SEC));
        assert_eq!(
            v.iter()
                .map(|v| (v.rule_id.as_str(), v.timestamp_ns, v.action.clone()))
                .collect::<Vec<_>>(),
            [(C002, 12 * SEC, ResponseAction::KillProcessTree)],
            "the C2 flow after the lookup"
        );

        // 203.0.113.9 is no configured resolver: its port 53 is an egress.
        let rules = chain002_with_resolvers(&[resolver]);
        fire_ids(&rules, &flow(44, 53, 11 * SEC));
        let v = verdicts(&rules, &tmp_exec_started(44, 9 * SEC, 10 * SEC));
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(
            (v[0].rule_id.as_str(), v[0].severity, v[0].action.clone()),
            (C002, Severity::Critical, ResponseAction::Log)
        );
        assert!(
            v[0].reasoning.contains("[held back: "),
            "{}",
            v[0].reasoning
        );
    }

    /// The window is the exec's, as in order: an egress at its end
    /// completes the chain, one past it does not — whichever is processed
    /// first.
    #[test]
    fn a_late_exec_keeps_the_five_minute_window() {
        for (delta, fires) in [
            (CORRELATION_WINDOW_NS, true),
            (CORRELATION_WINDOW_NS + 1, false),
        ] {
            let at = 10 * SEC + delta;
            let in_order = chain_rules();
            fire_ids(&in_order, &tmp_exec_started(42, 9 * SEC, 10 * SEC));
            let late = chain_rules();
            fire_ids(&late, &flow(42, 443, at));
            for fired in [
                fire_ids(&in_order, &flow(42, 443, at)),
                fire_ids(&late, &tmp_exec_started(42, 9 * SEC, 10 * SEC)),
            ] {
                assert_eq!(
                    fired.iter().any(|id| id == C002),
                    fires,
                    "{delta}: {fired:?}"
                );
            }
        }
    }

    /// A late exec completes CHAIN-002 only with an egress of its process
    /// after it: not one before the exec (kernel time), not another
    /// process's, not for an exec outside the staging directories or whose
    /// start is unknown.
    #[test]
    fn a_late_exec_completes_chain002_only_after_it() {
        let late = |flow_pid: u32, flow_ts: u64, exec: Event| {
            let rules = chain_rules();
            fire_ids(&rules, &flow(flow_pid, 443, flow_ts));
            fire_ids(&rules, &exec)
        };
        let staged = tmp_exec_started(42, 9 * SEC, 10 * SEC);
        let mut not_staged = staged.clone();
        if let Event::ProcessSpawn { filename, .. } = &mut not_staged {
            *filename = "/usr/bin/dropper".to_string();
        }
        for (what, fired) in [
            (
                "egress before the exec",
                late(42, 10 * SEC - 1, staged.clone()),
            ),
            (
                "another process's egress",
                late(43, 12 * SEC, staged.clone()),
            ),
            ("not staged", late(42, 12 * SEC, not_staged)),
            (
                "start unknown",
                late(42, 12 * SEC, tmp_exec_started(42, 0, 10 * SEC)),
            ),
        ] {
            assert!(!fired.iter().any(|id| id == C002), "{what}: {fired:?}");
        }
        assert_eq!(late(42, 12 * SEC, staged), [C002]);
    }

    /// A package transaction's staged scriptlet is spared on a late exec
    /// too (its flow falls to NN-L-NET-008); another staged program is not.
    #[test]
    fn a_late_exec_spares_a_package_transaction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // root's rpm (720, running) → its scriptlet (721)
        lineage.ingest_exec(720, 1, "/usr/bin/rpm", &[], SEC, SEC, 0);
        lineage.ingest_exec(721, 720, "/var/tmp/rpm-tmp.x", &[], 10 * SEC, 10 * SEC, 0);
        lineage.ingest_exec(702, 1, "/var/tmp/stage2", &[], 10 * SEC, 10 * SEC, 1000);
        std::fs::create_dir_all(tmp.path().join("720")).unwrap();
        let store = Arc::new(Mutex::new(CorrelationStore::new()));
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(
                NnLChain007TmpCredExfilSequence::new(Arc::clone(&store))
                    .with_lineage(Some(lineage.clone())),
            ),
            Box::new(NnLChain002TmpExecThenEgress::new(store).with_lineage(Some(lineage))),
        ];
        fire_ids(&rules, &flow(721, 443, 11 * SEC));
        fire_ids(&rules, &flow(702, 443, 11 * SEC));
        let scriptlet = fire_ids(&rules, &spawn_at(721, 720, "/var/tmp/rpm-tmp.x", 10 * SEC));
        assert!(scriptlet.is_empty(), "{scriptlet:?}");
        assert_eq!(
            fire_ids(&rules, &spawn_at(702, 1, "/var/tmp/stage2", 10 * SEC)),
            [C002]
        );
    }

    #[test]
    fn chain008_cross_pid_privesc_exfil_fires() {
        let rules = chain_rules();
        // sudo (pid 100) escalates and spawns a shell (200); the shell egresses.
        fire_ids(
            &rules,
            &proc_spawn(100, 1, "sudo", "/usr/bin/sudo", 10 * SEC),
        );
        fire_ids(&rules, &proc_spawn(200, 100, "bash", "/bin/bash", 11 * SEC));
        let fired = fire_ids(&rules, &flow(200, 443, 12 * SEC));
        assert!(
            fired.contains(&"NN-L-CHAIN-008_CrossPidPrivEscExfil".to_string()),
            "{fired:?}"
        );
    }

    /// Flow helper with an explicit destination address.
    fn flow_to(pid: u32, dst: IpAddr, dst_port: u16, ts_ns: u64) -> Event {
        let Event::NetFlow(mut nf) = flow(pid, dst_port, ts_ns) else {
            unreachable!()
        };
        nf.family = if dst.is_ipv4() { 2 } else { 10 };
        nf.dst_addr = dst;
        Event::NetFlow(nf)
    }

    /// sudo (100) → apt (200) → apt's `http` method (300), the shape the
    /// lab saw on `sudo apt-get update`.
    fn sudo_tree(rules: &[Box<dyn Rule>]) {
        fire_ids(
            rules,
            &proc_spawn(100, 1, "sudo", "/usr/bin/sudo", 10 * SEC),
        );
        fire_ids(
            rules,
            &proc_spawn(200, 100, "apt-get", "/usr/bin/apt-get", 11 * SEC),
        );
        fire_ids(
            rules,
            &proc_spawn(300, 200, "http", "/usr/lib/apt/methods/http", 12 * SEC),
        );
    }

    /// Lab finding 2026-10-11: CHAIN-008 killed `sudo apt-get update`.
    /// It is now informational — Medium + Log, never a kill.
    #[test]
    fn chain008_is_informational_log_not_kill() {
        let rules = chain_rules();
        sudo_tree(&rules);
        let v = rules
            .iter()
            .filter_map(|r| r.evaluate(&flow(300, 80, 13 * SEC)))
            .find(|v| v.rule_id == "NN-L-CHAIN-008_CrossPidPrivEscExfil")
            .expect("off-host flow under sudo still correlates");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.event_pid, 300);
    }

    /// Lab finding 2026-10-11: a loopback benchmark under sudo drew 499
    /// CHAIN-008 kills. A flow that never leaves the host is not egress.
    #[test]
    fn chain008_ignores_on_host_destinations() {
        use std::net::Ipv6Addr;
        let rules = chain_rules();
        sudo_tree(&rules);
        for dst in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped()),
        ] {
            let fired = fire_ids(&rules, &flow_to(300, dst, 5432, 13 * SEC));
            assert!(
                !fired.contains(&"NN-L-CHAIN-008_CrossPidPrivEscExfil".to_string()),
                "{dst} is on-host: {fired:?}"
            );
        }
        // Off-host neighbours of those addresses still correlate.
        for dst in [
            IpAddr::V4(Ipv4Addr::new(128, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ] {
            let fired = fire_ids(&rules, &flow_to(300, dst, 443, 13 * SEC));
            assert!(
                fired.contains(&"NN-L-CHAIN-008_CrossPidPrivEscExfil".to_string()),
                "{dst} is off-host: {fired:?}"
            );
        }
    }

    /// The other chains keep loopback triggers (rare, high-confidence
    /// precursors; local-proxy exfiltration is a real path).
    #[test]
    fn critical_chains_still_fire_on_loopback() {
        let rules = chain_rules();
        fire_ids(&rules, &cred_fim(42, 10 * SEC));
        let fired = fire_ids(
            &rules,
            &flow_to(42, IpAddr::V4(Ipv4Addr::LOCALHOST), 9050, 11 * SEC),
        );
        assert!(
            fired.contains(&"NN-L-CHAIN-001_CredReadThenEgress".to_string()),
            "{fired:?}"
        );
    }

    #[test]
    fn chain_rule_set_puts_only_chain008_in_the_tail() {
        let set = chain_rule_set();
        assert_eq!(set.head.len(), 7);
        assert!(set
            .head
            .iter()
            .all(|r| r.id() != "NN-L-CHAIN-008_CrossPidPrivEscExfil"));
        let tail: Vec<&str> = set.tail.iter().map(|r| r.id()).collect();
        assert_eq!(tail, vec!["NN-L-CHAIN-008_CrossPidPrivEscExfil"]);
    }

    /// Engine-level: CHAIN-008 is the LAST rule, so a sudo'd process that
    /// calls a high-risk C2 port still gets NN-L-NET-010's kill instead of
    /// CHAIN-008's Log; an ordinary off-host flow falls through to the
    /// informational verdict.
    #[test]
    fn engine_evaluates_chain008_after_every_blocking_rule() {
        use crate::decision::RuleEngine;
        let engine = RuleEngine::with_default_rules();
        engine.evaluate(&proc_spawn(100, 1, "sudo", "/usr/bin/sudo", 10 * SEC));
        engine.evaluate(&proc_spawn(200, 100, "bash", "/bin/bash", 11 * SEC));

        let c2 = engine
            .evaluate(&flow(200, 4444, 12 * SEC))
            .expect("port 4444 fires a net rule");
        assert_eq!(c2.rule_id, "NN-L-NET-010_OutboundToHighRiskC2Port");
        assert_eq!(c2.action, ResponseAction::KillProcess);

        let https = engine
            .evaluate(&flow(200, 443, 13 * SEC))
            .expect("off-host flow under sudo correlates");
        assert_eq!(https.rule_id, "NN-L-CHAIN-008_CrossPidPrivEscExfil");
        assert_eq!(https.action, ResponseAction::Log);
    }

    #[test]
    fn chain008_does_not_fire_without_privesc_ancestor() {
        let rules = chain_rules();
        // Parent is a normal shell, not sudo/su.
        fire_ids(
            &rules,
            &proc_spawn(200, 100, "bash", "/usr/bin/bash", 10 * SEC),
        );
        let fired = fire_ids(&rules, &flow(200, 443, 11 * SEC));
        assert!(!fired.contains(&"NN-L-CHAIN-008_CrossPidPrivEscExfil".to_string()));
    }
}
