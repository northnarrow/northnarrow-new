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
//! ## Rate limiting (§13 Q4)
//!
//! All chain rules are Critical and fire the deterministic
//! `KillProcessTree` unconditionally — never throttled. They carry a
//! `chain_*` category (not a `net_*` tier), so the future §6.5
//! NetFlow rate-limit bucket does not even scope them.
//!
//! The one exception is NN-L-CHAIN-008 (sudo/su then egress): it is
//! informational (`Medium` + `Log`) and is registered LAST in the
//! engine through [`ChainRuleSet::tail`], so its Log verdict never
//! shadows a blocking rule on the same flow. See its docs.

use std::net::IpAddr;
use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::decision::correlation::{
    CorrelationStore, EgressNote, PrecursorKind, ProcKey, CORRELATION_WINDOW_NS,
};
use crate::decision::Rule;
use crate::fim::rules::is_credential_store_access;

// ── verdict helper ───────────────────────────────────────────────────

/// Build a Critical chain Verdict from the triggering `NetFlowEvent`.
fn chain_verdict(rule: &dyn Rule, nf: &common::wire::NetFlowEvent, reasoning: &str) -> Verdict {
    chain_verdict_with(
        rule,
        nf,
        ResponseAction::KillProcessTree,
        Severity::Critical,
        reasoning,
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

fn egress_note(nf: &common::wire::NetFlowEvent) -> EgressNote {
    EgressNote {
        pid: nf.pid,
        comm: nf.comm.clone(),
        start_ns: nf.start_ns,
    }
}

/// Chain Verdict with an explicit action and severity (the
/// informational NN-L-CHAIN-008 uses `Log` + `Medium`).
fn chain_verdict_with(
    rule: &dyn Rule,
    nf: &common::wire::NetFlowEvent,
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
                // process that was processed first (another ring).
                let egress = store.take_egress_after(
                    ProcKey::unresolved(fe.modifier_pid),
                    fe.timestamp_ns,
                    CORRELATION_WINDOW_NS,
                )?;
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
            Event::NetFlow(nf) => {
                let mut store = self.buf.lock();
                if !store.has_recent_for_pid(
                    nf.pid,
                    PrecursorKind::CredRead,
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    return None;
                }
                // Review 70: completed in order; no late read may reuse it.
                store.claim_egress(ProcKey::unresolved(nf.pid), nf.start_ns);
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

/// A process executed from `/tmp/` (R001 shape) followed by a
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
pub struct NnLChain002TmpExecThenEgress {
    buf: Arc<Mutex<CorrelationStore>>,
}

impl NnLChain002TmpExecThenEgress {
    /// DNS port — a `/tmp` binary doing plain name resolution is not
    /// the egress that matters; any other port is.
    const DNS_PORT: u16 = 53;

    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Every spawn feeds the shared ancestry tree (D4) — this is
            // the one chain rule that sees `Event::ProcessSpawn`, so it
            // hosts lineage observation for the whole store. A `/tmp`
            // image additionally records the TmpExec precursor (R001
            // shape). Always returns None (record-only).
            Event::ProcessSpawn {
                pid,
                ppid,
                filename,
                timestamp_ns,
                parent_start_ns,
                exe,
                ..
            } => {
                let mut store = self.buf.lock();
                store.observe_spawn(
                    *pid,
                    crate::decision::correlation::ProcKey {
                        pid: *ppid,
                        start_ns: *parent_start_ns,
                    },
                );
                // Review 61: the file the kernel executed.
                if exe.path_or(filename).starts_with("/tmp/") {
                    store.record_for_pid(*pid, PrecursorKind::TmpExec, *timestamp_ns);
                }
                None
            }
            // Trigger: same-PID egress to a non-DNS port.
            Event::NetFlow(nf) if nf.dst_port != Self::DNS_PORT => {
                if !self.buf.lock().has_recent_for_pid(
                    nf.pid,
                    PrecursorKind::TmpExec,
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    return None;
                }
                Some(chain_verdict(
                    self,
                    nf,
                    "Process executed from /tmp/ then opened an outbound flow \
                     to a non-DNS port within the correlation window — \
                     dropper C2 (T1059 → T1571); kill the process tree + \
                     posture → COMBAT",
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Precursor: any canary trip, keyed on the accessor PID.
            Event::CanaryTripped {
                accessor_pid,
                timestamp_ns,
                ..
            } => {
                self.buf.lock().record_for_pid(
                    *accessor_pid,
                    PrecursorKind::CanaryTrip,
                    *timestamp_ns,
                );
                None
            }
            // Trigger: same-PID egress after the trip.
            Event::NetFlow(nf) => {
                if !self.buf.lock().has_recent_for_pid(
                    nf.pid,
                    PrecursorKind::CanaryTrip,
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    return None;
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !self.buf.lock().has_recent_in_ancestors(
            nf.pid,
            PrecursorKind::CredRead,
            nf.start_ns,
            CORRELATION_WINDOW_NS,
        ) {
            return None;
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
}

impl NnLChain005CrossPidTmpC2 {
    const DNS_PORT: u16 = 53;
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if nf.dst_port == Self::DNS_PORT {
            return None;
        }
        if !self.buf.lock().has_recent_in_ancestors(
            nf.pid,
            PrecursorKind::TmpExec,
            nf.start_ns,
            CORRELATION_WINDOW_NS,
        ) {
            return None;
        }
        Some(chain_verdict(
            self,
            nf,
            "A process ancestor executed from /tmp/ and a descendant then \
             opened an outbound flow to a non-DNS port — cross-PID \
             dropper C2 (T1059 → T1571); kill the process tree + \
             posture → COMBAT",
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !self.buf.lock().has_recent_in_ancestors(
            nf.pid,
            PrecursorKind::CanaryTrip,
            nf.start_ns,
            CORRELATION_WINDOW_NS,
        ) {
            return None;
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
}

impl NnLChain007TmpCredExfilSequence {
    pub fn new(buf: Arc<Mutex<CorrelationStore>>) -> Self {
        Self { buf }
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            Event::NetFlow(nf) => {
                let key = ProcKey::unresolved(nf.pid);
                let mut store = self.buf.lock();
                if !store.has_sequence(
                    key,
                    &[PrecursorKind::TmpExec, PrecursorKind::CredRead],
                    nf.start_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    // Review 70: this rule sees every flow first; keep it
                    // for a credential read processed after it.
                    store.note_egress(key, egress_note(nf));
                    return None;
                }
                Some(chain_verdict(
                    self,
                    nf,
                    "Process executed from /tmp/, then read a credential store, \
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
                let key = ProcKey::unresolved(fe.modifier_pid);
                let mut store = self.buf.lock();
                if !store.has_recent(
                    key,
                    PrecursorKind::TmpExec,
                    fe.timestamp_ns,
                    CORRELATION_WINDOW_NS,
                ) {
                    return None;
                }
                let egress =
                    store.take_egress_after(key, fe.timestamp_ns, CORRELATION_WINDOW_NS)?;
                store.record(key, PrecursorKind::CredRead, fe.timestamp_ns);
                Some(late_chain_verdict(
                    self,
                    &egress,
                    "Process executed from /tmp/, then read a credential store, \
                     then opened an outbound flow (the read was processed after \
                     the flow, in kernel order before it) — three-step dropper → \
                     credential-access → exfil chain (T1059 → T1555 → T1041); \
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
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            // Precursor: a sudo/su exec — record PrivEsc on its PID.
            Event::ProcessSpawn {
                pid,
                comm,
                timestamp_ns,
                ..
            } if PRIVESC_TOOLS.contains(&comm.as_str()) => {
                self.buf
                    .lock()
                    .record_for_pid(*pid, PrecursorKind::PrivEsc, *timestamp_ns);
                None
            }
            // Trigger: a descendant of the sudo/su process leaves the
            // host. Loopback is local IPC, not egress.
            Event::NetFlow(nf) if !is_on_host(&nf.dst_addr) => {
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
    let store = Arc::new(Mutex::new(CorrelationStore::new()));
    ChainRuleSet {
        head: vec![
            // CHAIN-007 (3-step same-PID) first: the richest verdict wins
            // first-match over the 2-step CHAIN-001/002 for the same flow.
            Box::new(NnLChain007TmpCredExfilSequence::new(Arc::clone(&store))),
            // Same-PID 2-step originals.
            Box::new(NnLChain001CredReadThenEgress::new(Arc::clone(&store))),
            Box::new(NnLChain002TmpExecThenEgress::new(Arc::clone(&store))),
            Box::new(NnLChain003CanaryThenEgress::new(Arc::clone(&store))),
            // Cross-PID variants (strict ancestor — never shadow the above).
            Box::new(NnLChain004CrossPidCredExfil::new(Arc::clone(&store))),
            Box::new(NnLChain005CrossPidTmpC2::new(Arc::clone(&store))),
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
    use common::wire::{FimEvent, FimOp, NetFlowEvent};
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
            parent_is_kthread: false,
            exe: Default::default(),
        }
    }

    fn canary_trip(pid: u32, ts_ns: u64) -> Event {
        Event::CanaryTripped {
            canary_id: "deadbeef".to_string(),
            canary_name: "decoy-aws".to_string(),
            canary_type: common::CanaryTypeTag::Credential,
            access_kind: common::CanaryAccessKind::FileOpen,
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
            bytes_sent: 1024,
            bytes_recv: 2048,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
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

    #[test]
    fn chain001_does_not_fire_after_ttl() {
        let r = chain001();
        r.evaluate(&cred_fim(42, 10 * SEC));
        // Egress 6 minutes later — precursor expired.
        assert!(r.evaluate(&flow(42, 443, 10 * SEC + 360 * SEC)).is_none());
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

    #[test]
    fn chain002_does_not_fire_on_dns_egress() {
        let r = chain002();
        r.evaluate(&tmp_spawn(42, 10 * SEC));
        // Port 53 is the benign-resolver carve-out.
        assert!(r.evaluate(&flow(42, 53, 10 * SEC + SEC)).is_none());
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
            parent_is_kthread: false,
            exe: Default::default(),
        };
        r.evaluate(&non_tmp);
        assert!(r.evaluate(&flow(42, 4444, 10 * SEC + SEC)).is_none());
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
            parent_is_kthread: false,
            exe: Default::default(),
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
        // DNS egress from the descendant is the carve-out.
        let dns = fire_ids(&rules, &flow(200, 53, 13 * SEC));
        assert!(!dns.contains(&"NN-L-CHAIN-005_CrossPidTmpC2".to_string()));
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
