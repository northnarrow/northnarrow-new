//! Tappa 10.5 (D5) — chain / correlation detection rules
//! NN-L-CHAIN-001..003.
//!
//! Two-event, same-PID correlation rules in the **stateful
//! single-trigger** shape locked in by design §13 Q2 / §3.5-A: each
//! rule holds a purpose-built per-PID rolling [`ChainCorrelationBuffer`]
//! (mirroring the NN-L-NET-005 `DnsBurstWindow` + NN-L-NET-013
//! `BeaconWindow` precedent — `Arc<Mutex<_>>` interior mutability
//! behind the single-event `Rule::evaluate` trait). No two-pass
//! correlation engine is introduced; the N-event / cross-PID set is
//! deferred to T10.6 (§13 Q2).
//!
//! ## How a single-trigger chain rule works
//!
//! Each rule watches for TWO event kinds across successive
//! `evaluate` calls:
//!
//! 1. A **precursor** event (a credential-store FIM access / a `/tmp`
//!    exec / a canary trip). On a precursor the rule RECORDS
//!    `(pid, timestamp)` in its buffer and returns `None` — so the
//!    event falls through to the precursor's own rule (FIM-015..017 /
//!    R001 / NN-L-CANARY-*), which fires as usual.
//! 2. A **trigger** event — an outbound `Event::NetFlow`. On a flow
//!    the rule LOOKS UP its buffer for a same-PID precursor within
//!    the [`CHAIN_WINDOW_NS`] lookback. A hit means "this process
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
//! ## Per-PID isolation (§13 Q2 lock-in)
//!
//! Correlation is keyed strictly on a shared PID. Cross-PID chains
//! (parent→child exfil, etc.) need the resolved parent comm /
//! ancestry the current `Event` shape lacks and are deferred to
//! T10.6 alongside the two-pass engine.
//!
//! ## Rate limiting (§13 Q4)
//!
//! All three rules are Critical and fire the deterministic
//! `KillProcessTree` unconditionally — never throttled. They carry a
//! `chain_*` category (not a `net_*` tier), so the future §6.5
//! NetFlow rate-limit bucket does not even scope them.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::decision::Rule;
use crate::fim::rules::is_credential_store_access;

// ── Correlation window + buffer bounds ───────────────────────────────

/// Lookback window: a precursor older than this can't correlate with
/// a trigger flow. 5 minutes — matches the §13 Q3 DNS-cache TTL
/// precedent (long enough to span a real read→exfil gap, short
/// enough that an unrelated later flow from a reused PID doesn't
/// false-correlate).
const CHAIN_WINDOW_NS: u64 = 300 * 1_000_000_000;

/// Bound the per-PID precursor history. A process that legitimately
/// re-accesses a credential store many times still only needs the
/// most recent few timestamps to answer "any precursor in window?".
const CHAIN_MAX_SAMPLES_PER_PID: usize = 16;

/// Bound the number of distinct PIDs tracked. On overflow the buffer
/// prunes stale (out-of-window) PIDs first; the cap is generous
/// relative to realistic concurrent precursor-bearing processes.
const CHAIN_MAX_TRACKED_PIDS: usize = 4096;

/// Per-PID sliding window of precursor-event timestamps. One instance
/// per chain rule records that rule's precursor kind; the trigger
/// flow queries [`ChainCorrelationBuffer::has_recent`]. Bounded
/// memory: per-PID samples are capped + TTL-pruned on every access,
/// and the tracked-PID count is capped with stale-first eviction.
#[derive(Debug, Default)]
pub struct ChainCorrelationBuffer {
    per_pid: HashMap<u32, VecDeque<u64>>,
}

impl ChainCorrelationBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a precursor for `pid` at `ts_ns`.
    pub fn record(&mut self, pid: u32, ts_ns: u64) {
        if self.per_pid.len() >= CHAIN_MAX_TRACKED_PIDS && !self.per_pid.contains_key(&pid) {
            self.prune_stale(ts_ns);
        }
        let q = self.per_pid.entry(pid).or_default();
        let cutoff = ts_ns.saturating_sub(CHAIN_WINDOW_NS);
        while q.front().is_some_and(|&t| t < cutoff) {
            q.pop_front();
        }
        q.push_back(ts_ns);
        while q.len() > CHAIN_MAX_SAMPLES_PER_PID {
            q.pop_front();
        }
    }

    /// `true` if `pid` has a recorded precursor within
    /// [`CHAIN_WINDOW_NS`] before `ts_ns`. Prunes out-of-window
    /// entries (and drops the PID entirely once empty) so the buffer
    /// stays bounded under steady event flow.
    pub fn has_recent(&mut self, pid: u32, ts_ns: u64) -> bool {
        let cutoff = ts_ns.saturating_sub(CHAIN_WINDOW_NS);
        let hit = if let Some(q) = self.per_pid.get_mut(&pid) {
            while q.front().is_some_and(|&t| t < cutoff) {
                q.pop_front();
            }
            !q.is_empty()
        } else {
            false
        };
        if let Some(q) = self.per_pid.get(&pid) {
            if q.is_empty() {
                self.per_pid.remove(&pid);
            }
        }
        hit
    }

    /// Drop PIDs whose every sample is out of the window relative to
    /// `now_ns`. Called on tracked-PID overflow.
    fn prune_stale(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(CHAIN_WINDOW_NS);
        self.per_pid.retain(|_, q| {
            while q.front().is_some_and(|&t| t < cutoff) {
                q.pop_front();
            }
            !q.is_empty()
        });
    }

    #[cfg(test)]
    fn tracked_pids(&self) -> usize {
        self.per_pid.len()
    }
}

// ── verdict helper ───────────────────────────────────────────────────

/// Build a Critical chain Verdict from the triggering `NetFlowEvent`.
fn chain_verdict(rule: &dyn Rule, nf: &common::wire::NetFlowEvent, reasoning: &str) -> Verdict {
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action: ResponseAction::KillProcessTree,
        severity: Severity::Critical,
        reasoning: reasoning.to_string(),
        event_pid: nf.pid,
        event_filename: nf.comm.clone(),
        timestamp_ns: nf.start_ns,
    }
}

// ── NN-L-CHAIN-001 — credential read → egress ────────────────────────

/// Credential-store FIM access (NN-L-FIM-015/016/017 path hit)
/// followed by a same-PID outbound flow within the window. MITRE
/// T1555 (Credentials from Password Stores) → T1041 (Exfiltration
/// Over C2 Channel). Critical + KillProcessTree → COMBAT.
pub struct NnLChain001CredReadThenEgress {
    buf: Arc<Mutex<ChainCorrelationBuffer>>,
}

impl NnLChain001CredReadThenEgress {
    pub fn new(buf: Arc<Mutex<ChainCorrelationBuffer>>) -> Self {
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
            Event::Fim(fe) if is_credential_store_access(fe) => {
                self.buf.lock().record(fe.modifier_pid, fe.timestamp_ns);
                None
            }
            // Trigger: same-PID egress after a recorded cred access.
            Event::NetFlow(nf) => {
                if !self.buf.lock().has_recent(nf.pid, nf.start_ns) {
                    return None;
                }
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
    buf: Arc<Mutex<ChainCorrelationBuffer>>,
}

impl NnLChain002TmpExecThenEgress {
    /// DNS port — a `/tmp` binary doing plain name resolution is not
    /// the egress that matters; any other port is.
    const DNS_PORT: u16 = 53;

    pub fn new(buf: Arc<Mutex<ChainCorrelationBuffer>>) -> Self {
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
            // Precursor: a process image under /tmp/ (R001 shape).
            Event::ProcessSpawn {
                pid,
                filename,
                timestamp_ns,
                ..
            } if filename.starts_with("/tmp/") => {
                self.buf.lock().record(*pid, *timestamp_ns);
                None
            }
            // Trigger: same-PID egress to a non-DNS port.
            Event::NetFlow(nf) if nf.dst_port != Self::DNS_PORT => {
                if !self.buf.lock().has_recent(nf.pid, nf.start_ns) {
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
    buf: Arc<Mutex<ChainCorrelationBuffer>>,
}

impl NnLChain003CanaryThenEgress {
    pub fn new(buf: Arc<Mutex<ChainCorrelationBuffer>>) -> Self {
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
                self.buf.lock().record(*accessor_pid, *timestamp_ns);
                None
            }
            // Trigger: same-PID egress after the trip.
            Event::NetFlow(nf) => {
                if !self.buf.lock().has_recent(nf.pid, nf.start_ns) {
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

// ── Factory ──────────────────────────────────────────────────────────

/// Build the 3 NN-L-CHAIN rules, each with a freshly-allocated
/// per-PID correlation buffer. Unlike the net blocklists / comm
/// allowlists, the chain buffers are PRIVATE runtime state (not
/// operator config), so they're constructed here rather than threaded
/// from `main.rs` — the `Arc<Mutex<_>>` lives for the engine's
/// lifetime inside the rule structs. The engine MUST register these
/// FIRST (see the module docs); the `default_rules*` builders prepend
/// them.
pub fn chain_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLChain001CredReadThenEgress::new(Arc::new(Mutex::new(
            ChainCorrelationBuffer::new(),
        )))),
        Box::new(NnLChain002TmpExecThenEgress::new(Arc::new(Mutex::new(
            ChainCorrelationBuffer::new(),
        )))),
        Box::new(NnLChain003CanaryThenEgress::new(Arc::new(Mutex::new(
            ChainCorrelationBuffer::new(),
        )))),
    ]
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
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 1000,
            modifier_comm: "exfil".to_string(),
            dest_path: None,
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

    // ── ChainCorrelationBuffer unit tests ───────────────────────────

    #[test]
    fn buffer_records_and_finds_within_window() {
        let mut b = ChainCorrelationBuffer::new();
        b.record(42, 10 * SEC);
        assert!(
            b.has_recent(42, 10 * SEC + 30 * SEC),
            "30s gap is in window"
        );
    }

    #[test]
    fn buffer_evicts_after_ttl() {
        let mut b = ChainCorrelationBuffer::new();
        b.record(42, 10 * SEC);
        // 6 minutes later — past the 5-minute window.
        assert!(!b.has_recent(42, 10 * SEC + 360 * SEC));
    }

    #[test]
    fn buffer_is_per_pid_isolated() {
        let mut b = ChainCorrelationBuffer::new();
        b.record(42, 10 * SEC);
        assert!(!b.has_recent(99, 10 * SEC + SEC), "pid 99 has no precursor");
        assert!(b.has_recent(42, 10 * SEC + SEC));
    }

    #[test]
    fn buffer_caps_samples_per_pid() {
        let mut b = ChainCorrelationBuffer::new();
        for i in 0..(CHAIN_MAX_SAMPLES_PER_PID as u64 + 50) {
            b.record(42, 100 * SEC + i);
        }
        // Deque is capped; the pid is still tracked once.
        assert_eq!(b.tracked_pids(), 1);
    }

    #[test]
    fn buffer_drops_pid_once_window_empties() {
        let mut b = ChainCorrelationBuffer::new();
        b.record(42, 10 * SEC);
        // A has_recent past the window prunes + drops the empty pid.
        assert!(!b.has_recent(42, 10 * SEC + 360 * SEC));
        assert_eq!(b.tracked_pids(), 0);
    }

    // ── NN-L-CHAIN-001 bespoke pairs ────────────────────────────────

    fn chain001() -> NnLChain001CredReadThenEgress {
        NnLChain001CredReadThenEgress::new(Arc::new(Mutex::new(ChainCorrelationBuffer::new())))
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
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "x".to_string(),
            dest_path: None,
        });
        assert!(r.evaluate(&benign).is_none());
        assert!(
            r.evaluate(&flow(42, 443, 10 * SEC + SEC)).is_none(),
            "non-cred FIM must not seed the chain"
        );
    }

    // ── NN-L-CHAIN-002 bespoke pairs ────────────────────────────────

    fn chain002() -> NnLChain002TmpExecThenEgress {
        NnLChain002TmpExecThenEgress::new(Arc::new(Mutex::new(ChainCorrelationBuffer::new())))
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
        NnLChain003CanaryThenEgress::new(Arc::new(Mutex::new(ChainCorrelationBuffer::new())))
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
    fn chain_rules_builder_returns_three_rules() {
        let rules = chain_rules();
        assert_eq!(rules.len(), 3);
        let ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            vec![
                "NN-L-CHAIN-001_CredReadThenEgress",
                "NN-L-CHAIN-002_TmpExecThenEgress",
                "NN-L-CHAIN-003_CanaryThenEgress",
            ]
        );
    }
}
