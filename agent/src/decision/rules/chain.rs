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
//! all three rules. Each rule records a typed [`PrecursorKind`] and
//! queries it by PID within [`CORRELATION_WINDOW_NS`] — same-PID,
//! single-precursor behaviour is preserved bit-for-bit. The store keys
//! on `(pid, start_ns)`; D3 uses the bare-PID API (`start_ns = 0`),
//! and D4 wires the ancestry tree to resolve real incarnations and add
//! the cross-PID lineage variants.
//!
//! ## Rate limiting (§13 Q4)
//!
//! All three rules are Critical and fire the deterministic
//! `KillProcessTree` unconditionally — never throttled. They carry a
//! `chain_*` category (not a `net_*` tier), so the future §6.5
//! NetFlow rate-limit bucket does not even scope them.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::decision::correlation::{CorrelationStore, PrecursorKind, CORRELATION_WINDOW_NS};
use crate::decision::Rule;
use crate::fim::rules::is_credential_store_access;

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
            Event::Fim(fe) if is_credential_store_access(fe) => {
                self.buf.lock().record_for_pid(
                    fe.modifier_pid,
                    PrecursorKind::CredRead,
                    fe.timestamp_ns,
                );
                None
            }
            // Trigger: same-PID egress after a recorded cred access.
            Event::NetFlow(nf) => {
                if !self.buf.lock().has_recent_for_pid(
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
            // Precursor: a process image under /tmp/ (R001 shape).
            Event::ProcessSpawn {
                pid,
                filename,
                timestamp_ns,
                ..
            } if filename.starts_with("/tmp/") => {
                self.buf
                    .lock()
                    .record_for_pid(*pid, PrecursorKind::TmpExec, *timestamp_ns);
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

// ── Factory ──────────────────────────────────────────────────────────

/// Build the 3 NN-L-CHAIN rules over **one shared** [`CorrelationStore`]
/// (Tappa 10.6 D3). Unlike the net blocklists / comm allowlists, the
/// store is PRIVATE runtime state (not operator config), so it's
/// constructed here rather than threaded from `main.rs` — the
/// `Arc<Mutex<_>>` lives for the engine's lifetime, cloned into each
/// rule. Sharing (vs the old per-rule buffers) is what lets D6's
/// multi-precursor chains correlate across rule kinds; per-rule
/// isolation is preserved by the typed [`PrecursorKind`]. The engine
/// MUST register these FIRST (see the module docs); the `default_rules*`
/// builders prepend them.
pub fn chain_rules() -> Vec<Box<dyn Rule>> {
    let store = Arc::new(Mutex::new(CorrelationStore::new()));
    vec![
        Box::new(NnLChain001CredReadThenEgress::new(Arc::clone(&store))),
        Box::new(NnLChain002TmpExecThenEgress::new(Arc::clone(&store))),
        Box::new(NnLChain003CanaryThenEgress::new(Arc::clone(&store))),
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
}
