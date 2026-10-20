//! Deterministic stage-logic tests for [`CombatLadder`].
//!
//! The actuator + evidence are mocked into a single ordered call log so a
//! test can assert both *what* happened and *in what order* (notably:
//! the evidence/dossier for a stage is emitted BEFORE that stage's
//! enforcement action — acceptance: a dossier is captured/emitted before
//! any isolation). Time is injected (`Instant`), so the deadline path is
//! exercised without sleeping.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use common::posture_types::TriggerType;
use common::Event;

use super::actuator::{CombatActuator, NeutralizeOutcome, SoftBlock};
use super::evidence::{AuditEvidence, LadderEvidence, StageTransition, Unrecorded};
use super::ProcRef;
use super::{
    CombatLadder, CombatStage, LadderConfig, NoProtectedProcs, ProtectedProcs, ProtectedReason,
};

/// Shared ordered call log for the mocks + the test.
#[derive(Clone)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Recorder {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    fn push(&self, s: impl Into<String>) {
        self.0.lock().push(s.into());
    }
    fn log(&self) -> Vec<String> {
        self.0.lock().clone()
    }
}

struct MockActuator {
    rec: Recorder,
    neutralize_outcome: NeutralizeOutcome,
    /// PIDs whose soft block does not take effect (external audit CMB-014).
    failing_blocks: Vec<u32>,
}

/// A captured process without a pidfd (nothing is signalled), with a
/// start time derived from the PID.
fn mock_ref(pid: u32) -> Arc<ProcRef> {
    Arc::new(ProcRef::for_test(pid, Some(u64::from(pid) * 10)))
}

/// PIDs from here up are offenders that have exited, for the mocks.
const EXITED_FROM: u32 = 90_000;

/// The mocks' identity check: an event start, when there is one, is the
/// captured start ticks as they are (`mock_ref`: the PID × 10); without
/// one, the process is the captured one while it runs (below
/// [`EXITED_FROM`]).
fn mock_same_process(target: &ProcRef, start_ns: u64) -> bool {
    if start_ns == 0 {
        return target.pid() < EXITED_FROM;
    }
    target.start_ticks() == Some(start_ns)
}

fn pids_of(offenders: &[Arc<ProcRef>]) -> Vec<u32> {
    offenders.iter().map(|r| r.pid()).collect()
}

impl CombatActuator for MockActuator {
    fn identify(&self, pid: u32, _start_ns: u64, _seen_ns: u64) -> Arc<ProcRef> {
        mock_ref(pid)
    }
    fn same_process(&self, target: &ProcRef, start_ns: u64) -> bool {
        mock_same_process(target, start_ns)
    }
    fn soft_egress_block(&self, target: &ProcRef) -> SoftBlock {
        let pid = target.pid();
        self.rec.push(format!("soft_block:{pid}"));
        if self.failing_blocks.contains(&pid) {
            SoftBlock::Failed("no nft".to_string())
        } else {
            SoftBlock::Blocked
        }
    }
    fn soft_egress_clear(&self, target: &ProcRef) {
        let pid = target.pid();
        assert_eq!(
            target.start_ticks(),
            Some(u64::from(pid) * 10),
            "the process captured at the attribution"
        );
        self.rec.push(format!("soft_clear:{pid}"));
    }
    fn neutralize(&self, offenders: &[Arc<ProcRef>]) -> NeutralizeOutcome {
        self.rec
            .push(format!("neutralize:{:?}", pids_of(offenders)));
        self.neutralize_outcome.clone()
    }
    fn isolate(&self) {
        self.rec.push("isolate".to_string());
    }
    fn is_dry_run(&self) -> bool {
        false
    }
}

struct MockEvidence {
    rec: Recorder,
}

impl LadderEvidence for MockEvidence {
    fn record_stage(&self, t: &StageTransition) -> Result<(), Unrecorded> {
        let from = t.from.map(|s| s.as_str()).unwrap_or("-");
        self.rec.push(format!("audit:{}->{}", from, t.to.as_str()));
        Ok(())
    }
}

fn ladder(neutralize: NeutralizeOutcome, window: Duration) -> (CombatLadder, Recorder) {
    let rec = Recorder::new();
    let actuator = Box::new(MockActuator {
        rec: rec.clone(),
        neutralize_outcome: neutralize,
        failing_blocks: Vec::new(),
    });
    let evidence = Box::new(MockEvidence { rec: rec.clone() });
    let l = CombatLadder::new(
        actuator,
        evidence,
        Box::new(NoProtectedProcs),
        LadderConfig {
            investigate_window: window,
            ..LadderConfig::default()
        },
    );
    (l, rec)
}

/// Stub guard: the given PIDs are host-critical (with the mapped reason);
/// everything else is fair game. Deterministic — no `/proc`.
struct StubProtected(HashMap<u32, ProtectedReason>);

impl ProtectedProcs for StubProtected {
    fn protected_reason(&self, pid: u32) -> Option<ProtectedReason> {
        self.0.get(&pid).copied()
    }
}

/// Evidence sink that captures each transition's `(to, reason)` so a test
/// can assert the escalation reason names the spared process. Kept
/// separate from [`MockEvidence`] so the ordered `Recorder` assertions in
/// the existing tests are untouched.
#[derive(Clone)]
struct ReasonEvidence(Arc<Mutex<Vec<(String, String)>>>);

impl LadderEvidence for ReasonEvidence {
    fn record_stage(&self, t: &StageTransition) -> Result<(), Unrecorded> {
        self.0
            .lock()
            .push((t.to.as_str().to_string(), t.reason.clone()));
        Ok(())
    }
}

/// Ladder with an injected protected-PID set. The shared `Recorder` still
/// captures actuator calls (kill / soft-block / isolate); the returned
/// reasons log captures each stage transition's reason string.
#[allow(clippy::type_complexity)]
fn ladder_protected(
    neutralize: NeutralizeOutcome,
    window: Duration,
    protected: HashMap<u32, ProtectedReason>,
) -> (CombatLadder, Recorder, Arc<Mutex<Vec<(String, String)>>>) {
    let rec = Recorder::new();
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let actuator = Box::new(MockActuator {
        rec: rec.clone(),
        neutralize_outcome: neutralize,
        failing_blocks: Vec::new(),
    });
    let evidence = Box::new(ReasonEvidence(reasons.clone()));
    let l = CombatLadder::new(
        actuator,
        evidence,
        Box::new(StubProtected(protected)),
        LadderConfig {
            investigate_window: window,
            ..LadderConfig::default()
        },
    );
    (l, rec, reasons)
}

fn tcp_connect(pid: u32, dst: [u8; 4]) -> Event {
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&dst);
    Event::TcpConnect {
        pid,
        uid: 1000,
        comm: "x".to_string(),
        family: 2, // AF_INET
        src_addr: [0u8; 16],
        src_port: 1234,
        dst_addr,
        dst_port: 443,
        timestamp_ns: 1,
    }
}

fn spawn(pid: u32, ppid: u32) -> Event {
    spawn_started(pid, 0, ppid, 0)
}

/// A spawn whose event carries the starts of the child and its parent.
fn spawn_started(pid: u32, start_ns: u64, ppid: u32, parent_start_ns: u64) -> Event {
    Event::ProcessSpawn {
        pid,
        ppid,
        uid: 1000,
        gid: 1000,
        comm: "x".to_string(),
        filename: "/tmp/x".to_string(),
        timestamp_ns: 1,
        argv: Vec::new(),
        parent_comm: String::new(),
        parent_start_ns,
        start_ns,
        parent_is_kthread: false,
        exe: Default::default(),
        argv_truncated: false,
        filename_truncated: false,
    }
}

// ── Acceptance #2: COMBAT entry → INVESTIGATE, network NOT dropped ──
#[test]
fn engage_enters_investigate_without_isolation() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(30));
    l.engage(
        Some(4242),
        Some(TriggerType::ConfirmedIntrusion),
        Instant::now(),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
    let log = rec.log();
    assert!(
        log.contains(&"soft_block:4242".to_string()),
        "offender gets surgical soft egress, not full isolation: {log:?}"
    );
    assert!(log.iter().any(|e| e == "audit:-->INVESTIGATE"), "{log:?}");
    assert!(
        !log.iter().any(|e| e == "isolate"),
        "COMBAT entry must NOT drop the network: {log:?}"
    );
    assert!(
        !log.iter().any(|e| e.starts_with("neutralize")),
        "no neutralization at INVESTIGATE: {log:?}"
    );
}

// ── Acceptance #3: contained threat → NEUTRALIZE, no isolation ──
#[test]
fn investigate_deadline_advances_to_neutralize_contained_no_isolation() {
    let win = Duration::from_secs(30);
    let (l, rec) = ladder(NeutralizeOutcome::Contained, win);
    let t0 = Instant::now();
    l.engage(Some(900), Some(TriggerType::ExfiltrationPattern), t0);

    // Before the deadline: still investigating.
    l.tick(t0 + Duration::from_secs(5));
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));

    // After the deadline: neutralize; contained → host stays online.
    l.tick(t0 + win + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    let log = rec.log();
    assert!(log.iter().any(|e| e == "neutralize:[900]"), "{log:?}");
    assert!(
        !log.iter().any(|e| e == "isolate"),
        "a contained threat must NOT isolate: {log:?}"
    );
    assert!(
        log.iter().any(|e| e == "audit:INVESTIGATE->NEUTRALIZE"),
        "{log:?}"
    );
}

// ── Acceptance #4 + #5: uncontainable → ISOLATE, dossier emitted first ──
#[test]
fn uncontainable_threat_escalates_to_isolate_last_resort() {
    let win = Duration::from_secs(30);
    let (l, rec) = ladder(
        NeutralizeOutcome::Uncontainable {
            reason: "respawns via supervisor".to_string(),
        },
        win,
    );
    let t0 = Instant::now();
    l.engage(Some(1234), Some(TriggerType::PersistenceMechanism), t0);
    l.tick(t0 + win + Duration::from_secs(1));

    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    assert!(log.iter().any(|e| e == "isolate"), "must isolate: {log:?}");

    // Acceptance #5: the ISOLATE audit/dossier is emitted BEFORE the
    // isolation action, so the operator is never blinded.
    let audit_idx = log
        .iter()
        .position(|e| e == "audit:NEUTRALIZE->ISOLATE")
        .expect("ISOLATE stage audit must be recorded");
    let isolate_idx = log
        .iter()
        .position(|e| e == "isolate")
        .expect("isolate action must run");
    assert!(
        audit_idx < isolate_idx,
        "evidence must be emitted BEFORE isolation: {log:?}"
    );
}

// ── Jump-ahead: active exfil pre-empts the INVESTIGATE deadline ──
#[test]
fn jump_ahead_on_active_exfil_preempts_deadline() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(300));
    let t0 = Instant::now();
    l.engage(Some(555), Some(TriggerType::ConfirmedIntrusion), t0);

    // Offender opens an outbound connection to an external dst, long
    // before the 5-minute deadline → jump straight to NEUTRALIZE.
    l.observe(
        &tcp_connect(555, [203, 0, 113, 9]),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    assert!(
        rec.log().iter().any(|e| e == "neutralize:[555]"),
        "{:?}",
        rec.log()
    );
}

#[test]
fn jump_ahead_ignores_loopback_connect() {
    let (l, _rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(300));
    let t0 = Instant::now();
    l.engage(Some(555), None, t0);
    // A connect to loopback is not exfil — stay in INVESTIGATE.
    l.observe(
        &tcp_connect(555, [127, 0, 0, 1]),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
}

// ── Jump-ahead: lateral spread attributes the child + advances ──
#[test]
fn jump_ahead_on_lateral_spread_attributes_child() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(300));
    let t0 = Instant::now();
    l.engage(Some(700), None, t0);

    // Offender 700 spawns child 701 → child attributed + jump-ahead.
    l.observe(&spawn(701, 700), t0 + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    let off = l.offenders();
    assert!(
        off.contains(&700) && off.contains(&701),
        "spawned child must be attributed: {off:?}"
    );
    assert!(
        rec.log().iter().any(|e| e == "neutralize:[700, 701]"),
        "{:?}",
        rec.log()
    );
}

/// External audit CMB-004: a child of a process that took an offender's
/// PID after the offender exited is not the offender's child.
#[test]
fn a_child_of_a_reused_offender_pid_is_not_attributed() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(300));
    let t0 = Instant::now();
    l.engage(Some(700), None, t0);
    // offender 700 started at 7000 (mock_ref); this parent started at 1
    l.observe(&spawn_started(701, 0, 700, 1), t0 + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
    assert_eq!(l.offenders(), vec![700]);
    assert!(
        !rec.log().iter().any(|e| e.starts_with("neutralize")),
        "{:?}",
        rec.log()
    );
    // the offender's own child: attributed
    l.observe(
        &spawn_started(702, 0, 700, 7000),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    assert_eq!(l.offenders(), vec![700, 702]);
}

/// External audit CMB-004: an offender's PID taken by a new child of the
/// tree after the offender exited — the new process is attributed (and
/// soft-blocked) in its place, not skipped as already known.
#[test]
fn an_offender_pid_reused_inside_the_tree_is_attributed_afresh() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(300));
    let t0 = Instant::now();
    l.engage(Some(700), None, t0);
    l.observe(&spawn(701, 700), t0 + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    let blocks = |rec: &Recorder| rec.log().iter().filter(|e| *e == "soft_block:701").count();
    let before = blocks(&rec);
    // the same child again: known, nothing new
    l.observe(
        &spawn_started(701, 7010, 700, 7000),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(blocks(&rec), before);
    // 701 exited; its PID now names a new child of 700 (another start)
    l.observe(
        &spawn_started(701, 99, 700, 7000),
        t0 + Duration::from_secs(3),
    );
    assert_eq!(blocks(&rec), before + 1, "{:?}", rec.log());
    assert_eq!(l.offenders(), vec![700, 701]);
}

// ── Idempotent engage: hook + process_event both call it ──
#[test]
fn engage_is_idempotent_and_merges_offenders() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(30));
    let t0 = Instant::now();
    l.engage(Some(10), Some(TriggerType::ConfirmedIntrusion), t0);
    // Second engage (context-free hook alongside context-carrying
    // process_event) merges a new offender; does NOT reset the episode
    // or re-emit the INVESTIGATE audit.
    l.engage(Some(11), None, t0 + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
    let off = l.offenders();
    assert!(off.contains(&10) && off.contains(&11), "{off:?}");
    let audits: Vec<_> = rec
        .log()
        .into_iter()
        .filter(|e| e.starts_with("audit:"))
        .collect();
    assert_eq!(
        audits,
        vec!["audit:-->INVESTIGATE".to_string()],
        "exactly one INVESTIGATE audit across both engages: {audits:?}"
    );
}

// ── Admin stand-down clears the episode + lifts soft egress ──
#[test]
fn stand_down_clears_episode_and_lifts_soft_egress() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(30));
    let t0 = Instant::now();
    l.engage(Some(42), None, t0);
    l.stand_down(t0 + Duration::from_secs(1));
    assert_eq!(l.current_stage(), None);
    assert!(
        rec.log().iter().any(|e| e == "soft_clear:42"),
        "{:?}",
        rec.log()
    );
    // Idempotent: a second stand-down is a no-op.
    l.stand_down(t0 + Duration::from_secs(2));
}

// ── Idle ladder ignores ticks + events ──
#[test]
fn tick_and_observe_are_noops_when_not_engaged() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(1));
    let t0 = Instant::now();
    l.tick(t0 + Duration::from_secs(10));
    l.observe(&tcp_connect(1, [8, 8, 8, 8]), t0);
    assert_eq!(l.current_stage(), None);
    assert!(
        rec.log().is_empty(),
        "no actions while idle: {:?}",
        rec.log()
    );
}

// ── Two drivers (observe jump-ahead + tick) neutralize at most once ──
//
// Fix-A property: drive_to mutates the stage flags under the lock, drops
// it, then acts — so a jump-ahead (observe) and a deadline (tick) both
// targeting NEUTRALIZE converge to a SINGLE neutralization via the
// `neutralize_attempted` guard that survives the re-lock gap.
#[test]
fn jump_ahead_then_deadline_tick_neutralizes_once() {
    let win = Duration::from_secs(30);
    let (l, rec) = ladder(NeutralizeOutcome::Contained, win);
    let t0 = Instant::now();
    l.engage(Some(321), None, t0);
    // observe() jump-ahead advances to NEUTRALIZE before the deadline.
    l.observe(
        &tcp_connect(321, [198, 51, 100, 7]),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    // A later deadline tick must NOT re-neutralize (already past INVESTIGATE).
    l.tick(t0 + win + Duration::from_secs(1));
    let neutralizes = rec
        .log()
        .into_iter()
        .filter(|e| e.starts_with("neutralize"))
        .count();
    assert_eq!(
        neutralizes, 1,
        "jump-ahead + deadline must neutralize exactly once"
    );
}

// ── Neutralize runs exactly once even on repeated ticks ──
#[test]
fn neutralize_runs_once_under_repeated_ticks() {
    let win = Duration::from_secs(10);
    let (l, rec) = ladder(NeutralizeOutcome::Contained, win);
    let t0 = Instant::now();
    l.engage(Some(77), None, t0);
    l.tick(t0 + win + Duration::from_secs(1));
    l.tick(t0 + win + Duration::from_secs(2));
    l.tick(t0 + win + Duration::from_secs(3));
    let neutralizes = rec
        .log()
        .into_iter()
        .filter(|e| e.starts_with("neutralize"))
        .count();
    assert_eq!(neutralizes, 1, "neutralize must fire exactly once");
}

// ── Guard: a host-critical offender is spared the kill, the rest are
//    neutralized, and the threat is still contained via ISOLATE ──
#[test]
fn neutralize_spares_protected_offender_and_escalates_to_isolate() {
    let win = Duration::from_secs(30);
    let mut prot = HashMap::new();
    prot.insert(4242, ProtectedReason::SshService);
    let (l, rec, reasons) = ladder_protected(NeutralizeOutcome::Contained, win, prot);
    let t0 = Instant::now();
    l.engage(Some(5000), Some(TriggerType::ConfirmedIntrusion), t0);
    l.engage(Some(4242), None, t0); // merge the protected (sshd) offender

    // INVESTIGATE: the killable offender is soft-blocked; the protected
    // one is NOT (cutting sshd would risk operator lockout).
    assert!(
        rec.log().iter().any(|e| e == "soft_block:5000"),
        "{:?}",
        rec.log()
    );
    assert!(
        !rec.log().iter().any(|e| e == "soft_block:4242"),
        "protected offender must not be soft-blocked: {:?}",
        rec.log()
    );

    // Deadline → NEUTRALIZE: kill ONLY 5000, spare 4242, and escalate to
    // ISOLATE (4242 is uncontainable at the process level).
    l.tick(t0 + win + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    assert!(
        log.iter().any(|e| e == "neutralize:[5000]"),
        "kill only the killable offender: {log:?}"
    );
    assert!(
        !log.iter().any(|e| e.contains("4242")),
        "the protected offender must NEVER reach the actuator: {log:?}"
    );
    assert!(
        log.iter().any(|e| e == "isolate"),
        "must escalate to ISOLATE: {log:?}"
    );
    // The ISOLATE audit reason names the spared SSH service.
    let r = reasons.lock();
    assert!(
        r.iter()
            .any(|(to, reason)| to == "ISOLATE" && reason.contains("ssh-service")),
        "ISOLATE reason must name the spared process: {r:?}"
    );
    // The NEUTRALIZE record (emitted before the kill) also notes the spared
    // process — pins the fmt_protected note on the NEUTRALIZE transition.
    assert!(
        r.iter().any(|(to, reason)| to == "NEUTRALIZE"
            && reason.contains("spared")
            && reason.contains("ssh-service")),
        "NEUTRALIZE record must note the spared process: {r:?}"
    );
}

/// External audit CMB-004: an offender that has exited, its PID now held
/// by a protected process (an sshd child): not "spared" — the guard's
/// lookup by PID would judge the new holder — and no ISOLATE for it. The
/// kill reports it gone.
#[test]
fn an_exited_offender_on_a_protected_pid_is_not_spared() {
    let win = Duration::from_secs(30);
    let gone = EXITED_FROM + 1;
    let mut prot = HashMap::new();
    prot.insert(gone, ProtectedReason::SshService);
    let (l, rec, reasons) = ladder_protected(NeutralizeOutcome::Contained, win, prot);
    let t0 = Instant::now();
    l.engage(Some(5000), Some(TriggerType::ConfirmedIntrusion), t0);
    l.engage(Some(gone), None, t0);
    l.tick(t0 + win + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    let log = rec.log();
    assert!(
        log.iter()
            .any(|e| *e == format!("neutralize:[5000, {gone}]")),
        "{log:?}"
    );
    assert!(!log.iter().any(|e| e == "isolate"), "{log:?}");
    assert!(
        !reasons.lock().iter().any(|(_, r)| r.contains("spared")),
        "{:?}",
        reasons.lock()
    );
}

// ── Guard: when EVERY offender is host-critical there is nothing to kill
//    — go straight to ISOLATE without ever calling neutralize ──
#[test]
fn neutralize_all_offenders_protected_isolates_without_killing() {
    let win = Duration::from_secs(30);
    let mut prot = HashMap::new();
    prot.insert(4242, ProtectedReason::SshService);
    prot.insert(4300, ProtectedReason::Watchdog);
    let (l, rec, reasons) = ladder_protected(NeutralizeOutcome::Contained, win, prot);
    let t0 = Instant::now();
    l.engage(Some(4242), Some(TriggerType::PersistenceMechanism), t0);
    l.engage(Some(4300), None, t0);
    l.tick(t0 + win + Duration::from_secs(1));

    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    assert!(
        !log.iter().any(|e| e.starts_with("neutralize")),
        "no kill attempt when every offender is host-critical: {log:?}"
    );
    assert!(
        !log.iter().any(|e| e.starts_with("soft_block")),
        "protected offenders are never soft-blocked: {log:?}"
    );
    assert!(log.iter().any(|e| e == "isolate"), "must isolate: {log:?}");
    let r = reasons.lock();
    assert!(
        r.iter().any(|(to, reason)| to == "ISOLATE"
            && reason.contains("ssh-service")
            && reason.contains("northnarrow-watchdog")),
        "ISOLATE reason names all spared processes: {r:?}"
    );
    // Evidence-before-enforcement invariant on the all-spared short-circuit:
    // the NEUTRALIZE dossier is still emitted, and BEFORE the ISOLATE record
    // (even though no kill runs on this path).
    let neut_idx = r.iter().position(|(to, _)| to == "NEUTRALIZE");
    let iso_idx = r.iter().position(|(to, _)| to == "ISOLATE");
    assert!(
        neut_idx.is_some(),
        "NEUTRALIZE dossier must still be recorded: {r:?}"
    );
    assert!(
        neut_idx < iso_idx,
        "NEUTRALIZE record must precede ISOLATE on the all-spared path: {r:?}"
    );
}

// ── Guard: engage skips soft-egress on a protected offender WITHOUT a
//    spurious immediate isolation (INVESTIGATE keeps the network up) ──
#[test]
fn engage_skips_soft_egress_on_protected_offender_no_escalation() {
    let mut prot = HashMap::new();
    prot.insert(1, ProtectedReason::Init);
    let (l, rec, _reasons) =
        ladder_protected(NeutralizeOutcome::Contained, Duration::from_secs(30), prot);
    l.engage(
        Some(1),
        Some(TriggerType::ConfirmedIntrusion),
        Instant::now(),
    );

    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
    let log = rec.log();
    assert!(
        !log.iter().any(|e| e.starts_with("soft_block")),
        "PID 1 must not be soft-blocked: {log:?}"
    );
    assert!(
        !log.iter().any(|e| e == "isolate"),
        "engage must NOT isolate at INVESTIGATE: {log:?}"
    );
}

// ── Guard: a protected offender that actively exfiltrates jump-aheads
//    straight to ISOLATE (observe → drive_to path, kill refused) ──
#[test]
fn jump_ahead_on_protected_offender_escalates_to_isolate() {
    let mut prot = HashMap::new();
    prot.insert(4242, ProtectedReason::SshService);
    let (l, rec, _reasons) =
        ladder_protected(NeutralizeOutcome::Contained, Duration::from_secs(300), prot);
    let t0 = Instant::now();
    l.engage(Some(4242), Some(TriggerType::ExfiltrationPattern), t0);
    // sshd (protected) actively exfiltrates → jump-ahead → cannot kill it
    // → straight to ISOLATE.
    l.observe(
        &tcp_connect(4242, [203, 0, 113, 9]),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    assert!(
        !log.iter().any(|e| e.starts_with("neutralize")),
        "protected offender is never killed: {log:?}"
    );
    assert!(log.iter().any(|e| e == "isolate"), "{log:?}");
}

// ── External audit POS-001 (NN-AUD-002): ISOLATE only in a locked COMBAT ──
#[test]
fn isolation_waits_for_a_locked_combat() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let win = Duration::from_secs(30);
    let (l, rec) = ladder(
        NeutralizeOutcome::Uncontainable {
            reason: "respawns via supervisor".to_string(),
        },
        win,
    );
    let locked = Arc::new(AtomicBool::new(false));
    let l = l.with_isolation_gate({
        let locked = Arc::clone(&locked);
        move || locked.load(Ordering::SeqCst)
    });
    let t0 = Instant::now();
    l.engage(Some(1234), Some(TriggerType::ExfiltrationPattern), t0);
    l.tick(t0 + win + Duration::from_secs(1));
    l.tick(t0 + win + Duration::from_secs(6));

    // Heuristic COMBAT: the offender is neutralized, the isolation it
    // would have escalated to is refused (recorded once), and the host
    // stays on the network.
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    let log = rec.log();
    assert!(log.iter().any(|e| e.starts_with("neutralize")), "{log:?}");
    assert!(!log.iter().any(|e| e == "isolate"), "{log:?}");
    assert_eq!(
        log.iter()
            .filter(|e| *e == "audit:NEUTRALIZE->NEUTRALIZE")
            .count(),
        1,
        "the refusal is recorded once: {log:?}"
    );

    // The posture locks COMBAT on later evidence: the next tick isolates,
    // once, evidence first.
    locked.store(true, Ordering::SeqCst);
    l.tick(t0 + win + Duration::from_secs(11));
    l.tick(t0 + win + Duration::from_secs(16));
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    assert_eq!(log.iter().filter(|e| *e == "isolate").count(), 1, "{log:?}");
    let audit_idx = log
        .iter()
        .position(|e| e == "audit:NEUTRALIZE->ISOLATE")
        .expect("ISOLATE stage audit must be recorded");
    let isolate_idx = log.iter().position(|e| e == "isolate").unwrap();
    assert!(audit_idx < isolate_idx, "{log:?}");
}

/// External audit POS-001: an unlocked COMBAT that decays stands the
/// ladder down; a deferred isolation does not survive it.
#[test]
fn stand_down_drops_a_deferred_isolation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let win = Duration::from_secs(30);
    let (l, rec) = ladder(
        NeutralizeOutcome::Uncontainable {
            reason: "respawns via supervisor".to_string(),
        },
        win,
    );
    let locked = Arc::new(AtomicBool::new(false));
    let l = l.with_isolation_gate({
        let locked = Arc::clone(&locked);
        move || locked.load(Ordering::SeqCst)
    });
    let t0 = Instant::now();
    l.engage(Some(1234), Some(TriggerType::ExfiltrationPattern), t0);
    l.tick(t0 + win + Duration::from_secs(1));
    l.stand_down(t0 + win + Duration::from_secs(2));
    locked.store(true, Ordering::SeqCst);
    l.tick(t0 + win + Duration::from_secs(6));
    assert_eq!(l.current_stage(), None);
    assert!(!rec.log().iter().any(|e| e == "isolate"), "{:?}", rec.log());
}

// ── External audit CMB-007 / 011 / 012 / 014 / 010: the ladder worker ──

/// Which call of [`HeldActuator`] waits for the test.
#[derive(Clone, Copy, PartialEq)]
enum Held {
    Neutralize,
    Isolate,
    SoftBlock(u32),
}

/// An actuator whose `held` call waits until the test lets it go.
struct HeldActuator {
    rec: Recorder,
    hold: Mutex<std::sync::mpsc::Receiver<()>>,
    held: Held,
    neutralize_outcome: NeutralizeOutcome,
}

impl HeldActuator {
    fn wait_if(&self, call: Held, name: &str) {
        if self.held == call {
            self.rec.push(format!("{name}:start"));
            let _ = self.hold.lock().recv_timeout(Duration::from_secs(10));
        }
    }
}

impl CombatActuator for HeldActuator {
    fn identify(&self, pid: u32, _start_ns: u64, _seen_ns: u64) -> Arc<ProcRef> {
        mock_ref(pid)
    }
    fn same_process(&self, target: &ProcRef, start_ns: u64) -> bool {
        mock_same_process(target, start_ns)
    }
    fn soft_egress_block(&self, target: &ProcRef) -> SoftBlock {
        let pid = target.pid();
        self.wait_if(Held::SoftBlock(pid), &format!("soft_block:{pid}"));
        self.rec.push(format!("soft_block:{pid}"));
        SoftBlock::Blocked
    }
    fn soft_egress_clear(&self, target: &ProcRef) {
        self.rec.push(format!("soft_clear:{}", target.pid()));
    }
    fn neutralize(&self, offenders: &[Arc<ProcRef>]) -> NeutralizeOutcome {
        self.wait_if(Held::Neutralize, "neutralize");
        self.rec
            .push(format!("neutralize:{:?}", pids_of(offenders)));
        self.neutralize_outcome.clone()
    }
    fn isolate(&self) {
        self.wait_if(Held::Isolate, "isolate");
        self.rec.push("isolate".to_string());
    }
    fn is_dry_run(&self) -> bool {
        false
    }
}

fn held_ladder(
    held: Held,
    neutralize: NeutralizeOutcome,
) -> (Arc<CombatLadder>, Recorder, std::sync::mpsc::SyncSender<()>) {
    let rec = Recorder::new();
    let (tx, rx) = std::sync::mpsc::sync_channel(4);
    let l = CombatLadder::new(
        Box::new(HeldActuator {
            rec: rec.clone(),
            hold: Mutex::new(rx),
            held,
            neutralize_outcome: neutralize,
        }),
        Box::new(MockEvidence { rec: rec.clone() }),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    )
    .with_worker();
    (Arc::new(l), rec, tx)
}

/// Wait until the log holds `entry` (the worker runs on its own thread).
fn wait_for(rec: &Recorder, entry: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !rec.log().iter().any(|e| e == entry) {
        assert!(
            std::time::Instant::now() < deadline,
            "never logged {entry}: {:?}",
            rec.log()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// External audit CMB-007: a NEUTRALIZE in progress does not hold up the
/// event path — the side effects run on the worker.
#[test]
fn observe_returns_while_neutralize_runs() {
    let (l, rec, go) = held_ladder(Held::Neutralize, NeutralizeOutcome::Contained);
    let t0 = Instant::now();
    l.engage(Some(100), None, t0);
    l.observe(&spawn(101, 100), t0); // jump-ahead
    wait_for(&rec, "neutralize:start");
    let start = std::time::Instant::now();
    for i in 0..200 {
        l.observe(&spawn(5000 + i, 1), t0);
        l.observe(&tcp_connect(100, [8, 8, 8, 8]), t0);
        l.tick(t0 + Duration::from_secs(60));
    }
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "the event path waited on the actuator: {:?}",
        start.elapsed()
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    go.send(()).unwrap();
    wait_for(&rec, "neutralize:[100, 101]");
    // one NEUTRALIZE, however many advances were asked for meanwhile
    std::thread::sleep(Duration::from_millis(50));
    let kills = rec
        .log()
        .iter()
        .filter(|e| e.starts_with("neutralize:["))
        .count();
    assert_eq!(kills, 1, "{:?}", rec.log());
}

/// External audit CMB-012: the stand-down runs after an ISOLATE already
/// under way, and the release waits for it — the isolation cannot land
/// after the release lifted it.
#[test]
fn stand_down_orders_after_an_in_flight_isolate() {
    let (l, rec, go) = held_ladder(
        Held::Isolate,
        NeutralizeOutcome::Uncontainable {
            reason: "respawning".into(),
        },
    );
    let t0 = Instant::now();
    l.engage(Some(100), None, t0);
    l.tick(t0 + Duration::from_secs(31));
    wait_for(&rec, "isolate:start");
    let releaser = {
        let l = Arc::clone(&l);
        let rec = rec.clone();
        std::thread::spawn(move || {
            l.stand_down_and_wait(t0 + Duration::from_secs(32), Duration::from_secs(10));
            rec.push("released");
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !rec.log().iter().any(|e| e == "released"),
        "the release must wait for the in-flight isolate: {:?}",
        rec.log()
    );
    assert_eq!(l.current_stage(), None, "the decision is immediate");
    go.send(()).unwrap();
    releaser.join().unwrap();
    let log = rec.log();
    let pos = |e: &str| log.iter().position(|x| x == e).unwrap_or(usize::MAX);
    assert!(pos("isolate") < pos("soft_clear:100"), "{log:?}");
    assert!(pos("soft_clear:100") < pos("released"), "{log:?}");
}

/// External audit CMB-012: a step queued for an episode that has since
/// closed is dropped; a block that finished after the close is released.
#[test]
fn a_step_from_a_past_episode_is_dropped() {
    let (l, rec, go) = held_ladder(Held::SoftBlock(100), NeutralizeOutcome::Contained);
    let t0 = Instant::now();
    l.engage(Some(100), None, t0);
    wait_for(&rec, "soft_block:100:start");
    l.engage(Some(101), None, t0); // queued for episode 1
    l.stand_down(t0 + Duration::from_secs(1)); // episode closes
    go.send(()).unwrap();
    wait_for(&rec, "soft_clear:100");
    std::thread::sleep(Duration::from_millis(50));
    let log = rec.log();
    assert!(
        !log.iter().any(|e| e == "soft_block:101"),
        "the closed episode's step must not run: {log:?}"
    );
}

/// External audit CMB-011: attribution stops at the cap; past it the
/// tree is not containable process by process and the ladder escalates.
#[test]
fn spread_attribution_is_capped_and_escalates() {
    let rec = Recorder::new();
    let l = CombatLadder::new(
        Box::new(MockActuator {
            rec: rec.clone(),
            neutralize_outcome: NeutralizeOutcome::Contained,
            failing_blocks: Vec::new(),
        }),
        Box::new(MockEvidence { rec: rec.clone() }),
        Box::new(NoProtectedProcs),
        LadderConfig {
            max_offenders: 3,
            ..LadderConfig::default()
        },
    );
    let t0 = Instant::now();
    l.engage(Some(100), None, t0);
    l.observe(&spawn(101, 100), t0); // jump-ahead: NEUTRALIZE, contained
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    l.observe(&spawn(102, 101), t0); // third offender: soft-blocked
    assert!(rec.log().iter().any(|e| e == "soft_block:102"));
    assert!(!rec.log().iter().any(|e| e == "isolate"));
    l.observe(&spawn(103, 102), t0); // past the cap
    l.observe(&spawn(104, 102), t0);
    assert_eq!(l.offenders(), vec![100, 101, 102]);
    let log = rec.log();
    assert_eq!(log.iter().filter(|e| *e == "isolate").count(), 1, "{log:?}");
    assert!(
        log.iter().any(|e| e == "audit:NEUTRALIZE->ISOLATE"),
        "{log:?}"
    );
    assert!(!log
        .iter()
        .any(|e| e == "soft_block:103" || e == "soft_block:104"));
}

/// External audit CMB-014: a soft block that did not take effect is in
/// the INVESTIGATE evidence, and the episode's window is the short one.
#[test]
fn a_failed_soft_block_is_recorded_and_shortens_investigate() {
    let rec = Recorder::new();
    let reasons = ReasonEvidence(Arc::new(Mutex::new(Vec::new())));
    let l = CombatLadder::new(
        Box::new(MockActuator {
            rec: rec.clone(),
            neutralize_outcome: NeutralizeOutcome::Contained,
            failing_blocks: vec![100],
        }),
        Box::new(reasons.clone()),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    );
    let t0 = Instant::now();
    l.engage(Some(100), None, t0);
    let r = reasons.0.lock().clone();
    assert!(
        r[0].0 == "INVESTIGATE" && r[0].1.contains("100 FAILED (no nft)"),
        "{r:?}"
    );
    l.tick(t0 + Duration::from_secs(9));
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
    l.tick(t0 + Duration::from_secs(10));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    assert!(rec.log().iter().any(|e| e == "neutralize:[100]"));
    let r = reasons.0.lock().clone();
    assert!(r[1].1.contains("shortened"), "{r:?}");
}

/// External audit CMB-014: an offender attributed after the INVESTIGATE
/// record whose block fails gets a signed record of its own (once per
/// episode).
#[test]
fn a_failed_block_after_the_investigate_record_is_recorded() {
    let reasons = ReasonEvidence(Arc::new(Mutex::new(Vec::new())));
    let l = CombatLadder::new(
        Box::new(MockActuator {
            rec: Recorder::new(),
            neutralize_outcome: NeutralizeOutcome::Contained,
            failing_blocks: vec![100, 101],
        }),
        Box::new(reasons.clone()),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    );
    let t0 = Instant::now();
    l.engage(None, None, t0); // the posture hook: no offender yet
    l.engage(Some(100), None, t0);
    l.engage(Some(101), None, t0);
    let r = reasons.0.lock().clone();
    assert_eq!(r.len(), 2, "{r:?}");
    assert!(
        r[1].0 == "INVESTIGATE" && r[1].1.contains("100 FAILED") && r[1].1.contains("10 s"),
        "{r:?}"
    );
}

/// External audit CMB-010: the stand-down releases what the episode
/// blocked — not a spared host-critical offender, not one whose block
/// failed.
#[test]
fn stand_down_releases_only_what_this_episode_blocked() {
    let rec = Recorder::new();
    let l = CombatLadder::new(
        Box::new(MockActuator {
            rec: rec.clone(),
            neutralize_outcome: NeutralizeOutcome::Contained,
            failing_blocks: vec![8],
        }),
        Box::new(MockEvidence { rec: rec.clone() }),
        Box::new(StubProtected(HashMap::from([(
            7,
            ProtectedReason::SshService,
        )]))),
        LadderConfig::default(),
    );
    let t0 = Instant::now();
    l.engage(Some(9), None, t0);
    l.engage(Some(7), None, t0);
    l.engage(Some(8), None, t0);
    assert_eq!(l.offenders(), vec![7, 8, 9]);
    l.stand_down(t0 + Duration::from_secs(1));
    let clears: Vec<_> = rec
        .log()
        .into_iter()
        .filter(|e| e.starts_with("soft_clear:"))
        .collect();
    assert_eq!(clears, vec!["soft_clear:9".to_string()]);
}

/// External audit CMB-027: the audit log refuses the transitions (here its
/// file is a directory for a while, as an I/O error or a full filesystem
/// would) — the ladder still drives every stage, kill and isolation
/// included, the counts say what the signed log lacks, and once the log
/// takes appends again the stand-down writes the waiting transitions, each
/// once, in order, marked `deferred` with the time it happened.
#[test]
fn a_failing_audit_log_never_holds_the_ladder() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
    let pubkey = key.verifying_key();
    let audit = Arc::new(Mutex::new(
        crate::audit::AuditLog::open(&log_path, key, [0u8; 16]).unwrap(),
    ));
    let rec = Recorder::new();
    let l = CombatLadder::new(
        Box::new(MockActuator {
            rec: rec.clone(),
            neutralize_outcome: NeutralizeOutcome::Uncontainable {
                reason: "respawns".to_string(),
            },
            failing_blocks: Vec::new(),
        }),
        Box::new(AuditEvidence::new(Some(Arc::clone(&audit)))),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    );
    // Break the log: appends fail (EISDIR) even for root.
    let away = dir.path().join("audit.log.away");
    if log_path.exists() {
        std::fs::rename(&log_path, &away).unwrap();
    }
    std::fs::create_dir(&log_path).unwrap();

    let t0 = Instant::now();
    l.engage(Some(1234), Some(TriggerType::PersistenceMechanism), t0);
    l.tick(t0 + LadderConfig::default().investigate_window + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    for step in ["soft_block:1234", "neutralize:[1234]", "isolate"] {
        assert!(log.iter().any(|e| e == step), "{step} not driven: {log:?}");
    }
    let c = l.evidence_counts();
    assert_eq!((c.unrecorded, c.pending, c.dropped), (3, 3, 0), "{c:?}");

    // The log is back; the stand-down writes what waited.
    std::fs::remove_dir(&log_path).unwrap();
    if away.exists() {
        std::fs::rename(&away, &log_path).unwrap();
    }
    l.stand_down(t0 + Duration::from_secs(120));
    let c = l.evidence_counts();
    assert_eq!((c.unrecorded, c.pending, c.dropped), (3, 0, 0), "{c:?}");
    let all: Vec<crate::audit::AuditEntry> = std::fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    crate::audit::verify_chain(&all, &pubkey).expect("the chain verifies");
    let stages: Vec<_> = all.iter().filter(|e| e.op == "combat_stage").collect();
    let to: Vec<_> = stages
        .iter()
        .map(|e| e.extra["to"].as_str().unwrap())
        .collect();
    assert_eq!(
        to,
        ["INVESTIGATE", "NEUTRALIZE", "ISOLATE"],
        "once each, in order"
    );
    for e in &stages {
        assert_eq!(e.extra["deferred"], true, "{e:?}");
        let at = e.extra["occurred_at"].as_str().unwrap();
        assert!(at <= e.ts.as_str(), "happened {at}, written {}", e.ts);
    }
}
