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

use super::actuator::{CombatActuator, NeutralizeOutcome};
use super::evidence::{LadderEvidence, StageTransition};
use super::{CombatLadder, CombatStage, LadderConfig, NoProtectedProcs, ProtectedProcs, ProtectedReason};

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
}

impl CombatActuator for MockActuator {
    fn soft_egress_block(&self, pid: u32) {
        self.rec.push(format!("soft_block:{pid}"));
    }
    fn soft_egress_clear(&self, pid: u32) {
        self.rec.push(format!("soft_clear:{pid}"));
    }
    fn neutralize(&self, offenders: &[u32]) -> NeutralizeOutcome {
        self.rec.push(format!("neutralize:{offenders:?}"));
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
    fn record_stage(&self, t: &StageTransition) {
        let from = t.from.map(|s| s.as_str()).unwrap_or("-");
        self.rec.push(format!("audit:{}->{}", from, t.to.as_str()));
    }
}

fn ladder(neutralize: NeutralizeOutcome, window: Duration) -> (CombatLadder, Recorder) {
    let rec = Recorder::new();
    let actuator = Box::new(MockActuator {
        rec: rec.clone(),
        neutralize_outcome: neutralize,
    });
    let evidence = Box::new(MockEvidence { rec: rec.clone() });
    let l = CombatLadder::new(
        actuator,
        evidence,
        Box::new(NoProtectedProcs),
        LadderConfig {
            investigate_window: window,
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
    fn record_stage(&self, t: &StageTransition) {
        self.0
            .lock()
            .push((t.to.as_str().to_string(), t.reason.clone()));
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
    });
    let evidence = Box::new(ReasonEvidence(reasons.clone()));
    let l = CombatLadder::new(
        actuator,
        evidence,
        Box::new(StubProtected(protected)),
        LadderConfig {
            investigate_window: window,
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
        parent_start_ns: 0,
        parent_is_kthread: false,
    }
}

// ── Acceptance #2: COMBAT entry → INVESTIGATE, network NOT dropped ──
#[test]
fn engage_enters_investigate_without_isolation() {
    let (l, rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(30));
    l.engage(Some(4242), Some(TriggerType::ConfirmedIntrusion), Instant::now());
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
    l.observe(&tcp_connect(555, [203, 0, 113, 9]), t0 + Duration::from_secs(2));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    assert!(rec.log().iter().any(|e| e == "neutralize:[555]"), "{:?}", rec.log());
}

#[test]
fn jump_ahead_ignores_loopback_connect() {
    let (l, _rec) = ladder(NeutralizeOutcome::Contained, Duration::from_secs(300));
    let t0 = Instant::now();
    l.engage(Some(555), None, t0);
    // A connect to loopback is not exfil — stay in INVESTIGATE.
    l.observe(&tcp_connect(555, [127, 0, 0, 1]), t0 + Duration::from_secs(2));
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
    assert!(rec.log().is_empty(), "no actions while idle: {:?}", rec.log());
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
    l.observe(&tcp_connect(321, [198, 51, 100, 7]), t0 + Duration::from_secs(2));
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    // A later deadline tick must NOT re-neutralize (already past INVESTIGATE).
    l.tick(t0 + win + Duration::from_secs(1));
    let neutralizes = rec
        .log()
        .into_iter()
        .filter(|e| e.starts_with("neutralize"))
        .count();
    assert_eq!(neutralizes, 1, "jump-ahead + deadline must neutralize exactly once");
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
    let neutralizes = rec.log().into_iter().filter(|e| e.starts_with("neutralize")).count();
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
    assert!(log.iter().any(|e| e == "isolate"), "must escalate to ISOLATE: {log:?}");
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
    assert!(neut_idx.is_some(), "NEUTRALIZE dossier must still be recorded: {r:?}");
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
    l.engage(Some(1), Some(TriggerType::ConfirmedIntrusion), Instant::now());

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
    l.observe(&tcp_connect(4242, [203, 0, 113, 9]), t0 + Duration::from_secs(2));
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    assert!(
        !log.iter().any(|e| e.starts_with("neutralize")),
        "protected offender is never killed: {log:?}"
    );
    assert!(log.iter().any(|e| e == "isolate"), "{log:?}");
}
