//! The ladder's tests that wire the agent's other modules (R08c, lab PR
//! 252): the production process identity on a real process, the agent's
//! signing key and audit log, its posture machine, its production actuator
//! in detect-only. Cut verbatim from the ladder's tests (`combat/tests.rs`,
//! nn-core's since R08c) with copies of the fixtures they use; the mocks
//! implement the actuator's trait on the agent's host.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use nn_model::posture_types::TriggerType;
use nn_model::Event;

use super::actuator::{
    CombatActuator, IsolateOutcome, NeutralizeOutcome, NeutralizeReport, SoftBlock,
};
use super::evidence::{ActionOutcome, LadderEvidence, StageTransition, Unrecorded};
use super::offender::ProcFacts;
use super::ProcRef;
use super::{AuditEvidence, CombatLadder, CombatStage, LadderConfig, NoProtectedProcs};
use crate::anti_tamper::network_isolate::{FamilyOutcome, IsolationReport};
use crate::chain_host_linux::LinuxHost;
use crate::posture::{CombatCause, CombatEntry, EntryProcess, TriggerEvidence};

/// Lab PR 245: the evidence the posture cites for `trigger`, raised on an
/// event of `pid`.
fn evidence_of(trigger: TriggerType, pid: Option<u32>) -> TriggerEvidence {
    TriggerEvidence {
        trigger,
        raised: vec![trigger],
        class: trigger.evidence_class(),
        confidence: trigger
            .confidence(nn_model::posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION),
        corroborated_by: Vec::new(),
        locked: trigger.locks_combat(),
        scope: "login uid 1000".to_string(),
        event_kind: "ProcessSpawn",
        event_pid: pid,
        event_ns: Some(1),
    }
}

/// What the posture hands the ladder on a COMBAT entry (lab PR 245): the
/// event of `pid` that raised `trigger`. With no trigger, the stand-in
/// cause of the tests that do not read it — `nn-admin debug
/// force-posture` (a real forced COMBAT names no process).
fn entry(pid: Option<u32>, trigger: Option<TriggerType>) -> CombatEntry {
    CombatEntry {
        cause: match trigger {
            Some(t) => CombatCause::Trigger(evidence_of(t, pid)),
            None => CombatCause::DebugForce,
        },
        offender: pid.map(|pid| EntryProcess {
            pid,
            start_ns: 0,
            seen_ns: 0,
        }),
    }
}

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
    /// Lab PR 217: what each isolate call reports, in order; once used up,
    /// every family isolated.
    isolate_plan: Mutex<std::collections::VecDeque<IsolateOutcome>>,
}

/// Lab PR 217: both families isolated, read back.
fn isolated() -> IsolateOutcome {
    IsolateOutcome::Applied(IsolationReport {
        v4: FamilyOutcome::Done,
        v6: FamilyOutcome::Done,
    })
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

/// Lab PR 245: what the mocks read of a process when it is attributed.
fn mock_facts(pid: u32) -> ProcFacts {
    ProcFacts {
        exe: Some(format!("/tmp/.x/payload-{pid}")),
        cgroup: Some("/user.slice/user-1000.slice/session-3.scope".to_string()),
    }
}

impl CombatActuator<LinuxHost> for MockActuator {
    fn identify(&self, pid: u32, _start_ns: u64, _seen_ns: u64) -> Arc<ProcRef> {
        mock_ref(pid)
    }
    fn same_process(&self, target: &ProcRef, start_ns: u64) -> bool {
        mock_same_process(target, start_ns)
    }
    fn describe(&self, target: &ProcRef) -> ProcFacts {
        mock_facts(target.pid())
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
    fn neutralize(&self, offenders: &[Arc<ProcRef>]) -> NeutralizeReport {
        self.rec
            .push(format!("neutralize:{:?}", pids_of(offenders)));
        NeutralizeReport::uniform(&pids_of(offenders), &self.neutralize_outcome)
    }
    fn isolate(&self) -> IsolateOutcome {
        self.rec.push("isolate".to_string());
        self.isolate_plan
            .lock()
            .pop_front()
            .unwrap_or_else(isolated)
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
    fn record_outcome(&self, o: &ActionOutcome) -> Result<(), Unrecorded> {
        self.rec.push(format!(
            "outcome:{}:{}",
            o.stage.as_str(),
            if o.success { "success" } else { "failure" }
        ));
        Ok(())
    }
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
        stdio: Default::default(),
    }
}

/// The mock's actions with production's process identity: `identify` and
/// `same_process` are the trait's own (a pidfd and the start the event
/// reported, `ProcRef::matches_event`), not [`mock_same_process`].
struct RealIdentity(MockActuator);

impl CombatActuator<LinuxHost> for RealIdentity {
    fn soft_egress_block(&self, target: &ProcRef) -> SoftBlock {
        self.0.soft_egress_block(target)
    }
    fn soft_egress_clear(&self, target: &ProcRef) {
        self.0.rec.push(format!("soft_clear:{}", target.pid()));
    }
    fn neutralize(&self, offenders: &[Arc<ProcRef>]) -> NeutralizeReport {
        self.0.neutralize(offenders)
    }
    fn isolate(&self) -> IsolateOutcome {
        self.0.isolate()
    }
    fn is_dry_run(&self) -> bool {
        false
    }
}

/// Lab PR 238 (lot 122): the exec sensor names, as `parent_start_ns`, the
/// start of the parent PROCESS — its thread-group leader's, the start its
/// own exec reported — also for a child forked by a thread other than its
/// main one; it named the forking thread's start before. With the process
/// identity of production, an offender that has exited is the parent of a
/// child whose event names the offender's start; the start of one of its
/// threads, begun after the attribution, names no captured process (the
/// residual of lab PR 120: such a child escaped the lateral spread).
#[test]
fn a_child_forked_by_an_exited_offenders_thread_is_attributed_by_its_start() {
    let rec = Recorder::new();
    let l = CombatLadder::new(
        Box::new(RealIdentity(MockActuator {
            rec: rec.clone(),
            neutralize_outcome: NeutralizeOutcome::Contained,
            failing_blocks: Vec::new(),
            isolate_plan: Default::default(),
        })),
        Box::new(MockEvidence { rec: rec.clone() }),
        Box::new(NoProtectedProcs),
        LadderConfig {
            investigate_window: Duration::from_secs(300),
            ..LadderConfig::default()
        },
    );
    // A real process, attributed by the event of its exec: its start, and
    // the event's time just after it.
    let mut offender = std::process::Command::new("sleep")
        .arg("30")
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = offender.id();
    let start = crate::response::proc_ref::proc_start_ns(pid).expect("its start");
    let t0 = Instant::now();
    let mut e = entry(Some(pid), Some(TriggerType::ConfirmedIntrusion));
    e.offender = Some(EntryProcess {
        pid,
        start_ns: start,
        seen_ns: start + 1_000_000,
    });
    l.engage(&e, t0);
    assert_eq!(l.offenders(), vec![pid]);
    // It exits before its children's exec records are read.
    offender.kill().unwrap();
    offender.wait().unwrap();

    // The forking thread's own start, five seconds after the process's
    // (what the sensor sent before): no captured process — not its child.
    let thread_start = start + 5_000_000_000;
    l.observe(
        &spawn_started(999_999_001, thread_start + 1, pid, thread_start),
        t0 + Duration::from_secs(1),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Investigate));
    assert_eq!(l.offenders(), vec![pid]);
    // The leader's start (what it sends now): the offender's child.
    l.observe(
        &spawn_started(999_999_002, thread_start + 2, pid, start),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(l.current_stage(), Some(CombatStage::Neutralize));
    assert_eq!(l.offenders(), vec![pid, 999_999_002]);
    assert!(
        rec.log()
            .iter()
            .any(|e| *e == format!("neutralize:[{pid}, 999999002]")),
        "{:?}",
        rec.log()
    );
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
            isolate_plan: Default::default(),
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
    l.engage(
        &entry(Some(1234), Some(TriggerType::PersistenceMechanism)),
        t0,
    );
    l.tick(t0 + LadderConfig::default().investigate_window + Duration::from_secs(1));
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));
    let log = rec.log();
    for step in ["soft_block:1234", "neutralize:[1234]", "isolate"] {
        assert!(log.iter().any(|e| e == step), "{step} not driven: {log:?}");
    }
    // INVESTIGATE, NEUTRALIZE and its outcome, ISOLATE and its outcome
    // (lab PR 217: the outcomes are signed too, behind the same queue).
    let c = l.evidence_counts();
    assert_eq!((c.unrecorded, c.pending, c.dropped), (5, 5, 0), "{c:?}");

    // The log is back; the stand-down writes what waited.
    std::fs::remove_dir(&log_path).unwrap();
    if away.exists() {
        std::fs::rename(&away, &log_path).unwrap();
    }
    l.stand_down(t0 + Duration::from_secs(120));
    let c = l.evidence_counts();
    assert_eq!((c.unrecorded, c.pending, c.dropped), (5, 0, 0), "{c:?}");
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
    // Lab PR 217: each action's outcome, after its transition, with the
    // result it had — the kill did not contain, the isolation took.
    let outcomes: Vec<(&str, &str)> = all
        .iter()
        .filter(|e| e.op == "combat_outcome")
        .map(|e| (e.extra["stage"].as_str().unwrap(), e.result.as_str()))
        .collect();
    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
    assert_eq!(outcomes[0].0, "NEUTRALIZE");
    assert!(outcomes[0].1.starts_with("failure: "), "{outcomes:?}");
    assert_eq!(outcomes[1], ("ISOLATE", "success"));
}

// ── Lab PR 245: every signed row says why the ladder engaged, against whom ──

/// A signed audit log of a test's own, read back after the chain verified.
struct SignedLog {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    pubkey: ed25519_dalek::VerifyingKey,
    log: Arc<Mutex<crate::audit::AuditLog>>,
}

impl SignedLog {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let pubkey = key.verifying_key();
        let log = Arc::new(Mutex::new(
            crate::audit::AuditLog::open(&path, key, [0u8; 16]).unwrap(),
        ));
        Self {
            _dir: dir,
            path,
            pubkey,
            log,
        }
    }

    fn evidence(&self) -> Box<AuditEvidence> {
        Box::new(AuditEvidence::new(Some(Arc::clone(&self.log))))
    }

    /// Every row, the whole chain verified first.
    fn rows(&self) -> Vec<crate::audit::AuditEntry> {
        let all: Vec<crate::audit::AuditEntry> = std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        crate::audit::verify_chain(&all, &self.pubkey).expect("the chain verifies");
        all
    }

    fn stages(&self) -> Vec<serde_json::Value> {
        self.rows()
            .into_iter()
            .filter(|e| e.op == "combat_stage")
            .map(|e| e.extra)
            .collect()
    }
}

fn mock_actuator(rec: &Recorder) -> Box<MockActuator> {
    Box::new(MockActuator {
        rec: rec.clone(),
        neutralize_outcome: NeutralizeOutcome::Contained,
        failing_blocks: Vec::new(),
        isolate_plan: Default::default(),
    })
}

fn denial(pid: u32, ts: u64) -> Event {
    Event::FsProtectDenial {
        pid,
        uid: 1000,
        comm: "payload".to_string(),
        target_dev: 1,
        target_ino: 2,
        operation: nn_model::FsProtectOperation::Unlink,
        timestamp_ns: ts,
    }
}

/// The pids a row's `offender_details` name, in order.
fn detail_pids(row: &serde_json::Value) -> Vec<u64> {
    row["offender_details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["pid"].as_u64().unwrap())
        .collect()
}

/// Lab PR 245: a COMBAT the posture reaches opens the ladder's episode
/// with the firing trigger, the evidence it cites and the process the
/// event names — the INVESTIGATE row names them, and so does every row
/// after it. The same entry again (what `process_event` sent after the
/// hook) changes nothing; it used to be the only call that named either,
/// and the trigger was dropped.
#[test]
fn a_posture_combat_names_its_trigger_and_offender_from_investigate_on() {
    let log = SignedLog::new();
    let rec = Recorder::new();
    let ladder = Arc::new(CombatLadder::new(
        mock_actuator(&rec),
        log.evidence(),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    ));
    let heard: Arc<Mutex<Vec<CombatEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let posture = {
        let (ladder, heard) = (Arc::clone(&ladder), Arc::clone(&heard));
        crate::posture::PostureMachine::new_with_combat_hook(Arc::new(move |e: &CombatEntry| {
            heard.lock().push(e.clone());
            ladder.engage(e, Instant::now());
        }))
    };
    let t0 = Instant::now();
    posture.observe(&denial(6100, 5_000), &[]);
    assert_eq!(ladder.current_stage(), Some(CombatStage::Investigate));
    assert_eq!(ladder.offenders(), vec![6100]);

    let rows = log.stages();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let investigate = &rows[0];
    assert_eq!(investigate["to"], "INVESTIGATE");
    assert_eq!(investigate["trigger"], "AntiTamperDenial");
    assert_eq!(investigate["offenders"], serde_json::json!([6100]));
    let d = &investigate["offender_details"][0];
    assert_eq!(d["pid"], 6100);
    assert_eq!(d["exe"], "/tmp/.x/payload-6100");
    assert_eq!(d["cgroup"], "/user.slice/user-1000.slice/session-3.scope");
    assert_eq!(d["via"], "entry");
    assert_eq!(d["start_ticks"], 61_000, "the mock's capture");
    let cause = &investigate["cause"];
    assert_eq!(cause["kind"], "posture_trigger");
    assert_eq!(cause["trigger"], "AntiTamperDenial");
    assert_eq!(cause["class"], "Kernel");
    assert_eq!(cause["confidence"], "Decisive");
    assert_eq!(cause["locked"], true);
    assert_eq!(cause["event"]["kind"], "FsProtectDenial");
    assert_eq!(cause["event"]["pid"], 6100);
    assert_eq!(cause["event"]["timestamp_ns"], 5_000);
    assert!(
        rec.log().iter().any(|e| e == "soft_block:6100"),
        "the offender is blocked as the episode opens: {:?}",
        rec.log()
    );

    // What `process_event` sent after the hook: the same process again.
    let again = heard.lock()[0].clone();
    ladder.engage(&again, t0);
    assert_eq!(log.stages().len(), 1, "nothing new to record");

    ladder.tick(Instant::now() + Duration::from_secs(31));
    assert_eq!(ladder.current_stage(), Some(CombatStage::Neutralize));
    let all = log.rows();
    for row in all.iter().filter(|e| e.op.starts_with("combat_")) {
        assert_eq!(row.extra["trigger"], "AntiTamperDenial", "{row:?}");
    }
    let rows = log.stages();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["to"], "NEUTRALIZE");
    assert_eq!(rows[1]["cause"], rows[0]["cause"]);
    assert_eq!(detail_pids(&rows[1]), vec![6100]);
}

/// Lab PR 245: two offenders in one episode — a later COMBAT entry naming
/// another process adds it, signed as an addition with that entry's
/// cause; the episode's trigger and cause stay the first entry's in every
/// row, the outcomes' included, and each row names both offenders.
#[test]
fn two_offenders_in_one_episode_keep_the_first_trigger() {
    let log = SignedLog::new();
    let rec = Recorder::new();
    let l = CombatLadder::new(
        Box::new(MockActuator {
            rec: rec.clone(),
            neutralize_outcome: NeutralizeOutcome::Uncontainable {
                reason: "respawns".to_string(),
            },
            failing_blocks: Vec::new(),
            isolate_plan: Default::default(),
        }),
        log.evidence(),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    );
    let t0 = Instant::now();
    l.engage(&entry(Some(700), Some(TriggerType::AntiTamperDenial)), t0);
    l.engage(
        &entry(Some(800), Some(TriggerType::ExfiltrationPattern)),
        t0,
    );
    // the first offender named again by yet another entry: known, no row
    l.engage(&entry(Some(700), Some(TriggerType::LateralMovement)), t0);
    assert_eq!(l.offenders(), vec![700, 800]);
    l.tick(t0 + Duration::from_secs(31));
    assert_eq!(l.current_stage(), Some(CombatStage::Isolate));

    let rows = log.stages();
    let to: Vec<&str> = rows.iter().map(|r| r["to"].as_str().unwrap()).collect();
    assert_eq!(to, ["INVESTIGATE", "INVESTIGATE", "NEUTRALIZE", "ISOLATE"]);
    for r in &rows {
        assert_eq!(r["trigger"], "AntiTamperDenial", "{r}");
        assert_eq!(r["cause"]["trigger"], "AntiTamperDenial", "{r}");
    }
    assert_eq!(detail_pids(&rows[0]), vec![700]);
    // the addition: from and to INVESTIGATE, the later entry's cause
    let added = &rows[1];
    assert_eq!(added["from"], "INVESTIGATE");
    assert_eq!(added["offenders"], serde_json::json!([700, 800]));
    assert_eq!(detail_pids(added), vec![700, 800]);
    assert_eq!(added["added"]["offender"]["pid"], 800);
    assert_eq!(added["added"]["offender"]["via"], "later_entry");
    assert_eq!(added["added"]["offender"]["exe"], "/tmp/.x/payload-800");
    assert_eq!(added["added"]["by"]["trigger"], "ExfiltrationPattern");
    assert!(
        added["reason"]
            .as_str()
            .unwrap()
            .contains("offender 800 added by a later COMBAT entry (ExfiltrationPattern"),
        "{added}"
    );
    assert!(rows[0].get("added").is_none() && rows[2].get("added").is_none());
    for r in &rows[2..] {
        assert_eq!(detail_pids(r), vec![700, 800], "{r}");
        assert_eq!(r["offender_details"][0]["via"], "entry");
        assert_eq!(r["offender_details"][1]["via"], "later_entry");
    }
    // the outcomes: the episode's trigger too
    let outcomes: Vec<_> = log
        .rows()
        .into_iter()
        .filter(|e| e.op == "combat_outcome")
        .collect();
    assert_eq!(outcomes.len(), 2);
    for o in &outcomes {
        assert_eq!(o.extra["trigger"], "AntiTamperDenial", "{o:?}");
    }
    assert!(rec.log().iter().any(|e| e == "soft_block:800"));
}

/// Lab PR 245: `--detect-only` — the rows still name the trigger and the
/// offender (its executable and cgroup read from `/proc`), and nothing is
/// done to it: no block, no kill, no quarantine, no isolation. A real
/// process, the production actuator in detect-only, a real signed log.
#[test]
fn detect_only_rows_name_the_trigger_and_offender_and_nothing_acts() {
    let tmp = tempfile::TempDir::new().unwrap();
    let exec = crate::response::Executor::with_config(
        crate::response::config::ExecutorConfig::for_test(&tmp.path().join("state")),
    );
    assert!(exec.config().dry_run, "for_test is detect-only");
    let log = SignedLog::new();
    let ladder = Arc::new(CombatLadder::new(
        Box::new(super::SystemActuator::new(exec, None, true)),
        log.evidence(),
        Box::new(NoProtectedProcs),
        LadderConfig::default(),
    ));
    let posture = {
        let ladder = Arc::clone(&ladder);
        crate::posture::PostureMachine::new_with_combat_hook(Arc::new(move |e: &CombatEntry| {
            ladder.engage(e, Instant::now())
        }))
    };
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    let start = crate::response::proc_ref::proc_start_ns(pid).expect("its start");
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .expect("its exe")
        .to_string_lossy()
        .into_owned();
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|t| super::offender::cgroup_path(&t).map(str::to_string));

    posture.observe(&denial(pid, start + 1_000_000_000), &[]);
    assert_eq!(ladder.current_stage(), Some(CombatStage::Investigate));
    ladder.tick(Instant::now() + Duration::from_secs(31));
    assert_eq!(ladder.current_stage(), Some(CombatStage::Neutralize));
    let still_running = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(still_running, "detect-only killed the offender");

    let rows = log.stages();
    let to: Vec<&str> = rows.iter().map(|r| r["to"].as_str().unwrap()).collect();
    assert_eq!(to, ["INVESTIGATE", "NEUTRALIZE"], "{rows:?}");
    for r in &rows {
        assert_eq!(r["trigger"], "AntiTamperDenial", "{r}");
        assert_eq!(r["offenders"], serde_json::json!([pid]), "{r}");
        let d = &r["offender_details"][0];
        assert_eq!(d["pid"], pid);
        assert_eq!(d["exe"], exe.as_str(), "{r}");
        assert_eq!(d["cgroup"].as_str(), cgroup.as_deref(), "{r}");
        assert!(d["start_ticks"].as_u64().is_some(), "{r}");
        assert_eq!(d["seen_ns"], start + 1_000_000_000, "the event's time: {r}");
        assert_eq!(d["via"], "entry", "{r}");
    }
    assert!(
        rows[0]["reason"]
            .as_str()
            .unwrap()
            .contains(&format!("{pid} not blocked (detect-only)")),
        "{}",
        rows[0]["reason"]
    );
    let outcome = log
        .rows()
        .into_iter()
        .find(|e| e.op == "combat_outcome")
        .expect("NEUTRALIZE's outcome");
    assert_eq!(outcome.extra["trigger"], "AntiTamperDenial");
    let o = &outcome.extra["detail"]["offenders"][0];
    assert!(
        o["kill"].as_str().unwrap().starts_with("WouldExecute"),
        "{o}"
    );
    assert_eq!(o["quarantine"], "detect-only: would be quarantined");
    assert!(
        std::path::Path::new(&exe).exists(),
        "the binary is not quarantined"
    );
}
