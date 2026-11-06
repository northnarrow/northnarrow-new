//! Lot 288 (#125): the stop's deadline — a stop that ends in time stands
//! it down, a stage that blocks is noted and cut within the budget, in this
//! process (an exit that records) and in a child (the agent's `_exit`).

use super::*;

/// A short budget for the tests in this process: 1.5 s, the note from
/// 0.8 s, the drains until 0.5 s.
const SHORT: Budget = Budget {
    total: Duration::from_millis(1500),
    note: Duration::from_millis(700),
    evidence: Duration::from_millis(300),
};

/// The scheduler's slack on a loaded host (the parallel harness).
const SLACK: Duration = Duration::from_millis(400);

/// The exits recorded: their status, when.
type Exits = Arc<Mutex<Vec<(i32, Instant)>>>;

/// The notes recorded: what each was told, when.
type Notes = Arc<Mutex<Vec<(Expired, Instant)>>>;

/// An exit that records its status and when.
fn recorder() -> (Exits, Exit) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let c = Arc::clone(&calls);
    (
        calls,
        Arc::new(move |status| c.lock().push((status, Instant::now()))),
    )
}

/// A note that records what it was told and when.
fn noted() -> (Notes, Note) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let c = Arc::clone(&calls);
    (
        calls,
        Box::new(move |e: &Expired| c.lock().push((e.clone(), Instant::now()))),
    )
}

/// The first exit, waited for at most `within`.
fn first_exit(calls: &Mutex<Vec<(i32, Instant)>>, within: Duration) -> Option<(i32, Instant)> {
    let until = Instant::now() + within;
    loop {
        if let Some(c) = calls.lock().first().copied() {
            return Some(c);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A stop that ends before its deadline stands it down: no note, no exit.
#[test]
fn a_stop_that_ends_in_time_is_never_cut() {
    let (exits, exit) = recorder();
    let stop = StopDeadline::start_with(SHORT, exit);
    let (notes, note) = noted();
    stop.begin("sigterm", note);
    stop.stage("decision");
    std::thread::sleep(Duration::from_millis(50));
    let at = Instant::now();
    stop.finish();
    assert!(
        at.elapsed() < Duration::from_millis(100),
        "finish returns at once"
    );
    std::thread::sleep(SHORT.total + SLACK);
    assert!(exits.lock().is_empty());
    assert!(notes.lock().is_empty());
}

/// A deadline never begun is never cut either (a start that failed).
#[test]
fn a_deadline_never_begun_never_exits() {
    let (exits, exit) = recorder();
    let stop = StopDeadline::start_with(SHORT, exit);
    std::thread::sleep(SHORT.total + SLACK);
    stop.finish();
    std::thread::sleep(Duration::from_millis(50));
    assert!(exits.lock().is_empty());
}

/// Lot 288: a stage that blocks is noted at the note's point, with the
/// stage, the reason and whether the stop was signed, then the process is
/// exited with the deadline's status — within the budget.
#[test]
fn a_blocked_stage_is_noted_then_cut_within_the_budget() {
    let (exits, exit) = recorder();
    let stop = StopDeadline::start_with(SHORT, exit);
    // the deadline's thread waits for the stop, as from the agent's start
    std::thread::sleep(Duration::from_millis(50));
    let (notes, note) = noted();
    let at = Instant::now();
    stop.begin("sigterm", note);
    stop.stage("dispatcher");
    stop.stage("decision");
    let (status, exited) = first_exit(&exits, SHORT.total + SLACK).expect("the deadline exits");
    assert_eq!(status, EXIT_STATUS);
    let notes = notes.lock();
    assert_eq!(notes.len(), 1, "one note");
    let (e, when) = &notes[0];
    assert_eq!(e.reason, "sigterm");
    assert_eq!(e.stage, "decision");
    assert!(!e.stop_signed);
    assert_eq!(e.budget, SHORT);
    let note_point = SHORT.total - SHORT.note;
    assert!(
        e.after >= note_point && e.after < note_point + Duration::from_millis(500),
        "{:?}",
        e.after
    );
    assert!(*when >= at + note_point);
    assert!(exited >= *when, "the exit follows the note");
    assert!(
        exited + Duration::from_millis(200) < at + SHORT.total,
        "the exit once the note is done: {:?}",
        exited - at
    );
    assert_eq!(exits.lock().len(), 1, "one exit");
}

/// A note that blocks (a log line, a disk) does not hold the exit: it
/// comes at the end of the budget.
#[test]
fn a_note_that_blocks_does_not_hold_the_exit() {
    let (exits, exit) = recorder();
    let stop = StopDeadline::start_with(SHORT, exit);
    let at = Instant::now();
    stop.begin(
        "sigterm",
        Box::new(|_: &Expired| loop {
            std::thread::park();
        }),
    );
    let (status, exited) = first_exit(&exits, SHORT.total + SLACK).expect("the deadline exits");
    assert_eq!(status, EXIT_STATUS);
    assert!(exited >= at + SHORT.total, "{:?}", exited - at);
    assert!(exited <= at + SHORT.total + SLACK, "{:?}", exited - at);
}

/// The note is told the stop signed its `agent_stop` (it signs no other),
/// and only the first `begin` counts: its reason, its note.
#[test]
fn the_note_is_told_the_first_begin_and_a_signed_stop() {
    let (exits, exit) = recorder();
    let stop = StopDeadline::start_with(SHORT, exit);
    let (notes, note) = noted();
    let (later, later_note) = noted();
    stop.begin("sigterm", note);
    stop.begin("sigint", later_note);
    stop.stage("anchor");
    stop.stop_signed();
    first_exit(&exits, SHORT.total + SLACK).expect("the deadline exits");
    let notes = notes.lock();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].0.reason, "sigterm");
    assert_eq!(notes[0].0.stage, "anchor");
    assert!(notes[0].0.stop_signed);
    assert!(later.lock().is_empty());
}

/// A stop that ends after the deadline expired leaves the exit to it, and
/// waits for it (the note may be writing a row) — until it comes, not to
/// the end of the budget.
#[test]
fn a_stop_that_ends_after_the_deadline_waits_for_its_exit() {
    let (exits, exit) = recorder();
    // the note from 0.5 s, the budget's end at 2 s
    let budget = Budget {
        total: Duration::from_secs(2),
        note: Duration::from_millis(1500),
        evidence: Duration::from_millis(100),
    };
    let stop = StopDeadline::start_with(budget, exit);
    let at = Instant::now();
    let started = Arc::new(Mutex::new(false));
    let s = Arc::clone(&started);
    stop.begin(
        "sigterm",
        Box::new(move |_: &Expired| {
            *s.lock() = true;
            std::thread::sleep(Duration::from_millis(100));
        }),
    );
    let until = Instant::now() + budget.total + SLACK;
    while !*started.lock() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(*started.lock(), "the note started");
    assert!(exits.lock().is_empty(), "not yet: the note is writing");
    stop.finish();
    assert_eq!(exits.lock().len(), 1, "finish returned after the exit");
    assert!(
        at.elapsed() < Duration::from_millis(1500),
        "and not at the budget's end: {:?}",
        at.elapsed()
    );
}

/// The stages that drain get their own bound, or what is left before the
/// part kept for the signed rows; the runtime what is left before the
/// note. Before the stop: their own, and the whole budget to the note.
#[test]
fn the_stages_get_what_is_left_of_the_budget() {
    let (_exits, exit) = recorder();
    let stop = StopDeadline::start_with(SHORT, exit);
    assert_eq!(stop.drain_until(), None);
    assert_eq!(
        stop.drain_bound(Duration::from_secs(7)),
        Duration::from_secs(7)
    );
    assert_eq!(stop.left(), SHORT.total - SHORT.note);
    let at = Instant::now();
    stop.begin("sigterm", Box::new(|_: &Expired| {}));
    let drain = SHORT.total - SHORT.note - SHORT.evidence;
    let until = stop.drain_until().expect("begun");
    assert!(until >= at + drain && until <= Instant::now() + drain);
    let bound = stop.drain_bound(Duration::from_secs(10));
    assert!(bound <= drain && bound + SLACK > drain, "{bound:?}");
    assert_eq!(
        stop.drain_bound(Duration::from_millis(1)),
        Duration::from_millis(1)
    );
    let left = stop.left();
    assert!(left <= SHORT.total - SHORT.note && left > drain, "{left:?}");
    std::thread::sleep(drain + Duration::from_millis(20));
    assert_eq!(stop.drain_bound(Duration::from_secs(1)), Duration::ZERO);
    assert!(stop.left() < SHORT.note);
    stop.finish();
}

/// The agent's budget stays under the unit's `TimeoutStopSec` with a
/// second of margin; its reserves fit in it.
#[test]
fn the_budget_fits_the_unit_s_timeout_stop_sec() {
    let unit = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/deploy/systemd/northnarrow-agent.service"
    ));
    let value = |key: &str| {
        let v: Vec<&str> = unit.lines().filter_map(|l| l.strip_prefix(key)).collect();
        assert_eq!(v.len(), 1, "{key} once in the unit");
        v[0].trim().to_string()
    };
    let secs: u64 = value("TimeoutStopSec=")
        .strip_suffix('s')
        .expect("in seconds")
        .parse()
        .unwrap();
    assert_eq!(Duration::from_secs(secs), UNIT_TIMEOUT_STOP);
    assert_eq!(value("SendSIGKILL="), "no");
    assert!(BUDGET.total + Duration::from_secs(1) <= UNIT_TIMEOUT_STOP);
    assert!(BUDGET.note + BUDGET.evidence < BUDGET.total);
    assert!(NOTE_LOCK_WAIT < BUDGET.note);
}

fn expired(stop_signed: bool) -> Expired {
    Expired {
        reason: "sigterm",
        stage: "decision",
        after: Duration::from_millis(3300),
        stop_signed,
        budget: BUDGET,
    }
}

/// The note's text: the stop's reason, the stage, the time, the budget,
/// the unit's timeout, the status, and what the run leaves isolated.
#[test]
fn the_note_says_the_stage_and_what_stays_isolated() {
    let e = expired(false);
    let kept = note_detail(&e, Isolation::Kept);
    for part in [
        "the stop (sigterm)",
        "stage decision still running after 3300 ms",
        "budget 4000 ms",
        "TimeoutStopSec 5 s",
        "status 75",
        "COMBAT isolation kept",
        "the next start tears it down and signs combat_reconcile",
    ] {
        assert!(kept.contains(part), "{part}: {kept}");
    }
    assert!(note_detail(&e, Isolation::None).ends_with("no COMBAT isolation in place"));
    assert!(note_detail(&e, Isolation::NoIsolator).ends_with("no network isolator in this run"));
    assert_eq!(Isolation::of(Some(true)), Isolation::Kept);
    assert_eq!(Isolation::of(Some(false)), Isolation::None);
    assert_eq!(Isolation::of(None), Isolation::NoIsolator);
}

fn audit_log(
    dir: &std::path::Path,
) -> (Mutex<crate::audit::AuditLog>, ed25519_dalek::VerifyingKey) {
    let key = crate::keys::AgentSigningKey::load_or_bootstrap(&dir.join("agent.key")).unwrap();
    let pubkey = key.verifying_key();
    let log = crate::audit::AuditLog::open(&dir.join("audit.log"), key, [0u8; 16]).unwrap();
    (Mutex::new(log), pubkey)
}

fn rows(
    dir: &std::path::Path,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> Vec<crate::audit::AuditEntry> {
    let text = std::fs::read_to_string(dir.join("audit.log")).unwrap_or_default();
    let entries: Vec<crate::audit::AuditEntry> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    crate::audit::verify_chain(&entries, pubkey).expect("the chain verifies");
    entries
}

/// The note signs the degradation (`subsystem_degraded`, source
/// `stop_deadline`) and, when the stop had not, the run's `agent_stop`
/// with its reason; one row only when the stop had signed it.
#[test]
fn the_note_signs_the_deadline_and_the_run_s_stop() {
    let dir = tempfile::tempdir().unwrap();
    let (log, pubkey) = audit_log(dir.path());
    let before = rows(dir.path(), &pubkey).len();
    assert_eq!(
        sign_note(&log, &expired(false), Isolation::Kept, 42),
        Signed::Rows {
            degraded: true,
            stop: true
        }
    );
    let all = rows(dir.path(), &pubkey);
    assert_eq!(all.len(), before + 2);
    let degraded = &all[before];
    assert_eq!(degraded.op, crate::audit::INTEGRITY_DRIFT_OP);
    assert_eq!(degraded.extra["kind"], "subsystem_degraded");
    assert_eq!(degraded.extra["source"], SOURCE);
    assert_eq!(
        degraded.extra["detail"],
        note_detail(&expired(false), Isolation::Kept)
    );
    let stop = &all[before + 1];
    assert_eq!(stop.op, "agent_stop");
    assert_eq!(stop.extra["reason"], "sigterm");
    assert_eq!(stop.extra["uptime_secs"], 42);
    assert_eq!(
        sign_note(&log, &expired(true), Isolation::None, 43),
        Signed::Rows {
            degraded: true,
            stop: false
        }
    );
    let all = rows(dir.path(), &pubkey);
    assert_eq!(all.len(), before + 3);
    assert_eq!(all[before + 2].extra["source"], SOURCE);
}

/// A log the blocked stage holds is not waited for past
/// [`NOTE_LOCK_WAIT`]: no row.
#[test]
fn a_held_audit_log_gets_no_note() {
    let dir = tempfile::tempdir().unwrap();
    let (log, pubkey) = audit_log(dir.path());
    let before = rows(dir.path(), &pubkey).len();
    let log = Arc::new(log);
    let held = Arc::new((Mutex::new(false), Condvar::new()));
    let (l, h) = (Arc::clone(&log), Arc::clone(&held));
    let holder = std::thread::spawn(move || {
        let _g = l.lock();
        *h.0.lock() = true;
        h.1.notify_all();
        std::thread::sleep(Duration::from_millis(1500));
    });
    {
        let mut g = held.0.lock();
        while !*g {
            held.1.wait(&mut g);
        }
    }
    let at = Instant::now();
    assert_eq!(
        sign_note(&log, &expired(false), Isolation::Kept, 1),
        Signed::NotWritable
    );
    let took = at.elapsed();
    assert!(
        took >= NOTE_LOCK_WAIT && took < Duration::from_millis(1200),
        "{took:?}"
    );
    holder.join().unwrap();
    assert_eq!(rows(dir.path(), &pubkey).len(), before);
}

/// The agent's note signs into its audit log; without one it signs
/// nothing and returns.
#[test]
fn the_agent_s_note_signs_into_its_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let (log, pubkey) = audit_log(dir.path());
    let before = rows(dir.path(), &pubkey).len();
    let rules = dir.path().join("combat-rules.v4");
    std::fs::write(&rules, "*filter\nCOMMIT\n").unwrap();
    let isolator = Arc::new(NetworkIsolator::new(rules).unwrap());
    let loop_started = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
    let note = audit_note(Some(Arc::new(log)), Some(isolator), loop_started);
    note(&expired(false));
    let all = rows(dir.path(), &pubkey);
    assert_eq!(all.len(), before + 2);
    assert_eq!(
        all[before].extra["detail"],
        note_detail(&expired(false), Isolation::None)
    );
    assert_eq!(all[before + 1].op, "agent_stop");
    assert!(all[before + 1].extra["uptime_secs"].as_u64() >= Some(5));
    audit_note(None, None, Instant::now())(&expired(false));
}

/// Lot 288 (#125): the agent's stop runs under its deadline — begun where
/// the event loop ends (on each way out of it, before the decision thread
/// is joined), every stage named, every wait bounded by what it leaves,
/// the `agent_stop` told to it; made before the runtime, whose shutdown
/// gets what is left, and finished after it.
#[test]
fn the_agent_s_stop_runs_under_its_deadline() {
    let src = |f: &str| {
        std::fs::read_to_string(format!("{}/agent/src/{f}", env!("NN_REPO_ROOT"))).unwrap()
    };
    let in_order = |text: &str, parts: &[&str]| {
        let mut at = 0;
        for p in parts {
            let i = text[at..]
                .find(p)
                .unwrap_or_else(|| panic!("`{p}`: missing, or before the one it follows"));
            at += i + p.len();
        }
    };
    let run_loop = src("run_loop.rs");
    in_order(
        &run_loop,
        &[
            "audit_note(audit_log.clone(), combat.isolator.clone(), loop_started)",
            "error!(\"event bus: no receiver to judge from — stopping\");",
            "begin(\"sensor_pump_exited\");",
            "return Stopped {",
            "the decision thread did not start — stopping",
            "begin(\"decision_thread_failed\");",
            "rt.block_on(watch_loop(",
            "begin(reason);",
            "stop.stage(\"decision\");",
            "decider.join()",
            "stop.stage(\"dispatcher\");",
            "off_the_runtime_stop(dispatcher, stop);",
            "stop.stage(\"canary\");",
            "d.flush(stop.drain_bound(Duration::from_secs(5)))",
            "stop.stage(\"bus\");",
            "sensor.stop_bus();",
            "dispatcher.stop_by(STOP_WAIT, stop.drain_until())",
        ],
    );
    in_order(
        &src("shutdown.rs"),
        &[
            "deadline.stage(\"heartbeat\");",
            "hb.stop(stop_reason);",
            "deadline.stage(\"export\");",
            "e.stop(deadline.drain_bound(northnarrow_agent::export::controller::STOP_WAIT));",
            "deadline.stage(\"workers\");",
            "workers.stop();",
            "deadline.stage(\"guards\");",
            "deadline.stage(\"agent_stop\");",
            "stop_entry(stop_reason, uptime)",
            "Ok(_) => {",
            "deadline.stop_signed();",
            "deadline.stage(\"anchor\");",
            "deadline.stage(\"files\");",
            "deadline.stage(\"teardown\");",
        ],
    );
    in_order(
        &src("boot/mod.rs"),
        &[
            "let stop = crate::stop_deadline::StopDeadline::start();",
            "tokio::runtime::Builder::new_multi_thread()",
            "runtime.block_on(run(cli, undumpable, image, &stop));",
            "stop.stage(\"runtime\");",
            "runtime.shutdown_timeout(stop.left());",
            "stop.finish();",
            "result",
        ],
    );
    assert!(src("boot/posture.rs").contains("isolator: isolator.clone(),"));
}

/// The child's switch: the helper below is a no-op without it.
const CHILD_ENV: &str = "NN_STOP_DEADLINE_CHILD";

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The child of [`a_stop_with_a_blocked_stage_exits_within_the_deadline`]:
/// the agent's deadline ([`StopDeadline::start`]: its budget, its `_exit`),
/// begun, and a stage that never ends. A no-op without [`CHILD_ENV`].
#[test]
#[ignore = "lot 288: the child of a_stop_with_a_blocked_stage_exits_within_the_deadline; a no-op \
            without NN_STOP_DEADLINE_CHILD"]
fn blocked_stop_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let stop = StopDeadline::start();
    println!("BEGIN {}", monotonic_ns());
    stop.begin(
        "sigterm",
        Box::new(|e: &Expired| println!("NOTE stage={} after_ms={}", e.stage, e.after.as_millis())),
    );
    stop.stage("decision");
    loop {
        std::thread::park();
    }
}

/// Lot 288 (#125): a stop whose stage blocks still ends the process —
/// with the deadline's status, its note written first, before the unit's
/// `TimeoutStopSec` (systemd would leave the process there and refuse the
/// restart's start). A child of this test binary runs the agent's
/// deadline with a stage that never ends.
#[test]
fn a_stop_with_a_blocked_stage_exits_within_the_deadline() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "stop_deadline::tests::blocked_stop_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let give_up = Instant::now() + Duration::from_secs(30);
    let (status, exit_ns) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, monotonic_ns());
        }
        if Instant::now() >= give_up {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the child's stop never ended");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
    assert_eq!(status.code(), Some(EXIT_STATUS), "{out}");
    let begin_ns: u64 = out
        .lines()
        .find_map(|l| l.split_once("BEGIN ").map(|(_, v)| v))
        .expect("the child began its stop")
        .parse()
        .unwrap();
    let after_ms: u64 = out
        .lines()
        .find_map(|l| {
            l.split_once("NOTE stage=decision after_ms=")
                .map(|(_, v)| v)
        })
        .expect("the note ran, with the stage")
        .parse()
        .unwrap();
    let note_point = BUDGET.total - BUDGET.note;
    assert!(after_ms >= note_point.as_millis() as u64, "{after_ms}");
    let took = Duration::from_nanos(exit_ns - begin_ns);
    assert!(took >= note_point, "{took:?}");
    assert!(took < UNIT_TIMEOUT_STOP, "{took:?}");
}
