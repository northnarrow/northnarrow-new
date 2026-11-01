//! R12c (lab PR 270): the response dispatcher — every action path writes
//! its signed intent before the action and its outcome after; the decision
//! never waits; a full queue never drops silently; the stop answers what is
//! left.

use std::time::{Duration, Instant};

use nn_core::decision::combine::{Applied, Response, RuleMatch};
use nn_model::{Event, ResponseAction, Severity, Verdict};
use northnarrow_agent::decision::combine::Decision;
use northnarrow_agent::detection_store::{DetectionRecord, DetectionSink};
use northnarrow_agent::response::journal::{ActionJournal, ActionResult, ActionRow};
use northnarrow_agent::response::{Executor, ExecutorConfig};

use super::*;

fn event(pid: u32) -> Event {
    Event::ProcessSpawn {
        pid,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "payload".to_string(),
        filename: "/tmp/payload".to_string(),
        timestamp_ns: 123,
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

fn verdict(rule: &str, action: ResponseAction, severity: Severity, pid: u32) -> Verdict {
    Verdict {
        rule_id: rule.to_string(),
        rule_name: rule.to_string(),
        category: "test".to_string(),
        action,
        severity,
        reasoning: "test".to_string(),
        event_pid: pid,
        event_filename: "/tmp/payload".to_string(),
        timestamp_ns: 123,
    }
}

/// A decision of `rule` (leaked: the engine's rule ids are static) running
/// `action` on `pid`, of `severity`.
fn decided(rule: &str, action: ResponseAction, severity: Severity, pid: u32) -> Arc<Decided> {
    decided_on(rule, action, severity, pid, "/tmp/payload")
}

/// [`decided`], its response on `file`.
fn decided_on(
    rule: &str,
    action: ResponseAction,
    severity: Severity,
    pid: u32,
    file: &str,
) -> Arc<Decided> {
    let rule: &'static str = Box::leak(rule.to_string().into_boxed_str());
    let v = verdict(rule, action.clone(), severity, pid);
    let decision = Decision {
        verdict: v.clone(),
        primary: 0,
        matches: vec![RuleMatch {
            index: 0,
            rule_id: rule,
            attack: &[],
            verdict: v,
            applied: Applied::Builtin,
            held: None,
            held_action: None,
            builtin_action: action.clone(),
            switch_held: false,
        }],
        responses: vec![Response {
            action,
            pid,
            filename: file.to_string(),
            timestamp_ns: 123,
            rule_id: rule,
            also: Vec::new(),
        }],
    };
    Decided::new(
        event(pid),
        decision,
        nn_model::posture_types::PostureKind::Observing,
        0,
        true,
    )
}

fn dispatcher(dry_run: bool, cap: usize) -> (Dispatcher, ActionJournal, DetectionSink) {
    dispatcher_with(dry_run, cap, None)
}

fn dispatcher_with(
    dry_run: bool,
    cap: usize,
    posture: Option<northnarrow_agent::posture::PostureMachine>,
) -> (Dispatcher, ActionJournal, DetectionSink) {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = ExecutorConfig::for_test(tmp.path());
    cfg.dry_run = dry_run;
    // the config's paths stay valid for the test's life
    std::mem::forget(tmp);
    let journal = ActionJournal::memory();
    let sink = DetectionSink::for_test(4096, 0);
    let d = Dispatcher::start_with(
        Executor::with_config(cfg),
        journal.clone(),
        Followups {
            sink: Some(sink.clone()),
            cow: northnarrow_agent::cow::CowGuard::off_for_test(),
        },
        posture,
        cap,
    );
    (d, journal, sink)
}

fn submit_one(d: &Dispatcher, x: &Arc<Decided>) {
    d.submit(ResponseJob::of(x, None, 0, 0));
}

/// The rows of one action: its intent, then its outcome, in this run.
fn pairs(
    rows: &[northnarrow_agent::response::journal::ActionRecord],
) -> Vec<(u64, String, ActionResult)> {
    let mut out = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        if r.row != ActionRow::Intent {
            continue;
        }
        let o = rows[i..]
            .iter()
            .find(|o| o.row == ActionRow::Outcome && o.action == r.action && o.run == r.run)
            .unwrap_or_else(|| panic!("intent {} has no outcome after it: {rows:#?}", r.action));
        out.push((
            r.action,
            r.intent.as_ref().unwrap().response.clone(),
            o.outcome.as_ref().unwrap().result,
        ));
    }
    out
}

/// Every acting response a decision can run goes through the dispatcher
/// with its intent row written before the action and its outcome after,
/// and the decision's detection record follows its outcome. Detect-only:
/// approved, not enforced — the rows say so.
#[test]
fn every_rule_response_writes_its_intent_then_its_outcome() {
    let (d, journal, sink) = dispatcher(true, 64);
    let actions = [
        ResponseAction::KillProcess,
        ResponseAction::KillProcessTree,
        ResponseAction::BlockOutbound,
        ResponseAction::Quarantine,
        ResponseAction::ThrottleProcess,
        ResponseAction::StripFileCapability,
    ];
    for (i, a) in actions.iter().enumerate() {
        submit_one(
            &d,
            &decided(
                &format!("NN-L-T-{i}"),
                a.clone(),
                Severity::High,
                5000 + i as u32,
            ),
        );
    }
    d.stop(Duration::from_secs(5));
    let rows = journal.rows();
    let p = pairs(&rows);
    assert_eq!(p.len(), actions.len(), "{rows:#?}");
    for a in &actions {
        assert!(p.iter().any(|(_, r, _)| r == &format!("{a:?}")), "{a:?}");
    }
    assert!(p
        .iter()
        .all(|(_, _, result)| *result == ActionResult::WouldExecute));
    // every intent before its own outcome, and each record written after
    let records: Vec<DetectionRecord> = sink.queued_for_test();
    assert_eq!(records.len(), actions.len());
    assert!(
        records.iter().all(|r| r.response.contains("detect-only")),
        "{records:#?}"
    );
    let st = d.status();
    assert_eq!(
        (st.executed, st.journal.intents, st.journal.outcomes),
        (6, 6, 6)
    );
    assert_eq!(st.journal.in_flight, 0);
    assert_eq!(st.queue.lost(), 0);
}

/// A real kill (a child of the test, no privilege needed): intent, the
/// SIGKILL, the outcome `success`; the record says the kill ran.
#[test]
fn a_kill_runs_between_its_intent_and_its_outcome() {
    use std::os::unix::process::ExitStatusExt;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    let (d, journal, sink) = dispatcher(false, 64);
    submit_one(
        &d,
        &decided(
            "NN-L-T-KILL",
            ResponseAction::KillProcess,
            Severity::Critical,
            pid,
        ),
    );
    d.stop(Duration::from_secs(5));
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    let rows = journal.rows();
    assert_eq!(
        rows.iter().map(|r| r.row).collect::<Vec<_>>(),
        [ActionRow::Intent, ActionRow::Outcome]
    );
    let i = rows[0].intent.as_ref().unwrap();
    assert_eq!(
        (i.response.as_str(), i.pid, i.severity.as_str()),
        ("KillProcess", pid, "critical")
    );
    assert_eq!(i.why, ["NN-L-T-KILL"]);
    assert_eq!(
        rows[1].outcome.as_ref().unwrap().result,
        ActionResult::Success
    );
    assert_eq!(sink.queued_for_test()[0].response, "KillProcess");
}

/// The decision never waits for the executor: with the dispatcher's thread
/// stalled, a flood of submissions returns at once — the queue takes what
/// fits, a more severe response displaces a less severe one, the rest is
/// refused — and every response not run is answered (its record says so),
/// counted per severity and signed in an overflow row. None is dropped
/// silently: queued + not run = submitted.
#[test]
fn the_decision_never_waits_and_a_full_queue_drops_nothing_silently() {
    let (d, journal, sink) = dispatcher(true, 8);
    let hold = d.shared.hold.lock();
    // the thread takes the first job and stalls on the hold
    submit_one(
        &d,
        &decided("NN-L-T-0", ResponseAction::KillProcess, Severity::Low, 7000),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the thread took nothing"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let started = Instant::now();
    for i in 1..=50u32 {
        let sev = if i % 10 == 0 {
            Severity::Critical
        } else {
            Severity::Low
        };
        submit_one(
            &d,
            &decided(
                &format!("NN-L-T-{i}"),
                ResponseAction::KillProcess,
                sev,
                7000 + i,
            ),
        );
    }
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(500),
        "50 submissions took {took:?}"
    );
    let st = d.status();
    assert_eq!(st.queue.depth.iter().sum::<u64>(), 8, "full");
    // 45 Low + 5 Critical: the Criticals displaced Lows, the rest refused
    assert_eq!(st.queue.displaced, [5, 0, 0, 0]);
    assert_eq!(st.queue.refused, [37, 0, 0, 0]);
    // the 42 not run are answered at once: their records are written
    let not_run = sink.queued_for_test();
    assert_eq!(not_run.len(), 42);
    assert!(
        not_run.iter().all(|r| r.response.contains("not run")),
        "{not_run:#?}"
    );
    drop(hold);
    d.stop(Duration::from_secs(5));
    let st = d.status();
    assert_eq!(st.executed, 9, "the one taken and the eight queued ran");
    assert_eq!(st.queue.submitted, 51);
    assert_eq!(st.queue.queued + st.queue.merged + st.queue.lost(), 51 + 5);
    let records = sink.queued_for_test();
    assert_eq!(records.len(), 51, "every decision has its record");
    // the overflow row names them, signed
    let rows = journal.rows();
    let over: Vec<_> = rows
        .iter()
        .filter(|r| r.row == ActionRow::Overflow)
        .collect();
    assert!(!over.is_empty(), "{rows:#?}");
    let o = over[0].overflow.as_ref().unwrap();
    assert_eq!(o.displaced, [5, 0, 0, 0]);
    assert_eq!(o.refused, [37, 0, 0, 0]);
    assert_eq!(o.total, 42);
    assert!(!o.samples.is_empty());
    assert_eq!(pairs(&rows).len(), 9);
}

/// A later response for the same process never overtakes an earlier one:
/// a Low strip then a Critical quarantine of the same pid run in that
/// order, both before another process's High block that was queued between
/// them (a kill goes first instead:
/// `a_kill_supersedes_its_process_s_queued_throttle`).
#[test]
fn a_process_s_responses_run_in_the_order_they_were_decided() {
    let (d, journal, _sink) = dispatcher(true, 64);
    let hold = d.shared.hold.lock();
    submit_one(
        &d,
        &decided("NN-L-T-A", ResponseAction::Log, Severity::Low, 8000),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    submit_one(
        &d,
        &decided(
            "NN-L-T-B",
            ResponseAction::StripFileCapability,
            Severity::Low,
            8001,
        ),
    );
    submit_one(
        &d,
        &decided(
            "NN-L-T-C",
            ResponseAction::BlockOutbound,
            Severity::High,
            8002,
        ),
    );
    submit_one(
        &d,
        &decided(
            "NN-L-T-D",
            ResponseAction::Quarantine,
            Severity::Critical,
            8001,
        ),
    );
    drop(hold);
    d.stop(Duration::from_secs(5));
    let order: Vec<(String, u32)> = journal
        .rows()
        .iter()
        .filter(|r| r.row == ActionRow::Intent)
        .map(|r| {
            let i = r.intent.as_ref().unwrap();
            (i.response.clone(), i.pid)
        })
        .collect();
    assert_eq!(
        order,
        [
            ("Log".to_string(), 8000),
            ("StripFileCapability".to_string(), 8001),
            ("Quarantine".to_string(), 8001),
            ("BlockOutbound".to_string(), 8002),
        ]
    );
}

/// The stop: what is still queued past its wait is answered "not run: the
/// agent stopped", counted and signed in an overflow row — never left
/// unanswered.
#[test]
fn the_stop_answers_what_it_could_not_run() {
    let (d, journal, sink) = dispatcher(true, 64);
    let hold = d.shared.hold.lock();
    submit_one(
        &d,
        &decided(
            "NN-L-T-0",
            ResponseAction::KillProcess,
            Severity::High,
            9000,
        ),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    for i in 1..5u32 {
        submit_one(
            &d,
            &decided(
                &format!("NN-L-T-{i}"),
                ResponseAction::KillProcess,
                Severity::High,
                9000 + i,
            ),
        );
    }
    // the stop waits 50 ms while the thread is held, then answers the rest
    let stopper = {
        let d = d.clone();
        std::thread::spawn(move || d.stop(Duration::from_millis(50)))
    };
    std::thread::sleep(Duration::from_millis(200));
    drop(hold);
    stopper.join().unwrap();
    let st = d.status();
    assert_eq!((st.executed, st.not_run_at_stop), (1, 4), "{st:?}");
    assert_eq!(sink.queued_for_test().len(), 5, "every decision answered");
    let rows = journal.rows();
    let o = rows
        .iter()
        .find(|r| r.row == ActionRow::Overflow)
        .and_then(|r| r.overflow.clone())
        .expect("the stop's overflow row");
    assert_eq!(o.queued_at_stop, st.not_run_at_stop);
    assert!(!st.running);
}

/// A dispatcher whose thread is not running answers every response "not
/// run", counts it — never runs it on the caller's thread.
#[test]
fn without_its_thread_nothing_runs_on_the_decision_thread() {
    let (d, journal, sink) = dispatcher(false, 64);
    d.stop(Duration::from_millis(10));
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    submit_one(
        &d,
        &decided(
            "NN-L-T-X",
            ResponseAction::KillProcess,
            Severity::Critical,
            child.id(),
        ),
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "not killed by the caller"
    );
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(d.status().not_run_down, 1);
    assert!(sink.queued_for_test()[0].response.contains("not running"));
    assert!(journal.rows().iter().all(|r| r.row != ActionRow::Intent));
}

/// A decision with two responses (two targets) is answered once, when both
/// ran: one record naming both outcomes; an intent and an outcome each.
#[test]
fn a_decision_s_record_waits_for_all_its_responses() {
    let (d, journal, sink) = dispatcher(true, 64);
    let x = decided(
        "NN-L-T-2R",
        ResponseAction::KillProcess,
        Severity::High,
        4100,
    );
    // a second response of the same decision, on another target
    let x = {
        let mut x = Arc::try_unwrap(x).ok().unwrap();
        let mut r = x.decision.responses[0].clone();
        r.pid = 4101;
        r.action = ResponseAction::BlockOutbound;
        x.decision.responses.push(r);
        Decided::new(x.event, x.decision, x.posture, 0, true)
    };
    submit_one(&d, &x);
    d.stop(Duration::from_secs(5));
    let records = sink.queued_for_test();
    assert_eq!(
        records.len(),
        1,
        "one record for the decision: {records:#?}"
    );
    assert!(
        records[0].response.contains("pid 4100") && records[0].response.contains("pid 4101"),
        "{}",
        records[0].response
    );
    assert_eq!(pairs(&journal.rows()).len(), 2);
}

/// A repeat of a queued response of the same process merges into it: one
/// action, both decisions' records answered by its outcome.
#[test]
fn a_repeat_merges_and_answers_both_decisions() {
    let (d, journal, sink) = dispatcher(true, 64);
    let hold = d.shared.hold.lock();
    submit_one(
        &d,
        &decided("NN-L-T-0", ResponseAction::Log, Severity::Low, 100),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    submit_one(
        &d,
        &decided(
            "NN-L-T-1",
            ResponseAction::KillProcessTree,
            Severity::High,
            4242,
        ),
    );
    submit_one(
        &d,
        &decided(
            "NN-L-T-2",
            ResponseAction::KillProcessTree,
            Severity::Critical,
            4242,
        ),
    );
    drop(hold);
    d.stop(Duration::from_secs(5));
    let st = d.status();
    assert_eq!((st.queue.merged, st.executed), (1, 2));
    let p = pairs(&journal.rows());
    assert_eq!(p.len(), 2);
    let kill = journal
        .rows()
        .into_iter()
        .find(|r| r.row == ActionRow::Intent && r.intent.as_ref().unwrap().pid == 4242)
        .unwrap();
    let i = kill.intent.unwrap();
    assert_eq!(i.why, ["NN-L-T-1", "NN-L-T-2"]);
    assert_eq!(i.severity, "critical");
    assert_eq!(sink.queued_for_test().len(), 3);
}

/// Responses not run raise the posture's `TelemetryLoss` with their signed
/// overflow row: an operator hears of them.
#[test]
fn responses_not_run_raise_telemetry_loss() {
    let posture = northnarrow_agent::posture::PostureMachine::new();
    assert_eq!(
        posture.current_kind(),
        nn_model::posture_types::PostureKind::Observing
    );
    let (d, journal, _sink) = dispatcher_with(true, 1, Some(posture.clone()));
    let hold = d.shared.hold.lock();
    submit_one(
        &d,
        &decided(
            "NN-L-T-0",
            ResponseAction::KillProcess,
            Severity::High,
            6000,
        ),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    submit_one(
        &d,
        &decided(
            "NN-L-T-1",
            ResponseAction::KillProcess,
            Severity::High,
            6001,
        ),
    );
    submit_one(
        &d,
        &decided(
            "NN-L-T-2",
            ResponseAction::KillProcess,
            Severity::High,
            6002,
        ),
    );
    drop(hold);
    d.stop(Duration::from_secs(5));
    assert_eq!(d.status().queue.refused, [0, 0, 1, 0]);
    assert!(journal.rows().iter().any(|r| r.row == ActionRow::Overflow));
    assert_eq!(
        posture.current_kind(),
        nn_model::posture_types::PostureKind::Alerted
    );
}

/// Review of #476 (X1): a process that reused a pid is another process —
/// its kill is not merged into the queued kill of the pid's earlier owner
/// (which would run with the old start, find it gone, and leave the new
/// process alive). Each kill runs with its own process's start.
#[test]
fn a_kill_of_a_reused_pid_is_not_merged_into_the_old_owner_s() {
    let (d, journal, sink) = dispatcher(true, 64);
    let a = decided(
        "NN-L-T-A",
        ResponseAction::KillProcess,
        Severity::High,
        4242,
    );
    let b = decided(
        "NN-L-T-B",
        ResponseAction::KillProcess,
        Severity::High,
        4242,
    );
    let mut jobs = ResponseJob::of(&a, Some(4242), 1_000, 1_000);
    jobs.extend(ResponseJob::of(&b, Some(4242), 9_000, 9_000));
    d.submit(jobs);
    d.stop(Duration::from_secs(5));
    assert_eq!(d.status().queue.merged, 0);
    let starts: Vec<u64> = journal
        .rows()
        .iter()
        .filter(|r| r.row == ActionRow::Intent)
        .map(|r| r.intent.as_ref().unwrap().start_ns)
        .collect();
    assert_eq!(starts, [1_000, 9_000]);
    assert_eq!(sink.queued_for_test().len(), 2);
    // the same action on the same pid is a repeat only for the same start
    let job = |d: &Arc<Decided>, start| ResponseJob::of(d, Some(4242), start, start).remove(0).1;
    assert!(!job(&a, 1_000).same_action(&job(&b, 9_000)));
    assert!(job(&a, 1_000).same_action(&job(&b, 1_000)));
}

/// Review of #476 (its mutation K11): two strips of one process's two
/// files are two actions, not one merged.
#[test]
fn two_strips_of_two_files_are_two_actions() {
    let (d, journal, _sink) = dispatcher(true, 64);
    let a = decided_on(
        "NN-L-T-S1",
        ResponseAction::StripFileCapability,
        Severity::High,
        4300,
        "/usr/local/bin/a",
    );
    let b = decided_on(
        "NN-L-T-S2",
        ResponseAction::StripFileCapability,
        Severity::High,
        4300,
        "/usr/local/bin/b",
    );
    let mut jobs = ResponseJob::of(&a, None, 0, 0);
    jobs.extend(ResponseJob::of(&b, None, 0, 0));
    d.submit(jobs);
    d.stop(Duration::from_secs(5));
    let files: Vec<Option<String>> = journal
        .rows()
        .iter()
        .filter(|r| r.row == ActionRow::Intent)
        .map(|r| r.intent.as_ref().unwrap().file.clone())
        .collect();
    assert_eq!(
        files,
        [
            Some("/usr/local/bin/a".to_string()),
            Some("/usr/local/bin/b".to_string())
        ]
    );
}

/// Review of #476 (its mutation K5): the overflow row names each
/// displaced response's severity — a Medium kill displaced by a Critical
/// one is counted Medium.
#[test]
fn the_overflow_row_counts_a_displaced_response_in_its_severity() {
    let (d, journal, _sink) = dispatcher(true, 1);
    let hold = d.shared.hold.lock();
    submit_one(
        &d,
        &decided(
            "NN-L-T-H",
            ResponseAction::KillProcess,
            Severity::High,
            4400,
        ),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    submit_one(
        &d,
        &decided(
            "NN-L-T-M",
            ResponseAction::KillProcess,
            Severity::Medium,
            4401,
        ),
    );
    submit_one(
        &d,
        &decided(
            "NN-L-T-C",
            ResponseAction::KillProcess,
            Severity::Critical,
            4402,
        ),
    );
    drop(hold);
    d.stop(Duration::from_secs(5));
    let o = journal
        .rows()
        .iter()
        .find_map(|r| r.overflow.clone())
        .expect("an overflow row");
    assert_eq!(o.displaced, [0, 1, 0, 0]);
    assert!(o.samples[0].contains("pid 4401"), "{o:?}");
}

/// Review of #476: a kill takes its process's queued throttle out — the
/// throttle's decision is answered "superseded", its record says so, and
/// nothing is counted lost; the kill runs.
#[test]
fn a_kill_supersedes_its_process_s_queued_throttle() {
    let (d, journal, sink) = dispatcher(true, 64);
    let hold = d.shared.hold.lock();
    submit_one(
        &d,
        &decided(
            "NN-L-T-0",
            ResponseAction::KillProcess,
            Severity::High,
            4500,
        ),
    );
    let t0 = Instant::now();
    while d.status().queue.taken == 0 {
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    submit_one(
        &d,
        &decided(
            "NN-L-T-T",
            ResponseAction::ThrottleProcess,
            Severity::Low,
            4501,
        ),
    );
    submit_one(
        &d,
        &decided(
            "NN-L-T-K",
            ResponseAction::KillProcessTree,
            Severity::Critical,
            4501,
        ),
    );
    let recs = sink.queued_for_test();
    assert_eq!(recs.len(), 1, "the throttle answered at once");
    assert!(
        recs[0].response.contains("superseded"),
        "{:?}",
        recs[0].response
    );
    drop(hold);
    d.stop(Duration::from_secs(5));
    let st = d.status();
    assert_eq!((st.queue.superseded, st.queue.lost()), (1, 0));
    let ran: Vec<String> = journal
        .rows()
        .iter()
        .filter(|r| r.row == ActionRow::Intent)
        .map(|r| r.intent.as_ref().unwrap().response.clone())
        .collect();
    assert_eq!(ran, ["KillProcess", "KillProcessTree"]);
}

/// The thread's end is seen: running until the stop, not after.
#[test]
fn the_dispatcher_says_whether_its_thread_runs() {
    let (d, _journal, _sink) = dispatcher(true, 8);
    assert!(d.is_running());
    d.stop(Duration::from_millis(10));
    assert!(!d.is_running());
}

/// A thread that ended outside a stop (a panic) is seen: not running, every
/// later response answered "not run" at once and counted, the response it
/// left queued answered at the stop — nothing runs, nothing is lost.
#[test]
fn a_dispatcher_whose_thread_ended_runs_nothing_more() {
    let (d, journal, sink) = dispatcher(true, 64);
    d.shared.panic_next.store(true, Ordering::Release);
    submit_one(
        &d,
        &decided(
            "NN-L-T-P",
            ResponseAction::KillProcess,
            Severity::High,
            9100,
        ),
    );
    let t0 = Instant::now();
    while d.is_running() {
        assert!(t0.elapsed() < Duration::from_secs(5), "the end not seen");
        std::thread::sleep(Duration::from_millis(1));
    }
    submit_one(
        &d,
        &decided(
            "NN-L-T-Q",
            ResponseAction::KillProcess,
            Severity::High,
            9101,
        ),
    );
    assert_eq!(d.status().not_run_down, 1);
    assert_eq!(sink.queued_for_test().len(), 1, "answered at once");
    assert!(sink.queued_for_test()[0].response.contains("not running"));
    d.stop(Duration::from_millis(10));
    let st = d.status();
    assert_eq!((st.executed, st.not_run_at_stop), (0, 1), "{st:?}");
    assert_eq!(sink.queued_for_test().len(), 2, "every decision answered");
    assert!(journal.rows().iter().all(|r| r.row != ActionRow::Intent));
}

/// The event loop stops the agent when the dispatcher's thread ended (as
/// for a dead pump), and the stop is a failure: pinned in the sources (the
/// loop's check is the watch's, not a unit's).
#[test]
fn a_dead_dispatcher_stops_the_agent() {
    let rl = include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/run_loop.rs"));
    let watch = &rl[rl.find("async fn watch_loop(").expect("watch_loop")..];
    let check = watch
        .find("if !dispatcher.is_running() {")
        .expect("the watch checks the dispatcher");
    let reason = watch[check..]
        .find("return \"response_dispatcher_exited\";")
        .expect("and stops");
    assert!(
        watch[check..check + reason].contains("attest_degraded_at("),
        "signed"
    );
    let sd = include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/shutdown.rs"));
    assert!(sd.contains("if stop_reason == \"response_dispatcher_exited\" {"));
}
