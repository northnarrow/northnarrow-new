//! Lot M4 (#633): the stop's sweep on real processes — children stopped
//! with `SIGSTOP` stand for what the kernel holds, a fake map names them.

use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::execq::record::ExecqRecord;
use crate::response::journal::{ActionJournal, ActionRow};

#[derive(Default)]
struct MapState {
    beat: u64,
    entries: Vec<(u32, ExecqStopped)>,
    /// What the sweep did to the maps, in order.
    log: Vec<String>,
    /// Added to the map at its first read (a stop the kernel decided while
    /// the sweep began).
    late: Option<(u32, ExecqStopped)>,
}

#[derive(Clone, Default)]
struct FakeMaps(Arc<Mutex<MapState>>);

impl HeldMaps for FakeMaps {
    fn set_beat(&mut self, ns: u64) {
        let mut st = self.0.lock();
        st.beat = ns;
        st.log.push(format!("beat {ns}"));
    }
    fn entries(&self) -> Vec<(u32, ExecqStopped)> {
        let mut st = self.0.lock();
        st.log.push("read".into());
        let out = st.entries.clone();
        if let Some(e) = st.late.take() {
            st.entries.push(e);
        }
        out
    }
    fn entry(&self, pid: u32) -> Option<ExecqStopped> {
        let st = self.0.lock();
        st.entries.iter().find(|(p, _)| *p == pid).map(|(_, v)| *v)
    }
    fn remove(&mut self, pid: u32) {
        self.0.lock().entries.retain(|(p, _)| *p != pid);
    }
    fn put(&mut self, pid: u32, v: ExecqStopped) -> Result<(), String> {
        let mut st = self.0.lock();
        match st.entries.iter_mut().find(|(p, _)| *p == pid) {
            Some(e) => e.1 = v,
            None => st.entries.push((pid, v)),
        }
        Ok(())
    }
    fn quiesce(&mut self) {
        self.0.lock().log.push("quiesce".into());
    }
}

/// The signed entries, and (lot M7) when each was signed.
#[derive(Clone, Default)]
struct Audits(
    Arc<Mutex<Vec<serde_json::Value>>>,
    Arc<Mutex<Vec<std::time::Instant>>>,
);

impl Recorder for Audits {
    fn detection(&self, _rec: ExecqRecord) {}
    fn audit(&self, extra: serde_json::Value, _result: &str) {
        self.0.lock().push(extra);
        self.1.lock().push(std::time::Instant::now());
    }
    fn degraded(&self, _detail: &str) {}
}

/// A child `sleep 30`, stopped as the kernel stops a held exec.
struct Stopped {
    child: Child,
    pid: u32,
    start_ns: u64,
}

impl Drop for Stopped {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn state(pid: u32) -> Option<char> {
    let s = nn_linux::state_read::read_state(format!("/proc/{pid}/stat")).ok()?;
    s.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

fn wait_state(pid: u32, want: impl Fn(Option<char>) -> bool) -> bool {
    for _ in 0..400 {
        if want(state(pid)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

fn stopped_child() -> Stopped {
    let child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    // SAFETY: stopping our own child.
    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    assert!(wait_state(pid, |s| s == Some('T')), "child not stopped");
    let start_ns = crate::response::proc_ref::proc_start_ns(pid).unwrap();
    Stopped {
        child,
        pid,
        start_ns,
    }
}

fn entry(c: &Stopped, stop_ns: u64) -> (u32, ExecqStopped) {
    (
        c.pid,
        ExecqStopped {
            start_ns: c.start_ns,
            stop_ns,
        },
    )
}

struct Rig {
    maps: FakeMaps,
    held: Arc<Held<FakeMaps>>,
    audits: Audits,
    journal: ActionJournal,
}

fn rig(entries: Vec<(u32, ExecqStopped)>) -> Rig {
    let maps = FakeMaps::default();
    maps.0.lock().entries = entries;
    let held = Arc::new(Held::new(maps.clone()));
    Rig {
        maps,
        held,
        audits: Audits::default(),
        journal: ActionJournal::memory(),
    }
}

impl Rig {
    fn sweeper(&self, enforce: bool, capture: SweepCapture) -> Sweeper<FakeMaps> {
        Sweeper::new(
            Arc::clone(&self.held),
            capture,
            enforce,
            self.journal.clone(),
            Some(SharedRecorder::new(Box::new(self.audits.clone()))),
        )
    }
    fn entries(&self) -> Vec<(u32, ExecqStopped)> {
        self.maps.0.lock().entries.clone()
    }
}

fn capture() -> SweepCapture {
    Box::new(ProcRef::open_started_at)
}

#[test]
fn a_beat_after_the_stops_clear_is_refused() {
    let r = rig(Vec::new());
    r.held.beat(5);
    assert_eq!(r.maps.0.lock().beat, 5);
    r.held.clear();
    assert!(r.held.cleared());
    // a pass that began before the stop beats late: the kernel stays off
    r.held.beat(7);
    assert_eq!(
        r.maps.0.lock().beat,
        0,
        "a beat re-armed the kernel after the stop"
    );
    // the controller's own stop clears it the old way: a clear too
    let r = rig(Vec::new());
    r.held.beat(0);
    r.held.beat(9);
    assert_eq!(r.maps.0.lock().beat, 0);
}

#[test]
fn the_sweep_resumes_every_process_the_map_names() {
    let kids: Vec<Stopped> = (0..3).map(|_| stopped_child()).collect();
    let r = rig(kids.iter().map(|c| entry(c, 1)).collect());
    let swept = r.sweeper(true, capture()).sweep("test", None);
    let mut want: Vec<u32> = kids.iter().map(|c| c.pid).collect();
    let mut got = swept.resumed.clone();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, want, "{swept:?}");
    for c in &kids {
        assert!(
            wait_state(c.pid, |s| s != Some('T')),
            "{} is still stopped after the sweep",
            c.pid
        );
    }
    assert!(r.entries().is_empty(), "{:?}", r.entries());
    // the heartbeat cleared, the programs waited for, then the map read
    let log = r.maps.0.lock().log.clone();
    assert_eq!(log[..3], ["beat 0", "quiesce", "read"], "{log:?}");
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["kind"], "stopping");
    assert_eq!(a[0]["by"], "test");
    assert_eq!(a[0]["resumed"].as_array().unwrap().len(), 3, "{a:?}");
    assert!(a[0]["left"].as_array().unwrap().is_empty(), "{a:?}");
    // lot M7: no signing time, one entry — the whole sweep
    assert_eq!(a[0]["part"], "whole", "{a:?}");
    assert!(a[0]["unfinished"].as_array().unwrap().is_empty(), "{a:?}");
}

#[test]
fn the_sweep_reads_the_map_again_until_it_names_nothing_new() {
    let first = stopped_child();
    let late = stopped_child();
    let r = rig(vec![entry(&first, 1)]);
    r.maps.0.lock().late = Some(entry(&late, 2));
    let swept = r.sweeper(true, capture()).sweep("test", None);
    assert_eq!(swept.resumed.len(), 2, "{swept:?}");
    assert!(wait_state(late.pid, |s| s != Some('T')));
    assert!(r.entries().is_empty());
}

#[test]
fn the_sweep_kills_a_kill_the_map_owes_with_its_signed_intent() {
    let c = stopped_child();
    let r = rig(vec![entry(&c, KILL_OWED)]);
    let swept = r.sweeper(true, capture()).sweep("test", None);
    assert_eq!(swept.killed, vec![c.pid], "{swept:?}");
    assert!(
        swept.resumed.is_empty(),
        "an owed kill was resumed: {swept:?}"
    );
    assert!(r.entries().is_empty());
    let rows = r.journal.rows();
    assert_eq!(rows.len(), 2, "{rows:#?}");
    assert!(matches!(rows[0].row, ActionRow::Intent), "{rows:#?}");
    let i = rows[0].intent.as_ref().unwrap();
    assert_eq!(
        (i.source.as_str(), i.response.as_str(), i.pid),
        ("exec_quarantine", "KillProcess", c.pid)
    );
    let a = r.audits.0.lock().clone();
    assert_eq!(a[0]["killed"].as_array().unwrap().len(), 1, "{a:?}");
}

#[test]
fn an_observing_sweep_resumes_a_kill_the_map_owes() {
    // lot 341: an observing run kills nothing
    let c = stopped_child();
    let r = rig(vec![entry(&c, KILL_OWED)]);
    let swept = r.sweeper(false, capture()).sweep("test", None);
    assert_eq!(swept.resumed, vec![c.pid], "{swept:?}");
    assert!(swept.killed.is_empty());
    assert!(wait_state(c.pid, |s| s != Some('T')));
    assert!(r.journal.rows().is_empty());
}

#[test]
fn a_process_the_sweep_cannot_capture_stays_in_the_map_signed() {
    let c = stopped_child();
    let r = rig(vec![entry(&c, 1)]);
    let swept = r
        .sweeper(
            true,
            Box::new(|pid, start| ProcRef::uncaptured_for_test(pid, start, libc::EMFILE)),
        )
        .sweep("test", None);
    assert_eq!(swept.left, vec![c.pid], "{swept:?}");
    assert_eq!(r.entries().len(), 1, "the next start must find it");
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 1, "a process left stopped is signed: {a:?}");
    assert_eq!(a[0]["left"].as_array().unwrap().len(), 1, "{a:?}");
}

#[test]
fn a_process_that_ended_leaves_the_map_unsigned() {
    let c = stopped_child();
    let (pid, start_ns) = (c.pid, c.start_ns);
    drop(c);
    let r = rig(vec![(
        pid,
        ExecqStopped {
            start_ns,
            stop_ns: 1,
        },
    )]);
    let swept = r.sweeper(true, capture()).sweep("test", None);
    assert_eq!(swept.gone, 1, "{swept:?}");
    assert!(r.entries().is_empty());
    assert!(r.audits.0.lock().is_empty(), "nothing to sign");
}

#[test]
fn the_deadlines_sweep_resumes_and_leaves_an_owed_kill_for_the_next_start() {
    let held_one = stopped_child();
    let owed = stopped_child();
    let r = rig(vec![entry(&held_one, 1), entry(&owed, KILL_OWED)]);
    let swept = r
        .sweeper(true, capture())
        .sweep_at_exit()
        .expect("the maps' lock is free");
    assert_eq!(swept.resumed, vec![held_one.pid], "{swept:?}");
    assert_eq!(swept.kills_left, vec![owed.pid], "{swept:?}");
    assert!(wait_state(held_one.pid, |s| s != Some('T')));
    assert_eq!(state(owed.pid), Some('T'), "the deadline kills nothing");
    assert_eq!(r.entries(), vec![entry(&owed, KILL_OWED)]);
    assert_eq!(r.maps.0.lock().beat, 0);
    assert!(r.held.cleared());
    assert!(
        r.audits.0.lock().is_empty(),
        "the deadline's exit signs nothing"
    );
    assert!(r.journal.rows().is_empty());
}

#[test]
fn the_deadlines_sweep_waits_for_the_maps_a_bounded_time() {
    let r = rig(Vec::new());
    let sweeper = Arc::new(r.sweeper(true, capture()));
    let taken = Arc::new(AtomicBool::new(false));
    let (held, t2) = (Arc::clone(&r.held), Arc::clone(&taken));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _g = held.inner.lock();
        t2.store(true, Ordering::SeqCst);
        let _ = rx.recv_timeout(Duration::from_secs(5));
    });
    while !taken.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
    let t0 = std::time::Instant::now();
    assert!(sweeper.sweep_at_exit().is_none());
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    tx.send(()).unwrap();
    holder.join().unwrap();
}

#[test]
fn the_shared_maps_never_touch_the_entry_of_a_later_holder_of_the_pid() {
    // lot 317 (review F5, F2), moved to the shared maps by lot M4
    let later = ExecqStopped {
        start_ns: 8,
        stop_ns: 1,
    };
    let r = rig(vec![(42, later)]);
    r.held.unstop(42, 7);
    assert_eq!(r.entries(), vec![(42, later)], "an earlier holder's unstop");
    r.held.owe_kill(42, 7);
    assert_eq!(r.entries(), vec![(42, later)], "an earlier holder's kill");
    r.held.owe_kill(42, 8);
    assert_eq!(
        r.entries(),
        vec![(
            42,
            ExecqStopped {
                start_ns: 8,
                stop_ns: KILL_OWED
            }
        )]
    );
    r.held.unstop(42, 8);
    assert!(r.entries().is_empty());
}

/// A stop flag of a test's own, as the agent's `STOPPING` is.
fn stop_flag() -> &'static AtomicBool {
    Box::leak(Box::new(AtomicBool::new(false)))
}

/// A controller's thread that sees the stop and takes 20 ms for its own
/// before it ends.
fn stopping_thread(stop: &'static AtomicBool) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(20));
    })
}

#[test]
fn a_controller_that_stops_in_time_is_waited_for_then_the_sweep_runs() {
    let c = stopped_child();
    let r = rig(vec![entry(&c, 1)]);
    let sweeper = r.sweeper(true, capture());
    let stop = stop_flag();
    let woken = AtomicBool::new(false);
    let t0 = std::time::Instant::now();
    let running = stop_then_sweep(
        stop,
        || woken.store(true, Ordering::Relaxed),
        stopping_thread(stop),
        &sweeper,
        Duration::from_secs(5),
        None,
    );
    assert!(
        running.is_none(),
        "the controller's own stop was not waited for"
    );
    assert!(t0.elapsed() < Duration::from_secs(4), "{:?}", t0.elapsed());
    assert!(
        woken.load(Ordering::Relaxed),
        "the controller was not woken"
    );
    // what its own stop left, the sweep releases (here: all of it)
    assert!(wait_state(c.pid, |s| s != Some('T')));
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["by"], "sweep after the controller's stop", "{a:?}");
}

/// Mini-hunt of #633: the controller's thread ended before the stop (a
/// panic): its own stop never runs, and the stop's sweep releases what the
/// kernel holds.
#[test]
fn a_controller_that_ended_before_the_stop_leaves_its_held_processes_to_the_sweep() {
    let kids: Vec<Stopped> = (0..2).map(|_| stopped_child()).collect();
    let r = rig(kids.iter().map(|c| entry(c, 1)).collect());
    let sweeper = r.sweeper(true, capture());
    let dead = std::thread::spawn(|| {});
    while !dead.is_finished() {
        std::thread::sleep(Duration::from_millis(1));
    }
    let running = stop_then_sweep(
        stop_flag(),
        || {},
        dead,
        &sweeper,
        Duration::from_secs(1),
        None,
    );
    assert!(running.is_none());
    for c in &kids {
        assert!(
            wait_state(c.pid, |s| s != Some('T')),
            "{} left stopped",
            c.pid
        );
    }
    assert!(r.entries().is_empty());
    assert_eq!(r.maps.0.lock().beat, 0);
}

#[test]
fn the_deadlines_sweep_clears_the_heartbeat_and_waits_for_the_programs_before_it_reads() {
    let c = stopped_child();
    let r = rig(vec![entry(&c, 1)]);
    r.held.beat(5);
    r.maps.0.lock().log.clear();
    r.sweeper(true, capture())
        .sweep_at_exit()
        .expect("the maps' lock is free");
    let log = r.maps.0.lock().log.clone();
    assert_eq!(log[..3], ["beat 0", "quiesce", "read"], "{log:?}");
    assert!(wait_state(c.pid, |s| s != Some('T')));
}

// ── lot M7: the sweep signs what it has released by the stop's signing time ──

/// A capture that takes `ms` (a slow guest, a burst still running).
fn slow_capture(ms: u64) -> SweepCapture {
    Box::new(move |pid, start| {
        std::thread::sleep(Duration::from_millis(ms));
        ProcRef::open_started_at(pid, start)
    })
}

/// The pids an entry's field names, sorted.
fn pids(e: &serde_json::Value, field: &str) -> Vec<u32> {
    let mut v: Vec<u32> = e[field]
        .as_array()
        .unwrap_or_else(|| panic!("no `{field}` in {e}"))
        .iter()
        .map(|p| p.as_u64().unwrap() as u32)
        .collect();
    v.sort_unstable();
    v
}

/// Lot M7 (the nightly of 27/11, ubuntu 26.04): a sweep of more than
/// 1 000 held processes outlasted what the stop's deadline left it, the
/// deadline's exit resumed the last ones, and the audit chain named none
/// of the processes the stop had resumed — it signed only at its end. A
/// sweep still releasing at its signing time now signs what it has done
/// (the `first` part, the rest named `unfinished`) before it goes on, and
/// the rest at its end. On main the one entry is signed after the last
/// release.
#[test]
fn a_sweep_past_its_signing_time_signs_what_it_released_then_the_rest() {
    let kids: Vec<Stopped> = (0..4).map(|_| stopped_child()).collect();
    let r = rig(kids.iter().map(|c| entry(c, 1)).collect());
    let sign_by = std::time::Instant::now() + Duration::from_millis(60);
    let swept = r
        .sweeper(true, slow_capture(40))
        .sweep("test", Some(sign_by));
    let ended = std::time::Instant::now();
    assert_eq!(swept.resumed.len(), 4, "{swept:?}");
    for c in &kids {
        assert!(
            wait_state(c.pid, |s| s != Some('T')),
            "{} is still stopped after the sweep",
            c.pid
        );
    }
    assert!(r.entries().is_empty(), "{:?}", r.entries());
    let a = r.audits.0.lock().clone();
    let at = r.audits.1.lock().clone();
    assert_eq!(a.len(), 2, "a first part and the rest: {a:?}");
    assert_eq!(
        (a[0]["part"].as_str(), a[1]["part"].as_str()),
        (Some("first"), Some("rest")),
        "{a:?}"
    );
    assert!(
        a.iter()
            .all(|e| e["kind"] == "stopping" && e["by"] == "test")
    );
    // the first part: signed at the signing time, before the releases left
    assert!(at[0] >= sign_by, "signed before its time: {a:?}");
    assert!(
        ended.duration_since(at[0]) >= Duration::from_millis(40),
        "the first part was not signed before the sweep's last release ({:?} before its end)",
        ended.duration_since(at[0])
    );
    let (done, unfinished) = (pids(&a[0], "resumed"), pids(&a[0], "unfinished"));
    assert!(!done.is_empty() && !unfinished.is_empty(), "{a:?}");
    let mut named: Vec<u32> = done.iter().chain(&unfinished).copied().collect();
    named.sort_unstable();
    let mut all: Vec<u32> = kids.iter().map(|c| c.pid).collect();
    all.sort_unstable();
    assert_eq!(named, all, "the first part names each process once: {a:?}");
    // the rest: what the first part left unfinished, nothing more
    assert_eq!(pids(&a[1], "resumed"), unfinished, "{a:?}");
    assert!(pids(&a[1], "unfinished").is_empty(), "{a:?}");
    assert_eq!(pids(&a[1], "unreported"), unfinished, "{a:?}");
}

/// Lot M7: a signing time already past when the sweep begins (the stages
/// before it took what the deadline left): the first part is signed after
/// the first release.
#[test]
fn a_signing_time_already_past_signs_after_the_first_release() {
    let kids: Vec<Stopped> = (0..3).map(|_| stopped_child()).collect();
    let r = rig(kids.iter().map(|c| entry(c, 1)).collect());
    let swept = r
        .sweeper(true, capture())
        .sweep("test", Some(std::time::Instant::now()));
    assert_eq!(swept.resumed.len(), 3, "{swept:?}");
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(a[0]["part"], "first", "{a:?}");
    assert_eq!(pids(&a[0], "resumed").len(), 1, "{a:?}");
    assert_eq!(pids(&a[0], "unfinished").len(), 2, "{a:?}");
    assert_eq!(a[1]["part"], "rest", "{a:?}");
    assert_eq!(pids(&a[1], "resumed"), pids(&a[0], "unfinished"), "{a:?}");
}

/// Lot M7: a sweep that ends before its signing time signs once, as
/// before — the whole of it, nothing unfinished.
#[test]
fn a_sweep_that_ends_before_its_signing_time_signs_once() {
    let kids: Vec<Stopped> = (0..3).map(|_| stopped_child()).collect();
    let r = rig(kids.iter().map(|c| entry(c, 1)).collect());
    let swept = r.sweeper(true, capture()).sweep(
        "test",
        Some(std::time::Instant::now() + Duration::from_secs(60)),
    );
    assert_eq!(swept.resumed.len(), 3, "{swept:?}");
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["part"], "whole", "{a:?}");
    assert_eq!(pids(&a[0], "resumed").len(), 3, "{a:?}");
    assert!(pids(&a[0], "unfinished").is_empty(), "{a:?}");
}

/// Lot M7: the processes the first part left unfinished ended before the
/// sweep reached them — the rest is signed all the same (`gone`): the
/// chain tells what became of every process the first part named.
#[test]
fn a_rest_of_processes_that_ended_is_signed() {
    let first = stopped_child();
    let ended: Vec<(u32, ExecqStopped)> = (0..2)
        .map(|_| {
            let c = stopped_child();
            let e = entry(&c, 1);
            drop(c);
            e
        })
        .collect();
    let mut entries = vec![entry(&first, 1)];
    entries.extend(ended.iter().copied());
    let r = rig(entries);
    let swept = r
        .sweeper(true, capture())
        .sweep("test", Some(std::time::Instant::now()));
    assert_eq!((swept.resumed.len(), swept.gone), (1, 2), "{swept:?}");
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(pids(&a[0], "resumed"), vec![first.pid], "{a:?}");
    assert_eq!(pids(&a[0], "unfinished").len(), 2, "{a:?}");
    assert_eq!(a[1]["part"], "rest", "{a:?}");
    assert_eq!(a[1]["gone"], 2, "{a:?}");
    assert!(pids(&a[1], "resumed").is_empty(), "{a:?}");
}

/// Lot M7: the stop of a controller stuck in its pass — the bounded wait,
/// then the sweep, which signs by the stop's signing time and goes on; the
/// two parts are the sweep of a controller that did not stop.
#[test]
fn a_stuck_controllers_sweep_signs_by_the_stops_signing_time() {
    let kids: Vec<Stopped> = (0..3).map(|_| stopped_child()).collect();
    let r = rig(kids.iter().map(|c| entry(c, 1)).collect());
    let sweeper = r.sweeper(true, slow_capture(40));
    // a pass that does not end until the test lets it
    let unstick = Arc::new(AtomicBool::new(false));
    let u2 = Arc::clone(&unstick);
    let stuck = std::thread::spawn(move || {
        while !u2.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let t0 = std::time::Instant::now();
    let running = stop_then_sweep(
        stop_flag(),
        || {},
        stuck,
        &sweeper,
        Duration::from_millis(20),
        Some(t0 + Duration::from_millis(70)),
    );
    let ended = std::time::Instant::now();
    unstick.store(true, Ordering::Relaxed);
    running
        .expect("the stuck controller's handle")
        .join()
        .unwrap();
    for c in &kids {
        assert!(
            wait_state(c.pid, |s| s != Some('T')),
            "{} left stopped",
            c.pid
        );
    }
    let a = r.audits.0.lock().clone();
    let at = r.audits.1.lock().clone();
    assert_eq!(a.len(), 2, "{a:?}");
    assert!(
        a.iter()
            .all(|e| e["by"] == "sweep: the controller did not stop in time"),
        "{a:?}"
    );
    assert_eq!(a[0]["part"], "first", "{a:?}");
    assert!(
        ended.duration_since(at[0]) >= Duration::from_millis(40),
        "the first part was not signed before the sweep's last release: {a:?}"
    );
    let mut resumed: Vec<u32> = pids(&a[0], "resumed");
    resumed.extend(pids(&a[1], "resumed"));
    resumed.sort_unstable();
    let mut all: Vec<u32> = kids.iter().map(|c| c.pid).collect();
    all.sort_unstable();
    assert_eq!(resumed, all, "{a:?}");
}

/// Lot M7: a sweep's last release past the signing time leaves nothing
/// unfinished — one entry, the whole sweep.
#[test]
fn a_last_release_past_the_signing_time_signs_once() {
    let c = stopped_child();
    let r = rig(vec![entry(&c, 1)]);
    let swept = r
        .sweeper(true, capture())
        .sweep("test", Some(std::time::Instant::now()));
    assert_eq!(swept.resumed, vec![c.pid], "{swept:?}");
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["part"], "whole", "{a:?}");
    assert!(pids(&a[0], "unfinished").is_empty(), "{a:?}");
}

/// Lot M7: each part names only what it did — a kill, a process left in
/// the map, a process that ended, before the first part is signed, are in
/// the first part and not in the rest.
#[test]
fn each_part_of_a_sweep_names_only_what_it_did() {
    // the kill the map owes, then a process to resume
    let owed = stopped_child();
    let other = stopped_child();
    let r = rig(vec![entry(&owed, KILL_OWED), entry(&other, 1)]);
    r.sweeper(true, capture())
        .sweep("test", Some(std::time::Instant::now()));
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(pids(&a[0], "killed"), vec![owed.pid], "{a:?}");
    assert!(pids(&a[1], "killed").is_empty(), "{a:?}");
    assert_eq!(pids(&a[1], "resumed"), vec![other.pid], "{a:?}");
    // a process the sweep cannot capture, then one to resume
    let stuck = stopped_child();
    let other = stopped_child();
    let r = rig(vec![entry(&stuck, 1), entry(&other, 1)]);
    let not = stuck.pid;
    r.sweeper(
        true,
        Box::new(move |pid, start| {
            if pid == not {
                ProcRef::uncaptured_for_test(pid, start, libc::EMFILE)
            } else {
                ProcRef::open_started_at(pid, start)
            }
        }),
    )
    .sweep("test", Some(std::time::Instant::now()));
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(pids(&a[0], "left"), vec![stuck.pid], "{a:?}");
    assert!(pids(&a[1], "left").is_empty(), "{a:?}");
    assert_eq!(
        r.entries(),
        vec![entry(&stuck, 1)],
        "left for the next start"
    );
    // a process that ended, then one to resume
    let ended = {
        let c = stopped_child();
        let e = entry(&c, 1);
        drop(c);
        e
    };
    let other = stopped_child();
    let r = rig(vec![ended, entry(&other, 1)]);
    r.sweeper(true, capture())
        .sweep("test", Some(std::time::Instant::now()));
    let a = r.audits.0.lock().clone();
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(
        (&a[0]["gone"], &a[1]["gone"]),
        (&1.into(), &0.into()),
        "{a:?}"
    );
    assert_eq!(pids(&a[1], "resumed"), vec![other.pid], "{a:?}");
}

/// Lot M7: the signing time is [`SIGN_MARGIN`] before the deadline's
/// note, at once when less is left; the margin fits in the part of the
/// stop's budget kept for its signed rows.
#[test]
fn the_signing_time_is_the_margin_before_the_note() {
    let now = std::time::Instant::now();
    assert_eq!(
        signing_time(now, Duration::from_millis(800)),
        now + Duration::from_millis(600)
    );
    assert_eq!(signing_time(now, SIGN_MARGIN), now);
    assert_eq!(signing_time(now, Duration::from_millis(50)), now);
    assert_eq!(signing_time(now, Duration::ZERO), now);
    let evidence = crate::stop_deadline::BUDGET.evidence;
    assert!(
        SIGN_MARGIN > Duration::ZERO && SIGN_MARGIN < evidence,
        "{SIGN_MARGIN:?} outside (0, {evidence:?})"
    );
}
