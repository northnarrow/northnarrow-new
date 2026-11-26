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

#[derive(Clone, Default)]
struct Audits(Arc<Mutex<Vec<serde_json::Value>>>);

impl Recorder for Audits {
    fn detection(&self, _rec: ExecqRecord) {}
    fn audit(&self, extra: serde_json::Value, _result: &str) {
        self.0.lock().push(extra);
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
            Some(self.journal.clone()),
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
    let swept = r.sweeper(true, capture()).sweep("test");
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
}

#[test]
fn the_sweep_reads_the_map_again_until_it_names_nothing_new() {
    let first = stopped_child();
    let late = stopped_child();
    let r = rig(vec![entry(&first, 1)]);
    r.maps.0.lock().late = Some(entry(&late, 2));
    let swept = r.sweeper(true, capture()).sweep("test");
    assert_eq!(swept.resumed.len(), 2, "{swept:?}");
    assert!(wait_state(late.pid, |s| s != Some('T')));
    assert!(r.entries().is_empty());
}

#[test]
fn the_sweep_kills_a_kill_the_map_owes_with_its_signed_intent() {
    let c = stopped_child();
    let r = rig(vec![entry(&c, KILL_OWED)]);
    let swept = r.sweeper(true, capture()).sweep("test");
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
    let swept = r.sweeper(false, capture()).sweep("test");
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
        .sweep("test");
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
    let swept = r.sweeper(true, capture()).sweep("test");
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
    let running = stop_then_sweep(stop_flag(), || {}, dead, &sweeper, Duration::from_secs(1));
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
