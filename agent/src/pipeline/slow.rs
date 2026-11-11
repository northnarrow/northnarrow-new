//! Wave 4 restructure, R12c (lab PR 270; EVENT_BUS.md §2d): the dispatcher
//! of slow work — the ransomware tracker's I/O off the decision thread.
//!
//! A mass-write or rename/unlink burst is judged on what the burst left
//! behind and on who wrote it: the tracker samples the burst's files
//! (their entropy, the copies beside the deleted originals) and judges the
//! writer's trust (its executable's package, its lineage's). Until R12c the
//! decision thread did that I/O in the judgement. Now, when the decision
//! thread takes a burst whose assessment is not prepared, it hands the
//! event to this thread ([`SlowWork::defer`]: a queue push) and takes the
//! next event; the thread prepares the assessment
//! (`RansomTracker::prepare`, with its I/O), queues the event back and
//! wakes the decision's wait ([`BusWaker`]); the decision thread memoises
//! the assessment (`RansomTracker::prime`) and judges the event at its next
//! turn — the posture and the rules read the prepared answer, as they read
//! the memoised one before.
//!
//! The bursts are prepared in the order the decision took them (one
//! thread, FIFO): an actor's window of shapes adds them up in the bus's
//! order of the file class, as before. A burst is judged later than the
//! events taken after it while it is prepared (milliseconds: at most four
//! files of 64 KiB read, a package database looked up); every lookup of
//! the lineage is as of the burst's own time (R-F), so what came between
//! changes nothing there. A full queue ([`SLOW_QUEUE_CAP`]) leaves the
//! burst to the decision thread, which judges it with its I/O (counted:
//! `inline`, WARNed) — never dropped.
//!
//! Lot 317 (third bug hunt, BUG-116 and BUG-115): at the stop the thread
//! prepares nothing more — it ended after preparing the whole inbox, up to
//! [`SLOW_QUEUE_CAP`] bursts with their I/O, inside the stop's budget, and
//! the stop then threw the assessments away and the decision thread judged
//! the same bursts again with their I/O. What it prepared goes back with its
//! assessment, the rest unprepared. Nothing it was handed is ever dropped:
//! an event it has no assessment for goes back without one. And no
//! `catch_unwind` around the preparation: the agent's release build aborts
//! on a panic (`panic = "abort"`, the watchdog restarts it, as for a panic
//! on the decision thread), so the fallback it guarded lived only in
//! unwinding builds — where it lost the event and said it was judged.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_model::Event;
use northnarrow_agent::impact::{Assessment, RansomTracker};
use northnarrow_agent::sensors::bus::BusWaker;
use parking_lot::{Condvar, Mutex};
use tracing::{error, warn};

/// Bursts waiting to be prepared at most.
pub(crate) const SLOW_QUEUE_CAP: usize = 256;

/// An event handed back to the decision thread, with the assessment
/// prepared for it (`None`: unprepared — the stop came first, or the event
/// is no burst). The decision memoises the assessment
/// (`RansomTracker::prime`) right before it judges the event.
pub(crate) type Prepared = (Event, Option<Arc<Assessment>>);

struct Shared {
    tracker: Arc<RansomTracker>,
    inbox: Mutex<VecDeque<(Instant, Event)>>,
    /// Each event handed over, in order, with its assessment (`None`: an
    /// event the tracker has none for).
    ready: Mutex<VecDeque<Prepared>>,
    wake_thread: Condvar,
    waker: Option<BusWaker>,
    stop: AtomicBool,
    /// Bursts deferred, and the longest from defer to ready (µs).
    deferred: AtomicU64,
    wait_max_us: AtomicU64,
    /// A full queue (or no thread) left the burst to the decision thread.
    full: AtomicU64,
}

/// The dispatcher of slow work (see the module's doc).
pub(crate) struct SlowWork {
    shared: Arc<Shared>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SlowWork {
    /// Start its thread (`nn-slow-work`); `waker` ends the decision's wait
    /// when an event is ready.
    pub(crate) fn start(tracker: Arc<RansomTracker>, waker: Option<BusWaker>) -> Self {
        let shared = Arc::new(Shared {
            tracker,
            inbox: Mutex::new(VecDeque::new()),
            ready: Mutex::new(VecDeque::new()),
            wake_thread: Condvar::new(),
            waker,
            stop: AtomicBool::new(false),
            deferred: AtomicU64::new(0),
            wait_max_us: AtomicU64::new(0),
            full: AtomicU64::new(0),
        });
        let thread = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("nn-slow-work".into())
                .spawn(move || {
                    // review of #482 (R14c-4): the core's set, whoever starts it
                    nn_linux::caps::restore_core();
                    run(&shared)
                })
        };
        let thread = match thread {
            Ok(t) => Some(t),
            Err(e) => {
                error!(
                    error = %e,
                    "the dispatcher of slow work did not start — the decision thread judges the \
                     ransomware bursts with their I/O"
                );
                None
            }
        };
        Self {
            shared,
            thread: Mutex::new(thread),
        }
    }

    /// The tracker whose assessments it prepares.
    pub(crate) fn tracker(&self) -> &RansomTracker {
        &self.shared.tracker
    }

    /// The decision thread: `event` is a burst whose assessment is not
    /// prepared — hand it over and judge the next event. `Err(event)`: the
    /// queue is full or the thread is not running — the caller judges it
    /// now (counted). Lot 317: a thread that has ended (a panic in an
    /// unwinding build) is not running.
    pub(crate) fn defer(&self, event: Event) -> Result<(), Box<Event>> {
        let s = &self.shared;
        let running = self
            .thread
            .lock()
            .as_ref()
            .is_some_and(|t| !t.is_finished())
            && !s.stop.load(Ordering::Acquire);
        {
            let mut q = s.inbox.lock();
            if running && q.len() < SLOW_QUEUE_CAP {
                q.push_back((Instant::now(), event));
                s.deferred.fetch_add(1, Ordering::Relaxed);
                drop(q);
                s.wake_thread.notify_one();
                return Ok(());
            }
        }
        let n = s.full.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            warn!(
                total = n,
                "dispatcher of slow work full (or not running): a ransomware burst is judged on \
                 the decision thread with its I/O"
            );
        }
        Err(Box::new(event))
    }

    /// The decision thread: the bursts prepared since its last turn, in
    /// order, each with its assessment (`None` for an event the tracker has
    /// none for).
    pub(crate) fn take_ready(&self) -> Vec<Prepared> {
        let mut r = self.shared.ready.lock();
        if r.is_empty() {
            return Vec::new();
        }
        r.drain(..).collect()
    }

    /// The decision thread, right before it judges an event handed back
    /// ([`Self::take_ready`], [`Self::stop`]): its assessment, when one was
    /// prepared, memoised (`RansomTracker::prime`); the event to judge.
    pub(crate) fn primed(&self, (event, a): Prepared) -> Event {
        if let Some(a) = a {
            self.shared.tracker.prime(&event, a);
        }
        event
    }

    /// Bursts deferred, the longest preparation (µs), and those the
    /// decision judged itself (a full queue).
    pub(crate) fn counts(&self) -> (u64, u64, u64) {
        let s = &self.shared;
        (
            s.deferred.load(Ordering::Relaxed),
            s.wait_max_us.load(Ordering::Relaxed),
            s.full.load(Ordering::Relaxed),
        )
    }

    /// The stop: the thread ends after the burst it prepares; the bursts
    /// it prepared come back with their assessment, the bursts still
    /// waiting unprepared (the caller primes the first, then judges each).
    /// Lot 317 (BUG-116): the prepared ones kept their events only — the
    /// decision judged them again with their I/O.
    pub(crate) fn stop(&self) -> Vec<Prepared> {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake_thread.notify_all();
        if let Some(t) = self.thread.lock().take() {
            if t.join().is_err() {
                error!("the dispatcher of slow work panicked");
            }
        }
        let mut left = self.take_ready();
        left.extend(self.shared.inbox.lock().drain(..).map(|(_, e)| (e, None)));
        let (deferred, wait_max_us, full) = self.counts();
        tracing::info!(
            deferred,
            wait_max_us,
            judged_on_the_decision_thread = full,
            left = left.len(),
            "dispatcher of slow work stopped (the bursts left are judged at the stop)"
        );
        left
    }
}

fn run(s: &Shared) {
    loop {
        let (at, event) = {
            let mut q = s.inbox.lock();
            loop {
                // lot 317 (BUG-116): the stop before the next burst — those
                // still waiting go back unprepared
                if s.stop.load(Ordering::Acquire) {
                    return;
                }
                if let Some(x) = q.pop_front() {
                    break x;
                }
                let _ = s.wake_thread.wait_for(&mut q, Duration::from_millis(500));
            }
        };
        // lot 317 (BUG-115): no catch_unwind — see the module's doc
        let prepared = s.tracker.prepare(&event);
        s.wait_max_us
            .fetch_max(at.elapsed().as_micros() as u64, Ordering::Relaxed);
        // an event with no assessment goes back as it came: never dropped
        s.ready.lock().push_back((event, prepared));
        if let Some(w) = &s.waker {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn burst(pid: u32, ts: u64) -> Event {
        Event::FileBurst {
            pid,
            uid: 1000,
            comm: "enc".to_string(),
            kind: nn_model::FileBurstKind::Unlink,
            count: 20,
            appended: 0,
            sources: 0,
            filename: "/srv/data/a.pdf".to_string(),
            timestamp_ns: ts,
            cgroup_id: 0,
            own_data: 0,
        }
    }

    /// A burst handed over comes back prepared, in order; once primed the
    /// tracker answers the judgement from the memo — nothing judged inline.
    #[test]
    fn a_burst_is_prepared_off_the_decision_thread_then_primed() {
        let tmp = tempfile::tempdir().unwrap();
        let lineage = northnarrow_agent::posture::lineage::AuthSessionTracker::new(tmp.path());
        let tracker = Arc::new(RansomTracker::new(lineage));
        let slow = SlowWork::start(Arc::clone(&tracker), None);
        let (a, b) = (burst(4242, 10), burst(4243, 20));
        assert!(slow.tracker().needs_preparing(&a));
        slow.defer(a.clone()).unwrap();
        slow.defer(b.clone()).unwrap();
        let started = Instant::now();
        let mut got = Vec::new();
        while got.len() < 2 {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "prepared in time"
            );
            got.extend(slow.take_ready());
            std::thread::sleep(Duration::from_millis(1));
        }
        let pid_of = |e: &Event| match e {
            Event::FileBurst { pid, .. } => *pid,
            _ => 0,
        };
        assert_eq!(pid_of(&got[0].0), pid_of(&a), "in order");
        assert_eq!(pid_of(&got[1].0), pid_of(&b));
        for (e, prepared) in got {
            let prepared = prepared.expect("a burst comes back prepared");
            tracker.prime(&e, Arc::clone(&prepared));
            assert!(!tracker.needs_preparing(&e));
            let judged = tracker.assess(&e).unwrap();
            assert!(
                Arc::ptr_eq(&judged, &prepared),
                "the prepared answer is the judgement's"
            );
        }
        let c = tracker.counts();
        assert_eq!((c.prepared, c.inline), (2, 0));
        assert!(slow.stop().is_empty());
        // stopped: the decision judges it itself
        assert!(slow.defer(burst(1, 30)).is_err());
        assert_eq!(slow.counts().2, 1);
    }

    /// A prepared burst ends the decision's wait on the bus at once (the
    /// waker), not at its next idle round.
    #[test]
    fn a_prepared_burst_wakes_the_decision() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_tx, mut rx) = northnarrow_agent::sensors::bus::channel();
        let tmp = tempfile::tempdir().unwrap();
        let lineage = northnarrow_agent::posture::lineage::AuthSessionTracker::new(tmp.path());
        let tracker = Arc::new(RansomTracker::new(lineage));
        let slow = SlowWork::start(tracker, Some(rx.waker()));
        slow.defer(burst(4242, 10)).unwrap();
        let started = Instant::now();
        let got = rx.recv_blocking(rt.handle(), None, Duration::from_secs(20));
        assert!(
            matches!(got, northnarrow_agent::sensors::bus::Recv::Idle),
            "woken, no event"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(slow.take_ready().len(), 1);
        slow.stop();
    }

    // ── lot 317 (bug hunt 1.4): BUG-116, BUG-115 ─────────────────────

    fn shared(tracker: Arc<RansomTracker>, stop: bool) -> Shared {
        Shared {
            tracker,
            inbox: Mutex::new(VecDeque::new()),
            ready: Mutex::new(VecDeque::new()),
            wake_thread: Condvar::new(),
            waker: None,
            stop: AtomicBool::new(stop),
            deferred: AtomicU64::new(0),
            wait_max_us: AtomicU64::new(0),
            full: AtomicU64::new(0),
        }
    }

    fn tracker() -> (tempfile::TempDir, Arc<RansomTracker>) {
        let tmp = tempfile::tempdir().unwrap();
        let lineage = northnarrow_agent::posture::lineage::AuthSessionTracker::new(tmp.path());
        (tmp, Arc::new(RansomTracker::new(lineage)))
    }

    /// BUG-116: `stop` promises "the thread ends after the burst it
    /// prepares; the bursts still waiting are handed back unprepared". The
    /// stop is set before the thread takes any of the 40 waiting bursts: it
    /// prepares none of them. On main it prepared all 40 (their I/O inside
    /// the stop's budget), then the stop threw the 40 assessments away.
    #[test]
    fn after_the_stop_the_waiting_bursts_are_not_prepared() {
        let (_tmp, tracker) = tracker();
        let shared = shared(Arc::clone(&tracker), true);
        for pid in 0..40u32 {
            shared
                .inbox
                .lock()
                .push_back((Instant::now(), burst(10_000 + pid, u64::from(pid) + 1)));
        }
        // the thread's loop, here: it must return at once
        run(&shared);
        assert_eq!(
            tracker.counts().prepared,
            0,
            "the stopped dispatcher prepared the whole inbox ({} left waiting, {} made ready \
             and then discarded by stop())",
            shared.inbox.lock().len(),
            shared.ready.lock().len()
        );
        assert_eq!(shared.inbox.lock().len(), 40, "handed back unprepared");
    }

    /// BUG-116: a burst prepared before the stop comes back with its
    /// assessment, and the decision judges it on that one — not again with
    /// its I/O (on main the stop kept the event only: `inline` 1).
    #[test]
    fn the_stop_hands_back_what_was_prepared_with_its_assessment() {
        let (_tmp, tracker) = tracker();
        let slow = SlowWork::start(Arc::clone(&tracker), None);
        let a = burst(4242, 10);
        slow.defer(a.clone()).unwrap();
        let started = Instant::now();
        while slow.shared.ready.lock().is_empty() {
            assert!(started.elapsed() < Duration::from_secs(10), "prepared");
            std::thread::sleep(Duration::from_millis(1));
        }
        let left = slow.stop();
        assert_eq!(left.len(), 1);
        assert!(left[0].1.is_some(), "its assessment was thrown away");
        for x in left {
            let e = slow.primed(x);
            assert!(!tracker.needs_preparing(&e));
            tracker.assess(&e).unwrap();
        }
        let c = tracker.counts();
        assert_eq!((c.prepared, c.inline), (1, 0), "judged twice");
    }

    /// BUG-115 (the minor branch beside it): nothing handed to the thread is
    /// dropped — an event the tracker has no assessment for (no burst)
    /// comes back without one, to be judged (on main: `continue`, lost).
    #[test]
    fn an_event_without_an_assessment_comes_back() {
        let (_tmp, tracker) = tracker();
        let slow = SlowWork::start(Arc::clone(&tracker), None);
        let e = Event::DefenderSignal {
            pid: 4242,
            uid: 0,
            comm: "kill".into(),
            target_pid: 1,
            signal: 19,
            timestamp_ns: 5,
        };
        slow.defer(e).unwrap();
        let started = Instant::now();
        let mut got = Vec::new();
        while got.is_empty() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the event was dropped"
            );
            got.extend(slow.take_ready());
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(got[0].0, Event::DefenderSignal { pid: 4242, .. }));
        assert!(got[0].1.is_none());
        assert!(slow.stop().is_empty());
    }

    /// BUG-115: a dispatcher whose thread has ended (a panic, in a build
    /// that unwinds) is not running: the decision judges the burst itself
    /// instead of handing it to a queue nobody reads.
    #[test]
    fn a_dispatcher_whose_thread_ended_takes_nothing() {
        let (_tmp, tracker) = tracker();
        let slow = SlowWork::start(tracker, None);
        let ended = std::thread::spawn(|| {});
        while !ended.is_finished() {
            std::thread::sleep(Duration::from_millis(1));
        }
        // the running thread put aside (stopped, so it ends) for one that ended
        let running = slow.thread.lock().replace(ended);
        assert!(slow.defer(burst(1, 1)).is_err(), "queued for a dead thread");
        assert_eq!(slow.counts().2, 1);
        slow.shared.stop.store(true, Ordering::Release);
        slow.shared.wake_thread.notify_all();
        running.unwrap().join().unwrap();
    }
}
