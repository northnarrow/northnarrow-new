//! The event pipeline (Wave 4 restructure, R11a, lab PR 261: from
//! `main.rs`): `process_event`, and what it shares with the start's tasks —
//! whether systemd is stopping the host.

use std::time::{Duration, Instant};

use tracing::{debug, warn};

pub(crate) mod process_event;

/// External audit EBPF-001: systemd (PID 1 itself, `SO_PEERCRED`) reported
/// the host as stopping — no posture escalation and no ladder until the
/// process ends at systemd-shutdown's final stage. R11c (lab PR 264): the
/// flag the ladder phase makes and hands to its tick, the shutdown watch
/// and the event loop (it was a process-wide `HOST_STOPPING`). Clones
/// share it.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostStopping(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl HostStopping {
    /// The host is shutting down: stand the ladder down once and stop
    /// escalating.
    pub(crate) fn stand_down(&self, ladder: &northnarrow_agent::combat::CombatLadder) {
        if !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
            warn!("host shutting down — active response stood down, detection continues");
            ladder.stand_down(Instant::now());
        }
    }

    /// Whether systemd reported the host as stopping.
    pub(crate) fn is_stopping(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// What systemd reports the host as (`SystemState`: `running`,
/// `degraded`, `stopping`, …), asked over its private socket from this
/// process ([`northnarrow_agent::systemd_state`]) — by the systemd watch
/// every 2 s, and when the decision wants a newer answer than its snapshot
/// holds ([`SystemdSnapshot`], fresh a second: at most about one question
/// a second). `None` when systemd does not answer within 1 s, or the socket
/// is not served by PID 1. R12b: the snapshot is the answer kept (the
/// process-wide cache of the event loop's own question is gone).
pub(crate) async fn systemd_state() -> Option<String> {
    let ask = tokio::task::spawn_blocking(|| {
        northnarrow_agent::systemd_state::system_state(
            std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET),
            Duration::from_millis(800),
        )
    });
    match tokio::time::timeout(Duration::from_secs(1), ask).await {
        Ok(Ok(Ok(state))) => Some(state),
        Ok(Ok(Err(e))) => {
            debug!(error = %e, "systemd's state could not be read");
            None
        }
        _ => None,
    }
}

/// How old an answer of systemd the decision judges a signal PID 1 relayed
/// on (the cache the event loop's own question kept until R12b).
pub(crate) const SYSTEMD_FRESH: Duration = Duration::from_secs(1);
/// The relayed signals the decision hands to the watch at most at once.
const DEFERRED_MAX: usize = 64;

/// R12b (lab PR 269, plan §3.4): systemd's state as a snapshot the decision
/// reads without waiting — a signal PID 1 relayed and the kernel refused
/// is expected while systemd stops the host (external audit EBPF-001), an
/// attempt otherwise. The decision asked systemd itself until R12b,
/// awaiting the answer up to a second in the event loop.
///
/// The systemd watch ([`systemd_watch`]) refreshes it every 2 s. A relayed
/// signal judged on an answer older than [`SYSTEMD_FRESH`] is handed to the
/// watch instead ([`Self::judge`] → [`SystemdAnswer::Deferred`]), which asks
/// systemd at once and hands it back answered ([`Self::take_answered`]):
/// the decision thread judges it at its next turn (within its idle wait,
/// half a second) on the new answer — once; handed back a second time it is
/// judged on what the snapshot holds. Not through the bus: a denial sent
/// again would be coalesced into the one already judged, or capped. Without
/// a watch (no systemd socket) nothing is handed over: the answer is
/// "none", as the question's was.
#[derive(Clone, Default)]
pub(crate) struct SystemdSnapshot(std::sync::Arc<SnapshotInner>);

#[derive(Default)]
struct SnapshotInner {
    /// The last answer and when it was asked.
    last: parking_lot::Mutex<Option<(Instant, Option<String>)>>,
    /// The watch runs and serves deferrals.
    watched: std::sync::atomic::AtomicBool,
    /// The decision wants a newer answer.
    wanted: tokio::sync::Notify,
    /// Signals handed to the watch, to hand back once it asked.
    deferred: parking_lot::Mutex<Vec<nn_model::Event>>,
    /// The ones it handed back, answered, for the decision thread.
    answered: parking_lot::Mutex<Vec<nn_model::Event>>,
    /// Their identities (record's time and target): judged on the snapshot
    /// as it is when they come back, never handed over again.
    handed: parking_lot::Mutex<std::collections::HashSet<(u64, u64, u64)>>,
}

/// What the decision judges a relayed signal on ([`SystemdSnapshot::judge`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SystemdAnswer {
    /// systemd's answer (`None`: it did not answer).
    Judge(Option<String>),
    /// Handed to the watch: it comes back on the bus.
    Deferred,
}

impl SystemdSnapshot {
    /// The answer for the relayed signal `event` at `now`: a fresh one,
    /// else — the watch running, the event not handed over before, room
    /// for it — [`SystemdAnswer::Deferred`], else the latest answer.
    pub(crate) fn judge(&self, event: &nn_model::Event, now: Instant) -> SystemdAnswer {
        let last = self.0.last.lock().clone();
        if let Some((at, state)) = &last {
            if now.saturating_duration_since(*at) < SYSTEMD_FRESH {
                return SystemdAnswer::Judge(state.clone());
            }
        }
        let latest = || SystemdAnswer::Judge(last.clone().and_then(|(_, s)| s));
        let key = signal_key(event);
        if self.0.handed.lock().remove(&key) {
            return latest();
        }
        if !self.0.watched.load(std::sync::atomic::Ordering::Acquire) {
            return latest();
        }
        {
            let mut deferred = self.0.deferred.lock();
            if deferred.len() >= DEFERRED_MAX {
                return latest();
            }
            deferred.push(event.clone());
        }
        self.0.wanted.notify_one();
        SystemdAnswer::Deferred
    }

    /// The signals the watch handed back answered, for the decision thread
    /// to judge (each once).
    pub(crate) fn take_answered(&self) -> Vec<nn_model::Event> {
        std::mem::take(&mut *self.0.answered.lock())
    }

    /// Store an answer asked at `at`.
    fn store(&self, at: Instant, state: Option<String>) {
        *self.0.last.lock() = Some((at, state));
    }
}

/// A relayed signal's identity: its record's time, signal and target.
fn signal_key(event: &nn_model::Event) -> (u64, u64, u64) {
    match event {
        nn_model::Event::FsProtectDenial {
            timestamp_ns,
            target_dev,
            target_ino,
            ..
        } => (*timestamp_ns, *target_dev, *target_ino),
        _ => (0, 0, 0),
    }
}

/// External audit EBPF-001, R12b: the systemd watch — every 2 s, and when
/// the decision asks, systemd's state into the snapshot; once systemd
/// stops the host, the ladder stood down (the shutdown's own traffic must
/// not drive the posture or the ladder); the relayed signals the decision
/// handed over handed back answered.
pub(crate) async fn systemd_watch(
    snapshot: SystemdSnapshot,
    stopping: HostStopping,
    ladder: std::sync::Arc<northnarrow_agent::combat::CombatLadder>,
) {
    watch_with(snapshot, Duration::from_secs(2), systemd_state, || {
        stopping.stand_down(&ladder)
    })
    .await
}

/// [`systemd_watch`]'s loop: every `every`, and when the decision wants a
/// newer answer, `ask` into the snapshot; `stopping` when the answer is
/// that systemd stops the host; the deferred signals sent back after the
/// answer.
async fn watch_with<F, Fut>(snapshot: SystemdSnapshot, every: Duration, ask: F, stopping: impl Fn())
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    snapshot
        .0
        .watched
        .store(true, std::sync::atomic::Ordering::Release);
    let mut tick = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = snapshot.0.wanted.notified() => {}
        }
        let asked = Instant::now();
        let state = ask().await;
        snapshot.store(asked, state.clone());
        if state.as_deref() == Some("stopping") {
            stopping();
        }
        let back: Vec<nn_model::Event> = std::mem::take(&mut *snapshot.0.deferred.lock());
        if back.is_empty() {
            continue;
        }
        {
            let mut handed = snapshot.0.handed.lock();
            for event in &back {
                handed.insert(signal_key(event));
            }
        }
        snapshot.0.answered.lock().extend(back);
    }
}

/// PID 1 is `systemd-shutdown` (its comm, truncated to 15 bytes): the
/// machine is in the last stage of a shutdown.
pub(crate) fn pid1_is_systemd_shutdown() -> bool {
    std::fs::read_to_string("/proc/1/comm").is_ok_and(|c| c.trim_end() == "systemd-shutdow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relayed(ts: u64) -> nn_model::Event {
        nn_model::Event::FsProtectDenial {
            pid: 1,
            uid: 0,
            comm: "systemd".into(),
            target_dev: 15,
            target_ino: 4242,
            operation: nn_model::FsProtectOperation::Signal,
            timestamp_ns: ts,
        }
    }

    /// R12b (lab PR 269): a fresh answer (under a second) judges the
    /// relayed signal at once; an older one hands it to the watch — once:
    /// handed back, it is judged on what the snapshot holds; without a
    /// watch nothing is handed over (no answer: "none", as the question's).
    #[test]
    fn a_relayed_signal_is_judged_on_a_fresh_answer_or_handed_to_the_watch() {
        let snap = SystemdSnapshot::default();
        let t0 = Instant::now();
        // no watch: the latest answer (none yet)
        assert_eq!(snap.judge(&relayed(1), t0), SystemdAnswer::Judge(None));
        snap.store(t0, Some("stopping".into()));
        assert_eq!(
            snap.judge(&relayed(1), t0 + Duration::from_millis(999)),
            SystemdAnswer::Judge(Some("stopping".into())),
            "fresh"
        );
        let later = t0 + SYSTEMD_FRESH;
        assert_eq!(
            snap.judge(&relayed(1), later),
            SystemdAnswer::Judge(Some("stopping".into())),
            "stale, but no watch to ask: the latest"
        );
        // a watch: handed over, once
        snap.0
            .watched
            .store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(snap.judge(&relayed(2), later), SystemdAnswer::Deferred);
        assert_eq!(snap.0.deferred.lock().len(), 1);
        // the watch sent it back: judged on the snapshot as it is then
        let back = std::mem::take(&mut *snap.0.deferred.lock());
        for e in &back {
            snap.0.handed.lock().insert(signal_key(e));
        }
        assert_eq!(
            snap.judge(&relayed(2), later + Duration::from_secs(5)),
            SystemdAnswer::Judge(Some("stopping".into())),
            "handed back: not handed again"
        );
        assert!(snap.0.handed.lock().is_empty());
        // bounded: past DEFERRED_MAX the decision judges on the latest
        for i in 0..DEFERRED_MAX as u64 {
            assert_eq!(
                snap.judge(&relayed(100 + i), later),
                SystemdAnswer::Deferred
            );
        }
        assert_eq!(
            snap.judge(&relayed(999), later),
            SystemdAnswer::Judge(Some("stopping".into()))
        );
    }

    /// R12b: the watch asks systemd when the decision wants a newer answer
    /// — not only at its tick — hands the signals back answered (for the
    /// decision thread, each once, never handed over again), and stands the
    /// ladder down once the answer is "stopping".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_watch_answers_the_decision_and_hands_the_signal_back() {
        let snap = SystemdSnapshot::default();
        let answer = std::sync::Arc::new(parking_lot::Mutex::new(Some("running".to_string())));
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stood_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watch = {
            let (snap, answer, asked, stood_down) = (
                snap.clone(),
                std::sync::Arc::clone(&answer),
                std::sync::Arc::clone(&asked),
                std::sync::Arc::clone(&stood_down),
            );
            tokio::spawn(async move {
                watch_with(
                    snap,
                    Duration::from_secs(3600),
                    move || {
                        asked.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        let a = answer.lock().clone();
                        async move { a }
                    },
                    move || stood_down.store(true, std::sync::atomic::Ordering::Release),
                )
                .await
            })
        };
        // the first tick's answer
        while asked.load(std::sync::atomic::Ordering::Acquire) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        // an hour's tick: a stale answer makes the decision ask
        snap.store(
            Instant::now() - Duration::from_secs(10),
            Some("running".into()),
        );
        *answer.lock() = Some("stopping".into());
        assert_eq!(
            snap.judge(&relayed(7), Instant::now()),
            SystemdAnswer::Deferred
        );
        let started = Instant::now();
        let back = loop {
            let answered = snap.take_answered();
            if !answered.is_empty() {
                break answered;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "handed back");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(back.len(), 1);
        assert!(matches!(
            back[0],
            nn_model::Event::FsProtectDenial {
                timestamp_ns: 7,
                ..
            }
        ));
        assert!(snap.take_answered().is_empty(), "taken once");
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::Acquire),
            2,
            "asked at once"
        );
        assert_eq!(
            snap.judge(&back[0], Instant::now() + Duration::from_secs(5)),
            SystemdAnswer::Judge(Some("stopping".into())),
            "judged on the watch's answer, even late; not handed over again"
        );
        assert!(
            stood_down.load(std::sync::atomic::Ordering::Acquire),
            "the ladder stood down"
        );
        watch.abort();
    }
}
