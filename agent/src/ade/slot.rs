//! External audit LLMR-002: ADE evaluations run off the event loop, one
//! at a time.
//!
//! The event loop used to await every evaluation inline. An exec that no
//! rule matched held every sensor's channel for up to the inference
//! timeout (15 s), and the kernel ring buffers dropped what arrived in the
//! meantime: any user could keep the agent blind by running unknown
//! binaries in a loop. The loop now hands the evaluation to a task and
//! moves on. One evaluation runs at a time — the backend serialises on its
//! weights anyway — and an exec that arrives while one runs is not
//! evaluated. It is counted, and the count is logged at most once a
//! minute, instead of queueing behind the model. The rules have already
//! judged it.
//!
//! Lab PR 162: an exec is offered once, as its `ProcessSpawn` (the child's
//! comm, argv and file), or as its `ExecCheck` when no spawn followed
//! ([`super::exec_pairing`]). The `ExecCheck` used to take the slot and the
//! spawn was skipped, so the count held one skip per exec under no load.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Semaphore;

/// How often the count of skipped evaluations reaches the log.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// At most one ADE evaluation in flight. See the module docs.
pub struct AdeSlot {
    permits: Arc<Semaphore>,
    skipped: AtomicU64,
    /// When the skipped count was last logged, and its value then.
    reported: Mutex<(Option<Instant>, u64)>,
}

impl Default for AdeSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl AdeSlot {
    pub fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(1)),
            skipped: AtomicU64::new(0),
            reported: Mutex::new((None, 0)),
        }
    }

    /// Run `evaluation` on its own task unless another is running.
    /// Returns `false`, and counts the skip, when one is. Never waits.
    pub fn try_spawn<F>(&self, evaluation: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            self.report_skips(Instant::now());
            return false;
        };
        tokio::spawn(async move {
            let _permit = permit;
            evaluation.await;
        });
        true
    }

    /// Evaluations skipped since boot because another was running: execs
    /// no rule matched, judged by the rules only.
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    fn report_skips(&self, now: Instant) {
        let mut reported = self.reported.lock();
        if reported
            .0
            .is_some_and(|at| now.saturating_duration_since(at) < REPORT_EVERY)
        {
            return;
        }
        let total = self.skipped();
        tracing::warn!(
            skipped_since_last_report = total - reported.1,
            skipped_total = total,
            "ADE busy: execs arriving while an evaluation runs are judged by the rules only, \
             not by ADE"
        );
        *reported = (Some(now), total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    /// One evaluation at a time; the next is refused and counted at once,
    /// never queued; the slot frees when the evaluation ends.
    #[tokio::test]
    async fn one_evaluation_at_a_time_and_never_waits() {
        let slot = AdeSlot::new();
        let (release, held) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        assert!(slot.try_spawn(async move {
            let _ = held.await;
            let _ = done_tx.send(());
        }));

        let started = Instant::now();
        for _ in 0..50 {
            assert!(!slot.try_spawn(async {}));
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(slot.skipped(), 50);

        release.send(()).unwrap();
        done_rx.await.unwrap();
        // The permit drops right after the evaluation's future ends.
        let mut freed = false;
        for _ in 0..100 {
            if slot.try_spawn(async {}) {
                freed = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(freed, "the slot frees once the evaluation ends");
    }
}
