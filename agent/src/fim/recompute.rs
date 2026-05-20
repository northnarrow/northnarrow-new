//! Tappa 9 (C7) — in-process FIM baseline recompute channel.
//!
//! Closes the C6 deferral: at C6 the `dispatch_fim_baseline` admin
//! handler logged "baseline scheduled for next agent restart" and
//! relied on the next boot to actually compute. C7 wires a tokio
//! mpsc channel + a long-lived task that runs the recompute in
//! the running agent — operators no longer need to bounce the
//! agent for a signed `fim baseline` op to take effect.
//!
//! ## Design
//!
//! [`BaselineRecomputeChannel`] is a `Clone`-able mpsc sender +
//! receiver pair built once at agent boot. `trigger(reason)` is
//! called from `crate::admin_socket::dispatch_fim_baseline` —
//! non-blocking, drops the request if the channel buffer is full
//! (a recompute is already in flight, so coalescing is semantically
//! correct: the next op picks up any path changes since the in-
//! flight pass started). `recv()` is async, called from the boot-
//! time recompute task.
//!
//! [`run_recompute_task`] is the boot-spawned tokio task. Per
//! iteration: await one `RecomputeRequest`, iterate the current
//! `watched_paths` snapshot, call [`compute_baseline`] per path,
//! append each resulting `BaselineEntryDraft` to the `BaselineDb`,
//! and log a one-line summary with `paths_processed`,
//! `entries_written`, `errors` at info level.
//!
//! Concurrency: the `BaselineDb` is wrapped in `parking_lot::Mutex`
//! so the recompute task and the (currently unimplemented; C7-future)
//! drain-loop's append-on-drift path serialise on a single writer.
//! The `InodePathMap` already has internal RwLock.
//!
//! Error handling: per-path failures (`compute_baseline` errors on
//! a missing or non-regular-file path) are WARN-logged + skipped;
//! the rest of the paths still get recomputed. Only systemic
//! failures (DB append errors) escalate; even those are logged
//! and the task continues so a transient I/O blip doesn't kill
//! the recompute channel for the rest of the agent's lifetime.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::fim::baseline::{compute_baseline, BaselineDb};
use crate::fim::drain::InodePathMap;

/// Bounded queue depth for the recompute channel. A pending op
/// coalesces with any in-flight one; a sustained burst of admin
/// `fim baseline` calls within a single recompute window simply
/// drops the extras. Anything above the in-flight + 1 queued is
/// pure duplication.
pub const RECOMPUTE_CHANNEL_CAPACITY: usize = 4;

/// One queued recompute request. The `requested_at_unix` is purely
/// informational (operator visibility via boot logs); the actual
/// re-walk timestamp comes from `compute_baseline`'s per-entry ts.
#[derive(Debug, Clone)]
pub struct RecomputeRequest {
    pub reason: RecomputeReason,
    pub requested_at_unix: u64,
}

/// Why a recompute fired. Surfaced in the info log so operators
/// can correlate audit-log `fim_baseline` ops with the recompute
/// summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecomputeReason {
    /// First boot — `fim_baseline.jsonl` was empty when the
    /// agent's main.rs opened it (§13 Q5 TOFU model).
    FirstBootTofu,
    /// Operator-initiated via signed `fim baseline` admin op
    /// (C6 dispatch).
    AdminRequest,
}

/// Channel handle. `sender` is `Clone`-able and lives in
/// [`crate::admin_socket::AdminSocketState`] so the dispatch
/// handler can fire requests without holding the receiver. The
/// receiver is consumed once by [`run_recompute_task`].
pub struct BaselineRecomputeChannel {
    sender: mpsc::Sender<RecomputeRequest>,
    receiver: Option<mpsc::Receiver<RecomputeRequest>>,
}

impl BaselineRecomputeChannel {
    /// New bounded channel.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(RECOMPUTE_CHANNEL_CAPACITY);
        Self {
            sender,
            receiver: Some(receiver),
        }
    }

    /// Clone the sender for handing to admin dispatch. Cheap.
    pub fn sender(&self) -> BaselineRecomputeSender {
        BaselineRecomputeSender {
            inner: self.sender.clone(),
        }
    }

    /// Consume the receiver. Called exactly once at boot when
    /// the recompute task spawns. Subsequent calls return `None`.
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<RecomputeRequest>> {
        self.receiver.take()
    }
}

impl Default for BaselineRecomputeChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Sender half. Clone-able + cheap. Used by `dispatch_fim_baseline`.
#[derive(Clone)]
pub struct BaselineRecomputeSender {
    inner: mpsc::Sender<RecomputeRequest>,
}

impl BaselineRecomputeSender {
    /// Non-blocking fire. Returns `true` if the request was
    /// queued; `false` if the channel is full (a recompute is
    /// already in flight + one queued — semantically a coalesce).
    pub fn trigger(&self, reason: RecomputeReason) -> bool {
        let req = RecomputeRequest {
            reason,
            requested_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        match self.inner.try_send(req) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::info!(
                    ?reason,
                    "fim recompute: channel full — request coalesced \
                     (an in-flight recompute will subsume it)"
                );
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    ?reason,
                    "fim recompute: channel closed (recompute task exited) — request dropped"
                );
                false
            }
        }
    }
}

/// Boot-spawned task that consumes the recompute channel. Runs
/// for the lifetime of the agent. The `Arc<Mutex<BaselineDb>>` +
/// `Arc<InodePathMap>` are shared with the (future) drain-loop
/// (single-writer DB invariant preserved by the Mutex).
///
/// `paths_snapshot` is a closure rather than a static set so an
/// operator who edits `/etc/northnarrow/fim-paths.local` and then
/// runs `nn-admin fim baseline` gets the freshly-merged set on
/// the next recompute. The closure re-reads + re-merges on each
/// iteration — cheap (the file is ~100 lines).
pub async fn run_recompute_task<F>(
    mut receiver: mpsc::Receiver<RecomputeRequest>,
    baseline_db: Arc<Mutex<BaselineDb>>,
    inode_map: Arc<InodePathMap>,
    paths_snapshot: F,
) where
    F: Fn() -> BTreeSet<PathBuf> + Send + 'static,
{
    info!("fim recompute task: ready");
    while let Some(req) = receiver.recv().await {
        let started = std::time::Instant::now();
        let paths = paths_snapshot();
        let total = paths.len();
        let mut entries_written = 0usize;
        let mut errors = 0usize;
        for path in &paths {
            match compute_baseline(path) {
                Ok(drafts) => {
                    let mut db = baseline_db.lock();
                    for draft in drafts {
                        let path_for_map = draft.path.clone();
                        match db.append(draft) {
                            Ok(_entry) => {
                                entries_written += 1;
                                // Refresh path resolution — the
                                // (dev, ino) lookup requires a
                                // stat after the recompute, so
                                // we just leave the inode_map
                                // entry to be repopulated by the
                                // next baseline-from-disk pass
                                // at the next agent boot. C7
                                // intentionally keeps recompute
                                // minimal — InodePathMap
                                // refresh from on-disk baseline
                                // is the boot path.
                                let _ = path_for_map;
                                let _ = &inode_map;
                            }
                            Err(e) => {
                                errors += 1;
                                warn!(
                                    error = %e,
                                    path = %path.display(),
                                    "fim recompute: BaselineDb append failed"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    errors += 1;
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "fim recompute: compute_baseline failed — skipping"
                    );
                }
            }
        }
        info!(
            reason = ?req.reason,
            requested_at_unix = req.requested_at_unix,
            paths_processed = total,
            entries_written,
            errors,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "fim recompute: pass complete"
        );
    }
    info!("fim recompute task: channel closed, exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C7 #6: `trigger` returns true while the channel has room,
    /// then false once full (coalescing behaviour). Confirms the
    /// non-blocking contract from the doc-comment.
    #[tokio::test]
    async fn trigger_coalesces_when_channel_full() {
        let chan = BaselineRecomputeChannel::new();
        let sender = chan.sender();
        // CAP recompute requests fit; the (CAP+1)th coalesces.
        for _ in 0..RECOMPUTE_CHANNEL_CAPACITY {
            assert!(sender.trigger(RecomputeReason::AdminRequest));
        }
        assert!(
            !sender.trigger(RecomputeReason::AdminRequest),
            "(CAP+1)th trigger must coalesce when no receiver drains"
        );
    }

    /// C7 #7: `take_receiver` is one-shot. Subsequent calls return
    /// `None` so a misconfigured boot doesn't double-spawn the
    /// recompute task.
    #[test]
    fn take_receiver_is_one_shot() {
        let mut chan = BaselineRecomputeChannel::new();
        assert!(chan.take_receiver().is_some());
        assert!(
            chan.take_receiver().is_none(),
            "second take_receiver call must yield None"
        );
    }
}
