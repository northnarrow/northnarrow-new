//! Lab PR 216 (capability C23): the event loop's progress, for the
//! watchdog.
//!
//! The watchdog's STATUS ping is answered by the admin socket's task. On
//! the agent's multi-thread runtime that task runs beside the event loop, so
//! a loop stuck behind one `process_event` (a lock, a blocking call) still
//! answered every ping and was never recovered. The loop counts its rounds
//! here ([`tick`]); the admin socket serves the count with
//! [`snapshot`] (`LoopProgress`, unsigned, read-only) and the watchdog
//! recovers an agent whose count stands still between its pings.
//!
//! Process-wide atomics: one event loop per agent process.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

use nn_proto::admin_protocol::LoopProgressResponse;

/// When this process started counting (the first [`start`], [`tick`] or
/// [`snapshot`]); `since_last_ms` before the first round counts from here.
static ANCHOR: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Rounds of the event loop since the agent started.
static ITERATIONS: AtomicU64 = AtomicU64::new(0);

/// Milliseconds after [`ANCHOR`] at which the last round began.
static LAST_MS: AtomicU64 = AtomicU64::new(0);

/// Fix the anchor at the agent's start (from `main`), so a loop that is
/// never entered reports the time since the start.
pub fn start() {
    LazyLock::force(&ANCHOR);
}

fn now_ms() -> u64 {
    u64::try_from(ANCHOR.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One round of the event loop began.
pub fn tick() {
    LAST_MS.store(now_ms(), Ordering::Relaxed);
    ITERATIONS.fetch_add(1, Ordering::Relaxed);
}

/// The reply to the watchdog's `LoopProgress`.
pub fn snapshot() -> LoopProgressResponse {
    let iterations = ITERATIONS.load(Ordering::Relaxed);
    let last = if iterations == 0 {
        0
    } else {
        LAST_MS.load(Ordering::Relaxed)
    };
    LoopProgressResponse {
        iterations,
        since_last_ms: now_ms().saturating_sub(last),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counter moves only with the loop's rounds; the age of the last
    /// round grows while nothing ticks and falls back when a round begins.
    /// (One test: the counters are process-wide.)
    #[test]
    fn the_counter_follows_the_loop_rounds() {
        start();
        let before = snapshot();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let idle = snapshot();
        assert_eq!(idle.iterations, before.iterations, "no round, no progress");
        assert!(idle.since_last_ms >= before.since_last_ms + 20, "{idle:?}");
        tick();
        tick();
        let after = snapshot();
        assert_eq!(after.iterations, before.iterations + 2);
        assert!(after.since_last_ms < 20, "{after:?}");
    }
}
