//! Running synchronous work from async code without holding up the
//! runtime's other tasks.
//!
//! The agent runs on tokio's multi-thread runtime (`#[tokio::main]`): a
//! task that reads a file, hashes it or fsyncs a log on a worker thread
//! keeps every other task queued on that worker waiting — the sensors'
//! ring drains, the telemetry probe, the admin socket's other
//! connections. [`off_the_runtime`] hands the worker to the runtime for
//! the duration of the call (`block_in_place`): the other tasks move to
//! another thread, the caller blocks, and the closure may borrow from the
//! caller (no `'static` bound, unlike `spawn_blocking`). Used by the FIM
//! drain (hashing, the drift log, `/proc`), R018's package-database
//! lookups and the admin socket's request handling (external audit
//! ASK-005, NN-AUD-236).

/// Run `f` where it does not hold up the runtime's other tasks: through
/// `block_in_place` on the multi-thread runtime, as a plain call on a
/// `current_thread` runtime (the unit tests', where `block_in_place`
/// panics) or outside any runtime.
///
/// `f` must not hold a lock another task needs while it waits for that
/// task: the caller's own task is suspended until `f` returns.
pub fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// External audit ASK-005: with one worker, a task blocked for 300 ms
    /// inside the helper does not stop a ticker task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_work_does_not_stop_the_other_tasks() {
        let ticks = Arc::new(AtomicU64::new(0));
        let t = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_millis(10));
            loop {
                every.tick().await;
                t.fetch_add(1, Ordering::Relaxed);
            }
        });
        // Let the ticker start on the only worker.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let blocked = tokio::spawn(async {
            off_the_runtime(|| std::thread::sleep(Duration::from_millis(300)));
        });
        // The test body runs on the `block_on` thread, not on the worker.
        std::thread::sleep(Duration::from_millis(50));
        let before = ticks.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(200));
        let during = ticks.load(Ordering::Relaxed) - before;
        blocked.await.unwrap();
        ticker.abort();
        assert!(
            during >= 5,
            "the ticker advanced {during} times in 200 ms while another task blocked"
        );
    }

    #[test]
    fn outside_a_runtime_it_is_a_plain_call() {
        assert_eq!(off_the_runtime(|| 7), 7);
    }

    #[tokio::test]
    async fn on_a_current_thread_runtime_it_is_a_plain_call() {
        assert_eq!(off_the_runtime(|| 8), 8);
    }
}
