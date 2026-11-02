//! A worker thread that is never replaced by its caller (review of #482):
//! jobs queue for it; it runs them in order; a job that panics is lost and
//! said, the thread goes on; a thread that could not start, or ended, is
//! started again by [`Supervised::ensure_running`] — the jobs wait in its
//! queue meanwhile (its receiver is held here, not by the thread).
//!
//! Why: the decision thread's seccomp filter (R14c) refuses it every
//! writing open and every signal to another process. Two side paths ran
//! their work *inline* — on the caller, the decision — when their thread
//! was missing: the canary's access writer (`nn-canary-log`) and the COMBAT
//! ladder's worker (`nn-combat-ladder`). Inline, their chain appends and
//! kills now fail with `EPERM`. With this, a missing thread is a signed
//! degradation ([`Report`]) and its work waits for it; nothing runs on the
//! caller.
//!
//! [`Supervised::ensure_running`] starts the thread from the calling
//! thread, whose capability sets it inherits: callers start it from the
//! start's thread or a runtime thread (the ladder's tick, the canary's
//! restart task), never from the decision thread.
//!
//! The release profile aborts on a panic (`panic = "abort"`): there a
//! panicking job ends the agent (the watchdog starts it again); the
//! catch is for builds that unwind.

use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::JoinHandle;

use parking_lot::Mutex;

/// How the thread is started: `std::thread::Builder` with the name in
/// production; the tests' seam (a start that fails).
pub type Spawn =
    Arc<dyn Fn(&str, Box<dyn FnOnce() + Send>) -> io::Result<JoinHandle<()>> + Send + Sync>;

/// A signed degradation: `(source, detail)` (the agent's
/// `boot::degradation::report`).
pub type Report = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// The production start: a named thread.
pub fn spawn_named() -> Spawn {
    Arc::new(|name: &str, f: Box<dyn FnOnce() + Send>| {
        std::thread::Builder::new().name(name.to_string()).spawn(f)
    })
}

/// A report that only logs (callers without a registry: the tests).
pub fn log_only() -> Report {
    Arc::new(|source: &str, detail: &str| {
        tracing::error!(source, "{detail}");
    })
}

/// See the module's documentation.
pub struct Supervised<T: Send + 'static> {
    name: String,
    source: &'static str,
    shared: Arc<Shared<T>>,
    handle: Mutex<Option<JoinHandle<()>>>,
    spawn: Spawn,
}

struct Shared<T> {
    rx: Mutex<Receiver<T>>,
    work: Box<dyn Fn(T) + Send + Sync>,
    /// Told when a job panicked (its work is lost).
    lost: Box<dyn Fn() + Send + Sync>,
    /// The thread's first call (its capabilities: the canary writer's role).
    on_start: Box<dyn Fn() + Send + Sync>,
    report: Report,
    source: &'static str,
}

impl<T: Send + 'static> Supervised<T> {
    /// A thread named `name` for the jobs of `rx`, each run by `work`; not
    /// started yet ([`Self::ensure_running`]). `source`: the degradation's.
    pub fn new(
        name: &str,
        source: &'static str,
        rx: Receiver<T>,
        work: impl Fn(T) + Send + Sync + 'static,
    ) -> Self {
        Supervised {
            name: name.to_string(),
            source,
            shared: Arc::new(Shared {
                rx: Mutex::new(rx),
                work: Box::new(work),
                lost: Box::new(|| {}),
                on_start: Box::new(|| {}),
                report: log_only(),
                source,
            }),
            handle: Mutex::new(None),
            spawn: spawn_named(),
        }
    }

    fn shared_mut(&mut self) -> &mut Shared<T> {
        Arc::get_mut(&mut self.shared).expect("configured before its first start")
    }

    /// Told when a job panicked.
    pub fn on_lost(mut self, lost: impl Fn() + Send + Sync + 'static) -> Self {
        self.shared_mut().lost = Box::new(lost);
        self
    }

    /// The thread's first call, before any job.
    pub fn on_start(mut self, on_start: impl Fn() + Send + Sync + 'static) -> Self {
        self.shared_mut().on_start = Box::new(on_start);
        self
    }

    /// Where its degradations are signed.
    pub fn reporting(mut self, report: Report) -> Self {
        self.shared_mut().report = report;
        self
    }

    /// How it is started (the tests' seam).
    pub fn spawning(mut self, spawn: Spawn) -> Self {
        self.spawn = spawn;
        self
    }

    /// The thread runs now.
    pub fn running(&self) -> bool {
        self.handle
            .lock()
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// Start the thread unless it runs: `true` when it runs after the
    /// call. A start that fails is a signed degradation (the registry keeps
    /// one row per distinct detail); its jobs wait in the queue.
    pub fn ensure_running(&self) -> bool {
        let mut handle = self.handle.lock();
        if handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return true;
        }
        let ended = handle.take().is_some();
        let shared = Arc::clone(&self.shared);
        match (self.spawn)(&self.name, Box::new(move || run(&shared))) {
            Ok(h) => {
                if ended {
                    tracing::warn!(thread = %self.name, "a worker thread had ended — started again");
                }
                *handle = Some(h);
                true
            }
            Err(e) => {
                (self.shared.report)(
                    self.source,
                    &format!(
                        "the {} thread could not start ({e}): its work waits in its queue, and it \
                         is started again later — never done on the caller's thread",
                        self.name
                    ),
                );
                false
            }
        }
    }
}

fn run<T>(shared: &Shared<T>) {
    (shared.on_start)();
    loop {
        let job = match shared.rx.lock().recv() {
            Ok(job) => job,
            Err(_) => return, // every sender gone: the end
        };
        if std::panic::catch_unwind(AssertUnwindSafe(|| (shared.work)(job))).is_err() {
            (shared.lost)();
            (shared.report)(
                shared.source,
                "a job panicked on its worker thread: that job's work is lost, the thread goes on",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::sync_channel;
    use std::time::{Duration, Instant};

    type Log = Arc<Mutex<Vec<String>>>;

    fn reports(log: &Log) -> Report {
        let log = Arc::clone(log);
        Arc::new(move |s: &str, d: &str| log.lock().push(format!("{s}: {d}")))
    }

    fn wait(cond: impl Fn() -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    /// The jobs run on the named thread, in order.
    #[test]
    fn jobs_run_in_order_on_the_named_thread() {
        let (tx, rx) = sync_channel::<u32>(8);
        let done: Log = Arc::default();
        let d = Arc::clone(&done);
        let s = Supervised::new("nn-sup-test", "test", rx, move |n| {
            let name = std::thread::current().name().unwrap_or("").to_string();
            d.lock().push(format!("{n}@{name}"));
        });
        assert!(s.ensure_running() && s.running());
        for n in 0..3 {
            tx.send(n).unwrap();
        }
        assert!(wait(|| done.lock().len() == 3));
        assert_eq!(
            *done.lock(),
            ["0@nn-sup-test", "1@nn-sup-test", "2@nn-sup-test"]
        );
    }

    /// A job that panics: lost, said, and the next one runs.
    #[test]
    fn a_panicking_job_is_lost_and_said_and_the_thread_goes_on() {
        let (tx, rx) = sync_channel::<u32>(8);
        let done: Log = Arc::default();
        let said: Log = Arc::default();
        let lost = Arc::new(AtomicU32::new(0));
        let (d, l) = (Arc::clone(&done), Arc::clone(&lost));
        let s = Supervised::new("nn-sup-panic", "test", rx, move |n| {
            if n == 1 {
                panic!("job 1 panics");
            }
            d.lock().push(n.to_string());
        })
        .on_lost(move || {
            l.fetch_add(1, Ordering::SeqCst);
        })
        .reporting(reports(&said));
        assert!(s.ensure_running());
        for n in 0..3 {
            tx.send(n).unwrap();
        }
        assert!(wait(|| done.lock().len() == 2), "{:?}", done.lock());
        assert_eq!(*done.lock(), ["0", "2"]);
        assert_eq!(lost.load(Ordering::SeqCst), 1);
        assert!(said.lock()[0].contains("panicked"), "{:?}", said.lock());
        assert!(s.running(), "the thread goes on");
    }

    /// A thread that cannot start: said, signed; its jobs wait in the
    /// queue — none runs on the caller — and run once it starts.
    #[test]
    fn a_thread_that_cannot_start_leaves_its_work_queued_for_its_start() {
        let (tx, rx) = sync_channel::<u32>(8);
        let done: Log = Arc::default();
        let said: Log = Arc::default();
        let fail = Arc::new(AtomicU32::new(2));
        let f = Arc::clone(&fail);
        let d = Arc::clone(&done);
        let caller = std::thread::current().id();
        let s = Supervised::new("nn-sup-start", "test_source", rx, move |n| {
            assert_ne!(std::thread::current().id(), caller, "never on the caller");
            d.lock().push(n.to_string());
        })
        .reporting(reports(&said))
        .spawning(Arc::new(
            move |name: &str, body: Box<dyn FnOnce() + Send>| {
                if f.load(Ordering::SeqCst) > 0 {
                    f.fetch_sub(1, Ordering::SeqCst);
                    return Err(io::Error::other("EAGAIN"));
                }
                std::thread::Builder::new()
                    .name(name.to_string())
                    .spawn(body)
            },
        ));
        assert!(!s.ensure_running());
        tx.send(7).unwrap();
        tx.send(8).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(done.lock().is_empty(), "nothing ran");
        assert!(!s.ensure_running());
        assert_eq!(said.lock().len(), 2);
        assert!(
            said.lock()[0].starts_with("test_source: the nn-sup-start thread could not start"),
            "{:?}",
            said.lock()
        );
        assert!(s.ensure_running());
        assert!(wait(|| done.lock().len() == 2));
        assert_eq!(*done.lock(), ["7", "8"]);
    }

    /// A thread that ended (here: its start panicked) is started again by
    /// the next `ensure_running`, and the jobs queued meanwhile run.
    #[test]
    fn a_thread_that_died_is_started_again_with_its_queue() {
        let (tx, rx) = sync_channel::<u32>(8);
        let done: Log = Arc::default();
        let starts = Arc::new(AtomicU32::new(0));
        let (d, st) = (Arc::clone(&done), Arc::clone(&starts));
        let s = Supervised::new("nn-sup-death", "test", rx, move |n| {
            d.lock().push(n.to_string());
        })
        .on_start(move || {
            if st.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("the first start dies");
            }
        });
        assert!(s.ensure_running());
        assert!(wait(|| !s.running()), "the thread died");
        tx.send(5).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(done.lock().is_empty());
        assert!(s.ensure_running());
        assert!(wait(|| done.lock().len() == 1));
        assert_eq!(starts.load(Ordering::SeqCst), 2);
    }
}
