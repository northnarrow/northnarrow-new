//! The decision thread's errands (R14c, plan §3.1).
//!
//! The decision thread's filter ([`super::filter`]) refuses it `execve` and
//! `bpf`; two things it did on its own judgement need them: the module
//! provenance rule's and the impact trust's `rpm -qf` (an RPM host's package
//! database), and the security tools' detector registering a tool's new
//! process in the kernel's `DEFENDER_PIDS`. Those are done for it here, on
//! a thread of the core's started at boot (`nn-errands`, role
//! [`Role::Errands`](super::Role::Errands): `BPF` effective), the caller
//! waiting for the answer as it waited for the call. A run without the
//! thread (a test, a tool) does the errand on the caller's thread.
//!
//! The thread must be started by a thread that holds the core's sets (it
//! inherits its creator's): the start's, before the decision thread runs.

use std::sync::mpsc::{self, Sender};
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::Mutex;

type Job = Box<dyn FnOnce() + Send>;

static ERRANDS: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();

/// The thread's name.
pub const THREAD: &str = "nn-errands";

/// Review of #482 (R14c-6): the longest a caller waits for its errand's
/// answer — the decision thread is the caller: an errand stuck behind
/// another (a hung `rpm`) never holds it longer. The errand itself goes on;
/// its late answer is dropped.
pub const ERRAND_WAIT: Duration = Duration::from_secs(2);

/// Start the errands thread (once; a second call does nothing). An error
/// when the thread could not start: the errands are then done on their
/// callers' threads, which the decision's filter refuses (a signed
/// degradation, by the caller).
pub fn start() -> std::io::Result<()> {
    if ERRANDS.get().is_some() {
        return Ok(());
    }
    let (tx, rx) = mpsc::channel::<Job>();
    std::thread::Builder::new()
        .name(THREAD.to_string())
        .spawn(move || {
            super::enter_or_report(super::Role::Errands);
            for job in rx {
                // a job that panics loses its own answer only
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            }
        })?;
    let _ = ERRANDS.set(Mutex::new(tx));
    Ok(())
}

/// The errands thread runs.
pub fn started() -> bool {
    ERRANDS.get().is_some()
}

/// `f` done on the errands thread, its answer returned; on the caller's
/// thread when there is none. `None`: the thread is gone, `f` panicked, or
/// no answer came within [`ERRAND_WAIT`].
pub fn run<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let Some(errands) = ERRANDS.get() else {
        return Some(f());
    };
    let (tx, rx) = mpsc::sync_channel::<T>(1);
    let job: Job = Box::new(move || {
        let _ = tx.send(f());
    });
    if errands.lock().send(job).is_err() {
        return None;
    }
    rx.recv_timeout(ERRAND_WAIT).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The errand runs on the errands thread (its name), the answer comes
    /// back; a panicking errand loses its answer, the thread goes on.
    #[test]
    fn an_errand_is_done_on_the_errands_thread() {
        start().unwrap();
        start().unwrap();
        assert!(started());
        let name = run(|| std::thread::current().name().map(str::to_string)).unwrap();
        assert_eq!(name.as_deref(), Some(THREAD));
        assert_eq!(run(|| -> u32 { panic!("an errand panics") }), None);
        assert_eq!(run(|| 7), Some(7));
        // review of #482 (R14c-6): a stuck errand holds its caller at most
        // ERRAND_WAIT, and the next errand's caller at most that too
        let t = std::time::Instant::now();
        assert_eq!(
            run(|| {
                std::thread::sleep(ERRAND_WAIT + Duration::from_millis(500));
                1
            }),
            None
        );
        assert!(
            t.elapsed() < ERRAND_WAIT + Duration::from_millis(400),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(run(|| 8), Some(8), "the thread goes on");
        // from a thread the decision's filter holds: the errand still
        // starts a program (the errands thread has no filter)
        let ok = std::thread::spawn(|| {
            let _ = super::super::enter(super::super::Role::Decision);
            let here = std::process::Command::new("/bin/true").status().is_err();
            let there = run(|| {
                std::process::Command::new("/bin/true")
                    .status()
                    .map(|s| s.success())
            })
            .and_then(Result::ok);
            here && there == Some(true)
        })
        .join()
        .unwrap();
        assert!(
            ok,
            "refused on the decision thread, done on the errands thread"
        );
    }
}
