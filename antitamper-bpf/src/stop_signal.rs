//! Lot 2.0 — a stop signal the agent or the watchdog did not request is no
//! clean stop.
//!
//! A stop signal (SIGTERM, SIGINT, SIGHUP) reaches the agent and the
//! watchdog, past the `task_kill` hook, from PID 1 under the grant of a
//! signed trusted-installer window (an install's, an upgrade's, an
//! uninstall's or the operator's `systemctl kill`), from `systemd-shutdown`
//! at the end of the host's shutdown, or from the kernel itself, which no
//! signal hook sees. Only the first two are a stop someone asked for. Any
//! other ends the process all the same — the signal is delivered — but not
//! as a clean stop: the role exits with a failure of its own, the surviving
//! role or systemd starts it again, and a signed record names the signal and
//! its sender as the kernel delivered them ([`Sender`]).
//!
//! [`capture`] keeps, for each stop signal, what the kernel's `siginfo`
//! said of its last delivery: an action of the signal registry the
//! runtime's own handler shares, which only stores to atomics and reads the
//! monotonic clock (both async-signal-safe). [`judge`] is the pure rule;
//! [`window_in_force`] reads the kernel's window grant at the signal's time.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// `si_code` of a `kill(2)` (`SI_USER`).
pub const SI_USER: i32 = 0;
/// `si_code` of a signal the kernel sent itself (`SI_KERNEL`): no process
/// is its sender.
pub const SI_KERNEL: i32 = 0x80;
/// `si_code` of a `sigqueue(3)` / `rt_sigqueueinfo(2)` (`SI_QUEUE`).
pub const SI_QUEUE: i32 = -1;
/// `si_code` of a `tkill(2)` / `tgkill(2)` (`SI_TKILL`).
pub const SI_TKILL: i32 = -6;

/// What the kernel's `siginfo` said of a stop signal's last delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sender {
    /// The signal.
    pub signo: i32,
    /// Its `si_code`.
    pub code: i32,
    /// The sending process (`si_pid`), for a code a process sends
    /// ([`Sender::from_process`]); 0 otherwise.
    pub pid: i32,
    /// When it was delivered (`CLOCK_MONOTONIC` ns, the kernel's window
    /// grant's clock).
    pub at_ns: u64,
}

impl Sender {
    /// Sent by a process (`kill`, `sigqueue`, `tkill`): its pid is the
    /// kernel's.
    pub const fn from_process(&self) -> bool {
        matches!(self.code, SI_USER | SI_QUEUE | SI_TKILL)
    }

    /// Sent by the kernel itself (`SI_KERNEL`): no process sent it.
    pub const fn from_kernel(&self) -> bool {
        self.code == SI_KERNEL
    }

    /// The record's words: the signal, and its sender (`comm`: the
    /// sender's command name read now, if it still runs).
    pub fn describe(&self, comm: Option<&str>) -> String {
        let sig = signal_name(self.signo);
        if self.from_kernel() {
            format!(
                "{sig} sent by the kernel itself (si_code SI_KERNEL: no sending process; no signal \
                 hook sees it)"
            )
        } else if self.from_process() {
            let comm = comm.map_or(String::new(), |c| format!(" `{c}`"));
            format!(
                "{sig} sent by pid {}{comm} (si_code {})",
                self.pid, self.code
            )
        } else {
            format!("{sig} (si_code {}: no sending process named)", self.code)
        }
    }
}

/// The signal's name.
pub fn signal_name(signo: i32) -> String {
    match signo {
        libc::SIGTERM => "SIGTERM".to_string(),
        libc::SIGINT => "SIGINT".to_string(),
        libc::SIGHUP => "SIGHUP".to_string(),
        n => format!("signal {n}"),
    }
}

/// One stop signal's last delivery: `(code << 32) | pid`, and its time
/// (0: none yet).
struct Slot {
    code_pid: AtomicU64,
    at_ns: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Slot {
            code_pid: AtomicU64::new(0),
            at_ns: AtomicU64::new(0),
        }
    }
}

/// SIGTERM, SIGINT, SIGHUP.
static SLOTS: [Slot; 3] = [Slot::new(), Slot::new(), Slot::new()];

fn slot(signo: i32) -> Option<&'static Slot> {
    match signo {
        libc::SIGTERM => Some(&SLOTS[0]),
        libc::SIGINT => Some(&SLOTS[1]),
        libc::SIGHUP => Some(&SLOTS[2]),
        _ => None,
    }
}

/// Keep what each delivery of `signo` (SIGTERM, SIGINT or SIGHUP) says of
/// its sender, beside whatever else handles it (the runtime's signal
/// streams share the registry). Call it before the process takes signals.
pub fn capture(signo: i32) -> std::io::Result<()> {
    if slot(signo).is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("not a stop signal: {signo}"),
        ));
    }
    // SAFETY: the action stores to atomics and reads the monotonic clock,
    // both async-signal-safe; it allocates nothing, takes no lock, and
    // panics on no path (`record`).
    unsafe { signal_hook_registry::register_sigaction(signo, move |info| record(signo, info)) }
        .map(|_| ())
}

/// The action: the delivery's `siginfo` into its slot.
fn record(signo: i32, info: &libc::siginfo_t) {
    let Some(s) = slot(signo) else { return };
    let code = info.si_code;
    let pid = if matches!(code, SI_USER | SI_QUEUE | SI_TKILL) {
        // SAFETY: for these codes the kernel fills the sender's pid (the
        // `_kill` / `_rt` member of the union).
        unsafe { info.si_pid() }
    } else {
        0
    };
    // the monotonic clock is never 0 once the host runs: 0 is "none yet"
    store(s, code, pid, crate::monotonic_ns().max(1));
}

fn store(s: &Slot, code: i32, pid: i32, at_ns: u64) {
    s.code_pid.store(
        (u64::from(code as u32) << 32) | u64::from(pid as u32),
        Ordering::Release,
    );
    s.at_ns.store(at_ns, Ordering::Release);
}

/// The last delivery of `signo` [`capture`] kept; `None` before one (or
/// for a signal it does not keep).
pub fn last(signo: i32) -> Option<Sender> {
    let s = slot(signo)?;
    let at_ns = s.at_ns.load(Ordering::Acquire);
    if at_ns == 0 {
        return None;
    }
    let cp = s.code_pid.load(Ordering::Acquire);
    Some(Sender {
        signo,
        code: (cp >> 32) as u32 as i32,
        pid: cp as u32 as i32,
        at_ns,
    })
}

/// Why a stop signal was a stop someone asked for, or that none did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// PID 1 is `systemd-shutdown`: the host's shutdown.
    HostShutdown,
    /// A signed trusted-installer window was in force: the operator's or
    /// an installer's stop.
    Window,
    /// Neither: not a clean stop.
    Unrequested,
}

impl Stop {
    /// A stop someone asked for (the clean ones).
    pub const fn requested(self) -> bool {
        !matches!(self, Stop::Unrequested)
    }
}

/// The rule: a stop signal is a requested stop only in the host's shutdown
/// or with a signed window in force — whoever sent it, the kernel or a
/// process (the agent's own stops, an admin's signed shutdown or a failure,
/// take no signal; the watchdog's stuck recovery names its SIGINT with a
/// marker of its own, a stop that is no clean one either).
pub const fn judge(host_shutdown: bool, window: bool) -> Stop {
    if host_shutdown {
        Stop::HostShutdown
    } else if window {
        Stop::Window
    } else {
        Stop::Unrequested
    }
}

/// `/proc/1/comm` of `systemd-shutdown` (15 bytes: the kernel's
/// `TASK_COMM_LEN` less the NUL).
pub const SHUTDOWN_COMM: &str = "systemd-shutdow";

/// PID 1 is `systemd-shutdown`, the last stage of the host's shutdown (its
/// comm, which no other process can write).
pub fn host_shutdown() -> bool {
    crate::read_proc_comm(1).is_some_and(|c| c == SHUTDOWN_COMM)
}

/// Whether the kernel's signed trusted-installer window grant
/// (`FS_GRANT[0]` of this boot's session, read from the pins under
/// `bpffs_root`) was in force at `at_ns` (`CLOCK_MONOTONIC`) — the
/// signal's time, so that a window ending between the delivery and this
/// read still counts. A grant not read is no window (the caller must be a
/// protected pid while the guard enforces).
pub fn window_in_force(bpffs_root: &Path, at_ns: u64) -> bool {
    match crate::read_grant(bpffs_root) {
        Ok((grant, session)) => grant.active(at_ns, session),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the host's shutdown and a window in force make a stop signal a
    /// requested stop; the sender does not (the kernel's, a process's).
    #[test]
    fn a_stop_signal_is_requested_only_in_the_shutdown_or_a_window() {
        assert_eq!(judge(true, false), Stop::HostShutdown);
        assert_eq!(judge(true, true), Stop::HostShutdown);
        assert_eq!(judge(false, true), Stop::Window);
        assert_eq!(judge(false, false), Stop::Unrequested);
        assert!(Stop::HostShutdown.requested() && Stop::Window.requested());
        assert!(!Stop::Unrequested.requested());
        assert_eq!(SHUTDOWN_COMM.len(), 15);
    }

    /// The sender as the kernel's `siginfo` gives it: a process's pid,
    /// or the kernel itself, named in the record.
    #[test]
    fn the_sender_is_named_as_the_kernel_gave_it() {
        let k = Sender {
            signo: libc::SIGTERM,
            code: SI_KERNEL,
            pid: 0,
            at_ns: 1,
        };
        assert!(k.from_kernel() && !k.from_process());
        let d = k.describe(None);
        assert!(d.starts_with("SIGTERM sent by the kernel itself"), "{d}");
        assert!(d.contains("SI_KERNEL"), "{d}");
        for code in [SI_USER, SI_QUEUE, SI_TKILL] {
            let p = Sender {
                signo: libc::SIGINT,
                code,
                pid: 4242,
                at_ns: 1,
            };
            assert!(p.from_process() && !p.from_kernel(), "{code}");
            let d = p.describe(Some("bash"));
            assert!(
                d.starts_with("SIGINT sent by pid 4242 `bash` (si_code"),
                "{d}"
            );
        }
        let o = Sender {
            signo: libc::SIGHUP,
            code: 1,
            pid: 0,
            at_ns: 1,
        };
        assert!(!o.from_process() && !o.from_kernel());
        assert!(o.describe(None).contains("no sending process named"));
        assert_eq!(signal_name(libc::SIGHUP), "SIGHUP");
        assert_eq!(signal_name(10), "signal 10");
    }

    /// A slot keeps the last delivery whole (code, pid, time) — negative
    /// codes included; none before the first; only the stop signals have
    /// one.
    #[test]
    fn a_slot_keeps_the_last_delivery() {
        let s = Slot::new();
        assert_eq!(s.at_ns.load(Ordering::Acquire), 0);
        store(&s, SI_TKILL, 77, 5);
        store(&s, SI_KERNEL, 0, 9);
        let cp = s.code_pid.load(Ordering::Acquire);
        assert_eq!(((cp >> 32) as u32 as i32, cp as u32 as i32), (SI_KERNEL, 0));
        assert_eq!(s.at_ns.load(Ordering::Acquire), 9);
        store(&s, SI_TKILL, 77, 11);
        let cp = s.code_pid.load(Ordering::Acquire);
        assert_eq!(((cp >> 32) as u32 as i32, cp as u32 as i32), (SI_TKILL, 77));
        assert!(slot(libc::SIGTERM).is_some() && slot(libc::SIGINT).is_some());
        assert!(slot(libc::SIGHUP).is_some() && slot(libc::SIGUSR1).is_none());
        assert!(capture(libc::SIGUSR1).is_err());
    }

    /// The capture sees a real delivery: a SIGHUP this test process sends
    /// itself (`kill`, SI_USER), and its pid, beside the registry's other
    /// handlers (an action ignoring it keeps the process).
    #[test]
    fn a_delivery_is_captured_with_its_sender() {
        // SAFETY: an action that does nothing, so that SIGHUP's default
        // (terminate) does not end the test process.
        unsafe { signal_hook_registry::register(libc::SIGHUP, || {}) }.unwrap();
        capture(libc::SIGHUP).unwrap();
        let before = crate::monotonic_ns();
        // SAFETY: a signal to this process, whose SIGHUP is handled above.
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGHUP) }, 0);
        let mut got = None;
        for _ in 0..200 {
            got = last(libc::SIGHUP).filter(|s| s.at_ns >= before);
            if got.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let s = got.expect("the delivery captured");
        assert_eq!(s.signo, libc::SIGHUP);
        assert_eq!(s.code, SI_USER);
        // SAFETY: a plain getter.
        assert_eq!(s.pid, unsafe { libc::getpid() });
        assert!(s.from_process());
    }

    /// No pins under the root: no window (a grant not read is none).
    #[test]
    fn a_grant_not_read_is_no_window() {
        let dir = std::env::temp_dir().join(format!("nn-stop-signal-{}", std::process::id()));
        assert!(!window_in_force(&dir, 1));
    }
}
