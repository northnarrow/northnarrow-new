//! The core's side of its workers (R14a, plan §3.5): start them, check
//! their hello, send them requests with a deadline, and give up on one
//! that breaks the protocol, hangs or dies — kill it, take its pid out of
//! `PROTECTED_PIDS`, reap it, start another under a backoff. After
//! [`DISABLE_AFTER`] failures in a row the kind is disabled: its requests
//! are refused at once (the core does without the enrichment: it never
//! parses in its own process instead, plan §5) and the degradation is
//! signed; a worker that then stays up [`STABLE`] enables it again, and the
//! capability manifest's next revision says so.
//!
//! One thread (`nn-workers`) runs [`Workers::tick`]: it starts what is due,
//! reads a starting worker's hello, notices a death, a packet nobody asked
//! for (a flood), and pings an idle worker every [`PING_EVERY`] (a hang is
//! found without traffic). Requests run on the caller's thread
//! ([`Workers::request`]), one at a time per worker.
//!
//! Review of #480:
//! - F2: nothing waits on a worker for good. The core never sends to a
//!   worker that left an earlier request unread (`SIOCOUTQ`), and never
//!   blocks on a send (`MSG_DONTWAIT`): either is a violation. The status
//!   ([`Workers::status`]: the heartbeat, the manifest, `nn-admin status`)
//!   is a snapshot each pass publishes, never the lock a request holds.
//! - F3: a worker's pid leaves `PROTECTED_PIDS` before the pid can be
//!   reused: a death is seen without reaping (`waitid(…, WNOWAIT)`), the pid
//!   is evicted, then the zombie is reaped; a pid that could not be evicted
//!   stays a zombie (no process can take it) until it is, and that is a
//!   signed degradation.
//! - F4: a worker's stderr is a pipe the supervisor reads: each line
//!   escaped, cut, prefixed and rate-limited into the agent's own log — a
//!   worker writes no line of the agent's journal itself.
//! - F12: a worker that burns half a CPU over [`SPIN_WINDOW`] while it is
//!   asked nothing but pings is killed as a hang.
//! - `PR_SET_PDEATHSIG` is a property of the thread that forks: a worker is
//!   started from the supervisor's thread only ([`SUPERVISOR_THREAD`]),
//!   which lives as long as the agent.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_proto::ipc::{
    check_hello, check_response, decode, encode, Answer, Expected, FromWorker, Request,
    SandboxLevel, ToWorker, Violation, WorkerHello, WorkerKind, MAX_FRAME,
};
use parking_lot::Mutex;
use tracing::{info, warn};

use super::serve::{EXIT_PROTOCOL, EXIT_SANDBOX, EXIT_USAGE};
use super::spawn::{spawn, Spawned};
use super::transport::{self, Recv};
use super::{SelfImage, WorkerAccount};

/// The supervisor's thread: the one thread that starts workers (their
/// `PR_SET_PDEATHSIG` is that thread's).
pub const SUPERVISOR_THREAD: &str = "nn-workers";

/// How long a started worker has to say hello.
pub const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// An idle worker is pinged this often.
pub const PING_EVERY: Duration = Duration::from_secs(10);
/// A ping's deadline.
pub const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// Failures in a row after which the kind is disabled.
pub const DISABLE_AFTER: u32 = 5;
/// A worker up this long clears its kind's failures (and enables it).
pub const STABLE: Duration = Duration::from_secs(60);
/// The longest wait between two starts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Failure reports of a kind closer than this are folded into the next.
pub const REPORT_EVERY: Duration = Duration::from_secs(60);
/// A ready worker's CPU is measured over this window (F12).
#[cfg(not(test))]
pub const SPIN_WINDOW: Duration = Duration::from_secs(10);
#[cfg(test)]
pub const SPIN_WINDOW: Duration = Duration::from_millis(400);
/// The CPU share over [`SPIN_WINDOW`], with no request but pings, that is a
/// spin.
pub const SPIN_SHARE: f64 = 0.5;
/// The most lines of a worker's stderr logged per minute; the rest are
/// counted (F4).
pub const STDERR_LINES_PER_MINUTE: u32 = 20;
/// A logged stderr line's longest length, escaped.
pub const STDERR_LINE_MAX: usize = 200;
/// How long [`Workers::stop`] waits for a slot before it kills by pid.
pub const STOP_WAIT: Duration = Duration::from_secs(2);
/// Lot 276: the longest a supervisor pass waits for a slot a request
/// holds before it passes over it.
pub const TICK_LOCK_WAIT: Duration = Duration::from_millis(10);

/// The wait before the next start after `failures` in a row: at once
/// after the first, then 1, 2, 4… seconds, at most [`MAX_BACKOFF`].
pub fn backoff(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::ZERO,
        n => Duration::from_secs(1u64 << (n - 2).min(6)).min(MAX_BACKOFF),
    }
}

/// Where a worker's pid is registered for the deny hooks
/// (`PROTECTED_PIDS`, role `WORKER`).
pub trait PidRoles: Send + Sync {
    fn register_worker(&self, pid: u32) -> Result<(), String>;
    fn evict(&self, pid: u32) -> Result<(), String>;
}

/// The pinned `PROTECTED_PIDS` under `bpffs_root` (opened per call: the
/// map is pinned by the attach phase, before any worker starts).
pub struct PinnedPidRoles {
    pub bpffs_root: PathBuf,
}

impl PidRoles for PinnedPidRoles {
    fn register_worker(&self, pid: u32) -> Result<(), String> {
        antitamper_bpf::ProtectedPidsHandle::open(&self.bpffs_root)
            .and_then(|mut h| h.insert_role(pid, antitamper_bpf::pid_role::WORKER))
            .map_err(|e| format!("{e:#}"))
    }
    fn evict(&self, pid: u32) -> Result<(), String> {
        antitamper_bpf::ProtectedPidsHandle::open(&self.bpffs_root)
            .and_then(|mut h| h.evict(pid))
            .map_err(|e| format!("{e:#}"))
    }
}

/// No deny hooks to tell (no bpffs, a test).
pub struct NoPidRoles;

impl PidRoles for NoPidRoles {
    fn register_worker(&self, _pid: u32) -> Result<(), String> {
        Ok(())
    }
    fn evict(&self, _pid: u32) -> Result<(), String> {
        Ok(())
    }
}

/// Where a failure is reported: `(source, detail)` — production's is
/// `crate::boot::degradation::report`, signed in the audit chain.
pub type Report = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// A kind's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Its hello was accepted: it serves.
    Ready,
    /// Started, its hello awaited.
    Starting,
    /// Down, started again at the end of its backoff.
    Backoff,
    /// [`DISABLE_AFTER`] failures in a row: its requests are refused, it
    /// is still started again at its backoff.
    Disabled,
    /// It cannot be started at all (no account, no image).
    Unavailable,
    /// The agent stopped it.
    Stopped,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Ready => "ready",
            Health::Starting => "starting",
            Health::Backoff => "backoff",
            Health::Disabled => "disabled",
            Health::Unavailable => "unavailable",
            Health::Stopped => "stopped",
        }
    }
}

/// Why a request was not answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    /// No worker serves now ([`Health`] says why); nothing was sent.
    Unavailable(Health),
    /// The worker was busy past the request's deadline (another request,
    /// a ping): nothing was sent.
    Busy,
    /// The worker broke the protocol: it was killed.
    Violation(String),
    /// No answer within the deadline: it was killed.
    Timeout,
    /// It died with the request: `why`.
    Died(String),
    /// The request does not fit the protocol (a core bug).
    Refused(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Unavailable(h) => write!(f, "no worker ({})", h.as_str()),
            WorkerError::Busy => write!(f, "worker busy"),
            WorkerError::Violation(v) => write!(f, "protocol violation: {v}"),
            WorkerError::Timeout => write!(f, "no answer in time"),
            WorkerError::Died(w) => write!(f, "worker died: {w}"),
            WorkerError::Refused(w) => write!(f, "request refused: {w}"),
        }
    }
}

/// What the status and the capability manifest show of a kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerStatus {
    pub kind: WorkerKind,
    pub health: Health,
    pub pid: Option<u32>,
    pub starts: u64,
    pub deaths: u64,
    pub violations: u64,
    pub hangs: u64,
    /// Failures in a row now.
    pub failures: u32,
    /// The last worker's end (`killed by signal 31 (SIGSYS)`…).
    pub last_exit: String,
    /// Why it is disabled or unavailable.
    pub why: String,
    /// The sandbox the running (or the last ready) worker declared.
    pub sandbox: Option<SandboxLevel>,
}

/// How a worker is started: production's [`ImageLauncher`]; the tests'
/// scripted workers.
pub trait Launcher: Send + Sync {
    /// Why no worker can be started at all (`None`: they can).
    fn unavailable(&self) -> Option<String>;
    /// The account a worker must declare in its hello.
    fn account(&self) -> Option<(u32, u32)>;
    /// Start a `kind` worker: the child and the core's end of its channel.
    fn launch(&self, kind: WorkerKind) -> std::io::Result<Spawned>;
    /// The kernel's Landlock ABI a worker's hello is checked against
    /// (review of #480, F7).
    fn kernel_landlock_abi(&self) -> u8 {
        crate::sandbox::kernel_landlock_abi()
    }
    /// A look of the core's own at a worker whose hello it accepted
    /// (production's: `/proc/<pid>/status` against the declaration);
    /// `Err(why)` refuses it. None for the tests' scripted workers, which
    /// are no sandboxed processes.
    fn verify(&self, _pid: u32, _declared: &SandboxLevel) -> Result<(), String> {
        Ok(())
    }
}

/// The agent's binary from its boot descriptor, as `northnarrow-worker`
/// ([`spawn`]).
pub struct ImageLauncher {
    /// `None`: the image could not be opened at boot.
    pub image: Option<SelfImage>,
    pub account: Result<WorkerAccount, String>,
    /// Arguments after the worker's own (the lab harness's).
    pub extra_args: Vec<String>,
}

impl Launcher for ImageLauncher {
    fn unavailable(&self) -> Option<String> {
        match (&self.image, &self.account) {
            (None, _) => Some("the agent's image could not be opened at boot".to_string()),
            (_, Err(e)) => Some(format!(
                "no worker account ({e}): reinstall the agent, which creates `{}`",
                super::WORKER_USER
            )),
            _ => None,
        }
    }
    fn account(&self) -> Option<(u32, u32)> {
        self.account.as_ref().ok().map(|a| (a.uid, a.gid))
    }
    fn launch(&self, kind: WorkerKind) -> std::io::Result<Spawned> {
        // PR_SET_PDEATHSIG fires when the thread that forked exits: only
        // the supervisor's thread, which lives as long as the agent, may
        let here = std::thread::current();
        if here.name() != Some(SUPERVISOR_THREAD) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "a worker is started from the supervisor's thread ({SUPERVISOR_THREAD}) only, \
                     not from {:?}: its death signal is that thread's",
                    here.name()
                ),
            ));
        }
        match (&self.image, &self.account) {
            (Some(image), Ok(account)) => spawn(image, kind, account, &self.extra_args),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no image or no account",
            )),
        }
    }
    fn verify(&self, pid: u32, declared: &SandboxLevel) -> Result<(), String> {
        verify_proc(
            &std::fs::read_to_string(format!("/proc/{pid}/status"))
                .map_err(|e| format!("/proc/{pid}/status unreadable: {e}"))?,
            declared,
        )
    }
}

/// Review of #480 (F7): the kernel's view of a worker (`/proc/<pid>/status`)
/// against what it declared: every uid and gid its account's, no
/// supplementary group, `no_new_privs`, a seccomp filter, every capability
/// set empty.
pub fn verify_proc(status: &str, declared: &SandboxLevel) -> Result<(), String> {
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix(':'))
            .map(str::trim)
            .ok_or_else(|| format!("no {k} line"))
    };
    let ids = |k: &str, want: u32| -> Result<(), String> {
        let v = field(k)?;
        let all: Vec<&str> = v.split_whitespace().collect();
        if all.len() != 4 || all.iter().any(|x| x.parse::<u32>().ok() != Some(want)) {
            return Err(format!("{k} {v} (declared {want})"));
        }
        Ok(())
    };
    ids("Uid", declared.uid)?;
    ids("Gid", declared.gid)?;
    if !field("Groups")?.is_empty() {
        return Err(format!("Groups {}", field("Groups")?));
    }
    if field("NoNewPrivs")? != "1" {
        return Err(format!("NoNewPrivs {}", field("NoNewPrivs")?));
    }
    if field("Seccomp")? != "2" {
        return Err(format!("Seccomp {}", field("Seccomp")?));
    }
    for k in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        let v = field(k)?;
        if u64::from_str_radix(v, 16).ok() != Some(0) {
            return Err(format!("{k} {v}"));
        }
    }
    Ok(())
}

/// What the supervisor is given.
pub struct Config {
    pub launcher: Arc<dyn Launcher>,
    pub roles: Arc<dyn PidRoles>,
    pub report: Report,
    pub kinds: Vec<WorkerKind>,
    /// `debug-trigger` builds only: the directory of the lab's trigger
    /// files (`debug-worker-crash`, `debug-worker-hang`, `debug-worker-kill`
    /// taken once; `debug-worker-crashloop` while it is there), next to the
    /// admin socket. Never read otherwise.
    pub debug_dir: Option<PathBuf>,
}

struct SlotState {
    child: Option<Child>,
    sock: Option<OwnedFd>,
    pid: u32,
    started_at: Option<Instant>,
    ready_at: Option<Instant>,
    hello: Option<WorkerHello>,
    next_id: u64,
    last_use: Instant,
    failures: u32,
    next_start: Instant,
    disabled: bool,
    why: String,
    stopped: bool,
    starts: u64,
    deaths: u64,
    violations: u64,
    hangs: u64,
    last_exit: String,
    last_report: Option<Instant>,
    folded: u32,
    buf: Vec<u8>,
    /// `debug-trigger`: every new worker is sent a crash.
    crash_loop: bool,
    /// F3: workers killed, not reaped yet: their pids leave
    /// `PROTECTED_PIDS` first.
    graveyard: Vec<Grave>,
    /// F4: the read end of the worker's stderr, and the reader's state.
    stderr: Option<OwnedFd>,
    err_partial: Vec<u8>,
    err_window: Option<Instant>,
    err_lines: u32,
    err_dropped: u64,
    /// F12: the CPU ticks at the window's start, and the requests served
    /// by then (pings aside).
    cpu_mark: Option<(Instant, u64, u64)>,
    served: u64,
}

/// A killed worker awaiting its eviction and its reap.
struct Grave {
    child: Child,
    pid: u32,
    /// Its failed eviction was reported.
    reported: bool,
}

impl SlotState {
    fn new(now: Instant) -> Self {
        Self {
            child: None,
            sock: None,
            pid: 0,
            started_at: None,
            ready_at: None,
            hello: None,
            next_id: 1,
            last_use: now,
            failures: 0,
            next_start: now,
            disabled: false,
            why: String::new(),
            stopped: false,
            starts: 0,
            deaths: 0,
            violations: 0,
            hangs: 0,
            last_exit: String::new(),
            last_report: None,
            folded: 0,
            buf: vec![0u8; MAX_FRAME],
            crash_loop: false,
            graveyard: Vec::new(),
            stderr: None,
            err_partial: Vec::new(),
            err_window: None,
            err_lines: 0,
            err_dropped: 0,
            cpu_mark: None,
            served: 0,
        }
    }

    fn ready(&self) -> bool {
        self.sock.is_some() && self.ready_at.is_some()
    }
}

struct Slot {
    kind: WorkerKind,
    s: Mutex<SlotState>,
    /// F2: what [`Workers::status`] reads — published after every pass,
    /// request and stop; never held during I/O.
    snap: Mutex<WorkerStatus>,
}

struct Shared {
    launcher: Arc<dyn Launcher>,
    /// R14b: given at construction, or later ([`Workers::arm_roles`]) once
    /// this boot's deny hooks are attached.
    roles: Mutex<Arc<dyn PidRoles>>,
    report: Report,
    slots: Vec<Slot>,
    stop: AtomicBool,
    #[cfg_attr(not(feature = "debug-trigger"), allow(dead_code))]
    debug_dir: Option<PathBuf>,
}

/// The core's workers. Cheap to clone.
#[derive(Clone)]
pub struct Workers(Arc<Shared>);

impl std::fmt::Debug for Workers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workers")
            .field(
                "kinds",
                &self.0.slots.iter().map(|s| s.kind).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// How a worker failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Died,
    Violation,
    Hang,
    NotReady,
}

impl Workers {
    pub fn new(cfg: Config) -> Self {
        let now = Instant::now();
        let slots = cfg
            .kinds
            .iter()
            .map(|&kind| Slot {
                kind,
                s: Mutex::new(SlotState::new(now)),
                snap: Mutex::new(WorkerStatus {
                    kind,
                    health: Health::Backoff,
                    pid: None,
                    starts: 0,
                    deaths: 0,
                    violations: 0,
                    hangs: 0,
                    failures: 0,
                    last_exit: String::new(),
                    why: String::new(),
                    sandbox: None,
                }),
            })
            .collect();
        let me = Self(Arc::new(Shared {
            launcher: cfg.launcher,
            roles: Mutex::new(cfg.roles),
            report: cfg.report,
            slots,
            stop: AtomicBool::new(false),
            debug_dir: cfg.debug_dir,
        }));
        let why = me.unavailable_why();
        for slot in &me.0.slots {
            let mut s = slot.s.lock();
            if let Some(why) = &why {
                s.why = why.clone();
                (me.0.report)(&source(slot.kind), &format!("cannot start: {why}"));
            }
            me.publish(slot, &s);
        }
        me
    }

    /// F2: the slot's status for [`Workers::status`].
    fn publish(&self, slot: &Slot, s: &SlotState) {
        *slot.snap.lock() = self.status_of(slot.kind, s);
    }

    fn unavailable_why(&self) -> Option<String> {
        self.0.launcher.unavailable()
    }

    /// Start the supervisor's thread.
    pub fn start(&self) -> std::io::Result<std::thread::JoinHandle<()>> {
        let me = self.clone();
        std::thread::Builder::new()
            .name(SUPERVISOR_THREAD.to_string())
            .spawn(move || {
                // R14c (plan §3.1): the supervisor's capabilities
                crate::caps::enter_or_report(crate::caps::Role::Supervisor);
                while !me.0.stop.load(Ordering::Acquire) {
                    #[cfg(feature = "debug-trigger")]
                    me.debug_triggers();
                    let pace = me.tick(Instant::now());
                    std::thread::sleep(pace);
                }
            })
    }

    fn roles(&self) -> Arc<dyn PidRoles> {
        Arc::clone(&self.0.roles.lock())
    }

    /// R14b: where the workers' pids go from now on — this boot's deny
    /// hooks, attached and pinned after the workers started (a worker
    /// starts before the sensors, so the first DNS records find it ready).
    /// The pid of each running worker is registered at once. Until then a
    /// worker is not in `PROTECTED_PIDS` (killable by root, never exempt):
    /// an earlier boot's hooks, which read any entry as both roles, never
    /// see one.
    pub fn arm_roles(&self, roles: Arc<dyn PidRoles>) {
        *self.0.roles.lock() = Arc::clone(&roles);
        for slot in &self.0.slots {
            let s = slot.s.lock();
            if s.child.is_some() && s.pid != 0 {
                if let Err(e) = roles.register_worker(s.pid) {
                    warn!(worker = slot.kind.name(), pid = s.pid, error = %e,
                        "the worker's pid is not in PROTECTED_PIDS: the deny hooks do not defend it");
                }
            }
        }
    }

    fn slot(&self, kind: WorkerKind) -> Option<&Slot> {
        self.0.slots.iter().find(|s| s.kind == kind)
    }

    /// One pass of the supervisor; the wait before the next.
    pub fn tick(&self, now: Instant) -> Duration {
        let mut pace = Duration::from_millis(250);
        for slot in &self.0.slots {
            // lot 276: a slot held by a request in flight (the export's
            // last up to its budget) is passed over this round — its
            // requester judges the worker meanwhile — never waited on, so
            // one worker's long request does not hold up another's watch
            let Some(mut s) = slot.s.try_lock_for(TICK_LOCK_WAIT) else {
                continue;
            };
            if !s.stopped {
                self.watch(slot.kind, &mut s, now);
                self.drain_stderr(slot.kind, &mut s);
                if s.child.is_some() && s.ready_at.is_none() {
                    pace = Duration::from_millis(20);
                }
            }
            self.publish(slot, &s);
        }
        pace
    }

    fn watch(&self, kind: WorkerKind, s: &mut SlotState, now: Instant) {
        self.bury(kind, s);
        if self.unavailable_why().is_some() {
            return;
        }
        // a death the channel has not shown yet: seen, not reaped (F3)
        if s.child.is_some() && ended(s.pid).is_some() {
            let at = if s.ready() { "" } else { " before its hello" };
            self.fail(kind, s, Fault::Died, &format!("exited{at}"));
            return;
        }
        match (s.child.is_some(), s.ready()) {
            (false, _) if now >= s.next_start => self.launch(kind, s, now),
            (true, false) => self.await_hello(kind, s, now),
            (true, true) => self.check_ready(kind, s, now),
            _ => {}
        }
    }

    fn launch(&self, kind: WorkerKind, s: &mut SlotState, now: Instant) {
        s.starts += 1;
        match self.0.launcher.launch(kind) {
            Ok(Spawned {
                child,
                sock,
                stderr,
            }) => {
                let pid = child.id();
                if let Err(e) = self.roles().register_worker(pid) {
                    // still sandboxed; only root's signals reach it now
                    warn!(worker = kind.name(), pid, error = %e,
                        "the worker's pid is not in PROTECTED_PIDS: the deny hooks do not defend it");
                }
                s.child = Some(child);
                s.sock = Some(sock);
                s.stderr = stderr;
                s.err_partial.clear();
                s.pid = pid;
                s.started_at = Some(now);
                s.ready_at = None;
                s.cpu_mark = None;
                info!(worker = kind.name(), pid, "worker started");
            }
            Err(e) => {
                s.failures = s.failures.saturating_add(1);
                s.next_start = now + backoff(s.failures);
                s.last_exit = format!("not started: {e}");
                let detail = s.last_exit.clone();
                self.report_failure(kind, s, &detail, true);
                self.maybe_disable(kind, s);
            }
        }
    }

    fn await_hello(&self, kind: WorkerKind, s: &mut SlotState, now: Instant) {
        let Some(fd) = s.sock.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        let got = transport::recv(fd, &mut s.buf, true);
        match got {
            Ok(Recv::Empty) => {
                if s.started_at
                    .is_some_and(|t| now.duration_since(t) >= READY_TIMEOUT)
                {
                    self.fail(
                        kind,
                        s,
                        Fault::NotReady,
                        &format!("no hello within {READY_TIMEOUT:?}"),
                    );
                }
            }
            Ok(Recv::Packet(n)) => {
                let hello = match decode::<FromWorker>(&s.buf[..n]) {
                    Ok(FromWorker::Hello(h)) => h,
                    Ok(FromWorker::Response(_)) => {
                        return self.violation(kind, s, Violation::Hello("not first".into()))
                    }
                    Err(v) => return self.violation(kind, s, v),
                };
                let Some((uid, gid)) = self.0.launcher.account() else {
                    return;
                };
                let want = Expected {
                    kind,
                    pid: s.pid,
                    uid,
                    gid,
                    kernel_landlock_abi: self.0.launcher.kernel_landlock_abi(),
                };
                if let Err(v) = check_hello(&hello, &want) {
                    return self.violation(kind, s, v);
                }
                // F7: the kernel's own view of it, against its word
                if let Err(why) = self.0.launcher.verify(s.pid, &hello.sandbox) {
                    return self.violation(
                        kind,
                        s,
                        Violation::Hello(format!("its process is not what it declared: {why}")),
                    );
                }
                info!(
                    worker = kind.name(),
                    pid = s.pid,
                    sandbox = %hello.sandbox.summary(),
                    "worker ready"
                );
                s.hello = Some(hello);
                s.ready_at = Some(now);
                s.last_use = now;
                if s.crash_loop {
                    let _ = self.round_trip(kind, s, &Request::DebugCrash, PING_TIMEOUT);
                }
            }
            Ok(Recv::Closed) | Err(_) => {
                self.fail(kind, s, Fault::Died, "closed its channel before its hello")
            }
            Ok(Recv::Refused(v)) => self.violation(kind, s, v),
        }
    }

    fn check_ready(&self, kind: WorkerKind, s: &mut SlotState, now: Instant) {
        let Some(fd) = s.sock.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        // nothing may be waiting between requests
        match transport::recv(fd, &mut s.buf, true) {
            Ok(Recv::Empty) => {}
            Ok(Recv::Packet(_)) => return self.violation(kind, s, Violation::Unsolicited),
            Ok(Recv::Refused(v)) => return self.violation(kind, s, v),
            Ok(Recv::Closed) | Err(_) => {
                return self.fail(kind, s, Fault::Died, "closed its channel")
            }
        }
        if s.ready_at.is_some_and(|t| now.duration_since(t) >= STABLE) && s.failures > 0 {
            s.failures = 0;
            if s.disabled {
                s.disabled = false;
                s.why.clear();
                info!(
                    worker = kind.name(),
                    "worker up for {STABLE:?}: its kind is enabled again"
                );
            }
        }
        if now.duration_since(s.last_use) >= PING_EVERY {
            match self.round_trip(kind, s, &Request::Ping, PING_TIMEOUT) {
                Ok(Answer::Pong) => {}
                Ok(other) => {
                    // a refused ping is a wrong answer: Refused is
                    // inside the protocol, but a ping is never refused
                    self.violation(
                        kind,
                        s,
                        Violation::Bounds(if matches!(other, Answer::Refused(_)) {
                            "ping refused"
                        } else {
                            "ping"
                        }),
                    );
                }
                Err(_) => return, // already failed and reaped
            }
        }
        self.check_spin(kind, s);
    }

    /// F12: a worker that burns [`SPIN_SHARE`] of a CPU over
    /// [`SPIN_WINDOW`] while it is asked nothing but pings is a hang.
    fn check_spin(&self, kind: WorkerKind, s: &mut SlotState) {
        let Some(ticks) = cpu_ticks(s.pid) else {
            return;
        };
        let now = Instant::now();
        match s.cpu_mark {
            Some((at, t0, served0)) if now.duration_since(at) >= SPIN_WINDOW => {
                let window = now.duration_since(at).as_secs_f64();
                let used = ticks.saturating_sub(t0) as f64 / clock_ticks();
                if s.served == served0 && used >= SPIN_SHARE * window {
                    let share = (100.0 * used / window).round();
                    return self.fail(
                        kind,
                        s,
                        Fault::Hang,
                        &format!(
                            "spinning: {share}% of a CPU over {window:.1} s, asked nothing but pings"
                        ),
                    );
                }
                s.cpu_mark = Some((now, ticks, s.served));
            }
            Some(_) => {}
            None => s.cpu_mark = Some((now, ticks, s.served)),
        }
    }

    /// One request to a `kind` worker, answered within `timeout` (the
    /// answer checked against the request), or why not. A worker that
    /// breaks the protocol, hangs or dies is killed here.
    pub fn request(
        &self,
        kind: WorkerKind,
        req: &Request,
        timeout: Duration,
    ) -> Result<Answer, WorkerError> {
        req.check()
            .map_err(|v| WorkerError::Refused(v.to_string()))?;
        let slot = self
            .slot(kind)
            .ok_or(WorkerError::Unavailable(Health::Unavailable))?;
        let Some(mut s) = slot.s.try_lock_for(timeout) else {
            return Err(WorkerError::Busy);
        };
        let health = self.health_of(&s);
        if health != Health::Ready {
            return Err(WorkerError::Unavailable(health));
        }
        let got = self.round_trip(kind, &mut s, req, timeout);
        self.publish(slot, &s);
        got
    }

    fn round_trip(
        &self,
        kind: WorkerKind,
        s: &mut SlotState,
        req: &Request,
        timeout: Duration,
    ) -> Result<Answer, WorkerError> {
        let Some(fd) = s.sock.as_ref().map(AsRawFd::as_raw_fd) else {
            return Err(WorkerError::Unavailable(Health::Backoff));
        };
        // a packet left from before: a flood
        match transport::recv(fd, &mut s.buf, true) {
            Ok(Recv::Empty) => {}
            Ok(Recv::Packet(_)) => {
                self.violation(kind, s, Violation::Unsolicited);
                return Err(WorkerError::Violation(Violation::Unsolicited.to_string()));
            }
            Ok(Recv::Refused(v)) => {
                let e = WorkerError::Violation(v.to_string());
                self.violation(kind, s, v);
                return Err(e);
            }
            Ok(Recv::Closed) | Err(_) => {
                self.fail(kind, s, Fault::Died, "closed its channel");
                return Err(WorkerError::Died("closed its channel".into()));
            }
        }
        // F2: an honest worker read every earlier request before it
        // answered it; one that did not would fill this side's buffer
        match transport::unread(fd) {
            Ok(0) => {}
            Ok(n) => {
                let v = Violation::Unread(n);
                let e = WorkerError::Violation(v.to_string());
                self.violation(kind, s, v);
                return Err(e);
            }
            Err(e) => {
                let why = format!("SIOCOUTQ: {e}");
                self.fail(kind, s, Fault::Died, &why);
                return Err(WorkerError::Died(why));
            }
        }
        let id = s.next_id;
        s.next_id += 1;
        let bytes = encode(&ToWorker {
            id,
            req: req.clone(),
        })
        .map_err(WorkerError::Refused)?;
        if let Err(e) = transport::send(fd, &bytes) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                // the buffer full: never waited on (F2)
                let v = Violation::Unread(transport::unread(fd).unwrap_or(0));
                let e = WorkerError::Violation(v.to_string());
                self.violation(kind, s, v);
                return Err(e);
            }
            let why = format!("send: {e}");
            self.fail(kind, s, Fault::Died, &why);
            return Err(WorkerError::Died(why));
        }
        let deadline = Instant::now() + timeout;
        match transport::wait_readable(fd, deadline) {
            Ok(true) => {}
            Ok(false) => {
                self.fail(
                    kind,
                    s,
                    Fault::Hang,
                    &format!("no answer to {} within {timeout:?}", req.name()),
                );
                return Err(WorkerError::Timeout);
            }
            Err(e) => {
                let why = format!("poll: {e}");
                self.fail(kind, s, Fault::Died, &why);
                return Err(WorkerError::Died(why));
            }
        }
        let n = match transport::recv(fd, &mut s.buf, true) {
            Ok(Recv::Packet(n)) => n,
            Ok(Recv::Refused(v)) => {
                let e = WorkerError::Violation(v.to_string());
                self.violation(kind, s, v);
                return Err(e);
            }
            Ok(Recv::Empty) => {
                self.fail(kind, s, Fault::Died, "readable with nothing to read");
                return Err(WorkerError::Died("readable with nothing to read".into()));
            }
            Ok(Recv::Closed) | Err(_) => {
                let why = format!("died with request {} ({})", id, req.name());
                self.fail(kind, s, Fault::Died, &why);
                return Err(WorkerError::Died(why));
            }
        };
        let resp = match decode::<FromWorker>(&s.buf[..n]) {
            Ok(FromWorker::Response(r)) => r,
            Ok(FromWorker::Hello(_)) => {
                let v = Violation::Hello("a second hello".into());
                let e = WorkerError::Violation(v.to_string());
                self.violation(kind, s, v);
                return Err(e);
            }
            Err(v) => {
                let e = WorkerError::Violation(v.to_string());
                self.violation(kind, s, v);
                return Err(e);
            }
        };
        if resp.id != id {
            let v = Violation::UnknownId(resp.id);
            let e = WorkerError::Violation(v.to_string());
            self.violation(kind, s, v);
            return Err(e);
        }
        if let Err(v) = check_response(req, &resp.answer) {
            let e = WorkerError::Violation(v.to_string());
            self.violation(kind, s, v);
            return Err(e);
        }
        s.last_use = Instant::now();
        if !matches!(req, Request::Ping) {
            s.served += 1;
        }
        Ok(resp.answer)
    }

    /// Lot 276: an answer that passed the protocol's check against its
    /// request and failed the requester's against what it had sent before
    /// (the export's window of rows in flight): the worker is killed and
    /// reported as for any violation.
    pub fn condemn(&self, kind: WorkerKind, why: &'static str) {
        let Some(slot) = self.slot(kind) else {
            return;
        };
        let mut s = slot.s.lock();
        if s.child.is_some() {
            self.violation(kind, &mut s, Violation::Bounds(why));
        }
        self.publish(slot, &s);
    }

    fn violation(&self, kind: WorkerKind, s: &mut SlotState, v: Violation) {
        s.violations += 1;
        self.fail(kind, s, Fault::Violation, &v.to_string());
    }

    /// Give up on the running worker: kill it, take its pid out of the
    /// deny hooks' map, reap it, schedule the next start, report.
    fn fail(&self, kind: WorkerKind, s: &mut SlotState, fault: Fault, why: &str) {
        let was_ready = s.ready();
        s.sock = None;
        s.ready_at = None;
        s.cpu_mark = None;
        // its last words, before its pipe goes
        self.drain_stderr(kind, s);
        s.stderr = None;
        let status = self.end_child(kind, s);
        s.pid = 0;
        s.deaths += 1;
        if fault == Fault::Hang {
            s.hangs += 1;
        }
        s.failures = s.failures.saturating_add(1);
        let now = Instant::now();
        s.next_start = now + backoff(s.failures);
        s.last_exit = status.clone();
        let detail = format!(
            "worker {} ({}): {why} — {status}; {} in a row, next start in {:?}",
            if was_ready { "ready" } else { "starting" },
            fault_name(fault),
            s.failures,
            backoff(s.failures)
        );
        warn!(worker = kind.name(), "{detail}");
        // a sandbox or a protocol refused, a seccomp kill: at once
        let at_once = fault == Fault::Violation
            || status.contains("SIGSYS")
            || status.contains(&format!("exit status {EXIT_SANDBOX}"));
        self.report_failure(kind, s, &detail, at_once);
        self.maybe_disable(kind, s);
    }

    /// Kill the running worker, wait (briefly) for its death without
    /// reaping it, then evict its pid and reap it ([`Workers::bury`]): the
    /// pid is never free while `PROTECTED_PIDS` holds it (F3). Its end in
    /// words.
    fn end_child(&self, kind: WorkerKind, s: &mut SlotState) -> String {
        let Some(mut c) = s.child.take() else {
            return "not running".to_string();
        };
        let pid = s.pid;
        // a SIGKILL to our own child, not reaped: the pid is still ours
        let _ = c.kill();
        let deadline = Instant::now() + Duration::from_millis(500);
        let end = loop {
            if let Some(end) = ended(pid) {
                break end;
            }
            if Instant::now() >= deadline {
                break "killed, its end not seen yet".to_string();
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        s.graveyard.push(Grave {
            child: c,
            pid,
            reported: false,
        });
        self.bury(kind, s);
        end
    }

    /// F3: every dead worker of the graveyard evicted from `PROTECTED_PIDS`,
    /// then reaped; one whose eviction fails stays a zombie (its pid taken)
    /// until it succeeds, reported once, signed.
    fn bury(&self, kind: WorkerKind, s: &mut SlotState) {
        let roles = self.roles();
        let mut failed: Vec<(u32, String)> = Vec::new();
        s.graveyard.retain_mut(|g| {
            if ended(g.pid).is_none() {
                return true; // not dead yet: next pass
            }
            match roles.evict(g.pid) {
                Ok(()) => {
                    let _ = g.child.wait();
                    false
                }
                Err(e) => {
                    if !g.reported {
                        g.reported = true;
                        failed.push((g.pid, e));
                    }
                    true
                }
            }
        });
        for (pid, e) in failed {
            let detail = format!(
                "the dead worker's pid {pid} could not be taken out of PROTECTED_PIDS ({e}): kept \
                 unreaped — no process can take its pid — and evicted again every pass"
            );
            warn!(worker = kind.name(), "{detail}");
            (self.0.report)(&source(kind), &detail);
        }
    }

    /// F4: what the worker wrote to stderr, each line escaped, cut and
    /// prefixed into the agent's log, at most [`STDERR_LINES_PER_MINUTE`]
    /// a minute (the rest counted, said once the minute is over).
    fn drain_stderr(&self, kind: WorkerKind, s: &mut SlotState) {
        let Some(fd) = s.stderr.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        let mut chunk = [0u8; 4096];
        // at most 64 KiB a pass: a worker that writes faster blocks on its
        // own pipe, and is then a hang
        for _ in 0..16 {
            let n = read_nonblocking(fd, &mut chunk);
            if n == 0 {
                break;
            }
            for &b in chunk.iter().take(n) {
                if b == b'\n' || s.err_partial.len() >= STDERR_LINE_MAX {
                    let line = std::mem::take(&mut s.err_partial);
                    self.log_stderr(kind, s, &line);
                    if b == b'\n' {
                        continue;
                    }
                }
                s.err_partial.push(b);
            }
        }
    }

    fn log_stderr(&self, kind: WorkerKind, s: &mut SlotState, line: &[u8]) {
        let now = Instant::now();
        if s.err_window
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60))
        {
            if s.err_dropped > 0 {
                warn!(
                    worker = kind.name(),
                    dropped = s.err_dropped,
                    "worker {}: {} line(s) of its stderr not logged (at most {STDERR_LINES_PER_MINUTE} a minute)",
                    kind.name(),
                    s.err_dropped
                );
            }
            s.err_window = Some(now);
            s.err_lines = 0;
            s.err_dropped = 0;
        }
        if s.err_lines >= STDERR_LINES_PER_MINUTE {
            s.err_dropped += 1;
            return;
        }
        s.err_lines += 1;
        warn!(
            worker = kind.name(),
            "worker {}: {}",
            kind.name(),
            escape_line(line)
        );
    }

    fn maybe_disable(&self, kind: WorkerKind, s: &mut SlotState) {
        if s.failures >= DISABLE_AFTER && !s.disabled {
            s.disabled = true;
            s.why = format!(
                "{} failures in a row (last: {}): its enrichment is off until a worker stays up {:?}",
                s.failures, s.last_exit, STABLE
            );
            (self.0.report)(&source(kind), &format!("disabled: {}", s.why));
        }
    }

    fn report_failure(&self, kind: WorkerKind, s: &mut SlotState, detail: &str, at_once: bool) {
        let now = Instant::now();
        let due = s
            .last_report
            .is_none_or(|t| now.duration_since(t) >= REPORT_EVERY);
        if !(at_once || due) {
            s.folded += 1;
            return;
        }
        let folded = std::mem::take(&mut s.folded);
        let text = if folded > 0 {
            format!("{detail} (and {folded} failure(s) before it, not reported one by one)")
        } else {
            detail.to_string()
        };
        s.last_report = Some(now);
        (self.0.report)(&source(kind), &text);
    }

    fn health_of(&self, s: &SlotState) -> Health {
        if s.stopped {
            Health::Stopped
        } else if self.unavailable_why().is_some() {
            Health::Unavailable
        } else if s.disabled {
            Health::Disabled
        } else if s.ready() {
            Health::Ready
        } else if s.child.is_some() {
            Health::Starting
        } else {
            Health::Backoff
        }
    }

    fn status_of(&self, kind: WorkerKind, s: &SlotState) -> WorkerStatus {
        WorkerStatus {
            kind,
            health: self.health_of(s),
            pid: (s.pid != 0).then_some(s.pid),
            starts: s.starts,
            deaths: s.deaths,
            violations: s.violations,
            hangs: s.hangs,
            failures: s.failures,
            last_exit: s.last_exit.clone(),
            why: s.why.clone(),
            sandbox: s.hello.as_ref().map(|h| h.sandbox.clone()),
        }
    }

    /// Each kind's state as last published (F2: a snapshot — the
    /// heartbeat, the manifest and `nn-admin status` never wait on a
    /// worker's I/O).
    pub fn status(&self) -> Vec<WorkerStatus> {
        self.0
            .slots
            .iter()
            .map(|slot| slot.snap.lock().clone())
            .collect()
    }

    /// Stop every worker (the agent stops); no new start after this. A slot
    /// held past [`STOP_WAIT`] (it should never be: no I/O waits) has its
    /// worker killed by pid — still our unreaped child, so no other
    /// process's.
    pub fn stop(&self) {
        self.0.stop.store(true, Ordering::Release);
        for slot in &self.0.slots {
            let Some(mut s) = slot.s.try_lock_for(STOP_WAIT) else {
                if let Some(pid) = slot.snap.lock().pid {
                    warn!(
                        worker = slot.kind.name(),
                        pid, "the worker's slot is held: killed by pid"
                    );
                    // SAFETY: SIGKILL to our own child (not reaped while
                    // the slot is held).
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                }
                continue;
            };
            s.stopped = true;
            s.sock = None;
            s.ready_at = None;
            s.stderr = None;
            let _ = self.end_child(slot.kind, &mut s);
            // what is still unburied: once more, with a moment to die
            let deadline = Instant::now() + Duration::from_millis(500);
            while !s.graveyard.is_empty() && Instant::now() < deadline {
                self.bury(slot.kind, &mut s);
                if !s.graveyard.is_empty() {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            s.pid = 0;
            self.publish(slot, &s);
        }
    }

    /// `debug-trigger` builds (the lab): make the `kind` worker crash
    /// (`DebugCrash`), hang (`DebugHang`), be killed by the core, or — with
    /// `crash_loop` — crash at every start until called with `false`.
    #[cfg(feature = "debug-trigger")]
    pub fn debug(&self, kind: WorkerKind, fault: DebugFault) {
        let Some(slot) = self.slot(kind) else {
            return;
        };
        let mut s = slot.s.lock();
        warn!(worker = kind.name(), ?fault, "debug-trigger: worker fault");
        match fault {
            DebugFault::Crash => {
                let _ = self.round_trip(kind, &mut s, &Request::DebugCrash, PING_TIMEOUT);
            }
            DebugFault::Hang => {
                let _ = self.round_trip(kind, &mut s, &Request::DebugHang, PING_TIMEOUT);
            }
            DebugFault::Kill => self.fail(
                kind,
                &mut s,
                Fault::Died,
                "killed by the core (debug-trigger)",
            ),
            DebugFault::CrashLoop(on) => {
                s.crash_loop = on;
                if on && s.ready() {
                    let _ = self.round_trip(kind, &mut s, &Request::DebugCrash, PING_TIMEOUT);
                }
            }
        }
        self.publish(slot, &s);
    }
}

#[cfg(feature = "debug-trigger")]
impl Workers {
    /// The lab's trigger files ([`Config::debug_dir`]), for the parse
    /// worker.
    fn debug_triggers(&self) {
        let Some(dir) = &self.0.debug_dir else {
            return;
        };
        let take = |name: &str| {
            let p = dir.join(name);
            std::fs::symlink_metadata(&p).is_ok() && std::fs::remove_file(&p).is_ok()
        };
        let kind = WorkerKind::Parse;
        if take("debug-worker-crash") {
            self.debug(kind, DebugFault::Crash);
        }
        if take("debug-worker-hang") {
            self.debug(kind, DebugFault::Hang);
        }
        if take("debug-worker-kill") {
            self.debug(kind, DebugFault::Kill);
        }
        let looping = std::fs::symlink_metadata(dir.join("debug-worker-crashloop")).is_ok();
        let on = self.slot(kind).is_some_and(|slot| slot.s.lock().crash_loop);
        if looping != on {
            self.debug(kind, DebugFault::CrashLoop(looping));
        }
    }
}

/// `debug-trigger` builds: a fault the lab asks for.
#[cfg(feature = "debug-trigger")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugFault {
    Crash,
    Hang,
    Kill,
    CrashLoop(bool),
}

/// The degradation's source for `kind` (`worker_parse`).
pub fn source(kind: WorkerKind) -> String {
    format!("worker_{}", kind.name())
}

fn fault_name(f: Fault) -> &'static str {
    match f {
        Fault::Died => "died",
        Fault::Violation => "protocol violation",
        Fault::Hang => "hung",
        Fault::NotReady => "not ready",
    }
}

/// F3: the child `pid` ended (not reaped: `WNOWAIT`): its end in words;
/// `None` while it runs (or when it is no child of ours).
fn ended(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: an all-zero siginfo_t is valid; waitid writes it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid on our own child, without reaping it.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // SAFETY: si_pid and si_status read the fields waitid filled.
    let (who, status) = unsafe { (info.si_pid(), info.si_status()) };
    if rc != 0 || who == 0 {
        return None;
    }
    Some(match info.si_code {
        libc::CLD_EXITED => describe(Some(status), None),
        _ => describe(None, Some(status)),
    })
}

/// Read what a non-blocking descriptor holds now (0: nothing, or its end).
fn read_nonblocking(fd: RawFd, buf: &mut [u8]) -> usize {
    // SAFETY: read into a live buffer from our own descriptor.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    usize::try_from(n).unwrap_or(0)
}

/// A worker's stderr line for the agent's log: printable ASCII, the rest
/// as `\xHH`, at most [`STDERR_LINE_MAX`] bytes.
pub fn escape_line(line: &[u8]) -> String {
    let mut out = String::new();
    for &b in line {
        if out.len() >= STDERR_LINE_MAX {
            out.push('…');
            break;
        }
        if (0x20..=0x7e).contains(&b) && b != b'\\' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// F12: the process's CPU ticks (`utime` + `stime` of `/proc/<pid>/stat`).
fn cpu_ticks(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // after the name: state is field 3, utime 14 and stime 15
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    Some(utime + stime)
}

fn clock_ticks() -> f64 {
    // SAFETY: sysconf has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 {
        t as f64
    } else {
        100.0
    }
}

/// An exit status in words, with the worker's own codes named.
pub fn describe_exit(st: std::process::ExitStatus) -> String {
    describe(st.code(), st.signal())
}

fn describe(code: Option<i32>, signal: Option<i32>) -> String {
    match (code, signal) {
        (Some(c), _) => {
            let what = match c {
                0 => " (its channel closed)",
                EXIT_SANDBOX => " (the sandbox could not be entered)",
                EXIT_PROTOCOL => " (the core's request did not decode)",
                EXIT_USAGE => " (a bad command line)",
                _ => "",
            };
            format!("exit status {c}{what}")
        }
        (None, Some(sig)) => {
            let name = match sig {
                libc::SIGSYS => " (SIGSYS: a system call outside its seccomp allowlist)",
                libc::SIGKILL => " (SIGKILL)",
                libc::SIGABRT => " (SIGABRT: an abort)",
                libc::SIGSEGV => " (SIGSEGV)",
                _ => "",
            };
            format!("killed by signal {sig}{name}")
        }
        _ => "ended".to_string(),
    }
}

#[cfg(test)]
mod tests;
