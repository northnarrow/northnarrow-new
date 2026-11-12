//! The exec quarantine's controller (lab PR 223): one thread that owns the
//! guard's kernel objects and the scanner, and decides on every held
//! process.
//!
//! A dedicated thread, not a tokio task: the budget of a held process must
//! run out even when the runtime is busy, and nothing here waits on the
//! agent's other work except the rule engine's verdict on the same exec
//! (through [`super::SpawnLedger`]). One loop polls the ring, the
//! scanner's channel and the ledger's eventfd, with the nearest deadline
//! as its timeout.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::wire::exe::exe_flags;
use common::wire::execq::{
    class_names, counter, stop_flags, ExecqKey, ExecqKnown, ExecqStopRaw, ExecqStopped,
};
use nn_model::{Event, ExeIdentity};
use nn_proto::execq::{ScanRequest, ScanResult, ScanVerdict};
use northnarrow_scan::supervisor::{ScannerEvent, Supervisor};
use tracing::{debug, info, warn};

use super::pkgtrust::{PackageTrust, PkgOutcome};
use super::policy::{decide, Action, Basis, Gate, Next, Outcome, Policy};
use super::record::{evidence, ExecqRecord};
use super::{kernel, SpawnLedger, AUDIT_OP, COUNTERS, HEARTBEAT_EVERY};
use crate::response::config::ExecutorConfig;
use crate::response::proc_ref::{Liveness, ProcRef};

/// How long an expired decision still waits for its scan verdict (a late
/// block-list hit kills the process then).
pub const LATE_WINDOW: Duration = Duration::from_secs(30);
/// Clean digests remembered (per agent run).
pub const KNOWN_HASHES: usize = 65_536;
/// How often the guarded mount roots are read again.
const ROOTS_EVERY: Duration = Duration::from_secs(10);

// ── the controller's three outside parts ────────────────────────────

/// The kernel side (the BPF maps and ring in production, a fake in tests).
pub trait KernelIo {
    fn ring_fd(&self) -> Option<RawFd>;
    fn drain(&mut self, out: &mut Vec<ExecqStopRaw>);
    fn beat(&mut self, ns: u64);
    fn remember(&mut self, key: ExecqKey, v: ExecqKnown);
    /// Lot 317 (review F5): the map's entry of process `pid` started at
    /// `start_ns` goes — not one a later holder of the pid has.
    fn unstop(&mut self, pid: u32, start_ns: u64);
    /// Lot 317 (review F2): the map's entry of that process says its kill
    /// is owed ([`kernel::KILL_OWED`]): the next start kills it.
    fn owe_kill(&mut self, pid: u32, start_ns: u64);
    fn stopped(&self) -> Vec<(u32, ExecqStopped)>;
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]);
    fn counters(&self) -> [u64; counter::SLOTS as usize];
    /// Lot 317 (BUG-118): return once every run of the kernel's programs
    /// that read the heartbeat before it was cleared has ended — the stop
    /// it decided is in [`Self::stopped`] by then.
    fn quiesce(&mut self);
}

impl KernelIo for kernel::Kernel {
    fn ring_fd(&self) -> Option<RawFd> {
        Some(self.ring.as_raw_fd())
    }
    fn drain(&mut self, out: &mut Vec<ExecqStopRaw>) {
        while let Some(item) = self.ring.next() {
            match bytemuck::try_from_bytes::<ExecqStopRaw>(&item) {
                Ok(r) => out.push(*r),
                Err(_) => {
                    self.reject
                        .record("execq", std::mem::size_of::<ExecqStopRaw>(), item.len())
                }
            }
        }
    }
    fn beat(&mut self, ns: u64) {
        kernel::Kernel::beat(self, ns)
    }
    fn remember(&mut self, key: ExecqKey, v: ExecqKnown) {
        let _ = self
            .known
            .insert(kernel::AyaKey(key), kernel::AyaKnown(v), 0);
    }
    fn unstop(&mut self, pid: u32, start_ns: u64) {
        kernel::Kernel::unstop(self, pid, start_ns)
    }
    fn owe_kill(&mut self, pid: u32, start_ns: u64) {
        kernel::Kernel::owe_kill(self, pid, start_ns)
    }
    fn stopped(&self) -> Vec<(u32, ExecqStopped)> {
        self.stopped
            .iter()
            .filter_map(|r| r.ok())
            .map(|(k, v)| (k, v.0))
            .collect()
    }
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) {
        kernel::Kernel::set_roots(self, roots)
    }
    fn counters(&self) -> [u64; counter::SLOTS as usize] {
        kernel::Kernel::counters(self)
    }
    fn quiesce(&mut self) {
        if !kernel::quiesce() {
            debug!("exec quarantine stop: membarrier refused — waited a fixed time instead");
        }
    }
}

/// The scanner (the supervised process in production).
pub trait Backend {
    fn fd(&self) -> Option<RawFd>;
    fn ready(&self) -> bool;
    /// The earliest a request can be served: now when ready, `None` when
    /// no scanner is expected.
    fn available_at(&self, now: Instant) -> Option<Instant>;
    /// Start it when due and read what it sent.
    fn tick(&mut self, now: Instant) -> Vec<ScannerEvent>;
    fn send(&mut self, req: &ScanRequest, fd: RawFd) -> Result<(), ScannerEvent>;
    /// Kill a hung scanner.
    fn kill(&mut self, why: &str) -> ScannerEvent;
}

impl Backend for Supervisor {
    fn fd(&self) -> Option<RawFd> {
        Supervisor::fd(self)
    }
    fn ready(&self) -> bool {
        self.is_ready()
    }
    fn available_at(&self, now: Instant) -> Option<Instant> {
        if self.is_ready() {
            Some(now)
        } else if self.is_running() {
            // starting: it says ready within a few milliseconds
            Some(now + Duration::from_millis(200))
        } else {
            self.next_start()
                .map(|t| t.max(now) + Duration::from_millis(200))
        }
    }
    fn tick(&mut self, now: Instant) -> Vec<ScannerEvent> {
        let mut out = Vec::new();
        if let Err(why) = self.start_if_due(now) {
            out.push(ScannerEvent::Died { why });
        }
        out.extend(self.poll(now));
        out
    }
    fn send(&mut self, req: &ScanRequest, fd: RawFd) -> Result<(), ScannerEvent> {
        Supervisor::send(self, req, fd)
    }
    fn kill(&mut self, why: &str) -> ScannerEvent {
        ScannerEvent::Died {
            why: Supervisor::kill(self, why),
        }
    }
}

/// Where records and signed entries go.
pub trait Recorder: Send {
    fn detection(&self, rec: ExecqRecord);
    /// A signed audit entry of the guard.
    fn audit(&self, extra: serde_json::Value, result: &str);
    /// A signed `subsystem_degraded`.
    fn degraded(&self, detail: &str);
}

/// The controller's settings.
#[derive(Debug, Clone)]
pub struct Settings {
    pub policy: Policy,
    pub budget: Duration,
    /// A scanner with requests in flight and silent this long is hung: it
    /// is killed and started again (the requests go to the next one).
    pub hung_after: Duration,
    /// The quarantine vault (`None`: never quarantine).
    pub exec_cfg: Option<ExecutorConfig>,
    /// The ctime offsets resolved: identities may be cached.
    pub ctime: bool,
    /// R12c (lab PR 270): its kills and quarantines are actions — each
    /// one's signed intent before, its outcome after.
    pub journal: crate::response::journal::ActionJournal,
}

// ── one held exec ───────────────────────────────────────────────────

struct Pending {
    raw: ExecqStopRaw,
    event: Event,
    path: String,
    proc_ref: ProcRef,
    file: Option<File>,
    /// `image` (through /proc/<pid>/exe), `script` (by path).
    target: &'static str,
    /// The file's ctime and size are the ones the kernel saw.
    stamp_ok: bool,
    gate: Gate,
    scan: Option<ScanResult>,
    /// Set when no scan verdict will come (package trust, unreachable,
    /// refused).
    basis: Option<Basis>,
    notes: Vec<String>,
    sent: bool,
    /// Decided by the default policy; kept for a late verdict until then.
    late_until: Option<Instant>,
}

impl Pending {
    fn held(&self) -> bool {
        self.raw.stopped()
    }
}

/// How the controller captures a process the kernel holds: its pid and
/// the start the kernel reported (production: [`ProcRef::open_started_at`];
/// tests: a capture that fails as one out of descriptors does).
pub type Capture = Box<dyn FnMut(u32, u64) -> ProcRef + Send>;

/// Lot 317 (BUG-124): what process `p` holds is now. A reference whose
/// capture failed — `pidfd_open` out of descriptors or memory, a failure
/// of the agent's, which passes — is captured again; while that fails the
/// process may still run, held: [`Liveness::Uncaptured`], never an exit.
fn recheck(capture: &mut Capture, p: &mut Pending) -> Liveness {
    if let Liveness::Uncaptured(_) = p.proc_ref.liveness() {
        p.proc_ref = capture(p.raw.pid, p.raw.start_ns);
    }
    p.proc_ref.liveness()
}

/// Lot 317 (BUG-124): a decision on a process the kernel holds that could
/// not be carried out — the process could not be captured. Its pid stays
/// in `EXECQ_STOPPED` (the process stays held) and the decision is retried
/// at every pass until the process is captured or has ended; an agent that
/// stops first leaves it there, and the next start resumes it.
struct Owed {
    pid: u32,
    start_ns: u64,
    /// [`Action::Resume`] or [`Action::Kill`].
    action: Action,
    /// The candidate's path (the kill's signed intent names it).
    path: String,
    /// Why it is held: the record's decision, or a stop a previous agent
    /// left.
    origin: &'static str,
    since: Instant,
    /// The last capture's error.
    errno: i32,
}

/// Clean digests, bounded (oldest out).
#[derive(Default)]
struct KnownSet {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl KnownSet {
    fn contains(&self, d: &[u8; 32]) -> bool {
        self.set.contains(d)
    }
    fn insert(&mut self, d: [u8; 32]) {
        if self.set.insert(d) {
            self.order.push_back(d);
            if self.order.len() > KNOWN_HASHES {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

pub struct Controller<K: KernelIo, B: Backend> {
    k: K,
    b: B,
    r: Box<dyn Recorder>,
    s: Settings,
    ledger: &'static SpawnLedger,
    pkg: Arc<PackageTrust>,
    entries: BTreeMap<u64, Pending>,
    queue: VecDeque<u64>,
    inflight: HashSet<u64>,
    known: KnownSet,
    next_id: u64,
    last_beat: Option<Instant>,
    last_roots: Option<Instant>,
    roots_source: std::path::PathBuf,
    /// Since when the scanner holds requests without a word.
    busy_since: Option<Instant>,
    /// The last signed degradation of the scanner (its cause, when) and
    /// the same ones held back since (a binary that cannot start fails
    /// every 30 s: one record per [`DEGRADED_EVERY`], with the count).
    last_degraded: Option<(String, Instant)>,
    degraded_held: u64,
    /// The kernel's fail-open counts already reported (the events ring
    /// full, the stop signal refused) and when: one signed degradation per
    /// [`DEGRADED_EVERY`] at most, with the counts since the previous one.
    fail_open_seen: (u64, u64, u64),
    fail_open_at: Option<Instant>,
    /// Lot 317 (BUG-124): how a held process is captured.
    capture: Capture,
    /// Lot 317 (BUG-124): the decisions not carried out yet, their process
    /// not captured ([`Owed`]).
    owed: Vec<Owed>,
}

/// One signed scanner degradation per cause at most this often.
pub const DEGRADED_EVERY: Duration = Duration::from_secs(600);

fn file_key(f: &File) -> Option<(u64, u64, i64, u32, i64)> {
    let m = f.metadata().ok()?;
    Some((
        crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        m.ino(),
        m.ctime(),
        m.ctime_nsec() as u32,
        m.size() as i64,
    ))
}

impl<K: KernelIo, B: Backend> Controller<K, B> {
    pub fn new(
        k: K,
        b: B,
        r: Box<dyn Recorder>,
        s: Settings,
        ledger: &'static SpawnLedger,
    ) -> Self {
        Self {
            k,
            b,
            r,
            s,
            ledger,
            pkg: Arc::new(PackageTrust::default()),
            entries: BTreeMap::new(),
            queue: VecDeque::new(),
            inflight: HashSet::new(),
            known: KnownSet::default(),
            next_id: 1,
            last_beat: None,
            last_roots: None,
            roots_source: "/proc/self/mountinfo".into(),
            busy_since: None,
            last_degraded: None,
            degraded_held: 0,
            fail_open_seen: (0, 0, 0),
            fail_open_at: None,
            capture: Box::new(ProcRef::open_started_at),
            owed: Vec::new(),
        }
    }

    /// Tests: another package database and mount table.
    #[cfg(test)]
    fn with_package_root(mut self, pkg: PackageTrust, mountinfo: std::path::PathBuf) -> Self {
        self.pkg = Arc::new(pkg);
        self.roots_source = mountinfo;
        self
    }

    /// The loop, until `stopping`.
    pub fn run(mut self, stopping: &AtomicBool) {
        self.recover();
        // The dpkg index is read on the first lookup that needs it, on this
        // thread: the guarded locations a package never uses skip it.
        loop {
            if stopping.load(Ordering::Relaxed) {
                self.stop_all();
                return;
            }
            let now = Instant::now();
            let wake = self.step(now);
            self.wait(wake);
        }
    }

    /// Lot 317 (review F6): a `debug-trigger` build's
    /// `NN_DEBUG_EXECQ_PAUSE_READS=<file>` (the lab's privileged e2e, never a
    /// release): while that file exists the ring is not read — the
    /// heartbeat beats on, so the kernel stops processes whose report the
    /// agent does not read: the window of BUG-118, held open from before
    /// the stop is asked (the stop's own 2 s budget untouched). With
    /// `NN_DEBUG_EXECQ_STOP_NO_LAST_READ=1` the stop's last read of the
    /// ring is skipped too ([`Self::stop_all`]), so that the map alone names
    /// them.
    #[cfg(feature = "debug-trigger")]
    fn debug_reads_paused() -> bool {
        std::env::var_os("NN_DEBUG_EXECQ_PAUSE_READS")
            .is_some_and(|f| std::path::Path::new(&f).exists())
    }

    /// One pass: heartbeat, scanner, ring, dispatch, decisions. Returns
    /// when the next pass is due at the latest.
    pub fn step(&mut self, now: Instant) -> Instant {
        if self
            .last_beat
            .is_none_or(|t| now.duration_since(t) >= HEARTBEAT_EVERY)
        {
            self.k.beat(kernel::monotonic_ns());
            self.last_beat = Some(now);
            let c = self.k.counters();
            COUNTERS
                .known_identity
                .store(c[counter::KNOWN_SKIP as usize], Ordering::Relaxed);
            COUNTERS.not_held.store(
                c[counter::OBSERVED as usize]
                    + c[counter::STALE as usize]
                    + c[counter::RING_FULL as usize]
                    + c[counter::SIGNAL_FAILED as usize]
                    + c[counter::MAP_FULL as usize],
                Ordering::Relaxed,
            );
            self.report_fail_open(
                [
                    c[counter::RING_FULL as usize],
                    c[counter::SIGNAL_FAILED as usize],
                    c[counter::MAP_FULL as usize],
                ],
                now,
            );
        }
        if self
            .last_roots
            .is_none_or(|t| now.duration_since(t) >= ROOTS_EVERY)
        {
            let text = std::fs::read_to_string(&self.roots_source).unwrap_or_default();
            self.k.set_roots(&kernel::guarded_roots(&text));
            self.last_roots = Some(now);
        }
        for ev in self.b.tick(now) {
            self.on_scanner(ev, now);
        }
        if self.inflight.is_empty() {
            self.busy_since = None;
        } else if self
            .busy_since
            .is_some_and(|t| now.duration_since(t) >= self.s.hung_after)
            && self.b.ready()
        {
            let ev = self.b.kill("no verdict within the decision budget");
            self.on_scanner(ev, now);
        }
        let mut raws = Vec::new();
        #[cfg(feature = "debug-trigger")]
        let read = !Self::debug_reads_paused();
        #[cfg(not(feature = "debug-trigger"))]
        let read = true;
        if read {
            self.k.drain(&mut raws);
        }
        for raw in raws {
            self.on_stop(raw, now);
        }
        self.dispatch(now);
        self.pay_owed(now);
        self.progress(now)
    }

    fn wait(&mut self, until: Instant) {
        let now = Instant::now();
        let beat = self.last_beat.map_or(now, |t| t + HEARTBEAT_EVERY);
        let at = until.min(beat);
        let ms = at.saturating_duration_since(now).as_millis().min(250) as i32;
        let mut fds: Vec<libc::pollfd> = [self.k.ring_fd(), self.b.fd(), self.ledger.wake_fd()]
            .into_iter()
            .flatten()
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: a valid array of pollfds for the duration of the call.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        self.ledger.drain_wake();
    }

    // ── inputs ───────────────────────────────────────────────────────

    fn on_stop(&mut self, raw: ExecqStopRaw, now: Instant) {
        if raw.flags & stop_flags::SCRIPT_REFUSED != 0 {
            self.script_refused(raw);
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        let held = raw.stopped();
        if held {
            COUNTERS.held.fetch_add(1, Ordering::Relaxed);
        }
        let mut exe = ExeIdentity::from_raw(&raw.exe);
        let walked = !exe.path.is_empty();
        let mut event = Event::ExecCheck {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            comm: common::wire::cstr_lossy(&raw.comm).into_owned(),
            filename: String::new(),
            timestamp_ns: raw.timestamp_ns,
            exe: std::mem::take(&mut exe),
        };
        crate::sensors::exe_identity::resolve(&mut event);
        let Event::ExecCheck { exe, .. } = &event else {
            unreachable!()
        };
        // A path the walk resolved names the candidate; one the fallback
        // read from /proc/<pid>/exe names the image, maybe not the script.
        let path = if walked {
            exe.path.clone()
        } else {
            String::new()
        };
        let proc_ref = (self.capture)(raw.pid, raw.start_ns);
        let (file, target, unreachable) = open_target(&raw, &path, proc_ref.has_fd());
        let mut notes = Vec::new();
        let stamp_ok = file
            .as_ref()
            .and_then(file_key)
            .is_some_and(|(_, _, cs, cn, sz)| {
                cs == raw.ctime_sec && cn == raw.ctime_nsec && sz == raw.size
            })
            && raw.flags & stop_flags::NO_CTIME == 0;
        let mut basis = unreachable.map(|detail| Basis::Unreachable { detail });
        if let (None, Some(f)) = (&basis, &file) {
            match self.pkg.check(&path, f) {
                PkgOutcome::Trusted { manager } => basis = Some(Basis::Package { manager }),
                PkgOutcome::Modified { manager } => {
                    notes.push(format!("{manager} lists the file with another content"))
                }
                PkgOutcome::NotOwned | PkgOutcome::Skipped => {}
            }
        }
        // Lot 317 (BUG-124): only a process that ended has no verdict of the
        // rules to wait for — one not captured may still run, held.
        let gone = proc_ref.liveness() == Liveness::Gone;
        let gate = Gate {
            since: now,
            budget: self.s.budget,
            stopped: held,
            verdict: basis.is_some(),
            spawn_judged: !held || gone || self.ledger.check(raw.pid, raw.start_ns),
        };
        debug!(
            pid = raw.pid,
            held,
            target,
            path = %nn_model::log_escape::Escaped(&path),
            classes = ?class_names(raw.class),
            "exec quarantine: candidate"
        );
        if basis.is_none() && file.is_some() {
            self.queue.push_back(id);
        }
        self.entries.insert(
            id,
            Pending {
                raw,
                event,
                path,
                proc_ref,
                file,
                target,
                stamp_ok,
                gate,
                scan: None,
                basis,
                notes,
                sent: false,
                late_until: None,
            },
        );
    }

    /// Lab PR 226: a script the kernel refused at its interpreter's pass
    /// (enforce mode): recorded, nothing to resume or scan.
    fn script_refused(&mut self, raw: ExecqStopRaw) {
        COUNTERS.script_refused.fetch_add(1, Ordering::Relaxed);
        let mut event = Event::ExecCheck {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            comm: common::wire::cstr_lossy(&raw.comm).into_owned(),
            filename: String::new(),
            timestamp_ns: raw.timestamp_ns,
            exe: ExeIdentity::from_raw(&raw.exe),
        };
        crate::sensors::exe_identity::resolve(&mut event);
        let path = match &event {
            Event::ExecCheck { exe, .. } => exe.path.clone(),
            _ => String::new(),
        };
        let o = decide(&self.s.policy, &Basis::ScriptRefused);
        info!(
            pid = raw.pid,
            path = %nn_model::log_escape::Escaped(&path),
            "exec quarantine: script refused at exec"
        );
        let ev = evidence(
            None,
            &o,
            true,
            false,
            0,
            raw.class,
            &["target: script (refused at its interpreter's pass)".to_string()],
        );
        self.r.detection(ExecqRecord::new(
            event,
            &path,
            &o,
            ev,
            "refused at exec (EACCES): the caller kept its image, the interpreter never ran"
                .to_string(),
            "script:",
        ));
    }

    fn on_scanner(&mut self, ev: ScannerEvent, now: Instant) {
        match ev {
            ScannerEvent::Ready(h) => info!(
                engine = %h.engine,
                uid = h.uid,
                block = h.block_entries,
                allow = h.allow_entries,
                yara = %h.yara,
                "exec quarantine scanner ready (seccomp on)"
            ),
            ScannerEvent::Result(r) => {
                self.inflight.remove(&r.id);
                self.busy_since = (!self.inflight.is_empty()).then_some(now);
                let id = r.id;
                let late = self
                    .entries
                    .get(&id)
                    .is_some_and(|p| p.late_until.is_some());
                if let Some(p) = self.entries.get_mut(&id) {
                    p.scan = Some(r);
                }
                if late {
                    self.late_verdict(id, now);
                }
            }
            ScannerEvent::Refused { id, reason } => {
                self.inflight.remove(&id);
                self.busy_since = (!self.inflight.is_empty()).then_some(now);
                if let Some(p) = self.entries.get_mut(&id) {
                    p.basis.get_or_insert(Basis::Unreachable {
                        detail: format!("the scanner refused it: {reason}"),
                    });
                }
            }
            ScannerEvent::Died { why } => {
                COUNTERS.scanner_deaths.fetch_add(1, Ordering::Relaxed);
                let waiting = self
                    .entries
                    .values()
                    .filter(|p| p.late_until.is_none())
                    .count();
                warn!(why = %why, waiting, "exec quarantine scanner lost — restarting it");
                self.busy_since = None;
                let cause = cause_of(&why);
                let repeat = self
                    .last_degraded
                    .as_ref()
                    .is_some_and(|(c, t)| *c == cause && now.duration_since(*t) < DEGRADED_EVERY);
                if repeat {
                    self.degraded_held += 1;
                } else {
                    let held = std::mem::take(&mut self.degraded_held);
                    let earlier = if held > 0 {
                        format!(" ({held} more of the same since the previous record)")
                    } else {
                        String::new()
                    };
                    self.r.degraded(&format!(
                        "exec quarantine scanner {why}{earlier}: {waiting} held process(es) wait \
                         for its restart within their budget, then get the default policy ({})",
                        self.s.policy.on_expiry.as_str()
                    ));
                    self.last_degraded = Some((cause, now));
                }
                // what it held goes to the next one, first
                let mut lost: Vec<u64> = self.inflight.drain().collect();
                lost.sort_unstable();
                for id in lost.into_iter().rev() {
                    if let Some(p) = self.entries.get_mut(&id) {
                        p.sent = false;
                        self.queue.push_front(id);
                    }
                }
            }
        }
    }

    /// Review of lab PR 223: an exec the kernel let run unheld because the
    /// events ring was full (or the stop signal was refused) is fail-open —
    /// never scanned. It was counted only (`not_held`, ring-drop slot
    /// `execq`); it is a signed degradation too, at most one per
    /// [`DEGRADED_EVERY`], with the counts since the previous one. Lot 317
    /// (review F3): and one the map of stopped processes could not name
    /// (`MAP_FULL`: the kernel stops only a process the map names).
    fn report_fail_open(&mut self, counts: [u64; 3], now: Instant) {
        let [ring_full, signal_failed, map_full] = counts;
        let (ring0, sig0, map0) = self.fail_open_seen;
        if ring_full <= ring0 && signal_failed <= sig0 && map_full <= map0 {
            return;
        }
        if self
            .fail_open_at
            .is_some_and(|t| now.duration_since(t) < DEGRADED_EVERY)
        {
            return;
        }
        let ring = ring_full.saturating_sub(ring0);
        let sig = signal_failed.saturating_sub(sig0);
        let map = map_full.saturating_sub(map0);
        warn!(
            ring_full = ring,
            signal_failed = sig,
            map_full = map,
            "exec quarantine fail-open: execs ran without being held"
        );
        self.r.degraded(&format!(
            "exec quarantine fail-open: {} exec(s) ran without being held or scanned since the \
             previous record — the events ring was full for {ring} (ring-drop slot execq), the \
             stop signal was refused for {sig}, the map of stopped processes was full for {map}",
            ring + sig + map
        ));
        self.fail_open_seen = (ring_full, signal_failed, map_full);
        self.fail_open_at = Some(now);
    }

    fn dispatch(&mut self, now: Instant) {
        if !self.b.ready() {
            // A scanner that cannot be back before a held process's budget
            // runs out: decide it now on the default policy, not later.
            let back = self.b.available_at(now);
            for id in &self.queue {
                if let Some(p) = self.entries.get_mut(id) {
                    if p.late_until.is_none()
                        && p.basis.is_none()
                        && back.is_none_or(|t| t >= p.gate.deadline())
                    {
                        p.basis = Some(Basis::Expired {
                            detail: "scanner unavailable".into(),
                        });
                    }
                }
            }
            return;
        }
        while let Some(id) = self.queue.pop_front() {
            let Some(p) = self.entries.get_mut(&id) else {
                continue;
            };
            let Some(fd) = p.file.as_ref().map(AsRawFd::as_raw_fd) else {
                continue;
            };
            if p.scan.is_some() {
                continue;
            }
            let req = ScanRequest {
                id,
                class: p.raw.class,
                path_hint: p.path.chars().take(512).collect(),
            };
            match self.b.send(&req, fd) {
                Ok(()) => {
                    p.sent = true;
                    if self.inflight.is_empty() {
                        self.busy_since = Some(now);
                    }
                    self.inflight.insert(id);
                }
                Err(ev) => {
                    self.queue.push_front(id);
                    self.on_scanner(ev, now);
                    break;
                }
            }
        }
    }

    /// Decide what is ready or expired; the next deadline.
    fn progress(&mut self, now: Instant) -> Instant {
        let mut wake = now + Duration::from_millis(250);
        let ids: Vec<u64> = self.entries.keys().copied().collect();
        for id in ids {
            let Some(p) = self.entries.get_mut(&id) else {
                continue;
            };
            if let Some(until) = p.late_until {
                if now >= until {
                    self.entries.remove(&id);
                    self.inflight.remove(&id);
                }
                continue;
            }
            if !p.gate.spawn_judged
                && (self.ledger.check(p.raw.pid, p.raw.start_ns)
                    || recheck(&mut self.capture, p) == Liveness::Gone)
            {
                p.gate.spawn_judged = true;
            }
            p.gate.verdict = p.scan.is_some() || p.basis.is_some();
            match p.gate.next(now) {
                Next::Decide => self.decide_one(id, now, None),
                Next::Expired => {
                    let missing = p.gate.missing();
                    self.decide_one(id, now, Some(missing));
                }
                Next::Wait(t) => wake = wake.min(t),
            }
        }
        wake
    }

    // ── decisions ────────────────────────────────────────────────────

    fn decide_one(&mut self, id: u64, now: Instant, expired: Option<String>) {
        let Some(p) = self.entries.get(&id) else {
            return;
        };
        // Lab PR 226: observe mode — a script would have been refused
        // (enforce refuses it in the kernel; it never gets here).
        let script =
            p.raw.flags & stop_flags::SCRIPT != 0 && p.raw.flags & stop_flags::INTERP_PASS == 0;
        let basis = if script && !self.s.policy.enforce {
            Basis::ScriptRefused
        } else if let Some(b) = &p.basis {
            b.clone()
        } else if let Some(r) = &p.scan {
            if r.verdict == ScanVerdict::Clean && self.known.contains(&r.sha256) {
                Basis::KnownHash
            } else {
                Basis::Scanned(r.verdict)
            }
        } else {
            Basis::Expired {
                detail: expired.unwrap_or_else(|| "no verdict".into()),
            }
        };
        let outcome = decide(&self.s.policy, &basis);
        let wait_late =
            matches!(basis, Basis::Expired { .. }) && p.scan.is_none() && p.file.is_some();
        let response = self.carry_out(id, &outcome);
        self.after(id, &basis, &outcome, response, now, false);
        if wait_late {
            if let Some(p) = self.entries.get_mut(&id) {
                p.late_until = Some(now + LATE_WINDOW);
                if !p.sent && !self.queue.contains(&id) {
                    self.queue.push_back(id);
                }
            }
        } else {
            self.entries.remove(&id);
            self.inflight.remove(&id);
        }
    }

    /// A verdict for a process the default policy already decided.
    fn late_verdict(&mut self, id: u64, now: Instant) {
        let Some(p) = self.entries.get(&id) else {
            return;
        };
        let Some(r) = &p.scan else {
            return;
        };
        let basis = Basis::Scanned(r.verdict);
        let outcome = decide(&self.s.policy, &basis);
        // the process runs now: only a kill changes anything, and a clean
        // verdict is cached
        let response = if outcome.action == Action::Kill {
            Some(self.carry_out(id, &outcome))
        } else {
            None
        };
        let record = outcome.action == Action::Kill || outcome.severity != nn_model::Severity::Low;
        match response {
            Some(resp) => self.after(id, &basis, &outcome, resp, now, true),
            None => {
                let resp =
                    "late verdict after the default policy; the process kept running".to_string();
                if record {
                    self.after(id, &basis, &outcome, resp, now, true);
                } else {
                    let quiet = Outcome {
                        record: false,
                        ..outcome.clone()
                    };
                    self.after(id, &basis, &quiet, resp, now, true);
                }
            }
        }
        self.entries.remove(&id);
    }

    /// Resume or kill (and quarantine); the record's `response`.
    fn carry_out(&mut self, id: u64, o: &Outcome) -> String {
        let enforce = self.s.policy.enforce;
        // Lot 317 (BUG-124): a process that could not be captured is
        // captured again; one that still cannot be is not one that ended.
        let liveness = match self.entries.get_mut(&id) {
            Some(p) => recheck(&mut self.capture, p),
            None => return "none".into(),
        };
        let Some(p) = self.entries.get(&id) else {
            return "none".into();
        };
        let was_held = p.held();
        let late = p.late_until.is_some();
        let pid = p.raw.pid;
        let start_ns = p.raw.start_ns;
        // Lot 317 (review F1): a process whose resume is still owed is
        // still held — the default policy's resume never reached it — so a
        // late verdict acts on a held process: its kill is owed in turn,
        // never "failed" while the owed resume would let it run
        let had_owed = self
            .owed
            .iter()
            .position(|o| o.pid == pid && o.start_ns == start_ns);
        let held = was_held && (!late || had_owed.is_some());
        // the capture's error when the decision is owed (the process stays
        // held, the decision retried)
        let mut owed = None;
        let mut out = if !enforce && o.refused {
            "observe: would refuse at exec (not held, the script ran)".to_string()
        } else if !enforce {
            format!("observe: would {} (not held)", o.action.as_str())
        } else {
            match (o.action, liveness) {
                (Action::Resume, _) if late => {
                    "running (resumed by the default policy)".to_string()
                }
                (Action::Resume, _) if !held => {
                    format!("not held ({}): ran unstopped", not_held_reason(&p.raw))
                }
                (Action::Resume, Liveness::Gone) => {
                    "ended while held (the rule engine's response, or a signal from elsewhere)"
                        .to_string()
                }
                (Action::Resume, Liveness::Uncaptured(errno)) => {
                    owed = Some(errno);
                    format!(
                        "resume deferred: the process could not be captured ({}); it stays \
                         held and is resumed as soon as it can be",
                        std::io::Error::from_raw_os_error(errno)
                    )
                }
                (Action::Resume, Liveness::Live) => resume(&p.proc_ref),
                (Action::Kill, Liveness::Gone) => "already ended".to_string(),
                (Action::Kill, Liveness::Uncaptured(errno)) => {
                    // R12c: the attempt is an action like any other — its
                    // signed intent, and the failure
                    let intent = self.intent("KillProcess", pid, &p.path);
                    let why = std::io::Error::from_raw_os_error(errno);
                    intent.finish(
                        crate::response::journal::ActionResult::Failure,
                        "the process could not be captured".to_string(),
                        Some(why.to_string()),
                    );
                    if held {
                        owed = Some(errno);
                        format!(
                            "kill deferred: the process could not be captured ({why}); it \
                             stays held and is killed as soon as it can be"
                        )
                    } else {
                        format!("kill failed: the process could not be captured ({why})")
                    }
                }
                (Action::Kill, Liveness::Live) => self.kill(&p.proc_ref, pid, &p.path, held).1,
            }
        };
        let path = p.path.clone();
        match (owed, had_owed) {
            // a decision on a process whose decision was owed takes its
            // place (a late kill replaces the owed resume)
            (Some(errno), Some(i)) => {
                let o2 = &mut self.owed[i];
                o2.action = o.action;
                o2.path = path;
                o2.errno = errno;
            }
            (Some(errno), None) => self.owed.push(Owed {
                pid,
                start_ns,
                action: o.action,
                path,
                origin: "decided",
                since: Instant::now(),
                errno,
            }),
            // carried out (killed, or ended): nothing owed any more
            (None, Some(i)) if held => {
                self.owed.remove(i);
            }
            _ => {}
        }
        // Lot 317 (review F2): a kill owed is written into the pinned map,
        // so that the next start kills the process instead of resuming it
        if owed.is_some() && o.action == Action::Kill {
            self.k.owe_kill(pid, start_ns);
        }
        if enforce && o.action == Action::Kill && o.quarantine {
            out.push_str("; ");
            out.push_str(&self.quarantine(id));
        }
        // an owed decision keeps the process in the kernel's map: the next
        // start resumes it — or kills it, its kill owed — if this agent
        // stops first
        if held && owed.is_none() {
            self.k.unstop(pid, start_ns);
        }
        out
    }

    /// Lot 317 (review F1): the verdict an entry of process `(pid,
    /// start_ns)` holds asks for its kill (a block-list hit, a suspicious
    /// verdict the policy kills): an owed resume must not run it.
    fn verdict_kills(&self, pid: u32, start_ns: u64) -> bool {
        self.entries.values().any(|p| {
            p.raw.pid == pid
                && p.raw.start_ns == start_ns
                && p.scan.as_ref().is_some_and(|r| {
                    decide(&self.s.policy, &Basis::Scanned(r.verdict)).action == Action::Kill
                })
        })
    }

    /// The kill of a captured process, with its signed intent (R12c, lab PR
    /// 270) and outcome: whether the signal was delivered, and the response.
    fn kill(&self, pr: &ProcRef, pid: u32, path: &str, held: bool) -> (bool, String) {
        let intent = self.intent("KillProcess", pid, path);
        match pr.signal(libc::SIGKILL) {
            Ok(()) => {
                COUNTERS.killed.fetch_add(1, Ordering::Relaxed);
                let text = if held {
                    "killed while held".to_string()
                } else {
                    "killed".to_string()
                };
                intent.finish(
                    crate::response::journal::ActionResult::Success,
                    text.clone(),
                    None,
                );
                (true, text)
            }
            Err(e) => {
                intent.finish(
                    crate::response::journal::ActionResult::Failure,
                    "kill failed".to_string(),
                    Some(e.to_string()),
                );
                (false, format!("kill failed: {e}"))
            }
        }
    }

    /// Lot 317 (BUG-124): the decisions owed to held processes that could
    /// not be captured ([`Owed`]), retried. A process captured now gets its
    /// decision and leaves the kernel's map; one that has ended leaves the
    /// map; one still not captured stays held for the next pass. Each one
    /// carried out is a signed `exec_quarantine` entry (`deferred`).
    fn pay_owed(&mut self, now: Instant) {
        if self.owed.is_empty() {
            return;
        }
        for mut o in std::mem::take(&mut self.owed) {
            // review F1: a resume owed to a process a verdict since asks to
            // kill is a kill — the binary never runs
            if o.action == Action::Resume && self.verdict_kills(o.pid, o.start_ns) {
                o.action = Action::Kill;
                self.k.owe_kill(o.pid, o.start_ns);
            }
            let pr = (self.capture)(o.pid, o.start_ns);
            let result = match pr.liveness() {
                Liveness::Uncaptured(errno) => {
                    o.errno = errno;
                    self.owed.push(o);
                    continue;
                }
                Liveness::Gone => "ended before it could be captured".to_string(),
                Liveness::Live => match o.action {
                    Action::Kill => self.kill(&pr, o.pid, &o.path, true).1,
                    Action::Resume => resume(&pr),
                },
            };
            self.k.unstop(o.pid, o.start_ns);
            info!(
                pid = o.pid,
                action = o.action.as_str(),
                result = %result,
                "exec quarantine: a decision deferred for a process not captured, carried out"
            );
            self.r.audit(
                serde_json::json!({
                    "kind": "deferred",
                    "detail": "a decision on a held process that could not be captured, \
                               carried out once it could be",
                    "pid": o.pid,
                    "action": o.action.as_str(),
                    "origin": o.origin,
                    "result": result,
                    "waited_ms": now.saturating_duration_since(o.since).as_millis() as u64,
                    "op": AUDIT_OP,
                }),
                "success",
            );
        }
    }

    fn quarantine(&mut self, id: u64) -> String {
        let Some(p) = self.entries.get(&id) else {
            return "not quarantined".into();
        };
        let (Some(cfg), Some(file)) = (&self.s.exec_cfg, &p.file) else {
            return "not quarantined (no vault, or no file)".into();
        };
        let handle = match file
            .try_clone()
            .and_then(crate::response::quarantine::ExeHandle::from_open_file)
        {
            // lot 312 (review F1): the exec's uid stands for the offender's
            Ok(h) => h.with_offender_uid(Some(p.raw.uid)),
            Err(e) => return format!("not quarantined ({e})"),
        };
        use crate::response::ExecutionOutcome as X;
        // R12c (lab PR 270): the quarantine's signed intent first.
        let intent = self.intent("Quarantine", p.raw.pid, &p.path);
        let outcome =
            crate::response::quarantine::quarantine_handle(&handle, p.raw.pid, cfg, &intent);
        let (result, text, reason) =
            crate::response::journal_outcome(&crate::response::ExecutionReport {
                action: nn_model::ResponseAction::Quarantine,
                primary: outcome.clone(),
                additional: Vec::new(),
                elapsed: std::time::Duration::from_micros(1),
            });
        intent.finish(result, text, reason);
        match outcome {
            X::Quarantined { vault_id, .. } => {
                COUNTERS.quarantined.fetch_add(1, Ordering::Relaxed);
                format!("quarantined (vault {vault_id})")
            }
            X::QuarantinedInPlace {
                vault_id,
                detail,
                effect,
                ..
            } => {
                if effect == crate::response::quarantine::InPlaceEffect::Emptied {
                    COUNTERS.quarantined.fetch_add(1, Ordering::Relaxed);
                }
                format!("quarantined in place (vault {vault_id}): {detail}")
            }
            X::QuarantineRefused { detail, .. } => format!("not quarantined ({detail})"),
            X::AlreadyGone { .. } => {
                "not quarantined (no file on disk: a memfd or unlinked)".into()
            }
            X::WouldExecute { .. } => "would quarantine (detect-only)".into(),
            X::Refused { reason, .. } => format!("not quarantined ({reason})"),
            X::Failed { errno, .. } => format!("quarantine failed (errno {errno})"),
            other => format!("quarantine: {other:?}"),
        }
    }

    /// R12c (lab PR 270): the signed intent of one of the exec quarantine's
    /// actions on `pid` (whose exec of `path` it held).
    fn intent(&self, response: &str, pid: u32, path: &str) -> crate::response::journal::Intent {
        let mut i = crate::response::journal::ActionIntent::named("exec_quarantine", response, pid);
        i.severity = "high".into();
        i.why = vec![super::RULE_ID.to_string()];
        let mut d = format!("exec of {path}");
        if d.len() > 200 {
            let mut cut = 200;
            while !d.is_char_boundary(cut) {
                cut -= 1;
            }
            d.truncate(cut);
        }
        i.detail = Some(d);
        self.s.journal.intent(i)
    }

    /// The cache, the known digests, the counters and the record.
    fn after(
        &mut self,
        id: u64,
        basis: &Basis,
        o: &Outcome,
        response: String,
        now: Instant,
        late: bool,
    ) {
        let Some(p) = self.entries.get(&id) else {
            return;
        };
        let enforce = self.s.policy.enforce;
        if let (Some(v), true, true) = (o.cache, p.stamp_ok, self.s.ctime) {
            let cacheable = o.action == Action::Resume || !enforce;
            if cacheable && p.raw.exe.flags & (exe_flags::MEMFD | exe_flags::DELETED) == 0 {
                self.k.remember(
                    ExecqKey {
                        dev: p.raw.exe.dev,
                        ino: p.raw.exe.ino,
                    },
                    ExecqKnown {
                        ctime_sec: p.raw.ctime_sec,
                        size: p.raw.size,
                        ctime_nsec: p.raw.ctime_nsec,
                        verdict: v,
                    },
                );
            }
        }
        if o.known_clean {
            if let Some(r) = &p.scan {
                self.known.insert(r.sha256);
            }
        }
        match basis {
            Basis::KnownHash => {
                COUNTERS.known_hash.fetch_add(1, Ordering::Relaxed);
            }
            Basis::Expired { .. }
            | Basis::Unreachable { .. }
            | Basis::Scanned(ScanVerdict::Unscanned) => {
                COUNTERS.defaulted.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.ledger.forget(p.raw.pid, p.raw.start_ns);
        let held_ms = now.duration_since(p.gate.since).as_millis() as u64;
        info!(
            pid = p.raw.pid,
            path = %nn_model::log_escape::Escaped(&p.path),
            basis = %o.why,
            response = %response,
            held_ms,
            "exec quarantine decision"
        );
        if !o.record {
            return;
        }
        let mut notes = p.notes.clone();
        notes.push(format!("target: {}", p.target));
        if late {
            notes.push("late: the verdict came after the default policy".into());
        }
        let ev = evidence(
            p.scan.as_ref(),
            o,
            enforce,
            p.held(),
            held_ms,
            p.raw.class,
            &notes,
        );
        self.r.detection(ExecqRecord::new(
            p.event.clone(),
            &p.path,
            o,
            ev,
            response,
            p.scan.as_ref().map(|r| r.format.as_str()).unwrap_or(""),
        ));
    }

    // ── boot and stop ────────────────────────────────────────────────

    /// Resume what an agent that died left stopped. Lot 317 (BUG-124): a
    /// process that cannot be captured now is not counted gone — it stays
    /// in the map, held, and its resume is owed ([`Self::pay_owed`]). Lot
    /// 317 (review F2): a process whose kill the previous agent owed (its
    /// map entry marked [`kernel::KILL_OWED`]) is killed, never resumed.
    fn recover(&mut self) {
        let left = self.k.stopped();
        if left.is_empty() {
            return;
        }
        let mut resumed = Vec::new();
        let mut killed = Vec::new();
        let mut gone = 0u64;
        let mut deferred = Vec::new();
        let now = Instant::now();
        for (pid, st) in &left {
            let kill = st.stop_ns == kernel::KILL_OWED;
            let pr = (self.capture)(*pid, st.start_ns);
            match pr.liveness() {
                Liveness::Uncaptured(errno) => {
                    deferred.push(*pid);
                    self.owed.push(Owed {
                        pid: *pid,
                        start_ns: st.start_ns,
                        action: if kill { Action::Kill } else { Action::Resume },
                        path: String::new(),
                        origin: if kill {
                            "a kill a previous agent owed"
                        } else {
                            "left stopped by a previous agent"
                        },
                        since: now,
                        errno,
                    });
                    continue;
                }
                Liveness::Live if kill => {
                    if self.kill(&pr, *pid, LEFT_BY_A_PREVIOUS_AGENT, true).0 {
                        killed.push(*pid);
                    } else {
                        gone += 1;
                    }
                }
                Liveness::Live if pr.signal(libc::SIGCONT).is_ok() => resumed.push(*pid),
                Liveness::Live | Liveness::Gone => gone += 1,
            }
            self.k.unstop(*pid, st.start_ns);
        }
        COUNTERS
            .recovered
            .fetch_add(resumed.len() as u64, Ordering::Relaxed);
        warn!(
            resumed = resumed.len(),
            killed = killed.len(),
            gone,
            deferred = deferred.len(),
            "exec quarantine: processes left stopped by the previous agent resumed"
        );
        self.r.audit(
            serde_json::json!({
                "kind": "recovered_at_boot",
                "detail": "held by an agent that exited before deciding; resumed undecided \
                           (a kill it owed: killed)",
                "resumed": resumed,
                // lot 317 (review F2): the kills the previous agent owed
                "killed": killed,
                "gone": gone,
                // lot 317: not captured yet — still held, carried out once they are
                "deferred": deferred,
                "op": AUDIT_OP,
            }),
            "success",
        );
    }

    /// Resume one process the kernel holds without an entry of this run
    /// (stopped after the ring's last read, or left by a previous agent):
    /// its kill if the map says one is owed. `None`: not captured, left in
    /// the map for the next start.
    fn release_unreported(&mut self, pid: u32, start_ns: u64, kill: bool) -> Option<Released> {
        let pr = (self.capture)(pid, start_ns);
        let r = match pr.liveness() {
            Liveness::Uncaptured(_) => return None,
            Liveness::Live if kill => {
                if self.kill(&pr, pid, LEFT_BY_A_PREVIOUS_AGENT, true).0 {
                    Released::Killed
                } else {
                    Released::Gone
                }
            }
            Liveness::Live if pr.signal(libc::SIGCONT).is_ok() => Released::Resumed,
            Liveness::Live | Liveness::Gone => Released::Gone,
        };
        self.k.unstop(pid, start_ns);
        Some(r)
    }

    /// The agent stops: every held process resumed, the heartbeat cleared.
    ///
    /// Lot 317 (BUG-118): what the kernel holds without an entry too — a
    /// process stopped after the ring's last read. The heartbeat is cleared
    /// first, then every program run that read it has ended
    /// ([`KernelIo::quiesce`]); the ring is read a last time (review F3,
    /// F7: a report the quiesce could not wait for — `membarrier` returns
    /// at once on a single CPU); then the entries are resumed, the owed
    /// decisions carried out (a kill still kills, and a resume a verdict
    /// since asks to kill is a kill), the reports of the last read and the
    /// rest of `EXECQ_STOPPED` resumed — each process keyed by its pid and
    /// start (review F5: a reused pid neither hides nor releases another
    /// process). A process that cannot be captured (BUG-124) stays in the
    /// pinned map, held, its kill marked if one is owed: the next start
    /// resumes it, or kills it.
    fn stop_all(&mut self) {
        self.k.beat(0);
        self.k.quiesce();
        let mut last = Vec::new();
        #[cfg(feature = "debug-trigger")]
        let read_last = std::env::var("NN_DEBUG_EXECQ_STOP_NO_LAST_READ").as_deref() != Ok("1");
        #[cfg(not(feature = "debug-trigger"))]
        let read_last = true;
        if read_last {
            self.k.drain(&mut last);
        }
        let mut resumed = Vec::new();
        let mut killed = Vec::new();
        let mut left = Vec::new();
        let mut unreported = Vec::new();
        let mut recaptured = Vec::new();
        let mut seen: HashSet<(u32, u64)> = HashSet::new();
        // review F1: the owed resumes a verdict since asks to kill (read
        // before the entries go)
        let kill_verdicts: HashSet<(u32, u64)> = self
            .owed
            .iter()
            .filter(|o| o.action == Action::Resume && self.verdict_kills(o.pid, o.start_ns))
            .map(|o| (o.pid, o.start_ns))
            .collect();
        // the processes held for a decision
        for (_, mut p) in std::mem::take(&mut self.entries) {
            if !p.held() || p.late_until.is_some() {
                continue;
            }
            seen.insert((p.raw.pid, p.raw.start_ns));
            if self
                .owed
                .iter()
                .any(|o| o.pid == p.raw.pid && o.start_ns == p.raw.start_ns)
            {
                continue; // its decision is owed: below
            }
            // the re-check of #541 (N1): a verdict that asks for the kill —
            // the scan answered, the rules' verdict on the exec still awaited
            // — is carried out at the stop, as for an owed resume: never a
            // resume undecided
            let kill = p.scan.as_ref().is_some_and(|r| {
                decide(&self.s.policy, &Basis::Scanned(r.verdict)).action == Action::Kill
            });
            let was_uncaptured = matches!(p.proc_ref.liveness(), Liveness::Uncaptured(_));
            match recheck(&mut self.capture, &mut p) {
                Liveness::Uncaptured(_) => {
                    if kill {
                        self.k.owe_kill(p.raw.pid, p.raw.start_ns);
                    }
                    left.push(p.raw.pid);
                    continue;
                }
                Liveness::Live if kill => {
                    if self.kill(&p.proc_ref, p.raw.pid, &p.path, true).0 {
                        killed.push(p.raw.pid);
                    }
                }
                Liveness::Live if p.proc_ref.signal(libc::SIGCONT).is_ok() => {
                    resumed.push(p.raw.pid);
                    if was_uncaptured {
                        recaptured.push(p.raw.pid);
                    }
                }
                Liveness::Live | Liveness::Gone => {}
            }
            self.k.unstop(p.raw.pid, p.raw.start_ns);
        }
        // the decisions owed, carried out on the processes captured now
        for mut o in std::mem::take(&mut self.owed) {
            seen.insert((o.pid, o.start_ns));
            if kill_verdicts.contains(&(o.pid, o.start_ns)) {
                o.action = Action::Kill;
            }
            let pr = (self.capture)(o.pid, o.start_ns);
            match (pr.liveness(), o.action) {
                (Liveness::Uncaptured(_), action) => {
                    // a kill owed is marked in the map since it was owed;
                    // one a verdict turns into a kill only now is marked here
                    if action == Action::Kill && kill_verdicts.contains(&(o.pid, o.start_ns)) {
                        self.k.owe_kill(o.pid, o.start_ns);
                    }
                    left.push(o.pid);
                    continue;
                }
                (Liveness::Live, Action::Kill) => {
                    if self.kill(&pr, o.pid, &o.path, true).0 {
                        killed.push(o.pid)
                    }
                }
                (Liveness::Live, Action::Resume) => {
                    if pr.signal(libc::SIGCONT).is_ok() {
                        resumed.push(o.pid)
                    }
                }
                (Liveness::Gone, _) => {}
            }
            self.k.unstop(o.pid, o.start_ns);
        }
        // BUG-118: what the kernel holds without an entry — the reports of
        // the last read, then the map (a kill a previous agent owed, too)
        let mut unentered: Vec<(u32, u64, bool)> = last
            .iter()
            .filter(|r| r.stopped() && r.flags & stop_flags::SCRIPT_REFUSED == 0)
            .map(|r| (r.pid, r.start_ns, false))
            .collect();
        unentered.extend(
            self.k
                .stopped()
                .into_iter()
                .map(|(pid, st)| (pid, st.start_ns, st.stop_ns == kernel::KILL_OWED)),
        );
        for (pid, start_ns, kill) in unentered {
            if !seen.insert((pid, start_ns)) {
                continue;
            }
            match self.release_unreported(pid, start_ns, kill) {
                None => {
                    left.push(pid);
                }
                Some(Released::Resumed) => {
                    resumed.push(pid);
                    unreported.push(pid);
                }
                Some(Released::Killed) => killed.push(pid),
                Some(Released::Gone) => {}
            }
        }
        if !left.is_empty() {
            warn!(
                left = ?left,
                "exec quarantine: held processes that could not be captured stay stopped — \
                 the next start resumes them, or kills them when their kill is owed"
            );
        }
        if !resumed.is_empty() || !killed.is_empty() || !left.is_empty() {
            self.r.audit(
                serde_json::json!({
                    "kind": "stopping",
                    "detail": "the agent stops: held processes resumed undecided, the kills \
                               owed carried out, those not captured left stopped for the next \
                               start",
                    "resumed": resumed,
                    // lot 317: kills owed and carried out; processes not
                    // captured, left in the pinned map for the next start
                    "killed": killed,
                    "left": left,
                    // BUG-118: of the resumed, those whose report the
                    // agent had not read (held without an entry)
                    "unreported": unreported,
                    // BUG-124: of the resumed, those held for a decision
                    // whose capture had failed until the stop
                    "recaptured": recaptured,
                    "op": AUDIT_OP,
                }),
                "success",
            );
        }
    }
}

/// What [`Controller::release_unreported`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Released {
    Resumed,
    Killed,
    Gone,
}

/// The path a kill's signed intent names for a process the agent holds
/// without an entry (its report unread, or its kill owed by a previous
/// agent).
const LEFT_BY_A_PREVIOUS_AGENT: &str = "(a process held without a report of this run)";

/// `SIGCONT` to a captured held process; the record's response.
fn resume(pr: &ProcRef) -> String {
    match pr.signal(libc::SIGCONT) {
        Ok(()) => {
            COUNTERS.resumed.fetch_add(1, Ordering::Relaxed);
            "resumed".to_string()
        }
        Err(e) => format!("resume failed: {e}"),
    }
}

/// What a degradation is about, numbers aside (a pid, a count).
fn cause_of(why: &str) -> String {
    why.chars().filter(|c| !c.is_ascii_digit()).collect()
}

fn not_held_reason(raw: &ExecqStopRaw) -> String {
    if raw.flags & stop_flags::OBSERVE != 0 {
        "observe mode".into()
    } else if raw.flags & stop_flags::SIGNAL_FAILED != 0 {
        format!("bpf_send_signal returned {}", raw.stop_rc)
    } else if raw.flags & stop_flags::MAP_FULL != 0 {
        "the map of stopped processes was full: the kernel stops only a process it names".into()
    } else {
        "the kernel did not stop it".into()
    }
}

/// The file to scan: the image through `/proc/<pid>/exe` when it is the
/// candidate, else the candidate by its path (a `#!` script, or the image
/// of a process already gone), always the inode the kernel reported.
fn open_target(
    raw: &ExecqStopRaw,
    path: &str,
    have_proc: bool,
) -> (Option<File>, &'static str, Option<String>) {
    let want = (raw.exe.dev, raw.exe.ino);
    let matches = |f: &File| file_key(f).is_some_and(|(d, i, ..)| (d, i) == want);
    if have_proc {
        if let Ok(f) = File::open(format!("/proc/{}/exe", raw.pid)) {
            if matches(&f) {
                return (Some(f), "image", None);
            }
        }
    }
    if raw.exe.flags & (exe_flags::MEMFD | exe_flags::DELETED) != 0 {
        return (
            None,
            "-",
            Some("a memfd or unlinked script: no path to open".into()),
        );
    }
    if !path.starts_with('/') {
        return (None, "-", Some("its path is unknown".into()));
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path);
    match f {
        Ok(f) if f.metadata().is_ok_and(|m| m.is_file()) && matches(&f) => {
            let what = if raw.flags & stop_flags::SCRIPT != 0 {
                "script"
            } else {
                "file"
            };
            (Some(f), what, None)
        }
        Ok(_) => (
            None,
            "-",
            Some("its path no longer names the executed inode".into()),
        ),
        Err(e) => (None, "-", Some(format!("open: {e}"))),
    }
}

#[cfg(test)]
mod tests;
