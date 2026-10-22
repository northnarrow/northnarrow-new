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

use common::execq::{ScanRequest, ScanResult, ScanVerdict};
use common::wire::exe::exe_flags;
use common::wire::execq::{
    class_names, counter, stop_flags, ExecqKey, ExecqKnown, ExecqStopRaw, ExecqStopped,
};
use nn_model::{Event, ExeIdentity};
use northnarrow_scan::supervisor::{ScannerEvent, Supervisor};
use tracing::{debug, info, warn};

use super::pkgtrust::{PackageTrust, PkgOutcome};
use super::policy::{decide, Action, Basis, Gate, Next, Outcome, Policy};
use super::record::{evidence, ExecqRecord};
use super::{kernel, SpawnLedger, AUDIT_OP, COUNTERS, HEARTBEAT_EVERY};
use crate::response::config::ExecutorConfig;
use crate::response::proc_ref::ProcRef;

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
    fn unstop(&mut self, pid: u32);
    fn stopped(&self) -> Vec<(u32, ExecqStopped)>;
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]);
    fn counters(&self) -> [u64; counter::SLOTS as usize];
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
    fn unstop(&mut self, pid: u32) {
        let _ = self.stopped.remove(&pid);
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
    fail_open_seen: (u64, u64),
    fail_open_at: Option<Instant>,
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
            fail_open_seen: (0, 0),
            fail_open_at: None,
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
                    + c[counter::SIGNAL_FAILED as usize],
                Ordering::Relaxed,
            );
            self.report_fail_open(
                c[counter::RING_FULL as usize],
                c[counter::SIGNAL_FAILED as usize],
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
        self.k.drain(&mut raws);
        for raw in raws {
            self.on_stop(raw, now);
        }
        self.dispatch(now);
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
        let proc_ref = ProcRef::open_started_at(raw.pid, raw.start_ns);
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
        let alive = proc_ref.is_live();
        let gate = Gate {
            since: now,
            budget: self.s.budget,
            stopped: held,
            verdict: basis.is_some(),
            spawn_judged: !held || !alive || self.ledger.check(raw.pid, raw.start_ns),
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
    /// [`DEGRADED_EVERY`], with the counts since the previous one.
    fn report_fail_open(&mut self, ring_full: u64, signal_failed: u64, now: Instant) {
        let (ring0, sig0) = self.fail_open_seen;
        if ring_full <= ring0 && signal_failed <= sig0 {
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
        warn!(
            ring_full = ring,
            signal_failed = sig,
            "exec quarantine fail-open: execs ran without being held"
        );
        self.r.degraded(&format!(
            "exec quarantine fail-open: {} exec(s) ran without being held or scanned since the \
             previous record — the events ring was full for {ring} (ring-drop slot execq), the \
             stop signal was refused for {sig}",
            ring + sig
        ));
        self.fail_open_seen = (ring_full, signal_failed);
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
                && (self.ledger.check(p.raw.pid, p.raw.start_ns) || !p.proc_ref.is_live())
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
        let Some(p) = self.entries.get(&id) else {
            return "none".into();
        };
        let was_held = p.held();
        let late = p.late_until.is_some();
        let held = was_held && !late;
        let alive = p.proc_ref.is_live();
        let pid = p.raw.pid;
        let mut out = if !enforce && o.refused {
            "observe: would refuse at exec (not held, the script ran)".to_string()
        } else if !enforce {
            format!("observe: would {} (not held)", o.action.as_str())
        } else {
            match o.action {
                Action::Resume if late => "running (resumed by the default policy)".to_string(),
                Action::Resume if !held => {
                    format!("not held ({}): ran unstopped", not_held_reason(&p.raw))
                }
                Action::Resume if !alive => {
                    "ended while held (the rule engine's response, or a signal from elsewhere)"
                        .to_string()
                }
                Action::Resume => match p.proc_ref.signal(libc::SIGCONT) {
                    Ok(()) => {
                        COUNTERS.resumed.fetch_add(1, Ordering::Relaxed);
                        "resumed".to_string()
                    }
                    Err(e) => format!("resume failed: {e}"),
                },
                Action::Kill if !alive => "already ended".to_string(),
                Action::Kill => match p.proc_ref.signal(libc::SIGKILL) {
                    Ok(()) => {
                        COUNTERS.killed.fetch_add(1, Ordering::Relaxed);
                        if held {
                            "killed while held".to_string()
                        } else {
                            "killed".to_string()
                        }
                    }
                    Err(e) => format!("kill failed: {e}"),
                },
            }
        };
        if enforce && o.action == Action::Kill && o.quarantine {
            out.push_str("; ");
            out.push_str(&self.quarantine(id));
        }
        if was_held && !late {
            self.k.unstop(pid);
        }
        out
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
            Ok(h) => h,
            Err(e) => return format!("not quarantined ({e})"),
        };
        use crate::response::ExecutionOutcome as X;
        match crate::response::quarantine::quarantine_handle(&handle, p.raw.pid, cfg) {
            X::Quarantined { vault_id, .. } => {
                COUNTERS.quarantined.fetch_add(1, Ordering::Relaxed);
                format!("quarantined (vault {vault_id})")
            }
            X::AlreadyGone { .. } => {
                "not quarantined (no file on disk: a memfd or unlinked)".into()
            }
            X::WouldExecute { .. } => "would quarantine (detect-only)".into(),
            X::Refused { reason, .. } => format!("not quarantined ({reason})"),
            X::Failed { errno, .. } => format!("quarantine failed (errno {errno})"),
            other => format!("quarantine: {other:?}"),
        }
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

    /// Resume what an agent that died left stopped.
    fn recover(&mut self) {
        let left = self.k.stopped();
        if left.is_empty() {
            return;
        }
        let mut resumed = Vec::new();
        let mut gone = 0u64;
        for (pid, st) in &left {
            let pr = ProcRef::open_started_at(*pid, st.start_ns);
            if pr.is_live() && pr.signal(libc::SIGCONT).is_ok() {
                resumed.push(*pid);
            } else {
                gone += 1;
            }
            self.k.unstop(*pid);
        }
        COUNTERS
            .recovered
            .fetch_add(resumed.len() as u64, Ordering::Relaxed);
        warn!(
            resumed = resumed.len(),
            gone, "exec quarantine: processes left stopped by the previous agent resumed"
        );
        self.r.audit(
            serde_json::json!({
                "kind": "recovered_at_boot",
                "detail": "held by an agent that exited before deciding; resumed undecided",
                "resumed": resumed,
                "gone": gone,
                "op": AUDIT_OP,
            }),
            "success",
        );
    }

    /// The agent stops: resume every held process, clear the heartbeat.
    fn stop_all(&mut self) {
        self.k.beat(0);
        let mut resumed = Vec::new();
        let ids: Vec<u64> = self.entries.keys().copied().collect();
        for id in ids {
            if let Some(p) = self.entries.remove(&id) {
                if p.held() && p.late_until.is_none() {
                    if p.proc_ref.signal(libc::SIGCONT).is_ok() {
                        resumed.push(p.raw.pid);
                    }
                    self.k.unstop(p.raw.pid);
                }
            }
        }
        if !resumed.is_empty() {
            self.r.audit(
                serde_json::json!({
                    "kind": "stopping",
                    "detail": "the agent stops: held processes resumed undecided",
                    "resumed": resumed,
                    "op": AUDIT_OP,
                }),
                "success",
            );
        }
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
