//! The guard at run time: the fanotify reader, the copiers, the index
//! worker, the deadline backstop and the rescan.
//!
//! ```text
//!  kernel ──FAN_OPEN_PERM──▶ reader ──(fast: allow now)──────────────▶ FAN_ALLOW
//!                              │
//!                              └─copy job─▶ copier ─(copy, then)─────▶ FAN_ALLOW
//!                                              │                         ▲
//!                                              └─commit─▶ index worker   │
//!                                     backstop ─(deadline + 20..25 ms)───┘
//! ```
//!
//! **Never block indefinitely.** Every event is answered `FAN_ALLOW` —
//! this lot never denies — by exactly one party: the reader for the fast
//! paths, the copier when its copy is done or abandoned, or the backstop
//! when the deadline passed with the copier still in a syscall. The bounds,
//! counted from when the reader read the event (time in the kernel queue
//! is not counted): the copy path is answered at the latest
//! `event_budget_ms` + 25 ms ([`COPY_ANSWER_BOUND`]: the backstop's 20 ms
//! grace and its 5 ms poll — 75 ms with the default budget), and a copy
//! answered by the backstop is discarded; a fast path has no deadline of
//! its own — it is answered once the reader has decided (`/proc` reads and
//! the index's lock), bounded only by the 3 s stall below. The reader
//! touches only `/proc` and the event's descriptor — never a file on a
//! marked filesystem, whose open would wait on the reader itself; the
//! agent's other threads' opens reach the reader as events of its own
//! process and are allowed first thing, and those threads never open a
//! journal file while holding a lock the reader takes (the journal's, the
//! index's), which made the guard wait on itself on a scope marked by
//! mount or filesystem, whose journal lies under the mark. If the reader stops making
//! progress for 3 s (a `/proc` read stuck on a hung task), the backstop
//! closes the group: the kernel then allows every pending and queued open
//! and generates no more events — the guard is off, signed
//! (`reader_stalled`), the host keeps running.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use super::config::MarkKind;
use super::copy::{snapshot, Snapshot};
use super::fanotify::{
    fd_path, fstat, is_own_thread, parse_events, read_open_intent, tgid_of, Group, OpenIntent,
    RawEvent,
};
use super::index::{FileState, Method, PostWrite, Refusal, Reservation};
use super::journal::{host_view, Journal};
use super::store::{now_ms, Stats, Store};
use super::trust::{proc_start_ticks, ProcId, TrustFilter, WriterInfo};
use crate::posture::lineage::AuthSessionTracker;

/// Extra time the backstop gives a copier past its deadline.
const BACKSTOP_GRACE: Duration = Duration::from_millis(20);
/// The backstop's poll while copies are pending.
const BACKSTOP_POLL: Duration = Duration::from_millis(5);
/// The backstop's sleep while nothing is pending: at most the grace, so a
/// copy queued while it sleeps is still answered by its deadline + grace +
/// poll ([`COPY_ANSWER_BOUND`]). It slept 100 ms, which put the bound at
/// about 170 ms with the default budget (review of lab PR 222).
const BACKSTOP_IDLE: Duration = BACKSTOP_GRACE;
/// How long after the reader read an event the copy path answers it at the
/// latest, past `event_budget_ms`: the grace and one poll (25 ms; 75 ms
/// with the default budget of 50 ms).
pub const COPY_ANSWER_BOUND: Duration =
    Duration::from_millis(BACKSTOP_GRACE.as_millis() as u64 + BACKSTOP_POLL.as_millis() as u64);
/// The reader is stalled after this long without progress.
const STALL: Duration = Duration::from_secs(3);
/// Copy jobs queued at most (beyond: the open is allowed uncopied).
const COPY_QUEUE: usize = 256;
/// Index-worker messages queued at most.
const WORK_QUEUE: usize = 4096;
/// How often the dirs-marked scopes are walked again for new directories.
const RESCAN: Duration = Duration::from_secs(60);
/// Signed summaries of a degradation, at most this often.
const DEGRADED_EVERY_MS: u64 = 10 * 60 * 1000;

struct Pending {
    fd: OwnedFd,
    deadline: Instant,
    read_at: Instant,
}

struct CopyJob {
    id: u64,
    src: OwnedFd,
    st: libc::stat,
    file: FileState,
    scope: usize,
    reservation: Reservation,
    writer: ProcId,
    info: Arc<WriterInfo>,
    deadline: Instant,
}

enum Work {
    Commit {
        reservation: Reservation,
        file: FileState,
        writer: ProcId,
        info: Arc<WriterInfo>,
        at_ms: u64,
        method: Method,
    },
    Forget(Vec<u64>),
    Degraded {
        reason: &'static str,
        detail: String,
    },
}

/// The running guard.
pub struct Runtime {
    pub store: Arc<Store>,
    group: Group,
    trust: TrustFilter,
    pending: Mutex<HashMap<u64, Pending>>,
    inflight: Mutex<HashSet<(u64, u64, ProcId)>>,
    next_id: AtomicU64,
    /// Monotonic milliseconds of the reader's last progress.
    heartbeat: AtomicU64,
    epoch: Instant,
    stop: AtomicBool,
    state: Mutex<String>,
    pub flags_source: String,
    marks: Vec<AtomicU64>,
    copy_methods: Vec<&'static str>,
    low_space: Vec<(AtomicU64, AtomicBool)>,
    copy_tx: Mutex<Option<SyncSender<CopyJob>>>,
    work_tx: SyncSender<Work>,
    budget: Duration,
}

/// Probe: does `/proc/<tid>/syscall` of another task read?
fn flags_source() -> String {
    match std::fs::read_to_string("/proc/1/syscall") {
        Ok(_) => "proc_syscall".into(),
        Err(e) => format!("unavailable ({e}): every open is treated as a write"),
    }
}

/// Probe: can the journal's filesystem reflink?
fn probe_reflink(objects: i32) -> bool {
    let src = std::ffi::CString::new(".probe-src").unwrap_or_default();
    let dst = std::ffi::CString::new(".probe-dst").unwrap_or_default();
    // SAFETY: valid directory descriptor and names; both files removed.
    unsafe {
        libc::unlinkat(objects, src.as_ptr(), 0);
        libc::unlinkat(objects, dst.as_ptr(), 0);
    }
    let ok = (|| {
        let s = super::copy::create_object(objects, &src).ok()?;
        let block = [0x5au8; 4096];
        // SAFETY: valid descriptor and buffer.
        unsafe {
            libc::write(
                s.as_raw_fd(),
                block.as_ptr() as *const libc::c_void,
                block.len(),
            )
        };
        // FICLONE needs a readable source.
        // SAFETY: valid directory descriptor and name.
        let r = unsafe { libc::openat(objects, src.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if r < 0 {
            return None;
        }
        // SAFETY: fresh descriptor.
        let r = unsafe { OwnedFd::from_raw_fd(r) };
        let d = super::copy::create_object(objects, &dst).ok()?;
        super::copy::reflink(r.as_raw_fd(), d.as_raw_fd()).ok()
    })()
    .is_some();
    // SAFETY: as above.
    unsafe {
        libc::unlinkat(objects, src.as_ptr(), 0);
        libc::unlinkat(objects, dst.as_ptr(), 0);
    }
    ok
}

/// The scope is a mount point in the host's mount namespace.
fn is_mount_point(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/1/mountinfo")
        .or_else(|_| std::fs::read_to_string("/proc/self/mountinfo"))
    else {
        return false;
    };
    let want = path.to_string_lossy();
    text.lines().any(|l| {
        l.split_whitespace()
            .nth(4)
            .is_some_and(|mp| mp.replace("\\040", " ") == want)
    })
}

impl Runtime {
    /// Start the guard on `store`'s scopes. Needs `CAP_SYS_ADMIN`
    /// (`fanotify_init` with a content class).
    pub fn start(store: Arc<Store>, tracker: AuthSessionTracker) -> Result<Arc<Self>, String> {
        let group = Group::init().map_err(|e| {
            if e.raw_os_error() == Some(libc::EPERM) {
                format!(
                    "fanotify_init: {e} — permission events need CAP_SYS_ADMIN \
                     (install deploy/systemd/20-cow-guard.conf)"
                )
            } else {
                format!("fanotify_init: {e}")
            }
        })?;
        let cfg = &store.cfg;
        let (copy_tx, copy_rx) = std::sync::mpsc::sync_channel::<CopyJob>(COPY_QUEUE);
        let (work_tx, work_rx) = std::sync::mpsc::sync_channel::<Work>(WORK_QUEUE);
        let copy_methods = store
            .objects_fds
            .iter()
            .map(|fd| {
                if *fd >= 0 && probe_reflink(*fd) {
                    "reflink"
                } else {
                    "copy"
                }
            })
            .collect();
        let rt = Arc::new(Self {
            trust: TrustFilter::new(&cfg.trusted_writers, tracker),
            group,
            pending: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashSet::new()),
            next_id: AtomicU64::new(1),
            heartbeat: AtomicU64::new(0),
            epoch: Instant::now(),
            stop: AtomicBool::new(false),
            state: Mutex::new("running".into()),
            flags_source: flags_source(),
            marks: cfg.scopes.iter().map(|_| AtomicU64::new(0)).collect(),
            copy_methods,
            low_space: cfg
                .scopes
                .iter()
                .map(|_| (AtomicU64::new(0), AtomicBool::new(false)))
                .collect(),
            copy_tx: Mutex::new(Some(copy_tx)),
            work_tx,
            budget: Duration::from_millis(cfg.event_budget_ms),
            store: Arc::clone(&store),
        });
        let mut marked = 0;
        for i in 0..rt.store.cfg.scopes.len() {
            if rt.store.objects_fds[i] < 0 {
                continue;
            }
            match rt.mark_scope(i) {
                Ok(n) => {
                    rt.marks[i].store(n, Ordering::Relaxed);
                    marked += 1;
                }
                Err(e) => {
                    let s = &rt.store.cfg.scopes[i];
                    warn!(scope = %s.path.display(), error = %e, "copy on first write: scope not marked");
                    rt.store.sign_degraded(
                        "scope_unmarked",
                        &format!("{}: {e}", s.path.display()),
                        serde_json::json!({ "scope": s.path.display().to_string() }),
                    );
                }
            }
        }
        if marked == 0 {
            rt.group.close_now();
            return Err("no scope could be marked".into());
        }
        rt.spawn_threads(copy_rx, work_rx)?;
        Ok(rt)
    }

    fn spawn_threads(
        self: &Arc<Self>,
        copy_rx: Receiver<CopyJob>,
        work_rx: Receiver<Work>,
    ) -> Result<(), String> {
        let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn(f)
                .map(|_| ())
                .map_err(|e| format!("spawn {name}: {e}"))
        };
        self.heartbeat.store(self.mono_ms(), Ordering::Relaxed);
        let copy_rx = Arc::new(Mutex::new(copy_rx));
        for n in 0..self.store.cfg.copiers {
            let rt = Arc::clone(self);
            let rx = Arc::clone(&copy_rx);
            spawn(
                &format!("nn-cow-copy-{n}"),
                Box::new(move || rt.copier_loop(rx)),
            )?;
        }
        let rt = Arc::clone(self);
        spawn("nn-cow-index", Box::new(move || rt.worker_loop(work_rx)))?;
        let rt = Arc::clone(self);
        spawn("nn-cow-backstop", Box::new(move || rt.backstop_loop()))?;
        if self
            .store
            .cfg
            .scopes
            .iter()
            .any(|s| s.mark == MarkKind::Dirs)
        {
            let rt = Arc::clone(self);
            spawn("nn-cow-rescan", Box::new(move || rt.rescan_loop()))?;
        }
        let rt = Arc::clone(self);
        spawn(
            "nn-cow-reader",
            Box::new(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rt.reader_loop()));
                if r.is_err() || !rt.stop.load(Ordering::Relaxed) {
                    // Never leave the group open without a reader.
                    rt.group.close_now();
                    rt.set_state("stopped: the fanotify reader ended");
                    rt.store.sign_degraded(
                        "reader_ended",
                        "the fanotify reader ended: guard off",
                        serde_json::json!({}),
                    );
                }
            }),
        )
    }

    fn mono_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn set_state(&self, s: &str) {
        *self.state.lock() = s.to_string();
    }

    pub fn state(&self) -> String {
        self.state.lock().clone()
    }

    pub fn copy_method(&self, scope: usize) -> &'static str {
        self.copy_methods.get(scope).copied().unwrap_or("copy")
    }

    pub fn marks(&self, scope: usize) -> u64 {
        self.marks
            .get(scope)
            .map(|m| m.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Stop the guard: the group is closed (the kernel allows whatever is
    /// pending) and the threads end.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.group.close_now();
        self.copy_tx.lock().take();
        self.set_state("stopped");
    }

    fn mark_scope(&self, i: usize) -> Result<u64, String> {
        let s = &self.store.cfg.scopes[i];
        let host = host_view(&s.path);
        let meta = std::fs::symlink_metadata(&host).map_err(|e| format!("stat: {e}"))?;
        if !meta.is_dir() {
            return Err("not a directory (or a link)".into());
        }
        match s.mark {
            MarkKind::Mount | MarkKind::Filesystem => {
                if !is_mount_point(&s.path) {
                    return Err(format!(
                        "mark={} needs a mount point; {} is not one (use mark=dirs)",
                        s.mark.as_str(),
                        s.path.display()
                    ));
                }
                let flag = if s.mark == MarkKind::Mount {
                    libc::FAN_MARK_MOUNT
                } else {
                    libc::FAN_MARK_FILESYSTEM
                };
                self.group
                    .mark(flag, libc::FAN_OPEN_PERM, &host)
                    .map_err(|e| format!("fanotify_mark: {e}"))?;
                Ok(1)
            }
            MarkKind::Dirs => self.mark_dirs(i),
        }
    }

    /// Mark every directory of the scope's tree (same filesystem, no link
    /// followed, the journal skipped), up to `max_dir_marks`.
    fn mark_dirs(&self, i: usize) -> Result<u64, String> {
        use std::os::unix::fs::MetadataExt;
        let s = &self.store.cfg.scopes[i];
        let host = host_view(&s.path);
        let journal = host_view(&s.journal);
        let dev = std::fs::symlink_metadata(&host)
            .map_err(|e| format!("stat: {e}"))?
            .dev();
        let mut stack = vec![host];
        let mut n = 0u64;
        let cap = self.store.cfg.max_dir_marks as u64;
        while let Some(dir) = stack.pop() {
            if n >= cap {
                warn!(scope = %s.path.display(), cap, "copy on first write: directory mark cap reached — deeper directories are not protected");
                let _ = self.work_tx.try_send(Work::Degraded {
                    reason: "mark_cap",
                    detail: format!("{}: more than {cap} directories", s.path.display()),
                });
                break;
            }
            match self.group.mark(
                libc::FAN_MARK_ONLYDIR,
                libc::FAN_OPEN_PERM | libc::FAN_EVENT_ON_CHILD,
                &dir,
            ) {
                Ok(()) => n += 1,
                Err(e) if n == 0 => return Err(format!("fanotify_mark: {e}")),
                Err(e) => {
                    warn!(dir = %dir.display(), error = %e, "copy on first write: a directory could not be marked");
                    continue;
                }
            }
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for ent in rd.filter_map(|e| e.ok()) {
                let Ok(ft) = ent.file_type() else { continue };
                if !ft.is_dir() {
                    continue;
                }
                let p = ent.path();
                if p == journal {
                    continue;
                }
                if ent.metadata().is_ok_and(|m| m.dev() == dev) {
                    stack.push(p);
                }
            }
        }
        Ok(n)
    }

    fn rescan_loop(&self) {
        let mut last = Instant::now();
        while !self.stop.load(Ordering::Relaxed) && self.group.is_open() {
            std::thread::sleep(Duration::from_millis(500));
            if last.elapsed() < RESCAN {
                continue;
            }
            last = Instant::now();
            for i in 0..self.store.cfg.scopes.len() {
                if self.store.cfg.scopes[i].mark == MarkKind::Dirs && self.store.objects_fds[i] >= 0
                {
                    if let Ok(n) = self.mark_dirs(i) {
                        self.marks[i].store(n, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    // ── the reader ────────────────────────────────────────────────────

    /// The guard is being stopped ([`Self::stop`]): the group closed on
    /// purpose, so a reader that sees it go is no failure.
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || !self.group.is_open()
    }

    fn reader_loop(&self) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            self.heartbeat.store(self.mono_ms(), Ordering::Relaxed);
            if self.stopping() {
                info!("copy on first write: the fanotify reader ends (the guard stops)");
                return;
            }
            let fd = self.group.raw();
            if fd < 0 {
                return;
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd (a number the stop may have closed
            // meanwhile: poll only reports, the read below is the group's).
            let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
            if rc <= 0 {
                continue;
            }
            let n = match self.group.read_events(&mut buf) {
                Ok(Some(n)) => n,
                // closed by the guard's stop between the poll and the read
                Ok(None) => {
                    info!("copy on first write: the fanotify reader ends (the guard stops)");
                    return;
                }
                Err(e) if matches!(e.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) => continue,
                Err(e) if self.stopping() => {
                    debug!(error = %e, "copy on first write: the fanotify reader ends (the guard stops)");
                    return;
                }
                Err(e) => {
                    // At run time a failed read is the guard going off: an
                    // ERROR, and the reader's end is signed as a degradation
                    // (`reader_ended`, the thread's wrapper).
                    error!(error = %e, "copy on first write: reading the fanotify group failed — guard off");
                    return;
                }
            };
            let (events, bad) = parse_events(&buf[..n]);
            for ev in events {
                self.heartbeat.store(self.mono_ms(), Ordering::Relaxed);
                self.handle(ev);
            }
            if let Some(why) = bad {
                // An event we cannot read is an open we cannot answer.
                error!(why, "copy on first write: unreadable fanotify record — closing the group (every open allowed)");
                return;
            }
        }
    }

    fn degraded(&self, reason: &'static str, detail: String) {
        let _ = self.work_tx.try_send(Work::Degraded { reason, detail });
    }

    fn allow_fast(&self, fd: OwnedFd, read_at: Instant, counter: &AtomicU64) {
        Stats::bump(counter);
        if let Err(e) = self.group.allow(fd.as_raw_fd()) {
            warn!(error = %e, "copy on first write: answering an open failed");
        }
        drop(fd);
        self.store
            .stats
            .answered(false, read_at.elapsed().as_micros() as u64);
    }

    /// Answer a dispatched event (whoever comes first).
    fn finish(&self, id: u64) -> bool {
        let Some(p) = self.pending.lock().remove(&id) else {
            return false;
        };
        if let Err(e) = self.group.allow(p.fd.as_raw_fd()) {
            warn!(error = %e, "copy on first write: answering an open failed");
        }
        let _ = p.deadline;
        self.store
            .stats
            .answered(true, p.read_at.elapsed().as_micros() as u64);
        true
    }

    fn handle(&self, ev: RawEvent) {
        let read_at = Instant::now();
        let s = &self.store.stats;
        Stats::bump(&s.events);
        if ev.mask & libc::FAN_Q_OVERFLOW != 0 {
            Stats::bump(&s.queue_overflows);
            self.degraded(
                "queue_overflow",
                "the fanotify queue overflowed: opens passed without a copy".into(),
            );
            return;
        }
        if ev.fd < 0 {
            return;
        }
        // SAFETY: the kernel opened this descriptor for us.
        let fd = unsafe { OwnedFd::from_raw_fd(ev.fd) };
        if is_own_thread(ev.tid) {
            return self.allow_fast(fd, read_at, &s.allowed_own);
        }
        let Ok(st) = fstat(fd.as_raw_fd()) else {
            return self.allow_fast(fd, read_at, &s.allowed_not_regular);
        };
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return self.allow_fast(fd, read_at, &s.allowed_not_regular);
        }
        if st.st_size <= 0 {
            return self.allow_fast(fd, read_at, &s.allowed_empty);
        }
        if read_open_intent(ev.tid) == OpenIntent::ReadOnly {
            return self.allow_fast(fd, read_at, &s.allowed_read_only);
        }
        let tgid = tgid_of(ev.tid).unwrap_or(ev.tid as u32);
        let start = proc_start_ticks(Path::new("/proc"), tgid).unwrap_or(0);
        let writer = ProcId { pid: tgid, start };
        let info = self.trust.evaluate(tgid, start);
        let (dev, ino) = (st.st_dev, st.st_ino);
        self.store.record_post_write(
            dev,
            ino,
            PostWrite {
                at_ms: now_ms(),
                writer,
                program: info.program.clone(),
                trusted: info.trust.is_trusted(),
            },
        );
        if info.trust.is_trusted() {
            return self.allow_fast(fd, read_at, &s.allowed_trusted);
        }
        let Some(path) = fd_path(fd.as_raw_fd()) else {
            return self.allow_fast(fd, read_at, &s.skipped_unresolved_path);
        };
        let cfg = &self.store.cfg;
        let Some(scope) = cfg.scope_of(Path::new(&path)) else {
            return self.allow_fast(fd, read_at, &s.allowed_outside_scope);
        };
        if cfg.in_journal(Path::new(&path)) || self.store.objects_fds[scope] < 0 {
            return self.allow_fast(fd, read_at, &s.allowed_outside_scope);
        }
        let key = (dev, ino, writer);
        if self.inflight.lock().contains(&key)
            || self.store.index.lock().has_entry_for(dev, ino, writer)
        {
            return self.allow_fast(fd, read_at, &s.allowed_already_copied);
        }
        let file = FileState {
            path,
            dev,
            ino,
            size: st.st_size as u64,
            mtime_ns: st.st_mtime * 1_000_000_000 + st.st_mtime_nsec,
            ctime_ns: st.st_ctime * 1_000_000_000 + st.st_ctime_nsec,
            mode: st.st_mode,
            uid: st.st_uid,
            gid: st.st_gid,
            btime_ns: super::fanotify::btime(fd.as_raw_fd(), None),
        };
        let reusable = self.store.index.lock().reusable_object(&file);
        if let Some(obj) = reusable {
            if self
                .store
                .link(
                    obj,
                    file.clone(),
                    writer,
                    info.program.clone(),
                    info.lineage.clone(),
                )
                .is_some()
            {
                return self.allow_fast(fd, read_at, &s.copies_linked);
            }
        }
        if self.low_on_space(scope) {
            self.degraded(
                "low_space",
                format!(
                    "{}: under {}% free — no copy taken",
                    cfg.scopes[scope].journal.display(),
                    cfg.min_free_percent
                ),
            );
            return self.allow_fast(fd, read_at, &s.skipped_low_space);
        }
        let (reservation, evicted) = match self.store.reserve(scope, file.size) {
            Ok(r) => r,
            Err(Refusal::BudgetFull) => {
                self.degraded(
                    "budget_full",
                    format!(
                        "{}: the journal's budget is held by recent copies",
                        cfg.scopes[scope].path.display()
                    ),
                );
                return self.allow_fast(fd, read_at, &s.skipped_budget_full);
            }
            Err(Refusal::LargerThanBudget) => {
                return self.allow_fast(fd, read_at, &s.skipped_larger_than_budget)
            }
            Err(Refusal::UnknownScope) => return self.allow_fast(fd, read_at, &s.skipped_failed),
        };
        if !evicted.is_empty() {
            if let Err(
                TrySendError::Full(Work::Forget(v)) | TrySendError::Disconnected(Work::Forget(v)),
            ) = self.work_tx.try_send(Work::Forget(evicted))
            {
                // unlinks only: no open from this thread
                self.store.forget_objects(&v);
            }
        }
        let src = match fd.try_clone() {
            Ok(d) => d,
            Err(_) => {
                self.store.release(reservation);
                return self.allow_fast(fd, read_at, &s.skipped_failed);
            }
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let deadline = read_at + self.budget;
        self.pending.lock().insert(
            id,
            Pending {
                fd,
                deadline,
                read_at,
            },
        );
        self.inflight.lock().insert(key);
        let job = CopyJob {
            id,
            src,
            st,
            file,
            scope,
            reservation,
            writer,
            info,
            deadline,
        };
        let sent = match self.copy_tx.lock().as_ref() {
            Some(tx) => tx.try_send(job).map_err(|e| match e {
                TrySendError::Full(j) | TrySendError::Disconnected(j) => j,
            }),
            None => Err(job),
        };
        if let Err(job) = sent {
            self.finish(job.id);
            self.store.release(job.reservation);
            self.inflight.lock().remove(&key);
            Stats::bump(&s.skipped_queue_full);
            self.degraded(
                "queue_full",
                "the copiers are busy: opens passed without a copy".into(),
            );
        }
    }

    /// Under `min_free_percent` free on the journal's filesystem (checked
    /// at most once a second).
    fn low_on_space(&self, scope: usize) -> bool {
        let (checked, low) = &self.low_space[scope];
        let now = self.mono_ms();
        if now.saturating_sub(checked.load(Ordering::Relaxed)) < 1000
            && checked.load(Ordering::Relaxed) != 0
        {
            return low.load(Ordering::Relaxed);
        }
        checked.store(now.max(1), Ordering::Relaxed);
        let min = self.store.cfg.min_free_percent as u64;
        // SAFETY: zeroed statvfs filled by the kernel for a valid descriptor.
        let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
        let fd = self.store.objects_fds[scope];
        // SAFETY: valid descriptor and buffer.
        let ok = unsafe { libc::fstatvfs(fd, &mut sv) } == 0;
        let is_low =
            ok && sv.f_blocks > 0 && (sv.f_bavail as u64) * 100 < (sv.f_blocks as u64) * min;
        low.store(is_low, Ordering::Relaxed);
        is_low
    }

    // ── the copiers ───────────────────────────────────────────────────

    fn copier_loop(&self, rx: Arc<Mutex<Receiver<CopyJob>>>) {
        loop {
            let job = {
                let rx = rx.lock();
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(j) => j,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if self.stop.load(Ordering::Relaxed) {
                            return;
                        }
                        continue;
                    }
                    Err(_) => return,
                }
            };
            self.copy_one(job);
        }
    }

    fn copy_one(&self, job: CopyJob) {
        let s = &self.store.stats;
        let name = Journal::object_name(job.reservation.object);
        let out = snapshot(
            job.src.as_raw_fd(),
            &job.st,
            self.store.objects_fds[job.scope],
            &name,
            self.store.cfg.copy_cap,
            job.deadline,
        );
        let in_time = self.finish(job.id);
        let key = (job.file.dev, job.file.ino, job.writer);
        let abandon = |counter: &AtomicU64| {
            Stats::bump(counter);
            self.store.release(job.reservation);
            self.inflight.lock().remove(&key);
        };
        match out {
            Snapshot::Reflinked { bytes } | Snapshot::Copied { bytes } => {
                let method = if matches!(out, Snapshot::Reflinked { .. }) {
                    Method::Reflink
                } else {
                    Method::Copy
                };
                if !in_time {
                    // the backstop answered: the writer may have written already
                    if let Some(j) = self.store.journals[job.scope].as_ref() {
                        j.lock().remove_object(job.reservation.object);
                    }
                    abandon(&s.late_answered_by_backstop);
                    return;
                }
                Stats::bump(if method == Method::Reflink {
                    &s.copies_reflink
                } else {
                    &s.copies_plain
                });
                s.copied_bytes.fetch_add(bytes, Ordering::Relaxed);
                let work = Work::Commit {
                    reservation: job.reservation,
                    file: job.file,
                    writer: job.writer,
                    info: job.info,
                    at_ms: now_ms(),
                    method,
                };
                if self.work_tx.send(work).is_err() {
                    self.inflight.lock().remove(&key);
                }
            }
            Snapshot::OverCap => {
                self.degraded(
                    "over_cap",
                    format!(
                        "{} is over the copy cap and the filesystem cannot reflink",
                        job.file.path
                    ),
                );
                abandon(&s.skipped_over_cap)
            }
            Snapshot::Deadline => {
                self.degraded(
                    "event_budget",
                    format!(
                        "the copy of {} did not finish within {} ms",
                        job.file.path,
                        self.budget.as_millis()
                    ),
                );
                abandon(&s.skipped_deadline)
            }
            Snapshot::SourceChanged => abandon(&s.skipped_source_changed),
            Snapshot::Failed(e) => {
                self.degraded("copy_failed", format!("{}: {e}", job.file.path));
                abandon(&s.skipped_failed)
            }
        }
    }

    // ── the index worker ──────────────────────────────────────────────

    fn worker_loop(&self, rx: Receiver<Work>) {
        let mut degraded: HashMap<&'static str, (u64, u64, String)> = HashMap::new();
        let mut last_tick = Instant::now();
        let mut last_sync = Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Work::Commit {
                    reservation,
                    file,
                    writer,
                    info,
                    at_ms,
                    method,
                }) => {
                    let key = (file.dev, file.ino, writer);
                    if let Err(e) = self.store.commit(
                        reservation,
                        file,
                        writer,
                        info.program.clone(),
                        info.lineage.clone(),
                        at_ms,
                        method,
                    ) {
                        warn!(error = %e, "copy on first write: recording a copy failed");
                        Stats::bump(&self.store.stats.skipped_failed);
                    }
                    self.inflight.lock().remove(&key);
                }
                Ok(Work::Forget(v)) => self.store.forget_objects(&v),
                Ok(Work::Degraded { reason, detail }) => {
                    let now = now_ms();
                    let e = degraded.entry(reason).or_insert((0, 0, String::new()));
                    if e.1 == 0 {
                        warn!(reason, detail = %nn_model::log_escape::Escaped(&detail), "copy on first write degraded");
                        self.store.sign_degraded(
                            reason,
                            &detail,
                            serde_json::json!({ "count": 1 }),
                        );
                        *e = (0, now, detail);
                    } else {
                        e.0 += 1;
                        e.2 = detail;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if self.stop.load(Ordering::Relaxed) {
                        self.store.sync();
                        return;
                    }
                }
                Err(_) => {
                    self.store.sync();
                    return;
                }
            }
            if last_sync.elapsed() >= Duration::from_secs(1) {
                self.store.sync();
                last_sync = Instant::now();
            }
            if last_tick.elapsed() >= Duration::from_secs(60) {
                last_tick = Instant::now();
                let now = now_ms();
                self.store.expire(now);
                self.store.compact_all();
                for (reason, (count, last, detail)) in degraded.iter_mut() {
                    if *count > 0 && now.saturating_sub(*last) >= DEGRADED_EVERY_MS {
                        self.store.sign_degraded(
                            reason,
                            detail,
                            serde_json::json!({ "count": *count, "summary": true }),
                        );
                        *count = 0;
                        *last = now;
                    }
                }
            }
        }
    }

    // ── the backstop ──────────────────────────────────────────────────

    fn backstop_loop(&self) {
        loop {
            if self.stop.load(Ordering::Relaxed) || !self.group.is_open() {
                return;
            }
            let busy = !self.pending.lock().is_empty();
            std::thread::sleep(if busy { BACKSTOP_POLL } else { BACKSTOP_IDLE });
            let now = Instant::now();
            let expired: Vec<u64> = self
                .pending
                .lock()
                .iter()
                .filter(|(_, p)| p.deadline + BACKSTOP_GRACE <= now)
                .map(|(id, _)| *id)
                .collect();
            for id in expired {
                if self.finish(id) {
                    Stats::bump(&self.store.stats.late_answered_by_backstop);
                    self.degraded(
                        "event_budget",
                        "a copy outlived its budget: the open was allowed by the backstop".into(),
                    );
                }
            }
            let since = self
                .mono_ms()
                .saturating_sub(self.heartbeat.load(Ordering::Relaxed));
            if since > STALL.as_millis() as u64
                && self.group.is_open()
                && !self.stop.load(Ordering::Relaxed)
            {
                error!(
                    stalled_ms = since,
                    "copy on first write: the fanotify reader stalled — closing the group (every open allowed, guard off)"
                );
                self.group.close_now();
                self.pending.lock().clear();
                self.set_state("stopped: the fanotify reader stalled");
                self.store.sign_degraded(
                    "reader_stalled",
                    &format!("no progress for {since} ms: the group was closed, the guard is off"),
                    serde_json::json!({}),
                );
                return;
            }
        }
    }

    /// The guard as `status --key` shows it.
    pub fn status(&self) -> nn_proto::admin_protocol::CowGuardStatus {
        use nn_proto::admin_protocol::{CowGuardStatus, CowScopeStatus};
        let ix = self.store.index.lock();
        let scopes = self
            .store
            .cfg
            .scopes
            .iter()
            .enumerate()
            .map(|(i, sc)| {
                let u = ix.usage(i).unwrap_or_default();
                CowScopeStatus {
                    path: sc.path.display().to_string(),
                    mark: sc.mark.as_str().to_string(),
                    journal: sc.journal.display().to_string(),
                    copy_method: self.copy_method(i).to_string(),
                    marks: self.marks(i),
                    budget_bytes: u.budget,
                    used_bytes: u.used,
                    entries: ix.entry_count(i) as u64,
                    objects: ix.object_count(i) as u64,
                }
            })
            .collect();
        drop(ix);
        CowGuardStatus {
            state: self.state(),
            flags_source: self.flags_source.clone(),
            auto_restore: self.store.cfg.auto_restore,
            scopes,
            counters: self.store.stats.snapshot(),
        }
    }

    /// Lab and tests: is the reader alive (its last progress, ms ago)?
    pub fn reader_idle_ms(&self) -> u64 {
        self.mono_ms()
            .saturating_sub(self.heartbeat.load(Ordering::Relaxed))
    }
}
