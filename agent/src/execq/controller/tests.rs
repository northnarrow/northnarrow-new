//! The controller on real processes (lab PR 223): children stopped with
//! `SIGSTOP` stand for what the kernel holds, a fake kernel side records
//! what the controller writes, and the scanner is the real engine in
//! process.

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use common::wire::exe::{exe_path_slot, EXE_PATH_SLOT_LEN};
use common::wire::execq::class;
use nn_proto::execq::{HashEntry, ScanConfig};
use northnarrow_scan::engine::Engine;
use northnarrow_scan::ipc::FdFile;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use super::*;
use crate::execq::policy::Action;

// ── fakes ───────────────────────────────────────────────────────────

#[derive(Default)]
struct KState {
    queue: Vec<ExecqStopRaw>,
    beats: Vec<u64>,
    known: Vec<(ExecqKey, ExecqKnown)>,
    unstopped: Vec<u32>,
    left: Vec<(u32, ExecqStopped)>,
    counters: [u64; counter::SLOTS as usize],
    /// Lot 311 (BUG-98): the roots last written.
    roots: Option<Vec<(ExecqKey, u32)>>,
    /// Lot 311 (F3): the roots map's size (`None`: unbounded).
    roots_cap: Option<usize>,
    /// Lot 317 (BUG-118): the heartbeat cleared, the programs waited for,
    /// the stopped map read — in the order the controller did them.
    log: Vec<&'static str>,
    /// The review of #547 (F4): the uids' shares recounted, how often.
    recounts: usize,
}

#[derive(Clone, Default)]
struct FakeKernel(Arc<Mutex<KState>>);

impl KernelIo for FakeKernel {
    fn ring_fd(&self) -> Option<RawFd> {
        None
    }
    fn drain(&mut self, out: &mut Vec<ExecqStopRaw>) {
        let mut st = self.0.lock();
        st.log.push("drain");
        out.append(&mut st.queue);
    }
    fn beat(&mut self, ns: u64) {
        let mut st = self.0.lock();
        st.beats.push(ns);
        if ns == 0 {
            st.log.push("beat 0");
        }
    }
    fn remember(&mut self, key: ExecqKey, v: ExecqKnown) {
        self.0.lock().known.push((key, v));
    }
    fn unstop(&mut self, pid: u32, start_ns: u64) {
        let mut st = self.0.lock();
        st.unstopped.push(pid);
        // the map's entry goes, as `EXECQ_STOPPED`'s does — the one of that
        // process (lot 317, review F5)
        st.left
            .retain(|(p, v)| !(*p == pid && v.start_ns == start_ns));
    }
    fn owe_kill(&mut self, pid: u32, start_ns: u64) {
        let mut st = self.0.lock();
        let v = ExecqStopped {
            start_ns,
            stop_ns: kernel::KILL_OWED,
        };
        // as the kernel's map is keyed: one entry per pid — rewritten only
        // when it is this process's (the re-check's N2)
        match st.left.iter_mut().find(|(p, _)| *p == pid) {
            Some(e) if kernel::entry_is_its_own(Some(e.1.start_ns), start_ns) => e.1 = v,
            Some(_) => {}
            None => st.left.push((pid, v)),
        }
    }
    fn stopped(&self) -> Vec<(u32, ExecqStopped)> {
        let mut st = self.0.lock();
        st.log.push("stopped");
        st.left.clone()
    }
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) -> kernel::RootsRefused {
        let mut k = self.0.lock();
        // lot 311 (F3, G2): a map of `cap` entries keeps the ranked list's
        // head
        let cap = k.roots_cap.unwrap_or(usize::MAX);
        k.roots = Some(roots.iter().take(cap).copied().collect());
        kernel::RootsRefused::of_tail(roots, cap)
    }
    fn counters(&self) -> [u64; counter::SLOTS as usize] {
        self.0.lock().counters
    }
    fn recount_shares(&mut self) {
        self.0.lock().recounts += 1;
    }
    fn quiesce(&mut self) {
        self.0.lock().log.push("quiesce");
    }
}

#[derive(Default)]
struct BState {
    ready: bool,
    /// Requests held, unanswered (a slow scanner).
    hold: bool,
    held: Vec<(ScanRequest, OwnedFd)>,
    out: Vec<ScannerEvent>,
    sent: u32,
}

#[derive(Clone)]
struct InProc {
    engine: Arc<Engine>,
    st: Arc<Mutex<BState>>,
}

impl InProc {
    fn new(cfg: &ScanConfig) -> Self {
        InProc {
            engine: Arc::new(Engine::new(cfg)),
            st: Arc::new(Mutex::new(BState {
                ready: true,
                ..BState::default()
            })),
        }
    }
    fn answer_held(&self) {
        let mut st = self.st.lock();
        let held = std::mem::take(&mut st.held);
        for (req, fd) in held {
            let r = self.engine.scan(&FdFile(&fd), &req);
            st.out.push(ScannerEvent::Result(r));
        }
    }
}

impl Backend for InProc {
    fn fd(&self) -> Option<RawFd> {
        None
    }
    fn ready(&self) -> bool {
        self.st.lock().ready
    }
    fn available_at(&self, now: Instant) -> Option<Instant> {
        self.st.lock().ready.then_some(now)
    }
    fn tick(&mut self, _now: Instant) -> Vec<ScannerEvent> {
        std::mem::take(&mut self.st.lock().out)
    }
    fn send(&mut self, req: &ScanRequest, fd: RawFd) -> Result<(), ScannerEvent> {
        let mut st = self.st.lock();
        if !st.ready {
            return Err(ScannerEvent::Died {
                why: "not ready".into(),
            });
        }
        st.sent += 1;
        // SAFETY: dup of a descriptor the controller holds open.
        let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(fd)) };
        if st.hold {
            st.held.push((req.clone(), fd));
        } else {
            let r = self.engine.scan(&FdFile(&fd), req);
            st.out.push(ScannerEvent::Result(r));
        }
        Ok(())
    }
    fn kill(&mut self, why: &str) -> ScannerEvent {
        let mut st = self.st.lock();
        st.held.clear();
        ScannerEvent::Died { why: why.into() }
    }
}

#[derive(Clone, Default)]
struct Rec {
    recs: Arc<Mutex<Vec<ExecqRecord>>>,
    audits: Arc<Mutex<Vec<serde_json::Value>>>,
    degraded: Arc<Mutex<Vec<String>>>,
}

impl Recorder for Rec {
    fn detection(&self, rec: ExecqRecord) {
        self.recs.lock().push(rec);
    }
    fn audit(&self, extra: serde_json::Value, _result: &str) {
        self.audits.lock().push(extra);
    }
    fn degraded(&self, detail: &str) {
        self.degraded.lock().push(detail.into());
    }
}

// ── processes ───────────────────────────────────────────────────────

struct Held {
    child: Child,
    pid: u32,
    start_ns: u64,
    exe: PathBuf,
}

impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn state(pid: u32) -> Option<char> {
    // lot 317: lot 311's reader, which no `comm` makes fail
    let s = nn_linux::state_read::read_state(format!("/proc/{pid}/stat")).ok()?;
    s.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

fn wait_state(pid: u32, want: impl Fn(Option<char>) -> bool) -> bool {
    for _ in 0..400 {
        if want(state(pid)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// `exe arg`, retried on ETXTBSY: another test thread's fork may still
/// hold the copy's write descriptor until its own exec.
fn spawn(exe: &Path, arg: &str) -> Child {
    let mut tries = 0;
    loop {
        match Command::new(exe).arg(arg).spawn() {
            Ok(c) => return c,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 100 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("spawn {}: {e}", exe.display()),
        }
    }
}

/// A copy of `sleep` at `dir/name/sleep`, started and stopped.
///
/// The copy keeps the name `sleep`, in a directory of its own per case:
/// `/bin/sleep` may be a multi-call binary that picks its utility from
/// the name it is run by (uutils coreutils on Ubuntu 26.04, the hosted CI
/// runner, reads it from the path given to `execve`; busybox from
/// `argv[0]`). A copy under another name printed "unknown program" and
/// exited at once, so a case that resumed it found it gone, which read
/// as a kill in observe mode and as "already ended" for a late verdict.
fn held_copy(dir: &Path, name: &str) -> Held {
    let home = dir.join(name);
    std::fs::create_dir(&home).unwrap();
    let exe = home.join("sleep");
    std::fs::copy("/bin/sleep", &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    // the fixture's own precondition: the copy runs as sleep
    let probe = spawn(&exe, "0").wait().unwrap();
    assert!(
        probe.success(),
        "the copy of /bin/sleep at {} does not run as sleep: {probe}",
        exe.display()
    );
    let child = spawn(&exe, "30");
    let pid = child.id();
    // SAFETY: stopping our own child.
    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    assert!(wait_state(pid, |s| s == Some('T')), "child not stopped");
    let start_ns = crate::response::proc_ref::proc_start_ns(pid).unwrap();
    Held {
        child,
        pid,
        start_ns,
        exe,
    }
}

/// What the kernel would report for `h`, the walk's path included.
fn raw_for(h: &Held, cls: u32) -> ExecqStopRaw {
    raw_of(h.pid, h.start_ns, &h.exe, cls)
}

/// The report for process `pid` whose candidate file is `exe`.
fn raw_of(pid: u32, start_ns: u64, exe: &Path, cls: u32) -> ExecqStopRaw {
    let m = std::fs::metadata(exe).unwrap();
    let mut r = ExecqStopRaw::zeroed();
    r.pid = pid;
    r.tid = pid;
    r.uid = m.uid();
    r.start_ns = start_ns;
    r.ctime_sec = m.ctime();
    r.ctime_nsec = m.ctime_nsec() as u32;
    r.size = m.size() as i64;
    r.class = cls;
    r.comm[..4].copy_from_slice(b"nn-x");
    r.exe.dev = crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev());
    r.exe.ino = m.ino();
    let names: Vec<String> = exe
        .iter()
        .skip(1)
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    assert!(names.len() <= 12, "fixture path too deep");
    for (level, n) in names.iter().rev().enumerate() {
        let at = exe_path_slot(level) * EXE_PATH_SLOT_LEN;
        let b = n.as_bytes();
        assert!(b.len() < EXE_PATH_SLOT_LEN, "fixture name too long");
        r.exe.path[at..at + b.len()].copy_from_slice(b);
    }
    r.exe.levels = names.len() as u16;
    r.exe.flags = exe_flags::KNOWN | exe_flags::TASK_ROOT;
    r
}

fn sha_of(p: &Path) -> [u8; 32] {
    Sha256::digest(std::fs::read(p).unwrap()).into()
}

struct World {
    k: FakeKernel,
    b: InProc,
    rec: Rec,
    ledger: &'static SpawnLedger,
    ctl: Controller<FakeKernel, InProc>,
    dir: tempfile::TempDir,
    /// R12c (lab PR 270): the actions chain its kills and quarantines write.
    journal: crate::response::journal::ActionJournal,
}

fn world(cfg: ScanConfig, policy: Policy, budget_ms: u64, vault: bool) -> World {
    let dir = tempfile::Builder::new()
        .prefix("nnq")
        .tempdir_in(std::env::temp_dir())
        .unwrap();
    let k = FakeKernel::default();
    let b = InProc::new(&cfg);
    let rec = Rec::default();
    let ledger: &'static SpawnLedger = Box::leak(Box::default());
    let mut exec_cfg = ExecutorConfig::for_test(&dir.path().join("vault"));
    exec_cfg.dry_run = false;
    let journal = crate::response::journal::ActionJournal::memory();
    let ctl = Controller::new(
        k.clone(),
        b.clone(),
        Box::new(rec.clone()),
        Settings {
            policy,
            budget: Duration::from_millis(budget_ms),
            hung_after: Duration::from_millis(budget_ms),
            exec_cfg: vault.then_some(exec_cfg),
            ctime: true,
            journal: journal.clone(),
        },
        ledger,
    )
    .with_package_root(
        PackageTrust::new(dir.path().join("no-root"), false),
        dir.path().join("no-mountinfo"),
    );
    World {
        k,
        b,
        rec,
        ledger,
        ctl,
        dir,
        journal,
    }
}

impl World {
    fn push(&self, raw: ExecqStopRaw) {
        self.k.0.lock().queue.push(raw);
    }
    /// Step until `done` or 3 s.
    fn run_until(&mut self, done: impl Fn(&World) -> bool) {
        for _ in 0..600 {
            self.ctl.step(Instant::now());
            if done(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("condition not reached");
    }
    fn records(&self) -> Vec<ExecqRecord> {
        self.rec.recs.lock().clone()
    }
    /// Lot 317 (BUG-124): from here every capture of a held process fails
    /// as `pidfd_open` out of descriptors does (`EMFILE`), until the switch
    /// returned is cleared.
    fn break_capture(&mut self) -> Arc<AtomicBool> {
        let broken = Arc::new(AtomicBool::new(true));
        let b = Arc::clone(&broken);
        self.ctl.capture = Box::new(move |pid, start| {
            if b.load(Ordering::Relaxed) {
                ProcRef::uncaptured_for_test(pid, start, libc::EMFILE)
            } else {
                ProcRef::open_started_at(pid, start)
            }
        });
        broken
    }
}

fn enforce() -> Policy {
    Policy::default()
}

// ── the cases ───────────────────────────────────────────────────────

/// Harness case 1: a new binary, clean → resumed after the rule engine
/// judged the exec, cached, one Low record; a copy of the same content at
/// another path → resumed on the known digest, no second record.
#[test]
fn a_clean_new_binary_is_resumed_cached_and_recorded_once() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    // the scan alone does not resume it: the rules judge the exec first
    for _ in 0..20 {
        w.ctl.step(Instant::now());
    }
    assert_eq!(
        state(h.pid),
        Some('T'),
        "resumed before the rules judged the exec"
    );
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "not resumed"
    );
    let r = &w.records()[0];
    assert_eq!(r.verdict.rule_id, crate::execq::RULE_ID);
    assert_eq!(r.verdict.severity, nn_model::Severity::Low);
    assert_eq!(r.evidence.verdict, "clean");
    assert_eq!(r.evidence.decision, "resume");
    assert_eq!(r.response, "resumed");
    assert!(r.evidence.held);
    assert_eq!(r.evidence.classes, ["home"]);
    assert_eq!(
        r.evidence.sha256.as_deref(),
        Some(hex::encode(sha_of(&h.exe)).as_str())
    );
    let ks = w.k.0.lock();
    assert_eq!(ks.known.len(), 1, "identity cached under its stamp");
    assert_eq!(ks.known[0].0.ino, std::fs::metadata(&h.exe).unwrap().ino());
    assert!(ks.unstopped.contains(&h.pid));
    drop(ks);

    let h2 = held_copy(w.dir.path(), "nn-y");
    w.push(raw_for(&h2, class::HOME));
    w.ledger.judged(h2.pid, h2.start_ns);
    w.run_until(|_| state(h2.pid) != Some('T'));
    assert_eq!(w.records().len(), 1, "known content: no second record");
    assert_eq!(
        w.k.0.lock().known.len(),
        2,
        "the copy's identity cached too"
    );
}

/// Harness case 2: a block-listed binary is killed while held and its file
/// quarantined; the record is Critical and names the list entry.
#[test]
fn a_blocklisted_binary_is_killed_and_quarantined() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-bad");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "nn-lab-test-elf".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 2000, true);
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "not killed"
    );
    let r = &w.records()[0];
    assert_eq!(r.verdict.severity, nn_model::Severity::Critical);
    assert_eq!(r.verdict.action, nn_model::ResponseAction::Quarantine);
    assert_eq!(r.evidence.verdict, "malicious");
    assert!(r.evidence.reasons[0].contains("nn-lab-test-elf"));
    assert!(
        r.response
            .starts_with("killed while held; quarantined (vault "),
        "{}",
        r.response
    );
    assert!(!h.exe.exists(), "the file left its path");
    assert!(
        w.k.0.lock().known.is_empty(),
        "a killed file is never cached"
    );
    // R12c (lab PR 270): the kill and the quarantine, each its signed
    // intent before and its outcome after
    use crate::response::journal::{ActionResult, ActionRow};
    let rows = w.journal.rows();
    let seen: Vec<String> = rows
        .iter()
        .map(|r| match r.row {
            ActionRow::Intent => {
                let i = r.intent.as_ref().unwrap();
                format!("intent {} {} {}", i.source, i.response, i.pid)
            }
            _ => format!("{:?} {:?}", r.row, r.outcome.as_ref().unwrap().result),
        })
        .collect();
    assert_eq!(
        seen,
        [
            format!("intent exec_quarantine KillProcess {}", h.pid),
            format!("Outcome {:?}", ActionResult::Success),
            format!("intent exec_quarantine Quarantine {}", h.pid),
            format!("Outcome {:?}", ActionResult::Success),
        ],
        "{rows:#?}"
    );
}

/// Harness case 6, the controller's half: no scanner → the default policy
/// at once (not after the budget), recorded, the digest unknown.
#[test]
fn no_scanner_means_the_default_policy_without_waiting_the_budget() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    w.b.st.lock().ready = false;
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ledger.judged(h.pid, h.start_ns);
    let t0 = Instant::now();
    w.run_until(|w| !w.records().is_empty());
    assert!(
        t0.elapsed() < Duration::from_millis(1500),
        "waited the budget"
    );
    let r = &w.records()[0];
    assert_eq!(r.evidence.verdict, "none");
    assert!(
        r.evidence.basis.contains("scanner unavailable"),
        "{}",
        r.evidence.basis
    );
    assert!(r.evidence.basis.contains("default policy (resume)"));
    assert_eq!(r.verdict.severity, nn_model::Severity::Medium);
    assert_eq!(r.response, "resumed");
    assert!(w.k.0.lock().known.is_empty());
}

/// A scanner that answers too late: the budget runs out (resume and alert),
/// then the late block-list verdict kills the running process.
#[test]
fn a_late_blocklist_verdict_kills_after_the_default_policy() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-slow");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "late".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 150, false);
    w.b.st.lock().hold = true;
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "resumed by default"
    );
    let first = w.records()[0].clone();
    assert!(
        first.evidence.basis.contains("decision budget expired"),
        "{}",
        first.evidence.basis
    );
    assert!(first.evidence.basis.contains("no scan verdict"));
    // the unanswered request past its budget: the scanner was killed as
    // hung (signed), the request goes to the next one, which answers
    assert!(w.rec.degraded.lock()[0].contains("no verdict within the decision budget"));
    w.b.st.lock().hold = false;
    w.run_until(|w| {
        w.b.answer_held();
        w.records().len() >= 2
    });
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "late kill"
    );
    let late = &w.records()[1];
    assert_eq!(late.evidence.verdict, "malicious");
    assert!(late.response.starts_with("killed"), "{}", late.response);
    assert!(late.evidence.reasons.iter().any(|r| r.starts_with("late:")));
}

/// A rule kill (R001 on a held /tmp binary) lands while held: the record
/// says it ended while held, nothing is resumed.
#[test]
fn a_process_the_rules_kill_while_held_is_not_resumed() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::TMP));
    w.ctl.step(Instant::now());
    // the rule engine's kill, then its verdict mark
    // SAFETY: killing our own child.
    unsafe { libc::kill(h.pid as i32, libc::SIGKILL) };
    assert!(wait_state(h.pid, |s| s.is_none() || s == Some('Z')));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(
        w.records()[0].response.starts_with("ended while held"),
        "{}",
        w.records()[0].response
    );
}

/// Observe mode (and a detect-only agent): nothing is held or killed; the
/// record says what would have been done.
#[test]
fn observe_mode_records_what_it_would_do() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-obs");
    // SAFETY: resuming our own child: observe mode holds nothing.
    unsafe { libc::kill(h.pid as i32, libc::SIGCONT) };
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "obs".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(
        cfg,
        Policy {
            enforce: false,
            ..Policy::default()
        },
        2000,
        true,
    );
    let mut raw = raw_for(&h, class::TMP);
    raw.flags |= stop_flags::OBSERVE;
    w.push(raw);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert_eq!(r.evidence.decision, "would kill");
    assert!(!r.evidence.held);
    assert!(
        r.response.starts_with("observe: would kill"),
        "{}",
        r.response
    );
    assert!(
        state(h.pid).is_some_and(|s| s != 'Z'),
        "observe mode killed it"
    );
    assert!(h.exe.exists(), "observe mode quarantined it");
}

/// Review of lab PR 223: an exec the kernel let run because the events ring
/// was full (fail-open) is a signed degradation with its count, at most one
/// per `DEGRADED_EVERY`; later ones are counted into the next record.
#[test]
fn a_full_ring_is_a_signed_rate_limited_degradation() {
    let mut w = world(ScanConfig::default(), enforce(), 3000, true);
    let t0 = Instant::now();
    w.ctl.step(t0);
    assert!(w.rec.degraded.lock().is_empty(), "nothing lost yet");
    w.k.0.lock().counters[counter::RING_FULL as usize] = 3;
    let t1 = t0 + HEARTBEAT_EVERY + Duration::from_millis(1);
    w.ctl.step(t1);
    {
        let d = w.rec.degraded.lock();
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(
            d[0].contains("3 exec(s) ran without being held")
                && d[0].contains("ring was full for 3"),
            "{}",
            d[0]
        );
    }
    w.k.0.lock().counters[counter::RING_FULL as usize] = 5;
    let t2 = t1 + HEARTBEAT_EVERY + Duration::from_millis(1);
    w.ctl.step(t2);
    assert_eq!(w.rec.degraded.lock().len(), 1, "held within the window");
    let t3 = t1 + super::DEGRADED_EVERY + HEARTBEAT_EVERY;
    w.ctl.step(t3);
    let d = w.rec.degraded.lock();
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d[1].contains("ring was full for 2"), "{}", d[1]);
}

/// The scanner dies with a request in flight: a signed degradation, the
/// request goes to the restarted scanner, the process is decided normally.
#[test]
fn a_scanner_death_is_signed_and_its_requests_requeued() {
    let mut w = world(ScanConfig::default(), enforce(), 3000, true);
    w.b.st.lock().hold = true;
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| w.b.st.lock().sent == 1);
    {
        let mut st = w.b.st.lock();
        st.held.clear();
        st.hold = false;
        st.out.push(ScannerEvent::Died {
            why: "killed by signal 9".into(),
        });
    }
    w.run_until(|w| !w.records().is_empty());
    assert_eq!(w.b.st.lock().sent, 2, "sent again after the death");
    assert_eq!(w.records()[0].evidence.verdict, "clean");
    let d = w.rec.degraded.lock();
    assert_eq!(d.len(), 1);
    assert!(
        d[0].contains("killed by signal 9") && d[0].contains("default policy (resume)"),
        "{}",
        d[0]
    );
}

/// A candidate whose file cannot be handed to the scanner (a memfd script)
/// gets the default policy, recorded with the reason.
#[test]
fn an_unreachable_file_takes_the_default_policy() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    let mut raw = raw_for(&h, class::MEMFD);
    raw.exe.ino ^= 0xdead; // not the image: a script the interpreter runs
    raw.exe.flags |= exe_flags::MEMFD;
    raw.flags |= stop_flags::SCRIPT;
    w.push(raw);
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert!(
        r.evidence
            .basis
            .contains("file not scannable (a memfd or unlinked script"),
        "{}",
        r.evidence.basis
    );
    assert_eq!(r.response, "resumed");
}

/// A process an agent that died left stopped is resumed at boot, signed.
#[test]
fn what_a_dead_agent_left_stopped_is_resumed_at_boot() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: 1,
        },
    ));
    w.ctl.recover();
    assert!(wait_state(h.pid, |s| s == Some('S') || s == Some('R')));
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["kind"], "recovered_at_boot");
    assert_eq!(a[0]["resumed"][0], h.pid);
    assert!(w.k.0.lock().unstopped.contains(&h.pid));
}

/// Stopping the agent resumes every held process and clears the
/// heartbeat.
#[test]
fn stopping_resumes_what_is_held() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ctl.step(Instant::now());
    assert_eq!(state(h.pid), Some('T'));
    w.ctl.stop_all();
    assert!(wait_state(h.pid, |s| s == Some('S') || s == Some('R')));
    assert_eq!(*w.k.0.lock().beats.last().unwrap(), 0);
    assert_eq!(w.rec.audits.lock()[0]["kind"], "stopping");
}

/// Suspicious with `--exec-quarantine-on-suspicious kill`.
#[test]
fn the_policy_decides_on_suspicious() {
    // a "binary" whose #! names an interpreter under /tmp: suspicious
    let mut w = world(
        ScanConfig::default(),
        Policy {
            on_suspicious: Action::Kill,
            ..Policy::default()
        },
        2000,
        true,
    );
    let h = held_copy(w.dir.path(), "nn-x");
    let script = w.dir.path().join("s.sh");
    std::fs::write(&script, "#!/tmp/.hidden/interp\n").unwrap();
    // the candidate is the script (pass 0); the image is the sleep copy
    let m = std::fs::metadata(&script).unwrap();
    let mut raw = raw_of(h.pid, h.start_ns, &script, class::TMP);
    raw.flags |= stop_flags::SCRIPT;
    assert_eq!(raw.exe.ino, m.ino());
    w.push(raw);
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert_eq!(r.evidence.verdict, "suspicious");
    assert_eq!(
        r.evidence.format.as_deref(),
        Some("script:/tmp/.hidden/interp")
    );
    assert_eq!(r.techniques(), ["T1204.002", "T1059"]);
    assert!(
        r.response.starts_with("killed while held"),
        "{}",
        r.response
    );
    assert!(wait_state(h.pid, |s| s.is_none() || s == Some('Z')));
}

/// A scanner that dies the same way again and again (a binary that cannot
/// start) is one signed degradation per window, the next one with the
/// count.
#[test]
fn repeated_scanner_deaths_are_signed_once_per_window() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, false);
    for pid in [100, 200, 300] {
        w.b.st.lock().out.push(ScannerEvent::Died {
            why: format!("spawn: No such file or directory (pid {pid})"),
        });
        w.ctl.step(Instant::now());
    }
    w.b.st.lock().out.push(ScannerEvent::Died {
        why: "closed its channel (killed by signal 9)".into(),
    });
    w.ctl.step(Instant::now());
    let d = w.rec.degraded.lock();
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d[0].contains("No such file"));
    assert!(d[1].contains("killed by signal"));
    assert!(COUNTERS.scanner_deaths.load(Ordering::Relaxed) >= 4);
}

/// Lab PR 226: a script the kernel refused at its interpreter's pass
/// (enforce mode) is one Medium record, "refuse", and nothing is signalled
/// (no process was held, the caller kept its image).
#[test]
fn a_refused_script_is_recorded_and_nothing_is_signalled() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, false);
    let script = w.dir.path().join("nn-s.sh");
    std::fs::write(&script, b"#!/bin/sh\ntrue\n").unwrap();
    // a pid nothing runs under: a signal to it would fail, a resume too
    let mut raw = raw_of(999_999, 1, &script, class::TMP);
    raw.flags |= stop_flags::SCRIPT | stop_flags::SCRIPT_REFUSED;
    raw.stop_rc = -libc::EACCES;
    assert!(!raw.stopped());
    let before = COUNTERS.script_refused.load(Ordering::Relaxed);
    w.push(raw);
    w.ctl.step(Instant::now());
    let recs = w.records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r.evidence.decision, "refuse");
    assert_eq!(r.verdict.severity, nn_model::Severity::Medium);
    assert!(
        r.response.starts_with("refused at exec (EACCES)"),
        "{}",
        r.response
    );
    assert!(r
        .verdict
        .reasoning
        .contains("interpreter reads by its path"));
    assert!(!r.evidence.held);
    assert_eq!(r.techniques(), ["T1204.002", "T1059"]);
    assert!(w.k.0.lock().unstopped.is_empty(), "nothing was held");
    assert!(w.k.0.lock().known.is_empty(), "nothing is cached");
    assert!(COUNTERS.script_refused.load(Ordering::Relaxed) > before);
}

/// Lab PR 226: in observe mode a held-path script is scanned but the
/// record says it would be refused (the interpreter re-reads the file by
/// path after any scan), and its content is remembered (one record).
#[test]
fn observe_mode_says_a_script_would_be_refused() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-obs-s");
    // SAFETY: resuming our own child: observe mode holds nothing.
    unsafe { libc::kill(h.pid as i32, libc::SIGCONT) };
    let mut w = world(
        ScanConfig::default(),
        Policy {
            enforce: false,
            ..Policy::default()
        },
        2000,
        true,
    );
    let mut raw = raw_for(&h, class::HOME);
    raw.flags |= stop_flags::OBSERVE | stop_flags::SCRIPT;
    w.push(raw);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert_eq!(r.evidence.decision, "would refuse");
    assert!(
        r.response.starts_with("observe: would refuse at exec"),
        "{}",
        r.response
    );
    assert!(state(h.pid).is_some_and(|s| s != 'Z'), "observe killed it");
    assert_eq!(w.k.0.lock().known.len(), 1, "one record per content");
}

// ── lot 311 (bug hunt 1.4): BUG-98 ───────────────────────────────────

/// BUG-98: a mount table the controller cannot read as UTF-8 (a FUSE mount
/// point with a 0xff byte, which the kernel writes as it is) does not
/// remove the guarded roots of the other lines; and (F4) a table that
/// cannot be read at all leaves the roots last published, signed.
#[test]
fn a_non_utf8_mount_point_does_not_remove_the_guarded_roots() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let mi = w.dir.path().join("mountinfo");
    let good_line = crate::execq::kernel::tmp_mount_line(30);
    let good: &[u8] = good_line.as_bytes();
    std::fs::write(&mi, good).unwrap();
    w.ctl.roots_source = mi.clone();
    let tmp = std::fs::metadata("/tmp").unwrap();
    let t0 = Instant::now();
    w.ctl.step(t0);
    let first = w.k.0.lock().roots.clone().unwrap();
    assert!(
        first.iter().any(|(k, _)| k.ino == tmp.ino()),
        "fixture: /tmp published, {first:?}"
    );
    // a user's FUSE mount at /home/u/<0xff> appears
    let mut odd = good.to_vec();
    odd.extend_from_slice(b"57 1 0:44 / /home/u/\xff rw,nosuid,nodev - fuse.x x rw,user_id=1000\n");
    std::fs::write(&mi, &odd).unwrap();
    w.ctl.step(t0 + ROOTS_EVERY + Duration::from_millis(1));
    let now = w.k.0.lock().roots.clone().unwrap();
    assert!(
        now.iter().any(|(k, _)| k.ino == tmp.ino()),
        "EXECQ_ROOTS emptied by one non-UTF-8 line of mountinfo: {now:?}"
    );
    // the table gone: nothing written, a degradation while it fails (the
    // controller's own account: the registry is shared by the tests)
    std::fs::remove_file(&mi).unwrap();
    w.k.0.lock().roots = None;
    w.ctl.step(t0 + 2 * ROOTS_EVERY + Duration::from_millis(2));
    assert_eq!(w.k.0.lock().roots, None, "the roots last published stay");
    assert!(w.ctl.roots_read.failing());
    std::fs::write(&mi, good).unwrap();
    w.ctl.step(t0 + 3 * ROOTS_EVERY + Duration::from_millis(3));
    assert!(w.k.0.lock().roots.is_some());
    assert!(!w.ctl.roots_read.failing());
}

/// Lot 311 (the review of #538, F2, F3): a user's FUSE mount whose source
/// is `-` (`fusermount3 -o fsname=-`) is still a guarded root (by its
/// device); a line not in the kernel's shape is a degradation, never a
/// silent drop; roots the kernel's map refuses (the test's holds 64 entries,
/// the kernel's 1024 since lot 318) are one too.
#[test]
fn a_dash_source_line_is_a_root_and_losses_are_signed() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let mi = w.dir.path().join("mountinfo");
    std::fs::write(
        &mi,
        format!(
            "{}57 1 0:44 / /home/u/mnt rw,nosuid,nodev - fuse.x - rw,user_id=1000\n",
            crate::execq::kernel::tmp_mount_line(30)
        ),
    )
    .unwrap();
    w.ctl.roots_source = mi.clone();
    let t0 = Instant::now();
    w.ctl.step(t0);
    let roots = w.k.0.lock().roots.clone().unwrap();
    assert!(
        roots.iter().any(|(k, _)| *k
            == ExecqKey {
                dev: 44,
                ino: kernel::FUSE_BY_DEVICE
            }),
        "the fsname=- mount is a guarded root: {roots:?}"
    );
    assert!(!w.ctl.roots_rows.holding() && !w.ctl.roots_full.holding());
    // a line not in the kernel's shape: a degradation
    std::fs::write(
        &mi,
        format!(
            "{}57 1 0:44 / /home/u/mnt rw fuse.x x rw\n",
            crate::execq::kernel::tmp_mount_line(30)
        ),
    )
    .unwrap();
    w.ctl.step(t0 + ROOTS_EVERY + Duration::from_millis(1));
    assert!(w.ctl.roots_rows.holding(), "a dropped line is signed");
    // the kernel's map full: the refused roots are a degradation
    w.k.0.lock().roots_cap = Some(0);
    let full_at = t0 + 2 * ROOTS_EVERY + Duration::from_millis(2);
    w.ctl.step(full_at);
    assert!(w.ctl.roots_full.holding());
    // the review of #538 (G2): it stands its hold, then ends
    w.k.0.lock().roots_cap = None;
    w.ctl.step(t0 + 3 * ROOTS_EVERY + Duration::from_millis(3));
    assert!(w.ctl.roots_full.holding(), "within its hold");
    w.ctl
        .step(full_at + crate::execpol::controller::ROOTS_FULL_HOLD + ROOTS_EVERY);
    assert!(!w.ctl.roots_full.holding());
    assert_eq!(w.ctl.roots_full.reports(), 1);
}

/// Lot 311 (the review of #538, G2): seventy FUSE mounts of a user's,
/// mounted before a system root, never keep it out of the kernel's map (the
/// test's holds 64 entries, the kernel's 1024 since lot 318): the roots are
/// ranked, the FUSE ones last. Their own
/// refusal — however its count moves — signs nothing (the exec hooks class
/// a FUSE file by its magic, lot 318); a system root refused is one record
/// per hold, however often it comes and goes.
#[test]
fn seventy_fuse_mounts_never_keep_a_system_root_out_and_sign_nothing() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    w.k.0.lock().roots_cap = Some(64);
    let mi = w.dir.path().join("mountinfo");
    let table = |n: u32| {
        let mut t = String::new();
        for i in 0..n {
            t.push_str(&format!(
                "{} 1 0:{} / /home/u/m{i} rw,nosuid,nodev - fuse.x - rw,user_id=1000\n",
                100 + i,
                200 + i
            ));
        }
        t + &crate::execq::kernel::tmp_mount_line(30)
    };
    w.ctl.roots_source = mi.clone();
    let tmp = std::fs::metadata("/tmp").unwrap();
    // the root's key: the kernel's dev_t (major << 20 | minor), the inode
    let tmp_key = ExecqKey {
        dev: (u64::from(libc::major(tmp.dev())) << 20) | u64::from(libc::minor(tmp.dev())),
        ino: tmp.ino(),
    };
    let t0 = Instant::now();
    for (round, n) in [70u32, 66, 75, 64, 90, 70].into_iter().enumerate() {
        std::fs::write(&mi, table(n)).unwrap();
        w.ctl
            .step(t0 + (round as u32) * (ROOTS_EVERY + Duration::from_millis(1)));
        let roots = w.k.0.lock().roots.clone().unwrap();
        assert_eq!(roots.len(), 64.min(n as usize + 1), "round {round}");
        assert!(
            roots.iter().any(|(k, _)| *k == tmp_key),
            "the system root /tmp, mounted after {n} FUSE mounts, is published"
        );
    }
    assert!(!w.ctl.roots_full.holding());
    assert_eq!(
        w.ctl.roots_full.reports(),
        0,
        "a FUSE refusal signs nothing"
    );
    // a system root refused: one record, however often it comes and goes
    let t1 = t0 + 10 * ROOTS_EVERY;
    for i in 0..12u32 {
        w.k.0.lock().roots_cap = Some(if i % 2 == 0 { 0 } else { 64 });
        w.ctl
            .step(t1 + i * (ROOTS_EVERY + Duration::from_millis(1)));
        assert!(w.ctl.roots_full.holding(), "{i}");
    }
    assert_eq!(w.ctl.roots_full.reports(), 1, "bounded: one per hold");
}

// ── lot 317 (bug hunt 1.4): BUG-118, BUG-124 ─────────────────────────

/// BUG-118: the kernel stopped a process after the last drain (its pid in
/// EXECQ_STOPPED, its report still on the ring): the agent stops and
/// resumes it all the same.
#[test]
fn stopping_resumes_what_the_kernel_holds_without_an_entry() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: 1,
        },
    ));
    assert_eq!(state(h.pid), Some('T'));
    w.ctl.stop_all();
    let resumed = wait_state(h.pid, |s| s == Some('S') || s == Some('R'));
    let unstopped = w.k.0.lock().unstopped.clone();
    assert!(
        resumed,
        "after stop_all the process the kernel holds is still {:?} (T = SIGSTOP); \
         unstop = {unstopped:?}",
        state(h.pid)
    );
    assert!(unstopped.contains(&h.pid));
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["kind"], "stopping");
    assert_eq!(a[0]["resumed"][0], h.pid, "{}", a[0]);
    assert_eq!(a[0]["unreported"], serde_json::json!([h.pid]), "{}", a[0]);
}

/// BUG-118: the stop reads the kernel's map only once nothing more can
/// land in it — the heartbeat cleared, then every program run that read
/// it before has ended — never before.
#[test]
fn the_stop_reads_the_kernels_map_once_no_program_can_add_to_it() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    w.ctl.stop_all();
    assert_eq!(w.k.0.lock().log, ["beat 0", "quiesce", "drain", "stopped"]);
}

/// BUG-118: a process both held for a decision and in the kernel's map is
/// resumed once, and named once.
#[test]
fn the_stop_resumes_a_held_process_once() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ctl.step(Instant::now());
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: 1,
        },
    ));
    w.ctl.stop_all();
    assert!(wait_state(h.pid, |s| s == Some('S') || s == Some('R')));
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["resumed"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["unreported"], serde_json::json!([]), "{}", a[0]);
    assert_eq!(a[0]["recaptured"], serde_json::json!([]), "{}", a[0]);
    assert!(w.k.0.lock().left.is_empty());
}

/// BUG-124: a held process the agent cannot capture (`pidfd_open` out of
/// descriptors) is not one that ended: its resume is deferred — it stays
/// held, its pid in the kernel's map — and carried out, signed, once the
/// capture succeeds. On main the record said "ended while held", its pid
/// left the map, and nothing would ever resume it.
#[test]
fn a_held_process_that_cannot_be_captured_is_not_taken_for_ended() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert!(
        r.response
            .starts_with("resume deferred: the process could not be captured"),
        "{}",
        r.response
    );
    assert!(r.response.contains("Too many open files"), "{}", r.response);
    assert_eq!(state(h.pid), Some('T'), "held");
    assert!(
        !w.k.0.lock().unstopped.contains(&h.pid),
        "its pid left the kernel's map: nothing would resume it"
    );
    // more passes while the capture fails: still held, nothing signed yet
    for _ in 0..5 {
        w.ctl.step(Instant::now());
    }
    assert_eq!(state(h.pid), Some('T'));
    assert!(w.rec.audits.lock().is_empty());
    // the agent has descriptors again: the resume is carried out
    broken.store(false, Ordering::Relaxed);
    w.ctl.step(Instant::now());
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "not resumed"
    );
    assert!(w.k.0.lock().unstopped.contains(&h.pid));
    let a = w.rec.audits.lock();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["kind"], "deferred");
    assert_eq!(a[0]["action"], "resume");
    assert_eq!(a[0]["origin"], "decided");
    assert_eq!(a[0]["result"], "resumed");
    assert_eq!(a[0]["pid"], h.pid);
    drop(a);
    w.ctl.step(Instant::now());
    assert_eq!(w.rec.audits.lock().len(), 1, "paid once");
}

/// BUG-124: a capture that failed when the report was read is tried again
/// at the decision — the failure (descriptors, memory) is the agent's, and
/// passes: the process is resumed then, nothing deferred.
#[test]
fn a_capture_that_failed_at_the_report_is_tried_again_at_the_decision() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ctl.step(Instant::now());
    assert!(w.records().is_empty(), "decided before the rules");
    broken.store(false, Ordering::Relaxed);
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert_eq!(w.records()[0].response, "resumed");
    assert!(wait_state(h.pid, |s| s == Some('S') || s == Some('R')));
    assert!(w.rec.audits.lock().is_empty(), "nothing deferred");
}

/// BUG-124: a block-list kill on a held process the agent cannot capture
/// is not "already ended": the process stays held — it never runs — and
/// is killed once it can be captured; each attempt is a signed action. On
/// main the record said "already ended", no SIGKILL was sent and the pid
/// left the kernel's map.
#[test]
fn a_kill_owed_to_a_held_process_is_carried_out_once_it_is_captured() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-bad");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "nn-lab-owed".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 2000, true);
    let broken = w.break_capture();
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert!(
        r.response
            .starts_with("kill deferred: the process could not be captured"),
        "{}",
        r.response
    );
    assert!(
        r.response.contains("; quarantined (vault "),
        "the file goes to the vault all the same: {}",
        r.response
    );
    assert_eq!(state(h.pid), Some('T'), "held: it never runs");
    assert!(!w.k.0.lock().unstopped.contains(&h.pid));
    broken.store(false, Ordering::Relaxed);
    w.ctl.step(Instant::now());
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "not killed"
    );
    assert!(w.k.0.lock().unstopped.contains(&h.pid));
    {
        let a = w.rec.audits.lock();
        assert_eq!(a[0]["kind"], "deferred");
        assert_eq!(a[0]["action"], "kill");
        assert_eq!(a[0]["result"], "killed while held");
    }
    use crate::response::journal::{ActionResult, ActionRow};
    let seen: Vec<String> = w
        .journal
        .rows()
        .iter()
        .map(|r| match r.row {
            ActionRow::Intent => {
                let i = r.intent.as_ref().unwrap();
                format!("intent {}", i.response)
            }
            _ => format!("{:?}", r.outcome.as_ref().unwrap().result),
        })
        .collect();
    assert_eq!(
        seen,
        [
            "intent KillProcess".to_string(),
            format!("{:?}", ActionResult::Failure),
            "intent Quarantine".to_string(),
            format!("{:?}", ActionResult::Success),
            "intent KillProcess".to_string(),
            format!("{:?}", ActionResult::Success),
        ]
    );
}

/// BUG-124: a held process not captured still waits for the rule engine's
/// verdict on its exec, as a captured one does. On main a failed capture
/// counted as an exit: the exec was decided without the rules.
#[test]
fn a_held_process_not_captured_still_waits_for_the_rules() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let _broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    for _ in 0..20 {
        w.ctl.step(Instant::now());
    }
    assert!(
        w.records().is_empty(),
        "decided before the rules judged the exec: {:?}",
        w.records().first().map(|r| r.response.clone())
    );
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(w.records()[0].response.starts_with("resume deferred"));
}

/// BUG-124: what an agent that died left stopped, and that cannot be
/// captured at boot, is not counted gone: it stays in the map and is
/// resumed once captured. On main it was counted gone and its pid left
/// the map.
#[test]
fn what_a_dead_agent_left_and_cannot_be_captured_is_resumed_later() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: 1,
        },
    ));
    w.ctl.recover();
    {
        let a = w.rec.audits.lock();
        assert_eq!(a[0]["kind"], "recovered_at_boot");
        assert_eq!(a[0]["gone"], 0, "{}", a[0]);
        assert_eq!(a[0]["deferred"], serde_json::json!([h.pid]), "{}", a[0]);
    }
    assert!(!w.k.0.lock().unstopped.contains(&h.pid), "kept in the map");
    assert_eq!(state(h.pid), Some('T'));
    broken.store(false, Ordering::Relaxed);
    w.ctl.step(Instant::now());
    assert!(wait_state(h.pid, |s| s == Some('S') || s == Some('R')));
    assert!(w.k.0.lock().unstopped.contains(&h.pid));
    let a = w.rec.audits.lock();
    assert_eq!(a[1]["kind"], "deferred");
    assert_eq!(a[1]["origin"], "left stopped by a previous agent");
    assert_eq!(a[1]["result"], "resumed");
}

/// BUG-124: at the stop, a held process the agent cannot capture stays in
/// the pinned map — the next start resumes it — and the signed `stopping`
/// entry names it. On main its pid left the map: nothing would resume it.
#[test]
fn the_stop_leaves_a_process_it_cannot_capture_in_the_kernels_map() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    let _broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ctl.step(Instant::now());
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: 1,
        },
    ));
    w.ctl.stop_all();
    assert_eq!(state(h.pid), Some('T'));
    assert!(
        !w.k.0.lock().unstopped.contains(&h.pid),
        "its pid left the map: the next start would not resume it"
    );
    assert_eq!(w.k.0.lock().left.len(), 1);
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["kind"], "stopping");
    assert_eq!(a[0]["left"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["resumed"], serde_json::json!([]));
}

/// BUG-124: a held process whose capture failed when its report was read
/// is captured again at the stop and resumed, named in `recaptured`. On
/// main its `SIGCONT` failed with the capture's error, its pid left the
/// map, and it stayed stopped.
#[test]
fn the_stop_captures_again_and_resumes_a_process_it_could_not_capture() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    let broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    w.ctl.step(Instant::now());
    broken.store(false, Ordering::Relaxed);
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "still {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["resumed"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["recaptured"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["left"], serde_json::json!([]), "{}", a[0]);
}

/// BUG-124: a kill owed when the agent stops is carried out if the
/// process can be captured by then — a stop resumes nothing it decided
/// to kill.
#[test]
fn the_stop_carries_out_a_kill_it_owes() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-bad");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "nn-lab-owed".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 2000, false);
    let broken = w.break_capture();
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(w.records()[0].response.starts_with("kill deferred"));
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: 1,
        },
    ));
    broken.store(false, Ordering::Relaxed);
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "resumed instead of killed: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["killed"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["resumed"], serde_json::json!([]), "{}", a[0]);
}

// ── lot 317, the review of #541 (rev541): F1, F2, F3, F5 ─────────────

/// A process `(pid, start)` the fake kernel holds.
fn hold_in_map(w: &World, pid: u32, start_ns: u64) {
    w.k.0.lock().left.push((
        pid,
        ExecqStopped {
            start_ns,
            stop_ns: 1,
        },
    ));
}

/// Review F1 (the reviewer's probe): a late block-list verdict arrives
/// while the default policy's resume is still owed (the capture failing):
/// the process is still held, so the kill is owed in turn — and carried
/// out once the capture succeeds. The probe found it resumed: the owed
/// resume ran a process with a block-list verdict.
#[test]
fn a_late_block_list_verdict_on_a_process_whose_resume_is_owed_kills_it() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-slow");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "late".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 150, false);
    w.b.st.lock().hold = true;
    let broken = w.break_capture();
    hold_in_map(&w, h.pid, h.start_ns);
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(
        w.records()[0].response.starts_with("resume deferred"),
        "{}",
        w.records()[0].response
    );
    assert_eq!(state(h.pid), Some('T'), "held: the resume is owed");
    w.b.st.lock().hold = false;
    w.run_until(|w| {
        w.b.answer_held();
        w.records().len() >= 2
    });
    let late = w.records()[1].response.clone();
    assert!(late.starts_with("kill deferred"), "{late}");
    assert_eq!(state(h.pid), Some('T'), "still held");
    assert_eq!(
        w.k.0.lock().left,
        [(
            h.pid,
            ExecqStopped {
                start_ns: h.start_ns,
                stop_ns: kernel::KILL_OWED
            }
        )],
        "the owed kill is marked in the map"
    );
    broken.store(false, Ordering::Relaxed);
    w.ctl.step(Instant::now());
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "a process with a block-list verdict ran: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0]["action"], "kill", "{}", a[0]);
    assert_eq!(a[0]["result"], "killed while held", "{}", a[0]);
    assert!(w.k.0.lock().left.is_empty());
}

/// Review F1, its variant: the late kill lands (the capture back by then):
/// the resume owed is dropped with it — no later signed `deferred` entry
/// for a process the agent itself killed.
#[test]
fn a_late_kill_that_lands_drops_the_resume_owed() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-slow");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "late".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 150, false);
    w.b.st.lock().hold = true;
    let broken = w.break_capture();
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(w.records()[0].response.starts_with("resume deferred"));
    // the capture back, the verdict arrives in the same pass (before the
    // owed resume is paid)
    broken.store(false, Ordering::Relaxed);
    w.b.st.lock().hold = false;
    w.b.answer_held();
    w.ctl.step(Instant::now());
    assert!(
        w.records()
            .get(1)
            .is_some_and(|r| r.response.starts_with("killed while held")),
        "{:?}",
        w.records()
            .iter()
            .map(|r| r.response.clone())
            .collect::<Vec<_>>()
    );
    assert!(wait_state(h.pid, |s| s.is_none() || s == Some('Z')));
    for _ in 0..3 {
        w.ctl.step(Instant::now());
    }
    assert!(
        w.rec.audits.lock().is_empty(),
        "a signed entry for a resume owed to a process the agent killed: {:?}",
        w.rec.audits.lock()
    );
}

/// Review F2 (the reviewer's probe): a kill still owed when the agent stops
/// (the capture failing) is marked in the pinned map, and the next start
/// kills the process instead of resuming it. The probe found it resumed.
#[test]
fn a_kill_owed_at_the_stop_is_carried_out_by_the_next_start() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-bad");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "nn-lab-owed".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 2000, false);
    let broken = w.break_capture();
    hold_in_map(&w, h.pid, h.start_ns);
    w.push(raw_for(&h, class::TMP));
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    assert!(w.records()[0].response.starts_with("kill deferred"));
    w.ctl.stop_all();
    {
        let a = w.rec.audits.lock();
        assert_eq!(a[0]["left"], serde_json::json!([h.pid]), "{}", a[0]);
        assert_eq!(a[0]["resumed"], serde_json::json!([]), "{}", a[0]);
    }
    assert_eq!(state(h.pid), Some('T'));
    assert_eq!(
        w.k.0.lock().left[0].1.stop_ns,
        kernel::KILL_OWED,
        "the owed kill outlives the agent in the pinned map"
    );
    // the next start, with descriptors again
    broken.store(false, Ordering::Relaxed);
    w.ctl.recover();
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "the next start resumed a process whose kill was owed: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[1]["kind"], "recovered_at_boot");
    assert_eq!(a[1]["killed"], serde_json::json!([h.pid]), "{}", a[1]);
    assert_eq!(a[1]["resumed"], serde_json::json!([]), "{}", a[1]);
}

/// Review F2: the next start that cannot capture a process whose kill is
/// owed owes the kill in turn — never a resume.
#[test]
fn a_kill_owed_by_a_previous_agent_stays_a_kill_while_the_capture_fails() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, false);
    let broken = w.break_capture();
    let h = held_copy(w.dir.path(), "nn-x");
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: kernel::KILL_OWED,
        },
    ));
    w.ctl.recover();
    broken.store(false, Ordering::Relaxed);
    w.ctl.step(Instant::now());
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "{:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[1]["kind"], "deferred");
    assert_eq!(a[1]["action"], "kill");
    assert_eq!(a[1]["origin"], "a kill a previous agent owed");
}

/// Named (lot 341, alpha 2/4): a run under the no-enforcement gate (the
/// `alpha` profile, detect-only: the exec quarantine observes) kills
/// nothing, not even a kill an enforcing run before it owed — the held
/// process is resumed, and the boot's record says it would have been killed.
#[test]
fn an_observing_run_resumes_a_kill_an_enforcing_run_owed() {
    let observe = Policy {
        enforce: false,
        ..Policy::default()
    };
    let mut w = world(ScanConfig::default(), observe, 2000, false);
    let h = held_copy(w.dir.path(), "nn-x");
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: kernel::KILL_OWED,
        },
    ));
    w.ctl.recover();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "an observing run killed (or left stopped) a process: {:?}",
        state(h.pid)
    );
    {
        let a = w.rec.audits.lock();
        assert_eq!(a[0]["kind"], "recovered_at_boot");
        assert_eq!(a[0]["killed"], serde_json::json!([]), "{}", a[0]);
        assert_eq!(a[0]["resumed"], serde_json::json!([h.pid]), "{}", a[0]);
        assert_eq!(
            a[0]["would_have_killed"],
            serde_json::json!([h.pid]),
            "{}",
            a[0]
        );
    }
    // the stop's sweep of an unreported hold owing a kill: resumed too
    w.k.0.lock().left.clear();
    hold_in_map(&w, h.pid, h.start_ns);
    w.k.0.lock().left[0].1.stop_ns = kernel::KILL_OWED;
    // SAFETY: stopping our own child, as the kernel's hold would
    unsafe { libc::kill(h.pid as i32, libc::SIGSTOP) };
    assert!(wait_state(h.pid, |s| s == Some('T')), "{:?}", state(h.pid));
    w.ctl.stop_all();
    // a kill takes the process to a zombie: given the time to land, it
    // would no longer read as running
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "the stop of an observing run killed (or left stopped) a process: {:?}",
        state(h.pid)
    );
}

/// Review F5 (the reviewer's probe): an entry whose process has ended
/// (its pid since taken by a process the kernel holds, its report not read
/// yet) neither takes the new process's map entry out nor hides it from
/// the sweep: the stop resumes it.
#[test]
fn a_reused_pid_neither_hides_nor_releases_the_process_the_kernel_holds() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    w.b.st.lock().hold = true;
    let h = held_copy(w.dir.path(), "nn-x");
    // an entry for an earlier holder of this pid (another start: gone)
    let mut raw = raw_for(&h, class::HOME);
    raw.start_ns = h.start_ns - 10_000_000_000;
    w.push(raw);
    w.ctl.step(Instant::now());
    // the kernel holds the pid's new process (its report not read)
    hold_in_map(&w, h.pid, h.start_ns);
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "the held process under a reused pid was left stopped: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["unreported"], serde_json::json!([h.pid]), "{}", a[0]);
}

/// Review F3, F7: a report still on the ring when the agent stops — its
/// process stopped after the controller's last pass — is read a last time
/// and the process resumed, whether or not the map names it.
#[test]
fn the_stop_reads_the_ring_a_last_time() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    w.push(raw_for(&h, class::HOME));
    // no pass in between: the report is still on the ring, the map empty
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s == Some('S') || s == Some('R')),
        "{:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["unreported"], serde_json::json!([h.pid]), "{}", a[0]);
}

/// Review F3: an exec the kernel could not name in its map is not held
/// (the kernel stops only a process the map names): its record says so,
/// nothing is resumed or unstopped, and the count is a signed fail-open
/// degradation.
#[test]
fn an_exec_the_map_could_not_name_is_not_held_and_is_signed() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    // SAFETY: resuming our own child: the kernel did not stop it.
    unsafe { libc::kill(h.pid as i32, libc::SIGCONT) };
    let mut raw = raw_for(&h, class::HOME);
    raw.flags |= stop_flags::MAP_FULL;
    assert!(!raw.stopped());
    w.push(raw);
    w.ledger.judged(h.pid, h.start_ns);
    w.run_until(|w| !w.records().is_empty());
    let r = &w.records()[0];
    assert!(!r.evidence.held);
    assert!(
        r.response
            .starts_with("not held (the map of stopped processes was full"),
        "{}",
        r.response
    );
    assert!(w.k.0.lock().unstopped.is_empty());
    let t0 = Instant::now();
    w.k.0.lock().counters[counter::MAP_FULL as usize] = 2;
    w.ctl.step(t0 + HEARTBEAT_EVERY + Duration::from_millis(1));
    let d = w.rec.degraded.lock();
    assert!(
        d.iter()
            .any(|d| d.contains("the map of stopped processes was full for 2")),
        "{d:?}"
    );
}

/// The review of #547 (F4): a candidate the kernel dropped — its map full,
/// or its uid's share taken — is an exec that ran unheld: a signed
/// fail-open degradation with its count (nobody read the counter). The
/// uids' shares are recounted from the entries every `SHARES_EVERY`.
#[test]
fn a_dropped_candidate_is_signed_and_the_shares_are_recounted() {
    let mut w = world(ScanConfig::default(), enforce(), 2000, true);
    let t0 = Instant::now();
    w.ctl.step(t0);
    assert_eq!(w.k.0.lock().recounts, 1, "recounted at the first pass");
    assert!(w.rec.degraded.lock().is_empty());
    w.k.0.lock().counters[counter::CAND_DROPPED as usize] = 4;
    let t1 = t0 + HEARTBEAT_EVERY + Duration::from_millis(1);
    w.ctl.step(t1);
    {
        let d = w.rec.degraded.lock();
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(
            d[0].contains("4 exec(s) ran without being held")
                && d[0].contains("(or the map was full with no candidate old enough to go) for 4"),
            "{}",
            d[0]
        );
    }
    assert_eq!(w.k.0.lock().recounts, 1, "not before SHARES_EVERY");
    w.ctl.step(t0 + super::SHARES_EVERY);
    assert_eq!(w.k.0.lock().recounts, 2);
    // the re-check of #547 (G5): an evicted candidate ran unheld too —
    // counted into the next signed record
    w.k.0.lock().counters[counter::CAND_EVICTED as usize] = 3;
    w.ctl.step(t1 + super::DEGRADED_EVERY + HEARTBEAT_EVERY);
    let d = w.rec.degraded.lock();
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(
        d[1].contains("3 exec(s) ran without being held")
            && d[1].contains("the oldest candidate went for a newer one, the map full, for 3"),
        "{}",
        d[1]
    );
}

/// A held process the scanner judged block-listed, its decision still
/// waiting for the rules' verdict on the exec (the ledger not judged): an
/// entry with a kill verdict and no decision yet.
fn held_with_a_kill_verdict(label: &str) -> (World, Held) {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), label);
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "nn-lab-owed".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 5000, false);
    hold_in_map(&w, h.pid, h.start_ns);
    w.push(raw_for(&h, class::TMP));
    w.run_until(|w| w.ctl.entries.values().any(|p| p.scan.is_some()));
    assert!(w.records().is_empty(), "decided before the rules");
    drop(dir);
    (w, h)
}

/// An owed resume for `h`, as a decision would have left it.
fn owe_a_resume(w: &mut World, h: &Held) {
    w.ctl.owed.push(Owed {
        pid: h.pid,
        start_ns: h.start_ns,
        action: Action::Resume,
        path: h.exe.display().to_string(),
        origin: "decided",
        since: Instant::now(),
        errno: libc::EMFILE,
    });
}

/// Review F1: an owed resume is never paid to a process a verdict asks to
/// kill — `pay_owed` reads the verdicts first, and kills.
#[test]
fn an_owed_resume_is_never_paid_to_a_process_a_verdict_kills() {
    let (mut w, h) = held_with_a_kill_verdict("nn-bad");
    owe_a_resume(&mut w, &h);
    w.ctl.pay_owed(Instant::now());
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "resumed: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["action"], "kill", "{}", a[0]);
}

/// Review F1: nor at the stop — an owed resume of a process a verdict asks
/// to kill is a kill there too.
#[test]
fn the_stop_kills_an_owed_resume_a_verdict_kills() {
    let (mut w, h) = held_with_a_kill_verdict("nn-bad");
    owe_a_resume(&mut w, &h);
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "resumed: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["killed"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["resumed"], serde_json::json!([]), "{}", a[0]);
}

/// Review F2: a process whose kill the map says is owed is never resumed
/// by the stop, whatever this run knows of it.
#[test]
fn the_stop_never_resumes_a_process_whose_kill_the_map_owes() {
    let mut w = world(ScanConfig::default(), enforce(), 5000, false);
    let h = held_copy(w.dir.path(), "nn-x");
    w.k.0.lock().left.push((
        h.pid,
        ExecqStopped {
            start_ns: h.start_ns,
            stop_ns: kernel::KILL_OWED,
        },
    ));
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "resumed: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["killed"], serde_json::json!([h.pid]), "{}", a[0]);
}

// ── the re-check of #541: N1, N2 ─────────────────────────────────────

/// The re-check's N1 (the reviewer's probe R1): a held process whose scan
/// already asks for its kill, the rules' verdict on its exec still
/// awaited and nothing owed: the stop kills it — the same verdict as an
/// owed resume's, the same end. The probe found it resumed.
#[test]
fn the_stop_kills_a_held_process_whose_verdict_asks_for_it() {
    let (mut w, h) = held_with_a_kill_verdict("nn-bad");
    w.ctl.stop_all();
    assert!(
        wait_state(h.pid, |s| s.is_none() || s == Some('Z')),
        "the stop resumed a held process whose block-list verdict it had: {:?}",
        state(h.pid)
    );
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["killed"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(a[0]["resumed"], serde_json::json!([]), "{}", a[0]);
    assert!(w.k.0.lock().left.is_empty());
}

/// N1: the same with the capture failing — the kill is owed in the map,
/// the process left stopped for the next start to kill.
#[test]
fn the_stop_owes_the_kill_of_a_held_process_it_cannot_capture() {
    let dir = tempfile::Builder::new().prefix("nnq").tempdir().unwrap();
    let h = held_copy(dir.path(), "nn-bad");
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha_of(&h.exe),
            label: "nn-lab-owed".into(),
        }],
        ..ScanConfig::default()
    };
    let mut w = world(cfg, enforce(), 5000, false);
    // not captured from its report on
    let _broken = w.break_capture();
    hold_in_map(&w, h.pid, h.start_ns);
    w.push(raw_for(&h, class::TMP));
    w.run_until(|w| w.ctl.entries.values().any(|p| p.scan.is_some()));
    assert!(w.records().is_empty(), "decided before the rules");
    w.ctl.stop_all();
    assert_eq!(state(h.pid), Some('T'));
    let a = w.rec.audits.lock();
    assert_eq!(a[0]["left"], serde_json::json!([h.pid]), "{}", a[0]);
    assert_eq!(
        w.k.0.lock().left[0].1.stop_ns,
        kernel::KILL_OWED,
        "the next start kills it"
    );
}

/// The re-check's N2: a kill owed to an earlier holder of a pid leaves the
/// entry of the pid's new process (another start) as it is — neither
/// marked for a kill nor, later, taken out of the map.
#[test]
fn a_kill_owed_to_an_earlier_holder_of_a_pid_leaves_its_new_process_alone() {
    let w = world(ScanConfig::default(), enforce(), 5000, true);
    let h = held_copy(w.dir.path(), "nn-x");
    hold_in_map(&w, h.pid, h.start_ns);
    let earlier = h.start_ns - 10_000_000_000;
    let mut k = w.k.clone();
    k.owe_kill(h.pid, earlier);
    k.unstop(h.pid, earlier);
    assert_eq!(
        w.k.0.lock().left,
        [(
            h.pid,
            ExecqStopped {
                start_ns: h.start_ns,
                stop_ns: 1
            }
        )],
        "the new process's entry was rewritten or removed"
    );
}
