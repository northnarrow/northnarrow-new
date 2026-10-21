//! The controller on real processes (lab PR 223): children stopped with
//! `SIGSTOP` stand for what the kernel holds, a fake kernel side records
//! what the controller writes, and the scanner is the real engine in
//! process.

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;

use common::execq::{HashEntry, ScanConfig};
use common::wire::exe::{exe_path_slot, EXE_PATH_SLOT_LEN};
use common::wire::execq::class;
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
}

#[derive(Clone, Default)]
struct FakeKernel(Arc<Mutex<KState>>);

impl KernelIo for FakeKernel {
    fn ring_fd(&self) -> Option<RawFd> {
        None
    }
    fn drain(&mut self, out: &mut Vec<ExecqStopRaw>) {
        out.append(&mut self.0.lock().queue);
    }
    fn beat(&mut self, ns: u64) {
        self.0.lock().beats.push(ns);
    }
    fn remember(&mut self, key: ExecqKey, v: ExecqKnown) {
        self.0.lock().known.push((key, v));
    }
    fn unstop(&mut self, pid: u32) {
        self.0.lock().unstopped.push(pid);
    }
    fn stopped(&self) -> Vec<(u32, ExecqStopped)> {
        self.0.lock().left.clone()
    }
    fn set_roots(&mut self, _roots: &[(ExecqKey, u32)]) {}
    fn counters(&self) -> [u64; counter::SLOTS as usize] {
        self.0.lock().counters
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
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
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
    assert_eq!(r.verdict.severity, common::Severity::Low);
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
    assert_eq!(r.verdict.severity, common::Severity::Critical);
    assert_eq!(r.verdict.action, common::ResponseAction::Quarantine);
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
    assert_eq!(r.verdict.severity, common::Severity::Medium);
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
