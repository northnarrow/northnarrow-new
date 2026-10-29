//! Lab PR 223 (EXPERIMENTAL) — exec quarantine at first sight, the agent
//! half. Design: `docs/design/EXEC_QUARANTINE.md`; kernel half:
//! `agent-ebpf/src/execq.rs`; scanner: the `northnarrow-scan` crate.
//!
//! An executable never judged on this host, run from a guarded location
//! (`/tmp`, `/var/tmp`, `/dev/shm`, a home directory, a world-writable
//! directory, a memory-backed filesystem, a memfd, an unlinked file), is
//! held by the kernel before its first instruction (`SIGSTOP` from
//! `sched_process_exec`). The [`controller`] opens the file the process
//! runs, asks the package database ([`pkgtrust`]) and the confined scanner,
//! waits for the rule engine to have judged the exec (a kill the rules
//! decide lands on a held process), then resumes the process or kills it
//! and quarantines the file ([`policy`]). A process without a decision
//! within the budget (2 s by default) gets the configured default policy
//! (resume and alert in this lot). Every decision is a signed detection
//! record (`NN-L-EXECQ-001`), every degradation a signed audit entry.
//!
//! Off unless `--exec-quarantine observe|enforce`; a detect-only agent
//! observes. Fail-open: without the agent's heartbeat the kernel stops
//! nothing.

pub mod controller;
pub mod kernel;
pub mod pkgtrust;
pub mod policy;
pub mod record;

use std::collections::{HashSet, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

use common::wire::execq::{class, mode};
use nn_model::Event;
use parking_lot::Mutex;
use tracing::{info, warn};

pub use policy::{Action, Policy};

use crate::decision::attack::{AttackRef, Tactic};

/// The rule id of every exec quarantine record (scheme `NN-L-<FAMILY>-NNN`).
pub const RULE_ID: &str = "NN-L-EXECQ-001_FirstSightQuarantine";
pub const RULE_NAME: &str = "Exec quarantine at first sight";
/// The record's `detection_type`.
pub const CATEGORY: &str = "malware_prevention";
/// The account `install.sh` creates for the scanner.
pub const DEFAULT_SCAN_USER: &str = "northnarrow-scan";
/// The scanner's file name, next to the agent's.
pub const SCANNER_BIN: &str = "northnarrow-scan";
/// Where the scanner is when it is not next to the agent.
pub const DEFAULT_SCANNER_EXE: &str = "/usr/local/bin/northnarrow-scan";
/// The signed hash list (`nn-admin config overlay set execq-hashes`).
pub const DEFAULT_HASHES_LOCAL: &str = "/etc/northnarrow/execq-hashes.local";
/// How often the controller tells the kernel it is there.
pub const HEARTBEAT_EVERY: Duration = Duration::from_millis(250);
/// A stop needs a heartbeat younger than this: six missed beats and the
/// kernel lets every exec run.
pub const HEARTBEAT_MAX: Duration = Duration::from_millis(1500);
/// A scanner silent this long with requests in flight is hung (at least
/// the budget): a 1 GiB file hashes in about a second.
pub const HUNG_AFTER: Duration = Duration::from_secs(5);
/// Audit op of the guard's own signed entries (recovery at boot, stop).
pub const AUDIT_OP: &str = "exec_quarantine";

/// `--exec-quarantine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// No candidate, no stop (the default).
    Off,
    /// Candidates are scanned while they run; the record says what would
    /// have been done.
    Observe,
    /// Candidates are held before their first instruction.
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        }
    }

    fn kernel(self) -> u64 {
        match self {
            Mode::Off => mode::OFF,
            Mode::Observe => mode::OBSERVE,
            Mode::Enforce => mode::ENFORCE,
        }
    }
}

/// The guard's configuration for this boot.
#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub budget: Duration,
    pub policy: Policy,
    pub classes: u32,
    pub scanner: PathBuf,
    pub scan_user: String,
    pub hashes_local: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Off,
            budget: policy::clamp_budget(policy::DEFAULT_BUDGET_MS),
            policy: Policy::default(),
            classes: class::ALL,
            scanner: PathBuf::from(DEFAULT_SCANNER_EXE),
            scan_user: DEFAULT_SCAN_USER.to_string(),
            hashes_local: PathBuf::from(DEFAULT_HASHES_LOCAL),
        }
    }
}

/// The scanner next to the agent's binary, else [`DEFAULT_SCANNER_EXE`].
pub fn sibling_scanner_exe(own_exe: Option<&std::path::Path>) -> PathBuf {
    own_exe
        .and_then(std::path::Path::parent)
        .map(|d| d.join(SCANNER_BIN))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SCANNER_EXE))
}

/// What `nn-admin status` says of the guard.
static STATE: Mutex<Option<String>> = Mutex::new(None);
/// The controller runs (the spawn ledger records).
static ACTIVE: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);

fn set_state(s: impl Into<String>) {
    *STATE.lock() = Some(s.into());
}

/// `off`, `enforce`, `observe`, or `degraded: <why>`.
pub fn state() -> String {
    STATE
        .lock()
        .clone()
        .unwrap_or_else(|| Mode::Off.as_str().to_string())
}

/// From the multiplexer, once the exec sensor is attached (`exec_on_lsm`:
/// the LSM one): write `cfg`'s kernel configuration (always, `OFF`
/// included, then frozen) and take the guard's maps, returned for the
/// controller ([`start`]; `None`: the guard does not run). A guard that
/// cannot run (the exec sensor is not on LSM) is written off and its reason
/// kept for the signed degradation. R11c (lab PR 264): the configuration
/// and the maps are the start's (`exec_guards::AgentExecGuards`); they were
/// process-wide statics (`configure`, `take_kernel`).
pub fn install(
    ebpf: &mut aya::Ebpf,
    cfg: &Config,
    exec_on_lsm: bool,
) -> anyhow::Result<Option<kernel::Kernel>> {
    let mut m = cfg.mode;
    if m != Mode::Off && !exec_on_lsm {
        set_state(
            "degraded: the exec sensor is not on LSM bprm_check_security (tracepoint mode or \
             refused), the guard has no candidate to hold",
        );
        m = Mode::Off;
    }
    kernel::write_conf(
        ebpf,
        m.kernel(),
        cfg.classes,
        HEARTBEAT_MAX.as_nanos() as u64,
    )?;
    if m == Mode::Off {
        if STATE.lock().is_none() {
            set_state(Mode::Off.as_str());
        }
        return Ok(None);
    }
    let taken = kernel::take(ebpf)?;
    set_state(format!("{} (starting)", m.as_str()));
    info!(
        mode = m.as_str(),
        budget_ms = cfg.budget.as_millis() as u64,
        classes = ?common::wire::execq::class_names(cfg.classes),
        "exec quarantine armed in the kernel (EXPERIMENTAL, lab PR 223)"
    );
    Ok(Some(taken))
}

/// The guard cannot run: `degraded: <why>` in the status, the reason for
/// the signed degradation (the caller keeps no kernel object of it).
pub fn fail(why: String) {
    set_state(format!("degraded: {why}"));
}

/// Whether the ctime offsets resolved on this kernel (the identity cache
/// works).
pub fn ctime_resolved() -> bool {
    use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
    let Some(r) = crate::anti_tamper::btf_revalidate::resolved() else {
        return true; // unarmed: the compiled 6.8 offsets apply
    };
    [
        slot::INODE_I_CTIME_SEC_OFFSET,
        slot::INODE_I_CTIME_NSEC_OFFSET,
    ]
    .iter()
    .all(|s| {
        r.values
            .iter()
            .any(|(k, v)| k == s && *v != BTF_OFFSETS_ABSENT)
    })
}

// ── counters ────────────────────────────────────────────────────────

/// What the guard did since boot (`nn-admin status`, appended fields).
#[derive(Debug, Default)]
pub struct Counters {
    /// Processes the kernel held.
    pub held: AtomicU64,
    pub resumed: AtomicU64,
    pub killed: AtomicU64,
    pub quarantined: AtomicU64,
    /// Decided by the default policy: the budget ran out, the file could
    /// not be scanned.
    pub defaulted: AtomicU64,
    /// Resumed on content judged clean earlier (no record).
    pub known_hash: AtomicU64,
    /// Candidates the kernel did not hold: observe mode, a stale
    /// heartbeat, a full ring, a refused signal.
    pub not_held: AtomicU64,
    /// Execs the kernel let through on an identity already judged.
    pub known_identity: AtomicU64,
    pub scanner_deaths: AtomicU64,
    /// Found stopped at boot and resumed.
    pub recovered: AtomicU64,
    /// Lab PR 226: scripts refused at exec (enforce mode).
    pub script_refused: AtomicU64,
}

pub static COUNTERS: LazyLock<Counters> = LazyLock::new(Counters::default);

/// A snapshot for the status reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub state: String,
    pub held: u64,
    pub resumed: u64,
    pub killed: u64,
    pub quarantined: u64,
    pub defaulted: u64,
    pub known_hash: u64,
    pub known_identity: u64,
    pub not_held: u64,
    pub scanner_deaths: u64,
    pub script_refused: u64,
}

pub fn snapshot() -> Snapshot {
    let c = &*COUNTERS;
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    Snapshot {
        state: state(),
        held: g(&c.held),
        resumed: g(&c.resumed),
        killed: g(&c.killed),
        quarantined: g(&c.quarantined),
        defaulted: g(&c.defaulted),
        known_hash: g(&c.known_hash),
        known_identity: g(&c.known_identity),
        not_held: g(&c.not_held),
        scanner_deaths: g(&c.scanner_deaths),
        script_refused: g(&c.script_refused),
    }
}

// ── the rule engine's verdicts on held execs ────────────────────────

/// Execs the rule engine has judged, so the controller resumes a held
/// process only after a kill the rules decided has landed. Filled from the
/// main loop for every `ProcessSpawn` while the guard runs (a bounded
/// recent window), read by the controller; an eventfd wakes the controller
/// when an exec it waits for is judged.
pub struct SpawnLedger {
    inner: Mutex<LedgerInner>,
    wake: Option<OwnedFd>,
}

#[derive(Default)]
struct LedgerInner {
    judged: HashSet<(u32, u64)>,
    order: VecDeque<(u32, u64)>,
    waiting: HashSet<(u32, u64)>,
}

/// Recent judged execs kept.
const LEDGER_CAP: usize = 8192;

impl Default for SpawnLedger {
    fn default() -> Self {
        // SAFETY: eventfd with plain flags; the result is checked.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        SpawnLedger {
            inner: Mutex::new(LedgerInner::default()),
            // SAFETY: a descriptor the kernel just returned.
            wake: (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) }),
        }
    }
}

impl SpawnLedger {
    /// The rules have judged the exec of `(pid, start_ns)`.
    pub fn judged(&self, pid: u32, start_ns: u64) {
        let key = (pid, start_ns);
        let wake = {
            let mut g = self.inner.lock();
            if g.judged.insert(key) {
                g.order.push_back(key);
                while g.order.len() > LEDGER_CAP {
                    if let Some(old) = g.order.pop_front() {
                        g.judged.remove(&old);
                    }
                }
            }
            g.waiting.contains(&key)
        };
        if wake {
            if let Some(fd) = &self.wake {
                let one: u64 = 1;
                // SAFETY: an 8-byte write to our eventfd.
                unsafe { libc::write(fd.as_raw_fd(), &one as *const u64 as *const _, 8) };
            }
        }
    }

    /// Whether the exec was judged; registers interest otherwise.
    pub fn check(&self, pid: u32, start_ns: u64) -> bool {
        let key = (pid, start_ns);
        let mut g = self.inner.lock();
        if g.judged.contains(&key) {
            g.waiting.remove(&key);
            true
        } else {
            g.waiting.insert(key);
            false
        }
    }

    /// No longer waited for.
    pub fn forget(&self, pid: u32, start_ns: u64) {
        self.inner.lock().waiting.remove(&(pid, start_ns));
    }

    /// The eventfd to poll.
    pub fn wake_fd(&self) -> Option<RawFd> {
        self.wake.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Clear the eventfd after a wake-up.
    pub fn drain_wake(&self) {
        if let Some(fd) = &self.wake {
            let mut v: u64 = 0;
            // SAFETY: an 8-byte read from our non-blocking eventfd.
            unsafe { libc::read(fd.as_raw_fd(), &mut v as *mut u64 as *mut _, 8) };
        }
    }
}

pub static LEDGER: LazyLock<SpawnLedger> = LazyLock::new(SpawnLedger::default);

/// Marks the exec of a `ProcessSpawn` judged when dropped — at the end of
/// `process_event`, after the rule engine's response (a kill included) was
/// carried out, whichever way the function returns.
pub struct SpawnGuard(Option<(u32, u64)>);

impl SpawnGuard {
    pub fn for_event(event: &Event) -> Self {
        if !ACTIVE.load(Ordering::Relaxed) {
            return SpawnGuard(None);
        }
        match event {
            Event::ProcessSpawn { pid, start_ns, .. } => SpawnGuard(Some((*pid, *start_ns))),
            _ => SpawnGuard(None),
        }
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        if let Some((pid, start)) = self.0 {
            LEDGER.judged(pid, start);
        }
    }
}

// ── start and stop ──────────────────────────────────────────────────

/// What the controller needs from the rest of the agent.
pub struct StartDeps {
    pub hashes: nn_proto::execq::HashList,
    /// Where it came from (`execq-hashes.local`, signed), for the log.
    pub hashes_source: String,
    pub recorder: Box<dyn controller::Recorder>,
    pub exec_cfg: crate::response::config::ExecutorConfig,
}

/// The running controller.
pub struct Handle {
    thread: std::thread::JoinHandle<()>,
}

/// Start the controller thread on the configuration `cfg` and the kernel
/// objects [`install`] took (`kernel`). `Err`: the guard does not run — the
/// kernel stops nothing without its heartbeat — and the reason is for the
/// signed `subsystem_degraded`.
pub fn start(
    cfg: &Config,
    kernel: Option<kernel::Kernel>,
    deps: StartDeps,
) -> Result<Handle, String> {
    let cfg = cfg.clone();
    let Some(k) = kernel else {
        return Err(match STATE.lock().clone() {
            Some(s) if s.starts_with("degraded") => s,
            _ => "the guard's kernel objects were not installed".to_string(),
        });
    };
    let user = northnarrow_scan::supervisor::lookup_user(&cfg.scan_user).map_err(|e| {
        let why = format!(
            "degraded: scanner account: {e} (install.sh creates `{}`)",
            cfg.scan_user
        );
        set_state(why.clone());
        why
    })?;
    let scan_cfg = nn_proto::execq::ScanConfig {
        block: deps.hashes.block.clone(),
        allow: deps.hashes.allow.clone(),
        suspicious_threshold: nn_proto::execq::DEFAULT_SUSPICIOUS_THRESHOLD,
        max_read_bytes: nn_proto::execq::DEFAULT_MAX_READ_BYTES,
        max_hash_bytes: nn_proto::execq::DEFAULT_MAX_HASH_BYTES,
        yara_rules: None,
    };
    let encoded = nn_proto::execq::encode_config(&scan_cfg)?;
    let sup = northnarrow_scan::supervisor::Supervisor::new(cfg.scanner.clone(), user, encoded);
    info!(
        scanner = %cfg.scanner.display(),
        user = %cfg.scan_user,
        block = deps.hashes.block.len(),
        allow = deps.hashes.allow.len(),
        hashes = %deps.hashes_source,
        "exec quarantine: starting its controller and scanner"
    );
    let enforce = cfg.mode == Mode::Enforce;
    let mut policy = cfg.policy;
    policy.enforce = enforce;
    let ctl = controller::Controller::new(
        k,
        sup,
        deps.recorder,
        controller::Settings {
            policy,
            budget: cfg.budget,
            hung_after: cfg.budget.max(HUNG_AFTER),
            exec_cfg: Some(deps.exec_cfg),
            ctime: ctime_resolved(),
        },
        &LEDGER,
    );
    ACTIVE.store(true, Ordering::Relaxed);
    set_state(cfg.mode.as_str());
    let thread = std::thread::Builder::new()
        .name("nn-execq".into())
        .spawn(move || ctl.run(&STOPPING))
        .map_err(|e| format!("controller thread: {e}"))?;
    Ok(Handle { thread })
}

/// Stop the controller: every held process is resumed, the heartbeat is
/// cleared (the kernel holds nothing more), the scanner is stopped.
pub fn shutdown(handle: Option<Handle>) {
    STOPPING.store(true, Ordering::Relaxed);
    if let Some(fd) = LEDGER.wake_fd() {
        let one: u64 = 1;
        // SAFETY: an 8-byte write to our eventfd.
        unsafe { libc::write(fd, &one as *const u64 as *const _, 8) };
    }
    if let Some(h) = handle {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !h.thread.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if h.thread.is_finished() {
            let _ = h.thread.join();
        } else {
            warn!("exec quarantine controller did not stop within 2 s");
        }
    }
    ACTIVE.store(false, Ordering::Relaxed);
}

/// Lab PR 221's typed mapping (ATT&CK Enterprise 20.0) of NN-L-EXECQ-001:
/// every reference its records can carry — User Execution of a malicious
/// file, and for a script the interpreter's technique. [`attack_refs`]
/// picks a record's; the rule catalogue lists them all.
pub const ATTACK: &[AttackRef] = &[
    AttackRef::new(Tactic::Execution, "T1204.002"),
    AttackRef::new(Tactic::Execution, "T1059.004"),
    AttackRef::new(Tactic::Execution, "T1059.006"),
    AttackRef::new(Tactic::Execution, "T1059.007"),
    AttackRef::new(Tactic::Execution, "T1059"),
];

/// The record's ATT&CK mapping: User Execution of a malicious file, and
/// the interpreter technique for a script — references of [`ATTACK`].
pub fn attack_refs(format: &str) -> Vec<AttackRef> {
    let pick = |id: &str| {
        *ATTACK
            .iter()
            .find(|r| r.technique.as_str() == id)
            .expect("an id of ATTACK")
    };
    let mut v = vec![pick("T1204.002")];
    if let Some(interp) = format.strip_prefix("script:") {
        let base = interp.rsplit('/').next().unwrap_or("");
        let sub = match base {
            "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "busybox" => "T1059.004",
            "python" | "python2" | "python3" => "T1059.006",
            "node" | "nodejs" => "T1059.007",
            "env" => "T1059",
            _ if base.starts_with("python") => "T1059.006",
            _ => "T1059",
        };
        v.push(pick(sub));
    }
    v
}

/// The technique ids of [`attack_refs`].
pub fn attack_techniques(format: &str) -> Vec<&'static str> {
    attack_refs(format)
        .iter()
        .map(|r| r.technique.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ledger_wakes_only_for_awaited_execs() {
        let l = SpawnLedger::default();
        assert!(!l.check(10, 5), "not judged yet: now awaited");
        l.judged(10, 5);
        assert!(l.check(10, 5));
        // judged before anyone waited: remembered
        l.judged(11, 6);
        assert!(l.check(11, 6));
        assert!(!l.check(12, 7));
        l.forget(12, 7);
        // the window is bounded
        for i in 0..(LEDGER_CAP as u32 + 10) {
            l.judged(1000 + i, 1);
        }
        assert!(!l.check(1000, 1), "the oldest fell out of the window");
        l.drain_wake();
    }

    #[test]
    fn attack_mapping() {
        assert_eq!(attack_techniques("elf64-x86_64-dyn"), ["T1204.002"]);
        assert_eq!(
            attack_techniques("script:/bin/sh"),
            ["T1204.002", "T1059.004"]
        );
        assert_eq!(
            attack_techniques("script:/usr/bin/python3"),
            ["T1204.002", "T1059.006"]
        );
        assert_eq!(
            attack_techniques("script:/usr/bin/perl"),
            ["T1204.002", "T1059"]
        );
    }

    #[test]
    fn the_scanner_is_found_next_to_the_agent() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(SCANNER_BIN), b"").unwrap();
        let agent = d.path().join("northnarrow-agent");
        assert_eq!(
            sibling_scanner_exe(Some(&agent)),
            d.path().join(SCANNER_BIN)
        );
        assert_eq!(
            sibling_scanner_exe(Some(std::path::Path::new("/nonexistent/agent"))),
            PathBuf::from(DEFAULT_SCANNER_EXE)
        );
    }
}
