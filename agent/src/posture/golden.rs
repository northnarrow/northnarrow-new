//! Lab PR 243: the golden replay of the posture and the COMBAT ladder.
//!
//! The decision golden (`decision::golden`, lab PR 228) replays what the
//! rules answer to an event stream; it does not replay what acts on their
//! answers — the posture state machine and the COMBAT ladder. This one
//! does, before R08 moves them into nn-core: recorded streams
//! (`agent/tests/golden/posture/cases/*.json`) go through the path
//! `process_event` (`main.rs`) takes for the posture and the ladder, on a
//! machine and a ladder wired the way `main.rs` wires them, over a host of
//! the case's own, and what each step gives is one line of
//! `agent/tests/golden/posture/expected/<case>.jsonl`: every posture
//! transition (from, to, trigger, the evidence it cites), every call the
//! ladder makes into its actuator and what the host did, every signed row
//! the ladder and the trusted-installer window write (`combat_stage`,
//! `combat_outcome`, `trusted_installer_window_close`), and the state
//! after it. The test compares those files byte for byte, replays every
//! case several times and on several threads at once, and requires the
//! same bytes each time.
//!
//! The fake host — nothing of the machine running the test is read, and
//! nothing needs root, the network or a real process:
//! - the clock: the replay's own ([`ReplayClock`]), on the events' clock
//!   (`timestamp_ns`); the posture machine (`PostureMachine::with_clock`)
//!   and the trusted-installer window (`TrustedInstallerOverride::
//!   with_clock`) read it, the ladder is handed it as `main.rs` hands it
//!   `Instant::now()`, and the wall clock starts at 2026-01-01T00:00:00Z
//!   at the events' zero. The heartbeats of `main.rs` fire as the clock
//!   passes them: the window's expiry every second, the ladder's tick
//!   every 5 s, the posture's decay every 60 s (in that order when they
//!   fall together);
//! - the processes: a table of the case's (`procs`, the exec events of the
//!   stream, `host` items), written as a `/proc` of the replay's own for
//!   the lineage, the posture's scopes, the security-tool detector and the
//!   ladder's host-critical guard (`SystemProtectedProcs` on that
//!   `/proc`), and acted on by the replay's [`HostActuator`] — the
//!   `CombatActuator` seam: soft egress blocks, the tree kill through a
//!   cgroup of its own (frozen, the descendants moved in, killed, each
//!   member checked by its identity), the quarantine, the isolation's
//!   tables per family. A process is its pid and start; a capture of one
//!   that has exited — or whose pid another process holds now, a stale
//!   pidfd — reaches nothing. The outcomes are worded by the production
//!   actuator's own functions (`SystemActuator::kill_outcome`,
//!   `quarantine_text`, `soft_block_of`); the Linux half of the kill
//!   (`response::kill`, pidfds, cgroupfs) is not replayed — its privileged
//!   tests are;
//! - the signed rows: the real `AuditEvidence` over a real `AuditLog` in
//!   the replay's directory, opened (lab PR 249) with a fixed key, the
//!   replay's wall clock (`nn_evidence::clock::Clock`) and the replayed
//!   agent's pid (`AuditStamps`): every row is printed whole — its time,
//!   hashes and signature — and the whole chain verifies with the key. They
//!   were the writer's own clock and the test's pid, named (`@TS@`, `#n`,
//!   `@SIG@`, `@AGENT_PID@`);
//! - the administrator: a fixed Ed25519 key in an `admin.pub` of the
//!   replay's own; a signed unlock or trusted-installer grant is verified
//!   by `ConnAuth` as the admin socket verifies it, then handed to what
//!   the socket hands it to (the posture's release, the window's arm).
//!
//! Not replayed, said so: the rule engine (the decision golden replays it;
//! the trackers it shares with the posture are assessed for every event,
//! as the rules would), the ladder's worker thread (its steps run in the
//! caller, in the order the worker runs them), the admin socket's own
//! audit rows.
//!
//! Lab PR 249: the ransomware directive of the per-rule policy and the
//! kernel mass-write mode are the machine's own (they were process-wide
//! switches, read at their defaults here: a case could not set them
//! without racing every other test). A case's `rule_policy` puts its lines
//! in force on its machine's own handle (`PostureMachine::with_rule_policy`);
//! the header names both values.
//!
//! `cargo xtask golden` runs these tests with the decision golden's;
//! `cargo xtask golden --update` rewrites the golden files
//! (`NN_GOLDEN_UPDATE=1`), to be read as a diff and committed with the
//! change that moved them. CI never writes them
//! (`docs/validation/GOLDEN_REPLAY.md`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nn_model::posture_types::TriggerType;
use nn_model::{Event, ResponseAction};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};

use super::clock::Clock;
use super::escalation_allow::EscalationAllowList;
use super::state::PostureState;
use super::{
    transitions, triggers, AuthSessionTracker, CombatEntry, ExemptPids, PostureMachine,
    ReleaseScope,
};
use crate::anti_tamper::admin_auth::{AdminAuth, ConnAuth};
use crate::anti_tamper::network_isolate::{FamilyOutcome, IsolationReport, UnlockToken};
use crate::anti_tamper::trusted_installer::{
    TrustedInstallerOverride, MAX_TRUSTED_INSTALLER_WINDOW_SECS,
};
use crate::audit::{AgentSigningKey, AuditEntry, AuditLog, AuditStamps};
use crate::combat::actuator::{SystemActuator, DETECT_ONLY_ISOLATE, NO_BINARY};
use crate::combat::{
    AuditEvidence, CombatActuator, CombatLadder, IsolateOutcome, LadderConfig, NeutralizeReport,
    OffenderOutcome, ProcFacts, ProcRef, ProtectedProcs, SoftBlock, SystemProtectedProcs,
};
use crate::config::comm_allowlist::{load_comm_allowlist, PROCESS_COMM_ALLOWLIST_SHIPPED};
use crate::config::overlay_auth::Verified;
use crate::correlation::CorrelationBuffer;
use crate::decision::rule_policy::{self, PolicyHandle, RulePolicy};
use crate::impact::entropy::{Sample, Sampler};
use crate::impact::trust::ProgramOwners;
use crate::impact::RansomTracker;
use crate::impair::{DefenseDetector, SecurityTools};
use crate::response::{ExecutionOutcome, ExecutionReport};

/// The decision golden's directory: the fixture root (`host/`) both
/// replays read.
const GOLDEN_DIR: &str = concat!(env!("NN_REPO_ROOT"), "/agent/tests/golden");
/// This replay's cases and golden files.
const POSTURE_DIR: &str = concat!(env!("NN_REPO_ROOT"), "/agent/tests/golden/posture");
/// The repository's shipped lists (`configs/`), as install.sh lays them.
const CONFIGS: &str = concat!(env!("NN_REPO_ROOT"), "/configs");
/// `1`: write the golden files instead of comparing (`cargo xtask golden
/// --update`), as the decision golden.
const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";
/// Stands for the replay's own file root in a case and its golden file.
const ROOT_TOKEN: &str = "@ROOT@";
/// The golden file's format; a change of the line shape bumps it.
const FORMAT: &str = "northnarrow-posture-golden/1";
/// Replays of each case in the determinism test, and threads at once.
const RUNS: usize = 3;
const THREADS: usize = 4;

/// The replayed agent's identity (the audit rows' `agent_id`, the signed
/// requests' binding).
const AGENT_ID: [u8; 16] = *b"golden-posture-1";
/// The replayed agent's own pid, exempt from the posture as `main.rs`
/// exempts `std::process::id()` (above `PID_MAX_LIMIT`, so never a case's).
const AGENT_PID: u32 = 4_200_000;
/// The administrator's key: a fixed seed, so its fingerprint is the same
/// in every replay.
const ADMIN_SEED: [u8; 32] = [0x2a; 32];
/// Lab PR 249: the replayed agent's signing key, a fixed seed — Ed25519
/// signs deterministically, so with the replay's clock and the agent's pid
/// a row is the same bytes, signature included, in every replay.
const AUDIT_KEY_SEED: [u8; 32] = [0x5e; 32];
/// The wall clock at the events' zero: 2026-01-01T00:00:00Z.
const WALL_AT_ZERO_SECS: u64 = 1_767_225_600;
/// `main.rs`'s heartbeats.
const INSTALLER_TICK: Duration = Duration::from_secs(1);
const LADDER_TICK: Duration = Duration::from_secs(5);
const DECAY_TICK: Duration = Duration::from_secs(60);
/// `main.rs`'s wait for the ladder's stand-down before a release.
const LADDER_RELEASE_WAIT: Duration = Duration::from_secs(30);
/// `/proc` clock ticks per second (`USER_HZ`).
const USER_HZ: u64 = 100;
/// The cgroup `main.rs`'s executor kills a tree in
/// (`ExecutorConfig::kill_cgroup_dir`), as the host's trace names it.
const KILL_CGROUP: &str = "northnarrow.slice/blocked.scope/neutralize";

// ── the case ─────────────────────────────────────────────────────────────

/// One recorded stream and the host it runs on.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    /// What the stream is and what its golden file must show.
    about: String,
    /// The levels the posture moves to, in order (each transition's `to`):
    /// an update of the golden file that changes them fails
    /// `every_posture_case_shows_what_it_says`.
    path: Vec<String>,
    /// The ladder stages the case reaches (in any order).
    #[serde(default)]
    stages: Vec<String>,
    /// The ops of the signed rows the case writes (in any order).
    #[serde(default)]
    signed: Vec<String>,
    /// `--detect-only`: the actuator touches nothing.
    #[serde(default)]
    detect_only: bool,
    /// Where the replay's clock starts (ns, the events' clock).
    #[serde(default)]
    start_ns: u64,
    /// The processes running when the stream starts.
    #[serde(default)]
    procs: Vec<ProcSpec>,
    /// Files there before the stream, under `@ROOT@`.
    #[serde(default)]
    files: Vec<String>,
    /// The entropy sampler's answers, by path prefix (the first that
    /// matches); any other path samples as plain content.
    #[serde(default)]
    entropy: Vec<EntropyAnswer>,
    /// What each ISOLATE attempt finds in the tables, in order; past the
    /// list, both families isolated.
    #[serde(default)]
    isolation: Vec<Families>,
    /// What each release of the isolation finds, in order; past the list,
    /// both families clear.
    #[serde(default)]
    release: Vec<Families>,
    /// Lab PR 249: the lines of the signed per-rule policy (lab PR 236,
    /// `rule-policy.local`) in force for this case's posture — its own
    /// handle (`PostureMachine::with_rule_policy`); none: the built-in
    /// defaults.
    #[serde(default)]
    rule_policy: Vec<String>,
    items: Vec<Item>,
}

/// One process of the case's host.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcSpec {
    pid: u32,
    ppid: u32,
    /// Its start on the events' clock (`start_ns` of its exec event).
    #[serde(default)]
    start_ns: u64,
    #[serde(default)]
    uid: u32,
    comm: String,
    exe: String,
    #[serde(default)]
    argv: Vec<String>,
    /// Its login uid; none for a process outside a login session. A
    /// process the stream's exec events create inherits its parent's.
    #[serde(default)]
    loginuid: Option<u32>,
    /// Its cgroup (`/proc/<pid>/cgroup`'s `0::` line); inherited likewise.
    #[serde(default)]
    cgroup: Option<String>,
    /// It has a controlling terminal; inherited likewise.
    #[serde(default)]
    tty: bool,
    /// In an uninterruptible wait: a kill does not take.
    #[serde(default)]
    stuck: bool,
    /// Its binary was deleted while it ran.
    #[serde(default)]
    deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntropyAnswer {
    prefix: String,
    examined: u32,
    high: u32,
}

/// What a family's table holds after an engage or a release: `done`,
/// `failed: why`, `unavailable: why`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Families {
    v4: String,
    v6: String,
}

impl Families {
    fn family(s: &str) -> FamilyOutcome {
        match s.split_once(": ") {
            None if s == "done" => FamilyOutcome::Done,
            Some(("failed", why)) => FamilyOutcome::Failed(why.to_string()),
            Some(("unavailable", why)) => FamilyOutcome::Unavailable(why.to_string()),
            _ => panic!("a family's outcome is `done`, `failed: …` or `unavailable: …`: {s:?}"),
        }
    }

    fn report(&self) -> IsolationReport {
        IsolationReport {
            v4: Self::family(&self.v4),
            v6: Self::family(&self.v6),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Item {
    /// One event as the agent serialises it (`nn_model::Event`); the clock
    /// moves to its time first (never back: an event read late is
    /// processed at the time it is read).
    Event(Box<Event>),
    /// The clock moves on, its heartbeats firing as they fall due.
    Wait { secs: u64 },
    /// A signed unlock (`OperationCode::Unlock`, lab PR 217) by the
    /// administrator's key.
    Unlock {},
    /// A signed trusted-installer grant of `window_secs`.
    InstallerGrant { window_secs: u32 },
    /// The host changes without an event the agent reads.
    Host(HostChange),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostChange {
    /// These processes exit (their children go to init, as the kernel
    /// reparents them).
    #[serde(default)]
    exit: Vec<u32>,
    /// These start — a fork the agent reads no exec of, or another process
    /// taking a pid that was freed.
    #[serde(default)]
    spawn: Vec<ProcSpec>,
    /// These enter an uninterruptible wait.
    #[serde(default)]
    stuck: Vec<u32>,
    /// `false`: the host has no `nft` (soft egress blocks fail).
    #[serde(default)]
    nft: Option<bool>,
}

// ── the clock ────────────────────────────────────────────────────────────

/// The replay's clock: nanoseconds on the events' clock, as the posture's
/// `Instant` (from a base taken when the replay starts) and the wall clock
/// (from [`WALL_AT_ZERO_SECS`]).
struct ReplayClock {
    base: Instant,
    ns: AtomicU64,
}

impl ReplayClock {
    fn new(start_ns: u64) -> Self {
        Self {
            base: Instant::now(),
            ns: AtomicU64::new(start_ns),
        }
    }

    fn ns(&self) -> u64 {
        self.ns.load(Ordering::SeqCst)
    }

    fn set(&self, ns: u64) {
        self.ns.store(ns, Ordering::SeqCst);
    }

    fn wall_secs(&self) -> u64 {
        WALL_AT_ZERO_SECS + self.ns() / 1_000_000_000
    }

    /// An `Instant` of this clock in milliseconds on the events' clock.
    fn ms_of(&self, t: Instant) -> u64 {
        t.saturating_duration_since(self.base).as_millis() as u64
    }
}

impl Clock for ReplayClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_nanos(self.ns())
    }

    fn wall(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(WALL_AT_ZERO_SECS) + Duration::from_nanos(self.ns())
    }
}

/// Lab PR 249: the audit log's clock — its rows are stamped with the
/// replay's wall clock, as the posture's records are.
impl nn_evidence::clock::Clock for ReplayClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from(Clock::wall(self))
    }
}

// ── the host ─────────────────────────────────────────────────────────────

/// A running process of the host.
#[derive(Debug, Clone)]
struct Proc {
    pid: u32,
    ppid: u32,
    start_ns: u64,
    uid: u32,
    comm: String,
    exe: String,
    argv: Vec<String>,
    loginuid: Option<u32>,
    cgroup: String,
    tty: bool,
    stuck: bool,
    deleted: bool,
}

/// The processes, the tables and the cgroups of the replay's host.
struct Host {
    /// The `/proc` every reader of the replay reads (the replay owns the
    /// directory).
    proc_root: PathBuf,
    procs: Mutex<BTreeMap<u32, Proc>>,
    /// `nft` is there: soft egress blocks take.
    nft: Mutex<bool>,
    /// Kill cgroups made, and binaries quarantined.
    cgroups: AtomicU64,
    vault: AtomicU64,
    /// What the isolation's tables will hold after each engage / release.
    isolation: Mutex<VecDeque<IsolationReport>>,
    release: Mutex<VecDeque<IsolationReport>>,
    /// What the host did and the ladder asked, since the last line.
    journal: Mutex<Vec<Value>>,
}

impl Host {
    fn new(case: &Case, proc_root: &Path) -> Self {
        let host = Self {
            proc_root: proc_root.to_path_buf(),
            procs: Mutex::new(BTreeMap::new()),
            nft: Mutex::new(true),
            cgroups: AtomicU64::new(0),
            vault: AtomicU64::new(0),
            isolation: Mutex::new(case.isolation.iter().map(Families::report).collect()),
            release: Mutex::new(case.release.iter().map(Families::report).collect()),
            journal: Mutex::new(Vec::new()),
        };
        for p in &case.procs {
            host.start(p.clone());
        }
        host
    }

    fn note(&self, v: Value) {
        self.journal.lock().push(v);
    }

    fn take_journal(&self) -> Vec<Value> {
        std::mem::take(&mut *self.journal.lock())
    }

    /// The process `pid` names now.
    fn running(&self, pid: u32) -> Option<Proc> {
        self.procs.lock().get(&pid).cloned()
    }

    /// `spec` starts (a process the case lists, or a fork with no exec
    /// read): it takes its pid, whatever held it.
    fn start(&self, spec: ProcSpec) {
        // The pid's holder, if any, has exited (its children go to init).
        if self.running(spec.pid).is_some() {
            self.exit(spec.pid);
        }
        let parent = self.running(spec.ppid);
        let p = Proc {
            pid: spec.pid,
            ppid: spec.ppid,
            start_ns: spec.start_ns,
            uid: spec.uid,
            comm: spec.comm,
            exe: spec.exe,
            argv: spec.argv,
            loginuid: spec
                .loginuid
                .or_else(|| parent.as_ref().and_then(|p| p.loginuid)),
            cgroup: spec
                .cgroup
                .or_else(|| parent.as_ref().map(|p| p.cgroup.clone()))
                .unwrap_or_else(|| "/".to_string()),
            tty: spec.tty || parent.as_ref().is_some_and(|p| p.tty),
            stuck: spec.stuck,
            deleted: spec.deleted,
        };
        self.write_proc(&p);
        self.procs.lock().insert(p.pid, p);
    }

    /// The host as an exec event shows it: the process it names runs (a
    /// fork and an exec; one the case already lists keeps its own
    /// attributes and takes the image).
    fn exec(&self, event: &Event) {
        let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            comm,
            filename,
            argv,
            start_ns,
            exe,
            ..
        } = event
        else {
            return;
        };
        let image = exe.path_or(filename).to_string();
        let known = self.running(*pid).filter(|p| p.start_ns == *start_ns);
        match known {
            Some(mut p) => {
                p.exe = image;
                p.comm = comm.clone();
                p.argv = argv.clone();
                p.uid = *uid;
                self.write_proc(&p);
                self.procs.lock().insert(p.pid, p);
            }
            None => self.start(ProcSpec {
                pid: *pid,
                ppid: *ppid,
                start_ns: *start_ns,
                uid: *uid,
                comm: comm.clone(),
                exe: image,
                argv: argv.clone(),
                loginuid: None,
                cgroup: None,
                tty: false,
                stuck: false,
                deleted: false,
            }),
        }
    }

    /// `pid` exits and is reaped; its children go to init.
    fn exit(&self, pid: u32) -> bool {
        let gone = self.procs.lock().remove(&pid);
        let _ = std::fs::remove_dir_all(self.proc_root.join(pid.to_string()));
        let orphans: Vec<Proc> = self
            .procs
            .lock()
            .values()
            .filter(|p| p.ppid == pid)
            .cloned()
            .collect();
        for mut o in orphans {
            o.ppid = 1;
            self.write_proc(&o);
            self.procs.lock().insert(o.pid, o);
        }
        gone.is_some()
    }

    fn change(&self, c: &HostChange) {
        for pid in &c.exit {
            let gone = self.exit(*pid);
            self.note(json!({"host": "exit", "pid": pid, "was_running": gone}));
        }
        for p in &c.spawn {
            let took = self.running(p.pid).map(|old| old.start_ns);
            self.note(json!({
                "host": "start",
                "pid": p.pid,
                "start_ns": p.start_ns,
                "exe": p.exe,
                "pid_was_held_by_start_ns": took,
            }));
            self.start(p.clone());
        }
        for pid in &c.stuck {
            if let Some(p) = self.procs.lock().get_mut(pid) {
                p.stuck = true;
            }
            self.note(json!({"host": "uninterruptible wait", "pid": pid}));
        }
        if let Some(on) = c.nft {
            *self.nft.lock() = on;
            self.note(json!({"host": "nft", "installed": on}));
        }
    }

    /// `/proc/<pid>` as the readers read it: `stat` (state, ppid, terminal,
    /// start in ticks), `status`, `loginuid`, `cgroup`, `cmdline`, `exe`.
    fn write_proc(&self, p: &Proc) {
        let d = self.proc_root.join(p.pid.to_string());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let tty = if p.tty { 34816 } else { 0 };
        let ticks = p.start_ns / (1_000_000_000 / USER_HZ);
        std::fs::write(
            d.join("stat"),
            format!(
                "{} ({}) S {} {} {} {tty} -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n",
                p.pid, p.comm, p.ppid, p.pid, p.pid
            ),
        )
        .unwrap();
        let u = p.uid;
        std::fs::write(
            d.join("status"),
            format!(
                "Name:\t{}\nPPid:\t{}\nUid:\t{u}\t{u}\t{u}\t{u}\nGid:\t{u}\t{u}\t{u}\t{u}\n",
                p.comm, p.ppid
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("loginuid"),
            p.loginuid.unwrap_or(u32::MAX).to_string(),
        )
        .unwrap();
        std::fs::write(d.join("cgroup"), format!("0::{}\n", p.cgroup)).unwrap();
        let mut cmdline = p.argv.join("\0");
        cmdline.push('\0');
        std::fs::write(d.join("cmdline"), cmdline).unwrap();
        let exe = if p.deleted {
            format!("{} (deleted)", p.exe)
        } else {
            p.exe.clone()
        };
        std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
    }

    /// The running descendants of `root`, as the kill's `/proc` walk finds
    /// them (`response::kill::collect_descendants`: the children of a
    /// process in pid order, depth first from the last one).
    fn descendants(&self, root: u32) -> Vec<u32> {
        let procs = self.procs.lock();
        let mut out = Vec::new();
        let mut frontier = vec![root];
        while let Some(parent) = frontier.pop() {
            for child in procs.values().filter(|p| p.ppid == parent && p.pid > 2) {
                out.push(child.pid);
                frontier.push(child.pid);
            }
        }
        out
    }
}

// ── the actuator on the host ─────────────────────────────────────────────

/// The `CombatActuator` of the replay: the ladder's calls, carried out on
/// the [`Host`] — the production actuator's (`SystemActuator`) steps and
/// words, on a table instead of the kernel.
struct HostActuator {
    host: Arc<Host>,
    detect_only: bool,
    /// The executor's tree guard (`main.rs`: the ladder's guard, on every
    /// pid the walk would kill).
    guard: SystemProtectedProcs,
}

/// A capture of the process `pid` names (start `start`): its identity, in
/// a reference without a pidfd (`ProcRef::for_test`), the host's table
/// standing for the pidfd.
fn capture(pid: u32, start: Option<u64>) -> ProcRef {
    ProcRef::for_test(pid, start)
}

impl HostActuator {
    /// The capture names the process that runs now (its pidfd is not
    /// readable yet).
    fn live(&self, r: &ProcRef) -> bool {
        self.host
            .running(r.pid())
            .is_some_and(|p| Some(p.start_ns) == r.start_ticks())
    }

    /// `KillProcessTree` of `root` through a cgroup of its own, as
    /// `Executor::execute_on` and `response::kill::kill_tree` take it
    /// (cgroup v2 with `cgroup.kill`): a capture that has exited is gone;
    /// else the root moved in and frozen, its descendants moved in (a
    /// guarded one refused), the cgroup killed, each member checked by its
    /// identity — one still running (an uninterruptible wait) is signalled
    /// on its own and reported failed.
    fn kill_tree(&self, root: &ProcRef) -> ExecutionReport {
        let pid = root.pid();
        let report = |primary, additional| ExecutionReport {
            action: ResponseAction::KillProcessTree,
            primary,
            additional,
            elapsed: Duration::ZERO,
        };
        if self.detect_only {
            return report(ExecutionOutcome::WouldExecute { pid }, Vec::new());
        }
        if !self.live(root) {
            let now = self.host.running(pid).map(|p| p.start_ns);
            self.host.note(json!({
                "host": "kill tree",
                "root": pid,
                "found": match now {
                    None => "the captured process has exited".to_string(),
                    Some(s) => format!("the pid names another process now (start_ns {s}): untouched"),
                },
            }));
            return report(ExecutionOutcome::AlreadyGone { pid }, Vec::new());
        }
        let n = self.host.cgroups.fetch_add(1, Ordering::SeqCst);
        let mut members = Vec::new();
        let mut others = Vec::new();
        for child in self.host.descendants(pid) {
            match self.guard.protected_reason(child) {
                Some(why) => others.push(ExecutionOutcome::Refused {
                    pid: child,
                    reason: why.as_str(),
                }),
                None => members.push(child),
            }
        }
        // the cgroup's kill; then each member by its identity
        let stuck = |p: u32| self.host.running(p).is_some_and(|p| p.stuck);
        let mut outcomes = Vec::new();
        let mut running = Vec::new();
        for m in &members {
            if stuck(*m) {
                running.push(*m);
            } else {
                self.host.exit(*m);
                outcomes.push(ExecutionOutcome::Killed { pid: *m });
            }
        }
        for m in &running {
            outcomes.push(ExecutionOutcome::Failed {
                pid: *m,
                errno: libc::ETIMEDOUT,
            });
        }
        let primary = if stuck(pid) {
            ExecutionOutcome::Failed {
                pid,
                errno: libc::ETIMEDOUT,
            }
        } else {
            self.host.exit(pid);
            ExecutionOutcome::Killed { pid }
        };
        self.host.note(json!({
            "host": "kill tree",
            "root": pid,
            "cgroup": format!("{KILL_CGROUP}-{n}"),
            "frozen_with": members,
            "spared": others.iter().map(|o| format!("{o:?}")).collect::<Vec<_>>(),
            "still_running": running.iter().copied().chain(stuck(pid).then_some(pid)).collect::<Vec<_>>(),
        }));
        outcomes.extend(others);
        report(primary, outcomes)
    }
}

impl CombatActuator for HostActuator {
    /// `ProcRef::open_for_event` on the host: the process `pid` names now,
    /// if it is the event's (started at `start_ns`, or — that unknown — by
    /// `seen_ns`).
    fn identify(&self, pid: u32, start_ns: u64, seen_ns: u64) -> Arc<ProcRef> {
        let found = self.host.running(pid);
        let (r, what) = match found {
            Some(p) if start_ns != 0 && p.start_ns != start_ns => (
                capture(pid, Some(start_ns)),
                format!("the pid names another process (start_ns {})", p.start_ns),
            ),
            Some(p) if start_ns == 0 && seen_ns != 0 && p.start_ns > seen_ns => (
                capture(pid, None),
                format!(
                    "the pid names a process started after the event (start_ns {})",
                    p.start_ns
                ),
            ),
            Some(p) => (
                capture(pid, Some(p.start_ns)),
                format!("running (start_ns {})", p.start_ns),
            ),
            None => (
                capture(pid, (start_ns != 0).then_some(start_ns)),
                "no process".to_string(),
            ),
        };
        self.host
            .note(json!({"ladder": "capture", "pid": pid, "found": what}));
        // As `open_for_event`: the event's time kept (lab PR 245: the rows
        // name it).
        Arc::new(r.seen_at(seen_ns))
    }

    /// `ProcRef::matches_event` on the host: the captured process while it
    /// runs; once it has exited, an event with its start.
    fn same_process(&self, target: &ProcRef, start_ns: u64) -> bool {
        self.live(target) || (start_ns != 0 && target.start_ticks() == Some(start_ns))
    }

    /// `SystemActuator::describe` on the host (lab PR 245): the production
    /// reader of `exe` and `cgroup`, on the replay's `/proc`, while the
    /// capture names the running process.
    fn describe(&self, target: &ProcRef) -> ProcFacts {
        if self.live(target) {
            crate::combat::actuator::read_proc_facts(&self.host.proc_root, target.pid())
        } else {
            ProcFacts::default()
        }
    }

    fn begin_episode(&self) {
        self.host.note(json!({"ladder": "begin episode"}));
    }

    fn soft_egress_block(&self, target: &ProcRef) -> SoftBlock {
        let pid = target.pid();
        let primary = if self.detect_only {
            ExecutionOutcome::WouldExecute { pid }
        } else if !self.live(target) {
            ExecutionOutcome::AlreadyGone { pid }
        } else if *self.host.nft.lock() {
            ExecutionOutcome::Blocked { pid }
        } else {
            ExecutionOutcome::Failed {
                pid,
                errno: libc::ENOENT,
            }
        };
        let answer = SystemActuator::soft_block_of(primary);
        self.host.note(json!({
            "ladder": "soft egress block",
            "pid": pid,
            "answer": format!("{answer:?}"),
        }));
        answer
    }

    fn soft_egress_clear(&self, target: &ProcRef) {
        let pid = target.pid();
        let answer = if self.detect_only {
            "detect-only: nothing to release"
        } else if !self.live(target) {
            "not released: the process has exited"
        } else {
            "released"
        };
        self.host.note(json!({
            "ladder": "soft egress release",
            "pid": pid,
            "answer": answer,
        }));
    }

    /// `SystemActuator::neutralize` on the host: each offender's binary
    /// looked up before the kill, every offender's tree killed, each
    /// binary quarantined once.
    fn neutralize(&self, offenders: &[Arc<ProcRef>]) -> NeutralizeReport {
        self.host.note(json!({
            "ladder": "neutralize",
            "offenders": offenders.iter().map(|r| r.pid()).collect::<Vec<_>>(),
        }));
        let binaries: Vec<(u32, Option<String>)> = offenders
            .iter()
            .map(|r| {
                let exe = self
                    .live(r)
                    .then(|| self.host.running(r.pid()))
                    .flatten()
                    .filter(|p| !p.deleted)
                    .map(|p| p.exe);
                (r.pid(), exe)
            })
            .collect();
        let mut outcomes: Vec<OffenderOutcome> = offenders
            .iter()
            .map(|r| {
                let (contained, kill) = SystemActuator::kill_outcome(&self.kill_tree(r));
                OffenderOutcome {
                    pid: r.pid(),
                    contained,
                    kill,
                    quarantine: String::new(),
                }
            })
            .collect();
        let mut done: Vec<(String, u32)> = Vec::new();
        for (slot, (pid, binary)) in outcomes.iter_mut().zip(binaries) {
            slot.quarantine = match binary {
                None => NO_BINARY.to_string(),
                Some(exe) => match done.iter().find(|(e, _)| *e == exe) {
                    Some((_, first)) => format!("same binary as pid {first}"),
                    None => {
                        done.push((exe.clone(), pid));
                        let primary = if self.detect_only {
                            ExecutionOutcome::WouldExecute { pid }
                        } else if crate::response::quarantine::is_quarantine_denied(Path::new(&exe))
                        {
                            // `quarantine::quarantine_handle`: kill-only.
                            ExecutionOutcome::Refused {
                                pid,
                                reason: "path is under a protected system prefix",
                            }
                        } else {
                            let n = self.host.vault.fetch_add(1, Ordering::SeqCst);
                            self.host.note(json!({
                                "host": "quarantine",
                                "pid": pid,
                                "binary": exe,
                                "vault_id": format!("golden-{n}"),
                            }));
                            ExecutionOutcome::Quarantined {
                                original_path: exe,
                                vault_id: format!("golden-{n}"),
                            }
                        };
                        SystemActuator::quarantine_text(pid, &primary)
                    }
                },
            };
        }
        NeutralizeReport {
            offenders: outcomes,
        }
    }

    fn isolate(&self) -> IsolateOutcome {
        if self.detect_only {
            self.host
                .note(json!({"ladder": "isolate", "answer": DETECT_ONLY_ISOLATE}));
            return IsolateOutcome::NotApplied(DETECT_ONLY_ISOLATE.to_string());
        }
        let report = self
            .host
            .isolation
            .lock()
            .pop_front()
            .unwrap_or(IsolationReport {
                v4: FamilyOutcome::Done,
                v6: FamilyOutcome::Done,
            });
        self.host.note(json!({
            "ladder": "isolate",
            "answer": report.summary("isolated (read back)"),
        }));
        IsolateOutcome::Applied(report)
    }

    fn is_dry_run(&self) -> bool {
        self.detect_only
    }
}

/// The entropy sampler of a case (as the decision golden's).
struct Answers(Vec<EntropyAnswer>);

impl Sampler for Answers {
    fn sample(&self, path: &str, _since: Duration) -> Sample {
        match self.0.iter().find(|a| path.starts_with(&a.prefix)) {
            Some(a) => Sample {
                examined: a.examined,
                high: a.high,
                containers: 0,
            },
            None => Sample {
                examined: 4,
                high: 0,
                containers: 0,
            },
        }
    }

    fn sample_copies(&self, copy: &str, _suffix: &str, since: Duration) -> Sample {
        self.sample(copy, since)
    }
}

// ── the replay ───────────────────────────────────────────────────────────

/// One replay of a case: the agent's posture, ladder and window over the
/// case's host.
struct Replay {
    root: tempfile::TempDir,
    /// The host's `/proc`.
    proc_dir: tempfile::TempDir,
    clock: Arc<ReplayClock>,
    host: Arc<Host>,
    ransom: Arc<RansomTracker>,
    defense: Arc<DefenseDetector>,
    window: Arc<TrustedInstallerOverride>,
    posture: PostureMachine,
    ladder: Arc<CombatLadder>,
    correlation: CorrelationBuffer,
    auth: AdminAuth,
    admin: ed25519_dalek::SigningKey,
    audit: Arc<Mutex<AuditLog>>,
    audit_path: PathBuf,
    audit_key: ed25519_dalek::VerifyingKey,
    /// The audit log's rows read so far.
    rows: Vec<AuditEntry>,
    /// The transitions of the posture's log rendered so far.
    transitions_seen: usize,
    /// The lines of the golden text.
    lines: Vec<Value>,
}

impl Replay {
    fn new(case: &Case, root: tempfile::TempDir) -> Self {
        for f in &case.files {
            let p = PathBuf::from(f);
            assert!(
                p.starts_with(root.path()),
                "{f}: a case's file lies under {ROOT_TOKEN}"
            );
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"golden fixture").unwrap();
        }
        let clock = Arc::new(ReplayClock::new(case.start_ns));
        let proc_dir = tempfile::TempDir::new().unwrap();
        let proc_root = proc_dir.path().to_path_buf();
        let host = Arc::new(Host::new(case, &proc_root));
        let fixture = Path::new(GOLDEN_DIR).join("host");
        let lineage = AuthSessionTracker::new(&proc_root).with_host_root(&fixture);

        // The signed audit log and its key (`main.rs`: the agent's). Lab PR
        // 249: a fixed key, the replay's clock and the replayed agent's pid,
        // so the rows — their hashes and signatures — are the same bytes in
        // every replay.
        let state = root.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let key_file = state.join("agent.key");
        std::fs::write(&key_file, format!("{}\n", hex::encode(AUDIT_KEY_SEED))).unwrap();
        let key = AgentSigningKey::load_or_bootstrap(&key_file).unwrap();
        let audit_key = key.verifying_key();
        let audit_path = state.join("audit.log");
        let audit = Arc::new(Mutex::new(
            AuditLog::open_with(
                &audit_path,
                key,
                AGENT_ID,
                AuditStamps {
                    clock: clock.clone(),
                    self_pid: AGENT_PID,
                },
            )
            .unwrap(),
        ));

        // The shared judges (`main.rs`: the shipped lists, the lineage).
        let ransom = Arc::new(RansomTracker::with(
            lineage.clone(),
            ProgramOwners::new(&fixture),
            Arc::new(Answers(
                case.entropy
                    .iter()
                    .map(|a| EntropyAnswer {
                        prefix: a.prefix.clone(),
                        examined: a.examined,
                        high: a.high,
                    })
                    .collect(),
            )),
        ));
        let process_allowlist = load_comm_allowlist(
            "process-comm-allowlist",
            &Path::new(CONFIGS).join("process-comm-allowlist.v1"),
            PROCESS_COMM_ALLOWLIST_SHIPPED,
            &Verified::Missing,
        )
        .unwrap_or_default();
        let (tools, _) = SecurityTools::load(&Path::new(CONFIGS).join("security-tools.v1"));
        let defense = Arc::new(DefenseDetector::with_proc_root(
            Arc::new(tools),
            lineage.clone(),
            Some(Arc::new(process_allowlist.with_identity(lineage.clone()))),
            &proc_root,
        ));
        let window = Arc::new(
            TrustedInstallerOverride::new(
                None,
                0,
                Some(Arc::clone(&audit)),
                Duration::from_secs(u64::from(MAX_TRUSTED_INSTALLER_WINDOW_SECS)),
            )
            .with_clock(clock.clone()),
        );

        // The posture, its hooks reaching the ladder through a slot as in
        // `main.rs`; the entry hook engages the ladder with the posture's
        // entry (lab PR 245: the trigger, the evidence it cites, the
        // event's process); the release hook stands the ladder down, then
        // lifts the isolation and reads the tables back. (Weakly: the
        // ladder's gate holds the posture, and a replay is dropped at its
        // end.)
        let slot: Arc<OnceLock<Weak<CombatLadder>>> = Arc::new(OnceLock::new());
        let entry = {
            let (slot, clock) = (Arc::clone(&slot), Arc::clone(&clock));
            Arc::new(move |entry: &CombatEntry| {
                if let Some(l) = slot.get().and_then(Weak::upgrade) {
                    l.engage(entry, clock.now());
                }
            })
        };
        let release = {
            let (slot, clock, host) = (Arc::clone(&slot), Arc::clone(&clock), Arc::clone(&host));
            Arc::new(move |token: UnlockToken, scope: ReleaseScope| {
                if scope == ReleaseScope::Combat {
                    if let Some(l) = slot.get().and_then(Weak::upgrade) {
                        l.stand_down_and_wait(clock.now(), LADDER_RELEASE_WAIT);
                    }
                }
                let _ = token;
                let report = host.release.lock().pop_front().unwrap_or(IsolationReport {
                    v4: FamilyOutcome::Done,
                    v6: FamilyOutcome::Done,
                });
                let summary = report.summary("cleared (read back)");
                host.note(json!({
                    "ladder": "release isolation",
                    "scope": format!("{scope:?}"),
                    "answer": summary,
                }));
                if report.complete() {
                    Ok(summary)
                } else {
                    Err(summary)
                }
            })
        };
        let posture = PostureMachine::new_with_hooks_and_exempt_and_auth_and_extras(
            entry,
            release,
            ExemptPids::with_agent(AGENT_PID),
            lineage.clone(),
            Vec::new(),
            EscalationAllowList::empty(),
        )
        .with_clock(clock.clone())
        // Lab PR 249: the case's per-rule policy, on a handle of its own.
        .with_rule_policy(PolicyHandle::new(case_policy(case)));
        posture.set_installer_window(Arc::clone(&window));
        posture.set_ransom_tracker(Arc::clone(&ransom));
        posture.set_defense_detector(Arc::clone(&defense));
        defense.set_installer_window(Arc::clone(&window));

        // The ladder (`main.rs`), its side effects in the caller.
        let guard = || {
            SystemProtectedProcs::with_parts(
                AGENT_PID,
                ExemptPids::with_agent(AGENT_PID),
                &proc_root,
                "/usr/bin/northnarrow-watchdog",
                crate::combat::protected::SSHD_EXES
                    .iter()
                    .map(PathBuf::from)
                    .collect(),
            )
        };
        let ladder = Arc::new(
            CombatLadder::new(
                Box::new(HostActuator {
                    host: Arc::clone(&host),
                    detect_only: case.detect_only,
                    guard: guard(),
                }),
                Box::new(AuditEvidence::new(Some(Arc::clone(&audit))).with_clock(clock.clone())),
                Box::new(guard()),
                LadderConfig::default(),
            )
            .with_isolation_gate({
                let posture = posture.clone();
                move || posture.is_combat_locked()
            })
            .with_neutralize_hook({
                let host = Arc::clone(&host);
                Box::new(move |refs: &[Arc<ProcRef>]| {
                    host.note(json!({
                        "ladder": "copy-on-first-write told the contained processes",
                        "pids": refs.iter().map(|r| r.pid()).collect::<Vec<_>>(),
                    }))
                })
            }),
        );
        let _ = slot.set(Arc::downgrade(&ladder));
        {
            let (ladder, clock) = (Arc::downgrade(&ladder), Arc::clone(&clock));
            posture.on_combat_decay(Arc::new(move || {
                if let Some(l) = ladder.upgrade() {
                    l.stand_down(clock.now());
                }
            }));
        }

        // The administrator's key, in an `admin.pub` of the replay's own.
        let admin = ed25519_dalek::SigningKey::from_bytes(&ADMIN_SEED);
        let admin_pub = root.path().join("admin.pub");
        std::fs::write(
            &admin_pub,
            format!(
                "{} unlock,trusted-installer\n",
                hex::encode(admin.verifying_key().to_bytes())
            ),
        )
        .unwrap();
        let auth = AdminAuth::load_with_agent_id(&admin_pub, AGENT_ID).unwrap();

        Self {
            root,
            proc_dir,
            clock,
            host,
            ransom,
            defense,
            window,
            posture,
            ladder,
            correlation: CorrelationBuffer::with_default_capacity(),
            auth,
            admin,
            audit,
            audit_path,
            audit_key,
            rows: Vec::new(),
            transitions_seen: 0,
            lines: Vec::new(),
        }
    }

    /// The clock to `ns`, the heartbeats firing as they fall due: the
    /// window's expiry every second, the ladder's tick every 5 s, the
    /// posture's decay every 60 s — each a line of its own when it changed
    /// something.
    fn advance_to(&mut self, ns: u64) {
        let step = INSTALLER_TICK.as_nanos() as u64;
        loop {
            let now = self.clock.ns();
            let next = (now / step + 1) * step;
            if next > ns {
                break;
            }
            self.clock.set(next);
            self.window.close_if_expired(self.clock.now());
            self.flush_tick("installer window");
            if next % (DECAY_TICK.as_nanos() as u64) == 0 {
                let _ = self.posture.tick_decay();
                self.flush_tick("posture decay");
            }
            if next % (LADDER_TICK.as_nanos() as u64) == 0 {
                self.ladder.tick(self.clock.now());
                self.flush_tick("ladder");
            }
        }
        if ns > self.clock.ns() {
            self.clock.set(ns);
        }
    }

    /// A heartbeat's line, when it changed something.
    fn flush_tick(&mut self, what: &str) {
        let mut line = json!({"tick": what});
        if self.collect(&mut line, None) {
            self.push(line);
        }
    }

    fn push(&mut self, mut line: Value) {
        line["seq"] = json!(self.lines.len());
        line["at_ms"] = json!(self.clock.ns() / 1_000_000);
        line["state"] = self.state();
        self.lines.push(line);
    }

    /// What happened since the last line, into `line`: the posture's
    /// transitions, the ladder's calls and the host's acts, the signed rows.
    /// `true` when there was anything.
    fn collect(&mut self, line: &mut Value, evidence: Option<&Value>) -> bool {
        // A heartbeat that changed nothing (most of them): no copy of the
        // logs.
        if self.posture.inner.transitions.read().len() == self.transitions_seen
            && self.host.journal.lock().is_empty()
            && self.audit.lock().rows() as usize == self.rows.len()
        {
            return false;
        }
        let log = self.posture.transition_log();
        assert!(
            log.len() < 256,
            "the posture's transition log is capped at 256: a case stays below"
        );
        let new: Vec<Value> = log[self.transitions_seen..]
            .iter()
            .map(|t| {
                let mut v = json!({
                    "from": t.from.as_str(),
                    "to": t.to.as_str(),
                    "trigger": t.trigger.map(|x| x.as_str()),
                    "reason": t.reason,
                    "unix_ts_secs": t.unix_ts_secs,
                });
                if let (Some(e), Some(_)) = (evidence, t.trigger) {
                    v["evidence"] = e.clone();
                }
                v
            })
            .collect();
        self.transitions_seen = log.len();
        let journal = self.host.take_journal();
        let rows = self.new_rows();
        let any = !new.is_empty() || !journal.is_empty() || !rows.is_empty();
        if !new.is_empty() {
            line["posture"] = Value::Array(new);
        }
        if !journal.is_empty() {
            line["acts"] = Value::Array(journal);
        }
        if !rows.is_empty() {
            line["signed"] = Value::Array(rows);
        }
        any
    }

    /// The audit log's rows written since the last call, whole. Lab PR 249:
    /// the replay's clock, a fixed key and the replayed agent's pid make
    /// every field the same in every replay — the time, the hashes and the
    /// signature over it are printed (they were named `@TS@`, `#n`, `@SIG@`
    /// and `@AGENT_PID@`). A row naming the replay's directories would not
    /// be: it fails here.
    fn new_rows(&mut self) -> Vec<Value> {
        let text = std::fs::read_to_string(&self.audit_path).unwrap_or_default();
        let raw: Vec<&str> = text.lines().collect();
        let all: Vec<AuditEntry> = raw
            .iter()
            .map(|l| serde_json::from_str(l).expect("an audit row"))
            .collect();
        let from = self.rows.len();
        let dirs = [
            self.root.path().to_str().unwrap(),
            self.proc_dir.path().to_str().unwrap(),
        ];
        let out = all[from..]
            .iter()
            .zip(&raw[from..])
            .map(|(e, line)| {
                assert_eq!(
                    e.client_pid, AGENT_PID,
                    "a row the replayed agent signs names its pid: {line}"
                );
                for d in dirs {
                    assert!(
                        !line.contains(d),
                        "a signed row names the replay's directory {d}, so its hash and \
                         signature differ in every replay: {line}"
                    );
                }
                serde_json::to_value(e).unwrap()
            })
            .collect();
        self.rows = all;
        out
    }

    /// The posture and the ladder now.
    fn state(&self) -> Value {
        let s = self.posture.current();
        let ms = |t: &Instant| self.clock.ms_of(*t);
        let mut v = json!({
            "posture": s.kind().as_str(),
            "stage": self.ladder.current_stage().map(|s| s.as_str()),
            "offenders": self.ladder.offenders(),
            "ledger": self.posture.corroboration_len(),
        });
        match &s {
            PostureState::Observing => {}
            PostureState::Alerted {
                since,
                last_trigger,
            }
            | PostureState::Engaged {
                since,
                last_trigger,
            } => {
                v["since_ms"] = json!(ms(since));
                v["last_trigger_ms"] = json!(ms(last_trigger));
            }
            PostureState::Combat { since, locked } => {
                v["since_ms"] = json!(ms(since));
                v["locked"] = json!(locked);
            }
        }
        v
    }

    /// The evidence an event's transition cites: its triggers (kind of
    /// evidence, level, confidence), the actor's scope and the signals that
    /// scope held before it (what corroborates a COMBAT-tier heuristic).
    fn evidence_before(&self, event: &Event) -> (super::corroboration::Scope, Value) {
        let scope = self.posture.inner.triggers.session_scope(event);
        let held: Vec<Value> = self
            .posture
            .inner
            .corroboration
            .lock()
            .signals_of(&scope, self.clock.now())
            .into_iter()
            .map(|(t, class, privileged, placed)| {
                json!({
                    "trigger": t.as_str(),
                    "class": format!("{class:?}"),
                    "privileged": privileged,
                    "placed": placed,
                })
            })
            .collect();
        (scope, Value::Array(held))
    }

    fn event(&mut self, index: usize, event: &Event) {
        let ts = event_ts(event);
        self.advance_to(ts);
        let now = self.clock.now();
        // The host as the event shows it: an exec's process runs.
        self.host.exec(event);
        let (scope, held) = self.evidence_before(event);
        let before = self.posture_mark();
        // `process_event`: the posture first, over the recent events…
        let fired = self
            .correlation
            .with_recent(|recent| self.posture.observe(event, recent));
        let mut cited = json!({
            "scope": scope.to_string(),
            "in_scope_before": held,
        });
        // A signal that moved no level (the same tier re-armed, a signal
        // recorded): the scope it was judged in, and what that scope held.
        let rearmed = fired.is_none() && self.posture_mark() != before;
        if let Some(reason) = self
            .posture
            .transition_log()
            .last()
            .map(|t| t.reason.clone())
        {
            if fired.is_some() {
                let decisive = self.posture.ransomware_combat_without_corroboration();
                cited["triggers"] = Value::Array(
                    reason
                        .split('+')
                        .filter_map(trigger_named)
                        .map(|t| trigger_json(t, event, decisive))
                        .collect(),
                );
            }
        }
        // (the COMBAT edge engaged the ladder from the entry hook, inside
        // `observe`, with the trigger and the event's process: lab PR 245)
        // …an engaged ladder sees every event (jump-ahead)…
        if self.ladder.current_stage().is_some() {
            self.ladder.observe(event, now);
        }
        // …and the buffer keeps it (an open flow's rows are the rules').
        if !matches!(event, Event::NetFlow(nf) if nf.phase.is_open()) {
            self.correlation.push(event.clone());
        }
        // The rules would assess the event with the trackers they share
        // with the posture (memoised: the posture's answer).
        let assessed = self.assessed(event);
        let mut line = json!({"item": index, "event": event_summary(event)});
        if let Some(a) = assessed {
            line["assessed"] = a;
        }
        if rearmed {
            line["signal"] = cited.clone();
        }
        self.collect(&mut line, Some(&cited));
        self.push(line);
    }

    /// What a signal that moves no level still changes: the time the
    /// current level was last triggered, and the ledger.
    fn posture_mark(&self) -> (Option<u64>, usize) {
        let last = match self.posture.current() {
            PostureState::Alerted { last_trigger, .. }
            | PostureState::Engaged { last_trigger, .. } => Some(self.clock.ms_of(last_trigger)),
            _ => None,
        };
        (last, self.posture.corroboration_len())
    }

    /// What the shared trackers made of `event`: a security tool switched
    /// off (sanctioned or not), the ransomware shapes of its actor.
    fn assessed(&self, event: &Event) -> Option<Value> {
        let mut v = serde_json::Map::new();
        if let Some(f) = self.defense.assess(event) {
            v.insert(
                "defense".into(),
                json!({
                    "rule": format!("{:?}", f.rule),
                    "tool": f.tool,
                    "what": f.what,
                    "sanctioned": f.sanctioned,
                    "suspicious": f.suspicious.map(|(p, prog)| json!({"pid": p, "program": prog})),
                    "coalesced_into": f.coalesced_into,
                }),
            );
        }
        if let Some(a) = self.ransom.assess(event) {
            if !a.signals.is_empty() || a.trusted.is_some() {
                v.insert(
                    "ransomware".into(),
                    json!({
                        "actor": a.actor,
                        "program": a.program,
                        "trusted": a.trusted,
                        "shapes": a.signals.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
                        "decisive": a.decisive,
                    }),
                );
            }
        }
        (!v.is_empty()).then_some(Value::Object(v))
    }

    /// A signed request by the administrator, verified by `ConnAuth` as the
    /// admin socket verifies it: the matched key's fingerprint, and the
    /// token.
    fn signed(
        &self,
        payload: impl FnOnce([u8; 32], u64) -> nn_proto::admin_signed_payload::SignedPayload,
        role: nn_proto::admin_signed_payload::Role,
        op: nn_proto::admin_signed_payload::OperationCode,
    ) -> (UnlockToken, String) {
        let conn = ConnAuth::new(&self.auth);
        let nonce = conn.issue_challenge().unwrap();
        let payload = payload(nonce, self.clock.wall_secs());
        let sig = nn_proto::admin_signed_payload::sign(&payload, &self.admin).unwrap();
        let (token, fps) = conn
            .verify_signed_payload_quorum(&payload, &[sig], 1, &[role], op, self.clock.wall_secs())
            .expect("the administrator's signed request verifies");
        (token, fps.first().cloned().unwrap_or_default())
    }

    /// `dispatch_signed_unlock`: verify, then the posture's release.
    fn unlock(&mut self, index: usize) {
        use nn_proto::admin_signed_payload::{OperationCode, Role, SignedPayload};
        let (token, signer) = self.signed(
            |nonce, ts| SignedPayload::new_unlock(nonce, ts, AGENT_ID),
            Role::Unlock,
            OperationCode::Unlock,
        );
        let outcome = match self.posture.admin_release_combat_with_token(token) {
            Ok(out) if out.left_combat => json!({
                "released": true,
                "message": format!("COMBAT released, posture {}: {}", out.state.kind(), out.detail),
            }),
            Ok(out) => json!({
                "released": true,
                "message": format!("not in COMBAT (posture {}): {}", out.state.kind(), out.detail),
            }),
            Err(e) => json!({"released": false, "error": e.to_string()}),
        };
        let mut line = json!({
            "item": index,
            "unlock": {"signer": signer, "role": "unlock", "outcome": outcome},
        });
        self.collect(&mut line, None);
        self.push(line);
    }

    /// `dispatch_trusted_installer_grant`: verify, then arm the window.
    fn grant(&mut self, index: usize, window_secs: u32) {
        use nn_proto::admin_signed_payload::{OperationCode, Role, SignedPayload};
        let (_token, signer) = self.signed(
            |nonce, ts| {
                SignedPayload::new_trusted_installer_grant(nonce, ts, AGENT_ID, window_secs)
            },
            Role::TrustedInstaller,
            OperationCode::TrustedInstallerGrant,
        );
        let window = self.window.arm_by(window_secs, self.clock.now(), &signer);
        let grant = self.window.current_grant();
        let mut line = json!({
            "item": index,
            "installer_grant": {
                "signer": signer,
                "window_secs": window.as_secs(),
                "until": grant.map(|g| g.expires_at),
            },
        });
        self.collect(&mut line, None);
        self.push(line);
    }

    fn run(&mut self, case: &Case) {
        for (i, item) in case.items.iter().enumerate() {
            match item {
                Item::Event(e) => self.event(i, e),
                Item::Wait { secs } => {
                    let to = self.clock.ns() + secs * 1_000_000_000;
                    self.advance_to(to);
                    let mut line = json!({"item": i, "wait_secs": secs});
                    self.collect(&mut line, None);
                    self.push(line);
                }
                Item::Unlock {} => self.unlock(i),
                Item::InstallerGrant { window_secs } => self.grant(i, *window_secs),
                Item::Host(c) => {
                    self.host.change(c);
                    let mut line = json!({"item": i, "host": "changed"});
                    self.collect(&mut line, None);
                    self.push(line);
                }
            }
        }
        // Every row the replay wrote is a genuine, chained, signed row.
        crate::audit::verify_chain(&self.rows, &self.audit_key)
            .expect("the replay's audit chain verifies");
    }
}

/// Lab PR 249: the per-rule policy a case's posture reads — its
/// `rule_policy` lines through the parser of `rule-policy.local` (any bad
/// line fails the case), or the built-in defaults.
fn case_policy(case: &Case) -> RulePolicy {
    if case.rule_policy.is_empty() {
        return RulePolicy::builtin();
    }
    let mut text = case.rule_policy.join("\n");
    text.push('\n');
    let mut p = rule_policy::parse(&text)
        .unwrap_or_else(|e| panic!("the case's rule_policy does not parse: {e}"));
    p.source = "the case's rule_policy".to_string();
    p
}

/// The time an event happened (ns, the events' clock).
fn event_ts(e: &Event) -> u64 {
    triggers::event_owner_seen(e).1.max(match e {
        Event::Fim(fe) => fe.timestamp_ns,
        _ => 0,
    })
}

/// An event as a golden line names it: its kind and its process (the case
/// file holds the rest).
fn event_summary(e: &Event) -> Value {
    let kind = serde_json::to_value(e)
        .ok()
        .and_then(|v| v.as_object().and_then(|o| o.keys().next().cloned()))
        .unwrap_or_default();
    json!({"kind": kind, "pid": triggers::event_owner_pid(e)})
}

/// Every trigger, by its name.
fn trigger_named(name: &str) -> Option<TriggerType> {
    use TriggerType::*;
    [
        Reconnaissance,
        SuspiciousDns,
        SensitiveFileAccess,
        Lolbas,
        ExploitAttempt,
        AdjacentCompromise,
        HeavyReconnaissance,
        CriticalFileModification,
        ConfirmedIntrusion,
        PersistenceMechanism,
        LateralMovement,
        ExfiltrationPattern,
        AntiTamperDenial,
        RelayedTamperAttempt,
        TelemetryLoss,
        StagingExec,
        ControlSurfaceTamper,
        ExploitPostcondition,
        RansomwareEncryption,
        DefenseImpairment,
    ]
    .into_iter()
    .find(|t| t.as_str() == name)
}

/// A trigger an event raised, as the posture judges it (`ransomware_decisive`:
/// the machine's ransomware directive, lab PR 249).
fn trigger_json(t: TriggerType, e: &Event, ransomware_decisive: bool) -> Value {
    json!({
        "trigger": t.as_str(),
        "class": format!("{:?}", triggers::evidence_class(t, e)),
        "level": t.target_level().as_str(),
        "confidence": format!("{:?}", t.confidence(ransomware_decisive)),
        "locks_combat": t.locks_combat(),
    })
}

/// The golden text of one replay: a header naming the case and the
/// settings it ran under, then one line per step.
fn render(name: &str, case: &Case, r: &Replay) -> String {
    let cfg = LadderConfig::default();
    let mut text = serde_json::to_string(&json!({
        "format": FORMAT,
        "case": name,
        "about": case.about,
        "detect_only": case.detect_only,
        "posture": {
            // Lab PR 249: the replay's machine's own (they were process-wide).
            "ransomware_combat_without_corroboration":
                r.posture.ransomware_combat_without_corroboration(),
            "kernel_mass_write": r.posture.kernel_mass_write(),
            "corroboration_window_secs": super::corroboration::CORROBORATION_WINDOW.as_secs(),
            "combat_quiet_window_secs": transitions::COMBAT_QUIET_WINDOW.as_secs(),
            "alerted_decay_secs": transitions::ALERTED_DECAY.as_secs(),
            "engaged_decay_secs": transitions::ENGAGED_DECAY.as_secs(),
        },
        "ladder": {
            "investigate_window_secs": cfg.investigate_window.as_secs(),
            "failed_block_window_secs": cfg.failed_block_window.as_secs(),
            "max_offenders": cfg.max_offenders,
            "isolate_attempts": cfg.isolate_attempts,
            "isolate_retry_after_secs": cfg.isolate_retry_after.as_secs(),
            "runner": "inline",
        },
        "heartbeats_secs": {
            "installer_window": INSTALLER_TICK.as_secs(),
            "ladder": LADDER_TICK.as_secs(),
            "posture_decay": DECAY_TICK.as_secs(),
        },
    }))
    .unwrap();
    text.push('\n');
    for l in &r.lines {
        text.push_str(&serde_json::to_string(l).unwrap());
        text.push('\n');
    }
    text.replace(r.proc_dir.path().to_str().unwrap(), "@PROC@")
        .replace(r.root.path().to_str().unwrap(), ROOT_TOKEN)
}

/// A case's text, read with `root` in place of [`ROOT_TOKEN`].
fn parse(name: &str, text: &str, root: &Path) -> Case {
    let root = root.to_str().unwrap();
    assert!(
        !root.contains(['"', '\\']) && !root.chars().any(char::is_control),
        "the temporary directory {root:?} cannot stand in for {ROOT_TOKEN}"
    );
    let text = text.replace(ROOT_TOKEN, root);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("case {name}: {e}"))
}

/// The case files, by name (`cases/<name>.json`, sorted), as text.
fn cases() -> Vec<(String, String)> {
    let dir = Path::new(POSTURE_DIR).join("cases");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_str().unwrap().to_string();
            (name, std::fs::read_to_string(&p).unwrap())
        })
        .collect()
}

/// One fresh replay of a case: the case as read for it, and the replay.
fn replay(name: &str, text: &str) -> (Case, Replay) {
    let root = tempfile::TempDir::new().unwrap();
    let case = parse(name, text, root.path());
    let mut r = Replay::new(&case, root);
    r.run(&case);
    (case, r)
}

/// One fresh replay of a case, as golden text.
fn golden_text(name: &str, text: &str) -> String {
    let (case, r) = replay(name, text);
    render(name, &case, &r)
}

fn expected_path(name: &str) -> PathBuf {
    Path::new(POSTURE_DIR)
        .join("expected")
        .join(format!("{name}.jsonl"))
}

fn updating() -> bool {
    let on = std::env::var(UPDATE_ENV).is_ok_and(|v| v == "1");
    if on && std::env::var_os("CI").is_some() {
        panic!(
            "{UPDATE_ENV}=1 with CI set: the golden files are written by a maintainer \
             (`cargo xtask golden --update`) and reviewed, never by CI"
        );
    }
    on
}

/// Every committed case gives its committed golden file, byte for byte;
/// every golden file has its case. `cargo xtask golden --update` rewrites
/// them.
#[test]
fn posture_golden_matches_the_committed_files() {
    let update = updating();
    let cases = cases();
    assert!(
        !cases.is_empty(),
        "no posture golden case in {POSTURE_DIR}/cases"
    );
    let mut stale = Vec::new();
    for (name, source) in &cases {
        let text = golden_text(name, source);
        let path = expected_path(name);
        if update {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                std::fs::write(&path, &text).unwrap();
                eprintln!("golden: wrote {}", path.display());
            }
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(committed) if committed == text => {}
            Ok(committed) => {
                let first = committed
                    .lines()
                    .zip(text.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| committed.lines().count().min(text.lines().count()));
                stale.push(format!(
                    "{name}: line {} differs\n  committed: {}\n  replayed:  {}",
                    first + 1,
                    committed.lines().nth(first).unwrap_or("(none)"),
                    text.lines().nth(first).unwrap_or("(none)")
                ));
            }
            Err(_) => stale.push(format!("{name}: no golden file {}", path.display())),
        }
    }
    let names: BTreeSet<&str> = cases.iter().map(|(n, _)| n.as_str()).collect();
    for e in std::fs::read_dir(Path::new(POSTURE_DIR).join("expected")).unwrap() {
        let p = e.unwrap().path();
        let stem = p.file_stem().unwrap().to_str().unwrap().to_string();
        if !names.contains(stem.as_str()) {
            if update {
                std::fs::remove_file(&p).unwrap();
                eprintln!("golden: removed {} (no case)", p.display());
            } else {
                stale.push(format!("{}: a golden file without a case", p.display()));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "the posture golden replay differs from the committed files — a change of the posture \
         or the ladder; if it is intended, `cargo xtask golden --update` and review the diff \
         (docs/validation/GOLDEN_REPLAY.md):\n{}",
        stale.join("\n")
    );
}

/// The same input gives the same bytes: every case replayed again on this
/// thread, and on several threads at once, each replay on its own host.
#[test]
fn posture_golden_is_deterministic_across_runs_and_threads() {
    let cases = Arc::new(cases());
    let first: Vec<String> = cases.iter().map(|(n, c)| golden_text(n, c)).collect();
    for _ in 1..RUNS {
        let again: Vec<String> = cases.iter().map(|(n, c)| golden_text(n, c)).collect();
        assert_eq!(again, first, "a second replay on one thread differs");
    }
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let cases = Arc::clone(&cases);
            std::thread::spawn(move || {
                cases
                    .iter()
                    .map(|(n, c)| golden_text(n, c))
                    .collect::<Vec<String>>()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(
            h.join().unwrap(),
            first,
            "a replay on another thread differs"
        );
    }
}

/// A replay leaves nothing behind: its directories (its `/proc` among
/// them) go with it, so nothing keeps the host alive past the replay.
#[test]
fn a_replay_leaves_no_directory_behind() {
    for (name, text) in cases() {
        let (case, r) = replay(&name, &text);
        let dirs = [r.root.path().to_path_buf(), r.proc_dir.path().to_path_buf()];
        let host = Arc::downgrade(&r.host);
        drop((case, r));
        assert!(
            host.upgrade().is_none(),
            "case {name}: the host outlives its replay"
        );
        for d in dirs {
            assert!(!d.exists(), "case {name}: {} left behind", d.display());
        }
    }
}

/// The levels the posture moved to, the stages the ladder reached and the
/// ops of the signed rows, from a replay's lines.
fn shown(r: &Replay) -> (Vec<String>, BTreeSet<String>, BTreeSet<String>) {
    let mut path = Vec::new();
    let mut stages = BTreeSet::new();
    let mut ops = BTreeSet::new();
    for l in &r.lines {
        for t in l["posture"].as_array().into_iter().flatten() {
            path.push(t["to"].as_str().unwrap().to_string());
        }
        if let Some(s) = l["state"]["stage"].as_str() {
            stages.insert(s.to_string());
        }
        for row in l["signed"].as_array().into_iter().flatten() {
            ops.insert(row["op"].as_str().unwrap().to_string());
        }
    }
    (path, stages, ops)
}

/// Each case moves the posture through the levels it names in `path`, in
/// order, reaches the ladder stages it names and writes the signed rows it
/// names: an update of a golden file that loses one fails even though the
/// file was rewritten.
#[test]
fn every_posture_case_shows_what_it_says() {
    for (name, text) in cases() {
        let (case, r) = replay(&name, &text);
        let (path, stages, ops) = shown(&r);
        assert_eq!(path, case.path, "case {name}: the posture's path");
        for s in &case.stages {
            assert!(
                stages.contains(s),
                "case {name}: stage {s} not reached ({stages:?})"
            );
        }
        for op in &case.signed {
            assert!(
                ops.contains(op),
                "case {name}: no signed `{op}` row ({ops:?})"
            );
        }
    }
}

/// Lab PR 245: every signed row of the ladder says why it engaged and
/// against whom — the trigger and the evidence it cites, the offenders as
/// captured, in the order of `offenders` — the INVESTIGATE row included.
/// (The replay showed `"trigger": null` in every one, and an INVESTIGATE
/// naming no offender.) Checked on the replay, so an update of the golden
/// files that loses them fails.
#[test]
fn every_ladder_row_names_its_trigger_and_offender() {
    let mut investigate_rows = 0;
    for (name, text) in cases() {
        let (_case, r) = replay(&name, &text);
        for row in r
            .lines
            .iter()
            .flat_map(|l| l["signed"].as_array().into_iter().flatten())
        {
            let op = row["op"].as_str().unwrap();
            if !op.starts_with("combat_") {
                continue;
            }
            let x = &row["extra"];
            let trigger = x["trigger"].as_str();
            assert!(trigger.is_some(), "case {name}: no trigger in {row}");
            if op != "combat_stage" {
                continue;
            }
            assert_eq!(x["cause"]["kind"], "posture_trigger", "case {name}: {row}");
            assert_eq!(
                x["cause"]["trigger"].as_str(),
                trigger,
                "case {name}: {row}"
            );
            let offenders: Vec<u64> = x["offenders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_u64().unwrap())
                .collect();
            assert!(!offenders.is_empty(), "case {name}: no offender in {row}");
            let detailed: Vec<u64> = x["offender_details"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["pid"].as_u64().unwrap())
                .collect();
            assert_eq!(detailed, offenders, "case {name}: {row}");
            if x["to"] == "INVESTIGATE" && x["from"].is_null() {
                investigate_rows += 1;
                let d = &x["offender_details"][0];
                assert_eq!(d["via"], "entry", "case {name}: {row}");
                assert!(
                    d["exe"].is_string() && d["cgroup"].is_string(),
                    "case {name}: the offender's executable and cgroup: {row}"
                );
                assert_eq!(
                    x["cause"]["event"]["pid"].as_u64(),
                    Some(offenders[0]),
                    "case {name}: the event names the offender: {row}"
                );
            }
        }
    }
    assert!(investigate_rows > 0, "no INVESTIGATE row in the cases");
}

/// The cases cover what the lot set out to replay before R08 moves the
/// posture and the ladder: ransomware corroborated to COMBAT and alone held
/// at ENGAGED, a security tool switched off raising ENGAGED and the
/// agent's own unit stopped inside a signed trusted-installer window not
/// moving the posture, a forking tree frozen and killed with the outcomes
/// of a process gone and of a stale capture, the signed unlock leaving
/// COMBAT, detect-only acting on nothing, decay down to OBSERVING. Lab PR
/// 249: and ransomware alone to COMBAT — decisive, nothing in its scope
/// before — only on a machine whose per-rule policy says
/// `combat-without-corroboration`.
#[test]
fn posture_golden_cases_cover_the_lot() {
    let mut ransomware_alone_combat = 0;
    let mut combat_by: BTreeSet<String> = BTreeSet::new();
    let mut engaged_by: BTreeSet<String> = BTreeSet::new();
    let mut kills_in_cgroup = 0;
    let mut gone = 0;
    let mut stale = 0;
    let mut window_sanctioned_quiet = 0;
    let mut unlocked = 0;
    let mut decayed_to_observing = 0;
    let mut detect_only_kills = 0;
    let mut detect_only_neutralize = 0;
    for (name, text) in cases() {
        let (case, r) = replay(&name, &text);
        for l in &r.lines {
            let transitions: Vec<&Value> = l["posture"].as_array().into_iter().flatten().collect();
            for t in &transitions {
                let trig = t["trigger"].as_str().unwrap_or("");
                let alone = t["evidence"]["in_scope_before"]
                    .as_array()
                    .is_some_and(Vec::is_empty);
                let decisive = t["evidence"]["triggers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|x| x["trigger"] == trig && x["confidence"] == "Decisive");
                if t["to"] == "COMBAT" && trig == "RansomwareEncryption" && alone {
                    assert!(
                        decisive && r.posture.ransomware_combat_without_corroboration(),
                        "case {name}: ransomware alone reached COMBAT without \
                         `combat-without-corroboration`: {t}"
                    );
                    assert!(!case.rule_policy.is_empty(), "case {name}");
                    ransomware_alone_combat += 1;
                }
                match t["to"].as_str() {
                    Some("COMBAT") => {
                        combat_by.insert(trig.to_string());
                    }
                    Some("ENGAGED") => {
                        engaged_by.insert(trig.to_string());
                    }
                    Some("OBSERVING") => decayed_to_observing += 1,
                    _ => {}
                }
            }
            for a in l["acts"].as_array().into_iter().flatten() {
                if a["host"] == "kill tree" && a.get("cgroup").is_some() {
                    kills_in_cgroup += 1;
                    if case.detect_only {
                        detect_only_kills += 1;
                    }
                }
                if a["host"] == "kill tree" {
                    match a["found"].as_str() {
                        Some(f) if f.starts_with("the captured process has exited") => gone += 1,
                        Some(f) if f.starts_with("the pid names another process") => stale += 1,
                        _ => {}
                    }
                }
                if a["ladder"] == "neutralize" && case.detect_only {
                    detect_only_neutralize += 1;
                }
            }
            let sanctioned = l["assessed"]["defense"]["sanctioned"]
                .as_str()
                .is_some_and(|s| s.contains("trusted-installer window"));
            if sanctioned && transitions.is_empty() {
                window_sanctioned_quiet += 1;
            }
            if l["unlock"]["outcome"]["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("COMBAT released"))
            {
                unlocked += 1;
            }
        }
    }
    assert!(
        combat_by.contains("RansomwareEncryption"),
        "no case corroborates ransomware to COMBAT: {combat_by:?}"
    );
    assert!(
        engaged_by.contains("RansomwareEncryption"),
        "no case holds lone ransomware at ENGAGED: {engaged_by:?}"
    );
    assert!(
        engaged_by.contains("DefenseImpairment"),
        "no case raises ENGAGED on a security tool switched off: {engaged_by:?}"
    );
    assert!(
        window_sanctioned_quiet > 0,
        "no own-unit stop sanctioned by the window"
    );
    assert!(kills_in_cgroup > 0, "no tree killed through its cgroup");
    assert!(gone > 0, "no offender gone before NEUTRALIZE");
    assert!(stale > 0, "no stale capture (pid held by another process)");
    assert!(unlocked > 0, "no signed unlock leaving COMBAT");
    assert!(decayed_to_observing > 0, "no decay down to OBSERVING");
    assert!(detect_only_neutralize > 0, "no detect-only NEUTRALIZE");
    assert_eq!(detect_only_kills, 0, "detect-only killed something");
    assert!(
        ransomware_alone_combat > 0,
        "no case takes ransomware alone to COMBAT under `combat-without-corroboration`"
    );
}

/// Lab PR 249: a case's per-rule policy is its machine's own. The case
/// under `combat-without-corroboration` (ransomware alone: COMBAT) and the
/// one without it (the same encryption: ENGAGED), replayed at once on
/// threads of their own, each give their committed golden file. The
/// directive was a process-wide switch: a case setting it would have moved
/// every case replayed beside it.
#[test]
fn a_case_s_rule_policy_is_its_machine_s_own() {
    const PAIRS: usize = 3;
    let cases = cases();
    let pick = |n: &str| {
        cases
            .iter()
            .find(|(c, _)| c == n)
            .cloned()
            .unwrap_or_else(|| panic!("no case {n}"))
    };
    let pair = [
        pick("ransomware-alone-combat-policy"),
        pick("ransomware-alone-engaged"),
    ];
    // Each alone on this thread first; then all at once.
    let alone: Vec<String> = pair.iter().map(|(n, t)| golden_text(n, t)).collect();
    let barrier = Arc::new(std::sync::Barrier::new(2 * PAIRS));
    let handles: Vec<_> = (0..2 * PAIRS)
        .map(|i| {
            let (name, text) = pair[i % 2].clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                (i % 2, golden_text(&name, &text))
            })
        })
        .collect();
    for h in handles {
        let (k, replayed) = h.join().unwrap();
        assert!(
            replayed == alone[k],
            "case {}: a replay beside the other case's differs from one alone",
            pair[k].0
        );
    }
    if !updating() {
        for ((name, _), text) in pair.iter().zip(&alone) {
            let committed = std::fs::read_to_string(expected_path(name)).unwrap();
            assert!(*text == committed, "case {name}: not its golden file");
        }
    }
}
