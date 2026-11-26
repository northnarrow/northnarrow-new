//! Lot 317 (third bug hunt, BUG-118): the agent stops in the middle of a
//! burst of execs the exec quarantine holds, and leaves no process
//! stopped.
//!
//! The kernel stops a candidate exec with `SIGSTOP` and notes it in the
//! pinned `EXECQ_STOPPED` map; the agent's stop resumed only the processes
//! it had an entry for — the reports it had read from the ring. A process
//! stopped after the ring's last drain, before the heartbeat was cleared,
//! stayed in state T until the next start of an agent with the guard on
//! (with the guard off: until a `kill -CONT` by hand). The stop now clears
//! the heartbeat, waits until every program run that read it has ended
//! (`membarrier`, `synchronize_rcu`), and resumes everything the map holds.
//!
//! The test starts this build's agent with the exec quarantine in enforce
//! mode and a scanner that never says ready (the default policy decides at
//! the end of an 8 s budget: every exec stays held until then), runs a
//! burst of new binaries from four threads, stops the agent the operator's
//! way (a signed 2-of-N `nn-admin shutdown`) while the burst goes on, and
//! checks that every process of the burst ran to its end (`true`, exit 0),
//! that no process on the host is left in state T that was not before, and
//! that the test's cgroup is not frozen. The signed `stopping` entry of the
//! agent's audit chain must name resumed processes: the stop did happen
//! with execs held. Lot M4 (#633): a case kills the agent instead (SIGKILL,
//! as the OOM killer does) and starts it again: the next start resumes what
//! the killed one held, signed (`recovered_at_boot`).
//!
//! Needs root, this build's eBPF object and `bpf` in the kernel's LSM list
//! (the exec quarantine's stop is on LSM): `sudo -E cargo test -p
//! northnarrow-agent --features test-privileged,debug-trigger --test
//! execq_stop_privileged_e2e -- --ignored` (lab: `nn-lab.sh test-ignored`).
#![cfg(feature = "test-privileged")]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::{InstalledBin, install_bin_at, install_to_priv_bin};

/// The guard's budget: a held exec waits this long for a verdict that never
/// comes, then the default policy resumes it.
const BUDGET_MS: &str = "8000";
/// Spawner threads, and the pause between two execs of one.
const SPAWNERS: usize = 4;
const SPAWN_EVERY: Duration = Duration::from_millis(5);
/// How long the burst runs before the stop is asked, and after the agent
/// has exited.
const BURST_BEFORE_STOP: Duration = Duration::from_millis(1500);
const BURST_AFTER_STOP: Duration = Duration::from_millis(300);
/// Distinct binaries the burst runs (a held exec is not judged before the
/// budget ends, so a binary run again is held again).
const BINARIES: usize = 16;

/// The state of process `pid` (`/proc/<pid>/stat`'s third field), read by
/// lot 311's reader (`nn_linux::state_read`): a process names itself, and a
/// `comm` that is not UTF-8 must not hide one from the check.
fn proc_state(pid: u32) -> Option<u8> {
    let stat = nn_linux::state_read::read_state(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?.1.trim_start().bytes().next()
}

/// Every process of the host in state T (stopped), with what it runs.
fn stopped_processes() -> BTreeSet<(u32, String)> {
    let mut out = BTreeSet::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if proc_state(pid) == Some(b'T') {
            let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            out.insert((pid, exe));
        }
    }
    out
}

/// The test's own cgroup (v2) says it is frozen.
fn own_cgroup_frozen() -> Option<bool> {
    let line = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = line.lines().find_map(|l| l.strip_prefix("0::"))?;
    let events = std::fs::read_to_string(format!("/sys/fs/cgroup{rel}/cgroup.events")).ok()?;
    Some(events.lines().any(|l| l.trim() == "frozen 1"))
}

/// A directory of the test's under `/var/lib`, writable by every user — the
/// guard's world-writable class, which no exec rule kills (R001 and R009
/// kill a root exec from /tmp, /var/tmp or /home). Removed on drop.
struct BurstDir(PathBuf);

impl Drop for BurstDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `n` copies of `/usr/bin/true`, each with bytes of its own appended (a
/// content the guard has never seen), each named `true` in a directory of
/// its own (a multi-call coreutils picks its utility from the name),
/// writable by every user: the kernel classes a file by the directory it
/// is in.
fn burst_binaries(dir: &Path, n: usize) -> Vec<PathBuf> {
    let base = std::fs::read("/usr/bin/true").expect("read /usr/bin/true");
    let mut out = Vec::new();
    for i in 0..n {
        let d = dir.join(format!("b{i:02}"));
        std::fs::create_dir(&d).unwrap();
        // the guard's class is the file's own directory's
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let exe = d.join("true");
        let mut body = base.clone();
        body.extend_from_slice(format!("\nnn-execq-stop {} {i}\n", std::process::id()).as_bytes());
        std::fs::write(&exe, &body).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let st = Command::new(&exe).status().expect("run a copy of true");
        assert!(
            st.success(),
            "the copy {} does not run as true: {st}",
            exe.display()
        );
        out.push(exe);
    }
    out
}

/// An admin key with `roles`, its public half appended to `admin_pub`.
fn admin_key(nn_admin: &Path, dir: &Path, admin_pub: &Path, label: &str, roles: &str) -> PathBuf {
    let key = dir.join(format!("{label}.priv"));
    let tmp_pub = dir.join(format!("{label}.pub.tmp"));
    let status = Command::new(nn_admin)
        .arg("init")
        .arg("--priv-out")
        .arg(&key)
        .arg("--pub-append")
        .arg(&tmp_pub)
        .stdout(Stdio::null())
        .status()
        .expect("spawn nn-admin init");
    assert!(status.success(), "nn-admin init failed for {label}");
    let body = std::fs::read_to_string(&tmp_pub).unwrap();
    let hex = body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .expect("a public key line");
    assert_eq!(hex.len(), 64, "{hex:?}");
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(admin_pub)
        .unwrap();
    writeln!(f, "{hex} {roles}").unwrap();
    let _ = std::fs::remove_file(&tmp_pub);
    key
}

/// The objects of the audit chain with `"kind": kind`, wherever they sit
/// in a row.
fn audit_objects(audit_log: &Path, kind: &str) -> Vec<serde_json::Value> {
    fn walk(v: &serde_json::Value, kind: &str, out: &mut Vec<serde_json::Value>) {
        match v {
            serde_json::Value::Object(m) => {
                if m.get("kind").and_then(|k| k.as_str()) == Some(kind) {
                    out.push(v.clone());
                }
                m.values().for_each(|x| walk(x, kind, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, kind, out)),
            serde_json::Value::String(s) if s.starts_with('{') => {
                if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
                    walk(&inner, kind, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for row in common::read_jsonl_strict(audit_log) {
        walk(&row, kind, &mut out);
    }
    out
}

/// The agent, stopped on drop the fixtures' way if the test did not stop
/// it (a failure on the way).
struct Agent(Option<Child>);

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

/// The burst's children, killed and reaped on drop (a process left
/// stopped by a failing run is resumed and killed: the guest stays clean).
struct Burst(Arc<Mutex<Vec<Child>>>);

impl Drop for Burst {
    fn drop(&mut self) {
        for c in self.0.lock().unwrap().iter_mut() {
            if let Ok(None) = c.try_wait() {
                // SAFETY: plain kill(2) on our own child, not reaped yet.
                unsafe { libc::kill(c.id() as i32, libc::SIGCONT) };
                let _ = c.kill();
            }
            let _ = c.wait();
        }
    }
}

#[test]
#[ignore = "requires root, this build's eBPF object and bpf in the LSM list; lab: nn-lab.sh test-ignored"]
fn a_stop_in_the_middle_of_an_exec_burst_leaves_no_process_stopped() {
    burst_and_stop("plain", &[], StopBy::Signed);
}

/// Lot 317 (the review of #541, F6): the window of BUG-118 held open — a
/// `debug-trigger` build's agent stops reading the ring 300 ms before the
/// stop is asked (`NN_DEBUG_EXECQ_PAUSE_READS`, the heartbeat beating on),
/// so that the kernel stops processes whose report the agent never reads
/// before it stops. The stop resumes them all (the signed `unreported`),
/// from the ring's last read.
#[cfg(feature = "debug-trigger")]
#[test]
#[ignore = "requires root, this build's eBPF object and bpf in the LSM list; lab: nn-lab.sh test-ignored"]
fn a_stop_with_reports_left_unread_resumes_them() {
    let unreported = burst_and_stop(
        "unread",
        &[("NN_DEBUG_EXECQ_PAUSE_READS", PAUSE)],
        StopBy::Signed,
    )
    .count;
    assert!(
        unreported > 0,
        "no process held without an entry: the window was not held open"
    );
}

/// Lot 317 (review F6): the same, the stop's last read of the ring skipped
/// — the pinned map alone names the processes the agent never read about,
/// and the stop resumes them from it.
#[cfg(feature = "debug-trigger")]
#[test]
#[ignore = "requires root, this build's eBPF object and bpf in the LSM list; lab: nn-lab.sh test-ignored"]
fn the_map_alone_names_what_the_stop_resumes() {
    let unreported = burst_and_stop(
        "map",
        &[
            ("NN_DEBUG_EXECQ_PAUSE_READS", PAUSE),
            ("NN_DEBUG_EXECQ_STOP_NO_LAST_READ", "1"),
        ],
        StopBy::Signed,
    )
    .count;
    assert!(
        unreported > 0,
        "no process held without an entry: the window was not held open"
    );
}

/// Lot M4 (#633): the agent stops while its controller is in a pass that
/// does not end — on AlmaLinux 9 each report asked `rpm -qf`, a ring's
/// worth took seconds, the stop's deadline ended the agent before the
/// controller's own stop and about a thousand held processes stayed in
/// state T. A `debug-trigger` build's agent blocks in the handling of a
/// report while `NN_DEBUG_EXECQ_STALL`'s file exists (created 300 ms before
/// the stop is asked, never removed): the controller never gets to its own
/// stop, and the stop's sweep releases every process the kernel holds (the
/// signed `stopping` entry `"by": "sweep: …"`).
#[cfg(feature = "debug-trigger")]
#[test]
#[ignore = "requires root, this build's eBPF object and bpf in the LSM list; lab: nn-lab.sh test-ignored"]
fn a_stop_while_the_controller_is_stuck_releases_every_held_process() {
    let ended = burst_and_stop("stuck", &[("NN_DEBUG_EXECQ_STALL", STALL)], StopBy::Signed);
    assert!(
        ended.count > 0,
        "the stop's sweep resumed nothing: the controller was not stuck at the stop"
    );
    // the review of #635 (P3-2): the controller's own stop also names
    // processes without an entry — the case tests the sweep only when the
    // stall held the controller past the stop's wait, and the sweep signed
    assert!(
        ended.overran,
        "the controller's stop did not overrun its wait: the stall did not take effect"
    );
    assert!(
        ended
            .by
            .iter()
            .any(|b| b.starts_with("sweep: the controller did not stop")),
        "no `stopping` entry signed by the sweep of a controller that did not stop: {:?}",
        ended.by
    );
}

/// Lot M4 (#633): the agent killed in the middle of the burst, as the OOM
/// killer kills it (SIGKILL: no stop of its own, no sweep). The processes
/// it held stay stopped in the pinned map; the next start of the agent
/// resumes every one of them before its first heartbeat, signed
/// (`recovered_at_boot`), and nothing is left in state T.
#[test]
#[ignore = "requires root, this build's eBPF object and bpf in the LSM list; lab: nn-lab.sh test-ignored"]
fn the_next_start_releases_what_a_killed_agent_held() {
    let recovered = burst_and_stop("killed", &[], StopBy::KillThenRestart).count;
    assert!(
        recovered > 0,
        "the next start's signed `recovered_at_boot` resumed nothing: the killed agent left \
         nothing held"
    );
}

/// How a case's agent stops.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopBy {
    /// The operator's signed `nn-admin shutdown`.
    Signed,
    /// Lot M4: SIGKILL ([`kill_agent`]), then the next start of the agent,
    /// stopped the operator's way.
    KillThenRestart,
}

/// Longer than the kernel's heartbeat bound (1.5 s): past it, the kernel
/// of a killed agent holds nothing more.
const HEARTBEAT_STALE: Duration = Duration::from_secs(2);

/// Lot M4: the agent killed as the OOM killer kills it — SIGKILL, no stop
/// of its own. Its tree is evicted from `PROTECTED_PIDS` first (the
/// task_kill hook refuses the signal otherwise), every process below sudo
/// is killed (the scanner with the agent), then sudo is reaped.
fn kill_agent(c: &mut Child) -> Result<(), String> {
    let tree = common::process_tree(c.id());
    common::unprotect_pids(&tree)?;
    for &p in tree.iter().skip(1) {
        // SAFETY: plain kill(2); a process that has gone answers ESRCH.
        unsafe { libc::kill(p as i32, libc::SIGKILL) };
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match c.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                return Err(format!(
                    "sudo pid {} did not exit after its agent's kill (tree {tree:?})",
                    c.id()
                ));
            }
            Err(e) => return Err(format!("waiting for sudo pid {}: {e}", c.id())),
        }
    }
}

/// The production pin root, wiped before each case of this file starts:
/// the cases start their agents in one run, and an agent refuses a start
/// whose protected directories differ from those its predecessor's pins
/// recorded (lab: the first run on a fresh guest). As the canary and FIM
/// suites do. Lot M4: the kill case's second start is not wiped for — it
/// starts on its killed predecessor's pins, the held map among them.
const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

fn wipe_pin_tree() {
    let pin = Path::new(BPFFS_PIN_ROOT);
    if let Ok(entries) = std::fs::read_dir(pin) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = std::fs::remove_dir(pin);
}

/// The placeholder of `NN_DEBUG_EXECQ_PAUSE_READS`'s value: the test's
/// pause file, created 300 ms before the stop is asked.
const PAUSE: &str = "@pause@";
/// Lot M4: the placeholder of `NN_DEBUG_EXECQ_STALL`'s value: the test's
/// stall file, created 300 ms before the stop is asked.
const STALL: &str = "@stall@";

/// What a case's stop did.
struct Ended {
    /// How many processes the stop resumed without an entry
    /// (`unreported`) — after a kill, how many the next start resumed
    /// (`recovered_at_boot`).
    count: usize,
    /// The controller's stop overran the wait the agent's stop gives it.
    overran: bool,
    /// Who signed each `stopping` entry (its `by`).
    by: Vec<String>,
}

/// A burst, a stop in its middle (`by`), the checks; `env`: the agent's
/// extra variables (`PAUSE`: the pause file).
fn burst_and_stop(case: &str, env: &[(&str, &str)], by: StopBy) -> Ended {
    common::require_root("run the exec quarantine's stop e2e");
    common::require_disposable_host("run the exec quarantine's stop e2e");
    common::refuse_if_northnarrow_running("run the exec quarantine's stop e2e");
    common::require_bpftool();
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    assert!(
        lsm.split(',').any(|m| m.trim() == "bpf"),
        "bpf is not in the kernel's LSM list ({lsm:?}): the exec quarantine needs it"
    );

    wipe_pin_tree();
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let installed_agent = InstalledAgent::install();
    let nn_admin = install_to_priv_bin(Path::new(env!("CARGO_BIN_EXE_nn-admin")));
    // the scanner: started as `nobody`, it never says ready (the
    // supervisor kills it after 5 s and starts it again): the held execs
    // wait for the budget
    let stub = dir.join("nn-execq-scan-stub");
    std::fs::write(&stub, "#!/bin/sh\nexec /bin/sleep 3600\n").unwrap();
    let scanner: InstalledBin = install_bin_at(
        &stub,
        &PathBuf::from(format!(
            "{}/nn-execq-scan-e2etest-{}",
            common::PRIV_BIN_DIR,
            std::process::id()
        )),
    );
    let state = AgentState::new(dir);
    let admin_pub = state.admin_pub();
    std::fs::write(&admin_pub, "").unwrap();
    let key_a = admin_key(&nn_admin.path, dir, &admin_pub, "admin_a", "shutdown");
    let key_b = admin_key(&nn_admin.path, dir, &admin_pub, "admin_b", "shutdown");
    let rules = dir.join("combat-rules.v4");
    std::fs::copy(
        PathBuf::from(env!("NN_REPO_ROOT")).join("configs/combat-rules.v4"),
        &rules,
    )
    .unwrap();
    let burst_dir = BurstDir(
        tempfile::Builder::new()
            .prefix("nn-e2etest-execq-")
            .tempdir_in("/var/lib")
            .expect("a directory under /var/lib")
            .keep(),
    );
    std::fs::set_permissions(&burst_dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    let binaries = burst_binaries(&burst_dir.0, BINARIES);

    let stopped_before = stopped_processes();
    let log = dir.join("agent.log");
    let pause = dir.join("nn-execq-pause-reads");
    let pause_s = pause.display().to_string();
    let stall = dir.join("nn-execq-stall");
    let stall_s = stall.display().to_string();
    let mut agent_env = vec![("NO_COLOR", "1")];
    for (k, v) in env {
        let v = match *v {
            PAUSE => pause_s.as_str(),
            STALL => stall_s.as_str(),
            v => v,
        };
        agent_env.push((k, v));
    }
    let pausing = env.iter().any(|(_, v)| *v == PAUSE);
    let stalling = env.iter().any(|(_, v)| *v == STALL);
    // the agent's start (lot M4: again after a kill, its log appended to)
    let spawn_agent = || {
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        let err = out.try_clone().unwrap();
        installed_agent
            .command(&state, Launch::Sudo, &agent_env)
            .arg("--combat-rules")
            .arg(&rules)
            .args(["--exec-quarantine", "enforce"])
            .args(["--exec-quarantine-budget-ms", BUDGET_MS])
            .arg("--exec-quarantine-scanner")
            .arg(&scanner.path)
            .args(["--exec-quarantine-scan-user", "nobody"])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn the agent")
    };
    let mut agent = Agent(Some(spawn_agent()));
    let tail = || {
        let text = common::strip_ansi(&std::fs::read_to_string(&log).unwrap_or_default());
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    };
    // the `n`th start of the agent has started its exec quarantine (lot
    // M4: after a kill, the socket answers again — its file outlived the
    // killed agent)
    let started = |n: usize| {
        common::wait_until(Duration::from_secs(30), || {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            (state.admin_socket().exists()
                && state.pid_file().exists()
                && text
                    .matches("exec quarantine: starting its controller and scanner")
                    .count()
                    >= n
                && (n == 1
                    || std::os::unix::net::UnixStream::connect(state.admin_socket()).is_ok()))
            .then_some(())
        })
    };
    assert!(
        started(1).is_some(),
        "the agent did not start its exec quarantine\n{}",
        tail()
    );

    // the burst, from four threads, until told to stop
    let children = Arc::new(Mutex::new(Vec::<Child>::new()));
    let burst = Burst(Arc::clone(&children));
    let halt = Arc::new(AtomicBool::new(false));
    let spawners: Vec<_> = (0..SPAWNERS)
        .map(|t| {
            let (children, halt, binaries) =
                (Arc::clone(&children), Arc::clone(&halt), binaries.clone());
            std::thread::spawn(move || {
                let mut i = t;
                while !halt.load(Ordering::Relaxed) {
                    let exe = &binaries[i % binaries.len()];
                    match Command::new(exe).stdin(Stdio::null()).spawn() {
                        Ok(c) => children.lock().unwrap().push(c),
                        Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {}
                        Err(e) => panic!("spawn {}: {e}", exe.display()),
                    }
                    i += SPAWNERS;
                    std::thread::sleep(SPAWN_EVERY);
                }
            })
        })
        .collect();
    std::thread::sleep(BURST_BEFORE_STOP);
    let held_at_stop = children
        .lock()
        .unwrap()
        .iter()
        .filter(|c| proc_state(c.id()) == Some(b'T'))
        .count();

    // the window held open: the agent stops reading the ring, 300 ms
    // before the stop is asked (the kernel goes on stopping)
    if pausing {
        std::fs::write(&pause, b"").unwrap();
    }
    // lot M4: the controller stuck in its pass from here (never undone)
    if stalling {
        std::fs::write(&stall, b"").unwrap();
    }
    if pausing || stalling {
        std::thread::sleep(Duration::from_millis(300));
    }
    // the operator's stop
    let stop_signed = |agent: &mut Agent| {
        let mut c = agent.0.take().unwrap();
        let stopped = common::shutdown_signed(
            &mut c,
            &common::SignedShutdown {
                nn_admin: &nn_admin.path,
                key: &key_a,
                cosign_key: &key_b,
                agent_id_file: &state.agent_id_file(),
                socket: &state.admin_socket(),
            },
            Duration::from_secs(30),
        );
        if let Err(e) = stopped {
            agent.0 = Some(c);
            panic!(
                "the signed shutdown did not stop the agent: {e}\n{}",
                tail()
            );
        }
    };
    // the stop, the burst going on
    match by {
        StopBy::Signed => stop_signed(&mut agent),
        StopBy::KillThenRestart => {
            let mut c = agent.0.take().unwrap();
            if let Err(e) = kill_agent(&mut c) {
                agent.0 = Some(c);
                panic!("the agent could not be killed: {e}\n{}", tail());
            }
            std::thread::sleep(HEARTBEAT_STALE);
        }
    }
    std::thread::sleep(BURST_AFTER_STOP);
    halt.store(true, Ordering::Relaxed);
    for s in spawners {
        s.join().expect("a spawner thread");
    }
    // lot M4: the killed agent's held processes stay stopped; the next start
    // resumes them, then is stopped the operator's way
    let mut left_by_kill = 0;
    if by == StopBy::KillThenRestart {
        left_by_kill = children
            .lock()
            .unwrap()
            .iter()
            .filter(|c| proc_state(c.id()) == Some(b'T'))
            .count();
        assert!(
            left_by_kill > 0,
            "the killed agent left no process of the burst stopped: the case tests nothing\n{}",
            tail()
        );
        agent.0 = Some(spawn_agent());
        assert!(
            started(2).is_some(),
            "the agent did not start again after its kill\n{}",
            tail()
        );
        stop_signed(&mut agent);
    }

    // every process of the burst runs to its end
    let mut left = Vec::new();
    let mut failed = Vec::new();
    let total;
    {
        let mut kids = children.lock().unwrap();
        total = kids.len();
        let deadline = Instant::now() + Duration::from_secs(15);
        for k in kids.iter_mut() {
            let pid = k.id();
            loop {
                match k.try_wait() {
                    Ok(Some(st)) => {
                        if !st.success() {
                            failed.push(format!("{pid}: {st}"));
                        }
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    _ => {
                        left.push(format!("{pid} state {:?}", proc_state(pid).map(char::from)));
                        break;
                    }
                }
            }
        }
    }
    let new_stopped: Vec<_> = stopped_processes()
        .difference(&stopped_before)
        .cloned()
        .collect();
    let frozen = own_cgroup_frozen();
    drop(burst);

    let stopping = audit_objects(&state.audit_log(), "stopping");
    let count = |field: &str| -> usize {
        stopping
            .iter()
            .filter_map(|s| s.get(field).and_then(|r| r.as_array()).map(Vec::len))
            .sum()
    };
    let (resumed, unreported, left_in_map) = (count("resumed"), count("unreported"), count("left"));
    let recaptured = count("recaptured");
    // lot M4: what the start after a kill resumed (and could not capture)
    let recovery = audit_objects(&state.audit_log(), "recovered_at_boot");
    let in_recovery = |field: &str| -> usize {
        recovery
            .iter()
            .filter_map(|s| s.get(field).and_then(|r| r.as_array()).map(Vec::len))
            .sum()
    };
    let (recovered, deferred) = (in_recovery("resumed"), in_recovery("deferred"));
    // lot M4: the controller's stop cut by the wait the agent's stop gives
    // it (the stop's sweep then releases what the kernel holds)
    let overran = common::strip_ansi(&std::fs::read_to_string(&log).unwrap_or_default())
        .contains("exec quarantine controller did not stop in time");
    // a process left stopped: what the agent's log says of its pid
    let named: Vec<String> = {
        let text = common::strip_ansi(&std::fs::read_to_string(&log).unwrap_or_default());
        left.iter()
            .filter_map(|l| l.split_whitespace().next())
            .flat_map(|pid| {
                let needle = format!("pid={pid}");
                text.lines()
                    .filter(|l| {
                        l.split(|c: char| c.is_whitespace() || c == ',')
                            .any(|w| w == needle)
                    })
                    .map(|l| l.chars().take(300).collect::<String>())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    // past the harness's capture (a passing test's `eprintln!` is not
    // shown): the lab reads this line
    {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "execq stop e2e [{case}]: {total} execs, {held_at_stop} held 1.5 s into the burst; the signed \
             stopping entries: {} — resumed {resumed}, of which {unreported} without an entry \
             and {recaptured} captured again, {left_in_map} left in the map; {left_by_kill} left \
             stopped by a kill, of which the next start resumed {recovered} ({deferred} deferred); \
             after the stop {} of \
             the burst still running, {} not exit 0, {} new process(es) in state T, cgroup frozen \
             {frozen:?}; the controller's stop overran its wait: {overran}; the agent's log on them: \
             {named:?}",
            stopping.len(),
            left.len(),
            failed.len(),
            new_stopped.len()
        );
    }
    assert!(
        held_at_stop > 0,
        "no exec of the burst was held: the guard did not hold (the test proves nothing)\n{}",
        tail()
    );
    assert!(
        left.is_empty(),
        "{} of {total} processes of the burst did not end after the stop (T = stopped): {left:?}",
        left.len()
    );
    assert!(
        new_stopped.is_empty(),
        "processes left in state T on the host after the stop: {new_stopped:?}"
    );
    assert_ne!(frozen, Some(true), "the test's cgroup is frozen");
    assert!(
        failed.is_empty(),
        "processes of the burst that did not exit 0 (killed?): {failed:?}"
    );
    match by {
        StopBy::Signed => assert!(
            resumed > 0,
            "the signed `stopping` entry names no resumed process ({stopping:?}): the stop did \
             not find the burst held\n{}",
            tail()
        ),
        // lot M4: the start after the kill resumed them, signed
        StopBy::KillThenRestart => assert!(
            recovered > 0 && deferred == 0,
            "the next start's signed `recovered_at_boot` ({recovery:?}) did not resume what the \
             killed agent held ({left_by_kill} stopped)\n{}",
            tail()
        ),
    }
    assert_eq!(left_in_map, 0, "{stopping:?}");
    drop(scanner);
    drop(nn_admin);
    drop(installed_agent);
    drop(burst_dir);
    let signers = stopping
        .iter()
        .filter_map(|s| s.get("by").and_then(|b| b.as_str()).map(str::to_string))
        .collect();
    Ended {
        count: match by {
            StopBy::Signed => unreported,
            StopBy::KillThenRestart => recovered,
        },
        overran,
        by: signers,
    }
}
