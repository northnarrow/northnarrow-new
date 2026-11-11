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
//! with execs held.
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
use common::{install_bin_at, install_to_priv_bin, InstalledBin};

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

/// The state of process `pid` (`/proc/<pid>/stat`'s third field), read as
/// bytes: a process names itself, and a `comm` that is not UTF-8 must not
/// hide one from the check.
fn proc_state(pid: u32) -> Option<u8> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    stat.get(close + 2).copied()
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
    common::require_root("run the exec quarantine's stop e2e");
    common::require_disposable_host("run the exec quarantine's stop e2e");
    common::refuse_if_northnarrow_running("run the exec quarantine's stop e2e");
    common::require_bpftool();
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    assert!(
        lsm.split(',').any(|m| m.trim() == "bpf"),
        "bpf is not in the kernel's LSM list ({lsm:?}): the exec quarantine needs it"
    );

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
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = installed_agent
        .command(&state, Launch::Sudo, &[("NO_COLOR", "1")])
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
        .expect("spawn the agent");
    let mut agent = Agent(Some(child));
    let tail = || {
        let text = common::strip_ansi(&std::fs::read_to_string(&log).unwrap_or_default());
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    };
    let ready = common::wait_until(Duration::from_secs(30), || {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        (state.admin_socket().exists()
            && state.pid_file().exists()
            && text.contains("exec quarantine: starting its controller and scanner"))
        .then_some(())
    });
    assert!(
        ready.is_some(),
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

    // the operator's stop, the burst going on
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
    std::thread::sleep(BURST_AFTER_STOP);
    halt.store(true, Ordering::Relaxed);
    for s in spawners {
        s.join().expect("a spawner thread");
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
    // past the harness's capture (a passing test's `eprintln!` is not
    // shown): the lab reads this line
    {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "execq stop e2e: {total} execs, {held_at_stop} held 1.5 s into the burst; the signed \
             stopping entries: {} — resumed {resumed}, of which {unreported} without an entry, \
             {left_in_map} left in the map; after the stop {} of the burst still running, {} not \
             exit 0, {} new process(es) in state T, cgroup frozen {frozen:?}",
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
    assert!(
        resumed > 0,
        "the signed `stopping` entry names no resumed process ({stopping:?}): the stop did not \
         find the burst held\n{}",
        tail()
    );
    assert_eq!(left_in_map, 0, "{stopping:?}");
    drop(scanner);
    drop(nn_admin);
    drop(installed_agent);
    drop(burst_dir);
}
