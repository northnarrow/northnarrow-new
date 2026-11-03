//! Lot 273b (the review of #489) — privileged behaviour test of the cgroup
//! move guard and of the write deny, which the host's tests only read.
//!
//! A real agent (its pid protected, outside a systemd service: its own
//! cgroup is not registered, the guard is pid-based) and root processes
//! outside its family, each a `python3 -I` of its own:
//!
//! - moving the agent's pid to another cgroup is refused with `EPERM` and
//!   signed `cgroup_move`;
//! - a move the DAC refused first (an unprivileged writer in a delegated
//!   subtree writes the agent's pid) leaves nothing behind: the same
//!   thread's next migration — of itself, inside its subtree — goes
//!   through (a stashed move that outlived its write refused it);
//! - two threads moving the agent at the same time are both refused;
//! - a write through a descriptor of a protected file opened inside a
//!   trusted-installer window is refused once the window closed;
//! - the agent's `oom_score_adj` is not written (`/proc/<pid>` and a
//!   thread's `/proc/<pid>/task/<tid>`).
//!
//! Run (lab guest, units stopped, pins purged — `nn-lab.sh test-ignored`
//! does both):
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test cgroup_guard_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::{install_to_priv_bin, EniIptablesGuard, InstalledBin};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const LOG_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

const CGROOT: &str = "/sys/fs/cgroup";

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}

// Path-safe install (R009: no root exec from a user path):
// `common::install_to_priv_bin`.

/// SIGQUIT-on-drop (the task_kill hook refuses SIGKILL/SIGTERM).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

// ── agent fixture ───────────────────────────────────────────────────

struct Fixture {
    state: AgentState,
    agent_log: PathBuf,
    nn_admin: PathBuf,
    admin_priv: PathBuf,
    _tempdir: tempfile::TempDir,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledAgent,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// Spawn an agent whose own files live in a tempdir; the directories
    /// it protects are the fixed ones (`/etc/northnarrow`, the state
    /// directory, the pin root). Per-test admin key with every role.
    ///
    /// Lab PR 256: every file the agent writes in the tempdir
    /// ([`AgentState`]). The detection and status logs were missing, so
    /// the agent appended its records, under its own key, to the installed
    /// agent's chain in `/var/lib/northnarrow/detections/` (lot 255).
    fn setup() -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();
        let state = AgentState::new(&dir);
        let installed_agent = InstalledAgent::install();
        let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));

        let admin_pub = state.admin_pub();
        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init = Command::new(&installed_admin.path)
            .args(["init", "--priv-out"])
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&tmp_pub)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn nn-admin init");
        assert!(init.success(), "nn-admin init failed");
        let body = std::fs::read_to_string(&tmp_pub).expect("read tmp pubkey");
        let hex = body
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .expect("init pub file has no hex line");
        let mut f = std::fs::File::create(&admin_pub).expect("create admin.pub");
        writeln!(f, "{hex} all").expect("write admin.pub");
        drop(f);
        let _ = std::fs::remove_file(&tmp_pub);

        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");
        let write_empty = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|_| panic!("write {name}"));
            p
        };
        let fim_v1 = write_empty("fim-paths.v1");
        let fim_local = write_empty("fim-paths.local");
        let nb_v1 = write_empty("netflow-blocklist.v1");
        let nb_local = write_empty("netflow-blocklist.local");
        let ja3_v1 = write_empty("netflow-ja3-blocklist.v1");
        let ja3_local = write_empty("netflow-ja3-blocklist.local");
        let pca_v1 = write_empty("process-comm-allowlist.v1");
        let pca_local = write_empty("process-comm-allowlist.local");
        let nca_v1 = write_empty("netflow-comm-allowlist.v1");
        let nca_local = write_empty("netflow-comm-allowlist.local");

        let agent_log = dir.join("agent.log");
        let log = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_err = log.try_clone().expect("clone log handle");
        let child = installed_agent
            .command(&state, Launch::Sudo, &[common::OWN_DEFAULT_LISTS_ENV])
            .arg("--combat-rules")
            .arg(&combat)
            .arg("--fim-paths-v1")
            .arg(&fim_v1)
            .arg("--fim-paths-local")
            .arg(&fim_local)
            .arg("--netflow-blocklist-v1")
            .arg(&nb_v1)
            .arg("--netflow-blocklist-local")
            .arg(&nb_local)
            .arg("--netflow-ja3-blocklist-v1")
            .arg(&ja3_v1)
            .arg("--netflow-ja3-blocklist-local")
            .arg(&ja3_local)
            .arg("--process-comm-allowlist-v1")
            .arg(&pca_v1)
            .arg("--process-comm-allowlist-local")
            .arg(&pca_local)
            .arg("--netflow-comm-allowlist-v1")
            .arg(&nca_v1)
            .arg("--netflow-comm-allowlist-local")
            .arg(&nca_local)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn northnarrow-agent");
        let guard = AgentGuard(Some(child));
        let fx = Self {
            nn_admin: installed_admin.path.clone(),
            state,
            agent_log,
            admin_priv,
            _tempdir: tempdir,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        };
        fx.wait_for_path(&fx.state.admin_socket(), SOCKET_POLL_TIMEOUT);
        // The agent's own line once every filesystem deny hook attached.
        fx.wait_for_log("all inode_protect deny hooks attached");
        fx
    }

    fn wait_for_path(&self, p: &Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if p.exists() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("{} never appeared\n{}", p.display(), self.log_tail());
    }

    /// The agent's output without the ANSI colour codes.
    fn log_text(&self) -> String {
        let raw = std::fs::read_to_string(&self.agent_log).unwrap_or_default();
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    fn log_tail(&self) -> String {
        let text = self.log_text();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(25)..].join("\n")
    }

    fn wait_for_log(&self, needle: &str) {
        let deadline = Instant::now() + LOG_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if self.log_text().contains(needle) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("agent log never contained {needle:?}\n{}", self.log_tail());
    }

    /// `ANTI-TAMPER DENIAL` lines naming `op=<op>`.
    fn denials(&self, op: &str) -> usize {
        let want = format!("op={op}");
        self.log_text()
            .lines()
            .filter(|l| l.contains("ANTI-TAMPER DENIAL"))
            .filter(|l| l.split_whitespace().any(|w| w == want))
            .count()
    }

    fn wait_for_denial(&self, op: &str) {
        let deadline = Instant::now() + LOG_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if self.denials(op) > 0 {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("no ANTI-TAMPER DENIAL op={op}\n{}", self.log_tail());
    }

    /// Open the trusted-installer window the way `install.sh` does.
    fn grant_window(&self, secs: u32) {
        let out = Command::new(&self.nn_admin)
            .arg("trusted-installer-grant")
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--window-secs")
            .arg(secs.to_string())
            .args(self.state.client_args())
            .output()
            .expect("spawn nn-admin trusted-installer-grant");
        assert!(
            out.status.success(),
            "trusted-installer-grant failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Fixture {
    /// The agent's pid, from its pid file.
    fn agent_pid(&self) -> u32 {
        let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
        loop {
            if let Some(p) = std::fs::read_to_string(self.state.pid_file())
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
            {
                return p;
            }
            assert!(
                Instant::now() < deadline,
                "no pid file\n{}",
                self.log_tail()
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// The agent attached the move guard and its self-test refused a move
    /// (where it did not, the kernel has no guard: the test says so).
    fn guard_attached(&self) -> bool {
        self.wait_for_log("all LSM hooks attached");
        !self.log_text().contains("move guard not attached")
    }
}

/// `python3 -I -c <code> <args>` in its own process group (a refusal's
/// COMBAT ladder acts on the actor, never the harness); exit status and
/// output.
fn py(code: &str, args: &[&str]) -> (i32, String) {
    use std::os::unix::process::CommandExt;
    let out = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(code)
        .args(args)
        .process_group(0)
        .output()
        .expect("spawn python3");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Write `pid` to `procs`; prints `ok` or `errno=<NAME>`.
const MOVE: &str = r#"
import errno, os, sys
try:
    fd = os.open(sys.argv[1], os.O_WRONLY)
    os.write(fd, sys.argv[2].encode())
    os.close(fd)
    print("ok")
except OSError as e:
    print("errno=" + errno.errorcode.get(e.errno, str(e.errno)))
"#;

/// A throwaway cgroup at the root, removed on drop (after its processes
/// are gone).
struct TempCgroup(PathBuf);
impl TempCgroup {
    fn new(name: &str) -> Self {
        let p = PathBuf::from(CGROOT).join(name);
        let _ = std::fs::remove_dir(&p);
        std::fs::create_dir(&p).unwrap_or_else(|e| panic!("mkdir {}: {e}", p.display()));
        TempCgroup(p)
    }
    fn procs(&self) -> String {
        self.0.join("cgroup.procs").display().to_string()
    }
}
impl Drop for TempCgroup {
    fn drop(&mut self) {
        for _ in 0..50 {
            let mut empty = true;
            if let Ok(rd) = std::fs::read_dir(&self.0) {
                for e in rd.flatten() {
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let _ = std::fs::remove_dir(e.path());
                        empty = false;
                    }
                }
            }
            if empty && std::fs::remove_dir(&self.0).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The cgroup of `pid` (the v2 line of `/proc/<pid>/cgroup`).
fn cgroup_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        .unwrap_or_default()
}

/// Moving the agent's pid to another cgroup is refused and signed; the
/// agent stays where it was.
#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_move_of_the_agent_is_refused() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();
    if !fx.guard_attached() {
        eprintln!("the kernel has no move guard: nothing to test");
        return;
    }
    let pid = fx.agent_pid();
    let before = cgroup_of(pid);
    let dst = TempCgroup::new("nn-e2e-273b-move");
    let (_, out) = py(MOVE, &[&dst.procs(), &pid.to_string()]);
    assert_eq!(out.trim(), "errno=EPERM", "{}", fx.log_tail());
    assert_eq!(cgroup_of(pid), before);
    fx.wait_for_denial("cgroup_move");
}

/// A move whose permission check the DAC refused (an unprivileged writer
/// of the agent's pid, in a subtree delegated to it) leaves no record: the
/// same thread then moves itself inside its subtree, and is not refused.
#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_move_the_dac_refused_leaves_no_record_behind() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();
    if !fx.guard_attached() {
        eprintln!("the kernel has no move guard: nothing to test");
        return;
    }
    let pid = fx.agent_pid();
    let d = TempCgroup::new("nn-e2e-273b-dac");
    let child = d.0.join("x");
    std::fs::create_dir(&child).expect("mkdir the delegated child");
    // delegate the subtree to nobody (the directory and its members' files)
    for p in [
        d.0.clone(),
        d.0.join("cgroup.procs"),
        child.clone(),
        child.join("cgroup.procs"),
    ] {
        std::os::unix::fs::lchown(&p, Some(65534), Some(65534)).expect("chown the delegation");
    }
    // One thread: into the subtree as root, then nobody; the agent's pid
    // (EACCES: the common ancestor is the root's cgroup.procs); then its
    // own pid one level down (the common ancestor is the delegated one).
    let script = r#"
import errno, os, sys
d, x, agent = sys.argv[1], sys.argv[2], sys.argv[3]
def move(procs, pid):
    try:
        fd = os.open(procs, os.O_WRONLY)
        os.write(fd, str(pid).encode())
        os.close(fd)
        return "ok"
    except OSError as e:
        return "errno=" + errno.errorcode.get(e.errno, str(e.errno))
r0 = move(d + "/cgroup.procs", os.getpid())
os.setgid(65534); os.setuid(65534)
r1 = move(x + "/cgroup.procs", agent)
r2 = move(x + "/cgroup.procs", os.getpid())
print(r0, r1, r2)
"#;
    let (_, out) = py(
        script,
        &[
            &d.0.display().to_string(),
            &child.display().to_string(),
            &pid.to_string(),
        ],
    );
    assert_eq!(
        out.trim(),
        "ok errno=EACCES ok",
        "the self-move after a DAC-refused move of the agent: {}",
        fx.log_tail()
    );
}

/// Two threads moving the agent at the same time are both refused.
#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn concurrent_moves_are_both_refused() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();
    if !fx.guard_attached() {
        eprintln!("the kernel has no move guard: nothing to test");
        return;
    }
    let pid = fx.agent_pid();
    let a = TempCgroup::new("nn-e2e-273b-a");
    let b = TempCgroup::new("nn-e2e-273b-b");
    let script = r#"
import errno, os, sys, threading
res = {}
go = threading.Barrier(2)
def move(k, procs, pid):
    go.wait()
    for _ in range(200):
        try:
            fd = os.open(procs, os.O_WRONLY)
            os.write(fd, pid.encode())
            os.close(fd)
            res[k] = "ok"
            return
        except OSError as e:
            res[k] = "errno=" + errno.errorcode.get(e.errno, str(e.errno))
            if e.errno != errno.EPERM:
                return
ts = [threading.Thread(target=move, args=(k, p, sys.argv[3])) for k, p in (("a", sys.argv[1]), ("b", sys.argv[2]))]
[t.start() for t in ts]; [t.join() for t in ts]
print(res["a"], res["b"])
"#;
    let before = cgroup_of(pid);
    let (_, out) = py(script, &[&a.procs(), &b.procs(), &pid.to_string()]);
    assert_eq!(out.trim(), "errno=EPERM errno=EPERM", "{}", fx.log_tail());
    assert_eq!(cgroup_of(pid), before);
}

/// A descriptor of a protected file opened inside a trusted-installer
/// window writes nothing once the window is closed (an empty write: the
/// file is not changed either way); and the agent's `oom_score_adj` is
/// not written, through its pid or a thread's.
///
/// The file is the installed `/etc/northnarrow/admin.pub`: the agent
/// write-protects the fixed directory's files (`ETC_WRITE_DENY_FILES`),
/// not the tempdir's `--admin-pub` (a first version wrote there, and its
/// "refused" write went through: nothing protected it).
#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn an_earlier_descriptor_and_the_oom_score_are_refused() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();
    let target = "/etc/northnarrow/admin.pub";
    if !Path::new(target).exists() {
        eprintln!("no installed {target}: nothing to test");
        return;
    }
    // Outside a window its write-open is refused: the file is protected.
    let open = r#"
import errno, os, sys
try:
    os.close(os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND))
    print("ok")
except OSError as e:
    print("errno=" + errno.errorcode.get(e.errno, str(e.errno)))
"#;
    let (_, out) = py(open, &[target]);
    assert_eq!(out.trim(), "errno=EPERM", "{}", fx.log_tail());
    let script = r#"
import errno, os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND)
print("opened", flush=True)
time.sleep(int(sys.argv[2]))
try:
    os.write(fd, b"")
    print("ok")
except OSError as e:
    print("errno=" + errno.errorcode.get(e.errno, str(e.errno)))
"#;
    fx.grant_window(5);
    fx.wait_for_log("trusted-installer override ARMED");
    let (_, out) = py(script, &[target, "12"]);
    assert_eq!(
        out.split_whitespace().collect::<Vec<_>>(),
        ["opened", "errno=EPERM"],
        "{}",
        fx.log_tail()
    );
    let pid = fx.agent_pid();
    let before = std::fs::read_to_string(format!("/proc/{pid}/oom_score_adj")).unwrap();
    let (_, out) = py(MOVE, &[&format!("/proc/{pid}/oom_score_adj"), "1000"]);
    assert_eq!(out.trim(), "errno=EPERM", "{}", fx.log_tail());
    let tid = std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|t| *t != pid.to_string());
    if let Some(tid) = tid {
        let (_, out) = py(
            MOVE,
            &[&format!("/proc/{pid}/task/{tid}/oom_score_adj"), "1000"],
        );
        assert_eq!(out.trim(), "errno=EPERM", "{}", fx.log_tail());
    }
    assert_eq!(
        std::fs::read_to_string(format!("/proc/{pid}/oom_score_adj")).unwrap(),
        before
    );
    fx.wait_for_denial("oom_adj");
}
