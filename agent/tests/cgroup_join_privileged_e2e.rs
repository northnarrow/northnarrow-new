//! Lot 277 (the review of #494, D5) — privileged behaviour test of the
//! start-in-cgroup tracker, whose eBPF programs the host's tests only read
//! (`xtask/tests/cgroup_join.rs`).
//!
//! A real agent (the tracker attached, its maps and links pinned under
//! `/sys/fs/bpf/northnarrow`) and root processes outside its family, each a
//! `python3 -I` of its own; the marks read from the pinned map:
//!
//! - a process that writes its own pid into a cgroup's `cgroup.procs` is
//!   marked (`moved`, by itself), and each of ten children it forks after
//!   is marked too (`inherited`, by it); the marks go when they exit;
//! - a second thread writing its process's leader into a threaded child's
//!   `cgroup.threads` marks the process (the review's B1: the writer itself
//!   does not move, which the first no-op test took for "no move");
//! - a child started by `clone3(CLONE_INTO_CGROUP)` is marked (`born
//!   into`, by its forker);
//! - a process whose leader exits first keeps its mark while a thread
//!   lives, and loses it with the last one;
//! - systemd's own placement marks nothing: a transient service's main
//!   process, ten restarts in a row, and a scope's process;
//! - a mark made on a dead group (a zombie's pid written into a cgroup:
//!   its exit came first) is not the pid's next owner's: the fork of a new
//!   process at that pid clears it (the review of #494, N5);
//! - the re-review of #494 (its point 3): with the marks' map at 64 entries
//!   (`NN_DEBUG_CGROUP_JOINED_ENTRIES`, a `debug-trigger` build's knob) a
//!   marked process's forks past the map are "not known" (never neither
//!   marked nor not known), a fork of one of those is too, a unit systemd
//!   starts meanwhile is neither, and the pid of a "not known" process,
//!   once it is gone, is a new process's with nothing;
//! - the third review of #494 (R2-b): a tracker directory planted beside
//!   the pin root under a name a later start could take, an LRU map in it
//!   as the marks, is never adopted — the agent keeps its registered pins
//!   and removes the planted one, signed.
//!
//! Run (lab guest, units stopped, pins purged — `nn-lab.sh test-ignored`
//! does both):
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test cgroup_join_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nn_linux::cgroup_join::{pinned_lost, pinned_mark, Mark};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::{install_to_priv_bin, InstalledBin};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const LOG_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const CGROOT: &str = "/sys/fs/cgroup";

use ::common::cgroup_join::{HOW_BORN_INTO, HOW_INHERITED, HOW_MOVED};

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}

/// SIGQUIT-on-drop (the task_kill hook refuses SIGKILL/SIGTERM).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

struct Fixture {
    agent_log: PathBuf,
    _state: AgentState,
    _tempdir: tempfile::TempDir,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledAgent,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// An agent whose own files live in a tempdir (as the move guard's
    /// test starts it), once its tracker is attached.
    fn setup() -> Self {
        Self::setup_with(&[])
    }

    /// [`Fixture::setup`] with `env` for the agent too (a `debug-trigger`
    /// build's knobs).
    fn setup_with(env: &[(&str, &str)]) -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();
        let state = AgentState::new(&dir);
        let installed_agent = InstalledAgent::install();
        let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));
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
        let mut f = std::fs::File::create(state.admin_pub()).expect("create admin.pub");
        writeln!(f, "{hex} all").expect("write admin.pub");
        drop(f);
        let _ = std::fs::remove_file(&tmp_pub);
        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");
        let empty = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|_| panic!("write {name}"));
            p
        };
        let agent_log = dir.join("agent.log");
        let log = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_err = log.try_clone().expect("clone log handle");
        let mut all_env = vec![common::OWN_DEFAULT_LISTS_ENV];
        all_env.extend_from_slice(env);
        let mut cmd = installed_agent.command(&state, Launch::Sudo, &all_env);
        cmd.arg("--combat-rules").arg(&combat);
        for (flag, file) in [
            ("--fim-paths-v1", "fim-paths.v1"),
            ("--fim-paths-local", "fim-paths.local"),
            ("--netflow-blocklist-v1", "netflow-blocklist.v1"),
            ("--netflow-blocklist-local", "netflow-blocklist.local"),
            ("--netflow-ja3-blocklist-v1", "netflow-ja3-blocklist.v1"),
            (
                "--netflow-ja3-blocklist-local",
                "netflow-ja3-blocklist.local",
            ),
            ("--process-comm-allowlist-v1", "process-comm-allowlist.v1"),
            (
                "--process-comm-allowlist-local",
                "process-comm-allowlist.local",
            ),
            ("--netflow-comm-allowlist-v1", "netflow-comm-allowlist.v1"),
            (
                "--netflow-comm-allowlist-local",
                "netflow-comm-allowlist.local",
            ),
        ] {
            cmd.arg(flag).arg(empty(file));
        }
        let child = cmd
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn northnarrow-agent");
        let fx = Self {
            agent_log,
            _state: state,
            _tempdir: tempdir,
            _agent_guard: AgentGuard(Some(child)),
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        };
        fx.wait_for_log("start-in-cgroup tracker is attached");
        fx
    }

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

    fn wait_for_log(&self, needle: &str) {
        let deadline = Instant::now() + LOG_POLL_TIMEOUT.max(SOCKET_POLL_TIMEOUT);
        while Instant::now() < deadline {
            let t = self.log_text();
            if t.contains(needle) {
                return;
            }
            assert!(
                !t.contains("cgroup exemptions: tracker"),
                "the tracker did not attach:\n{}",
                tail(&t)
            );
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "agent log never contained {needle:?}\n{}",
            tail(&self.log_text())
        );
    }
}

fn tail(t: &str) -> String {
    let lines: Vec<&str> = t.lines().collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

fn root() -> &'static Path {
    Path::new(antitamper_bpf::DEFAULT_BPFFS_ROOT)
}

fn mark(pid: u32) -> Option<Mark> {
    pinned_mark(root(), pid).unwrap_or_else(|e| panic!("reading the mark of {pid}: {e}"))
}

/// The tracker's pins as the running agent registered them.
fn registered() -> nn_linux::cgroup_join::PinState {
    let text = std::fs::read_to_string(nn_linux::cgroup_join::STATE_PATH)
        .expect("the tracker's pin state");
    nn_linux::cgroup_join::PinState::parse(&text).expect("a whole pin state")
}

fn lost(pid: u32) -> bool {
    pinned_lost(root(), pid).unwrap_or_else(|e| panic!("reading the lost byte of {pid}: {e}"))
}

/// `pid`'s mark once it is there (the writes are synchronous; the read is
/// a poll only for the process to have got that far).
fn wait_mark(pid: u32) -> Option<Mark> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(m) = mark(pid) {
            return Some(m);
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if mark(pid).is_none() {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// A `python3 -I -c <code> <args>` in its own process group, its stdout
/// piped: the harness reads the pids it prints.
fn spawn_py(code: &str, args: &[&str]) -> Child {
    use std::os::unix::process::CommandExt;
    Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(code)
        .args(args)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn python3")
}

/// The first line the child prints, as numbers.
fn read_pids(child: &mut Child) -> Vec<u32> {
    use std::io::BufRead;
    let out = child.stdout.as_mut().expect("piped stdout");
    let mut line = String::new();
    std::io::BufReader::new(out)
        .read_line(&mut line)
        .expect("a line");
    line.split_whitespace()
        .map(|w| w.parse().unwrap_or_else(|_| panic!("not a pid: {line:?}")))
        .collect()
}

/// A throwaway cgroup at the root, removed on drop.
struct TempCgroup(PathBuf);
impl TempCgroup {
    fn new(name: &str) -> Self {
        let p = PathBuf::from(CGROOT).join(name);
        let _ = std::fs::remove_dir(&p);
        std::fs::create_dir(&p).unwrap_or_else(|e| panic!("mkdir {}: {e}", p.display()));
        TempCgroup(p)
    }
    fn path(&self) -> String {
        self.0.display().to_string()
    }
}
impl Drop for TempCgroup {
    fn drop(&mut self) {
        for _ in 0..50 {
            if std::fs::remove_dir(&self.0).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Moves itself into argv[1], forks ten children that sleep, prints its
/// pid and theirs, waits for them.
const MOVE_AND_FORK: &str = r#"
import os, sys, time
with open(sys.argv[1] + "/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
kids = []
for _ in range(10):
    k = os.fork()
    if k == 0:
        time.sleep(3)
        os._exit(0)
    kids.append(k)
print(os.getpid(), *kids, flush=True)
for k in kids:
    os.waitpid(k, 0)
time.sleep(1)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_move_is_marked_and_passed_on_to_every_fork() {
    let _fx = Fixture::setup();
    let cg = TempCgroup::new("nn-test-join-move");
    let mut p = spawn_py(MOVE_AND_FORK, &[&cg.path()]);
    let pids = read_pids(&mut p);
    let (me, kids) = (pids[0], &pids[1..]);
    assert_eq!(
        wait_mark(me),
        Some(Mark {
            how: HOW_MOVED,
            by: me
        }),
        "the process that moved itself"
    );
    for k in kids {
        assert_eq!(
            mark(*k),
            Some(Mark {
                how: HOW_INHERITED,
                by: me
            }),
            "child {k} of a marked process"
        );
    }
    let _ = p.wait();
    for pid in &pids {
        assert!(wait_gone(*pid), "{pid}'s mark outlived it");
    }
}

/// Run as a scope (systemd places it: no mark), makes a threaded child
/// named like an exempt unit, and a second thread writes the leader's tid
/// into its `cgroup.threads`; prints its pid and its cgroup after.
const THREADED_MOVE: &str = r#"
import os, sys, threading, time
own = [l[3:] for l in open("/proc/self/cgroup").read().splitlines() if l.startswith("0::")][0]
d = "/sys/fs/cgroup" + own + "/nn-test-join.service"
os.mkdir(d)
with open(d + "/cgroup.type", "w") as f:
    f.write("threaded")
def mover():
    with open(d + "/cgroup.threads", "w") as f:
        f.write(str(os.getpid()))
t = threading.Thread(target=mover)
t.start(); t.join()
cg = [l[3:] for l in open("/proc/%d/cgroup" % os.getpid()).read().splitlines() if l.startswith("0::")][0]
print(os.getpid(), flush=True)
sys.stderr.write("leader now in " + cg + "\n")
time.sleep(2)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_threaded_move_of_the_leader_is_marked() {
    let _fx = Fixture::setup();
    let mut p = Command::new("systemd-run")
        .args([
            "--scope",
            "--quiet",
            "--unit=nn-test-join-threaded.scope",
            "python3",
            "-I",
            "-c",
            THREADED_MOVE,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn systemd-run --scope");
    let pids = read_pids(&mut p);
    let me = pids[0];
    assert_eq!(
        wait_mark(me),
        Some(Mark {
            how: HOW_MOVED,
            by: me
        }),
        "the leader moved by its own second thread"
    );
    let _ = p.wait();
    assert!(wait_gone(me));
}

/// `clone3(CLONE_INTO_CGROUP)` into argv[1]; prints its pid and the
/// child's; the child sleeps, then exits.
const CLONE_INTO: &str = r#"
import ctypes, os, sys, time
CLONE_INTO_CGROUP = 0x200000000
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
args = (ctypes.c_uint64 * 11)(CLONE_INTO_CGROUP, 0, 0, 0, 17, 0, 0, 0, 0, 0, fd)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
pid = libc.syscall(435, ctypes.byref(args), ctypes.c_size_t(88))
if pid == 0:
    time.sleep(3)
    os._exit(0)
if pid < 0:
    sys.stderr.write("clone3: errno %d\n" % ctypes.get_errno()); sys.exit(1)
print(os.getpid(), pid, flush=True)
os.waitpid(pid, 0)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_clone_into_cgroup_start_is_marked() {
    let _fx = Fixture::setup();
    let cg = TempCgroup::new("nn-test-join-clone");
    let mut p = spawn_py(CLONE_INTO, &[&cg.path()]);
    let pids = read_pids(&mut p);
    let (me, kid) = (pids[0], pids[1]);
    assert_eq!(
        wait_mark(kid),
        Some(Mark {
            how: HOW_BORN_INTO,
            by: me
        }),
        "the child started in another cgroup"
    );
    assert_eq!(mark(me), None, "its forker moved nowhere");
    let _ = p.wait();
    assert!(wait_gone(kid));
}

/// Moves itself into argv[1], starts a thread that lives 3 s, prints its
/// pid, then ends its leader alone (`SYS_exit`, not `exit_group`).
const LEADER_FIRST: &str = r#"
import ctypes, os, sys, threading, time
with open(sys.argv[1] + "/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
threading.Thread(target=lambda: time.sleep(3)).start()
print(os.getpid(), flush=True)
time.sleep(0.5)
ctypes.CDLL(None).syscall(60, 0)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn the_mark_goes_with_the_last_thread_not_the_leader() {
    let _fx = Fixture::setup();
    let cg = TempCgroup::new("nn-test-join-leader");
    let mut p = spawn_py(LEADER_FIRST, &[&cg.path()]);
    let me = read_pids(&mut p)[0];
    assert!(wait_mark(me).is_some(), "marked at its move");
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        mark(me).is_some(),
        "its leader exited, a thread lives: the mark stays"
    );
    let _ = p.wait();
    assert!(wait_gone(me), "the last thread exited: the mark goes");
}

/// Forks a child that exits at once, waits for it to be a zombie, writes
/// its pid into argv[1]'s `cgroup.procs` (the move of a group already
/// dead), prints it; on a line from stdin reaps it, forks again at that pid
/// (`ns_last_pid`; a few tries: other forks may take it), prints the new
/// child's pid (0 when the pid was not had), waits for it.
const DEAD_GROUP: &str = r#"
import os, sys, time
z = os.fork()
if z == 0:
    os._exit(0)
for _ in range(500):
    with open(f"/proc/{z}/stat") as f:
        if f.read().rsplit(")", 1)[1].split()[0] == "Z":
            break
    time.sleep(0.01)
with open(sys.argv[1] + "/cgroup.procs", "w") as f:
    f.write(str(z))
print(z, flush=True)
sys.stdin.readline()
os.waitpid(z, 0)
got = 0
for _ in range(50):
    with open("/proc/sys/kernel/ns_last_pid", "w") as f:
        f.write(str(z - 1))
    n = os.fork()
    if n == 0:
        time.sleep(2)
        os._exit(0)
    if n == z:
        got = n
        break
    os.kill(n, 9)
    os.waitpid(n, 0)
print(got, flush=True)
if got:
    os.waitpid(got, 0)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_dead_group_s_mark_is_not_the_next_owner_s() {
    use std::os::unix::process::CommandExt;
    let _fx = Fixture::setup();
    let cg = TempCgroup::new("nn-test-join-dead");
    let mut p = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(DEAD_GROUP)
        .arg(cg.path())
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn python3");
    let z = read_pids(&mut p)[0];
    let planted = wait_mark(z);
    p.stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(b"go\n")
        .expect("go");
    let n = read_pids(&mut p)[0];
    let next = if n == 0 { None } else { Some(mark(n)) };
    let _ = p.wait();
    assert_eq!(
        planted,
        Some(Mark {
            how: HOW_MOVED,
            by: p.id()
        }),
        "the move of a dead group marks its tgid (the case this test is about)"
    );
    assert_eq!(n, z, "the pid's next process (ns_last_pid, 50 tries)");
    assert_eq!(
        next,
        Some(None),
        "a new process at {z} inherited a dead group's mark"
    );
}

/// Moves itself into argv[1], forks 80 children that sleep, then a child X
/// that forks a grandchild Y; prints its pid, the 80, X and Y. On a line
/// from stdin kills X and Y, reaps X, prints "done", waits for the 80.
const FILL_AND_LOSE: &str = r#"
import os, signal, sys, time
with open(sys.argv[1] + "/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
kids = []
for _ in range(80):
    k = os.fork()
    if k == 0:
        time.sleep(30)
        os._exit(0)
    kids.append(k)
r, w = os.pipe()
x = os.fork()
if x == 0:
    os.close(r)
    y = os.fork()
    if y == 0:
        time.sleep(30)
        os._exit(0)
    os.write(w, b"%d\n" % y)
    os.close(w)
    time.sleep(30)
    os._exit(0)
os.close(w)
y = int(os.read(r, 32).split()[0])
print(os.getpid(), *kids, x, y, flush=True)
sys.stdin.readline()
os.kill(y, signal.SIGKILL)
os.kill(x, signal.SIGKILL)
os.waitpid(x, 0)
print("done", flush=True)
for k in kids:
    os.kill(k, signal.SIGKILL)
    os.waitpid(k, 0)
"#;

/// Forks at pid argv[1] (`ns_last_pid`, a few tries), prints the child's
/// pid (0 when the pid was not had), waits for it.
const REUSE_PID: &str = r#"
import os, sys, time
want = int(sys.argv[1])
got = 0
for _ in range(50):
    with open("/proc/sys/kernel/ns_last_pid", "w") as f:
        f.write(str(want - 1))
    n = os.fork()
    if n == 0:
        time.sleep(2)
        os._exit(0)
    if n == want:
        got = n
        break
    os.kill(n, 9)
    os.waitpid(n, 0)
print(got, flush=True)
if got:
    os.waitpid(got, 0)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_full_map_makes_that_tree_not_known_and_no_one_else() {
    use std::os::unix::process::CommandExt;
    let _fx = Fixture::setup_with(&[("NN_DEBUG_CGROUP_JOINED_ENTRIES", "64")]);
    let state = registered();
    let joined = state
        .maps
        .iter()
        .find(|m| m.name == nn_linux::cgroup_join::JOINED_MAP)
        .expect("the marks registered");
    assert_eq!(
        joined.max_entries,
        64,
        "the knob sized the marks: {}",
        state.dir.display()
    );
    let cg = TempCgroup::new("nn-test-join-full");
    let mut p = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(FILL_AND_LOSE)
        .arg(cg.path())
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn python3");
    let pids = read_pids(&mut p);
    assert_eq!(pids.len(), 83);
    let (me, kids, x, y) = (pids[0], &pids[1..81], pids[81], pids[82]);
    // a unit systemd starts while the map is full: neither
    let unit = "nn-test-join-full.service";
    let _ = Command::new("systemctl").args(["stop", unit]).status();
    let st = Command::new("systemd-run")
        .args(["--quiet", "--unit", unit, "-p", "Type=exec", "sleep", "60"])
        .status()
        .expect("systemd-run");
    assert!(st.success());
    let svc = main_pid(unit);
    let svc_state = (mark(svc), lost(svc));
    let _ = Command::new("systemctl").args(["stop", unit]).status();
    let me_state = (mark(me), lost(me));
    let kid_states: Vec<(u32, Option<Mark>, bool)> =
        kids.iter().map(|k| (*k, mark(*k), lost(*k))).collect();
    let (x_state, y_state) = ((mark(x), lost(x)), (mark(y), lost(y)));
    p.stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(b"go\n")
        .expect("go");
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(p.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut line)
            .expect("done");
        assert_eq!(line.trim(), "done");
    }
    // X is gone: its pid, a new process's, is not "not known"
    let mut r = spawn_py(REUSE_PID, &[&x.to_string()]);
    let again = read_pids(&mut r)[0];
    let again_state = (again != 0).then(|| (mark(again), lost(again)));
    let _ = r.wait();
    let _ = p.wait();

    assert!(
        me_state.0.is_some() || me_state.1,
        "the mover: marked or not known"
    );
    let neither: Vec<u32> = kid_states
        .iter()
        .filter(|(_, m, l)| m.is_none() && !l)
        .map(|(k, _, _)| *k)
        .collect();
    assert!(
        neither.is_empty(),
        "forks of a marked process neither marked nor not known (exempt): {neither:?}"
    );
    let marked = kid_states.iter().filter(|(_, m, _)| m.is_some()).count();
    let lost_n = kid_states.iter().filter(|(_, _, l)| *l).count();
    assert!(marked <= 64, "{marked} marks in a map of 64");
    assert!(lost_n >= 16, "past the map, not known: {lost_n} of 80");
    assert_eq!(x_state, (None, true), "X, forked past the map: not known");
    assert_eq!(
        y_state,
        (None, true),
        "Y, a fork of a not-known process: not known"
    );
    assert_eq!(
        svc_state,
        (None, false),
        "a unit systemd started keeps its standing"
    );
    assert_eq!(again, x, "the pid's next process (ns_last_pid, 50 tries)");
    assert_eq!(
        again_state,
        Some((None, false)),
        "a new process at {x} inherited the not-known state of a dead group"
    );
}

/// Pins an LRU hash shaped like the marks (key 4, value 16, 64 entries) at
/// argv[1]/CGROUP_JOINED, the directory made first; prints the map's fd's
/// result ("ok").
const PLANT_LRU: &str = r#"
import ctypes, os, struct, sys
SYS_BPF, BPF_MAP_CREATE, BPF_OBJ_PIN, LRU_HASH = 321, 0, 6, 9
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
os.makedirs(sys.argv[1], mode=0o700, exist_ok=True)
attr = (ctypes.c_uint8 * 128)()
struct.pack_into("<IIIII", attr, 0, LRU_HASH, 4, 16, 64, 0)
fd = libc.syscall(SYS_BPF, BPF_MAP_CREATE, ctypes.byref(attr), ctypes.c_uint(128))
if fd < 0:
    raise SystemExit("map create: errno %d" % ctypes.get_errno())
path = ctypes.create_string_buffer((sys.argv[1] + "/CGROUP_JOINED").encode())
attr = (ctypes.c_uint8 * 128)()
struct.pack_into("<QI", attr, 0, ctypes.addressof(path), fd)
if libc.syscall(SYS_BPF, BPF_OBJ_PIN, ctypes.byref(attr), ctypes.c_uint(128)) != 0:
    raise SystemExit("pin: errno %d" % ctypes.get_errno())
print("ok", flush=True)
"#;

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn a_planted_tracker_directory_is_never_adopted() {
    // an agent first, so that the tracker's pins are registered
    let before = {
        let _fx = Fixture::setup();
        registered()
    };
    let gen = before
        .dir
        .to_string_lossy()
        .rsplit_once('.')
        .and_then(|(_, g)| g.parse::<u32>().ok())
        .expect("a generation");
    let planted = format!(
        "{}{}{}.{}",
        root().display(),
        ::common::cgroup_join::PIN_DIR_INFIX,
        ::common::cgroup_join::PIN_SCHEMA,
        gen + 1
    );
    let out = Command::new("python3")
        .args(["-I", "-c", PLANT_LRU, &planted])
        .output()
        .expect("python3");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "ok",
        "planting: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fx = Fixture::setup();
    let after = registered();
    assert_eq!(
        after.dir, before.dir,
        "the registered pins adopted, not the planted ones"
    );
    assert!(
        !Path::new(&planted).exists(),
        "the planted directory {planted} left beside the pin root"
    );
    fx.wait_for_log("an unregistered tracker directory beside the pin root removed");
}

/// The main pid of transient unit `unit`.
fn main_pid(unit: &str) -> u32 {
    let out = Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", unit])
        .output()
        .expect("systemctl show");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn systemd_s_own_placement_marks_nothing() {
    let _fx = Fixture::setup();
    let unit = "nn-test-join-svc.service";
    let _ = Command::new("systemctl").args(["stop", unit]).status();
    let st = Command::new("systemd-run")
        .args(["--quiet", "--unit", unit, "-p", "Type=exec", "sleep", "300"])
        .status()
        .expect("systemd-run");
    assert!(st.success());
    for round in 0..10 {
        let pid = main_pid(unit);
        assert_ne!(pid, 0, "round {round}: no main pid");
        assert_eq!(
            mark(pid),
            None,
            "round {round}: systemd started {pid} in its unit"
        );
        let st = Command::new("systemctl")
            .args(["restart", unit])
            .status()
            .expect("systemctl restart");
        assert!(st.success());
    }
    let _ = Command::new("systemctl").args(["stop", unit]).status();
    // a scope's process: systemd attaches it on the caller's request
    let mut p = Command::new("systemd-run")
        .args([
            "--scope",
            "--quiet",
            "--unit=nn-test-join-scope.scope",
            "python3",
            "-I",
            "-c",
            "import os, time; print(os.getpid(), flush=True); time.sleep(2)",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("systemd-run --scope");
    let pid = read_pids(&mut p)[0];
    assert_eq!(mark(pid), None, "a scope's process systemd placed");
    let _ = p.wait();
}
