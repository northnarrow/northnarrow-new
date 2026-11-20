//! Watchdog W8 — privileged end-to-end integration tests.
//!
//! Consolidates the three integration tests deferred from W3
//! ("kill a fake agent, assert evict latency < 1 ms"), W4
//! ("3 restart cycles"), and W5 ("wedge a sleep(99999) agent
//! and assert unstuck-then-restart") per the design §12
//! commit plan. All three need the same coordinated harness
//! (real BPF env + real subprocess + tempdir setup +
//! RAII cleanup), so shipping them together avoids three
//! near-duplicate harnesses.
//!
//! ## Requirements
//!
//! - **Root** (or passwordless sudo) for bpf(2) + iptables.
//! - **bpffs** mounted at `/sys/fs/bpf`.
//! - **`bpf`** in the kernel's runtime `lsm=` chain
//!   (`cat /sys/kernel/security/lsm`).
//! - Workspace built with `--features test-privileged`.
//!
//! ## Run path
//!
//! ```text
//! sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-watchdog \
//!     --features test-privileged \
//!     --test privileged_e2e \
//!     -- --test-threads=1 --nocapture
//! ```
//!
//! Tests serialise on the bpffs `PROTECTED_PIDS` pin (which is
//! a process-global resource at `/sys/fs/bpf/northnarrow/`),
//! so `--test-threads=1` is mandatory.
//!
//! ## R009 avoidance
//!
//! The production decision rule `R009_RootExecFromUserPath`
//! kills any root subprocess whose binary path is under
//! `/home/*`, `/tmp/*`, or `/var/tmp/*` — the rule the ENI
//! integration test originally tripped on (ISSUE_001). The
//! helper [`install_to_priv_bin`] sudo-copies the cargo
//! build outputs to `/usr/local/bin/<name>-e2etest-<ts>-<pid>`
//! before launch so R009 doesn't match. RAII cleanup removes
//! the installed copies on test exit; the timestamp+PID
//! suffix means a leftover never blocks a future run.
//!
//! ## RAII cleanup
//!
//! Every test exit (success, failure, panic) runs:
//! 1. `sudo rm -f /sys/fs/bpf/northnarrow/PROTECTED_PIDS` and
//!    the rest of the pin tree — the next test starts from a
//!    clean slate.
//! 2. `sudo rm -f /usr/local/bin/*-e2etest-*` — installed
//!    binaries removed.
//! 3. tempdir auto-removal (the per-test tempdir owns all
//!    sockets, pidfiles, configs).
//!
//! CI deliberately does NOT run these tests — the gate is
//! `--features test-privileged` AND a sudo wrapper. Bit-rot
//! is caught by `cargo test --no-run --features test-privileged`
//! against the workspace.

#![cfg(feature = "test-privileged")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Lab PR 256: where the agent a test starts keeps its state, and the one
// way to start it — the agent tests' helper, the same file (std only).
#[allow(dead_code)]
mod agent_state {
    include!(concat!(
        env!("NN_REPO_ROOT"),
        "/agent/tests/common/agent_state.rs"
    ));
}
use agent_state::{AgentState, InstalledAgent, Launch};

// ── shared constants ────────────────────────────────────────────────

/// bpffs root the agent pins PROTECTED_PIDS at — also the path
/// the watchdog's `--bpffs-root` flag defaults to. Tests share
/// this single root (it's process-global; --test-threads=1
/// keeps the contention serial).
const BPFFS_ROOT: &str = "/sys/fs/bpf/northnarrow";

/// /usr/local/bin/ prefix for the R009-avoiding install copies.
const PRIV_BIN_DIR: &str = "/usr/local/bin";

// ── install-to-priv-bin helper ──────────────────────────────────────

/// RAII handle for a binary copy under [`PRIV_BIN_DIR`]. Drop
/// `sudo rm -f`s the file so a test panic never leaves it
/// behind. Failures during drop are swallowed (best-effort
/// cleanup; the ts+PID suffix in the name means a leftover
/// never blocks a future run).
struct InstalledBin {
    path: PathBuf,
}
impl Drop for InstalledBin {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .arg("rm")
            .arg("-f")
            .arg(&self.path)
            .status();
    }
}

/// Copy `src` to `/usr/local/bin/<basename>-e2etest-<ts_ns>-<pid>`
/// with mode 0755 + owner root:root. Uses `sudo install` so it
/// works whether the test process is already root or invoked
/// via passwordless sudo. Panics if install fails — without
/// the relocated copy R009 eats any spawn from the
/// `/home/.../target/release/` cargo path.
fn install_to_priv_bin(src: &Path) -> InstalledBin {
    let basename = src
        .file_name()
        .and_then(|s| s.to_str())
        .expect("binary path has a UTF-8 basename");
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let dst = PathBuf::from(format!("{PRIV_BIN_DIR}/{basename}-e2etest-{ts_ns}-{pid}"));
    let status = Command::new("sudo")
        .arg("install")
        .arg("-m")
        .arg("755")
        .arg("-o")
        .arg("root")
        .arg("-g")
        .arg("root")
        .arg(src)
        .arg(&dst)
        .status()
        .expect("spawn sudo install");
    assert!(
        status.success(),
        "sudo install of {} to {} failed (status={:?})",
        src.display(),
        dst.display(),
        status.code()
    );
    InstalledBin { path: dst }
}

// ── bpffs cleanup ───────────────────────────────────────────────────

/// Wipe the entire PROTECTED_PIDS pin tree under [`BPFFS_ROOT`].
/// Run before every test (so a leftover from a prior aborted
/// run doesn't pollute the new test's view) AND after (so a
/// passing test doesn't leak state into a follow-on test).
fn purge_bpffs_root() {
    let _ = Command::new("sudo")
        .arg("rm")
        .arg("-rf")
        .arg(BPFFS_ROOT)
        .status();
}

// ── cargo-provided binary paths ─────────────────────────────────────

// The agent's: `agent_state::InstalledAgent::install` (the sibling
// package's release output, which `CARGO_BIN_EXE_<name>` does not give
// this crate's tests).

fn watchdog_bin_src() -> &'static str {
    env!("CARGO_BIN_EXE_northnarrow-watchdog")
}

/// Path of the agent's combat-rules.v4 in the repo tree. Each
/// test copies it into its tempdir so the agent loads a stable
/// shape regardless of operator overrides.
fn combat_rules_src() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}

// ── per-test fixture ────────────────────────────────────────────────

/// Per-test tempdir + agent + watchdog install. Drop tears
/// everything down: kills running processes (SIGINT then
/// SIGQUIT then SIGKILL escalation), removes the
/// /usr/local/bin/ installs, purges the bpffs root, tempdir
/// auto-removes its contents.
struct E2eFixture {
    tempdir: tempfile::TempDir,
    agent_install: Option<InstalledAgent>,
    watchdog_install: Option<InstalledBin>,
    agent_child: Option<Child>,
    watchdog_child: Option<Child>,
}

impl E2eFixture {
    fn setup() -> Self {
        // Start from a clean bpffs slate.
        purge_bpffs_root();
        // Lot 370 (the re-check of #578): the agent registers
        // /etc/northnarrow (and the state directory's detections/) only if
        // it exists at its start, and the next start is refused when the
        // directories it protects are not the previous agent's ("not the
        // ones the previous agent protected"): on a guest without them, a
        // respawned agent that made them refused every later test's agent.
        // Made first, as the agent suites' fixtures make them.
        let _ = Command::new("sudo")
            .args([
                "mkdir",
                "-p",
                "/etc/northnarrow",
                "/var/lib/northnarrow/detections",
            ])
            .status();
        Self {
            tempdir: tempfile::tempdir().expect("create tempdir"),
            agent_install: Some(InstalledAgent::install()),
            watchdog_install: Some(install_to_priv_bin(Path::new(watchdog_bin_src()))),
            agent_child: None,
            watchdog_child: None,
        }
    }

    fn tempdir_path(&self) -> &Path {
        self.tempdir.path()
    }

    fn agent_priv_path(&self) -> &Path {
        self.agent_install.as_ref().unwrap().agent_exe()
    }

    fn watchdog_priv_path(&self) -> &Path {
        &self.watchdog_install.as_ref().unwrap().path
    }

    /// Lab PR 256: every file the agent writes, its key and its id in the
    /// tempdir. The agent had its socket, pid files and id there, and
    /// signed the installed agent's chains with the installed key.
    fn state(&self) -> AgentState {
        AgentState::new(self.tempdir_path())
    }

    fn agent_pidfile(&self) -> PathBuf {
        self.state().pid_file()
    }

    fn watchdog_pidfile(&self) -> PathBuf {
        self.state().watchdog_pidfile()
    }

    fn admin_socket(&self) -> PathBuf {
        self.state().admin_socket()
    }

    fn admin_pub_path(&self) -> PathBuf {
        self.state().admin_pub()
    }

    fn agent_id_path(&self) -> PathBuf {
        self.state().agent_id_file()
    }

    fn combat_rules_path(&self) -> PathBuf {
        self.tempdir_path().join("combat-rules.v4")
    }

    fn shutdown_marker_path(&self) -> PathBuf {
        self.state().shutdown_marker()
    }

    /// Spawn the real agent with per-test tempdir paths. Agent
    /// loads its eBPF object (pins PROTECTED_PIDS under
    /// /sys/fs/bpf/northnarrow/), opens admin socket, writes
    /// pidfile. Returns when the pidfile is observable (the
    /// agent's own readiness signal).
    fn spawn_agent(&mut self) -> u32 {
        self.spawn_agent_with(&[])
    }

    /// [`Self::spawn_agent`] with `extra` arguments after the fixture's.
    fn spawn_agent_with(&mut self, extra: &[&std::ffi::OsStr]) -> u32 {
        // Seed admin.pub with one fresh keypair just so AdminAuth::load
        // doesn't reject an empty file. Tests don't actually use the
        // key — they only need the agent's anti_tamper bring-up.
        // Generate via openssl-equivalent: 32 random bytes as a
        // hex-encoded ed25519 public key shape.
        // A test that signs shutdowns writes its own keys first.
        if !self.admin_pub_path().exists() {
            let dummy_pub = "00".repeat(32);
            fs::write(self.admin_pub_path(), format!("{dummy_pub}\n")).expect("write admin.pub");
        }
        fs::copy(combat_rules_src(), self.combat_rules_path()).expect("copy combat-rules");

        let child = self
            .agent_install
            .as_ref()
            .unwrap()
            .command(&self.state(), Launch::Sudo, &[])
            .arg("--combat-rules")
            .arg(self.combat_rules_path())
            // External audit MAIN-001 / ATP-002: the agent protects only
            // a watchdog running the binary it expects — here the test's.
            .arg("--watchdog-exe")
            .arg(self.watchdog_priv_path())
            .args(extra)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("sudo spawn agent");
        self.agent_child = Some(child);

        // Poll for pidfile readiness (agent writes it AFTER all
        // anti-tamper attach completes — solid readiness signal). 30 s,
        // like the respawn waits: a cold boot on the lab guest was seen
        // to take 15.07 s (a slow blocklist load after the hooks).
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(s) = fs::read_to_string(self.agent_pidfile()) {
                if let Ok(pid) = s.trim().parse::<u32>() {
                    return pid;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "agent pidfile {} never appeared within 30s",
            self.agent_pidfile().display()
        );
    }

    /// Spawn the watchdog pointed at the agent's pidfile +
    /// admin socket + the canonical bpffs root.
    fn spawn_watchdog(&mut self) {
        let child = Command::new("sudo")
            .arg(self.watchdog_priv_path())
            // The agent's pid file and socket, this watchdog's pid file
            // (the one the agent looks for), and — external audit WDG-001
            // — the marker, and the keys and install id it is verified
            // against: the agent's state, all in this test's directory.
            .args(self.state().watchdog_args())
            .arg("--bpffs-root")
            .arg(BPFFS_ROOT)
            // --agent-bin: skip /proc/<pid>/exe readlink. The agent's
            // ptrace_access_check LSM hook denies the readlink until
            // the watchdog's PID is in PROTECTED_PIDS, and the agent's
            // W6 watchdog-pidfile poll only catches the watchdog
            // AFTER it's already booted past this point. Production
            // systemd ExecStart pins the binary path the same way.
            // Respawn v2 picks the systemd backend on a booted systemd
            // host; this fixture's agent is NOT the installed unit, so
            // force the fork-exec backend (the one the test exercises).
            .arg("--respawn-backend")
            .arg("exec")
            .arg("--agent-bin")
            .arg(self.agent_priv_path())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("sudo spawn watchdog");
        self.watchdog_child = Some(child);

        // Poll for watchdog pidfile (its W2 boot sequence writes
        // it after pidfd_open succeeds + sd_notify).
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if fs::read_to_string(self.watchdog_pidfile())
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .is_some()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "watchdog pidfile {} never appeared within 15s",
            self.watchdog_pidfile().display()
        );
    }

    /// Force-kill the agent: delete its PID from PROTECTED_PIDS
    /// (race-free unprotect — without this the LSM hook denies
    /// the SIGKILL), then SIGKILL.
    fn unprotect_and_sigkill_agent(&self, agent_pid: u32) {
        self.unprotect_and_signal_agent(agent_pid, "-9");
    }

    /// [`Self::unprotect_and_sigkill_agent`] with any `kill` signal flag.
    fn unprotect_and_signal_agent(&self, agent_pid: u32, signal: &str) {
        // Unprotect, then SIGKILL — and RETRY. The watchdog performs a
        // "defensive PROTECTED_PIDS reinsert" right after it observes
        // the new pidfile, i.e. at the very moment this test also sees
        // the pid: a single `bpftool map delete` + `kill -9` raced that
        // reinsert on the lab guest (`kill: Operation not permitted`,
        // the respawned agent survived, "cycle 2: watchdog never
        // respawned agent"). The watchdog reinserts once per respawn, so
        // the second attempt wins; bound the loop so a genuine kill
        // denial still fails the test loudly.
        let key_bytes = format!(
            "{} {} {} {}",
            agent_pid & 0xFF,
            (agent_pid >> 8) & 0xFF,
            (agent_pid >> 16) & 0xFF,
            (agent_pid >> 24) & 0xFF,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            // Unprotect: bpftool map delete pinned <map> key <le_u32>
            let _ = Command::new("sudo")
                .arg("bpftool")
                .arg("map")
                .arg("delete")
                .arg("pinned")
                .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
                .arg("key")
                .args(key_bytes.split_whitespace())
                .stderr(Stdio::null())
                .status();
            // SAFETY: kill(2) on a known PID with SIGKILL is a
            // trivial syscall; we already have root (the test
            // launched the agent under sudo).
            let killed = Command::new("sudo")
                .arg("kill")
                .arg(signal)
                .arg(agent_pid.to_string())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if killed {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "could not signal ({signal}) agent pid {agent_pid} after {attempts} attempts in \
                 10 s: the task_kill hook keeps denying it (PROTECTED_PIDS eviction not taking \
                 effect?)"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// Remove `pid` and every process below it from the pinned
/// PROTECTED_PIDS map. Since `task-kill-signals-1` the task_kill hook
/// refuses EVERY userspace signal towards a protected pid unless the
/// caller is itself, another protected pid or PID 1 with the nonce; the
/// test runner is none of those, and the fixtures spawn through `sudo`
/// (so `Child::id()` is sudo and the agent is its child). Evicting the
/// subtree first lets the SIGQUIT/SIGTERM below reach the processes.
fn unprotect_tree(pid: u32) -> Vec<u32> {
    let mut todo = vec![pid];
    let mut seen: Vec<u32> = Vec::new();
    while let Some(p) = todo.pop() {
        if seen.contains(&p) {
            continue;
        }
        seen.push(p);
        if let Ok(out) = Command::new("pgrep").args(["-P", &p.to_string()]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Ok(c) = line.trim().parse::<u32>() {
                    todo.push(c);
                }
            }
        }
    }
    for &p in &seen {
        let key = [
            p & 0xFF,
            (p >> 8) & 0xFF,
            (p >> 16) & 0xFF,
            (p >> 24) & 0xFF,
        ]
        .map(|b| b.to_string());
        let _ = Command::new("sudo")
            .args(["bpftool", "map", "delete", "pinned"])
            .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
            .arg("key")
            .args(key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    seen
}

impl Drop for E2eFixture {
    fn drop(&mut self) {
        // Stop watchdog first (so it doesn't try to respawn the
        // agent mid-cleanup). The watchdog's bindsTo is per-unit;
        // for ad-hoc test spawn we kill it directly.
        // `w.id()` is the sudo pid and sudo 1.9.9 does not relay our
        // signal (see the agent branch below), so every pid of the
        // subtree is signalled directly, leaves first: the agent the
        // watchdog respawned (SIGTERM reaches it once unprotected),
        // then the watchdog. The agent re-registers the watchdog in
        // PROTECTED_PIDS while alive, so unprotect + kill is retried
        // until the kill is accepted, within a 10 s budget.
        if let Some(mut w) = self.watchdog_child.take() {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                for p in unprotect_tree(w.id()).iter().rev() {
                    let _ = Command::new("sudo")
                        .arg("kill")
                        .arg("-TERM")
                        .arg(p.to_string())
                        .stderr(Stdio::null())
                        .status();
                }
                if matches!(w.try_wait(), Ok(Some(_))) || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if let Ok(None) = w.try_wait() {
                eprintln!(
                    "E2eFixture: watchdog sudo pid {} still alive 10 s after SIGTERM — leaving it",
                    w.id()
                );
            }
        }
        // Then the agent. SIGTERM is hook-blocked; use SIGQUIT
        // which is the documented escape hatch. `a.id()` is the sudo
        // pid: signal every pid of its subtree ourselves (leaves
        // first) because sudo 1.9.9 (Ubuntu 22.04) does not relay a
        // signal sent from its own process group, and bound the wait
        // so a teardown problem fails loudly instead of wedging the
        // suite (it hung every teardown on the 5.15 lab guest).
        if let Some(mut a) = self.agent_child.take() {
            let tree = unprotect_tree(a.id());
            // SIGCONT first: a test that stopped the agent
            // (`a_removed_admin_socket_is_rebound_and_a_stopped_agent_recovered`)
            // leaves its sudo stopped too — sudo stops itself when its
            // command stops — and a stopped process keeps SIGQUIT pending:
            // it stayed, holding the runner's stdout, and the lab gate
            // never got past this suite.
            for p in tree.iter().rev() {
                for sig in ["-CONT", "-QUIT"] {
                    let _ = Command::new("sudo")
                        .arg("kill")
                        .arg(sig)
                        .arg(p.to_string())
                        .stderr(Stdio::null())
                        .status();
                }
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = a.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if let Ok(None) = a.try_wait() {
                eprintln!(
                    "E2eFixture: sudo pid {} still alive 10 s after SIGQUIT — leaving it",
                    a.id()
                );
            }
        }
        // Kill any watchdog-respawned agent we never tracked as
        // a Child (W4 cycles): match on the install basename
        // (`<bin>-e2etest-<ts>-<pid>`) and SIGQUIT all of them.
        // Without this, a respawned agent can survive past the
        // test's teardown, observe unrelated host activity, and
        // transition POSTURE→COMBAT — which on a dev host can
        // start applying iptables rules. pkill -QUIT is harmless
        // when nothing matches.
        if let Some(install) = &self.agent_install {
            if let Some(basename) = install.agent_exe().file_name().and_then(|s| s.to_str()) {
                if let Ok(out) = Command::new("pgrep").args(["-f", basename]).output() {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        if let Ok(p) = line.trim().parse::<u32>() {
                            unprotect_tree(p);
                        }
                    }
                }
                for sig in ["-CONT", "-QUIT"] {
                    let _ = Command::new("sudo")
                        .arg("pkill")
                        .arg(sig)
                        .arg("-f")
                        .arg(basename)
                        .status();
                }
            }
        }
        // Purge bpffs so the next test starts clean.
        purge_bpffs_root();
        // InstalledBin drops handle /usr/local/bin/ cleanup.
        // Tempdir drops handle pidfile/socket/config cleanup.
    }
}

// ── PROTECTED_PIDS introspection ────────────────────────────────────

/// `bpftool map dump pinned …` parsed for the set of keys
/// present. Empty when the map is absent or unreadable. Tests
/// use this to assert PROTECTED_PIDS membership without
/// linking aya directly into the test binary.
fn dump_protected_pids() -> Vec<u32> {
    let out = match Command::new("sudo")
        .arg("bpftool")
        .arg("map")
        .arg("dump")
        .arg("pinned")
        .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
        .arg("-j")
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    if !out.status.success() {
        return Vec::new();
    }
    // bpftool -j output for a HashMap<u32, u8> is
    //   [{"key":["0x15","0xc9","0x00","0x00"],"value":["0x01"]}, ...]
    // The four key bytes are little-endian, quoted, and hex-formatted
    // ("0x" prefix). We extract them by string-match rather than
    // dragging in serde_json — the format is stable and trivially
    // grepped.
    let body = String::from_utf8_lossy(&out.stdout);
    let mut pids = Vec::new();
    let mut idx = 0;
    while let Some(start) = body[idx..].find(r#""key":["#) {
        let abs = idx + start + r#""key":["#.len();
        if let Some(end) = body[abs..].find(']') {
            let inner = &body[abs..abs + end];
            let bytes: Vec<u8> = inner
                .split(',')
                .filter_map(|s| {
                    let t = s.trim().trim_matches('"');
                    let t = t.strip_prefix("0x").unwrap_or(t);
                    u8::from_str_radix(t, 16).ok()
                })
                .collect();
            if bytes.len() == 4 {
                let pid = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                pids.push(pid);
            }
            idx = abs + end;
        } else {
            break;
        }
    }
    pids
}

/// The bytes of `value` in a `bpftool … -j` record (`"value":["0x00",…]`).
fn json_bytes(body: &str, field: &str) -> Option<Vec<u8>> {
    let tag = format!("\"{field}\":[");
    let at = body.find(&tag)? + tag.len();
    let end = body[at..].find(']')?;
    Some(
        body[at..at + end]
            .split(',')
            .filter_map(|s| {
                let t = s.trim().trim_matches('"');
                u8::from_str_radix(t.strip_prefix("0x").unwrap_or(t), 16).ok()
            })
            .collect(),
    )
}

/// The watchdog's slot (0) of the pinned `ROLE_TGIDS`: `None` when the map
/// is not pinned (a boot's first claim).
fn watchdog_role_slot() -> Option<u32> {
    let out = Command::new("sudo")
        .args(["bpftool", "map", "lookup", "pinned"])
        .arg(format!("{BPFFS_ROOT}/ROLE_TGIDS"))
        .args(["key", "0", "0", "0", "0", "-j"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = json_bytes(&String::from_utf8_lossy(&out.stdout), "value")?;
    (v.len() == 4).then(|| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

/// Lot 370 (F10-4; the re-check of #578): the watchdog's role as at a
/// boot — its slot of the pinned `ROLE_TGIDS` never held (0) — so the
/// watchdog a test starts is the role's first claim. The suite's earlier
/// tests leave the slot vacated (`ROLE_VACATED`: their watchdogs exited, and
/// the fixture's purge of the pins is refused while the hooks guard them);
/// a watchdog started from the test's shell into a vacated role is not one
/// started for it (its parent is neither PID 1 nor the live agent), and its
/// handles are then a foreign process's: NN-L-BPF-002 High, by design. In
/// observe mode root writes the map (the write is recorded as the foreign
/// write it is). The slot read back.
fn establish_first_claim_of_the_watchdog_role() -> Option<u32> {
    let _ = Command::new("sudo")
        .args(["bpftool", "map", "update", "pinned"])
        .arg(format!("{BPFFS_ROOT}/ROLE_TGIDS"))
        .args(["key", "0", "0", "0", "0", "value", "0", "0", "0", "0"])
        .stderr(Stdio::null())
        .status();
    watchdog_role_slot()
}

// ── Test 1: W3 layer-2 evict ────────────────────────────────────────

/// **Required W3 privileged integration:** the watchdog evicts
/// the agent's PID from PROTECTED_PIDS on pidfd POLLIN. Spawns
/// real agent + watchdog, force-kills the agent (unprotect +
/// SIGKILL), asserts the PID disappears from PROTECTED_PIDS
/// within 5 s.
///
#[test]
fn watchdog_evicts_agent_pid_on_pidfd_pollin() {
    let mut fx = E2eFixture::setup();
    let agent_pid = fx.spawn_agent();
    fx.spawn_watchdog();

    // Sanity: PROTECTED_PIDS should contain the agent PID.
    let pids = dump_protected_pids();
    assert!(
        pids.contains(&agent_pid),
        "PROTECTED_PIDS missing agent_pid {agent_pid}; map = {pids:?}"
    );

    // Force-kill the agent.
    fx.unprotect_and_sigkill_agent(agent_pid);

    // Wait for watchdog's layer-2 evict. Generous 5 s budget;
    // typical wakeup→evict latency is sub-millisecond per W3
    // unit tests, but the test runs under sudo + parallel
    // workload so we give it slack.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_pids = Vec::new();
    while Instant::now() < deadline {
        let pids = dump_protected_pids();
        if !pids.contains(&agent_pid) {
            // SUCCESS. The watchdog may have already
            // re-inserted a new agent PID (W4 respawn) — we
            // only care that the OLD pid is gone.
            return;
        }
        last_pids = pids;
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "watchdog did not evict agent_pid {agent_pid} from PROTECTED_PIDS within 5s; \
         last map snapshot = {last_pids:?}"
    );
}

// ── Test 2: W4 3-restart cycle ──────────────────────────────────────

/// **Required W4 privileged integration:** the watchdog respawns
/// the agent through 3 kill cycles, observing 3 distinct PIDs.
/// Verifies the W4 backoff state machine + reinsert path under
/// real BPF conditions.
#[test]
fn watchdog_respawns_agent_3_cycles_with_backoff() {
    let mut fx = E2eFixture::setup();
    let pid0 = fx.spawn_agent();
    fx.spawn_watchdog();

    let mut seen_pids = vec![pid0];
    for cycle in 1..=3 {
        let last_pid = *seen_pids.last().unwrap();
        fx.unprotect_and_sigkill_agent(last_pid);

        // Wait for the watchdog to spawn a new agent + the new
        // agent to publish its pidfile. 30 s budget per cycle: the
        // agent BPF load is slow on a cold cache, and the first cycle
        // right after a release rebuild on the lab guest was seen to
        // overrun the previous 15 s (watchdog backoff + BTF parse).
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut new_pid: Option<u32> = None;
        while Instant::now() < deadline {
            if let Ok(s) = fs::read_to_string(fx.agent_pidfile()) {
                if let Ok(pid) = s.trim().parse::<u32>() {
                    if pid != last_pid {
                        new_pid = Some(pid);
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let new_pid =
            new_pid.unwrap_or_else(|| panic!("cycle {cycle}: watchdog never respawned agent"));
        seen_pids.push(new_pid);
    }

    // Assert: 4 distinct PIDs across the original + 3 respawns.
    let unique: std::collections::HashSet<u32> = seen_pids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        seen_pids.len(),
        "expected 4 distinct PIDs (orig + 3 respawns), got: {seen_pids:?}"
    );

    // Final agent PID is in PROTECTED_PIDS (W4 reinsert path).
    let final_pid = *seen_pids.last().unwrap();
    let pids = dump_protected_pids();
    assert!(
        pids.contains(&final_pid),
        "final agent PID {final_pid} not in PROTECTED_PIDS: {pids:?}"
    );

    // External audit WDG-010 (NN-AUD-360): the agents the exec backend
    // respawned (cycles 1 and 2 killed two of them) were never waited for
    // and stayed zombie children of the watchdog. Each is collected before
    // the next respawn, so none is left once the new pidfile appeared.
    let watchdog_pid = fs::read_to_string(fx.watchdog_pidfile())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .expect("watchdog pidfile");
    let zombies = zombie_children_of(watchdog_pid);
    assert!(
        zombies.is_empty(),
        "zombie children of the watchdog (pid {watchdog_pid}): {zombies:?}"
    );
}

/// Lot 297 (external bug hunt BUG58, BUG67): the exec backend respawns the
/// agent with its first launch's argv byte for byte — an empty argument
/// and one that is not UTF-8 included. The empty one was dropped (the
/// respawned agent's parser refused `--ade-prompt --ade-model …` and it
/// never came back) and the other rewritten with U+FFFD. The two removed
/// advisor flags take any value and are ignored with a WARN. The lab's
/// first run of this test found the agent itself aborting at the start on
/// the non-UTF-8 argument (its self-integrity check read
/// `std::env::args()`): fixed with it.
#[test]
fn a_respawned_agent_has_its_first_launchs_argv_byte_for_byte() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let non_utf8 = std::ffi::OsString::from_vec(b"/nonexistent/mod\xe8le".to_vec());
    let mut fx = E2eFixture::setup();
    let pid0 = fx.spawn_agent_with(&[
        std::ffi::OsStr::new("--ade-prompt"),
        std::ffi::OsStr::new(""),
        std::ffi::OsStr::new("--ade-model"),
        &non_utf8,
    ]);
    let cmdline = |pid: u32| -> Vec<u8> {
        let out = Command::new("sudo")
            .arg("cat")
            .arg(format!("/proc/{pid}/cmdline"))
            .output()
            .expect("sudo cat");
        out.stdout
    };
    let first = cmdline(pid0);
    let mut tail = b"--ade-prompt\0\0--ade-model\0".to_vec();
    tail.extend_from_slice(non_utf8.as_bytes());
    tail.push(0);
    assert!(
        first.ends_with(&tail),
        "the first launch's argv: {:?}",
        String::from_utf8_lossy(&first)
    );
    fx.spawn_watchdog();
    fx.unprotect_and_sigkill_agent(pid0);
    let new_pid = new_agent_pid(&fx, pid0, Duration::from_secs(30)).unwrap_or_else(|| {
        panic!("the watchdog never respawned the agent (an argv its parser refused?)")
    });
    let again = cmdline(new_pid);
    assert_eq!(
        again,
        first,
        "respawn argv {:?}, first launch {:?}",
        String::from_utf8_lossy(&again),
        String::from_utf8_lossy(&first)
    );
}

/// Pids in state `Z` whose parent is `ppid` (`/proc/<pid>/stat`: the
/// fields after the parenthesised comm are state, then ppid).
fn zombie_children_of(ppid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut f = rest.split_whitespace();
        let (state, parent) = (f.next(), f.next().and_then(|p| p.parse::<u32>().ok()));
        if state == Some("Z") && parent == Some(ppid) {
            out.push(pid);
        }
    }
    out
}

// ── External audit WDG-007: a removed admin socket ─────────────────

/// External audit WDG-007 (NN-AUD-358): root could remove the agent's
/// admin socket and then stop the agent (here SIGSTOP after unprotecting
/// it; on a host, a cgroup freeze): the watchdog read the missing socket as
/// "never came up" and never recovered the agent. Now (1) a running agent
/// binds its socket again within one check (10 s), and (2) once the agent
/// answered, a socket that stays away is reported (a `watchdog.hold` line,
/// reason `admin_socket_vanished`) and, on the third ping without it, the
/// agent is recovered like a hang: a new agent runs.
#[test]
fn a_removed_admin_socket_is_rebound_and_a_stopped_agent_recovered() {
    let mut fx = E2eFixture::setup();
    let pid0 = fx.spawn_agent();
    fx.spawn_watchdog();
    let watchdog_started = Instant::now();
    let socket = fx.admin_socket();
    let ino = |p: &Path| {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(p).ok().map(|m| m.ino())
    };

    // (1) A running agent binds it again. Its first bind is waited for: the
    // agent opens its admin plane late in its boot (seconds on a slow guest:
    // the Debian 12 gate of lab PRs 167-171 read it too early).
    let bound_by = Instant::now() + Duration::from_secs(30);
    let first = loop {
        if let Some(i) = ino(&socket) {
            break i;
        }
        assert!(
            Instant::now() < bound_by,
            "admin socket bound by the agent within 30 s"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let removed = Command::new("sudo")
        .args(["rm", "-f"])
        .arg(&socket)
        .status()
        .expect("sudo rm");
    assert!(removed.success());
    let deadline = Instant::now() + Duration::from_secs(20);
    let again = loop {
        if let Some(i) = ino(&socket) {
            break i;
        }
        assert!(
            Instant::now() < deadline,
            "the agent did not bind its admin socket again within 20 s"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_ne!(again, first, "a new socket file");

    // (2) The watchdog's first ping (30 s after its start) is answered;
    // then the agent stops and its socket goes.
    let answered_by = watchdog_started + Duration::from_secs(38);
    if let Some(wait) = answered_by.checked_duration_since(Instant::now()) {
        std::thread::sleep(wait);
    }
    fx.unprotect_and_signal_agent(pid0, "-STOP");
    let removed = Command::new("sudo")
        .args(["rm", "-f"])
        .arg(&socket)
        .status()
        .expect("sudo rm");
    assert!(removed.success());
    // Three pings 30 s apart, SIGINT + 5 s grace + SIGKILL, the respawn's
    // pidfile wait: under 3 minutes.
    let new_pid = new_agent_pid(&fx, pid0, Duration::from_secs(180)).unwrap_or_else(|| {
        panic!("the stopped agent {pid0} without its admin socket was never recovered")
    });
    assert_ne!(new_pid, pid0);
    let holds = fx.tempdir_path().join("watchdog.hold");
    let out = Command::new("sudo")
        .arg("cat")
        .arg(&holds)
        .output()
        .expect("sudo cat");
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"reason\":\"admin_socket_vanished\""),
        "no admin_socket_vanished record in {}: {body}",
        holds.display()
    );
}

/// The agent pid the pidfile names once it differs from `old`, or `None`
/// after `within`.
fn new_agent_pid(fx: &E2eFixture, old: u32, within: Duration) -> Option<u32> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(s) = fs::read_to_string(fx.agent_pidfile()) {
            if let Ok(pid) = s.trim().parse::<u32>() {
                if pid != old && Path::new(&format!("/proc/{pid}")).exists() {
                    return Some(pid);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// External audit WDG-004: past the restart ceiling (5 respawns in 60 s)
/// the watchdog used to exit 0 — no restart by systemd, no failed unit,
/// agent and watchdog gone. It now holds: alive, not respawning, until
/// an agent is started again, which it then supervises.
#[test]
fn watchdog_holds_after_the_restart_ceiling() {
    let mut fx = E2eFixture::setup();
    let mut pid = fx.spawn_agent();
    fx.spawn_watchdog();
    let watchdog: u32 = fs::read_to_string(fx.watchdog_pidfile())
        .expect("watchdog pidfile")
        .trim()
        .parse()
        .expect("watchdog pid");

    // Kill every agent the watchdog brings back until it stops doing so.
    let mut respawns = 0;
    loop {
        fx.unprotect_and_sigkill_agent(pid);
        match new_agent_pid(&fx, pid, Duration::from_secs(30)) {
            Some(next) => {
                respawns += 1;
                assert!(respawns <= 8, "the restart ceiling never tripped");
                pid = next;
            }
            None => break,
        }
    }
    assert!(respawns >= 5, "held after only {respawns} respawns");
    assert!(
        Path::new(&format!("/proc/{watchdog}")).exists(),
        "the watchdog must stay alive past the ceiling"
    );

    // An agent started by hand: supervised again, with a fresh window.
    let manual = fx.spawn_agent();
    std::thread::sleep(Duration::from_secs(5));
    fx.unprotect_and_sigkill_agent(manual);
    assert!(
        new_agent_pid(&fx, manual, Duration::from_secs(30)).is_some(),
        "the watchdog must resume supervision once an agent runs again"
    );
}

/// External audit WDG-001 / TST-003: a shutdown marker that is not
/// signed by the admin quorum — the shape any root process could write
/// before — no longer stands the watchdog down. The agent is respawned,
/// and the refusal is recorded for the agent's signed audit chain.
#[test]
fn a_forged_shutdown_marker_is_refused_and_the_agent_respawned() {
    let mut fx = E2eFixture::setup();
    let pid = fx.spawn_agent();
    fx.spawn_watchdog();
    fs::write(
        fx.shutdown_marker_path(),
        format!(
            r#"{{"entry_hash":"{}","grace_deadline_unix_ts":99999999999}}"#,
            "ab".repeat(32)
        ),
    )
    .expect("write forged marker");
    fx.unprotect_and_sigkill_agent(pid);
    assert!(
        new_agent_pid(&fx, pid, Duration::from_secs(30)).is_some(),
        "a forged marker must not stop the respawn"
    );
    assert!(
        !fx.shutdown_marker_path().exists(),
        "the forged marker is removed"
    );
    let rejected = fs::read_to_string(fx.tempdir_path().join("agent.shutdown_rejected"))
        .expect("the refusal is recorded");
    assert!(
        rejected.contains(&format!(r#""agent_pid":{pid}"#)),
        "{rejected}"
    );
}

/// External audit TST-003: a shutdown the admin quorum signed for the
/// agent that exits stands the watchdog down — no respawn — and the
/// authorisation is recorded so it cannot be presented again.
#[test]
fn a_quorum_signed_shutdown_marker_stands_the_watchdog_down() {
    use nn_proto::admin_signed_payload::{sign, SignedPayload};
    use nn_proto::shutdown_marker::ShutdownMarker;

    let mut fx = E2eFixture::setup();
    let a = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let b = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
    fs::write(
        fx.admin_pub_path(),
        format!(
            "{} shutdown\n{} unlock\n",
            hex::encode(a.verifying_key().to_bytes()),
            hex::encode(b.verifying_key().to_bytes())
        ),
    )
    .expect("write admin.pub");
    let pid = fx.spawn_agent();
    fx.spawn_watchdog();
    let agent_id = nn_proto::shutdown_marker::parse_agent_id(
        &fs::read_to_string(fx.agent_id_path()).expect("agent_id written at boot"),
    )
    .expect("agent_id");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = SignedPayload::new_shutdown([0x5A; 32], now, agent_id, 30);
    let sigs = [sign(&payload, &a).unwrap(), sign(&payload, &b).unwrap()];
    let marker = ShutdownMarker::new(&payload, &sigs, pid).unwrap();
    fs::write(fx.shutdown_marker_path(), marker.to_line()).expect("write marker");

    fx.unprotect_and_sigkill_agent(pid);
    let wd = fx.watchdog_child.as_mut().expect("watchdog child");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(st) = wd.try_wait().expect("try_wait") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "the watchdog did not stand down after an authorised shutdown"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success(), "stand-down exits 0: {status:?}");
    assert!(
        new_agent_pid(&fx, pid, Duration::from_secs(3)).is_none(),
        "no respawn after an authorised shutdown"
    );
    let honoured = fs::read_to_string(fx.tempdir_path().join("watchdog.honoured"))
        .expect("the authorisation is recorded");
    assert!(honoured.starts_with(&"5a".repeat(32)), "{honoured}");
}

// ── Test 3: W5 stuck-recovery on real BPF map ───────────────────────

/// **Required W5 privileged integration:** `stuck_recovery`
/// kills a SIGINT-ignoring subprocess via the escalation path
/// (SIGINT → grace → unprotect + SIGKILL) against a real
/// pinned PROTECTED_PIDS map.
///
/// Uses a `bash -c 'trap "" INT; sleep 60'` subprocess as the
/// stuck-agent stand-in: bash's trap eats SIGINT, sleep keeps
/// running, escalation fires after the short test-only
/// hardkill_grace.
#[test]
fn stuck_recovery_kills_sigint_ignoring_subprocess_via_real_bpf() {
    use northnarrow_watchdog::stuck_recovery;

    // Need a pinned PROTECTED_PIDS map for stuck_recovery to
    // open. The real agent sets it up — spawn just the agent
    // (no watchdog needed for this test; we call stuck_recovery
    // directly).
    let mut fx = E2eFixture::setup();
    let _agent_pid = fx.spawn_agent();

    // Sentinel: a `sleep` that ignores SIGINT (the disposition survives
    // the exec). External audit WDG-003: recovery checks the binary, so
    // the stand-in must BE `sleep` before it is signalled — wait for the
    // exec (bash itself may or may not exec its last command).
    let sleeper = Command::new("sh")
        .arg("-c")
        .arg("trap '' INT; exec sleep 60")
        .spawn()
        .expect("spawn sleeper subprocess");
    let sleeper_pid = sleeper.id();
    let sleep_bin = fs::canonicalize("/bin/sleep").expect("sleep binary");
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_link(format!("/proc/{sleeper_pid}/exe")).ok() != Some(sleep_bin.clone()) {
        assert!(Instant::now() < deadline, "the sentinel never exec'd sleep");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Insert the sleeper PID into PROTECTED_PIDS via bpftool so
    // we exercise the real evict path. Key is little-endian u32.
    let key_bytes = format!(
        "{} {} {} {}",
        sleeper_pid & 0xFF,
        (sleeper_pid >> 8) & 0xFF,
        (sleeper_pid >> 16) & 0xFF,
        (sleeper_pid >> 24) & 0xFF,
    );
    let status = Command::new("sudo")
        .arg("bpftool")
        .arg("map")
        .arg("update")
        .arg("pinned")
        .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
        .arg("key")
        .args(key_bytes.split_whitespace())
        .arg("value")
        .arg("1")
        .status()
        .expect("spawn bpftool map update");
    assert!(
        status.success(),
        "bpftool map update for sleeper PID failed"
    );

    // Call stuck_recovery with a SHORT hardkill_grace so the
    // test runs fast — production default is 5s; 200ms is
    // enough to prove the SIGINT path (subprocess ignored it)
    // before escalation fires.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // This test process plays the watchdog: since task-kill-signals-1
    // only a PROTECTED caller may signal a protected pid, so register
    // ourselves the way the real watchdog does at boot (and evict below).
    let own = std::process::id();
    let own_key = format!(
        "{} {} {} {}",
        own & 0xFF,
        (own >> 8) & 0xFF,
        (own >> 16) & 0xFF,
        (own >> 24) & 0xFF
    );
    let st = Command::new("sudo")
        .args(["bpftool", "map", "update", "pinned"])
        .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
        .arg("key")
        .args(own_key.split_whitespace())
        .args(["value", "1"])
        .status()
        .expect("spawn bpftool");
    assert!(st.success(), "bpftool map update for own PID failed");
    // External audit WDG-003: recovery signals only a process running
    // the expected binary — here the `sleep` stand-in.
    let result = runtime.block_on(stuck_recovery(
        sleeper_pid,
        Path::new(BPFFS_ROOT),
        Duration::from_millis(200),
        &sleep_bin,
    ));
    let _ = Command::new("sudo")
        .args(["bpftool", "map", "delete", "pinned"])
        .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
        .arg("key")
        .args(own_key.split_whitespace())
        .status();
    assert!(
        result.is_ok(),
        "stuck_recovery failed: {:?}",
        result.unwrap_err()
    );

    // Assert: sleeper is dead. wait() reaps it; the child
    // handle's exit status confirms it was killed.
    let mut sleeper = sleeper; // shadowing for mut access
    let exit = sleeper
        .try_wait()
        .expect("try_wait should not fail post-recovery");
    assert!(
        exit.is_some(),
        "sleeper {sleeper_pid} should be reaped after stuck_recovery"
    );

    // Assert: sleeper PID no longer in PROTECTED_PIDS (W5's
    // evict path inside stuck_recovery removed it).
    let pids = dump_protected_pids();
    assert!(
        !pids.contains(&sleeper_pid),
        "sleeper {sleeper_pid} should be evicted from PROTECTED_PIDS: {pids:?}"
    );
}

// ── Test 4: PHASE_D_002 ptrace_access_check caller-side exemption ──

/// **PHASE_D_002 verification:** ptrace_access_check exempts
/// callers whose own tgid is in PROTECTED_PIDS (mutual whitelist,
/// symmetric to W6's target-side protection). Reads
/// `/proc/<agent_pid>/exe` from the test process — which goes
/// through `proc_pid_readlink` → `ptrace_may_access` →
/// `security_ptrace_access_check` → the agent's BPF program. The
/// readlink must succeed when the caller (test pid) is in
/// PROTECTED_PIDS, and fail with EPERM when it isn't.
///
/// This is the BPF-side proof that the W8 `--agent-bin` flag is
/// no longer load-bearing for *correctness* — only kept as
/// defense-in-depth + a clean operator override.
#[test]
fn ptrace_access_check_exempts_caller_in_protected_pids() {
    let mut fx = E2eFixture::setup();
    let agent_pid = fx.spawn_agent();
    let test_pid = std::process::id();

    // Baseline: caller (this test process) NOT in PROTECTED_PIDS.
    // readlink /proc/<agent_pid>/exe must fail because the agent
    // is in PROTECTED_PIDS and the BPF hook denies any unprotected
    // caller. The kernel surface errno can be either EPERM (1, the
    // LSM verdict directly) or EACCES (13, when an earlier
    // `inode_permission` check on the /proc/<pid>/exe symlink
    // trips before the LSM hook); both indicate "denied".
    let exe_path = format!("/proc/{agent_pid}/exe");
    let baseline = std::fs::read_link(&exe_path);
    assert!(
        baseline.is_err(),
        "PROTECTED_PIDS-target readlink should fail for unprotected caller; \
         got {baseline:?} (PHASE_D_002 baseline)"
    );
    let baseline_errno = baseline.unwrap_err().raw_os_error();
    assert!(
        matches!(baseline_errno, Some(1) | Some(13)),
        "expected EPERM (1) or EACCES (13), got errno={baseline_errno:?}"
    );

    // Insert the test process's tgid into PROTECTED_PIDS via
    // bpftool. Key is little-endian u32. Now the test process is
    // a "protected" caller and the BPF program's PHASE_D_002
    // mutual-whitelist branch should allow the readlink through.
    let key_bytes = format!(
        "{} {} {} {}",
        test_pid & 0xFF,
        (test_pid >> 8) & 0xFF,
        (test_pid >> 16) & 0xFF,
        (test_pid >> 24) & 0xFF,
    );
    let status = Command::new("sudo")
        .arg("bpftool")
        .arg("map")
        .arg("update")
        .arg("pinned")
        .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
        .arg("key")
        .args(key_bytes.split_whitespace())
        .arg("value")
        .arg("1")
        .status()
        .expect("spawn bpftool map update");
    assert!(
        status.success(),
        "bpftool map update for test pid {test_pid} failed"
    );

    // Same readlink, same target — must now succeed because the
    // caller (test_pid) is in PROTECTED_PIDS. If this still EPERMs,
    // the PHASE_D_002 BPF caller-exemption is broken.
    let post = std::fs::read_link(&exe_path);
    // Evict the test pid before any panic so a failed assert
    // doesn't leave a stray protected PID across the fixture
    // teardown.
    let _ = Command::new("sudo")
        .arg("bpftool")
        .arg("map")
        .arg("delete")
        .arg("pinned")
        .arg(format!("{BPFFS_ROOT}/PROTECTED_PIDS"))
        .arg("key")
        .args(key_bytes.split_whitespace())
        .status();
    assert!(
        post.is_ok(),
        "ptrace_access_check should EXEMPT caller in PROTECTED_PIDS, but readlink \
         /proc/{agent_pid}/exe returned {post:?} (PHASE_D_002 regression)"
    );
}

// ── Lot 344: the watchdog's own start is not a foreign BPF handle ────

/// The detection records whose principal is `pid` and whose rule is
/// `rule` (the agent's detections file, read through `sudo`: the agent
/// writes it as root), whole.
fn records_of(path: &Path, rule: &str, pid: u32) -> Vec<String> {
    let out = Command::new("sudo")
        .arg("cat")
        .arg(path)
        .output()
        .expect("sudo cat the detections file");
    let pid_field = format!("\"pid\":{pid},");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(rule) && l.contains(&pid_field))
        .map(str::to_string)
        .collect()
}

/// The first 400 characters of each record, for a message.
fn heads(records: &[&String]) -> Vec<String> {
    records
        .iter()
        .map(|l| l.chars().take(400).collect())
        .collect()
}

/// Lot 374 (the witness record when the agent dies): the watchdog, the
/// surviving role, signs each vacancy of the agent's role and the process
/// that takes it in its own chain — never the successor's to write — and
/// the next agent imports the rows into its signed audit log. The first
/// agent is the test's (no wait of the watchdog's: its cause not known);
/// its successor is the watchdog's child (the exec backend: a signal the
/// wait reports, and not its unit's restart).
///
/// Fix round 4 of #582 (its KVM suites): the watchdog signs a successor
/// once that start is over — seconds after the respawn the agent's pidfile
/// shows — so the rows are waited for, not read at once. And the watchdog
/// here is the test's, not its unit's restart: the agent judges it at its
/// start (the review of #582, F3 and F6; the re-check 3, R2-1), signs
/// `watchdog_successor_foreign` and does not register it — so it vouches
/// for no key of it, and imports its rows as `witness_row_uncertified`
/// (High: the watchdog's claim alone). The kinds are matched whole: the old
/// `contains("witness_row")` took an uncertified row for a certified one.
/// The certified import — a unit's watchdog, its key read from its sealed
/// memory file — is the lab's `witness_open` case and nn-linux's
/// `witness_rows_are_imported_once_after_their_key_is_certified`.
#[test]
fn the_watchdog_signs_the_agent_s_vacancy_and_its_successor() {
    use nn_proto::witness::{
        judge_chain, Judged, CHAIN_FILE, KIND_SUCCESSOR_FOREIGN, KIND_VACATED,
    };
    let mut fx = E2eFixture::setup();
    let pid0 = fx.spawn_agent();
    fx.spawn_watchdog();
    let wd_pid: u32 = fs::read_to_string(fx.watchdog_pidfile())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .expect("watchdog pidfile");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !dump_protected_pids().contains(&wd_pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
    fx.unprotect_and_sigkill_agent(pid0);
    let pid1 = new_agent_pid(&fx, pid0, Duration::from_secs(30)).expect("no successor of pid0");
    // the successor's start over (its own registration) before its kill
    std::thread::sleep(Duration::from_secs(5));
    fx.unprotect_and_sigkill_agent(pid1);
    let pid2 = new_agent_pid(&fx, pid1, Duration::from_secs(30)).expect("no successor of pid1");
    let chain = fx.state().witness_dir().join(CHAIN_FILE);
    let read = |p: &Path| {
        let out = Command::new("sudo")
            .arg("cat")
            .arg(p)
            .output()
            .expect("sudo cat");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let wanted = [
        (KIND_VACATED, format!("the agent (pid {pid0}) exited")),
        (KIND_SUCCESSOR_FOREIGN, format!("taken by pid {pid1}:")),
        (KIND_VACATED, format!("the agent (pid {pid1}) exited")),
        (KIND_SUCCESSOR_FOREIGN, format!("taken by pid {pid2}:")),
    ];
    let has = |rows: &[nn_proto::witness::Row], kind: &str, needle: &str| {
        rows.iter()
            .position(|r| r.kind == kind && r.detail.contains(needle))
    };
    // the successor's row follows its start (its registration): waited for
    let deadline = Instant::now() + Duration::from_secs(30);
    let rows: Vec<nn_proto::witness::Row> = loop {
        let rows: Vec<nn_proto::witness::Row> = judge_chain(&read(&chain))
            .into_iter()
            .map(|j| match j {
                Judged::Valid { row, .. } => row,
                Judged::Broken { line, why } => {
                    panic!("witness chain broken at line {line}: {why}")
                }
            })
            .collect();
        if wanted.iter().all(|(k, n)| has(&rows, k, n).is_some()) || Instant::now() >= deadline {
            break rows;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let find = |kind: &str, needle: &str| {
        has(&rows, kind, needle)
            .map(|i| &rows[i])
            .unwrap_or_else(|| panic!("no {kind} row naming `{needle}` in {} rows", rows.len()))
    };
    assert!(
        rows.iter().all(|r| r.tgid == wd_pid),
        "signed by the watchdog"
    );
    find(KIND_VACATED, &wanted[0].1);
    let s1 = find(KIND_SUCCESSOR_FOREIGN, &wanted[1].1);
    assert!(
        s1.detail.contains("NOT its unit's restart"),
        "the watchdog's child is not its unit's restart"
    );
    let v1 = find(KIND_VACATED, &wanted[2].1);
    assert!(v1.detail.contains("signal 9"), "the wait's cause");
    find(KIND_SUCCESSOR_FOREIGN, &wanted[3].1);
    // imported by the agent into its signed audit log — the kinds whole
    let kind = |k: &str| format!("\"kind\":\"{k}\"");
    let needle = &wanted[2].1;
    // the agent's round every 30 s, its first before its audit log is open
    let deadline = Instant::now() + Duration::from_secs(70);
    let audit = loop {
        let audit = read(&fx.state().audit_log());
        if audit
            .lines()
            .any(|l| l.contains(&kind("witness_row_uncertified")) && l.contains(needle.as_str()))
        {
            break audit;
        }
        assert!(
            Instant::now() < deadline,
            "the witness rows never reached the audit log"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let judged = format!("taken by pid {wd_pid}: NOT its unit's restart");
    assert!(
        audit
            .lines()
            .any(|l| l.contains(&kind("watchdog_successor_foreign")) && l.contains(&judged)),
        "the agent did not sign its verdict on the test's watchdog (not its unit's restart)"
    );
    assert!(
        !audit.contains(&kind("witness_key_certified")),
        "the key of a watchdog the agent does not register was certified"
    );
    assert!(
        !audit.contains(&kind("witness_row")),
        "a row signed by a key the agent never certified was imported as certified"
    );
}

/// Lot 344 (the alpha's false positives, item 1): a freshly started
/// watchdog opens `PROTECTED_PIDS`' pin to register itself before it is
/// a protected pid. The `bpf` hook let that through (the watchdog's
/// binary by device and inode, its role vacant, its first minute) but
/// still reported it: NN-L-BPF-002 High "took a handle to one of
/// NorthNarrow's own BPF objects" for OUR watchdog at every start, the
/// first record a tester saw. The start leaves no such record now.
///
/// The review of #554: the start is recorded on its own, Low (F2: a
/// foreign program made the watchdog's binary through `PR_SET_MM_EXE_FILE`
/// takes the same path) — and that record, found by the same filter, is
/// this test's positive control (F5): the start was seen and judged, not
/// lost to a filter or a profile that records nothing.
///
/// #554's KVM suites: the agent's `bpf` hook knew the agent's sibling
/// `northnarrow-watchdog` as the watchdog, not this one (`--watchdog-exe`):
/// two High records at every run; and the control looked for the verdict's
/// reasoning, which the signed record does not carry.
///
/// Lot 370 (F10-4; the re-check of #578's KVM suites): a role its holder
/// left this boot is vacated, and the suite's earlier tests leave the
/// watchdog's so — a watchdog this test started was then a foreign handle
/// (two High records, as F10-4 means). The test establishes what it is
/// about, the role's first claim ([`establish_first_claim_of_the_watchdog_role`]);
/// the vacated role's successor has its own test
/// (`a_role_its_holder_left_outside_a_window_is_recorded_high`).
#[test]
fn the_watchdog_s_own_start_is_not_a_foreign_bpf_handle() {
    let mut fx = E2eFixture::setup();
    // before any agent of this test runs: no agent records the write
    let slot = establish_first_claim_of_the_watchdog_role();
    assert!(
        matches!(slot, None | Some(0)),
        "the watchdog's role could not be made a first claim (slot {slot:?})"
    );
    let _agent_pid = fx.spawn_agent();
    fx.spawn_watchdog();
    let wd_pid: u32 = fs::read_to_string(fx.watchdog_pidfile())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .expect("watchdog pidfile");
    // registered (a protected pid): its start is over
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !dump_protected_pids().contains(&wd_pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        dump_protected_pids().contains(&wd_pid),
        "the watchdog never registered itself in PROTECTED_PIDS"
    );
    // the bpf observations' pump and the rule's record: well under this
    std::thread::sleep(Duration::from_secs(5));
    let found = records_of(
        &fx.state().detections(),
        "NN-L-BPF-002_BpfForeignHandleOrDetach",
        wd_pid,
    );
    let low = "\"severity\":\"Low\"";
    let (start, foreign): (Vec<&String>, Vec<&String>) =
        found.iter().partition(|l| l.contains(low));
    assert!(
        foreign.is_empty(),
        "the watchdog's own start recorded as a foreign BPF handle: {:?}",
        heads(&foreign)
    );
    // The signed record carries no reasoning (`DetectionRecord`): the
    // fresh instance's record is NN-L-BPF-002's only Low one (nn-core
    // `bpf002_is_low_for_a_fresh_instance_only`), here for the watchdog's
    // pid and its name.
    assert!(
        start
            .iter()
            .any(|l| l.contains("\"comm\":\"northnarrow-wat\"")),
        "the watchdog's start was not seen: no Low record of its own (pid {wd_pid}): {:?}",
        heads(&start)
    );
}

/// The review of #578 (N2, named): the agent ends as the OOM killer ends
/// it — a kill nothing refused, outside any trusted-installer window (here
/// its pid evicted from `PROTECTED_PIDS`, then SIGKILL: the kernel's
/// `sched_process_exit` vacates its role either way) — and the watchdog's
/// respawn takes the role. That successor is recorded NN-L-BPF-002 High,
/// under its own pid. On 382be007 nothing reached the detections: the
/// start's handles on the pins were judged by the previous agent's pinned
/// `bpf` hook, which wrote its record into that agent's ring — read by
/// nobody once that agent was gone (lab r2 of lot 370: no NN-L-BPF-002 of
/// any kind after the restart).
#[test]
fn a_role_its_holder_left_outside_a_window_is_recorded_high() {
    let mut fx = E2eFixture::setup();
    let pid0 = fx.spawn_agent();
    fx.spawn_watchdog();
    let wd_pid: u32 = fs::read_to_string(fx.watchdog_pidfile())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .expect("watchdog pidfile");
    // the watchdog registered: the respawn is its own
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !dump_protected_pids().contains(&wd_pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        dump_protected_pids().contains(&wd_pid),
        "the watchdog never registered itself in PROTECTED_PIDS"
    );
    fx.unprotect_and_sigkill_agent(pid0);
    let pid1 = new_agent_pid(&fx, pid0, Duration::from_secs(30))
        .expect("the watchdog never respawned the agent");
    let rule = "NN-L-BPF-002_BpfForeignHandleOrDetach";
    let high = "\"severity\":\"High\"";
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let found = records_of(&fx.state().detections(), rule, pid1);
        if found.iter().any(|l| l.contains(high)) {
            // the successor's own record, under its name
            assert!(
                found
                    .iter()
                    .any(|l| l.contains(high) && l.contains("\"comm\":\"northnarrow-age\"")),
                "the successor's High record does not name it: {:?}",
                heads(&found.iter().collect::<Vec<_>>())
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no NN-L-BPF-002 High for the successor (pid {pid1}) of the agent the kernel killed \
             outside a window (pid {pid0}): {:?}",
            heads(&found.iter().collect::<Vec<_>>())
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
