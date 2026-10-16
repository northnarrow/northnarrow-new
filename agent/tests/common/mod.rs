//! Shared utilities for the agent's privileged integration tests.
//!
//! Cargo treats files directly in `tests/` as standalone test
//! crates; the `common/mod.rs` layout deliberately nests under a
//! directory so this file is NOT a test target, just a module
//! consumed via `mod common;` from each test file that needs it.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ── Tappa 10 hotfix — EniIptablesGuard ────────────────────────────────
//
// Privileged tests that drive the agent into the COMBAT posture
// install the production-shape `NORTHNARROW_COMBAT` iptables chain
// + jump rules in INPUT/OUTPUT/FORWARD. The agent's own
// `NetworkIsolator::release` tears those down on a verified
// unlock — but if the test panics, asserts before reaching
// release, or relies on a kill-side rule (canary tests) that
// transitions to Combat WITHOUT going through unlock, the chain
// stays in place and the host loses outbound connectivity until
// an operator runs `iptables -F NORTHNARROW_COMBAT && iptables
// -X NORTHNARROW_COMBAT` by hand. That actually happened during
// the Tappa 9.5 K8 verification: VM lost outbound network twice.
//
// `EniIptablesGuard` is the RAII counterpart: drop it at test
// exit (pass, fail, panic — all routes through Drop) and the
// chain is detached + flushed + deleted regardless. Each
// command tolerates "rule does not exist" / "no chain by that
// name" so dropping the guard on a clean state is a cheap
// no-op. Same idempotency contract as
// `agent/src/anti_tamper/network_isolate.rs::run_iptables_idempotent`.

/// Base chains the agent's `NetworkIsolator` jumps from when it
/// engages COMBAT (mirrors `network_isolate.rs::release` order
/// — detach in INPUT/OUTPUT/FORWARD order, then -F, then -X).
const BASE_CHAINS: &[&str] = &["INPUT", "OUTPUT", "FORWARD"];

/// Production combat chain name the agent installs. Mirrors
/// `agent/src/anti_tamper/network_isolate.rs::COMBAT_CHAIN`.
pub const COMBAT_CHAIN: &str = "NORTHNARROW_COMBAT";

/// RAII cleanup guard for the production `NORTHNARROW_COMBAT`
/// iptables chain. Instantiate at the start of any privileged
/// test that could leave the chain installed (any test that
/// drives the agent into Combat — directly via
/// `nn-admin debug force-posture combat`, or indirectly via
/// a Critical-severity rule that the posture FSM translates to
/// Combat, such as the Tappa 9.5 K5 NN-L-CANARY-* family).
///
/// Drop runs unconditionally (pass / fail / panic) so the host's
/// network is restored even when the test panics before its
/// own cleanup path executes. Subprocess errors are swallowed
/// — the goal is "best-effort cleanup, never blame the guard for
/// a downstream failure." Tests that need to assert a clean
/// state can call [`Self::is_clean`] after construction.
pub struct EniIptablesGuard {
    chain: &'static str,
}

impl EniIptablesGuard {
    /// Install a Drop-on-scope-exit cleanup. Cheap to construct —
    /// no iptables commands run at construction time; the cleanup
    /// only runs on Drop. Caller-side pattern:
    ///
    /// ```ignore
    /// let _eni = EniIptablesGuard::install();
    /// // ... test body that might trigger Combat ...
    /// // Drop runs at function end (or on panic) and cleans the
    /// // chain.
    /// ```
    pub fn install() -> Self {
        Self {
            chain: COMBAT_CHAIN,
        }
    }

    /// The same cleanup for another chain: the guard's self-tests
    /// (`fixture_selftest.rs`) exercise it on a chain of their own, never
    /// on the production one (external audit NN-AUD-232).
    #[allow(dead_code)]
    pub fn install_for(chain: &'static str) -> Self {
        Self { chain }
    }

    /// Probe `iptables -S NORTHNARROW_COMBAT` and return `true`
    /// when the chain is absent (the expected post-Drop state).
    /// Useful for "did the cleanup actually work?" assertions
    /// in the guard's self-tests; production callers don't need
    /// to call this.
    pub fn is_clean() -> bool {
        let out = Command::new("iptables")
            .args(["-S", COMBAT_CHAIN])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        match out {
            Ok(o) => !o.status.success(),
            // Couldn't even spawn iptables — treat as "clean" so
            // the guard doesn't fail tests on hosts without
            // iptables installed. The production path runs under
            // sudo + iptables-present anyway.
            Err(_) => true,
        }
    }
}

impl Drop for EniIptablesGuard {
    fn drop(&mut self) {
        // Step 1: detach the jump rules from each base chain.
        // `iptables -X` refuses to delete a chain still
        // referenced anywhere, so detach BEFORE flush/delete.
        for base in BASE_CHAINS {
            let _ = Command::new("iptables")
                .args(["-D", base, "-j", self.chain])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        // Step 2: flush the chain's contents (so a future -X
        // succeeds even if the rules were partially built).
        let _ = Command::new("iptables")
            .args(["-F", self.chain])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // Step 3: delete the chain itself.
        let _ = Command::new("iptables")
            .args(["-X", self.chain])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ── Self-tests ────────────────────────────────────────────────────────
//
// External audit NN-AUD-232 (TST-011): the guard's two iptables self-tests
// lived here, in a `#[cfg(test)]` module, so every test binary with
// `mod common;` compiled and ran them (eight copies), and the clean-state
// one deleted the production chain unconditionally. They are in
// `fixture_selftest.rs` now, one binary, with the helpers below.

/// `pid` plus every process below it (`pgrep -P`, breadth first), the
/// root first. Best effort: a pid that exits mid-walk is simply skipped.
fn process_tree(pid: u32) -> Vec<u32> {
    let mut todo = vec![pid];
    let mut seen = Vec::new();
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
    seen
}

/// The agent's pinned `PROTECTED_PIDS` (every fixture uses the default
/// pin root).
pub fn protected_pids_pin() -> PathBuf {
    Path::new(northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT).join("PROTECTED_PIDS")
}

/// `pid` as the four little-endian key bytes `bpftool map … key` takes.
pub fn pid_key_bytes(pid: u32) -> [String; 4] {
    pid.to_le_bytes().map(|b| b.to_string())
}

/// A command's stderr (else stdout) on one line, for messages.
fn brief(out: &std::process::Output) -> String {
    let text = if out.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
        String::from_utf8_lossy(&out.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let line: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    line.join(" / ").chars().take(300).collect()
}

/// Refuse to start an agent this fixture could not stop.
///
/// Teardown evicts the agent from `PROTECTED_PIDS` with `bpftool`
/// ([`unprotect_pid`]) before signalling it. On an Ubuntu 22.04 lab guest
/// `bpftool` was only linux-tools-common's wrapper, without
/// `linux-tools-$(uname -r)`: the eviction failed unnoticed, the SIGQUIT
/// that followed was refused and counted as a tamper attempt by the test
/// runner, and the agent (COMBAT) killed the runner, outlived it and
/// killed the next test binaries (lab PR 153). Checked once per binary;
/// call it before spawning an agent.
pub fn require_bpftool() {
    static CHECK: OnceLock<Result<(), String>> = OnceLock::new();
    let res = CHECK.get_or_init(|| {
        match Command::new("sudo")
            .args(["bpftool", "version"])
            .stdin(Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(format!("exit {:?}: {}", o.status.code(), brief(&o))),
            Err(e) => Err(format!("could not run: {e}")),
        }
    });
    if let Err(e) = res {
        panic!(
            "`sudo bpftool version` fails ({e}). The fixture's teardown evicts the agent \
             from PROTECTED_PIDS with bpftool, so an agent started now could not be \
             stopped: not starting one. On Ubuntu install linux-tools-$(uname -r)."
        );
    }
}

/// Remove `pid` AND every process below it from the pinned
/// `PROTECTED_PIDS` map so a plain signal from the test runner reaches
/// the agent. Since `task-kill-signals-1` the task_kill LSM hook denies
/// EVERY userspace signal towards a protected pid unless the caller is
/// the process itself, another protected pid or PID 1 with the armed
/// nonce — the test runner is none of those. The fixtures spawn the
/// agent through `sudo`, so `Child::id()` is sudo's pid and the agent is
/// its child. Walking the descendants covers both shapes.
///
/// This works only while the BPF guard observes (`debug-trigger` builds):
/// in enforce mode the write handle on the map is refused, by design
/// (`privileged_e2e::bpf_guard_enforce_refuses_protected_pids_write`).
/// External audit TST-010: the outcome is returned, not dropped. `Ok`
/// when every pid was evicted or was not in the map (sudo's own pid) or
/// when there is no pin at all (nothing protected); `Err` names every pid
/// bpftool could not evict and why.
pub fn unprotect_pid(pid: u32) -> Result<(), String> {
    let pin = protected_pids_pin();
    match Command::new("sudo")
        .arg("test")
        .arg("-e")
        .arg(&pin)
        .status()
    {
        Ok(s) if !s.success() => return Ok(()),
        Ok(_) => {}
        Err(e) => return Err(format!("sudo test -e {}: {e}", pin.display())),
    }
    let mut errors = Vec::new();
    for p in process_tree(pid) {
        let out = Command::new("sudo")
            .args(["bpftool", "map", "delete", "pinned"])
            .arg(&pin)
            .arg("key")
            .args(pid_key_bytes(p))
            .stdin(Stdio::null())
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let msg = brief(&o);
                // Not in the map: nothing to evict.
                if !(msg.contains("delete failed") && msg.contains("No such file or directory")) {
                    errors.push(format!("pid {p}: {msg}"));
                }
            }
            Err(e) => errors.push(format!("pid {p}: bpftool could not run: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// `pid` still exists (signal 0: the task_kill hook lets it through).
fn pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// `child` has been reaped and none of `known` (its tree when the stop
/// began) is left: an agent that outlived its sudo parent is not "stopped".
fn tree_exited(child: &mut Child, known: &[u32]) -> Result<bool, String> {
    match child.try_wait() {
        Ok(Some(_)) => Ok(known.iter().all(|&p| p == child.id() || !pid_alive(p))),
        Ok(None) => Ok(false),
        Err(e) => Err(format!("try_wait on pid {}: {e}", child.id())),
    }
}

/// Poll [`tree_exited`] until `deadline`.
fn wait_tree_exited(child: &mut Child, known: &[u32], deadline: Instant) -> Result<bool, String> {
    loop {
        if tree_exited(child, known)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// How long [`quit_agent`] tries before it gives up.
pub const QUIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Panic with `msg`, or only print it when this thread is already
/// unwinding: a panic in `Drop` during an unwind aborts the whole test
/// binary and hides the first failure.
pub fn fail_teardown(msg: &str) {
    if std::thread::panicking() {
        eprintln!("{msg}");
    } else {
        panic!("{msg}");
    }
}

/// Stop an agent the fixture spawned through `sudo` and reap it; panics
/// (see [`fail_teardown`]) when it cannot, naming why. See
/// [`try_quit_agent`].
pub fn quit_agent(child: &mut Child) {
    if let Err(msg) = try_quit_agent(child, QUIT_TIMEOUT) {
        fail_teardown(&msg);
    }
}

/// Evict the agent's tree from `PROTECTED_PIDS`, SIGQUIT it and wait,
/// retried until `timeout`.
///
/// SIGQUIT is delivered to EVERY process in the `sudo` subtree, agent
/// included, not only to `Child::id()` (the sudo pid): sudo 1.9.9 (Ubuntu
/// 22.04) does not relay a signal sent by a process in its own process
/// group — the test runner — while 1.9.15 (Ubuntu 24.04) does.
///
/// External audit TST-010: this used to ignore the eviction's and the
/// signal's outcome and, after 10 s, print a line and return with the
/// agent still running. Now `Err` says why the agent survived. When the
/// eviction fails no signal is sent: the hook would refuse it and count
/// it as a tamper attempt by this test process, which an enforcing agent
/// answers (COMBAT, then the runner is killed).
pub fn try_quit_agent(child: &mut Child, timeout: Duration) -> Result<(), String> {
    let root = child.id();
    let mut known = process_tree(root);
    let deadline = Instant::now() + timeout;
    let mut eviction: Result<(), String>;
    let mut refused: Option<(u32, std::io::Error)> = None;
    let mut signalled = false;
    loop {
        if tree_exited(child, &known)? {
            return Ok(());
        }
        eviction = unprotect_pid(root);
        if eviction.is_ok() {
            // Leaves first, then sudo itself, so nothing is left to re-spawn.
            for p in process_tree(root).into_iter().rev() {
                if !known.contains(&p) {
                    known.push(p);
                }
                if unsafe { libc::kill(p as i32, libc::SIGQUIT) } != 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::ESRCH) {
                        refused = Some((p, e));
                    }
                }
            }
            signalled = true;
        }
        let step = (Instant::now() + Duration::from_millis(500)).min(deadline);
        if wait_tree_exited(child, &known, step)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    let why = match (&eviction, &refused) {
        (Err(e), _) => format!(
            "its eviction from PROTECTED_PIDS failed ({e}); no signal was sent (the \
             task_kill hook would refuse it)"
        ),
        (Ok(()), Some((p, e))) => format!(
            "SIGQUIT to pid {p} refused ({e}): signal denied by the task_kill hook, the pid \
             is still in PROTECTED_PIDS"
        ),
        (Ok(()), None) if signalled => "SIGQUIT was delivered but it did not exit".to_string(),
        (Ok(()), None) => "no signal could be sent".to_string(),
    };
    Err(format!(
        "quit_agent: the agent of sudo pid {root} (tree {known:?}) is still alive {timeout:?} \
         into teardown: {why}. It keeps running: stop it with a signed `nn-admin shutdown` \
         or restart the host before more privileged tests run (a leftover agent treats the \
         next fixtures as an intrusion)."
    ))
}

/// What a signed `nn-admin shutdown` needs: two distinct keys carrying
/// the `shutdown` role (2-of-N quorum), the agent's id file and socket.
pub struct SignedShutdown<'a> {
    pub nn_admin: &'a Path,
    pub key: &'a Path,
    pub cosign_key: &'a Path,
    pub agent_id_file: &'a Path,
    pub socket: &'a Path,
}

/// Stop the agent the authorised way — the one stop an agent whose BPF
/// guard enforces accepts from an unprotected process — and wait until
/// `child` and every process below it are gone.
pub fn shutdown_signed(
    child: &mut Child,
    s: &SignedShutdown<'_>,
    timeout: Duration,
) -> Result<(), String> {
    let known = process_tree(child.id());
    if tree_exited(child, &known)? {
        return Ok(());
    }
    let out = Command::new(s.nn_admin)
        .arg("shutdown")
        .arg("--key")
        .arg(s.key)
        .arg("--cosign-key")
        .arg(s.cosign_key)
        .arg("--agent-id-file")
        .arg(s.agent_id_file)
        .arg("--socket")
        .arg(s.socket)
        .args(["--grace-secs", "10"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawning nn-admin shutdown: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "nn-admin shutdown failed (exit {:?}): {}",
            out.status.code(),
            brief(&out)
        ));
    }
    if wait_tree_exited(child, &known, Instant::now() + timeout)? {
        Ok(())
    } else {
        Err(format!(
            "the agent of sudo pid {} (tree {known:?}) is still alive {timeout:?} after an \
             acknowledged signed shutdown",
            child.id()
        ))
    }
}

// ── External audit NN-AUD-227/228/234 — structured waits and barriers ──
//
// Added at the end of the file on purpose (other fixes touch the teardown
// helpers above). A negative assertion is checked after a barrier — an
// event observed to have gone through the same pipeline after the window
// — never after a bare sleep, which a merely slow pipeline also passes.

const WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Poll `probe` every 100 ms until it returns `Some`, at most `timeout`.
pub fn wait_until<T>(
    timeout: std::time::Duration,
    mut probe: impl FnMut() -> Option<T>,
) -> Option<T> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(WAIT_POLL);
    }
}

/// The parsed rows of a JSONL chain log (blank or unparsable lines skipped).
pub fn jsonl_rows(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The first row of `path` that `pred` accepts, waited for at most
/// `timeout`; panics with every row seen.
pub fn wait_jsonl_row(
    path: &std::path::Path,
    timeout: std::time::Duration,
    what: &str,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    wait_until(timeout, || jsonl_rows(path).into_iter().find(|r| pred(r))).unwrap_or_else(|| {
        panic!(
            "no {what} in {} within {timeout:?}; rows: {:?}",
            path.display(),
            jsonl_rows(path)
        )
    })
}

/// The detection records of `rule_id` in `detections`.
pub fn records_of(detections: &std::path::Path, rule_id: &str) -> Vec<serde_json::Value> {
    jsonl_rows(detections)
        .into_iter()
        .filter(|r| r["rule_id"].as_str() == Some(rule_id))
        .collect()
}

/// Exec barrier: a copy of `/bin/true` run from a fresh directory under
/// `/tmp` (R001, or whichever exec rule matches first, records it), and its
/// detection record waited for in `detections`. The agent's event loop
/// handles one event at a time, in the order the sensors deliver them, so
/// once that record is written every event delivered before the exec has
/// been through the rule engine and its record, if any, written before it.
/// Returns the barrier's record.
pub fn exec_barrier(
    detections: &std::path::Path,
    timeout: std::time::Duration,
) -> serde_json::Value {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .prefix("nnbarrier")
        .tempdir_in("/tmp")
        .expect("barrier dir under /tmp");
    let bin = dir.path().join("nn_barrier");
    std::fs::copy("/bin/true", &bin).expect("copy /bin/true for the barrier");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the barrier");
    let mut child = Command::new(&bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("exec the barrier");
    let pid = u64::from(child.id());
    let _ = child.wait();
    wait_jsonl_row(detections, timeout, "barrier exec record", |r| {
        r["principal"]["pid"].as_u64() == Some(pid)
            && r["exe"]
                .as_str()
                .is_some_and(|e| e.ends_with("/nn_barrier"))
    })
}

/// The value `count` settles on: read every `window`, returned once two
/// consecutive windows saw no change; panics if it is still moving after
/// `timeout`. For an upper bound ("at most N rows"), which a pipeline still
/// draining would pass vacuously after a fixed sleep.
pub fn wait_count_stable(
    window: std::time::Duration,
    timeout: std::time::Duration,
    mut count: impl FnMut() -> usize,
) -> usize {
    let deadline = std::time::Instant::now() + timeout;
    let mut last = count();
    let mut still = 0;
    loop {
        std::thread::sleep(window);
        let now = count();
        if now == last {
            still += 1;
            if still == 2 {
                return now;
            }
        } else {
            still = 0;
            last = now;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the count was still moving after {timeout:?} (last {now})"
        );
    }
}

/// `child`'s exit status, waited for at most `timeout`; `None` while it runs.
pub fn wait_exit(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    wait_until(timeout, || child.try_wait().ok().flatten())
}

/// `pid` has exited: no `/proc` entry, or a zombie waiting for its reaper.
pub fn pid_gone(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| matches!(state, "Z" | "X")),
        Err(_) => true,
    }
}

// ── External audit NN-AUD-232/233 — fixtures that change host state ──
//
// The iptables self-tests and the honeypot suite change state that is not
// a tempdir's: the production `NORTHNARROW_COMBAT` chain and the real bait
// files under /etc, /var/lib and /run. They refuse to start where that
// state can belong to a running agent, the honeypot suite refuses a host
// that is not a disposable lab guest, and it puts back the files it found.
// Their self-tests are in `fixture_selftest.rs` (a `#[test]` in this file
// runs in every binary with `mod common;`).

/// Written by the lab's cloud-init (`deploy/lab/user-data*.tmpl`, every
/// distro) once the guest is provisioned.
pub const LAB_GUEST_MARKER: &str = "/var/lib/nn-lab-provisioned";

/// `1` declares a host that is not an nn-lab guest disposable (a throwaway
/// VM): the operator accepts that the suite rewrites real paths there.
pub const DISPOSABLE_HOST_ENV: &str = "NN_TEST_DISPOSABLE_HOST";

/// `Ok` on an nn-lab guest (`marker_present`) or with
/// [`DISPOSABLE_HOST_ENV`] set to exactly `1`; `Err` says what is missing.
pub fn disposable_host_verdict(marker_present: bool, opt_in: Option<&str>) -> Result<(), String> {
    if marker_present || opt_in == Some("1") {
        return Ok(());
    }
    Err(format!(
        "{LAB_GUEST_MARKER} is missing (not an nn-lab guest) and {DISPOSABLE_HOST_ENV}=1 is not set"
    ))
}

/// Panic unless this host is disposable ([`disposable_host_verdict`]).
pub fn require_disposable_host(what: &str) {
    let opt_in = std::env::var(DISPOSABLE_HOST_ENV).ok();
    let marker = Path::new(LAB_GUEST_MARKER).exists();
    if let Err(e) = disposable_host_verdict(marker, opt_in.as_deref()) {
        panic!(
            "refusing to {what}: {e}. Run it on an nn-lab guest (deploy/lab/nn-lab.sh \
             test-ignored), or set {DISPOSABLE_HOST_ENV}=1 on a host you can throw away."
        );
    }
}

/// Panic unless the effective uid is 0: a fixture that must read and put
/// back root-owned files cannot do it halfway.
pub fn require_root(what: &str) {
    if unsafe { libc::geteuid() } != 0 {
        panic!(
            "refusing to {what}: not root. Run the suite as its header says \
             (sudo -E env \"PATH=$PATH\" cargo test …)."
        );
    }
}

/// A process is a NorthNarrow agent or watchdog: the installed binaries and
/// the fixtures' copies (`northnarrow-agent-e2etest-…`), by the basename of
/// `/proc/<pid>/exe` when it can be read, or by `comm`, which the kernel
/// cuts to 15 bytes (`northnarrow-age`, `northnarrow-wat`). Either match
/// counts: a false refusal costs a rerun, a miss costs the host's state.
pub fn is_northnarrow_daemon(exe_name: Option<&str>, comm: &str) -> bool {
    let exe = exe_name.is_some_and(|n| {
        n.starts_with("northnarrow-agent") || n.starts_with("northnarrow-watchdog")
    });
    let comm = comm.trim_end();
    exe || comm.starts_with("northnarrow-age") || comm.starts_with("northnarrow-wat")
}

/// Every live NorthNarrow agent or watchdog on the host, as `"<pid> <exe>"`
/// (zombies excluded).
pub fn northnarrow_daemons() -> Vec<String> {
    let me = std::process::id();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let exe = std::fs::read_link(entry.path().join("exe")).ok();
        let exe_name = exe
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str());
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if is_northnarrow_daemon(exe_name, &comm) && !pid_gone(pid) {
            let what = exe.map_or_else(|| comm.trim_end().to_string(), |p| p.display().to_string());
            found.push(format!("{pid} {what}"));
        }
    }
    found
}

/// Panic when a NorthNarrow agent or watchdog runs: the state `what`
/// changes may be its own (its COMBAT chain, the baits it watches), and a
/// running agent answers the change as a tamper.
pub fn refuse_if_northnarrow_running(what: &str) {
    let found = northnarrow_daemons();
    if !found.is_empty() {
        panic!(
            "refusing to {what}: NorthNarrow processes run on this host ({found:?}). Stop \
             them first (nn-lab.sh test-ignored does, through lab_purge_pins); an agent \
             left by an earlier fixture needs a signed `nn-admin shutdown` or a reboot."
        );
    }
}

/// `iptables -S NORTHNARROW_COMBAT`'s outcome read strictly: `Ok(true)`
/// the chain exists, `Ok(false)` iptables said it does not, `Err` for any
/// other answer (not root, iptables missing, killed). Unlike
/// [`EniIptablesGuard::is_clean`], "could not ask" is never "absent".
pub fn combat_chain_verdict(status: Option<i32>, stderr: &str) -> Result<bool, String> {
    match status {
        Some(0) => Ok(true),
        Some(_) if stderr.contains("No chain/target/match by that name") => Ok(false),
        _ => Err(format!(
            "`iptables -S {COMBAT_CHAIN}` ended with {status:?}: {}",
            stderr.trim()
        )),
    }
}

/// Whether the production COMBAT chain exists ([`combat_chain_verdict`]).
pub fn combat_chain_present() -> Result<bool, String> {
    chain_present(COMBAT_CHAIN)
}

/// Whether the iptables chain `chain` exists ([`combat_chain_verdict`]).
/// iptables-nft 1.8.9 (Debian 12) answers `-S <chain>` for a chain that
/// does not exist with "… is incompatible, use 'nft' tool" instead of "No
/// chain/target/match by that name"; the listing of the whole table still
/// reads, so the chain is looked for there (`-N <chain>`).
pub fn chain_present(chain: &str) -> Result<bool, String> {
    let out = Command::new("iptables")
        .args(["-S", chain])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run iptables: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stderr.to_ascii_lowercase().contains("incompatible") {
        return combat_chain_verdict(out.status.code(), &stderr);
    }
    let table = Command::new("iptables")
        .args(["-S"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run iptables: {e}"))?;
    if !table.status.success() {
        return Err(format!(
            "`iptables -S {chain}`: {}; `iptables -S`: {}",
            stderr.trim(),
            String::from_utf8_lossy(&table.stderr).trim()
        ));
    }
    let want = format!("-N {chain}");
    Ok(String::from_utf8_lossy(&table.stdout)
        .lines()
        .any(|l| l.trim() == want))
}

/// What a real path held before a fixture changed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    Absent,
    /// A regular file: content, permission bits, owner, mtime.
    File {
        bytes: Vec<u8>,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: std::time::SystemTime,
    },
    /// Anything else, not followed (`"symlink"`, `"directory"`, …): it is
    /// named, never restored.
    Other(&'static str),
}

fn file_kind(t: std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if t.is_symlink() {
        "symlink"
    } else if t.is_dir() {
        "directory"
    } else if t.is_fifo() {
        "FIFO"
    } else if t.is_socket() {
        "socket"
    } else if t.is_block_device() || t.is_char_device() {
        "device"
    } else {
        "special file"
    }
}

impl PathState {
    /// The state of `path`, without following a symlink at its end.
    pub fn read(path: &Path) -> std::io::Result<Self> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_file() => {}
            Ok(m) => return Ok(Self::Other(file_kind(m.file_type()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(e) => return Err(e),
        }
        // O_NOFOLLOW: a link swapped in after the lstat is not read through.
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = f.metadata()?;
        if !meta.file_type().is_file() {
            return Ok(Self::Other(file_kind(meta.file_type())));
        }
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Ok(Self::File {
            bytes,
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: meta.modified()?,
        })
    }

    /// One line for messages: kind, mode, owner, size and sha256.
    pub fn describe(&self) -> String {
        use sha2::Digest;
        match self {
            Self::Absent => "absent".to_string(),
            Self::File {
                bytes,
                mode,
                uid,
                gid,
                ..
            } => format!(
                "file {mode:04o} {uid}:{gid}, {} bytes, sha256 {}",
                bytes.len(),
                hex::encode(sha2::Sha256::digest(bytes))
            ),
            Self::Other(kind) => format!("a {kind}"),
        }
    }
}

/// Put `path` back to `state` and check it: a file gets its content, mode,
/// owner and mtime back (recreated if it was deleted, written in place
/// otherwise; a symlink or other non-file found there is removed first,
/// never written through); a path that was absent is removed. A directory
/// is never removed, and an `Other` state is never recreated: both are
/// `Err`. Nothing is written when the path already matches.
pub fn restore_path(path: &Path, state: &PathState) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let shown = path.display();
    let now = PathState::read(path).map_err(|e| format!("{shown}: reading it: {e}"))?;
    if &now == state {
        return Ok(());
    }
    if let PathState::Other(kind) = state {
        return Err(format!("{shown} was a {kind} before the run: not restored"));
    }
    match &now {
        PathState::Absent | PathState::File { .. } => {}
        PathState::Other("directory") => {
            return Err(format!(
                "{shown} is a directory now ({} expected): not removed",
                state.describe()
            ))
        }
        PathState::Other(_) => {
            std::fs::remove_file(path).map_err(|e| format!("{shown}: removing {now:?}: {e}"))?
        }
    }
    match state {
        PathState::Absent => {
            if matches!(now, PathState::File { .. }) {
                std::fs::remove_file(path).map_err(|e| format!("{shown}: removing it: {e}"))?;
            }
        }
        PathState::File {
            bytes,
            mode,
            uid,
            gid,
            mtime,
        } => {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(*mode)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|e| format!("{shown}: opening it for the restore: {e}"))?;
            f.write_all(bytes)
                .map_err(|e| format!("{shown}: writing the content back: {e}"))?;
            // Owner before mode: a chown clears the set-id bits.
            std::os::unix::fs::fchown(&f, Some(*uid), Some(*gid))
                .map_err(|e| format!("{shown}: chown {uid}:{gid}: {e}"))?;
            f.set_permissions(std::fs::Permissions::from_mode(*mode))
                .map_err(|e| format!("{shown}: chmod {mode:04o}: {e}"))?;
            f.set_modified(*mtime)
                .map_err(|e| format!("{shown}: setting the mtime back: {e}"))?;
            f.sync_all().map_err(|e| format!("{shown}: fsync: {e}"))?;
        }
        PathState::Other(_) => unreachable!("refused above"),
    }
    let after = PathState::read(path).map_err(|e| format!("{shown}: re-reading it: {e}"))?;
    if &after == state {
        Ok(())
    } else {
        Err(format!(
            "{shown} is {} after the restore, {} expected",
            after.describe(),
            state.describe()
        ))
    }
}

/// `s` without ANSI escape sequences (the agent colours its log unless
/// `NO_COLOR` is set).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for d in chars.by_ref() {
                if ('@'..='~').contains(&d) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
