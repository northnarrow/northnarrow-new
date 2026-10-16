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
const COMBAT_CHAIN: &str = "NORTHNARROW_COMBAT";

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
pub struct EniIptablesGuard;

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
        Self
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
                .args(["-D", base, "-j", COMBAT_CHAIN])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        // Step 2: flush the chain's contents (so a future -X
        // succeeds even if the rules were partially built).
        let _ = Command::new("iptables")
            .args(["-F", COMBAT_CHAIN])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // Step 3: delete the chain itself.
        let _ = Command::new("iptables")
            .args(["-X", COMBAT_CHAIN])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ── Self-tests ────────────────────────────────────────────────────────
//
// These tests verify Drop semantics under both panic and clean-state
// paths. They REQUIRE root + iptables and run only under the
// `test-privileged` feature gate. `#[ignore]` follows the same
// runbook pattern as the FIM + canary priv-e2e tests — operators
// run them with `--include-ignored` from `docs/integration-test-
// runbook.md`. They do NOT run during `cargo test --workspace`
// on a dev box.

#[cfg(all(test, feature = "test-privileged"))]
mod tests {
    use super::*;

    /// Manually install a fake `NORTHNARROW_COMBAT` chain (so the
    /// test doesn't need a running agent), then drop the guard
    /// inside `catch_unwind` to prove the cleanup runs even when
    /// the surrounding test panics. The chain MUST be gone after
    /// the drop regardless of the panic outcome.
    #[test]
    #[ignore = "requires sudo + iptables (run via integration runbook)"]
    fn iptables_guard_drops_cleans_chain_even_on_panic() {
        // Pre-install the chain + a jump rule so the guard has
        // something to clean.
        let new_chain = Command::new("iptables")
            .args(["-N", COMBAT_CHAIN])
            .status()
            .expect("spawn iptables -N");
        assert!(
            new_chain.success(),
            "iptables -N {COMBAT_CHAIN} failed (test precondition)"
        );
        let jump = Command::new("iptables")
            .args(["-I", "INPUT", "-j", COMBAT_CHAIN])
            .status()
            .expect("spawn iptables -I INPUT");
        assert!(jump.success(), "iptables -I INPUT failed (precondition)");

        // Sanity: chain is present pre-drop.
        assert!(
            !EniIptablesGuard::is_clean(),
            "test precondition: chain should be present before guard drop"
        );

        // Force a panic INSIDE the guard's scope so Drop runs on
        // the unwind path, not the normal-return path.
        let result = std::panic::catch_unwind(|| {
            let _guard = EniIptablesGuard::install();
            panic!("simulated test failure to exercise unwind-path Drop");
        });
        assert!(result.is_err(), "the inner closure should have panicked");

        // Chain MUST be gone after guard drop (unwind-path
        // cleanup completed).
        assert!(
            EniIptablesGuard::is_clean(),
            "EniIptablesGuard::drop failed to clean NORTHNARROW_COMBAT \
             after panic; iptables -S {COMBAT_CHAIN} still succeeds"
        );
    }

    /// Drop the guard on an already-clean state. No iptables
    /// chain exists; the three commands (`-D` / `-F` / `-X`)
    /// each fail individually, and Drop must swallow those
    /// failures rather than panic-on-drop (which would mask
    /// the actual test failure).
    #[test]
    #[ignore = "requires sudo + iptables (run via integration runbook)"]
    fn iptables_guard_idempotent_on_clean_state() {
        // Ensure chain is gone (best-effort — already absent is
        // fine; this is the test precondition).
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-j", COMBAT_CHAIN])
            .status();
        let _ = Command::new("iptables").args(["-F", COMBAT_CHAIN]).status();
        let _ = Command::new("iptables").args(["-X", COMBAT_CHAIN]).status();
        assert!(
            EniIptablesGuard::is_clean(),
            "test precondition: chain must be absent at start"
        );

        // Construct + drop. No panic-on-drop, no test failure.
        {
            let _guard = EniIptablesGuard::install();
        }

        // Still clean afterwards.
        assert!(
            EniIptablesGuard::is_clean(),
            "guard's idempotent drop should not have created a chain"
        );
    }
}

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
