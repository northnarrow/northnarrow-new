//! Shared utilities for the agent's privileged integration tests.
//!
//! Cargo treats files directly in `tests/` as standalone test
//! crates; the `common/mod.rs` layout deliberately nests under a
//! directory so this file is NOT a test target, just a module
//! consumed via `mod common;` from each test file that needs it.

#![allow(dead_code)]

use std::process::{Command, Stdio};

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

/// Remove `pid` AND every process below it from the pinned
/// `PROTECTED_PIDS` map so a plain signal from the test runner reaches
/// the agent. Since `task-kill-signals-1` the task_kill LSM hook denies
/// EVERY userspace signal towards a protected pid unless the caller is
/// the process itself, another protected pid or PID 1 with the armed
/// nonce — the test runner is none of those. The fixtures spawn the
/// agent through `sudo`, so `Child::id()` is sudo's pid and the agent is
/// its child. Walking the descendants covers both shapes. Best effort:
/// a missing pin or bpftool means the agent was never protected.
#[allow(dead_code)]
pub fn unprotect_pid(pid: u32) {
    for p in process_tree(pid) {
        let key_bytes = [
            p & 0xFF,
            (p >> 8) & 0xFF,
            (p >> 16) & 0xFF,
            (p >> 24) & 0xFF,
        ]
        .map(|b| b.to_string());
        let _ = Command::new("sudo")
            .args([
                "bpftool",
                "map",
                "delete",
                "pinned",
                "/sys/fs/bpf/northnarrow/PROTECTED_PIDS",
                "key",
            ])
            .args(key_bytes)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Stop an agent the fixture spawned through `sudo` and reap it.
///
/// SIGQUIT is the supported shutdown (the LSM hook denies SIGKILL and
/// SIGTERM from userland). The signal is delivered to EVERY process in
/// the `sudo` subtree, agent included, not only to `Child::id()` (the
/// sudo pid): sudo 1.9.9 (Ubuntu 22.04) does not relay a signal sent
/// by a process in its own process group — the test runner — while
/// 1.9.15 (Ubuntu 24.04) does, so relying on the relay hung every
/// fixture teardown in `wait4` on the 22.04 / 5.15 lab guest. The
/// wait is bounded (10 s) so a teardown problem fails the test loudly
/// instead of wedging the whole suite.
#[allow(dead_code)]
pub fn quit_agent(child: &mut std::process::Child) {
    let root = child.id();
    unprotect_pid(root);
    // Leaves first, then sudo itself, so nothing is left to re-spawn.
    for p in process_tree(root).into_iter().rev() {
        unsafe {
            libc::kill(p as i32, libc::SIGQUIT);
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Ok(None) => {
                eprintln!(
                    "quit_agent: sudo pid {root} still alive 10 s after SIGQUIT — leaving it"
                );
                return;
            }
            Err(e) => {
                eprintln!("quit_agent: try_wait on pid {root} failed: {e}");
                return;
            }
        }
    }
}
