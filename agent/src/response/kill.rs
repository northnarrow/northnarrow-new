//! `kill_process` and `kill_process_tree` — the actual SIGKILL plumbing.
//!
//! Tappa 3 contract:
//! - Refuse PID 0 and the protected set; everything else gets SIGKILL.
//! - After the syscall, verify the target is gone via `kill(pid, 0)`
//!   (signal 0 is the canonical "does this process exist?" probe).
//!   Retry briefly because SIGKILL is asynchronous: the scheduler
//!   needs a few cycles to dispatch and reap the task.
//! - The tree variant walks `/proc` once, BFS from the root, then
//!   kills the parent FIRST so a fork-bombing target can't keep
//!   spawning new children faster than we can reap them.

use std::{collections::HashSet, thread, time::Duration};

use nix::{
    errno::Errno,
    sys::signal::{kill as nix_kill, Signal},
    unistd::Pid,
};

use super::ExecutionOutcome;

/// Number of post-SIGKILL existence probes before giving up and
/// reporting `Failed`. 5 × 10 ms = 50 ms hard cap on a stuck reap.
const VERIFY_RETRIES: u32 = 5;
/// Per-retry delay between probes.
const VERIFY_DELAY: Duration = Duration::from_millis(10);
/// Safety cap on tree size; refuse to chase fork bombs forever.
const MAX_DESCENDANTS: usize = 1000;

/// Kill exactly one PID. Verifies the target is gone post-kill.
pub fn kill_process(pid: u32, protected: &HashSet<u32>) -> ExecutionOutcome {
    if pid == 0 {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID 0 invalid",
        };
    }
    if protected.contains(&pid) {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID is protected",
        };
    }
    let nix_pid = Pid::from_raw(pid as i32);

    match nix_kill(nix_pid, Signal::SIGKILL) {
        Ok(()) => verify_dead(pid, nix_pid),
        Err(Errno::ESRCH) => ExecutionOutcome::AlreadyGone { pid },
        Err(Errno::EPERM) => ExecutionOutcome::PermissionDenied {
            pid,
            errno: Errno::EPERM as i32,
        },
        Err(e) => ExecutionOutcome::Failed {
            pid,
            errno: e as i32,
        },
    }
}

/// Confirm the target is no longer running.
///
/// "No longer running" covers two states from a defender's POV:
///
/// - `ESRCH` from `kill(pid, 0)` — the task is gone entirely.
/// - The task exists as a zombie (`/proc/<pid>/stat` state `Z`) —
///   killed, awaiting reap by its parent. Can't execute code, so for
///   incident response that's "neutralised". Reaping is the parent's
///   problem; we don't want to depend on it here because orphans only
///   get reaped when init(1) gets to them.
fn verify_dead(pid: u32, nix_pid: Pid) -> ExecutionOutcome {
    for attempt in 0..VERIFY_RETRIES {
        match nix_kill(nix_pid, None) {
            Err(Errno::ESRCH) => return ExecutionOutcome::Killed { pid },
            Ok(()) => {
                if is_zombie(pid) {
                    return ExecutionOutcome::Killed { pid };
                }
            }
            // EPERM probing our own SIGKILL target is unexpected; retry.
            Err(Errno::EPERM) => {}
            Err(e) => {
                return ExecutionOutcome::Failed {
                    pid,
                    errno: e as i32,
                }
            }
        }
        if attempt + 1 < VERIFY_RETRIES {
            thread::sleep(VERIFY_DELAY);
        }
    }
    ExecutionOutcome::Failed {
        pid,
        // Map "still alive after retries" to ETIMEDOUT so the caller can
        // distinguish it from "real" syscall failures.
        errno: Errno::ETIMEDOUT as i32,
    }
}

/// True if `/proc/<pid>/stat` reports the task in zombie state (`Z`).
/// Falls back to `false` on any I/O / parse error — callers retry, so
/// a transient race resolves itself.
fn is_zombie(pid: u32) -> bool {
    procfs::process::Process::new(pid as i32)
        .and_then(|p| p.stat())
        .map(|s| s.state == 'Z')
        .unwrap_or(false)
}

/// Kill `root_pid` then every descendant found via /proc walk.
/// Returns `(primary, descendants)`.
pub fn kill_process_tree(
    root_pid: u32,
    protected: &HashSet<u32>,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    kill_process_tree_guarded(root_pid, protected, &|_| None)
}

/// [`kill_process_tree`] with an extra per-pid guard consulted for EVERY
/// pid the walk would kill (root and descendants). Audit
/// `combat-avail-2`: the COMBAT ladder's `ProtectedProcs` guard (sshd,
/// the watchdog, auth-session lineage) was only applied to the attributed
/// offenders, never to the `/proc` descendants this walk reaps — a
/// guarded sshd or watchdog *child* of an offender was killed. `guard`
/// returns the reason a pid must be spared; spared pids are reported as
/// `Refused` so the caller's audit sees them.
pub fn kill_process_tree_guarded(
    root_pid: u32,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<&'static str>,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    // Hard floor: PID 0 (the kernel's own parent in the /proc ppid map)
    // and PID 1 (init) can never be a tree root. `kill_process` already
    // refuses PID 0 and `protected` normally holds 1, but the /proc walk
    // below would STILL enumerate their descendants — for PID 0 that is
    // init + kthreadd, i.e. every process on the host — and reap them
    // one by one. Refuse before walking anything.
    if root_pid <= 1 {
        return (
            ExecutionOutcome::Refused {
                pid: root_pid,
                reason: "PID <= 1 is never a kill-tree root",
            },
            Vec::new(),
        );
    }
    // Snapshot the proc tree once before we kill anything; new
    // children spawned after this point are out of scope of this run.
    let descendants = collect_descendants(root_pid).unwrap_or_default();

    // Kill the parent FIRST: stops a fork bomb from outpacing us.
    let primary = match guard(root_pid) {
        Some(reason) => ExecutionOutcome::Refused {
            pid: root_pid,
            reason,
        },
        None => kill_process(root_pid, protected),
    };

    let mut outcomes = Vec::with_capacity(descendants.len());
    for child_pid in descendants {
        outcomes.push(match guard(child_pid) {
            Some(reason) => ExecutionOutcome::Refused {
                pid: child_pid,
                reason,
            },
            None => kill_process(child_pid, protected),
        });
    }
    (primary, outcomes)
}

/// BFS through the parent→children map built from `/proc/<pid>/status`.
/// Returns descendant PIDs in BFS order, capped at [`MAX_DESCENDANTS`].
fn collect_descendants(root_pid: u32) -> std::io::Result<Vec<u32>> {
    let map = build_ppid_map()?;
    let mut out: Vec<u32> = Vec::new();
    let mut frontier: Vec<u32> = vec![root_pid];

    while let Some(parent) = frontier.pop() {
        if let Some(children) = map.get(&parent) {
            for &child in children {
                // init (1) and kthreadd (2) are never "descendants" of
                // anything we are allowed to kill; skipping them here
                // also prunes every kernel thread from the walk.
                if child <= 2 {
                    continue;
                }
                if out.len() >= MAX_DESCENDANTS {
                    return Ok(out);
                }
                out.push(child);
                frontier.push(child);
            }
        }
    }
    Ok(out)
}

/// Build the `ppid → [child_pid, ...]` adjacency map from /proc.
fn build_ppid_map() -> std::io::Result<std::collections::HashMap<u32, Vec<u32>>> {
    use std::collections::HashMap;
    let mut map: HashMap<u32, Vec<u32>> = HashMap::new();
    let processes = match procfs::process::all_processes() {
        Ok(it) => it,
        Err(e) => {
            return Err(std::io::Error::other(format!(
                "procfs::all_processes failed: {e}"
            )))
        }
    };
    for proc in processes.flatten() {
        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue, // race: process exited mid-walk; skip
        };
        let pid = stat.pid as u32;
        let ppid = stat.ppid as u32;
        map.entry(ppid).or_default().push(pid);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protected_with(extra: &[u32]) -> HashSet<u32> {
        let mut s = HashSet::new();
        s.insert(1);
        s.insert(2);
        s.insert(std::process::id());
        for p in extra {
            s.insert(*p);
        }
        s
    }

    #[test]
    fn refuses_pid_zero() {
        let out = kill_process(0, &protected_with(&[]));
        assert!(matches!(out, ExecutionOutcome::Refused { pid: 0, .. }));
    }

    #[test]
    fn refuses_protected_pid_one() {
        let out = kill_process(1, &protected_with(&[]));
        assert!(matches!(
            out,
            ExecutionOutcome::Refused {
                pid: 1,
                reason: "PID is protected"
            }
        ));
    }

    #[test]
    fn refuses_own_pid() {
        let own = std::process::id();
        let out = kill_process(own, &protected_with(&[]));
        assert!(
            matches!(out, ExecutionOutcome::Refused { reason: "PID is protected", .. } if matches!(out, ExecutionOutcome::Refused { pid, .. } if pid == own))
        );
    }

    #[test]
    fn returns_already_gone_for_nonexistent_pid() {
        // PID 999_999_999 is well above the kernel's PID limit — guaranteed absent.
        let out = kill_process(999_999_999, &protected_with(&[]));
        assert!(matches!(
            out,
            ExecutionOutcome::AlreadyGone { pid: 999_999_999 }
        ));
    }

    /// combat-avail-2: a guarded descendant is spared and reported, the
    /// unguarded siblings are still killed. Uses our own process tree:
    /// two `sleep` children, one guarded by pid.
    #[test]
    fn kill_tree_guard_spares_descendants() {
        use std::process::{Command, Stdio};
        let mut a = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn sleep a");
        let mut b = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn sleep b");
        let (spared, killed) = (a.id(), b.id());
        // Root = this test process, which the executor set protects.
        let own = std::process::id();
        let protected = protected_with(&[]);
        let (primary, rest) = kill_process_tree_guarded(own, &protected, &|pid| {
            if pid == spared {
                Some("host-critical (test guard)")
            } else {
                None
            }
        });
        assert!(matches!(primary, ExecutionOutcome::Refused { .. }));
        assert!(
            rest.iter().any(|o| matches!(o, ExecutionOutcome::Refused { pid, reason } if *pid == spared && reason.contains("test guard"))),
            "spared child must be reported as Refused: {rest:?}"
        );
        assert!(
            rest.iter().any(|o| matches!(o, ExecutionOutcome::Killed { pid } | ExecutionOutcome::AlreadyGone { pid } if *pid == killed)),
            "unguarded child must be killed: {rest:?}"
        );
        // Cleanup: the spared sleeper is still alive; the killed one is not.
        assert!(
            a.try_wait().expect("try_wait").is_none(),
            "spared child was killed"
        );
        let _ = a.kill();
        let _ = a.wait();
        let _ = b.wait();
    }

    #[test]
    fn kill_tree_refuses_pid_zero_without_walking() {
        // PID 0's /proc "children" are init + kthreadd: walking them
        // would enumerate the whole host. Must refuse with NO outcomes.
        let (primary, rest) = kill_process_tree(0, &protected_with(&[]));
        assert!(matches!(primary, ExecutionOutcome::Refused { pid: 0, .. }));
        assert!(rest.is_empty(), "no descendant may be touched: {rest:?}");
    }

    #[test]
    fn kill_tree_refuses_pid_one_without_walking() {
        let (primary, rest) = kill_process_tree(1, &protected_with(&[]));
        assert!(matches!(primary, ExecutionOutcome::Refused { pid: 1, .. }));
        assert!(rest.is_empty(), "no descendant may be touched: {rest:?}");
    }

    #[test]
    fn collect_descendants_never_yields_init_or_kthreadd() {
        // Even when asked for PID 0's subtree directly, the walk must
        // not surface PID 1 / PID 2 (and therefore none of their kids).
        let kids = collect_descendants(0).expect("walk ok");
        assert!(kids.is_empty(), "got {kids:?}");
    }

    #[test]
    fn collect_descendants_returns_empty_for_unknown_root() {
        // PID 999_999_998 has no entry in /proc, so no descendants.
        let kids = collect_descendants(999_999_998).expect("walk ok");
        assert!(kids.is_empty());
    }

    #[test]
    fn build_ppid_map_includes_at_least_one_child_of_init() {
        // On a Linux host running this test, init (PID 1) always has
        // direct children. This pins the /proc walk against silent
        // regressions.
        let map = build_ppid_map().expect("walk ok");
        assert!(
            map.get(&1).map(|v| !v.is_empty()).unwrap_or(false),
            "expected init to have at least one direct child, got {:?}",
            map.get(&1)
        );
    }
}
