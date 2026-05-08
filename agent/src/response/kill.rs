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
    // Snapshot the proc tree once before we kill anything; new
    // children spawned after this point are out of scope of this run.
    let descendants = collect_descendants(root_pid).unwrap_or_default();

    // Kill the parent FIRST: stops a fork bomb from outpacing us.
    let primary = kill_process(root_pid, protected);

    let mut outcomes = Vec::with_capacity(descendants.len());
    for child_pid in descendants {
        outcomes.push(kill_process(child_pid, protected));
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
