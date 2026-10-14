//! `kill_process` and `kill_process_tree` — the actual SIGKILL plumbing.
//!
//! Tappa 3 contract:
//! - Refuse PID 0 and the protected set; everything else gets SIGKILL.
//! - External audit CMB-004: the signal goes through a pidfd
//!   ([`ProcRef`]) — it reaches the process that was meant, or nothing
//!   once it has exited, never a later holder of its PID — and the death
//!   is confirmed by polling the pidfd (readable once the process has
//!   exited, zombie included), not by `kill(pid, 0)` plus sleeps.
//! - The tree variant (external audit CMB-019) moves the root and its
//!   descendants into a cgroup of their own, walking `/proc` again until no
//!   new child appears outside it, then freezes and kills that cgroup: a
//!   tree that keeps forking cannot leave survivors (a child forked after
//!   its parent was moved is born inside). Where that is not possible (no
//!   cgroup v2 at the configured root, a kernel without `cgroup.kill`), the
//!   tree is killed process by process from a depth-first `/proc` snapshot,
//!   parent first, each process by the identity it had in the snapshot.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use super::proc_ref::{proc_stat, ProcRef};
use super::ExecutionOutcome;

/// How long a SIGKILLed process may take to exit before the kill is
/// reported `Failed` (`ETIMEDOUT`).
const EXIT_WAIT: Duration = Duration::from_millis(50);
/// Safety cap on tree size; refuse to chase fork bombs forever.
const MAX_DESCENDANTS: usize = 1000;
/// The kill cgroup's walks go further: moving a process is cheap, and a
/// descendant left outside survives. Past this the tree is reported cut
/// short (`TreeTruncated`), and NEUTRALIZE escalates.
const MAX_CGROUP_WALK: usize = 65_536;
/// External audit CMB-019: walks of `/proc` that move descendants into the
/// kill cgroup, until one moves nothing new.
const MAX_MOVE_PASSES: usize = 20;
/// How long a frozen cgroup may take to report `frozen 1`: briefly — a
/// member in an uninterruptible wait does not freeze, the kill does not
/// need it, and a rule's kill is waited for in the event loop.
const FREEZE_WAIT: Duration = Duration::from_millis(100);
/// How long a killed cgroup may take to report `populated 0`, and the
/// members still running after it may take to die once signalled again.
const KILL_WAIT: Duration = Duration::from_millis(500);

/// Kill exactly one PID (the process it names now). Verifies the target
/// is gone post-kill.
pub fn kill_process(pid: u32, protected: &HashSet<u32>) -> ExecutionOutcome {
    if pid == 0 {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID 0 invalid",
        };
    }
    kill_ref(&ProcRef::open(pid), protected)
}

/// Kill exactly the process `target` holds (external audit CMB-004).
pub fn kill_ref(target: &ProcRef, protected: &HashSet<u32>) -> ExecutionOutcome {
    let pid = target.pid();
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
    match target.signal(libc::SIGKILL) {
        Ok(()) => {
            if target.wait_exit(EXIT_WAIT) {
                ExecutionOutcome::Killed { pid }
            } else {
                ExecutionOutcome::Failed {
                    pid,
                    // "still alive after the wait": distinct from a real
                    // syscall failure.
                    errno: libc::ETIMEDOUT,
                }
            }
        }
        Err(e) => match e.raw_os_error() {
            Some(libc::ESRCH) => ExecutionOutcome::AlreadyGone { pid },
            Some(libc::EPERM) => ExecutionOutcome::PermissionDenied {
                pid,
                errno: libc::EPERM,
            },
            errno => ExecutionOutcome::Failed {
                pid,
                errno: errno.unwrap_or(0),
            },
        },
    }
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
    if root_pid <= 1 {
        return refuse_root(root_pid);
    }
    kill_tree(&ProcRef::open(root_pid), protected, guard, None)
}

fn refuse_root(root_pid: u32) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    (
        ExecutionOutcome::Refused {
            pid: root_pid,
            reason: "PID <= 1 is never a kill-tree root",
        },
        Vec::new(),
    )
}

/// Kill the tree of the process `root` holds. With `scope` (a cgroup
/// directory to create, e.g. `northnarrow.slice/blocked.scope/
/// neutralize-<n>`), through that cgroup (external audit CMB-019);
/// without it, or where the cgroup cannot be used, process by process.
pub fn kill_tree(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<&'static str>,
    scope: Option<&Path>,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    // Hard floor: PID 0 (the kernel's own parent in the /proc ppid map)
    // and PID 1 (init) can never be a tree root. The /proc walk below
    // would enumerate their descendants — for PID 0 init + kthreadd,
    // every process on the host. Refuse before walking anything.
    let root_pid = root.pid();
    if root_pid <= 1 {
        return refuse_root(root_pid);
    }
    let root_spared =
        guard(root_pid).or(protected.contains(&root_pid).then_some("PID is protected"));
    if let (Some(dir), None) = (scope, root_spared) {
        if root.is_live() {
            match kill_tree_in_cgroup(root, protected, guard, dir) {
                Ok(done) => return done,
                Err(e) => tracing::warn!(
                    root_pid,
                    scope = %dir.display(),
                    error = %e,
                    "kill tree: the kill cgroup cannot be used — killing process by process"
                ),
            }
        }
    }
    kill_tree_by_pid(root, protected, guard)
}

/// The tree killed process by process from a `/proc` snapshot taken
/// before any kill: the parent first (it stops a fork bomb), then each
/// descendant by the identity it had in the snapshot — a PID that names
/// another process by then is not touched.
fn kill_tree_by_pid(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<&'static str>,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    let root_pid = root.pid();
    // External audit CMB-004: the children of the PID are the root's only
    // while the PID names it — checked after the walk (the PID cannot
    // change hands while the root runs). A root that has exited left its
    // children to a reaper; a walk from its PID finds those of the
    // process that holds it now.
    let walk = collect_descendants(root_pid);
    let named = root.still_named_by_pid();
    let (descendants, truncated, walk_error) = match walk {
        Ok((found, cut)) if named => (found, cut, None),
        // A root that still runs, its tree unreadable (out of
        // descriptors): not "no descendants".
        Err(e) if named => (Vec::new(), false, e.raw_os_error().or(Some(libc::EIO))),
        _ => (Vec::new(), false, None),
    };

    let primary = match guard(root_pid) {
        Some(reason) => ExecutionOutcome::Refused {
            pid: root_pid,
            reason,
        },
        None => kill_ref(root, protected),
    };

    let mut outcomes = Vec::with_capacity(descendants.len() + 1);
    for (child_pid, start) in descendants {
        outcomes.push(match guard(child_pid) {
            Some(reason) => ExecutionOutcome::Refused {
                pid: child_pid,
                reason,
            },
            None => {
                let child = ProcRef::open(child_pid);
                if child.start_ticks() == Some(start) {
                    kill_ref(&child, protected)
                } else if let Some(errno) = child.capture_errno() {
                    // not captured (the agent out of descriptors): it may
                    // still run
                    ExecutionOutcome::Failed {
                        pid: child_pid,
                        errno,
                    }
                } else {
                    // exited since the snapshot (its PID free, or reused)
                    ExecutionOutcome::AlreadyGone { pid: child_pid }
                }
            }
        });
    }
    if let Some(errno) = walk_error {
        tracing::warn!(
            root_pid,
            error = %std::io::Error::from_raw_os_error(errno),
            "kill tree: the /proc walk failed; the descendants were not reached"
        );
        outcomes.push(ExecutionOutcome::Failed {
            pid: root_pid,
            errno,
        });
    }
    // External audit CMB-002: a walk cut short is reported, not hidden —
    // the descendants it did not reach are still running.
    if truncated {
        tracing::warn!(
            root_pid,
            limit = MAX_DESCENDANTS,
            "kill tree: the /proc walk stopped at the descendant limit; the rest were not reached"
        );
        outcomes.push(ExecutionOutcome::TreeTruncated {
            pid: root_pid,
            limit: MAX_DESCENDANTS,
        });
    }
    (primary, outcomes)
}

/// External audit CMB-019: kill the tree through a cgroup of its own.
/// `Err` when the cgroup cannot be used at all (the caller falls back to
/// [`kill_tree_by_pid`]); once processes were moved, the outcome reports
/// what the kill achieved.
fn kill_tree_in_cgroup(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<&'static str>,
    dir: &Path,
) -> std::io::Result<(ExecutionOutcome, Vec<ExecutionOutcome>)> {
    use std::io::{Error, ErrorKind};
    let root_pid = root.pid();
    make_kill_cgroup(dir)?;
    let procs = dir.join("cgroup.procs");
    if !procs.exists() || !dir.join("cgroup.kill").exists() {
        let _ = std::fs::remove_dir(dir);
        return Err(Error::new(
            ErrorKind::Unsupported,
            "not a cgroup v2 directory with cgroup.kill (kernel 5.14+)",
        ));
    }
    // The root: only while its PID still names it (CMB-004).
    if !root.still_named_by_pid() {
        let _ = std::fs::remove_dir(dir);
        return Ok((ExecutionOutcome::AlreadyGone { pid: root_pid }, Vec::new()));
    }
    if let Err(e) = super::block_outbound::write_pid(&procs, root_pid) {
        let _ = std::fs::remove_dir(dir);
        if e.raw_os_error() == Some(libc::ESRCH) {
            return Ok((ExecutionOutcome::AlreadyGone { pid: root_pid }, Vec::new()));
        }
        return Err(e);
    }
    let rel = cgroup_rel(dir);
    // Every descendant moved in or found inside, by its start: each is
    // checked after the kill.
    let mut members: Vec<(u32, u64)> = Vec::new();
    // The descendants the cgroup did not take: spared by the guard, not
    // captured, or not moved (then killed on their own).
    let mut others: Vec<ExecutionOutcome> = Vec::new();
    let mut seen: HashSet<(u32, u64)> = HashSet::new();
    let mut truncated = false;
    let mut walk_error: Option<i32> = None;
    // Move every descendant still outside the cgroup; a child forked by a
    // moved process is born inside. Again until a walk moves nothing.
    let mut sweep = |members: &mut Vec<(u32, u64)>, others: &mut Vec<ExecutionOutcome>| -> usize {
        let (descendants, cut) = match collect_descendants_capped(root_pid, MAX_CGROUP_WALK) {
            Ok(found) => found,
            Err(e) => {
                walk_error = e.raw_os_error().or(Some(libc::EIO));
                return 0;
            }
        };
        // The walk found the root's descendants only if the PID still
        // named the root when it ended (CMB-004; the root exits on its own
        // at times): nothing more is moved once it does not.
        if !root.still_named_by_pid() {
            return 0;
        }
        walk_error = None;
        truncated |= cut;
        let mut new = 0;
        for (pid, start) in descendants {
            if !seen.insert((pid, start)) {
                continue;
            }
            if let Some(reason) =
                guard(pid).or(protected.contains(&pid).then_some("PID is protected"))
            {
                others.push(ExecutionOutcome::Refused { pid, reason });
                continue;
            }
            if rel.as_deref().is_some_and(|r| pid_in_cgroup(pid, r)) {
                // born inside: the cgroup's kill reaches it
                members.push((pid, start));
                continue;
            }
            let child = ProcRef::open(pid);
            if let Some(errno) = child.capture_errno() {
                others.push(ExecutionOutcome::Failed { pid, errno });
                continue;
            }
            if child.start_ticks() != Some(start) || !child.still_named_by_pid() {
                continue; // exited since the walk
            }
            match super::block_outbound::write_pid(&procs, pid) {
                Ok(()) => {
                    members.push((pid, start));
                    new += 1;
                }
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                // not moved: killed on its own
                Err(_) => others.push(kill_ref(&child, protected)),
            }
        }
        new
    };
    for _ in 0..MAX_MOVE_PASSES {
        if sweep(&mut members, &mut others) == 0 {
            break;
        }
    }
    // Freeze, sweep until nothing more is moved (a child forked by a
    // process not yet moved when the last walk read it), then kill
    // everything inside.
    let _ = std::fs::write(dir.join("cgroup.freeze"), "1");
    let _ = wait_cgroup_event(dir, "frozen 1", FREEZE_WAIT);
    for _ in 0..MAX_MOVE_PASSES {
        if sweep(&mut members, &mut others) == 0 {
            break;
        }
    }
    if let Err(e) = std::fs::write(dir.join("cgroup.kill"), "1") {
        // The caller kills them process by process: not left frozen.
        let _ = std::fs::write(dir.join("cgroup.freeze"), "0");
        return Err(e);
    }
    let emptied = wait_cgroup_event(dir, "populated 0", KILL_WAIT);
    if emptied {
        let _ = std::fs::remove_dir(dir);
    }
    // Checked by identity, not by `cgroup.procs`: a process moved out of
    // the cgroup before the kill (by a concurrent action, or by itself)
    // was not reached by it.
    let primary = if root.wait_exit(EXIT_WAIT) {
        ExecutionOutcome::Killed { pid: root_pid }
    } else {
        kill_ref(root, protected)
    };
    let mut outcomes = check_members(&members);
    outcomes.extend(others);
    if let Some(errno) = walk_error {
        tracing::warn!(
            root_pid,
            error = %std::io::Error::from_raw_os_error(errno),
            "kill tree: the last /proc walk failed; descendants outside the cgroup were not reached"
        );
        outcomes.push(ExecutionOutcome::Failed {
            pid: root_pid,
            errno,
        });
    }
    if truncated {
        // The descendants past the walk's limit were not moved: still
        // running outside the cgroup (external audit CMB-002).
        tracing::warn!(
            root_pid,
            limit = MAX_CGROUP_WALK,
            "kill tree: a /proc walk stopped at the descendant limit; the descendants past it were not reached"
        );
        outcomes.push(ExecutionOutcome::TreeTruncated {
            pid: root_pid,
            limit: MAX_CGROUP_WALK,
        });
    }
    tracing::info!(
        root_pid,
        killed = outcomes
            .iter()
            .filter(|o| matches!(o, ExecutionOutcome::Killed { .. }))
            .count(),
        emptied,
        "kill tree: the tree was frozen and killed in a cgroup of its own"
    );
    Ok((primary, outcomes))
}

/// After the cgroup's kill, each member by its identity. One still
/// running — moved out before the kill, or stuck in an uninterruptible
/// wait — is signalled on its own; they are waited for together.
fn check_members(members: &[(u32, u64)]) -> Vec<ExecutionOutcome> {
    let mut outcomes = Vec::with_capacity(members.len());
    let mut running: Vec<ProcRef> = Vec::new();
    for &(pid, start) in members {
        if !proc_stat(pid).is_some_and(|s| s.start_ticks == start && !s.zombie) {
            outcomes.push(ExecutionOutcome::Killed { pid });
            continue;
        }
        let r = ProcRef::open(pid);
        if r.start_ticks() != Some(start) {
            outcomes.push(match r.capture_errno() {
                Some(errno) => ExecutionOutcome::Failed { pid, errno },
                None => ExecutionOutcome::Killed { pid },
            });
            continue;
        }
        let _ = r.signal(libc::SIGKILL);
        running.push(r);
    }
    let deadline = std::time::Instant::now() + KILL_WAIT;
    for r in running {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let pid = r.pid();
        outcomes.push(if r.wait_exit(left) {
            ExecutionOutcome::Killed { pid }
        } else {
            ExecutionOutcome::Failed {
                pid,
                errno: libc::ETIMEDOUT,
            }
        });
    }
    outcomes
}

/// Create the kill cgroup, a fresh one. Its name holds the agent's PID and
/// a counter: a directory an earlier agent with the same PID left is
/// removed first when it is empty; one that still holds processes is not
/// reused (`EBUSY`: the caller kills process by process).
fn make_kill_cgroup(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::create_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_dir(dir)?;
            std::fs::create_dir(dir)
        }
        other => other,
    }
}

/// At start: the kill cgroups (`neutralize-*` under `blocked`) an earlier
/// agent left — stopped in the middle of a kill, its tree frozen. What
/// they hold was moved there to be killed: the kill is finished, and the
/// directories removed. Returns how many were removed.
pub fn reap_stale_kill_cgroups(blocked: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(blocked) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with("neutralize-")
        {
            continue;
        }
        let dir = entry.path();
        let populated = std::fs::read_to_string(dir.join("cgroup.events"))
            .is_ok_and(|e| e.lines().any(|l| l.trim() == "populated 1"));
        if populated {
            tracing::warn!(
                cgroup = %dir.display(),
                "a kill cgroup left by an earlier agent still holds processes — killing them"
            );
            let _ = std::fs::write(dir.join("cgroup.kill"), "1");
            let _ = wait_cgroup_event(&dir, "populated 0", KILL_WAIT);
        }
        if std::fs::remove_dir(&dir).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The cgroup v2 path of `dir` as `/proc/<pid>/cgroup` shows it (relative
/// to the cgroup2 mount), when `dir` is under `/sys/fs/cgroup`.
fn cgroup_rel(dir: &Path) -> Option<String> {
    let rel = dir.strip_prefix("/sys/fs/cgroup").ok()?;
    Some(format!("/{}", rel.display()))
}

fn pid_in_cgroup(pid: u32, rel: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|c| c.lines().any(|l| l.strip_prefix("0::") == Some(rel)))
}

/// Wait until `cgroup.events` holds the line `want`, at most `timeout`.
fn wait_cgroup_event(dir: &Path, want: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(dir.join("cgroup.events"))
            .is_ok_and(|e| e.lines().any(|l| l.trim() == want))
        {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Depth-first walk through the parent→children map built from `/proc`.
/// Returns descendant `(pid, start ticks)`, capped at [`MAX_DESCENDANTS`],
/// and whether the cap cut the walk short (external audit CMB-002).
fn collect_descendants(root_pid: u32) -> std::io::Result<(Vec<(u32, u64)>, bool)> {
    collect_descendants_capped(root_pid, MAX_DESCENDANTS)
}

fn collect_descendants_capped(
    root_pid: u32,
    cap: usize,
) -> std::io::Result<(Vec<(u32, u64)>, bool)> {
    let map = build_ppid_map()?;
    let mut out: Vec<(u32, u64)> = Vec::new();
    let mut frontier: Vec<u32> = vec![root_pid];

    while let Some(parent) = frontier.pop() {
        if let Some(children) = map.get(&parent) {
            for &(child, start) in children {
                // init (1) and kthreadd (2) are never "descendants" of
                // anything we are allowed to kill; skipping them here
                // also prunes every kernel thread from the walk.
                if child <= 2 {
                    continue;
                }
                if out.len() >= cap {
                    return Ok((out, true));
                }
                out.push((child, start));
                frontier.push(child);
            }
        }
    }
    Ok((out, false))
}

/// Build the `ppid → [(child_pid, start ticks), ...]` adjacency map from
/// /proc.
fn build_ppid_map() -> std::io::Result<HashMap<u32, Vec<(u32, u64)>>> {
    let mut map: HashMap<u32, Vec<(u32, u64)>> = HashMap::new();
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
        map.entry(stat.ppid as u32)
            .or_default()
            .push((stat.pid as u32, stat.starttime));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::proc_ref::ProcRef;

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

    /// A shell with two `sleep` children; returns (shell, [child pids]).
    /// Its own tree: the tests kill it, never the test runner's children
    /// (other tests run theirs in parallel).
    fn shell_with_two_sleepers() -> (std::process::Child, Vec<u32>) {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let mut sh = Command::new("sh")
            .args(["-c", "sleep 30 & echo $!; sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let mut out = std::io::BufReader::new(sh.stdout.take().unwrap());
        let mut kids = Vec::new();
        for _ in 0..2 {
            let mut line = String::new();
            out.read_line(&mut line).unwrap();
            kids.push(line.trim().parse::<u32>().unwrap());
        }
        (sh, kids)
    }

    /// combat-avail-2: a guarded descendant is spared and reported, the
    /// unguarded ones are still killed.
    #[test]
    fn kill_tree_guard_spares_descendants() {
        let (mut sh, kids) = shell_with_two_sleepers();
        let (spared, killed) = (kids[0], kids[1]);
        let (primary, rest) = kill_process_tree_guarded(sh.id(), &protected_with(&[]), &|pid| {
            (pid == spared).then_some("host-critical (test guard)")
        });
        assert!(
            matches!(primary, ExecutionOutcome::Killed { pid } if pid == sh.id()),
            "{primary:?}"
        );
        assert!(
            rest.iter().any(|o| matches!(o, ExecutionOutcome::Refused { pid, reason } if *pid == spared && reason.contains("test guard"))),
            "spared child must be reported as Refused: {rest:?}"
        );
        assert!(
            rest.iter().any(|o| matches!(o, ExecutionOutcome::Killed { pid } | ExecutionOutcome::AlreadyGone { pid } if *pid == killed)),
            "unguarded child must be killed: {rest:?}"
        );
        let _ = sh.wait();
        // the spared sleeper still runs
        assert!(ProcRef::open(spared).is_live(), "spared child was killed");
        // SAFETY: plain kill(2) on a process this test started.
        unsafe { libc::kill(spared as i32, libc::SIGKILL) };
    }

    /// External audit CMB-004: the captured root has exited and its PID
    /// names another process (here: a shell with two children) — the tree
    /// kill touches neither that process nor its children.
    #[test]
    fn a_tree_kill_spares_the_children_of_a_reused_root_pid() {
        let (mut sh, kids) = shell_with_two_sleepers();
        // a capture of an earlier holder of the shell's PID, since exited
        let earlier = ProcRef::for_test(sh.id(), Some(1));
        let (primary, rest) = kill_tree(&earlier, &protected_with(&[]), &|_| None, None);
        assert!(
            matches!(primary, ExecutionOutcome::AlreadyGone { pid } if pid == sh.id()),
            "{primary:?}"
        );
        assert!(
            rest.is_empty(),
            "no walk from a PID that names another process: {rest:?}"
        );
        for kid in &kids {
            assert!(
                ProcRef::open(*kid).is_live(),
                "child {kid} of the PID's new holder was killed"
            );
        }
        assert!(ProcRef::open(sh.id()).is_live());
        let _ = sh.kill();
        let _ = sh.wait();
        for kid in kids {
            // SAFETY: plain kill(2) on processes this test started.
            unsafe { libc::kill(kid as i32, libc::SIGKILL) };
        }
    }

    /// External audit CMB-004 (privileged: writes `ns_last_pid`): a
    /// process captured, exited, and its PID given to a harmless one — the
    /// kill through the capture does not reach the new holder.
    #[test]
    #[ignore = "privileged: root (ns_last_pid)"]
    fn a_reused_pid_is_not_killed() {
        use std::process::{Command, Stdio};
        for _attempt in 0..20 {
            let mut first = Command::new("sleep")
                .arg("30")
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let pid = first.id();
            let captured = ProcRef::open(pid);
            first.kill().unwrap();
            first.wait().unwrap();
            // the next fork gets `pid` (unless another one takes it first)
            if std::fs::write("/proc/sys/kernel/ns_last_pid", format!("{}", pid - 1)).is_err() {
                panic!("cannot write ns_last_pid: run as root");
            }
            let mut harmless = Command::new("sleep")
                .arg("30")
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            if harmless.id() != pid {
                let _ = harmless.kill();
                let _ = harmless.wait();
                continue;
            }
            let outcome = kill_ref(&captured, &HashSet::new());
            assert!(
                matches!(outcome, ExecutionOutcome::AlreadyGone { .. }),
                "{outcome:?}"
            );
            assert!(
                harmless.try_wait().unwrap().is_none(),
                "the process now holding the PID was killed"
            );
            // the old path, by PID, would have reached it
            assert!(ProcRef::open(pid).is_live());
            let _ = harmless.kill();
            let _ = harmless.wait();
            return;
        }
        panic!("the PID was never reused in 20 attempts");
    }

    /// External audit CMB-019 (privileged: root, cgroup v2, kernel 5.14+):
    /// a tree whose processes keep forking is killed whole through its
    /// kill cgroup — no process carrying the test's marker survives.
    #[test]
    #[ignore = "privileged: root, cgroup v2 with cgroup.kill"]
    fn kill_tree_reaps_a_tree_that_keeps_forking() {
        use std::process::{Command, Stdio};
        const MARKER: &str = "NNX_CMB019_FORK_TREE";
        let marked = || -> Vec<u32> {
            std::fs::read_dir("/proc")
                .unwrap()
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .filter(|pid| {
                    std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|env| {
                        env.split(|b| *b == 0)
                            .any(|kv| kv.starts_with(MARKER.as_bytes()))
                    })
                })
                .collect()
        };
        // the root keeps forking (a child every 3 ms, each with one
        // grandchild): linear growth, never a fork bomb
        let script = "while :; do ( sleep 600 & sleep 600 ) & sleep 0.003; done";
        let mut root = Command::new("bash")
            .args(["-c", script])
            .env(MARKER, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(marked().len() > 5, "the tree did not grow");
        let scope = std::path::PathBuf::from(format!(
            "/sys/fs/cgroup/northnarrow-test.slice/blocked.scope/neutralize-{}",
            std::process::id()
        ));
        // the cgroup path itself: the per-process fallback must not pass
        // this test in its place
        let (primary, rest) = kill_tree_in_cgroup(
            &ProcRef::open(root.id()),
            &HashSet::new(),
            &|_| None,
            &scope,
        )
        .expect("the kill cgroup could not be used");
        let _ = root.wait();
        std::thread::sleep(Duration::from_millis(200));
        let left = marked();
        // clean up whatever survived before asserting
        for pid in &left {
            // SAFETY: plain kill(2) on the test's own marked processes.
            unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
        }
        let _ = std::fs::remove_dir(&scope);
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice/blocked.scope");
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice");
        assert!(
            matches!(primary, ExecutionOutcome::Killed { .. }),
            "{primary:?}"
        );
        assert!(
            left.is_empty(),
            "survivors of the fork tree: {left:?} ({} outcomes)",
            rest.len()
        );
        assert!(
            rest.iter()
                .all(|o| matches!(o, ExecutionOutcome::Killed { .. })),
            "every member killed: {:?}",
            rest.iter()
                .filter(|o| !matches!(o, ExecutionOutcome::Killed { .. }))
                .collect::<Vec<_>>()
        );
    }

    /// External audit CMB-019: a member is checked by its identity after
    /// the cgroup's kill — one still running (moved out of the cgroup
    /// before the kill) is killed on its own, not counted from
    /// `cgroup.procs`.
    #[test]
    fn a_member_still_running_after_the_kill_is_killed_on_its_own() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let start = crate::response::proc_ref::proc_start_ticks(pid).unwrap();
        // with a member that has gone: both killed
        let outcomes = check_members(&[(pid, start), (999_999_999, 1)]);
        assert_eq!(outcomes.len(), 2, "{outcomes:?}");
        for p in [pid, 999_999_999] {
            assert!(
                outcomes.contains(&ExecutionOutcome::Killed { pid: p }),
                "{outcomes:?}"
            );
        }
        let status = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the running member was killed"
        );
        // a PID that names another process by now (another start): untouched
        let mut other = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let outcomes = check_members(&[(other.id(), 1)]);
        assert!(matches!(outcomes[..], [ExecutionOutcome::Killed { .. }]));
        assert!(
            ProcRef::open(other.id()).is_live(),
            "another process was killed"
        );
        let _ = other.kill();
        let _ = other.wait();
    }

    /// The kill cgroup is a fresh directory: an empty one left with the
    /// same name is replaced; one that cannot be removed is not reused.
    #[test]
    fn a_kill_cgroup_is_never_reused() {
        let base = std::env::temp_dir().join(format!("nn-killcg-{}", std::process::id()));
        let dir = base.join("blocked.scope/neutralize-1-0");
        make_kill_cgroup(&dir).unwrap();
        assert!(dir.is_dir());
        make_kill_cgroup(&dir).unwrap(); // empty: replaced
        std::fs::write(dir.join("left"), "x").unwrap();
        assert!(
            make_kill_cgroup(&dir).is_err(),
            "a used directory is not reused"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// At start, the kill cgroups an earlier agent left are removed; the
    /// other directories below the blocked scope are not touched.
    #[test]
    fn stale_kill_cgroups_are_removed_at_start() {
        let blocked = std::env::temp_dir().join(format!("nn-reap-{}", std::process::id()));
        std::fs::create_dir_all(blocked.join("neutralize-7-0")).unwrap();
        std::fs::create_dir_all(blocked.join("neutralize-7-1")).unwrap();
        std::fs::create_dir_all(blocked.join("other")).unwrap();
        assert_eq!(reap_stale_kill_cgroups(&blocked), 2);
        assert!(blocked.join("other").is_dir());
        assert!(!blocked.join("neutralize-7-0").exists());
        assert_eq!(reap_stale_kill_cgroups(&blocked.join("missing")), 0);
        let _ = std::fs::remove_dir_all(&blocked);
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
        let (kids, truncated) = collect_descendants(0).expect("walk ok");
        assert!(kids.is_empty(), "got {kids:?}");
        assert!(!truncated);
    }

    #[test]
    fn collect_descendants_returns_empty_for_unknown_root() {
        // PID 999_999_998 has no entry in /proc, so no descendants.
        let (kids, truncated) = collect_descendants(999_999_998).expect("walk ok");
        assert!(kids.is_empty());
        assert!(!truncated);
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
