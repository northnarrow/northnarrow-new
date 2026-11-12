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

use super::journal::Intent;
use super::proc_ref::{is_gone, read_stat, ProcRef, ProcStat};
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

/// What the guard of a tree kill spares (lot 312, external bug hunt 1.4,
/// BUG-122). Decided by the coordinator for the lot:
///
/// - a host-critical process (the SSH service) is spared ALONE: the
///   offender's processes below it are killed — an sshd that forked the
///   offender's shell does not shield the shell;
/// - a protected process (the agent, its watchdog, init; a pid of the
///   executor's protected set) is spared with its whole tree: its children
///   are its own (the agent's workers and scanner).
///
/// The outcomes say each spared pid, with the reason, next to each killed
/// one. A refused root used to refuse only itself — the walk under it went
/// on and killed its children: the agent's own tree, had a verdict named
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spare {
    /// Why, for the outcome (`Refused { reason }`).
    pub reason: &'static str,
    /// It and its whole tree (`true`), or itself only.
    pub tree: bool,
}

impl Spare {
    /// A host-critical process: itself only.
    pub const fn process(reason: &'static str) -> Self {
        Self {
            reason,
            tree: false,
        }
    }

    /// A protected process: it and every process below it.
    pub const fn tree(reason: &'static str) -> Self {
        Self { reason, tree: true }
    }
}

/// The reason of a descendant spared as part of a protected tree.
pub const IN_A_PROTECTED_TREE: &str = "in the tree of a protected process";

/// The protected set's spare: the pid and its tree.
const PROTECTED: Spare = Spare::tree("PID is protected");

/// Kill exactly one PID (the process it names now). Verifies the target
/// is gone post-kill.
/// R12c (lab PR 270): only for an action whose intent is signed (`intent`).
pub fn kill_process(pid: u32, protected: &HashSet<u32>, intent: &Intent) -> ExecutionOutcome {
    if pid == 0 {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID 0 invalid",
        };
    }
    kill_ref(&ProcRef::open(pid), protected, intent)
}

/// Kill exactly the process `target` holds (external audit CMB-004). R12c
/// (lab PR 270): only for an action whose intent is signed (`intent`).
pub fn kill_ref(target: &ProcRef, protected: &HashSet<u32>, _intent: &Intent) -> ExecutionOutcome {
    kill_one(target, protected)
}

/// [`kill_ref`]'s work: the tree's kills call it for each process of an
/// action whose intent is signed.
fn kill_one(target: &ProcRef, protected: &HashSet<u32>) -> ExecutionOutcome {
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
    intent: &Intent,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    kill_process_tree_guarded(root_pid, protected, &|_| None, intent)
}

/// [`kill_process_tree`] with an extra per-pid guard consulted for EVERY
/// pid the walk would kill (root and descendants). Audit
/// `combat-avail-2`: the COMBAT ladder's `ProtectedProcs` guard (sshd,
/// the watchdog, auth-session lineage) was only applied to the attributed
/// offenders, never to the `/proc` descendants this walk reaps — a
/// guarded sshd or watchdog *child* of an offender was killed. `guard`
/// says what a pid's sparing covers ([`Spare`]); spared pids are reported
/// as `Refused` so the caller's audit sees them.
pub fn kill_process_tree_guarded(
    root_pid: u32,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
    intent: &Intent,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    if root_pid <= 1 {
        return refuse_root(root_pid);
    }
    kill_tree(&ProcRef::open(root_pid), protected, guard, None, intent)
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
/// R12c (lab PR 270): only for an action whose intent is signed (`intent`).
pub fn kill_tree(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
    scope: Option<&Path>,
    _intent: &Intent,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    // Hard floor: PID 0 (the kernel's own parent in the /proc ppid map)
    // and PID 1 (init) can never be a tree root. The /proc walk below
    // would enumerate their descendants — for PID 0 init + kthreadd,
    // every process on the host. Refuse before walking anything.
    let root_pid = root.pid();
    if root_pid <= 1 {
        return refuse_root(root_pid);
    }
    let root_spared = spare_of(root_pid, protected, guard);
    // Lot 312 (BUG-122): a protected root keeps its whole tree — nothing
    // is killed, every process of it is said spared.
    if let Some(spare) = root_spared.filter(|s| s.tree) {
        return spared_tree(root, spare);
    }
    if let (Some(dir), None) = (scope, root_spared) {
        // lot 317: a root not captured goes process by process, whose
        // outcome carries the capture's error
        if root.liveness() == super::proc_ref::Liveness::Live {
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

/// What sparing `pid` covers: the guard's answer, or the protected set's
/// (the pid and its tree).
fn spare_of(
    pid: u32,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
) -> Option<Spare> {
    guard(pid).or(protected.contains(&pid).then_some(PROTECTED))
}

/// Lot 312 (BUG-122): what sparing a descendant covers — the pid itself,
/// or every pid below it ([`Spare::tree`]): one under a spared tree
/// (`trees`, filled in the walk's order, parents first) is spared with it.
fn spare_in_walk(
    pid: u32,
    parent: u32,
    trees: &mut HashSet<u32>,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
) -> Option<Spare> {
    let spare = if trees.contains(&parent) {
        Some(Spare::tree(IN_A_PROTECTED_TREE))
    } else {
        spare_of(pid, protected, guard)
    };
    if spare.is_some_and(|s| s.tree) {
        trees.insert(pid);
    }
    spare
}

/// Lot 312 (BUG-122): the root is protected — it and every process below
/// it are spared, and said so one by one; nothing is signalled.
fn spared_tree(root: &ProcRef, spare: Spare) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    let root_pid = root.pid();
    let primary = ExecutionOutcome::Refused {
        pid: root_pid,
        reason: spare.reason,
    };
    let mut outcomes = Vec::new();
    match collect_descendants(root_pid) {
        Ok((found, cut)) if root.still_named_by_pid() => {
            outcomes.extend(
                found
                    .into_iter()
                    .map(|(pid, _, _)| ExecutionOutcome::Refused {
                        pid,
                        reason: IN_A_PROTECTED_TREE,
                    }),
            );
            if cut {
                outcomes.push(ExecutionOutcome::TreeTruncated {
                    pid: root_pid,
                    limit: MAX_DESCENDANTS,
                });
            }
        }
        _ => {}
    }
    (primary, outcomes)
}

/// The tree killed process by process from a `/proc` snapshot taken
/// before any kill: the parent first (it stops a fork bomb), then each
/// descendant by the identity it had in the snapshot — a PID that names
/// another process by then is not touched.
fn kill_tree_by_pid(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    kill_tree_by_pid_toward(root, None, protected, guard, read_stat)
}

/// Lot 312 (review of #543, F6; the coordinator's decision for BUG-122):
/// the offending lineage below a host-critical root (the SSH listener),
/// killed — the chain from the root down to the attributed offender
/// `offender`, and the offender's own subtree. The root is spared; every
/// other process below it (the other sessions) is never touched, nor
/// named. On the chain a host-critical process is killed (it is the
/// offender's session); in the offender's subtree the guard spares a
/// host-critical one alone and a protected one with its tree, as in any
/// tree kill. An offender not below the root: nothing is killed.
pub fn kill_lineage(
    root_pid: u32,
    offender: u32,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
    _intent: &Intent,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    if root_pid <= 1 {
        return refuse_root(root_pid);
    }
    let root = ProcRef::open(root_pid);
    match spare_of(root_pid, protected, guard) {
        Some(spare) if spare.tree => spared_tree(&root, spare),
        _ => kill_tree_by_pid_toward(&root, Some(offender), protected, guard, read_stat),
    }
}

/// Lot 312 (review F6): the processes a spared host-critical root's kill
/// may reach — the chain down to `toward` (the root excluded, the offender
/// excluded) and the offender's own subtree (the offender included). With
/// no offender, or one not below the root: none.
fn lineage_of(descendants: &[Descendant], toward: Option<u32>) -> (HashSet<u32>, HashSet<u32>) {
    let (mut chain, mut subtree) = (HashSet::new(), HashSet::new());
    let Some(offender) = toward else {
        return (chain, subtree);
    };
    let parent: HashMap<u32, u32> = descendants.iter().map(|&(p, _, pp)| (p, pp)).collect();
    if !parent.contains_key(&offender) {
        return (chain, subtree);
    }
    let mut up = parent[&offender];
    while let Some(&pp) = parent.get(&up) {
        chain.insert(up);
        up = pp;
    }
    subtree.insert(offender);
    for &(p, _, pp) in descendants {
        if subtree.contains(&pp) {
            subtree.insert(p);
        }
    }
    (chain, subtree)
}

/// [`kill_tree_by_pid`], the descendants' `stat` read by `read` (tests: a
/// read that fails).
#[cfg(test)]
fn kill_tree_by_pid_with(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
    read: fn(u32) -> std::io::Result<ProcStat>,
) -> (ExecutionOutcome, Vec<ExecutionOutcome>) {
    kill_tree_by_pid_toward(root, None, protected, guard, read)
}

/// [`kill_tree_by_pid`] — `toward` the attributed offender below a spared
/// host-critical root ([`kill_lineage`]).
fn kill_tree_by_pid_toward(
    root: &ProcRef,
    toward: Option<u32>,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
    read: fn(u32) -> std::io::Result<ProcStat>,
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

    // A host-critical root is spared (BUG-122); review F6: below it only
    // the offending lineage is reached — the chain to the attributed
    // offender and its subtree — never the root's other processes.
    let root_spare = spare_of(root_pid, protected, guard);
    let primary = match root_spare {
        Some(spare) => ExecutionOutcome::Refused {
            pid: root_pid,
            reason: spare.reason,
        },
        None => kill_one(root, protected),
    };
    let lineage = root_spare.map(|_| lineage_of(&descendants, toward));

    let mut trees = HashSet::new();
    let mut outcomes = Vec::with_capacity(descendants.len() + 1);
    for (child_pid, start, parent) in descendants {
        let spare = match &lineage {
            Some((chain, subtree))
                if !chain.contains(&child_pid) && !subtree.contains(&child_pid) =>
            {
                continue;
            }
            // on the chain: the offender's session, killed unless protected
            Some((chain, _)) if chain.contains(&child_pid) => {
                spare_in_walk(child_pid, parent, &mut trees, protected, &|p| {
                    guard(p).filter(|s| s.tree)
                })
            }
            _ => spare_in_walk(child_pid, parent, &mut trees, protected, guard),
        };
        outcomes.push(match spare {
            Some(spare) => ExecutionOutcome::Refused {
                pid: child_pid,
                reason: spare.reason,
            },
            None => {
                let child = ProcRef::open_checked_with(child_pid, None, read);
                if child.holds_start(start) {
                    kill_one(&child, protected)
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
    guard: &dyn Fn(u32) -> Option<Spare>,
    dir: &Path,
) -> std::io::Result<(ExecutionOutcome, Vec<ExecutionOutcome>)> {
    kill_tree_in_cgroup_with(root, protected, guard, dir, read_stat)
}

/// [`kill_tree_in_cgroup`], the descendants' and members' `stat` read by
/// `read` (tests: a read that fails).
fn kill_tree_in_cgroup_with(
    root: &ProcRef,
    protected: &HashSet<u32>,
    guard: &dyn Fn(u32) -> Option<Spare>,
    dir: &Path,
    read: fn(u32) -> std::io::Result<ProcStat>,
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
    // Lab PR 166: frozen as soon as the root is inside, before the walks
    // that move its descendants (milliseconds on a busy host), so the root
    // can neither exit nor fork meanwhile; a descendant moved in later
    // freezes on entry. The cgroup freezer, unlike SIGSTOP, is invisible
    // to the root's parent: a `sudo` mirrors a stopped command by stopping
    // itself, and stayed stopped once the command was killed (lab).
    let _ = std::fs::write(dir.join("cgroup.freeze"), "1");
    let rel = cgroup_rel(dir);
    // Every descendant moved in or found inside, by its start: each is
    // checked after the kill.
    let mut members: Vec<(u32, u64)> = Vec::new();
    // The descendants the cgroup did not take: spared by the guard, not
    // captured, or not moved (then killed on their own).
    let mut others: Vec<ExecutionOutcome> = Vec::new();
    let mut seen: HashSet<(u32, u64)> = HashSet::new();
    // Lot 312 (BUG-122): the pids whose whole tree is spared, kept across
    // the walks (a child forked later is spared with its parent).
    let mut trees: HashSet<u32> = HashSet::new();
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
        for (pid, start, parent) in descendants {
            if !seen.insert((pid, start)) {
                continue;
            }
            if let Some(spare) = spare_in_walk(pid, parent, &mut trees, protected, guard) {
                others.push(ExecutionOutcome::Refused {
                    pid,
                    reason: spare.reason,
                });
                continue;
            }
            if rel.as_deref().is_some_and(|r| pid_in_cgroup(pid, r)) {
                // born inside: the cgroup's kill reaches it
                members.push((pid, start));
                continue;
            }
            let child = ProcRef::open_checked_with(pid, None, read);
            if let Some(errno) = child.capture_errno() {
                others.push(ExecutionOutcome::Failed { pid, errno });
                continue;
            }
            if !child.holds_start(start) || !child.still_named_by_pid() {
                continue; // exited since the walk
            }
            match super::block_outbound::write_pid(&procs, pid) {
                Ok(()) => {
                    members.push((pid, start));
                    new += 1;
                }
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                // not moved: killed on its own
                Err(_) => others.push(kill_one(&child, protected)),
            }
        }
        new
    };
    // R12c-3 (lab PR 270): a root with no child — its threads' `children`
    // files, read once it is inside the cgroup, where a child it forks from
    // now on is born — has no descendant outside it: the /proc walks (each
    // reads every process's `stat`, ~50 ms of CPU a kill with EXP-13r's 400
    // processes alive) are skipped, and the cgroup's kill reaches it all.
    let childless = has_no_children(root_pid) == Some(true) && root.still_named_by_pid();
    if !childless {
        for _ in 0..MAX_MOVE_PASSES {
            if sweep(&mut members, &mut others) == 0 {
                break;
            }
        }
    }
    // Frozen (since the root moved in), sweep until nothing more is moved
    // (a child forked by a process not yet moved when the last walk read
    // it), then kill everything inside.
    let _ = wait_cgroup_event(dir, "frozen 1", FREEZE_WAIT);
    if !childless {
        for _ in 0..MAX_MOVE_PASSES {
            if sweep(&mut members, &mut others) == 0 {
                break;
            }
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
        kill_one(root, protected)
    };
    let mut outcomes = check_members_with(&members, read);
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

/// R12c-3: whether process `pid` has no child now — every thread's
/// `/proc/<pid>/task/<tid>/children` empty (CONFIG_PROC_CHILDREN). `None`
/// when they cannot be read: the caller walks `/proc` instead.
fn has_no_children(pid: u32) -> Option<bool> {
    has_no_children_in(Path::new("/proc"), pid)
}

/// [`has_no_children`] under `proc` (tests: a tree of their own).
fn has_no_children_in(proc: &Path, pid: u32) -> Option<bool> {
    let tasks = std::fs::read_dir(proc.join(pid.to_string()).join("task")).ok()?;
    for t in tasks {
        let children = std::fs::read_to_string(t.ok()?.path().join("children")).ok()?;
        if !children.trim().is_empty() {
            return Some(false);
        }
    }
    Some(true)
}

/// A member of a killed cgroup, by what its `stat` reads now: dead when
/// the PID names no process, or another (another start), or a zombie.
/// Lot 311: a `stat` that cannot be read is not a death — the member is
/// captured and signalled (on main it was reported killed, and one whose
/// name was not UTF-8 never had its `stat` read).
fn member_is_dead(stat: std::io::Result<ProcStat>, start: u64) -> bool {
    match stat {
        Ok(s) => s.start_ticks != start || s.zombie,
        Err(e) => is_gone(&e),
    }
}

/// After the cgroup's kill, each member by its identity. One still
/// running — moved out before the kill, or stuck in an uninterruptible
/// wait — is signalled on its own; they are waited for together.
/// Each member's `stat` is read by `read` (`read_stat`; tests: a read that
/// fails).
fn check_members_with(
    members: &[(u32, u64)],
    read: fn(u32) -> std::io::Result<ProcStat>,
) -> Vec<ExecutionOutcome> {
    let mut outcomes = Vec::with_capacity(members.len());
    let mut running: Vec<ProcRef> = Vec::new();
    for &(pid, start) in members {
        if member_is_dead(read(pid), start) {
            outcomes.push(ExecutionOutcome::Killed { pid });
            continue;
        }
        let r = ProcRef::open_checked_with(pid, None, read);
        // lot 311: running, its start unread — the pidfd holds it
        if !r.holds_start(start) {
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

/// Whether `/proc/<pid>/cgroup` places `pid` in the cgroup `rel` itself
/// (lot 312: by components from the root, the shared helper's rule).
fn pid_in_cgroup(pid: u32, rel: &str) -> bool {
    crate::state_read::read_state(format!("/proc/{pid}/cgroup")).is_ok_and(|c| {
        nn_core::response::cgroup::unified_path(&c)
            .is_some_and(|p| nn_core::response::cgroup::cgroup_at(p, rel))
    })
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
/// Returns descendant `(pid, start ticks, parent pid)` — a parent before
/// its children — capped at [`MAX_DESCENDANTS`], and whether the cap cut
/// the walk short (external audit CMB-002).
fn collect_descendants(root_pid: u32) -> std::io::Result<(Vec<Descendant>, bool)> {
    collect_descendants_capped(root_pid, MAX_DESCENDANTS)
}

/// A descendant a walk found: `(pid, start ticks, parent pid)`.
type Descendant = (u32, u64, u32);

fn collect_descendants_capped(
    root_pid: u32,
    cap: usize,
) -> std::io::Result<(Vec<Descendant>, bool)> {
    let map = build_ppid_map()?;
    let mut out: Vec<Descendant> = Vec::new();
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
                out.push((child, start, parent));
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
        let out = kill_process(
            0,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
        assert!(matches!(out, ExecutionOutcome::Refused { pid: 0, .. }));
    }

    #[test]
    fn refuses_protected_pid_one() {
        let out = kill_process(
            1,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
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
        let out = kill_process(
            own,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(out, ExecutionOutcome::Refused { reason: "PID is protected", .. } if matches!(out, ExecutionOutcome::Refused { pid, .. } if pid == own))
        );
    }

    #[test]
    fn returns_already_gone_for_nonexistent_pid() {
        // PID 999_999_999 is well above the kernel's PID limit — guaranteed absent.
        let out = kill_process(
            999_999_999,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
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
    /// R12c-3: a process with children, and one without, by their
    /// threads' `children` files.
    #[test]
    fn a_process_with_no_child_is_seen_as_such() {
        let (mut sh, kids) = shell_with_two_sleepers();
        assert_eq!(has_no_children(sh.id()), Some(false));
        assert_eq!(has_no_children(kids[0]), Some(true));
        assert_eq!(has_no_children(u32::MAX), None, "no such process");
        // a kernel without CONFIG_PROC_CHILDREN: not known, never "none"
        let fake = tempfile::tempdir().unwrap();
        let task = fake.path().join("42/task/42");
        std::fs::create_dir_all(&task).unwrap();
        assert_eq!(has_no_children_in(fake.path(), 42), None);
        std::fs::write(task.join("children"), "").unwrap();
        assert_eq!(has_no_children_in(fake.path(), 42), Some(true));
        let other = fake.path().join("42/task/43");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("children"), "77 ").unwrap();
        assert_eq!(has_no_children_in(fake.path(), 42), Some(false));
        for k in &kids {
            let _ = std::process::Command::new("kill")
                .arg("-9")
                .arg(k.to_string())
                .status();
        }
        let _ = sh.kill();
        let _ = sh.wait();
    }

    /// Lot 311 (N6): the kill of a process whose `comm` is not UTF-8 —
    /// its own choice, no privilege needed — runs and reports it killed.
    /// On main the capture could not read its `stat` as text: `Failed
    /// { errno: EIO }`, and the process ran on.
    #[test]
    fn a_process_whose_comm_is_not_utf8_is_killed() {
        let mut p = crate::state_read::testing::sleeper_with_non_utf8_comm(30);
        let pid = p.pid();
        let out = kill_process(
            pid,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(out, ExecutionOutcome::Killed { pid: k } if k == pid),
            "{out:?}"
        );
        let status = p.child.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL)
        );
    }

    /// Lot 311: after a cgroup's kill, a member whose `stat` cannot be read
    /// is not counted dead (on main: "Killed", and it ran on); one whose
    /// PID is free, another process's, or a zombie is.
    #[test]
    fn an_unreadable_member_is_not_counted_dead() {
        use std::io::Error;
        let alive = ProcStat {
            start_ticks: 7,
            zombie: false,
        };
        assert!(!member_is_dead(Ok(alive), 7));
        assert!(member_is_dead(Ok(alive), 8), "another process's");
        assert!(member_is_dead(
            Ok(ProcStat {
                zombie: true,
                ..alive
            }),
            7
        ));
        assert!(member_is_dead(
            Err(Error::from_raw_os_error(libc::ENOENT)),
            7
        ));
        assert!(member_is_dead(
            Err(Error::from_raw_os_error(libc::ESRCH)),
            7
        ));
        assert!(!member_is_dead(
            Err(Error::from_raw_os_error(libc::EMFILE)),
            7
        ));
        assert!(!member_is_dead(Err(Error::from_raw_os_error(libc::EIO)), 7));
    }

    /// Lot 311: a member of the killed cgroup still running with a `comm`
    /// that is not UTF-8 is signalled and reported killed (not alive).
    #[test]
    fn a_running_member_whose_comm_is_not_utf8_is_signalled() {
        let mut p = crate::state_read::testing::sleeper_with_non_utf8_comm(30);
        let pid = p.pid();
        let start = crate::response::proc_ref::proc_start_ticks(pid).expect("its start");
        let out = check_members_with(&[(pid, start)], read_stat);
        assert!(
            matches!(out.as_slice(), [ExecutionOutcome::Killed { pid: k }] if *k == pid),
            "{out:?}"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let status = loop {
            match p.child.try_wait().unwrap() {
                Some(status) => break status,
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                None => panic!("reported killed, still running"),
            }
        };
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL)
        );
    }

    /// A `stat` read that fails as the agent out of descriptors would.
    fn unreadable(_pid: u32) -> std::io::Result<ProcStat> {
        Err(std::io::Error::from_raw_os_error(libc::EMFILE))
    }

    /// Wait for `child` to end, at most 2 s: its exit status.
    fn ended(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait().unwrap() {
                Some(status) => return Some(status),
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                None => return None,
            }
        }
    }

    /// Lot 311: a member of a killed cgroup that still runs, its `stat`
    /// unreadable (the agent out of descriptors), is signalled through its
    /// pidfd and reported killed — on main it was reported killed and
    /// never signalled.
    #[test]
    fn a_running_member_whose_stat_cannot_be_read_is_signalled() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let start = crate::response::proc_ref::proc_start_ticks(pid).unwrap();
        let out = check_members_with(&[(pid, start)], unreadable);
        assert!(
            matches!(out.as_slice(), [ExecutionOutcome::Killed { pid: k }] if *k == pid),
            "{out:?}"
        );
        let status = ended(&mut child);
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let status = status.expect("reported killed, still running");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL)
        );
    }

    /// Lot 311: a descendant whose `stat` cannot be read when the tree is
    /// killed process by process (the agent out of descriptors) is still
    /// killed — not "already gone" and left running.
    #[test]
    fn a_descendant_whose_stat_cannot_be_read_is_killed_with_its_tree() {
        let (mut sh, kids) = shell_with_two_sleepers();
        let root = ProcRef::open(sh.id());
        let (primary, rest) =
            kill_tree_by_pid_with(&root, &protected_with(&[]), &|_| None, unreadable);
        assert!(
            matches!(primary, ExecutionOutcome::Killed { .. }),
            "{primary:?}"
        );
        let _ = sh.wait();
        let mut alive = Vec::new();
        for kid in &kids {
            let r = ProcRef::open(*kid);
            if r.is_live() {
                let _ = r.signal(libc::SIGKILL);
                alive.push(*kid);
            }
        }
        assert!(
            alive.is_empty(),
            "left running: {alive:?}; outcomes {rest:?}"
        );
        for kid in &kids {
            assert!(
                rest.iter()
                    .any(|o| matches!(o, ExecutionOutcome::Killed { pid } if pid == kid)),
                "{rest:?}"
            );
        }
    }

    /// Lot 311 (N6): a descendant whose `comm` is not UTF-8 is killed with
    /// its tree. On main the tree's walk found it (the walk reads `stat`
    /// as bytes) but its capture did not: `Failed { errno: EIO }`, and it
    /// ran on under init.
    #[test]
    fn a_descendant_whose_comm_is_not_utf8_is_killed_with_its_tree() {
        use std::io::BufRead;
        use std::os::unix::ffi::OsStrExt;
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().unwrap();
        // the kid: a shell run through the link, looping on `sleep 1` (a
        // shell does not dispatch on `argv[0]`, as uutils' multicall
        // coreutils — Ubuntu 26.04, the CI's image — does)
        let link = dir.path().join(std::ffi::OsStr::from_bytes(b"\xff\xfe"));
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        let mut sh = Command::new("sh")
            .args([
                "-c",
                "\"$0\" -c 'while :; do sleep 1; done' & echo $!; wait",
            ])
            .arg(&link)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let mut line = String::new();
        std::io::BufReader::new(sh.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let kid: u32 = line.trim().parse().unwrap();
        // the precondition: the kid runs the link (its `comm` the link's
        // name) as a child of the shell — waited for, at most 10 s
        let stat = format!("/proc/{kid}/stat");
        let ready = |s: &[u8]| {
            let parent = s.iter().rposition(|b| *b == b')').and_then(|i| {
                String::from_utf8_lossy(&s[i + 1..])
                    .split_whitespace()
                    .nth(1)
                    .map(str::to_string)
            });
            s.windows(3).any(|w| w == b"(\xff\xfe") && parent == Some(sh.id().to_string())
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            seen = std::fs::read(&stat).unwrap_or_default();
            if ready(&seen) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ready(&seen),
            "precondition: the kid {kid} of sh {} is not running the link: {:?}",
            sh.id(),
            String::from_utf8_lossy(&seen)
        );
        // what the walk sees, for the failure's message
        let walk = collect_descendants(sh.id());
        let seen_by_procfs = procfs::process::Process::new(kid as i32)
            .and_then(|p| p.stat())
            .map(|st| (st.ppid, st.comm));
        let named = ProcRef::open(sh.id()).still_named_by_pid();
        let (primary, rest) = kill_process_tree(
            sh.id(),
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(primary, ExecutionOutcome::Killed { .. }),
            "{primary:?}"
        );
        assert!(
            rest.iter()
                .any(|o| matches!(o, ExecutionOutcome::Killed { pid } if *pid == kid)),
            "the descendant {kid} must be killed: {rest:?}; before the kill the walk from {} \
             found {walk:?}, procfs read the kid as {seen_by_procfs:?}, the root named: {named}",
            sh.id()
        );
        let _ = sh.wait();
        let gone = ProcRef::open(kid);
        if gone.is_live() {
            let _ = gone.signal(libc::SIGKILL);
            panic!("the descendant {kid} still runs");
        }
    }

    #[test]
    fn kill_tree_guard_spares_descendants() {
        let (mut sh, kids) = shell_with_two_sleepers();
        let (spared, killed) = (kids[0], kids[1]);
        let (primary, rest) = kill_process_tree_guarded(
            sh.id(),
            &protected_with(&[]),
            &|pid| (pid == spared).then_some(Spare::process("host-critical (test guard)")),
            &super::super::journal::test_intent(),
        );
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
        let (primary, rest) = kill_tree(
            &earlier,
            &protected_with(&[]),
            &|_| None,
            None,
            &super::super::journal::test_intent(),
        );
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
            let outcome = kill_ref(
                &captured,
                &HashSet::new(),
                &super::super::journal::test_intent(),
            );
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

    /// Lab PR 166: the root is frozen while its descendants are moved (it
    /// can neither exit nor fork meanwhile), through the cgroup freezer:
    /// its parent — this test — sees it killed, never stopped (a `sudo`
    /// stops itself when its command stops).
    #[test]
    #[ignore = "privileged: root, cgroup v2 with cgroup.kill"]
    fn a_tree_kill_freezes_the_root_before_moving_its_descendants() {
        let (sh, kids) = shell_with_two_sleepers();
        let root = sh.id();
        let freeze_of_root = || -> Option<String> {
            let cg = std::fs::read_to_string(format!("/proc/{root}/cgroup")).ok()?;
            let path = cg.lines().find_map(|l| l.strip_prefix("0::"))?.to_owned();
            std::fs::read_to_string(format!("/sys/fs/cgroup{path}/cgroup.freeze"))
                .ok()
                .map(|v| v.trim().to_owned())
        };
        let seen = std::cell::RefCell::new(Vec::new());
        let scope = std::path::PathBuf::from(format!(
            "/sys/fs/cgroup/northnarrow-test.slice/blocked.scope/neutralize-f{}",
            std::process::id()
        ));
        let (primary, rest) = kill_tree_in_cgroup(
            &ProcRef::open(root),
            &HashSet::new(),
            &|pid| {
                if kids.contains(&pid) {
                    seen.borrow_mut().push(freeze_of_root());
                }
                None
            },
            &scope,
        )
        .expect("the kill cgroup could not be used");
        // the parent's view: the first state change it can wait for
        let mut status = 0;
        // SAFETY: waitpid(2) on this test's own child.
        let r = unsafe { libc::waitpid(root as i32, &mut status, libc::WUNTRACED) };
        let _ = std::fs::remove_dir(&scope);
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice/blocked.scope");
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice");
        drop(sh); // reaped above (dropping a Child neither waits nor kills)
        let seen = seen.into_inner();
        assert!(!seen.is_empty(), "the guard never saw a descendant");
        assert!(
            seen.iter().all(|f| f.as_deref() == Some("1")),
            "the root was not frozen while its descendants were moved: {seen:?}"
        );
        assert_eq!(r, root as i32);
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "the parent saw {status:#x} (stopped: {}), not a SIGKILL",
            libc::WIFSTOPPED(status)
        );
        assert!(
            matches!(primary, ExecutionOutcome::Killed { pid } if pid == root),
            "{primary:?}"
        );
        for kid in kids {
            assert!(
                rest.iter()
                    .any(|o| matches!(o, ExecutionOutcome::Killed { pid } if *pid == kid)),
                "child {kid} not killed: {rest:?}"
            );
        }
    }

    /// Lot 311 (privileged: root, cgroup v2 with cgroup.kill): descendants
    /// whose `stat` cannot be read (the agent out of descriptors) are
    /// moved into the kill cgroup by their pidfd and killed with it — on
    /// main they were skipped as "exited since the walk" and ran on.
    #[test]
    #[ignore = "privileged: root, cgroup v2 with cgroup.kill"]
    fn a_tree_kill_moves_descendants_whose_stat_cannot_be_read() {
        let (sh, kids) = shell_with_two_sleepers();
        let root = sh.id();
        let scope = std::path::PathBuf::from(format!(
            "/sys/fs/cgroup/northnarrow-test.slice/blocked.scope/neutralize-u{}",
            std::process::id()
        ));
        let result = kill_tree_in_cgroup_with(
            &ProcRef::open(root),
            &HashSet::new(),
            &|_| None,
            &scope,
            unreadable,
        );
        let mut status = 0;
        // SAFETY: waitpid(2) on this test's own child.
        unsafe { libc::waitpid(root as i32, &mut status, 0) };
        drop(sh);
        let mut alive = Vec::new();
        for kid in &kids {
            let r = ProcRef::open(*kid);
            if r.is_live() {
                let _ = r.signal(libc::SIGKILL);
                alive.push(*kid);
            }
        }
        let _ = std::fs::remove_dir(&scope);
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice/blocked.scope");
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice");
        let (primary, rest) = result.expect("the kill cgroup could not be used");
        assert!(
            alive.is_empty(),
            "left running: {alive:?}; outcomes {rest:?}"
        );
        assert!(
            matches!(primary, ExecutionOutcome::Killed { .. }),
            "{primary:?}"
        );
        for kid in &kids {
            assert!(
                rest.iter()
                    .any(|o| matches!(o, ExecutionOutcome::Killed { pid } if pid == kid)),
                "child {kid}: {rest:?}"
            );
        }
    }

    /// Lot 317 (BUG-124's family; privileged: root, cgroup v2 with
    /// `cgroup.kill`): a tree kill whose root the agent could not capture
    /// goes process by process, and reports the capture's error — through
    /// the kill cgroup it would read as "already gone" (the root's PID is
    /// checked by its capture there), the process running on.
    #[test]
    #[ignore = "privileged: root, cgroup v2 with cgroup.kill"]
    fn a_tree_kill_whose_root_was_not_captured_reports_its_error() {
        let (mut sh, kids) = shell_with_two_sleepers();
        let root = sh.id();
        let scope = std::path::PathBuf::from(format!(
            "/sys/fs/cgroup/northnarrow-test.slice/blocked.scope/neutralize-u{}",
            std::process::id()
        ));
        let (primary, _rest) = kill_tree(
            &ProcRef::uncaptured_for_test(root, 0, libc::EMFILE),
            &HashSet::new(),
            &|_| None,
            Some(&scope),
            &super::super::journal::test_intent(),
        );
        let alive = ProcRef::open(root).liveness();
        let _ = sh.kill();
        let _ = sh.wait();
        for kid in &kids {
            // SAFETY: plain kill(2) on the test's own sleepers.
            unsafe { libc::kill(*kid as i32, libc::SIGKILL) };
        }
        let _ = std::fs::remove_dir(&scope);
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice/blocked.scope");
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice");
        assert_eq!(
            primary,
            ExecutionOutcome::Failed {
                pid: root,
                errno: libc::EMFILE
            }
        );
        assert_eq!(alive, super::super::proc_ref::Liveness::Live, "reached");
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
        let outcomes = check_members_with(&[(pid, start), (999_999_999, 1)], read_stat);
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
        let outcomes = check_members_with(&[(other.id(), 1)], read_stat);
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
        let (primary, rest) = kill_process_tree(
            0,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
        assert!(matches!(primary, ExecutionOutcome::Refused { pid: 0, .. }));
        assert!(rest.is_empty(), "no descendant may be touched: {rest:?}");
    }

    #[test]
    fn kill_tree_refuses_pid_one_without_walking() {
        let (primary, rest) = kill_process_tree(
            1,
            &protected_with(&[]),
            &super::super::journal::test_intent(),
        );
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

/// Lot 312 (external bug hunt 1.4, BUG-122): a spared root, its
/// descendants still killed. The coordinator's decision: a protected
/// process (the agent, the watchdog, init, the protected set) keeps its
/// whole tree; a host-critical one (the SSH service) is spared alone.
#[cfg(test)]
mod bug122 {
    use super::*;

    /// A shell of the test's own with two `sleep` children (only this
    /// shell's subtree is ever walked: never the test process's). The root
    /// then becomes a `sleep` itself (`exec`): it lives on when its
    /// children are killed.
    fn shell_with_two_sleepers() -> (std::process::Child, Vec<u32>) {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let mut sh = Command::new("sh")
            .args([
                "-c",
                "sleep 30 & echo $!; sleep 30 & echo $!; exec sleep 30",
            ])
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

    fn reap(mut sh: std::process::Child, kids: &[u32]) {
        for k in kids {
            // SAFETY: plain kill(2) on processes this test started.
            unsafe { libc::kill(*k as i32, libc::SIGKILL) };
        }
        let _ = sh.kill();
        let _ = sh.wait();
    }

    fn refused_in_tree(rest: &[ExecutionOutcome], kids: &[u32]) -> bool {
        kids.iter().all(|k| {
            rest.contains(&ExecutionOutcome::Refused {
                pid: *k,
                reason: IN_A_PROTECTED_TREE,
            })
        })
    }

    /// The root in the protected set (the agent's own PID when no tree
    /// guard is installed): nothing of its tree is killed, and every
    /// process of it is said spared.
    #[test]
    fn bug122_a_protected_root_keeps_its_children() {
        let (sh, kids) = shell_with_two_sleepers();
        let root = sh.id();
        let refs: Vec<ProcRef> = kids.iter().map(|k| ProcRef::open(*k)).collect();
        let (primary, rest) = kill_process_tree(
            root,
            &HashSet::from([1, 2, root]),
            &super::super::journal::test_intent(),
        );
        let alive: Vec<bool> = refs.iter().map(|r| r.is_live()).collect();
        reap(sh, &kids);
        assert!(
            matches!(primary, ExecutionOutcome::Refused { pid, reason: "PID is protected" } if pid == root),
            "premise: {primary:?}"
        );
        assert!(
            alive.iter().all(|a| *a),
            "BUG-122: root {root} refused (protected) but children alive {alive:?}, outcomes {rest:?}"
        );
        assert!(
            refused_in_tree(&rest, &kids),
            "each one said spared: {rest:?}"
        );
        assert_eq!(rest.len(), kids.len(), "{rest:?}");
    }

    /// The same with the guard naming the root protected (the watchdog):
    /// its tree is spared.
    #[test]
    fn bug122_a_guard_protected_root_keeps_its_children() {
        let (sh, kids) = shell_with_two_sleepers();
        let root = sh.id();
        let refs: Vec<ProcRef> = kids.iter().map(|k| ProcRef::open(*k)).collect();
        let (primary, rest) = kill_process_tree_guarded(
            root,
            &HashSet::from([1, 2]),
            &|pid| (pid == root).then_some(Spare::tree("northnarrow-watchdog")),
            &super::super::journal::test_intent(),
        );
        let alive: Vec<bool> = refs.iter().map(|r| r.is_live()).collect();
        reap(sh, &kids);
        assert!(
            matches!(primary, ExecutionOutcome::Refused { pid, reason: "northnarrow-watchdog" } if pid == root),
            "premise: {primary:?}"
        );
        assert!(alive.iter().all(|a| *a), "{alive:?} {rest:?}");
        assert!(refused_in_tree(&rest, &kids), "{rest:?}");
    }

    /// A host-critical root (the SSH listener) is refused itself, and with
    /// no attributed offender below it nothing of its tree is touched
    /// (review of #543, F6: its other sessions are never killed).
    #[test]
    fn bug122_a_host_critical_root_is_spared_and_nothing_below_it_killed() {
        let (sh, kids) = shell_with_two_sleepers();
        let root = sh.id();
        let (primary, rest) = kill_process_tree_guarded(
            root,
            &HashSet::from([1, 2]),
            &|pid| (pid == root).then_some(Spare::process("ssh-service(sshd)")),
            &super::super::journal::test_intent(),
        );
        let alive: Vec<bool> = kids.iter().map(|k| ProcRef::open(*k).is_live()).collect();
        let root_alive = ProcRef::open(root).is_live();
        reap(sh, &kids);
        assert!(
            matches!(primary, ExecutionOutcome::Refused { pid, reason: "ssh-service(sshd)" } if pid == root),
            "{primary:?}"
        );
        assert!(root_alive && alive.iter().all(|a| *a), "{alive:?}");
        assert!(rest.is_empty(), "nothing below it named: {rest:?}");
    }

    /// Review of #543 (F6), sshd-shaped: a listener, two sessions, the
    /// offender (with a child) under one of them. Only that lineage dies —
    /// the session the offender runs in, the offender, its child; the
    /// listener and the other session (and its shell) are untouched and
    /// not even named; the record says who was spared and who was killed.
    #[test]
    fn review_f6_only_the_offending_lineage_under_an_sshd_listener_dies() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let tmp = tempfile::TempDir::new().unwrap();
        let d = tmp.path();
        let put = |n: &str, body: String| std::fs::write(d.join(n), body).unwrap();
        let dir = d.display();
        put(
            "l.sh",
            format!("sh {dir}/sa.sh & echo a $!; sh {dir}/sb.sh & echo b $!; exec sleep 30\n"),
        );
        put(
            "sa.sh",
            format!("sh {dir}/o.sh & echo o $!; exec sleep 30\n"),
        );
        put("o.sh", "sleep 30 & echo c $!; exec sleep 30\n".to_string());
        put("sb.sh", "sleep 30 & echo x $!; exec sleep 30\n".to_string());
        let mut l = Command::new("sh")
            .arg(d.join("l.sh"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(l.stdout.take().unwrap());
        let mut pid = std::collections::HashMap::new();
        for _ in 0..5 {
            let mut line = String::new();
            out.read_line(&mut line).unwrap();
            let (k, v) = line.trim().split_once(' ').unwrap();
            pid.insert(k.to_string(), v.parse::<u32>().unwrap());
        }
        let (root, a, b, o, c, x) = (l.id(), pid["a"], pid["b"], pid["o"], pid["c"], pid["x"]);
        // let every process exec its sleep (its children were forked first)
        std::thread::sleep(std::time::Duration::from_millis(200));
        let sshd = [root, a, b];
        let (primary, rest) = kill_lineage(
            root,
            o,
            &HashSet::from([1, 2]),
            &|p| {
                sshd.contains(&p)
                    .then_some(Spare::process("ssh-service(sshd)"))
            },
            &super::super::journal::test_intent(),
        );
        let live = |p: u32| ProcRef::open(p).is_live();
        let state: Vec<(u32, bool)> = [root, a, b, o, c, x]
            .iter()
            .map(|&p| (p, live(p)))
            .collect();
        for p in [root, a, b, o, c, x] {
            // SAFETY: plain kill(2) on processes this test started.
            unsafe { libc::kill(p as i32, libc::SIGKILL) };
        }
        let _ = l.wait();
        assert!(
            matches!(primary, ExecutionOutcome::Refused { pid, .. } if pid == root),
            "{primary:?}"
        );
        assert_eq!(
            state,
            vec![
                (root, true),
                (a, false),
                (b, true),
                (o, false),
                (c, false),
                (x, true)
            ],
            "only the offending lineage dies: {rest:?}"
        );
        let named: HashSet<u32> = rest
            .iter()
            .filter_map(|o| match o {
                ExecutionOutcome::Killed { pid } | ExecutionOutcome::AlreadyGone { pid } => {
                    Some(*pid)
                }
                _ => None,
            })
            .collect();
        assert_eq!(named, HashSet::from([a, o, c]), "{rest:?}");
        assert_eq!(rest.len(), 3, "the other session is not named: {rest:?}");
        // an offender not below the root: nothing is killed
        let (_, rest) = kill_lineage(
            std::process::id(),
            u32::MAX,
            &HashSet::from([1, 2]),
            &|p| (p == std::process::id()).then_some(Spare::process("test")),
            &super::super::journal::test_intent(),
        );
        assert!(rest.is_empty(), "{rest:?}");
    }

    /// A protected DESCENDANT keeps its own tree, a host-critical one does
    /// not; the other offender processes are killed. Shell `m` (the middle
    /// one) runs a sleeper `g`; the root runs `m` and a sibling sleeper
    /// `s`.
    #[test]
    fn bug122_a_protected_descendant_keeps_its_tree() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        for tree in [true, false] {
            let mut sh = Command::new("sh")
                .args([
                    "-c",
                    "sh -c 'sleep 30 & echo g $!; wait' & echo m $!; sleep 30 & echo s $!; wait",
                ])
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn sh");
            let mut out = std::io::BufReader::new(sh.stdout.take().unwrap());
            let mut pid_of = std::collections::HashMap::new();
            for _ in 0..3 {
                let mut line = String::new();
                out.read_line(&mut line).unwrap();
                let (k, v) = line.trim().split_once(' ').unwrap();
                pid_of.insert(k.to_string(), v.parse::<u32>().unwrap());
            }
            let (m, g, s) = (pid_of["m"], pid_of["g"], pid_of["s"]);
            let spare = if tree {
                Spare::tree("northnarrow-agent(self)")
            } else {
                Spare::process("ssh-service(sshd)")
            };
            let (primary, rest) = kill_process_tree_guarded(
                sh.id(),
                &HashSet::from([1, 2]),
                &|pid| (pid == m).then_some(spare),
                &super::super::journal::test_intent(),
            );
            let (m_alive, g_alive, s_alive) = (
                ProcRef::open(m).is_live(),
                ProcRef::open(g).is_live(),
                ProcRef::open(s).is_live(),
            );
            for p in [m, g, s] {
                // SAFETY: plain kill(2) on processes this test started.
                unsafe { libc::kill(p as i32, libc::SIGKILL) };
            }
            let _ = sh.wait();
            assert!(
                matches!(primary, ExecutionOutcome::Killed { .. }),
                "{primary:?}"
            );
            assert!(
                rest.contains(&ExecutionOutcome::Refused {
                    pid: m,
                    reason: spare.reason
                }),
                "tree {tree}: the spared process is said spared: {rest:?}"
            );
            // (alone, it exits by itself once its only child is killed)
            assert!(m_alive || !tree, "tree {tree}: the spared process lives");
            assert!(
                !s_alive,
                "tree {tree}: the sibling offender is killed: {rest:?}"
            );
            assert_eq!(g_alive, tree, "tree {tree}: its child {rest:?}");
            let g_said = rest.iter().find(|o| matches!(o, ExecutionOutcome::Refused { pid, .. } | ExecutionOutcome::Killed { pid } if *pid == g));
            if tree {
                assert_eq!(
                    g_said,
                    Some(&ExecutionOutcome::Refused {
                        pid: g,
                        reason: IN_A_PROTECTED_TREE
                    })
                );
            } else {
                assert_eq!(g_said, Some(&ExecutionOutcome::Killed { pid: g }));
            }
        }
    }

    /// The walk's rule on its own, parents first: under a tree-spared pid
    /// everything is spared, under a process-spared one nothing is.
    #[test]
    fn bug122_the_walk_spares_whole_trees_only_below_protected_pids() {
        // 10 → 11 (tree) → 12 → 13; 10 → 14 (process) → 15; 10 → 16
        let walk = [(11, 10), (12, 11), (13, 12), (14, 10), (15, 14), (16, 10)];
        let guard = |pid: u32| match pid {
            11 => Some(Spare::tree("watchdog")),
            14 => Some(Spare::process("sshd")),
            _ => None,
        };
        let protected = HashSet::from([16]);
        let mut trees = HashSet::new();
        let got: Vec<Option<Spare>> = walk
            .iter()
            .map(|&(pid, parent)| spare_in_walk(pid, parent, &mut trees, &protected, &guard))
            .collect();
        assert_eq!(
            got,
            vec![
                Some(Spare::tree("watchdog")),
                Some(Spare::tree(IN_A_PROTECTED_TREE)),
                Some(Spare::tree(IN_A_PROTECTED_TREE)),
                Some(Spare::process("sshd")),
                None,
                Some(PROTECTED),
            ]
        );
    }
}
