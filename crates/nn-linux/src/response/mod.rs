//! Response executors.
//!
//! - Tappa 3: `KillProcess` / `KillProcessTree` via SIGKILL.
//! - Tappa 5: `BlockOutbound`, `FullNetworkIsolation`, `Quarantine`,
//!   `ThrottleProcess` — the full arsenal.
//!
//! Each action lives in its own module under this directory and is
//! reached through [`Executor::execute`]. All operations are
//! idempotent (re-running them on the same target is a no-op) and
//! reversible (each module exposes a paired undo function).

pub mod block_outbound;
pub mod caps_preflight;
// R08c (lab PR 252): the executor's configuration and its policy (the
// detect-only gate, the variables that switch it on) are nn-core's, here
// under their path.
pub use nn_core::response::config;
pub mod containment;
pub mod executor;
pub mod file_caps;
// Lot 312: whether an executable is gone, from the inode the agent holds
// (`st_nlink`), never from the kernel's ` (deleted)` suffix.
pub mod inode;
// R12c (lab PR 270): no action without a signed record — the actions
// chain's writer and the ticket an action needs.
pub mod journal;
pub mod kill;
pub mod network_isolation;
pub mod proc_ref;
pub mod quarantine;
pub mod throttle;

pub use config::ExecutorConfig;
pub use executor::Executor;

use std::time::Duration;

use nn_model::ResponseAction;

/// Outcome of a single execution attempt.
///
/// Tappa 3's PID-centric variants are joined in Tappa 5 by four
/// outcomes that map to the new actions. `Killed` and `Quarantined`
/// are "we definitively did the thing" successes; the rest are
/// specific failure modes the caller may want to surface differently
/// in dashboards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// SIGKILL accepted; target no longer exists in /proc.
    Killed { pid: u32 },
    /// Target had already exited by the time we tried (race with
    /// natural exit). Not an error.
    AlreadyGone { pid: u32 },
    /// Kernel returned `EPERM`. Either we lack `CAP_KILL` or the
    /// target is protected by an LSM policy.
    PermissionDenied { pid: u32, errno: i32 },
    /// Refused by the agent itself (protected PID, PID 0, action not
    /// implemented yet, ...). `reason` is a static string so it is
    /// safe to include in metrics labels.
    Refused { pid: u32, reason: &'static str },
    /// Any other syscall / I/O failure; `errno` carries the raw value
    /// when one is available, or 0 when the failure is logical.
    Failed { pid: u32, errno: i32 },
    /// Detect-only / monitor mode (BUG-033): the agent WOULD have
    /// executed this action, but enforcement is globally suppressed
    /// (see [`ExecutorConfig::dry_run`], surfaced as `--detect-only`),
    /// so the system was left untouched. Deliberately distinct from
    /// `Refused`: `Refused` means the agent declined on the merits (a
    /// protected PID, a sub-floor PID); `WouldExecute` means the action
    /// was approved but not enforced because we are observing only. It
    /// never claims success it didn't achieve — the honest counterpart
    /// to the old `dry_run` path that reported `Blocked`/`Killed` for
    /// things it never did.
    WouldExecute { pid: u32 },

    // ---- Tappa 5 ----
    /// `BlockOutbound`: the PID was placed into the
    /// `northnarrow.slice/blocked.scope` cgroup and an `nftables`
    /// drop rule against that cgroup is now in effect.
    Blocked { pid: u32 },
    /// `Quarantine`: the target's executable was encrypted into the
    /// vault and the original file was unlinked. Lot 312 (BUG-90): where
    /// another hard link, a name the agent cannot see, still held the
    /// inode, it was also emptied through the agent's descriptor — read
    /// back empty — so no name of it runs the binary any more.
    Quarantined {
        original_path: String,
        vault_id: String,
    },
    /// Lot 312 (review F1, F4, F5): the target's executable was encrypted
    /// into the vault, and its inode — kept by other names (a shared store,
    /// a hard link), owned by another user, its name not verified, or its
    /// removal failed — neutralized where it is: emptied when it is the
    /// offender's own file with no other name (`complete`), else made mode
    /// 000 with its content kept, or not changed (`detail` says which, with
    /// the owner and the link count). A restore puts content and mode back
    /// into that inode; it creates no name.
    QuarantinedInPlace {
        vault_id: String,
        /// A verified name of it, when one was.
        original_path: Option<String>,
        detail: String,
        complete: bool,
    },
    /// Lot 312 (review F2): `BlockOutbound` moved the process into the
    /// blocked scope and new sockets are dropped; `sockets` inet sockets
    /// it held before the move are not (the drop matches a socket's cgroup
    /// at its creation), nor sockets passed to it later from outside the
    /// scope (`SCM_RIGHTS`). They may run until NEUTRALIZE's kill or
    /// ISOLATE. Partial, never a success.
    BlockedNewOnly { pid: u32, sockets: usize },
    /// `ThrottleProcess`: the PID was placed in
    /// `northnarrow.slice/throttled.scope`. External audit CMB-013: each
    /// limit as read back from the scope after it was written — `None`
    /// where it could not be set (controller not enabled, knob missing).
    Throttled {
        pid: u32,
        cpu_max_pct: Option<u8>,
        io_weight: Option<u16>,
        memory_high_bytes: Option<u64>,
    },
    /// Review 86, `StripFileCapability`: the file no longer carries a
    /// `security.capability` xattr.
    CapabilityStripped { path: String },
    /// External audit CMB-002, `KillProcessTree`: the `/proc` walk under
    /// `pid` stopped at `limit` descendants; any beyond were not reached.
    TreeTruncated { pid: u32, limit: usize },
    /// Lot 312 (external bug hunt 1.4, family F5): the action ran, and
    /// reading its effect back showed it did not take — the process is not
    /// in the agent's scope after the move, the binary is still on disk
    /// under another name. `reason` says what was found. Never a success:
    /// an action reports what the host holds afterwards, not what it wrote.
    NotInEffect { pid: u32, reason: &'static str },
}

/// Aggregate report for one verdict execution.
///
/// `additional` is empty for [`ResponseAction::KillProcess`] and
/// holds child outcomes for [`ResponseAction::KillProcessTree`].
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub action: ResponseAction,
    pub primary: ExecutionOutcome,
    pub additional: Vec<ExecutionOutcome>,
    pub elapsed: Duration,
}

/// R12c-3 (lab PR 270): the calling thread's nice value moved by `by` (-20
/// to 19) — the decision thread keeps the CPU against the response workers
/// when they contend (EXP-13r: eight workers walking `/proc` on a 4-CPU
/// guest made 1,247 decisions late); a negative `by` needs CAP_SYS_NICE (the
/// agent runs as root). Linux keeps a nice value per thread. Returns the
/// new value.
pub fn renice_this_thread(by: i32) -> std::io::Result<i32> {
    // SAFETY: gettid(2) takes no argument and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::id_t;
    // SAFETY: getpriority(2) reads two integers; -1 is also a valid nice
    // value, told from an error by errno (cleared first).
    let now = unsafe {
        *libc::__errno_location() = 0;
        libc::getpriority(libc::PRIO_PROCESS, tid)
    };
    if now == -1 && std::io::Error::last_os_error().raw_os_error() != Some(0) {
        return Err(std::io::Error::last_os_error());
    }
    let nice = (now + by).clamp(-20, 19);
    // SAFETY: setpriority(2) reads three integers and changes only this
    // thread's nice value (raising it needs no privilege).
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, nice) };
    if rc == 0 {
        Ok(nice)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// R12c (lab PR 270): an action's report as its signed outcome — the
/// result, the report as text, and why when it is not a success. A kill
/// tree that left a descendant running (not killed, spared, beyond a walk
/// cut short) is a partial success.
pub fn journal_outcome(
    report: &ExecutionReport,
) -> (journal::ActionResult, String, Option<String>) {
    use journal::ActionResult as R;
    let (mut result, mut reason) = match &report.primary {
        ExecutionOutcome::Killed { .. }
        | ExecutionOutcome::Blocked { .. }
        | ExecutionOutcome::Quarantined { .. }
        | ExecutionOutcome::CapabilityStripped { .. } => (R::Success, None),
        ExecutionOutcome::Throttled {
            cpu_max_pct,
            io_weight,
            memory_high_bytes,
            ..
        } => {
            if cpu_max_pct.is_some() && io_weight.is_some() && memory_high_bytes.is_some() {
                (R::Success, None)
            } else {
                (
                    R::Partial,
                    Some("a limit could not be set (read back none)".to_string()),
                )
            }
        }
        ExecutionOutcome::WouldExecute { .. } => (
            R::WouldExecute,
            Some("detect-only: approved, not enforced".to_string()),
        ),
        ExecutionOutcome::AlreadyGone { .. } => {
            (R::NotRun, Some("the target was already gone".to_string()))
        }
        ExecutionOutcome::Refused { reason, .. } => (R::Failure, Some((*reason).to_string())),
        ExecutionOutcome::PermissionDenied { errno, .. } => (
            R::Failure,
            Some(format!(
                "permission denied: {}",
                std::io::Error::from_raw_os_error(*errno)
            )),
        ),
        ExecutionOutcome::Failed { errno, .. } => (
            R::Failure,
            Some(if *errno == libc::ETIMEDOUT {
                "still running after the kill's wait".to_string()
            } else if *errno == 0 {
                "failed".to_string()
            } else {
                std::io::Error::from_raw_os_error(*errno).to_string()
            }),
        ),
        ExecutionOutcome::TreeTruncated { limit, .. } => (
            R::Partial,
            Some(format!("the tree walk stopped at {limit} descendants")),
        ),
        ExecutionOutcome::NotInEffect { reason, .. } => {
            (R::Failure, Some(format!("not in effect: {reason}")))
        }
        ExecutionOutcome::QuarantinedInPlace {
            detail, complete, ..
        } => {
            if *complete {
                (R::Success, Some(detail.clone()))
            } else {
                (R::Partial, Some(detail.clone()))
            }
        }
        ExecutionOutcome::BlockedNewOnly { sockets, .. } => {
            (R::Partial, Some(blocked_new_only(*sockets)))
        }
    };
    let mut text = format!("{:?}", report.primary);
    if !report.additional.is_empty() {
        let left = report
            .additional
            .iter()
            .filter(|o| {
                !matches!(
                    o,
                    ExecutionOutcome::Killed { .. }
                        | ExecutionOutcome::AlreadyGone { .. }
                        | ExecutionOutcome::WouldExecute { .. }
                )
            })
            .count();
        text.push_str(&format!(
            "; {} descendant(s), {left} not contained",
            report.additional.len()
        ));
        if left > 0 && result == R::Success {
            result = R::Partial;
            reason = Some(format!("{left} descendant(s) not contained"));
        }
    }
    (result, text, reason)
}

/// Lot 312 (review F2): what a [`ExecutionOutcome::BlockedNewOnly`] row says.
pub fn blocked_new_only(sockets: usize) -> String {
    format!(
        "new connections blocked; {sockets} inet socket(s) opened before the move are not (the \
         drop matches a socket's cgroup at its creation), nor sockets passed in later from \
         outside the scope (SCM_RIGHTS): they may run until NEUTRALIZE's kill or ISOLATE"
    )
}

/// Reviews 86 and 87: the host's view of `path`, for a response that
/// changes a file. The agent's unit runs with `ProtectSystem=strict`
/// (deploy/systemd/northnarrow-agent.service): in its own mount namespace
/// everything but its state directories is read-only, so removing a
/// binary or an xattr failed with `EROFS`. Through `/proc/1/root` the path
/// resolves in PID 1's mount namespace, the host's, where the file is
/// writable; traversing it needs `CAP_SYS_PTRACE`, which the unit grants.
/// The sandbox still covers everything else the agent does.
pub fn host_path(path: &std::path::Path) -> std::path::PathBuf {
    let rel = path.strip_prefix("/").unwrap_or(path);
    std::path::Path::new("/proc/1/root").join(rel)
}

/// Run `op` on [`host_path`]`(path)`, or on `path` itself when the host's
/// view cannot be reached at all (no `CAP_SYS_PTRACE`, as in tests). When
/// it can, its error is the answer: a fallback to the read-only path would
/// only turn it into `EROFS`.
pub fn on_host_path<T>(
    path: &std::path::Path,
    op: impl Fn(&std::path::Path) -> std::io::Result<T>,
) -> std::io::Result<T> {
    static REACHABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *REACHABLE.get_or_init(|| std::fs::metadata("/proc/1/root/").is_ok()) {
        op(&host_path(path))
    } else {
        op(path)
    }
}

#[cfg(test)]
mod tests;
