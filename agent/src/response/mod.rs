//! Response executors (Tappa 3).
//!
//! Tappa 3 ships the first real action: `KillProcess` (and its tree
//! variant) actually kill processes via `SIGKILL`. The rest of the
//! [`ResponseAction`](common::ResponseAction) enum (BlockOutbound,
//! FullNetworkIsolation, Quarantine, ThrottleProcess) is intentionally
//! unimplemented and rejected with a `Refused` outcome until Tappa 5.

pub mod executor;
pub mod kill;

pub use executor::Executor;

use std::time::Duration;

use common::ResponseAction;

/// Outcome of a single execution attempt against one target PID.
///
/// `Killed` is the only "we definitively did the thing" success.
/// `AlreadyGone` is also a non-error: from the agent's perspective the
/// target is gone, which is what was requested. The remaining variants
/// describe specific failure modes the caller may want to surface
/// differently in dashboards.
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
    /// Any other syscall failure; `errno` carries the raw value.
    Failed { pid: u32, errno: i32 },
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

#[cfg(test)]
mod tests;
