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
pub mod config;
pub mod executor;
pub mod kill;
pub mod network_isolation;
pub mod quarantine;
pub mod throttle;

pub use config::ExecutorConfig;
pub use executor::Executor;

use std::time::Duration;

use common::ResponseAction;

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

    // ---- Tappa 5 ----
    /// `BlockOutbound`: the PID was placed into the
    /// `northnarrow.slice/blocked.scope` cgroup and an `nftables`
    /// drop rule against that cgroup is now in effect.
    Blocked { pid: u32 },
    /// `FullNetworkIsolation`: the host-wide isolation ruleset is
    /// installed; the persistence flag has been written.
    NetworkIsolated,
    /// `Quarantine`: the target's executable was encrypted into the
    /// vault and the original file was unlinked.
    Quarantined {
        original_path: String,
        vault_id: String,
    },
    /// `ThrottleProcess`: the PID was placed in
    /// `northnarrow.slice/throttled.scope` with hard limits.
    Throttled {
        pid: u32,
        cpu_max_pct: u8,
        io_weight: u16,
    },
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
