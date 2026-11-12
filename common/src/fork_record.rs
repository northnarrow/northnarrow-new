//! Lot 310 (the re-check 4 of #539): what an exec does with its process's
//! fork record — the eBPF exec program's decision ([`on_exec`]), here so
//! that it is tested where it is written once.
//!
//! `sched_process_fork` records, for each new process, the thread group
//! that forked it and the process's start (`FORK_PARENTS`, keyed by the
//! `task_struct`). The process's FIRST exec since that fork carries the
//! forker (`fork_ppid`); the record is then marked used, not removed, so a
//! later exec of the same process finds it used — not lost — and carries 0.
//! `sched_process_exit` removes it.
//!
//! systemd ≥ 254: a manager's fork executes `systemd-executor` first, then
//! the unit's own program (`ExecStart`) in the same process. When the file
//! the exec ran is a VERIFIED executor identity (`EXECUTOR_IDS`, filled by
//! the agent with the packaged file's identities and the copies PID 1
//! holds), the record is left unused: the unit's program, the next exec,
//! carries the forker too. Decided in the kernel at the exec, with the
//! identity the LSM exec hook read (`bprm->file`): no race with a reader of
//! `/proc` (the re-check 4: the agent's former carry needed the image while
//! the executor still ran it). Without that hook (tracepoint mode) no exec
//! is known to be the executor's: the record is used at once.
//!
//! A user can make the executor its own process's first exec (it is
//! executable by all): the forker carried is still the process that forked
//! it — the user's — never PID 1 or a manager.

/// The most executor identities the kernel holds (`EXECUTOR_IDS`): the
/// packaged file's and PID 1's copies, each at most the agent's 16.
pub const EXECUTOR_IDS_MAX: u32 = 32;

/// What one exec does with the fork record of its process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnExec {
    /// No record: the process was forked before the record was attached,
    /// or the map evicted it. Carries 0; counted lost when the process
    /// started after the record was attached ([`counts_as_lost`]).
    Missing,
    /// A record of an earlier task at the same address (its exit not seen):
    /// not this process's. Carries 0, removed; counted as [`Self::Missing`].
    Stale,
    /// The record a first exec used: this is a later exec. Carries 0, not
    /// lost.
    Used,
    /// The first exec since the fork: carries the forker. `keep`: the exec
    /// ran a verified executor — the record stays unused for the next exec.
    First { keep: bool },
}

impl OnExec {
    /// The exec record's `fork_ppid` for a record naming `forker`.
    pub const fn fork_ppid(self, forker: u32) -> u32 {
        match self {
            OnExec::First { .. } => forker,
            _ => 0,
        }
    }

    /// The record is marked used after this exec.
    pub const fn marks_used(self) -> bool {
        matches!(self, OnExec::First { keep: false })
    }
}

/// The decision: `record` the process's record as `(start, used)` if any;
/// `start` the exec'ing process's start (`task_struct->start_time`);
/// `executor` the file executed is a verified executor identity.
#[inline(always)]
pub const fn on_exec(record: Option<(u64, bool)>, start: u64, executor: bool) -> OnExec {
    match record {
        None => OnExec::Missing,
        Some((rec_start, _)) if rec_start != start => OnExec::Stale,
        Some((_, true)) => OnExec::Used,
        Some((_, false)) => OnExec::First { keep: executor },
    }
}

/// A missing or stale record is a loss (`FORK_RECORD_LOST`) when the
/// process started after the record was attached (`since`, the agent's
/// `CLOCK_MONOTONIC` at the attach; 0: not attached yet).
#[inline(always)]
pub const fn counts_as_lost(outcome: OnExec, start: u64, since: u64) -> bool {
    matches!(outcome, OnExec::Missing | OnExec::Stale) && since != 0 && start > since
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unit on systemd ≥ 254: PID 1's fork, the executor, then `sh -c`,
    /// then whatever `sh` runs: the executor and the unit's program carry
    /// the forker, the exec after them does not, and none is a loss.
    #[test]
    fn the_executor_leaves_the_record_to_the_unit_s_program() {
        let start = 50;
        let mut rec = Some((start, false));
        let mut carried = [0u32; 3];
        for (n, executor) in [true, false, false].into_iter().enumerate() {
            let o = on_exec(rec, start, executor);
            carried[n] = o.fork_ppid(1);
            assert!(!counts_as_lost(o, start, 10), "exec {n}");
            if o.marks_used() {
                rec = Some((start, true));
            }
        }
        assert_eq!(carried, [1, 1, 0]);
    }

    /// Any other first exec uses the record at once: the exec after it
    /// carries 0 and is no loss (re-check 4: every second exec was counted).
    #[test]
    fn a_later_exec_is_no_loss() {
        let o = on_exec(Some((50, false)), 50, false);
        assert_eq!(o, OnExec::First { keep: false });
        assert!(o.marks_used());
        let later = on_exec(Some((50, true)), 50, false);
        assert_eq!(later, OnExec::Used);
        assert_eq!(later.fork_ppid(1), 0);
        assert!(!counts_as_lost(later, 50, 10));
        // the executor run again later carries nothing either
        assert_eq!(on_exec(Some((50, true)), 50, true), OnExec::Used);
    }

    /// No record, or another task's: 0; a loss only for a process that
    /// started after the record was attached.
    #[test]
    fn a_missing_record_is_a_loss_only_after_the_attach() {
        let missing = on_exec(None, 50, true);
        assert_eq!(missing.fork_ppid(1), 0);
        assert!(counts_as_lost(missing, 50, 10));
        assert!(!counts_as_lost(missing, 5, 10), "forked before the attach");
        assert!(!counts_as_lost(missing, 50, 0), "not attached");
        let stale = on_exec(Some((40, false)), 50, true);
        assert_eq!(stale, OnExec::Stale);
        assert_eq!(stale.fork_ppid(1), 0);
        assert!(counts_as_lost(stale, 50, 10));
        assert!(!stale.marks_used());
    }
}
