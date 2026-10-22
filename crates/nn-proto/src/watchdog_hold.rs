//! The watchdog's record of a hold (external audit DEP-004).
//!
//! The watchdog holds — alive, protected, no more respawns — when the
//! agent cannot be brought back: the restart ceiling tripped, or a respawn
//! failed. A respawn through systemd is `systemctl start --no-block`, which
//! succeeds as soon as the job is queued; a unit that fails its bpffs
//! pre-flight, is skipped or is stopped then never writes its pidfile. The
//! watchdog holds no signing key, so it leaves one JSON line per hold at
//! [`HOLD_PATH`] and the agent's self-integrity check turns each into a
//! signed `integrity_drift` (`watchdog_hold`) when the agent runs again —
//! the same path as a refused shutdown marker
//! ([`crate::shutdown_marker::REJECTED_PATH`]).
//!
//! The same file carries the supervision events the watchdog sees and
//! cannot sign either, each with its own `reason`
//! ([`REASON_ADMIN_SOCKET_VANISHED`], [`REASON_RESPAWN_ARGV_DEGRADED`],
//! and since lab PR 216 [`REASON_WATCHDOG_EXIT`], [`REASON_WATCHDOG_FAILED`],
//! [`REASON_STUCK_RECOVERY_FAILED`], [`REASON_EVENT_LOOP_STALLED`],
//! [`REASON_HOLD_RETRY`], [`REASON_HOLD_ENDED`]); the agent signs them under
//! their own kind.

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Where the watchdog records its holds (`/run/northnarrow`, mode 0700:
/// root only; tmpfs, so a reboot drops records not yet signed).
pub const HOLD_PATH: &str = "/run/northnarrow/watchdog.hold";

/// External audit WDG-007 (NN-AUD-358): the agent answered the watchdog's
/// STATUS ping, then its admin socket left the path (removed, replaced, or
/// answered by another process) and the agent did not bind it again.
pub const REASON_ADMIN_SOCKET_VANISHED: &str = "admin_socket_vanished";

/// External audit WDG-008 (NN-AUD-359): the exec backend could not capture
/// the agent's argv from /proc; respawns use a recorded or the minimal
/// argv.
pub const REASON_RESPAWN_ARGV_DEGRADED: &str = "respawn_argv_degraded";

/// Lab PR 216 (capability C23): the watchdog exited on an error, with its
/// exit status (`northnarrow-watchdog`'s exit statuses are listed in the
/// watchdog crate, `ExitReason`). Written by the watchdog itself just
/// before it exits; systemd restarts it (`Restart=always`).
pub const REASON_WATCHDOG_EXIT: &str = "watchdog_exit";

/// Lab PR 216: `northnarrow-watchdog.service` entered systemd's failed
/// state (a start or stop job of its own failed; a death of the process is
/// restarted, the unit has no start limit) and stays down until it is
/// started again. Written
/// by the unit's `OnFailure=` handler (`northnarrow-watchdog-failed.service`,
/// `northnarrow-watchdog --record-unit-failure`).
pub const REASON_WATCHDOG_FAILED: &str = "watchdog_failed";

/// Lab PR 216: the agent did not answer (or its event loop stood still) and
/// the stuck recovery could not confirm that it exited. The watchdog kept
/// its protection and its pidfile and goes on supervising it; before, it
/// was treated as dead and lost its `PROTECTED_PIDS` entry while it ran.
pub const REASON_STUCK_RECOVERY_FAILED: &str = "stuck_recovery_failed";

/// Lab PR 216: the agent answered its STATUS pings, but its event loop made
/// no progress between them (the admin socket runs on other tasks). Stuck
/// recovery follows; the agent signs the record once it runs again.
pub const REASON_EVENT_LOOP_STALLED: &str = "event_loop_stalled";

/// Lab PR 216: a hold made one of its bounded retries (a respawn after
/// waiting, at intervals that double up to an hour).
pub const REASON_HOLD_RETRY: &str = "hold_retry";

/// Lab PR 216: a hold ended — an agent runs again — after the time the
/// detail gives.
pub const REASON_HOLD_ENDED: &str = "hold_ended";

/// One hold (or supervision event), as the watchdog records it at
/// [`HOLD_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldRecord {
    /// Unix seconds when the hold began.
    pub at: u64,
    /// The pid of the last agent the watchdog supervised.
    pub agent_pid: u32,
    /// Why the watchdog stopped respawning, or one of the `REASON_*`
    /// events.
    pub reason: String,
    /// The error behind it (the failed start, the missing pidfile).
    pub detail: String,
    /// The agent unit's state as systemd reported it (`ActiveState=…
    /// Result=…`), when the respawn goes through systemd and it answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_state: Option<String>,
}
