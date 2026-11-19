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
//! [`REASON_HOLD_RETRY`], [`REASON_HOLD_ENDED`]; lot 359:
//! [`REASON_PIN_HANDLE_FAILED`]); the agent signs them under
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

/// Lot 273c (the review of #490): the watchdog found a resource value of
/// the agent's fresh cgroup (at its start, after a respawn) or of its own
/// below its floor and restored it — registered, written, read back
/// (`antitamper_bpf::cgroup_floors`). The detail is the file, the value
/// and the floor; the agent signs it as `limit_floor_restored`.
pub const REASON_LIMIT_FLOOR_RESTORED: &str = "limit_floor_restored";

/// Lot 273c: the same, the value NOT restored (the detail says why); the
/// agent signs it as `limit_floor_not_restored`.
pub const REASON_LIMIT_FLOOR_NOT_RESTORED: &str = "limit_floor_not_restored";

/// Lot 273d (the review of #492): before a respawn, the watchdog found
/// systemd's copy of our units below the floors (the next start applies
/// it: a `memory.max` of one page kills the agent at its exec); the detail
/// says what, whether the reload it asked was confirmed or withheld, and
/// what stayed below. The agent signs it as `systemd_copy_below_floor`.
pub const REASON_COPY_BEFORE_RESPAWN: &str = "systemd_copy_before_respawn";

/// Lot 353 (pre-alpha Phase 3, X6): the watchdog's stuck recovery stopped
/// an agent that did not answer its STATUS pings (which ping failed, how
/// many in a row, for how long). Written before the recovery's SIGINT;
/// the agent signs it under its own kind (`stuck_unresponsive`), and the
/// stop the SIGINT starts is named so ([`STUCK_STOP_REASON`]): the
/// heartbeat's verifier counts it as no clean stop.
pub const REASON_STUCK_UNRESPONSIVE: &str = "stuck_unresponsive";
/// Lot 353: [`RESTART_LOOP_RECOVERIES`] stuck recoveries within
/// [`RESTART_LOOP_WINDOW_SECS`] — an agent restarted again and again (a
/// mount over a path it reads held for long, a resource starved): signed
/// High by the agent (`agent_restart_loop`), a degradation of its status.
pub const REASON_AGENT_RESTART_LOOP: &str = "agent_restart_loop";
/// Lot 353 (pre-alpha Phase 3, X6 on 6.12): the stuck recovery's SIGKILL
/// could not end the agent — a thread of it waited, uninterruptibly, on a
/// FUSE request its daemon never answered — and the watchdog aborted that
/// FUSE connection (`/sys/fs/fuse/connections/<id>/abort`): a FUSE mounted
/// over `/proc`, `/sys` (the cgroup tree) or the agent's own directories
/// only, with requests waiting. The detail names the mount, its source and
/// the connection; the agent signs it High (`fuse_aborted`).
pub const REASON_FUSE_ABORTED: &str = "fuse_aborted";
/// Lot 353 (the review of #563, F1): the agent answered its pings, but its
/// `LoopProgress` reply said its signed records had been failing for the
/// time the detail gives (an append that cannot reach its log: a mount
/// over a path it writes, a full disk) — the watchdog's record, signed by
/// the next agent that can sign, High.
pub const REASON_SIGNED_RECORDS_FAILED: &str = "signed_records_failed";
/// Lot 359 (the re-check 3 of #567, P3 e): a handle of the watchdog's on a
/// pinned map of the agent's failed — its registration in
/// `PROTECTED_PIDS` (`register_self_pid`) or of its role (`claim_role`),
/// the respawned agent's re-insert (`reinsert_new_agent_pid`), a dead
/// agent's eviction (`evict_dead_agent`). They fail when the pins cannot
/// be reached (the bpffs lost its last mount): a watchdog restarted then
/// stays outside `PROTECTED_PIDS` until a reboot. The detail names the
/// handle and the error; the agent signs it as a degradation
/// (`watchdog_pin_handle_failed`), once per handle and watchdog.
pub const REASON_PIN_HANDLE_FAILED: &str = "pin_handle_failed";
/// Lot 374: a start of the watchdog refused itself before it took its role
/// — a loader variable in its environment, or a mapped file that is neither
/// its binary nor a library the release links (the detail names them). The
/// live agent, the surviving role, signs it High
/// (`watchdog_start_refused`).
pub const REASON_START_SELF_CHECK: &str = "start_self_check";
/// Lot 353: how many stuck recoveries make a restart loop…
pub const RESTART_LOOP_RECOVERIES: usize = 3;
/// …within this many seconds.
pub const RESTART_LOOP_WINDOW_SECS: u64 = 600;
/// Lot 353: the stop reason of an agent the watchdog's stuck recovery
/// stopped (its `agent_stop` row, its heartbeat's stop beat).
pub const STUCK_STOP_REASON: &str = "stuck_unresponsive";
/// Lot 353: where the watchdog leaves, before its stuck recovery's SIGINT,
/// the one [`HoldRecord`] (`REASON_STUCK_UNRESPONSIVE`) the agent reads to
/// name its stop ([`STUCK_STOP_REASON`]); the agent removes it.
pub const STUCK_PATH: &str = "/run/northnarrow/watchdog.stuck";
/// Lot 353: how old a stuck marker may be and still name a stop.
pub const STUCK_MARKER_MAX_AGE_SECS: u64 = 120;

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

/// Lot 353: whether the stuck marker `text` (one [`HoldRecord`]) names the
/// agent `pid` and is at most [`STUCK_MARKER_MAX_AGE_SECS`] old at `now`
/// (unix seconds): its detail when it does.
pub fn stuck_marker_names(text: &str, pid: u32, now: u64) -> Option<String> {
    let r: HoldRecord = serde_json::from_str(text.trim()).ok()?;
    (r.reason == REASON_STUCK_UNRESPONSIVE
        && r.agent_pid == pid
        && now.saturating_sub(r.at) <= STUCK_MARKER_MAX_AGE_SECS
        && r.at <= now.saturating_add(5))
    .then_some(r.detail)
}
