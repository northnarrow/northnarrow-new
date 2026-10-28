//! NorthNarrow XDR watchdog — testable library surface (Watchdog
//! W2 + forward sprint commits).
//!
//! The binary entry point at `src/main.rs` is a thin wrapper that
//! parses CLI + sequences the boot-time helpers exported here, so
//! every step (process hardening, pidfd-open retry, pidfile
//! atomic write, systemd `READY=1` notification) is unit-testable
//! WITHOUT root or systemd. Real Linux behaviour is exercised in
//! the future W8 privileged e2e against the real
//! `northnarrow-agent` binary.
//!
//! ## Boot sequence (W2)
//!
//! 1. [`harden_self`] — `prctl(PR_SET_DUMPABLE, 0)` +
//!    `prctl(PR_SET_NAME, "northnarrow-wat")` per design §7.4.
//! 2. [`open_agent_pidfd_with_retry`] — read agent PID from the
//!    pidfile, `pidfd_open(2)` it, retry every 100 ms for up to
//!    30 s if the file hasn't appeared yet (design §F11).
//! 3. [`write_pidfile_atomic`] — publish the watchdog's own PID
//!    via tmpfile + fsync + `rename(2)`.
//! 4. [`sd_notify_ready`] — manual `NOTIFY_SOCKET` Unix datagram
//!    so systemd unblocks `After=` ordering on units depending
//!    on the watchdog.
//! 5. Wait for SIGTERM/SIGINT and exit — restart loop + layer-2
//!    PROTECTED_PIDS evict + STATUS ping land in W3/W4/W5.

use std::collections::VecDeque;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use antitamper_bpf::ProtectedPidsHandle;
use anyhow::{anyhow, Context, Result};
use nn_proto::admin_protocol::{
    decode_loop_progress, decode_status_liveness, encode_frame, AdminMessage, LoopProgressRequest,
    StatusRequest, MAX_FRAME_BODY,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;
use tracing::{debug, error, info, warn};

/// Default CLI values mirror the design §10.2 systemd unit file
/// exactly so an operator running `northnarrow-watchdog` from a
/// shell sees the same paths the production unit binds.
pub const DEFAULT_AGENT_PIDFILE: &str = "/run/northnarrow/agent.pid";
pub const DEFAULT_ADMIN_SOCKET: &str = "/run/northnarrow/admin.sock";
pub const DEFAULT_WATCHDOG_PIDFILE: &str = "/run/northnarrow/watchdog.pid";
pub const DEFAULT_BPFFS_ROOT: &str = "/sys/fs/bpf/northnarrow";
pub const DEFAULT_ADMIN_PUB: &str = "/etc/northnarrow/admin.pub";
/// The installed agent binary: what a pid must be running to be treated
/// as the agent when `--agent-bin` is not given (external audit WDG-003).
pub const DEFAULT_AGENT_BIN: &str = "/usr/local/bin/northnarrow-agent";
pub const DEFAULT_AGENT_ID_FILE: &str = "/etc/northnarrow/agent_id";

/// Cap on the `pidfd_open` retry loop. The watchdog
/// `After=northnarrow-agent.service` ordering means systemd has
/// already started the agent before us in production, so we
/// expect the pidfile to appear within seconds. The 30 s budget
/// covers a slow first boot (agent attaching every LSM hook +
/// loading combat rules on a cold host).
pub const PIDFD_OPEN_RETRY_DEADLINE: Duration = Duration::from_secs(30);

/// Poll cadence for the `pidfd_open` retry loop — 100 ms gives
/// sub-second post-agent-start latency without hammering the
/// filesystem.
pub const PIDFD_OPEN_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// CLI surface, factored out so unit tests can `Cli::try_parse_from`
/// with deterministic argv without going through `main`.
#[derive(Debug, clap::Parser)]
#[command(
    name = "northnarrow-watchdog",
    version,
    about = "NorthNarrow XDR anti-tamper supervisor (Tappa 7 task 6)."
)]
pub struct Cli {
    /// Path to the agent's PID file (written atomically by the
    /// agent's `--pid-file` flow once every LSM hook is attached).
    /// We `read_to_string` + parse, then `pidfd_open` the PID.
    #[arg(long = "agent-pidfile", value_name = "PATH", default_value = DEFAULT_AGENT_PIDFILE)]
    pub agent_pidfile: PathBuf,

    /// Path to the agent's admin socket. Consumed by W5's STATUS
    /// ping for stuck-detection; ignored in W2. CLI present now
    /// so the systemd unit file binds the same surface across
    /// the sprint.
    #[arg(long = "admin-socket", value_name = "PATH", default_value = DEFAULT_ADMIN_SOCKET)]
    pub admin_socket: PathBuf,

    /// Path the watchdog writes ITS own PID into after `pidfd_open`
    /// succeeds. Atomic tmpfile + fsync + rename so a reader
    /// (the agent's W6 PROTECTED_PIDS widening, future operator
    /// tooling) never observes a truncated value.
    #[arg(long = "pidfile", value_name = "PATH", default_value = DEFAULT_WATCHDOG_PIDFILE)]
    pub pidfile: PathBuf,

    /// bpffs root holding the agent's pinned anti-tamper objects.
    /// W3 opens `<root>/PROTECTED_PIDS` via
    /// [`antitamper_bpf::ProtectedPidsHandle::open`] for the
    /// layer-2 evict path; W2 stores the flag but doesn't use it.
    #[arg(long = "bpffs-root", value_name = "PATH", default_value = DEFAULT_BPFFS_ROOT)]
    pub bpffs_root: PathBuf,
    /// Optional explicit path to the agent binary. When omitted,
    /// the watchdog reads `/proc/<agent_pid>/exe` to discover it
    /// at boot. Provided as an escape hatch for environments where
    /// the agent's `ptrace_access_check` LSM hook is active and the
    /// watchdog's PID is not yet in PROTECTED_PIDS at boot — the
    /// agent's mutual-protection insertion (via the W6 watchdog
    /// pidfile poll) races with the watchdog's own boot, so the
    /// `/proc/<pid>/exe` readlink can fail with EPERM during the
    /// race window. Production systemd units pass this explicitly
    /// to skip the race entirely.
    #[arg(long = "agent-bin", value_name = "PATH")]
    pub agent_bin: Option<PathBuf>,

    /// How the agent is brought back after a crash (respawn v2,
    /// docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md). `auto` picks
    /// `systemd` when /run/systemd/system exists, else `exec`.
    #[arg(long = "respawn-backend", value_enum, default_value_t = RespawnBackendChoice::Auto)]
    pub respawn_backend: RespawnBackendChoice,

    /// systemd unit started by the `systemd` respawn backend.
    #[arg(long = "agent-unit", value_name = "UNIT", default_value = DEFAULT_AGENT_UNIT)]
    pub agent_unit: String,

    /// The shutdown-authorisation marker the agent leaves when an admin
    /// quorum stops it ([`check_shutdown_marker`]).
    #[arg(long = "shutdown-marker", value_name = "PATH", default_value = nn_proto::shutdown_marker::MARKER_PATH)]
    pub shutdown_marker: PathBuf,

    /// The admin keys a shutdown must be signed by (external audit
    /// WDG-001: the watchdog verifies the quorum the agent verified).
    #[arg(long = "admin-pub", value_name = "PATH", default_value = DEFAULT_ADMIN_PUB)]
    pub admin_pub: PathBuf,

    /// This install's id; a shutdown signed for another install is refused.
    #[arg(long = "agent-id-file", value_name = "PATH", default_value = DEFAULT_AGENT_ID_FILE)]
    pub agent_id_file: PathBuf,

    /// Lab PR 216: record that systemd put the watchdog unit in its failed
    /// state, and exit — what `northnarrow-watchdog-failed.service`, the
    /// watchdog unit's `OnFailure=` handler, runs. Reads systemd's
    /// `MONITOR_*` variables ([`unit_failure_record`]) and appends one
    /// record beside the shutdown marker (`watchdog.hold`), which the agent
    /// signs at its next round.
    #[arg(long = "record-unit-failure")]
    pub record_unit_failure: bool,
}

// ────────────────────────────────────────────────────────────────────
// Lab PR 216 (capability C23) — fail-visible exit statuses
// ────────────────────────────────────────────────────────────────────

/// Why `northnarrow-watchdog` exits, and its exit status. Every failure is
/// non-zero and has its own status, so `systemctl status` and the journal
/// say which one, and the unit's `Restart=always` restarts it (static
/// review C-44 / G-05: "pidfd wait failed" ended the restart loop with a
/// clean 0, and `Restart=on-failure` left the agent without a supervisor).
/// The unit keeps 0 from a restart (`RestartPreventExitStatus=0`): a stop
/// the watchdog was told to make.
///
/// | status | reason |
/// |---|---|
/// | 0 | stopped: SIGTERM/SIGINT, or a shutdown signed by the admin quorum |
/// | 1 | an error without a status of its own (none is known) |
/// | 2 | the command line was refused (clap) |
/// | 10 | process hardening (`prctl`) failed |
/// | 11 | no verified agent within the start-up deadline (30 s) |
/// | 12 | the watchdog's pidfile could not be written |
/// | 13 | the respawn backend could not be set up |
/// | 14 | `READY=1` could not be sent to systemd |
/// | 15 | the signal handlers could not be installed |
/// | 20 | the wait on the agent's pidfd failed |
/// | 30 | `--record-unit-failure`: the record could not be written |
///
/// Each non-zero exit of the daemon leaves a [`REASON_WATCHDOG_EXIT`]
/// record ([`exit_record`]) for the agent to sign first.
///
/// [`REASON_WATCHDOG_EXIT`]: nn_proto::watchdog_hold::REASON_WATCHDOG_EXIT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Stopped,
    Unclassified,
    Usage,
    Harden,
    NoAgent,
    Pidfile,
    Backend,
    Notify,
    Signals,
    PidfdWait,
    RecordFailed,
}

impl ExitReason {
    /// Every reason, in the order of the table above.
    pub const ALL: [ExitReason; 11] = [
        ExitReason::Stopped,
        ExitReason::Unclassified,
        ExitReason::Usage,
        ExitReason::Harden,
        ExitReason::NoAgent,
        ExitReason::Pidfile,
        ExitReason::Backend,
        ExitReason::Notify,
        ExitReason::Signals,
        ExitReason::PidfdWait,
        ExitReason::RecordFailed,
    ];

    /// The exit status.
    pub fn code(self) -> u8 {
        match self {
            ExitReason::Stopped => 0,
            ExitReason::Unclassified => 1,
            ExitReason::Usage => 2,
            ExitReason::Harden => 10,
            ExitReason::NoAgent => 11,
            ExitReason::Pidfile => 12,
            ExitReason::Backend => 13,
            ExitReason::Notify => 14,
            ExitReason::Signals => 15,
            ExitReason::PidfdWait => 20,
            ExitReason::RecordFailed => 30,
        }
    }

    /// A short name for the journal and the record.
    pub fn name(self) -> &'static str {
        match self {
            ExitReason::Stopped => "stopped",
            ExitReason::Unclassified => "unclassified",
            ExitReason::Usage => "usage",
            ExitReason::Harden => "hardening_failed",
            ExitReason::NoAgent => "no_verified_agent",
            ExitReason::Pidfile => "pidfile_unwritable",
            ExitReason::Backend => "respawn_backend_failed",
            ExitReason::Notify => "sd_notify_failed",
            ExitReason::Signals => "signal_handlers_failed",
            ExitReason::PidfdWait => "pidfd_wait_failed",
            ExitReason::RecordFailed => "record_failed",
        }
    }
}

/// A failure that ends the watchdog: its [`ExitReason`], the agent it was
/// supervising (0 before one was verified), and the error.
#[derive(Debug)]
pub struct Failure {
    pub reason: ExitReason,
    pub agent_pid: u32,
    pub error: anyhow::Error,
}

impl Failure {
    pub fn new(reason: ExitReason, error: anyhow::Error) -> Self {
        Failure {
            reason,
            agent_pid: 0,
            error,
        }
    }

    /// The agent supervised when it happened.
    pub fn agent(mut self, pid: u32) -> Self {
        self.agent_pid = pid;
        self
    }
}

/// `result.exit_as(reason)`: an error becomes a [`Failure`] with `reason`.
pub trait ExitAs<T> {
    fn exit_as(self, reason: ExitReason) -> std::result::Result<T, Failure>;
}

impl<T> ExitAs<T> for Result<T> {
    fn exit_as(self, reason: ExitReason) -> std::result::Result<T, Failure> {
        self.map_err(|e| Failure::new(reason, e))
    }
}

/// What the restart loop does when the wait on the agent's pidfd fails
/// (the AsyncFd registration or its readiness): exit with
/// [`ExitReason::PidfdWait`] — systemd restarts the watchdog, which opens a
/// new pidfd on the verified agent. It used to `break` the loop and exit 0.
pub fn pidfd_wait_failed(error: anyhow::Error, agent_pid: u32) -> Failure {
    Failure::new(ExitReason::PidfdWait, error).agent(agent_pid)
}

/// Unix seconds now (0 before 1970).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The [`nn_proto::watchdog_hold::REASON_WATCHDOG_EXIT`] record of `failure`,
/// written just before the watchdog exits with its status.
pub fn exit_record(failure: &Failure, at: u64) -> nn_proto::watchdog_hold::HoldRecord {
    nn_proto::watchdog_hold::HoldRecord {
        at,
        agent_pid: failure.agent_pid,
        reason: nn_proto::watchdog_hold::REASON_WATCHDOG_EXIT.to_string(),
        detail: format!(
            "exit status {} ({}): {}",
            failure.reason.code(),
            failure.reason.name(),
            bounded(&format!("{:#}", failure.error), 300)
        ),
        unit_state: None,
    }
}

/// `text` cut to `max` bytes at a char boundary, control characters as
/// spaces (one record per line).
fn bounded(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.len() > max {
        let mut end = max;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// The variables systemd passes to an `OnFailure=` handler (systemd 251+;
/// only when exactly one unit names the handler).
pub const MONITOR_VARS: [&str; 5] = [
    "MONITOR_UNIT",
    "MONITOR_SERVICE_RESULT",
    "MONITOR_EXIT_CODE",
    "MONITOR_EXIT_STATUS",
    "MONITOR_INVOCATION_ID",
];

/// The [`nn_proto::watchdog_hold::REASON_WATCHDOG_FAILED`] record the
/// `OnFailure=` handler writes: systemd put the watchdog unit in its failed
/// state (a start or stop job of its own failed — a death of the process is
/// restarted, the unit has no start limit) and no longer restarts it.
/// `var` reads the handler's environment ([`MONITOR_VARS`]); an older
/// systemd passes none, and the record says so. `agent_pid` is the agent the pidfile names, 0
/// when none.
pub fn unit_failure_record(
    var: impl Fn(&str) -> Option<String>,
    agent_pid: u32,
    at: u64,
) -> nn_proto::watchdog_hold::HoldRecord {
    let fields: Vec<String> = MONITOR_VARS
        .iter()
        .filter_map(|k| {
            var(k).map(|v| {
                format!(
                    "{}={}",
                    k.trim_start_matches("MONITOR_").to_lowercase(),
                    bounded(&v, 64)
                )
            })
        })
        .collect();
    let unit = var("MONITOR_UNIT").unwrap_or_else(|| DEFAULT_WATCHDOG_UNIT.to_string());
    let detail = if fields.is_empty() {
        format!(
            "{} entered the failed state — systemd no longer restarts it (no MONITOR_* \
             variables: systemd older than 251)",
            bounded(&unit, 64)
        )
    } else {
        format!(
            "{} entered the failed state — systemd no longer restarts it: {}",
            bounded(&unit, 64),
            fields.join(" ")
        )
    };
    nn_proto::watchdog_hold::HoldRecord {
        at,
        agent_pid,
        reason: nn_proto::watchdog_hold::REASON_WATCHDOG_FAILED.to_string(),
        detail,
        unit_state: None,
    }
}

/// The watchdog's own unit, named in a failure record without
/// `MONITOR_UNIT`.
pub const DEFAULT_WATCHDOG_UNIT: &str = "northnarrow-watchdog.service";

/// Apply the W2 process-hardening prctls per design §7.4:
///
/// 1. `PR_SET_DUMPABLE = 0` — no core dumps, no
///    `/proc/<pid>/mem` reads by other root processes.
/// 2. `PR_SET_NAME = "northnarrow-wat"` — `comm` stamped
///    deterministically so the agent's stale-PID eviction sees
///    a stable allowed-comm match.
///
/// `cfg(test)` no-op (per §12 W2 test contract). Production code
/// path runs the real `prctl` syscalls.
pub fn harden_self() -> Result<()> {
    #[cfg(test)]
    {
        // Test no-op: the integration test on Hetzner exercises
        // the real prctls; unit tests just verify this function
        // is callable + returns Ok without root.
        Ok(())
    }

    #[cfg(not(test))]
    {
        use anyhow::anyhow;
        use std::ffi::CString;
        // PR_SET_DUMPABLE — no core dumps, no readable /proc/<pid>/mem.
        let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) };
        if r != 0 {
            return Err(anyhow!(
                "prctl(PR_SET_DUMPABLE, 0) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // PR_SET_NAME — comm = "northnarrow-wat" (TASK_COMM_LEN
        // is 16 bytes including NUL, so "northnarrow-wat" with
        // 15 bytes + NUL fits exactly).
        let name = CString::new("northnarrow-wat").expect("static name has no NUL");
        let r = unsafe {
            libc::prctl(
                libc::PR_SET_NAME,
                name.as_ptr() as libc::c_ulong,
                0u64,
                0u64,
                0u64,
            )
        };
        if r != 0 {
            return Err(anyhow!(
                "prctl(PR_SET_NAME, northnarrow-wat) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// Read a PID from a pidfile. Trims one trailing newline (the
/// agent's atomic pidfile writer emits `<pid>\n`); rejects
/// anything that isn't a single positive `u32`.
pub fn read_pid_from_file(path: &Path) -> Result<u32> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading PID file {}", path.display()))?;
    let trimmed = raw.trim();
    trimmed.parse::<u32>().with_context(|| {
        format!(
            "PID file {} did not contain a u32: {trimmed:?}",
            path.display()
        )
    })
}

/// External audit WDG-003: `pid` runs `bin` — `/proc/<pid>/exe` is the
/// same file (device and inode). Another program, or the agent binary
/// replaced on disk while the process ran, is not the agent. Reading
/// another root process's `exe` needs CAP_SYS_PTRACE (the agent is not
/// dumpable) and a caller the agent's `ptrace_access_check` hook admits
/// (the watchdog registers itself in PROTECTED_PIDS first).
pub fn runs_binary(pid: u32, bin: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let want = std::fs::metadata(bin).with_context(|| format!("stat {}", bin.display()))?;
    let exe = format!("/proc/{pid}/exe");
    let got = std::fs::metadata(&exe).with_context(|| format!("stat {exe}"))?;
    if (got.dev(), got.ino()) == (want.dev(), want.ino()) {
        return Ok(());
    }
    let runs = std::fs::read_link(&exe)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| String::from("?"));
    Err(anyhow!("pid {pid} runs {runs}, not {}", bin.display()))
}

/// `pidfd_send_signal(2)`: signal the process the pidfd was opened on,
/// never a process that later reused its pid. `sig == 0` checks that it
/// still runs.
pub fn pidfd_signal(pidfd: RawFd, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: plain syscall on an fd we hold; a null siginfo is allowed.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The process behind `pidfd` has exited (a zombie, or reaped): the pidfd
/// polls readable.
pub fn pidfd_exited(pidfd: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, zero timeout.
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n > 0 && pfd.revents & libc::POLLIN != 0
}

/// Open a pidfd on `pid` and keep it only if the process runs `bin`. The
/// pidfd is opened first and checked again after the identity check, so
/// the pid cannot have been reused in between.
///
/// A process that has already exited is returned unverified (its `exe` is
/// gone): it is no one's agent — nothing to protect or signal — and the
/// caller sees its death at once ([`pidfd_exited`]). An agent killed right
/// after a respawn must lead to the next respawn, not to a verification
/// that can never succeed.
pub fn open_verified_pidfd(pid: u32, bin: &Path) -> Result<OwnedFd> {
    let raw = pidfd_open(pid).with_context(|| format!("pidfd_open({pid})"))?;
    // SAFETY: pidfd_open returned this fd to us; we own it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if pidfd_exited(&fd) {
        return Ok(fd);
    }
    if let Err(e) = runs_binary(pid, bin) {
        if pidfd_exited(&fd) {
            return Ok(fd);
        }
        return Err(e);
    }
    pidfd_signal(fd.as_raw_fd(), 0)
        .with_context(|| format!("pid {pid} exited while it was being verified"))?;
    Ok(fd)
}

/// The agent the pidfile names, verified ([`open_verified_pidfd`]). A
/// pidfile naming another process — anyone who can write
/// `/run/northnarrow` can make it name any pid — is an error: the
/// watchdog does not protect, signal, or copy the command line of a
/// process it has not verified.
pub fn open_verified_agent(pidfile: &Path, bin: &Path) -> Result<(u32, OwnedFd)> {
    let pid = read_pid_from_file(pidfile)?;
    let fd = open_verified_pidfd(pid, bin)
        .with_context(|| format!("the agent pidfile {} names pid {pid}", pidfile.display()))?;
    Ok((pid, fd))
}

/// Raw `pidfd_open(2)` syscall wrapper. Linux 5.3+. Returns the
/// fd on success or the underlying I/O error on failure (most
/// commonly `ESRCH` — no such process).
pub fn pidfd_open(pid: u32) -> std::io::Result<RawFd> {
    // SAFETY: pidfd_open(2) is a thin syscall that takes a
    // `pid_t` + `flags` and returns an fd. Reading errno on
    // negative return is the documented contract.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as RawFd)
    }
}

/// Open a `pidfd_open(2)` on the agent's PID, polling the
/// `agent_pidfile` every [`PIDFD_OPEN_RETRY_INTERVAL`] until the
/// file appears and the PID resolves OR until `deadline` elapses.
///
/// Every error is retried until `deadline`, then returned: the pidfile
/// missing (`NotFound`) or not yet a valid u32, `pidfd_open` → `ESRCH` (a
/// stale PID from a crashed previous boot the agent has not rewritten
/// yet), and `EACCES`/`EPERM` on `/proc/<pid>/exe` — transient by design
/// (external audit WDG-003: the read succeeds once the watchdog is in
/// PROTECTED_PIDS, and a failed [`register_self_pid`] is healed by the
/// agent's 30 s refresh). A misconfigured path therefore costs `deadline`
/// and is then reported; failing fast on it would turn a boot-order race
/// into a watchdog exit loop (external audit WDG-019, NN-AUD-437: this
/// comment promised a short-circuit the loop never had).
///
/// External audit WDG-003: the pid must run `agent_bin`
/// ([`open_verified_agent`]); a pidfile naming any other process is
/// waited out like a missing one, and reported once as tamper.
pub async fn open_agent_pidfd_with_retry(
    agent_pidfile: &Path,
    deadline: Duration,
    agent_bin: &Path,
) -> Result<(u32, OwnedFd)> {
    let start = Instant::now();
    let mut attempts: u32 = 0;
    let mut reported: Option<String> = None;
    loop {
        attempts += 1;
        match open_verified_agent(agent_pidfile, agent_bin) {
            Ok((pid, fd)) => {
                info!(
                    target: "watchdog.pidfd",
                    attempts,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    pid,
                    pidfile = %agent_pidfile.display(),
                    "agent pidfd opened (identity verified)"
                );
                return Ok((pid, fd));
            }
            Err(e) if format!("{e:#}").contains(" runs ") => {
                // A live process that is not the agent: worth an error
                // once, then the same patience as for a missing pidfile.
                let text = format!("{e:#}");
                if reported.as_deref() != Some(text.as_str()) {
                    error!(
                        target: "watchdog.tamper",
                        error = %text,
                        "agent pidfile names a process that is not the agent — not protecting, \
                         signalling or respawning from it"
                    );
                    reported = Some(text);
                }
                if start.elapsed() >= deadline {
                    return Err(e).context("no verified agent before the deadline");
                }
                tokio::time::sleep(PIDFD_OPEN_RETRY_INTERVAL).await;
            }
            Err(transient) if start.elapsed() < deadline => {
                debug!(
                    target: "watchdog.pidfd",
                    attempts,
                    error = format!("{transient:#}"),
                    pidfile = %agent_pidfile.display(),
                    "agent pidfd not yet available, retrying"
                );
                tokio::time::sleep(PIDFD_OPEN_RETRY_INTERVAL).await;
            }
            Err(fatal) => {
                warn!(
                    target: "watchdog.pidfd",
                    attempts,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    error = format!("{fatal:#}"),
                    pidfile = %agent_pidfile.display(),
                    "agent pidfd retry deadline elapsed"
                );
                return Err(fatal).with_context(|| {
                    format!(
                        "opening pidfd on agent (pidfile {}) timed out after {:?}",
                        agent_pidfile.display(),
                        deadline
                    )
                });
            }
        }
    }
}

/// Atomic pidfile write — tmpfile + fsync + `rename(2)`. Mode 0644 so the
/// agent's W6 PROTECTED_PIDS widening (running as root) can read this
/// trivially.
///
/// External audit WDG-015 (NN-AUD-364): the temporary file was opened at
/// `<pidfile>.tmp` with `create(true).truncate(true)`, so a link planted at
/// that name in `/run/northnarrow` (root-writable, outside the inode deny
/// set) was written through by a process the hooks trust. It is now the
/// agent's AUT-003 writer ([`antitamper_bpf::atomic_file::write_pidfile`]): the
/// temporary name is removed, created exclusively, renamed into place, and
/// the directory synced.
///
/// Lab PR 216 (static review C-43 / G-06): a missing parent is created
/// 0700, the mode of the units' `RuntimeDirectoryMode=` — it was created
/// with the process umask (0755 under systemd), like `install.sh`'s
/// `/run/northnarrow`.
pub fn write_pidfile_atomic(path: &Path, pid: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(RUN_DIR_MODE)
                .create(parent)
                .with_context(|| format!("creating pidfile parent {}", parent.display()))?;
        }
    }
    antitamper_bpf::atomic_file::write_pidfile(path, pid)
        .with_context(|| format!("writing pidfile {} (atomic replace)", path.display()))
}

/// Lab PR 216: the mode of `/run/northnarrow` (the units'
/// `RuntimeDirectoryMode=`, `install.sh`'s `install -d -m 0700`).
pub const RUN_DIR_MODE: u32 = 0o700;

/// Manual systemd `sd_notify(READY=1)` — sends a single Unix
/// datagram to `$NOTIFY_SOCKET` per the `sd_notify(3)` wire
/// protocol ([`antitamper_bpf::sd_notify`], shared with the agent): a path,
/// or `@name` in the abstract namespace (external audit MAIN-016:
/// it was sent to `@name` as a path, and never arrived). Cheap and
/// no new dep vs `libsystemd-rs` / `sd-notify` crates.
///
/// Returns Ok WHEN `NOTIFY_SOCKET` is unset (watchdog not running
/// under `Type=notify`) — that's a normal dev-shell invocation,
/// not an error. A value it cannot send to is an error.
pub fn sd_notify_ready() -> Result<()> {
    let sent = antitamper_bpf::sd_notify::notify(b"READY=1\n").with_context(|| {
        format!(
            "sending READY=1 to NOTIFY_SOCKET={}",
            std::env::var_os("NOTIFY_SOCKET")
                .unwrap_or_default()
                .to_string_lossy()
        )
    })?;
    match sent {
        Some(socket) => info!(
            target: "watchdog.sd_notify",
            socket = %socket.to_string_lossy(),
            "systemd READY=1 sent"
        ),
        None => debug!(
            target: "watchdog.sd_notify",
            "NOTIFY_SOCKET unset — not running under systemd Type=notify; skipping"
        ),
    }
    Ok(())
}

/// External audit WDG-004: `STATUS=<status>` to systemd, best effort (a
/// no-op outside `Type=notify`). `systemctl status` shows it.
pub fn sd_notify_status(status: &str) {
    if let Err(e) = antitamper_bpf::sd_notify::notify(format!("STATUS={status}\n").as_bytes()) {
        warn!(target: "watchdog.sd_notify", error = %e, status, "sd_notify STATUS failed");
    }
}

/// External audit WDG-004: how a hold ended.
pub enum HoldOutcome {
    /// An agent runs again; supervise it.
    Resumed { pid: u32, pidfd: OwnedFd },
    /// The watchdog itself was told to stop.
    Shutdown(&'static str),
}

/// How often a holding watchdog looks for an agent started again.
pub const HOLD_POLL: Duration = Duration::from_secs(2);

/// Lab PR 216: how often a holding watchdog refreshes its `STATUS=` line
/// (`systemctl status`: how long it has held, when it retries).
pub const HOLD_STATUS_EVERY: Duration = Duration::from_secs(60);

/// Lab PR 216: how often a hold repeats its ERROR line on
/// `watchdog.tamper` — a hold that lasts is not a single line in the
/// journal.
pub const HOLD_REMIND_EVERY: Duration = Duration::from_secs(600);

/// Lab PR 216: the first wait of a hold before it starts the agent once
/// more, without an operator.
pub const HOLD_RETRY_FIRST: Duration = Duration::from_secs(600);

/// Lab PR 216: the longest wait between two retries of a hold.
pub const HOLD_RETRY_MAX: Duration = Duration::from_secs(3600);

/// Lab PR 216 (static review C-44: "after 5 restarts in 60 s the hold is
/// indefinite"): the hold is bounded. After [`HOLD_RETRY_FIRST`] it starts
/// the agent once more, then waits twice as long before the next retry, up
/// to [`HOLD_RETRY_MAX`]; the count carries across the holds of one
/// watchdog, so an agent that keeps failing is retried at most once an
/// hour. Each retry is recorded (`hold_retry`) and is what lets an agent
/// run again to sign the hold — a hold with no agent had no signer.
#[derive(Debug, Clone)]
pub struct HoldRetry {
    first: Duration,
    max: Duration,
    retries: u32,
}

impl HoldRetry {
    /// [`HOLD_RETRY_FIRST`] doubling up to [`HOLD_RETRY_MAX`].
    pub fn new() -> Self {
        Self::with(HOLD_RETRY_FIRST, HOLD_RETRY_MAX)
    }

    /// Other bounds (tests).
    pub fn with(first: Duration, max: Duration) -> Self {
        HoldRetry {
            first,
            max,
            retries: 0,
        }
    }

    /// How long to hold before the next retry: `first * 2^retries`, at
    /// most `max`.
    pub fn next_wait(&self) -> Duration {
        let factor = 1u32.checked_shl(self.retries.min(31)).unwrap_or(u32::MAX);
        self.first
            .checked_mul(factor)
            .unwrap_or(self.max)
            .min(self.max)
    }

    /// A retry was made.
    pub fn record(&mut self) {
        self.retries = self.retries.saturating_add(1);
    }

    /// Retries made so far.
    pub fn retries(&self) -> u32 {
        self.retries
    }
}

impl Default for HoldRetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Lab PR 216: the `STATUS=` line of a hold — why, for how long, and when
/// the next retry starts the agent. `systemctl status northnarrow-watchdog`
/// shows it.
pub fn hold_status_line(why: &str, held_for: Duration, next_retry_in: Duration) -> String {
    format!(
        "DEGRADED: {why} — holding for {} s, not respawning the agent; next retry in {} s \
         (or start northnarrow-agent once investigated)",
        held_for.as_secs(),
        next_retry_in.as_secs()
    )
}

/// External audit WDG-004: wait, without respawning anything, until an
/// agent runs again — an operator started it after investigating, and its
/// pidfile names a live pid — or until `shutdown` resolves. The caller
/// removes the dead agent's pidfile first: once its PID is reused it would
/// read as a live agent.
pub async fn hold_until_agent_returns<S>(
    agent_pidfile: &Path,
    poll: Duration,
    shutdown: S,
    agent_bin: &Path,
) -> HoldOutcome
where
    S: std::future::Future<Output = &'static str>,
{
    tokio::pin!(shutdown);
    let mut tick = tokio::time::interval(poll);
    loop {
        tokio::select! {
            name = &mut shutdown => return HoldOutcome::Shutdown(name),
            _ = tick.tick() => {
                // External audit WDG-003: only a process running the agent
                // binary ends the hold.
                if let Ok((pid, pidfd)) = open_verified_agent(agent_pidfile, agent_bin) {
                    return HoldOutcome::Resumed { pid, pidfd };
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Watchdog W3 — pidfd-driven agent death detection + layer-2
// PROTECTED_PIDS evict (design §6.2 + §12 row W3)
// ────────────────────────────────────────────────────────────────────

/// Outcome of one layer-2 evict — what was done + how long the
/// wakeup→delete leg took. The design's typical-case budget is
/// ≤ 50 µs (§6.2); a tracing log records the measured value at
/// every fire so an operator can spot regressions in the kernel
/// or the bpf syscall path without redeploying.
#[derive(Debug, Clone, Copy)]
pub struct EvictReport {
    /// The PID we just deleted from `PROTECTED_PIDS`.
    pub agent_pid: u32,
    /// Elapsed time from the start of [`evict_dead_agent`] to
    /// successful bpf map delete. Includes the
    /// `ProtectedPidsHandle::open(bpffs_root)` cost (one
    /// `BPF_OBJ_GET` syscall on the pin path); the typical
    /// budget is single-digit microseconds end-to-end.
    pub evict_latency: Duration,
}

/// Park on the agent's pidfd until the kernel signals
/// `POLLIN` — fires the moment the agent task is reaped, with
/// µs-latency from `do_exit` to wakeup. Race-free vs the
/// PID-recycle window (the pidfd is bound to the kernel task
/// struct, not the numeric PID; a future process at the recycled
/// PID is a different kernel task and never triggers this fd).
///
/// Consumes the [`OwnedFd`] (registers it inside the
/// [`AsyncFd`]); on return the fd is dropped by the
/// AsyncFd. Idempotent re-arming is not supported — one fd,
/// one wakeup, one watchdog cycle (the agent dies once per
/// boot per the design's process model).
pub async fn wait_for_agent_death(agent_pidfd: &OwnedFd) -> Result<()> {
    // AsyncFd registers the fd with mio's epoll; `Interest::READABLE`
    // maps to EPOLLIN, which is exactly what pidfd signals on
    // task reap. `with_interest` is preferred over `new()` so we
    // don't accidentally register WRITE interest and pay for
    // pointless EPOLLOUT wakeups.
    // SAFETY: `agent_pidfd` is borrowed for this whole function and the
    // `AsyncFd` is dropped before it returns: the pidfd stays open and
    // names the same process for the `AsyncFd`'s life (tokio#8587 made
    // that contract explicit in `register_with_interest`).
    let async_fd =
        unsafe { AsyncFd::register_with_interest(agent_pidfd.as_fd(), Interest::READABLE) }
            .map_err(std::io::Error::from)
            .context("registering agent pidfd with tokio AsyncFd")?;
    // `readable()` returns when epoll reports POLLIN. We drop
    // the ready guard immediately — there's nothing to "read"
    // from a pidfd; the wakeup IS the message.
    let _guard = async_fd
        .readable()
        .await
        .context("awaiting agent pidfd POLLIN")?;
    Ok(())
}

/// What [`reap_agent`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaped {
    /// A child of the watchdog (the exec backend started it): its exit
    /// status collected, the zombie gone. `code` is the exit code or the
    /// signal number, as `si_code` says.
    Collected { pid: u32, si_code: i32, code: i32 },
    /// Not a child of the watchdog (systemd or an operator started it):
    /// its parent collects it. The normal case on a systemd host.
    NotOurChild,
    /// A child that has not exited yet.
    Running,
}

/// External audit WDG-010 (NN-AUD-360): the exec backend dropped each
/// respawned agent's `Child` at once and nothing ever waited for it, so
/// every respawned agent stayed a zombie child of the watchdog (inside the
/// unit, `TasksMax=8`). Called once the pidfd reports the agent's exit:
/// `waitid(P_PIDFD, fd, WEXITED | WNOHANG)` collects it through the pidfd
/// already held — never by pid, which may have been reused. `ECHILD` (an
/// agent the watchdog did not start) is [`Reaped::NotOurChild`].
pub fn reap_agent(pidfd: &OwnedFd) -> std::io::Result<Reaped> {
    // SAFETY: an all-zero siginfo_t is a valid value to pass to waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid on a pidfd we hold, writing into `info`, which we own.
    let ret = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd.as_raw_fd() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG,
        )
    };
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ECHILD) => Ok(Reaped::NotOurChild),
            _ => Err(e),
        };
    }
    // SAFETY: waitid filled `info` (or left it zeroed under WNOHANG when
    // the child has not exited: si_pid 0).
    let (pid, code) = unsafe { (info.si_pid(), info.si_status()) };
    if pid == 0 {
        return Ok(Reaped::Running);
    }
    Ok(Reaped::Collected {
        pid: pid as u32,
        si_code: info.si_code,
        code,
    })
}

/// Perform the layer-2 PROTECTED_PIDS evict on confirmed agent
/// death (design §6.2 step 2-4). Opens
/// [`ProtectedPidsHandle::open`] on the bpffs pin path AND
/// deletes the agent's PID from the map, returning the
/// [`EvictReport`] for the caller to log.
///
/// Idempotent: [`ProtectedPidsHandle::evict`] swallows
/// "key not found" so a layer-1 race (agent already removed
/// its own entry on graceful shutdown via `evict_stale_pids`
/// at next boot) doesn't surface as an error here.
pub fn evict_dead_agent(bpffs_root: &Path, agent_pid: u32) -> Result<EvictReport> {
    let start = Instant::now();
    let mut handle = ProtectedPidsHandle::open(bpffs_root).with_context(|| {
        format!(
            "opening PROTECTED_PIDS handle at {} for layer-2 evict",
            bpffs_root.display()
        )
    })?;
    handle
        .evict(agent_pid)
        .with_context(|| format!("evicting agent PID {agent_pid} from PROTECTED_PIDS"))?;
    let latency = start.elapsed();
    info!(
        target: "watchdog.layer2_evict",
        pid = agent_pid,
        latency_us = latency.as_micros() as u64,
        bpffs_root = %bpffs_root.display(),
        "evicted dead agent PID from PROTECTED_PIDS"
    );
    Ok(EvictReport {
        agent_pid,
        evict_latency: latency,
    })
}

// ────────────────────────────────────────────────────────────────────
// Watchdog W4 — respawn with bounded exponential backoff +
// 5-in-60s ceiling (design §5 + §12 row W4)
// ────────────────────────────────────────────────────────────────────

/// First restart fires immediately (within ~10 ms after pidfd
/// POLLIN, bounded by evict + Command::spawn latency). Subsequent
/// attempts grow exponentially.
pub const RESTART_INITIAL_DELAY: Duration = Duration::ZERO;
/// Base for the exponential backoff: attempt 2 waits 100 ms,
/// attempt 3 waits 200 ms, attempt 4 waits 400 ms, attempt 5
/// waits 800 ms. Formula: `RESTART_BACKOFF_BASE * 2^(attempt - 2)`.
pub const RESTART_BACKOFF_BASE: Duration = Duration::from_millis(100);
/// Per design §5.1, the exponential growth caps at 5 s so a
/// long-troubled host doesn't burn minutes between restart
/// attempts. (Capped after 4 doublings = 1.6 s would be the
/// natural 6th-attempt delay; the cap kicks in beyond that.)
pub const RESTART_BACKOFF_CAP: Duration = Duration::from_secs(5);
/// Per design §5.1, 5 failed restarts within a 60 s sliding
/// window trips the "tamper suspected" ceiling and the watchdog
/// stops restarting (but stays alive for operator inspection).
pub const RESTART_CEILING_MAX_ATTEMPTS: u8 = 5;
pub const RESTART_CEILING_WINDOW: Duration = Duration::from_secs(60);

/// Outcome of a single backoff-state-machine tick. Either tells
/// the caller how long to wait before the next spawn, or that
/// the per-window ceiling has been reached and respawn must
/// stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackoffOutcome {
    /// Wait `delay` then spawn the agent. Carries the attempt
    /// number for log context (1-based — `attempt == 1` is the
    /// first restart in the current window).
    Wait { delay: Duration, attempt: u8 },
    /// The sliding window has accumulated
    /// [`RESTART_CEILING_MAX_ATTEMPTS`] failures; the watchdog
    /// must NOT respawn. Carries the actual attempt count + the
    /// window width so the journal line is self-describing.
    CeilingExceeded {
        attempts_in_window: u8,
        window: Duration,
    },
}

/// Restart backoff state machine. Holds the sliding-window of
/// recent restart timestamps + the configured timing knobs (so
/// tests can use a short window without sleeping for real
/// minutes).
#[derive(Debug, Clone)]
pub struct RestartBackoff {
    /// Recent restart attempt timestamps, in arrival order. The
    /// window prunes any entries older than `window` on every
    /// `next_delay` call. Bounded by `max_attempts` in steady
    /// state (older entries fall off as new ones arrive).
    attempts: VecDeque<Instant>,
    /// Sliding-window width. Production: 60 s per §5.1.
    window: Duration,
    /// Per-window ceiling. Production: 5 per §5.1.
    max_attempts: u8,
    /// Exponential base. Production: 100 ms.
    base: Duration,
    /// Hard cap on the exponential growth. Production: 5 s.
    cap: Duration,
}

impl RestartBackoff {
    /// Production constructor — every knob set to the design
    /// §5.1 default.
    pub fn new() -> Self {
        Self::with_config(
            RESTART_CEILING_WINDOW,
            RESTART_CEILING_MAX_ATTEMPTS,
            RESTART_BACKOFF_BASE,
            RESTART_BACKOFF_CAP,
        )
    }

    /// Test-only knobs so the 60 s window doesn't drag unit tests
    /// into the minute-scale. Public so future custom integration
    /// tests (W8) can tune it; production callers go through
    /// [`Self::new`].
    pub fn with_config(window: Duration, max_attempts: u8, base: Duration, cap: Duration) -> Self {
        Self {
            attempts: VecDeque::new(),
            window,
            max_attempts,
            base,
            cap,
        }
    }

    /// Record one restart attempt and compute the delay before
    /// the spawn. `now` is taken as a parameter so tests can
    /// inject deterministic time without a Clock trait.
    ///
    /// Returns:
    /// - `Wait { delay = ZERO, attempt = 1 }` for the first
    ///   attempt in a fresh window (immediate restart per §5.1).
    /// - `Wait { delay = base * 2^(attempt - 2), attempt }`
    ///   capped at `cap` for attempts 2..=max_attempts.
    /// - `CeilingExceeded { attempts_in_window, window }` when
    ///   the count of attempts inside the sliding window meets
    ///   or exceeds `max_attempts` — the caller must NOT respawn.
    pub fn next_delay(&mut self, now: Instant) -> BackoffOutcome {
        // Prune entries that fell out the window's tail.
        while let Some(&oldest) = self.attempts.front() {
            if now.saturating_duration_since(oldest) > self.window {
                self.attempts.pop_front();
            } else {
                break;
            }
        }

        if (self.attempts.len() as u8) >= self.max_attempts {
            return BackoffOutcome::CeilingExceeded {
                attempts_in_window: self.attempts.len() as u8,
                window: self.window,
            };
        }

        // Record THIS attempt before computing the delay so the
        // attempt number lines up with the design's 1-based
        // counting ("first restart" = attempt 1 = immediate).
        self.attempts.push_back(now);
        let attempt = self.attempts.len() as u8;

        let delay = if attempt <= 1 {
            Duration::ZERO
        } else {
            // attempt 2 → 2^0 = 1× base = 100 ms
            // attempt 3 → 2^1 = 2× base = 200 ms
            // attempt 4 → 2^2 = 4× base = 400 ms
            // attempt 5 → 2^3 = 8× base = 800 ms
            let exp = (attempt - 2) as u32;
            // checked_pow avoids overflow at extreme attempt
            // counts (the ceiling fires first in practice but
            // belt-and-suspenders here is cheap).
            let multiplier = 2u64.checked_pow(exp).unwrap_or(u64::MAX);
            let unbounded = self
                .base
                .checked_mul(multiplier.min(u32::MAX as u64) as u32)
                .unwrap_or(self.cap);
            unbounded.min(self.cap)
        };

        BackoffOutcome::Wait { delay, attempt }
    }

    /// Number of attempts currently inside the sliding window.
    /// Used in the "tamper suspected" log line. Does NOT prune
    /// — callers see the count as of the last `next_delay`.
    pub fn attempts_in_window(&self) -> usize {
        self.attempts.len()
    }
}

impl Default for RestartBackoff {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the agent with the persisted argv. Per design §5.3 the
/// canonical respawn command is the first launch's argv (in
/// systemd deployment, `ExecStart=` of `northnarrow-agent.service`).
/// For W4 the caller is responsible for supplying that argv —
/// argv parsing from systemd happens in W7's deploy commit; W4
/// just consumes whatever slice it's given.
///
/// `argv[0]` must be the agent binary path; `argv[1..]` are the
/// flags. Inherits stdio from the watchdog (so journald captures
/// agent logs through the watchdog unit's journal — by design,
/// the agent's own unit `Restart=no` means systemd-direct journal
/// only sees the agent's first crash before the watchdog took
/// over respawn).
pub fn spawn_agent(argv: &[String]) -> Result<Child> {
    let bin = argv
        .first()
        .ok_or_else(|| anyhow!("spawn_agent: empty argv (need at least the binary path)"))?;
    let child = Command::new(bin)
        .args(&argv[1..])
        .spawn()
        .with_context(|| format!("Command::spawn({bin})"))?;
    info!(
        target: "watchdog.respawn",
        bin,
        argc = argv.len(),
        new_pid = child.id(),
        "agent respawned"
    );
    Ok(child)
}

// ── Respawn v2 — backend selection (design: WATCHDOG_RESPAWN_V2_DESIGN) ──

/// Directory systemd creates only when it is PID 1 of a booted system
/// (`sd_booted(3)` checks the same path).
pub const SYSTEMD_RUNTIME_DIR: &str = "/run/systemd/system";
/// Agent unit the `systemd` backend starts.
pub const DEFAULT_AGENT_UNIT: &str = "northnarrow-agent.service";
/// `systemctl` locations tried in order (merged-/usr first).
pub const SYSTEMCTL_CANDIDATES: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];

/// Operator choice for the respawn backend (`--respawn-backend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RespawnBackendChoice {
    /// `systemd` when [`SYSTEMD_RUNTIME_DIR`] exists, else `exec`.
    Auto,
    /// `systemctl start <unit>`: the agent returns under ITS OWN unit
    /// (ExecStart argv, cgroup, caps, ProtectHome, journal namespace).
    Systemd,
    /// Fork-exec with the persisted first-launch argv (non-systemd hosts).
    Exec,
}

/// How the watchdog brings the agent back. The watchdog still decides
/// WHEN (backoff, ceiling, shutdown marker); this is only the HOW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespawnBackend {
    SystemdUnit { unit: String },
    ForkExec { argv: Vec<String> },
}

impl RespawnBackend {
    /// One-line description for the boot log.
    pub fn describe(&self) -> String {
        match self {
            RespawnBackend::SystemdUnit { unit } => format!("systemd:{unit}"),
            RespawnBackend::ForkExec { argv } => {
                format!(
                    "exec:{} (argc={})",
                    argv.first().map(String::as_str).unwrap_or("?"),
                    argv.len()
                )
            }
        }
    }
}

/// `true` when systemd is the running init (same test as `sd_booted`).
pub fn systemd_is_booted(runtime_dir: &Path) -> bool {
    runtime_dir.is_dir()
}

/// Resolve the operator's choice into a concrete backend. `exec_argv`
/// is only invoked when the exec backend is selected, so a systemd host
/// never pays for (or fails on) the /proc argv reconstruction.
pub fn select_backend(
    choice: RespawnBackendChoice,
    systemd_booted: bool,
    unit: &str,
    exec_argv: impl FnOnce() -> Result<Vec<String>>,
) -> Result<RespawnBackend> {
    let use_systemd = match choice {
        RespawnBackendChoice::Systemd => true,
        RespawnBackendChoice::Exec => false,
        RespawnBackendChoice::Auto => systemd_booted,
    };
    if use_systemd {
        if !systemd_booted {
            warn!(
                target: "watchdog.respawn",
                "--respawn-backend systemd requested but {SYSTEMD_RUNTIME_DIR} is absent; \
                 systemctl calls will fail until systemd is the running init"
            );
        }
        return Ok(RespawnBackend::SystemdUnit {
            unit: unit.to_string(),
        });
    }
    let argv = exec_argv().context("building the exec respawn argv")?;
    if argv.is_empty() {
        return Err(anyhow!("exec respawn backend needs a non-empty argv"));
    }
    Ok(RespawnBackend::ForkExec { argv })
}

/// Split a `/proc/<pid>/cmdline` body (NUL-separated, NUL-terminated)
/// into argv. An empty body (zombie / kernel thread) yields an empty vec.
pub fn parse_proc_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// The agent's FULL first-launch argv from `/proc/<pid>/cmdline`, with
/// `argv[0]` optionally replaced by `--agent-bin` (an installer may have
/// moved the binary since the agent started). This is what §5.3 of the
/// Tappa 7 design asked for and what closes `combat-avail-1`: every
/// flag — `--combat-rules`, `--admin-pub`, `--detect-only`, … —
/// survives the respawn.
pub fn agent_argv_from_proc(pid: u32, agent_bin: Option<&Path>) -> Result<Vec<String>> {
    let path = format!("/proc/{pid}/cmdline");
    let bytes = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
    let mut argv = parse_proc_cmdline(&bytes);
    if argv.is_empty() {
        return Err(anyhow!(
            "{path} is empty (agent exited before argv capture?)"
        ));
    }
    if let Some(bin) = agent_bin {
        argv[0] = bin.to_string_lossy().into_owned();
    }
    Ok(argv)
}

/// External audit WDG-008 (NN-AUD-359): where the exec backend keeps the
/// agent's last captured argv, next to the agent pidfile
/// (`/run/northnarrow/agent.argv`; the watchdog unit may write only there,
/// `ReadWritePaths=/run/northnarrow`).
pub const AGENT_ARGV_FILE_NAME: &str = "agent.argv";

/// Largest argv record read back.
pub const AGENT_ARGV_MAX_BYTES: u64 = 64 * 1024;

/// [`AGENT_ARGV_FILE_NAME`] beside `agent_pidfile`.
pub fn agent_argv_record_path(agent_pidfile: &Path) -> PathBuf {
    agent_pidfile.with_file_name(AGENT_ARGV_FILE_NAME)
}

/// Keep a successful capture: NUL-separated like `/proc/<pid>/cmdline`,
/// 0600, with the AUT-003 writer (never through a link at the name).
pub fn persist_agent_argv(path: &Path, argv: &[String]) -> Result<()> {
    let mut body = Vec::new();
    for arg in argv {
        body.extend_from_slice(arg.as_bytes());
        body.push(0);
    }
    antitamper_bpf::atomic_file::replace(path, &body, 0o600)
        .with_context(|| format!("recording the agent argv at {}", path.display()))
}

/// The argv [`persist_agent_argv`] kept: a regular file (a link is not
/// followed), owned by the watchdog's user, closed to others, at most
/// [`AGENT_ARGV_MAX_BYTES`], with at least the binary.
pub fn read_persisted_agent_argv(path: &Path) -> Result<Vec<String>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = f
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.file_type().is_file() {
        return Err(anyhow!("{} is not a regular file", path.display()));
    }
    if meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return Err(anyhow!(
            "{} is owned by uid {} with mode {:o}: not the watchdog's 0600 record",
            path.display(),
            meta.uid(),
            meta.mode() & 0o7777
        ));
    }
    if meta.len() > AGENT_ARGV_MAX_BYTES {
        return Err(anyhow!(
            "{} is larger than {AGENT_ARGV_MAX_BYTES} bytes",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    f.take(AGENT_ARGV_MAX_BYTES)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    let argv = parse_proc_cmdline(&bytes);
    if argv.is_empty() {
        return Err(anyhow!("{} is empty", path.display()));
    }
    Ok(argv)
}

/// Argv for the exec backend, captured once at the watchdog's start
/// (external audit WDG-008, NN-AUD-359): the agent's full
/// `/proc/<pid>/cmdline` (`--agent-bin` overriding argv[0]), kept at
/// `record` for a later start of the watchdog; when /proc cannot be read
/// (the agent exited between the pidfd open and the capture), the argv
/// kept at `record` by an earlier capture, with argv[0] the binary the
/// agent was verified to run; with neither, the minimal
/// `[verified_bin, --pid-file, pidfile]`, which drops every other flag.
/// Each fallback is a WARN and a record at `hold_path`
/// ([`nn_proto::watchdog_hold::REASON_RESPAWN_ARGV_DEGRADED`]) that the agent
/// signs at its next round: every later respawn uses that argv. Only the
/// exec backend (non-systemd hosts) calls this.
pub fn exec_respawn_argv(
    agent_pid: u32,
    agent_bin: Option<&Path>,
    verified_bin: &Path,
    agent_pidfile: &Path,
    hold_path: &Path,
) -> Vec<String> {
    let record = agent_argv_record_path(agent_pidfile);
    let capture_error = match agent_argv_from_proc(agent_pid, agent_bin) {
        Ok(argv) => {
            if let Err(e) = persist_agent_argv(&record, &argv) {
                warn!(
                    target: "watchdog.respawn",
                    error = format!("{e:#}"),
                    "the agent argv was captured but not recorded; a later watchdog start that \
                     cannot read /proc falls back to the minimal argv"
                );
            }
            return argv;
        }
        Err(e) => e,
    };
    let (argv, source) = match read_persisted_agent_argv(&record) {
        Ok(mut argv) => {
            argv[0] = verified_bin.to_string_lossy().into_owned();
            (argv, format!("the argv recorded at {}", record.display()))
        }
        Err(e) => (
            vec![
                verified_bin.to_string_lossy().into_owned(),
                "--pid-file".to_string(),
                agent_pidfile.to_string_lossy().into_owned(),
            ],
            format!(
                "the minimal argv (flags such as --detect-only / --admin-pub do NOT survive a \
                 respawn; no usable record: {e:#})"
            ),
        ),
    };
    warn!(
        target: "watchdog.respawn",
        error = format!("{capture_error:#}"),
        args = ?argv,
        "full argv capture from /proc failed — respawns use {source}"
    );
    let detail = format!(
        "/proc/{agent_pid}/cmdline unreadable ({capture_error:#}); respawns use {source}: {argv:?}"
    );
    let rec = nn_proto::watchdog_hold::HoldRecord {
        at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        agent_pid,
        reason: nn_proto::watchdog_hold::REASON_RESPAWN_ARGV_DEGRADED.to_string(),
        detail,
        unit_state: None,
    };
    if let Err(e) = record_hold(hold_path, &rec) {
        warn!(
            target: "watchdog.respawn",
            error = format!("{e:#}"),
            path = %hold_path.display(),
            "could not record the degraded respawn argv for the agent's audit chain"
        );
    }
    argv
}

/// First existing `systemctl` from [`SYSTEMCTL_CANDIDATES`].
pub fn find_systemctl() -> Option<PathBuf> {
    SYSTEMCTL_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// `systemctl start --no-block <unit>`: queue the start job and return.
/// Readiness is observed by the caller through the agent pidfile, exactly
/// as for the exec backend, so `--no-block` loses nothing and keeps the
/// watchdog's restart loop from blocking on a slow agent boot.
pub fn systemctl_start_command(systemctl: &Path, unit: &str) -> Command {
    let mut cmd = Command::new(systemctl);
    cmd.arg("start").arg("--no-block").arg(unit);
    cmd
}

/// Run [`systemctl_start_command`] and map the exit status.
pub fn systemctl_start(unit: &str) -> Result<()> {
    let systemctl = find_systemctl()
        .ok_or_else(|| anyhow!("systemctl not found at any of {SYSTEMCTL_CANDIDATES:?}"))?;
    let out = systemctl_start_command(&systemctl, unit)
        .output()
        .with_context(|| format!("spawning {} start {unit}", systemctl.display()))?;
    if out.status.success() {
        info!(
            target: "watchdog.respawn",
            unit,
            systemctl = %systemctl.display(),
            "systemctl start queued"
        );
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let masked = stderr.contains("masked");
    error!(
        target: "watchdog.respawn",
        unit,
        status = ?out.status.code(),
        unit_masked = masked,
        stderr = %stderr,
        "systemctl start FAILED"
    );
    Err(anyhow!(
        "systemctl start {unit} failed (status {:?}): {stderr}",
        out.status.code()
    ))
}

/// Bring the agent back through `backend`. For the exec backend the
/// child handle is dropped immediately: the agent is tracked by its pidfd,
/// and collected through it once it exits ([`reap_agent`], external audit
/// WDG-010).
pub fn respawn_agent(backend: &RespawnBackend) -> Result<()> {
    match backend {
        RespawnBackend::SystemdUnit { unit } => systemctl_start(unit),
        RespawnBackend::ForkExec { argv } => {
            let child = spawn_agent(argv)?;
            std::mem::drop(child);
            Ok(())
        }
    }
}

/// External audit WDG-009: run blocking work (`systemctl`, fork-exec) on
/// tokio's blocking pool. The watchdog's runtime has one thread; a
/// `systemctl` call waiting on a busy PID 1 (up to the D-Bus timeout) used
/// to stop the STATUS ping and the timers with it.
pub async fn off_runtime<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow!("blocking task: {e}"))?
}

/// [`respawn_agent`] off the runtime thread ([`off_runtime`]).
pub async fn respawn_agent_off_runtime(backend: &RespawnBackend) -> Result<()> {
    let backend = backend.clone();
    off_runtime(move || respawn_agent(&backend)).await
}

/// Unit properties recorded with a hold (external audit DEP-004): they
/// tell a unit that failed (`ActiveState=failed`, `Result=exit-code` for
/// the bpffs pre-flight), was skipped (`ConditionResult=no`) or was
/// stopped from one still starting.
pub const UNIT_STATE_PROPERTIES: &str = "ActiveState,SubState,Result,ConditionResult,AssertResult";

/// How long a hold waits for `systemctl show` before recording no state.
pub const UNIT_STATE_TIMEOUT: Duration = Duration::from_secs(5);

/// `systemctl show --property=… <unit>`.
pub fn systemctl_show_command(systemctl: &Path, unit: &str) -> Command {
    let mut cmd = Command::new(systemctl);
    cmd.arg("show")
        .arg(format!("--property={UNIT_STATE_PROPERTIES}"))
        .arg(unit);
    cmd
}

/// `systemctl show`'s `Key=Value` lines on one line, in its order; at most
/// 256 bytes. `None` when there is none.
pub fn unit_state_from_show(stdout: &str) -> Option<String> {
    let mut state = stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.contains('='))
        .collect::<Vec<_>>()
        .join(" ");
    if state.is_empty() {
        return None;
    }
    if state.len() > 256 {
        let mut end = 256;
        while !state.is_char_boundary(end) {
            end -= 1;
        }
        state.truncate(end);
    }
    Some(state)
}

/// The agent unit's state ([`UNIT_STATE_PROPERTIES`]). Blocking: call
/// through [`off_runtime`].
pub fn systemctl_unit_state(unit: &str) -> Result<String> {
    let systemctl = find_systemctl()
        .ok_or_else(|| anyhow!("systemctl not found at any of {SYSTEMCTL_CANDIDATES:?}"))?;
    let out = systemctl_show_command(&systemctl, unit)
        .output()
        .with_context(|| format!("spawning {} show {unit}", systemctl.display()))?;
    if !out.status.success() {
        return Err(anyhow!(
            "systemctl show {unit} failed (status {:?})",
            out.status.code()
        ));
    }
    unit_state_from_show(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| anyhow!("systemctl show {unit}: no properties"))
}

/// External audit DEP-004: record a hold at `path` for the agent's signed
/// audit chain ([`nn_proto::watchdog_hold`]). One JSON line per hold,
/// appended (0600, never through a symlink).
pub fn record_hold(path: &Path, record: &nn_proto::watchdog_hold::HoldRecord) -> Result<()> {
    let line = serde_json::to_string(record).context("serialising the hold record")? + "\n";
    append_line(path, &line).with_context(|| format!("appending to {}", path.display()))
}

/// Where [`record_hold`] writes: next to the shutdown marker, like the
/// refused-marker record ([`nn_proto::watchdog_hold::HOLD_PATH`] with the
/// default paths).
pub fn hold_record_path(shutdown_marker: &Path) -> PathBuf {
    shutdown_marker.with_file_name(file_name_of(nn_proto::watchdog_hold::HOLD_PATH))
}

/// Defensive re-insert of the new agent's PID into
/// PROTECTED_PIDS — the design §5.4 "load-bearing" duplicate
/// of the agent's own [`register_protected_pids`] call. Closes
/// the brief window between "new agent process spawned" and
/// "new agent finished its own anti_tamper::attach()". Both
/// writes are idempotent (BPF_ANY upsert).
///
/// Errors are surfaced but the caller's typical response is
/// warn-and-continue: the agent will re-insert its own PID via
/// `register_protected_pids` shortly anyway, so a failure here
/// only widens the race window — it doesn't permanently lose
/// PROTECTED_PIDS coverage.
/// Register the watchdog's OWN pid in PROTECTED_PIDS (design §7.1 /
/// §7.3 — "the new watchdog re-registers its own PID"). Two reasons it
/// must be the watchdog itself and not only the agent: (1) ordering —
/// the watchdog unit starts After= the agent, so at the first boot the
/// agent finds no watchdog pidfile and registers nobody but itself;
/// (2) since `task-kill-signals-1` the task_kill hook accepts a signal
/// towards a protected pid only from another PROTECTED pid (or PID 1 /
/// self), so an unregistered watchdog could not deliver its
/// stuck-recovery SIGINT→SIGKILL. Best effort for the caller: no pinned
/// map (agent without BPF-LSM) is a warn, not a fatal.
pub fn register_self_pid(bpffs_root: &Path, own_pid: u32) -> Result<()> {
    let mut handle = ProtectedPidsHandle::open(bpffs_root).with_context(|| {
        format!(
            "opening PROTECTED_PIDS handle at {} for self-registration",
            bpffs_root.display()
        )
    })?;
    handle
        .insert(own_pid)
        .with_context(|| format!("inserting watchdog PID {own_pid} into PROTECTED_PIDS"))?;
    info!(
        target: "watchdog",
        pid = own_pid,
        bpffs_root = %bpffs_root.display(),
        "watchdog PID registered in PROTECTED_PIDS"
    );
    // External audit EBPF-002: now a protected pid, record this watchdog
    // as the live one — a second watchdog binary started beside it takes
    // no write handle on the agent's maps. The agent records it too once
    // it verifies this pid; a failure here is not fatal.
    if let Err(e) =
        antitamper_bpf::claim_role(bpffs_root, antitamper_bpf::ROLE_SLOT_WATCHDOG, own_pid)
    {
        debug!(target: "watchdog", error = %e, "watchdog role not recorded (the agent records it on verification)");
    }
    Ok(())
}

/// Counterpart of [`register_self_pid`] for a clean shutdown: leave no
/// stale entry behind (the map holds 16 slots).
pub fn unregister_self_pid(bpffs_root: &Path, own_pid: u32) -> Result<()> {
    let mut handle = ProtectedPidsHandle::open(bpffs_root)
        .with_context(|| format!("opening PROTECTED_PIDS handle at {}", bpffs_root.display()))?;
    handle
        .evict(own_pid)
        .with_context(|| format!("evicting watchdog PID {own_pid} from PROTECTED_PIDS"))?;
    Ok(())
}

pub fn reinsert_new_agent_pid(bpffs_root: &Path, new_pid: u32) -> Result<()> {
    let mut handle = ProtectedPidsHandle::open(bpffs_root).with_context(|| {
        format!(
            "opening PROTECTED_PIDS handle at {} for defensive reinsert",
            bpffs_root.display()
        )
    })?;
    handle
        .insert(new_pid)
        .with_context(|| format!("inserting new agent PID {new_pid} into PROTECTED_PIDS"))?;
    info!(
        target: "watchdog.respawn",
        pid = new_pid,
        bpffs_root = %bpffs_root.display(),
        "defensive PROTECTED_PIDS reinsert complete"
    );
    Ok(())
}

/// What the agent's exit means, from the shutdown-authorisation marker
/// (Tappa 8 A7/A8, design §10.4; external audit WDG-001, EVD-021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownVerdict {
    /// No marker: the agent died — respawn it.
    Absent,
    /// A marker that verifies against the admin quorum: stand down.
    Authorised,
    /// A marker that does not (forged, replayed, stale, or the keys or the
    /// install id could not be read): respawn, and report it. The marker
    /// is removed and recorded at [`nn_proto::shutdown_marker::REJECTED_PATH`]
    /// for the agent's signed audit chain.
    Refused(String),
}

/// What [`check_shutdown_marker`] reads.
#[derive(Debug, Clone)]
pub struct ShutdownCheck<'a> {
    /// The marker; the records of refusals and honoured authorisations sit
    /// next to it.
    pub marker: &'a Path,
    /// `admin.pub`: the keys the shutdown must be signed by.
    pub admin_pub: &'a Path,
    /// `agent_id`: the install the shutdown must be signed for.
    pub agent_id_file: &'a Path,
    /// The agent that exited.
    pub agent_pid: u32,
    /// When it started (unix seconds), when known ([`process_start_unix`]).
    pub agent_started: Option<u64>,
}

/// Decide what the agent's exit means. A marker is honoured only when it
/// carries a shutdown signed by the admin quorum for this install, recent,
/// written by the agent that exited, and not honoured before
/// ([`nn_proto::shutdown_marker::verify`]); it was a JSON with a hash and a
/// deadline any root process could write. Every failure is a refusal —
/// the agent is respawned.
pub fn check_shutdown_marker(c: &ShutdownCheck<'_>) -> ShutdownVerdict {
    use nn_proto::shutdown_marker as sm;
    let raw = match std::fs::read(c.marker) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                target: "watchdog.shutdown_marker",
                path = %c.marker.display(),
                "no shutdown-authorisation marker — proceeding with restart"
            );
            return ShutdownVerdict::Absent;
        }
        Err(e) => return refuse(c, &[], format!("reading the marker: {e}")),
    };
    let marker = match sm::ShutdownMarker::parse(&String::from_utf8_lossy(&raw)) {
        Ok(m) => m,
        Err(r) => return refuse(c, &raw, r.to_string()),
    };
    // External audit AUT-004: the agent's key set — a malformed line costs
    // its own key, as in the agent, so both judge the marker with the same
    // keys.
    let keys = match std::fs::read_to_string(c.admin_pub)
        .map(|body| nn_proto::admin_quorum::parse_admin_pub_lenient(&body).keys)
    {
        Ok(k) if !k.is_empty() => k,
        Ok(_) => {
            return refuse(
                c,
                &raw,
                format!("{}: no valid admin key", c.admin_pub.display()),
            )
        }
        Err(e) => return refuse(c, &raw, format!("{}: {e}", c.admin_pub.display())),
    };
    let agent_id = match std::fs::read_to_string(c.agent_id_file)
        .map_err(|e| e.to_string())
        .and_then(|body| sm::parse_agent_id(&body))
    {
        Ok(id) => id,
        Err(e) => return refuse(c, &raw, format!("{}: {e}", c.agent_id_file.display())),
    };
    let honoured_path = c.marker.with_file_name(file_name_of(sm::HONOURED_PATH));
    let honoured = std::fs::read_to_string(&honoured_path).unwrap_or_default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = sm::Expectation {
        keys: &keys,
        agent_id,
        agent_pid: c.agent_pid,
        agent_started: c.agent_started,
        now,
    };
    match sm::verify(&marker, &exp, |nonce| sm::was_honoured(&honoured, nonce)) {
        Ok(auth) => {
            // Recorded before standing down: the same authorisation is
            // refused if it is ever presented again.
            if let Err(e) = append_line(&honoured_path, &sm::honoured_line(&auth)) {
                warn!(
                    target: "watchdog.shutdown_marker",
                    error = %e,
                    path = %honoured_path.display(),
                    "could not record the honoured authorisation; its replay is bounded by the signature's age only"
                );
            }
            let _ = std::fs::remove_file(c.marker);
            info!(
                target: "watchdog.shutdown_marker",
                signed_at = auth.ts,
                signers = auth.signers.len(),
                "admin-authorised shutdown verified against admin.pub — watchdog standing down"
            );
            ShutdownVerdict::Authorised
        }
        Err(r) => refuse(c, &raw, r.to_string()),
    }
}

/// Record a refused marker for the agent and remove it.
fn refuse(c: &ShutdownCheck<'_>, raw: &[u8], reason: String) -> ShutdownVerdict {
    use nn_proto::shutdown_marker as sm;
    let record = sm::RejectedRecord {
        at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        agent_pid: c.agent_pid,
        reason: reason.clone(),
        sha256: sm::marker_sha256(raw),
    };
    let path = c.marker.with_file_name(file_name_of(sm::REJECTED_PATH));
    let line = serde_json::to_string(&record).unwrap_or_default() + "\n";
    if let Err(e) = append_line(&path, &line) {
        warn!(target: "watchdog.shutdown_marker", error = %e, path = %path.display(), "could not record the refused marker");
    }
    let _ = std::fs::remove_file(c.marker);
    ShutdownVerdict::Refused(reason)
}

fn file_name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Append `line` to `path` (created 0600; never through a symlink).
fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_all()
}

/// When `pid` started, in unix seconds: `/proc/<pid>/stat` field 22
/// (clock ticks since boot) over `/proc/stat`'s `btime`. Read while the
/// process runs; `None` when either cannot be read.
pub fn process_start_unix(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesised comm, which may contain spaces.
    let rest = stat.rsplit_once(')')?.1;
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let btime: u64 = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    Some(btime + ticks / hz as u64)
}

/// Helper: emit the "tamper suspected" journal line + escalate.
/// The ceiling is the design §5.1 "5-in-60s" trigger; the
/// watchdog stays alive after this for operator inspection
/// (external audit WDG-004: it holds — [`hold_until_agent_returns`] —
/// instead of exiting) and resumes once the agent is started again.
pub fn log_tamper_suspected(attempts_in_window: u8, window: Duration) {
    error!(
        target: "watchdog.tamper",
        attempts_in_window,
        window_secs = window.as_secs(),
        "TAMPER SUSPECTED: agent restart ceiling tripped ({attempts_in_window} attempts in last {} s) — \
         watchdog stops respawning and holds; after investigating, \
         `systemctl reset-failed northnarrow-agent` then `systemctl start northnarrow-agent`, \
         and the watchdog resumes supervision",
        window.as_secs()
    );
}

// ────────────────────────────────────────────────────────────────────
// Watchdog W5 — STATUS-ping secondary stuck detection +
// stuck-agent SIGINT recovery (design §3.3-4 + §4.1 + §12 row W5)
// ────────────────────────────────────────────────────────────────────

/// Interval between STATUS pings — every 30 s per design §4.
/// Balances detection latency for "stuck" agents against
/// socket-load noise (the agent's own tracing heartbeat fires
/// at 60 s, so 30 s gives ≤ 1-cycle skew detection).
pub const STATUS_PING_INTERVAL: Duration = Duration::from_secs(30);

/// The STATUS-ping ticker. External audit WDG-009: after a stall of the
/// watchdog (VM paused, memory-pressure stall) the default `Burst` fires
/// every missed tick back to back, so "two timeouts 60 s apart" became two
/// pings ~2 s apart. `Delay` fires one late tick and then keeps `period`
/// between ticks.
pub fn ping_ticker(period: Duration) -> tokio::time::Interval {
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick
}

/// Per-ping reply timeout — 2 s per design §4. Conservative cap
/// on healthy reply (the admin socket handler runs on the
/// agent's tokio runtime; under steady state replies are
/// sub-100 ms). 2 s tolerates pathological GC pauses,
/// page-fault storms, brief schedlatency.
pub const STATUS_PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Per §4: two consecutive timeouts in a row promote "stuck"
/// to "dead" and trigger the recovery path. One timeout could
/// be a CPU steal spike or a long pause of the agent; two in a row
/// (60 s gap with the 30 s interval) is strong evidence the
/// agent's main loop is not making progress.
pub const STATUS_PING_CONSECUTIVE_TIMEOUT_THRESHOLD: u8 = 2;

/// Per §4.1 recovery sequence: after SIGINT, wait this long
/// for graceful exit before escalating to evict + SIGKILL.
pub const STUCK_RECOVERY_HARDKILL_GRACE: Duration = Duration::from_secs(5);

/// Outcome of one STATUS-ping tracker tick — pure value for
/// unit testing the timeout state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingOutcome {
    /// Reply received within the timeout window. Counter reset.
    Ok,
    /// First timeout in a row — log WARN, continue (per §4.1
    /// "STATUS reply timeout × 1 only → log WARN, continue").
    TimeoutOnce,
    /// Threshold reached (default 2 consecutive timeouts, or
    /// [`STATUS_PING_VANISHED_STUCK_AFTER`] pings without the agent's
    /// socket after it had answered). Caller should kick off the
    /// stuck-recovery sequence ([`stuck_recovery`]).
    StuckDetected,
    /// Nothing that is the agent listens at the admin socket path, and the
    /// agent has not answered since it started: it never opened the
    /// socket (no admin plane, a slow start). This never feeds the stuck
    /// threshold; `consecutive` counts how many pings in a row saw it so
    /// the caller can escalate the log level without ever SIGINT-ing a
    /// healthy agent.
    SocketAbsent { consecutive: u32 },
    /// External audit WDG-007 (NN-AUD-358): the same, after the agent
    /// answered — its socket was removed or replaced while it ran (a
    /// healthy agent binds it again within
    /// [`AGENT_SOCKET_REBIND_WITHIN`]). Counts toward stuck recovery:
    /// [`STATUS_PING_VANISHED_STUCK_AFTER`] in a row are
    /// [`PingOutcome::StuckDetected`].
    SocketVanished { consecutive: u32 },
    /// Lab PR 216: the agent answered, and its event loop made no round
    /// since the previous ping (`consecutive` pings in a row, the last
    /// round `since_last_ms` before this one). Below
    /// [`STATUS_PING_STALLED_STUCK_AFTER`]: a WARN.
    LoopStalled {
        consecutive: u32,
        since_last_ms: u64,
    },
    /// Lab PR 216: [`STATUS_PING_STALLED_STUCK_AFTER`] answers in a row
    /// with the event loop standing still — recovered like a hang (stuck
    /// recovery), and recorded (`event_loop_stalled`).
    LoopStuck { pings: u32, since_last_ms: u64 },
}

/// Lab PR 216: what the agent reported of its event loop with its STATUS
/// answer ([`ping_agent_status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopProgress {
    /// Not reported: an agent older than the request (it closed the
    /// connection), or not asked. The status answer alone counts.
    Unreported,
    /// The loop has gone round `iterations` times (0: not entered yet, the
    /// agent is starting), the last round `since_last_ms` ago.
    Reported { iterations: u64, since_last_ms: u64 },
}

/// Lab PR 216: answers in a row with the event loop standing still before
/// stuck recovery — three pings 30 s apart, each without a round since the
/// one before, over a loop that goes round at least every 5 s
/// (`PUMP_CHECK_PERIOD`): at least 90 s without a round, eighteen times
/// the loop's idle period, so one slow event is not taken for a hang.
pub const STATUS_PING_STALLED_STUCK_AFTER: u32 = 3;

/// Why a STATUS ping failed, as far as the stuck-recovery policy cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingFailure {
    /// Nothing listens at the path: `connect(2)` → ENOENT (no file, or a
    /// dangling link), ECONNREFUSED (a socket nobody listens on, or a
    /// file or directory at the path), ENOTDIR. Not a hang — whether it
    /// is a misconfiguration or a removal depends on whether the agent
    /// answered before ([`StatusPingTracker::record_socket_absent`]).
    SocketAbsent,
    /// Something answered that is not the agent the watchdog supervises
    /// (external audit WDG-007: the peer's `SO_PEERCRED` pid; a process
    /// that binds the path after removing the agent's socket can answer
    /// STATUS itself). Handled like [`PingFailure::SocketAbsent`].
    NotTheAgent,
    /// Anything else: connect reset, protocol error, or the 2 s timeout —
    /// the agent is there but not answering.
    Unresponsive,
}

/// The STATUS answer came from a process other than the agent
/// ([`ping_agent_status`] with an expected pid).
#[derive(Debug)]
pub struct NotTheAgent {
    /// The peer's pid as the kernel recorded it at `listen(2)`.
    pub peer_pid: Option<i32>,
    /// The agent the watchdog supervises.
    pub agent_pid: u32,
}

impl std::fmt::Display for NotTheAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.peer_pid {
            Some(p) => write!(
                f,
                "the admin socket is served by pid {p}, not by the agent (pid {})",
                self.agent_pid
            ),
            None => write!(
                f,
                "the admin socket's server has no pid in this namespace (agent pid {})",
                self.agent_pid
            ),
        }
    }
}

impl std::error::Error for NotTheAgent {}

/// Classify a [`ping_agent_status`] error by walking its source chain.
pub fn classify_ping_error(e: &anyhow::Error) -> PingFailure {
    if e.chain().any(|c| c.downcast_ref::<NotTheAgent>().is_some()) {
        return PingFailure::NotTheAgent;
    }
    let nothing_listens = e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .map(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) || io.raw_os_error() == Some(libc::ENOTDIR)
            })
            .unwrap_or(false)
    });
    if nothing_listens {
        PingFailure::SocketAbsent
    } else {
        PingFailure::Unresponsive
    }
}

/// After this many consecutive absent-socket pings (30 s apart) the
/// ping loop raises its log line to ERROR: the agent has been up for
/// minutes without ever opening its admin socket.
pub const STATUS_PING_ABSENT_ERROR_AFTER: u32 = 4;

/// External audit WDG-007: how long a healthy agent takes at most to bind
/// its admin socket again after it was removed (the agent checks its path
/// every 10 s, `admin_socket::SOCKET_CHECK_EVERY`). Documentation of the
/// thresholds below; the watchdog does not wait on it.
pub const AGENT_SOCKET_REBIND_WITHIN: Duration = Duration::from_secs(10);

/// External audit WDG-007: a vanished socket on this many pings in a row
/// (≥ 30 s without the socket, three times
/// [`AGENT_SOCKET_REBIND_WITHIN`]) is reported as tamper — an ERROR on
/// `watchdog.tamper` and a record the agent signs
/// ([`nn_proto::watchdog_hold::REASON_ADMIN_SOCKET_VANISHED`]). Not on the
/// first: a ping can land between the agent's clean unlink at shutdown and
/// its exit, or inside the rebind window.
pub const STATUS_PING_VANISHED_TAMPER_AFTER: u32 = 2;

/// External audit WDG-007: a vanished socket on this many pings in a row
/// (≥ 60 s without the socket an agent rebinds within 10 s) is a stuck
/// agent: a frozen one cannot bind it again, and its STATUS ping —
/// what recovers a frozen agent — would otherwise never fail again.
pub const STATUS_PING_VANISHED_STUCK_AFTER: u32 = 3;

/// Sliding-counter state machine that tracks consecutive
/// STATUS-ping timeouts. Reset on any successful ping. Threshold
/// configurable for tests so we don't have to hardcode 2 in
/// every assertion.
///
/// External audit WDG-007 (NN-AUD-358): it also remembers whether the
/// agent it watches answered once. A socket that never came up is a
/// misconfiguration ([`PingOutcome::SocketAbsent`], never stuck — the
/// 2026-10-08 restart loop); a socket that left after the agent answered
/// is [`PingOutcome::SocketVanished`] and feeds stuck recovery. Root could
/// `rm` the socket (`/run/northnarrow` is outside the inode deny set) and
/// freeze the agent's cgroup: the watchdog read "never came up" and
/// recovered nothing.
#[derive(Debug, Clone)]
pub struct StatusPingTracker {
    consecutive_timeouts: u8,
    threshold: u8,
    consecutive_absent: u32,
    /// The agent watched answered a STATUS ping at least once.
    answered: bool,
    consecutive_vanished: u32,
    vanished_threshold: u32,
    /// Lab PR 216: the loop's round count at the last answer that reported
    /// one (`None` before, or while the loop was not entered).
    last_iterations: Option<u64>,
    consecutive_stalls: u32,
    stall_threshold: u32,
}

impl StatusPingTracker {
    /// Production constructor — threshold = 2 per design §4.
    pub fn new() -> Self {
        Self::with_threshold(STATUS_PING_CONSECUTIVE_TIMEOUT_THRESHOLD)
    }

    /// Test-friendly knob (and forward-compat for a future
    /// hardening tappa that tightens the threshold to 1).
    pub fn with_threshold(threshold: u8) -> Self {
        Self {
            consecutive_timeouts: 0,
            threshold,
            consecutive_absent: 0,
            answered: false,
            consecutive_vanished: 0,
            vanished_threshold: STATUS_PING_VANISHED_STUCK_AFTER,
            last_iterations: None,
            consecutive_stalls: 0,
            stall_threshold: STATUS_PING_STALLED_STUCK_AFTER,
        }
    }

    /// Record a successful ping. Resets the counters and remembers that
    /// this agent answered; returns [`PingOutcome::Ok`].
    pub fn record_ok(&mut self) -> PingOutcome {
        self.consecutive_timeouts = 0;
        self.consecutive_absent = 0;
        self.consecutive_vanished = 0;
        self.answered = true;
        PingOutcome::Ok
    }

    /// Nothing that is the agent listens at the path. Before the agent
    /// ever answered this does NOT touch the stuck counters: an agent that
    /// never opened its admin socket is misconfigured, not hung, and
    /// SIGINT-ing it only produces a restart loop (seen on the lab guest
    /// with a missing combat-rules.v4, 2026-10-08). After it answered, the
    /// socket was taken away while it ran (external audit WDG-007):
    /// [`PingOutcome::SocketVanished`], and
    /// [`STATUS_PING_VANISHED_STUCK_AFTER`] in a row are
    /// [`PingOutcome::StuckDetected`].
    pub fn record_socket_absent(&mut self) -> PingOutcome {
        if !self.answered {
            self.consecutive_absent = self.consecutive_absent.saturating_add(1);
            return PingOutcome::SocketAbsent {
                consecutive: self.consecutive_absent,
            };
        }
        self.consecutive_vanished = self.consecutive_vanished.saturating_add(1);
        if self.consecutive_vanished >= self.vanished_threshold {
            PingOutcome::StuckDetected
        } else {
            PingOutcome::SocketVanished {
                consecutive: self.consecutive_vanished,
            }
        }
    }

    /// Record a ping failure (reply timeout OR transport error
    /// — both are "agent not responding" from the watchdog's
    /// perspective). Returns [`PingOutcome::TimeoutOnce`] for
    /// the first failure in a row, [`PingOutcome::StuckDetected`]
    /// when the threshold is met.
    pub fn record_timeout(&mut self) -> PingOutcome {
        self.consecutive_absent = 0;
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
        if self.consecutive_timeouts >= self.threshold {
            PingOutcome::StuckDetected
        } else {
            PingOutcome::TimeoutOnce
        }
    }

    /// Reset the tracker for a new agent, or after a stuck signal so the
    /// respawned agent gets a fresh ping budget: the counters, and whether
    /// the agent answered (external audit WDG-007: the next agent has to
    /// answer before its socket can "vanish").
    pub fn reset(&mut self) {
        self.consecutive_timeouts = 0;
        self.consecutive_absent = 0;
        self.consecutive_vanished = 0;
        self.answered = false;
        self.last_iterations = None;
        self.consecutive_stalls = 0;
    }

    /// Lab PR 216 (static review C-44 / TD-08): a STATUS answer, with what
    /// the agent reported of its event loop. The answer resets the
    /// timeout, absent and vanished counters as [`Self::record_ok`] does;
    /// the loop's round count must also have moved since the previous
    /// answer that reported one. A count that stands still is
    /// [`PingOutcome::LoopStalled`], and [`STATUS_PING_STALLED_STUCK_AFTER`]
    /// in a row [`PingOutcome::LoopStuck`] — even though the socket
    /// answers. Not reported (an older agent) or 0 (the loop not entered
    /// yet, the agent starting) is an answer like before.
    pub fn record_answer(&mut self, progress: LoopProgress) -> PingOutcome {
        let ok = self.record_ok();
        let (iterations, since_last_ms) = match progress {
            LoopProgress::Reported {
                iterations,
                since_last_ms,
            } if iterations > 0 => (iterations, since_last_ms),
            _ => {
                self.last_iterations = None;
                self.consecutive_stalls = 0;
                return ok;
            }
        };
        if self.last_iterations.replace(iterations) != Some(iterations) {
            self.consecutive_stalls = 0;
            return ok;
        }
        self.consecutive_stalls = self.consecutive_stalls.saturating_add(1);
        if self.consecutive_stalls >= self.stall_threshold {
            PingOutcome::LoopStuck {
                pings: self.consecutive_stalls,
                since_last_ms,
            }
        } else {
            PingOutcome::LoopStalled {
                consecutive: self.consecutive_stalls,
                since_last_ms,
            }
        }
    }

    /// Snapshot of the consecutive-timeout counter. Used by log
    /// lines + tests.
    pub fn consecutive_timeouts(&self) -> u8 {
        self.consecutive_timeouts
    }

    /// The agent watched answered since its start (or the last
    /// [`Self::reset`]).
    pub fn answered(&self) -> bool {
        self.answered
    }
}

impl Default for StatusPingTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Send one STATUS frame over the agent's admin socket and
/// await the reply. Returns `Ok(())` on a well-formed
/// [`AdminMessage::StatusResponse`]; returns `Err` on any of:
/// - socket connect failure (agent down / restart in progress)
/// - frame write timeout
/// - reply read timeout (the design's "STATUS reply timeout"
///   case — what triggers the `record_timeout` call)
/// - decode failure
///
/// Per design §3.3 the watchdog inspects only **reply latency**,
/// not contents. The match against `StatusResponse` is purely
/// for protocol-shape validation — content fields are ignored.
///
/// External audit ASK-009 (lab PR 213): the reply is read only as far as
/// its variant and its two leading fields
/// ([`decode_status_liveness`]), so the ping does not depend on the fields
/// appended to the status reply: a watchdog newer than the agent no longer
/// fails on an older agent's reply (postcard has no field count, so the
/// full decode did), and the agent withholding its telemetry from the
/// unsigned reply changes nothing here. The request stays the unsigned
/// `Status`.
///
/// External audit WDG-007: with `agent_pid`, the server must be that
/// process (`SO_PEERCRED`, recorded by the kernel when the server called
/// `listen(2)`); any other server is a [`NotTheAgent`] error before a
/// byte is sent. A root process that removed the agent's socket could
/// otherwise bind its own and answer for a frozen agent.
///
/// Lab PR 216 (static review C-44 / TD-08): the status reply proves that
/// the admin socket's task answers, which runs beside the event loop. On the
/// same connection the ping then asks for the event loop's progress
/// (`LoopProgress`, unsigned): the agent's reply is the round count the
/// tracker compares from ping to ping ([`StatusPingTracker::record_answer`]).
/// An agent older than the request closes the connection
/// ([`LoopProgress::Unreported`], the status answer alone counts); with
/// `ask_progress` false (an agent seen not to know it) it is not asked.
pub async fn ping_agent_status(
    socket_path: &Path,
    timeout: Duration,
    agent_pid: Option<u32>,
) -> Result<LoopProgress> {
    ping_agent(socket_path, timeout, agent_pid, true).await
}

/// [`ping_agent_status`], asking for the loop progress or not.
pub async fn ping_agent(
    socket_path: &Path,
    timeout: Duration,
    agent_pid: Option<u32>,
    ask_progress: bool,
) -> Result<LoopProgress> {
    let fut = async {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("connect {}", socket_path.display()))?;
        if let Some(agent_pid) = agent_pid {
            let peer_pid = stream
                .peer_cred()
                .context("SO_PEERCRED on the admin socket")?
                .pid();
            if peer_pid != Some(agent_pid as i32) {
                return Err(anyhow::Error::new(NotTheAgent {
                    peer_pid,
                    agent_pid,
                }));
            }
        }

        let req = AdminMessage::Status(StatusRequest {});
        let bytes = encode_frame(&req).map_err(|e| anyhow!("encode_frame: {e}"))?;
        stream
            .write_all(&bytes)
            .await
            .context("writing STATUS request frame")?;

        // Read length-prefixed reply frame: 4-byte big-endian
        // length + body. Length cap mirrors the agent-side
        // MAX_FRAME_BODY so a malicious peer can't ask us to
        // allocate gigabytes.
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .context("reading reply frame header")?;
        let body_len = u32::from_be_bytes(header) as usize;
        if body_len > MAX_FRAME_BODY {
            return Err(anyhow!(
                "reply body length {body_len} exceeds MAX_FRAME_BODY {MAX_FRAME_BODY}"
            ));
        }
        let mut body = vec![0u8; body_len];
        stream
            .read_exact(&mut body)
            .await
            .context("reading reply frame body")?;

        decode_status_liveness(&body).map_err(|e| anyhow!("STATUS reply: {e}"))?;
        if !ask_progress {
            return Ok::<LoopProgress, anyhow::Error>(LoopProgress::Unreported);
        }
        let req = AdminMessage::LoopProgress(LoopProgressRequest {});
        let bytes = encode_frame(&req).map_err(|e| anyhow!("encode_frame: {e}"))?;
        if stream.write_all(&bytes).await.is_err() {
            // closed after the status reply: an agent without the request
            return Ok(LoopProgress::Unreported);
        }
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(LoopProgress::Unreported)
            }
            Err(e) => return Err(e).context("reading the loop progress reply header"),
        }
        let body_len = u32::from_be_bytes(header) as usize;
        if body_len > MAX_FRAME_BODY {
            return Err(anyhow!(
                "loop progress reply length {body_len} exceeds MAX_FRAME_BODY {MAX_FRAME_BODY}"
            ));
        }
        let mut body = vec![0u8; body_len];
        stream
            .read_exact(&mut body)
            .await
            .context("reading the loop progress reply body")?;
        let p = decode_loop_progress(&body).map_err(|e| anyhow!("loop progress reply: {e}"))?;
        Ok(LoopProgress::Reported {
            iterations: p.iterations,
            since_last_ms: p.since_last_ms,
        })
    };

    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(progress)) => Ok(progress),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Err(anyhow!(
            "STATUS ping timed out after {:?} (socket {})",
            timeout,
            socket_path.display()
        )),
    }
}

/// Lab PR 216: how long stuck recovery waits for the kernel to report the
/// agent's exit after its SIGKILL. A task in uninterruptible sleep dies
/// only when it leaves it; the wait was unbounded, and it ran inside the
/// restart loop's select arm, where neither SIGTERM nor the pidfd were
/// heard meanwhile.
pub const STUCK_RECOVERY_REAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Stuck-agent recovery sequence per design §4.1:
///
/// 1. SIGINT through the pidfd: a graceful stop for the agent.
///    The task_kill hook lets it through because the watchdog
///    is itself in `PROTECTED_PIDS` (since `task-kill-signals-1`
///    every other sender is refused, root included).
/// 2. Wait `hardkill_grace` OR pidfd POLLIN, whichever first.
///    POLLIN → agent died gracefully, restart path takes over.
///    Timeout → agent is wedged past SIGINT response; escalate.
/// 3. SIGKILL through the pidfd.
/// 4. Wait for pidfd POLLIN — the kernel reaps the agent — at most
///    [`STUCK_RECOVERY_REAP_TIMEOUT`].
/// 5. Only then, the exit confirmed, evict its pid from
///    `PROTECTED_PIDS` (the pid may be reused).
///
/// Lab PR 216 (static review C-44 / G-05): the eviction came before the
/// SIGKILL ("best effort ... the worst case is the kernel rejects the
/// kill"), and the caller treated every failure as a death — evict, remove
/// the pidfile, respawn — so a recovery refused with EPERM, or a SIGKILL
/// that did not end the agent, left a live agent without its
/// `PROTECTED_PIDS` entry, which the agent writes only at its start. Now
/// nothing is evicted before the exit is confirmed: the task_kill hook
/// lets the watchdog's SIGKILL through for the reason it lets its SIGINT
/// through (the watchdog is a protected pid; if it is not, the SIGINT is
/// refused first and nothing is sent). An `Err` leaves the agent as it
/// was, and the caller decides on its own pidfd ([`stuck_verdict`]).
///
/// Returns Ok when the agent is confirmed dead (pidfd POLLIN
/// observed) so the W4 caller's restart loop can proceed
/// directly to backoff + spawn. Opens its own fresh pidfd
/// inside (cheap; kernel ref-counts the task struct) so the
/// W4 main loop's `OwnedFd` ownership stays clean.
pub async fn stuck_recovery(
    agent_pid: u32,
    bpffs_root: &Path,
    hardkill_grace: Duration,
    agent_bin: &Path,
) -> Result<()> {
    stuck_recovery_with(
        agent_pid,
        bpffs_root,
        hardkill_grace,
        STUCK_RECOVERY_REAP_TIMEOUT,
        agent_bin,
    )
    .await
}

/// [`stuck_recovery`] with its reap timeout (tests).
pub async fn stuck_recovery_with(
    agent_pid: u32,
    bpffs_root: &Path,
    hardkill_grace: Duration,
    reap_timeout: Duration,
    agent_bin: &Path,
) -> Result<()> {
    // External audit WDG-003: signal only a process verified to run the
    // agent binary, and only through its pidfd — never a pid that a dead
    // agent left behind for another process to reuse.
    let owned = open_verified_pidfd(agent_pid, agent_bin)
        .with_context(|| format!("stuck recovery: pid {agent_pid} is not the agent"))?;
    if pidfd_exited(&owned) {
        info!(
            target: "watchdog.stuck_recovery",
            agent_pid,
            "agent already exited — restart path takes over"
        );
        return Ok(());
    }
    // SAFETY: the `AsyncFd` takes `owned`, the pidfd, and keeps it open
    // and unchanged until it is dropped (tokio#8587).
    let async_fd = unsafe { AsyncFd::register_with_interest(owned, Interest::READABLE) }
        .map_err(std::io::Error::from)
        .context("registering pidfd with AsyncFd for stuck recovery")?;

    // 1. SIGINT.
    info!(
        target: "watchdog.stuck_recovery",
        agent_pid,
        "stuck recovery: sending SIGINT (hook-passing graceful stop)"
    );
    pidfd_signal(async_fd.get_ref().as_raw_fd(), libc::SIGINT)
        .with_context(|| format!("pidfd_send_signal(SIGINT, pid={agent_pid})"))?;

    // 2. Wait grace OR pidfd POLLIN.
    let gracefully_dead = tokio::select! {
        guard = async_fd.readable() => {
            // POLLIN observed — agent died after SIGINT.
            drop(guard);
            true
        }
        _ = tokio::time::sleep(hardkill_grace) => false,
    };

    if gracefully_dead {
        info!(
            target: "watchdog.stuck_recovery",
            agent_pid,
            "agent died gracefully after SIGINT — restart path takes over"
        );
        return Ok(());
    }

    // 3. Escalate: SIGKILL, the agent still in PROTECTED_PIDS.
    warn!(
        target: "watchdog.stuck_recovery",
        agent_pid,
        grace_secs = hardkill_grace.as_secs(),
        "agent did not exit within grace — escalating to SIGKILL"
    );
    pidfd_signal(async_fd.get_ref().as_raw_fd(), libc::SIGKILL).with_context(|| {
        format!("pidfd_send_signal(SIGKILL, pid={agent_pid}); the agent keeps its protection")
    })?;

    // 4. Wait for the kernel reap, bounded.
    match tokio::time::timeout(reap_timeout, async_fd.readable()).await {
        Ok(Ok(guard)) => drop(guard),
        Ok(Err(e)) => {
            return Err(anyhow::Error::from(e))
                .context("awaiting post-SIGKILL pidfd POLLIN; the agent keeps its protection")
        }
        Err(_) => {
            return Err(anyhow!(
                "agent pid {agent_pid} has not exited {} s after SIGKILL (uninterruptible \
                 sleep?); it keeps its protection and stays supervised",
                reap_timeout.as_secs()
            ))
        }
    }

    // 5. The exit is confirmed: its pid leaves PROTECTED_PIDS.
    if let Err(e) = ProtectedPidsHandle::open(bpffs_root).and_then(|mut h| h.evict(agent_pid)) {
        warn!(
            target: "watchdog.stuck_recovery",
            error = %e,
            agent_pid,
            bpffs_root = %bpffs_root.display(),
            "PROTECTED_PIDS evict after the confirmed exit failed (the restart path retries it)"
        );
    }
    info!(
        target: "watchdog.stuck_recovery",
        agent_pid,
        "agent hard-killed (exit confirmed), then evicted — restart path takes over"
    );
    Ok(())
}

/// Lab PR 216: what the restart loop makes of a stuck recovery, from the
/// agent's own pidfd — never from the recovery's result alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckVerdict {
    /// The pidfd is readable: the agent exited. Evict, check the shutdown
    /// marker, respawn.
    Exited,
    /// The agent still runs: the recovery failed before or after its
    /// signals. It keeps its `PROTECTED_PIDS` entry and its pidfile, the
    /// watchdog keeps watching its pidfd, the failure is recorded
    /// ([`stuck_recovery_failed_record`]) and the next stuck signal
    /// tries again.
    StillRunning,
}

/// [`StuckVerdict`] of the agent behind `agent_pidfd`.
pub fn stuck_verdict(agent_pidfd: &OwnedFd) -> StuckVerdict {
    if pidfd_exited(agent_pidfd) {
        StuckVerdict::Exited
    } else {
        StuckVerdict::StillRunning
    }
}

/// The [`nn_proto::watchdog_hold::REASON_STUCK_RECOVERY_FAILED`] record.
pub fn stuck_recovery_failed_record(
    agent_pid: u32,
    error: &str,
    at: u64,
) -> nn_proto::watchdog_hold::HoldRecord {
    nn_proto::watchdog_hold::HoldRecord {
        at,
        agent_pid,
        reason: nn_proto::watchdog_hold::REASON_STUCK_RECOVERY_FAILED.to_string(),
        detail: format!(
            "the agent did not answer (or its event loop stood still) and could not be stopped: \
             {} — still protected, its pidfile kept, still supervised",
            bounded(error, 300)
        ),
        unit_state: None,
    }
}

/// The [`nn_proto::watchdog_hold::REASON_EVENT_LOOP_STALLED`] record:
/// `pings` STATUS pings in a row answered while the event loop stood still,
/// its last round `since_last_ms` before the last of them.
pub fn event_loop_stalled_record(
    agent_pid: u32,
    pings: u32,
    since_last_ms: u64,
    at: u64,
) -> nn_proto::watchdog_hold::HoldRecord {
    nn_proto::watchdog_hold::HoldRecord {
        at,
        agent_pid,
        reason: nn_proto::watchdog_hold::REASON_EVENT_LOOP_STALLED.to_string(),
        detail: format!(
            "the admin socket answered {pings} STATUS pings in a row while the event loop made \
             no round (the last one {} s before); stuck recovery follows",
            since_last_ms / 1000
        ),
        unit_state: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::TempDir;

    /// Required W2 test 1 — CLI parse. Asserts every flag the
    /// systemd unit file binds (design §10.2) can be parsed
    /// AND that omitting all flags yields the canonical default
    /// paths.
    #[test]
    fn cli_parses_with_defaults_and_overrides() {
        // Defaults.
        let cli = Cli::try_parse_from(["northnarrow-watchdog"]).expect("defaults");
        assert_eq!(cli.agent_pidfile, PathBuf::from(DEFAULT_AGENT_PIDFILE));
        assert_eq!(cli.admin_socket, PathBuf::from(DEFAULT_ADMIN_SOCKET));
        assert_eq!(cli.pidfile, PathBuf::from(DEFAULT_WATCHDOG_PIDFILE));
        assert_eq!(cli.bpffs_root, PathBuf::from(DEFAULT_BPFFS_ROOT));

        // Overrides — exactly the systemd unit's ExecStart shape.
        let cli = Cli::try_parse_from([
            "northnarrow-watchdog",
            "--agent-pidfile",
            "/tmp/a.pid",
            "--admin-socket",
            "/tmp/a.sock",
            "--pidfile",
            "/tmp/w.pid",
            "--bpffs-root",
            "/sys/fs/bpf/nn",
        ])
        .expect("overrides");
        assert_eq!(cli.agent_pidfile, PathBuf::from("/tmp/a.pid"));
        assert_eq!(cli.admin_socket, PathBuf::from("/tmp/a.sock"));
        assert_eq!(cli.pidfile, PathBuf::from("/tmp/w.pid"));
        assert_eq!(cli.bpffs_root, PathBuf::from("/sys/fs/bpf/nn"));
    }

    /// Required W2 test 2 — `prctl` noop under cfg(test). The
    /// real prctls only fire in production builds; under tests
    /// `harden_self` returns Ok without touching the kernel.
    /// Anchors the test-mode contract called out in
    /// `harden_self`'s doc-comment.
    #[test]
    fn harden_self_is_noop_under_cfg_test() {
        for _ in 0..3 {
            // Idempotent: callable any number of times in tests.
            harden_self().expect("noop must return Ok");
        }
    }

    /// Required W2 test 3 — pidfd-open retry behaviour. Uses a
    /// pidfile pointing at a guaranteed-dead PID (u32::MAX, far
    /// above Linux's `pid_max`), runs with a short deadline,
    /// asserts the loop terminates with a contextual error.
    /// Exercises both the retry budget and the final-error
    /// reporting shape.
    #[tokio::test]
    async fn open_agent_pidfd_with_retry_terminates_on_known_bad_pid() {
        let dir = TempDir::new().unwrap();
        let pidfile = dir.path().join("agent.pid");
        std::fs::write(&pidfile, format!("{}\n", u32::MAX)).unwrap();

        let started = Instant::now();
        let result = open_agent_pidfd_with_retry(
            &pidfile,
            // Short deadline so the test runs in <300 ms.
            Duration::from_millis(150),
            Path::new("/bin/sleep"),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(
            result.is_err(),
            "u32::MAX is above Linux pid_max — pidfd_open must always ESRCH"
        );
        let err = result.unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("pidfd_open") || chain.contains("opening pidfd"),
            "error chain should reference pidfd_open, got: {chain}"
        );
        assert!(
            elapsed >= Duration::from_millis(140),
            "retry loop must honour deadline, elapsed: {elapsed:?}"
        );
    }

    // ── Supplementary unit tests (W2 hardening anchors) ────────────

    /// Pidfile parser tolerates the canonical `<pid>\n` shape AND
    /// rejects garbage. Anchors the read_pid_from_file contract.
    #[test]
    fn read_pid_from_file_round_trips_and_rejects_garbage() {
        let dir = TempDir::new().unwrap();

        // Canonical: trailing newline tolerated.
        let p = dir.path().join("ok.pid");
        std::fs::write(&p, "1234\n").unwrap();
        assert_eq!(read_pid_from_file(&p).unwrap(), 1234);

        // No trailing newline still works.
        let p = dir.path().join("ok2.pid");
        std::fs::write(&p, "9999").unwrap();
        assert_eq!(read_pid_from_file(&p).unwrap(), 9999);

        // Garbage rejected.
        let p = dir.path().join("bad.pid");
        std::fs::write(&p, "not a pid\n").unwrap();
        assert!(read_pid_from_file(&p).is_err());

        // Missing file rejected.
        let p = dir.path().join("missing.pid");
        assert!(read_pid_from_file(&p).is_err());
    }

    /// Atomic pidfile write round-trip — write a PID, read it
    /// back, verify content. Plus assert no `.tmp` leftover.
    #[test]
    fn write_pidfile_atomic_round_trip_and_cleans_up_tmp() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("watchdog.pid");
        write_pidfile_atomic(&p, 12345).unwrap();

        let read = read_pid_from_file(&p).unwrap();
        assert_eq!(read, 12345);

        for tmp in ["watchdog.pid.tmp", ".watchdog.pid.tmp"] {
            let tmp = dir.path().join(tmp);
            assert!(
                !tmp.exists(),
                "atomic write must clean up its temporary file: {}",
                tmp.display()
            );
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    /// External audit WDG-015 (NN-AUD-364): a link planted at the temporary
    /// name (the old `watchdog.pid.tmp` and the new `.watchdog.pid.tmp`) is
    /// replaced, never written through.
    #[test]
    fn write_pidfile_atomic_replaces_a_planted_link() {
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("audit.log");
        std::fs::write(&victim, "CHAIN").unwrap();
        for name in ["watchdog.pid.tmp", ".watchdog.pid.tmp"] {
            std::os::unix::fs::symlink(&victim, dir.path().join(name)).unwrap();
        }
        let p = dir.path().join("watchdog.pid");
        write_pidfile_atomic(&p, 4242).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "CHAIN");
        assert_eq!(read_pid_from_file(&p).unwrap(), 4242);
        assert!(std::fs::symlink_metadata(&p).unwrap().file_type().is_file());
    }

    /// sd_notify_ready is a no-op when NOTIFY_SOCKET is unset
    /// (the common dev-shell case). Anchors the "not under
    /// systemd is not an error" contract.
    /// `NOTIFY_SOCKET` is process-global: the sd_notify tests take turns.
    static NOTIFY_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// External audit MAIN-016: under an abstract `NOTIFY_SOCKET`
    /// (`@name`), `READY=1` and `STATUS=` arrive; a socket nobody listens
    /// on makes `sd_notify_ready` fail, not succeed.
    #[test]
    fn sd_notify_reaches_an_abstract_notify_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let _env = NOTIFY_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let name = format!("nn-watchdog-notify-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&addr).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // SAFETY: the tests that touch NOTIFY_SOCKET hold NOTIFY_ENV; no
        // other test of this crate reads it.
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", format!("@{name}"));
        }
        let ready = sd_notify_ready();
        sd_notify_status("supervising agent pid 42");
        let mut buf = [0u8; 128];
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(listener.recv(&mut buf).map(|n| buf[..n].to_vec()));
        }
        // Lab PR 258: shut down before it is closed. A child another test
        // spawns gets a copy of every descriptor of the process, the
        // listener's too, and holds it until its exec (`CLOEXEC`): closed
        // in that window, the socket lived on and took the datagram — the
        // flake of the crate's tests under load. Shut down, it takes none,
        // whoever holds a descriptor of it.
        listener.shutdown(std::net::Shutdown::Both).unwrap();
        drop(listener);
        let refused = sd_notify_ready();
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
        ready.expect("READY=1 sent");
        let got: Vec<Vec<u8>> = got.into_iter().map(|r| r.expect("a datagram")).collect();
        assert_eq!(got[0], b"READY=1\n");
        assert_eq!(got[1], b"STATUS=supervising agent pid 42\n");
        assert!(refused.is_err(), "nobody listens any more");
    }

    #[test]
    fn sd_notify_ready_is_ok_when_notify_socket_unset() {
        let _env = NOTIFY_ENV.lock().unwrap_or_else(|e| e.into_inner());
        // Test runs outside systemd; NOTIFY_SOCKET is unset.
        // Defensively unset in case CI sets it for the test
        // binary itself — the public API contract is "Ok when
        // env var absent", so explicitly removing first matches
        // production behaviour.
        // SAFETY: env var manipulation in tests is the canonical
        // way to exercise the unset path; no other thread reads
        // NOTIFY_SOCKET here.
        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
        sd_notify_ready().expect("must be Ok when NOTIFY_SOCKET unset");
    }

    // ── Watchdog W3: pidfd-driven death + layer-2 evict ────────────
    //
    // Full kernel-level POLLIN behaviour requires a live BPF
    // env (handled by the future W8 privileged e2e). The unit
    // tests below cover everything testable WITHOUT root:
    // - pidfd_open on a real Linux process (caller's own child
    //   — no special perms required)
    // - tokio AsyncFd registration + readable() wakeup on real
    //   SIGKILL-ing the child
    // - latency budget under normal load
    // - evict_dead_agent error paths (no BPF env → opens fails)
    // - EvictReport shape

    /// Helper: spawn a long-sleeping child subprocess, pidfd_open
    /// it, return both the OwnedFd and the child for the test to
    /// reap. `sleep 60` is the simplest portable POSIX way to get
    /// a quiet long-running child.
    fn spawn_sleep_child_and_open_pidfd() -> (std::process::Child, OwnedFd) {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawning `sleep 60` must succeed on any Linux test host");
        let raw = pidfd_open(child.id())
            .expect("pidfd_open on caller's own child must succeed without CAP_*");
        // SAFETY: pidfd_open returned this fd to us; we own it.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        (child, owned)
    }

    /// External audit WDG-004: a holding watchdog resumes when an agent
    /// runs again, and only then.
    #[tokio::test]
    async fn hold_resumes_when_an_agent_runs_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let pidfile = dir.path().join("agent.pid");
        // External audit WDG-004: no agent → the hold lasts until told
        // to stop.
        let agent_bin = Path::new("/bin/sleep");
        let out = hold_until_agent_returns(
            &pidfile,
            Duration::from_millis(20),
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                "SIGTERM"
            },
            agent_bin,
        )
        .await;
        assert!(matches!(out, HoldOutcome::Shutdown("SIGTERM")));
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        std::fs::write(&pidfile, format!("{}\n", child.id())).unwrap();
        // External audit WDG-003: a live pid that runs another program is
        // not the agent coming back.
        let out = hold_until_agent_returns(
            &pidfile,
            Duration::from_millis(20),
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                "SIGTERM"
            },
            Path::new("/bin/true"),
        )
        .await;
        assert!(matches!(out, HoldOutcome::Shutdown("SIGTERM")));
        // An agent started again (its pidfile names a live pid running the
        // agent binary) ends it.
        let out = hold_until_agent_returns(
            &pidfile,
            Duration::from_millis(20),
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                "SIGTERM"
            },
            agent_bin,
        )
        .await;
        let _ = child.kill();
        let _ = child.wait();
        match out {
            HoldOutcome::Resumed { pid, .. } => assert_eq!(pid, child.id()),
            HoldOutcome::Shutdown(s) => panic!("expected a resume, got shutdown by {s}"),
        }
    }

    /// Required W3 test 1: AsyncFd registration + POLLIN wakeup
    /// on real child death. Spawns `sleep 60`, opens pidfd,
    /// schedules a SIGKILL after a short delay, and asserts
    /// `wait_for_agent_death` returns within a generous budget.
    /// Anchors the load-bearing W3 mechanic.
    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_agent_death_returns_on_child_exit() {
        let (mut child, pidfd) = spawn_sleep_child_and_open_pidfd();
        let child_pid = child.id();

        // Schedule the kill in the background so the await is
        // already parked when SIGKILL fires.
        let killer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            // SAFETY: SIGKILL on a known PID is a trivial syscall;
            // we own the child so this is unambiguous.
            let r = unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGKILL) };
            assert_eq!(
                r,
                0,
                "kill(child, SIGKILL) must succeed: {}",
                std::io::Error::last_os_error()
            );
        });

        let start = Instant::now();
        wait_for_agent_death(&pidfd)
            .await
            .expect("pidfd POLLIN must fire on child death");
        let elapsed = start.elapsed();
        // Generous bound — typical wakeup is sub-millisecond on
        // a quiet host but CI can be slow. 2 s rules out any
        // notion of the await silently never returning.
        assert!(
            elapsed < Duration::from_secs(2),
            "wakeup latency too high: {elapsed:?}"
        );

        killer.await.expect("killer task");
        // Reap the zombie.
        let _ = child.wait();
    }

    /// Required W3 test 2: AsyncFd readable() on an
    /// already-dead-and-reaped child returns immediately. pidfd
    /// signals POLLIN persistently once the task is gone, so a
    /// late-binding watchdog (started after agent already died)
    /// still sees the wakeup.
    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_agent_death_returns_immediately_for_already_dead_child() {
        let (mut child, pidfd) = spawn_sleep_child_and_open_pidfd();
        let child_pid = child.id();

        // Kill + reap FIRST, then await. This is the "watchdog
        // started after agent died" race the design considers
        // safe because pidfd POLLIN is persistent.
        unsafe {
            libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
        }
        let _ = child.wait();

        let start = Instant::now();
        wait_for_agent_death(&pidfd)
            .await
            .expect("POLLIN on already-dead child must still fire");
        let elapsed = start.elapsed();
        // Should be near-instant — kernel already has POLLIN
        // set on the pidfd by the time we register AsyncFd.
        assert!(
            elapsed < Duration::from_millis(500),
            "POLLIN on already-dead pidfd should be near-instant: {elapsed:?}"
        );
    }

    /// Required W3 test 3: `evict_dead_agent` surfaces a clear
    /// error when the bpffs root is unavailable (e.g., the host
    /// has no `bpf` in lsm= chain so the agent never pinned
    /// PROTECTED_PIDS). Error chain mentions both the operation
    /// (layer-2 evict) AND the path it tried.
    #[test]
    fn evict_dead_agent_fails_when_bpffs_root_missing() {
        let dir = TempDir::new().unwrap();
        // dir exists but contains no PROTECTED_PIDS pin.
        let result = evict_dead_agent(dir.path(), 12345);
        let err = result.expect_err("missing bpffs pin must surface as Err");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("PROTECTED_PIDS") || chain.contains("layer-2 evict"),
            "error chain should reference the operation, got: {chain}"
        );
        assert!(
            chain.contains(dir.path().to_str().unwrap()),
            "error chain should reference the attempted path, got: {chain}"
        );
    }

    /// Required W3 test 4: `EvictReport` field shape — pid and
    /// latency populated correctly. We can't exercise the
    /// success path without real BPF, but we can lock the type
    /// surface as a build-time guard so a future refactor can't
    /// silently drop the latency field (which is what the
    /// design's §6.2 "log latencies" requirement materialises as).
    #[test]
    fn evict_report_shape_carries_pid_and_latency() {
        let report = EvictReport {
            agent_pid: 4321,
            evict_latency: Duration::from_micros(42),
        };
        assert_eq!(report.agent_pid, 4321);
        assert_eq!(report.evict_latency, Duration::from_micros(42));
        // Sanity: report is Copy + Debug for cheap log embedding.
        let copied = report;
        assert_eq!(copied.agent_pid, 4321);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("4321"));
        assert!(dbg.contains("42"));
    }

    // ── Watchdog W4: backoff state machine + marker check ─────────

    /// Required W4 test 1: first restart fires immediately. The
    /// design §5.1 contract: "First restart: immediate (within
    /// ~10 ms after pidfd POLLIN, bounded by evict_pid +
    /// Command::spawn latency)" — so the backoff state machine
    /// must yield ZERO for attempt 1 in a fresh window.
    #[test]
    fn backoff_first_attempt_is_immediate() {
        let mut bo = RestartBackoff::new();
        let now = Instant::now();
        match bo.next_delay(now) {
            BackoffOutcome::Wait { delay, attempt } => {
                assert_eq!(delay, Duration::ZERO);
                assert_eq!(attempt, 1);
            }
            other => panic!("expected immediate Wait, got {other:?}"),
        }
        assert_eq!(bo.attempts_in_window(), 1);
    }

    /// Required W4 test 2: exponential growth for attempts 2..5
    /// matches the design §5.1 numbers exactly (100 ms, 200 ms,
    /// 400 ms, 800 ms). Anchors the doubling rule against a
    /// future "let's tune the constants" regression that would
    /// silently change operator-visible backoff timing.
    #[test]
    fn backoff_exponential_growth_attempts_2_through_5() {
        let mut bo = RestartBackoff::new();
        let t0 = Instant::now();
        // Attempt 1 — consumed, not asserted here (covered in
        // test 1).
        let _ = bo.next_delay(t0);
        // Attempts 2..=5 grow as base * 2^(n-2).
        let expected = [
            (2u8, Duration::from_millis(100)),
            (3, Duration::from_millis(200)),
            (4, Duration::from_millis(400)),
            (5, Duration::from_millis(800)),
        ];
        for (n, want) in expected {
            match bo.next_delay(t0) {
                BackoffOutcome::Wait { delay, attempt } => {
                    assert_eq!(attempt, n, "attempt count");
                    assert_eq!(delay, want, "delay for attempt {n}");
                }
                other => panic!("attempt {n}: expected Wait, got {other:?}"),
            }
        }
    }

    /// Required W4 test 3: 5-in-60s ceiling. After
    /// `RESTART_CEILING_MAX_ATTEMPTS` attempts inside the
    /// window, the next call must return CeilingExceeded with
    /// the accurate attempt count + window.
    #[test]
    fn backoff_ceiling_after_max_attempts_in_window() {
        // Use the production knobs but with a tight window so
        // the test stays fast — even production's 60 s window
        // works here because all attempts happen at the same
        // `Instant`.
        let mut bo = RestartBackoff::new();
        let t0 = Instant::now();
        // Drain the 5-attempt allowance.
        for _ in 0..RESTART_CEILING_MAX_ATTEMPTS {
            let outcome = bo.next_delay(t0);
            assert!(matches!(outcome, BackoffOutcome::Wait { .. }));
        }
        // 6th call within the same window must exceed.
        match bo.next_delay(t0) {
            BackoffOutcome::CeilingExceeded {
                attempts_in_window,
                window,
            } => {
                assert_eq!(attempts_in_window, RESTART_CEILING_MAX_ATTEMPTS);
                assert_eq!(window, RESTART_CEILING_WINDOW);
            }
            other => panic!("expected CeilingExceeded, got {other:?}"),
        }
    }

    /// Required W4 test 4: sliding-window pruning. Attempts
    /// older than the window must drop off; the count resets
    /// once enough time elapses. Uses a tight 50 ms window via
    /// `with_config` so the test runs in <100 ms.
    #[test]
    fn backoff_window_slides_old_attempts_drop() {
        let window = Duration::from_millis(50);
        let mut bo = RestartBackoff::with_config(
            window,
            RESTART_CEILING_MAX_ATTEMPTS,
            RESTART_BACKOFF_BASE,
            RESTART_BACKOFF_CAP,
        );
        let t0 = Instant::now();
        // Burn through the allowance at t0.
        for _ in 0..RESTART_CEILING_MAX_ATTEMPTS {
            let _ = bo.next_delay(t0);
        }
        // Ceiling tripped at t0.
        assert!(matches!(
            bo.next_delay(t0),
            BackoffOutcome::CeilingExceeded { .. }
        ));
        // Jump past the window — old attempts must prune.
        let t_future = t0 + window + Duration::from_millis(1);
        match bo.next_delay(t_future) {
            BackoffOutcome::Wait { delay, attempt } => {
                assert_eq!(
                    delay,
                    Duration::ZERO,
                    "window slid; this is attempt 1 again"
                );
                assert_eq!(attempt, 1);
            }
            other => panic!("expected fresh-window Wait, got {other:?}"),
        }
    }

    /// Required W4 test 5: exponential cap. Beyond the natural
    /// growth point, delay must clamp at `RESTART_BACKOFF_CAP`.
    /// Uses tweaked knobs (smaller cap, larger max_attempts) to
    /// exercise the cap path without burning real seconds.
    #[test]
    fn backoff_caps_at_max_delay() {
        let base = Duration::from_millis(100);
        let cap = Duration::from_millis(300); // cap before 800ms
        let mut bo = RestartBackoff::with_config(
            Duration::from_secs(60),
            10, // higher max to allow more attempts
            base,
            cap,
        );
        let t0 = Instant::now();
        // Attempts: 1=0ms, 2=100ms, 3=200ms, 4=400ms→cap=300ms,
        // 5=800ms→cap=300ms, ...
        let _ = bo.next_delay(t0); // 1 → 0
        let _ = bo.next_delay(t0); // 2 → 100
        let _ = bo.next_delay(t0); // 3 → 200
        match bo.next_delay(t0) {
            BackoffOutcome::Wait { delay, attempt: 4 } => {
                assert_eq!(
                    delay, cap,
                    "attempt 4 (400ms unbounded) must cap at {cap:?}"
                );
            }
            other => panic!("expected capped Wait at attempt 4, got {other:?}"),
        }
        match bo.next_delay(t0) {
            BackoffOutcome::Wait { delay, attempt: 5 } => {
                assert_eq!(
                    delay, cap,
                    "attempt 5 (800ms unbounded) must cap at {cap:?}"
                );
            }
            other => panic!("expected capped Wait at attempt 5, got {other:?}"),
        }
    }

    /// External audit WDG-001 / TST-003: only a marker the admin quorum
    /// signed for this agent stands the watchdog down. The old shape —
    /// which this test used to prove was accepted — is refused, recorded
    /// for the agent and removed; a genuine authorisation is honoured once.
    #[test]
    fn only_a_quorum_signed_marker_stands_the_watchdog_down() {
        use nn_proto::admin_signed_payload::{sign, SignedPayload};
        use nn_proto::shutdown_marker::ShutdownMarker;
        let dir = TempDir::new().unwrap();
        let marker = dir.path().join("agent.shutdown_authorised");
        let admin_pub = dir.path().join("admin.pub");
        let agent_id_file = dir.path().join("agent_id");
        let a = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let b = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        std::fs::write(
            &admin_pub,
            format!(
                "{} shutdown\n{} unlock\n",
                hex::encode(a.verifying_key().to_bytes()),
                hex::encode(b.verifying_key().to_bytes())
            ),
        )
        .unwrap();
        std::fs::write(&agent_id_file, format!("{}\n", "07".repeat(16))).unwrap();
        let check = ShutdownCheck {
            marker: &marker,
            admin_pub: &admin_pub,
            agent_id_file: &agent_id_file,
            agent_pid: 4242,
            agent_started: None,
        };
        assert_eq!(check_shutdown_marker(&check), ShutdownVerdict::Absent);

        // what any root process could write before
        std::fs::write(
            &marker,
            format!(
                r#"{{"entry_hash":"{}","grace_deadline_unix_ts":99999999999}}"#,
                "ab".repeat(32)
            ),
        )
        .unwrap();
        assert!(matches!(
            check_shutdown_marker(&check),
            ShutdownVerdict::Refused(_)
        ));
        assert!(!marker.exists(), "a refused marker is removed");
        let rejected = std::fs::read_to_string(dir.path().join("agent.shutdown_rejected")).unwrap();
        assert!(rejected.contains(r#""agent_pid":4242"#), "{rejected}");

        // a genuine authorisation, then the same one again
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = SignedPayload::new_shutdown([9; 32], now, [7; 16], 30);
        let sigs = [sign(&payload, &a).unwrap(), sign(&payload, &b).unwrap()];
        let genuine = ShutdownMarker::new(&payload, &sigs, 4242)
            .unwrap()
            .to_line();
        std::fs::write(&marker, &genuine).unwrap();
        assert_eq!(check_shutdown_marker(&check), ShutdownVerdict::Authorised);
        assert!(!marker.exists());
        std::fs::write(&marker, &genuine).unwrap();
        assert!(matches!(
            check_shutdown_marker(&check),
            ShutdownVerdict::Refused(r) if r.contains("replay")
        ));

        // the keys cannot be read: refused, never honoured
        std::fs::remove_file(&admin_pub).unwrap();
        let payload = SignedPayload::new_shutdown([10; 32], now, [7; 16], 30);
        let sigs = [sign(&payload, &a).unwrap(), sign(&payload, &b).unwrap()];
        std::fs::write(
            &marker,
            ShutdownMarker::new(&payload, &sigs, 4242)
                .unwrap()
                .to_line(),
        )
        .unwrap();
        assert!(matches!(
            check_shutdown_marker(&check),
            ShutdownVerdict::Refused(_)
        ));
    }

    #[test]
    fn process_start_is_read_for_a_live_process() {
        let me = process_start_unix(std::process::id()).expect("own start time");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(me <= now && now - me < 24 * 3600, "start {me}, now {now}");
        assert_eq!(process_start_unix(u32::MAX), None);
    }

    // ── Supplementary W4 tests (anchors for forward-compat) ────────

    /// Anchor: `spawn_agent` with an empty argv slice surfaces
    /// a clear error before touching `Command::spawn`. Guards
    /// against a future caller forgetting the binary-path
    /// element.
    // ── respawn v2 backend ─────────────────────────────────────────
    #[test]
    fn parse_proc_cmdline_splits_on_nul_and_ignores_trailing() {
        let body = b"/usr/local/bin/northnarrow-agent\0--detect-only\0--admin-pub\0/etc/northnarrow/admin.pub\0";
        assert_eq!(
            parse_proc_cmdline(body),
            vec![
                "/usr/local/bin/northnarrow-agent",
                "--detect-only",
                "--admin-pub",
                "/etc/northnarrow/admin.pub"
            ]
        );
        assert!(parse_proc_cmdline(b"").is_empty());
        assert!(parse_proc_cmdline(b"\0\0").is_empty());
    }

    #[test]
    fn agent_argv_from_proc_reads_own_cmdline_and_overrides_bin() {
        // Our own process is a valid /proc source.
        let own = std::process::id();
        let argv = agent_argv_from_proc(own, None).expect("own cmdline");
        assert!(!argv.is_empty());
        let over = agent_argv_from_proc(own, Some(Path::new("/opt/nn/agent"))).unwrap();
        assert_eq!(over[0], "/opt/nn/agent");
        assert_eq!(over[1..], argv[1..]);
    }

    #[test]
    fn select_backend_auto_prefers_systemd_when_booted() {
        let b = select_backend(RespawnBackendChoice::Auto, true, "nn.service", || {
            panic!("exec argv must not be built on a systemd host")
        })
        .unwrap();
        assert_eq!(
            b,
            RespawnBackend::SystemdUnit {
                unit: "nn.service".into()
            }
        );
        assert_eq!(b.describe(), "systemd:nn.service");
    }

    #[test]
    fn select_backend_auto_falls_back_to_exec_without_systemd() {
        let b = select_backend(RespawnBackendChoice::Auto, false, "nn.service", || {
            Ok(vec!["/bin/agent".into(), "--detect-only".into()])
        })
        .unwrap();
        assert_eq!(
            b,
            RespawnBackend::ForkExec {
                argv: vec!["/bin/agent".into(), "--detect-only".into()]
            }
        );
        assert_eq!(b.describe(), "exec:/bin/agent (argc=2)");
    }

    #[test]
    fn select_backend_exec_rejects_empty_argv() {
        let err = select_backend(RespawnBackendChoice::Exec, true, "nn.service", || {
            Ok(vec![])
        })
        .unwrap_err();
        assert!(err.to_string().contains("non-empty argv"), "{err}");
    }

    #[test]
    fn select_backend_explicit_systemd_even_when_not_booted() {
        let b = select_backend(RespawnBackendChoice::Systemd, false, "nn.service", || {
            panic!("exec argv must not be built")
        })
        .unwrap();
        assert!(matches!(b, RespawnBackend::SystemdUnit { .. }));
    }

    #[test]
    fn systemctl_start_command_shape() {
        let cmd =
            systemctl_start_command(Path::new("/usr/bin/systemctl"), "northnarrow-agent.service");
        assert_eq!(cmd.get_program(), "/usr/bin/systemctl");
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec!["start", "--no-block", "northnarrow-agent.service"]
        );
    }

    /// External audit WDG-009: the ping ticker never bursts.
    #[test]
    fn ping_ticker_delays_missed_ticks() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            assert_eq!(
                ping_ticker(STATUS_PING_INTERVAL).missed_tick_behavior(),
                tokio::time::MissedTickBehavior::Delay
            );
        });
    }

    /// External audit WDG-009: after a stall of three intervals one late
    /// tick fires, then the next is a whole interval later — two pings are
    /// never closer than the interval, so two timeouts span it.
    #[tokio::test(start_paused = true)]
    async fn ping_ticks_stay_an_interval_apart_after_a_stall() {
        let period = STATUS_PING_INTERVAL;
        let mut tick = ping_ticker(period);
        tick.tick().await; // the immediate first tick
        tick.tick().await;
        // The watchdog thread does not run for three intervals.
        tokio::time::advance(period * 3).await;
        tick.tick().await; // the late tick
        let late = tokio::time::Instant::now();
        tick.tick().await;
        let next = tokio::time::Instant::now();
        assert!(
            next - late >= period,
            "two ticks {:?} apart after a stall (interval {period:?})",
            next - late
        );
    }

    /// External audit WDG-009: blocking work does not hold the runtime's
    /// only thread — a timer task keeps running while it blocks.
    #[tokio::test(flavor = "current_thread")]
    async fn off_runtime_keeps_the_runtime_thread_free() {
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = ticks.clone();
        let timer = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        off_runtime(|| {
            std::thread::sleep(Duration::from_millis(400));
            Ok(())
        })
        .await
        .unwrap();
        let seen = ticks.load(std::sync::atomic::Ordering::Relaxed);
        timer.abort();
        assert!(
            seen >= 5,
            "only {seen} timer ticks while the blocking call ran"
        );
        let err = off_runtime(|| -> Result<()> { Err(anyhow!("systemctl said no")) })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("systemctl said no"), "{err}");
    }

    #[test]
    fn systemctl_show_command_shape() {
        let cmd =
            systemctl_show_command(Path::new("/usr/bin/systemctl"), "northnarrow-agent.service");
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "show",
                "--property=ActiveState,SubState,Result,ConditionResult,AssertResult",
                "northnarrow-agent.service"
            ]
        );
    }

    #[test]
    fn unit_state_from_show_is_one_bounded_line() {
        let out = "ActiveState=failed\nSubState=failed\nResult=exit-code\nConditionResult=yes\nAssertResult=yes\n";
        assert_eq!(
            unit_state_from_show(out).as_deref(),
            Some("ActiveState=failed SubState=failed Result=exit-code ConditionResult=yes AssertResult=yes")
        );
        assert_eq!(unit_state_from_show("\n\n"), None);
        let long = format!("Result={}\n", "é".repeat(300));
        let s = unit_state_from_show(&long).unwrap();
        assert!(s.len() <= 256 && s.starts_with("Result="), "{}", s.len());
    }

    /// External audit DEP-004: a hold leaves one JSON line per hold where
    /// the agent reads it (next to the shutdown marker).
    #[test]
    fn record_hold_appends_one_line_per_hold() {
        use nn_proto::watchdog_hold::{HoldRecord, HOLD_PATH};
        assert_eq!(
            hold_record_path(Path::new(nn_proto::shutdown_marker::MARKER_PATH)),
            Path::new(HOLD_PATH)
        );
        let dir = TempDir::new().unwrap();
        let path = hold_record_path(&dir.path().join("agent.shutdown_authorised"));
        let rec = HoldRecord {
            at: 1_800_000_000,
            agent_pid: 4242,
            reason: "agent respawn failed".into(),
            detail: "no agent after the start job".into(),
            unit_state: Some("ActiveState=failed Result=exit-code".into()),
        };
        record_hold(&path, &rec).unwrap();
        record_hold(
            &path,
            &HoldRecord {
                unit_state: None,
                ..rec.clone()
            },
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<HoldRecord> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], rec);
        assert_eq!(lines[1].unit_state, None);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn cli_defaults_to_auto_backend_and_agent_unit() {
        let cli = Cli::try_parse_from(["northnarrow-watchdog"]).unwrap();
        assert_eq!(cli.respawn_backend, RespawnBackendChoice::Auto);
        assert_eq!(cli.agent_unit, DEFAULT_AGENT_UNIT);
        let cli = Cli::try_parse_from([
            "northnarrow-watchdog",
            "--respawn-backend",
            "exec",
            "--agent-unit",
            "x.service",
        ])
        .unwrap();
        assert_eq!(cli.respawn_backend, RespawnBackendChoice::Exec);
        assert_eq!(cli.agent_unit, "x.service");
    }

    // ── STATUS ping: absent socket is not "stuck" ─────────────────
    #[test]
    fn absent_socket_never_trips_stuck_threshold() {
        let mut t = StatusPingTracker::with_threshold(2);
        for i in 1..=10u32 {
            assert_eq!(
                t.record_socket_absent(),
                PingOutcome::SocketAbsent { consecutive: i }
            );
        }
        assert_eq!(t.consecutive_timeouts(), 0);
        // A real unresponsive ping still counts from zero afterwards.
        assert_eq!(t.record_timeout(), PingOutcome::TimeoutOnce);
        assert_eq!(t.record_timeout(), PingOutcome::StuckDetected);
    }

    #[test]
    fn ok_ping_resets_absent_counter() {
        let mut t = StatusPingTracker::new();
        t.record_socket_absent();
        t.record_socket_absent();
        assert_eq!(t.record_ok(), PingOutcome::Ok);
        // External audit WDG-007: once the agent answered, a missing
        // socket is a vanished one, counted from 1.
        assert_eq!(
            t.record_socket_absent(),
            PingOutcome::SocketVanished { consecutive: 1 }
        );
    }

    #[test]
    fn classify_not_found_as_socket_absent() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e = anyhow::Error::from(io).context("connect /run/northnarrow/admin.sock");
        assert_eq!(classify_ping_error(&e), PingFailure::SocketAbsent);
        // External audit WDG-007: a socket nobody listens on (or a file at
        // the path) is "nothing listens", not a hang.
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
        let e = anyhow::Error::from(io).context("connect");
        assert_eq!(classify_ping_error(&e), PingFailure::SocketAbsent);
        let io = std::io::Error::from_raw_os_error(libc::ENOTDIR);
        let e = anyhow::Error::from(io).context("connect");
        assert_eq!(classify_ping_error(&e), PingFailure::SocketAbsent);
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "nope");
        let e = anyhow::Error::from(io).context("reading reply frame header");
        assert_eq!(classify_ping_error(&e), PingFailure::Unresponsive);
        assert_eq!(
            classify_ping_error(&anyhow!("reply body length exceeds")),
            PingFailure::Unresponsive
        );
        let e = anyhow::Error::new(NotTheAgent {
            peer_pid: Some(7),
            agent_pid: 42,
        })
        .context("STATUS ping");
        assert_eq!(classify_ping_error(&e), PingFailure::NotTheAgent);
    }

    /// External audit WDG-007: `connect` to a path that holds a stale
    /// socket, a regular file or a directory fails with ECONNREFUSED —
    /// "nothing listens" — like a missing path.
    #[tokio::test]
    async fn nothing_listening_at_the_path_is_absent_not_unresponsive() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.sock");
        // Lab PR 258: shut down before it is closed, as in
        // `sd_notify_reaches_an_abstract_notify_socket` — a child another
        // test spawns holds a copy of the listener's descriptor until its
        // exec, and the socket would still take the connection (served by
        // this process: `NotTheAgent`).
        let listener = std::os::unix::net::UnixListener::bind(&stale).unwrap();
        // SAFETY: shutdown(2) of the listener's own open descriptor.
        assert_eq!(
            unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR) },
            0
        );
        drop(listener);
        let file = dir.path().join("file.sock");
        std::fs::write(&file, "").unwrap();
        let sub = dir.path().join("dir.sock");
        std::fs::create_dir(&sub).unwrap();
        let dangling = dir.path().join("dangling.sock");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        for path in [&stale, &file, &sub, &dangling] {
            let err = ping_agent_status(path, Duration::from_secs(1), Some(1))
                .await
                .unwrap_err();
            assert_eq!(
                classify_ping_error(&err),
                PingFailure::SocketAbsent,
                "{}: {err:#}",
                path.display()
            );
        }
    }

    /// External audit WDG-007: a server that is not the agent — a process
    /// that bound the path after removing the agent's socket — is refused
    /// before a request is sent, whatever it would answer.
    #[tokio::test(flavor = "current_thread")]
    async fn a_status_answer_from_another_process_is_not_the_agent() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("impostor.sock");
        let _listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let not_us = std::process::id() + 1;
        let err = ping_agent_status(&socket, Duration::from_secs(2), Some(not_us))
            .await
            .unwrap_err();
        assert_eq!(classify_ping_error(&err), PingFailure::NotTheAgent);
        assert!(
            format!("{err:#}").contains(&format!("served by pid {}", std::process::id())),
            "{err:#}"
        );
    }

    // ── External audit WDG-007: never seen vs. vanished ────────────
    #[test]
    fn socket_never_seen_is_not_stuck() {
        let mut t = StatusPingTracker::new();
        for i in 1..=20u32 {
            assert_eq!(
                t.record_socket_absent(),
                PingOutcome::SocketAbsent { consecutive: i }
            );
        }
        assert!(!t.answered());
        assert_eq!(t.consecutive_timeouts(), 0);
    }

    #[test]
    fn socket_vanished_after_an_answer_feeds_recovery() {
        let mut t = StatusPingTracker::new();
        assert_eq!(t.record_ok(), PingOutcome::Ok);
        for i in 1..STATUS_PING_VANISHED_STUCK_AFTER {
            assert_eq!(
                t.record_socket_absent(),
                PingOutcome::SocketVanished { consecutive: i }
            );
        }
        assert_eq!(t.record_socket_absent(), PingOutcome::StuckDetected);
        // The thresholds keep their order: tamper report first, then
        // recovery, and the healthy agent's rebind window well inside.
        const {
            assert!(STATUS_PING_VANISHED_TAMPER_AFTER < STATUS_PING_VANISHED_STUCK_AFTER);
            assert!(
                STATUS_PING_INTERVAL.as_secs() * (STATUS_PING_VANISHED_STUCK_AFTER as u64 - 1)
                    >= 3 * AGENT_SOCKET_REBIND_WITHIN.as_secs()
            );
        }
    }

    #[test]
    fn a_socket_that_comes_back_ends_the_vanished_streak() {
        let mut t = StatusPingTracker::new();
        t.record_ok();
        assert_eq!(
            t.record_socket_absent(),
            PingOutcome::SocketVanished { consecutive: 1 }
        );
        // The agent bound it again.
        assert_eq!(t.record_ok(), PingOutcome::Ok);
        for i in 1..STATUS_PING_VANISHED_STUCK_AFTER {
            assert_eq!(
                t.record_socket_absent(),
                PingOutcome::SocketVanished { consecutive: i }
            );
        }
    }

    #[test]
    fn reset_forgets_the_answer() {
        let mut t = StatusPingTracker::new();
        t.record_ok();
        t.record_socket_absent();
        t.reset();
        assert!(!t.answered());
        // A new agent whose socket is not up yet is not stuck.
        for i in 1..=10u32 {
            assert_eq!(
                t.record_socket_absent(),
                PingOutcome::SocketAbsent { consecutive: i }
            );
        }
    }

    #[tokio::test]
    async fn missing_socket_ping_error_classifies_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.sock");
        let err = ping_agent_status(&path, Duration::from_secs(1), Some(1))
            .await
            .unwrap_err();
        assert_eq!(classify_ping_error(&err), PingFailure::SocketAbsent);
    }

    // ── External audit WDG-010: reaping exec-backend children ──────
    #[test]
    fn reap_ignores_echild() {
        // PID 1 is never our child: its pidfd can be opened, not reaped.
        let raw = pidfd_open(1).expect("pidfd_open(1)");
        // SAFETY: pidfd_open returned this fd to us.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(reap_agent(&fd).unwrap(), Reaped::NotOurChild);
    }

    #[test]
    fn reap_collects_an_exited_child_through_its_pidfd() {
        let mut child = Command::new("sh").args(["-c", "exit 7"]).spawn().unwrap();
        let pid = child.id();
        let raw = pidfd_open(pid).expect("pidfd_open(child)");
        // SAFETY: pidfd_open returned this fd to us.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !pidfd_exited(&fd) {
            assert!(Instant::now() < deadline, "the child never exited");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Exited and not collected: a zombie until reap_agent.
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        assert!(state.contains(") Z "), "{state}");
        assert_eq!(
            reap_agent(&fd).unwrap(),
            Reaped::Collected {
                pid,
                si_code: libc::CLD_EXITED,
                code: 7
            }
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists(), "zombie left");
        // Nothing left to collect (Child::try_wait sees ECHILD too).
        assert_eq!(reap_agent(&fd).unwrap(), Reaped::NotOurChild);
        assert!(child.try_wait().is_err());
    }

    #[test]
    fn reap_leaves_a_running_child_alone() {
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let raw = pidfd_open(child.id()).expect("pidfd_open(child)");
        // SAFETY: pidfd_open returned this fd to us.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(reap_agent(&fd).unwrap(), Reaped::Running);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    // ── External audit WDG-008: the exec backend's argv ─────────────
    /// A pid that does not exist (pid_max is at most 2^22).
    const NO_SUCH_PID: u32 = 4_194_304 + 17;

    #[test]
    fn exec_argv_records_the_capture_and_prefers_it_later() {
        let dir = TempDir::new().unwrap();
        let pidfile = dir.path().join("agent.pid");
        let holds = dir.path().join("watchdog.hold");
        let bin = Path::new("/usr/local/bin/northnarrow-agent");
        // A capture that works (this process) is recorded, 0600.
        let own = exec_respawn_argv(std::process::id(), Some(bin), bin, &pidfile, &holds);
        assert_eq!(own[0], bin.to_string_lossy());
        let record = agent_argv_record_path(&pidfile);
        assert_eq!(record, dir.path().join(AGENT_ARGV_FILE_NAME));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!holds.exists(), "a successful capture records no event");
        // An agent gone before its capture: the recorded argv, argv[0] the
        // verified binary, and a record for the agent to sign.
        persist_agent_argv(
            &record,
            &[
                "/old/northnarrow-agent".to_string(),
                "--detect-only".to_string(),
                "--admin-pub".to_string(),
                "/etc/northnarrow/admin.pub".to_string(),
            ],
        )
        .unwrap();
        let verified = Path::new("/usr/local/bin/northnarrow-agent.verified");
        let argv = exec_respawn_argv(NO_SUCH_PID, None, verified, &pidfile, &holds);
        assert_eq!(
            argv,
            [
                "/usr/local/bin/northnarrow-agent.verified",
                "--detect-only",
                "--admin-pub",
                "/etc/northnarrow/admin.pub"
            ]
        );
        let line = std::fs::read_to_string(&holds).unwrap();
        let rec: nn_proto::watchdog_hold::HoldRecord =
            serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(
            rec.reason,
            nn_proto::watchdog_hold::REASON_RESPAWN_ARGV_DEGRADED
        );
        assert_eq!(rec.agent_pid, NO_SUCH_PID);
        assert!(rec.detail.contains("--detect-only"), "{}", rec.detail);
    }

    #[test]
    fn exec_argv_records_a_degraded_fallback() {
        let dir = TempDir::new().unwrap();
        let pidfile = dir.path().join("agent.pid");
        let holds = dir.path().join("watchdog.hold");
        let verified = Path::new("/usr/local/bin/northnarrow-agent");
        // No record: the minimal argv, recorded as degraded.
        let argv = exec_respawn_argv(NO_SUCH_PID, None, verified, &pidfile, &holds);
        assert_eq!(
            argv,
            [
                verified.to_string_lossy().into_owned(),
                "--pid-file".to_string(),
                pidfile.to_string_lossy().into_owned()
            ]
        );
        let body = std::fs::read_to_string(&holds).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains(nn_proto::watchdog_hold::REASON_RESPAWN_ARGV_DEGRADED));
        assert!(body.contains("minimal argv"), "{body}");
    }

    #[test]
    fn a_planted_argv_record_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let record = dir.path().join(AGENT_ARGV_FILE_NAME);
        // A link at the name is not followed.
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"/bin/sh\0-c\0id\0").unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &record).unwrap();
        assert!(read_persisted_agent_argv(&record).is_err());
        // A record others can write is not the watchdog's.
        std::fs::remove_file(&record).unwrap();
        persist_agent_argv(&record, &["/a".to_string()]).unwrap();
        assert_eq!(read_persisted_agent_argv(&record).unwrap(), ["/a"]);
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_persisted_agent_argv(&record).is_err());
        // Neither is an empty one, or a directory.
        std::fs::remove_file(&record).unwrap();
        persist_agent_argv(&record, &[]).unwrap();
        assert!(read_persisted_agent_argv(&record).is_err());
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();
        assert!(read_persisted_agent_argv(&record).is_err());
    }

    #[test]
    fn spawn_agent_rejects_empty_argv() {
        let err = spawn_agent(&[]).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("empty argv"),
            "error should explain the missing binary path, got: {chain}"
        );
    }

    /// External audit WDG-003: the agent is the pid the pidfile names
    /// only when that process runs the agent binary — any other live
    /// process is refused, and a pidfd is never handed out for it.
    #[test]
    fn a_pidfile_naming_another_program_is_not_the_agent() {
        let dir = TempDir::new().unwrap();
        let pidfile = dir.path().join("agent.pid");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        // `spawn` can return before the child has exec'd: until then its
        // `exe` is this test binary.
        let deadline = Instant::now() + Duration::from_secs(5);
        while runs_binary(child.id(), Path::new("/bin/sleep")).is_err() {
            assert!(
                Instant::now() < deadline,
                "the child never exec'd /bin/sleep"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::write(&pidfile, format!("{}\n", child.id())).unwrap();
        let (pid, fd) = open_verified_agent(&pidfile, Path::new("/bin/sleep")).unwrap();
        assert_eq!(pid, child.id());
        pidfd_signal(fd.as_raw_fd(), 0).unwrap();
        let err = open_verified_agent(&pidfile, Path::new("/bin/true")).unwrap_err();
        assert!(format!("{err:#}").contains(" runs "), "{err:#}");
        assert!(runs_binary(child.id(), Path::new("/bin/true")).is_err());
        let _ = child.kill();
        let _ = child.wait();
        // gone: no pidfd either
        assert!(open_verified_agent(&pidfile, Path::new("/bin/sleep")).is_err());
    }

    /// Required W3 test 5: layer-2 evict latency is observable
    /// from the call site. Round-trips a real `pidfd_open` →
    /// `wait_for_agent_death` cycle on a child and measures the
    /// total elapsed time, asserting it stays well under the
    /// design's "≤ 50 µs typical" budget by an order of
    /// magnitude (5 ms slack accounts for scheduler / test-host
    /// noise). Doesn't actually evict (no BPF env in unit
    /// tests) — but proves the wakeup→delete leg latency the
    /// watchdog's `tokio::select!` arm will produce in
    /// production is sub-millisecond on a healthy host.
    #[tokio::test(flavor = "current_thread")]
    async fn pidfd_wakeup_latency_stays_in_sub_millisecond_budget() {
        let (mut child, pidfd) = spawn_sleep_child_and_open_pidfd();
        let child_pid = child.id();

        let kill_signaled_at = std::sync::Arc::new(std::sync::Mutex::new(None::<Instant>));
        let signaled_at = std::sync::Arc::clone(&kill_signaled_at);
        let killer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let t = Instant::now();
            unsafe {
                libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
            }
            *signaled_at.lock().unwrap() = Some(t);
        });

        wait_for_agent_death(&pidfd).await.unwrap();
        let wakeup_at = Instant::now();
        killer.await.unwrap();
        let kill_at = kill_signaled_at.lock().unwrap().unwrap();
        let wakeup_latency = wakeup_at.duration_since(kill_at);

        // 5 ms is two orders of magnitude over the design's
        // µs-class typical. If this trips in CI it's a real
        // regression worth investigating.
        assert!(
            wakeup_latency < Duration::from_millis(5),
            "pidfd POLLIN wakeup latency exceeded 5 ms budget: {wakeup_latency:?}"
        );

        let _ = child.wait();
    }

    // ── Watchdog W5: STATUS-ping tracker + ping client ─────────────

    /// Required W5 test 1: a successful ping resets the
    /// counter — the next timeout starts a fresh streak, not a
    /// resumption of an earlier one. Anchors the
    /// "isolated transient + recovery" contract.
    #[test]
    fn status_ping_tracker_record_ok_resets_counter() {
        let mut tracker = StatusPingTracker::new();
        // One timeout → counter = 1.
        assert_eq!(tracker.record_timeout(), PingOutcome::TimeoutOnce);
        assert_eq!(tracker.consecutive_timeouts(), 1);
        // Ok → reset to 0.
        assert_eq!(tracker.record_ok(), PingOutcome::Ok);
        assert_eq!(tracker.consecutive_timeouts(), 0);
        // Another timeout starts a fresh streak.
        assert_eq!(tracker.record_timeout(), PingOutcome::TimeoutOnce);
        assert_eq!(tracker.consecutive_timeouts(), 1);
    }

    /// Required W5 test 2: a single timeout returns
    /// `TimeoutOnce` — caller logs WARN and continues. The
    /// stuck-recovery sequence is NOT triggered on one
    /// transient.
    #[test]
    fn status_ping_tracker_single_timeout_returns_timeout_once() {
        let mut tracker = StatusPingTracker::new();
        let outcome = tracker.record_timeout();
        assert_eq!(outcome, PingOutcome::TimeoutOnce);
        assert_eq!(tracker.consecutive_timeouts(), 1);
    }

    /// Required W5 test 3: two consecutive timeouts return
    /// `StuckDetected`. This is the design §4 trigger for the
    /// SIGINT recovery sequence — locks the threshold against
    /// a future "let's tune to 3" silent change.
    #[test]
    fn status_ping_tracker_two_consecutive_timeouts_returns_stuck_detected() {
        let mut tracker = StatusPingTracker::new();
        assert_eq!(tracker.record_timeout(), PingOutcome::TimeoutOnce);
        let outcome = tracker.record_timeout();
        assert_eq!(outcome, PingOutcome::StuckDetected);
        assert_eq!(tracker.consecutive_timeouts(), 2);
    }

    /// Required W5 test 4: custom threshold for forward-compat
    /// (a hardening tappa tightening to 1 OR loosening to 3
    /// uses the same machinery). With threshold=3, two
    /// timeouts give TimeoutOnce; the third gives
    /// StuckDetected.
    #[test]
    fn status_ping_tracker_with_threshold_3_triggers_on_third_timeout() {
        let mut tracker = StatusPingTracker::with_threshold(3);
        assert_eq!(tracker.record_timeout(), PingOutcome::TimeoutOnce);
        assert_eq!(tracker.record_timeout(), PingOutcome::TimeoutOnce);
        assert_eq!(tracker.record_timeout(), PingOutcome::StuckDetected);
        assert_eq!(tracker.consecutive_timeouts(), 3);
    }

    // ── Supplementary W5 tests ─────────────────────────────────────

    /// Reset method actually zeros the counter — used by the
    /// main loop after a stuck-recovery cycle to give the new
    /// respawned agent a fresh ping budget.
    #[test]
    fn status_ping_tracker_reset_zeros_counter() {
        let mut tracker = StatusPingTracker::new();
        let _ = tracker.record_timeout();
        let _ = tracker.record_timeout();
        // At threshold — but reset clears.
        tracker.reset();
        assert_eq!(tracker.consecutive_timeouts(), 0);
        // Next timeout is the first of a new streak.
        assert_eq!(tracker.record_timeout(), PingOutcome::TimeoutOnce);
    }

    /// `ping_agent_status` against a non-existent socket
    /// surfaces a clear Err quickly (UnixStream::connect
    /// returns ENOENT/ECONNREFUSED before the timeout window
    /// elapses). Anchors the "socket missing = treated as
    /// timeout" contract — what the agent-restart-in-progress
    /// race produces.
    #[tokio::test(flavor = "current_thread")]
    async fn ping_agent_status_fails_quickly_on_missing_socket() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("never_bound.sock");
        let start = Instant::now();
        let result = ping_agent_status(&socket, Duration::from_secs(5), None).await;
        let elapsed = start.elapsed();
        assert!(result.is_err(), "missing socket must error");
        // Connect fail is near-instant; well under the 5 s
        // budget. 500 ms gives generous CI slack.
        assert!(
            elapsed < Duration::from_millis(500),
            "connect-fail should be near-instant: {elapsed:?}"
        );
    }

    /// `ping_agent_status` returns Ok when a mock server
    /// answers with a well-formed `StatusResponse`. Proves the
    /// full request → encode → write → read → decode pipeline
    /// works end-to-end against the common wire types without
    /// needing a real agent.
    #[tokio::test(flavor = "current_thread")]
    async fn ping_agent_status_round_trips_through_mock_server() {
        use nn_model::posture_types::PostureKind;
        use nn_proto::admin_protocol::StatusResponse;

        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("mock.sock");

        // Mock server: accept once, read one frame, send one
        // StatusResponse, close.
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Drain the request frame (we don't care about its
            // bytes — the contract is "client sends Status,
            // server replies StatusResponse").
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.expect("read hdr");
            let body_len = u32::from_be_bytes(header) as usize;
            let mut body = vec![0u8; body_len];
            stream.read_exact(&mut body).await.expect("read body");
            // Reply.
            let reply = AdminMessage::StatusResponse(StatusResponse {
                posture: PostureKind::Observing,
                network_isolation_engaged: false,
                last_admin_action_secs_ago: None,
                ringbuf_drops_total: None,
                ringbuf_drops: None,
                combat_stage: None,
                combat_locked: None,
                ringbuf_rejected_total: None,
                ringbuf_rejected: None,
                netflow_rows_skipped_total: None,
                netflow_pending_evicted_total: None,
                net_inactive_rules: None,
                flow_sock_pending: None,
                flow_sock_capacity: None,
                flow_sock_forgotten_min: None,
                detect_only: None,
                detect_only_source: None,
                combat_evidence_unrecorded: None,
                combat_evidence_pending: None,
                combat_evidence_dropped: None,
                net_dot_rows_total: None,
                net_dot_rows_resolver: None,
                net_quic_rows_total: None,
                deny_fail_open_total: None,
                deny_fail_open: None,
                network_isolation_v4: None,
                network_isolation_v6: None,
                trust_level: None,
                trust_reasons: None,
                degradations: None,
                capability_manifest: None,
                exploit_guard: None,
                cow_guard: None,
                execq_state: None,
                execq_held_total: None,
                execq_resumed_total: None,
                execq_killed_total: None,
                execq_quarantined_total: None,
                execq_defaulted_total: None,
                execq_known_identity_total: None,
                execq_known_hash_total: None,
                execq_not_held_total: None,
                execq_scanner_deaths_total: None,
                net_connect_verdicts_total: None,
                net_flow_snapshots_total: None,
                net_flow_snapshots_deferred_total: None,
                net_connect_denied_total: None,
                ransomware_decisive_total: None,
                ransomware_signals_total: None,
                ransomware_trusted_total: None,
                ransomware_samplings_total: None,
                defense_tamper_total: None,
                defense_tamper_sanctioned_total: None,
                defense_tools_watched: None,
                execpol_state: None,
                execpol_denied_total: None,
                execpol_would_deny_total: None,
                execpol_quarantine_total: None,
                execpol_quarantine_inactive_total: None,
                execpol_env_denied_total: None,
                execpol_env_recorded_total: None,
                execpol_map_denied_total: None,
                execpol_map_recorded_total: None,
                execq_script_refused_total: None,
            });
            let bytes = encode_frame(&reply).expect("encode reply");
            stream.write_all(&bytes).await.expect("write reply");
        });

        // Give the listener a tick to be ready.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // External audit WDG-007: the server is this process, so the ping
        // expecting it succeeds.
        ping_agent_status(&socket, Duration::from_secs(2), Some(std::process::id()))
            .await
            .expect("ping must succeed against mock server");

        mock.await.expect("mock task");
    }

    /// A mock agent that reads one request frame and answers `body` (a
    /// frame body, without its length).
    async fn ping_against(body: Vec<u8>) -> Result<LoopProgress> {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("mock.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.expect("read hdr");
            let mut req = vec![0u8; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut req).await.expect("read body");
            assert_eq!(req, vec![2], "the ping is the unsigned Status, unchanged");
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend(body);
            stream.write_all(&frame).await.expect("write reply");
        });
        let out = ping_agent_status(&socket, Duration::from_secs(2), None).await;
        mock.await.expect("mock task");
        out
    }

    /// External audit ASK-009 (lab PR 213): the ping reads the reply's
    /// variant and its two leading fields only. An agent older than the
    /// fields this watchdog knows — here one that sends only the first three
    /// fields, and lab PR 193's shape — is alive: the full decode failed on
    /// them (postcard has no field count), so a watchdog upgraded before
    /// the agent counted every ping as a timeout.
    #[tokio::test(flavor = "current_thread")]
    async fn a_ping_does_not_depend_on_the_status_fields() {
        use nn_model::posture_types::PostureKind;
        use nn_proto::admin_protocol::{StatusResponse, STATUS_RESPONSE_INDEX};
        // The first agents' reply, as postcard writes it: the variant, then
        // posture Combat (3), isolation engaged (1), last admin action
        // Some(4) — and nothing after.
        let old = vec![STATUS_RESPONSE_INDEX as u8, 3, 1, 1, 4];
        assert!(
            nn_proto::admin_protocol::decode_frame(&{
                let mut f = (old.len() as u32).to_be_bytes().to_vec();
                f.extend(&old);
                f
            })
            .is_err(),
            "the full decode refuses the older shape"
        );
        // Lab PR 216: it closes the connection at the progress request — not
        // reported, the status answer alone counts.
        assert_eq!(
            ping_against(old).await.expect("an older agent is alive"),
            LoopProgress::Unreported
        );
        // This build's unsigned reply: the telemetry withheld.
        let public = encode_frame(&AdminMessage::StatusResponse(StatusResponse::public(
            PostureKind::Observing,
            false,
            None,
            None,
            Some(false),
        )))
        .unwrap();
        ping_against(public[4..].to_vec())
            .await
            .expect("the public reply is a ping answer");
        // Fields a newer agent appends: trailing bytes, ignored.
        let mut newer = public[4..].to_vec();
        newer.extend([1, 42, 1, 7]);
        ping_against(newer).await.expect("a newer agent is alive");
    }

    /// Another reply than a status reply is still a failed ping.
    #[tokio::test(flavor = "current_thread")]
    async fn a_ping_answered_with_another_variant_fails() {
        use nn_proto::admin_protocol::UnlockResult;
        let other = encode_frame(&AdminMessage::UnlockResult(UnlockResult::Success)).unwrap();
        let err = ping_against(other[4..].to_vec()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("wanted StatusResponse"),
            "{err:#}"
        );
        assert!(ping_against(Vec::new()).await.is_err(), "an empty body");
    }

    // ── Lab PR 216 (capability C23): fail-visible supervision ──────────

    /// Every failure has a non-zero status of its own; only a stop the
    /// watchdog was told to make is 0 (the unit's
    /// `RestartPreventExitStatus=0`). 2 is clap's own usage status.
    #[test]
    fn every_failure_exits_non_zero_with_its_own_status() {
        let mut codes: Vec<u8> = ExitReason::ALL.iter().map(|r| r.code()).collect();
        let mut names: Vec<&str> = ExitReason::ALL.iter().map(|r| r.name()).collect();
        for r in ExitReason::ALL {
            assert_eq!(r.code() == 0, r == ExitReason::Stopped, "{r:?}");
            // clear of systemd's own statuses (200-245) and the shell's (126+)
            assert!(r.code() < 126, "{r:?}");
        }
        codes.sort_unstable();
        codes.dedup();
        names.sort_unstable();
        names.dedup();
        assert_eq!(codes.len(), ExitReason::ALL.len(), "statuses are distinct");
        assert_eq!(names.len(), ExitReason::ALL.len(), "names are distinct");
        let usage = Cli::try_parse_from(["northnarrow-watchdog", "--no-such-flag"]).unwrap_err();
        assert_eq!(usage.exit_code(), i32::from(ExitReason::Usage.code()));
        assert_eq!(ExitReason::PidfdWait.code(), 20);
    }

    /// Static review C-44 / G-05: the wait on the agent's pidfd failing is
    /// a failure with status 20 — the loop used to `break` and exit 0. A
    /// real failed wait (an fd epoll cannot watch) maps to it, and its
    /// record names the status for the agent to sign.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_pidfd_wait_exits_non_zero_and_is_recorded() {
        let dir = TempDir::new().unwrap();
        let file = std::fs::File::create(dir.path().join("not-a-pidfd")).unwrap();
        let fd: OwnedFd = file.into();
        let err = wait_for_agent_death(&fd)
            .await
            .expect_err("a regular file cannot be waited on");
        let failure = pidfd_wait_failed(err, 4242);
        assert_eq!(failure.reason, ExitReason::PidfdWait);
        assert_ne!(failure.reason.code(), 0);
        assert_eq!(failure.agent_pid, 4242);
        let rec = exit_record(&failure, 1_800_000_000);
        assert_eq!(rec.reason, nn_proto::watchdog_hold::REASON_WATCHDOG_EXIT);
        assert_eq!(rec.agent_pid, 4242);
        assert!(
            rec.detail
                .starts_with("exit status 20 (pidfd_wait_failed): ")
                && rec.detail.contains("AsyncFd"),
            "{}",
            rec.detail
        );
        // one record per line, bounded
        let long = Failure::new(ExitReason::NoAgent, anyhow!("a\nb{}", "x".repeat(1000)));
        let rec = exit_record(&long, 0);
        assert!(
            !rec.detail.contains('\n') && rec.detail.len() < 400,
            "{}",
            rec.detail
        );
        assert!(rec.detail.starts_with("exit status 11 (no_verified_agent)"));
    }

    /// `result.exit_as(reason)` keeps the error and sets the status.
    #[test]
    fn exit_as_sets_the_status() {
        let r: Result<()> = Err(anyhow!("boom"));
        let f = r.exit_as(ExitReason::Pidfile).unwrap_err();
        assert_eq!((f.reason, f.agent_pid), (ExitReason::Pidfile, 0));
        assert_eq!(format!("{}", f.error), "boom");
        assert_eq!(f.agent(7).agent_pid, 7);
    }

    /// The `OnFailure=` handler's record carries systemd's result; without
    /// the `MONITOR_*` variables (systemd before 251) it says so.
    #[test]
    fn the_unit_failure_record_carries_systemds_result() {
        let vars = |k: &str| match k {
            "MONITOR_UNIT" => Some("northnarrow-watchdog.service".to_string()),
            "MONITOR_SERVICE_RESULT" => Some("timeout".to_string()),
            "MONITOR_EXIT_CODE" => Some("exited".to_string()),
            "MONITOR_EXIT_STATUS" => Some("20".to_string()),
            "MONITOR_INVOCATION_ID" => Some("0123\nabcd".to_string()),
            _ => None,
        };
        let rec = unit_failure_record(vars, 4242, 1_800_000_000);
        assert_eq!(rec.reason, nn_proto::watchdog_hold::REASON_WATCHDOG_FAILED);
        assert_eq!(rec.agent_pid, 4242);
        for part in [
            "northnarrow-watchdog.service entered the failed state",
            "service_result=timeout",
            "exit_code=exited",
            "exit_status=20",
            "invocation_id=0123 abcd",
        ] {
            assert!(rec.detail.contains(part), "{part}: {}", rec.detail);
        }
        let bare = unit_failure_record(|_| None, 0, 0);
        assert!(
            bare.detail.contains("northnarrow-watchdog.service")
                && bare.detail.contains("systemd older than 251"),
            "{}",
            bare.detail
        );
        let cli = Cli::try_parse_from(["northnarrow-watchdog", "--record-unit-failure"]).unwrap();
        assert!(cli.record_unit_failure);
        assert!(
            !Cli::try_parse_from(["northnarrow-watchdog"])
                .unwrap()
                .record_unit_failure
        );
    }

    /// Static review C-44 / G-05: a stuck recovery that fails leaves a
    /// live agent alive and supervised — the verdict comes from the
    /// agent's own pidfd, and only an exit is a death. Here the recovery
    /// refuses a process that does not run the agent binary (no signal is
    /// sent); before, the loop evicted and respawned it all the same.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_recovery_of_a_live_agent_is_not_a_death() {
        let (mut child, pidfd) = spawn_sleep_child_and_open_pidfd();
        let dir = TempDir::new().unwrap();
        let r = stuck_recovery(
            child.id(),
            dir.path(),
            Duration::from_millis(50),
            Path::new("/bin/true"),
        )
        .await;
        assert!(r.is_err(), "not the agent: the recovery refuses it");
        assert_eq!(stuck_verdict(&pidfd), StuckVerdict::StillRunning);
        assert!(pidfd_signal(pidfd.as_raw_fd(), 0).is_ok(), "it still runs");
        let rec = stuck_recovery_failed_record(child.id(), &format!("{:#}", r.unwrap_err()), 1);
        assert_eq!(
            rec.reason,
            nn_proto::watchdog_hold::REASON_STUCK_RECOVERY_FAILED
        );
        assert!(rec.detail.contains("still protected"), "{}", rec.detail);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(stuck_verdict(&pidfd), StuckVerdict::Exited);
    }

    /// A process that ignores SIGINT is SIGKILLed, its exit awaited (within
    /// the bound) and confirmed before anything is evicted; an eviction that
    /// fails after the confirmed exit (no pinned map here) does not fail
    /// the recovery.
    #[tokio::test(flavor = "current_thread")]
    async fn a_recovery_confirms_the_exit_before_it_evicts() {
        let sleep_bin = std::fs::canonicalize("/bin/sleep").unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("trap '' INT; exec sleep 60")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_link(format!("/proc/{}/exe", child.id())).ok()
            != Some(sleep_bin.clone())
        {
            assert!(Instant::now() < deadline, "never exec'd sleep");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // SAFETY: pidfd_open returned this fd to us; we own it.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_open(child.id()).unwrap()) };
        let dir = TempDir::new().unwrap();
        stuck_recovery_with(
            child.id(),
            dir.path(),
            Duration::from_millis(100),
            Duration::from_secs(5),
            &sleep_bin,
        )
        .await
        .expect("SIGINT ignored, SIGKILL confirmed");
        assert_eq!(stuck_verdict(&pidfd), StuckVerdict::Exited);
        let _ = child.wait();
    }

    /// Static review C-44 / TD-08: an answer whose event-loop count does
    /// not move is a stall, and three in a row a stuck agent — though the
    /// socket answered. Moving counts, an older agent (not reported) and a
    /// loop not entered yet (0) are answers.
    #[test]
    fn a_loop_that_stands_still_is_stuck_though_the_socket_answers() {
        let at = |iterations| LoopProgress::Reported {
            iterations,
            since_last_ms: 31_000,
        };
        let mut t = StatusPingTracker::new();
        assert_eq!(t.record_answer(at(10)), PingOutcome::Ok, "the baseline");
        assert_eq!(t.record_answer(at(16)), PingOutcome::Ok, "it moved");
        assert_eq!(
            STATUS_PING_STALLED_STUCK_AFTER, 3,
            "at least 90 s without a round"
        );
        for consecutive in 1..STATUS_PING_STALLED_STUCK_AFTER {
            assert_eq!(
                t.record_answer(at(16)),
                PingOutcome::LoopStalled {
                    consecutive,
                    since_last_ms: 31_000
                }
            );
        }
        assert_eq!(
            t.record_answer(at(16)),
            PingOutcome::LoopStuck {
                pings: STATUS_PING_STALLED_STUCK_AFTER,
                since_last_ms: 31_000
            }
        );
        assert!(t.answered(), "the socket did answer");
        // a round ends the streak
        let mut t = StatusPingTracker::new();
        t.record_answer(at(5));
        assert!(matches!(
            t.record_answer(at(5)),
            PingOutcome::LoopStalled { .. }
        ));
        assert_eq!(t.record_answer(at(6)), PingOutcome::Ok);
        assert!(matches!(
            t.record_answer(at(6)),
            PingOutcome::LoopStalled { consecutive: 1, .. }
        ));
        // an older agent, and a loop not entered yet, never stall
        let mut t = StatusPingTracker::new();
        for _ in 0..5 {
            assert_eq!(t.record_answer(LoopProgress::Unreported), PingOutcome::Ok);
            assert_eq!(t.record_answer(at(0)), PingOutcome::Ok);
        }
        // the next agent starts without a baseline
        let mut t = StatusPingTracker::new();
        t.record_answer(at(9));
        t.reset();
        assert_eq!(t.record_answer(at(9)), PingOutcome::Ok);
        // an answer clears the timeouts, a stall does not count as one
        let mut t = StatusPingTracker::new();
        t.record_answer(at(3));
        assert_eq!(t.record_timeout(), PingOutcome::TimeoutOnce);
        assert!(matches!(
            t.record_answer(at(3)),
            PingOutcome::LoopStalled { .. }
        ));
        assert_eq!(t.consecutive_timeouts(), 0);
        assert_eq!(t.record_timeout(), PingOutcome::TimeoutOnce);
    }

    /// The ping asks for the loop progress on its connection after the
    /// status reply and returns the agent's count.
    #[tokio::test(flavor = "current_thread")]
    async fn the_ping_reads_the_loop_progress_after_the_status() {
        use nn_model::posture_types::PostureKind;
        use nn_proto::admin_protocol::{LoopProgressResponse, StatusResponse};
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("mock.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut asked = Vec::new();
            for reply in [
                AdminMessage::StatusResponse(StatusResponse::public(
                    PostureKind::Observing,
                    false,
                    None,
                    None,
                    None,
                )),
                AdminMessage::LoopProgressResponse(LoopProgressResponse {
                    iterations: 77,
                    since_last_ms: 1_500,
                }),
            ] {
                let mut header = [0u8; 4];
                stream.read_exact(&mut header).await.expect("read hdr");
                let mut req = vec![0u8; u32::from_be_bytes(header) as usize];
                stream.read_exact(&mut req).await.expect("read body");
                asked.push(req);
                stream
                    .write_all(&encode_frame(&reply).unwrap())
                    .await
                    .expect("write reply");
            }
            asked
        });
        let got = ping_agent_status(&socket, Duration::from_secs(2), Some(std::process::id()))
            .await
            .expect("ping");
        assert_eq!(
            got,
            LoopProgress::Reported {
                iterations: 77,
                since_last_ms: 1_500
            }
        );
        let asked = mock.await.unwrap();
        assert_eq!(asked[0], vec![2], "the unsigned Status first");
        assert_eq!(
            asked[1],
            encode_frame(&AdminMessage::LoopProgress(LoopProgressRequest {})).unwrap()[4..]
                .to_vec(),
            "then the progress query"
        );
    }

    /// The hold is bounded: retries after 10, 20, 40 minutes, then at most
    /// once an hour, counted across the holds of one watchdog.
    #[test]
    fn the_hold_retries_on_a_doubling_bounded_schedule() {
        let mut r = HoldRetry::new();
        let mut waits = Vec::new();
        for _ in 0..6 {
            waits.push(r.next_wait().as_secs() / 60);
            r.record();
        }
        assert_eq!(waits, [10, 20, 40, 60, 60, 60]);
        assert_eq!(r.retries(), 6);
        let mut r = HoldRetry::with(Duration::from_millis(5), Duration::from_millis(12));
        assert_eq!(r.next_wait(), Duration::from_millis(5));
        for _ in 0..40 {
            r.record();
        }
        assert_eq!(r.next_wait(), Duration::from_millis(12), "no overflow");
        let line = hold_status_line(
            "agent restart ceiling tripped",
            Duration::from_secs(125),
            Duration::from_secs(475),
        );
        assert!(
            line.starts_with("DEGRADED: agent restart ceiling tripped")
                && line.contains("holding for 125 s")
                && line.contains("next retry in 475 s"),
            "{line}"
        );
    }

    /// Static review C-43 / G-06: a missing `/run/northnarrow` is created
    /// 0700 by the watchdog, as the units declare it.
    #[test]
    fn a_missing_run_directory_is_created_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let run = dir.path().join("run").join("northnarrow");
        write_pidfile_atomic(&run.join("watchdog.pid"), 42).unwrap();
        let mode = std::fs::metadata(&run).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, RUN_DIR_MODE, "{mode:o}");
        assert_eq!(read_pid_from_file(&run.join("watchdog.pid")).unwrap(), 42);
    }
}
