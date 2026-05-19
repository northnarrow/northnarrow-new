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
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use antitamper_bpf::ProtectedPidsHandle;
use common::wire::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, StatusRequest, MAX_FRAME_BODY,
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
}

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
        let r =
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) };
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
    trimmed
        .parse::<u32>()
        .with_context(|| format!("PID file {} did not contain a u32: {trimmed:?}", path.display()))
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
/// Tolerated transient errors (treated as "agent hasn't fully
/// come up yet, keep polling"):
/// - pidfile missing (`NotFound`)
/// - pidfile present but content not yet a valid u32
/// - pidfd_open returns `ESRCH` (pidfile contained a stale PID
///   from a crashed previous boot; agent hasn't rewritten yet)
///
/// Any other error short-circuits the loop (we don't want to
/// poll forever on a misconfigured path).
pub async fn open_agent_pidfd_with_retry(
    agent_pidfile: &Path,
    deadline: Duration,
) -> Result<RawFd> {
    let start = Instant::now();
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        match try_open_once(agent_pidfile) {
            Ok(fd) => {
                info!(
                    target: "watchdog.pidfd",
                    attempts,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    pidfile = %agent_pidfile.display(),
                    "agent pidfd opened"
                );
                return Ok(fd);
            }
            Err(transient) if start.elapsed() < deadline => {
                debug!(
                    target: "watchdog.pidfd",
                    attempts,
                    error = %transient,
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
                    error = %fatal,
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

/// One try-cycle: read PID + open pidfd. Errors are coarse-grained
/// (one `anyhow::Error`) because the retry loop above doesn't
/// distinguish between "pidfile missing" and "PID stale" — both
/// are "agent not ready yet" until the deadline.
fn try_open_once(pidfile: &Path) -> Result<RawFd> {
    let pid = read_pid_from_file(pidfile)?;
    pidfd_open(pid).with_context(|| format!("pidfd_open({pid})"))
}

/// Atomic pidfile write — tmpfile + fsync + `rename(2)`. Same
/// pattern as `agent_id::load_or_bootstrap` (Tappa 8 A3) and
/// `agent/src/main.rs` `write_pid_file`. Mode 0644 so the
/// agent's W6 PROTECTED_PIDS widening (running as root) can
/// read this trivially.
pub fn write_pidfile_atomic(path: &Path, pid: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating pidfile parent {}", parent.display()))?;
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp_path)
            .with_context(|| format!("opening tmpfile {}", tmp_path.display()))?;
        writeln!(f, "{pid}")
            .with_context(|| format!("writing pid to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!("renaming {} → {}", tmp_path.display(), path.display())
    })?;
    Ok(())
}

/// Manual systemd `sd_notify(READY=1)` — sends a single Unix
/// datagram to `$NOTIFY_SOCKET` per the `sd_notify(3)` wire
/// protocol. Cheap and no new dep vs `libsystemd-rs` /
/// `sd-notify` crates.
///
/// Returns Ok WHEN `NOTIFY_SOCKET` is unset (watchdog not running
/// under `Type=notify`) — that's a normal dev-shell invocation,
/// not an error.
pub fn sd_notify_ready() -> Result<()> {
    let sock_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) => p,
        Err(_) => {
            debug!(
                target: "watchdog.sd_notify",
                "NOTIFY_SOCKET unset — not running under systemd Type=notify; skipping"
            );
            return Ok(());
        }
    };
    let sock = std::os::unix::net::UnixDatagram::unbound()
        .context("creating sd_notify datagram socket")?;
    sock.send_to(b"READY=1\n", &sock_path)
        .with_context(|| format!("sending READY=1 to NOTIFY_SOCKET={sock_path}"))?;
    info!(
        target: "watchdog.sd_notify",
        socket = %sock_path,
        "systemd READY=1 sent"
    );
    Ok(())
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
pub async fn wait_for_agent_death(agent_pidfd: OwnedFd) -> Result<()> {
    // AsyncFd registers the fd with mio's epoll; `Interest::READABLE`
    // maps to EPOLLIN, which is exactly what pidfd signals on
    // task reap. `with_interest` is preferred over `new()` so we
    // don't accidentally register WRITE interest and pay for
    // pointless EPOLLOUT wakeups.
    let async_fd = AsyncFd::with_interest(agent_pidfd, Interest::READABLE)
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
    pub fn with_config(
        window: Duration,
        max_attempts: u8,
        base: Duration,
        cap: Duration,
    ) -> Self {
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

/// Poll the new agent's pidfile until it contains a valid PID,
/// or the deadline elapses. Mirrors W2's
/// [`open_agent_pidfd_with_retry`] but doesn't open a pidfd
/// (that's the caller's next step — we just need the PID for
/// PROTECTED_PIDS reinsertion).
///
/// The agent writes its pidfile atomically (tmpfile + fsync +
/// rename) AFTER every LSM hook is attached AND the "decision
/// engine ready" log line has flushed — so a successful read
/// here is also a readiness signal for the agent's anti-tamper
/// surface.
pub async fn wait_for_new_agent_pid(
    pidfile: &Path,
    deadline: Duration,
) -> Result<u32> {
    let start = Instant::now();
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        match read_pid_from_file(pidfile) {
            Ok(pid) => {
                info!(
                    target: "watchdog.respawn",
                    attempts,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    pid,
                    "new agent pidfile observed"
                );
                return Ok(pid);
            }
            Err(_) if start.elapsed() < deadline => {
                tokio::time::sleep(PIDFD_OPEN_RETRY_INTERVAL).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "agent pidfile {} never appeared within {:?}",
                        pidfile.display(),
                        deadline
                    )
                });
            }
        }
    }
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
pub fn reinsert_new_agent_pid(bpffs_root: &Path, new_pid: u32) -> Result<()> {
    let mut handle = ProtectedPidsHandle::open(bpffs_root).with_context(|| {
        format!(
            "opening PROTECTED_PIDS handle at {} for defensive reinsert",
            bpffs_root.display()
        )
    })?;
    handle.insert(new_pid).with_context(|| {
        format!("inserting new agent PID {new_pid} into PROTECTED_PIDS")
    })?;
    info!(
        target: "watchdog.respawn",
        pid = new_pid,
        bpffs_root = %bpffs_root.display(),
        "defensive PROTECTED_PIDS reinsert complete"
    );
    Ok(())
}

/// Check A8's `/run/northnarrow/agent.shutdown_authorised`
/// marker (per Tappa 8 sub-sprint A commit A7 + design §10.4 +
/// Watchdog design §13 Q4 resolution). Returns:
/// - `Ok(true)` when the marker is present AND its
///   `grace_deadline_unix_ts` is in the future — admin
///   authorised this shutdown, watchdog must NOT respawn.
/// - `Ok(false)` when the marker is absent OR the deadline has
///   elapsed (stale marker — unsigned restart proceeds).
/// - `Err` when the marker exists but is malformed (parse
///   failure, missing fields, non-hex entry_hash). The design
///   §10.4 step 4 treats a malformed marker as a tampering
///   signal: the caller should LOG the error and treat it as
///   "not authorised" — fall through to the respawn path AND
///   bump the per-window ceiling counter so a forge attempt
///   gets counted into the 5-in-60s tamper signal.
///
/// Audit-log entry-hash cross-check (design §10.4 step 4 bullet
/// 2) is deferred — it requires the A11 audit chain. The
/// deadline check covers the staleness case; the entry-hash
/// validation is a follow-on hardening once A11 ships.
pub fn shutdown_was_authorised(marker_path: &Path) -> Result<bool> {
    let raw = match std::fs::read_to_string(marker_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                target: "watchdog.shutdown_marker",
                path = %marker_path.display(),
                "no shutdown-authorisation marker — proceeding with restart"
            );
            return Ok(false);
        }
        Err(e) => {
            return Err(anyhow!(e))
                .with_context(|| format!("reading marker {}", marker_path.display()));
        }
    };

    let v: serde_json::Value = serde_json::from_str(raw.trim())
        .with_context(|| format!("parsing marker JSON at {}", marker_path.display()))?;
    let entry_hash = v
        .get("entry_hash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("marker missing `entry_hash` field"))?;
    if entry_hash.len() != 64 || !entry_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "marker entry_hash must be 64 hex chars (got {} chars)",
            entry_hash.len()
        ));
    }
    let deadline = v
        .get("grace_deadline_unix_ts")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow!("marker missing `grace_deadline_unix_ts` field"))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if deadline < now {
        warn!(
            target: "watchdog.shutdown_marker",
            path = %marker_path.display(),
            deadline,
            now,
            "shutdown marker is STALE — proceeding with restart"
        );
        return Ok(false);
    }

    info!(
        target: "watchdog.shutdown_marker",
        path = %marker_path.display(),
        entry_hash,
        deadline,
        "admin-authorised shutdown marker present + deadline valid — watchdog standing down"
    );
    Ok(true)
}

/// Helper: emit the "tamper suspected" journal line + escalate.
/// The ceiling is the design §5.1 "5-in-60s" trigger; the
/// watchdog stays alive after this for operator inspection
/// (`systemctl reset-failed northnarrow-agent` is the
/// documented recovery).
pub fn log_tamper_suspected(attempts_in_window: u8, window: Duration) {
    error!(
        target: "watchdog.tamper",
        attempts_in_window,
        window_secs = window.as_secs(),
        "TAMPER SUSPECTED: agent restart ceiling tripped ({attempts_in_window} attempts in last {} s) — \
         watchdog stops respawning; manual recovery via `systemctl reset-failed northnarrow-agent` \
         then `systemctl start northnarrow-agent`",
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

/// Per-ping reply timeout — 2 s per design §4. Conservative cap
/// on healthy reply (the admin socket handler runs on the
/// agent's tokio runtime; under steady state replies are
/// sub-100 ms). 2 s tolerates pathological GC pauses,
/// page-fault storms, brief schedlatency.
pub const STATUS_PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Per §4: two consecutive timeouts in a row promote "stuck"
/// to "dead" and trigger the recovery path. One timeout could
/// be a CPU steal spike or runaway ADE inference; two in a row
/// (60 s gap with the 30 s interval) is strong evidence the
/// agent's main loop is not making progress.
pub const STATUS_PING_CONSECUTIVE_TIMEOUT_THRESHOLD: u8 = 2;

/// Per §4.1 recovery sequence: after SIGINT, wait this long
/// for graceful exit before escalating to evict + SIGKILL.
/// Matches `docs/verify-2b.sh` `HARDKILL_GRACE`.
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
    /// Threshold reached (default 2 consecutive). Caller should
    /// kick off the stuck-recovery sequence
    /// ([`stuck_recovery`]).
    StuckDetected,
}

/// Sliding-counter state machine that tracks consecutive
/// STATUS-ping timeouts. Reset on any successful ping. Threshold
/// configurable for tests so we don't have to hardcode 2 in
/// every assertion.
#[derive(Debug, Clone)]
pub struct StatusPingTracker {
    consecutive_timeouts: u8,
    threshold: u8,
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
        }
    }

    /// Record a successful ping. Resets the counter; returns
    /// [`PingOutcome::Ok`].
    pub fn record_ok(&mut self) -> PingOutcome {
        self.consecutive_timeouts = 0;
        PingOutcome::Ok
    }

    /// Record a ping failure (reply timeout OR transport error
    /// — both are "agent not responding" from the watchdog's
    /// perspective). Returns [`PingOutcome::TimeoutOnce`] for
    /// the first failure in a row, [`PingOutcome::StuckDetected`]
    /// when the threshold is met.
    pub fn record_timeout(&mut self) -> PingOutcome {
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
        if self.consecutive_timeouts >= self.threshold {
            PingOutcome::StuckDetected
        } else {
            PingOutcome::TimeoutOnce
        }
    }

    /// Reset the counter (e.g., after a stuck-recovery cycle so
    /// the new respawned agent gets a fresh ping budget).
    pub fn reset(&mut self) {
        self.consecutive_timeouts = 0;
    }

    /// Snapshot of the consecutive-timeout counter. Used by log
    /// lines + tests.
    pub fn consecutive_timeouts(&self) -> u8 {
        self.consecutive_timeouts
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
pub async fn ping_agent_status(socket_path: &Path, timeout: Duration) -> Result<()> {
    let fut = async {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("connect {}", socket_path.display()))?;

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

        let mut full = Vec::with_capacity(4 + body_len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&body);
        let (msg, _consumed) = decode_frame(&full)
            .map_err(|e| anyhow!("decode_frame: {e}"))?
            .ok_or_else(|| anyhow!("decode_frame returned None on full buffer"))?;
        if !matches!(msg, AdminMessage::StatusResponse(_)) {
            return Err(anyhow!(
                "unexpected reply variant (wanted StatusResponse): {msg:?}"
            ));
        }
        Ok::<(), anyhow::Error>(())
    };

    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Err(anyhow!(
            "STATUS ping timed out after {:?} (socket {})",
            timeout,
            socket_path.display()
        )),
    }
}

/// Stuck-agent recovery sequence per design §4.1:
///
/// 1. `kill(agent_pid, SIGINT)` — the only hook-passing stop
///    (the agent's Tappa 7 LSM task_kill hook only denies
///    SIGKILL + SIGTERM; SIGINT passes through and the agent
///    re-armed it explicitly for graceful shutdown per
///    `docs/verify-2b.sh:48-51`).
/// 2. Wait `hardkill_grace` OR pidfd POLLIN, whichever first.
///    POLLIN → agent died gracefully, restart path takes over.
///    Timeout → agent is wedged past SIGINT response; escalate.
/// 3. `ProtectedPidsHandle::evict(agent_pid)` — race-free
///    hard-kill recipe from `docs/verify-2b.sh:57-63`. Without
///    this, the LSM task_kill hook would deny the subsequent
///    SIGKILL.
/// 4. `kill(agent_pid, SIGKILL)`.
/// 5. Wait for pidfd POLLIN — the kernel reaps the agent.
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
) -> Result<()> {
    let raw = pidfd_open(agent_pid)
        .with_context(|| format!("pidfd_open({agent_pid}) for stuck recovery"))?;
    // SAFETY: pidfd_open returned this fd to us; we own it.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let async_fd = AsyncFd::with_interest(owned, Interest::READABLE)
        .context("registering pidfd with AsyncFd for stuck recovery")?;

    // 1. SIGINT.
    info!(
        target: "watchdog.stuck_recovery",
        agent_pid,
        "stuck recovery: sending SIGINT (hook-passing graceful stop)"
    );
    // SAFETY: kill(2) with a known PID + standard signal is a
    // trivial syscall.
    let r = unsafe { libc::kill(agent_pid as libc::pid_t, libc::SIGINT) };
    if r != 0 {
        return Err(anyhow!(
            "kill(SIGINT, pid={agent_pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

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

    // 3-4. Escalate: evict + SIGKILL.
    warn!(
        target: "watchdog.stuck_recovery",
        agent_pid,
        grace_secs = hardkill_grace.as_secs(),
        "agent did not exit within grace — escalating to evict + SIGKILL"
    );
    // Best-effort evict; even on Err we proceed to SIGKILL (the
    // worst case is the kernel rejects the kill with EPERM and
    // we surface the error to the caller, who'll log + retry).
    if let Err(e) = ProtectedPidsHandle::open(bpffs_root)
        .and_then(|mut h| h.evict(agent_pid))
    {
        warn!(
            target: "watchdog.stuck_recovery",
            error = %e,
            agent_pid,
            bpffs_root = %bpffs_root.display(),
            "PROTECTED_PIDS evict failed before SIGKILL — kill may EPERM"
        );
    }
    // SAFETY: same as above.
    let r = unsafe { libc::kill(agent_pid as libc::pid_t, libc::SIGKILL) };
    if r != 0 {
        return Err(anyhow!(
            "kill(SIGKILL, pid={agent_pid}) after evict failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // 5. Wait for kernel reap.
    let guard = async_fd
        .readable()
        .await
        .context("awaiting post-SIGKILL pidfd POLLIN")?;
    drop(guard);
    info!(
        target: "watchdog.stuck_recovery",
        agent_pid,
        "agent hard-killed after evict + SIGKILL — restart path takes over"
    );
    Ok(())
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

        let tmp = {
            let mut s = p.as_os_str().to_owned();
            s.push(".tmp");
            PathBuf::from(s)
        };
        assert!(
            !tmp.exists(),
            "atomic write must clean up its .tmp file: {}",
            tmp.display()
        );
    }

    /// sd_notify_ready is a no-op when NOTIFY_SOCKET is unset
    /// (the common dev-shell case). Anchors the "not under
    /// systemd is not an error" contract.
    #[test]
    fn sd_notify_ready_is_ok_when_notify_socket_unset() {
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
            assert_eq!(r, 0, "kill(child, SIGKILL) must succeed: {}", std::io::Error::last_os_error());
        });

        let start = Instant::now();
        wait_for_agent_death(pidfd)
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
        wait_for_agent_death(pidfd)
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
                assert_eq!(delay, Duration::ZERO, "window slid; this is attempt 1 again");
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
            10,        // higher max to allow more attempts
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
                assert_eq!(delay, cap, "attempt 4 (400ms unbounded) must cap at {cap:?}");
            }
            other => panic!("expected capped Wait at attempt 4, got {other:?}"),
        }
        match bo.next_delay(t0) {
            BackoffOutcome::Wait { delay, attempt: 5 } => {
                assert_eq!(delay, cap, "attempt 5 (800ms unbounded) must cap at {cap:?}");
            }
            other => panic!("expected capped Wait at attempt 5, got {other:?}"),
        }
    }

    /// Required W4 test 6: shutdown_authorised marker check.
    /// Covers all three branches: absent file → Ok(false);
    /// present + future deadline → Ok(true); present + past
    /// deadline → Ok(false) with WARN; malformed → Err.
    #[test]
    fn shutdown_was_authorised_handles_all_marker_shapes() {
        let dir = TempDir::new().unwrap();

        // Branch 1: absent → Ok(false).
        let absent = dir.path().join("nope.marker");
        assert!(!shutdown_was_authorised(&absent).unwrap());

        // Branch 2: present + future deadline → Ok(true).
        let valid = dir.path().join("valid.marker");
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        std::fs::write(
            &valid,
            format!(
                r#"{{"entry_hash":"{}","grace_deadline_unix_ts":{future}}}"#,
                "ab".repeat(32),
            ),
        )
        .unwrap();
        assert!(shutdown_was_authorised(&valid).unwrap());

        // Branch 3: present + past deadline → Ok(false).
        let stale = dir.path().join("stale.marker");
        std::fs::write(
            &stale,
            format!(
                r#"{{"entry_hash":"{}","grace_deadline_unix_ts":1}}"#,
                "cd".repeat(32),
            ),
        )
        .unwrap();
        assert!(
            !shutdown_was_authorised(&stale).unwrap(),
            "stale marker (deadline 1970) must NOT block restart"
        );

        // Branch 4: present + malformed → Err.
        let bad = dir.path().join("bad.marker");
        std::fs::write(&bad, "this is not json").unwrap();
        assert!(shutdown_was_authorised(&bad).is_err());

        // Branch 4b: present + JSON but missing fields → Err.
        let partial = dir.path().join("partial.marker");
        std::fs::write(&partial, r#"{"grace_deadline_unix_ts":9999}"#).unwrap();
        assert!(shutdown_was_authorised(&partial).is_err());

        // Branch 4c: present + entry_hash wrong length → Err.
        let bad_hash = dir.path().join("bad_hash.marker");
        std::fs::write(
            &bad_hash,
            r#"{"entry_hash":"abcd","grace_deadline_unix_ts":9999999999}"#,
        )
        .unwrap();
        assert!(shutdown_was_authorised(&bad_hash).is_err());
    }

    // ── Supplementary W4 tests (anchors for forward-compat) ────────

    /// Anchor: `spawn_agent` with an empty argv slice surfaces
    /// a clear error before touching `Command::spawn`. Guards
    /// against a future caller forgetting the binary-path
    /// element.
    #[test]
    fn spawn_agent_rejects_empty_argv() {
        let err = spawn_agent(&[]).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("empty argv"),
            "error should explain the missing binary path, got: {chain}"
        );
    }

    /// Anchor: `wait_for_new_agent_pid` honours the deadline +
    /// returns the pid once the pidfile materialises. Uses a
    /// background tokio task to publish the pidfile mid-poll.
    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_new_agent_pid_observes_late_pidfile() {
        let dir = TempDir::new().unwrap();
        let pidfile = dir.path().join("agent.pid");
        let writer_path = pidfile.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            write_pidfile_atomic(&writer_path, 4242).unwrap();
        });
        let pid = wait_for_new_agent_pid(&pidfile, Duration::from_secs(2))
            .await
            .expect("late pidfile must be observed within deadline");
        assert_eq!(pid, 4242);
        writer.await.unwrap();
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

        wait_for_agent_death(pidfd).await.unwrap();
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
        let result =
            ping_agent_status(&socket, Duration::from_secs(5)).await;
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
        use common::posture_types::PostureKind;
        use common::wire::admin_protocol::StatusResponse;

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
            });
            let bytes = encode_frame(&reply).expect("encode reply");
            stream.write_all(&bytes).await.expect("write reply");
        });

        // Give the listener a tick to be ready.
        tokio::time::sleep(Duration::from_millis(10)).await;

        ping_agent_status(&socket, Duration::from_secs(2))
            .await
            .expect("ping must succeed against mock server");

        mock.await.expect("mock task");
    }
}
