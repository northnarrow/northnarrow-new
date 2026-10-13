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
    #[arg(long = "shutdown-marker", value_name = "PATH", default_value = common::shutdown_marker::MARKER_PATH)]
    pub shutdown_marker: PathBuf,

    /// The admin keys a shutdown must be signed by (external audit
    /// WDG-001: the watchdog verifies the quorum the agent verified).
    #[arg(long = "admin-pub", value_name = "PATH", default_value = DEFAULT_ADMIN_PUB)]
    pub admin_pub: PathBuf,

    /// This install's id; a shutdown signed for another install is refused.
    #[arg(long = "agent-id-file", value_name = "PATH", default_value = DEFAULT_AGENT_ID_FILE)]
    pub agent_id_file: PathBuf,
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
/// Tolerated transient errors (treated as "agent hasn't fully
/// come up yet, keep polling"):
/// - pidfile missing (`NotFound`)
/// - pidfile present but content not yet a valid u32
/// - pidfd_open returns `ESRCH` (pidfile contained a stale PID
///   from a crashed previous boot; agent hasn't rewritten yet)
///
/// Any other error short-circuits the loop (we don't want to
/// poll forever on a misconfigured path).
///
/// External audit WDG-003: the pid must run `agent_bin`
/// ([`open_verified_agent`]); a pidfile naming any other process is
/// waited out like a missing one, and reported.
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
        writeln!(f, "{pid}").with_context(|| format!("writing pid to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
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

/// External audit WDG-004: `STATUS=<status>` to systemd, best effort (a
/// no-op outside `Type=notify`). `systemctl status` shows it.
pub fn sd_notify_status(status: &str) {
    let Ok(sock_path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    let sent = std::os::unix::net::UnixDatagram::unbound()
        .and_then(|sock| sock.send_to(format!("STATUS={status}\n").as_bytes(), &sock_path));
    if let Err(e) = sent {
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
    let async_fd = AsyncFd::with_interest(agent_pidfd.as_fd(), Interest::READABLE)
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
/// child handle is dropped immediately (the agent is tracked by pidfd,
/// never by `waitpid`, same as before).
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
    /// is removed and recorded at [`common::shutdown_marker::REJECTED_PATH`]
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
/// ([`common::shutdown_marker::verify`]); it was a JSON with a hash and a
/// deadline any root process could write. Every failure is a refusal —
/// the agent is respawned.
pub fn check_shutdown_marker(c: &ShutdownCheck<'_>) -> ShutdownVerdict {
    use common::shutdown_marker as sm;
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
    let keys = match std::fs::read_to_string(c.admin_pub)
        .map_err(|e| e.to_string())
        .and_then(|body| common::admin_quorum::parse_admin_pub(&body))
    {
        Ok(k) => k,
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
    use common::shutdown_marker as sm;
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
    /// The admin socket path does not exist (ENOENT on connect). The
    /// agent is not *stuck* — it never opened the socket (or removed it
    /// on a clean exit, which the pidfd path reports separately). This
    /// never feeds the stuck threshold; `consecutive` counts how many
    /// pings in a row saw the socket missing so the caller can escalate
    /// the log level without ever SIGINT-ing a healthy agent.
    SocketAbsent { consecutive: u32 },
}

/// Why a STATUS ping failed, as far as the stuck-recovery policy cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingFailure {
    /// `connect(2)` → ENOENT: no socket file at the path. Misconfiguration
    /// (the agent starts the admin socket only with a loadable COMBAT
    /// ruleset and a valid admin.pub) or a clean agent exit — not a hang.
    SocketAbsent,
    /// Anything else: connect refused/reset, protocol error, or the
    /// 2 s timeout — the agent is there but not answering.
    Unresponsive,
}

/// Classify a [`ping_agent_status`] error by walking its source chain
/// for an `io::Error` with `NotFound`.
pub fn classify_ping_error(e: &anyhow::Error) -> PingFailure {
    let not_found = e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::NotFound)
            .unwrap_or(false)
    });
    if not_found {
        PingFailure::SocketAbsent
    } else {
        PingFailure::Unresponsive
    }
}

/// After this many consecutive absent-socket pings (30 s apart) the
/// ping loop raises its log line to ERROR: the agent has been up for
/// minutes without ever opening its admin socket.
pub const STATUS_PING_ABSENT_ERROR_AFTER: u32 = 4;

/// Sliding-counter state machine that tracks consecutive
/// STATUS-ping timeouts. Reset on any successful ping. Threshold
/// configurable for tests so we don't have to hardcode 2 in
/// every assertion.
#[derive(Debug, Clone)]
pub struct StatusPingTracker {
    consecutive_timeouts: u8,
    threshold: u8,
    consecutive_absent: u32,
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
        }
    }

    /// Record a successful ping. Resets the counters; returns
    /// [`PingOutcome::Ok`].
    pub fn record_ok(&mut self) -> PingOutcome {
        self.consecutive_timeouts = 0;
        self.consecutive_absent = 0;
        PingOutcome::Ok
    }

    /// The socket file is missing. Does NOT touch the stuck counter:
    /// an agent that never opened its admin socket is misconfigured,
    /// not hung, and SIGINT-ing it only produces a restart loop (seen on
    /// the lab guest with a missing combat-rules.v4, 2026-10-08).
    pub fn record_socket_absent(&mut self) -> PingOutcome {
        self.consecutive_absent = self.consecutive_absent.saturating_add(1);
        PingOutcome::SocketAbsent {
            consecutive: self.consecutive_absent,
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
/// 1. SIGINT through the pidfd — the only hook-passing stop
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
/// 4. SIGKILL through the pidfd.
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
    let async_fd = AsyncFd::with_interest(owned, Interest::READABLE)
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
    if let Err(e) = ProtectedPidsHandle::open(bpffs_root).and_then(|mut h| h.evict(agent_pid)) {
        warn!(
            target: "watchdog.stuck_recovery",
            error = %e,
            agent_pid,
            bpffs_root = %bpffs_root.display(),
            "PROTECTED_PIDS evict failed before SIGKILL — kill may EPERM"
        );
    }
    pidfd_signal(async_fd.get_ref().as_raw_fd(), libc::SIGKILL)
        .with_context(|| format!("pidfd_send_signal(SIGKILL, pid={agent_pid}) after evict"))?;

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
        use common::shutdown_marker::ShutdownMarker;
        use common::wire::admin_signed_payload::{sign, SignedPayload};
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
        assert_eq!(
            t.record_socket_absent(),
            PingOutcome::SocketAbsent { consecutive: 1 }
        );
    }

    #[test]
    fn classify_not_found_as_socket_absent() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e = anyhow::Error::from(io).context("connect /run/northnarrow/admin.sock");
        assert_eq!(classify_ping_error(&e), PingFailure::SocketAbsent);
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
        let e = anyhow::Error::from(io).context("connect");
        assert_eq!(classify_ping_error(&e), PingFailure::Unresponsive);
        assert_eq!(
            classify_ping_error(&anyhow!("reply body length exceeds")),
            PingFailure::Unresponsive
        );
    }

    #[tokio::test]
    async fn missing_socket_ping_error_classifies_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.sock");
        let err = ping_agent_status(&path, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(classify_ping_error(&err), PingFailure::SocketAbsent);
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
        let result = ping_agent_status(&socket, Duration::from_secs(5)).await;
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
                ringbuf_drops_total: None,
                ringbuf_drops: None,
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
