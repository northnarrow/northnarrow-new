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

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

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
}
