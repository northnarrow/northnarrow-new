//! `northnarrow-watchdog` — anti-tamper supervisor daemon (Tappa 7
//! task 6, Watchdog sprint W2).
//!
//! Thin clap dispatcher over the testable library surface in
//! [`northnarrow_watchdog`]. The W2 boot sequence:
//!
//! 1. Parse CLI.
//! 2. [`harden_self`] — `prctl(PR_SET_DUMPABLE, 0)` +
//!    `prctl(PR_SET_NAME, "northnarrow-wat")`.
//! 3. [`open_agent_pidfd_with_retry`] — block until the agent's
//!    pidfile exists and a `pidfd_open(2)` on its PID succeeds,
//!    capped at 30 s (design §F11).
//! 4. [`write_pidfile_atomic`] — publish the watchdog's own PID.
//! 5. [`sd_notify_ready`] — manual NOTIFY_SOCKET datagram so
//!    `Type=notify` units After=northnarrow-watchdog.service
//!    unblock.
//! 6. Wait for SIGTERM/SIGINT. On signal, close the pidfd, unlink
//!    the watchdog pidfile, return.
//!
//! Restart loop, layer-2 PROTECTED_PIDS evict, and the STATUS
//! ping land in W3/W4/W5.

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use northnarrow_watchdog::{
    evict_dead_agent, harden_self, log_tamper_suspected, open_agent_pidfd_with_retry,
    ping_agent_status, pidfd_open, read_pid_from_file, reinsert_new_agent_pid, sd_notify_ready,
    shutdown_was_authorised, spawn_agent, stuck_recovery, wait_for_agent_death,
    wait_for_new_agent_pid, write_pidfile_atomic, BackoffOutcome, Cli, PingOutcome,
    RestartBackoff, StatusPingTracker, PIDFD_OPEN_RETRY_DEADLINE, STATUS_PING_INTERVAL,
    STATUS_PING_TIMEOUT, STUCK_RECOVERY_HARDKILL_GRACE,
};

/// Path of the A8 shutdown-authorisation marker (Tappa 8 A7
/// design §10.3). Hardcoded — the watchdog and the agent agree
/// on this canonical location.
const SHUTDOWN_MARKER_PATH: &str = "/run/northnarrow/agent.shutdown_authorised";

/// Deadline budget for the post-respawn pidfile-readiness wait.
/// Same shape as W2's PIDFD_OPEN_RETRY_DEADLINE — the agent's
/// `attach()` + LSM hook attachment takes seconds on a cold
/// host. 30 s is generous.
const NEW_AGENT_PIDFILE_DEADLINE: Duration = Duration::from_secs(30);

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Single-source EnvFilter init mirroring the agent. RUST_LOG
    // env var still wins; default is "info" so the boot-sequence
    // log lines are visible without extra flags.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();

    let cli = Cli::parse();
    info!(
        target: "watchdog",
        agent_pidfile = %cli.agent_pidfile.display(),
        admin_socket = %cli.admin_socket.display(),
        pidfile = %cli.pidfile.display(),
        bpffs_root = %cli.bpffs_root.display(),
        "watchdog starting"
    );

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            warn!(error = %e, "watchdog exited with error");
            ExitCode::FAILURE
        }
    }
}

/// Body of the watchdog boot/wait/teardown cycle, extracted so
/// the binary surface stays a thin error→exit-code mapper.
async fn run(cli: Cli) -> Result<()> {
    harden_self().context("harden_self (prctl PR_SET_DUMPABLE + PR_SET_NAME)")?;

    // W4: persist the agent's argv for respawn (design §5.3
    // "first launch's argv is the canonical respawn command").
    // For this commit we capture the agent binary path from
    // the pidfile's `/proc/<pid>/exe` realpath + reconstruct
    // a minimal argv. Production deployment in W7 reads the
    // systemd `ExecStart=` via `systemctl show
    // northnarrow-agent.service --property=ExecStart` — this
    // build keeps the wiring straightforward by using the agent
    // binary's own `--pid-file` flag pointed at the same
    // pidfile path the watchdog reads.
    let agent_fd = open_agent_pidfd_with_retry(&cli.agent_pidfile, PIDFD_OPEN_RETRY_DEADLINE)
        .await
        .context("opening initial agent pidfd")?;
    let mut agent_pid = read_pid_from_file(&cli.agent_pidfile)
        .context("re-reading agent PID for layer-2 evict context")?;
    let agent_argv = match cli.agent_bin.as_deref() {
        Some(bin) => vec![
            bin.to_string_lossy().into_owned(),
            "--pid-file".to_string(),
            cli.agent_pidfile.to_string_lossy().into_owned(),
        ],
        None => derive_agent_argv(agent_pid, &cli.agent_pidfile)?,
    };

    let own_pid = std::process::id();
    write_pidfile_atomic(&cli.pidfile, own_pid)
        .with_context(|| format!("writing watchdog pidfile {}", cli.pidfile.display()))?;

    sd_notify_ready().context("sd_notify(READY=1)")?;

    info!(
        target: "watchdog",
        own_pid,
        agent_pid,
        bpffs_root = %cli.bpffs_root.display(),
        agent_bin = %agent_argv[0],
        argc = agent_argv.len(),
        "boot sequence complete — entering restart-backoff loop"
    );

    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut backoff = RestartBackoff::new();
    let mut agent_pidfd = unsafe { OwnedFd::from_raw_fd(agent_fd) };

    // W5: spawn the parallel STATUS-ping task. It pings the
    // agent's admin socket every STATUS_PING_INTERVAL (30s),
    // tracks consecutive timeouts, and on two-in-a-row sends
    // a Stuck signal via the channel. The main loop's select
    // arm below picks it up and runs the recovery sequence.
    //
    // Channel capacity 4 is generous — at most one stuck signal
    // per restart cycle, and the main loop drains before the
    // ping task can send a second. Buffer of 4 covers any
    // pathological burst without backpressure-blocking the
    // ping task.
    let (stuck_tx, mut stuck_rx) = tokio::sync::mpsc::channel::<()>(4);
    let ping_socket = cli.admin_socket.clone();
    let ping_handle = tokio::spawn(run_ping_loop(ping_socket, stuck_tx));

    // W4 restart loop. Each iteration:
    //   1. Park on {SIGTERM, SIGINT, agent pidfd POLLIN}
    //   2. On pidfd POLLIN: layer-2 evict, check shutdown marker,
    //      compute backoff, respawn, reinsert PROTECTED_PIDS,
    //      loop back
    //   3. On signal: break out cleanly
    //   4. On ceiling breach: log TAMPER, break out (watchdog
    //      stays alive after this; the loop exit + main exit
    //      handler logs `watchdog stopped`)
    'restart_loop: loop {
        let select_outcome = tokio::select! {
            _ = sigint.recv() => SelectOutcome::Signal("SIGINT"),
            _ = sigterm.recv() => SelectOutcome::Signal("SIGTERM"),
            result = wait_for_agent_death(agent_pidfd) => SelectOutcome::AgentDied(result),
            // W5 stuck-recovery arm: the parallel ping task has
            // observed two consecutive STATUS-ping timeouts and
            // decided the agent is wedged. Run the SIGINT →
            // grace → evict + SIGKILL sequence; the subsequent
            // pidfd POLLIN fires inside `stuck_recovery` (it
            // opens its own fresh pidfd), then we fall through
            // to the normal layer-2 evict + respawn path below.
            // We synthesise an `AgentDied(Ok(()))` outcome so
            // the existing match arm handles the rest.
            _ = stuck_rx.recv() => {
                warn!(
                    target: "watchdog.stuck_recovery",
                    agent_pid,
                    "STATUS-ping stuck signal received from ping task — running recovery"
                );
                let recovery = stuck_recovery(agent_pid, &cli.bpffs_root, STUCK_RECOVERY_HARDKILL_GRACE).await;
                if let Err(e) = recovery {
                    warn!(
                        target: "watchdog.stuck_recovery",
                        error = %e,
                        agent_pid,
                        "stuck_recovery failed — falling through to restart logic anyway"
                    );
                }
                SelectOutcome::AgentDied(Ok(()))
            }
        };

        match select_outcome {
            SelectOutcome::Signal(name) => {
                info!(target: "watchdog", signal = name, "shutting down");
                break 'restart_loop;
            }
            SelectOutcome::AgentDied(Err(e)) => {
                warn!(target: "watchdog.pidfd", error = %e, "pidfd wait failed — exiting");
                break 'restart_loop;
            }
            SelectOutcome::AgentDied(Ok(())) => {
                info!(
                    target: "watchdog.layer2_evict",
                    agent_pid,
                    "agent pidfd POLLIN — agent has exited; running layer-2 evict"
                );
                match evict_dead_agent(&cli.bpffs_root, agent_pid) {
                    Ok(report) => info!(
                        target: "watchdog.layer2_evict",
                        agent_pid = report.agent_pid,
                        latency_us = report.evict_latency.as_micros() as u64,
                        "layer-2 evict complete"
                    ),
                    Err(e) => warn!(
                        error = %e,
                        agent_pid,
                        bpffs_root = %cli.bpffs_root.display(),
                        "layer-2 evict failed; widens layer-1 race window but next agent will fire evict_stale_pids"
                    ),
                }

                // A8 shutdown-authorisation check per Watchdog
                // §13 Q4 resolution. If admin signed the
                // shutdown, the marker is on disk and we stand
                // down WITHOUT respawning.
                match shutdown_was_authorised(&PathBuf::from(SHUTDOWN_MARKER_PATH)) {
                    Ok(true) => {
                        info!(
                            target: "watchdog.shutdown_marker",
                            "admin-authorised shutdown observed — watchdog standing down (no respawn)"
                        );
                        // Best-effort marker cleanup: the agent
                        // wrote it, we honoured it, now remove
                        // it so the next agent boot doesn't
                        // inherit a stale "I was authorised"
                        // signal.
                        let _ = std::fs::remove_file(SHUTDOWN_MARKER_PATH);
                        break 'restart_loop;
                    }
                    Ok(false) => { /* unsigned exit — proceed with respawn */ }
                    Err(e) => {
                        // Per design §10.4 step 4: malformed
                        // marker is a TAMPERING signal. Log
                        // loudly + proceed with respawn AND
                        // count toward the ceiling (the bump
                        // happens naturally — the next
                        // `backoff.next_delay` call records
                        // this attempt).
                        warn!(
                            target: "watchdog.shutdown_marker",
                            error = %e,
                            path = SHUTDOWN_MARKER_PATH,
                            "shutdown marker exists but is malformed — treating as tampering signal"
                        );
                    }
                }

                // Backoff state machine — compute the per-attempt
                // delay AND detect the per-window ceiling.
                let now = Instant::now();
                let outcome = backoff.next_delay(now);
                let (delay, attempt) = match outcome {
                    BackoffOutcome::Wait { delay, attempt } => (delay, attempt),
                    BackoffOutcome::CeilingExceeded {
                        attempts_in_window,
                        window,
                    } => {
                        log_tamper_suspected(attempts_in_window, window);
                        break 'restart_loop;
                    }
                };

                if !delay.is_zero() {
                    info!(
                        target: "watchdog.respawn",
                        attempt,
                        delay_ms = delay.as_millis() as u64,
                        "backing off before respawn"
                    );
                    if let Some(reason) = sleep_or_signal(delay, &mut sigint, &mut sigterm).await
                    {
                        info!(target: "watchdog", signal = reason, "shutting down during backoff");
                        break 'restart_loop;
                    }
                }

                // Best-effort: remove the dead agent's pidfile
                // BEFORE respawn so `wait_for_new_agent_pid`
                // doesn't immediately read the dead PID.
                let _ = std::fs::remove_file(&cli.agent_pidfile);

                match respawn_cycle(&agent_argv, &cli.agent_pidfile, &cli.bpffs_root, attempt)
                    .await
                {
                    Ok((new_pid, new_fd)) => {
                        agent_pid = new_pid;
                        agent_pidfd = new_fd;
                        info!(
                            target: "watchdog.respawn",
                            attempt,
                            new_pid,
                            "respawn cycle complete — watching new pidfd"
                        );
                    }
                    Err(e) => {
                        warn!(
                            target: "watchdog.respawn",
                            attempt,
                            error = %e,
                            "respawn cycle failed — counting toward ceiling, continuing loop"
                        );
                        // The failed attempt already incremented
                        // `backoff`'s sliding-window count (we
                        // called `next_delay` above). The next
                        // pidfd POLLIN... but we don't HAVE a new
                        // pidfd to wait on. Fall through: the
                        // `loop` runs again, signal-arm catches
                        // operator stops, and pidfd wait would
                        // immediately fail. Exit instead.
                        break 'restart_loop;
                    }
                }
            }
        }
    }

    // Best-effort pidfile cleanup. Crash paths deliberately leave
    // the file STALE; readers must re-confirm via /proc/<pid>.
    if cli.pidfile.exists() {
        if let Err(e) = std::fs::remove_file(&cli.pidfile) {
            warn!(
                error = %e,
                path = %cli.pidfile.display(),
                "pidfile cleanup failed on shutdown (left stale)"
            );
        }
    }

    // Abort the ping task so it doesn't outlive the main loop
    // (cleaner shutdown for journald logs).
    ping_handle.abort();

    info!(target: "watchdog", "watchdog stopped");
    Ok(())
}

/// Internal select-arm outcome — folds the three branches of the
/// W4 main loop into one match.
enum SelectOutcome {
    Signal(&'static str),
    AgentDied(Result<()>),
}

/// Reconstruct the agent's argv from its running PID. For W4
/// without systemd `ExecStart=` introspection (that lands in
/// W7), we capture the binary path from `/proc/<pid>/exe`
/// realpath + emit a minimal `--pid-file` argv so the respawned
/// agent writes to the same pidfile we'll wait on. Future W7
/// commit reads the systemd unit's actual ExecStart.
fn derive_agent_argv(agent_pid: u32, pidfile: &std::path::Path) -> Result<Vec<String>> {
    let exe = std::fs::read_link(format!("/proc/{agent_pid}/exe"))
        .with_context(|| format!("reading /proc/{agent_pid}/exe for argv reconstruction"))?;
    let bin = exe.to_string_lossy().into_owned();
    Ok(vec![
        bin,
        "--pid-file".to_string(),
        pidfile.to_string_lossy().into_owned(),
    ])
}

/// One full respawn cycle: spawn the agent, wait for its
/// pidfile, open a new pidfd, defensive-reinsert the new PID
/// into PROTECTED_PIDS. Returns the new PID + the new pidfd
/// for the main loop's next select-arm.
async fn respawn_cycle(
    argv: &[String],
    pidfile: &std::path::Path,
    bpffs_root: &std::path::Path,
    attempt: u8,
) -> Result<(u32, OwnedFd)> {
    info!(
        target: "watchdog.respawn",
        attempt,
        bin = %argv[0],
        "spawning agent"
    );
    let child = spawn_agent(argv)?;
    // We don't await `child.wait()` — the parent watchdog
    // observes death via the new pidfd, NOT via waitpid. The
    // `Child` handle drops at function end; that doesn't kill
    // the spawned process (Rust's `Child::drop` is a no-op on
    // Unix). systemd would normally reap, but with `Restart=no`
    // on the agent unit + the agent being a forked subprocess
    // of the watchdog, the watchdog inherits the role. For W4
    // we accept that a child that exits BEFORE we open its
    // pidfd will become a zombie; W5 (stuck-agent recovery)
    // adds the reaping path.
    std::mem::drop(child);

    let new_pid = wait_for_new_agent_pid(pidfile, NEW_AGENT_PIDFILE_DEADLINE).await?;

    let raw = pidfd_open(new_pid)
        .with_context(|| format!("pidfd_open({new_pid}) for respawned agent"))?;
    // SAFETY: pidfd_open returned this fd to us; we own it.
    let new_fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Defensive reinsert. Failure here just widens the brief
    // window before the new agent's own register_protected_pids
    // fires — not a fatal restart-cycle error.
    if let Err(e) = reinsert_new_agent_pid(bpffs_root, new_pid) {
        warn!(
            target: "watchdog.respawn",
            error = %e,
            new_pid,
            bpffs_root = %bpffs_root.display(),
            "defensive PROTECTED_PIDS reinsert failed; agent's own register will retry shortly"
        );
    }

    Ok((new_pid, new_fd))
}

/// Sleep `delay`, but bail early if SIGTERM/SIGINT fires —
/// returns Some(name) on signal, None on natural sleep
/// completion. Without this an operator-issued
/// `systemctl stop northnarrow-watchdog` while we're backing
/// off for 800 ms could miss the signal.
async fn sleep_or_signal(
    delay: Duration,
    sigint: &mut Signal,
    sigterm: &mut Signal,
) -> Option<&'static str> {
    tokio::select! {
        _ = tokio::time::sleep(delay) => None,
        _ = sigint.recv() => Some("SIGINT"),
        _ = sigterm.recv() => Some("SIGTERM"),
    }
}

/// W5 STATUS-ping loop. Runs as a parallel tokio task spawned
/// at boot; pings the agent's admin socket every
/// `STATUS_PING_INTERVAL` (30 s), tracks consecutive timeouts
/// via `StatusPingTracker`, and on `StuckDetected` (two-in-a-row)
/// sends a single message on `stuck_tx` to wake the main loop's
/// recovery arm.
///
/// On send failure (the main loop has exited and dropped the
/// receiver), this loop exits cleanly — there's no point in
/// continuing to ping when nobody is listening.
///
/// After signalling Stuck, the tracker is reset so the next
/// respawned agent gets a fresh ping budget. If the new agent
/// never comes up, the next cycle of timeouts will trigger
/// another stuck signal — but in practice the W4 restart loop
/// will hit its 5-in-60s ceiling first and break out, dropping
/// the channel and stopping this task.
async fn run_ping_loop(socket_path: PathBuf, stuck_tx: tokio::sync::mpsc::Sender<()>) {
    let mut tick = tokio::time::interval(STATUS_PING_INTERVAL);
    // `interval()` fires immediately on first tick — skip that
    // so the watchdog isn't immediately pinging the agent
    // mid-boot (before the agent's admin socket is even bound).
    tick.tick().await;

    let mut tracker = StatusPingTracker::new();
    loop {
        tick.tick().await;
        let outcome = match ping_agent_status(&socket_path, STATUS_PING_TIMEOUT).await {
            Ok(()) => tracker.record_ok(),
            Err(e) => {
                warn!(
                    target: "watchdog.status_ping",
                    error = %e,
                    socket = %socket_path.display(),
                    consecutive = tracker.consecutive_timeouts(),
                    "STATUS ping failed"
                );
                tracker.record_timeout()
            }
        };
        match outcome {
            PingOutcome::Ok | PingOutcome::TimeoutOnce => {}
            PingOutcome::StuckDetected => {
                warn!(
                    target: "watchdog.status_ping",
                    consecutive = tracker.consecutive_timeouts(),
                    "STATUS ping threshold tripped — signalling main loop for stuck recovery"
                );
                tracker.reset();
                if stuck_tx.send(()).await.is_err() {
                    // Main loop has dropped the receiver. Exit
                    // cleanly — no listener.
                    info!(
                        target: "watchdog.status_ping",
                        "main loop dropped stuck channel; ping task exiting"
                    );
                    return;
                }
            }
        }
    }
}

// `FromRawFd` is brought in at the top of this file alongside
// `IntoRawFd` so both trait-method call sites resolve. The
// `IntoRawFd` import is kept for forward-compat with W4's
// AgentGuard pattern (it'll consume + re-wrap raw fds for child
// process inheritance during agent respawn).
#[allow(dead_code, reason = "IntoRawFd is used by W4's respawn path; kept in scope here for forward-compat")]
fn _trait_anchor() {
    let _: fn(OwnedFd) -> i32 = |fd| fd.into_raw_fd();
}
