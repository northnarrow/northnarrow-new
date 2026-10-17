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

use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use northnarrow_watchdog::{
    agent_argv_from_proc, classify_ping_error, hold_record_path, off_runtime, ping_ticker,
    record_hold, respawn_agent_off_runtime, select_backend, systemctl_unit_state,
    systemd_is_booted, PingFailure, RespawnBackend, STATUS_PING_ABSENT_ERROR_AFTER,
    SYSTEMD_RUNTIME_DIR, UNIT_STATE_TIMEOUT,
};
use northnarrow_watchdog::{
    check_shutdown_marker, evict_dead_agent, harden_self, hold_until_agent_returns,
    log_tamper_suspected, open_agent_pidfd_with_retry, pidfd_exited, ping_agent_status,
    process_start_unix, register_self_pid, reinsert_new_agent_pid, sd_notify_ready,
    sd_notify_status, stuck_recovery, unregister_self_pid, wait_for_agent_death,
    write_pidfile_atomic, BackoffOutcome, Cli, HoldOutcome, PingOutcome, RestartBackoff,
    ShutdownCheck, ShutdownVerdict, StatusPingTracker, DEFAULT_AGENT_BIN, HOLD_POLL,
    PIDFD_OPEN_RETRY_DEADLINE, STATUS_PING_INTERVAL, STATUS_PING_TIMEOUT,
    STUCK_RECOVERY_HARDKILL_GRACE,
};

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
    // A write to a closed log stream (journald@northnarrow stopped) must
    // not abort the watchdog: the fmt layer's own error report is an
    // `eprintln!` that panics on the same broken pipe (panic = "abort").
    // External audit Wave 3 (journal line injection, lab PR 167): one
    // event is one journal line, as in the agent (common::log_escape).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(common::log_escape::stdout_ansi())
        .with_writer(common::log_escape::stdout_one_line)
        .log_internal_errors(false)
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
    // External audit WDG-003: the agent is the process the pidfile names
    // only if it runs the agent binary. Checking that reads the agent's
    // /proc/<pid>/exe, which its ptrace_access_check hook allows only to a
    // protected caller: register first (see register_self_pid below).
    let agent_bin = cli
        .agent_bin
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_BIN));
    let own_pid = std::process::id();
    let self_registered = register_self_pid(&cli.bpffs_root, own_pid);
    let (mut agent_pid, mut agent_pidfd) =
        open_agent_pidfd_with_retry(&cli.agent_pidfile, PIDFD_OPEN_RETRY_DEADLINE, &agent_bin)
            .await
            .context("opening initial agent pidfd")?;
    // Respawn v2 (docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md): on a
    // systemd host the agent is brought back through ITS OWN unit, so
    // it gets the unit's ExecStart argv, cgroup, caps and ProtectHome —
    // not the watchdog's 64 MiB / 2-cap sandbox it used to inherit as a
    // fork-exec child. The exec backend (non-systemd hosts) now persists
    // the agent's FULL first-launch argv from /proc instead of a
    // `--pid-file`-only reconstruction (combat-avail-1).
    let backend = select_backend(
        cli.respawn_backend,
        systemd_is_booted(std::path::Path::new(SYSTEMD_RUNTIME_DIR)),
        &cli.agent_unit,
        || {
            exec_argv(
                agent_pid,
                cli.agent_bin.as_deref(),
                &agent_bin,
                &cli.agent_pidfile,
            )
        },
    )?;

    write_pidfile_atomic(&cli.pidfile, own_pid)
        .with_context(|| format!("writing watchdog pidfile {}", cli.pidfile.display()))?;

    // Self-protection + signalling rights (see register_self_pid): the
    // task_kill hook only lets a PROTECTED caller signal the protected
    // agent, so without this entry stuck recovery could not fire.
    if let Err(e) = self_registered {
        warn!(
            target: "watchdog",
            error = %e,
            "could not register the watchdog PID in PROTECTED_PIDS — no BPF-LSM on this host? \
             stuck recovery will be refused by the task_kill hook until the agent registers us"
        );
    }

    sd_notify_ready().context("sd_notify(READY=1)")?;

    info!(
        target: "watchdog",
        own_pid,
        agent_pid,
        bpffs_root = %cli.bpffs_root.display(),
        respawn = %backend.describe(),
        "boot sequence complete — entering restart-backoff loop"
    );

    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut backoff = RestartBackoff::new();
    // External audit WDG-001: a shutdown authorisation must have been
    // signed while the agent it stops was running.
    let mut agent_started = process_start_unix(agent_pid);

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
    //
    // External audit WDG-002: a signal names the agent it was raised
    // against, the ping task restarts its count whenever the agent
    // changes (`current_agent`), and the main loop drops a signal for an
    // agent that is gone — a timeout buffered while the old agent was
    // dying used to SIGINT, evict and SIGKILL the healthy new one.
    let (stuck_tx, mut stuck_rx) = tokio::sync::mpsc::channel::<u32>(4);
    let (current_agent, agent_watch) = tokio::sync::watch::channel(agent_pid);
    let ping_socket = cli.admin_socket.clone();
    let ping_handle = tokio::spawn(run_ping_loop(ping_socket, stuck_tx, agent_watch));

    // W4 restart loop. Each iteration:
    //   1. Park on {SIGTERM, SIGINT, agent pidfd POLLIN}
    //   2. On pidfd POLLIN: layer-2 evict, check shutdown marker,
    //      compute backoff, respawn, reinsert PROTECTED_PIDS,
    //      loop back
    //   3. On signal: break out cleanly
    //   4. On ceiling breach, or a failed respawn: log, then hold —
    //      alive and protected, no respawn — until an operator starts
    //      the agent again (external audit WDG-004; see `hold`)
    'restart_loop: loop {
        let select_outcome = tokio::select! {
            _ = sigint.recv() => SelectOutcome::Signal("SIGINT"),
            _ = sigterm.recv() => SelectOutcome::Signal("SIGTERM"),
            result = wait_for_agent_death(&agent_pidfd) => SelectOutcome::AgentDied(result),
            // W5 stuck-recovery arm: the parallel ping task has
            // observed two consecutive STATUS-ping timeouts and
            // decided the agent is wedged. Run the SIGINT →
            // grace → evict + SIGKILL sequence; the subsequent
            // pidfd POLLIN fires inside `stuck_recovery` (it
            // opens its own fresh pidfd), then we fall through
            // to the normal layer-2 evict + respawn path below.
            // We synthesise an `AgentDied(Ok(()))` outcome so
            // the existing match arm handles the rest.
            Some(stuck_pid) = stuck_rx.recv() => {
                if stuck_pid != agent_pid {
                    SelectOutcome::StaleStuck(stuck_pid)
                } else {
                warn!(
                    target: "watchdog.stuck_recovery",
                    agent_pid,
                    "STATUS-ping stuck signal received from ping task — running recovery"
                );
                let recovery = stuck_recovery(
                    agent_pid,
                    &cli.bpffs_root,
                    STUCK_RECOVERY_HARDKILL_GRACE,
                    &agent_bin,
                )
                .await;
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
            }
        };

        match select_outcome {
            SelectOutcome::Signal(name) => {
                info!(target: "watchdog", signal = name, "shutting down");
                break 'restart_loop;
            }
            SelectOutcome::StaleStuck(pid) => {
                info!(
                    target: "watchdog.stuck_recovery",
                    stale_pid = pid,
                    agent_pid,
                    "dropping a stuck signal raised against an agent that is gone"
                );
                continue 'restart_loop;
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

                // A8 shutdown-authorisation check (Watchdog §13 Q4): stand
                // down only for a shutdown the admin quorum signed for
                // this agent (external audit WDG-001). Anything else on
                // disk is a forgery or a replay: respawn, and count the
                // attempt toward the ceiling like any other death.
                let check = ShutdownCheck {
                    marker: &cli.shutdown_marker,
                    admin_pub: &cli.admin_pub,
                    agent_id_file: &cli.agent_id_file,
                    agent_pid,
                    agent_started,
                };
                match check_shutdown_marker(&check) {
                    ShutdownVerdict::Authorised => {
                        info!(
                            target: "watchdog.shutdown_marker",
                            "admin-authorised shutdown observed — watchdog standing down (no respawn)"
                        );
                        break 'restart_loop;
                    }
                    ShutdownVerdict::Absent => { /* unsigned exit — proceed with respawn */ }
                    ShutdownVerdict::Refused(reason) => {
                        error!(
                            target: "watchdog.tamper",
                            agent_pid,
                            reason = %reason,
                            "shutdown marker REFUSED — not signed by the admin quorum for this agent; respawning"
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
                        // External audit WDG-004: hold, never exit 0.
                        let held = Hold {
                            why: "agent restart ceiling tripped (tamper suspected)",
                            detail: format!(
                                "{attempts_in_window} restarts in the last {} s",
                                window.as_secs()
                            ),
                            agent_pid,
                        };
                        match hold(
                            &cli,
                            &backend,
                            &mut sigint,
                            &mut sigterm,
                            &mut stuck_rx,
                            held,
                            &agent_bin,
                        )
                        .await
                        {
                            Some((pid, fd)) => {
                                agent_pid = pid;
                                agent_pidfd = fd;
                                agent_started = process_start_unix(pid);
                                new_generation(&current_agent, &mut stuck_rx, pid);
                                backoff = RestartBackoff::new();
                                continue 'restart_loop;
                            }
                            None => break 'restart_loop,
                        }
                    }
                };

                if !delay.is_zero() {
                    info!(
                        target: "watchdog.respawn",
                        attempt,
                        delay_ms = delay.as_millis() as u64,
                        "backing off before respawn"
                    );
                    if let Some(reason) = sleep_or_signal(delay, &mut sigint, &mut sigterm).await {
                        info!(target: "watchdog", signal = reason, "shutting down during backoff");
                        break 'restart_loop;
                    }
                }

                // Best-effort: remove the dead agent's pidfile
                // BEFORE respawn so the wait for the new agent
                // doesn't immediately read the dead PID.
                let _ = std::fs::remove_file(&cli.agent_pidfile);

                // External audit WDG-009: a stop request is honoured while
                // the respawn runs (the start job, then up to 30 s for the
                // new agent's pidfile), not after it.
                let respawned = tokio::select! {
                    r = respawn_cycle(
                        &backend,
                        &cli.agent_pidfile,
                        &cli.bpffs_root,
                        attempt,
                        &agent_bin,
                    ) => r,
                    _ = sigint.recv() => {
                        info!(target: "watchdog", signal = "SIGINT", "shutting down during respawn");
                        break 'restart_loop;
                    }
                    _ = sigterm.recv() => {
                        info!(target: "watchdog", signal = "SIGTERM", "shutting down during respawn");
                        break 'restart_loop;
                    }
                };
                match respawned {
                    Ok((new_pid, new_fd)) => {
                        agent_pid = new_pid;
                        agent_pidfd = new_fd;
                        agent_started = process_start_unix(new_pid);
                        new_generation(&current_agent, &mut stuck_rx, new_pid);
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
                            "respawn cycle failed"
                        );
                        // No new pidfd to wait on. External audit
                        // WDG-004: hold until the agent runs again,
                        // rather than exit 0 and leave the host with
                        // neither agent nor watchdog.
                        let held = Hold {
                            why: "agent respawn failed",
                            detail: format!("{e:#}"),
                            agent_pid,
                        };
                        match hold(
                            &cli,
                            &backend,
                            &mut sigint,
                            &mut sigterm,
                            &mut stuck_rx,
                            held,
                            &agent_bin,
                        )
                        .await
                        {
                            Some((pid, fd)) => {
                                agent_pid = pid;
                                agent_pidfd = fd;
                                agent_started = process_start_unix(pid);
                                new_generation(&current_agent, &mut stuck_rx, pid);
                                backoff = RestartBackoff::new();
                            }
                            None => break 'restart_loop,
                        }
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

    if let Err(e) = unregister_self_pid(&cli.bpffs_root, own_pid) {
        debug!(target: "watchdog", error = %e, "own PID not evicted from PROTECTED_PIDS (no pin?)");
    }
    info!(target: "watchdog", "watchdog stopped");
    Ok(())
}

/// Internal select-arm outcome — folds the three branches of the
/// W4 main loop into one match.
/// External audit WDG-002: a new agent is watched — tell the ping task,
/// and drop the stuck signals raised against the previous one.
fn new_generation(
    current: &tokio::sync::watch::Sender<u32>,
    stuck_rx: &mut tokio::sync::mpsc::Receiver<u32>,
    pid: u32,
) {
    current.send_replace(pid);
    while stuck_rx.try_recv().is_ok() {}
}

enum SelectOutcome {
    Signal(&'static str),
    AgentDied(Result<()>),
    /// External audit WDG-002: a stuck signal for an earlier agent.
    StaleStuck(u32),
}

/// Argv for the exec backend: the agent's full `/proc/<pid>/cmdline`
/// (with `--agent-bin` overriding argv[0]); if /proc is unreadable
/// (observer registration not yet arrived), fall back to the legacy
/// minimal reconstruction so a non-systemd host still gets SOME
/// respawn rather than none — logged loudly, because that argv drops
/// every flag. External audit WDG-009: the fallback names `verified_bin`,
/// the binary the agent was just verified to run (WDG-003); it no longer
/// re-reads `/proc/<pid>/exe` in a 60 s `std::thread::sleep` loop.
fn exec_argv(
    agent_pid: u32,
    agent_bin: Option<&std::path::Path>,
    verified_bin: &std::path::Path,
    pidfile: &std::path::Path,
) -> Result<Vec<String>> {
    match agent_argv_from_proc(agent_pid, agent_bin) {
        Ok(argv) => Ok(argv),
        Err(e) => {
            warn!(
                target: "watchdog.respawn",
                error = %e,
                "full argv capture from /proc failed — falling back to minimal argv \
                 (flags such as --detect-only / --admin-pub will NOT survive a respawn)"
            );
            Ok(vec![
                verified_bin.to_string_lossy().into_owned(),
                "--pid-file".to_string(),
                pidfile.to_string_lossy().into_owned(),
            ])
        }
    }
}

/// One full respawn cycle: spawn the agent, wait for its
/// pidfile, open a new pidfd, defensive-reinsert the new PID
/// into PROTECTED_PIDS. Returns the new PID + the new pidfd
/// for the main loop's next select-arm.
async fn respawn_cycle(
    backend: &RespawnBackend,
    pidfile: &std::path::Path,
    bpffs_root: &std::path::Path,
    attempt: u8,
    agent_bin: &std::path::Path,
) -> Result<(u32, OwnedFd)> {
    info!(
        target: "watchdog.respawn",
        attempt,
        backend = %backend.describe(),
        "respawning agent"
    );
    // systemd backend: the start job is queued (--no-block) and the
    // agent boots under its own unit; exec backend: fork-exec, child
    // handle dropped (death is observed via the new pidfd, never
    // waitpid — Child::drop is a no-op on Unix). Either way readiness
    // is the pidfile below, written after every LSM hook is attached.
    // External audit WDG-009: off the runtime's only thread.
    respawn_agent_off_runtime(backend)
        .await
        .context("starting the agent")?;

    // External audit WDG-003: the new agent is verified before it is
    // protected or watched. External audit DEP-004: a queued start job
    // proves nothing — the unit may fail its bpffs pre-flight, be skipped or
    // be stopped before it runs; the missing pidfile is what says so.
    let (new_pid, new_fd) =
        open_agent_pidfd_with_retry(pidfile, NEW_AGENT_PIDFILE_DEADLINE, agent_bin)
            .await
            .with_context(|| match backend {
                RespawnBackend::SystemdUnit { unit } => format!(
                    "start job for {unit} queued, but no agent within {} s",
                    NEW_AGENT_PIDFILE_DEADLINE.as_secs()
                ),
                RespawnBackend::ForkExec { .. } => format!(
                    "agent spawned, but no verified pidfile within {} s",
                    NEW_AGENT_PIDFILE_DEADLINE.as_secs()
                ),
            })?;

    // Defensive reinsert — never for an agent that already exited (its pid
    // would wait in PROTECTED_PIDS for reuse). Failure here just widens
    // the brief window before the new agent's own register_protected_pids
    // fires — not a fatal restart-cycle error.
    if pidfd_exited(&new_fd) {
        info!(
            target: "watchdog.respawn",
            new_pid,
            "the respawned agent already exited — its death is handled next"
        );
    } else if let Err(e) = reinsert_new_agent_pid(bpffs_root, new_pid) {
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

/// Why the watchdog holds ([`hold`]).
struct Hold {
    why: &'static str,
    /// The error or count behind it.
    detail: String,
    /// The last agent supervised.
    agent_pid: u32,
}

/// External audit WDG-004: the watchdog never exits on the restart
/// ceiling or a failed respawn. It exited 0 there, and the unit's
/// `Restart=on-failure` neither restarted it nor marked it failed: agent
/// and watchdog gone, silently. It holds instead — alive, still in
/// PROTECTED_PIDS, `DEGRADED` in `systemctl status` — until an operator
/// starts the agent again, then supervises it with a fresh restart
/// window. `None` when the watchdog is told to stop meanwhile.
///
/// External audit DEP-004: each hold is also recorded for the agent's
/// signed audit chain ([`record_hold`]) — with the agent unit's state on a
/// systemd host — and signed as an `integrity_drift` (`watchdog_hold`) at
/// the agent's next start. The journal line alone stayed on this host.
async fn hold(
    cli: &Cli,
    backend: &RespawnBackend,
    sigint: &mut Signal,
    sigterm: &mut Signal,
    stuck_rx: &mut tokio::sync::mpsc::Receiver<u32>,
    held: Hold,
    agent_bin: &std::path::Path,
) -> Option<(u32, OwnedFd)> {
    let why = held.why;
    // Once the dead agent's PID is reused its pidfile would read as live.
    let _ = std::fs::remove_file(&cli.agent_pidfile);
    sd_notify_status(&format!(
        "DEGRADED: {why} — not respawning the agent; start northnarrow-agent once investigated"
    ));
    let unit_state = match backend {
        RespawnBackend::SystemdUnit { unit } => {
            let unit = unit.clone();
            match tokio::time::timeout(
                UNIT_STATE_TIMEOUT,
                off_runtime(move || systemctl_unit_state(&unit)),
            )
            .await
            {
                Ok(Ok(state)) => Some(state),
                Ok(Err(e)) => {
                    warn!(target: "watchdog", error = %e, "agent unit state unavailable");
                    None
                }
                Err(_) => {
                    warn!(target: "watchdog", "systemctl show timed out; hold recorded without the unit state");
                    None
                }
            }
        }
        RespawnBackend::ForkExec { .. } => None,
    };
    error!(
        target: "watchdog.tamper",
        why,
        detail = %held.detail,
        unit_state = unit_state.as_deref().unwrap_or("-"),
        "watchdog HOLDING: alive and protected, not respawning the agent until an operator \
         starts it"
    );
    let record = common::watchdog_hold::HoldRecord {
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        agent_pid: held.agent_pid,
        reason: why.to_string(),
        detail: held.detail,
        unit_state,
    };
    let path = hold_record_path(&cli.shutdown_marker);
    if let Err(e) = record_hold(&path, &record) {
        warn!(
            target: "watchdog.tamper",
            error = %e,
            path = %path.display(),
            "could not record the hold for the agent's audit chain; the journal line above is the only trace"
        );
    }
    let shutdown = async {
        tokio::select! {
            _ = sigint.recv() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        }
    };
    match hold_until_agent_returns(&cli.agent_pidfile, HOLD_POLL, shutdown, agent_bin).await {
        HoldOutcome::Resumed { pid, pidfd } => {
            // Pings failed while no agent ran: those stuck signals are stale.
            while stuck_rx.try_recv().is_ok() {}
            if !pidfd_exited(&pidfd) {
                if let Err(e) = reinsert_new_agent_pid(&cli.bpffs_root, pid) {
                    warn!(target: "watchdog", error = %e, pid, "PROTECTED_PIDS reinsert after hold failed");
                }
            }
            sd_notify_status(&format!("supervising agent pid {pid}"));
            info!(
                target: "watchdog",
                pid,
                "agent running again — supervision resumed with a fresh restart window"
            );
            Some((pid, pidfd))
        }
        HoldOutcome::Shutdown(name) => {
            info!(target: "watchdog", signal = name, "shutting down while holding");
            None
        }
    }
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
async fn run_ping_loop(
    socket_path: PathBuf,
    stuck_tx: tokio::sync::mpsc::Sender<u32>,
    mut agent: tokio::sync::watch::Receiver<u32>,
) {
    // External audit WDG-009: `Delay`, so a stall never fires two pings
    // back to back.
    let mut tick = ping_ticker(STATUS_PING_INTERVAL);
    // `interval()` fires immediately on first tick — skip that
    // so the watchdog isn't immediately pinging the agent
    // mid-boot (before the agent's admin socket is even bound).
    tick.tick().await;

    let mut tracker = StatusPingTracker::new();
    let mut watching = *agent.borrow_and_update();
    loop {
        tick.tick().await;
        // External audit WDG-002: timeouts against the previous agent do
        // not count toward the new one.
        let current = *agent.borrow_and_update();
        if current != watching {
            tracker.reset();
            watching = current;
        }
        let outcome = match ping_agent_status(&socket_path, STATUS_PING_TIMEOUT).await {
            Ok(()) => tracker.record_ok(),
            Err(e) => match classify_ping_error(&e) {
                PingFailure::SocketAbsent => tracker.record_socket_absent(),
                PingFailure::Unresponsive => {
                    warn!(
                        target: "watchdog.status_ping",
                        error = %e,
                        socket = %socket_path.display(),
                        consecutive = tracker.consecutive_timeouts(),
                        "STATUS ping failed"
                    );
                    tracker.record_timeout()
                }
            },
        };
        match outcome {
            PingOutcome::Ok | PingOutcome::TimeoutOnce => {}
            PingOutcome::SocketAbsent { consecutive } => {
                // Not a hang: never feed stuck recovery (it would SIGINT
                // a healthy-but-misconfigured agent every 30 s forever).
                if consecutive >= STATUS_PING_ABSENT_ERROR_AFTER {
                    error!(
                        target: "watchdog.status_ping",
                        socket = %socket_path.display(),
                        consecutive,
                        "admin socket has NEVER come up — agent misconfigured (combat-rules.v4 / \
                         admin.pub missing?), NOT treating as stuck; nn-admin will not work"
                    );
                } else {
                    warn!(
                        target: "watchdog.status_ping",
                        socket = %socket_path.display(),
                        consecutive,
                        "admin socket absent (ENOENT) — not counted as stuck"
                    );
                }
            }
            PingOutcome::StuckDetected => {
                warn!(
                    target: "watchdog.status_ping",
                    consecutive = tracker.consecutive_timeouts(),
                    "STATUS ping threshold tripped — signalling main loop for stuck recovery"
                );
                tracker.reset();
                if stuck_tx.send(watching).await.is_err() {
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

// The `IntoRawFd` import is kept for forward-compat with W4's
// AgentGuard pattern (it'll consume + re-wrap raw fds for child
// process inheritance during agent respawn).
#[allow(
    dead_code,
    reason = "IntoRawFd is used by W4's respawn path; kept in scope here for forward-compat"
)]
fn _trait_anchor() {
    let _: fn(OwnedFd) -> i32 = |fd| fd.into_raw_fd();
}
