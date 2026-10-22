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
//!
//! Lab PR 216 (capability C23): every failure exits non-zero with a status
//! of its own ([`northnarrow_watchdog::ExitReason`]) after a record the
//! agent signs; `--record-unit-failure` is the unit's `OnFailure=`
//! handler.

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
    check_shutdown_marker, evict_dead_agent, harden_self, hold_until_agent_returns,
    log_tamper_suspected, open_agent_pidfd_with_retry, pidfd_exited, process_start_unix,
    register_self_pid, reinsert_new_agent_pid, sd_notify_ready, sd_notify_status, stuck_recovery,
    unregister_self_pid, wait_for_agent_death, write_pidfile_atomic, BackoffOutcome, Cli,
    HoldOutcome, PingOutcome, RestartBackoff, ShutdownCheck, ShutdownVerdict, StatusPingTracker,
    DEFAULT_AGENT_BIN, HOLD_POLL, PIDFD_OPEN_RETRY_DEADLINE, STATUS_PING_INTERVAL,
    STATUS_PING_TIMEOUT, STUCK_RECOVERY_HARDKILL_GRACE,
};
use northnarrow_watchdog::{
    classify_ping_error, exec_respawn_argv, hold_record_path, off_runtime, ping_ticker, reap_agent,
    record_hold, respawn_agent_off_runtime, select_backend, systemctl_unit_state,
    systemd_is_booted, PingFailure, Reaped, RespawnBackend, STATUS_PING_ABSENT_ERROR_AFTER,
    STATUS_PING_VANISHED_TAMPER_AFTER, SYSTEMD_RUNTIME_DIR, UNIT_STATE_TIMEOUT,
};
use northnarrow_watchdog::{
    event_loop_stalled_record, exit_record, hold_status_line, pidfd_wait_failed, ping_agent,
    read_pid_from_file, stuck_recovery_failed_record, stuck_verdict, unit_failure_record, unix_now,
    ExitAs, ExitReason, Failure, HoldRetry, LoopProgress, StuckVerdict, HOLD_REMIND_EVERY,
    HOLD_STATUS_EVERY,
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
    // event is one journal line, as in the agent (nn_model::log_escape).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(nn_model::log_escape::stdout_ansi())
        .with_writer(nn_model::log_escape::stdout_one_line)
        .log_internal_errors(false)
        .try_init();

    let cli = Cli::parse();
    if cli.record_unit_failure {
        return record_unit_failure(&cli);
    }
    info!(
        target: "watchdog",
        agent_pidfile = %cli.agent_pidfile.display(),
        admin_socket = %cli.admin_socket.display(),
        pidfile = %cli.pidfile.display(),
        bpffs_root = %cli.bpffs_root.display(),
        "watchdog starting"
    );

    let holds = hold_record_path(&cli.shutdown_marker);
    let bpffs_root = cli.bpffs_root.clone();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            // A failure before the restart loop skips its teardown: the pid
            // this watchdog registered at its start must not stay protected
            // for whoever reuses it (idempotent after the teardown).
            let _ = unregister_self_pid(&bpffs_root, std::process::id());
            // Lab PR 216: a status of its own, and a record the agent signs
            // — systemd restarts the watchdog (`Restart=always`).
            error!(
                target: "watchdog.tamper",
                status = failure.reason.code(),
                reason = failure.reason.name(),
                agent_pid = failure.agent_pid,
                error = format!("{:#}", failure.error),
                "watchdog EXITING on a failure — systemd restarts it; the agent signs the record"
            );
            if let Err(e) = record_hold(&holds, &exit_record(&failure, unix_now())) {
                warn!(
                    target: "watchdog.tamper",
                    error = %e,
                    path = %holds.display(),
                    "could not record the exit for the agent's audit chain"
                );
            }
            ExitCode::from(failure.reason.code())
        }
    }
}

/// Lab PR 216: `--record-unit-failure`, the mode
/// `northnarrow-watchdog-failed.service` runs when systemd puts the
/// watchdog unit in its failed state (`OnFailure=`): one
/// `watchdog_failed` record, signed by the agent at its next round, and an
/// ERROR line. Exit 0, or [`ExitReason::RecordFailed`].
fn record_unit_failure(cli: &Cli) -> ExitCode {
    let agent_pid = read_pid_from_file(&cli.agent_pidfile).unwrap_or(0);
    let record = unit_failure_record(|k| std::env::var(k).ok(), agent_pid, unix_now());
    error!(
        target: "watchdog.tamper",
        detail = %record.detail,
        "the watchdog unit FAILED — systemd no longer restarts it; the agent runs unsupervised \
         until `systemctl start northnarrow-watchdog`"
    );
    let path = hold_record_path(&cli.shutdown_marker);
    match record_hold(&path, &record) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(target: "watchdog.tamper", error = %e, path = %path.display(), "could not record the watchdog's failure");
            ExitCode::from(ExitReason::RecordFailed.code())
        }
    }
}

/// Body of the watchdog boot/wait/teardown cycle, extracted so
/// the binary surface stays a thin error→exit-code mapper.
async fn run(cli: Cli) -> std::result::Result<(), Failure> {
    harden_self()
        .context("harden_self (prctl PR_SET_DUMPABLE + PR_SET_NAME)")
        .exit_as(ExitReason::Harden)?;

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
            .context("opening initial agent pidfd")
            .exit_as(ExitReason::NoAgent)?;
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
            // External audit WDG-008: the capture is recorded for a later
            // start of the watchdog, and a fallback is signed by the agent.
            Ok(exec_respawn_argv(
                agent_pid,
                cli.agent_bin.as_deref(),
                &agent_bin,
                &cli.agent_pidfile,
                &hold_record_path(&cli.shutdown_marker),
            ))
        },
    )
    .map_err(|e| Failure::new(ExitReason::Backend, e).agent(agent_pid))?;

    write_pidfile_atomic(&cli.pidfile, own_pid)
        .with_context(|| format!("writing watchdog pidfile {}", cli.pidfile.display()))
        .map_err(|e| Failure::new(ExitReason::Pidfile, e).agent(agent_pid))?;

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

    sd_notify_ready()
        .context("sd_notify(READY=1)")
        .map_err(|e| Failure::new(ExitReason::Notify, e).agent(agent_pid))?;
    sd_notify_status(&format!("supervising agent pid {agent_pid}"));

    info!(
        target: "watchdog",
        own_pid,
        agent_pid,
        bpffs_root = %cli.bpffs_root.display(),
        respawn = %backend.describe(),
        "boot sequence complete — entering restart-backoff loop"
    );

    let mut sigint = signal(SignalKind::interrupt())
        .context("installing SIGINT handler")
        .map_err(|e| Failure::new(ExitReason::Signals, e).agent(agent_pid))?;
    let mut sigterm = signal(SignalKind::terminate())
        .context("installing SIGTERM handler")
        .map_err(|e| Failure::new(ExitReason::Signals, e).agent(agent_pid))?;
    let mut backoff = RestartBackoff::new();
    // Lab PR 216: the hold's bounded retries, counted over this watchdog's
    // life.
    let mut hold_retry = HoldRetry::new();
    // Lab PR 216: how the restart loop ended — a stop it was told to make,
    // or a failure with its own exit status. Teardown is the same.
    let mut failure: Option<Failure> = None;
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
    //
    // External audit WDG-007: `None` while no agent runs (from its death to
    // the next one), so the ping task neither pings a dead agent's socket
    // nor reads a hold's missing socket as a removal.
    let (stuck_tx, mut stuck_rx) = tokio::sync::mpsc::channel::<u32>(4);
    let (current_agent, agent_watch) = tokio::sync::watch::channel(Some(agent_pid));
    let ping_socket = cli.admin_socket.clone();
    let ping_holds = hold_record_path(&cli.shutdown_marker);
    let ping_handle = tokio::spawn(run_ping_loop(
        ping_socket,
        ping_holds,
        stuck_tx,
        agent_watch,
    ));

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
            result = wait_agent(&agent_pidfd, &cli.agent_pidfile) => SelectOutcome::AgentDied(result),
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
                let recovery = if debug_refuse_recovery(&cli.agent_pidfile) {
                    Err(anyhow::anyhow!("debug-trigger: stuck recovery refused before its signals"))
                } else {
                    stuck_recovery(
                        agent_pid,
                        &cli.bpffs_root,
                        STUCK_RECOVERY_HARDKILL_GRACE,
                        &agent_bin,
                    )
                    .await
                };
                // Lab PR 216 (static review C-44 / G-05): a death is what
                // the agent's own pidfd says, never a failed recovery.
                match (stuck_verdict(&agent_pidfd), recovery) {
                    (StuckVerdict::Exited, _) => SelectOutcome::AgentDied(Ok(())),
                    (StuckVerdict::StillRunning, Err(e)) => {
                        SelectOutcome::RecoveryFailed(format!("{e:#}"))
                    }
                    (StuckVerdict::StillRunning, Ok(())) => SelectOutcome::RecoveryFailed(
                        "the recovery reported an exit the agent's pidfd does not show".to_string(),
                    ),
                }
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
                // Lab PR 216 (static review C-44 / G-05): this `break` was
                // a clean exit 0, which `Restart=on-failure` did not
                // restart. A status of its own: systemd restarts the
                // watchdog, which opens a pidfd on the agent again.
                error!(
                    target: "watchdog.pidfd",
                    error = %e,
                    agent_pid,
                    "pidfd wait failed — exiting with status {} for a restart",
                    ExitReason::PidfdWait.code()
                );
                failure = Some(pidfd_wait_failed(e, agent_pid));
                break 'restart_loop;
            }
            SelectOutcome::RecoveryFailed(error) => {
                // Lab PR 216: the agent runs. It keeps its PROTECTED_PIDS
                // entry (written again: idempotent) and its pidfile; the
                // pidfd stays watched and the next stuck signal tries again.
                recovery_failed(&cli, agent_pid, &error);
                continue 'restart_loop;
            }
            SelectOutcome::AgentDied(Ok(())) => {
                info!(
                    target: "watchdog.layer2_evict",
                    agent_pid,
                    "agent pidfd POLLIN — agent has exited; running layer-2 evict"
                );
                // External audit WDG-007: no agent to ping until the next.
                current_agent.send_replace(None);
                // External audit WDG-010: an agent the exec backend started
                // is our child — collect it, or it stays a zombie.
                match reap_agent(&agent_pidfd) {
                    Ok(Reaped::Collected { pid, si_code, code }) => info!(
                        target: "watchdog.respawn",
                        pid,
                        si_code,
                        code,
                        "exited agent collected (exec backend child)"
                    ),
                    Ok(Reaped::NotOurChild) => {}
                    Ok(Reaped::Running) => debug!(
                        target: "watchdog.respawn",
                        agent_pid,
                        "agent reported exited but not yet collectable"
                    ),
                    Err(e) => debug!(
                        target: "watchdog.respawn",
                        error = %e,
                        agent_pid,
                        "waitid on the agent pidfd failed"
                    ),
                }
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
                            &mut hold_retry,
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
                            &mut hold_retry,
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

    // Lab PR 216: the same teardown after a failure as after a stop — the
    // next watchdog (systemd restarts this one) registers itself again.
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
    match failure {
        Some(f) => Err(f),
        None => {
            info!(target: "watchdog", "watchdog stopped");
            Ok(())
        }
    }
}

/// The wait on the agent's pidfd ([`wait_for_agent_death`]). `debug-trigger`
/// builds (the lab's) only: a file `debug-fail-pidfd-wait` beside the agent
/// pidfile makes it fail once — lab check of lab PR 216 (exit status 20, a
/// `watchdog_exit` record, systemd's restart). Polled every second.
async fn wait_agent(pidfd: &OwnedFd, agent_pidfile: &std::path::Path) -> Result<()> {
    #[cfg(feature = "debug-trigger")]
    {
        let trigger = agent_pidfile.with_file_name("debug-fail-pidfd-wait");
        let injected = async {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if std::fs::remove_file(&trigger).is_ok() {
                    warn!(target: "watchdog.pidfd", "debug-trigger: pidfd wait failure injected (lab test of lab PR 216)");
                    return anyhow::anyhow!("debug-trigger: pidfd wait failure injected");
                }
            }
        };
        tokio::select! {
            r = wait_for_agent_death(pidfd) => r,
            e = injected => Err(e),
        }
    }
    #[cfg(not(feature = "debug-trigger"))]
    {
        let _ = agent_pidfile;
        wait_for_agent_death(pidfd).await
    }
}

/// `debug-trigger` builds only: a file `debug-refuse-recovery` beside the
/// agent pidfile makes the next stuck recovery fail before its signals, as
/// a refused SIGINT does — lab check of lab PR 216 (the agent keeps its
/// protection). Consumed by that recovery. Always `false` otherwise.
fn debug_refuse_recovery(agent_pidfile: &std::path::Path) -> bool {
    #[cfg(feature = "debug-trigger")]
    {
        let taken =
            std::fs::remove_file(agent_pidfile.with_file_name("debug-refuse-recovery")).is_ok();
        if taken {
            warn!(target: "watchdog.stuck_recovery", "debug-trigger: stuck recovery refused (lab test of lab PR 216)");
        }
        taken
    }
    #[cfg(not(feature = "debug-trigger"))]
    {
        let _ = agent_pidfile;
        false
    }
}

/// Internal select-arm outcome — folds the three branches of the
/// W4 main loop into one match.
/// External audit WDG-002: a new agent is watched — tell the ping task,
/// and drop the stuck signals raised against the previous one.
fn new_generation(
    current: &tokio::sync::watch::Sender<Option<u32>>,
    stuck_rx: &mut tokio::sync::mpsc::Receiver<u32>,
    pid: u32,
) {
    current.send_replace(Some(pid));
    while stuck_rx.try_recv().is_ok() {}
    // Lab PR 216: a DEGRADED line from a failed recovery or a hold ends
    // with the agent it was about.
    sd_notify_status(&format!("supervising agent pid {pid}"));
}

enum SelectOutcome {
    Signal(&'static str),
    AgentDied(Result<()>),
    /// External audit WDG-002: a stuck signal for an earlier agent.
    StaleStuck(u32),
    /// Lab PR 216: stuck recovery could not confirm the agent's exit.
    RecoveryFailed(String),
}

/// Lab PR 216 (static review C-44 / G-05): stuck recovery failed and the
/// agent still runs. Before, it was handled as a death — evicted from
/// `PROTECTED_PIDS`, its pidfile removed, a respawn queued — with the agent
/// alive, which re-registers its pid only at its start. Now: its entry
/// written again (idempotent; nothing removed it), `DEGRADED` in
/// `systemctl status`, an ERROR, and a record the agent signs
/// (`stuck_recovery_failed`).
fn recovery_failed(cli: &Cli, agent_pid: u32, error: &str) {
    if let Err(e) = reinsert_new_agent_pid(&cli.bpffs_root, agent_pid) {
        debug!(target: "watchdog.stuck_recovery", error = %e, agent_pid, "PROTECTED_PIDS re-assert (no pin?)");
    }
    sd_notify_status(&format!(
        "DEGRADED: agent pid {agent_pid} unresponsive and could not be stopped — still protected \
         and supervised"
    ));
    error!(
        target: "watchdog.tamper",
        agent_pid,
        error,
        "stuck recovery FAILED and the agent still runs — NOT evicted, pidfile kept, still \
         supervised; the next stuck signal tries again"
    );
    let path = hold_record_path(&cli.shutdown_marker);
    if let Err(e) = record_hold(
        &path,
        &stuck_recovery_failed_record(agent_pid, error, unix_now()),
    ) {
        warn!(
            target: "watchdog.tamper",
            error = %e,
            path = %path.display(),
            "could not record the failed recovery for the agent's audit chain"
        );
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
///
/// Lab PR 216 (static review C-44: the hold was indefinite, and with no
/// agent nothing signed its record): the hold is bounded and stays
/// visible ([`hold_supervision`]) — its `STATUS=` line says for how long
/// and when it retries, an ERROR repeats every 10 minutes, and after
/// [`northnarrow_watchdog::HOLD_RETRY_FIRST`] (then twice as long, up to an
/// hour) it starts the agent once more, recorded as `hold_retry`. Its end
/// is recorded too (`hold_ended`, with its length). The retries supersede
/// WDG-004's "only an operator starts the agent again" (the maintainer's
/// decision); an operator's start still ends the hold at once.
#[allow(clippy::too_many_arguments)]
async fn hold(
    cli: &Cli,
    backend: &RespawnBackend,
    sigint: &mut Signal,
    sigterm: &mut Signal,
    stuck_rx: &mut tokio::sync::mpsc::Receiver<u32>,
    held: Hold,
    agent_bin: &std::path::Path,
    retry: &mut HoldRetry,
) -> Option<(u32, OwnedFd)> {
    let why = held.why;
    // Once the dead agent's PID is reused its pidfile would read as live.
    let _ = std::fs::remove_file(&cli.agent_pidfile);
    sd_notify_status(&hold_status_line(why, Duration::ZERO, retry.next_wait()));
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
        retry_in_secs = retry.next_wait().as_secs(),
        "watchdog HOLDING: alive and protected, not respawning the agent until an operator \
         starts it or the hold's next retry"
    );
    let record = nn_proto::watchdog_hold::HoldRecord {
        at: unix_now(),
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
    let started = Instant::now();
    let shutdown = async {
        tokio::select! {
            _ = sigint.recv() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        }
    };
    let outcome = tokio::select! {
        out = hold_until_agent_returns(&cli.agent_pidfile, HOLD_POLL, shutdown, agent_bin) => out,
        never = hold_supervision(why, backend, &path, held.agent_pid, started, &mut *retry) => match never {},
    };
    match outcome {
        HoldOutcome::Resumed { pid, pidfd } => {
            // Pings failed while no agent ran: those stuck signals are stale.
            while stuck_rx.try_recv().is_ok() {}
            if !pidfd_exited(&pidfd) {
                if let Err(e) = reinsert_new_agent_pid(&cli.bpffs_root, pid) {
                    warn!(target: "watchdog", error = %e, pid, "PROTECTED_PIDS reinsert after hold failed");
                }
            }
            sd_notify_status(&format!("supervising agent pid {pid}"));
            let held_for = started.elapsed().as_secs();
            info!(
                target: "watchdog",
                pid,
                held_for_secs = held_for,
                "agent running again — supervision resumed with a fresh restart window"
            );
            let ended = nn_proto::watchdog_hold::HoldRecord {
                at: unix_now(),
                agent_pid: pid,
                reason: nn_proto::watchdog_hold::REASON_HOLD_ENDED.to_string(),
                detail: format!(
                    "the hold ({why}) lasted {held_for} s; agent pid {pid} runs again after {} \
                     retries in this watchdog's life",
                    retry.retries()
                ),
                unit_state: None,
            };
            if let Err(e) = record_hold(&path, &ended) {
                warn!(target: "watchdog.tamper", error = %e, "could not record the end of the hold");
            }
            Some((pid, pidfd))
        }
        HoldOutcome::Shutdown(name) => {
            info!(target: "watchdog", signal = name, "shutting down while holding");
            None
        }
    }
}

/// Lab PR 216: what a hold does while it waits, never returning — the
/// caller races it against the agent's return. Every
/// [`HOLD_STATUS_EVERY`] it refreshes the `STATUS=` line; every
/// [`HOLD_REMIND_EVERY`] it repeats the ERROR; when [`HoldRetry`] says, it
/// records a `hold_retry` and starts the agent once (its pidfile, polled by
/// the caller, ends the hold).
async fn hold_supervision(
    why: &'static str,
    backend: &RespawnBackend,
    holds: &std::path::Path,
    agent_pid: u32,
    started: Instant,
    retry: &mut HoldRetry,
) -> std::convert::Infallible {
    let mut tick = ping_ticker(HOLD_STATUS_EVERY);
    tick.tick().await; // the first fires at once
    let mut next_retry = started + retry.next_wait();
    let mut reminders = 0u64;
    loop {
        tick.tick().await;
        let now = Instant::now();
        let held_for = now.saturating_duration_since(started);
        if now >= next_retry {
            retry.record();
            let attempt = retry.retries();
            error!(
                target: "watchdog.tamper",
                why,
                attempt,
                held_for_secs = held_for.as_secs(),
                "hold retry: starting the agent once more"
            );
            let record = nn_proto::watchdog_hold::HoldRecord {
                at: unix_now(),
                agent_pid,
                reason: nn_proto::watchdog_hold::REASON_HOLD_RETRY.to_string(),
                detail: format!(
                    "holding ({why}) for {} s; retry {attempt} starts the agent through {}",
                    held_for.as_secs(),
                    backend.describe()
                ),
                unit_state: None,
            };
            if let Err(e) = record_hold(holds, &record) {
                warn!(target: "watchdog.tamper", error = %e, "could not record the hold retry");
            }
            if let Err(e) = respawn_agent_off_runtime(backend).await {
                error!(target: "watchdog.respawn", attempt, error = %e, "hold retry: the start failed");
            }
            next_retry = now + retry.next_wait();
        }
        let due = held_for.as_secs() / HOLD_REMIND_EVERY.as_secs().max(1);
        if due > reminders {
            reminders = due;
            error!(
                target: "watchdog.tamper",
                why,
                held_for_secs = held_for.as_secs(),
                "watchdog STILL HOLDING: the agent is not running"
            );
        }
        sd_notify_status(&hold_status_line(
            why,
            held_for,
            next_retry.saturating_duration_since(now),
        ));
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
///
/// External audit WDG-007 (NN-AUD-358): the ping must be answered by the
/// agent watched (its pid), and an admin socket that leaves the path after
/// the agent answered is reported at `holds` (signed by the agent) and,
/// [`northnarrow_watchdog::STATUS_PING_VANISHED_STUCK_AFTER`] pings in a
/// row, recovered like a hang. Nothing is pinged while no agent runs.
async fn run_ping_loop(
    socket_path: PathBuf,
    holds: PathBuf,
    stuck_tx: tokio::sync::mpsc::Sender<u32>,
    mut agent: tokio::sync::watch::Receiver<Option<u32>>,
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
    // Lab PR 216: whether to ask this agent for its loop progress (an agent
    // older than the request is asked once).
    let mut ask_progress = true;
    // Lab PR 216: a stuck signal was sent for this agent; its next healthy
    // answer clears the DEGRADED line a failed recovery leaves.
    let mut signalled = false;
    loop {
        tick.tick().await;
        // External audit WDG-002: timeouts against the previous agent do
        // not count toward the new one (WDG-007: nor its answers).
        let current = *agent.borrow_and_update();
        if current != watching {
            tracker.reset();
            watching = current;
            ask_progress = true;
            signalled = false;
        }
        let Some(agent_pid) = watching else {
            continue;
        };
        let outcome = match ping_agent(
            &socket_path,
            STATUS_PING_TIMEOUT,
            Some(agent_pid),
            ask_progress,
        )
        .await
        {
            Ok(progress) => {
                if ask_progress && progress == LoopProgress::Unreported {
                    info!(
                        target: "watchdog.status_ping",
                        agent_pid,
                        "the agent does not report its event loop's progress (older than \
                         lab PR 216) — its STATUS answer alone counts"
                    );
                    ask_progress = false;
                }
                tracker.record_answer(progress)
            }
            Err(e) => match classify_ping_error(&e) {
                PingFailure::SocketAbsent => tracker.record_socket_absent(),
                PingFailure::NotTheAgent => {
                    warn!(
                        target: "watchdog.tamper",
                        error = %e,
                        socket = %socket_path.display(),
                        agent_pid,
                        "a process that is not the agent serves the admin socket — not \
                         counted as an answer"
                    );
                    tracker.record_socket_absent()
                }
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
            PingOutcome::Ok => {
                if std::mem::take(&mut signalled) {
                    info!(
                        target: "watchdog.status_ping",
                        agent_pid,
                        "the agent answers again, its event loop moving"
                    );
                    sd_notify_status(&format!("supervising agent pid {agent_pid}"));
                }
            }
            PingOutcome::TimeoutOnce => {}
            PingOutcome::LoopStalled {
                consecutive,
                since_last_ms,
            } => {
                warn!(
                    target: "watchdog.status_ping",
                    agent_pid,
                    consecutive,
                    since_last_ms,
                    "the agent answered, but its event loop made no round since the last ping"
                );
            }
            PingOutcome::LoopStuck {
                pings,
                since_last_ms,
            } => {
                // Lab PR 216 (static review C-44 / TD-08): the socket
                // answers, the loop does not move — a hang all the same.
                error!(
                    target: "watchdog.tamper",
                    agent_pid,
                    pings,
                    since_last_ms,
                    "the agent's event loop stands still while its admin socket answers — \
                     signalling the main loop for stuck recovery"
                );
                if let Err(e) = record_hold(
                    &holds,
                    &event_loop_stalled_record(agent_pid, pings, since_last_ms, unix_now()),
                ) {
                    warn!(target: "watchdog.tamper", error = %e, "could not record the stalled event loop");
                }
                tracker.reset();
                signalled = true;
                if stuck_tx.send(agent_pid).await.is_err() {
                    info!(
                        target: "watchdog.status_ping",
                        "main loop dropped stuck channel; ping task exiting"
                    );
                    return;
                }
            }
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
                        "admin socket absent — the agent has not answered yet; not counted as stuck"
                    );
                }
            }
            PingOutcome::SocketVanished { consecutive } => {
                if consecutive == STATUS_PING_VANISHED_TAMPER_AFTER {
                    socket_vanished(&holds, &socket_path, agent_pid, consecutive);
                } else {
                    warn!(
                        target: "watchdog.status_ping",
                        socket = %socket_path.display(),
                        agent_pid,
                        consecutive,
                        "the agent's admin socket is gone after it answered — waiting for the \
                         agent to bind it again"
                    );
                }
            }
            PingOutcome::StuckDetected => {
                warn!(
                    target: "watchdog.status_ping",
                    consecutive_timeouts = tracker.consecutive_timeouts(),
                    agent_pid,
                    "STATUS ping threshold tripped (timeouts, or the admin socket gone after \
                     the agent answered) — signalling main loop for stuck recovery"
                );
                tracker.reset();
                signalled = true;
                if stuck_tx.send(agent_pid).await.is_err() {
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

/// External audit WDG-007: the agent's admin socket stayed away after the
/// agent answered (removed, replaced, or served by another process) — an
/// ERROR on `watchdog.tamper` and a record the agent signs
/// (`admin_socket_vanished`); a frozen agent signs it after its recovery.
fn socket_vanished(holds: &std::path::Path, socket: &std::path::Path, agent_pid: u32, pings: u32) {
    let secs = STATUS_PING_INTERVAL.as_secs() * u64::from(pings.saturating_sub(1));
    error!(
        target: "watchdog.tamper",
        socket = %socket.display(),
        agent_pid,
        pings,
        "the agent's admin socket has been gone for at least {secs} s after the agent answered — \
         removed or replaced while the agent runs, and not bound again (agent frozen or \
         stuck?); stuck recovery follows if it stays away"
    );
    let record = nn_proto::watchdog_hold::HoldRecord {
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        agent_pid,
        reason: nn_proto::watchdog_hold::REASON_ADMIN_SOCKET_VANISHED.to_string(),
        detail: format!(
            "{}: nothing that is the agent answers there on {pings} STATUS pings in a row \
             (at least {secs} s) after it had answered",
            socket.display()
        ),
        unit_state: None,
    };
    if let Err(e) = record_hold(holds, &record) {
        warn!(
            target: "watchdog.tamper",
            error = %e,
            path = %holds.display(),
            "could not record the vanished admin socket for the agent's audit chain"
        );
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
