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
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use northnarrow_watchdog::{
    evict_dead_agent, harden_self, open_agent_pidfd_with_retry, read_pid_from_file,
    sd_notify_ready, wait_for_agent_death, write_pidfile_atomic, Cli,
    PIDFD_OPEN_RETRY_DEADLINE,
};

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

    let agent_fd = open_agent_pidfd_with_retry(&cli.agent_pidfile, PIDFD_OPEN_RETRY_DEADLINE)
        .await
        .context("opening agent pidfd")?;
    // SAFETY: pidfd_open returned this fd to us; we own it
    // exclusively. AsyncFd consumes the OwnedFd on registration
    // — we hand it over to wait_for_agent_death below.
    let agent_pidfd = unsafe { OwnedFd::from_raw_fd(agent_fd) };

    // W3: capture the agent PID for the layer-2 PROTECTED_PIDS
    // evict on death. Re-read from the pidfile rather than
    // calling pidfd_getfd-like introspection — the agent's
    // pidfile is the canonical source of truth, AND a stale
    // PID here would only matter if the file changed between
    // pidfd_open and now (impossible without an agent
    // restart, which we'd detect via pidfd POLLIN anyway).
    let agent_pid = read_pid_from_file(&cli.agent_pidfile)
        .context("re-reading agent PID for layer-2 evict context")?;

    let own_pid = std::process::id();
    write_pidfile_atomic(&cli.pidfile, own_pid)
        .with_context(|| format!("writing watchdog pidfile {}", cli.pidfile.display()))?;

    sd_notify_ready().context("sd_notify(READY=1)")?;

    info!(
        target: "watchdog",
        own_pid,
        agent_pid,
        bpffs_root = %cli.bpffs_root.display(),
        "boot sequence complete — waiting for agent pidfd POLLIN or SIGTERM/SIGINT"
    );

    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;

    // W3 select arm — three possible exits from the boot wait:
    // (a) agent's pidfd fires POLLIN → layer-2 evict, log, exit
    //     (W4 will replace exit with restart-backoff)
    // (b) SIGTERM/SIGINT → cleanup, exit
    //
    // Per design §12 W3: "No respawn yet (the agent stays dead
    // in this commit; verified via journal + bpftool dump)."
    tokio::select! {
        _ = sigint.recv() => {
            info!(target: "watchdog", "SIGINT received; shutting down");
        }
        _ = sigterm.recv() => {
            info!(target: "watchdog", "SIGTERM received; shutting down");
        }
        result = wait_for_agent_death(agent_pidfd) => {
            match result {
                Ok(()) => {
                    info!(
                        target: "watchdog.layer2_evict",
                        agent_pid,
                        "agent pidfd POLLIN — agent process has exited; running layer-2 evict"
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
                            "layer-2 evict failed (the recycled-PID race window stays open until layer-1 fires on next agent restart)"
                        ),
                    }
                    info!(
                        target: "watchdog",
                        "W3 exits after evict — agent stays dead (W4 will add restart-backoff)"
                    );
                }
                Err(e) => warn!(
                    target: "watchdog.pidfd",
                    error = %e,
                    "pidfd wait failed — exiting"
                ),
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

    info!(target: "watchdog", "watchdog stopped");
    Ok(())
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
