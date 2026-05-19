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
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use northnarrow_watchdog::{
    harden_self, open_agent_pidfd_with_retry, sd_notify_ready, write_pidfile_atomic,
    Cli, PIDFD_OPEN_RETRY_DEADLINE,
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
    // Wrap in OwnedFd so we close on scope exit (RAII), AND keep
    // the raw fd usable for W3 when we wire AsyncFd polling.
    // SAFETY: pidfd_open returned this fd to us; we own it
    // exclusively.
    let _agent_pidfd = unsafe { OwnedFd::from_raw_fd(agent_fd) };

    let own_pid = std::process::id();
    write_pidfile_atomic(&cli.pidfile, own_pid)
        .with_context(|| format!("writing watchdog pidfile {}", cli.pidfile.display()))?;

    sd_notify_ready().context("sd_notify(READY=1)")?;

    info!(
        target: "watchdog",
        own_pid,
        "boot sequence complete — waiting for SIGTERM/SIGINT (W3 wires pidfd POLLIN)"
    );

    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        _ = sigint.recv() => info!(target: "watchdog", "SIGINT received; shutting down"),
        _ = sigterm.recv() => info!(target: "watchdog", "SIGTERM received; shutting down"),
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

// `OwnedFd::from_raw_fd` is the cleanest RAII shape but requires
// the trait in scope. Bring it in via the standard import.
use std::os::fd::FromRawFd;
// (Unused-import lint is fine — `_agent_pidfd` keeps the trait
// usage live.)
#[allow(dead_code, reason = "trait used by OwnedFd::from_raw_fd above")]
fn _trait_anchor() {
    let _: fn(i32) -> OwnedFd = |fd| unsafe { OwnedFd::from_raw_fd(fd) };
    let _: fn(OwnedFd) -> i32 = |fd| fd.into_raw_fd();
}
