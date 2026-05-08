//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 3: load the eBPF exec sensor, route every event through the
//! [`RuleEngine`], and dispatch the resulting verdict to the
//! [`Executor`] which actually performs the action (KillProcess /
//! KillProcessTree). Other actions are still NOPs awaiting Tappa 5.

use anyhow::{Context, Result};
use common::Event;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::ExecSensor;
use tokio::signal;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("NorthNarrow agent starting...");

    if let Err(e) = bump_memlock_rlimit() {
        warn!(error = %e, "failed to raise RLIMIT_MEMLOCK; eBPF maps may fail to allocate");
    }

    let mut sensor = ExecSensor::start()
        .await
        .context("starting the exec sensor")?;
    info!("exec sensor attached: tracing sched/sched_process_exec");

    let engine = RuleEngine::with_default_rules();
    info!(rules = engine.rule_count(), "decision engine ready");

    let executor = Executor::new();
    info!(
        own_pid = executor.own_pid(),
        protected = executor.protected().len(),
        "response executor ready (KillProcess + KillProcessTree active)"
    );

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    loop {
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => process_event(&engine, &executor, e).await,
                None => {
                    warn!("sensor pump exited; shutting down");
                    break;
                }
            },
            _ = signal::ctrl_c() => {
                info!("SIGINT received; shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received; shutting down");
                break;
            }
        }
    }

    info!("NorthNarrow agent stopped.");
    Ok(())
}

/// Log the spawn, evaluate the rule engine, dispatch the action.
///
/// The kill syscalls are blocking and `verify_dead` retries can sleep
/// up to 50 ms, so we offload to `spawn_blocking`. The agent's main
/// task keeps draining the sensor channel meanwhile.
async fn process_event(engine: &RuleEngine, executor: &Executor, event: Event) {
    info!(event = ?event, "process spawn detected");

    let Some(verdict) = engine.evaluate(&event) else {
        debug!(event = ?event, "process spawn produced no verdict");
        return;
    };

    warn!(
        rule = %verdict.rule_id,
        rule_name = %verdict.rule_name,
        category = %verdict.category,
        action = ?verdict.action,
        severity = ?verdict.severity,
        target_pid = verdict.event_pid,
        target_filename = %verdict.event_filename,
        reasoning = %verdict.reasoning,
        "VERDICT"
    );

    let exec = executor.clone();
    let action = verdict.action.clone();
    let target_pid = verdict.event_pid;
    let report = match tokio::task::spawn_blocking(move || exec.execute(action, target_pid)).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "executor task join failed");
            return;
        }
    };

    info!(
        action = ?report.action,
        primary = ?report.primary,
        additional_count = report.additional.len(),
        elapsed_us = report.elapsed.as_micros() as u64,
        "EXECUTED"
    );
}

/// Raise `RLIMIT_MEMLOCK` to infinity so older kernels accept large
/// eBPF map allocations. Best-effort: failure is logged and ignored.
fn bump_memlock_rlimit() -> std::io::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: a valid `rlimit` is passed by reference; the kernel only
    // reads from it. Failure is reported via the return code.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
