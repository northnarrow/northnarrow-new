//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 2: load the eBPF process-exec sensor and route every event
//! through the hardcoded [`RuleEngine`]. Verdicts are LOGGED ONLY —
//! no response action is executed yet. Tappa 3 wires real KillProcess.

use anyhow::{Context, Result};
use common::Event;
use northnarrow_agent::decision::RuleEngine;
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
    info!(
        rules = engine.rule_count(),
        "decision engine ready (would-execute mode)"
    );

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    loop {
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => process_event(&engine, e),
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

/// Log the spawn, run the rule engine, log the verdict (if any).
///
/// Tappa 2 contract: the agent does NOT execute the verdict's action.
/// `KillProcess` becomes a `would_kill_pid` tag in the warn log.
fn process_event(engine: &RuleEngine, event: Event) {
    info!(event = ?event, "process spawn detected");
    if let Some(verdict) = engine.evaluate(&event) {
        warn!(
            rule = %verdict.rule_id,
            rule_name = %verdict.rule_name,
            category = %verdict.category,
            action = ?verdict.action,
            severity = ?verdict.severity,
            would_target_pid = verdict.event_pid,
            target_filename = %verdict.event_filename,
            reasoning = %verdict.reasoning,
            "VERDICT (would-execute mode, no action taken in Tappa 2)"
        );
    } else {
        debug!(event = ?event, "process spawn produced no verdict");
    }
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
