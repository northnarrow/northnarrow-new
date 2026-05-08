//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 1: load the eBPF process-exec sensor and stream events to the
//! log. No decision engine, no response actions yet (those land in
//! Tappe 2 and 3 respectively).

use anyhow::{Context, Result};
use northnarrow_agent::sensors::ExecSensor;
use tokio::signal;
use tracing::{info, warn};
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

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    loop {
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => info!(event = ?e, "process spawn detected"),
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
