//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 4: the agent loads a single eBPF object exposing six
//! programs (process exec, file open, exec validation, TCP v4/v6
//! connect, UDP/DNS) via [`SensorMultiplexer`]. Every decoded event
//! flows through the [`RuleEngine`] (only `ProcessSpawn` matches
//! current rules) and any verdict is enacted by the [`Executor`]
//! exactly as in Tappa 3.

use anyhow::{Context, Result};
use common::Event;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::SensorMultiplexer;
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

    let mut sensor = SensorMultiplexer::start()
        .await
        .context("starting the sensor multiplexer")?;
    info!(
        sensors = "process_spawn, file_open, exec_check, tcp_connect_v4, tcp_connect_v6, dns_query",
        "sensor multiplexer attached"
    );

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

/// Categorise + log + evaluate + (maybe) execute.
///
/// Tappa 4 ships five sensors; Tappa 2 rules only match `ProcessSpawn`,
/// so non-spawn events flow through as DEBUG telemetry and bypass the
/// engine. The kill syscalls + verify retries can sleep up to 50 ms,
/// so any execution dispatch goes through `spawn_blocking`.
async fn process_event(engine: &RuleEngine, executor: &Executor, event: Event) {
    match &event {
        Event::ProcessSpawn { .. } => info!(event = ?event, "process spawn detected"),
        Event::FileOpen {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %comm, filename = %filename, "file open")
        }
        Event::ExecCheck {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %comm, filename = %filename, "exec_check")
        }
        Event::TcpConnect {
            dst_addr,
            dst_port,
            family,
            comm,
            pid,
            ..
        } => {
            debug!(
                pid, comm = %comm, family,
                dst = %render_addr(*family, dst_addr),
                dst_port,
                "tcp_connect"
            )
        }
        Event::DnsQuery {
            dns_server,
            family,
            comm,
            pid,
            query_name,
            ..
        } => {
            debug!(
                pid, comm = %comm,
                server = %render_addr(*family, dns_server),
                query = %query_name,
                "dns_query"
            )
        }
    }

    let Some(verdict) = engine.evaluate(&event) else {
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

/// Render a 16-byte address according to family (`2` = AF_INET → first
/// 4 bytes; `10` = AF_INET6 → full v6).
fn render_addr(family: u8, bytes: &[u8; 16]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if family == 2 {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else if family == 10 {
        Ipv6Addr::from(*bytes).to_string()
    } else {
        format!("family={family}")
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
