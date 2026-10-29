//! The event loop (Wave 4 restructure, R11a, lab PR 261: from `main.rs`):
//! the sensors' events through the pipeline, the telemetry tasks' liveness,
//! the signals and the admin shutdown; the lab builds' triggers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::posture::PostureMachine;
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::SensorMultiplexer;
use tracing::{error, info, warn};

use crate::boot::cli::Cli;
use crate::boot::evidence::{attest_degraded_at, AuditHandle};
use crate::boot::posture::Combat;
use crate::boot::ready::Armed;
use crate::boot::tasks::Signals;
use crate::pipeline::pid1_is_systemd_shutdown;
use crate::pipeline::process_event::process_event;

/// Why the event loop ended (the signed `agent_stop`), and when it began.
pub(crate) struct Stopped {
    pub(crate) stop_reason: &'static str,
    pub(crate) loop_started: Instant,
}

/// The event loop: every event offered to the telemetry probe, then
/// [`process_event`]; every 5 s the telemetry tasks checked (SNS-001); a
/// signal or the admin shutdown ends it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    _armed: Armed,
    // the debug triggers' files sit next to the admin socket
    #[cfg_attr(not(feature = "debug-trigger"), allow(unused_variables))] cli: &Cli,
    sensor: &mut SensorMultiplexer,
    engine: &RuleEngine,
    executor: &Executor,
    correlation: &CorrelationBuffer,
    posture: &PostureMachine,
    combat: &Combat,
    canary_detector: &Option<Arc<northnarrow_agent::canary::detector::Detector>>,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    detection_sink: &Option<northnarrow_agent::detection_store::DetectionSink>,
    audit_log: &AuditHandle,
    telemetry_probe: &Option<northnarrow_agent::telemetry_probe::TelemetryProbe>,
    expected_denial: &northnarrow_agent::boot::deny_selftest::ExpectedDenial,
    signals: &mut Signals,
) -> Stopped {
    let Combat {
        ladder,
        #[cfg(feature = "debug-trigger")]
        debug_guard,
        shutdown_signal,
        host_stopping,
        cow_guard,
    } = combat;
    let Signals {
        sigint,
        sigterm,
        sighup,
    } = signals;
    // Why the event loop ended — written as the signed `agent_stop` entry
    // below; a run that never writes it is reported by the next boot.
    let loop_started = std::time::Instant::now();
    #[allow(unused_assignments)]
    let mut stop_reason = "unknown";
    // External audit SNS-001: a telemetry task that ended (a dead ring
    // pump, a drain, the open-sensor rule refresher) is checked for here;
    // `next_event()` can never report it.
    let mut pump_check = tokio::time::interval(PUMP_CHECK_PERIOD);
    pump_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // Lab PR 216: one round of the loop, for the watchdog's progress
        // check — `pump_check` brings a round at least every 5 s on an idle
        // host, so a count that stands still is a loop that does.
        northnarrow_agent::loop_progress::tick();
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => {
                    // Tappa 10.8 telemetry probe: every event is offered to
                    // the probe tracker before the decision engine (R11c, lab
                    // PR 264: the probe the late binding started).
                    if let Some(probe) = telemetry_probe {
                        probe.observe(&e);
                    }
                    process_event(
                    engine,
                    executor,
                    correlation,
                    posture,
                    ladder,
                    // Tappa 9.5 K6: detector handle wired in. When
                    // the canary subsystem boot above failed
                    // (missing signing key, registry open error),
                    // canary_detector is None and process_event
                    // short-circuits to the source event without
                    // canary filtering.
                    canary_detector.as_deref(),
                    // FIM-009 self-upgrade (§15.1): lazy TTL expiry sweep.
                    installer_override,
                    // Tappa 9.0.a: detection-persistence sink (off the hot path).
                    detection_sink.as_ref(),
                    expected_denial,
                    host_stopping,
                    cow_guard,
                    e,
                ).await
                }
                None => {
                    warn!("sensor pump exited; shutting down");
                    stop_reason = "sensor_pump_exited";
                    break;
                }
            },
            _ = pump_check.tick() => {
                #[cfg(feature = "debug-trigger")]
                debug_abort_pump(sensor, &cli.admin_socket);
                #[cfg(feature = "debug-trigger")]
                debug_protected_query(debug_guard, &cli.admin_socket);
                #[cfg(feature = "debug-trigger")]
                debug_stall_loop(&cli.admin_socket);
                let dead = sensor.finished_pumps();
                if !dead.is_empty() {
                    // A blind sensor is not hidden behind a silent restart:
                    // signed `subsystem_degraded` naming the task, signed
                    // `agent_stop` (`sensor_pump_exited`), non-zero exit, and
                    // the watchdog respawns the agent (its ceiling bounds a
                    // pump that dies at every start).
                    let names = dead.join(", ");
                    error!(
                        pumps = %names,
                        "sensor pump exited — its telemetry is lost; stopping so the watchdog restarts the agent"
                    );
                    attest_degraded_at(
                        audit_log.as_ref(),
                        &format!(
                            "sensor pump exited: {names} (its telemetry was lost; the agent stops for a watchdog restart)"
                        ),
                        false,
                    );
                    stop_reason = "sensor_pump_exited";
                    break;
                }
            }
            _ = sigint.recv() => {
                info!("SIGINT received; shutting down");
                stop_reason = "sigint";
                break;
            }
            _ = sigterm.recv() => {
                // External audit EBPF-001: PID 1's SIGTERM reaches the agent
                // only inside a signed trusted-installer window or from
                // `systemd-shutdown`, the last stage of a shutdown.
                stop_reason = if pid1_is_systemd_shutdown() { "system_shutdown" } else { "sigterm" };
                info!(reason = stop_reason, "SIGTERM received; shutting down");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; shutting down");
                stop_reason = "sighup";
                break;
            }
            // Tappa 8 A8: admin-authorised graceful shutdown. The
            // dispatcher has already (a) verified the
            // ShutdownRequest quorum, (b) written the on-disk
            // marker the watchdog will honour, and (c) replied
            // Success to the client BEFORE firing this signal.
            // Breaking the loop runs the existing shutdown
            // sequence (pid_file removal, admin socket
            // unlink), then main() returns Ok(()) and the
            // process exits 0.
            //
            // Design note (§10.3 step 4): we deliberately do NOT
            // release the COMBAT iptables ruleset here. "Shutdown
            // of the agent is orthogonal to network state" — the
            // operator's intent is to stop the agent, not to
            // declare the threat over. The next agent boot
            // inherits the existing iptables state and reports
            // COMBAT in `status`; the operator clears it with a
            // separate `nn-admin unlock` after restart if they
            // want.
            _ = shutdown_signal.wait() => {
                info!(
                    target: "admin.shutdown",
                    "admin-authorised shutdown signal received; \
                     beginning graceful exit (COMBAT state preserved \
                     across restart per design §10.3 step 4)"
                );
                stop_reason = "admin_shutdown";
                break;
            }
        }
    }
    Stopped {
        stop_reason,
        loop_started,
    }
}

/// External audit SNS-001: how often the main loop checks that every
/// telemetry task still runs.
const PUMP_CHECK_PERIOD: Duration = Duration::from_secs(5);

/// `debug-trigger` builds only: a file `debug-protected-query` next to the
/// admin socket, holding PIDs, is answered with one WARN per PID — what the
/// COMBAT guard decides for it, and what `/proc/<pid>/exe` gave. Lab check
/// of CMB-022 (lab PR 181): with `CAP_SYS_PTRACE` removed, sshd and the
/// watchdog spared by their uid-0 unit, a session's root process not.
#[cfg(feature = "debug-trigger")]
fn debug_protected_query(
    guard: &dyn northnarrow_agent::combat::ProtectedProcs,
    admin_socket: &std::path::Path,
) {
    let Some(dir) = admin_socket.parent() else {
        return;
    };
    let trigger = dir.join("debug-protected-query");
    let Ok(text) = std::fs::read_to_string(&trigger) else {
        return;
    };
    let _ = std::fs::remove_file(&trigger);
    for pid in text
        .split_whitespace()
        .filter_map(|p| p.parse::<u32>().ok())
        .take(64)
    {
        let exe = match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(p) => p.display().to_string(),
            Err(e) => format!("unreadable ({e})"),
        };
        warn!(
            pid,
            exe = %nn_model::log_escape::Escaped(&exe),
            spared = guard.protected_reason(pid).map_or("no", |r| r.as_str()),
            "debug-trigger: COMBAT guard query (lab test of CMB-022)"
        );
    }
}

/// `debug-trigger` builds only: a file `debug-stall-loop` next to the admin
/// socket, holding a number of seconds (at most 600), blocks the event loop
/// that long — the admin socket, on other workers, keeps answering. Lab
/// check of lab PR 216: the watchdog must see the loop stand still
/// (`event_loop_stalled`) and recover the agent.
#[cfg(feature = "debug-trigger")]
fn debug_stall_loop(admin_socket: &std::path::Path) {
    let Some(dir) = admin_socket.parent() else {
        return;
    };
    let trigger = dir.join("debug-stall-loop");
    let Ok(text) = std::fs::read_to_string(&trigger) else {
        return;
    };
    let _ = std::fs::remove_file(&trigger);
    let secs = text.trim().parse::<u64>().unwrap_or(0).min(600);
    warn!(
        secs,
        "debug-trigger: the event loop stalls on request (lab test of lab PR 216)"
    );
    std::thread::sleep(Duration::from_secs(secs));
}

/// `debug-trigger` builds only: a file `debug-abort-pump` next to the admin
/// socket, holding a pump label (`fs_protect`), aborts that pump; the next
/// liveness check then stops the agent. Lab check of SNS-001 without a
/// way to kill a task from outside the process.
#[cfg(feature = "debug-trigger")]
fn debug_abort_pump(
    sensor: &northnarrow_agent::sensors::SensorMultiplexer,
    admin_socket: &std::path::Path,
) {
    let Some(dir) = admin_socket.parent() else {
        return;
    };
    let trigger = dir.join("debug-abort-pump");
    let Ok(label) = std::fs::read_to_string(&trigger) else {
        return;
    };
    let _ = std::fs::remove_file(&trigger);
    let label = label.trim();
    let found = sensor.debug_abort_pump(label);
    warn!(
        pump = label,
        found, "debug-trigger: pump aborted on request (lab test of SNS-001)"
    );
}
