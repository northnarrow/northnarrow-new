//! The event loop (Wave 4 restructure, R11a, lab PR 261: from `main.rs`):
//! the sensors' events through the pipeline, the telemetry tasks' liveness,
//! the signals and the admin shutdown; the lab builds' triggers.
//!
//! R12b (lab PR 269, plan §3.4): the decision runs on a thread of its own,
//! `nn-decision` ([`decision_loop`]) — it takes each event from the bus
//! (blocked, not awaiting), judges it ([`process_event`], no `await`) and
//! counts its delay; this task keeps the rest: the signals, the admin
//! shutdown, the telemetry tasks' liveness (SNS-001), the lab triggers.
//! Either end ends the other: a stop here stops the thread, the bus closed
//! (or the thread's end) stops the loop here; the thread is joined before
//! the bus is stopped and the stop reported.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::posture::PostureMachine;
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::bus::{BusReceiver, Recv};
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

/// What the decision thread judges with (the event loop's handles).
struct Pipeline<'a> {
    engine: &'a RuleEngine,
    executor: &'a Executor,
    correlation: &'a CorrelationBuffer,
    posture: &'a PostureMachine,
    combat: &'a Combat,
    canary_detector: &'a Option<Arc<northnarrow_agent::canary::detector::Detector>>,
    detection_sink: &'a Option<northnarrow_agent::detection_store::DetectionSink>,
    telemetry_probe: &'a Option<northnarrow_agent::telemetry_probe::TelemetryProbe>,
    expected_denial: &'a northnarrow_agent::boot::deny_selftest::ExpectedDenial,
}

/// R12b: between the event loop and its decision thread.
#[derive(Default)]
struct DecisionControl {
    /// The loop stops: the thread ends at its next turn.
    stop: AtomicBool,
    /// The thread ended (the bus closed, or a panic): the loop stops.
    ended: tokio::sync::Notify,
    /// `debug-trigger` builds: the seconds the decision is to stand still
    /// (lab PR 216's `debug-stall-loop`, read by the loop's check).
    #[cfg(feature = "debug-trigger")]
    stall_secs: std::sync::atomic::AtomicU64,
}

/// Wakes the loop when the decision thread ends, however it ends.
struct Ended<'a>(&'a DecisionControl);

impl Drop for Ended<'_> {
    fn drop(&mut self) {
        self.0.ended.notify_one();
    }
}

/// How long the decision thread waits for an event before it looks at its
/// stop flag and counts a round of the loop (lab PR 216: the watchdog's
/// progress check).
const DECISION_IDLE: Duration = Duration::from_millis(500);

/// The event loop: every 5 s the telemetry tasks checked (SNS-001); a
/// signal or the admin shutdown ends it. The events are judged on the
/// decision thread ([`decision_loop`]): each offered to the telemetry
/// probe, then [`process_event`].
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
    detection_sink: &Option<northnarrow_agent::detection_store::DetectionSink>,
    audit_log: &AuditHandle,
    telemetry_probe: &Option<northnarrow_agent::telemetry_probe::TelemetryProbe>,
    expected_denial: &northnarrow_agent::boot::deny_selftest::ExpectedDenial,
    signals: &mut Signals,
) -> Stopped {
    // Why the event loop ended — written as the signed `agent_stop` entry
    // below; a run that never writes it is reported by the next boot.
    let loop_started = std::time::Instant::now();
    let Some(mut rx) = sensor.take_receiver() else {
        error!("event bus: no receiver to judge from — stopping");
        return Stopped {
            stop_reason: "sensor_pump_exited",
            loop_started,
        };
    };
    let lineage = sensor.lineage();
    let pipeline = Pipeline {
        engine,
        executor,
        correlation,
        posture,
        combat,
        canary_detector,
        detection_sink,
        telemetry_probe,
        expected_denial,
    };
    let rt = tokio::runtime::Handle::current();
    let ctl = DecisionControl::default();
    // The decision thread borrows the event loop's handles: a scoped thread,
    // this task's worker handed to the runtime meanwhile (`block_in_place`);
    // the loop below runs on this thread (`Handle::block_on`).
    let stop_reason = northnarrow_agent::runtime::off_the_runtime(|| {
        std::thread::scope(|s| {
            let decider = std::thread::Builder::new()
                .name("nn-decision".to_string())
                .spawn_scoped(s, || {
                    let _ended = Ended(&ctl);
                    let _rt = rt.enter();
                    decision_loop(&mut rx, lineage.as_ref(), &rt, &ctl, &pipeline)
                });
            let decider = match decider {
                Ok(d) => d,
                Err(e) => {
                    error!(error = %e, "the decision thread did not start — stopping");
                    return "decision_thread_failed";
                }
            };
            let reason = rt.block_on(watch_loop(cli, sensor, combat, audit_log, signals, &ctl));
            ctl.stop.store(true, Ordering::Release);
            match decider.join() {
                Ok(()) => reason,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    });
    // Lab PR 267 (R12a), review #471 M3: the bus is closed, the events it
    // still held counted in a signed row, and every drop not in a signed
    // row yet signed, before the stop is (a queue's window does not hold
    // it back). R12b: the receiver back from the joined decision thread.
    sensor.restore_receiver(rx);
    // R12b: the canary trips judged are in their chain before the stop.
    if let Some(d) = canary_detector {
        if !d.flush(Duration::from_secs(5)) {
            warn!("canary: trips still queued for their access rows at the stop");
        }
        let (per_canary, unwritten) = d.unwritten();
        if unwritten > 0 {
            warn!(
                unwritten,
                canaries = per_canary.len(),
                "canary: trips whose access rows the full writer's queue did not take (counted, \
                 their events judged)"
            );
        }
    }
    sensor.stop_bus();
    Stopped {
        stop_reason,
        loop_started,
    }
}

/// R12b (lab PR 269): the decision thread — each event taken from the bus
/// (the execs it overtook taught to the lineage by the receiver, to the
/// rules here, before it is judged), offered to the telemetry probe, judged
/// ([`process_event`]), its delay counted; a round of the loop counted for
/// the watchdog at least every [`DECISION_IDLE`]. Ends on the loop's stop,
/// or when the bus is closed and empty.
fn decision_loop(
    rx: &mut BusReceiver,
    lineage: Option<&northnarrow_agent::posture::lineage::AuthSessionTracker>,
    rt: &tokio::runtime::Handle,
    ctl: &DecisionControl,
    p: &Pipeline<'_>,
) {
    let Combat {
        ladder,
        host_stopping,
        systemd,
        cow_guard,
        ..
    } = p.combat;
    // One event judged: offered to the telemetry probe (Tappa 10.8: every
    // event before the decision engine; R11c, lab PR 264: the probe the late
    // binding started), then `process_event`.
    let judge = |e: nn_model::Event| {
        if let Some(probe) = p.telemetry_probe {
            probe.observe(&e);
        }
        process_event(
            p.engine,
            p.executor,
            p.correlation,
            p.posture,
            ladder,
            // Tappa 9.5 K6: detector handle wired in. When the canary
            // subsystem boot failed (missing signing key, registry open
            // error), canary_detector is None and process_event
            // short-circuits to the source event without canary filtering.
            p.canary_detector.as_deref(),
            // Tappa 9.0.a: detection-persistence sink (off the hot path).
            p.detection_sink.as_ref(),
            p.expected_denial,
            host_stopping,
            systemd,
            cow_guard,
            e,
        );
    };
    loop {
        if ctl.stop.load(Ordering::Acquire) {
            return;
        }
        // R12b: the signals PID 1 relayed that the decision handed to the
        // systemd watch, judged now on its answer (`SystemdSnapshot`).
        for e in systemd.take_answered() {
            judge(e);
        }
        // Lab PR 216: one round of the loop, for the watchdog's progress
        // check — the bus's wait brings a round at least every
        // `DECISION_IDLE` on an idle host, so a count that stands still is
        // a decision thread that does.
        northnarrow_agent::loop_progress::tick();
        #[cfg(feature = "debug-trigger")]
        debug_stall_decision(ctl);
        match rx.recv_blocking(rt, lineage, DECISION_IDLE) {
            Recv::Event(received) => {
                let received = *received;
                // Lab PR 267 (R12a): a tamper event taken ahead of execs
                // still queued brings them; the lineage has learned them,
                // the engine's rules learn them here, so the event is
                // judged on the process tree of every exec that reached the
                // bus before it (they are judged in their own turn, which
                // then changes nothing there).
                for exec in &received.overtaken {
                    p.engine.observe_arrival(exec);
                }
                let e = received.envelope.event;
                judge(e);
                // Lab PR 267: the event's latency, queue to decision; R12b:
                // its delay from the record's kernel time (stage 5).
                rx.decided();
            }
            Recv::Idle => {}
            Recv::Closed => {
                warn!("sensor pump exited; shutting down");
                return;
            }
        }
    }
}

/// The event loop's own part: the telemetry tasks' liveness (SNS-001)
/// every 5 s, the lab triggers, the signals, the admin shutdown, the
/// decision thread's end. Returns why it ended.
async fn watch_loop(
    #[cfg_attr(not(feature = "debug-trigger"), allow(unused_variables))] cli: &Cli,
    sensor: &SensorMultiplexer,
    combat: &Combat,
    audit_log: &AuditHandle,
    signals: &mut Signals,
    ctl: &DecisionControl,
) -> &'static str {
    let Combat {
        #[cfg(feature = "debug-trigger")]
        debug_guard,
        shutdown_signal,
        ..
    } = combat;
    let Signals {
        sigint,
        sigterm,
        sighup,
    } = signals;
    // External audit SNS-001: a telemetry task that ended (a dead ring
    // pump, a drain, the open-sensor rule refresher) is checked for here;
    // the bus can never report it.
    let mut pump_check = tokio::time::interval(PUMP_CHECK_PERIOD);
    pump_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = ctl.ended.notified() => {
                // the decision thread ended: the bus closed (every sender
                // gone), or it panicked (the join below rethrows)
                return "sensor_pump_exited";
            }
            _ = pump_check.tick() => {
                #[cfg(feature = "debug-trigger")]
                debug_abort_pump(sensor, &cli.admin_socket);
                #[cfg(feature = "debug-trigger")]
                debug_protected_query(debug_guard, &cli.admin_socket);
                #[cfg(feature = "debug-trigger")]
                debug_stall_loop(&cli.admin_socket, ctl);
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
                    return "sensor_pump_exited";
                }
            }
            _ = sigint.recv() => {
                info!("SIGINT received; shutting down");
                return "sigint";
            }
            _ = sigterm.recv() => {
                // External audit EBPF-001: PID 1's SIGTERM reaches the agent
                // only inside a signed trusted-installer window or from
                // `systemd-shutdown`, the last stage of a shutdown.
                let reason = if pid1_is_systemd_shutdown() { "system_shutdown" } else { "sigterm" };
                info!(reason, "SIGTERM received; shutting down");
                return reason;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; shutting down");
                return "sighup";
            }
            // Tappa 8 A8: admin-authorised graceful shutdown. The
            // dispatcher has already (a) verified the
            // ShutdownRequest quorum, (b) written the on-disk
            // marker the watchdog will honour, and (c) replied
            // Success to the client BEFORE firing this signal.
            // Ending the loop runs the existing shutdown
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
                return "admin_shutdown";
            }
        }
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
/// socket, holding a number of seconds (at most 600), makes the decision
/// thread stand still that long (R12b: the decision's own thread; the
/// event loop and the admin socket keep answering). Lab check of lab PR
/// 216: the watchdog must see the loop stand still (`event_loop_stalled`)
/// and recover the agent; EXP-13b's stalled loop.
#[cfg(feature = "debug-trigger")]
fn debug_stall_loop(admin_socket: &std::path::Path, ctl: &DecisionControl) {
    let Some(dir) = admin_socket.parent() else {
        return;
    };
    let trigger = dir.join("debug-stall-loop");
    let Ok(text) = std::fs::read_to_string(&trigger) else {
        return;
    };
    let _ = std::fs::remove_file(&trigger);
    let secs = text.trim().parse::<u64>().unwrap_or(0).min(600);
    ctl.stall_secs.store(secs, Ordering::Release);
}

/// `debug-trigger` builds only: the decision thread stands still the
/// seconds `debug-stall-loop` asked for (lab PR 216's check, EXP-13b).
#[cfg(feature = "debug-trigger")]
fn debug_stall_decision(ctl: &DecisionControl) {
    let secs = ctl.stall_secs.swap(0, Ordering::AcqRel);
    if secs > 0 {
        warn!(
            secs,
            "debug-trigger: the decision thread stalls on request (lab test of lab PR 216)"
        );
        std::thread::sleep(Duration::from_secs(secs));
    }
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
