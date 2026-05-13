//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 4: the agent loads a single eBPF object exposing six
//! programs (process exec, file open, exec validation, TCP v4/v6
//! connect, UDP/DNS) via [`SensorMultiplexer`].
//!
//! Tappa 6 cascades each event through:
//!
//!   sensor → posture.observe → rule_engine
//!     → (match? execute : ade.evaluate → posture.modulate → execute?)
//!
//! ADE is invoked only when the rule engine produces no verdict, so
//! Tappa 3+5 regression behaviour is preserved exactly: `R001` still
//! kills `/tmp/nn-test-payload` before ADE ever sees the event.
//!
//! Sub-tappa 6.5: every event is also fed to the
//! [`PostureMachine`](northnarrow_agent::posture::PostureMachine), a
//! 4-tier defensive posture that persists across events. ADE
//! verdicts are passed through `posture.modulate_verdict` before
//! execution so an ambiguous `Allow` in `OBSERVING` becomes an
//! `Alert` once the posture has lifted to `ALERTED+`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use common::Event;
use northnarrow_agent::ade::{AdeConfig, AdeEngine, EventContext, HostContext};
use northnarrow_agent::admin_socket;
use northnarrow_agent::anti_tamper::admin_auth::AdminAuth;
use northnarrow_agent::anti_tamper::network_isolate::{NetworkIsolator, UnlockToken};
use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::posture::{CombatEntryHook, CombatReleaseHook, PostureMachine};
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::SensorMultiplexer;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "northnarrow-agent",
    version,
    about = "NorthNarrow XDR agent daemon (Linux)."
)]
struct Cli {
    /// Disable the Active Defense Engine (rule engine only).
    #[arg(long = "no-ade", default_value_t = false)]
    no_ade: bool,

    /// Override the GGUF model path used by ADE.
    #[arg(long = "ade-model", value_name = "PATH")]
    ade_model: Option<PathBuf>,

    /// Override the ADE inference timeout (seconds).
    #[arg(long = "ade-timeout", value_name = "SECS")]
    ade_timeout: Option<u64>,

    /// Override the ADE system prompt path.
    #[arg(long = "ade-prompt", value_name = "PATH")]
    ade_prompt: Option<PathBuf>,

    /// Override the rayon worker count candle uses for CPU
    /// inference. Defaults to `physical_cores - 1` (Sub-tappa 6.8).
    /// Setting `RAYON_NUM_THREADS` in the environment takes priority.
    #[arg(long = "ade-threads", value_name = "N")]
    ade_threads: Option<usize>,

    /// Path to the iptables ruleset NetworkIsolator applies on
    /// COMBAT entry. Production install: /etc/northnarrow/combat-rules.v4.
    /// Repo dev path: configs/combat-rules.v4.
    #[arg(
        long = "combat-rules",
        value_name = "PATH",
        default_value = "/etc/northnarrow/combat-rules.v4"
    )]
    combat_rules: PathBuf,

    /// Path to the admin pubkey file. If the file is missing, the
    /// admin socket is not started (the agent still runs, posture
    /// state still moves into Combat on intrusion, network isolation
    /// still engages — but there is no way to release without an
    /// admin pub key, so operators must reboot to clear COMBAT).
    #[arg(
        long = "admin-pub",
        value_name = "PATH",
        default_value = "/etc/northnarrow/admin.pub"
    )]
    admin_pub: PathBuf,

    /// Unix-socket path nn-admin connects to. Removed on startup if
    /// it already exists (stale file from prior unclean shutdown).
    #[arg(
        long = "admin-socket",
        value_name = "PATH",
        default_value = "/run/northnarrow/admin.sock"
    )]
    admin_socket: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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

    // Tappa 7: turn ourselves opaque to kill(2) and ptrace(2) before
    // anything spawns child tasks or holds resources we'd hate to
    // leak. Per-hook failures are logged WARN inside the call and
    // tolerated so the agent still runs on kernels without BPF-LSM.
    let agent_pid = std::process::id();
    if let Err(e) = sensor.attach_anti_tamper(agent_pid) {
        warn!(error = %e, agent_pid, "anti-tamper setup failed");
    }

    #[cfg(feature = "demo-tappa5")]
    let engine = RuleEngine::with_default_rules_and_demo_tappa5();
    #[cfg(not(feature = "demo-tappa5"))]
    let engine = RuleEngine::with_default_rules();
    info!(
        rules = engine.rule_count(),
        demo_tappa5 = cfg!(feature = "demo-tappa5"),
        "decision engine ready"
    );

    let executor = Executor::new();
    info!(
        own_pid = executor.own_pid(),
        protected = executor.protected().len(),
        "response executor ready (KillProcess + KillProcessTree active)"
    );

    let ade_engine = if cli.no_ade {
        info!("ADE disabled by --no-ade");
        None
    } else {
        let mut cfg = AdeConfig::default();
        if let Some(p) = cli.ade_model.clone() {
            cfg.model_path = p;
        }
        if let Some(p) = cli.ade_prompt.clone() {
            cfg.system_prompt_path = p;
        }
        if let Some(secs) = cli.ade_timeout {
            cfg.timeout = Duration::from_secs(secs);
        }
        if let Some(n) = cli.ade_threads {
            cfg.num_threads = Some(n);
        }
        // Sub-tappa 6.8 audit: this is the ONLY AdeEngine::new call
        // in the agent's hot path — model weights, tokenizer, KV
        // state machine and the rayon pool are loaded ONCE at
        // startup and the resulting handle is shared into
        // process_event via Arc<AdeEngine> (cheap to clone). Any
        // future change that constructs a new engine inside the
        // event loop would silently re-pay the ~5 GiB GGUF mmap
        // and the warmup pass, so guard this invariant in review.
        match AdeEngine::new(cfg).await {
            Ok(engine) => {
                info!(
                    backend = engine.backend_name(),
                    model_path = %engine.config().model_path.display(),
                    warmup_latency_ms = engine.warmup_latency_ms(),
                    timeout_s = engine.config().timeout.as_secs(),
                    "ADE engine ready"
                );
                Some(Arc::new(engine))
            }
            Err(e) => {
                warn!(?e, "ADE engine unavailable, fallback to rule-only mode");
                None
            }
        }
    };

    let correlation = CorrelationBuffer::with_default_capacity();
    let host = HostContext::discover();

    // Tappa 7 task 7 / Tappa 8: anti-tamper response pipeline. The
    // NetworkIsolator owns the iptables shell-out; engage runs on
    // any non-Combat → Combat edge, release only fires for an
    // Ed25519-verified admin unlock (capability gated via
    // UnlockToken). If the ruleset is missing we WARN-and-continue
    // with no isolator, so the agent still boots in dev environments
    // without /etc/northnarrow/ provisioned.
    let isolator = match NetworkIsolator::new(cli.combat_rules.clone()) {
        Ok(i) => Some(Arc::new(i)),
        Err(e) => {
            warn!(
                error = %e,
                path = %cli.combat_rules.display(),
                "combat ruleset missing; COMBAT entry will not engage network isolation"
            );
            None
        }
    };

    let posture = if let Some(iso) = isolator.as_ref() {
        let iso_engage = Arc::clone(iso);
        let iso_release = Arc::clone(iso);
        let engage_hook: CombatEntryHook = Arc::new(move || {
            if let Err(e) = iso_engage.engage() {
                tracing::error!(error = %e, "COMBAT engage failed; agent continues in degraded mode");
            }
        });
        let release_hook: CombatReleaseHook = Arc::new(move |token: UnlockToken| {
            if let Err(e) = iso_release.release(token) {
                tracing::error!(
                    error = %e,
                    "admin release failed; iptables state may need manual cleanup"
                );
            }
        });
        PostureMachine::new_with_hooks(engage_hook, release_hook)
    } else {
        PostureMachine::new()
    };
    info!("posture state machine initialized (state: OBSERVING)");

    // Optional admin socket: only spawned if admin pubkey config
    // is present. Missing config = no unlock path; the agent still
    // runs but COMBAT can only be cleared by reboot.
    if let Some(iso) = isolator.as_ref() {
        match AdminAuth::load(&cli.admin_pub) {
            Ok(auth) => {
                let auth = Arc::new(auth);
                let posture_clone = posture.clone();
                let iso_clone = Arc::clone(iso);
                let socket_path = cli.admin_socket.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        admin_socket::serve(socket_path, auth, Arc::new(posture_clone), iso_clone)
                            .await
                    {
                        warn!(error = %e, "admin socket serve loop exited");
                    }
                });
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %cli.admin_pub.display(),
                    "admin pub key file missing or invalid; admin socket disabled"
                );
            }
        }
    }

    // Decay loop: walks the posture down (ALERTED→OBSERVING after 1h
    // idle, ENGAGED→ALERTED after 24h idle). COMBAT never decays
    // here; it requires an admin-signed release. The 60 s cadence is
    // a coarse heartbeat, not a precise deadline.
    let posture_decay = posture.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if let Some(new_state) = posture_decay.tick_decay() {
                info!(state = %new_state.kind(), "posture decay transition");
            }
        }
    });

    // Install the three shutdown signals up front, before the loop.
    // Re-creating the future inside `select!` every iteration (the
    // old `signal::ctrl_c()` shorthand) re-runs handler registration
    // each tick and interacts badly with `SIG_IGN` inherited from
    // `bash &` + `nohup` (live test 2026-05-12 found SIGINT and
    // SIGHUP silently dropped; only SIGQUIT brought the agent down).
    // A pre-registered `Signal` stream is the documented robust path.
    //
    // SIGTERM is normally caught by the Tappa 7 LSM hook before
    // userland ever sees it; the handler is here for builds running
    // without anti-tamper (kernels lacking `bpf` in their LSM chain).
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    loop {
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => process_event(
                    &engine,
                    &executor,
                    ade_engine.as_deref(),
                    &correlation,
                    &host,
                    &posture,
                    e,
                ).await,
                None => {
                    warn!("sensor pump exited; shutting down");
                    break;
                }
            },
            _ = sigint.recv() => {
                info!("SIGINT received; shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received; shutting down");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; shutting down");
                break;
            }
        }
    }

    if let Some(ade) = &ade_engine {
        let snap = ade.stats();
        info!(
            total = snap.total_inferences,
            success = snap.successful_verdicts,
            malformed = snap.malformed_outputs,
            timeouts = snap.timeouts,
            backend_errors = snap.backend_errors,
            avg_ms = snap.avg_latency_ms,
            p50_ms = snap.p50_latency_ms,
            p95_ms = snap.p95_latency_ms,
            p99_ms = snap.p99_latency_ms,
            "ADE shutdown stats"
        );
    }

    // Best-effort socket cleanup so a future agent process can bind
    // without first encountering a stale file. The accept loop is
    // about to be torn down with the runtime, so this race is between
    // tokio's drop-of-the-listener and our unlink — either order
    // leaves the filesystem clean.
    admin_socket::unlink_socket(&cli.admin_socket);

    info!("NorthNarrow agent stopped.");
    Ok(())
}

/// Categorise + log + evaluate + (maybe) execute.
///
/// Tappa 4 ships five sensors; Tappa 2 rules only match `ProcessSpawn`,
/// so non-spawn events flow through as DEBUG telemetry and bypass the
/// engine. The kill syscalls + verify retries can sleep up to 50 ms,
/// so any execution dispatch goes through `spawn_blocking`.
///
/// Tappa 6: every event also lands in the correlation buffer (so ADE
/// has recent context), and unmatched events get routed through ADE
/// when the engine is enabled.
async fn process_event(
    engine: &RuleEngine,
    executor: &Executor,
    ade: Option<&AdeEngine>,
    correlation: &CorrelationBuffer,
    host: &HostContext,
    posture: &PostureMachine,
    event: Event,
) {
    // Run posture detection BEFORE we push the focal event into the
    // correlation buffer — the trigger detector counts the focal as
    // a fresh +1 on top of `recent`, and `recent` already containing
    // the focal would double-count it.
    let recent_for_posture = correlation.snapshot();
    if let Some(new_state) = posture.observe(&event, &recent_for_posture) {
        warn!(state = %new_state.kind(), "POSTURE TRANSITION");
    }
    correlation.push(event.clone());

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
        // Tappa 7: kernel-side LSM hook denied a tamper attempt on
        // protected state. The posture machine observed the event
        // at the top of this function and will route it through the
        // ConfirmedIntrusion trigger (anti-tamper denial = strongest
        // possible posture signal, ENGAGED → COMBAT).
        Event::FsProtectDenial {
            pid,
            uid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } => {
            warn!(
                pid, uid, comm = %comm,
                op = %operation,
                target_dev, target_ino,
                "ANTI-TAMPER DENIAL"
            );
            // Short-circuit: a kernel deny is not something the
            // rule engine or ADE LLM should re-evaluate. The
            // posture trigger above is the response; we are done.
            return;
        }
    }

    if let Some(verdict) = engine.evaluate(&event) {
        warn!(
            rule = %verdict.rule_id,
            rule_name = %verdict.rule_name,
            category = %verdict.category,
            action = ?verdict.action,
            severity = ?verdict.severity,
            target_pid = verdict.event_pid,
            target_filename = %verdict.event_filename,
            reasoning = %verdict.reasoning,
            "VERDICT (rule)"
        );

        let exec = executor.clone();
        let action = verdict.action.clone();
        let target_pid = verdict.event_pid;
        let report =
            match tokio::task::spawn_blocking(move || exec.execute(action, target_pid)).await {
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
        return;
    }

    let Some(ade) = ade else {
        return;
    };

    // Only ProcessSpawn / ExecCheck warrant ADE evaluation today;
    // FileOpen / TCP / DNS volumes are too high to feed the LLM and
    // they don't have an immediate executor mapping anyway.
    if !matches!(&event, Event::ProcessSpawn { .. } | Event::ExecCheck { .. }) {
        return;
    }

    debug!("no rule matched, escalating to ADE");
    let context = EventContext {
        recent_events: correlation.get_correlated_default(&event),
        host_context: host.clone(),
    };

    info!("ADE inference started");
    let verdict = match ade.evaluate(&event, &context).await {
        Ok(v) => v,
        Err(e) => {
            warn!(?e, "ADE error, defaulting to log-only");
            return;
        }
    };

    info!(
        latency_ms = verdict.metadata.inference_latency_ms,
        "ADE inference completed"
    );
    warn!(
        action = %verdict.verdict,
        severity = %verdict.severity,
        confidence = verdict.confidence,
        trace_id = %verdict.trace_id,
        reasoning = %verdict.reasoning.step_5_decision,
        "VERDICT (ADE)"
    );

    let raw_action = verdict.verdict;
    let raw_severity = verdict.severity;
    let verdict = posture.modulate_verdict(verdict);
    if verdict.verdict != raw_action || verdict.severity != raw_severity {
        info!(
            posture = %posture.current_kind(),
            from_action = %raw_action,
            from_severity = %raw_severity,
            to_action = %verdict.verdict,
            to_severity = %verdict.severity,
            "verdict modulated by posture"
        );
    }

    if !verdict.requires_execution() {
        info!(action = %verdict.verdict, "ADE verdict logged, no execution needed");
        return;
    }

    let exec = executor.clone();
    let action = verdict.to_response_action();
    let target_pid = match &event {
        Event::ProcessSpawn { pid, .. } | Event::ExecCheck { pid, .. } => *pid,
        _ => return,
    };
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
        "EXECUTED (from ADE)"
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
