
/// The network drain (Tappa 10 N9): the netflow and listener logs (one that
/// cannot be opened is a signed degradation and the drain runs without it:
/// lab PR 218, P0 C-14), the rules' gate, the open-flow snapshots, the
/// drain task.
#[allow(clippy::too_many_arguments)]
fn boot_net(
    cli: &Cli,
    agent_id: [u8; 16],
    rotation_protection: std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager>,
    netflow_rotation: northnarrow_agent::chainlog::RotationConfig,
    audit_log: &AuditHandle,
    flow_tracker: Arc<parking_lot::Mutex<FlowTracker>>,
    dns_cache: Arc<DnsCache>,
    lineage: &AuthSessionTracker,
    sensor: &mut SensorMultiplexer,
    net_bufs: northnarrow_agent::sensors::multiplexer::NetRingBufs,
    netflow_blocklist: Arc<NetBlocklist>,
    chain_store: Arc<
        parking_lot::Mutex<northnarrow_agent::decision::correlation::CorrelationStore>,
    >,
) {
    // ── Tappa 10 N9 — net drain subsystem boot ─────────────────────
    //
    // Closes the kernel→userland net loop: the multiplexer above
    // has already attached the three N2 BPF programs (kprobe
    // inet_csk_listen_start + fexit tcp_close + kprobe
    // udp_sendmsg_outbound) and surfaced the two new ringbufs in
    // `net_bufs`. Here we:
    //   1. Open the two chained on-disk logs (`netflow.jsonl` +
    //      `netflow_listeners.jsonl`) — same chain shape as the
    //      Tappa 8 audit log + Tappa 9 drift log;
    //   2. spawn `net::drain::drain_loop` against the two ringbufs
    //      with shared `flow_tracker` + `dns_cache` (the
    //      multiplexer's TcpConnect / DnsQuery pumps feed those
    //      from the connect / DNS-query sides);
    //   3. register the spawned handle on the multiplexer so a
    //      clean shutdown aborts it alongside the sensor pumps.
    //
    // Per-step failures are warn-logged and skipped — the agent
    // still boots without net drain (mirrors the FIM degrade-not-
    // fail posture). Without the drain, kernel close + listen
    // events accumulate in the ringbuf until it fills + the
    // verifier-side ringbuf drop counter ticks; NN-L-NET-001..009
    // see zero events but the agent stays up.
    {
        use northnarrow_agent::net::drain::{drain_loop, NetFlowDb, NetListenerDb};

        let netflow_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        )
        .and_then(|key| {
            NetFlowDb::open(
                &cli.netflow_file,
                key,
                agent_id,
                std::sync::Arc::clone(&rotation_protection),
                netflow_rotation,
            )
        }) {
            Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
            Err(e) => {
                // Lab PR 218 (external review P0 C-14): the drain no longer
                // stays off for the whole boot (TCP, UDP and listeners
                // blind): it runs without the log, signed.
                error!(
                    error = %e,
                    path = %cli.netflow_file.display(),
                    "netflow log cannot be opened — flows are evaluated by the rules but not \
                     persisted this boot"
                );
                northnarrow_agent::boot::degradation::report_signed(
                    audit_log.as_ref(),
                    "net_drain",
                    &format!(
                        "netflow log {} cannot be opened ({e:#}): flows reach the rules, not \
                         persisted this boot",
                        cli.netflow_file.display()
                    ),
                    true,
                );
                None
            }
        };
        let listener_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        )
        .and_then(|key| NetListenerDb::open(&cli.netflow_listeners_file, key, agent_id))
        {
            Ok(mut db) => {
                if let (Some(r), Some(log)) = (db.take_tail_repair(), audit_log.as_ref()) {
                    if let Err(e) = log
                        .lock()
                        .attest_tail_repair(&cli.netflow_listeners_file, &r)
                    {
                        warn!(error = %e, "attesting the listener log repair failed");
                    }
                }
                Some(Arc::new(parking_lot::Mutex::new(db)))
            }
            Err(e) => {
                // External audit NET-003: no longer stops the whole drain —
                // flows and listener events still reach the rules; only the
                // listener log is not written.
                error!(
                    error = %e,
                    path = %cli.netflow_listeners_file.display(),
                    "netflow_listeners log cannot be opened — listener events are \
                     evaluated but not persisted this boot"
                );
                // Lab PR 218: signed, not only an ERROR.
                northnarrow_agent::boot::degradation::report_signed(
                    audit_log.as_ref(),
                    "net_drain",
                    &format!(
                        "netflow_listeners log {} cannot be opened ({e:#}): listener events \
                         reach the rules, not persisted this boot",
                        cli.netflow_listeners_file.display()
                    ),
                    true,
                );
                None
            }
        };
        {
            let netflow_db = netflow_db_opt;
            let listener_db = listener_db_opt;
            let flow_tracker_for_drain = Arc::clone(&flow_tracker);
            let dns_cache_for_drain = Arc::clone(&dns_cache);
            let lineage_for_net = lineage.clone();
            let event_tx = sensor.event_tx();
            let close_rb = net_bufs.close_rb;
            let listen_rb = net_bufs.listen_rb;
            let udp_rb = net_bufs.udp_rb;
            let audit_for_drain = audit_log.clone();
            // External audit NET-019: the per-uid pacing of the rows handed
            // to the rules, with its exemptions (blocklist, chain store).
            let gate = northnarrow_agent::net::limiter::RuleGate::new(
                Arc::clone(&netflow_blocklist),
                Arc::clone(&chain_store),
            );
            // Lab PR 224 (CM-02 b): the open-flow snapshots.
            let snapshot = northnarrow_agent::net::flow_tracker::SnapshotPolicy {
                interval_ns: cli.net_snapshot_interval_secs * 1_000_000_000,
                min_age_ns: cli.net_snapshot_min_age_secs * 1_000_000_000,
                max_per_tick: cli.net_snapshot_max,
            };
            let handle = tokio::spawn(async move {
                let outcome = drain_loop(
                    close_rb,
                    listen_rb,
                    udp_rb,
                    flow_tracker_for_drain,
                    dns_cache_for_drain,
                    netflow_db,
                    listener_db,
                    lineage_for_net,
                    gate,
                    snapshot,
                    event_tx,
                )
                .await;
                drain_ended("net", outcome, audit_for_drain.as_ref());
            });
            sensor.register_pump_handle("net_drain", handle);
            info!("net: drain loop spawned (NET_FLOW_CLOSE_EVENTS + NET_LISTEN_EVENTS)");
        }
    }
}

/// The admin socket, started only with the network isolator (its ruleset):
/// the admin key set (a skipped line signed, AUT-004; the one-key bootstrap
/// over once a second key was added, ATP-004), the serve loop with the
/// admin states of FIM, the canaries, the detections, the response verbs
/// and the read verbs.
#[allow(clippy::too_many_arguments)]
fn boot_admin(
    cli: &Cli,
    isolator: &Option<Arc<NetworkIsolator>>,
    agent_id: [u8; 16],
    audit_log: &AuditHandle,
    chain_anchor: &AnchorHandle,
    posture: &PostureMachine,
    shutdown_signal: &ShutdownSignal,
    fim_admin_state: &Option<Arc<admin_socket::FimAdminState>>,
    canary_admin_state: &Option<Arc<admin_socket::CanaryAdminState>>,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    detection_admin_state: &Option<Arc<admin_socket::DetectionAdminState>>,
    executor: &Executor,
    ladder: &Arc<northnarrow_agent::combat::CombatLadder>,
    detect_only_source: &Option<String>,
    exempt: &ExemptPids,
) {
    // Optional admin socket: only spawned if admin pubkey config
    // is present. Missing config = no unlock path; the agent still
    // runs but COMBAT can only be cleared by reboot.
    if let Some(iso) = isolator.as_ref() {
        match AdminAuth::load_with_agent_id(&cli.admin_pub, agent_id) {
            Ok(auth) => {
                // External audit AUT-004: a skipped line is in the signed
                // chain, not only in the journal.
                let skipped = auth.skipped_lines();
                if !skipped.is_empty() {
                    let lines: Vec<String> = skipped
                        .iter()
                        .map(|(n, why)| format!("line {n}: {why}"))
                        .collect();
                    attest_degraded(
                        audit_log.as_ref(),
                        &format!(
                            "{}: {} line(s) skipped, their keys not loaded — {}",
                            cli.admin_pub.display(),
                            skipped.len(),
                            lines.join("; ")
                        ),
                    );
                }
                // External audit ATP-004: the one-key bootstrap is over for
                // good once the signed chain shows a second key was added.
                // Lab PR 160: also when the head anchor carries it, or the
                // audit chain was found cut (it could have held the add).
                if audit_log
                    .as_ref()
                    .is_some_and(|l| l.lock().second_key_added())
                    || chain_anchor
                        .as_ref()
                        .is_some_and(|a| a.lock().second_key_added())
                {
                    auth.mark_bootstrap_consumed();
                }
                let auth = Arc::new(auth);
                let posture_clone = posture.clone();
                let iso_clone = Arc::clone(iso);
                let socket_path = cli.admin_socket.clone();
                let signal_for_serve = shutdown_signal.clone();
                // Tappa 8 B5: the AuditLog is opened ONCE at boot (above,
                // right after agent_id) and shared with the COMBAT ladder;
                // the admin socket takes its own Arc clone. post-A14 the
                // file's inode is already in PROTECTED_INODES so an
                // attacker can't replace it underneath us.
                let audit_log = audit_log.clone();
                let marker_path = cli.shutdown_marker_file.clone();
                let fim_state_for_serve = fim_admin_state.clone();
                let canary_state_for_serve = canary_admin_state.clone();
                // FIM-009 self-upgrade (§15.1): the dispatcher arms this
                // override on a verified TrustedInstallerGrantRequest.
                let installer_override_for_serve = Some(Arc::clone(installer_override));
                // Tappa 9.0.c: detection triage state (status-event chain).
                let detection_state_for_serve = detection_admin_state.clone();
                // External audit NN-AUD-082: the read verbs serve the
                // files the flags name, not the built-in paths.
                let read_paths_for_serve = Arc::new(admin_socket::AdminReadPaths {
                    fim_drift: cli.fim_drift_file.clone(),
                    netflow: cli.netflow_file.clone(),
                    netflow_listeners: cli.netflow_listeners_file.clone(),
                });
                // External audit CMB-016: the response verbs read the
                // executor's record and vault, and the ladder's stage.
                let response_state_for_serve = Some(Arc::new(admin_socket::ResponseAdminState {
                    config: executor.config().clone(),
                    combat_stage: {
                        let ladder = Arc::clone(ladder);
                        Arc::new(move || ladder.current_stage().map(|s| s.as_str().to_string()))
                    },
                    // External audit CMB-018 / CMB-027 (lab PR 193): `status`
                    // says detect-only and its source, and what the signed
                    // audit log lacks of the ladder.
                    detect_only_source: detect_only_source.clone(),
                    combat_evidence: {
                        let ladder = Arc::clone(ladder);
                        Arc::new(move || ladder.evidence_counts())
                    },
                }));
                // External audit ASK-009 (lab PR 213): the unsigned status
                // polling is summarised per peer in the signed audit log;
                // the verified watchdog (the pid in PROTECTED_PIDS) is not.
                let status_polls_for_serve =
                    Arc::new(admin_socket::StatusPolls::new(exempt.clone()));
                // External audit NN-AUD-077: the loop now outlives a
                // transient accept error; if it still ends, the admin plane
                // is gone until a restart — an ERROR and a signed record.
                let audit_log_on_exit = audit_log.clone();
                tokio::spawn(async move {
                    if let Err(e) = admin_socket::serve_with_marker_path(
                        socket_path,
                        auth,
                        Arc::new(posture_clone),
                        iso_clone,
                        marker_path,
                        Some(signal_for_serve),
                        audit_log,
                        fim_state_for_serve,
                        canary_state_for_serve,
                        installer_override_for_serve,
                        detection_state_for_serve,
                        response_state_for_serve,
                        read_paths_for_serve,
                        status_polls_for_serve,
                    )
                    .await
                    {
                        error!(
                            error = %e,
                            "admin socket serve loop exited — no unlock, shutdown or key \
                             rotation until the agent restarts"
                        );
                        attest_degraded_at(
                            audit_log_on_exit.as_ref(),
                            &format!("admin socket serve loop exited: {e:#}"),
                            false,
                        );
                    }
                });
            }
            Err(e) => {
                // External audit AUT-004: the agent without its admin
                // socket cannot be unlocked or upgraded — an ERROR and a
                // signed record, not a WARN.
                error!(
                    error = %e,
                    path = %cli.admin_pub.display(),
                    "admin pub key file missing or invalid; admin socket disabled"
                );
                attest_degraded(audit_log.as_ref(), &format!("admin socket disabled: {e:#}"));
            }
        }
    } else {
        error!(
            socket = %cli.admin_socket.display(),
            "admin socket NOT started: no NetworkIsolator (combat ruleset missing, see above) — \
             the watchdog STATUS ping will fail until the ruleset is installed and the agent restarted"
        );
    }
}

/// SIGINT, SIGTERM and SIGHUP, registered before the event loop.
struct Signals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
}

/// What [`boot_tasks`] started.
struct Tasks {
    execq_handle: Option<northnarrow_agent::execq::Handle>,
    execpol_handle: Option<northnarrow_agent::execpol::Handle>,
    signals: Signals,
}

/// The running agent's tasks: the posture's decay, the trusted-installer
/// window's deadline, the exec quarantine's and the exec policy's
/// controllers (EXPERIMENTAL; one that cannot start is signed); then the
/// shutdown signals, installed before the loop.
#[allow(clippy::too_many_arguments)]
fn boot_tasks(
    posture: &PostureMachine,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    execq_mode: northnarrow_agent::execq::Mode,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    detection_sink: &Option<northnarrow_agent::detection_store::DetectionSink>,
    audit_log: &AuditHandle,
    execq_exec_cfg: ExecutorConfig,
    execpol_mode: northnarrow_agent::execpol::Mode,
) -> Result<Tasks> {
    // Decay loop: walks the posture down (ALERTED→OBSERVING after 1h
    // idle, ENGAGED→ALERTED after 24h idle, and — external audit POS-001 —
    // an unlocked COMBAT, reached on heuristics alone, to ENGAGED after
    // 30 min without a new escalation signal). A locked COMBAT never
    // decays; it requires an admin-signed release. The 60 s cadence is
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

    // External audit ATP-003: the trusted-installer window is closed — and
    // its close recorded — at its deadline, not at the next event. The
    // kernel grant ends at the same deadline by itself; this keeps the
    // in-memory state, the PID-1 stop grant and the audit chain on time,
    // and retries a zeroing that failed.
    let installer_ticker = installer_override.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            installer_ticker.close_if_expired(Instant::now());
        }
    });

    // Lab PR 223 (EXPERIMENTAL): the exec quarantine's controller and
    // scanner, once the detection chain and the audit log are open (every
    // decision is a signed record). Until its first heartbeat the kernel
    // holds nothing; a guard that cannot start is a signed degradation.
    let execq_handle = if execq_mode == northnarrow_agent::execq::Mode::Off {
        None
    } else {
        let cfg = northnarrow_agent::execq::config()
            .cloned()
            .unwrap_or_default();
        let (hashes, hashes_source) = match overlay_gate
            .verified(OverlayKind::ExecqHashes, &cfg.hashes_local)
        {
            northnarrow_agent::config::overlay_auth::Verified::Content { path, text } => {
                match nn_proto::execq::parse_hash_list(&text) {
                    Ok(l) => (l, format!("{} (signed)", path.display())),
                    Err(e) => {
                        error!(error = %e, path = %path.display(), "exec quarantine hash list unreadable — empty lists");
                        (
                            nn_proto::execq::HashList::default(),
                            format!("{}: {e}", path.display()),
                        )
                    }
                }
            }
            _ => (nn_proto::execq::HashList::default(), "none".to_string()),
        };
        let posture_for_execq = posture.clone();
        let recorder = northnarrow_agent::execq::record::SinkRecorder {
            sink: detection_sink.clone(),
            audit: audit_log.clone(),
            posture: Box::new(move || posture_for_execq.current_kind()),
        };
        match northnarrow_agent::execq::start(northnarrow_agent::execq::StartDeps {
            hashes,
            hashes_source,
            recorder: Box::new(recorder),
            exec_cfg: execq_exec_cfg,
        }) {
            Ok(h) => Some(h),
            Err(why) => {
                error!(reason = %why, "exec quarantine NOT running — the kernel holds nothing");
                attest_degraded(audit_log.as_ref(), &format!("exec quarantine: {why}"));
                None
            }
        }
    };

    // Lab PR 226 (EXPERIMENTAL): the exec policy's controller — the slices
    // and images published, the kernel's reports into signed records —
    // and each part of the policy that could not start, signed.
    let execpol_handle = if execpol_mode == northnarrow_agent::execpol::Mode::Off {
        None
    } else {
        let posture_for_execpol = posture.clone();
        let recorder = northnarrow_agent::execpol::record::SinkRecorder {
            sink: detection_sink.clone(),
            posture: Box::new(move || posture_for_execpol.current_kind()),
        };
        let execq_on = execq_handle.is_some();
        let handle = match northnarrow_agent::execpol::start(Box::new(recorder), execq_on) {
            Ok(h) => Some(h),
            Err(why) => {
                error!(reason = %why, "exec policy controller NOT running — nothing is recorded");
                attest_degraded(audit_log.as_ref(), &format!("exec policy: {why}"));
                None
            }
        };
        for why in northnarrow_agent::execpol::degradations() {
            attest_degraded(audit_log.as_ref(), &why);
        }
        handle
    };

    // Install the three shutdown signals up front, before the loop.
    // Re-creating the future inside `select!` every iteration (the
    // old `signal::ctrl_c()` shorthand) re-runs handler registration
    // each tick and interacts badly with `SIG_IGN` inherited from
    // `bash &` + `nohup` (live test 2026-05-12 found SIGINT and
    // SIGHUP silently dropped; only SIGQUIT brought the agent down).
    // A pre-registered `Signal` stream is the documented robust path.
    //
    // SIGTERM reaches the agent only from itself, the watchdog, PID 1
    // inside a signed trusted-installer window, or `systemd-shutdown` at
    // the end of a shutdown (the task_kill hook refuses everyone else) —
    // and from anyone on a kernel without `bpf` in its LSM chain.
    let sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    Ok(Tasks {
        execq_handle,
        execpol_handle,
        signals: Signals {
            sigint,
            sigterm,
            sighup,
        },
    })
}

/// The boot is over: the capability manifest and the trust level are
/// signed and systemd was told the agent is ready ([`boot_ready`]); the
/// event loop takes it.
struct Armed {
    _private: (),
}

/// `BootPhase::Run` (lab PR 218, external review G-12): every attach of the
/// boot is done — the capability manifest and the trust level are signed
/// before systemd hears the agent is ready (`sd_notify`), then the boot's
/// transient heap goes back to the kernel (lab PR 231).
fn boot_ready(
    boot: &mut BootSequence,
    bpf_lsm_state: northnarrow_agent::boot::lsm::BpfLsm,
    self_test: northnarrow_agent::boot::deny_selftest::SelfTestOutcome,
    host_checks: Vec<northnarrow_agent::host_hardening::Check>,
    detect_only: bool,
    audit_log: &AuditHandle,
) -> Result<Armed> {
    // Lab PR 218 (external review G-12): every attach of this boot is done.
    // The capability manifest — kernel, BTF, LSMs, deny hooks, self-test,
    // sensors, host hardening, degradations — and the trust level are
    // signed before systemd hears the agent is ready.
    boot.enter(BootPhase::Run)?;
    {
        use northnarrow_agent::boot::manifest;
        let deny = northnarrow_agent::anti_tamper::deny_report().unwrap_or_default();
        let resolved = northnarrow_agent::anti_tamper::btf_revalidate::resolved();
        let trust = northnarrow_agent::boot::trust::current().unwrap_or_else(|| {
            northnarrow_agent::boot::trust::Trust {
                level: northnarrow_agent::boot::trust::TrustLevel::L0,
                reasons: vec!["the boot measured nothing".to_string()],
            }
        });
        let m = manifest::CapabilityManifest {
            manifest_version: manifest::MANIFEST_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            kernel: manifest::kernel_release(),
            btf: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
            btf_offsets_resolved: resolved.map_or(0, |r| r.values.len()),
            btf_offsets_drifted: resolved.map_or(0, |r| r.drifted.len()),
            btf_offsets_absent: resolved
                .map(|r| r.absent.iter().map(|m| m.name.to_string()).collect())
                .unwrap_or_default(),
            active_lsms: bpf_lsm_state.list().map(str::to_string),
            bpf_lsm: bpf_lsm_state.label().to_string(),
            deny_hooks: manifest::DenyHooks {
                expected: deny.expected,
                attached: deny.attached,
                missing: deny.missing,
                observe_missing: deny.observe_missing,
            },
            deny_self_test: self_test.describe(),
            bpf_guard: if northnarrow_agent::anti_tamper::bpf_defense::enforce_mode() {
                "enforce"
            } else {
                "observe"
            }
            .to_string(),
            sensors: manifest::sensors(),
            host_hardening: manifest::host_checks(&host_checks),
            detect_only,
            degradations: northnarrow_agent::boot::degradation::snapshot(),
            trust_level: trust.level.as_u8(),
            trust_reasons: trust.reasons.clone(),
        };
        if trust.level < northnarrow_agent::boot::trust::TrustLevel::L3 {
            warn!(
                trust_level = trust.level.name(),
                meaning = trust.level.meaning(),
                reasons = %trust.reasons.join("; "),
                "trust level below L3"
            );
        } else {
            info!(
                trust_level = trust.level.name(),
                "trust level L3: every mandatory deny hook attached and self-tested, nothing degraded"
            );
        }
        northnarrow_agent::boot::manifest::sign(audit_log.as_ref(), m);
    }
    boot.done(BootStep::CapabilityManifest)?;
    northnarrow_agent::boot::degradation::mark_boot_over();

    // T7.10: the unit is `Type=notify`; tell systemd we are ready now
    // that every subsystem is wired (anti-tamper attached, decision
    // engine loaded, drains + admin socket spawned, signal
    // handlers installed) and we are about to enter the event loop.
    // Without this, systemd holds the unit `activating` until
    // `TimeoutStartSec` then marks it failed — and the agent's own
    // anti-tamper hook denies the resulting SIGTERM, stranding the
    // unit `failed` while the process runs and dragging the watchdog
    // down via `BindsTo`. No-op when not under systemd (NOTIFY_SOCKET
    // unset), so dev runs and tests are unaffected. Non-fatal: a send
    // failure is logged, not propagated — a healthy agent must not
    // refuse to run just because the readiness ping didn't land.
    if let Err(e) = northnarrow_agent::sd_notify::ready() {
        warn!(error = %e, "sd_notify(READY=1) failed; systemd may report the unit as not-ready");
    }
    // Lab PR 231: the boot's transient heap (the vmlinux BTF parses of the
    // attach) back to the kernel; under aya 0.14 glibc kept it.
    let released = northnarrow_agent::boot::release_boot_heap();
    debug!(released, "boot heap released after READY (malloc_trim)");
    Ok(Armed { _private: () })
}

/// Why the event loop ended (the signed `agent_stop`), and when it began.
struct Stopped {
    stop_reason: &'static str,
    loop_started: Instant,
}

/// The event loop: every event offered to the telemetry probe, then
/// [`process_event`]; every 5 s the telemetry tasks checked (SNS-001); a
/// signal or the admin shutdown ends it.
#[allow(clippy::too_many_arguments)]
async fn run_loop(
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
    signals: &mut Signals,
) -> Stopped {
    let Combat {
        ladder,
        #[cfg(feature = "debug-trigger")]
        debug_guard,
        shutdown_signal,
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
                    // the probe tracker before the decision engine.
                    northnarrow_agent::telemetry_probe::observe(&e);
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

/// The stop: the exec guards release what they hold, the BPF self-check
/// is told the links go, the copy guard closes, the signed `agent_stop`,
/// the heads anchored at stop, the pid file and the admin socket removed.
/// A pump that exited is a failure (SNS-001): the watchdog restarts the
/// agent.
fn shutdown(
    cli: &Cli,
    execq_handle: Option<northnarrow_agent::execq::Handle>,
    execpol_handle: Option<northnarrow_agent::execpol::Handle>,
    audit_log: &AuditHandle,
    chain_anchor: &AnchorHandle,
    stopped: Stopped,
) -> Result<()> {
    let Stopped {
        stop_reason,
        loop_started,
    } = stopped;
    // Lab PR 223: nothing stays held by an agent that stops.
    northnarrow_agent::execq::shutdown(execq_handle);
    // Lab PR 226: the kernel keeps the policy until its programs detach.
    northnarrow_agent::execpol::shutdown(execpol_handle);
    // The links go with the agent from here on: the self-check stops
    // reporting them (a spurious signed bpf_link_missing otherwise).
    northnarrow_agent::anti_tamper::bpf_defense::mark_stopping();
    // Lab PR 222: the guard's fanotify group closes first — no open on a
    // protected scope waits on an agent that is leaving.
    northnarrow_agent::cow::shutdown();

    if let Some(log) = &audit_log {
        let uptime = loop_started.elapsed().as_secs();
        match log.lock().stop_entry(stop_reason, uptime) {
            Ok(_) => info!(
                reason = stop_reason,
                uptime_secs = uptime,
                "audit: agent_stop entry appended"
            ),
            Err(e) => warn!(error = format!("{e:#}"), "audit: agent_stop entry failed"),
        }
    }
    // Lab PR 160: the heads as this run leaves them, `agent_stop` included,
    // so a file emptied or cut while the agent is down is found at the
    // next start.
    if let Some(a) = &chain_anchor {
        let second = audit_log
            .as_ref()
            .is_some_and(|l| l.lock().second_key_added());
        match a.lock().refresh(true, second) {
            Ok(_) => info!("chain heads anchored at stop"),
            Err(e) => warn!(
                error = format!("{e:#}"),
                "chain heads: not anchored at stop"
            ),
        }
    }

    // Tappa 7 task 6 #2b-verify: remove our PID file on GRACEFUL
    // shutdown only, so a supervisor/harness reads "file gone =>
    // agent exited cleanly". A crash (panic / SIGKILL — neither
    // reaches here) deliberately leaves it STALE; that is why readers
    // must confirm /proc/<pid> is alive (and is the agent binary)
    // before trusting the contents. Removal failure is logged loudly,
    // never swallowed, but is non-fatal — we are already shutting down.
    if let Some(pid_file) = cli.pid_file.as_deref() {
        match std::fs::remove_file(pid_file) {
            Ok(()) => info!(
                target: "anti-tamper",
                path = %pid_file.display(),
                "pid_file removed on graceful shutdown"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => debug!(
                target: "anti-tamper",
                path = %pid_file.display(),
                "pid_file already absent at shutdown (nothing to remove)"
            ),
            Err(e) => warn!(
                target: "anti-tamper",
                path = %pid_file.display(),
                error = %e,
                "pid_file removal failed on shutdown (left stale)"
            ),
        }
    }

    // Best-effort socket cleanup so a future agent process can bind
    // without first encountering a stale file. The accept loop is
    // about to be torn down with the runtime, so this race is between
    // tokio's drop-of-the-listener and our unlink — either order
    // leaves the filesystem clean.
    admin_socket::unlink_socket(&cli.admin_socket);

    info!("NorthNarrow agent stopped.");
    if stop_reason == "sensor_pump_exited" {
        // External audit SNS-001: a failure, not a clean stop.
        anyhow::bail!("a sensor pump exited; the agent stopped so the watchdog restarts it");
    }
    Ok(())
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

/// Categorise + log + evaluate + (maybe) execute.
///
/// Tappa 4 ships five sensors; Tappa 2 rules only match `ProcessSpawn`,
/// so non-spawn events flow through as DEBUG telemetry and bypass the
/// engine. The kill syscalls + verify retries can sleep up to 50 ms,
/// so any execution dispatch goes through `spawn_blocking`.
///
/// Tappa 6: every event also lands in the correlation buffer, the recent
/// events the posture triggers read. An event no rule matches gets no
/// verdict: the LLM advisor that judged such execs was removed in Wave 4
/// (lab PR 214).
#[allow(clippy::too_many_arguments)]
async fn process_event(
    engine: &RuleEngine,
    executor: &Executor,
    correlation: &CorrelationBuffer,
    posture: &PostureMachine,
    ladder: &northnarrow_agent::combat::CombatLadder,
    canary_detector: Option<&northnarrow_agent::canary::detector::Detector>,
    // FIM-009 self-upgrade (§15.1): consulted for lazy TTL expiry.
    installer_override: &northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    // Tappa 9.0.a: detection-persistence sink. `None` ⇒ not persisting
    // this boot (e.g. signing key / store open failed at startup). All
    // record calls are off the hot path (bounded queue + writer task).
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
    event: Event,
) {
    // Lab PR 218: the deny self-test's own refused signal is the boot's
    // measurement, not an attempt on the agent — taken before the posture
    // (it would raise COMBAT) and the rules; any other denial goes on.
    if northnarrow_agent::boot::deny_selftest::take_expected_denial(&event) {
        return;
    }
    // Tappa 10.9 step 2: an exec event's path made absolute before any
    // consumer reads it (review 61).
    let mut event = event;
    northnarrow_agent::sensors::exe_identity::resolve(&mut event);
    // Lab PR 223: the exec quarantine resumes a held process only once
    // this exec has been judged — dropped at the end of this function,
    // after a kill the rules decided was carried out.
    let _execq_judged = northnarrow_agent::execq::SpawnGuard::for_event(&event);
    // FIM-009 self-upgrade (§15.1): lazy TTL expiry on the event path —
    // if a trusted-installer window has passed its deadline, close it
    // (re-engage the FS pin + audit) before handling this event. A cheap
    // no-op (a single atomic load) when no window is open. No timer:
    // detection already expires exactly at the deadline via the rule's
    // own is_window_open() read; this sweep re-syncs the kernel map.
    installer_override.close_if_expired(Instant::now());

    // External audit EBPF-001: while systemd stops the host, its SIGTERM to
    // the agent and the watchdog is refused until `systemd-shutdown` (the
    // units outlive their stop jobs). Expected, so neither an attempt nor a
    // posture signal.
    if let Event::FsProtectDenial {
        pid: 1,
        operation: nn_model::FsProtectOperation::Signal,
        target_dev: sig,
        target_ino: target,
        ..
    } = &event
    {
        let state = systemd_state().await;
        if state.as_deref() == Some("stopping") {
            info!(
                signal = sig,
                target,
                "systemd is stopping the host — its signal to a protected process is refused \
                 until systemd-shutdown's final stage (expected, not an attempt)"
            );
            host_stopping(ladder);
            return;
        }
        info!(
            signal = sig,
            target,
            systemd_state = state.as_deref().unwrap_or("(no answer)"),
            "signal relayed by systemd outside a trusted-installer window — not a shutdown"
        );
    }

    // Tappa 9.5 (K3): canary precedence over FIM rules per
    // §12 Q9 OPTION B inline-filter lock-in. The detector
    // checks the event against the deployed canary registry;
    // on match, it returns Some(Event::CanaryTripped { … }),
    // marks the canary as tripped (idempotent per §12 Q2),
    // and appends to the canary_access.jsonl chain. We
    // REPLACE the source event with the canary event so
    // downstream (correlation buffer push, posture observer,
    // rule engine) routes through the K5 canary rule family
    // instead of the K9 FIM rule layer.
    //
    // When `canary_detector` is `None` (early-boot path
    // before K6 wires the Detector handle), this is a no-op.
    let event = match canary_detector.and_then(|d| d.process_event(&event)) {
        Some(canary_event) => canary_event,
        None => event,
    };
    // Lab PR 163: the close of a connection that tripped a network canary
    // belongs to the trip (its row is in the signed netflow log already);
    // judged again, NN-L-CHAIN-003 answered the one access a second time.
    // Lab PR 246: every row of that connection, as the engine's flow ledger
    // keys it (the trip's accessor and connect time) — a close the flow
    // tracker synthesised included, and a row that follows the close.
    if engine.owned_by_trip(&event) {
        debug!("row of a network canary trip's connection — part of the trip, not judged again");
        return;
    }

    // Run posture detection BEFORE we push the focal event into the
    // correlation buffer — the trigger detector counts the focal as
    // a fresh +1 on top of `recent`, and `recent` already containing
    // the focal would double-count it.
    // Review 72: borrowed under the buffer's read lock, not cloned (up to
    // 1,000 events, for every event, was most of the agent's CPU under an
    // exec burst). Nothing pushes to the buffer until this returns.
    let host_stopping = HOST_STOPPING.load(std::sync::atomic::Ordering::SeqCst);
    if let Some((new_state, firing_trigger)) = (!host_stopping)
        .then(|| correlation.with_recent(|recent| posture.observe(&event, recent)))
        .flatten()
    {
        // BUG-015 observability: include the firing TriggerType so
        // operators can see in the journal what caused a transition.
        // `firing_trigger` is `Some` for any upward crossing and `None`
        // for same-tier re-arms; the latter case still gets a log line
        // because the kind() display alone is enough to follow state.
        warn!(
            state = %new_state.kind(),
            // External audit POS-001: a COMBAT reached on heuristics alone
            // is unlocked — no isolation, and it decays once quiet.
            locked = new_state.is_combat_locked(),
            trigger = ?firing_trigger,
            "POSTURE TRANSITION"
        );
        // On the non-Combat → Combat edge the combat-entry hook, inside
        // `observe`, has opened the ladder's episode (STAGE 1 INVESTIGATE,
        // network up) with the firing trigger, the evidence it cites and
        // the process the event names (lab PR 245: the posture's
        // `CombatEntry`; external audit EBPF-001: never init; CMB-004: with
        // the offender's start and a time it was running). Reaching COMBAT
        // does NOT isolate — the ladder does.
    }
    // While a COMBAT episode is active, feed every event to the ladder
    // for the jump-ahead check: an offender actively exfiltrating or
    // spawning children DURING INVESTIGATE pre-empts the time-bound
    // deadline and advances straight to NEUTRALIZE.
    if !host_stopping && ladder.current_stage().is_some() {
        ladder.observe(&event, Instant::now());
    }
    // Lab PR 222: a mass rewrite of existing files flags its writer for the
    // copy-on-first-write guard (a ransomware verdict's offender).
    northnarrow_agent::cow::observe_event(&event);
    // Lab PR 224: an open flow's rows (its connect, its snapshots, a
    // refused connect) are for the rules; the correlation buffer keeps its
    // `TcpConnect` and its closed row, as before.
    let open_flow_row = matches!(&event, Event::NetFlow(nf) if nf.phase.is_open());
    if !open_flow_row {
        correlation.push(event.clone());
    }

    // Review 71: per-event lines for the frequent events (every exec,
    // every flow, every open) are DEBUG. At INFO, an exec burst made
    // journald rate-limit the agent and drop its other lines (boot, sensor
    // arming, verdict context), and every command line on the host, with
    // any secret in its arguments, was copied into the journal. Exec and
    // flow records live in the detection store and the signed netflow log.
    // External audit Wave 3 (journal line injection, lab PR 167): a value
    // another user names (comm, file name, DNS name, the rule text quoting
    // them) is logged through Escaped, quoted when it holds a separator.
    use nn_model::log_escape::Escaped;
    match &event {
        Event::ProcessSpawn { .. } => debug!(event = ?event, "process spawn detected"),
        Event::ModuleLoad {
            method,
            loader_pid,
            loader_comm,
            path,
            ..
        } => info!(
            loader_pid = *loader_pid,
            loader_comm = %Escaped(loader_comm),
            method = ?method,
            path = path.as_deref().unwrap_or("none"),
            "kernel module load detected (BUG-034)"
        ),
        Event::IoUring {
            created,
            pid,
            comm,
            classes,
            count,
            sq_thread,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            created = *created,
            classes = ?nn_model::io_uring_class_names(*classes),
            count = *count,
            sq_thread = *sq_thread,
            "io_uring activity"
        ),
        Event::BpfSyscall {
            pid,
            comm,
            cmd,
            arg,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            cmd = common::wire::bpf_cmd_name(*cmd),
            arg = *arg,
            "bpf() syscall by a non-protected process"
        ),
        Event::FileOpen {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %Escaped(comm), filename = %Escaped(filename), "file open")
        }
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            cgroup_window: true,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            overwrites = *count,
            last = %Escaped(filename),
            "mass write: overwrite threshold crossed by the processes of one cgroup (counted in the kernel)"
        ),
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            count = *count,
            last = %Escaped(filename),
            "mass write: write-open threshold crossed (counted in the kernel)"
        ),
        // Lab PR 225: the rename and unlink bursts (NN-L-IMP-001/002 read them).
        Event::FileBurst {
            pid,
            comm,
            kind,
            count,
            filename,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            kind = kind.as_str(),
            count = *count,
            last = %Escaped(filename),
            "file burst: rename or unlink threshold crossed (counted in the kernel)"
        ),
        // Lab PR 225: NN-L-EVA-003 reports it.
        Event::DefenderSignal {
            pid,
            comm,
            target_pid,
            signal,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            target_pid = *target_pid,
            signal = *signal,
            "signal to a security tool's process (task_kill, not refused)"
        ),
        Event::ExecCheck {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %Escaped(comm), filename = %Escaped(filename), "exec_check")
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
                pid, comm = %Escaped(comm), family,
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
                pid, comm = %Escaped(comm),
                server = %render_addr(*family, dns_server),
                query = %Escaped(query_name),
                "dns_query"
            )
        }
        // Review 78: the rule (NN-L-NET-020) reports it.
        Event::DnsFlood {
            pid,
            comm,
            held,
            uid_level,
            ..
        } => debug!(pid, comm = %Escaped(comm), held, uid_level, "dns_flood"),
        // External audit EBPF-013: the rule (NN-L-NET-021) reports it.
        Event::SensorFlood {
            source,
            pid,
            comm,
            held,
            uid_level,
            ..
        } => debug!(
            pid,
            comm = %Escaped(comm),
            source = source.as_str(),
            held,
            uid_level,
            "sensor_flood"
        ),
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
            // Short-circuit: a kernel deny is not something the
            // rule engine should re-evaluate. The
            // posture trigger above is the response. The attempt itself
            // is persisted as a signed detection (NN-L-AT-001, Log only:
            // the kernel already refused it) — the adversarial check found
            // refused attempts that left no record in the chain logs.
            use northnarrow_agent::decision::Rule as _;
            let at001 = northnarrow_agent::decision::rules::anti_tamper::NnLAt001AntiTamperDenial;
            let verdict = at001.evaluate(&event);
            // Review 75: a loop of denied attempts is logged and stored
            // within the rule's budget for that uid.
            let admit = match &verdict {
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            if admit.record() {
                warn!(
                    pid, uid, comm = %Escaped(comm),
                    op = %operation,
                    target_dev, target_ino,
                    "ANTI-TAMPER DENIAL"
                );
            }
            if let Some(verdict) = verdict {
                if let Admit::Record { suppressed_before } = admit {
                    warn!(
                        rule = %verdict.rule_id,
                        severity = ?verdict.severity,
                        reasoning = %Escaped(&verdict.reasoning),
                        "VERDICT (rule)"
                    );
                    if let Some(sink) = detection_sink {
                        sink.record_rule(
                            &event,
                            &verdict,
                            at001.attack(),
                            posture.current_kind(),
                            "denied in kernel (anti-tamper LSM hook)".to_string(),
                            suppressed_before,
                        );
                    }
                }
            }
            return;
        }
        // Lab PR 219: the exploit post-condition guard. The kernel already
        // did what the mode asks (enforce: SIGKILL before the return to user
        // mode; detect: nothing), so neither the rule engine nor the
        // executor runs: the finding is recorded as a signed detection
        // (NN-L-EPG-001/002) within the rule's budget, and the posture
        // trigger above observed it.
        Event::ExploitPostcondition {
            pid,
            tid,
            uid,
            comm,
            kind,
            killed,
            abi,
            syscall,
            ..
        } => {
            use northnarrow_agent::decision::rules::epg;
            let rule = epg::rule_for(&event);
            let verdict = rule.and_then(|r| r.evaluate(&event));
            let admit = match &verdict {
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            if admit.record() {
                error!(
                    pid, tid, uid, comm = %Escaped(comm),
                    kind = kind.as_str(),
                    call = %abi.describe_call(*syscall),
                    killed,
                    "EXPLOIT POST-CONDITION"
                );
            }
            if let Some(verdict) = verdict {
                if let Admit::Record { suppressed_before } = admit {
                    warn!(
                        rule = %verdict.rule_id,
                        severity = ?verdict.severity,
                        reasoning = %Escaped(&verdict.reasoning),
                        "VERDICT (rule)"
                    );
                    if let Some(sink) = detection_sink {
                        sink.record_rule(
                            &event,
                            &verdict,
                            rule.map_or(&[][..], |r| r.attack()),
                            posture.current_kind(),
                            epg::response_line(&event),
                            suppressed_before,
                        );
                    }
                }
            }
            return;
        }
        // Tappa 9 (C4): FIM drift events. The drain loop in
        // agent/src/fim/drain.rs already wrote the chained
        // fim_drift.jsonl audit row + emitted Event::Fim
        // here only if NOT rate-limited (§6.5). Log a one-
        // line summary; the rule engine (C5 NN-L-FIM-001..009)
        // picks up the event via the normal `engine.evaluate`
        // path below.
        Event::Fim(fe) => {
            // BUG-012 (v2): a read (op=Opened) is NOT an integrity
            // drift, so it must never be logged as "FIM DRIFT" — that
            // is semantically wrong and just quieter noise. An Opened
            // event reaches this arm ONLY for a credential path the
            // FIM drain forwarded for the NN-L-FIM-011..017 read rules
            // (every other read is dropped at the drain). It flows
            // silently to `engine.evaluate` below; if a cred-read rule
            // fires, THE RULE emits the alert with proper framing.
            // Only integrity-changing ops get the FIM DRIFT line.
            if fe.op == nn_model::telemetry::FimOp::Opened {
                debug!(
                    path = %Escaped(&fe.path),
                    modifier_pid = fe.modifier_pid,
                    modifier_comm = %Escaped(&fe.modifier_comm),
                    "fim credential-path read forwarded to rule engine (not drift)"
                );
            } else if budget_admit("FIM-DRIFT", fe.modifier_uid, &event).record() {
                // Review 76: every drift now reaches the rules; its journal
                // line has the per-uid budget (the signed fim_drift.jsonl
                // row is always written).
                warn!(
                    path = %Escaped(&fe.path),
                    op = ?fe.op,
                    modifier_pid = fe.modifier_pid,
                    modifier_uid = fe.modifier_uid,
                    modifier_comm = %Escaped(&fe.modifier_comm),
                    "FIM DRIFT"
                );
            }
        }
        // Tappa 9.5 (K3): canary trip events. The K3 inline
        // detector intercepts source events BEFORE they reach
        // this match arm and re-emits as `Event::CanaryTripped`
        // ONLY when a canary fires (§12 Q9 OPTION B inline-
        // filter lock-in). Reaching this arm via the regular
        // event-bus path means a downstream component
        // (correlation snapshot replay, future K6 admin
        // synthetic-event injection) re-fed the canary event;
        // we log + let the K5 rule layer fire the standard
        // KillProcessTree + posture→COMBAT response.
        Event::CanaryTripped {
            canary_id,
            canary_name,
            canary_type,
            access_kind,
            accessor_pid,
            accessor_uid,
            accessor_comm,
            ..
        } => {
            warn!(
                canary_id = %canary_id,
                canary_name = %Escaped(canary_name),
                canary_type = ?canary_type,
                access_kind = ?access_kind,
                accessor_pid = %accessor_pid,
                accessor_uid = %accessor_uid,
                accessor_comm = %Escaped(accessor_comm),
                "CANARY TRIPPED"
            );
        }
        // Tappa 10 (N6) — minimal logging arms; the N3 flow
        // tracker + N2 listener kprobe feed these into the rule
        // engine below. Full drain wiring is a follow-up commit.
        Event::NetFlow(nf) => {
            debug!(
                pid = %nf.pid,
                comm = %Escaped(&nf.comm),
                dst_addr = %nf.dst_addr,
                dst_port = %nf.dst_port,
                proto = %nf.proto,
                bytes_sent = %nf.bytes_sent,
                phase = nf.phase.as_str(),
                "net flow"
            );
        }
        Event::NetListener(nl) => {
            info!(
                pid = %nl.pid,
                comm = %Escaped(&nl.comm),
                bind_addr = %nl.bind_addr,
                bind_port = %nl.bind_port,
                "net listener"
            );
        }
    }

    // Lab PR 236 (multi-match): every rule judged the event; the decision
    // names the primary rule and every match, and runs, per target, the
    // strongest response the per-rule policy allows.
    if let Some(decision) = engine.decide(&event) {
        let verdict = &decision.verdict;
        // Review 75: every verdict is acted on; its log lines and its
        // record count against the primary rule's budget for the acting uid.
        let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
        let admit = budget_admit(&verdict.rule_id, uid, &event);
        if admit.record() {
            let also: Vec<&str> = decision
                .matches
                .iter()
                .filter(|m| m.rule_id != verdict.rule_id)
                .map(|m| m.rule_id)
                .collect();
            if decision.audit_only() {
                info!(
                    rule = %verdict.rule_id,
                    also = ?also,
                    severity = ?verdict.severity,
                    target_pid = verdict.event_pid,
                    reasoning = %Escaped(&verdict.reasoning),
                    "AUDIT (rule, per-rule policy)"
                );
            } else {
                warn!(
                    rule = %verdict.rule_id,
                    rule_name = %verdict.rule_name,
                    category = %verdict.category,
                    action = ?verdict.action,
                    severity = ?verdict.severity,
                    also = ?also,
                    target_pid = verdict.event_pid,
                    target_filename = %Escaped(&verdict.event_filename),
                    reasoning = %Escaped(&verdict.reasoning),
                    "VERDICT (rule)"
                );
            }
        }

        // External audit CMB-004: what the event says about the process
        // the verdict is about — its start (an exec), the event's time — so
        // a kill does not reach a process that took the PID after the event.
        let owner = northnarrow_agent::posture::triggers::event_owner_pid(&event);
        let (owner_start_ns, owner_seen_ns) =
            northnarrow_agent::posture::triggers::event_owner_seen(&event);
        let mut reports = Vec::new();
        if decision.responses.is_empty() {
            // A Log decision runs nothing: no blocking task for it.
            reports.push((
                None,
                executor.execute(nn_model::ResponseAction::Log, verdict.event_pid),
            ));
        }
        for response in &decision.responses {
            let exec = executor.clone();
            let action = response.action.clone();
            let target_pid = response.pid;
            let target_file = response.filename.clone();
            let (target_start_ns, target_seen_ns) = if owner == Some(target_pid) {
                (owner_start_ns, owner_seen_ns)
            } else {
                (0, 0)
            };
            let report = match tokio::task::spawn_blocking(move || {
                exec.execute_for_started(
                    action,
                    target_pid,
                    target_start_ns,
                    target_seen_ns,
                    &target_file,
                )
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "executor task join failed");
                    return;
                }
            };
            reports.push((Some(response), report));
        }
        // Lab PR 222: a ransomware rule's match flags its writer, and a kill
        // of that process (whichever matched rule's response it was)
        // neutralized it.
        for m in &decision.matches {
            let pid = m.verdict.event_pid;
            let neutralized = reports.iter().any(|(r, report)| {
                r.is_some_and(|r| r.pid == pid)
                    && matches!(
                        report.primary,
                        northnarrow_agent::response::ExecutionOutcome::Killed { .. }
                            | northnarrow_agent::response::ExecutionOutcome::AlreadyGone { .. }
                    )
            });
            northnarrow_agent::cow::after_rule_response(m.rule_id, pid, neutralized);
        }
        if let Admit::Record { suppressed_before } = admit {
            for (_, report) in &reports {
                info!(
                    action = ?report.action,
                    primary = ?report.primary,
                    additional_count = report.additional.len(),
                    elapsed_us = report.elapsed.as_micros() as u64,
                    "EXECUTED"
                );
            }
            // Tappa 9.0.a: persist the rule detection (off the hot path).
            if let Some(sink) = detection_sink {
                let response = match reports.as_slice() {
                    [(_, only)] => northnarrow_agent::detection_store::describe_response(only),
                    many => many
                        .iter()
                        .map(|(r, report)| {
                            format!(
                                "{} (pid {}, {})",
                                northnarrow_agent::detection_store::describe_response(report),
                                r.map_or(verdict.event_pid, |r| r.pid),
                                r.map_or("", |r| r.rule_id)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                };
                sink.record_decision(
                    &event,
                    &decision,
                    posture.current_kind(),
                    response,
                    suppressed_before,
                );
            }
        }
    }
}

/// [`detection_budget::admit`], plus one WARN when a (rule, uid) runs out
/// of budget (review 75). The counts of what it held back reach the
/// journal and the audit log through the budget's reporter task.
fn budget_admit(rule: &str, uid: u32, event: &Event) -> Admit {
    let admit = detection_budget::admit(rule, uid, || {
        northnarrow_agent::detection_store::held_sample(event)
    });
    if admit == (Admit::Hold { first: true }) {
        warn!(
            rule,
            uid,
            burst = detection_budget::BURST,
            "detections of this rule and uid exceed the record budget: further ones are acted on \
             and counted, one per second is logged and stored, until the rate falls"
        );
    }
    admit
}

/// Render a 16-byte address according to family (`2` = AF_INET → first
/// 4 bytes; `10` = AF_INET6 → full v6).
fn render_addr(family: u8, bytes: &[u8; 16]) -> String {
    // External audit NET-001: one form in the logs, IPv4-mapped folded.
    if family == 2 || family == 10 {
        nn_model::netaddr::canonical_ip(family, bytes).to_string()
    } else {
        format!("family={family}")
    }
}

/// External audit MAIN-001: remove a former watchdog pid from
/// PROTECTED_PIDS unless it still runs the watchdog binary.
/// `pid` runs the watchdog binary at `watchdog_exe` (same file identity).
fn runs_watchdog_binary(pid: u32, watchdog_exe: &std::path::Path) -> bool {
    use northnarrow_agent::anti_tamper::ExeIdentity;
    let watchdog = ExeIdentity::of_file(watchdog_exe);
    watchdog.is_some() && ExeIdentity::of_process(pid) == watchdog
}

fn withdraw_watchdog_pid(
    bpffs_root: Option<&std::path::Path>,
    pid: u32,
    watchdog_exe: &std::path::Path,
) {
    use northnarrow_agent::anti_tamper::ExeIdentity;
    let watchdog = ExeIdentity::of_file(watchdog_exe);
    if watchdog.is_some() && ExeIdentity::of_process(pid) == watchdog {
        warn!(
            pid,
            "the watchdog pidfile no longer names the running watchdog — keeping it protected"
        );
        return;
    }
    match northnarrow_agent::anti_tamper::evict_protected_pid(bpffs_root, pid) {
        Ok(()) => info!(pid, "former watchdog pid removed from PROTECTED_PIDS"),
        Err(e) => {
            warn!(pid, error = %e, "could not remove a former watchdog pid from PROTECTED_PIDS")
        }
    }
}

/// External audit CMB-006: the removal of an older agent's host-wide
/// nftables isolation at start is recorded in the signed audit chain.
fn attest_legacy_isolation_removed(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "legacy_isolation_removed",
            "detail": "an older agent's nftables isolation chains (isolation_input, \
                       isolation_output) were found at start and removed",
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "repaired".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the removed legacy isolation failed");
    }
}

/// External audit FIMR-008: record the boot id the agent runs under, in
/// the immutable state directory — lifted as the log rotation lifts it —
/// and protected against foreign writes as the logs there are.
fn record_boot_id(
    protection: Option<&northnarrow_agent::anti_tamper::filesystem::StateDirProtection>,
    dir: &std::path::Path,
    now: &str,
) {
    use northnarrow_agent::chainlog::ProtectionManager;
    use northnarrow_agent::fim::honeypot;
    let file = dir.join(honeypot::BOOT_ID_FILE);
    let written = match protection {
        Some(p) => {
            if file.exists() {
                // The renamed-over inode leaves the protected set.
                let _ = p.release(&file);
            }
            p.with_mutable_dir(&mut || {
                honeypot::write_boot_id(dir, now).map_err(anyhow::Error::from)
            })
            .and_then(|()| p.register_active(&file))
        }
        None => honeypot::write_boot_id(dir, now).map_err(anyhow::Error::from),
    };
    if let Err(e) = written {
        warn!(
            error = %format!("{e:#}"),
            "recording the boot id failed — the next start will judge missing runtime \
             control-surface files as after a reboot"
        );
    }
}

/// External audit FIMR-008: control-surface files missing, replaced or
/// unrestorable at boot — removed while the agent was not running, or a
/// tmpfs one within the same boot — recorded in the signed audit chain.
fn attest_bait_integrity(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    report: &northnarrow_agent::fim::honeypot::HoneypotIntegrityReport,
    rebooted: bool,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "bait_missing_at_boot",
            "recreated": report.recreated,
            "replaced": report.replaced,
            "unrestorable": report.failed,
            "rebooted": rebooted,
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the control-surface file check failed");
    }
}

/// Lab PR 260: the boot's record of the trips the canary access log holds
/// and the registry does not ([`Registry::unrecorded_trips`]), before the
/// detector runs. Each is an ERROR and a signed `canary_trip_recovered`
/// (attested first: a stop before the `Trip` row is written finds and
/// attests it again), then a `Trip` row naming its access row
/// (`Registry::mark_tripped`); a row that cannot be written leaves the trip
/// for this run, and the next start finds it again. A log that cannot be
/// read is a signed `subsystem_degraded`: the canaries are then as the
/// registry says.
///
/// [`Registry::unrecorded_trips`]: northnarrow_agent::canary::registry::Registry::unrecorded_trips
fn record_unrecorded_trips(
    registry: &mut northnarrow_agent::canary::registry::Registry,
    access_log: &std::path::Path,
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let trips = match registry.unrecorded_trips(access_log) {
        Ok(trips) => trips,
        Err(e) => {
            error!(
                error = %format!("{e:#}"),
                path = %access_log.display(),
                "canary: the access log could not be read for trips the registry does not \
                 record — the canaries are as the registry says"
            );
            attest_degraded(
                audit_log,
                &format!(
                    "canary: trips the registry does not record not looked for (the access log \
                     could not be read: {e:#})"
                ),
            );
            return;
        }
    };
    for trip in trips {
        error!(
            canary_id = %trip.canary_id,
            name = %nn_model::log_escape::Escaped(&trip.name),
            access_row = trip.access_row,
            access_ts = %trip.access.ts,
            accessor_pid = trip.access.accessor_pid,
            accessor_comm = %nn_model::log_escape::Escaped(&trip.access.accessor_comm),
            first_trip_rows = trip.first_trip_rows,
            "canary: a trip the registry did not record — its access row is in the access log \
             (the agent stopped before the registry's row, or could not write it); recorded now, \
             the canary stays tripped. If the agent stopped, the response to that access did not \
             run: look for its detection and at its accessor"
        );
        attest_trip_recovered(audit_log, &trip);
        if let Err(e) = registry.mark_tripped(&trip.canary_id, Some(trip.access.entry_hash.clone()))
        {
            error!(
                error = %format!("{e:#}"),
                canary_id = %trip.canary_id,
                "canary: recording the trip found in the access log failed — it holds for this \
                 run; the next start finds it again"
            );
        }
    }
}

/// Lab PR 260: a trip found in the canary access log at boot, in the signed
/// audit chain (`canary_trip_recovered`): the canary, its access row (row,
/// hash, time, kind) and its accessor.
fn attest_trip_recovered(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    trip: &northnarrow_agent::canary::registry::UnrecordedTrip,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::canary::registry::TRIP_RECOVERED_OP.to_string(),
        extra: serde_json::json!({
            "canary_id": trip.canary_id,
            "name": trip.name,
            "canary_type": trip.access.canary_type,
            "access_kind": trip.access.access_kind,
            "access_row": trip.access_row,
            "access_entry_hash": trip.access.entry_hash,
            "access_ts": trip.access.ts,
            "accessor_pid": trip.access.accessor_pid,
            "accessor_uid": trip.access.accessor_uid,
            "accessor_comm": trip.access.accessor_comm,
            "accessor_exe": trip.access.accessor_exe,
            "first_trip_rows": trip.first_trip_rows,
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "recovered".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the canary trip found at boot failed");
    }
}

/// External audit DEC-010: a decoy found at boot in a state other than
/// the one recorded, in the signed audit chain: `integrity_drift`
/// (`canary_decoy_missing`, or `canary_decoy_tampered` for a decoy
/// modified, replaced by something not a regular file, or unreadable), and
/// `integrity_drift_cleared` when it is intact again.
fn attest_decoy_state(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    canary: &northnarrow_agent::canary::registry::CanaryLiveState,
    path: &str,
    check: &northnarrow_agent::canary::registry::DecoyCheck,
) {
    use northnarrow_agent::canary::registry::DecoyState;
    let Some(log) = audit_log else {
        return;
    };
    let kind = |s: DecoyState| match s {
        DecoyState::Missing => "canary_decoy_missing",
        _ => "canary_decoy_tampered",
    };
    let (op, kind, result) = if check.state == DecoyState::Intact {
        (
            northnarrow_agent::self_integrity::CLEARED_OP,
            kind(canary.decoy_state),
            "cleared",
        )
    } else {
        (
            northnarrow_agent::self_integrity::AUDIT_OP,
            kind(check.state),
            "detected",
        )
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: op.to_string(),
        extra: serde_json::json!({
            "kind": kind,
            "canary_id": canary.canary_id,
            "name": canary.name,
            "path": path,
            "state": check.state.as_str(),
            "recorded_state": canary.decoy_state.as_str(),
            "expected_sha256": canary.content.as_ref().map(|c| c.contents_sha256.as_str()),
            "found_sha256": check.found_sha256,
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the decoy check failed");
    }
}

/// External audit MAIN-003: a subsystem running degraded is recorded in
/// the signed audit chain, not only in the journal.
fn attest_degraded(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    detail: &str,
) {
    attest_degraded_at(audit_log, detail, true);
}

/// External audit EBPF-016: the signed `subsystem_degraded` of
/// [`northnarrow_agent::fs_type::IdentityReport`] (`reason:
/// inode_identity_unverified`, the filesystems, their counts and first
/// paths).
fn attest_identity_unverified(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    report: &northnarrow_agent::fs_type::IdentityReport,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: report.audit_extra(),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "attesting the unverified inode identity failed");
    }
}

/// [`attest_degraded`] for a subsystem that stopped after boot (external
/// audit MAIN-007: a drain loop that returns ends a telemetry stream for
/// the rest of the run).
///
/// Lab PR 218: through the degradation registry — signed now as before, and
/// listed by `nn-admin status --key` and counted against the trust level.
fn attest_degraded_at(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    detail: &str,
    at_boot: bool,
) {
    northnarrow_agent::boot::degradation::report_signed(audit_log, "", detail, at_boot);
}

/// Lab PR 218: a start refused by a boot gate (`install_manifest`,
/// `bpf_lsm`, `deny_self_test`) leaves the refusal in the signed chain
/// before the process exits — the rollback floor, the identity, then the
/// `subsystem_degraded` (`degraded`: source and detail) and the `agent_boot`
/// `refused` naming the gate — so root cannot quietly remove the trace
/// (lab PR 21).
fn record_refused_boot(
    cli: &Cli,
    identity: &agent_id::AgentIdentity,
    overlay_gate: &northnarrow_agent::config::overlay_auth::OverlayGate,
    gate: &str,
    (integrity, provenance): (&str, &str),
    degraded: Option<(&str, &str)>,
    detail: &str,
) {
    let Ok(key) =
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
    else {
        return;
    };
    let Ok(mut log) =
        northnarrow_agent::audit::AuditLog::open(&cli.audit_log_file, key, identity.id)
    else {
        return;
    };
    overlay_gate.attest_floor(&mut log);
    // External audit EVD-020: a refused boot records its identity too.
    if let Err(e) = log.attest_identity(identity) {
        warn!(error = format!("{e:#}"), "agent identity not recorded");
    }
    if let Some((source, what)) = degraded {
        northnarrow_agent::boot::degradation::sign_into(&mut log, source, what, true);
    }
    match log.boot_refused_by(
        gate,
        integrity,
        provenance,
        detail,
        &northnarrow_agent::build_info::agent_build(),
    ) {
        Ok(e) => {
            info!(entry_hash = %e.entry_hash, gate, "refused boot recorded in the audit chain")
        }
        Err(e) => error!(
            error = format!("{e:#}"),
            "could not record the refused boot in the audit chain"
        ),
    }
}

/// A drain loop returned: its telemetry stream is gone for the rest of
/// this run. Per-event errors never end a drain (they are logged and the
/// loop goes on), so this is a tokio I/O failure — recorded in the signed
/// chain, not only as a journal line (external audit MAIN-007).
fn drain_ended(
    stream: &str,
    outcome: std::io::Result<()>,
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let why = match outcome {
        Ok(()) => "returned".to_string(),
        Err(e) => format!("failed: {e}"),
    };
    error!(
        stream,
        reason = %why,
        "drain loop ended — this telemetry stream stops until the agent restarts"
    );
    attest_degraded_at(
        audit_log,
        &format!("{stream} drain loop ended ({why}): no {stream} telemetry until restart"),
        false,
    );
}

/// External audit LLMR-016: a default list that could not be read, and
/// gave way to the copy built into the agent, is recorded in the signed
/// chain through the overlay gate (queued until the audit log is open);
/// LLMR-015 (NN-AUD-327): so is one edited by hand, which is not applied.
/// An earlier release's list, superseded by the built-in copy, is a WARN
/// only: what is in force is what shipped.
fn report_builtin_defaults(
    gate: &northnarrow_agent::config::overlay_auth::OverlayGate,
    list: &str,
    v1: &std::path::Path,
    source: &northnarrow_agent::config::overlay::DefaultsSource,
) {
    use northnarrow_agent::config::overlay::DefaultsSource;
    match source {
        DefaultsSource::BuiltIn(why) => gate.report_default_unavailable(list, v1, why),
        DefaultsSource::Modified {
            sha256,
            builtin_sha256,
            loaded_anyway,
        } => gate.report_default_modified(list, v1, sha256, builtin_sha256, *loaded_anyway),
        DefaultsSource::Disk | DefaultsSource::Superseded { .. } => {}
    }
}

/// Lab PR 160: the head anchor of this run, written once now with the heads
/// this boot found (before this boot appends anything). Reports a removed
/// anchor first ([`northnarrow_agent::chain_anchor::BootCheck::heads_missing`]).
fn start_chain_anchor(
    cli: &Cli,
    heads_file: &std::path::Path,
    targets: &[northnarrow_agent::chain_anchor::ChainTarget],
    boot: &mut northnarrow_agent::chain_anchor::BootCheck,
    agent_id: [u8; 16],
    log: &northnarrow_agent::audit::AuditLog,
) -> Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>> {
    boot.heads_missing(heads_file, log.anchoring_started());
    let key =
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "chain heads: no signing key — heads not anchored"
                );
                return None;
            }
        };
    let mut anchor = northnarrow_agent::chain_anchor::Anchor::new(
        heads_file.to_path_buf(),
        key,
        agent_id,
        targets.to_vec(),
        boot.previous.clone(),
        log.anchoring_started(),
    );
    let second = log.second_key_added() || boot.second_key_added();
    match anchor.refresh(true, second) {
        Ok(_) => info!(path = %heads_file.display(), "chain heads anchored at start"),
        Err(e) => warn!(
            error = format!("{e:#}"),
            path = %heads_file.display(),
            "chain heads: not anchored at start (retried every few minutes)"
        ),
    }
    Some(Arc::new(parking_lot::Mutex::new(anchor)))
}

/// Lab PR 160: what a chain's open verification found (external audit
/// NN-AUD-174), in the signed audit chain.
fn attest_chain_findings(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    findings: Vec<northnarrow_agent::chain_anchor::ChainFinding>,
) {
    if findings.is_empty() {
        return;
    }
    let mut guard = audit_log.map(|l| l.lock());
    for f in &findings {
        f.attest(guard.as_deref_mut());
    }
}

/// External audit DEC-006 / NET-003: what a chain log's open repaired or
/// skipped is recorded in the signed audit chain.
fn attest_open_findings(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    file: &std::path::Path,
    (repair, skipped): (Option<northnarrow_agent::chainlog::TailRepair>, usize),
) {
    let Some(log) = audit_log else {
        return;
    };
    let mut log = log.lock();
    if let Some(r) = repair {
        if let Err(e) = log.attest_tail_repair(file, &r) {
            warn!(error = %e, file = %file.display(), "attesting a chain repair failed");
        }
    }
    if skipped > 0 {
        if let Err(e) = log.attest_skipped_lines(file, skipped) {
            warn!(error = %e, file = %file.display(), "attesting skipped chain lines failed");
        }
    }
}

/// Beta Step 3: background task that keeps the watchdog PID slot of
/// `exempt` in sync with the live, exe-verified watchdog.
///
/// Re-resolves every 30 s (the first tick fires immediately so the
/// exemption activates as soon as the watchdog publishes its pidfile).
/// Logs only on a *change* of verified PID so a steady state doesn't
/// flood the journal; any non-`Verified` outcome clears the exemption
/// (fail toward over-triggering).
/// External audit EBPF-001: systemd (PID 1 itself, `SO_PEERCRED`) reported
/// the host as stopping — no posture escalation and no ladder until the
/// process ends at systemd-shutdown's final stage.
static HOST_STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// External audit CMB-012: how long the COMBAT release waits for the
/// ladder's queued steps (a NEUTRALIZE of a large tree takes seconds)
/// before it lifts the isolation anyway.
const LADDER_RELEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The host is shutting down: stand the ladder down once and stop
/// escalating (see [`HOST_STOPPING`]).
fn host_stopping(ladder: &northnarrow_agent::combat::CombatLadder) {
    if !HOST_STOPPING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        warn!("host shutting down — active response stood down, detection continues");
        ladder.stand_down(Instant::now());
    }
}

/// What systemd reports the host as (`SystemState`: `running`,
/// `degraded`, `stopping`, …), asked over its private socket from this
/// process ([`northnarrow_agent::systemd_state`]) — only for a signal PID 1
/// relayed and the kernel refused, and every 2 s by the shutdown watch;
/// at most once a second. `None` when
/// systemd does not answer within 1 s, or the socket is not served by
/// PID 1.
async fn systemd_state() -> Option<String> {
    static LAST: parking_lot::Mutex<Option<(Instant, Option<String>)>> =
        parking_lot::Mutex::new(None);
    if let Some((at, state)) = LAST.lock().clone() {
        if at.elapsed() < Duration::from_secs(1) {
            return state;
        }
    }
    let ask = tokio::task::spawn_blocking(|| {
        northnarrow_agent::systemd_state::system_state(
            std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET),
            Duration::from_millis(800),
        )
    });
    let state = match tokio::time::timeout(Duration::from_secs(1), ask).await {
        Ok(Ok(Ok(state))) => Some(state),
        Ok(Ok(Err(e))) => {
            debug!(error = %e, "systemd's state could not be read");
            None
        }
        _ => None,
    };
    *LAST.lock() = Some((Instant::now(), state.clone()));
    state
}

/// PID 1 is `systemd-shutdown` (its comm, truncated to 15 bytes): the
/// machine is in the last stage of a shutdown.
fn pid1_is_systemd_shutdown() -> bool {
    std::fs::read_to_string("/proc/1/comm").is_ok_and(|c| c.trim_end() == "systemd-shutdow")
}

/// External audit EBPF-001: re-record `systemd-shutdown`'s identity every
/// minute (a package upgrade gives it a new inode).
fn spawn_shutdown_exe_refresh() {
    let Some(root) = northnarrow_agent::anti_tamper::prepare_pin_root() else {
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match northnarrow_agent::anti_tamper::refresh_shutdown_exe(root) {
                Ok(Some(k)) => info!(
                    dev = k.dev,
                    ino = k.ino,
                    "anti-tamper: systemd-shutdown changed on disk — final-stage identity updated"
                ),
                Ok(None) => {}
                Err(e) => warn!(
                    error = format!("{e:#}"),
                    "anti-tamper: SHUTDOWN_EXE refresh failed"
                ),
            }
        }
    });
}

/// The signed audit log, as the watchdog refresh gets it once it is open.
type WatchdogAudit = Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>;

fn spawn_watchdog_exempt_refresh(
    exempt: ExemptPids,
    pidfile: PathBuf,
    expected_exe: PathBuf,
    audit: Arc<std::sync::OnceLock<WatchdogAudit>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        // Last verified PID we stored (`None` == exemption cleared).
        let mut last: Option<u32> = None;
        // A pid the pidfile named while the registered watchdog ran (logged once).
        let mut refused: Option<u32> = None;
        // BUG-011 (PHASE 15.1): resolve the bpffs root once. None ⇒
        // no bpffs ⇒ register_protected_observer is a no-op (it
        // logs the degraded mode internally).
        let bpffs_root = northnarrow_agent::anti_tamper::prepare_pin_root();
        loop {
            tick.tick().await;
            let resolution = resolve_verified_watchdog_pid(&pidfile, &expected_exe);
            let new_pid = match &resolution {
                WatchdogResolution::Verified { pid, .. } => Some(*pid),
                _ => None,
            };
            if new_pid == last {
                // External audit POS-009: the posture exemption follows the
                // start of the process verified now (a restart that drew the
                // same PID).
                if let WatchdogResolution::Verified { pid, start_ticks } = &resolution {
                    exempt.set_watchdog(*pid, *start_ticks);
                }
                continue; // no change — stay quiet on the hot path
            }
            // External audit EBPF-002: one watchdog at a time. While the
            // registered watchdog still runs, a pidfile naming another
            // process — even one running the watchdog binary, possibly with
            // LD_PRELOAD — is not protected: rewritten or mounted over, it
            // would hand a root shell's process the agent's maps.
            if let (Some(prev), Some(p)) = (last, new_pid) {
                if runs_watchdog_binary(prev, &expected_exe) {
                    if refused != Some(p) {
                        warn!(
                            registered = prev,
                            named = p,
                            "the watchdog pidfile names another process while the registered \
                             watchdog runs — not protected"
                        );
                        refused = Some(p);
                    }
                    continue;
                }
            }
            // External audit MAIN-001: PROTECTED_PIDS follows the verified
            // watchdog. The previous pid leaves it once it no longer runs
            // the watchdog binary (dead, or recycled by another program);
            // a deleted or rewritten pidfile alone does not unprotect the
            // watchdog that still runs.
            if let Some(prev) = last {
                // Lab PR 216: a watchdog gone is signed, once per pid.
                if !runs_watchdog_binary(prev, &expected_exe) {
                    let f = northnarrow_agent::self_integrity::watchdog_gone(prev, &resolution);
                    let log = audit.get().and_then(|l| l.as_ref());
                    northnarrow_agent::self_integrity::report_event(log, &f);
                }
                withdraw_watchdog_pid(bpffs_root, prev, &expected_exe);
            }
            if let Some(p) = new_pid {
                if let Err(e) =
                    northnarrow_agent::anti_tamper::register_protected_pid(bpffs_root, p)
                {
                    warn!(watchdog_pid = p, error = %e, "PROTECTED_PIDS register of the verified watchdog failed");
                }
                // External audit EBPF-002: the verified watchdog is the
                // live one — no second watchdog binary may load beside it.
                if let Err(e) = northnarrow_agent::anti_tamper::claim_watchdog_role(bpffs_root, p) {
                    debug!(watchdog_pid = p, error = %e, "watchdog role not recorded");
                }
            }
            match &resolution {
                WatchdogResolution::Verified {
                    pid: p,
                    start_ticks,
                } => {
                    // External audit POS-009: with its start time — the
                    // exemption ends with that process, not with its PID.
                    exempt.set_watchdog(*p, *start_ticks);
                    // BUG-011: register the verified watchdog PID
                    // in PROTECTED_OBSERVERS so the kernel
                    // ptrace_access_check hook allows it to read
                    // /proc/<agent>/exe (the watchdog's argv
                    // reconstruction path). Eviction of the prior
                    // verified PID (if any) happens first to keep
                    // the map's set semantics tight — a watchdog
                    // restart with a new PID otherwise leaves the
                    // old PID lingering for whatever else might
                    // recycle it.
                    if let Some(prev) = last {
                        if let Err(e) = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        ) {
                            warn!(
                                pid = prev,
                                error = %e,
                                "BUG-011: failed to evict prior watchdog PID from \
                                 PROTECTED_OBSERVERS (continuing; new PID will still register)"
                            );
                        }
                    }
                    match northnarrow_agent::anti_tamper::register_protected_observer(
                        bpffs_root, *p,
                    ) {
                        Ok(()) => info!(
                            watchdog_pid = *p,
                            start_ticks = *start_ticks,
                            exe = %expected_exe.display(),
                            "watchdog PID verified; exempting it from posture triggers + \
                             registering in PROTECTED_OBSERVERS (BUG-011)"
                        ),
                        Err(e) => warn!(
                            watchdog_pid = *p,
                            error = %e,
                            "BUG-011: PROTECTED_OBSERVERS register failed; watchdog \
                             will still be posture-exempt but ptrace_access_check will deny"
                        ),
                    }
                }
                WatchdogResolution::NotPresent => {
                    exempt.clear_watchdog();
                    // BUG-011: withdraw observer rights on watchdog
                    // teardown so a recycled PID can't inherit them.
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    info!(
                        pidfile = %pidfile.display(),
                        "watchdog pidfile absent; no watchdog exemption active"
                    );
                }
                WatchdogResolution::InvalidPidfile { reason } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(%reason, "watchdog pidfile unparseable; watchdog exemption cleared");
                }
                WatchdogResolution::Unverifiable { pid, reason } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(pid, %reason, "watchdog exe verification failed; exemption cleared");
                }
                WatchdogResolution::ExeMismatch { pid, resolved } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(
                        pid,
                        resolved = %resolved.display(),
                        expected = %expected_exe.display(),
                        "watchdog PID maps to an unexpected binary (PID reuse or \
                         substitution); exemption refused"
                    );
                }
            }
            last = new_pid;
        }
    });
}

/// Best-effort compatibility record for a Beta Step 4a stale-COMBAT
/// reconcile: one JSONL line in
/// [`northnarrow_agent::combat::reconcile::LOG_PATH`]; a write failure is
/// logged but never fatal — the teardown it records has already happened,
/// and the signed `integrity_drift` (`combat_reconcile`) is the evidence
/// (external audit MAIN-013). Lab follow-up (lab PR 188): written once the
/// state directory's protection exists, a missing file created inside
/// `protection`'s dance ([`northnarrow_agent::combat::reconcile::record_line`]).
fn audit_combat_reconcile(
    protection: &dyn northnarrow_agent::chainlog::ProtectionManager,
    rules_removed: usize,
) {
    use northnarrow_agent::combat::reconcile::{record_line, CAP_BYTES, LOG_PATH};
    // BUG-026 B-cap: combat-audit is the lone UNSIGNED / unchained
    // best-effort log (BUG-028). `/var/lib/northnarrow` is `chattr +i`, so
    // a rename-based rotate is a blocked dir-entry op — capped by
    // TRUNCATE-IN-PLACE (a content op, allowed under `+i`).
    if let Err(e) = record_line(
        std::path::Path::new(LOG_PATH),
        rules_removed,
        CAP_BYTES,
        protection,
    ) {
        warn!(
            error = format!("{e:#}"),
            path = LOG_PATH,
            "could not write COMBAT reconcile audit line (non-fatal)"
        );
    }
}

/// External audit DEP-006: where the ids of the agent's loaded BPF programs
/// go — next to `--pid-file` (the unit: `/run/northnarrow/bpf-own-ids`).
/// Without `--pid-file` (the e2e fixtures, a manual run) nothing is
/// written, so the installed agent's list is never overwritten by another.
fn own_prog_ids_file(cli: &Cli) -> Option<PathBuf> {
    cli.pid_file
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(|dir| dir.join(northnarrow_agent::anti_tamper::bpf_defense::OWN_IDS_FILE_NAME))
}

/// Write the program-id list (see [`own_prog_ids_file`]); a failure is a
/// WARN: the scripts then fall back to their older, host-wide wait.
fn record_own_prog_ids(path: Option<&std::path::Path>, ebpf: &aya::Ebpf) {
    let Some(path) = path else {
        return;
    };
    match northnarrow_agent::anti_tamper::bpf_defense::write_own_prog_ids(ebpf, path) {
        Ok(n) => debug!(
            path = %path.display(),
            programs = n,
            "own BPF program ids recorded (install.sh / uninstall.sh wait for them)"
        ),
        Err(e) => warn!(
            error = format!("{e:#}"),
            path = %path.display(),
            "own BPF program ids NOT recorded — install.sh --upgrade and uninstall.sh wait on the \
             list written earlier this boot, or fall back to waiting for no LSM program on the host"
        ),
    }
}

/// Atomically publish the current PID to `path` (Tappa 7 task 6
/// #2b-verify). A sibling tempfile is written then `rename(2)`d over
/// the target, so the rename is a same-filesystem atomic swap and a
/// concurrent reader observes either the old file or the complete new
/// one — never a truncated or empty file. The tempfile name carries
/// the PID so two agents misconfigured onto one path cannot corrupt
/// each other's tempfile mid-write. Every error is contextualised and
/// propagated (never swallowed) so the caller can make it fatal and a
/// failing harness can pinpoint which syscall failed.
fn write_pid_file(path: &std::path::Path) -> Result<()> {
    let pid = std::process::id();
    if path.file_name().is_none() {
        anyhow::bail!(
            "--pid-file path has no file-name component: {}",
            path.display()
        );
    }
    // External audit WDG-015 (NN-AUD-364): `/run/northnarrow` is writable
    // by root and outside the inode deny set, and the agent is a process
    // the hooks trust: its temporary file (`agent.pid.tmp.<pid>`, written
    // with `fs::write`) followed a link planted at that predictable name.
    // The AUT-003 writer removes whatever sits at the temporary name and
    // creates it exclusively, then renames it into place. A missing parent
    // directory still fails here, at startup, loudly.
    northnarrow_agent::atomic_file::write_pidfile(path, pid)
        .with_context(|| format!("writing PID file {} (atomic replace)", path.display()))?;

    info!(
        target: "anti-tamper",
        path = %path.display(),
        pid,
        "pid_file written (atomic tempfile+rename; existence == post-attach readiness gate)"
    );
    Ok(())
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit (at most 65 536).
/// Returns the new soft limit.
fn raise_nofile_rlimit() -> std::io::Result<u64> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid `rlimit` to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let want = rlim.rlim_max.min(65_536);
    if rlim.rlim_cur >= want {
        return Ok(rlim.rlim_cur);
    }
    rlim.rlim_cur = want;
    // SAFETY: a valid `rlimit` passed by reference; the kernel only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(want)
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

/// `--btf-check`: resolve the runtime offset table against a BTF file and
/// print a one-line verdict plus every drifted or missing entry.
fn btf_check(path: &std::path::Path) -> i32 {
    use northnarrow_agent::anti_tamper::btf_revalidate::resolve_offsets_from;
    match resolve_offsets_from(path) {
        ResolveOutcome::Resolved(r) => {
            println!(
                "btf-check {}: {} — {} slots resolved, {} differ from the build kernel, {} absent, {} hook arguments checked",
                path.display(),
                if r.absent.is_empty() {
                    "SUPPORTED"
                } else {
                    "SUPPORTED (degraded)"
                },
                r.values.len(),
                r.drifted.len(),
                r.absent.len(),
                r.hook_args_checked
            );
            for m in &r.absent {
                let effect = if m.struct_name.starts_with("bpf_lsm_") {
                    format!(
                        "not attached: {} (the agent starts only with NN_ANTI_TAMPER_ALLOW_DEGRADED=1)",
                        northnarrow_agent::anti_tamper::btf_revalidate::hook_arg_effect(m.struct_name)
                    )
                } else {
                    "dependent sensor path disabled".to_string()
                };
                println!(
                    "  absent  {:<34} {:<12} {} — {effect}",
                    m.name, m.struct_name, m.detail
                );
            }
            // Lab PR 174: the deny hooks only some kernels have, counted
            // as expected where the BTF has them.
            for (hook, present) in &r.optional_deny_hooks {
                let verdict = if *present {
                    format!(
                        "present — bpf_lsm_{hook} in the BTF: its deny program attaches and counts as an expected deny hook"
                    )
                } else {
                    format!("absent  — no bpf_lsm_{hook} in the BTF: no deny program on it, not expected")
                };
                println!("  optional {hook:<33} {verdict}");
            }
            for module in &r.modules_not_loaded {
                println!(
                    "  module  {module:<34} no BTF next to the vmlinux file — its types' offsets stay unset (not a degradation)"
                );
            }
            for m in &r.drifted {
                println!(
                    "  drift   {:<34} {:<12} compiled={:<6} runtime={}",
                    m.name,
                    m.struct_name,
                    m.expected,
                    m.actual
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                );
            }
            0
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            println!("btf-check {}: UNREADABLE — {reason}", path.display());
            3
        }
        ResolveOutcome::Refuse(RefuseReason::Drift(missing)) => {
            println!(
                "btf-check {}: NOT SUPPORTED — {} field(s)/enumerator(s)/hook argument(s) missing (the agent would refuse to start)",
                path.display(),
                missing.len()
            );
            for m in &missing {
                println!(
                    "  missing {:<34} {:<12} {}",
                    m.name, m.struct_name, m.detail
                );
            }
            2
        }
        ResolveOutcome::Refuse(RefuseReason::ParseError(e)) => {
            println!("btf-check {}: UNPARSEABLE — {e}", path.display());
            3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wave 4 (lab PR 214): a unit written for an agent with the LLM
    /// advisor still parses — its flags are accepted, ignored and named.
    #[test]
    fn the_removed_advisor_flags_still_parse_and_are_named() {
        let cli = Cli::try_parse_from([
            "northnarrow-agent",
            "--no-ade",
            "--ade-model",
            "/var/lib/northnarrow/models/m.gguf",
            "--ade-timeout",
            "15",
            "--ade-prompt",
            "dataset/system_prompt_v1.md",
            "--ade-threads",
            "3",
            "--detect-only",
        ])
        .expect("an old unit's command line parses");
        assert_eq!(
            cli.removed_flags(),
            northnarrow_agent::removed_settings::REMOVED_FLAGS
        );
        assert!(cli.detect_only, "the other flags keep their meaning");

        let cli = Cli::try_parse_from(["northnarrow-agent", "--ade-timeout", "not-a-number"])
            .expect("a removed flag's value is not parsed");
        assert_eq!(cli.removed_flags(), ["--ade-timeout"]);

        let cli = Cli::try_parse_from(["northnarrow-agent"]).unwrap();
        assert!(cli.removed_flags().is_empty());
    }

    /// Lab (21/10, debian12): an agent unit with `NN_NET_CONNECT_DENY=1`,
    /// the value the help and the CHANGELOG give, did not start — exit 2,
    /// "invalid value '1' for '--net-connect-deny'" (clap's plain bool
    /// parser takes only `true` / `false` from the environment) — and the
    /// watchdog held. An environment switch reads 1/0, true/false, yes/no,
    /// on/off; anything else is refused, never read as on.
    #[test]
    fn env_switches_read_1_and_0() {
        const SWITCHES: &[(&str, &str)] = &[
            ("NN_NET_CONNECT_DENY", "--net-connect-deny"),
            ("NN_EXEC_POLICY_NO_ENV", "--exec-policy-no-env"),
            ("NN_EXEC_POLICY_NO_MAP", "--exec-policy-no-map"),
        ];
        fn get(cli: &Cli, flag: &str) -> bool {
            match flag {
                "--net-connect-deny" => cli.net_connect_deny,
                "--exec-policy-no-env" => cli.exec_policy_no_env,
                "--exec-policy-no-map" => cli.exec_policy_no_map,
                _ => unreachable!("{flag}"),
            }
        }
        let clear = || {
            for (env, _) in SWITCHES {
                std::env::remove_var(env);
            }
        };
        clear();
        let cli = Cli::try_parse_from(["northnarrow-agent"]).unwrap();
        for (_, flag) in SWITCHES {
            assert!(!get(&cli, flag), "{flag} off by default");
            let cli = Cli::try_parse_from(["northnarrow-agent", flag]).unwrap();
            assert!(get(&cli, flag), "{flag} on the command line");
        }
        for (value, on) in [
            ("1", true),
            ("true", true),
            ("yes", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("no", false),
            ("off", false),
        ] {
            for (env, flag) in SWITCHES {
                std::env::set_var(env, value);
                let cli = Cli::try_parse_from(["northnarrow-agent"]);
                std::env::remove_var(env);
                let cli = cli.unwrap_or_else(|e| panic!("{env}={value}: {e}"));
                assert_eq!(get(&cli, flag), on, "{env}={value}");
            }
        }
        for (env, _) in SWITCHES {
            std::env::set_var(env, "maybe");
            let r = Cli::try_parse_from(["northnarrow-agent"]);
            std::env::remove_var(env);
            assert!(r.is_err(), "{env}=maybe is refused, not read as on");
        }
        clear();
    }

    /// The removed flags are hidden: `--help` no longer offers them.
    #[test]
    fn the_removed_advisor_flags_are_not_in_the_help() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        for flag in northnarrow_agent::removed_settings::REMOVED_FLAGS {
            assert!(!help.contains(flag), "{flag} in:\n{help}");
        }
    }
}
