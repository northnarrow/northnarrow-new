
/// The signed audit log, once [`boot_attest`] opened it (`None`: the boot
/// runs unaudited, as the attest phase allowed).
type AuditHandle = Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>;

/// The chains' head anchor of this run (lab PR 160).
type AnchorHandle = Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>>;

/// What [`boot_attest`] opened.
struct Attested {
    chain_anchor: AnchorHandle,
    audit_log: AuditHandle,
}

/// `BootPhase::Attest` (lab PR 218): the signed audit log opens — the heads
/// anchored as this boot found them, the rollback floor, the chains'
/// findings, the identity, then the boot's own `agent_boot` (an audit log
/// that cannot be written refuses the start unless that is allowed) — and
/// every degradation found so far is signed. Then `BootPhase::Subsystems`.
#[allow(clippy::too_many_arguments)]
fn boot_attest(
    cli: &Cli,
    boot: &mut BootSequence,
    heads_file: PathBuf,
    chain_targets: &[northnarrow_agent::chain_anchor::ChainTarget],
    mut boot_chains: northnarrow_agent::chain_anchor::BootCheck,
    agent_id: [u8; 16],
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    identity: agent_id::AgentIdentity,
    detect_only_source: &Option<String>,
    integrity: northnarrow_agent::install_manifest::IntegrityOutcome,
    tracepoint_degraded: Option<String>,
    hook_args_degraded: Option<String>,
    exploit_guard_degraded: Option<String>,
    caps_degraded: Vec<String>,
) -> Result<Attested> {
    // Lab PR 218: the signed audit log right after the self-test, before
    // the subsystems below load (the blocklists, the rules, the response
    // executor, the posture, FIM): every degradation found so far is signed
    // now, and later ones within `boot::degradation::FLUSH_PERIOD`.
    boot.enter(BootPhase::Attest)?;
    // ── Shared audit log + COMBAT graduated-response ladder ─────────
    //
    // The signed, hash-chained audit log is opened ONCE here (now that
    // agent_id is ready) and shared by both the COMBAT ladder (per-stage
    // signed transitions) and the admin socket (admin-op audit). A `None`
    // audit log (open/key failure) degrades to log-only, exactly as the
    // admin-op path already tolerates.
    let mut chain_anchor: Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>> =
        None;
    let audit_log: Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>> =
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => {
                match northnarrow_agent::audit::AuditLog::open(&cli.audit_log_file, key, agent_id) {
                    // Boot write probe (etc-readonly-audit-1): a signed
                    // `agent_boot` entry proves the chain is writable NOW
                    // instead of failing silently at the first COMBAT
                    // transition. Fail-closed in enforcement mode.
                    Ok(mut log) => {
                        // Lab PR 160: anchor the heads as this boot found
                        // them before it appends anything (the snapshot is on
                        // disk before the first numbered row of an upgrade).
                        // A row-number break in the audit chain counts as
                        // lost history there too (ATP-004 fails closed).
                        for f in log.take_open_findings(&cli.audit_log_file) {
                            boot_chains.findings.push(f);
                        }
                        chain_anchor = start_chain_anchor(
                            cli,
                            &heads_file,
                            chain_targets,
                            &mut boot_chains,
                            agent_id,
                            &log,
                        );
                        // External audit LLMR-014: the rollback floor's
                        // reset / anchor come first in this boot's entries.
                        overlay_gate.attest_floor(&mut log);
                        // Lab PR 160: what the chain checks found, then the
                        // one-time record of where numbering starts.
                        for f in &boot_chains.findings {
                            f.attest(Some(&mut log));
                        }
                        if let Some(marker) =
                            chain_anchor.as_ref().and_then(|a| a.lock().take_marker())
                        {
                            if let Err(e) = log.append(marker) {
                                warn!(error = %format!("{e:#}"), "chain heads: start not recorded");
                            }
                        }
                        // External audit EVD-020 / MAIN-009: a minted id, an
                        // id other than the one the chain's last row carries,
                        // or a per-boot id (the file unusable) is signed
                        // before the boot's own entry.
                        if let Err(e) = log.attest_identity(&identity) {
                            warn!(error = format!("{e:#}"), "agent identity not recorded");
                        }
                        match log.boot_probe(
                            detect_only_source.as_deref(),
                            integrity.label(),
                            integrity.provenance(),
                            &northnarrow_agent::build_info::agent_build(),
                        ) {
                            Ok(entry) => {
                                info!(
                                    path = %cli.audit_log_file.display(),
                                    entry_hash = %entry.entry_hash,
                                    "audit log writable — agent_boot entry appended"
                                );
                                if let northnarrow_agent::audit::PreviousRun::Abrupt {
                                    booted_at,
                                    last_entry_at,
                                } = log.previous_run()
                                {
                                    warn!(
                                        booted_at = %booted_at,
                                        last_entry_at = %last_entry_at,
                                        "PREVIOUS RUN ENDED ABRUPTLY — the agent that booted then never \
                                         wrote agent_stop: SIGKILL (systemctl kill, cgroup.kill), OOM, \
                                         crash or power loss; recorded in this boot's audit entry"
                                    );
                                }
                                Some(Arc::new(parking_lot::Mutex::new(log)))
                            }
                            Err(e) => {
                                let fatal = northnarrow_agent::audit::audit_failure_is_fatal(
                                    std::env::var(
                                        northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV,
                                    )
                                    .ok()
                                    .as_deref(),
                                );
                                error!(
                                    error = format!("{e:#}"),
                                    path = %cli.audit_log_file.display(),
                                    fatal,
                                    "audit log NOT writable — the signed audit chain would stop here \
                                     (is the directory in the unit's ReadWritePaths?)"
                                );
                                if fatal {
                                    anyhow::bail!(
                                    "audit log {} is not writable: {e:#}. Refusing to run unaudited; \
                                     set {}=1 to start anyway.",
                                    cli.audit_log_file.display(),
                                    northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                                );
                                }
                                None
                            }
                        }
                    }
                    Err(e) => {
                        let fatal = northnarrow_agent::audit::audit_failure_is_fatal(
                            std::env::var(northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV)
                                .ok()
                                .as_deref(),
                        );
                        error!(error = format!("{e:#}"), fatal, "audit log open failed — COMBAT stage transitions + admin ops would be UNAUDITED");
                        if fatal {
                            anyhow::bail!(
                                "audit log {} cannot be opened: {e:#}. Refusing to run unaudited; set {}=1 to start anyway.",
                                cli.audit_log_file.display(),
                                northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                            );
                        }
                        None
                    }
                }
            }
            Err(e) => {
                warn!(error = format!("{e:#}"), "agent signing key load failed — COMBAT stage transitions + admin ops UNAUDITED this boot");
                None
            }
        };
    boot.done(BootStep::AgentBoot)?;
    // External audit ATP-016 (NN-AUD-264): a start under
    // NN_ANTI_TAMPER_ALLOW_DEGRADED=1 and a missing observe hook, in the
    // signed chain with what is missing — the journal line was the only
    // trace.
    for detail in northnarrow_agent::anti_tamper::take_degraded_boot_details() {
        northnarrow_agent::boot::degradation::report("anti_tamper", &detail);
    }
    // External audit NN-AUD-098 / lab PR 164 / CMB-028: found before the
    // attach, signed here (lab PR 218: they waited for the subsystems'
    // setup).
    if let Some(detail) = &tracepoint_degraded {
        northnarrow_agent::boot::degradation::report("tracepoint_offsets", detail);
    }
    if let Some(detail) = &hook_args_degraded {
        northnarrow_agent::boot::degradation::report("lsm_hook_args", detail);
    }
    // Lab PR 219: the exploit guard off or unavailable (found at its attach).
    if let Some(detail) = &exploit_guard_degraded {
        northnarrow_agent::boot::degradation::report("exploit_guard", detail);
    }
    for detail in &caps_degraded {
        northnarrow_agent::boot::degradation::report("capabilities", detail);
    }
    // External audit EBPF-006: on the `udp_sendmsg` sensor (a kernel
    // without what the socket-buffer programs need, or `--dns-sensor
    // sendmsg`) a query's name is read from the sender's memory before the
    // kernel copies it: the sender can change it in between, so the name
    // recorded and the one sent may differ.
    if !northnarrow_agent::sensors::dns_sensor::skb_active() {
        northnarrow_agent::boot::degradation::report(
            "dns_sensor",
            "DNS sensor on udp_sendmsg: query names read from the sender's memory, which it \
             can rewrite before the kernel sends them (IPv4 only)",
        );
    }
    // Lab PR 219: the exploit guard sampler's saturation entries from now on.
    northnarrow_agent::sensors::epg::set_audit_log(audit_log.clone());
    let signed = northnarrow_agent::boot::degradation::attach_audit_log(audit_log.clone());
    northnarrow_agent::boot::degradation::spawn_flusher();
    if signed > 0 {
        info!(
            degradations = signed,
            "boot degradations signed in the audit chain (nn-admin status --key lists them)"
        );
    }
    boot.done(BootStep::BootDegradations)?;
    boot.enter(BootPhase::Subsystems)?;
    Ok(Attested {
        chain_anchor,
        audit_log,
    })
}

/// The audit log reaches what was built before it opened (the late binding
/// R11c turns into explicit handles): the BPF links' self-check, the
/// watchdog refresh, the foreign pins, a rolled-back upgrade, the overlay
/// gate, the executor, the telemetry probe, the self-integrity watcher, the
/// chains' tasks, the ring drops, the deny hooks' fail-opens, the FIM
/// drain, the trusted-installer window.
#[allow(clippy::too_many_arguments)]
fn boot_wire(
    cli: &Cli,
    audit_log: &AuditHandle,
    watchdog_audit: &std::sync::OnceLock<WatchdogAudit>,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    executor: &Executor,
    chain_anchor: &AnchorHandle,
    chain_targets: Vec<northnarrow_agent::chain_anchor::ChainTarget>,
    posture: &PostureMachine,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
) {
    // Tappa 10.8 BPF self-defence: the link self-check needs the audit log,
    // which did not exist when the hooks attached.
    northnarrow_agent::anti_tamper::bpf_defense::spawn_link_self_check(audit_log.clone());
    // Lab PR 216: and the watchdog refresh, to sign a watchdog that is gone.
    let _ = watchdog_audit.set(audit_log.clone());
    // External audit ATP-017 (NN-AUD-265): the `link_*` entries of the pin
    // root that are not the agent's links, one signed `integrity_drift` each.
    northnarrow_agent::anti_tamper::bpf_defense::attest_foreign_pins(audit_log.as_ref());
    // Lab PR 220: an upgrade install.sh rolled back to this agent, signed
    // as `upgrade_rolled_back` before the agent says it is ready.
    northnarrow_agent::upgrade_rollback::attest(
        audit_log.as_ref(),
        std::path::Path::new(northnarrow_agent::upgrade_rollback::DEFAULT_MARKER_PATH),
    );
    // Tappa 10.8 — overlay decisions taken before the audit log existed.
    overlay_gate.attach_audit_log(audit_log.clone());
    // External audit CMB-017: quarantines are recorded in the signed chain.
    if let Some(audit) = audit_log.as_ref() {
        executor.set_audit_log(Arc::clone(audit));
    }
    // Tappa 10.8 telemetry probe: known events on each sensor, every minute.
    northnarrow_agent::telemetry_probe::spawn(audit_log.clone());
    // Tappa 10.8 adversarial findings: drop-ins, set-property, oom_score_adj, mounts.
    northnarrow_agent::self_integrity::spawn(
        audit_log.clone(),
        cli.watchdog_pidfile.clone(),
        Some(Arc::clone(overlay_gate)),
    );
    // Lab PR 160: the heads re-anchored as they move, and the bounded
    // verification of the rotating logs in the background
    // (external audit NN-AUD-108, NN-AUD-112).
    if let Some(a) = &chain_anchor {
        northnarrow_agent::chains::spawn(Arc::clone(a), audit_log.clone());
    }
    northnarrow_agent::chains::set_audit_log(audit_log.clone());
    if let Some(pk) = northnarrow_agent::keys::boot_verifying_key(&cli.signing_key_file) {
        northnarrow_agent::chains::spawn_boot_verify(chain_targets.clone(), pk, audit_log.clone());
    }
    northnarrow_agent::sensors::ring_drops::set_audit_log(audit_log.clone());
    // Lab PR 215: a deny hook that let an operation through undecided.
    northnarrow_agent::anti_tamper::fail_open::set_audit_log(audit_log.clone());
    // External audit NN-AUD-120: a full FIM watch set is attested.
    northnarrow_agent::fim::drain::set_audit_log(audit_log.clone());
    // External audit SNS-009: a security ring that loses events raises
    // ALERTED (TelemetryLoss), outside trusted-installer windows.
    northnarrow_agent::sensors::ring_drops::set_posture(
        posture.clone(),
        Some(Arc::clone(installer_override)),
    );

    // FIM-009 self-upgrade (§15.1): late-bind the audit-chain writer to
    // the trusted-installer override so its close/expiry records chain.
    if let Some(audit) = audit_log.as_ref() {
        installer_override.set_audit_log(Arc::clone(audit));
    }
}

/// What [`boot_stores`] opened.
struct Stores {
    state_protection:
        Option<std::sync::Arc<northnarrow_agent::anti_tamper::filesystem::StateDirProtection>>,
    rotation_protection: std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager>,
    fim_drift_rotation: northnarrow_agent::chainlog::RotationConfig,
    netflow_rotation: northnarrow_agent::chainlog::RotationConfig,
    detection_sink: Option<northnarrow_agent::detection_store::DetectionSink>,
    detection_admin_state: Option<Arc<admin_socket::DetectionAdminState>>,
}

/// The state directory's protection (BUG-026) and the rotation it lets the
/// logs have (append-only without it), the stale chain's compatibility
/// line, the head anchor in the same dance; the detection log, its writer
/// and its reporter; the status-event log the detection triage writes.
fn boot_stores(
    cli: &Cli,
    sensor: &mut SensorMultiplexer,
    stale_combat: &Option<northnarrow_agent::combat::reconcile::StaleChain>,
    chain_anchor: &AnchorHandle,
    audit_log: &AuditHandle,
) -> Stores {
    // BUG-026: ONE shared StateDirProtection for the rotating on-disk logs
    // under /var/lib/northnarrow (netflow + fim_drift share its dance
    // mutex so two concurrent rotations can't race the dir's chattr +i).
    // `take_protected_inodes_map` takes the PROTECTED_INODES handle out of
    // the Ebpf — it MUST run AFTER the anti-tamper bootstrap registered the
    // protected inodes and (THE VM-VALIDATE ITEM, catalog §24) with nothing
    // else mutating that map via the Ebpf handle afterward. If a runtime
    // path (canary deploy / admin) re-registers a protected inode via the
    // Ebpf, switch this to opening the PINNED map by path instead of
    // `take`. On failure the rotating writers don't open (degrade-not-fail).
    let state_protection: Option<
        std::sync::Arc<northnarrow_agent::anti_tamper::filesystem::StateDirProtection>,
    > = match northnarrow_agent::anti_tamper::filesystem::take_protected_inodes_map(
        sensor.ebpf_mut(),
    ) {
        Ok(h) => Some(std::sync::Arc::new(
            northnarrow_agent::anti_tamper::filesystem::StateDirProtection::new(
                std::path::PathBuf::from(northnarrow_agent::anti_tamper::filesystem::STATE_DIR),
                h,
            ),
        )),
        Err(e) => {
            // ERROR, not warn: anti-tamper FS protection of the state logs is
            // compromised (PROTECTED_INODES missing) AND rotation is disabled.
            tracing::error!(
                error = %e,
                "BUG-026: take_protected_inodes_map failed — anti-tamper FS protection of the \
                 state logs is COMPROMISED and on-disk log ROTATION is disabled this boot; \
                 netflow + fim_drift keep logging APPEND-ONLY (the disk-fill vector returns \
                 until a restart recovers anti-tamper)"
            );
            None
        }
    };
    // Degrade-not-fail (BUG-026 ②): if protection is unavailable, keep
    // telemetry flowing — open the writers with NoProtection + rotation
    // DISABLED (append-only) rather than dropping FIM-drift + netflow, the two
    // core telemetry streams. Losing them is the worse failure for an XDR; the
    // disk grows (the original vector) only until a restart recovers
    // anti-tamper. An effectively-infinite cap means the writer never invokes
    // the chattr dance (which would EPERM under `+i` and stall logging).
    let rotation_protection: std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager> =
        match &state_protection {
            // `p.clone()` clones the concrete Arc, then the match arm
            // unsize-coerces it to Arc<dyn> (Arc::clone(p) would infer the
            // wrong type param from the expected `dyn` and mismatch).
            Some(p) => p.clone(),
            None => std::sync::Arc::new(northnarrow_agent::chainlog::NoProtection),
        };
    // Lab follow-up (lab PR 188): the stale chain's compatibility line, now
    // that the state directory's protection exists — a missing file is
    // created with the directory's `chattr +i` lifted for that moment (a
    // plain open at the teardown was refused with EPERM).
    if let Some(northnarrow_agent::combat::reconcile::StaleChain::TornDown { rules_removed }) =
        &stale_combat
    {
        audit_combat_reconcile(rotation_protection.as_ref(), *rules_removed);
    }
    let rotation_on = state_protection.is_some();
    let cap = |bytes: u64| if rotation_on { bytes } else { u64::MAX };
    // Lab PR 160: the head anchor is created inside the same dance when
    // the state directory is already immutable.
    if let Some(a) = &chain_anchor {
        a.lock().set_protection(rotation_protection.clone());
    }
    // Test/ops knob: NN_FIM_DRIFT_CAP_BYTES overrides the fim_drift active-file
    // rotation cap (default 32 MiB) so rotation can be validated without
    // generating 32 MiB of drift. Unset = default; still gated by rotation_on.
    // External audit MAIN-004: never below 1 MiB, every override logged
    // (and reported as weakening_env by the self-integrity check).
    const FIM_DRIFT_CAP_DEFAULT: u64 = 32 * 1024 * 1024;
    let fim_drift_cap = northnarrow_agent::chainlog::cap_from_env(
        northnarrow_agent::chainlog::FIM_DRIFT_CAP_ENV,
        FIM_DRIFT_CAP_DEFAULT,
    );
    let fim_drift_rotation = northnarrow_agent::chainlog::RotationConfig {
        size_cap_bytes: cap(fim_drift_cap),
        max_archives: 8,
        file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
    };
    let netflow_rotation = northnarrow_agent::chainlog::RotationConfig {
        size_cap_bytes: cap(16 * 1024 * 1024),
        max_archives: 16,
        file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
    };

    // Tappa 9.0.a: open the detection store + spawn its dedicated writer
    // task. Detections are lower-volume than netflow → default 16 MiB ×
    // 8 archives (≈144 MiB budget), overridable via NN_DETECTIONS_CAP_BYTES
    // for rotation validation. Re-load the signing key (separate domain
    // handle, like the FIM block below). Degrade-not-fail: any error here
    // means "no detection persistence this boot", never an agent abort.
    // The writer JoinHandle is detached on drop (tokio keeps the task
    // running); the sink is threaded into the event loop.
    let detection_sink: Option<northnarrow_agent::detection_store::DetectionSink> = {
        let cap_bytes = northnarrow_agent::chainlog::cap_from_env(
            northnarrow_agent::chainlog::DETECTIONS_CAP_ENV,
            northnarrow_agent::detection_store::DEFAULT_DETECTIONS_CAP_BYTES,
        );
        let detections_rotation = northnarrow_agent::chainlog::RotationConfig {
            size_cap_bytes: cap(cap_bytes),
            max_archives: northnarrow_agent::detection_store::DEFAULT_MAX_ARCHIVES,
            file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
        };
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => match northnarrow_agent::detection_store::open(
                &cli.detections_file,
                key,
                detections_rotation,
                rotation_protection.clone(),
                northnarrow_agent::detection_store::DEFAULT_QUEUE_CAP,
            ) {
                Ok((sink, _writer)) => Some(sink),
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %cli.detections_file.display(),
                        "detection store open failed — detections will NOT persist this boot"
                    );
                    None
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    "detection store needs the agent signing key — load failed; \
                     detections will NOT persist this boot"
                );
                None
            }
        }
    };

    // Review 75: detections held back by the per-rule budget, reported.
    // External audit NN-AUD-111: started once the detection store exists,
    // so the same task records the store's queue drops.
    detection_report::spawn_reporter(audit_log.clone(), detection_sink.clone());

    // Tappa 9.0.c: open the status-event chainlog + build the detection
    // admin state for the admin socket (set-status writes here; the
    // detections read overlays current status from it). Lower-volume
    // than detections → smaller 4 MiB cap, overridable via
    // NN_STATUS_EVENTS_CAP_BYTES. Degrade-not-fail: any error here
    // means "no triage status changes this boot" (the `detections` read
    // still works, showing initial Open), never an agent abort.
    let detection_admin_state: Option<Arc<admin_socket::DetectionAdminState>> = {
        let cap_bytes = northnarrow_agent::chainlog::cap_from_env(
            northnarrow_agent::chainlog::STATUS_EVENTS_CAP_ENV,
            northnarrow_agent::detection_store::DEFAULT_STATUS_EVENTS_CAP_BYTES,
        );
        let status_rotation = northnarrow_agent::chainlog::RotationConfig {
            size_cap_bytes: cap(cap_bytes),
            max_archives: northnarrow_agent::detection_store::DEFAULT_MAX_ARCHIVES,
            file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
        };
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => match northnarrow_agent::detection_store::open_status_log(
                &cli.status_events_file,
                key,
                status_rotation,
                rotation_protection.clone(),
            ) {
                Ok(log) => Some(Arc::new(admin_socket::DetectionAdminState {
                    status_log: Arc::new(parking_lot::Mutex::new(log)),
                    detections_path: cli.detections_file.clone(),
                    status_events_path: cli.status_events_file.clone(),
                })),
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %cli.status_events_file.display(),
                        "status-event store open failed — detection triage \
                         (set-status) DISABLED this boot"
                    );
                    None
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    "status-event store needs the agent signing key — load failed; \
                     detection triage (set-status) DISABLED this boot"
                );
                None
            }
        }
    };
    Stores {
        state_protection,
        rotation_protection,
        fim_drift_rotation,
        netflow_rotation,
        detection_sink,
        detection_admin_state,
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
