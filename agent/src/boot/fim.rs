
/// Lab PR 218 (external review P0 C-13): the file-open sensor stays on
/// `sys_enter_openat` — every open goes to userland and its path is read
/// from the caller's memory. Signed and in `nn-admin status`, not only a
/// WARN.
fn open_sensor_on_tracepoint(why: &str) {
    northnarrow_agent::boot::manifest::note_sensor(
        "file_open",
        "tracepoint:syscalls/sys_enter_openat (user memory)",
    );
    northnarrow_agent::boot::degradation::report(
        "file_open_sensor",
        &format!(
            "file-open sensor on sys_enter_openat: every open goes to userland and its path is \
             read from the caller's memory — {why}"
        ),
    );
}

/// Review 69: the LSM file-open sensor could not be armed, so
/// `sys_enter_openat` (attached, inert until now) starts emitting.
fn open_tracepoint_fallback(sensor: &mut SensorMultiplexer) {
    if let Err(e) =
        northnarrow_agent::sensors::open_sensor::set_tracepoint_emitting(sensor.ebpf_mut(), true)
    {
        error!(
            error = %e,
            "file-open sensor: sys_enter_openat could not be turned on — file opens are NOT observed"
        );
    }
}

/// Tappa 10.9 step 1: switch the file-open sensor to LSM `file_open`, once
/// the FIM observer that hosts it is attached; otherwise (or on
/// `--file-open-sensor tracepoint`) `sys_enter_openat` stays in charge.
fn start_open_sensor(
    sensor: &mut SensorMultiplexer,
    mode: FileOpenSensor,
    fim_attached: &[&str],
    carveout: &[String],
    audit_log: Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    posture: &PostureMachine,
) {
    use northnarrow_agent::sensors::open_sensor::{
        pump, refresh, take_ringbuf, warn_refused_carveouts, DepthCapLog, OpenSensorMaps,
        RuleHealth, RuleInputs, RuleSet, RULE_CAPACITY,
    };
    if mode == FileOpenSensor::Tracepoint {
        info!("file-open sensor: tracepoint mode (--file-open-sensor tracepoint) — every open reaches userland");
        open_sensor_on_tracepoint("chosen with --file-open-sensor tracepoint");
        return;
    }
    if !fim_attached.contains(&northnarrow_agent::fim::attach::OPEN_SENSOR_PROGRAM) {
        warn!(
            "file-open sensor: its file_open observer is not attached — keeping sys_enter_openat"
        );
        open_tracepoint_fallback(sensor);
        open_sensor_on_tracepoint("its file_open observer is not attached");
        return;
    }
    let rules = RuleSet::build(&RuleInputs::from_host(carveout));
    warn_refused_carveouts(None, &rules);
    let mut maps = match OpenSensorMaps::take(sensor.ebpf_mut()) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "file-open sensor: rule maps unavailable — keeping sys_enter_openat");
            open_tracepoint_fallback(sensor);
            open_sensor_on_tracepoint(&format!("its rule maps are unavailable ({e})"));
            return;
        }
    };
    // External audit SNS-007: every rule that fits is written, the
    // posture's own first; a refused rule degrades the sensor (ERROR, one
    // signed `subsystem_degraded`) and is tried again at every refresh.
    let applied = maps.apply(&rules, None);
    let mut health = RuleHealth::default();
    report_open_rules(&mut health, &applied, audit_log.as_ref(), true);
    let ring = match take_ringbuf(sensor.ebpf_mut()) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "file-open sensor: ring unavailable — keeping sys_enter_openat");
            open_tracepoint_fallback(sensor);
            open_sensor_on_tracepoint(&format!("its ring is unavailable ({e})"));
            return;
        }
    };
    let handle = tokio::spawn(pump(ring, sensor.event_tx()));
    sensor.register_pump_handle(northnarrow_agent::sensors::open_sensor::PUMP_LABEL, handle);
    if let Err(e) = maps.arm(true) {
        warn!(error = %e, "file-open sensor: arming failed — keeping sys_enter_openat");
        open_tracepoint_fallback(sensor);
        open_sensor_on_tracepoint(&format!("arming failed ({e})"));
        return;
    }
    northnarrow_agent::boot::manifest::note_sensor("file_open", "lsm:file_open (FIM observer)");
    // Lab PR 249: the posture's own switch (it was process-wide).
    posture.set_kernel_mass_write(true);
    // Armed: the old tracepoint (every openat to userland) goes. Its link
    // is retired first, or the BPF self-defence would report its absence
    // as tampering.
    let detached = match sensor.ebpf_mut().program_mut("sys_enter_openat") {
        Some(p) => match <&mut aya::programs::TracePoint>::try_from(p) {
            Ok(tp) => {
                if let Ok(info) = tp.info() {
                    northnarrow_agent::anti_tamper::bpf_defense::retire_program_links(info.id());
                }
                tp.unload().is_ok()
            }
            Err(_) => false,
        },
        None => false,
    };
    info!(
        inode_rules = rules.inodes.len(),
        child_rules = rules.children.len(),
        name_rules = rules.names.len(),
        runtime_dirs = rules.runtime.len(),
        rules_failed = applied.failed,
        capacity = ?RULE_CAPACITY,
        skipped = ?rules.skipped,
        sys_enter_openat_detached = detached,
        "file-open sensor armed on LSM file_open (Tappa 10.9 step 1)"
    );
    // New homes, runtime directories (logins) and paths created since:
    // re-registered every minute, against what the maps really hold.
    let carveout = carveout.to_vec();
    let refresher = tokio::spawn(async move {
        let mut current = applied.in_maps;
        let mut depth_cap = DepthCapLog::default();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            depth_cap.sample(&maps);
            if let Some(applied) = refresh(&mut maps, &current, &carveout) {
                report_open_rules(&mut health, &applied, audit_log.as_ref(), false);
                current = applied.in_maps;
            }
        }
    });
    sensor.register_pump_handle("open_sensor_rules", refresher);
}

/// External audit SNS-007: the outcome of a rule write, said once per
/// change — refused rules are an ERROR and one signed `subsystem_degraded`
/// (not a WARN every minute), a different count while degraded a WARN, the
/// recovery an INFO.
fn report_open_rules(
    health: &mut northnarrow_agent::sensors::open_sensor::RuleHealth,
    applied: &northnarrow_agent::sensors::open_sensor::Applied,
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    at_boot: bool,
) {
    use northnarrow_agent::sensors::open_sensor::RuleHealthChange;
    let first = applied.first_error.as_deref().unwrap_or("");
    match health.note(applied) {
        RuleHealthChange::Degraded => {
            error!(
                failed = applied.failed,
                written = applied.inserted,
                generation_failed = applied.generation_failed,
                first_error = %first,
                "file-open sensor: rules NOT all written — coverage is partial (the posture's own \
                 paths go first; the rest is retried every minute)"
            );
            attest_degraded_at(
                audit_log,
                &format!(
                    "file-open sensor rules partially written: {} refused, generation bump {}; \
                     first error: {first}",
                    applied.failed,
                    if applied.generation_failed {
                        "failed"
                    } else {
                        "done"
                    }
                ),
                at_boot,
            );
        }
        RuleHealthChange::Changed => warn!(
            failed = applied.failed,
            first_error = %first,
            "file-open sensor: rules still partially written"
        ),
        RuleHealthChange::Recovered => {
            info!("file-open sensor: every rule written again")
        }
        RuleHealthChange::Same => {}
    }
}

/// What [`boot_fim_paths`] read.
struct FimPaths {
    watched_paths_load: northnarrow_agent::fim::paths_config::WatchedPathsLoad,
    paths_summary: admin_socket::WatchedPathsSummary,
}

/// FIM's watched paths (the shipped list and the signed overlay); the
/// legacy isolation removed and the stale COMBAT chain, signed here, where
/// the start has always signed them.
fn boot_fim_paths(
    cli: &Cli,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    audit_log: &AuditHandle,
    legacy_isolation_removed: bool,
    stale_combat: &Option<northnarrow_agent::combat::reconcile::StaleChain>,
) -> FimPaths {
    // ── Tappa 9 C7 — FIM subsystem boot ────────────────────────────
    //
    // Order:
    //  1. Load the watched-paths set (v1 default + .local overlay
    //     merge per §13 Q7). A missing v1 just yields an empty
    //     effective set + WARN; the agent stays up so a misconfigured
    //     install is still operator-recoverable.
    //  2. Open the [`BaselineDb`] for the chained baseline log.
    //     Failure here is also tolerated: the recompute channel
    //     stays unwired so admin `fim baseline` returns
    //     `UnknownOperation` rather than crashing.
    //  3. Build the [`BaselineRecomputeChannel`] + spawn the
    //     long-lived recompute task.
    //  4. Fire `RecomputeReason::FirstBootTofu` (§13 Q5 trust-on-
    //     first-use) when the baseline DB is empty AND at least
    //     one path is configured. First-boot trust model is
    //     documented in `docs/operator/TAPPA9_FIM_TRUST_MODEL.md`.
    //  5. Build the [`FimAdminState`] for the admin socket so
    //     `fim baseline` triggers (3) and `fim status` reads the
    //     in-process snapshot.
    let watched_paths_load = match northnarrow_agent::fim::paths_config::load_watched_paths(
        &cli.fim_paths_v1,
        &overlay_gate.verified(OverlayKind::FimPaths, &cli.fim_paths_local),
    ) {
        Ok(load) => load,
        Err(e) => {
            warn!(
                error = %e,
                v1 = %cli.fim_paths_v1.display(),
                local = %cli.fim_paths_local.display(),
                "fim paths-config: load failed — proceeding with empty watched-paths set"
            );
            Default::default()
        }
    };
    report_builtin_defaults(
        overlay_gate,
        "fim-paths",
        &cli.fim_paths_v1,
        &watched_paths_load.defaults,
    );
    if legacy_isolation_removed {
        attest_legacy_isolation_removed(audit_log.as_ref());
    }
    if let Some(outcome) = &stale_combat {
        northnarrow_agent::combat::reconcile::attest(audit_log.as_ref(), outcome);
    }
    // Lab PR 218: the tracepoint offsets, the hook arguments, the
    // capabilities and the DNS sensor are signed at the audit log's open
    // (above); the JA3 gap and `nft` where they are found.
    // External audit FIMR-001: FIM watching nothing used to show only as
    // `effective=0` in an INFO line.
    if watched_paths_load.effective.is_empty() {
        error!(
            v1 = %cli.fim_paths_v1.display(),
            "fim paths-config: no path to watch — FIM and the anti-tamper baits see nothing"
        );
        attest_degraded(
            audit_log.as_ref(),
            &format!(
                "fim watches no path ({} yields none)",
                cli.fim_paths_v1.display()
            ),
        );
    }
    let paths_summary = admin_socket::WatchedPathsSummary::from_load(&watched_paths_load);
    FimPaths {
        watched_paths_load,
        paths_summary,
    }
}

/// FIM (Tappa 9 C7): the baseline database and its verified cache, the
/// observers attached and the file-open sensor armed on them, the late
/// programs registered, the security tools' processes, the watched inodes,
/// the recompute task, the drift log and its drain, the first-boot
/// baseline; then the filesystems' identity report and the control-surface
/// baits (Tappa 9.5.1).
#[allow(clippy::too_many_arguments)]
fn boot_fim(
    cli: &Cli,
    agent_id: [u8; 16],
    audit_log: &AuditHandle,
    sensor: &mut SensorMultiplexer,
    open_sensor_carveout: Vec<String>,
    posture: &PostureMachine,
    own_prog_ids_file: &Option<PathBuf>,
    watched_paths_load: northnarrow_agent::fim::paths_config::WatchedPathsLoad,
    defense_detector: &Arc<northnarrow_agent::impair::DefenseDetector>,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    rotation_protection: &std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager>,
    fim_drift_rotation: northnarrow_agent::chainlog::RotationConfig,
    lineage: &AuthSessionTracker,
    paths_summary: admin_socket::WatchedPathsSummary,
    state_protection: &Option<
        std::sync::Arc<northnarrow_agent::anti_tamper::filesystem::StateDirProtection>,
    >,
) -> Option<Arc<admin_socket::FimAdminState>> {
    let fim_admin_state: Option<Arc<admin_socket::FimAdminState>> = {
        // Re-derive the signing key + agent_id for FIM the same way
        // the audit log does (re-load rather than steal the audit
        // log's clone — they're separate domains with separate Db
        // handles). A failure here downgrades the FIM CLI surface
        // to "scheduled for next restart" + zero-snapshot status.
        let mut baseline_pubkey: Option<ed25519_dalek::VerifyingKey> = None;
        let baseline_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        ) {
            Ok(key) => {
                baseline_pubkey = Some(key.verifying_key());
                match northnarrow_agent::fim::baseline::BaselineDb::open(
                    &cli.fim_baseline_file,
                    key,
                    agent_id,
                ) {
                    Ok(mut db) => {
                        attest_open_findings(
                            audit_log.as_ref(),
                            &cli.fim_baseline_file,
                            db.take_open_findings(),
                        );
                        Some(Arc::new(parking_lot::Mutex::new(db)))
                    }
                    Err(e) => {
                        // External audit MAIN-003: the sensors, the drain and
                        // every FIM rule still run below; only re-baselining
                        // is off this boot.
                        error!(
                            error = %e,
                            path = %cli.fim_baseline_file.display(),
                            "fim baseline DB open failed — FIM still detects; \
                             `fim baseline` cannot record a new baseline this boot"
                        );
                        attest_degraded(
                            audit_log.as_ref(),
                            &format!("fim baseline database unavailable ({e:#}): re-baselining off this boot"),
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "fim baseline DB needs the agent signing key — load failed; \
                     FIM admin surface degraded"
                );
                None
            }
        };
        {
            {
                use northnarrow_agent::fim::attach::{
                    attach_observe_programs, populate_watched_paths, take_fs_fim_events_ringbuf,
                    take_watched_paths_map,
                };
                use northnarrow_agent::fim::baseline::BaselineCache;
                use northnarrow_agent::fim::drain::{
                    drain_loop, DriftClassifier, DriftRateLimiter, FimDriftDb, InodePathMap,
                };
                use northnarrow_agent::fim::recompute::{
                    run_recompute_task, BaselineRecomputeChannel, RecomputeReason,
                };

                let rate_limiter = Arc::new(DriftRateLimiter::new());

                // Polish #2: populate the per-path baseline cache
                // from the chained baseline log so the drain loop
                // can suppress no-op kernel events (touch -t,
                // permission-set-to-same-value, etc.) — the cache
                // miss path treats the event as a first observation
                // and emits drift normally.
                // External audit FIMP-001: only the verified suffix of the
                // chain may silence an event.
                let loaded = match baseline_pubkey.as_ref() {
                    Some(pk) => BaselineCache::load_verified(&cli.fim_baseline_file, pk),
                    None => Err(anyhow::anyhow!("no agent key to verify the baseline with")),
                };
                let baseline_cache = match loaded {
                    Ok((c, trust)) => {
                        info!(
                            entries = c.len(),
                            rows = trust.rows,
                            untrusted = trust.untrusted,
                            "fim: baseline cache loaded from the verified chain"
                        );
                        if trust.breaks > 0 {
                            error!(
                                breaks = trust.breaks,
                                untrusted = trust.untrusted,
                                path = %cli.fim_baseline_file.display(),
                                "fim: baseline rows that do not verify are kept out of the \
                                 cache — their paths report every change until a new baseline"
                            );
                            attest_degraded(
                                audit_log.as_ref(),
                                &format!(
                                    "{}: {} baseline row(s) behind {} chain break(s) not trusted",
                                    cli.fim_baseline_file.display(),
                                    trust.untrusted,
                                    trust.breaks
                                ),
                            );
                        }
                        Arc::new(c)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.fim_baseline_file.display(),
                            "fim baseline cache load failed — drain will emit drift \
                             for every kernel event (no-op suppression disabled)"
                        );
                        Arc::new(BaselineCache::new())
                    }
                };

                // C8: attach the 6 fim_*_observe LSM programs +
                // populate WATCHED_PATHS from the effective paths
                // set. populate_watched_paths returns the populated
                // InodePathMap so the drain loop can resolve
                // (dev,ino) → path. Per-step failures are logged
                // WARN inside the helpers — the agent still boots
                // (degrade-not-fail posture matches anti_tamper).
                let btf = match aya::Btf::from_sys_fs() {
                    Ok(b) => Some(b),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fim: BTF load failed — observe programs cannot attach this boot"
                        );
                        None
                    }
                };
                let mut fim_attached: Vec<&'static str> = Vec::new();
                if let Some(btf) = btf.as_ref() {
                    match attach_observe_programs(
                        sensor.ebpf_mut(),
                        btf,
                        cli.file_open_sensor == FileOpenSensor::Lsm,
                    ) {
                        Ok(a) => fim_attached = a,
                        Err(e) => warn!(
                            error = %e,
                            "fim: attach_observe_programs returned error — \
                             observe hooks may be partial"
                        ),
                    }
                }
                start_open_sensor(
                    sensor,
                    cli.file_open_sensor,
                    &fim_attached,
                    &open_sensor_carveout,
                    audit_log.clone(),
                    posture,
                );
                // External audit ATP-013: the FIM observers and the file-open
                // sensor were loaded after the BPF guard registered the
                // agent's objects: their programs and links join the set.
                match northnarrow_agent::anti_tamper::bpf_defense::register_late_objects(
                    sensor.ebpf_mut(),
                ) {
                    Ok(n) => debug!(
                        ids = n,
                        "BPF self-defence: late programs and links registered"
                    ),
                    Err(e) => error!(
                        error = format!("{e:#}"),
                        "BPF self-defence: the FIM and file-open programs NOT registered as the \
                         agent's own — the guard does not refuse handles to them"
                    ),
                }
                record_own_prog_ids(own_prog_ids_file.as_deref(), sensor.ebpf_mut());
                // Lab PR 225 (NN-L-EVA-004): the security tools' configuration
                // files, and those their listed directories hold now.
                let mut fim_watch_set = watched_paths_load.effective.clone();
                fim_watch_set.extend(defense_detector.tools().fim_paths());
                // Lab PR 225 (NN-L-EVA-003): the tools' running processes,
                // into the map `task_kill` reports their stop signals by.
                match sensor
                    .ebpf_mut()
                    .take_map("DEFENDER_PIDS")
                    .map(northnarrow_agent::impair::DefenderMap::try_from)
                {
                    Some(Ok(map)) => {
                        defense_detector.attach_map(map);
                        info!(
                            defenders = defense_detector.counts().defenders,
                            "security tools' processes registered for task_kill reports"
                        );
                        // A tool's exec registers its pid; a forking
                        // daemon's own process is registered by the
                        // `/proc` scans the exec asks for.
                        let rescanner = Arc::clone(defense_detector);
                        tokio::spawn(async move {
                            let mut tick = tokio::time::interval(
                                northnarrow_agent::impair::FORK_RESCAN_SPACING,
                            );
                            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            loop {
                                tick.tick().await;
                                if !rescanner.rescan_due(Instant::now()) {
                                    continue;
                                }
                                let r = Arc::clone(&rescanner);
                                let _ = tokio::task::spawn_blocking(move || {
                                    r.rescan_if_due(Instant::now())
                                })
                                .await;
                            }
                        });
                    }
                    Some(Err(e)) => warn!(
                        error = %e,
                        "DEFENDER_PIDS is not a HashMap<u32, u8> — signals to the security \
                         tools are seen only through kill/pkill/killall execs"
                    ),
                    None => warn!(
                        "DEFENDER_PIDS missing from the eBPF object — signals to the security \
                         tools are seen only through kill/pkill/killall execs"
                    ),
                }
                let inode_map = match populate_watched_paths(sensor.ebpf_mut(), &fim_watch_set) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fim: populate_watched_paths failed — drain loop will see \
                             zero (dev,ino) → path mappings; events will warn-and-skip"
                        );
                        Arc::new(InodePathMap::new())
                    }
                };
                northnarrow_agent::boot::manifest::note_sensor(
                    "fim_observers",
                    &format!(
                        "lsm: {} of {} observe programs",
                        fim_attached.len(),
                        northnarrow_agent::fim::attach::FIM_OBSERVE_PROGRAMS.len()
                    ),
                );
                // External audit FIMP-011: a FIM that attached no observer, or
                // watches nothing, sees no file change at all. Said in the
                // signed audit chain, not only in an INFO among the boot lines.
                if let Some(shortfall) = northnarrow_agent::fim::attach::coverage_shortfall(
                    fim_attached.len(),
                    northnarrow_agent::fim::attach::FIM_OBSERVE_PROGRAMS.len(),
                    inode_map.len(),
                    watched_paths_load.effective.len(),
                ) {
                    error!(target: "fim", "{shortfall}");
                    attest_degraded(audit_log.as_ref(), &shortfall);
                }

                // BUG-022 — take an OWNED writable handle to WATCHED_PATHS
                // (post-populate) so the drain loop can enroll children of
                // a watched directory on the fly. Best-effort: on failure
                // the drain still runs — create-detection via child-leaf
                // reconstruction still works; only the later in-place edit
                // of a freshly-dropped child would go unwatched.
                let watched_paths_handle = match take_watched_paths_map(sensor.ebpf_mut()) {
                    Ok(h) => Some(Arc::new(parking_lot::Mutex::new(h))),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fim: take_watched_paths_map failed — runtime child \
                             enrollment disabled this boot"
                        );
                        None
                    }
                };

                // The recompute task snapshots the merged watched-
                // paths set every iteration — operators who edit
                // fim-paths.local and run `nn-admin fim baseline`
                // pick up the new set without an agent restart.
                let mut recompute_chan = BaselineRecomputeChannel::new();
                let sender = recompute_chan.sender();
                let receiver = recompute_chan
                    .take_receiver()
                    .expect("freshly-constructed channel has a receiver");
                let v1_for_snapshot = cli.fim_paths_v1.clone();
                let local_for_snapshot = cli.fim_paths_local.clone();
                let gate_for_snapshot = Arc::clone(overlay_gate);
                if let Some(baseline_db) = baseline_db_opt.as_ref() {
                    tokio::spawn(run_recompute_task(
                        receiver,
                        Arc::clone(baseline_db),
                        Arc::clone(&baseline_cache),
                        Arc::clone(&inode_map),
                        watched_paths_handle.clone(),
                        move || {
                            // A signed `fim baseline` re-reads the overlay:
                            // the same signature check as at boot, and the
                            // bytes it verified are the ones applied.
                            let load = northnarrow_agent::fim::paths_config::load_watched_paths(
                                &v1_for_snapshot,
                                &gate_for_snapshot
                                    .verified(OverlayKind::FimPaths, &local_for_snapshot),
                            )
                            .unwrap_or_default();
                            report_builtin_defaults(
                                &gate_for_snapshot,
                                "fim-paths",
                                &v1_for_snapshot,
                                &load.defaults,
                            );
                            load.effective
                        },
                    ));
                } else {
                    // No database to write a baseline into: requests are
                    // refused (logged), detection is not affected.
                    drop(receiver);
                }

                // C8: open the chained drift log + spawn the drain
                // task. The drain takes ownership of the FS_FIM_EVENTS
                // ringbuf (taken out of the Ebpf object); subsequent
                // map_mut("FS_FIM_EVENTS") calls would return None,
                // which is fine because no other code references the
                // map name.
                let drift_db_for_drain =
                    match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
                        &cli.signing_key_file,
                    )
                    .and_then(|key| {
                        FimDriftDb::open(
                            &cli.fim_drift_file,
                            key,
                            agent_id,
                            std::sync::Arc::clone(rotation_protection),
                            fim_drift_rotation,
                        )
                    }) {
                        Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
                        Err(e) => {
                            warn!(
                                error = %e,
                                path = %cli.fim_drift_file.display(),
                                "fim drift DB open failed — drain loop will not spawn; \
                                 kernel drift events will be dropped this boot"
                            );
                            None
                        }
                    };

                if let Some(drift_db) = drift_db_for_drain {
                    match take_fs_fim_events_ringbuf(sensor.ebpf_mut()) {
                        Ok(rb) => {
                            let classifier = Arc::new(DriftClassifier::new());
                            let rate_limiter_clone = Arc::clone(&rate_limiter);
                            let inode_map_for_drain = Arc::clone(&inode_map);
                            let baseline_cache_for_drain = Arc::clone(&baseline_cache);
                            let watched_paths_for_drain = watched_paths_handle.clone();
                            // Review 76: only package-manager drift is paced.
                            let lineage_for_drain = lineage.clone();
                            let event_tx = sensor.event_tx();
                            let audit_for_drain = audit_log.clone();
                            let handle = tokio::spawn(async move {
                                let outcome = drain_loop(
                                    rb,
                                    inode_map_for_drain,
                                    baseline_cache_for_drain,
                                    drift_db,
                                    classifier,
                                    rate_limiter_clone,
                                    watched_paths_for_drain,
                                    lineage_for_drain,
                                    event_tx,
                                )
                                .await;
                                drain_ended("fim", outcome, audit_for_drain.as_ref());
                            });
                            sensor.register_pump_handle("fim_drain", handle);
                            info!("fim: drain loop spawned");
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "fim: take_fs_fim_events_ringbuf failed — drain loop \
                                 not spawned; kernel drift events will be dropped"
                            );
                        }
                    }
                }

                // §13 Q5 TOFU: empty baseline file + non-empty paths
                // set = first boot, fire a recompute. The recompute
                // task is already running (tokio::spawn doesn't
                // block on the future's first poll).
                if baseline_db_opt.as_ref().is_some_and(|db| {
                    db.lock().last_hash() == northnarrow_agent::audit::GENESIS_PREV_HASH
                }) && !watched_paths_load.effective.is_empty()
                {
                    info!(
                        paths = watched_paths_load.effective.len(),
                        "fim: first-boot TOFU baseline triggered (§13 Q5)"
                    );
                    sender.trigger(RecomputeReason::FirstBootTofu);
                }

                Some(Arc::new(admin_socket::FimAdminState {
                    recompute_sender: sender,
                    rate_limiter,
                    paths_summary,
                    baseline_log_path: cli.fim_baseline_file.clone(),
                    drift_log_path: cli.fim_drift_file.clone(),
                    // External audit DEC-001: shared with the canaries.
                    watch: northnarrow_agent::fim::attach::FimWatch {
                        path_map: Arc::clone(&inode_map),
                        watched_paths: watched_paths_handle.clone(),
                    },
                }))
            }
        }
    };

    // External audit EBPF-016 (NN-AUD-267): protected inodes and FIM
    // watches on overlayfs, FUSE or NFS, where the agent cannot vouch that
    // stat() and the eBPF hooks see the same (dev, ino) — one WARN and one
    // signed `subsystem_degraded` per boot (registrations and the watch set
    // are all in by now).
    if let Some(report) = northnarrow_agent::fs_type::take_identity_report() {
        warn!("{}", report.detail());
        attest_identity_unverified(audit_log.as_ref(), &report);
    }

    // ── Tappa 9.5.1 — anti-tamper honeypot integrity sweep ─────────
    //
    // After the FIM observe programs are attached (above) and the agent
    // is in PROTECTED_PIDS, verify the NN-L-FIM-024 bait files exist and
    // recreate any missing one from its embedded template. The recreate
    // is an agent write → PROTECTED_PIDS-exempt, so it cannot
    // self-trigger NN-L-FIM-024. A missing bait at boot is itself a
    // tamper signal (Medium); all-present logs at Info.
    let report = northnarrow_agent::fim::honeypot::check_and_restore();
    // External audit FIMR-008: a bait re-created here was absent when the
    // watch set was built above, and nothing enrolled it afterwards — after
    // every reboot the tmpfs pair under /run went unwatched until the next
    // agent restart. Watched now.
    if let Some(fim) = fim_admin_state.as_ref() {
        for path in &report.recreated {
            let watched = northnarrow_agent::fim::attach::key_for_path(std::path::Path::new(path))
                .map(|key| {
                    fim.watch.watch(
                        key,
                        path,
                        northnarrow_agent::fim::drain::WatchClass::Configured,
                    )
                });
            if !matches!(watched, Ok(true)) {
                warn!(
                    target: "fim.honeypot",
                    path = %path,
                    "re-created control-surface file could not be watched"
                );
            }
        }
    }
    let rebooted = {
        use northnarrow_agent::fim::honeypot;
        let state_dir = std::path::Path::new(northnarrow_agent::anti_tamper::filesystem::STATE_DIR);
        match honeypot::current_boot_id() {
            Some(now) => {
                let changed = honeypot::boot_changed(state_dir, &now);
                if changed {
                    record_boot_id(state_protection.as_deref(), state_dir, &now);
                }
                changed
            }
            None => true,
        }
    };
    if report.all_present() {
        info!(
            present = report.present,
            total = report.total,
            "Honeypot integrity: {}/{} present",
            report.present,
            report.total
        );
    } else if report.only_volatile_after_reboot(rebooted) {
        // The tmpfs pair is gone after every reboot: expected, not a tamper.
        info!(
            present = report.present,
            total = report.total,
            recreated = ?report.recreated,
            "Honeypot integrity: {}/{} present; the runtime pair re-created after a reboot",
            report.present,
            report.total
        );
    } else {
        warn!(
            target: "fim.honeypot",
            rule = "NN-L-FIM-024-INTEGRITY",
            severity = "Medium",
            present = report.present,
            recreated = report.recreated.len(),
            failed = report.failed.len(),
            replaced = report.replaced.len(),
            "Honeypot integrity: {} present, recreated {:?}, not a file {:?}, unrestorable {:?}",
            report.present,
            report.recreated,
            report.replaced,
            report.failed
        );
        // FIMR-008: in the signed audit chain, not only in the journal.
        attest_bait_integrity(audit_log.as_ref(), &report, rebooted);
    }
    fim_admin_state
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
