//! File integrity monitoring at boot (R11a, lab PR 261: from `main.rs`):
//! the watched paths, the observers, the file-open sensor armed on them,
//! the drain, the baseline, the filesystems' identity, the control-surface
//! baits.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_proto::admin_signed_payload::OverlayKind;
use northnarrow_agent::admin_socket;
use northnarrow_agent::posture::{AuthSessionTracker, PostureMachine};
use northnarrow_agent::sensors::SensorMultiplexer;
use tracing::{debug, error, info, warn};

use super::attach::record_own_prog_ids;
use super::cli::{Cli, FileOpenSensor};
use super::evidence::{
    attest_degraded, attest_degraded_at, attest_open_findings, drain_ended, AuditHandle,
};
use super::policy::report_builtin_defaults;
use super::response::attest_legacy_isolation_removed;

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

/// What [`paths`] read.
pub(crate) struct FimPaths {
    pub(crate) watched_paths_load: northnarrow_agent::fim::paths_config::WatchedPathsLoad,
    pub(crate) paths_summary: admin_socket::WatchedPathsSummary,
}

/// FIM's watched paths (the shipped list and the signed overlay); the
/// legacy isolation removed and the stale COMBAT chain, signed here, where
/// the start has always signed them.
pub(crate) fn paths(
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
pub(crate) fn start(
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
