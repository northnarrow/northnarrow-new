
/// What [`boot_canary`] opened.
struct Canary {
    canary_admin_state: Option<Arc<admin_socket::CanaryAdminState>>,
    canary_detector: Option<Arc<northnarrow_agent::canary::detector::Detector>>,
}

/// The canaries (Tappa 9.5 K6): the signed registry and access log, the
/// indexes rebuilt, every decoy checked against what was deployed and
/// watched again, the detector and the admin state.
fn boot_canary(
    cli: &Cli,
    agent_id: [u8; 16],
    audit_log: &AuditHandle,
    fim_admin_state: &Option<Arc<admin_socket::FimAdminState>>,
) -> Canary {
    // ── Tappa 9.5 K6 — canary subsystem boot ───────────────────────
    //
    // Order (mirrors the FIM boot above):
    //  1. Open the [`Registry`] for the chained canary log. Failure
    //     leaves `canary_admin_state` + `canary_detector` as `None`;
    //     the agent stays up, admin `canary` ops return
    //     `UnknownOperation`, and the rule engine sees zero
    //     `Event::CanaryTripped` events.
    //  2. Open the [`CanaryAccessDb`] for the chained access log.
    //     Same degraded-mode policy as the registry.
    //  3. Build empty [`CanaryIndexes`] and call
    //     `rebuild_from_registry` so the K3 detector sees any
    //     canaries deployed in a prior boot.
    //  4. Layer File + Credential paths into `exe_index` via
    //     `add_file_path_index` (the K3 path-based fallback for
    //     FimEvent that doesn't carry (dev, ino) yet — same
    //     pragmatism the K6 dispatch helper uses post-deploy).
    //  5. Construct the [`Detector`] holding all three shared
    //     `Arc<Mutex<_>>` handles + the [`CanaryAdminState`] for
    //     the admin socket.
    let (canary_admin_state, canary_detector): (
        Option<Arc<admin_socket::CanaryAdminState>>,
        Option<Arc<northnarrow_agent::canary::detector::Detector>>,
    ) = {
        let signing_key_for_canary =
            match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
                &cli.signing_key_file,
            ) {
                Ok(key) => Some(key),
                Err(e) => {
                    warn!(
                        error = %e,
                        "canary subsystem needs agent signing key — load failed; \
                         canary admin surface disabled this boot"
                    );
                    None
                }
            };
        let signing_key_for_access =
            northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
                .ok();
        match (signing_key_for_canary, signing_key_for_access) {
            (Some(reg_key), Some(access_key)) => {
                let registry = match northnarrow_agent::canary::registry::Registry::open(
                    &cli.canary_registry_file,
                    reg_key,
                    agent_id,
                ) {
                    Ok(mut r) => {
                        attest_open_findings(
                            audit_log.as_ref(),
                            &cli.canary_registry_file,
                            r.take_open_findings(),
                        );
                        attest_chain_findings(audit_log.as_ref(), r.take_chain_findings());
                        Some(Arc::new(parking_lot::Mutex::new(r)))
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.canary_registry_file.display(),
                            "canary registry open failed — admin `canary` ops will \
                             return UnknownOperation; rule engine sees no \
                             CanaryTripped events"
                        );
                        None
                    }
                };
                let access_log = match northnarrow_agent::canary::access_log::CanaryAccessDb::open(
                    &cli.canary_access_file,
                    access_key,
                    agent_id,
                ) {
                    Ok(mut a) => {
                        attest_open_findings(
                            audit_log.as_ref(),
                            &cli.canary_access_file,
                            a.take_open_findings(),
                        );
                        attest_chain_findings(audit_log.as_ref(), a.take_chain_findings());
                        Some(Arc::new(parking_lot::Mutex::new(a)))
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.canary_access_file.display(),
                            "canary access log open failed — detector trips will \
                             not be persisted this boot"
                        );
                        None
                    }
                };
                match (registry, access_log) {
                    (Some(registry), Some(access_log)) => {
                        // Lab PR 260: a trip the access log holds and the
                        // registry does not record (the agent stopped
                        // between the access row and the `Trip` row, or
                        // that row could not be written) is recorded before
                        // the detector runs — an ERROR, a signed
                        // `canary_trip_recovered`, then the `Trip` row: the
                        // canary stays tripped (before lab PR 260 the start
                        // re-armed it).
                        record_unrecorded_trips(
                            &mut registry.lock(),
                            &cli.canary_access_file,
                            audit_log.as_ref(),
                        );
                        let indexes = Arc::new(parking_lot::Mutex::new(
                            northnarrow_agent::canary::detector::CanaryIndexes::new(),
                        ));
                        // Rebuild indexes from any pre-existing
                        // registry entries. V1.0 inode resolver
                        // returns None — the K3 detector's
                        // path-based exe_index fallback covers
                        // File + Credential (added below); Process
                        // canaries are exe-path keyed (handled by
                        // rebuild_from_registry directly).
                        let fim_watch = fim_admin_state.as_ref().map(|f| f.watch.clone());
                        {
                            use northnarrow_agent::canary::registry::{check_decoy, DecoyState};
                            let mut reg = registry.lock();
                            let mut idx = indexes.lock();
                            // External audit DEC-003: inodes resolved at
                            // boot too — they feed read-forward.
                            idx.rebuild_live(&reg);
                            // External audit DEC-001: the FIM boot keeps only
                            // the watches it registers, so the decoys are
                            // watched again here, every boot. External audit
                            // DEC-010: each decoy is first compared with what
                            // its row says was written. One modified, removed
                            // or replaced while the agent was down used to be
                            // adopted in silence: it is an ERROR, and when its
                            // state changed a DecoyCheck row (shown by `canary
                            // list`) and a signed `integrity_drift`. Only a
                            // regular file is watched.
                            let mut unverified = 0usize;
                            for canary in reg.list() {
                                let Some(path) = admin_socket::canary_path(&canary.deployment)
                                else {
                                    continue;
                                };
                                let expected =
                                    canary.content.as_ref().map(|c| c.contents_sha256.as_str());
                                unverified += usize::from(expected.is_none());
                                let check = check_decoy(std::path::Path::new(path), expected);
                                if check.state != DecoyState::Intact {
                                    error!(
                                        canary_id = %canary.canary_id,
                                        name = %nn_model::log_escape::Escaped(&canary.name),
                                        path,
                                        state = check.state.as_str(),
                                        "canary: the decoy is not what was deployed — changed, \
                                         removed or replaced while the agent was not watching it; \
                                         `nn-admin canary refresh` writes it again"
                                    );
                                }
                                match reg.record_decoy_state(&canary.canary_id, check.state) {
                                    Ok(true) => attest_decoy_state(
                                        audit_log.as_ref(),
                                        &canary,
                                        path,
                                        &check,
                                    ),
                                    Ok(false) => {}
                                    Err(e) => {
                                        warn!(
                                            error = %format!("{e:#}"),
                                            path,
                                            "canary: recording the decoy state failed"
                                        );
                                        attest_decoy_state(
                                            audit_log.as_ref(),
                                            &canary,
                                            path,
                                            &check,
                                        );
                                    }
                                }
                                match (check.key, &fim_watch) {
                                    (Some(key), Some(watch)) => {
                                        // External audit NN-AUD-120: a decoy is
                                        // never evicted; a refusal is attested.
                                        if !watch.watch(
                                            key,
                                            path,
                                            northnarrow_agent::fim::drain::WatchClass::Decoy,
                                        ) {
                                            error!(
                                                path,
                                                "canary: the kernel watch map refused the decoy \
                                                 — its opens are not seen"
                                            );
                                        }
                                    }
                                    (Some(_), None) => warn!(
                                        path,
                                        "canary: FIM is not running — decoy opens unseen"
                                    ),
                                    // nothing to watch: reported above
                                    (None, _) => {}
                                }
                            }
                            if unverified > 0 {
                                warn!(
                                    decoys = unverified,
                                    "canary: decoys deployed before their content was recorded — \
                                     only their presence is checked; `nn-admin canary refresh` \
                                     writes them again and records it"
                                );
                            }
                            let read_forward = northnarrow_agent::canary::read_forward::len();
                            info!(
                                canaries = idx.len(),
                                read_forward, "canary indexes rebuilt from registry"
                            );
                        }
                        let detector =
                            Arc::new(northnarrow_agent::canary::detector::Detector::new(
                                registry.clone(),
                                access_log,
                                indexes.clone(),
                            ));
                        let admin_state = Arc::new(admin_socket::CanaryAdminState {
                            fim_watch,
                            registry,
                            indexes,
                            registry_log_path: cli.canary_registry_file.clone(),
                            template_dir: Some(cli.canary_template_dir.clone()),
                        });
                        (Some(admin_state), Some(detector))
                    }
                    _ => (None, None),
                }
            }
            _ => (None, None),
        }
    };
    Canary {
        canary_admin_state,
        canary_detector,
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
