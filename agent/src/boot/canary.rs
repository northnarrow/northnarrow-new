
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
