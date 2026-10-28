
/// What [`boot_posture`] built.
struct Posture {
    /// The COMBAT ladder's slot the posture's hooks read, set by
    /// [`boot_ladder`].
    ladder_slot: Arc<std::sync::OnceLock<Arc<northnarrow_agent::combat::CombatLadder>>>,
    exempt: ExemptPids,
    /// The operator's mass-write carve-outs, for the file-open sensor.
    open_sensor_carveout: Vec<String>,
    posture: PostureMachine,
    /// The audit log the watchdog refresh signs to, set by [`boot_wire`].
    watchdog_audit: Arc<std::sync::OnceLock<WatchdogAudit>>,
    /// A stale COMBAT chain found at boot, signed once the state directory
    /// is protected.
    stale_combat: Option<northnarrow_agent::combat::reconcile::StaleChain>,
}

/// The posture: the COMBAT hooks on the ladder's slot, the stack's
/// exemption, the posture machine (with the release through the isolator,
/// or without one), its window, tracker and detector; the watchdog's and
/// systemd-shutdown's refreshes; a stale COMBAT chain torn down.
fn boot_posture(
    cli: &Cli,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    lineage: &AuthSessionTracker,
    isolator: &Option<Arc<NetworkIsolator>>,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    ransom_tracker: &Arc<northnarrow_agent::impact::RansomTracker>,
    defense_detector: &Arc<northnarrow_agent::impair::DefenseDetector>,
) -> Posture {
    // The COMBAT graduated-response ladder is constructed once agent_id
    // + the audit log are available (further down). The posture combat
    // hooks reference it through this slot, so an admin-forced COMBAT
    // engages the same ladder as a detector-driven one. The slot is set
    // before the event loop / admin socket start — always populated by
    // the time any COMBAT transition can fire the hooks.
    let ladder_slot: Arc<std::sync::OnceLock<Arc<northnarrow_agent::combat::CombatLadder>>> =
        Arc::new(std::sync::OnceLock::new());

    // Reaching COMBAT now means "enter active-response mode", NOT
    // "isolate". This entry hook engages the graduated ladder at STAGE 1
    // INVESTIGATE (network stays UP); the ladder decides if/when isolation
    // (STAGE 3, last resort) is warranted, honours detect-only internally,
    // and emits the per-stage signed audit trail. It is wired into BOTH
    // the prod (isolator) and dev (no-isolator) posture branches so an
    // admin-forced COMBAT engages the same ladder either way. Lab PR 245:
    // the posture hands it the entry — the firing trigger with the evidence
    // it cites (or the forced COMBAT's signers) and the process the event
    // names — so the episode opens with its cause and its offender. It
    // used to open the episode with neither (`engage(None, None)`) before
    // `process_event` named them, and the trigger was lost.
    let engage_hook: CombatEntryHook = {
        let ladder_for_entry = Arc::clone(&ladder_slot);
        Arc::new(move |entry: &northnarrow_agent::posture::CombatEntry| {
            if let Some(ladder) = ladder_for_entry.get() {
                ladder.engage(entry, Instant::now());
            }
        })
    };

    let exempt = ExemptPids::with_agent(std::process::id());
    // Tappa 10.9 step 1: the file-open sensor applies the operator's
    // mass-write carve-outs in the kernel (same signed overlay, read and
    // verified once for both — external audit LLMR-013).
    let mass_write_overlay = overlay_gate.verified(
        OverlayKind::MassWriteCarveout,
        std::path::Path::new(
            northnarrow_agent::posture::mass_write_overlay::DEFAULT_MASS_WRITE_OVERLAY,
        ),
    );
    let open_sensor_carveout =
        northnarrow_agent::posture::mass_write_overlay::load_mass_write_carveout_extras(
            &mass_write_overlay,
        );
    let posture = if let Some(iso) = isolator.as_ref() {
        // T7.13 (Beta Step 5): the auth-lineage tracker shared with
        // the posture trigger detector. Reads /proc on cache miss;
        // populated live from Event::ProcessSpawn inside
        // TriggerDetector::detect. The dev (no-iptables) branch uses
        // PostureMachine::new() which already constructs a default
        // tracker internally, so this clone is only needed here.
        let auth_tracker = lineage.clone();
        let iso_release = Arc::clone(iso);
        let ladder_for_release = Arc::clone(&ladder_slot);
        let release_hook: CombatReleaseHook = Arc::new(
            move |token: UnlockToken, scope: ReleaseScope| -> ReleaseResult {
                // Admin released COMBAT: stand the ladder down (clears the
                // episode + lifts the surgical per-PID soft-egress blocks),
                // THEN tear down any full isolation STAGE 3 had engaged.
                // External audit CMB-012: after every step queued before the
                // stand-down has run, so an ISOLATE taken just before the
                // unlock cannot land after the release. Outside COMBAT no
                // ladder episode is touched, and the teardown is still run
                // and read back: no isolation is legitimate there (the
                // ladder isolates only in a locked COMBAT, which never
                // decays), and a stale chain the boot teardown could not
                // remove is lifted — the answer is the tables, not a flag.
                if scope == ReleaseScope::Combat {
                    if let Some(ladder) = ladder_for_release.get() {
                        ladder.stand_down_and_wait(Instant::now(), LADDER_RELEASE_WAIT);
                    }
                }
                // Lab PR 217 (NN-AUD-243 residue): the outcome is the tables
                // read back, and it goes back to the operator — a failed
                // teardown keeps the posture in COMBAT and answers a failure.
                let report = iso_release.release(token);
                if report.complete() {
                    Ok(report.summary("cleared (read back)"))
                } else {
                    tracing::error!(
                        outcome = %report.summary("cleared (read back)"),
                        "admin release: the COMBAT isolation is NOT released — the posture stays \
                         COMBAT; retry the signed unlock, or remove the chain by hand (see \
                         docs/operator) and unlock"
                    );
                    Err(report.summary("cleared (read back)"))
                }
            },
        );
        // Exempt the NorthNarrow stack's own PIDs from posture
        // triggers. The agent's own PID is fixed here; the watchdog's
        // verified PID is filled in by the refresh task spawned below.
        // Without this, the agent's FIM drift logging self-trips the
        // mass-write heuristic into COMBAT at boot, and the watchdog's
        // startup /proc scan trips it too (2026-05-22 sshd-reset
        // diagnosis).
        //
        // T7.13 — also pass the auth-lineage tracker so sudo-mediated
        // PIDs are exempt from sensitive_file_access and the
        // mass-write arm of confirmed_intrusion. Every other
        // COMBAT-tier trigger fires unchanged.
        //
        // BUG-017 P-8 — load the operator-supplemental mass-write
        // path-prefix carve-out from
        // /etc/northnarrow/mass-write-carveout.local. Missing file =
        // empty list (no extra exemptions; hardcoded
        // MASS_WRITE_CARVEOUT_PREFIXES still applies). The list is
        // path-prefix-based (e.g. "/home/<user>/.claude/" for dev
        // tooling), additive on top of the hardcoded kernel-RPC
        // pseudo-FS prefixes. See SECURITY note in
        // mass_write_overlay.rs — DO NOT add /home, /var, /tmp
        // wholesale (external audit POS-010: the loader refuses them).
        // Parsed once, above, for the sensor and the posture together:
        // its WARNs (refused entries, the accepted list) are said once.
        let mass_write_extras = open_sensor_carveout.clone();
        // BUG-032 — escalation allowlist (count-filter for exfil/lateral).
        // Missing file = empty (fail-secure). Loaded once at boot;
        // reload-on-restart for beta.
        let escalation_allow =
            northnarrow_agent::posture::escalation_allow::EscalationAllowList::load(
                &overlay_gate.verified(
                    OverlayKind::EscalationAllow,
                    std::path::Path::new(
                        northnarrow_agent::posture::escalation_allow::DEFAULT_ESCALATION_ALLOW,
                    ),
                ),
            );
        if !escalation_allow.is_empty() {
            info!(
                entries = escalation_allow.len(),
                "escalation allowlist loaded — count-filter for exfil/lateral (BUG-032)"
            );
        }
        PostureMachine::new_with_hooks_and_exempt_and_auth_and_extras(
            engage_hook,
            release_hook,
            exempt.clone(),
            auth_tracker,
            mass_write_extras,
            escalation_allow,
        )
        // Lab PR 249: the ransomware directive of the per-rule policy put
        // in force above, read from the engine's handle (it was a
        // process-wide switch set by `install_global`).
        .with_rule_policy(northnarrow_agent::decision::rule_policy::global().clone())
    } else {
        // Dev / no-isolator build: still wire the ladder hooks so a
        // (detector- or admin-forced) COMBAT engages the same graduated
        // ladder as production. The ladder's actuator finds no isolator,
        // so STAGE 3 degrades to a loud warning instead of an iptables
        // DROP — but INVESTIGATE + NEUTRALIZE still run.
        let ladder_for_release = Arc::clone(&ladder_slot);
        let release_hook: CombatReleaseHook = Arc::new(
            move |token: UnlockToken, scope: ReleaseScope| -> ReleaseResult {
                if scope == ReleaseScope::Combat {
                    if let Some(ladder) = ladder_for_release.get() {
                        ladder.stand_down(Instant::now());
                    }
                }
                // No isolator to release in this build; consume the token.
                let _ = token;
                Ok("no network isolator in this build: nothing to release".to_string())
            },
        );
        // Same defaults as `new_with_hooks`, but on the shared lineage
        // cache so the FIM package-manager carve-out is fed here too.
        PostureMachine::new_with_hooks_and_exempt_and_auth(
            engage_hook,
            release_hook,
            ExemptPids::default(),
            lineage.clone(),
        )
        .with_rule_policy(northnarrow_agent::decision::rule_policy::global().clone())
    };
    // Lab PR 162: inside the trusted-installer window a control-surface
    // tamper (NN-L-FIM-024) does not raise the posture; the rule still acts.
    posture.set_installer_window(Arc::clone(installer_override));
    // Lab PR 225: the ransomware combination (RansomwareEncryption, never
    // locked; COMBAT without corroboration held behind the per-rule policy,
    // off by default) and the security tools switched off
    // (DefenseImpairment, ENGAGED), judged as the rules judge them.
    posture.set_ransom_tracker(Arc::clone(ransom_tracker));
    posture.set_defense_detector(Arc::clone(defense_detector));
    // Lab PR 225 (decision of 21/10): inside a valid signed trusted-installer
    // window a stop or restart of the agent's own units is sanctioned (Low,
    // the window named; no posture move).
    defense_detector.set_installer_window(Arc::clone(installer_override));
    // Lab PR 225: their counters in `status --key`.
    northnarrow_agent::impact::publish(ransom_tracker);
    northnarrow_agent::impair::publish(defense_detector);
    info!("posture state machine initialized (state: OBSERVING)");

    // Beta Step 3: keep the watchdog PID exemption fresh. The watchdog
    // starts *after* the agent and may be restarted (systemd
    // Restart=on-failure), so we re-resolve its PID from the pidfile
    // and re-verify /proc/<pid>/exe every 30 s. Verification failure
    // (PID reuse, substituted binary, dead PID) clears the exemption —
    // fail toward over-triggering, never under-triggering. Only wired
    // when the posture machine actually carries the exemption (the
    // dev-mode `PostureMachine::new()` branch has none).
    // Lab PR 216: the signed log the refresh reports a vanished watchdog
    // to, set once it is open (below).
    let watchdog_audit: Arc<std::sync::OnceLock<WatchdogAudit>> =
        Arc::new(std::sync::OnceLock::new());
    if isolator.is_some() {
        spawn_watchdog_exempt_refresh(
            exempt.clone(),
            cli.watchdog_pidfile.clone(),
            cli.resolved_watchdog_exe(),
            Arc::clone(&watchdog_audit),
        );
    }
    // External audit EBPF-001: PID 1 may signal the agent at the very end
    // of a shutdown only while it runs the `systemd-shutdown` the hook
    // knows; follow a systemd upgrade that replaces it.
    spawn_shutdown_exe_refresh();

    // Beta Step 4a: reconcile a stale COMBAT chain left by a crash.
    // The agent always boots into OBSERVING, so if the
    // NORTHNARROW_COMBAT chain is already present the previous run died
    // mid-COMBAT and the orphaned iptables chain is now isolating the
    // host with no live posture state behind it (the B3 split-brain).
    // Tear it down and audit it. If an attack is still under way the
    // posture machine will re-engage COMBAT within seconds; an operator
    // can also force it via the admin socket.
    // External audit MAIN-013 (lab PR 180): the outcome is signed once the
    // audit log is open (below); the unsigned jsonl line stays.
    let mut stale_combat: Option<northnarrow_agent::combat::reconcile::StaleChain> = None;
    if let Some(iso) = isolator.as_ref() {
        if posture.current_kind() == PostureKind::Observing {
            match iso.reconcile_stale_chain() {
                Ok(outcome) if outcome.chain_existed => {
                    warn!(
                        rules_removed = outcome.rules_removed,
                        "stale COMBAT chain detected at boot — torn down (likely crash-orphaned). \
                         Re-engage via the admin socket if the threat is still active."
                    );
                    // Lab follow-up (lab PR 188): the jsonl line is written
                    // once the state directory protection exists (below).
                    stale_combat =
                        Some(northnarrow_agent::combat::reconcile::StaleChain::TornDown {
                            rules_removed: outcome.rules_removed,
                        });
                }
                Ok(_) => debug!("no stale COMBAT chain at boot (clean)"),
                Err(e) => {
                    warn!(error = %e, "stale COMBAT chain reconcile failed; manual iptables cleanup may be needed");
                    // Without a trusted iptables there is nothing to probe
                    // with (the ERROR above names it): not a failed teardown.
                    if iso.binaries().is_ok() {
                        stale_combat =
                            Some(northnarrow_agent::combat::reconcile::StaleChain::Failed {
                                error: format!("{e:#}"),
                            });
                    }
                }
            }
        }
    }
    Posture {
        ladder_slot,
        exempt,
        open_sensor_carveout,
        posture,
        watchdog_audit,
        stale_combat,
    }
}

/// What [`boot_ladder`] armed.
struct Combat {
    ladder: Arc<northnarrow_agent::combat::CombatLadder>,
    /// Lab PR 181: the guard the `debug-protected-query` trigger asks.
    #[cfg(feature = "debug-trigger")]
    debug_guard: northnarrow_agent::combat::SystemProtectedProcs,
    /// Tappa 8 A8: fired by a verified admin `ShutdownRequest`.
    shutdown_signal: ShutdownSignal,
}

/// The COMBAT ladder on the system actuator and the signed evidence,
/// published to the posture hooks' slot; the executor's tree guard; the
/// copy-on-first-write guard; the ladder's tick and the watch on systemd
/// stopping the host; the admin shutdown signal.
#[allow(clippy::too_many_arguments)]
fn boot_ladder(
    cli: &Cli,
    executor: &Executor,
    isolator: &Option<Arc<NetworkIsolator>>,
    detect_only: bool,
    audit_log: &AuditHandle,
    exempt: &ExemptPids,
    posture: &PostureMachine,
    ladder_slot: &std::sync::OnceLock<Arc<northnarrow_agent::combat::CombatLadder>>,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    lineage: &AuthSessionTracker,
) -> Combat {
    // Build the ladder with the system actuator (real kill / quarantine /
    // per-PID egress / full isolation) + the signed-audit evidence sink,
    // then publish it to the slot the posture combat hooks read. Driven
    // from three places: the combat-entry hook (above: the episode opens
    // with the posture's cause and offender, lab PR 245), `process_event`
    // (per-event jump-ahead), and the tick below.
    let ladder = Arc::new(
        northnarrow_agent::combat::CombatLadder::new(
            Box::new(northnarrow_agent::combat::SystemActuator::new(
                executor.clone(),
                isolator.clone(),
                detect_only,
            )),
            Box::new(northnarrow_agent::combat::AuditEvidence::new(
                audit_log.clone(),
            )),
            // Never kill / net-cut PID 1, the agent, its watchdog, or sshd —
            // skip + escalate to ISOLATE instead. Reuses the same `exempt`
            // handle the posture machine holds (so the watchdog PID stays the
            // timer-refreshed value) plus the same `--watchdog-exe` the refresh
            // task verifies against, so the watchdog branch can re-check
            // /proc/<pid>/exe inline at the kill/spare decision.
            Box::new(northnarrow_agent::combat::SystemProtectedProcs::new(
                executor.own_pid(),
                exempt.clone(),
                cli.resolved_watchdog_exe(),
            )),
            northnarrow_agent::combat::LadderConfig::default(),
        )
        // External audit POS-001 (NN-AUD-002): ISOLATE only in a locked COMBAT
        // (non-heuristic evidence, or forced by an administrator).
        .with_isolation_gate({
            let posture = posture.clone();
            move || posture.is_combat_locked()
        })
        // Lab PR 222: a NEUTRALIZE that contained a ransomware tree lets the
        // copy-on-first-write guard restore what it rewrote (a no-op
        // without the guard, or without copies of that tree's writes).
        .with_neutralize_hook(Box::new(|refs| {
            northnarrow_agent::cow::on_ladder_neutralized(
                refs.iter()
                    .map(|r| northnarrow_agent::cow::trust::ProcId {
                        pid: r.pid(),
                        start: r.start_ticks().unwrap_or(0),
                    })
                    .collect(),
            )
        }))
        // External audit CMB-007: the ladder's side effects (nft, cgroup
        // writes, kills, quarantine, iptables, audit) run on a worker of
        // their own, in order — never on the event loop.
        .with_worker(),
    );
    // External audit POS-001: an unlocked COMBAT decays once quiet; the
    // ladder stands down with it (lifts the per-PID egress blocks).
    {
        let ladder = Arc::clone(&ladder);
        posture.on_combat_decay(Arc::new(move || ladder.stand_down(Instant::now())));
    }
    // combat-avail-2: the same host-critical knowledge the ladder uses to
    // spare attributed offenders must also spare the /proc DESCENDANTS a
    // KillProcessTree walk reaps (an sshd or the watchdog under an
    // offender). The executor was built before the guard existed, so bind
    // it late; ProtectedReason has a static name for the audit row.
    {
        let guard = northnarrow_agent::combat::SystemProtectedProcs::new(
            executor.own_pid(),
            exempt.clone(),
            cli.resolved_watchdog_exe(),
        );
        executor.set_tree_guard(Arc::new(move |pid: u32| {
            use northnarrow_agent::combat::ProtectedProcs;
            guard.protected_reason(pid).map(|r| r.as_str())
        }));
    }
    // Lab PR 181 (debug-trigger builds only): the same guard answers the
    // PIDs written to `debug-protected-query` next to the admin socket.
    #[cfg(feature = "debug-trigger")]
    let debug_guard = northnarrow_agent::combat::SystemProtectedProcs::new(
        executor.own_pid(),
        exempt.clone(),
        cli.resolved_watchdog_exe(),
    );
    if ladder_slot.set(Arc::clone(&ladder)).is_err() {
        warn!("COMBAT ladder slot already set — unexpected double-init");
    }
    info!(
        "COMBAT graduated-response ladder armed (INVESTIGATE → NEUTRALIZE → ISOLATE; \
         isolation is last resort)"
    );

    // Lab PR 222: copy on first write (EXPERIMENTAL). Off without a signed
    // `cow-guard.local` that says `enabled = true`; started here, after the
    // anti-tamper hooks (its journals are registered in their map) and the
    // audit log (its degradations and restores are signed rows).
    match northnarrow_agent::cow::boot(
        &overlay_gate.verified(
            OverlayKind::CowGuard,
            std::path::Path::new(northnarrow_agent::cow::config::COW_GUARD_LOCAL),
        ),
        lineage.clone(),
        audit_log.clone(),
        northnarrow_agent::anti_tamper::prepare_pin_root().map(|p| p.to_path_buf()),
        detect_only,
    ) {
        northnarrow_agent::cow::GuardState::Off => {
            debug!("copy on first write: off (no signed cow-guard.local enabling it)")
        }
        northnarrow_agent::cow::GuardState::Failed(why) => {
            warn!(why = %why, "copy on first write: configured but not running")
        }
        northnarrow_agent::cow::GuardState::Running(_) => {}
    }

    // Fast heartbeat advancing the time-bound INVESTIGATE deadline. The
    // 60 s posture-decay loop is too coarse for the ladder's
    // seconds-scale windows; this 5 s tick is a no-op unless a COMBAT
    // episode is active and its investigate deadline has elapsed.
    let ladder_tick = Arc::clone(&ladder);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if HOST_STOPPING.load(std::sync::atomic::Ordering::SeqCst) {
                continue;
            }
            ladder_tick.tick(Instant::now());
        }
    });

    // External audit EBPF-001: the agent now outlives the units' stop jobs
    // and runs until systemd-shutdown's final stage. Ask systemd every 2 s
    // whether the host is stopping: from then on the shutdown's own traffic
    // (logs truncated, services killed, the console written) must not drive
    // the posture or the ladder. Detection goes on.
    if std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET).exists() {
        let ladder_stop = Arc::clone(&ladder);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                if systemd_state().await.as_deref() == Some("stopping") {
                    host_stopping(&ladder_stop);
                    break;
                }
            }
        });
    }

    // Tappa 8 A8: shutdown signal — the dispatcher fires it on a
    // successfully-verified `ShutdownRequest` so this main loop
    // can break and the agent can exit cleanly. The same Arc is
    // cloned into `serve_with_marker_path` (Some(...)) and kept
    // here for the select-arm `wait()`.
    let shutdown_signal = ShutdownSignal::new();
    Combat {
        ladder,
        #[cfg(feature = "debug-trigger")]
        debug_guard,
        shutdown_signal,
    }
}

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
