//! The posture machine and the COMBAT ladder (R11a, lab PR 261: from
//! `main.rs`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_model::posture_types::PostureKind;
use nn_proto::admin_signed_payload::OverlayKind;
use northnarrow_agent::admin_socket::ShutdownSignal;
use northnarrow_agent::anti_tamper::network_isolate::{NetworkIsolator, UnlockToken};
use northnarrow_agent::posture::{
    AuthSessionTracker, CombatEntryHook, CombatReleaseHook, ExemptPids, PostureMachine,
    ReleaseResult, ReleaseScope,
};
use northnarrow_agent::response::Executor;
use tracing::{debug, info, warn};

use super::cli::Cli;
use super::evidence::AuditHandle;
use super::tasks::{spawn_shutdown_exe_refresh, spawn_watchdog_exempt_refresh, WatchdogAudit};
use crate::pipeline::{systemd_watch, HostStopping, SystemdSnapshot};

/// What [`machine`] built.
pub(crate) struct Posture {
    /// The COMBAT ladder's slot the posture's hooks read, set by
    /// [`ladder`].
    pub(crate) ladder_slot: Arc<std::sync::OnceLock<Arc<northnarrow_agent::combat::CombatLadder>>>,
    pub(crate) exempt: ExemptPids,
    /// The operator's mass-write carve-outs, for the file-open sensor.
    pub(crate) open_sensor_carveout: Vec<String>,
    pub(crate) posture: PostureMachine,
    /// The audit log the watchdog refresh signs to, set by [`crate::boot::evidence::wire`].
    pub(crate) watchdog_audit: Arc<std::sync::OnceLock<WatchdogAudit>>,
    /// A stale COMBAT chain found at boot, signed once the state directory
    /// is protected.
    pub(crate) stale_combat: Option<northnarrow_agent::combat::reconcile::StaleChain>,
}

/// The posture: the COMBAT hooks on the ladder's slot, the stack's
/// exemption, the posture machine (with the release through the isolator,
/// or without one), its window, tracker and detector; the watchdog's and
/// systemd-shutdown's refreshes; a stale COMBAT chain torn down.
#[allow(clippy::too_many_arguments)]
pub(crate) fn machine(
    cli: &Cli,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    lineage: &AuthSessionTracker,
    isolator: &Option<Arc<NetworkIsolator>>,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    ransom_tracker: &Arc<northnarrow_agent::impact::RansomTracker>,
    defense_detector: &Arc<northnarrow_agent::impair::DefenseDetector>,
    rule_policy: &northnarrow_agent::decision::rule_policy::PolicyHandle,
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
        // process-wide switch; R11c, lab PR 264: the handle the policy
        // phase made, no longer the process-wide handle).
        .with_rule_policy(rule_policy.clone())
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
        .with_rule_policy(rule_policy.clone())
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
    // Lab PR 225: their counters in `status --key` — R11c (lab PR 264): the
    // admin socket gets them from the start, no longer a published slot.
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

/// What [`ladder`] armed.
pub(crate) struct Combat {
    pub(crate) ladder: Arc<northnarrow_agent::combat::CombatLadder>,
    /// Lab PR 181: the guard the `debug-protected-query` trigger asks.
    #[cfg(feature = "debug-trigger")]
    pub(crate) debug_guard: northnarrow_agent::combat::SystemProtectedProcs,
    /// Tappa 8 A8: fired by a verified admin `ShutdownRequest`.
    pub(crate) shutdown_signal: ShutdownSignal,
    /// R11c (lab PR 264): systemd reported the host as stopping (the event
    /// loop reads it; process-wide until then).
    pub(crate) host_stopping: HostStopping,
    /// R12b (lab PR 269): systemd's state, as the systemd watch last read
    /// it — what the decision judges a relayed signal on without waiting.
    pub(crate) systemd: SystemdSnapshot,
    /// R11c (lab PR 264): the copy-on-first-write guard of this boot (the
    /// event loop, the admin socket and the stop use it; process-wide until
    /// then).
    pub(crate) cow_guard: northnarrow_agent::cow::CowGuard,
}

/// The COMBAT ladder on the system actuator and the signed evidence,
/// published to the posture hooks' slot; the executor's tree guard; the
/// copy-on-first-write guard; the ladder's tick and the watch on systemd
/// stopping the host; the admin shutdown signal.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ladder(
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
    // R11c (lab PR 264): the copy-on-first-write guard the NEUTRALIZE hook
    // tells, filled once the guard has booted below (before, the hook found
    // no running guard, as it found none in the process-wide state).
    let cow_slot: Arc<std::sync::OnceLock<northnarrow_agent::cow::CowGuard>> = Arc::default();
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
        .with_neutralize_hook({
            let cow_slot = Arc::clone(&cow_slot);
            Box::new(move |refs| {
                if let Some(cow) = cow_slot.get() {
                    cow.on_ladder_neutralized(
                        refs.iter()
                            .map(|r| northnarrow_agent::cow::trust::ProcId {
                                pid: r.pid(),
                                start: r.start_ticks().unwrap_or(0),
                            })
                            .collect(),
                    )
                }
            })
        })
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
    let cow_guard = northnarrow_agent::cow::boot(
        &overlay_gate.verified(
            OverlayKind::CowGuard,
            std::path::Path::new(northnarrow_agent::cow::config::COW_GUARD_LOCAL),
        ),
        lineage.clone(),
        audit_log.clone(),
        northnarrow_agent::anti_tamper::prepare_pin_root().map(|p| p.to_path_buf()),
        detect_only,
    );
    match cow_guard.state() {
        northnarrow_agent::cow::GuardState::Off => {
            debug!("copy on first write: off (no signed cow-guard.local enabling it)")
        }
        northnarrow_agent::cow::GuardState::Failed(why) => {
            warn!(why = %why, "copy on first write: configured but not running")
        }
        northnarrow_agent::cow::GuardState::Running(_) => {}
    }
    let _ = cow_slot.set(cow_guard.clone());
    let host_stopping = HostStopping::default();

    // Fast heartbeat advancing the time-bound INVESTIGATE deadline. The
    // 60 s posture-decay loop is too coarse for the ladder's
    // seconds-scale windows; this 5 s tick is a no-op unless a COMBAT
    // episode is active and its investigate deadline has elapsed.
    let ladder_tick = Arc::clone(&ladder);
    let stopping_tick = host_stopping.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if stopping_tick.is_stopping() {
                continue;
            }
            ladder_tick.tick(Instant::now());
        }
    });

    // External audit EBPF-001: the agent now outlives the units' stop jobs
    // and runs until systemd-shutdown's final stage. Ask systemd every 2 s
    // whether the host is stopping: from then on the shutdown's own traffic
    // (logs truncated, services killed, the console written) must not drive
    // the posture or the ladder. Detection goes on. R12b (lab PR 269): the
    // answer is the snapshot the decision judges a relayed signal on, and
    // the watch asks at once when the decision wants a newer one.
    let systemd = SystemdSnapshot::default();
    if std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET).exists() {
        tokio::spawn(systemd_watch(
            systemd.clone(),
            host_stopping.clone(),
            Arc::clone(&ladder),
        ));
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
        host_stopping,
        systemd,
        cow_guard,
    }
}

/// External audit CMB-012: how long the COMBAT release waits for the
/// ladder's queued steps (a NEUTRALIZE of a large tree takes seconds)
/// before it lifts the isolation anyway.
const LADDER_RELEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Best-effort compatibility record for a Beta Step 4a stale-COMBAT
/// reconcile: one JSONL line in
/// [`northnarrow_agent::combat::reconcile::LOG_PATH`]; a write failure is
/// logged but never fatal — the teardown it records has already happened,
/// and the signed `integrity_drift` (`combat_reconcile`) is the evidence
/// (external audit MAIN-013). Lab follow-up (lab PR 188): written once the
/// state directory's protection exists, a missing file created inside
/// `protection`'s dance ([`northnarrow_agent::combat::reconcile::record_line`]).
pub(crate) fn audit_combat_reconcile(
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
