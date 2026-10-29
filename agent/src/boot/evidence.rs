//! The signed evidence of the start (R11a, lab PR 261: from `main.rs`):
//! `BootPhase::Attest` — the audit log, the heads, `agent_boot`, the
//! degradations so far —, the late binding of the audit log to what was
//! built before it, the rotating logs and the detection stores; and the
//! signed records the other phases write through it.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use northnarrow_agent::admin_socket;
use northnarrow_agent::agent_id;
use northnarrow_agent::boot::{checks, BootPhase, BootSequence, BootStep};
use northnarrow_agent::detection_report;
use northnarrow_agent::posture::PostureMachine;
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::SensorMultiplexer;
use tracing::{error, info, warn};

use super::cli::Cli;
use super::posture::audit_combat_reconcile;
use super::refusal::{self, Refusal};
use super::tasks::WatchdogAudit;

/// The signed audit log, once [`attest`] opened it (`None`: the boot
/// runs unaudited, as the attest phase allowed).
pub(crate) type AuditHandle = Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>;

/// The chains' head anchor of this run (lab PR 160).
pub(crate) type AnchorHandle =
    Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>>;

/// What [`attest`] opened.
pub(crate) struct Attested {
    pub(crate) chain_anchor: AnchorHandle,
    pub(crate) audit_log: AuditHandle,
}

/// `BootPhase::Attest` (lab PR 218): the signed audit log — opened by the
/// integrity phase before the load (R11b, lab PR 262; `audit`), here when
/// that was deferred — takes the heads anchored as this boot found them,
/// the rollback floor, the chains' findings, the identity, then the boot's
/// own `agent_boot` (an audit log that cannot be written refuses the start
/// unless that is allowed) — and every degradation found so far is signed.
/// Then `BootPhase::Subsystems`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attest(
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
    exploit_guard: &Option<northnarrow_agent::sensors::epg::ExploitGuard>,
    caps_degraded: Vec<String>,
    audit: checks::AuditOpen,
) -> Result<Attested> {
    // Lab PR 218: the signed audit log right after the self-test, before
    // the subsystems below load (the blocklists, the rules, the response
    // executor, the posture, FIM): every degradation found so far is signed
    // now, and later ones within `boot::degradation::FLUSH_PERIOD`.
    boot.enter(BootPhase::Attest)?;
    // R11b (lab PR 262): what signs a refusal of this phase — the boot's own
    // row that cannot be written, a deferred open that fails.
    let refusals = refusal::Context {
        cli,
        identity: &identity,
        overlay_gate,
        integrity: (integrity.label(), integrity.provenance()),
    };
    // ── Shared audit log + COMBAT graduated-response ladder ─────────
    //
    // The signed, hash-chained audit log is opened ONCE (R11b, lab PR 262:
    // by the integrity phase, before the load; here when that was deferred)
    // and shared by both the COMBAT ladder (per-stage signed transitions)
    // and the admin socket (admin-op audit). A `None` audit log (open/key
    // failure) degrades to log-only, exactly as the admin-op path already
    // tolerates.
    let mut chain_anchor: Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>> =
        None;
    // R11b (lab PR 262): the integrity phase opened the log before the load
    // (`boot::checks::audit_log`: its chain read, a broken one refused there);
    // it is opened here only when that was deferred — the previous agent's
    // hooks closed it to this process until the attach registered it — as
    // every start opened it until then.
    let opened = match audit {
        checks::AuditOpen::Open(log) => Some(*log),
        checks::AuditOpen::Deferred(_) => open_after_attach(&refusals, agent_id),
        // found, said (and refused when fatal) before the load
        checks::AuditOpen::NoKey(_)
        | checks::AuditOpen::Failed(_)
        | checks::AuditOpen::NotTried => None,
    };
    let audit_log: Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>> =
        match opened {
            // Boot write probe (etc-readonly-audit-1): a signed
            // `agent_boot` entry proves the chain is writable NOW
            // instead of failing silently at the first COMBAT
            // transition. Fail-closed in enforcement mode.
            Some(mut log) => {
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
                if let Some(marker) = chain_anchor.as_ref().and_then(|a| a.lock().take_marker()) {
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
                // R11b (lab PR 262): the refusals earlier starts could not
                // sign here (the audit log could not take them), from their
                // fallback chains beside --pid-file, before this boot's row
                // (review #466 F2: each read once, verified, bound to this
                // log).
                if let Some(dir) = refusal::fallback_dir(cli) {
                    let pk = northnarrow_agent::keys::boot_verifying_key(&cli.signing_key_file);
                    for e in refusal::record_fallback(&mut log, &dir, pk.as_ref(), agent_id)
                        .into_iter()
                        .filter_map(Result::err)
                    {
                        warn!(
                            error = %e,
                            path = %dir.display(),
                            "boot refusals of a fallback chain NOT recorded — kept for the next start"
                        );
                    }
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
                            std::env::var(northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV)
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
                            // R11b (lab PR 262): the write itself, after the
                            // attach by its nature (a full disk is found by
                            // it); signed in the fallback chain
                            let detail = format!(
                                "audit log {} is not writable: {e:#}. Refusing to run unaudited; \
                                 set {}=1 to start anyway.",
                                cli.audit_log_file.display(),
                                northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                            );
                            refusals.refuse(Some(&mut log), Refusal::new("audit_log", detail));
                        }
                        None
                    }
                }
            }
            None => None,
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
    // Lab PR 219: the exploit guard sampler's saturation entries from now on
    // (R11c, lab PR 264: bound in the guard the attach gave, no longer a
    // process-wide setter).
    if let Some(guard) = exploit_guard {
        guard.bind_audit_log(audit_log.clone());
    }
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

/// The audit log's open after the attach, when the integrity phase could
/// not open it before the load (R11b, lab PR 262: `AuditOpen::Deferred`):
/// as the attest phase opened it until then — fatal unless
/// `NN_AUDIT_ALLOW_UNWRITABLE=1` (the refusal signed, `refusals`), and so is
/// a key that cannot be loaded (review #466 F4: it ran unaudited; the
/// refusal is then the journal's alone).
fn open_after_attach(
    refusals: &refusal::Context<'_>,
    agent_id: [u8; 16],
) -> Option<northnarrow_agent::audit::AuditLog> {
    let cli = refusals.cli;
    let fatal = northnarrow_agent::audit::audit_failure_is_fatal(
        std::env::var(northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV)
            .ok()
            .as_deref(),
    );
    let refuse = |what: String| -> ! {
        refusals.refuse(
            None,
            Refusal::new(
                "audit_log",
                format!(
                    "{what}. Refusing to run unaudited; set {}=1 to start anyway.",
                    northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                ),
            ),
        )
    };
    let key =
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => key,
            Err(e) => {
                error!(
                    error = format!("{e:#}"),
                    fatal,
                    path = %cli.signing_key_file.display(),
                    "agent signing key cannot be loaded — no row of the audit chain could be signed"
                );
                if fatal {
                    refuse(format!(
                        "the agent's signing key {} cannot be loaded: {e:#}",
                        cli.signing_key_file.display()
                    ));
                }
                warn!("COMBAT stage transitions + admin ops UNAUDITED this boot");
                return None;
            }
        };
    match northnarrow_agent::audit::AuditLog::open(&cli.audit_log_file, key, agent_id) {
        Ok(log) => Some(log),
        Err(e) => {
            error!(
                error = format!("{e:#}"),
                fatal,
                "audit log open failed — COMBAT stage transitions + admin ops would be UNAUDITED"
            );
            if fatal {
                refuse(format!(
                    "audit log {} cannot be opened: {e:#}",
                    cli.audit_log_file.display()
                ));
            }
            None
        }
    }
}

/// The audit log reaches what was built before it opened: the BPF links'
/// self-check, the watchdog refresh, the foreign pins, a rolled-back
/// upgrade, the overlay gate, the executor, the telemetry probe, the
/// self-integrity watcher, the chains' tasks, the ring drops, the deny
/// hooks' fail-opens, the FIM drain, the trusted-installer window. R11c
/// (lab PR 264): each through the handle the part that holds it gave the
/// start (the samplers through `sensor`), no longer a process-wide setter.
/// What [`wire`] started that the event loop reads.
pub(crate) struct Wired {
    /// The telemetry probe, offered every event (`None`: disabled). R11c
    /// (lab PR 264): it was a process-wide tracker its spawn set.
    pub(crate) telemetry_probe: Option<northnarrow_agent::telemetry_probe::TelemetryProbe>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn wire(
    cli: &Cli,
    sensor: &SensorMultiplexer,
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
) -> Wired {
    // Tappa 10.8 BPF self-defence: the link self-check needs the audit log,
    // which did not exist when the hooks attached.
    sensor.bpf_guard().spawn_link_self_check(audit_log.clone());
    // Lab PR 216: and the watchdog refresh, to sign a watchdog that is gone.
    let _ = watchdog_audit.set(audit_log.clone());
    // External audit ATP-017 (NN-AUD-265): the `link_*` entries of the pin
    // root that are not the agent's links, one signed `integrity_drift` each.
    sensor.bpf_guard().attest_foreign_pins(audit_log.as_ref());
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
    let telemetry_probe = northnarrow_agent::telemetry_probe::spawn(audit_log.clone());
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
    if let Some(pk) = northnarrow_agent::keys::boot_verifying_key(&cli.signing_key_file) {
        northnarrow_agent::chains::spawn_boot_verify(chain_targets.clone(), pk, audit_log.clone());
    }
    sensor.ring_drops().bind_audit_log(audit_log.clone());
    // Lab PR 215: a deny hook that let an operation through undecided.
    sensor.fail_open().bind_audit_log(audit_log.clone());
    // External audit SNS-009: a security ring that loses events raises
    // ALERTED (TelemetryLoss), outside trusted-installer windows.
    sensor
        .ring_drops()
        .bind_posture(posture.clone(), Some(Arc::clone(installer_override)));

    // FIM-009 self-upgrade (§15.1): late-bind the audit-chain writer to
    // the trusted-installer override so its close/expiry records chain.
    if let Some(audit) = audit_log.as_ref() {
        installer_override.set_audit_log(Arc::clone(audit));
    }
    Wired { telemetry_probe }
}

/// What [`stores`] opened.
pub(crate) struct Stores {
    pub(crate) state_protection:
        Option<std::sync::Arc<northnarrow_agent::anti_tamper::filesystem::StateDirProtection>>,
    pub(crate) rotation_protection:
        std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager>,
    pub(crate) fim_drift_rotation: northnarrow_agent::chainlog::RotationConfig,
    pub(crate) netflow_rotation: northnarrow_agent::chainlog::RotationConfig,
    pub(crate) detection_sink: Option<northnarrow_agent::detection_store::DetectionSink>,
    pub(crate) detection_admin_state: Option<Arc<admin_socket::DetectionAdminState>>,
}

/// The state directory's protection (BUG-026) and the rotation it lets the
/// logs have (append-only without it), the stale chain's compatibility
/// line, the head anchor in the same dance; the detection log, its writer
/// and its reporter; the status-event log the detection triage writes.
pub(crate) fn stores(
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
    // NN_STATUS_EVENTS_CAP_BYTES. Degrade-not-fail: a status log that
    // does not open means "no triage status changes this boot" (the
    // `detections` read still works, showing initial Open, its rows
    // verified with the agent key); without the agent key there is no
    // state, and the read is refused too (lab PR 263: it served the
    // built-in paths' rows unverified), never an agent abort.
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
            Ok(key) => {
                let agent_key = key.verifying_key();
                let status_log = match northnarrow_agent::detection_store::open_status_log(
                    &cli.status_events_file,
                    key,
                    status_rotation,
                    rotation_protection.clone(),
                ) {
                    Ok(log) => Some(Arc::new(parking_lot::Mutex::new(log))),
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.status_events_file.display(),
                            "status-event store open failed — detection triage \
                             (set-status) DISABLED this boot"
                        );
                        None
                    }
                };
                Some(Arc::new(admin_socket::DetectionAdminState {
                    status_log,
                    agent_key,
                    detections_path: cli.detections_file.clone(),
                    status_events_path: cli.status_events_file.clone(),
                    // External audit NN-AUD-112 (R11c, lab PR 264: the
                    // audit log given here, no longer a process-wide setter).
                    unverified: Arc::new(northnarrow_agent::chains::UnverifiedRows::new(
                        audit_log.clone(),
                    )),
                }))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "status-event store needs the agent signing key — load failed; \
                     detection triage (set-status) and the detections read DISABLED \
                     this boot"
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
pub(crate) fn attest_degraded(
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
pub(crate) fn attest_degraded_at(
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
pub(crate) fn drain_ended(
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
pub(crate) fn attest_chain_findings(
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
pub(crate) fn attest_open_findings(
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
