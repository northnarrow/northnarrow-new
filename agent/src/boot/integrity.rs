
/// What [`boot_integrity`] decided: the no-enforcement gate, the checks'
/// results the attest phase and the capability manifest sign, and the
/// permit the attach takes.
struct Integrity {
    exec_cfg: ExecutorConfig,
    detect_only: bool,
    /// Where detect-only came from (MAIN-008), for `agent_boot`.
    detect_only_source: Option<String>,
    /// The capabilities missing in enforcement, signed once the audit log
    /// is open.
    caps_degraded: Vec<String>,
    /// The install manifest's verdict, for `agent_boot`.
    integrity: northnarrow_agent::install_manifest::IntegrityOutcome,
    /// The host hardening table, for the capability manifest.
    host_checks: Vec<northnarrow_agent::host_hardening::Check>,
    /// `NN_ANTI_TAMPER_ALLOW_DEGRADED`, for the self-test.
    allow_degraded: bool,
    /// The active LSMs, for the self-test, the trust level and the
    /// capability manifest.
    bpf_lsm_state: northnarrow_agent::boot::lsm::BpfLsm,
    /// Lab PR 218: the only way into the kernel, given by
    /// `BootSequence::enter_attach` once every preflight step is done.
    attach_permit: northnarrow_agent::boot::AttachPermit,
}

/// `BootPhase::Preflight`, its checks before anything attaches (lab PR 218,
/// external review G-09 / Q11-03): the no-enforcement gate and the demo
/// rules' gate, the capability bounding set, the install manifest, the
/// audit log's writability, the host hardening, the BPF LSM. A refusal is
/// signed (`record_refused_boot`) and the start stops with the host
/// untouched. It ends in `BootSequence::enter_attach`, which hands out the
/// attach permit only once every preflight step is done.
fn boot_integrity(
    cli: &Cli,
    boot: &mut BootSequence,
    identity: &agent_id::AgentIdentity,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    early_registration_failed: bool,
) -> Result<Integrity> {
    // Lab PR 218: resolved before the attach — the capability gate below
    // depends on it.
    // BUG-033 detect-only: resolve the one no-enforcement gate from the
    // CLI flag OR-ed with the env inputs (`from_env` reads
    // `NN_DETECT_ONLY` / legacy `NORTHNARROW_DRY_RUN`). The resolved
    // value drives BOTH the response Executor (via the config) and the
    // COMBAT engage-hook below, so there is exactly one switch.
    let mut exec_cfg = ExecutorConfig::from_env();
    if cli.detect_only {
        exec_cfg.dry_run = true;
    }
    let detect_only = exec_cfg.dry_run;
    // External audit PROC-015 (NN-AUD-302): a demo-tappa5 build enforces
    // R901..R904 on a file-name suffix any user picks; it starts in
    // enforcement only with NN_ALLOW_DEMO_RULES=1 (a weakening variable,
    // recorded as a signed integrity_drift). Before any response runs.
    {
        use northnarrow_agent::decision::engine as eng;
        let allow = std::env::var(eng::ALLOW_DEMO_RULES_ENV).ok();
        eng::demo_rules_gate(eng::DEMO_RULES_BUILD, detect_only, allow.as_deref())
            .map_err(anyhow::Error::msg)?;
        if eng::DEMO_RULES_BUILD {
            warn!(
                detect_only,
                allow = allow.as_deref().unwrap_or(""),
                "demo-tappa5 build: R901..R904 run ahead of every production rule — \
                 a lab binary, never a release"
            );
        }
    }
    // External audit MAIN-008: the signed agent_boot entry says where
    // detect-only came from.
    let detect_only_source: Option<String> = if cli.detect_only {
        Some("--detect-only".to_string())
    } else {
        northnarrow_agent::response::config::detect_only_env()
            .map(|(name, v)| format!("{name}={v}"))
    };
    // Capability preflight (before anything attaches since lab PR 218,
    // external review G-09 / Q11-03): the systemd CapabilityBoundingSet is the
    // hard ceiling on what this root process can do. Without CAP_KILL,
    // kill(2) only reaches uid-0 targets, so every KillProcess verdict
    // against a user-owned process would EPERM — in enforcement mode
    // that is a refuse-to-start, not a warning, and so is a set that
    // cannot be verified (external audit CMB-028). The other caps only
    // degrade a secondary surface: in enforcement an ERROR each here and
    // a signed `subsystem_degraded` each once the audit log is open
    // (below); in detect-only a WARN.
    let caps_degraded: Vec<String> = {
        use northnarrow_agent::response::caps_preflight as caps;
        let reading = caps::read_effective();
        if let caps::CapsReading::Read {
            note: Some(note), ..
        } = &reading
        {
            warn!("capability preflight: {note}");
        }
        match caps::boot_gate(&reading, detect_only) {
            caps::BootGate::Refuse(why) => anyhow::bail!("{why}"),
            caps::BootGate::Start { degraded } if degraded.is_empty() => {
                debug!("capability preflight: all required caps present");
                Vec::new()
            }
            caps::BootGate::Start { degraded } if detect_only => {
                for d in &degraded {
                    warn!("capability preflight: {d}");
                }
                Vec::new()
            }
            caps::BootGate::Start { degraded } => {
                for d in &degraded {
                    error!("capability preflight: {d}");
                }
                degraded
            }
        }
    };
    boot.done(BootStep::Capabilities)?;

    // Supply chain, runtime half: the binaries running now must be the
    // ones install.sh verified and recorded. Checked before the audit
    // log opens so the agent_boot entry carries the result — and, since
    // lab PR 218 (external review G-09 / Q11-03), before anything attaches.
    let integrity = {
        use northnarrow_agent::install_manifest::{
            self, BootHistory, IntegrityOutcome, ALLOW_UNVERIFIED_ENV,
        };
        let own_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
        let outcome = install_manifest::check(
            &cli.install_manifest,
            &own_exe,
            northnarrow_agent::sensors::ebpf_object::OBJECT_SHA,
        );
        // External audit DEP-009: a missing manifest is a removal once a
        // boot of this install verified against it — the signed chain is
        // the sentinel, read (only in that case) before the decision.
        let history = match &outcome {
            IntegrityOutcome::NoManifest { .. } => {
                match northnarrow_agent::audit::verified_boot_recorded(&cli.audit_log_file) {
                    Ok(true) => BootHistory::VerifiedBefore,
                    Ok(false) => BootHistory::NeverVerified,
                    Err(e) => {
                        error!(
                            error = format!("{e:#}"),
                            path = %cli.audit_log_file.display(),
                            "audit chain unreadable — cannot show that this install never had a \
                             verified boot; the missing install manifest counts as removed"
                        );
                        BootHistory::Unknown
                    }
                }
            }
            _ => BootHistory::NeverVerified,
        };
        match &outcome {
            IntegrityOutcome::Verified {
                provenance,
                checked,
            } => info!(
                provenance,
                checked,
                manifest = %cli.install_manifest.display(),
                "binary integrity verified against the install manifest"
            ),
            IntegrityOutcome::NoManifest { path } if history == BootHistory::NeverVerified => {
                info!(
                    path = %path.display(),
                    "no install manifest and no verified boot in the audit chain — not installed \
                     by install.sh (a developer run): binaries not re-verified at boot"
                )
            }
            IntegrityOutcome::NoManifest { path } => error!(
                path = %path.display(),
                "install manifest MISSING after a verified boot of this install — it was removed \
                 (install.sh writes it on every install, source trees included)"
            ),
            IntegrityOutcome::NotApplicable { own_exe, bin_dir } => info!(
                own_exe = %own_exe.display(),
                bin_dir,
                "install manifest describes another copy (this binary runs outside bin_dir) — \
                 not compared"
            ),
            IntegrityOutcome::Unreadable { path, reason } => error!(
                path = %path.display(),
                reason,
                "install manifest unreadable — it sits under inode_protect, a broken one is a signal"
            ),
            IntegrityOutcome::Mismatch {
                provenance,
                mismatches,
            } => {
                for m in mismatches {
                    error!(
                        file = %m.name,
                        expected = %m.expected,
                        actual = %m.actual,
                        provenance,
                        "binary integrity MISMATCH — the running file is not the one install.sh \
                         verified and recorded"
                    );
                }
            }
        }
        let allow = std::env::var(ALLOW_UNVERIFIED_ENV).ok();
        if outcome.is_fatal(allow.as_deref(), history) {
            error!(
                "refusing to start: install-manifest check = {} (set {ALLOW_UNVERIFIED_ENV}=1 to \
                 override on a dev host; re-run install.sh to restore a verified install)",
                outcome.label()
            );
            // Leave the refusal in the signed audit chain before exiting.
            let detail = match &outcome {
                IntegrityOutcome::Mismatch { mismatches, .. } => mismatches
                    .iter()
                    .map(|m| format!("{}: expected {} got {}", m.name, m.expected, m.actual))
                    .collect::<Vec<_>>()
                    .join("; "),
                IntegrityOutcome::Unreadable { reason, .. } => reason.clone(),
                IntegrityOutcome::NoManifest { path } => format!(
                    "{} missing ({}) — re-run install.sh",
                    path.display(),
                    if history == BootHistory::VerifiedBefore {
                        "removed after a verified boot of this install"
                    } else {
                        "audit chain unreadable"
                    }
                ),
                _ => String::new(),
            };
            record_refused_boot(
                cli,
                identity,
                overlay_gate,
                "install_manifest",
                (outcome.label(), outcome.provenance()),
                None,
                &detail,
            );
            std::process::exit(78);
        } else if matches!(
            outcome,
            IntegrityOutcome::Mismatch { .. } | IntegrityOutcome::Unreadable { .. }
        ) || (matches!(outcome, IntegrityOutcome::NoManifest { .. })
            && history != BootHistory::NeverVerified)
        {
            warn!(
                "install-manifest check = {} but {ALLOW_UNVERIFIED_ENV}=1 — continuing (dev override)",
                outcome.label()
            );
        }
        outcome
    };
    boot.done(BootStep::InstallManifest)?;

    // Lab PR 218 (external review G-09 / Q11-03): the audit log's
    // writability before anything attaches — a read-only mount or an
    // immutable file refuses the start while the host is untouched. The
    // signed `agent_boot` after the attach still proves it with a row.
    match northnarrow_agent::audit_preflight::preflight_writable(
        &cli.audit_log_file,
        early_registration_failed,
    ) {
        northnarrow_agent::audit_preflight::AuditPreflight::Writable => {
            debug!(path = %cli.audit_log_file.display(), "audit log writable (preflight)")
        }
        northnarrow_agent::audit_preflight::AuditPreflight::Deferred(why) => info!(
            why,
            "audit log closed to this process until the attach registers it — the boot probe \
             decides"
        ),
        northnarrow_agent::audit_preflight::AuditPreflight::Unwritable(why) => {
            let fatal = northnarrow_agent::audit::audit_failure_is_fatal(
                std::env::var(northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV)
                    .ok()
                    .as_deref(),
            );
            error!(
                why,
                fatal,
                "audit log NOT writable — found before anything attached (is the directory in \
                 the unit's ReadWritePaths?)"
            );
            if fatal {
                anyhow::bail!(
                    "audit log {} is not writable: {why}. Refusing to run unaudited; set {}=1 to \
                     start anyway.",
                    cli.audit_log_file.display(),
                    northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                );
            }
        }
    }
    boot.done(BootStep::AuditWritable)?;

    // Host hardening (Tappa 10.8): the anti-tamper holds only while root
    // cannot rewrite the kernel at runtime. One WARN per missing setting,
    // with the fix; `nn-admin host-check` prints the same table.
    // Lab PR 218: before the attach, and kept for the capability manifest
    // (signed at every boot, next to the trust level).
    let host_checks = {
        let checks = northnarrow_agent::host_hardening::run();
        let warns = northnarrow_agent::host_hardening::warn_count(&checks);
        for c in &checks {
            if c.status == northnarrow_agent::host_hardening::Status::Warn {
                warn!(check = c.id, value = %c.value, fix = c.fix, "host hardening: {}", c.name);
            }
        }
        info!(
            checks = checks.len(),
            warnings = warns,
            "host hardening checks done (nn-admin host-check for the table)"
        );
        checks
    };
    boot.done(BootStep::HostHardening)?;

    // Lab PR 218 (external review AR-09 / G-11): without `bpf` in the
    // active LSM list the deny hooks attach and never run. Refused before
    // anything attaches, unless NN_ANTI_TAMPER_ALLOW_DEGRADED=1; signed
    // either way (`northnarrow_agent::boot::lsm`).
    let allow_degraded = northnarrow_agent::boot::lsm::allow_degraded_from_env();
    let bpf_lsm_state = northnarrow_agent::boot::lsm::read_in(std::path::Path::new("/"));
    match northnarrow_agent::boot::lsm::gate(&bpf_lsm_state, allow_degraded) {
        northnarrow_agent::boot::lsm::LsmGate::Proceed => info!(
            lsms = bpf_lsm_state.list().unwrap_or(""),
            "BPF LSM active — the deny hooks will run"
        ),
        northnarrow_agent::boot::lsm::LsmGate::Degraded { detail } => {
            error!("{detail}");
            northnarrow_agent::boot::degradation::report("bpf_lsm", &detail);
        }
        northnarrow_agent::boot::lsm::LsmGate::Refuse { detail } => {
            error!("refusing to start: {detail}. Exiting 78.");
            record_refused_boot(
                cli,
                identity,
                overlay_gate,
                "bpf_lsm",
                (integrity.label(), integrity.provenance()),
                Some(("bpf_lsm", detail.as_str())),
                &detail,
            );
            std::process::exit(78);
        }
    }
    boot.done(BootStep::BpfLsm)?;
    let attach_permit = boot.enter_attach()?;
    Ok(Integrity {
        exec_cfg,
        detect_only,
        detect_only_source,
        caps_degraded,
        integrity,
        host_checks,
        allow_degraded,
        bpf_lsm_state,
        attach_permit,
    })
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
