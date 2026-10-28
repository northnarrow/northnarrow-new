//! `BootPhase::Preflight`, its checks before anything attaches, and the
//! integrity proof (R11a, lab PR 261: from `main.rs`; R11b, lab PR 262: the
//! checks record their steps, `verify_integrity` gives the proof).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use northnarrow_agent::agent_id;
use northnarrow_agent::boot::{checks, BootSequence, BootStep};
use northnarrow_agent::response::ExecutorConfig;
use tracing::{debug, error, info, warn};

use super::cli::Cli;

/// What [`check`] decided: the no-enforcement gate, the checks'
/// results the attest phase and the capability manifest sign, and the
/// proof the attach takes.
pub(crate) struct Integrity {
    pub(crate) exec_cfg: ExecutorConfig,
    pub(crate) detect_only: bool,
    /// Where detect-only came from (MAIN-008), for `agent_boot`.
    pub(crate) detect_only_source: Option<String>,
    /// The capabilities missing in enforcement, signed once the audit log
    /// is open.
    pub(crate) caps_degraded: Vec<String>,
    /// The install manifest's verdict, for `agent_boot`.
    pub(crate) integrity: northnarrow_agent::install_manifest::IntegrityOutcome,
    /// The host hardening table, for the capability manifest.
    pub(crate) host_checks: Vec<northnarrow_agent::host_hardening::Check>,
    /// `NN_ANTI_TAMPER_ALLOW_DEGRADED`, for the self-test.
    pub(crate) allow_degraded: bool,
    /// The active LSMs, for the self-test, the trust level and the
    /// capability manifest.
    pub(crate) bpf_lsm_state: northnarrow_agent::boot::lsm::BpfLsm,
    /// R11b (lab PR 262): the audit log, opened before the load (its chain
    /// read): the attest phase appends the boot's rows to it.
    pub(crate) audit: checks::AuditOpen,
    /// Lab PR 218: the only way into the kernel, given by
    /// `BootSequence::verify_integrity` once every preflight check has
    /// passed (R11b, lab PR 262: the load, the pins and the attaches take
    /// it).
    pub(crate) verified: northnarrow_agent::boot::IntegrityVerified,
}

/// `BootPhase::Preflight`, its checks before anything attaches (lab PR 218,
/// external review G-09 / Q11-03): the no-enforcement gate and the demo
/// rules' gate, the capability bounding set, the install manifest, the
/// audit log's writability, the host hardening, the BPF LSM. A refusal is
/// signed (`record_refused_boot`) and the start stops with the host
/// untouched. It ends in `BootSequence::verify_integrity`, which hands out
/// the integrity proof only once every preflight check has passed (R11b,
/// lab PR 262: each recorded by its check, `boot::checks`).
pub(crate) fn check(
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
        let (reading, gate) = checks::capabilities(boot, detect_only)?;
        if let caps::CapsReading::Read {
            note: Some(note), ..
        } = &reading
        {
            warn!("capability preflight: {note}");
        }
        match gate {
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

    // Supply chain, runtime half: the binaries running now must be the
    // ones install.sh verified and recorded. Checked before the audit
    // log opens so the agent_boot entry carries the result — and, since
    // lab PR 218 (external review G-09 / Q11-03), before anything attaches.
    let integrity = {
        use northnarrow_agent::install_manifest::{
            BootHistory, IntegrityOutcome, ALLOW_UNVERIFIED_ENV,
        };
        let own_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
        let allow = std::env::var(ALLOW_UNVERIFIED_ENV).ok();
        // External audit DEP-009: a missing manifest is a removal once a
        // boot of this install verified against it — the signed chain is
        // the sentinel, read (only in that case) before the decision.
        let checks::ManifestCheck {
            outcome,
            history,
            history_error,
            fatal,
        } = checks::install_manifest(
            boot,
            &cli.install_manifest,
            &own_exe,
            &cli.audit_log_file,
            allow.as_deref(),
        )?;
        if let Some(e) = &history_error {
            error!(
                error = %e,
                path = %cli.audit_log_file.display(),
                "audit chain unreadable — cannot show that this install never had a \
                 verified boot; the missing install manifest counts as removed"
            );
        }
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
        if fatal {
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

    // Lab PR 218 (external review G-09 / Q11-03): the audit log's
    // writability before anything attaches — a read-only mount or an
    // immutable file refuses the start while the host is untouched. The
    // signed `agent_boot` after the attach still proves it with a row.
    // R11b (lab PR 262): and its chain, opened here — a broken chain refuses
    // the start before anything is loaded (the attest phase opened it after
    // the attach until then), and the attest phase appends to this log.
    let audit = checks::audit_log(
        boot,
        &cli.audit_log_file,
        &cli.signing_key_file,
        identity.id,
        early_registration_failed,
        std::env::var(northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV)
            .ok()
            .as_deref(),
    )?;
    let preflight_deferred = matches!(
        audit.preflight,
        northnarrow_agent::audit_preflight::AuditPreflight::Deferred(_)
    );
    match audit.preflight {
        northnarrow_agent::audit_preflight::AuditPreflight::Writable => {
            debug!(path = %cli.audit_log_file.display(), "audit log writable (preflight)")
        }
        northnarrow_agent::audit_preflight::AuditPreflight::Deferred(why) => info!(
            why,
            "audit log closed to this process until the attach registers it — the boot probe \
             decides"
        ),
        northnarrow_agent::audit_preflight::AuditPreflight::Unwritable(why) => {
            let fatal = audit.fatal;
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
    let audit_open = match audit.open {
        checks::AuditOpen::Failed(why) => {
            let fatal = audit.fatal;
            error!(
                error = why,
                fatal,
                "audit log open failed — COMBAT stage transitions + admin ops would be UNAUDITED"
            );
            if fatal {
                anyhow::bail!(
                    "audit log {} cannot be opened: {why}. Refusing to run unaudited; set {}=1 to \
                     start anyway.",
                    cli.audit_log_file.display(),
                    northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                );
            }
            checks::AuditOpen::Failed(why)
        }
        checks::AuditOpen::NoKey(why) => {
            warn!(
                error = why,
                "agent signing key load failed — COMBAT stage transitions + admin ops UNAUDITED \
                 this boot"
            );
            checks::AuditOpen::NoKey(why)
        }
        checks::AuditOpen::Deferred(why) if !preflight_deferred => {
            info!(
                why,
                "audit chain closed to this process until the attach registers it — opened after \
                 the attach"
            );
            checks::AuditOpen::Deferred(why)
        }
        other => other,
    };

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
    let (bpf_lsm_state, lsm_gate) =
        checks::bpf_lsm(boot, std::path::Path::new("/"), allow_degraded)?;
    match lsm_gate {
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
    let verified = boot.verify_integrity()?;
    Ok(Integrity {
        exec_cfg,
        detect_only,
        detect_only_source,
        caps_degraded,
        integrity,
        host_checks,
        allow_degraded,
        bpf_lsm_state,
        audit: audit_open,
        verified,
    })
}

/// Lab PR 218: a start refused by a boot gate (`install_manifest`,
/// `bpf_lsm`, `deny_self_test`) leaves the refusal in the signed chain
/// before the process exits — the rollback floor, the identity, then the
/// `subsystem_degraded` (`degraded`: source and detail) and the `agent_boot`
/// `refused` naming the gate — so root cannot quietly remove the trace
/// (lab PR 21).
pub(crate) fn record_refused_boot(
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
