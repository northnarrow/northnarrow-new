//! The response executor and the network isolator (R11a, lab PR 261: from
//! `main.rs`'s `run`).

use std::sync::Arc;

use anyhow::{Context, Result};
use northnarrow_agent::anti_tamper::network_isolate::NetworkIsolator;
use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::response::{Executor, ExecutorConfig};
use tracing::{debug, error, info, warn};

use super::cli::{Cli, ExploitGuard};
use super::evidence::{attest_degraded, AuditHandle};

/// What [`build`] built.
pub(crate) struct Response {
    pub(crate) legacy_isolation_removed: bool,
    /// The exec quarantine's copy of the executor's configuration.
    pub(crate) execq_exec_cfg: ExecutorConfig,
    pub(crate) executor: Executor,
    pub(crate) correlation: CorrelationBuffer,
    pub(crate) isolator: Option<Arc<NetworkIsolator>>,
}

/// The response side: the optional pid file (the hooks attached, the engine
/// loaded), the exploit guard's response, an older agent's host-wide
/// isolation removed, the quarantine's deny of the agent's own files, the
/// executor and what an earlier run left (kill cgroups, contained
/// processes), the correlation buffer, the network isolator.
pub(crate) fn build(
    cli: &Cli,
    exec_cfg: ExecutorConfig,
    detect_only: bool,
    audit_log: &AuditHandle,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    exploit_guard: &Option<northnarrow_agent::sensors::epg::ExploitGuard>,
) -> Result<Response> {
    // Tappa 7 task 6 #2b-verify: optional PID file. `attach_anti_tamper`
    // above is fully synchronous (anti_tamper::attach attempts AND pins
    // every LSM hook before it returns — crates/nn-linux/src/anti_tamper/mod.rs),
    // and the "decision engine ready" line has now flushed, so the
    // file's *existence* is a sound readiness gate: anything that sees
    // it knows every hook is attached and self-protection is live.
    //
    // The agent writing its OWN pid is immune to the failure class that
    // sank three external-resolution strategies in the retired #2b
    // harness, docs/verify-2b.sh (989c292 pgrep -P / -x, 6e746c6
    // /proc/*/exe diff): the sudo+exec
    // process-tree race, TASK_COMM_LEN comm truncation, and pgrep
    // quirks. A write failure here is FATAL by design — a harness or
    // supervisor that asked for a PID file cannot proceed without it,
    // and silently degrading would resurrect exactly the "agent is
    // alive but the watcher can't find it" bug this flag exists to
    // kill. The shipped unit passes `--pid-file /run/northnarrow/agent.pid`
    // (the watchdog and the scripts read it; the BPF program-id list and,
    // R11b, lab PR 262, the refused starts' fallback chains go beside it —
    // review #466 N3: this said production never passed it).
    if let Some(pid_file) = cli.pid_file.as_deref() {
        write_pid_file(pid_file)
            .with_context(|| format!("writing --pid-file {}", pid_file.display()))?;
    } else {
        debug!("no --pid-file provided; PID file write skipped");
    }

    // Lab PR 219: the exploit guard enforces only when asked to and outside
    // detect-only (the one no-enforcement switch wins). R11c (lab PR 264):
    // the guard the attach gave, no longer a process-wide control.
    if cli.exploit_guard != ExploitGuard::Off {
        use northnarrow_agent::sensors::epg::{effective_response, set_response, Response};
        let requested = cli.exploit_guard_response.response();
        match effective_response(requested, detect_only) {
            Response::Enforce => match set_response(exploit_guard.as_ref(), Response::Enforce) {
                Ok(()) => warn!(
                    "exploit post-condition guard ENFORCING: a task found holding what no \
                     legitimate transition gave it is sent SIGKILL in the kernel (lite: and \
                     the use is refused)"
                ),
                Err(e) => warn!(reason = %e, "exploit guard: enforce requested, not applied"),
            },
            Response::Detect if requested == Response::Enforce => {
                info!("exploit guard: enforce requested, detect-only in force — detect mode")
            }
            Response::Detect => {}
        }
    }
    // External audit CMB-006: an older agent's host-wide nftables blackout
    // (no carve-out, no release, no status) is removed before anything
    // else; host-wide isolation is the COMBAT ladder's alone.
    let legacy_isolation_removed =
        match northnarrow_agent::response::network_isolation::retire_legacy(&exec_cfg) {
            Ok(removed) => {
                if removed {
                    warn!(
                        "removed the host-wide nftables isolation an older agent left \
                         (external audit CMB-006): host-wide isolation is the COMBAT ladder's"
                    );
                }
                removed
            }
            Err(e) => {
                error!(
                    error = %e,
                    "an older agent's host-wide nftables isolation could not be removed — \
                     `nft delete chain inet northnarrow isolation_output` (and isolation_input) \
                     from the console"
                );
                false
            }
        };
    // External audit CMB-025: the quarantine never takes the agent's own
    // files, wherever this host keeps them (`--watchdog-exe`, the running
    // binary, the executor's key, vault and containment record).
    {
        let own_exe = std::env::current_exe().ok();
        let deny = northnarrow_agent::response::quarantine::RuntimeDeny::new(
            &exec_cfg,
            own_exe.as_deref(),
            &cli.resolved_watchdog_exe(),
        );
        info!(
            paths = %deny.describe(),
            "quarantine: the agent's own files are never quarantined"
        );
        northnarrow_agent::response::quarantine::set_runtime_deny(deny);
    }
    // Lab PR 223: the exec quarantine vaults block-listed files.
    let execq_exec_cfg = exec_cfg.clone();
    let executor = Executor::with_config(exec_cfg);
    // External audit CMB-019: a kill cgroup an earlier agent left in the
    // middle of a kill (its tree frozen) is finished and removed.
    if !detect_only {
        let removed = northnarrow_agent::response::kill::reap_stale_kill_cgroups(
            &executor.config().blocked_cgroup_dir(),
        );
        if removed > 0 {
            warn!(
                removed,
                "kill cgroups left by an earlier agent were finished and removed"
            );
        }
    }
    // External audit CMB-010: the processes an earlier run moved into the
    // blocked / throttled scopes — the gone ones dropped from the record,
    // the still-contained ones reported (no automatic release after a
    // restart).
    let contained = northnarrow_agent::response::containment::reconcile(executor.config());
    if !contained.still_contained.is_empty() {
        warn!(
            count = contained.still_contained.len(),
            "processes contained by an earlier run are still in the blocked / throttled scopes"
        );
    }
    if detect_only {
        warn!(
            "DETECT-ONLY mode active (--detect-only / NN_DETECT_ONLY / NORTHNARROW_DRY_RUN): \
             detection + posture run normally, but NO response action or COMBAT network \
             isolation will touch the system — verdicts are logged as \"would execute\" only"
        );
    }
    // Lab follow-up (lab PR 165): without `nft` the per-process outbound
    // block cannot work. Said once here, and in the signed chain once the
    // audit log is open (below), instead of only at the first block.
    let nft_gap = northnarrow_agent::response::block_outbound::nft_gap_at_boot();
    if let Some(gap) = &nft_gap {
        error!("{gap}");
        attest_degraded(audit_log.as_ref(), gap);
    }
    info!(
        own_pid = executor.own_pid(),
        protected = executor.protected().len(),
        detect_only,
        "response executor ready (KillProcess + KillProcessTree active)"
    );

    let correlation = CorrelationBuffer::with_default_capacity();

    // Tappa 7 task 7 / Tappa 8: anti-tamper response pipeline. The
    // NetworkIsolator owns the iptables shell-out; engage runs on
    // any non-Combat → Combat edge, release only fires for an
    // Ed25519-verified admin unlock (capability gated via
    // UnlockToken). If the ruleset is missing we WARN-and-continue
    // with no isolator, so the agent still boots in dev environments
    // without /etc/northnarrow/ provisioned.
    let isolator = match NetworkIsolator::new(cli.combat_rules.clone()) {
        Ok(i) => Some(Arc::new(
            i.with_allow_cidrs_path(cli.combat_allow_cidrs.clone())
                .with_rules_v6(cli.combat_rules_v6.clone())
                // External audit ATP-001 / DEP-003: the COMBAT files are
                // applied only as shipped or admin-signed.
                .with_overlay_gate(Arc::clone(overlay_gate)),
        )),
        Err(e) => {
            // ERROR, not WARN: besides losing isolation, no isolator means
            // the admin socket below is never started — nn-admin status /
            // unlock / detections all fail and the watchdog's STATUS ping
            // trips its stuck-recovery restart loop every 30 s.
            error!(
                error = %e,
                path = %cli.combat_rules.display(),
                "combat ruleset missing or invalid: COMBAT entry will NOT engage network \
                 isolation AND the admin socket will NOT be started (nn-admin unusable, \
                 watchdog STATUS ping will fail) — install combat-rules.v4 (configs/) and restart"
            );
            None
        }
    };
    // External audit ATP-014 (NN-AUD-262): the files COMBAT's isolation
    // runs — looked up in the system directories only, never on PATH —
    // named once at boot, or why the isolation could not run.
    if let Some(iso) = isolator.as_ref() {
        match iso.binaries() {
            Ok(files) => info!(binaries = %files, "COMBAT isolation binaries (system directories)"),
            Err(why) => error!(
                error = %why,
                "COMBAT isolation cannot run: no trusted iptables in /usr/sbin, /usr/bin, /sbin or \
                 /bin — a STAGE 3 isolation will fail (install iptables; a copy in /usr/local is \
                 not used)"
            ),
        }
    }
    Ok(Response {
        legacy_isolation_removed,
        execq_exec_cfg,
        executor,
        correlation,
        isolator,
    })
}

/// External audit CMB-006: the removal of an older agent's host-wide
/// nftables isolation at start is recorded in the signed audit chain.
pub(crate) fn attest_legacy_isolation_removed(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "legacy_isolation_removed",
            "detail": "an older agent's nftables isolation chains (isolation_input, \
                       isolation_output) were found at start and removed",
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "repaired".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the removed legacy isolation failed");
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
