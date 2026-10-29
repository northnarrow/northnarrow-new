//! The admin socket at boot (R11a, lab PR 261: from `main.rs`'s `run`).

use std::sync::Arc;

use northnarrow_agent::admin_socket::{self, ShutdownSignal};
use northnarrow_agent::anti_tamper::admin_auth::AdminAuth;
use northnarrow_agent::anti_tamper::network_isolate::NetworkIsolator;
use northnarrow_agent::posture::{ExemptPids, PostureMachine};
use northnarrow_agent::response::Executor;
use tracing::error;

use super::cli::Cli;
use super::evidence::{attest_degraded, attest_degraded_at, AnchorHandle, AuditHandle};

/// The admin socket, started only with the network isolator (its ruleset):
/// the admin key set (a skipped line signed, AUT-004; the one-key bootstrap
/// over once a second key was added, ATP-004), the serve loop with the
/// admin states of FIM, the canaries, the detections, the response verbs
/// and the read verbs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start(
    cli: &Cli,
    isolator: &Option<Arc<NetworkIsolator>>,
    agent_id: [u8; 16],
    audit_log: &AuditHandle,
    chain_anchor: &AnchorHandle,
    posture: &PostureMachine,
    shutdown_signal: &ShutdownSignal,
    fim_admin_state: &Option<Arc<admin_socket::FimAdminState>>,
    canary_admin_state: &Option<Arc<admin_socket::CanaryAdminState>>,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    detection_admin_state: &Option<Arc<admin_socket::DetectionAdminState>>,
    executor: &Executor,
    ladder: &Arc<northnarrow_agent::combat::CombatLadder>,
    detect_only_source: &Option<String>,
    exempt: &ExemptPids,
    handles: admin_socket::AdminHandles,
) {
    // Optional admin socket: only spawned if admin pubkey config
    // is present. Missing config = no unlock path; the agent still
    // runs but COMBAT can only be cleared by reboot.
    if let Some(iso) = isolator.as_ref() {
        match AdminAuth::load_with_agent_id(&cli.admin_pub, agent_id) {
            Ok(auth) => {
                // External audit AUT-004: a skipped line is in the signed
                // chain, not only in the journal.
                let skipped = auth.skipped_lines();
                if !skipped.is_empty() {
                    let lines: Vec<String> = skipped
                        .iter()
                        .map(|(n, why)| format!("line {n}: {why}"))
                        .collect();
                    attest_degraded(
                        audit_log.as_ref(),
                        &format!(
                            "{}: {} line(s) skipped, their keys not loaded — {}",
                            cli.admin_pub.display(),
                            skipped.len(),
                            lines.join("; ")
                        ),
                    );
                }
                // External audit ATP-004: the one-key bootstrap is over for
                // good once the signed chain shows a second key was added.
                // Lab PR 160: also when the head anchor carries it, or the
                // audit chain was found cut (it could have held the add).
                if audit_log
                    .as_ref()
                    .is_some_and(|l| l.lock().second_key_added())
                    || chain_anchor
                        .as_ref()
                        .is_some_and(|a| a.lock().second_key_added())
                {
                    auth.mark_bootstrap_consumed();
                }
                let auth = Arc::new(auth);
                let posture_clone = posture.clone();
                let iso_clone = Arc::clone(iso);
                let socket_path = cli.admin_socket.clone();
                let signal_for_serve = shutdown_signal.clone();
                // Tappa 8 B5: the AuditLog is opened ONCE at boot (above,
                // right after agent_id) and shared with the COMBAT ladder;
                // the admin socket takes its own Arc clone. post-A14 the
                // file's inode is already in PROTECTED_INODES so an
                // attacker can't replace it underneath us.
                let audit_log = audit_log.clone();
                let marker_path = cli.shutdown_marker_file.clone();
                let fim_state_for_serve = fim_admin_state.clone();
                let canary_state_for_serve = canary_admin_state.clone();
                // FIM-009 self-upgrade (§15.1): the dispatcher arms this
                // override on a verified TrustedInstallerGrantRequest.
                let installer_override_for_serve = Some(Arc::clone(installer_override));
                // Tappa 9.0.c: detection triage state (status-event chain).
                let detection_state_for_serve = detection_admin_state.clone();
                // External audit NN-AUD-082: the read verbs serve the
                // files the flags name, not the built-in paths.
                let read_paths_for_serve = Arc::new(admin_socket::AdminReadPaths {
                    fim_drift: cli.fim_drift_file.clone(),
                    netflow: cli.netflow_file.clone(),
                    netflow_listeners: cli.netflow_listeners_file.clone(),
                });
                // External audit CMB-016: the response verbs read the
                // executor's record and vault, and the ladder's stage.
                let response_state_for_serve = Some(Arc::new(admin_socket::ResponseAdminState {
                    config: executor.config().clone(),
                    combat_stage: {
                        let ladder = Arc::clone(ladder);
                        Arc::new(move || ladder.current_stage().map(|s| s.as_str().to_string()))
                    },
                    // External audit CMB-018 / CMB-027 (lab PR 193): `status`
                    // says detect-only and its source, and what the signed
                    // audit log lacks of the ladder.
                    detect_only_source: detect_only_source.clone(),
                    combat_evidence: {
                        let ladder = Arc::clone(ladder);
                        Arc::new(move || ladder.evidence_counts())
                    },
                }));
                // External audit ASK-009 (lab PR 213): the unsigned status
                // polling is summarised per peer in the signed audit log;
                // the verified watchdog (the pid in PROTECTED_PIDS) is not.
                let status_polls_for_serve =
                    Arc::new(admin_socket::StatusPolls::new(exempt.clone()));
                // R11c (lab PR 264): the start's handles the verbs read or
                // act on — the per-rule policy the engine and the posture
                // read, … (they were process-wide globals the start set).
                let handles_for_serve = Arc::new(handles);
                // External audit NN-AUD-077: the loop now outlives a
                // transient accept error; if it still ends, the admin plane
                // is gone until a restart — an ERROR and a signed record.
                let audit_log_on_exit = audit_log.clone();
                tokio::spawn(async move {
                    if let Err(e) = admin_socket::serve_with_marker_path(
                        socket_path,
                        auth,
                        Arc::new(posture_clone),
                        iso_clone,
                        marker_path,
                        Some(signal_for_serve),
                        audit_log,
                        fim_state_for_serve,
                        canary_state_for_serve,
                        installer_override_for_serve,
                        detection_state_for_serve,
                        response_state_for_serve,
                        read_paths_for_serve,
                        status_polls_for_serve,
                        handles_for_serve,
                    )
                    .await
                    {
                        error!(
                            error = %e,
                            "admin socket serve loop exited — no unlock, shutdown or key \
                             rotation until the agent restarts"
                        );
                        attest_degraded_at(
                            audit_log_on_exit.as_ref(),
                            &format!("admin socket serve loop exited: {e:#}"),
                            false,
                        );
                    }
                });
            }
            Err(e) => {
                // External audit AUT-004: the agent without its admin
                // socket cannot be unlocked or upgraded — an ERROR and a
                // signed record, not a WARN.
                error!(
                    error = %e,
                    path = %cli.admin_pub.display(),
                    "admin pub key file missing or invalid; admin socket disabled"
                );
                attest_degraded(audit_log.as_ref(), &format!("admin socket disabled: {e:#}"));
            }
        }
    } else {
        error!(
            socket = %cli.admin_socket.display(),
            "admin socket NOT started: no NetworkIsolator (combat ruleset missing, see above) — \
             the watchdog STATUS ping will fail until the ruleset is installed and the agent restarted"
        );
    }
}
