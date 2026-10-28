//! The state files, bootstrapped before the attach (R11a, lab PR 261: from
//! `main.rs`'s `run`).

use tracing::{info, warn};

use super::cli::Cli;

/// What [`bootstrap`] found.
pub(crate) struct StateReady {
    /// Lab PR 218: the previous agent's hooks may close the agent's files to
    /// this process until the attach registers it (the audit preflight).
    pub(crate) early_registration_failed: bool,
}

/// The state files, before the attach (Tappa 8 A14): the agent registered
/// in the pinned PROTECTED_PIDS first (EBPF-015), then the key, the audit
/// log, the FIM, detection, status, canary and network logs and the head
/// anchor bootstrapped, so the deny hooks protect their inodes from the
/// moment they attach.
pub(crate) fn bootstrap(cli: &Cli, heads_file: &std::path::Path) -> StateReady {
    // External audit EBPF-015: the predecessor's pinned deny hooks refuse
    // a new entry in the agent's directories to a process not yet
    // registered — the files bootstrapped below when one is missing, a map
    // pin the eBPF load makes. Register in the pinned PROTECTED_PIDS first;
    // anti_tamper::attach does it again, with the stale-pid scan.
    // Lab PR 218: whether the previous hooks may close the agent's files to
    // this process until the attach registers it (the audit preflight).
    let early_registration_failed = match northnarrow_agent::anti_tamper::preregister_self(
        std::path::Path::new(northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT),
    ) {
        Ok(true) => {
            info!(
                "anti-tamper: registered in the pinned PROTECTED_PIDS before the bootstraps \
                 (a previous agent's hooks are attached)"
            );
            false
        }
        Ok(false) => false,
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "anti-tamper: early registration in PROTECTED_PIDS failed — a file or map pin \
                 this boot must recreate before the attach is refused by the previous hooks"
            );
            true
        }
    };

    // Tappa 8 A14 (B4): bootstrap the four /etc/northnarrow/ files
    // BEFORE the sensor multiplexer attaches the LSM hooks, so the
    // hooks see their inodes in PROTECTED_INODES the moment they
    // fire. agent_id + signing key bootstraps were previously done
    // post-attach (line ~360); moved here so the LSM-protected
    // window starts at boot rather than at "first signed admin op".
    // audit.log is created as a zero-byte placeholder if absent
    // (first append writes the genesis entry).
    if let Err(e) =
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
    {
        // External audit EVD-001: on a restart the previous instance's
        // pinned hooks close the key to a process not yet registered (the
        // early registration above failed); the loads after the attach
        // read it.
        let refused = e
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied);
        if refused {
            info!(
                path = %cli.signing_key_file.display(),
                "agent signing key closed to this process until it is registered with the \
                 anti-tamper hooks — read after the attach"
            );
        } else {
            warn!(
                error = %e,
                path = %cli.signing_key_file.display(),
                "agent signing key bootstrap failed pre-attach — audit log will be \
                 unsigned this boot"
            );
        }
    }
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_audit_log(&cli.audit_log_file)
    {
        warn!(
            error = %e,
            path = %cli.audit_log_file.display(),
            "audit log bootstrap failed pre-attach — file will be lazily created \
             on first append (and protected only from agent restart onwards)"
        );
    }
    // Tappa 9 C7: bootstrap the two FIM logs pre-attach for the
    // same reason audit.log gets it — STATE_PROTECTED_FILES needs
    // an inode to register against before LSM hooks come up. A
    // present file is left untouched (existing chain preserved).
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_fim_log(&cli.fim_baseline_file)
    {
        warn!(
            error = %e,
            path = %cli.fim_baseline_file.display(),
            "fim baseline log bootstrap failed pre-attach — file will be lazily \
             created on first append (and unprotected this boot)"
        );
    }
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_fim_log(&cli.fim_drift_file)
    {
        warn!(
            error = %e,
            path = %cli.fim_drift_file.display(),
            "fim drift log bootstrap failed pre-attach — file will be lazily \
             created on first append (and unprotected this boot)"
        );
    }
    // Tappa 9.0.a: bootstrap the detection chainlog pre-attach (creates
    // the detections/ sub-dir + a zero-byte active file) — same inode-
    // registration rationale as the FIM / canary logs.
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_detections_log(&cli.detections_file)
    {
        warn!(
            error = %e,
            path = %cli.detections_file.display(),
            "detections log bootstrap failed pre-attach — file will be lazily \
             created on first detection (and unprotected this boot)"
        );
    }
    // Tappa 9.0.c: bootstrap the status-event chainlog pre-attach (same
    // detections/ dir, sibling of detections.jsonl) — same inode-
    // registration rationale.
    if let Err(e) = northnarrow_agent::anti_tamper::filesystem::bootstrap_status_events_log(
        &cli.status_events_file,
    ) {
        warn!(
            error = %e,
            path = %cli.status_events_file.display(),
            "status-events log bootstrap failed pre-attach — file will be lazily \
             created on first triage (and unprotected this boot)"
        );
    }
    // Tappa 9.5 K7: bootstrap the two canary state logs pre-attach
    // for the same reason as the FIM logs — STATE_PROTECTED_FILES
    // needs an inode to register against before LSM hooks come up.
    // A present file is left untouched (existing canary registry +
    // access chain preserved across restarts).
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_canary_log(&cli.canary_registry_file)
    {
        warn!(
            error = %e,
            path = %cli.canary_registry_file.display(),
            "canary registry log bootstrap failed pre-attach — file will be lazily \
             created on first deploy (and unprotected this boot)"
        );
    }
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_canary_log(&cli.canary_access_file)
    {
        warn!(
            error = %e,
            path = %cli.canary_access_file.display(),
            "canary access log bootstrap failed pre-attach — file will be lazily \
             created on first trip (and unprotected this boot)"
        );
    }
    // Lab PR 160: the head anchor, for the same inode-registration reason.
    if let Err(e) = northnarrow_agent::anti_tamper::filesystem::bootstrap_chain_heads(heads_file) {
        warn!(
            error = %e,
            path = %heads_file.display(),
            "chain heads bootstrap failed pre-attach — the anchor is created at its first \
             write (and protected from the next start)"
        );
    }
    // Tappa 10 N8: bootstrap the NetFlow chain log pre-attach for
    // the same reason as the FIM + canary logs — STATE_PROTECTED_FILES
    // needs an inode to register against before LSM hooks come up.
    // A present file is left untouched (existing NetFlow chain
    // preserved across restarts). N7's `dispatch_net_flows` already
    // tolerates an absent file, but PROTECTED_INODES does not, so
    // we bootstrap here to close the brief race window on first boot.
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_netflow_log(&cli.netflow_file)
    {
        warn!(
            error = %e,
            path = %cli.netflow_file.display(),
            "netflow log bootstrap failed pre-attach — file will be lazily \
             created on first flow close (and unprotected this boot)"
        );
    }
    // Tappa 10 N9: bootstrap the NetListener chain log pre-attach
    // for the same reason — STATE_PROTECTED_FILES needs an inode
    // before LSM hooks come up. A present file is left untouched.
    if let Err(e) = northnarrow_agent::anti_tamper::filesystem::bootstrap_netflow_listeners_log(
        &cli.netflow_listeners_file,
    ) {
        warn!(
            error = %e,
            path = %cli.netflow_listeners_file.display(),
            "netflow_listeners log bootstrap failed pre-attach — file will be \
             lazily created on first listener event (and unprotected this boot)"
        );
    }
    StateReady {
        early_registration_failed,
    }
}
