//! The state files, bootstrapped before the attach (R11a, lab PR 261: from
//! `main.rs`'s `run`).

use tracing::{info, warn};

use super::cli::Cli;

/// What [`bootstrap`] found. Only [`bootstrap`] builds one (`_once` is
/// private to this module): the attach takes it (R11b, lab PR 262: the
/// plan's `attach(&IntegrityVerified, &StateReady)`), so the deny hooks
/// never attach before the files they protect were bootstrapped.
pub(crate) struct StateReady {
    /// Lab PR 218: the previous agent's hooks may close the agent's files to
    /// this process until the attach registers it (the audit preflight).
    pub(crate) early_registration_failed: bool,
    _once: (),
}

/// The state files, before the attach (Tappa 8 A14): the agent registered
/// in the pinned PROTECTED_PIDS first (EBPF-015), then the key, the audit
/// log, the FIM, detection, status, canary and network logs and the head
/// anchor bootstrapped, so the deny hooks protect their inodes from the
/// moment they attach. R11b (lab PR 262): `preflight_refused`, the
/// preflight refused the start (the eBPF object, the state directory, the
/// BTF offsets): the registration only (the refusal is signed under the
/// previous agent's hooks, then withdrawn), no file (review #466 F8: the
/// refusal's signature makes what it needs, the key and the chain).
pub(crate) fn bootstrap(
    cli: &Cli,
    heads_file: &std::path::Path,
    preflight_refused: bool,
    signing_key: &northnarrow_agent::keys::BootKey,
) -> StateReady {
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

    if preflight_refused {
        warn!(
            "state files not bootstrapped: the preflight refused the start (signed, then exit, \
             before anything is loaded)"
        );
        return StateReady {
            early_registration_failed,
            _once: (),
        };
    }
    // Tappa 8 A14 (B4): bootstrap the four /etc/northnarrow/ files
    // BEFORE the sensor multiplexer attaches the LSM hooks, so the
    // hooks see their inodes in PROTECTED_INODES the moment they
    // fire. agent_id + signing key bootstraps were previously done
    // post-attach (line ~360); moved here so the LSM-protected
    // window starts at boot rather than at "first signed admin op".
    // audit.log is created as a zero-byte placeholder if absent
    // (first append writes the genesis entry).
    // The review of #468, R4: the start's one load of its key, as the
    // preflight decided it — the key there (never minted, the file the check
    // saw), or a first install's, minted once —; every chain takes a copy.
    if let Err(e) = signing_key.load() {
        match e {
            // External audit EVD-001: on a restart the previous instance's
            // pinned hooks close the key to a process not yet registered
            // (the early registration above failed); the decision is kept
            // and the key read at its next use, after the attach.
            northnarrow_agent::keys::NoKey::Closed(_) => info!(
                path = %cli.signing_key_file.display(),
                "agent signing key closed to this process until it is registered with the \
                 anti-tamper hooks — read after the attach"
            ),
            // Review #466 F4: the integrity phase's audit check refuses the
            // start on it (unless NN_AUDIT_ALLOW_UNWRITABLE=1).
            northnarrow_agent::keys::NoKey::Failed(why) => warn!(
                error = %why,
                path = %cli.signing_key_file.display(),
                "agent signing key cannot be loaded pre-attach — the audit check refuses the \
                 start unless NN_AUDIT_ALLOW_UNWRITABLE=1; nothing is minted"
            ),
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
        _once: (),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;

    use super::*;

    /// The state files' flags, every one in `dir`.
    fn cli(dir: &Path) -> Cli {
        let _env = super::super::cli::TEST_ENV.lock();
        let mut args = vec!["northnarrow-agent".to_string()];
        for (flag, file) in [
            ("--agent-id-file", "agent_id"),
            ("--admin-pub", "admin.pub"),
            ("--signing-key-file", "agent.sig.key"),
            ("--audit-log-file", "audit.log"),
            ("--fim-baseline-file", "fim_baseline.jsonl"),
            ("--fim-drift-file", "fim_drift.jsonl"),
            ("--detections-file", "detections/detections.jsonl"),
            ("--status-events-file", "detections/status_events.jsonl"),
            ("--canary-registry-file", "canary_registry.jsonl"),
            ("--canary-access-file", "canary_access.jsonl"),
            ("--netflow-file", "netflow.jsonl"),
            ("--netflow-listeners-file", "netflow_listeners.jsonl"),
        ] {
            args.push(flag.to_string());
            args.push(dir.join(file).to_string_lossy().into_owned());
        }
        Cli::try_parse_from(args).expect("a command line with the test's paths")
    }

    /// Review #466 F8: a start the preflight refused (the eBPF object, the
    /// state directory, the BTF offsets) bootstraps no state file before its
    /// signed refusal; any other start does.
    #[test]
    fn a_refused_preflight_bootstraps_no_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let cli = cli(dir.path());
        let heads = dir.path().join("chain_heads.json");
        let key = northnarrow_agent::keys::BootKey::decided(
            northnarrow_agent::boot::checks::KeyDecision::first_install_for_tests(
                &cli.signing_key_file,
            ),
        );
        bootstrap(&cli, &heads, true, &key);
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(left.is_empty(), "{left:?}");
        bootstrap(&cli, &heads, false, &key);
        for made in [
            "agent.sig.key",
            "audit.log",
            "fim_baseline.jsonl",
            "netflow.jsonl",
        ] {
            assert!(dir.path().join(made).exists(), "{made}");
        }
    }

    /// The review of #468, R4: the key the preflight decided present and
    /// gone before the bootstrap's one load — hidden by a mount laid during
    /// the start, every piece of evidence with it — is not minted: the load
    /// fails, the audit check refuses the start (review #466 F4), no file
    /// is written at the key's name or its public half's, and no later
    /// phase gets a key.
    #[test]
    fn a_key_gone_between_the_check_and_the_load_is_never_minted() {
        let dir = tempfile::tempdir().unwrap();
        let cli = cli(dir.path());
        let heads = dir.path().join("chain_heads.json");
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
            .unwrap();
        let mut boot = northnarrow_agent::boot::BootSequence::for_tests();
        let decision =
            northnarrow_agent::boot::checks::KeyDecision::present_for_tests(&cli.signing_key_file);
        let key = northnarrow_agent::keys::BootKey::decided(decision);
        let public = northnarrow_agent::keys::verifying_key_path(&cli.signing_key_file);
        std::fs::remove_file(&cli.signing_key_file).unwrap();
        std::fs::remove_file(&public).unwrap();
        bootstrap(&cli, &heads, false, &key);
        assert!(!cli.signing_key_file.exists(), "a key minted");
        assert!(!public.exists(), "a public half published");
        let audit = northnarrow_agent::boot::checks::audit_log(
            &mut boot,
            &cli.audit_log_file,
            &key,
            [7; 16],
            false,
        )
        .unwrap();
        assert!(
            matches!(&audit.open, northnarrow_agent::boot::checks::AuditOpen::NoKey(w)
                if w.contains("refusing to mint")),
            "{:?}",
            audit.open
        );
        assert!(
            audit.fatal || std::env::var("NN_AUDIT_ALLOW_UNWRITABLE").is_ok(),
            "refused"
        );
        assert!(key.signer().is_err(), "a later phase got a key");
        assert!(!cli.signing_key_file.exists(), "a key minted");
    }
}
