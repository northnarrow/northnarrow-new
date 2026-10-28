//! The agent's identity, read once, and the overlay gate on it (R11a, lab
//! PR 261: from `main.rs`'s `run`).

use std::sync::Arc;

use anyhow::Result;
use northnarrow_agent::agent_id;
use northnarrow_agent::boot::{BootSequence, BootStep};

use super::cli::Cli;

/// What [`resolve`] read. Only [`resolve`] builds one (`_once` is private
/// to this module), `run` calls it once and it is the start's one caller
/// of `agent_id::resolve` (the start's tests hold both): the phases after
/// it take the agent's id from this value (MAIN-009; R11a, lab PR 261:
/// the plan's "Identity si costruisce una volta sola").
pub(crate) struct Identity {
    /// The agent's identity, read once (MAIN-009).
    pub(crate) identity: agent_id::AgentIdentity,
    /// Its id: every consumer takes this binding.
    pub(crate) agent_id: [u8; 16],
    /// The operators' signed overlays, verified against that id.
    pub(crate) overlay_gate: Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    _once: (),
}

/// The agent's identity, read once (MAIN-009), and the signed overlays'
/// gate on it (Tappa 10.8).
pub(crate) fn resolve(
    cli: &Cli,
    boot: &mut BootSequence,
    rollback_floor: northnarrow_agent::config::overlay_floor::RollbackFloor,
) -> Result<Identity> {
    // Tappa 8 A3 + A8: the per-install agent UUID, the third anti-replay
    // layer of the signed-payload verify path (design §6.4 layer 3). Read
    // (or, on the first start, minted) here, before the attach, so its
    // inode is in PROTECTED_INODES from boot.
    //
    // External audit MAIN-009 (NN-AUD-251): the one read of this boot. The
    // overlay gate, the audit log, the chains and the admin plane all take
    // `agent_id` from it (a second read used to feed the admin plane, and
    // both fell back to the all-zero id the test fixtures sign with). A file
    // that cannot be used gives a per-boot random id — ERROR now, a signed
    // `subsystem_degraded` once the audit log is open — so nothing signed
    // for another install or for zero verifies; the legacy unlock does not
    // bind the id. A minted id or one that differs from the audit chain's
    // last row is signed there too (EVD-020, `attest_identity`).
    let identity = agent_id::resolve(&cli.agent_id_file);
    let agent_id = identity.id;
    boot.done(BootStep::Identity)?;

    // Tappa 10.8 — signed operator overlays: every `*.local` below is read
    // only if an admin key with `config-manage` signed its exact content
    // (`<overlay>.sig`); otherwise the shipped defaults are used for that
    // list and the refusal is recorded once the audit log is open.
    let overlay_gate = Arc::new(northnarrow_agent::config::overlay_auth::OverlayGate::new(
        &cli.admin_pub,
        agent_id,
        rollback_floor,
    ));
    Ok(Identity {
        identity,
        agent_id,
        overlay_gate,
        _once: (),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;
    use northnarrow_agent::agent_id::IdentitySource;
    use northnarrow_agent::config::overlay_floor::RollbackFloor;

    use super::*;

    fn cli(dir: &Path) -> Cli {
        let _env = super::super::cli::TEST_ENV.lock();
        let arg = |name: &str| dir.join(name).to_string_lossy().into_owned();
        Cli::try_parse_from([
            "northnarrow-agent".to_string(),
            "--agent-id-file".to_string(),
            arg("agent_id"),
            "--admin-pub".to_string(),
            arg("admin.pub"),
        ])
        .expect("a command line with the test's paths")
    }

    /// The identity phase (R11a, lab PR 261): a first start mints the id
    /// and writes it, and every value the phase gives — the identity, the
    /// id the later phases take — is that file's; the next start reads the
    /// same id back. The step is recorded in the boot sequence.
    #[test]
    fn the_phase_reads_the_identity_and_gives_its_id() {
        let dir = tempfile::tempdir().unwrap();
        let cli = cli(dir.path());
        let floor = || RollbackFloor::scan(&dir.path().join("audit.log"), &dir.path().join("key"));

        let mut boot = BootSequence::new();
        let first = resolve(&cli, &mut boot, floor()).expect("the identity phase");
        assert!(boot.has_done(BootStep::Identity));
        assert!(matches!(first.identity.source, IdentitySource::Minted));
        assert_eq!(first.agent_id, first.identity.id);
        let on_disk = std::fs::read_to_string(dir.path().join("agent_id")).unwrap();
        assert_eq!(on_disk, format!("{}\n", hex::encode(first.agent_id)));

        let mut boot = BootSequence::new();
        let again = resolve(&cli, &mut boot, floor()).expect("the identity phase");
        assert!(matches!(again.identity.source, IdentitySource::Loaded));
        assert_eq!(again.agent_id, first.agent_id);
        assert_eq!(again.identity.id, first.agent_id);
    }
}
