//! The agent reads its identity once (MAIN-009): a scan of its start's
//! code (R11a, lab PR 261: `main.rs` until it was cut into the phases).
//! Wave 4 restructure, R09a (lab PR 253): cut verbatim from the tests of
//! `agent_id`, which leaves for nn-linux; the scan reads the agent binary's
//! source, so it stays with it. R10 (lab PR 259): and nn-admin's read of
//! the identity beside the agent's (MAIN-009, MAIN-010), the two tests of
//! nn-linux's `agent_id` that read both.

/// MAIN-009: the agent reads its identity once and every consumer gets
/// that value — no second read, no zero fallback in the start's code
/// (`main.rs` and the phases cut from it, R11a, lab PR 261).
#[test]
fn the_agent_reads_its_identity_once() {
    let main = crate::boot::start_sources();
    let main = main.as_str();
    assert_eq!(main.matches("agent_id::resolve(").count(), 1);
    assert_eq!(main.matches("agent_id::load_or_bootstrap(").count(), 0);
    assert_eq!(main.matches("agent_id::load_existing(").count(), 0);
    assert!(!main.contains("[0u8; 16]"), "no zero fallback");
    // the overlay gate, the audit log and the admin plane take the one
    // binding
    assert!(main.contains("let agent_id = identity.id;"));
    let gate = main.find("OverlayGate::new(").expect("the overlay gate");
    assert!(
        main[gate..gate + 80].contains("agent_id,"),
        "the overlay gate takes the one binding"
    );
    for consumer in [
        "AuditLog::open(&cli.audit_log_file, key, agent_id)",
        "AdminAuth::load_with_agent_id(&cli.admin_pub, agent_id)",
    ] {
        assert!(main.contains(consumer), "{consumer}");
    }
    // the boot's own entry, and a refused boot's (lab PR 218: one
    // helper, `record_refused_boot`, for every gate)
    assert_eq!(main.matches(".attest_identity(&identity)").count(), 1);
    assert_eq!(main.matches(".attest_identity(identity)").count(), 1);
    assert!(main.contains("AuditLog::open(&cli.audit_log_file, key, identity.id)"));
}

// R10 (lab PR 259): nn-admin's read of the identity (`load_existing`) left
// nn-linux's `agent_id` with nn-admin; these two tests of that module read
// it beside the agent's own (`resolve`, `load_or_bootstrap`), cut verbatim
// with a copy of the helpers they use.

use std::fs;
use std::path::PathBuf;

use nn_admin::agent_id::load_existing;
use tempfile::TempDir;

use crate::agent_id::{load_or_bootstrap, resolve, IdentitySource, AGENT_ID_LEN};

/// Width of the on-disk hex encoding of one [`AGENT_ID_LEN`]-byte value.
const HEX_LEN: usize = AGENT_ID_LEN * 2;

fn fresh_path() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("agent_id");
    (dir, path)
}

/// MAIN-009: the same for nn-admin's read and the agent's boot, which
/// signs as a per-boot id instead.
#[test]
fn an_all_zero_agent_id_is_unavailable_at_boot() {
    let (_dir, path) = fresh_path();
    fs::write(&path, format!("{}\n", "0".repeat(HEX_LEN))).unwrap();
    assert!(load_existing(&path).is_err());
    let r = resolve(&path);
    assert!(matches!(r.source, IdentitySource::Unavailable(_)));
    assert_ne!(r.id, [0u8; AGENT_ID_LEN]);
}

/// MAIN-010: nn-admin's read never mints — a missing file fails naming
/// it and the agent's first start, and nothing is created (not even
/// the directory).
#[test]
fn load_existing_never_mints() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("etc/northnarrow/agent_id");
    let err = load_existing(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains(&path.display().to_string()), "{msg}");
    assert!(msg.contains("first start"), "{msg}");
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());

    let (_d, path) = fresh_path();
    let minted = load_or_bootstrap(&path).unwrap();
    assert_eq!(load_existing(&path).unwrap(), minted);
    fs::write(&path, "zz\n").unwrap();
    let msg = format!("{:#}", load_existing(&path).unwrap_err());
    assert!(msg.contains("corrupted"), "{msg}");
}
