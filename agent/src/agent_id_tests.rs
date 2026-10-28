//! The agent reads its identity once (MAIN-009): a scan of its `main.rs`.
//! Wave 4 restructure, R09a (lab PR 253): cut verbatim from the tests of
//! `agent_id`, which leaves for nn-linux; the scan reads the agent binary's
//! source, so it stays with it.

/// MAIN-009: the agent reads its identity once and every consumer gets
/// that value — no second read, no zero fallback in `main.rs`.
#[test]
fn the_agent_reads_its_identity_once() {
    let main = include_str!("main.rs");
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
