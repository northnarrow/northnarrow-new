//! The machine's tests that call its test-only doors — the legacy boolean
//! release (external audit POS-013, WDG-R02: no build of the library has
//! it) and a clock that moves only when told (lab PR 243). R08a (lab PR
//! 250): cut from the agent's `posture/tests.rs`, where the cross-module
//! tests that wire the agent's rules, ladder and judges stay; these run on
//! the portable test host.

use std::sync::Arc;
use std::thread;

use nn_model::posture_types::PostureKind;
use nn_model::Event;

use super::host::testing::TestHost;
use super::triggers::testutil::{fs_protect_denial, spawn, tcp_v4};
use super::AdminReleaseError;

/// The machine on the portable test host.
type PostureMachine = super::PostureMachine<TestHost>;

#[test]
fn admin_release_unauthorized_is_rejected() {
    let m = PostureMachine::new();
    // Force COMBAT first.
    let recent: Vec<Event> = vec![];
    let focal = fs_protect_denial(42, 1);
    m.observe(&focal, &recent);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert_eq!(
        m.admin_release_combat(false).unwrap_err(),
        AdminReleaseError::Unauthorized
    );
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

#[test]
fn admin_release_authorized_drops_to_engaged() {
    let m = PostureMachine::new();
    let focal = fs_protect_denial(42, 1);
    m.observe(&focal, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    let next = m.admin_release_combat(true).expect("ok");
    assert_eq!(next.kind(), PostureKind::Engaged);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

#[test]
fn admin_release_clears_corroboration_ledger() {
    // posture-2: the signals that justified COMBAT must not keep
    // corroborating the next heuristic after an admin has released.
    let m = PostureMachine::new();
    let focal = fs_protect_denial(42, 1);
    m.observe(&focal, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(
        m.corroboration_len() > 0,
        "the COMBAT-tier signal must have been recorded in the ledger"
    );
    m.admin_release_combat(true).expect("ok");
    assert_eq!(
        m.corroboration_len(),
        0,
        "ledger must be empty after release"
    );
}

#[test]
fn admin_release_when_not_in_combat_errors() {
    let m = PostureMachine::new();
    assert_eq!(
        m.admin_release_combat(true).unwrap_err(),
        AdminReleaseError::NotInCombat
    );
}

#[test]
fn full_recon_to_combat_flow() {
    let m = PostureMachine::new();

    // Phase 1: 3 distinct ports → Reconnaissance → ALERTED.
    let recon_recent = vec![
        tcp_v4(42, [127, 0, 0, 1], 22, 100),
        tcp_v4(42, [127, 0, 0, 1], 80, 200),
    ];
    let recon_focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
    let t1 = m.observe(&recon_focal, &recon_recent);
    assert!(t1.is_some(), "recon should trigger transition");
    assert_eq!(m.current_kind(), PostureKind::Alerted);

    // Phase 2: netcat exec → ExploitAttempt → ENGAGED.
    let nc = spawn(99, 1, "ncat", "/usr/bin/ncat", 400);
    let t2 = m.observe(&nc, &[]);
    assert!(t2.is_some());
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    // Phase 3: exec from /tmp → ConfirmedIntrusion → COMBAT.
    let intrusion = fs_protect_denial(100, 500);
    let t3 = m.observe(&intrusion, &[]);
    assert!(t3.is_some());
    assert_eq!(m.current_kind(), PostureKind::Combat);

    // Phase 4: admin release.
    m.admin_release_combat(true).expect("authorized release");
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    // The transition log should record at least 4 transitions
    // (Observing→Alerted, Alerted→Engaged, Engaged→Combat, Combat→Engaged).
    assert!(m.transition_log().len() >= 4);
}

#[test]
fn concurrent_admin_release_serializes_correctly() {
    let m = Arc::new(PostureMachine::new());
    // Drive into COMBAT.
    let intrusion = fs_protect_denial(100, 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);

    let mut handles = Vec::new();
    for _ in 0..4 {
        let m2 = m.clone();
        handles.push(thread::spawn(move || m2.admin_release_combat(true)));
    }
    let mut oks = 0;
    let mut errs = 0;
    for h in handles {
        match h.join().expect("thread panic") {
            Ok(_) => oks += 1,
            Err(AdminReleaseError::NotInCombat) => errs += 1,
            Err(other) => panic!("unexpected error {:?}", other),
        }
    }
    // Exactly one releaser must have observed Combat; the rest must
    // have seen NotInCombat.
    assert_eq!(oks, 1);
    assert_eq!(errs, 3);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

#[test]
fn transition_log_caps_at_bound() {
    let m = PostureMachine::new();
    // Force many transitions: alternate intrusion+admin release.
    let intrusion = fs_protect_denial(100, 500);
    for _ in 0..300 {
        m.observe(&intrusion, &[]);
        let _ = m.admin_release_combat(true);
    }
    // Cap is 256; we should never exceed it.
    assert!(m.transition_log().len() <= 256);
    // Final state must be ENGAGED (last operation was admin release).
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// Lab PR 243: the machine reads the time through its clock — its timers
/// (here the ALERTED decay) and the wall-clock second of its transition
/// records — never the host's.
#[test]
fn a_machine_runs_on_its_clock() {
    use std::time::{Duration, UNIX_EPOCH};

    use super::clock::TestClock;
    use super::transitions::ALERTED_DECAY;

    let clock = Arc::new(TestClock::at(
        UNIX_EPOCH + Duration::from_secs(1_767_225_600),
    ));
    let m = PostureMachine::new().with_clock(clock.clone());
    m.observe(&spawn(42, 1, "nmap", "/usr/bin/nmap", 1), &[]);
    assert_eq!(m.current_kind(), PostureKind::Alerted);
    clock.advance(ALERTED_DECAY - Duration::from_secs(1));
    assert!(m.tick_decay().is_none());
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        m.tick_decay().map(|s| s.kind()),
        Some(PostureKind::Observing)
    );
    let log = m.transition_log();
    assert_eq!(log[0].unix_ts_secs, 1_767_225_600);
    assert_eq!(log[1].unix_ts_secs, 1_767_225_600 + ALERTED_DECAY.as_secs());
    // Shared already: a later clock is refused, the machine keeps its own.
    let shared = m.clone();
    let other = Arc::new(TestClock::at(UNIX_EPOCH));
    let m = m.with_clock(other);
    m.observe(&spawn(43, 1, "nmap", "/usr/bin/nmap", 2), &[]);
    assert_eq!(
        shared.transition_log().last().unwrap().unix_ts_secs,
        1_767_225_600 + ALERTED_DECAY.as_secs()
    );
}
