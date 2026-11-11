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

/// The machine of [`loopback_burst_after_another_class_stays_engaged`]:
/// pid 42 of `app.service` (no login), its combat entries heard.
fn service_machine(
    tmp: &tempfile::TempDir,
) -> (
    PostureMachine,
    Arc<parking_lot::Mutex<Vec<super::CombatEntry>>>,
) {
    use super::{AuthSessionTracker, CombatEntry, ExemptPids};
    let d = tmp.path().join("42");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("cgroup"), "0::/system.slice/app.service\n").unwrap();
    std::fs::write(d.join("loginuid"), "4294967295").unwrap();
    let heard = Arc::new(parking_lot::Mutex::new(Vec::<CombatEntry>::new()));
    let h = Arc::clone(&heard);
    let m = PostureMachine::new_with_hooks_and_exempt_and_auth(
        Arc::new(move |e: &CombatEntry| h.lock().push(e.clone())),
        Arc::new(|_, _| Ok(String::new())),
        ExemptPids::default(),
        AuthSessionTracker::new(tmp.path()),
    );
    (m, heard)
}

/// Bug hunt 1.3, BUG41 (downstream): twenty connects to 127.0.0.1:443 by
/// pid 42 of a service, after an offensive-tool exec in the same service
/// (ENGAGED), never left the host: no ExfiltrationPattern, so the posture
/// stays ENGAGED and no combat entry names pid 42. The triage's design
/// test asserted the old path (COMBAT, an entry with pid 42 as the
/// offender, then INVESTIGATE and NEUTRALIZE's kill); it is inverted here.
/// The control: the same burst to a public address still corroborates the
/// exec's class up to COMBAT.
#[test]
fn loopback_burst_after_another_class_stays_engaged() {
    use nn_model::posture_types::TriggerType;
    let burst = |m: &PostureMachine, dst: [u8; 4]| {
        let recent: Vec<Event> = (0..20u64).map(|i| tcp_v4(42, dst, 443, i + 1)).collect();
        m.observe(&tcp_v4(42, dst, 443, 100), &recent);
    };
    for lo in [[127, 0, 0, 1], [127, 1, 2, 3], [169, 254, 169, 254]] {
        let tmp = tempfile::TempDir::new().unwrap();
        let (m, heard) = service_machine(&tmp);
        m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
        assert_eq!(m.current_kind(), PostureKind::Engaged);
        burst(&m, lo);
        assert_eq!(m.current_kind(), PostureKind::Engaged, "{lo:?}");
        assert!(heard.lock().is_empty(), "{lo:?}: {:?}", heard.lock());
    }
    // control: a public destination still reaches COMBAT
    let tmp = tempfile::TempDir::new().unwrap();
    let (m, heard) = service_machine(&tmp);
    m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
    burst(&m, [203, 0, 113, 9]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    let heard = heard.lock().clone();
    assert_eq!(heard.len(), 1);
    let super::CombatCause::Trigger(t) = &heard[0].cause else {
        panic!("{:?}", heard[0].cause)
    };
    assert_eq!(t.trigger, TriggerType::ExfiltrationPattern);
    assert!(!t.locked);
    assert_eq!(heard[0].offender.map(|p| p.pid), Some(42));
}

// ── Bug hunt 3 (edition 1.4) triage, group A: BUG-84, BUG-94 ────────────

/// BUG-84: a force-posture to the state the machine is already in is
/// promised a no-op (`admin_force_state_with_token`'s doc: "Same-direction
/// (before == target) is a no-op"; `ForceOutcome::state`: "unchanged when
/// `from` was already the target"). On main the state is rewritten before
/// the `before == target` check: the decay timers restart and an unlocked
/// COMBAT becomes locked, with no transition logged.
mod bug84 {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::posture::clock::{Clock, TestClock};
    use crate::posture::state::PostureState;
    use crate::posture::ForceOutcome;

    const MIN: Duration = Duration::from_secs(60);

    fn clock() -> Arc<TestClock> {
        Arc::new(TestClock::at(
            UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        ))
    }

    fn force(m: &PostureMachine, to: PostureKind) -> ForceOutcome {
        m.admin_force_state_with_token((), to, true)
            .expect("force-posture")
    }

    fn timers(s: &PostureState) -> Option<(std::time::Instant, std::time::Instant)> {
        match s {
            PostureState::Alerted {
                since,
                last_trigger,
            }
            | PostureState::Engaged {
                since,
                last_trigger,
            } => Some((*since, *last_trigger)),
            _ => None,
        }
    }

    #[test]
    fn bug84_same_state_force_alerted_keeps_the_decay_deadline() {
        let clock = clock();
        let m = PostureMachine::new().with_clock(clock.clone());
        let t0 = clock.now();
        assert_eq!(force(&m, PostureKind::Alerted).from, PostureKind::Observing);
        let log0 = m.transition_log().len();
        clock.advance(59 * MIN);
        let out = force(&m, PostureKind::Alerted);
        assert_eq!(out.from, PostureKind::Alerted);
        assert_eq!(m.transition_log().len(), log0, "no transition logged");
        assert_eq!(
            (timers(&out.state), timers(&m.current())),
            (Some((t0, t0)), Some((t0, t0))),
            "BUG-84: a force to the current ALERTED rewrote since/last_trigger (t0 = {t0:?})"
        );
        clock.advance(2 * MIN);
        assert_eq!(
            m.tick_decay().map(|s| s.kind()),
            Some(PostureKind::Observing),
            "BUG-84: ALERTED must decay one hour after its last trigger (t0+60min), the no-op \
             force at t0+59min re-armed it"
        );
    }

    #[test]
    fn bug84_same_state_force_engaged_keeps_the_decay_deadline() {
        let clock = clock();
        let m = PostureMachine::new().with_clock(clock.clone());
        force(&m, PostureKind::Engaged);
        clock.advance(24 * 60 * MIN - MIN);
        force(&m, PostureKind::Engaged);
        clock.advance(2 * MIN);
        assert_eq!(
            m.tick_decay().map(|s| s.kind()),
            Some(PostureKind::Alerted),
            "BUG-84: ENGAGED must decay 24 h after its last trigger; the no-op force at \
             t0+23h59 re-armed it"
        );
    }

    /// Case (b): an unlocked (heuristic) COMBAT forced to COMBAT. Whatever
    /// the owner decides (keep it a no-op, as the doc says, or lock it as
    /// an administrator's order — POS-001), the lock must not change
    /// silently: either it stays unlocked, or the change is logged.
    #[test]
    fn bug84_same_state_force_combat_never_locks_silently() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (m, _heard) = service_machine(&tmp);
        let clock = clock();
        let m = m.with_clock(clock.clone());
        m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
        let recent: Vec<Event> = (0..20u64)
            .map(|i| tcp_v4(42, [203, 0, 113, 9], 443, i + 1))
            .collect();
        m.observe(&tcp_v4(42, [203, 0, 113, 9], 443, 100), &recent);
        assert_eq!(m.current_kind(), PostureKind::Combat);
        assert!(!m.is_combat_locked(), "precondition: a heuristic COMBAT");
        let log0 = m.transition_log().len();
        clock.advance(5 * MIN);
        let out = force(&m, PostureKind::Combat);
        assert_eq!(out.from, PostureKind::Combat);
        assert!(
            !m.is_combat_locked() || m.transition_log().len() > log0,
            "BUG-84: force-posture combat on an unlocked COMBAT locked it (ISOLATE now allowed, \
             no quiet-window decay) with nothing in the transition log: {:?}",
            m.current()
        );
    }
}

/// BUG-94: an unlocked COMBAT decays once no escalation signal has been
/// recorded for `COMBAT_QUIET_WINDOW` (30 min, `tick_decay_at`'s doc). The
/// quiet is read from the corroboration ledger's newest entry, and
/// `observe()` prunes the ledger to `CORROBORATION_WINDOW` (15 min) at every
/// event with a hit: an unrelated ALERTED-tier event between 15 and 30 min
/// after the last signal erases it, and the quiet is counted from COMBAT's
/// entry instead.
mod bug94 {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::posture::clock::TestClock;

    const MIN: Duration = Duration::from_secs(60);

    /// pid 42 of `app.service`: an unlocked COMBAT at t0 (an offensive
    /// tool's exec, then a burst of connects to a public address).
    fn unlocked_combat(tmp: &tempfile::TempDir) -> (PostureMachine, Arc<TestClock>) {
        let (m, _heard) = service_machine(tmp);
        let clock = Arc::new(TestClock::at(
            UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        ));
        let m = m.with_clock(clock.clone());
        m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
        let recent: Vec<Event> = (0..20u64)
            .map(|i| tcp_v4(42, [203, 0, 113, 9], 443, i + 1))
            .collect();
        m.observe(&tcp_v4(42, [203, 0, 113, 9], 443, 100), &recent);
        assert_eq!(m.current_kind(), PostureKind::Combat);
        assert!(!m.is_combat_locked());
        (m, clock)
    }

    #[test]
    fn bug94_quiet_window_counts_from_the_last_signal_despite_a_prune() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (m, clock) = unlocked_combat(&tmp);
        // t0+20: a new escalation signal (the offensive tool again)
        clock.advance(20 * MIN);
        m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 200), &[]);
        assert_eq!(m.current_kind(), PostureKind::Combat);
        // t0+36: an unrelated ALERTED-tier event (nmap: Reconnaissance)
        clock.advance(16 * MIN);
        m.observe(&spawn(42, 1, "nmap", "/usr/bin/nmap", 300), &[]);
        // t0+37: the agent's 60 s tick
        clock.advance(MIN);
        let out = m.tick_decay();
        assert!(
            out.is_none(),
            "BUG-94: the unlocked COMBAT decayed to {:?} 17 min after the last escalation \
             signal (promised quiet window: 30 min, until t0+50)",
            out.map(|s| s.kind())
        );
    }

    /// Guard: the same scenario without the unrelated event keeps COMBAT
    /// until 30 min after the last signal (passes on main).
    #[test]
    fn bug94_control_without_the_prune_combat_holds() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (m, clock) = unlocked_combat(&tmp);
        clock.advance(20 * MIN);
        m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 200), &[]);
        clock.advance(17 * MIN);
        assert!(m.tick_decay().is_none());
        clock.advance(14 * MIN);
        assert_eq!(m.tick_decay().map(|s| s.kind()), Some(PostureKind::Engaged));
    }
}

/// Lot 314, the mini-hunt's variant of BUG-84: a lock a later signal
/// acquires on an unlocked COMBAT (a kernel denial: decisive, it locks) is a
/// transition row of its own, COMBAT → COMBAT, naming it — it was a WARN of
/// the journal only, and the transition log said nothing of it.
#[test]
fn a_lock_a_later_signal_acquires_is_a_transition_row() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (m, heard) = service_machine(&tmp);
    m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
    let recent: Vec<Event> = (0..20u64)
        .map(|i| tcp_v4(42, [203, 0, 113, 9], 443, i + 1))
        .collect();
    m.observe(&tcp_v4(42, [203, 0, 113, 9], 443, 100), &recent);
    assert!(!m.is_combat_locked(), "precondition: a heuristic COMBAT");
    let rows = m.transition_log().len();
    assert!(
        m.observe(&fs_protect_denial(42, 200), &[]).is_none(),
        "no change of kind"
    );
    assert!(m.is_combat_locked());
    let log = m.transition_log();
    assert_eq!(log.len(), rows + 1, "one row: {log:?}");
    let row = log.last().unwrap();
    assert_eq!((row.from, row.to), (PostureKind::Combat, PostureKind::Combat));
    assert!(row.reason.starts_with("COMBAT locked: "), "{}", row.reason);
    assert_eq!(heard.lock().len(), 1, "the ladder is not engaged again");
}
