//! Cross-module tests: PostureMachine end-to-end behaviour.

use std::sync::Arc;
use std::thread;

use common::posture_types::{PostureKind, TriggerType};
use common::Event;

use super::triggers::testutil::{
    file_open, fs_protect_denial, spawn, spawn_by, spawn_exe_flags, tcp_v4,
};
use super::{AdminReleaseError, AuthSessionTracker, ExemptPids, PostureMachine};

/// External audit POS-005: `/proc/<pid>` of a process with no login uid
/// whose cgroup is `cgroup` (a systemd service, a container).
fn workload_proc(dir: &std::path::Path, pid: u32, cgroup: &str) {
    let d = dir.join(pid.to_string());
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
    std::fs::write(d.join("loginuid"), "4294967295").unwrap();
}

/// A machine reading the fixture `/proc` at `dir`.
fn machine_on(dir: &std::path::Path) -> PostureMachine {
    PostureMachine::new_with_hooks_and_exempt_and_auth(
        Arc::new(|| {}),
        Arc::new(|_| {}),
        ExemptPids::default(),
        AuthSessionTracker::new(dir),
    )
}

/// External audit POS-005: a machine whose pid 42 runs in one service
/// (a signal that cannot be placed corroborates nothing).
fn machine_with_pid_42_in_a_unit() -> (tempfile::TempDir, PostureMachine) {
    let tmp = tempfile::TempDir::new().unwrap();
    workload_proc(tmp.path(), 42, "/system.slice/app.service");
    let m = machine_on(tmp.path());
    (tmp, m)
}

/// BUG-032 — an exfiltration burst: 21 connects (focal + 20) by one pid
/// to a public dst on 443 → `ExfiltrationPattern` (a NeedsCorroboration
/// COMBAT-tier signal).
fn exfil_burst(pid: u32) -> (Event, Vec<Event>) {
    let recent: Vec<Event> = (0..20u64)
        .map(|i| tcp_v4(pid, [203, 0, 113, 9], 443, i + 1))
        .collect();
    (tcp_v4(pid, [203, 0, 113, 9], 443, 100), recent)
}

/// BUG-032 — a lateral-movement burst: 3 distinct RFC1918 hosts on an
/// admin port from one pid → `LateralMovement`.
fn lateral_burst(pid: u32) -> (Event, Vec<Event>) {
    let recent = vec![
        tcp_v4(pid, [10, 0, 0, 1], 22, 1),
        tcp_v4(pid, [10, 0, 0, 2], 22, 2),
    ];
    (tcp_v4(pid, [10, 0, 0, 3], 22, 3), recent)
}

#[test]
fn machine_starts_in_observing() {
    let m = PostureMachine::new();
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

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
fn observe_is_idempotent_when_already_at_target_level() {
    let m = PostureMachine::new();
    // First recon transitions OBSERVING -> ALERTED.
    let recent = vec![
        tcp_v4(42, [127, 0, 0, 1], 22, 100),
        tcp_v4(42, [127, 0, 0, 1], 80, 200),
    ];
    let focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
    let first = m.observe(&focal, &recent);
    assert!(first.is_some());
    // Second recon hit at same level should not produce a new
    // transition record (returns None) but state stays ALERTED.
    let recent2 = vec![
        tcp_v4(42, [127, 0, 0, 1], 22, 1000),
        tcp_v4(42, [127, 0, 0, 1], 80, 2000),
    ];
    let focal2 = tcp_v4(42, [127, 0, 0, 1], 8080, 3000);
    let second = m.observe(&focal2, &recent2);
    assert!(second.is_none());
    assert_eq!(m.current_kind(), PostureKind::Alerted);
}

#[test]
fn observe_ignores_uncorrelated_events() {
    let m = PostureMachine::new();
    let benign = file_open(42, 1000, "/home/user/foo.txt", 0, 1);
    let out = m.observe(&benign, &[]);
    assert!(out.is_none());
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

#[test]
fn concurrent_observe_and_read_is_safe() {
    let m = Arc::new(PostureMachine::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let m2 = m.clone();
        handles.push(thread::spawn(move || {
            let recent = vec![
                tcp_v4(42, [127, 0, 0, 1], 22, 100),
                tcp_v4(42, [127, 0, 0, 1], 80, 200),
            ];
            let focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
            for _ in 0..50 {
                m2.observe(&focal, &recent);
            }
        }));
    }
    for _ in 0..4 {
        let m2 = m.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                let _ = m2.current_kind();
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panic");
    }
    // Final state must be Alerted (recon detected at least once).
    assert_eq!(m.current_kind(), PostureKind::Alerted);
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

#[test]
fn combat_hook_fires_on_first_combat_entry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    let m = PostureMachine::new_with_combat_hook(Arc::new(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    }));

    // Reconnaissance only takes us to ALERTED — hook must not fire.
    let recon_recent = vec![
        tcp_v4(42, [127, 0, 0, 1], 22, 100),
        tcp_v4(42, [127, 0, 0, 1], 80, 200),
    ];
    let recon_focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
    m.observe(&recon_focal, &recon_recent);
    assert_eq!(m.current_kind(), PostureKind::Alerted);
    assert_eq!(count.load(Ordering::SeqCst), 0);

    // A kernel anti-tamper denial (Decisive) crosses into COMBAT —
    // hook fires exactly once.
    let intrusion = fs_protect_denial(100, 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

// ─── BUG-032: corroboration / progression ──────────────────────────

#[test]
fn single_blunt_combat_signal_caps_at_engaged() {
    // A lone ExfiltrationPattern (the harness-egress shape) escalates to
    // ENGAGED (alert), NOT COMBAT (auto-isolation). This is the core
    // precision win + the documented single-vector limit.
    let m = PostureMachine::new();
    let (focal, recent) = exfil_burst(42);
    let out = m.observe(&focal, &recent);
    assert!(out.is_some(), "exfil shape must transition");
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "a single blunt COMBAT-tier signal must cap at ENGAGED"
    );
}

/// External audit SNS-009: a ring that lost events raises ALERTED, is never
/// recorded as corroboration, and a lone COMBAT-tier heuristic after it
/// still stops at ENGAGED. Nothing stronger than ALERTED can be raised
/// without an event.
#[test]
fn telemetry_loss_targets_alerted_and_never_corroborates() {
    let m = PostureMachine::new();
    let out = m.raise_signal(TriggerType::TelemetryLoss, "exec ring dropped 500 events");
    assert_eq!(out.map(|s| s.kind()), Some(PostureKind::Alerted));
    assert_eq!(m.current_kind(), PostureKind::Alerted);
    assert_eq!(
        m.corroboration_len(),
        0,
        "telemetry loss must not enter the ledger"
    );
    let last = m.transition_log().pop().expect("transition recorded");
    assert_eq!(last.trigger, Some(TriggerType::TelemetryLoss));

    // A second loss at the same level only re-arms the decay.
    assert!(m
        .raise_signal(TriggerType::TelemetryLoss, "again")
        .is_none());

    let (ef, er) = exfil_burst(42);
    m.observe(&ef, &er);
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "telemetry loss must not corroborate a COMBAT-tier heuristic"
    );

    // Escalation without an event is refused.
    let fresh = PostureMachine::new();
    assert!(fresh
        .raise_signal(TriggerType::AntiTamperDenial, "forged")
        .is_none());
    assert_eq!(fresh.current_kind(), PostureKind::Observing);
}

/// External audit POS-001 (NN-AUD-002): an update's HTTPS burst, then
/// three internal SSH sessions — two network patterns any unprivileged
/// user produces — are one kind of behaviour and stay at ENGAGED.
#[test]
fn unprivileged_pair_does_not_reach_combat() {
    let (_tmp, m) = machine_with_pid_42_in_a_unit();
    let (ef, er) = exfil_burst(42);
    m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    let (lf, lr) = lateral_burst(42);
    m.observe(&lf, &lr);
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "two network patterns must not corroborate each other"
    );
}

/// External audit POS-001: evidence of another kind — an offensive tool
/// run, then an exfiltration burst — still corroborates to COMBAT, but an
/// unlocked one: heuristics alone never let the ladder isolate.
#[test]
fn cross_class_pair_reaches_unlocked_combat() {
    let (_tmp, m) = machine_with_pid_42_in_a_unit();
    m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    let (ef, er) = exfil_burst(42);
    m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(!m.is_combat_locked(), "heuristic COMBAT must not be locked");
}

/// External audit POS-001: a kernel-adjudicated denial still reaches a
/// locked COMBAT, and a heuristic after it keeps it locked.
#[test]
fn decisive_plus_heuristic_reaches_combat() {
    let m = PostureMachine::new();
    m.observe(&fs_protect_denial(42, 1), &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(m.is_combat_locked());
    let (ef, er) = exfil_burst(42);
    m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(m.is_combat_locked());
}

/// External audit POS-001: a heuristic COMBAT locks once evidence an
/// unprivileged user cannot produce arrives — here a kernel denial.
#[test]
fn unlocked_combat_locks_on_decisive_evidence() {
    let (_tmp, m) = machine_with_pid_42_in_a_unit();
    m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
    let (ef, er) = exfil_burst(42);
    m.observe(&ef, &er);
    assert!(!m.is_combat_locked());
    m.observe(&fs_protect_denial(42, 200), &[]);
    assert!(m.is_combat_locked());
}

/// External audit POS-001: root changing a system file outside an
/// administrator's session is evidence an unprivileged user cannot
/// produce — the COMBAT it corroborates is locked. The same unit written
/// through a user's crontab (uid 1000) leaves it unlocked.
#[test]
fn root_system_file_change_locks_combat() {
    for (uid, path, locked) in [
        (0, "/etc/systemd/system/evil.service", true),
        (1000, "/var/spool/cron/crontabs/u", false),
    ] {
        let tmp = tempfile::TempDir::new().unwrap();
        workload_proc(tmp.path(), 900, "/system.slice/cryptor.service");
        let m = machine_on(tmp.path());
        let _ = m.observe(&spawn(900, 1, "cryptor", "/usr/local/bin/cryptor", 1), &[]);
        let _ = m.observe(&spawn(901, 900, "nc", "/usr/bin/nc", 2), &[]);
        assert_eq!(m.current_kind(), PostureKind::Engaged);
        let _ = m.observe(&file_open(900, uid, path, 1, 300), &[]);
        assert_eq!(m.current_kind(), PostureKind::Combat, "{path}");
        assert_eq!(m.is_combat_locked(), locked, "{path}");
    }
}

/// External audit POS-001: an unlocked COMBAT decays to ENGAGED after a
/// quiet window (the decay hook stands the ladder down); a locked one
/// never decays.
#[test]
fn unlocked_combat_decays_once_quiet() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::transitions::COMBAT_QUIET_WINDOW;

    let (_tmp, m) = machine_with_pid_42_in_a_unit();
    let decays = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&decays);
    m.on_combat_decay(Arc::new(move || {
        d.fetch_add(1, Ordering::SeqCst);
    }));
    m.observe(&spawn(42, 1, "nc", "/usr/bin/nc", 1), &[]);
    let (ef, er) = exfil_burst(42);
    m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);

    let now = Instant::now();
    assert!(m
        .tick_decay_at(now + COMBAT_QUIET_WINDOW - Duration::from_secs(60))
        .is_none());
    assert_eq!(m.current_kind(), PostureKind::Combat);
    let next = m.tick_decay_at(now + COMBAT_QUIET_WINDOW + Duration::from_secs(1));
    assert_eq!(next.map(|s| s.kind()), Some(PostureKind::Engaged));
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    assert_eq!(decays.load(Ordering::SeqCst), 1);

    let m = PostureMachine::new();
    m.observe(&fs_protect_denial(42, 1), &[]);
    assert!(m
        .tick_decay_at(Instant::now() + COMBAT_QUIET_WINDOW * 4)
        .is_none());
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

#[test]
fn decisive_anti_tamper_denial_reaches_combat_alone() {
    // A kernel-adjudicated FsProtectDenial (AntiTamperDenial, Decisive)
    // reaches COMBAT on its own — no corroboration required.
    let m = PostureMachine::new();
    let out = m.observe(&fs_protect_denial(7, 1), &[]);
    assert!(out.is_some());
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

#[test]
fn combat_hook_does_not_refire_while_already_in_combat() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    let m = PostureMachine::new_with_combat_hook(Arc::new(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    }));

    let intrusion = fs_protect_denial(100, 500);
    m.observe(&intrusion, &[]);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // A second intrusion event while already in COMBAT must not
    // re-engage isolation — apply_trigger short-circuits and observe
    // returns None, so the upward-edge check never fires the hook.
    let again = spawn(101, 1, "evil2", "/tmp/payload2", 600);
    let result = m.observe(&again, &[]);
    assert!(result.is_none(), "no transition expected while in COMBAT");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn default_new_has_no_combat_hook() {
    // Smoke test: PostureMachine::new() still constructs a working
    // machine that can reach COMBAT without panicking. Older tests
    // implicitly rely on this; making it an explicit assertion
    // protects against accidental hook-required regressions.
    let m = PostureMachine::new();
    let intrusion = fs_protect_denial(100, 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

// ─── admin_release_combat_with_token (Tappa 7 task 7 / Tappa 8) ─────

#[test]
fn admin_release_with_token_transitions_combat_to_alerted() {
    let m = PostureMachine::new();
    let intrusion = fs_protect_denial(100, 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);

    let token = crate::anti_tamper::_test_mint_unlock_token();
    let new_state = m
        .admin_release_combat_with_token(token)
        .expect("token release should succeed from Combat");
    assert_eq!(new_state.kind(), PostureKind::Alerted);
    assert_eq!(m.current_kind(), PostureKind::Alerted);
    // last_admin_action populated.
    assert!(m.last_admin_action_secs_ago().is_some());
}

#[test]
fn admin_release_with_token_fails_when_not_in_combat() {
    let m = PostureMachine::new();
    assert_eq!(m.current_kind(), PostureKind::Observing);
    let token = crate::anti_tamper::_test_mint_unlock_token();
    let err = m.admin_release_combat_with_token(token).unwrap_err();
    assert_eq!(err, super::AdminReleaseError::NotInCombat);
    // last_admin_action stays None — failed releases must not stamp it.
    assert!(m.last_admin_action_secs_ago().is_none());
}

#[test]
fn release_hook_fires_with_token_on_successful_release() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    let entry_hook: super::CombatEntryHook = Arc::new(|| {});
    let release_hook: super::CombatReleaseHook = Arc::new(move |_token| {
        // The token is consumed by-value into the closure body —
        // dropping it here exercises the production ownership flow.
        c2.fetch_add(1, Ordering::SeqCst);
    });
    let m = PostureMachine::new_with_hooks(entry_hook, release_hook);
    let intrusion = fs_protect_denial(100, 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert_eq!(count.load(Ordering::SeqCst), 0);

    let token = crate::anti_tamper::_test_mint_unlock_token();
    let _ = m.admin_release_combat_with_token(token).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn release_hook_does_not_fire_on_not_in_combat() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    let entry_hook: super::CombatEntryHook = Arc::new(|| {});
    let release_hook: super::CombatReleaseHook = Arc::new(move |_token| {
        c2.fetch_add(1, Ordering::SeqCst);
    });
    let m = PostureMachine::new_with_hooks(entry_hook, release_hook);
    // Never entered Combat — release must reject + leave hook untouched.
    let token = crate::anti_tamper::_test_mint_unlock_token();
    assert!(m.admin_release_combat_with_token(token).is_err());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn last_admin_action_secs_ago_returns_none_before_release() {
    let m = PostureMachine::new();
    assert!(m.last_admin_action_secs_ago().is_none());
}

// ─── admin_force_state_with_token (Tappa 8 A10, §12.2) ──────────────

/// Required A10 test 1: any → any transition works under the
/// capability gate. Exercises every starting state via the
/// debug-trigger force_state_for_test setter to set the initial
/// state without going through observe(), then forces to each of
/// the 4 target states and asserts the resulting kind.
#[cfg(feature = "debug-trigger")]
#[test]
fn admin_force_state_with_token_any_to_any() {
    use PostureKind::*;
    for from in [Observing, Alerted, Engaged, Combat] {
        for to in [Observing, Alerted, Engaged, Combat] {
            let m = PostureMachine::new();
            m.force_state_for_test(from);
            assert_eq!(m.current_kind(), from);
            let token = crate::anti_tamper::_test_mint_unlock_token();
            let out = m
                .admin_force_state_with_token(token, to, true)
                .expect("any-to-any allowed");
            assert_eq!(out.state.kind(), to);
            // External audit ASK-015: `from` is the state left, not the
            // state entered.
            assert_eq!(out.from, from);
            assert_eq!(m.current_kind(), to);
        }
    }
}

/// Required A10 test 2: non-COMBAT → COMBAT fires the
/// `combat_entry_hook` (iptables engage per §12.2). Sets up a
/// counter-incrementing hook so the test directly observes
/// firing rather than relying on side-effects elsewhere.
#[test]
fn admin_force_state_with_token_non_combat_to_combat_fires_entry_hook() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);
    let entry_hook: super::CombatEntryHook = Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    });
    let m = PostureMachine::new_with_combat_hook(entry_hook);
    // Starts in Observing (PostureMachine::new() default).
    assert_eq!(m.current_kind(), PostureKind::Observing);

    let token = crate::anti_tamper::_test_mint_unlock_token();
    let _ = m
        .admin_force_state_with_token(token, PostureKind::Combat, true)
        .expect("Observing → Combat allowed");
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "combat_entry_hook should fire exactly once on non-Combat → Combat"
    );
}

/// Required A10 test 3: COMBAT → non-COMBAT fires the
/// `combat_release_hook` AND consumes the token (the hook closure
/// receives it by value).
#[cfg(feature = "debug-trigger")]
#[test]
fn admin_force_state_with_token_combat_to_non_combat_fires_release_hook() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);
    let release_hook: super::CombatReleaseHook = Arc::new(move |_token| {
        c.fetch_add(1, Ordering::SeqCst);
    });
    // Build a PostureMachine with both hooks present so the
    // combat-entry path also works for state setup.
    let entry_hook: super::CombatEntryHook = Arc::new(|| {});
    let m = PostureMachine::new_with_hooks(entry_hook, release_hook);
    m.force_state_for_test(PostureKind::Combat);
    assert_eq!(m.current_kind(), PostureKind::Combat);

    let token = crate::anti_tamper::_test_mint_unlock_token();
    let _ = m
        .admin_force_state_with_token(token, PostureKind::Observing, true)
        .expect("Combat → Observing allowed");
    assert_eq!(m.current_kind(), PostureKind::Observing);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "combat_release_hook should fire exactly once on Combat → non-Combat"
    );
}

/// External audit NN-AUD-083: without `may_release` (no signer holding
/// `unlock`), COMBAT → non-COMBAT is refused with the state, the lock and
/// the corroboration ledger untouched and no release hook fired; entering
/// COMBAT and moving between non-COMBAT states need no such signer.
#[test]
fn admin_force_state_out_of_combat_needs_may_release() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let released = Arc::new(AtomicU32::new(0));
    let r = Arc::clone(&released);
    let release_hook: super::CombatReleaseHook = Arc::new(move |_token| {
        r.fetch_add(1, Ordering::SeqCst);
    });
    let m = PostureMachine::new_with_hooks(Arc::new(|| {}), release_hook);
    let token = crate::anti_tamper::_test_mint_unlock_token();
    m.admin_force_state_with_token(token, PostureKind::Alerted, false)
        .expect("a lateral move needs no unlock");
    let token = crate::anti_tamper::_test_mint_unlock_token();
    m.admin_force_state_with_token(token, PostureKind::Combat, false)
        .expect("entering COMBAT needs no unlock");
    assert!(m.is_combat_locked());
    let transitions = m.transition_log().len();

    for target in [
        PostureKind::Observing,
        PostureKind::Alerted,
        PostureKind::Engaged,
    ] {
        let token = crate::anti_tamper::_test_mint_unlock_token();
        assert_eq!(
            m.admin_force_state_with_token(token, target, false)
                .unwrap_err(),
            AdminReleaseError::NeedsUnlock
        );
        assert_eq!(m.current_kind(), PostureKind::Combat);
        assert!(m.is_combat_locked());
    }
    assert_eq!(released.load(Ordering::SeqCst), 0);
    assert_eq!(m.transition_log().len(), transitions);

    let token = crate::anti_tamper::_test_mint_unlock_token();
    m.admin_force_state_with_token(token, PostureKind::Engaged, true)
        .expect("with an unlock signer the release goes through");
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

/// External audit ASK-015: the outcome names the state the force left —
/// without the `debug-trigger` setter, so the default build checks it too.
#[test]
fn admin_force_state_reports_the_state_it_left() {
    let m = PostureMachine::new();
    let force = |to, may_release| {
        let token = crate::anti_tamper::_test_mint_unlock_token();
        m.admin_force_state_with_token(token, to, may_release)
            .expect("allowed")
    };
    let out = force(PostureKind::Combat, false);
    assert_eq!(out.from, PostureKind::Observing);
    assert_eq!(out.state.kind(), PostureKind::Combat);
    let out = force(PostureKind::Observing, true);
    assert_eq!(out.from, PostureKind::Combat);
    assert_eq!(out.state.kind(), PostureKind::Observing);
    let out = force(PostureKind::Observing, true);
    assert_eq!(out.from, PostureKind::Observing, "a no-op names its state");
    assert_eq!(out.state.kind(), PostureKind::Observing);
}

// ─── T7.13 (Beta Step 5) — end-to-end lineage exemption tests ──────
//
// Drive the full PostureMachine through realistic event sequences
// covering the sudo cascade, the negative control (ransomware shape),
// and the self-write regression guard. These exercise the same code
// path as production: TriggerDetector::detect ingests ProcessSpawn
// into the AuthSessionTracker on every observe() call.

/// Helper: build a posture machine carrying a fresh AuthSessionTracker
/// pointed at a nonexistent /proc, so the lineage gate only sees what
/// the test explicitly ingests via ProcessSpawn events.
fn machine_with_isolated_auth() -> PostureMachine {
    let entry_hook: super::CombatEntryHook = Arc::new(|| {});
    let release_hook: super::CombatReleaseHook = Arc::new(|_| {});
    PostureMachine::new_with_hooks_and_exempt_and_auth(
        entry_hook,
        release_hook,
        ExemptPids::default(),
        AuthSessionTracker::new("/this/path/does/not/exist"),
    )
}

/// Test #15 — sudo cascade end-to-end stays at OBSERVING.
/// Replays the empirically-observed T7.13 cascade: sudo opens
/// /etc/shadow (uid=1000), an apt subprocess writes 25 files. With
/// the lineage gate the posture must NOT transition.
#[test]
fn sudo_cascade_e2e_stays_at_observing() {
    let m = machine_with_isolated_auth();

    // 1. sudo spawns: ingested into AuthSessionTracker via detect().
    let sudo_spawn = spawn(100, 50, "sudo", "/usr/bin/sudo", 1);
    let r = m.observe(&sudo_spawn, &[]);
    assert!(r.is_none(), "sudo spawn must not transition: {r:?}");
    assert_eq!(m.current_kind(), PostureKind::Observing);

    // 2. sudo's PAM auth chain reads /etc/shadow as uid=1000 (still
    //    pre-setuid at LSM file_open fire time).
    let shadow_read = file_open(100, 1000, "/etc/shadow", 0, 2);
    let r = m.observe(&shadow_read, &[]);
    assert!(
        r.is_none(),
        "sudo /etc/shadow read must not transition: {r:?}"
    );
    assert_eq!(m.current_kind(), PostureKind::Observing);

    // 3. apt spawns as sudo's child.
    let apt_spawn = spawn_by(0, 200, 100, "apt", "/usr/bin/apt", 3);
    let r = m.observe(&apt_spawn, &[]);
    assert!(r.is_none(), "apt spawn must not transition: {r:?}");

    // 4. apt mass-writes /var/cache/apt/* — 25 writes in window.
    let recent: Vec<Event> = (0..25u64)
        .map(|i| file_open(200, 0, "/var/cache/apt/x", 1, i + 100))
        .collect();
    let focal = file_open(200, 0, "/var/cache/apt/x", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(
        r.is_none(),
        "apt mass-write under sudo lineage must NOT transition: {r:?}"
    );
    assert_eq!(
        m.current_kind(),
        PostureKind::Observing,
        "T7.13 fix did not hold — sudo cascade still escalated"
    );
}

/// Test #16 — exec-from-/tmp still escalates (to ENGAGED).
/// Negative control: a non-auth-mediated exec from /tmp must still
/// raise the posture — the lineage gate must NOT be too broad. External
/// audit POS-015: it is a staging exec (ENGAGED); with a second factor it
/// is ConfirmedIntrusion, which also stops at ENGAGED alone (BUG-032).
#[test]
fn ransomware_shape_reaches_engaged_alone() {
    let m = machine_with_isolated_auth();
    // No sudo lineage. Direct exec from /tmp.
    let evil = spawn(900, 1, "payload", "/tmp/payload", 1);
    let r = m.observe(&evil, &[]);
    assert!(r.is_some(), "exec-from-/tmp must transition");
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "non-auth exec from /tmp escalates to ENGAGED on its own (BUG-032)"
    );
}

/// Test #17 — mass-write alone from a non-auth PID still escalates
/// (now to ENGAGED). Confirms the mass-write arm itself still works
/// for adversarial PIDs (the lineage gate is the only suppressor);
/// BUG-032 caps a single signal at ENGAGED.
#[test]
fn mass_write_alone_from_non_auth_pid_reaches_engaged() {
    let m = machine_with_isolated_auth();
    // Spawn a non-auth parent so the writer's lineage is clean.
    let _ = m.observe(&spawn(900, 1, "zsh", "/usr/bin/zsh", 1), &[]);

    let recent: Vec<Event> = (0..25u64)
        .map(|i| file_open(900, 1000, "/home/u/x", 1, i + 100))
        .collect();
    let focal = file_open(900, 1000, "/home/u/x", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(r.is_some(), "non-auth mass-write must transition");
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// Audit `posture-1` — a single round that raises TWO blunt
/// COMBAT-tier signals (mass-write arm of ConfirmedIntrusion AND
/// PersistenceMechanism, both from one write under
/// `/etc/systemd/system/`) must NOT collapse OBSERVING→COMBAT. Same-round
/// signals do not corroborate each other; only a prior ledger entry does.
#[test]
fn two_blunt_combat_signals_in_one_round_cap_at_engaged() {
    let tmp = tempfile::TempDir::new().unwrap();
    workload_proc(tmp.path(), 900, "/system.slice/zsh-job.service");
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(900, 1, "zsh", "/usr/bin/zsh", 1), &[]);
    assert_eq!(m.current_kind(), PostureKind::Observing);

    let recent: Vec<Event> = (0..25u64)
        .map(|i| {
            file_open(
                900,
                0,
                &format!("/etc/systemd/system/nn-test-{i}.service"),
                1,
                i + 100,
            )
        })
        .collect();
    let focal = file_open(900, 0, "/etc/systemd/system/nn-test-99.service", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(r.is_some(), "the round must still escalate");
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "same-round blunt signals must not corroborate each other into COMBAT"
    );

    // A SECOND round of the same kind (more unit files) is still one kind
    // of evidence (external audit POS-001)…
    let focal2 = file_open(900, 0, "/etc/systemd/system/nn-test-100.service", 1, 300);
    let _ = m.observe(&focal2, &recent);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    // …while evidence of another kind, with the earlier rounds' signals in
    // the ledger, is the legitimate corroboration path and reaches COMBAT
    // (external audit POS-015: a staged binary unlinked as it ran).
    let deleted = common::wire::exe::exe_flags::DELETED;
    let _ = m.observe(&spawn_exe_flags(901, 900, "/tmp/x", deleted, 400), &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

/// Audit `posture-3` — a PAM session writing into its OWN
/// `/run/user/<loginuid>/` (session start plumbing) must not trip the
/// mass-write arm; the same burst anywhere else, or into another uid's
/// runtime dir, still escalates.
#[test]
fn own_runtime_dir_burst_is_not_mass_write_but_home_burst_is() {
    let proc_root = tempfile::tempdir().expect("fake /proc");
    let pid_dir = proc_root.path().join("900");
    std::fs::create_dir_all(&pid_dir).unwrap();
    std::fs::write(pid_dir.join("loginuid"), "1000\n").unwrap();
    let mk = || {
        let entry_hook: super::CombatEntryHook = Arc::new(|| {});
        let release_hook: super::CombatReleaseHook = Arc::new(|_| {});
        PostureMachine::new_with_hooks_and_exempt_and_auth(
            entry_hook,
            release_hook,
            ExemptPids::with_agent(4242),
            AuthSessionTracker::new(proc_root.path()),
        )
    };
    let burst = |prefix: &str| -> (Vec<Event>, Event) {
        let recent: Vec<Event> = (0..25u64)
            .map(|i| file_open(900, 1000, &format!("{prefix}/f-{i}"), 1, i + 100))
            .collect();
        (
            recent,
            file_open(900, 1000, &format!("{prefix}/f-99"), 1, 200),
        )
    };

    // Own runtime dir: carved out.
    let m = mk();
    let (recent, focal) = burst("/run/user/1000");
    let r = m.observe(&focal, &recent);
    assert!(r.is_none(), "own /run/user burst must not escalate: {r:?}");
    assert_eq!(m.current_kind(), PostureKind::Observing);

    // Another uid's runtime dir: still counted.
    let m = mk();
    let (recent, focal) = burst("/run/user/1001");
    m.observe(&focal, &recent);
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    // $HOME: a session's ransomware-shaped burst is still caught.
    let m = mk();
    let (recent, focal) = burst("/home/u");
    m.observe(&focal, &recent);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// Review `posture-ledger-scope-1` — a blunt COMBAT-tier burst in login
/// session B is not corroborated by an earlier escalation signal from
/// session A; the same two rounds inside ONE session still reach COMBAT.
#[test]
fn corroboration_is_scoped_to_the_login_session() {
    let proc_root = tempfile::tempdir().expect("fake /proc");
    for (pid, uid) in [(900u32, 1000u32), (901, 1001)] {
        let d = proc_root.path().join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("loginuid"), format!("{uid}\n")).unwrap();
    }
    let mk = || {
        let entry_hook: super::CombatEntryHook = Arc::new(|| {});
        let release_hook: super::CombatReleaseHook = Arc::new(|_| {});
        PostureMachine::new_with_hooks_and_exempt_and_auth(
            entry_hook,
            release_hook,
            ExemptPids::with_agent(4242),
            AuthSessionTracker::new(proc_root.path()),
        )
    };
    let burst = |pid: u32, prefix: &str, base: u64| -> (Vec<Event>, Event) {
        let recent: Vec<Event> = (0..25u64)
            .map(|i| file_open(pid, 1000, &format!("{prefix}/f-{i}"), 1, base + i))
            .collect();
        (
            recent,
            file_open(pid, 1000, &format!("{prefix}/f-99"), 1, base + 100),
        )
    };

    // Session A (uid 1000): an offensive tool run → ENGAGED, ledger entry
    // scoped to 1000. Session B (uid 1001): a $HOME burst — evidence of
    // another kind (external audit POS-001) — must NOT be vouched for by
    // A's signal.
    let m = mk();
    m.observe(&spawn(900, 1, "nc", "/usr/bin/nc", 50), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (recent, focal) = burst(901, "/home/b", 300);
    m.observe(&focal, &recent);
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "a different login session must not corroborate into COMBAT"
    );

    // Same session for both rounds: legitimate corroboration → COMBAT.
    let m = mk();
    m.observe(&spawn(900, 1, "nc", "/usr/bin/nc", 50), &[]);
    let (recent, focal) = burst(900, "/home/a", 300);
    m.observe(&focal, &recent);
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

/// Test #18 — agent's own writes still exempt (PR #123 regression
/// guard). Validates that adding the auth-lineage gate did not
/// break the pre-existing stack-PID exclusion.
#[test]
fn agent_self_writes_still_exempt() {
    const AGENT_PID: u32 = 4242;
    let entry_hook: super::CombatEntryHook = Arc::new(|| {});
    let release_hook: super::CombatReleaseHook = Arc::new(|_| {});
    let m = PostureMachine::new_with_hooks_and_exempt_and_auth(
        entry_hook,
        release_hook,
        ExemptPids::with_agent(AGENT_PID),
        AuthSessionTracker::new("/this/path/does/not/exist"),
    );

    let recent: Vec<Event> = (0..25u64)
        .map(|i| {
            file_open(
                AGENT_PID,
                0,
                "/var/lib/northnarrow/fim_drift.jsonl",
                1,
                i + 100,
            )
        })
        .collect();
    let focal = file_open(AGENT_PID, 0, "/var/lib/northnarrow/fim_drift.jsonl", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(
        r.is_none(),
        "agent's own state-log writes must still be fully exempt: {r:?}"
    );
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

// ─── T7.13 generalisation: PAM-daemon login chains, end-to-end ──────
//
// The original T7.13 fix covered sudo; the same false-positive class
// applies to every PAM-mediated login daemon (cron jobs, display
// managers, logind sessions) whose credential read is observed at the
// authenticating user's uid. These FSM-level tests assert such chains
// never push posture upward — the "trigger bar" guarantee that benign
// authentication cannot escalate toward COMBAT.

/// A cron job's PAM `session` chain reading /etc/shadow as uid=1000
/// (lineage: crond → job shell) must NOT transition the posture.
#[test]
fn cron_job_shadow_read_e2e_stays_at_observing() {
    let m = machine_with_isolated_auth();
    assert!(m
        .observe(&spawn(500, 1, "cron", "/usr/sbin/cron", 1), &[])
        .is_none());
    assert!(m
        .observe(&spawn(501, 500, "sh", "/bin/sh", 2), &[])
        .is_none());
    let shadow_read = file_open(501, 1000, "/etc/shadow", 0, 3);
    let r = m.observe(&shadow_read, &[]);
    assert!(
        r.is_none(),
        "cron-job /etc/shadow read must NOT transition: {r:?}"
    );
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

/// A display-manager login (gdm daemon → gdm-session-worker PAM stack →
/// session child) reading /etc/gshadow as uid=1000 must NOT transition.
#[test]
fn gdm_login_gshadow_read_e2e_stays_at_observing() {
    let m = machine_with_isolated_auth();
    assert!(m
        .observe(&spawn(600, 1, "gdm3", "/usr/sbin/gdm3", 1), &[])
        .is_none());
    assert!(m
        .observe(
            &spawn(
                601,
                600,
                "gdm-session-wor",
                "/usr/lib/gdm3/gdm-session-worker",
                2
            ),
            &[],
        )
        .is_none());
    let gshadow_read = file_open(601, 1000, "/etc/gshadow", 0, 3);
    let r = m.observe(&gshadow_read, &[]);
    assert!(
        r.is_none(),
        "gdm-session-worker /etc/gshadow read must NOT transition: {r:?}"
    );
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

/// Negative control: an unexpected uid=1000 reader of /etc/gshadow with
/// no auth lineage STILL escalates (to ALERTED — SensitiveFileAccess is
/// an ALERTED-tier trigger). gshadow is monitored symmetrically with
/// /etc/shadow; the expanded daemon allowlist must not blind us to real
/// group-credential theft.
#[test]
fn unexpected_gshadow_read_e2e_reaches_alerted() {
    let m = machine_with_isolated_auth();
    // Non-auth lineage: a plain shell child.
    assert!(m
        .observe(&spawn(900, 1, "bash", "/usr/bin/bash", 1), &[])
        .is_none());
    let r = m.observe(&file_open(900, 1000, "/etc/gshadow", 0, 2), &[]);
    assert!(r.is_some(), "unexpected /etc/gshadow read must transition");
    assert_eq!(
        m.current_kind(),
        PostureKind::Alerted,
        "unexpected /etc/gshadow read escalates to ALERTED (SensitiveFileAccess tier)"
    );
}

/// Screen-unlock end-to-end: an unprivileged locker execs the setuid
/// pam_unix helper unix_chkpwd, which reads /etc/shadow at the caller's
/// real uid (1000). The unprivileged-auth credential read must NOT push
/// posture — the screen-unlock FP the user flagged.
#[test]
fn screen_unlock_unix_chkpwd_e2e_stays_at_observing() {
    let m = machine_with_isolated_auth();
    assert!(m
        .observe(
            &spawn(
                700,
                1,
                "cinnamon-screen",
                "/usr/bin/cinnamon-screensaver",
                1
            ),
            &[],
        )
        .is_none());
    assert!(m
        .observe(
            &spawn(701, 700, "unix_chkpwd", "/usr/sbin/unix_chkpwd", 2),
            &[]
        )
        .is_none());
    let shadow_read = file_open(701, 1000, "/etc/shadow", 0, 3);
    let r = m.observe(&shadow_read, &[]);
    assert!(
        r.is_none(),
        "screen-unlock unix_chkpwd /etc/shadow read must NOT transition: {r:?}"
    );
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

// ─── (ii) — system package-management daemon exemption, end-to-end ──
//
// The 2026-06-02 self-lock: snapd's refresh did a mass-write burst on
// /var/lib/snapd/state.json (ConfirmedIntrusion → ENGAGED) AND wrote a
// systemd mount unit (PersistenceMechanism); the two distinct signals
// corroborated to COMBAT. (ii) exempts the daemon from BOTH arms — but
// the identical shape from a non-daemon pid must still reach COMBAT.

/// snapd's normal refresh (mass-write + unit write) must NOT escalate.
#[test]
fn snapd_refresh_e2e_stays_at_observing() {
    let m = machine_with_isolated_auth();
    // snapd daemon spawned by systemd (pid 1).
    assert!(m
        .observe(
            &spawn_by(0, 1096, 1, "snapd", "/usr/lib/snapd/snapd", 1),
            &[]
        )
        .is_none());

    // 1. 25 atomic state.json rewrites in-window (mass-write arm).
    let recent: Vec<Event> = (0..25u64)
        .map(|i| file_open(1096, 0, "/var/lib/snapd/state.json.tmp", 1, i + 100))
        .collect();
    let focal = file_open(1096, 0, "/var/lib/snapd/state.json.tmp", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(r.is_none(), "snapd mass-write must NOT transition: {r:?}");
    assert_eq!(m.current_kind(), PostureKind::Observing);

    // 2. snapd writes its mount unit (persistence arm) — the original
    //    corroborating signal that pushed ENGAGED → COMBAT.
    let unit = file_open(
        1096,
        0,
        "/etc/systemd/system/snap-snapd-26865.mount",
        1,
        300,
    );
    let r = m.observe(&unit, &[]);
    assert!(r.is_none(), "snapd unit write must NOT transition: {r:?}");
    assert_eq!(
        m.current_kind(),
        PostureKind::Observing,
        "(ii) did not hold — snapd refresh still escalated"
    );
}

/// Detection intact: the IDENTICAL mass-write + persistence pair from a
/// NON-daemon pid still raises both signals. External audit POS-001: they
/// are one kind of evidence (file system), so together they stay at
/// ENGAGED; evidence of another kind from the same actor — a binary run
/// from /tmp and unlinked as it ran (external audit POS-015: a plain /tmp
/// exec is no longer enough) — then reaches COMBAT, locked because root
/// changed a system file outside an administrator's session.
#[test]
fn non_daemon_masswrite_plus_persistence_reaches_combat() {
    let tmp = tempfile::TempDir::new().unwrap();
    workload_proc(tmp.path(), 900, "/system.slice/cryptor.service");
    let m = machine_on(tmp.path());
    // Non-daemon writer, clean lineage (parent = init).
    let _ = m.observe(&spawn(900, 1, "cryptor", "/usr/local/bin/cryptor", 1), &[]);

    // 1. mass-write → ConfirmedIntrusion → ENGAGED (seeds the ledger).
    let recent: Vec<Event> = (0..25u64)
        .map(|i| file_open(900, 1000, "/home/u/docs/f", 1, i + 100))
        .collect();
    let focal = file_open(900, 1000, "/home/u/docs/f", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(r.is_some(), "non-daemon mass-write must transition");
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    // 2. persistence (systemd unit drop) → PersistenceMechanism: the same
    //    kind of evidence as the mass-write, so still ENGAGED.
    let unit = file_open(900, 0, "/etc/systemd/system/evil.service", 1, 300);
    let _ = m.observe(&unit, &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    // 3. the writer runs a binary from /tmp: a staging exec, which is no
    //    corroboration…
    let _ = m.observe(&spawn(901, 900, "x", "/tmp/x", 400), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    // …and one unlinked as it ran → evidence of another kind.
    let deleted = common::wire::exe::exe_flags::DELETED;
    let r = m.observe(&spawn_exe_flags(902, 900, "/tmp/x", deleted, 450), &[]);
    assert!(r.is_some(), "exec from /tmp must transition");
    assert_eq!(
        m.current_kind(),
        PostureKind::Combat,
        "file-system evidence + an unlinked exec from /tmp must corroborate to COMBAT"
    );
    assert!(m.is_combat_locked(), "root wrote the unit: locked");
}

// ─── Review 52 — an admin session's configuration changes ───────────
//
// Lab, 2026-10-12 (Ubuntu 24.04): `sudo` appending to sshd_config
// (CriticalFileModification → ENGAGED) and then writing a unit
// (PersistenceMechanism) from the same terminal corroborated to COMBAT,
// and the ladder named the unit's writer an offender to kill.

/// `/proc/<pid>` of a process in an interactive session: login uid 1000
/// and a terminal.
fn session_proc(dir: &std::path::Path, pid: u32, ppid: u32) {
    let d = dir.join(pid.to_string());
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("loginuid"), "1000").unwrap();
    std::fs::write(
        d.join("stat"),
        format!("{pid} (x) S {ppid} {pid} {pid} 34816 -1 0\n"),
    )
    .unwrap();
}

/// A terminal shell (700) that ran sudo (710) → two writers (720, 730),
/// and ran a writer (800) and `nc` (810) without sudo.
fn admin_session_machine() -> (tempfile::TempDir, PostureMachine) {
    let tmp = tempfile::TempDir::new().unwrap();
    for (pid, ppid) in [
        (700, 1),
        (710, 700),
        (720, 710),
        (730, 710),
        (800, 700),
        (810, 700),
    ] {
        session_proc(tmp.path(), pid, ppid);
    }
    let m = PostureMachine::new_with_hooks_and_exempt_and_auth(
        Arc::new(|| {}),
        Arc::new(|_| {}),
        ExemptPids::default(),
        AuthSessionTracker::new(tmp.path()),
    );
    for (pid, ppid, comm, exe) in [
        (700, 1, "bash", "/usr/bin/bash"),
        (710, 700, "sudo", "/usr/bin/sudo"),
        (720, 710, "tee", "/usr/bin/tee"),
        (730, 710, "tee", "/usr/bin/tee"),
        (800, 700, "tee", "/usr/bin/tee"),
    ] {
        let _ = m.observe(&spawn(pid, ppid, comm, exe, 1), &[]);
    }
    (tmp, m)
}

#[test]
fn admin_session_config_changes_stay_engaged() {
    let (_tmp, m) = admin_session_machine();
    let _ = m.observe(&file_open(720, 0, "/etc/ssh/sshd_config", 1, 100), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let _ = m.observe(
        &file_open(730, 0, "/etc/systemd/system/backup.service", 1, 200),
        &[],
    );
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "routine admin edits must not corroborate each other to COMBAT"
    );
    // External audit POS-001: nor do they corroborate evidence of another
    // kind from the session (the admin then pushes a backup over HTTPS).
    let (ef, er) = exfil_burst(810);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// The same change without sudo in the lineage still corroborates
/// (external audit POS-001: evidence of another kind), and — root
/// changing a system file outside an administrator's session — locks the
/// COMBAT it reaches.
#[test]
fn config_changes_without_sudo_still_reach_combat() {
    let (_tmp, m) = admin_session_machine();
    let _ = m.observe(&file_open(800, 0, "/etc/ssh/sshd_config", 1, 100), &[]);
    let (ef, er) = exfil_burst(810);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(m.is_combat_locked());
}

/// An admin session that first ran an offensive tool: its unit write is
/// corroborated by that signal, so sudo is still no free pass.
#[test]
fn admin_change_after_another_signal_reaches_combat() {
    let (_tmp, m) = admin_session_machine();
    let _ = m.observe(&spawn(810, 700, "nc", "/usr/bin/nc", 50), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let _ = m.observe(
        &file_open(730, 0, "/etc/systemd/system/backup.service", 1, 200),
        &[],
    );
    assert_eq!(m.current_kind(), PostureKind::Combat);
    // External audit POS-001: an administrator's change is not evidence
    // an unprivileged user cannot produce — unlocked.
    assert!(!m.is_combat_locked());
}

/// `sudo tee` on sshd_config (740) has exited and its exec event is still
/// in flight when its write is read: the change is recorded pending.
/// Placed when the next signal arrives (sudo in its lineage, the shell
/// that ran it still running with a terminal), it corroborates nothing.
#[test]
fn exited_admin_writer_is_placed_before_it_corroborates() {
    let (_tmp, m) = admin_session_machine();
    let _ = m.observe(&file_open(740, 0, "/etc/ssh/sshd_config", 1, 100), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let _ = m.observe(&spawn(740, 710, "tee", "/usr/bin/tee", 101), &[]);
    let (ef, er) = exfil_burst(810);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// The same exited writer without sudo above it is placed as an ordinary
/// signal of its session, and corroborates.
#[test]
fn exited_writer_without_sudo_still_corroborates() {
    let (_tmp, m) = admin_session_machine();
    let _ = m.observe(&file_open(840, 0, "/etc/ssh/sshd_config", 1, 100), &[]);
    let _ = m.observe(&spawn(840, 700, "sh", "/usr/bin/sh", 101), &[]);
    let (ef, er) = exfil_burst(810);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    // External audit POS-001: placed outside an administrator's session,
    // root's change counts as privileged — locked.
    assert!(m.is_combat_locked());
}

/// Required A10 test 4: same-state transition is a no-op — no
/// `last_admin_action` timestamp recorded, no log transition
/// added, no hook fires. Anchors the §12.2 design contract that
/// idempotent forces don't pollute the audit log.
#[test]
fn admin_force_state_with_token_same_state_is_noop() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);
    let entry_hook: super::CombatEntryHook = Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    });
    let m = PostureMachine::new_with_combat_hook(entry_hook);
    // Starts in Observing. Force to Observing.
    let transitions_before = m.transition_log().len();
    let last_action_before = m.last_admin_action_secs_ago();
    assert!(last_action_before.is_none(), "no admin action yet");

    let token = crate::anti_tamper::_test_mint_unlock_token();
    let _ = m
        .admin_force_state_with_token(token, PostureKind::Observing, true)
        .expect("idempotent same-state allowed");

    assert_eq!(m.current_kind(), PostureKind::Observing);
    assert_eq!(
        m.transition_log().len(),
        transitions_before,
        "same-state force must not log a transition"
    );
    assert!(
        m.last_admin_action_secs_ago().is_none(),
        "same-state force must not record last_admin_action"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "no hook should fire on same-state transition"
    );
}

// ── BUG-015 P-5 regression — observe() returns the firing trigger ──

#[test]
fn observe_returns_firing_trigger_on_transition() {
    // A kernel anti-tamper denial fires the Decisive AntiTamperDenial →
    // COMBAT. The returned tuple must carry that TriggerType so callers
    // (main.rs WARN log) can surface which signal caused the escalation.
    let m = PostureMachine::new();
    let focal = fs_protect_denial(42, 1);
    let result = m.observe(&focal, &[]);
    let (new_state, firing) = result.expect("posture transitioned");
    assert_eq!(new_state.kind(), PostureKind::Combat);
    assert_eq!(firing, Some(TriggerType::AntiTamperDenial));
}

/// External audit EBPF-001: a signal PID 1 relayed for a `systemctl stop`
/// outside a trusted-installer window is refused and raises ENGAGED — the
/// requester is unknown, and a COMBAT with init as the offender could only
/// end in ISOLATE (lab: one refused `systemctl kill` isolated the host).
#[test]
fn a_relayed_signal_denial_engages_but_never_reaches_combat() {
    let m = PostureMachine::new();
    let relayed = Event::FsProtectDenial {
        pid: 1,
        uid: 0,
        comm: "systemd".into(),
        target_dev: 15,
        target_ino: 4242,
        operation: common::FsProtectOperation::Signal,
        timestamp_ns: 1,
    };
    let (state, firing) = m.observe(&relayed, &[]).expect("posture transitioned");
    assert_eq!(state.kind(), PostureKind::Engaged);
    assert_eq!(firing, Some(TriggerType::RelayedTamperAttempt));
    for ts in 2..6 {
        let again = Event::FsProtectDenial {
            pid: 1,
            uid: 0,
            comm: "systemd".into(),
            target_dev: 9,
            target_ino: 4242,
            operation: common::FsProtectOperation::Signal,
            timestamp_ns: ts,
        };
        let _ = m.observe(&again, &[]);
    }
    assert_ne!(
        m.current().kind(),
        PostureKind::Combat,
        "repeats alone never isolate"
    );
}

#[test]
fn observe_returns_none_when_no_transition() {
    // A spawn that matches no trigger leaves posture at Observing
    // and observe() returns None — no log line in main.rs.
    let m = PostureMachine::new();
    let benign = spawn(42, 1, "ls", "/usr/bin/ls", 1);
    assert!(m.observe(&benign, &[]).is_none());
    assert_eq!(m.current_kind(), PostureKind::Observing);
}

/// External audit EVD-001: a refused read of the agent's signing key is a
/// credential reach (ALERTED), not the decisive tamper that reaches COMBAT
/// alone — a backup of /etc meets it too.
#[test]
fn a_refused_read_of_the_signing_key_alerts_without_combat() {
    let m = PostureMachine::new();
    let mut read = super::triggers::testutil::fs_protect_denial(7, 1);
    if let common::Event::FsProtectDenial { operation, .. } = &mut read {
        *operation = common::FsProtectOperation::Read;
    }
    m.observe(&read, &[]);
    assert_eq!(m.current_kind(), PostureKind::Alerted);
}

// ─── External audit POS-015 — a staging-directory exec ──────────────

/// A build in a login session: pip's sdist runs configure, whose
/// `conftest` runs from /tmp; then the session uploads the result. The
/// exec raises ENGAGED as a `StagingExec`, is not recorded, and the
/// upload is not corroborated by it (was: COMBAT, and NEUTRALIZE killed
/// the upload).
#[test]
fn a_staging_exec_raises_engaged_and_is_not_recorded() {
    let tmp = tempfile::TempDir::new().unwrap();
    session_proc(tmp.path(), 700, 1);
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(700, 1, "bash", "/usr/bin/bash", 1), &[]);
    let _ = m.observe(&spawn(770, 700, "twine", "/usr/bin/python3", 2), &[]);
    let conftest = spawn(760, 700, "conftest", "/tmp/pip-install-x/pkg/conftest", 3);
    let r = m.observe(&conftest, &[]);
    assert_eq!(
        r.map(|(state, firing)| (state.kind(), firing)),
        Some((PostureKind::Engaged, Some(TriggerType::StagingExec)))
    );
    assert_eq!(m.corroboration_len(), 0, "a staging exec is not recorded");
    let (ef, er) = exfil_burst(770);
    assert!(m.observe(&ef, &er).is_none());
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// The same build run through sudo in an administrator's terminal: sudo
/// gives no free pass, and no extra weight either.
#[test]
fn an_admin_sessions_build_and_upload_stay_engaged() {
    let (_tmp, m) = admin_session_machine();
    let _ = m.observe(&spawn(750, 710, "make", "/usr/bin/make", 1), &[]);
    let r = m.observe(
        &spawn(751, 750, "conftest", "/tmp/cc-build/conftest", 2),
        &[],
    );
    assert_eq!(
        r.and_then(|(_, firing)| firing),
        Some(TriggerType::StagingExec)
    );
    let (ef, er) = exfil_burst(810);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// A package manager's maintainer script runs a helper it unpacked in /tmp
/// (unlinked as it runs), then the same unit downloads: ENGAGED only.
#[test]
fn a_package_managers_staged_helper_stays_engaged() {
    let tmp = tempfile::TempDir::new().unwrap();
    let unit = "/system.slice/unattended-upgrades.service";
    for pid in [300, 310] {
        workload_proc(tmp.path(), pid, unit);
    }
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn_by(0, 300, 1, "dpkg", "/usr/bin/dpkg", 1), &[]);
    let deleted = common::wire::exe::exe_flags::DELETED;
    let r = m.observe(
        &spawn_exe_flags(301, 300, "/tmp/dpkg-helper", deleted, 2),
        &[],
    );
    assert_eq!(
        r.and_then(|(_, firing)| firing),
        Some(TriggerType::StagingExec)
    );
    let _ = m.observe(
        &spawn(310, 1, "https", "/usr/lib/apt/methods/https", 3),
        &[],
    );
    let (ef, er) = exfil_burst(310);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

// ─── External audit POS-005 — scope of a process without a login uid ──

/// puppet (a root daemon, no administrator's session) rewrites a unit:
/// privileged file-system evidence in `puppet.service` → ENGAGED.
fn puppet_wrote_a_unit() -> (tempfile::TempDir, PostureMachine) {
    let tmp = tempfile::TempDir::new().unwrap();
    workload_proc(tmp.path(), 300, "/system.slice/puppet.service");
    for pid in [400, 401] {
        workload_proc(tmp.path(), pid, "/system.slice/docker-0123abcd.scope");
    }
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(300, 1, "ruby", "/usr/bin/ruby", 1), &[]);
    let _ = m.observe(&spawn(400, 1, "python3", "/usr/bin/python3", 2), &[]);
    let _ = m.observe(
        &file_open(300, 0, "/etc/systemd/system/backup.service", 1, 10),
        &[],
    );
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    (tmp, m)
}

/// A container's exfiltration burst is another actor's: it is not
/// corroborated by puppet's change (was: COMBAT, locked by it). Two
/// signals of the container itself still corroborate — unlocked.
#[test]
fn two_daemons_do_not_corroborate_into_combat() {
    let (_tmp, m) = puppet_wrote_a_unit();
    let (ef, er) = exfil_burst(400);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);

    let _ = m.observe(&spawn(401, 400, "nc", "/usr/bin/nc", 20), &[]);
    let (ef, er) = exfil_burst(400);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(
        !m.is_combat_locked(),
        "the container did not change a system file"
    );
}

/// With the container's COMBAT running unlocked, puppet rewriting another
/// unit does not lock it — nothing of puppet's pairs with that change
/// (was: locked, no decay, isolation if NEUTRALIZE failed). puppet's own
/// burst then pairs with its root change: locked.
#[test]
fn a_root_change_locks_only_its_own_units_combat() {
    let (_tmp, m) = puppet_wrote_a_unit();
    let _ = m.observe(&spawn(401, 400, "nc", "/usr/bin/nc", 20), &[]);
    let (ef, er) = exfil_burst(400);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);

    let _ = m.observe(
        &file_open(300, 0, "/etc/systemd/system/backup2.service", 1, 30),
        &[],
    );
    assert!(!m.is_combat_locked(), "another unit's root change");
    let (ef, er) = exfil_burst(300);
    let _ = m.observe(&ef, &er);
    assert!(
        m.is_combat_locked(),
        "puppet's own pair, with its root change"
    );
}

/// A root change whose writer and every ancestor the agent knows have
/// exited cannot be placed: recorded, but it corroborates nothing and
/// locks nothing.
#[test]
fn an_unplaced_root_change_corroborates_nothing() {
    let tmp = tempfile::TempDir::new().unwrap();
    workload_proc(tmp.path(), 400, "/system.slice/docker-0123abcd.scope");
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(500, 1, "sh", "/usr/bin/sh", 1), &[]);
    let _ = m.observe(&file_open(500, 0, "/etc/cron.d/job", 1, 2), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    assert_eq!(m.corroboration_len(), 1, "recorded");
    let (ef, er) = exfil_burst(400);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (ef, er) = exfil_burst(501);
    let _ = m.observe(&ef, &er);
    assert_eq!(
        m.current_kind(),
        PostureKind::Engaged,
        "nor another unplaced one"
    );
}

// ─── External audit POS-005 — containers of a login session ──────────

/// `/proc/<pid>` of a process with user 1000's login uid whose cgroup is
/// `cgroup`: the user's shell, or a rootless container the user started
/// (Podman keeps the caller's login uid in the container).
fn login_proc(dir: &std::path::Path, pid: u32, cgroup: &str) {
    let d = dir.join(pid.to_string());
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
    std::fs::write(d.join("loginuid"), "1000").unwrap();
}

/// The cgroup of user 1000's rootless Podman container whose id is `c`
/// repeated (64 hex digits), or of its conmon with `conmon`.
fn rootless_podman(c: char, conmon: bool) -> String {
    let id = c.to_string().repeat(64);
    let kind = if conmon { "libpod-conmon" } else { "libpod" };
    let base = "/user.slice/user-1000.slice/user@1000.service/user.slice";
    if conmon {
        format!("{base}/{kind}-{id}.scope")
    } else {
        format!("{base}/{kind}-{id}.scope/container")
    }
}

const SHELL_SESSION: &str = "/user.slice/user-1000.slice/session-3.scope";

/// Two containers one user started: an exploit tool in one, an
/// exfiltration burst in the other. They used to share the user's login
/// scope and reach COMBAT together; each is now an actor of its own.
#[test]
fn two_rootless_containers_of_one_user_do_not_corroborate() {
    let tmp = tempfile::TempDir::new().unwrap();
    login_proc(tmp.path(), 900, &rootless_podman('a', false));
    login_proc(tmp.path(), 950, &rootless_podman('b', false));
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(900, 1, "sh", "/usr/bin/sh", 1), &[]);
    let _ = m.observe(&spawn(950, 1, "python3", "/usr/bin/python3", 2), &[]);
    // `nc` exits at once: placed through the container's shell.
    let _ = m.observe(&spawn(901, 900, "nc", "/usr/bin/nc", 3), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (ef, er) = exfil_burst(950);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// The user's shell runs an exploit tool, a container of theirs bursts:
/// two actors. The shell's own burst still pairs with its tool. A
/// container whose init has exited is placed through its conmon, not
/// through the session that started it.
#[test]
fn a_container_and_its_users_shell_do_not_corroborate() {
    let tmp = tempfile::TempDir::new().unwrap();
    login_proc(tmp.path(), 700, SHELL_SESSION);
    login_proc(tmp.path(), 710, SHELL_SESSION);
    login_proc(tmp.path(), 900, &rootless_podman('a', false));
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(700, 1, "bash", "/usr/bin/bash", 1), &[]);
    let _ = m.observe(&spawn(710, 700, "python3", "/usr/bin/python3", 2), &[]);
    let _ = m.observe(&spawn(900, 1, "python3", "/usr/bin/python3", 3), &[]);
    let _ = m.observe(&spawn(701, 700, "nc", "/usr/bin/nc", 4), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (ef, er) = exfil_burst(900);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (ef, er) = exfil_burst(710);
    let _ = m.observe(&ef, &er);
    assert_eq!(
        m.current_kind(),
        PostureKind::Combat,
        "the shell's own pair"
    );
    assert!(!m.is_combat_locked());

    // `podman run … nc`: the tool is the container's init, gone by the
    // time its event is read; conmon (880) is its nearest running ancestor.
    let tmp = tempfile::TempDir::new().unwrap();
    login_proc(tmp.path(), 710, SHELL_SESSION);
    login_proc(tmp.path(), 880, &rootless_podman('a', true));
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(710, 1, "python3", "/usr/bin/python3", 1), &[]);
    let _ = m.observe(&spawn(880, 1, "conmon", "/usr/bin/conmon", 2), &[]);
    let _ = m.observe(&spawn(890, 880, "nc", "/usr/bin/nc", 3), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (ef, er) = exfil_burst(710);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
}

/// Two signals inside one container still corroborate: in a rootless
/// container (two of its processes), and in a container that runs its own
/// systemd, whose units are the container's (no login uid: a daemon
/// started it).
#[test]
fn two_signals_in_one_container_corroborate() {
    let tmp = tempfile::TempDir::new().unwrap();
    for pid in [900, 902] {
        login_proc(tmp.path(), pid, &rootless_podman('a', false));
    }
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(900, 1, "sh", "/usr/bin/sh", 1), &[]);
    let _ = m.observe(&spawn(902, 900, "python3", "/usr/bin/python3", 2), &[]);
    let _ = m.observe(&spawn(901, 900, "nc", "/usr/bin/nc", 3), &[]);
    let (ef, er) = exfil_burst(902);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(!m.is_combat_locked());

    let tmp = tempfile::TempDir::new().unwrap();
    let container = format!("/system.slice/docker-{}.scope", "c".repeat(64));
    workload_proc(
        tmp.path(),
        400,
        &format!("{container}/system.slice/cron.service"),
    );
    workload_proc(
        tmp.path(),
        410,
        &format!("{container}/system.slice/app.service"),
    );
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(400, 1, "cron", "/usr/sbin/cron", 1), &[]);
    let _ = m.observe(&spawn(410, 1, "python3", "/usr/bin/python3", 2), &[]);
    let _ = m.observe(&spawn(401, 400, "nc", "/usr/bin/nc", 3), &[]);
    let (ef, er) = exfil_burst(410);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(!m.is_combat_locked());
}

/// External audit EBPF-015: a refused new entry in the agent's directories
/// or a refused extended-attribute change is a tamper the kernel stopped,
/// decisive like a refused unlink: COMBAT on its own.
#[test]
fn a_refused_new_entry_or_xattr_change_reaches_combat() {
    for op in [
        common::FsProtectOperation::Create,
        common::FsProtectOperation::Link,
        common::FsProtectOperation::Symlink,
        common::FsProtectOperation::Mkdir,
        common::FsProtectOperation::Mknod,
        common::FsProtectOperation::Xattr,
    ] {
        let m = PostureMachine::new();
        let mut denial = super::triggers::testutil::fs_protect_denial(7, 1);
        if let common::Event::FsProtectDenial { operation, .. } = &mut denial {
            *operation = op;
        }
        let (state, firing) = m.observe(&denial, &[]).expect("posture transitioned");
        assert_eq!(state.kind(), PostureKind::Combat, "{op}");
        assert_eq!(firing, Some(TriggerType::AntiTamperDenial), "{op}");
    }
}

// ─── Lab PR 162 — a tamper of an anti-tamper control-surface file ───

/// A FIM event: `op` on `path` by `pid`.
fn fim(op: common::wire::FimOp, path: &str, pid: u32) -> Event {
    Event::Fim(common::wire::FimEvent {
        timestamp_ns: 1_000,
        path: path.into(),
        op,
        new_sha256: None,
        baseline_sha256: None,
        new_size: None,
        baseline_size: None,
        modifier_exe: None,
        modifier_pid: pid,
        modifier_uid: 0,
        modifier_comm: "rm".into(),
        dest_path: None,
        child_truncated: false,
        wide_coverage: false,
        owner_uid: None,
        reader_dac_capable: false,
        capability: None,
        attrs: None,
        file_key: None,
        is_dir: false,
        moved_in: false,
    })
}

const KILL_SWITCH: &str = "/etc/northnarrow/kill_switch.conf";

/// A writer pid no host has (`pid_max` is at most 2^22), so never the test
/// runner's own, which the trigger leaves out.
const TAMPERER: u32 = 999_999_999;

/// The finding: NN-L-FIM-024 said "posture → COMBAT" and no trigger read
/// a FIM event. A tamper of a control-surface file now reaches a locked
/// COMBAT on its own, naming the writer as the offender.
#[test]
fn a_control_surface_tamper_reaches_locked_combat() {
    let m = PostureMachine::new();
    let tamper = fim(common::wire::FimOp::Deleted, KILL_SWITCH, TAMPERER);
    let (state, firing) = m.observe(&tamper, &[]).expect("posture transitioned");
    assert_eq!(state.kind(), PostureKind::Combat);
    assert_eq!(firing, Some(TriggerType::ControlSurfaceTamper));
    assert!(m.is_combat_locked());
    assert_eq!(super::triggers::event_owner_pid(&tamper), Some(TAMPERER));
}

/// The trigger and NN-L-FIM-024 answer the same events: every op on every
/// control-surface file and on files next to them.
#[test]
fn the_trigger_fires_exactly_where_fim024_does() {
    use crate::decision::Rule as _;
    use crate::fim::rules::{NnLFim024AntiTamperHoneypotModified, HONEYPOT_PATHS};
    use common::wire::FimOp;
    let rule = NnLFim024AntiTamperHoneypotModified::new(1);
    let ops = [
        FimOp::Modified,
        FimOp::Created,
        FimOp::Deleted,
        FimOp::Renamed,
        FimOp::Linked,
        FimOp::Opened,
        FimOp::CapabilitySet,
        FimOp::AttrChanged,
    ];
    let others = [
        "/etc/northnarrow/agent.toml",
        "/etc/northnarrow/admin.pub",
        "/run/northnarrow/agent.pid",
        "/etc/northnarrow/kill_switch.conf.bak",
    ];
    for path in HONEYPOT_PATHS.iter().copied().chain(others) {
        for op in ops {
            let event = fim(op, path, TAMPERER);
            let fires = super::TriggerDetector::new()
                .detect(&event, &[])
                .contains(&TriggerType::ControlSurfaceTamper);
            assert_eq!(fires, rule.evaluate(&event).is_some(), "{op:?} {path}");
        }
    }
}

/// The rule's exemption, mirrored: the agent's own write (its boot sweep
/// recreating a missing file) raises nothing, whether the agent is in the
/// stack exemption or known only as this process.
#[test]
fn the_agents_own_write_of_a_control_surface_file_raises_nothing() {
    let exempt = PostureMachine::new_with_hooks_and_exempt_and_auth(
        Arc::new(|| {}),
        Arc::new(|_| {}),
        ExemptPids::with_agent(4242),
        AuthSessionTracker::default(),
    );
    let recreate = fim(common::wire::FimOp::Created, KILL_SWITCH, 4242);
    assert!(exempt.observe(&recreate, &[]).is_none());
    assert_eq!(exempt.current_kind(), PostureKind::Observing);

    let unwired = PostureMachine::new();
    let own = fim(
        common::wire::FimOp::Created,
        KILL_SWITCH,
        std::process::id(),
    );
    assert!(unwired.observe(&own, &[]).is_none());
    assert_eq!(unwired.current_kind(), PostureKind::Observing);
}

/// Inside the trusted-installer window the kernel refuses no write, so no
/// anti-tamper denial reaches the posture; a control-surface tamper does
/// not either. The window closed, the same tamper reaches COMBAT.
#[test]
fn a_control_surface_tamper_inside_the_trusted_installer_window_raises_nothing() {
    use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
    let window = Arc::new(TrustedInstallerOverride::new(
        None,
        0,
        None,
        std::time::Duration::from_secs(600),
    ));
    let m = PostureMachine::new();
    m.set_installer_window(Arc::clone(&window));
    window.arm(120, std::time::Instant::now());
    let tamper = fim(common::wire::FimOp::Modified, KILL_SWITCH, TAMPERER);
    assert!(m.observe(&tamper, &[]).is_none());
    assert_eq!(m.current_kind(), PostureKind::Observing);

    window.close("test");
    let (state, firing) = m.observe(&tamper, &[]).expect("posture transitioned");
    assert_eq!(state.kind(), PostureKind::Combat);
    assert_eq!(firing, Some(TriggerType::ControlSurfaceTamper));
}

// ─── External audit POS-008 — one ledger bound for every scope ─────────

/// User 1000's shell (pid 700) runs `nc` `n` times: each exec an
/// ExploitAttempt recorded in `login uid 1000`.
fn nc_flood(m: &PostureMachine, n: u32) {
    let _ = m.observe(&spawn(700, 1, "bash", "/usr/bin/bash", 1), &[]);
    for i in 0..n {
        let pid = 10_000 + i;
        let _ = m.observe(
            &spawn(pid, 700, "nc", "/usr/bin/nc", 100 + u64::from(i)),
            &[],
        );
    }
}

/// The finding: a service (no login uid) runs an exploit tool, then an
/// unprivileged user runs `nc` in a loop. The flood pushed the service's
/// signal out of the one 64-entry FIFO every scope shared, and the
/// service's exfiltration burst stayed at ENGAGED. Its signal now stays:
/// COMBAT, unlocked, as without the flood.
#[test]
fn another_users_nc_flood_does_not_evict_a_units_evidence() {
    let tmp = tempfile::TempDir::new().unwrap();
    workload_proc(tmp.path(), 42, "/system.slice/app.service");
    login_proc(tmp.path(), 700, SHELL_SESSION);
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(42, 1, "sh", "/usr/bin/sh", 1), &[]);
    let _ = m.observe(&spawn(43, 42, "nc", "/usr/bin/nc", 2), &[]);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    nc_flood(&m, 200);
    assert_eq!(m.corroboration_len(), 2, "the flood is one entry");
    let (ef, er) = exfil_burst(42);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(!m.is_combat_locked());
}

/// The privileged case: puppet's root change to a unit file, then the
/// user's `nc` flood, then puppet's burst. The flood evicted the change,
/// and with it the lock; the burst now reaches a locked COMBAT.
#[test]
fn a_privileged_units_evidence_survives_another_users_flood() {
    let (tmp, m) = puppet_wrote_a_unit();
    login_proc(tmp.path(), 700, SHELL_SESSION);
    nc_flood(&m, 200);
    let (ef, er) = exfil_burst(300);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(
        m.is_combat_locked(),
        "puppet's own pair, with its root change"
    );
}

/// The flood itself corroborates nothing: one kind of evidence, however
/// often, is not two (the user's own burst after it still pairs with it).
#[test]
fn an_nc_flood_alone_stays_engaged() {
    let tmp = tempfile::TempDir::new().unwrap();
    login_proc(tmp.path(), 700, SHELL_SESSION);
    login_proc(tmp.path(), 710, SHELL_SESSION);
    let m = machine_on(tmp.path());
    let _ = m.observe(&spawn(710, 700, "python3", "/usr/bin/python3", 2), &[]);
    nc_flood(&m, 200);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
    let (ef, er) = exfil_burst(710);
    let _ = m.observe(&ef, &er);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert!(!m.is_combat_locked());
}
