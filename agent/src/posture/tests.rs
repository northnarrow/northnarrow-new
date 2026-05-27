//! Cross-module tests: PostureMachine end-to-end behaviour.

use std::sync::Arc;
use std::thread;

use common::ade_types::{
    AdeAction, AdeMetadata, AdeSeverity, AdeVerdict, AlternativeExplanations, Evidence, FollowUp,
    FollowUpPolicy, MitreAttack, ReasoningSteps, RecommendedAction, ThreatClassification,
    ADE_SCHEMA_VERSION,
};
use common::posture_types::PostureKind;
use common::Event;

use super::triggers::testutil::{file_open, spawn, tcp_v4};
use super::{AdminReleaseError, AuthSessionTracker, ExemptPids, PostureMachine};

fn baseline_verdict(action: AdeAction, severity: AdeSeverity) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.to_string(),
        trace_id: "00000000-0000-4000-8000-000000000000".to_string(),
        timestamp_utc: "2026-05-09T08:30:00Z".to_string(),
        language_used: "en-US".to_string(),
        verdict: action,
        severity,
        confidence: 0.70,
        threat_classification: ThreatClassification {
            family: "x".to_string(),
            kind: "x".to_string(),
            novelty: 0.5,
        },
        reasoning: ReasoningSteps {
            step_1_extract: "x".to_string(),
            step_2_pattern_match: "x".to_string(),
            step_3_criticality: "x".to_string(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["dev".to_string()],
                assessment: "x".to_string(),
            },
            step_5_decision: "x".to_string(),
        },
        evidence: Evidence {
            primary_indicators: vec!["x".to_string()],
            secondary_indicators: vec![],
            correlation_window_s: None,
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0002".to_string()],
            technique: vec![],
        },
        recommended_action: RecommendedAction {
            action,
            justification: "x".to_string(),
            side_effects: vec![],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::None,
            monitoring_duration_s: None,
        },
        escalation_tier: None,
        escalation_package: None,
        metadata: AdeMetadata {
            model_id: "test".to_string(),
            model_quantization: "Q4_K_M".to_string(),
            backend: "mock".to_string(),
            host_id: "host-x".to_string(),
            agent_version: "0.0.1".to_string(),
            inference_latency_ms: 0,
        },
    }
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
    let focal = spawn(42, 1, "evil", "/tmp/evil", 1);
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
    let focal = spawn(42, 1, "evil", "/tmp/evil", 1);
    m.observe(&focal, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    let next = m.admin_release_combat(true).expect("ok");
    assert_eq!(next.kind(), PostureKind::Engaged);
    assert_eq!(m.current_kind(), PostureKind::Engaged);
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
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
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
fn modulate_verdict_unchanged_in_observing() {
    let m = PostureMachine::new();
    let v = baseline_verdict(AdeAction::Allow, AdeSeverity::None);
    let out = m.modulate_verdict(v);
    assert_eq!(out.verdict, AdeAction::Allow);
    assert_eq!(out.severity, AdeSeverity::None);
}

#[test]
fn modulate_verdict_promotes_allow_to_alert_in_alerted() {
    let m = PostureMachine::new();
    // Push to ALERTED via recon.
    let recon_recent = vec![
        tcp_v4(42, [127, 0, 0, 1], 22, 100),
        tcp_v4(42, [127, 0, 0, 1], 80, 200),
    ];
    let recon_focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
    m.observe(&recon_focal, &recon_recent);
    assert_eq!(m.current_kind(), PostureKind::Alerted);

    let v = baseline_verdict(AdeAction::Allow, AdeSeverity::None);
    let out = m.modulate_verdict(v);
    assert_eq!(out.verdict, AdeAction::Alert);
    assert_eq!(out.severity, AdeSeverity::Low);
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
fn concurrent_observe_and_modulate_is_safe() {
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
            let v = baseline_verdict(AdeAction::Allow, AdeSeverity::None);
            for _ in 0..50 {
                let _ = m2.modulate_verdict(v.clone());
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
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
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
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
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

    // ConfirmedIntrusion crosses into COMBAT — hook fires exactly once.
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn combat_hook_does_not_refire_while_already_in_combat() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    let m = PostureMachine::new_with_combat_hook(Arc::new(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    }));

    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
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
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
    m.observe(&intrusion, &[]);
    assert_eq!(m.current_kind(), PostureKind::Combat);
}

// ─── admin_release_combat_with_token (Tappa 7 task 7 / Tappa 8) ─────

#[test]
fn admin_release_with_token_transitions_combat_to_alerted() {
    let m = PostureMachine::new();
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
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
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
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
            let next = m
                .admin_force_state_with_token(token, to)
                .expect("any-to-any allowed");
            assert_eq!(next.kind(), to);
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
        .admin_force_state_with_token(token, PostureKind::Combat)
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
        .admin_force_state_with_token(token, PostureKind::Observing)
        .expect("Combat → Observing allowed");
    assert_eq!(m.current_kind(), PostureKind::Observing);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "combat_release_hook should fire exactly once on Combat → non-Combat"
    );
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
    let apt_spawn = spawn(200, 100, "apt", "/usr/bin/apt", 3);
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

/// Test #16 — ransomware-shape from /tmp still reaches COMBAT.
/// Negative control: a non-auth-mediated exec from /tmp must still
/// trip ConfirmedIntrusion via the exec-from-/tmp arm. The lineage
/// gate must NOT be too broad.
#[test]
fn ransomware_shape_still_reaches_combat() {
    let m = machine_with_isolated_auth();
    // No sudo lineage. Direct exec from /tmp.
    let evil = spawn(900, 1, "payload", "/tmp/payload", 1);
    let r = m.observe(&evil, &[]);
    assert!(r.is_some(), "exec-from-/tmp must transition");
    assert_eq!(
        m.current_kind(),
        PostureKind::Combat,
        "non-auth exec from /tmp must still drive COMBAT"
    );
}

/// Test #17 — mass-write alone from a non-auth PID still reaches
/// COMBAT. Confirms the mass-write arm itself still works for
/// adversarial PIDs (the lineage gate is the only suppressor).
#[test]
fn mass_write_alone_from_non_auth_pid_still_reaches_combat() {
    let m = machine_with_isolated_auth();
    // Spawn a non-auth parent so the writer's lineage is clean.
    let _ = m.observe(&spawn(900, 1, "zsh", "/usr/bin/zsh", 1), &[]);

    let recent: Vec<Event> = (0..25u64)
        .map(|i| file_open(900, 1000, "/home/u/x", 1, i + 100))
        .collect();
    let focal = file_open(900, 1000, "/home/u/x", 1, 200);
    let r = m.observe(&focal, &recent);
    assert!(r.is_some(), "non-auth mass-write must transition");
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
        .admin_force_state_with_token(token, PostureKind::Observing)
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
