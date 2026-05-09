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
use super::{AdminReleaseError, PostureMachine};

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
