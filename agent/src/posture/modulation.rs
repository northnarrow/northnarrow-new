//! Modulate ADE verdicts according to the current posture.
//!
//! Modulation is two things stacked:
//!
//! 1. *Severity inflation* — bump the severity up by a fixed number
//!    of levels (`Low → Medium`, `Medium → High`, `High → Critical`).
//!    Ladder is one-way: nothing ever gets de-escalated by posture.
//! 2. *Action upgrade* — a `severity ≥ Medium` verdict that the LLM
//!    issued as `Allow` becomes `Alert`; in `Combat` even `Monitor`
//!    becomes `Alert`. This is the lever that turns "ambiguous event
//!    in OBSERVING → Allow" into "ambiguous event in ALERTED → Alert".
//!
//! The ADE schema rule "verdict==Allow ⇔ severity==None" is preserved:
//! if we inflate severity, we also lift the action so we don't end up
//! with `Allow + Medium` (illegal). The exact mapping is:
//!
//! | Posture     | Severity bump | Action floor for severity ≥ Medium |
//! |-------------|---------------|-----------------------------------|
//! | Observing   | +0            | unchanged                          |
//! | Alerted     | +1            | Allow→Alert                        |
//! | Engaged     | +1            | Allow/Monitor→Alert                |
//! | Combat      | +2            | Allow/Monitor→Alert                |
//!
//! `Isolate` already requires `severity==Critical` per schema rule 4,
//! so we never need to *upgrade into* `Isolate` here — modulation
//! sits below that line.

use common::ade_types::{AdeAction, AdeSeverity, AdeVerdict};
use common::posture_types::PostureKind;

/// Apply posture-driven modulation to `verdict`. Returns the modified
/// verdict; never mutates the input.
pub fn modulate(verdict: &AdeVerdict, posture: PostureKind) -> AdeVerdict {
    let bump = severity_bump(posture);
    let mut out = verdict.clone();

    out.severity = inflate(verdict.severity, bump);

    // Recompute the action so we stay within ADE schema rule 5
    // (`Allow ⇔ severity==None`). When severity has lifted off of
    // None, the action must follow.
    if out.severity != AdeSeverity::None {
        out.verdict = upgrade_action(verdict.verdict, posture);
        out.recommended_action.action = out.verdict;
    }

    out
}

fn severity_bump(p: PostureKind) -> u8 {
    match p {
        PostureKind::Observing => 0,
        PostureKind::Alerted | PostureKind::Engaged => 1,
        PostureKind::Combat => 2,
    }
}

fn inflate(sev: AdeSeverity, bump: u8) -> AdeSeverity {
    if bump == 0 {
        return sev;
    }
    let mut idx = severity_index(sev);
    idx = idx.saturating_add(bump as usize);
    if idx > 4 {
        idx = 4;
    }
    severity_from_index(idx)
}

fn severity_index(sev: AdeSeverity) -> usize {
    match sev {
        AdeSeverity::None => 0,
        AdeSeverity::Low => 1,
        AdeSeverity::Medium => 2,
        AdeSeverity::High => 3,
        AdeSeverity::Critical => 4,
    }
}

fn severity_from_index(i: usize) -> AdeSeverity {
    match i {
        0 => AdeSeverity::None,
        1 => AdeSeverity::Low,
        2 => AdeSeverity::Medium,
        3 => AdeSeverity::High,
        _ => AdeSeverity::Critical,
    }
}

/// Upgrade `action` for a severity that is now ≥ Low.
///
/// In `Combat`, `Monitor` also lifts to `Alert`. We never weaken an
/// existing executor-bound action (Kill, Quarantine, BlockNetwork,
/// etc.) — those stay intact.
fn upgrade_action(action: AdeAction, posture: PostureKind) -> AdeAction {
    match (action, posture) {
        (AdeAction::Allow, PostureKind::Observing) => AdeAction::Allow,
        (AdeAction::Allow, _) => AdeAction::Alert,
        (AdeAction::Monitor, PostureKind::Combat) => AdeAction::Alert,
        (a, _) => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ade_types::{
        AdeAction, AdeMetadata, AlternativeExplanations, Evidence, FollowUp, FollowUpPolicy,
        MitreAttack, ReasoningSteps, RecommendedAction, ThreatClassification, ADE_SCHEMA_VERSION,
    };

    fn sample_verdict(action: AdeAction, severity: AdeSeverity) -> AdeVerdict {
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
    fn observing_does_not_modify_verdict() {
        let v = sample_verdict(AdeAction::Allow, AdeSeverity::None);
        let m = modulate(&v, PostureKind::Observing);
        assert_eq!(m.verdict, AdeAction::Allow);
        assert_eq!(m.severity, AdeSeverity::None);
    }

    #[test]
    fn alerted_inflates_low_to_medium() {
        let v = sample_verdict(AdeAction::Monitor, AdeSeverity::Low);
        let m = modulate(&v, PostureKind::Alerted);
        assert_eq!(m.severity, AdeSeverity::Medium);
    }

    #[test]
    fn alerted_promotes_allow_to_alert_when_severity_lifts_off_none() {
        let v = sample_verdict(AdeAction::Allow, AdeSeverity::None);
        // Allow+None inflated by +1 → severity becomes Low, action
        // must lift to Alert (Allow with non-None severity is illegal).
        let m = modulate(&v, PostureKind::Alerted);
        assert_eq!(m.severity, AdeSeverity::Low);
        assert_eq!(m.verdict, AdeAction::Alert);
        assert_eq!(m.recommended_action.action, AdeAction::Alert);
    }

    #[test]
    fn engaged_keeps_kill_action_intact() {
        let v = sample_verdict(AdeAction::Kill, AdeSeverity::High);
        let m = modulate(&v, PostureKind::Engaged);
        assert_eq!(m.verdict, AdeAction::Kill);
        assert_eq!(m.severity, AdeSeverity::Critical);
    }

    #[test]
    fn combat_inflates_by_two_levels() {
        let v = sample_verdict(AdeAction::Monitor, AdeSeverity::Low);
        let m = modulate(&v, PostureKind::Combat);
        assert_eq!(m.severity, AdeSeverity::High);
        assert_eq!(m.verdict, AdeAction::Alert);
    }

    #[test]
    fn combat_caps_severity_at_critical() {
        let v = sample_verdict(AdeAction::Kill, AdeSeverity::High);
        let m = modulate(&v, PostureKind::Combat);
        assert_eq!(m.severity, AdeSeverity::Critical);
    }

    #[test]
    fn combat_promotes_monitor_to_alert() {
        let v = sample_verdict(AdeAction::Monitor, AdeSeverity::Medium);
        let m = modulate(&v, PostureKind::Combat);
        assert_eq!(m.verdict, AdeAction::Alert);
    }
}
