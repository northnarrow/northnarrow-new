//! The ADE is a consultant (product decision, 2026-10-15; lab PR 134).
//!
//! A model's verdict is built from strings an attacker writes — command
//! lines, file names, DNS names — and no prompt hardening makes that safe
//! enough to hand it a kill. A verdict that names a response (Kill,
//! KillTree, Quarantine, BlockNetwork, Isolate) is therefore recorded as a
//! recommendation — a detection with the model's reasoning — and nothing
//! is executed. Responses stay with the deterministic rules and the COMBAT
//! ladder, which can be verified. `NN_ADE_ENFORCE=1` lets the verdicts act
//! again; it is a weakening variable (`self_integrity::WEAKENING_ENV`):
//! the agent reports it in the signed chain at every boot.

use common::ade_types::AdeVerdict;

/// Lets ADE verdicts execute their response again (`1`, `true`, `yes`).
pub const ADE_ENFORCE_ENV: &str = "NN_ADE_ENFORCE";

/// Whether this process lets ADE verdicts act (read once).
pub fn enforce() -> bool {
    static ENFORCE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENFORCE.get_or_init(|| {
        std::env::var(ADE_ENFORCE_ENV).is_ok_and(|v| crate::response::config::is_truthy(&v))
    })
}

/// What the agent does with a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// No response named (Allow, Monitor, Alert, Escalate): recorded as it
    /// is (Allow is not a detection).
    Record,
    /// A response named, the ADE a consultant: recorded as a
    /// recommendation, nothing executed.
    Recommend,
    /// A response named and `NN_ADE_ENFORCE` set: executed.
    Execute,
}

/// The disposition of `verdict` — `enforce` is [`enforce`] in the agent.
pub fn disposition(verdict: &AdeVerdict, enforce: bool) -> Disposition {
    if !verdict.requires_execution() {
        Disposition::Record
    } else if enforce {
        Disposition::Execute
    } else {
        Disposition::Recommend
    }
}

/// The response field of the detection record for a verdict that was
/// only recommended.
pub fn recommended(verdict: &AdeVerdict) -> String {
    format!(
        "advisory: {:?} recommended by the model, not executed",
        verdict.to_response_action()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ade_types::*;

    fn verdict(action: AdeAction) -> AdeVerdict {
        AdeVerdict {
            schema_version: ADE_SCHEMA_VERSION.into(),
            trace_id: "00000000-0000-4000-8000-000000000000".into(),
            timestamp_utc: "2026-05-09T08:30:00Z".into(),
            language_used: "it-IT".into(),
            verdict: action,
            severity: AdeSeverity::High,
            confidence: 0.9,
            threat_classification: ThreatClassification {
                family: "x".into(),
                kind: "x".into(),
                novelty: 0.5,
            },
            reasoning: ReasoningSteps {
                step_1_extract: "x".into(),
                step_2_pattern_match: "x".into(),
                step_3_criticality: "x".into(),
                step_4_alternative_explanations: AlternativeExplanations {
                    legitimate_uses: vec!["dev work".into()],
                    assessment: "x".into(),
                },
                step_5_decision: "x".into(),
            },
            evidence: Evidence {
                primary_indicators: vec!["x".into()],
                secondary_indicators: vec![],
                correlation_window_s: None,
            },
            mitre_attack: MitreAttack {
                tactic: vec!["TA0002".into()],
                technique: vec![],
            },
            recommended_action: RecommendedAction {
                action,
                justification: "x".into(),
                side_effects: vec![],
            },
            follow_up: FollowUp {
                policy: FollowUpPolicy::None,
                monitoring_duration_s: None,
            },
            escalation_tier: None,
            escalation_package: None,
            metadata: AdeMetadata {
                model_id: "test".into(),
                model_quantization: "Q4_K_M".into(),
                backend: "mock".into(),
                host_id: "host-x".into(),
                agent_version: "0.0.1".into(),
                inference_latency_ms: 0,
            },
        }
    }

    #[test]
    fn the_flag_takes_truthy_values_only() {
        for (v, on) in [
            ("1", true),
            ("true", true),
            ("yes", true),
            ("0", false),
            ("", false),
            ("on", false),
        ] {
            assert_eq!(crate::response::config::is_truthy(v), on, "{v:?}");
        }
    }

    #[test]
    fn a_named_response_is_only_recommended_unless_enforced() {
        for (action, named) in [
            (AdeAction::Allow, false),
            (AdeAction::Monitor, false),
            (AdeAction::Alert, false),
            (AdeAction::Escalate, false),
            (AdeAction::Kill, true),
            (AdeAction::KillTree, true),
            (AdeAction::Quarantine, true),
            (AdeAction::BlockNetwork, true),
            (AdeAction::Isolate, true),
        ] {
            let v = verdict(action);
            let (advisory, enforced) = (disposition(&v, false), disposition(&v, true));
            if named {
                assert_eq!(advisory, Disposition::Recommend, "{action:?}");
                assert_eq!(enforced, Disposition::Execute, "{action:?}");
                assert!(
                    recommended(&v).starts_with("advisory: "),
                    "{}",
                    recommended(&v)
                );
            } else {
                assert_eq!(
                    (advisory, enforced),
                    (Disposition::Record, Disposition::Record),
                    "{action:?}"
                );
            }
        }
    }

    #[test]
    fn the_enforce_flag_is_a_weakening_variable() {
        assert!(crate::self_integrity::WEAKENING_ENV
            .iter()
            .any(|(name, weakens)| *name == ADE_ENFORCE_ENV && weakens("1") && !weakens("0")));
    }
}
