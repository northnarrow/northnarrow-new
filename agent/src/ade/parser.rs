//! Parse + validate ADE model output.
//!
//! Enforces the 14 schema rules documented in
//! `common::ade_types`. Any violation surfaces as a precise
//! [`ValidationError`] so the escalation transformer can fold it into
//! a Tier1 review with full diagnostic detail.

use common::ade_types::{
    AdeAction, AdeSeverity, AdeVerdict, EscalationTier, FollowUpPolicy, ADE_SCHEMA_VERSION,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("malformed JSON: {0}")]
    MalformedJson(String),

    #[error("schema_version mismatch: expected {expected}, got {got}")]
    SchemaVersionMismatch { expected: String, got: String },

    #[error(
        "rule violation: confidence < 0.40 requires verdict=Escalate, got verdict={verdict}"
    )]
    ConfidenceLowVerdictMismatch { verdict: String },

    #[error(
        "rule violation: verdict={verdict} requires confidence >= 0.40, got {confidence:.4}"
    )]
    VerdictRequiresHigherConfidence { verdict: String, confidence: f64 },

    #[error("rule violation: verdict=Isolate requires confidence >= 0.85 AND severity=Critical")]
    IsolateRequirementsNotMet,

    #[error("rule violation: severity=None requires verdict=Allow")]
    SeverityNoneRequiresAllow,

    #[error("rule violation: verdict=Allow requires severity=None")]
    AllowRequiresSeverityNone,

    #[error(
        "rule violation: verdict=Escalate requires non-null escalation_tier and escalation_package"
    )]
    EscalateRequiresPackage,

    #[error(
        "rule violation: verdict={verdict} requires null escalation_tier and escalation_package"
    )]
    NonEscalateMustNotHavePackage { verdict: String },

    #[error(
        "rule violation: follow_up.policy={policy} requires monitoring_duration_s in [30, 3600], got {got:?}"
    )]
    InvalidMonitoringDuration { policy: String, got: Option<i64> },

    #[error("rule violation: mitre_attack.tactic must have at least 1 element")]
    EmptyMitreTactic,

    #[error("rule violation: evidence.primary_indicators must have at least 1 element")]
    EmptyPrimaryIndicators,

    #[error(
        "rule violation: reasoning.step_4_alternative_explanations.legitimate_uses must have at least 1 element"
    )]
    EmptyLegitimateUses,

    #[error("rule violation: invalid UUID v4 format in field {field}: '{value}'")]
    InvalidUuid { field: String, value: String },

    #[error("rule violation: confidence must have at most 2 decimal places, got {got}")]
    InvalidConfidencePrecision { got: f64 },
}

/// Validates parsed [`AdeVerdict`] instances.
#[derive(Debug, Default, Clone)]
pub struct VerdictParser {
    schema_version: String,
}

impl VerdictParser {
    pub fn new() -> Self {
        Self {
            schema_version: ADE_SCHEMA_VERSION.to_string(),
        }
    }

    pub fn parse(&self, raw: &str) -> Result<AdeVerdict, ValidationError> {
        let trimmed = strip_code_fences(raw);
        let verdict: AdeVerdict = serde_json::from_str(trimmed)
            .map_err(|e| ValidationError::MalformedJson(e.to_string()))?;
        self.validate(&verdict)?;
        Ok(verdict)
    }

    pub fn validate(&self, v: &AdeVerdict) -> Result<(), ValidationError> {
        // 1. schema_version
        if v.schema_version != self.schema_version {
            return Err(ValidationError::SchemaVersionMismatch {
                expected: self.schema_version.clone(),
                got: v.schema_version.clone(),
            });
        }

        // 12. trace_id format (UUID v4)
        if !is_uuid_v4(&v.trace_id) {
            return Err(ValidationError::InvalidUuid {
                field: "trace_id".into(),
                value: v.trace_id.clone(),
            });
        }

        // 13. confidence precision
        if !has_at_most_two_decimals(v.confidence) {
            return Err(ValidationError::InvalidConfidencePrecision { got: v.confidence });
        }

        // 2. confidence < 0.40 ⇒ verdict = Escalate
        if v.confidence < 0.40 && v.verdict != AdeAction::Escalate {
            return Err(ValidationError::ConfidenceLowVerdictMismatch {
                verdict: v.verdict.as_str().into(),
            });
        }

        // 3. non-low-conf verdicts that aren't Allow/Monitor/Escalate
        //    require confidence >= 0.40. Allow has its own rule (5),
        //    Monitor is fine at any conf since it's read-only.
        if !matches!(
            v.verdict,
            AdeAction::Allow | AdeAction::Monitor | AdeAction::Escalate
        ) && v.confidence < 0.40
        {
            return Err(ValidationError::VerdictRequiresHigherConfidence {
                verdict: v.verdict.as_str().into(),
                confidence: v.confidence,
            });
        }

        // 4. Isolate ⇒ confidence >= 0.85 AND severity = Critical
        if v.verdict == AdeAction::Isolate
            && (v.confidence < 0.85 || v.severity != AdeSeverity::Critical)
        {
            return Err(ValidationError::IsolateRequirementsNotMet);
        }

        // 5. severity=None ⇒ verdict=Allow
        if v.severity == AdeSeverity::None && v.verdict != AdeAction::Allow {
            return Err(ValidationError::SeverityNoneRequiresAllow);
        }
        // 5b (companion). verdict=Allow ⇒ severity=None
        if v.verdict == AdeAction::Allow && v.severity != AdeSeverity::None {
            return Err(ValidationError::AllowRequiresSeverityNone);
        }

        // 6 + 7. Escalate ⇔ non-null escalation_tier + package
        match v.verdict {
            AdeAction::Escalate => {
                if v.escalation_tier.is_none() || v.escalation_package.is_none() {
                    return Err(ValidationError::EscalateRequiresPackage);
                }
            }
            other => {
                if v.escalation_tier.is_some() || v.escalation_package.is_some() {
                    return Err(ValidationError::NonEscalateMustNotHavePackage {
                        verdict: other.as_str().into(),
                    });
                }
            }
        }

        // 8. follow_up.Monitor requires monitoring_duration_s in [30, 3600]
        if v.follow_up.policy == FollowUpPolicy::Monitor {
            match v.follow_up.monitoring_duration_s {
                Some(d) if (30..=3600).contains(&d) => {}
                got => {
                    return Err(ValidationError::InvalidMonitoringDuration {
                        policy: "Monitor".into(),
                        got,
                    });
                }
            }
        }

        // 9. mitre_attack.tactic ≥ 1
        if v.mitre_attack.tactic.is_empty() {
            return Err(ValidationError::EmptyMitreTactic);
        }

        // 10. evidence.primary_indicators ≥ 1
        if v.evidence.primary_indicators.is_empty() {
            return Err(ValidationError::EmptyPrimaryIndicators);
        }

        // 11. reasoning.step_4 legitimate_uses ≥ 1
        if v.reasoning
            .step_4_alternative_explanations
            .legitimate_uses
            .is_empty()
        {
            return Err(ValidationError::EmptyLegitimateUses);
        }

        // Note: rule 14 (unknown enum variants) is enforced by serde
        // automatically — `AdeAction`, `AdeSeverity`, etc. are
        // closed enums, so an unknown string surfaces as a
        // `MalformedJson` error.
        let _ = (v.recommended_action.action, v.escalation_tier);
        let _: Option<EscalationTier> = v.escalation_tier;

        Ok(())
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

/// Strips `\`\`\`json … \`\`\`` and `\`\`\` … \`\`\`` wrappers if the
/// model emits one despite the prompt's instructions.
fn strip_code_fences(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        return rest.trim().strip_suffix("```").unwrap_or(rest).trim();
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        return rest.trim().strip_suffix("```").unwrap_or(rest).trim();
    }
    trimmed
}

/// Lower-case canonical UUID v4: 8-4-4-4-12 hex with the version
/// nibble = 4 and the variant bits = 10xx (i.e. `8|9|a|b` in
/// position 19).
fn is_uuid_v4(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let dashes = [8, 13, 18, 23];
    for (i, &b) in bytes.iter().enumerate() {
        if dashes.contains(&i) {
            if b != b'-' {
                return false;
            }
            continue;
        }
        if !is_hex_lower(b) {
            return false;
        }
    }
    if bytes[14] != b'4' {
        return false;
    }
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    true
}

fn is_hex_lower(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

/// Accept a confidence with at most 2 decimal places. Allow tiny
/// floating-point error — rounding to centi-units must yield the
/// same value.
fn has_at_most_two_decimals(v: f64) -> bool {
    if !v.is_finite() {
        return false;
    }
    let scaled = v * 100.0;
    (scaled - scaled.round()).abs() < 1e-6
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ade_types::{
        AlternativeExplanations, EscalationPackage, Evidence, FollowUp, MitreAttack,
        AdeMetadata, ReasoningSteps, RecommendedAction, ThreatClassification,
    };

    fn base_verdict() -> AdeVerdict {
        AdeVerdict {
            schema_version: ADE_SCHEMA_VERSION.into(),
            trace_id: "00000000-0000-4000-8000-000000000000".into(),
            timestamp_utc: "2026-05-09T08:00:00Z".into(),
            language_used: "it-IT".into(),
            verdict: AdeAction::Alert,
            severity: AdeSeverity::Medium,
            confidence: 0.65,
            threat_classification: ThreatClassification {
                family: "unknown".into(),
                kind: "process_spawn".into(),
                novelty: 0.50,
            },
            reasoning: ReasoningSteps {
                step_1_extract: "x".into(),
                step_2_pattern_match: "x".into(),
                step_3_criticality: "x".into(),
                step_4_alternative_explanations: AlternativeExplanations {
                    legitimate_uses: vec!["dev".into()],
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
                action: AdeAction::Alert,
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
                host_id: "h".into(),
                agent_version: "0.0.1".into(),
                inference_latency_ms: 0,
            },
        }
    }

    fn parser() -> VerdictParser {
        VerdictParser::new()
    }

    // ---- 14 validation-rule tests -----------------------------------

    #[test]
    fn r01_schema_version_mismatch() {
        let mut v = base_verdict();
        v.schema_version = "0.9.0".into();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::SchemaVersionMismatch { .. }
        ));
    }

    #[test]
    fn r02_low_confidence_must_escalate() {
        let mut v = base_verdict();
        v.confidence = 0.30;
        v.verdict = AdeAction::Alert;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ConfidenceLowVerdictMismatch { .. }
        ));
    }

    #[test]
    fn r03_kill_with_low_confidence_rejected() {
        let mut v = base_verdict();
        v.confidence = 0.30;
        v.verdict = AdeAction::Kill;
        v.severity = AdeSeverity::High;
        // The low-confidence rule fires first (rule 2).
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ConfidenceLowVerdictMismatch { .. }
        ));
    }

    #[test]
    fn r04_isolate_requires_high_confidence_and_critical() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Isolate;
        v.severity = AdeSeverity::Critical;
        v.confidence = 0.80;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::IsolateRequirementsNotMet));

        let mut v2 = base_verdict();
        v2.verdict = AdeAction::Isolate;
        v2.confidence = 0.95;
        v2.severity = AdeSeverity::High; // not Critical
        let err = parser().validate(&v2).unwrap_err();
        assert!(matches!(err, ValidationError::IsolateRequirementsNotMet));
    }

    #[test]
    fn r05a_severity_none_requires_allow() {
        let mut v = base_verdict();
        v.severity = AdeSeverity::None;
        v.verdict = AdeAction::Alert;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::SeverityNoneRequiresAllow));
    }

    #[test]
    fn r05b_allow_requires_severity_none() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Allow;
        v.severity = AdeSeverity::Low;
        v.confidence = 0.97;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::AllowRequiresSeverityNone));
    }

    #[test]
    fn r06_escalate_requires_package() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Escalate;
        v.confidence = 0.30;
        v.escalation_tier = None;
        v.escalation_package = None;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::EscalateRequiresPackage));
    }

    #[test]
    fn r07_non_escalate_must_not_have_package() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Alert;
        v.escalation_tier = Some(EscalationTier::Tier1Review);
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::NonEscalateMustNotHavePackage { .. }
        ));
    }

    #[test]
    fn r08_monitor_policy_requires_valid_duration() {
        let mut v = base_verdict();
        v.follow_up.policy = FollowUpPolicy::Monitor;
        v.follow_up.monitoring_duration_s = Some(5); // < 30
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::InvalidMonitoringDuration { .. }
        ));

        v.follow_up.monitoring_duration_s = None;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::InvalidMonitoringDuration { .. }
        ));

        v.follow_up.monitoring_duration_s = Some(7200); // > 3600
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::InvalidMonitoringDuration { .. }
        ));
    }

    #[test]
    fn r09_mitre_tactic_must_be_non_empty() {
        let mut v = base_verdict();
        v.mitre_attack.tactic.clear();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::EmptyMitreTactic));
    }

    #[test]
    fn r10_primary_indicators_must_be_non_empty() {
        let mut v = base_verdict();
        v.evidence.primary_indicators.clear();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::EmptyPrimaryIndicators));
    }

    #[test]
    fn r11_legitimate_uses_must_be_non_empty() {
        let mut v = base_verdict();
        v.reasoning
            .step_4_alternative_explanations
            .legitimate_uses
            .clear();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::EmptyLegitimateUses));
    }

    #[test]
    fn r12_invalid_uuid_rejected() {
        let mut v = base_verdict();
        v.trace_id = "not-a-uuid".into();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUuid { .. }));

        // v3 uuid (version nibble != 4) — rejected
        v.trace_id = "00000000-0000-3000-8000-000000000000".into();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUuid { .. }));

        // wrong variant nibble (should be 8/9/a/b at pos 19)
        v.trace_id = "00000000-0000-4000-c000-000000000000".into();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUuid { .. }));

        // upper-case rejected
        v.trace_id = "AAAAAAAA-0000-4000-8000-000000000000".into();
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUuid { .. }));
    }

    #[test]
    fn r13_confidence_precision_capped_at_2_decimals() {
        let mut v = base_verdict();
        v.confidence = 0.873;
        let err = parser().validate(&v).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::InvalidConfidencePrecision { .. }
        ));
    }

    #[test]
    fn r14_unknown_enum_variants_rejected_via_serde() {
        let raw = r#"{
            "schema_version":"1.0.0",
            "trace_id":"00000000-0000-4000-8000-000000000000",
            "timestamp_utc":"2026-05-09T08:00:00Z",
            "language_used":"it-IT",
            "verdict":"Nuke",
            "severity":"Medium",
            "confidence":0.65,
            "threat_classification":{"family":"u","kind":"k","novelty":0.5},
            "reasoning":{"step_1_extract":"x","step_2_pattern_match":"x","step_3_criticality":"x","step_4_alternative_explanations":{"legitimate_uses":["x"],"assessment":"x"},"step_5_decision":"x"},
            "evidence":{"primary_indicators":["x"]},
            "mitre_attack":{"tactic":["TA0002"]},
            "recommended_action":{"action":"Nuke","justification":"x"},
            "follow_up":{"policy":"None"},
            "metadata":{"model_id":"x","model_quantization":"Q4","backend":"mock","host_id":"h","agent_version":"v","inference_latency_ms":0}
        }"#;
        let err = parser().parse(raw).unwrap_err();
        assert!(matches!(err, ValidationError::MalformedJson(_)));
    }

    // ---- happy-path tests -------------------------------------------

    #[test]
    fn happy_alert_passes() {
        let v = base_verdict();
        parser().validate(&v).expect("valid alert");
    }

    #[test]
    fn happy_kill_high_confidence_passes() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Kill;
        v.severity = AdeSeverity::High;
        v.confidence = 0.94;
        v.recommended_action.action = AdeAction::Kill;
        parser().validate(&v).expect("valid kill");
    }

    #[test]
    fn happy_allow_severity_none_passes() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Allow;
        v.severity = AdeSeverity::None;
        v.confidence = 0.97;
        v.recommended_action.action = AdeAction::Allow;
        parser().validate(&v).expect("valid allow");
    }

    #[test]
    fn happy_escalate_with_package_passes() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Escalate;
        v.confidence = 0.40;
        v.escalation_tier = Some(EscalationTier::Tier1Review);
        v.escalation_package = Some(EscalationPackage {
            summary: "review me".into(),
            key_questions: vec!["who?".into()],
            raw_model_output: None,
            source_event_pid: Some(1234),
            source_event_filename: Some("/x".into()),
        });
        v.recommended_action.action = AdeAction::Escalate;
        parser().validate(&v).expect("valid escalate");
    }

    #[test]
    fn happy_isolate_at_threshold_passes() {
        let mut v = base_verdict();
        v.verdict = AdeAction::Isolate;
        v.severity = AdeSeverity::Critical;
        v.confidence = 0.85;
        v.recommended_action.action = AdeAction::Isolate;
        parser().validate(&v).expect("valid isolate");
    }

    // ---- edge cases --------------------------------------------------

    #[test]
    fn edge_malformed_json_unbalanced_braces() {
        let raw = r#"{"schema_version":"1.0.0""#;
        let err = parser().parse(raw).unwrap_err();
        assert!(matches!(err, ValidationError::MalformedJson(_)));
    }

    #[test]
    fn edge_truncated_output_is_malformed() {
        let raw = r#"{"schema_version":"1.0.0","trace_id":"0000"#;
        let err = parser().parse(raw).unwrap_err();
        assert!(matches!(err, ValidationError::MalformedJson(_)));
    }

    #[test]
    fn edge_extra_unknown_fields_are_accepted() {
        // We use serde defaults, which ignore unknown fields. This is
        // intentional: future schema additions should not break old
        // parsers.
        let raw = r#"{
            "schema_version":"1.0.0",
            "trace_id":"00000000-0000-4000-8000-000000000000",
            "timestamp_utc":"2026-05-09T08:00:00Z",
            "language_used":"it-IT",
            "verdict":"Alert",
            "severity":"Medium",
            "confidence":0.65,
            "threat_classification":{"family":"u","kind":"k","novelty":0.5},
            "reasoning":{"step_1_extract":"x","step_2_pattern_match":"x","step_3_criticality":"x","step_4_alternative_explanations":{"legitimate_uses":["x"],"assessment":"x"},"step_5_decision":"x"},
            "evidence":{"primary_indicators":["x"]},
            "mitre_attack":{"tactic":["TA0002"]},
            "recommended_action":{"action":"Alert","justification":"x"},
            "follow_up":{"policy":"None"},
            "metadata":{"model_id":"x","model_quantization":"Q4","backend":"mock","host_id":"h","agent_version":"v","inference_latency_ms":0},
            "future_field_2027":"safe to ignore"
        }"#;
        parser().parse(raw).expect("forward-compatible");
    }

    #[test]
    fn parses_output_wrapped_in_json_code_fences() {
        let raw = "```json\n".to_string()
            + r#"{
            "schema_version":"1.0.0",
            "trace_id":"00000000-0000-4000-8000-000000000000",
            "timestamp_utc":"2026-05-09T08:00:00Z",
            "language_used":"it-IT",
            "verdict":"Alert",
            "severity":"Medium",
            "confidence":0.65,
            "threat_classification":{"family":"u","kind":"k","novelty":0.5},
            "reasoning":{"step_1_extract":"x","step_2_pattern_match":"x","step_3_criticality":"x","step_4_alternative_explanations":{"legitimate_uses":["x"],"assessment":"x"},"step_5_decision":"x"},
            "evidence":{"primary_indicators":["x"]},
            "mitre_attack":{"tactic":["TA0002"]},
            "recommended_action":{"action":"Alert","justification":"x"},
            "follow_up":{"policy":"None"},
            "metadata":{"model_id":"x","model_quantization":"Q4","backend":"mock","host_id":"h","agent_version":"v","inference_latency_ms":0}
        }"#
            + "\n```";
        parser().parse(&raw).expect("fence-stripping parser");
    }
}
