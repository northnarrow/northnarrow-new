//! Active Defense Engine (ADE) verdict schema (v1.0.0).
//!
//! These structs mirror the JSON schema documented in `docs/ADE_SCHEMA.md`.
//! ADE produces an [`AdeVerdict`] for every event the deterministic rule
//! engine cannot classify; the [`crate::Verdict`] (rule-engine output)
//! and the richer [`AdeVerdict`] coexist:
//!
//! - `Verdict` is a flat decision record produced by hardcoded rules.
//! - `AdeVerdict` is the full structured output of the LLM, including
//!   reasoning chain, MITRE mapping, evidence and (optionally) an
//!   escalation package for human review.
//!
//! Both ultimately collapse to a [`crate::ResponseAction`] when the
//! executor runs them. The bridge is [`AdeVerdict::to_response_action`].
//!
//! Schema rules (enforced by `agent::ade::parser`):
//!
//! 1.  `schema_version` MUST equal `ADE_SCHEMA_VERSION`.
//! 2.  `confidence < 0.40` ⇒ `verdict == AdeAction::Escalate`.
//! 3.  Any non-`Escalate`/`Allow`/`Monitor` verdict requires
//!     `confidence ≥ 0.40`.
//! 4.  `verdict == Isolate` requires `confidence ≥ 0.85` AND
//!     `severity == Critical`.
//! 5.  `severity == None` ⇔ `verdict == Allow`.
//! 6.  `verdict == Escalate` requires non-null `escalation_tier` AND
//!     non-null `escalation_package`.
//! 7.  Non-`Escalate` verdicts MUST have null `escalation_tier` AND
//!     null `escalation_package`.
//! 8.  When `follow_up.policy == Monitor`, `monitoring_duration_s`
//!     MUST be in `[30, 3600]`.
//! 9.  `mitre_attack.tactic` MUST have at least one entry.
//! 10. `evidence.primary_indicators` MUST have at least one entry.
//! 11. `reasoning.step_4_alternative_explanations.legitimate_uses`
//!     MUST have at least one entry.
//! 12. `trace_id` MUST be a UUID v4 (canonical lower-case form).
//! 13. `confidence` MUST be a value with at most 2 decimal places.
//! 14. Unknown enum variants in `verdict`, `severity`, `escalation_tier`,
//!     `follow_up.policy` MUST be rejected.

use alloc::string::String;
#[cfg(test)]
use alloc::string::ToString;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::model::ResponseAction;

/// Schema version embedded in every ADE output. Bump on breaking changes.
pub const ADE_SCHEMA_VERSION: &str = "1.0.0";

/// Top-level ADE output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdeVerdict {
    pub schema_version: String,
    pub trace_id: String,
    pub timestamp_utc: String,
    pub language_used: String,

    pub verdict: AdeAction,
    pub severity: AdeSeverity,
    pub confidence: f64,

    pub threat_classification: ThreatClassification,
    pub reasoning: ReasoningSteps,
    pub evidence: Evidence,
    pub mitre_attack: MitreAttack,

    pub recommended_action: RecommendedAction,
    pub follow_up: FollowUp,

    /// Required when `verdict == Escalate`, MUST be null otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_tier: Option<EscalationTier>,

    /// Required when `verdict == Escalate`, MUST be null otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_package: Option<EscalationPackage>,

    pub metadata: AdeMetadata,
}

/// Top-level action proposed by ADE.
///
/// Maps onto [`ResponseAction`] via [`AdeVerdict::to_response_action`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdeAction {
    Allow,
    Monitor,
    Alert,
    Throttle,
    Kill,
    KillTree,
    Quarantine,
    BlockNetwork,
    Isolate,
    Escalate,
}

/// Severity class. `None` is reserved for `verdict == Allow`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdeSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Tier of human review when ADE escalates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EscalationTier {
    Tier1Review,
    Tier2Review,
    Tier3Review,
}

/// Coarse threat taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatClassification {
    pub family: String,
    pub kind: String,
    pub novelty: f64,
}

/// 5-step reasoning chain mandated by the ADE system prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningSteps {
    pub step_1_extract: String,
    pub step_2_pattern_match: String,
    pub step_3_criticality: String,
    pub step_4_alternative_explanations: AlternativeExplanations,
    pub step_5_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeExplanations {
    pub legitimate_uses: Vec<String>,
    pub assessment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub primary_indicators: Vec<String>,
    #[serde(default)]
    pub secondary_indicators: Vec<String>,
    #[serde(default)]
    pub correlation_window_s: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttack {
    pub tactic: Vec<String>,
    #[serde(default)]
    pub technique: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action: AdeAction,
    pub justification: String,
    #[serde(default)]
    pub side_effects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowUp {
    pub policy: FollowUpPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_duration_s: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FollowUpPolicy {
    None,
    Monitor,
    Recheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPackage {
    pub summary: String,
    pub key_questions: Vec<String>,
    #[serde(default)]
    pub raw_model_output: Option<String>,
    #[serde(default)]
    pub source_event_pid: Option<u32>,
    #[serde(default)]
    pub source_event_filename: Option<String>,
}

/// Telemetry stamped onto every verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdeMetadata {
    pub model_id: String,
    pub model_quantization: String,
    pub backend: String,
    pub host_id: String,
    pub agent_version: String,
    pub inference_latency_ms: u64,
}

impl AdeVerdict {
    /// Translate the LLM verdict to the executor-level [`ResponseAction`].
    ///
    /// Verdicts that don't map to a concrete executor (e.g. `Alert`,
    /// `Monitor`, `Escalate`, `Allow`) collapse to [`ResponseAction::Log`]
    /// — the agent loop is responsible for additional handling
    /// (e.g. queueing the escalation package).
    pub fn to_response_action(&self) -> ResponseAction {
        match self.verdict {
            AdeAction::Kill => ResponseAction::KillProcess,
            AdeAction::KillTree => ResponseAction::KillProcessTree,
            AdeAction::Quarantine => ResponseAction::Quarantine,
            AdeAction::BlockNetwork => ResponseAction::BlockOutbound,
            AdeAction::Isolate => ResponseAction::FullNetworkIsolation,
            AdeAction::Throttle => ResponseAction::ThrottleProcess,
            AdeAction::Allow
            | AdeAction::Monitor
            | AdeAction::Alert
            | AdeAction::Escalate => ResponseAction::Log,
        }
    }

    /// Returns true if the verdict has an actionable executor mapping
    /// (i.e. would actually run something on the host).
    pub fn requires_execution(&self) -> bool {
        !matches!(
            self.verdict,
            AdeAction::Allow | AdeAction::Monitor | AdeAction::Alert | AdeAction::Escalate
        )
    }
}

impl AdeAction {
    /// Render in the canonical PascalCase form used by the schema.
    pub fn as_str(&self) -> &'static str {
        match self {
            AdeAction::Allow => "Allow",
            AdeAction::Monitor => "Monitor",
            AdeAction::Alert => "Alert",
            AdeAction::Throttle => "Throttle",
            AdeAction::Kill => "Kill",
            AdeAction::KillTree => "KillTree",
            AdeAction::Quarantine => "Quarantine",
            AdeAction::BlockNetwork => "BlockNetwork",
            AdeAction::Isolate => "Isolate",
            AdeAction::Escalate => "Escalate",
        }
    }
}

impl AdeSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdeSeverity::None => "None",
            AdeSeverity::Low => "Low",
            AdeSeverity::Medium => "Medium",
            AdeSeverity::High => "High",
            AdeSeverity::Critical => "Critical",
        }
    }
}

impl core::fmt::Display for AdeAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Display for AdeSeverity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verdict(action: AdeAction, severity: AdeSeverity, confidence: f64) -> AdeVerdict {
        AdeVerdict {
            schema_version: ADE_SCHEMA_VERSION.to_string(),
            trace_id: "00000000-0000-4000-8000-000000000000".to_string(),
            timestamp_utc: "2026-05-09T08:30:00Z".to_string(),
            language_used: "it-IT".to_string(),
            verdict: action,
            severity,
            confidence,
            threat_classification: ThreatClassification {
                family: "unknown".to_string(),
                kind: "unspecified".to_string(),
                novelty: 0.50,
            },
            reasoning: ReasoningSteps {
                step_1_extract: "x".to_string(),
                step_2_pattern_match: "x".to_string(),
                step_3_criticality: "x".to_string(),
                step_4_alternative_explanations: AlternativeExplanations {
                    legitimate_uses: alloc::vec!["dev work".to_string()],
                    assessment: "x".to_string(),
                },
                step_5_decision: "x".to_string(),
            },
            evidence: Evidence {
                primary_indicators: alloc::vec!["x".to_string()],
                secondary_indicators: Vec::new(),
                correlation_window_s: None,
            },
            mitre_attack: MitreAttack {
                tactic: alloc::vec!["TA0002".to_string()],
                technique: Vec::new(),
            },
            recommended_action: RecommendedAction {
                action,
                justification: "x".to_string(),
                side_effects: Vec::new(),
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
    fn kill_maps_to_kill_process() {
        let v = sample_verdict(AdeAction::Kill, AdeSeverity::High, 0.9);
        assert_eq!(v.to_response_action(), ResponseAction::KillProcess);
        assert!(v.requires_execution());
    }

    #[test]
    fn escalate_maps_to_log_and_skips_execution() {
        let v = sample_verdict(AdeAction::Escalate, AdeSeverity::Medium, 0.30);
        assert_eq!(v.to_response_action(), ResponseAction::Log);
        assert!(!v.requires_execution());
    }

    #[test]
    fn allow_maps_to_log_and_skips_execution() {
        let v = sample_verdict(AdeAction::Allow, AdeSeverity::None, 0.97);
        assert_eq!(v.to_response_action(), ResponseAction::Log);
        assert!(!v.requires_execution());
    }

    #[test]
    fn isolate_maps_to_full_network_isolation() {
        let v = sample_verdict(AdeAction::Isolate, AdeSeverity::Critical, 0.92);
        assert_eq!(v.to_response_action(), ResponseAction::FullNetworkIsolation);
        assert!(v.requires_execution());
    }

    #[test]
    fn ade_verdict_round_trips_through_serde_json() {
        let v = sample_verdict(AdeAction::Alert, AdeSeverity::Medium, 0.65);
        let json = serde_json::to_string(&v).expect("serialize");
        let parsed: AdeVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.verdict, AdeAction::Alert);
        assert_eq!(parsed.severity, AdeSeverity::Medium);
        assert!((parsed.confidence - 0.65).abs() < f64::EPSILON);
    }
}
