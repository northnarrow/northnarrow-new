//! Build Tier1Review verdicts from invalid model outputs.
//!
//! When the parser rejects a generation we can't simply discard it —
//! the agent still needs a structured decision. We synthesise a valid
//! [`AdeVerdict`] of `verdict=Escalate, escalation_tier=Tier1Review`,
//! confidence 0.0, and embed the raw output + the validation error in
//! the package so the SOC analyst can inspect what the model
//! produced.

use chrono::Utc;
use common::ade_types::{
    AdeAction, AdeMetadata, AdeSeverity, AdeVerdict, AlternativeExplanations, EscalationPackage,
    EscalationTier, Evidence, FollowUp, FollowUpPolicy, MitreAttack, ReasoningSteps,
    RecommendedAction, ThreatClassification, ADE_SCHEMA_VERSION,
};
use common::Event;
use uuid::Uuid;

use super::context::HostContext;

/// Snapshot used by `transform_to_escalate` to populate the metadata
/// without depending on a live `AdeEngine`.
#[derive(Debug, Clone)]
pub struct EscalateMeta<'a> {
    pub model_id: &'a str,
    pub model_quantization: &'a str,
    pub backend: &'a str,
    pub host: &'a HostContext,
    pub language: &'a str,
    pub inference_latency_ms: u64,
}

/// Build a valid `Escalate` verdict from an arbitrary error string and
/// the raw model output (if any). The caller is responsible for
/// passing the focal event so we can stamp pid/filename into the
/// escalation package.
pub fn transform_to_escalate(
    event: &Event,
    error: &str,
    raw_output: Option<&str>,
    meta: &EscalateMeta<'_>,
) -> AdeVerdict {
    let (pid, filename) = match event {
        Event::ProcessSpawn { pid, filename, .. }
        | Event::FileOpen { pid, filename, .. }
        | Event::ExecCheck { pid, filename, .. } => (*pid, filename.clone()),
        Event::TcpConnect { pid, comm, .. } | Event::DnsQuery { pid, comm, .. } => {
            (*pid, comm.clone())
        }
        // FsProtectDenial is short-circuited before ADE in main.rs's
        // process_event; this arm is unreachable in practice. Kept
        // for exhaustiveness so the compiler doesn't bite if the
        // short-circuit is ever moved.
        Event::FsProtectDenial { pid, operation, .. } => {
            (*pid, format!("fs_protect_denial:{operation}"))
        }
        // Tappa 9 (C4): FIM drift events don't reach ADE in V1.0
        // (Tappa 6's escalate path is for the deterministic-rule
        // / decision-engine flow). C9 optional commit may add
        // FIM-aware ADE; until then this arm is unreachable.
        Event::Fim(fe) => (fe.modifier_pid, fe.path.clone()),
    };

    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.into(),
        trace_id: Uuid::new_v4().to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        language_used: meta.language.to_string(),
        verdict: AdeAction::Escalate,
        severity: AdeSeverity::Medium,
        confidence: 0.00,
        threat_classification: ThreatClassification {
            family: "unknown".into(),
            kind: "ade_malformed_output".into(),
            novelty: 1.00,
        },
        reasoning: ReasoningSteps {
            step_1_extract: format!(
                "Synthetic escalation: ADE failed to produce a parseable verdict for pid={pid} filename={filename}."
            ),
            step_2_pattern_match: "n/a — parser rejected upstream output".into(),
            step_3_criticality: "Indeterminate without analyst review".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["model load issue or transient malformed generation".into()],
                assessment: "Cannot decide autonomously; safe default is human review.".into(),
            },
            step_5_decision: format!("Escalate Tier1Review. Validation error: {error}"),
        },
        evidence: Evidence {
            primary_indicators: vec![format!("malformed_ade_output: {error}")],
            secondary_indicators: vec![],
            correlation_window_s: None,
        },
        mitre_attack: MitreAttack {
            // We don't know the threat tactic; mark as Unknown
            // (closest official tactic is "TA0002 Execution" since the
            // event is ProcessSpawn-shaped — but we use a generic
            // placeholder so analysts see the synthetic origin).
            tactic: vec!["TA0000".into()],
            technique: vec![],
        },
        recommended_action: RecommendedAction {
            action: AdeAction::Escalate,
            justification: "Validation failed; escalating to Tier1 review".into(),
            side_effects: vec!["analyst latency".into()],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::None,
            monitoring_duration_s: None,
        },
        escalation_tier: Some(EscalationTier::Tier1Review),
        escalation_package: Some(EscalationPackage {
            summary: format!("ADE produced malformed output: {error}"),
            key_questions: vec![
                "Is the model file corrupted?".into(),
                "Is the prompt template stale?".into(),
                "Has the schema drifted?".into(),
            ],
            raw_model_output: raw_output.map(|s| {
                if s.len() > 4096 {
                    format!("{}…(truncated)", &s[..4096])
                } else {
                    s.to_string()
                }
            }),
            source_event_pid: Some(pid),
            source_event_filename: Some(filename),
        }),
        metadata: AdeMetadata {
            model_id: meta.model_id.to_string(),
            model_quantization: meta.model_quantization.to_string(),
            backend: meta.backend.to_string(),
            host_id: meta.host.host_id.clone(),
            agent_version: meta.host.agent_version.clone(),
            inference_latency_ms: meta.inference_latency_ms,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::context::HostContext;
    use crate::ade::parser::VerdictParser;

    fn host() -> HostContext {
        HostContext {
            hostname: "h".into(),
            host_id: "id1".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.0.1".into(),
        }
    }

    fn meta<'a>(host: &'a HostContext) -> EscalateMeta<'a> {
        EscalateMeta {
            model_id: "test",
            model_quantization: "Q4_K_M",
            backend: "mock",
            host,
            language: "it-IT",
            inference_latency_ms: 0,
        }
    }

    #[test]
    fn synthetic_escalate_validates_against_schema() {
        let event = Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: "/tmp/x".into(),
            timestamp_ns: 0,
        };
        let host = host();
        let m = meta(&host);
        let v = transform_to_escalate(&event, "garbage output", Some("not json"), &m);
        VerdictParser::new()
            .validate(&v)
            .expect("synthetic escalate is always schema-valid");
        assert_eq!(v.verdict, AdeAction::Escalate);
        assert_eq!(v.confidence, 0.00);
        assert!(v.escalation_package.is_some());
        let pkg = v.escalation_package.unwrap();
        assert_eq!(pkg.source_event_pid, Some(1234));
    }

    #[test]
    fn raw_output_truncated_to_4096_bytes() {
        let event = Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: "/x".into(),
            timestamp_ns: 0,
        };
        let host = host();
        let m = meta(&host);
        let raw = "A".repeat(8192);
        let v = transform_to_escalate(&event, "long", Some(&raw), &m);
        let pkg = v.escalation_package.unwrap();
        let stored = pkg.raw_model_output.unwrap();
        assert!(stored.len() <= 4096 + "…(truncated)".len());
        assert!(stored.ends_with("…(truncated)"));
    }

    #[test]
    fn no_raw_output_handled_gracefully() {
        let event = Event::FileOpen {
            pid: 99,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: "/etc/passwd".into(),
            flags: 0,
            timestamp_ns: 0,
        };
        let host = host();
        let m = meta(&host);
        let v = transform_to_escalate(&event, "missing", None, &m);
        VerdictParser::new().validate(&v).expect("valid");
        let pkg = v.escalation_package.unwrap();
        assert!(pkg.raw_model_output.is_none());
        assert_eq!(pkg.source_event_pid, Some(99));
        assert_eq!(pkg.source_event_filename.as_deref(), Some("/etc/passwd"));
    }
}
