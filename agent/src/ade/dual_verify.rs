//! Layer 4 of ADE prompt-injection hardening: dual-model
//! verification (stub).
//!
//! For destructive actions (Kill, KillTree, Quarantine, Isolate,
//! BlockOutbound) we want a second opinion before pulling the
//! trigger. The eventual implementation runs the verdict past a
//! second LLM with a different system prompt; that costs a full
//! inference round-trip and is too expensive to ship in the
//! current sub-tappa.
//!
//! The stub here implements the **interface** plus a
//! [`DeterministicVerifier`] that checks the verdict against a few
//! deterministic safety rails:
//!
//! - never `Kill` a low-pid system process,
//! - `Isolate` requires `severity == Critical` (already part of the
//!   schema, but doubled-up here so a malformed verdict that slipped
//!   the parser still gets caught),
//! - `KillTree` and `Quarantine` need a confidence floor.
//!
//! When the deterministic check rejects, the engine swaps the
//! verdict for an Escalate Tier3Review. When it returns
//! `Inconclusive`, the engine keeps the verdict but stamps a flag
//! into metadata (handled by the caller).

use common::ade_types::{AdeAction, AdeSeverity, AdeVerdict};
use common::Event;

/// Decision a [`CriticalActionVerifier`] returns.
#[derive(Debug, Clone)]
pub enum VerificationResult {
    Confirmed,
    Rejected { reason: String },
    Inconclusive,
}

/// Pluggable second-opinion verifier.
///
/// `verify` is called only for verdicts that map onto a destructive
/// executor action — see [`is_critical_action`].
pub trait CriticalActionVerifier: Send + Sync {
    fn verify(&self, verdict: &AdeVerdict, event: &Event) -> VerificationResult;
}

/// Returns `true` if the verdict's executor mapping would mutate
/// host state.
///
/// Sub-tappa 6.6 maps the following actions onto a destructive
/// executor: `Kill`, `KillTree`, `Quarantine`, `Isolate`,
/// `BlockNetwork`. `Throttle` is borderline (CPU cgroup); we
/// include it in the "needs second opinion" set on principle.
pub fn is_critical_action(action: AdeAction) -> bool {
    matches!(
        action,
        AdeAction::Kill
            | AdeAction::KillTree
            | AdeAction::Quarantine
            | AdeAction::Isolate
            | AdeAction::BlockNetwork
            | AdeAction::Throttle
    )
}

/// Stub verifier driven by deterministic safety rails.
///
/// This is **not** a second LLM — that is Sub-tappa 6.6+ work. The
/// rules below are minimal but enforce invariants that no LLM can
/// override: don't kill init, don't isolate without critical
/// severity, etc.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicVerifier;

/// PIDs ≤ this value are treated as system processes whose
/// destruction is never authorized via ADE.
pub const SYSTEM_PID_FLOOR: u32 = 1000;

impl CriticalActionVerifier for DeterministicVerifier {
    fn verify(&self, verdict: &AdeVerdict, event: &Event) -> VerificationResult {
        let target_pid = pid_of(event);

        match verdict.verdict {
            AdeAction::Kill | AdeAction::KillTree => {
                if target_pid > 0 && target_pid < SYSTEM_PID_FLOOR {
                    return VerificationResult::Rejected {
                        reason: format!(
                            "refuse to {} system pid {} (< {})",
                            verdict.verdict, target_pid, SYSTEM_PID_FLOOR
                        ),
                    };
                }
                if matches!(verdict.verdict, AdeAction::KillTree) && verdict.confidence < 0.85 {
                    return VerificationResult::Inconclusive;
                }
                if verdict.confidence < 0.70 {
                    return VerificationResult::Rejected {
                        reason: format!(
                            "{} requires confidence ≥ 0.70 (got {:.2})",
                            verdict.verdict, verdict.confidence
                        ),
                    };
                }
                VerificationResult::Confirmed
            }
            AdeAction::Quarantine => {
                if verdict.confidence < 0.70 {
                    return VerificationResult::Rejected {
                        reason: format!(
                            "Quarantine requires confidence ≥ 0.70 (got {:.2})",
                            verdict.confidence
                        ),
                    };
                }
                VerificationResult::Confirmed
            }
            AdeAction::Isolate => {
                if verdict.severity != AdeSeverity::Critical {
                    return VerificationResult::Rejected {
                        reason: format!(
                            "Isolate requires severity=Critical (got {})",
                            verdict.severity
                        ),
                    };
                }
                if verdict.confidence < 0.85 {
                    return VerificationResult::Rejected {
                        reason: format!(
                            "Isolate requires confidence ≥ 0.85 (got {:.2})",
                            verdict.confidence
                        ),
                    };
                }
                VerificationResult::Confirmed
            }
            AdeAction::BlockNetwork | AdeAction::Throttle => {
                if verdict.confidence < 0.60 {
                    return VerificationResult::Inconclusive;
                }
                VerificationResult::Confirmed
            }
            // Non-critical action — verifier is a no-op.
            _ => VerificationResult::Confirmed,
        }
    }
}

fn pid_of(e: &Event) -> u32 {
    match e {
        Event::ProcessSpawn { pid, .. }
        | Event::FileOpen { pid, .. }
        | Event::ExecCheck { pid, .. }
        | Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. } => *pid,
        // Tappa 9 (C4): FIM drift carries `modifier_pid` as the
        // analogous field. dual_verify reaches Fim only via the
        // C9 ADE-enrichment path.
        Event::Fim(fe) => fe.modifier_pid,
        // Tappa 9.5 (K3): canary trips short-circuit in main —
        // never reach dual_verify; arm for exhaustiveness only.
        Event::CanaryTripped { accessor_pid, .. } => *accessor_pid,
        // Tappa 10 (N6).
        Event::NetFlow(nf) => nf.pid,
        Event::NetListener(nl) => nl.pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ade_types::{
        AdeMetadata, AlternativeExplanations, Evidence, FollowUp, FollowUpPolicy, MitreAttack,
        ReasoningSteps, RecommendedAction, ThreatClassification, ADE_SCHEMA_VERSION,
    };

    fn spawn(pid: u32) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: "/x".into(),
            timestamp_ns: 0,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
        }
    }

    fn baseline(action: AdeAction, severity: AdeSeverity, confidence: f64) -> AdeVerdict {
        AdeVerdict {
            schema_version: ADE_SCHEMA_VERSION.into(),
            trace_id: "00000000-0000-4000-8000-000000000000".into(),
            timestamp_utc: "2026-05-09T08:30:00Z".into(),
            language_used: "it-IT".into(),
            verdict: action,
            severity,
            confidence,
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
    fn is_critical_covers_destructive_actions() {
        for a in [
            AdeAction::Kill,
            AdeAction::KillTree,
            AdeAction::Quarantine,
            AdeAction::Isolate,
            AdeAction::BlockNetwork,
            AdeAction::Throttle,
        ] {
            assert!(is_critical_action(a), "{a} should be critical");
        }
        for a in [AdeAction::Allow, AdeAction::Monitor, AdeAction::Alert] {
            assert!(!is_critical_action(a));
        }
    }

    #[test]
    fn kill_on_system_pid_is_rejected() {
        let v = baseline(AdeAction::Kill, AdeSeverity::High, 0.95);
        let r = DeterministicVerifier.verify(&v, &spawn(42));
        assert!(matches!(r, VerificationResult::Rejected { .. }));
    }

    #[test]
    fn kill_on_user_pid_with_high_conf_is_confirmed() {
        let v = baseline(AdeAction::Kill, AdeSeverity::High, 0.92);
        let r = DeterministicVerifier.verify(&v, &spawn(4242));
        assert!(matches!(r, VerificationResult::Confirmed));
    }

    #[test]
    fn isolate_without_critical_severity_is_rejected() {
        let v = baseline(AdeAction::Isolate, AdeSeverity::High, 0.95);
        let r = DeterministicVerifier.verify(&v, &spawn(4242));
        assert!(matches!(r, VerificationResult::Rejected { .. }));
    }

    #[test]
    fn killtree_with_borderline_conf_is_inconclusive() {
        let v = baseline(AdeAction::KillTree, AdeSeverity::High, 0.78);
        let r = DeterministicVerifier.verify(&v, &spawn(4242));
        assert!(matches!(r, VerificationResult::Inconclusive));
    }
}
