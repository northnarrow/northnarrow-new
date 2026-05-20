//! Saliency source: the perturbation engine + the hybrid seam (plan
//! §3.3, §7).
//!
//! [`PerturbationSource`] is the canonical Article-13 source: for each
//! [`occlusion`]-enumerated unit it asks a [`DecisionProbe`] for the
//! verdict with that unit removed, and scores the decision delta against
//! the baseline `V0`. It is deliberately **flat** here — coarse-to-fine,
//! bounded-K, the `tail`, the fail-closed budget and `Refinement`
//! assignment are the P3 driver's job; P2 owns the taxonomy, the
//! occlusion operator, the per-unit scoring and the faithfulness oracle.
//!
//! [`SaliencySource`] is the §7 hybrid seam: `PerturbationSource` today,
//! an `AttentionSource` later (a second, corroborating implementation),
//! never replacing the causal perturbation score.
//!
//! `DecisionProbe` decouples scoring from ADE: tests drive it with a
//! deterministic causal stub (the plan §8 oracle), and P4 wires the real
//! adapter over `AdeEngine::evaluate` under the §3.2-R1 deterministic
//! inference settings. Native async-fn-in-trait (Rust ≥1.75; workspace
//! is 1.83) with static dispatch — no `dyn`, no `async-trait` dep.

use common::ade_types::{AdeSeverity, AdeVerdict};
use common::xai_types::{Region, SaliencyDelta, SaliencyWeights};
use common::Event;

use crate::ade::EventContext;
use crate::xai::occlusion::{self, FieldClass};

/// Plan §3.3 default scoring weights. Single source of truth for the
/// engine; P4 records the in-force values into `method.weights`.
pub const DEFAULT_WEIGHTS: SaliencyWeights = SaliencyWeights {
    w_action: 0.6,
    w_severity: 0.25,
    w_confidence: 0.15,
};

/// Total severity ordinal span (`None`=0 … `Critical`=4) used to
/// normalise `severity_shift` into `[0, 1]`.
const SEVERITY_SPAN: f64 = 4.0;

/// Probe failure, decoupled from `ade::AdeError` so P2 carries no ADE
/// dependency. The P4 real adapter fills this from the ADE error.
#[derive(Debug, thiserror::Error)]
#[error("decision probe failed: {0}")]
pub struct XaiProbeError(pub String);

/// Saliency-source failure.
#[derive(Debug, thiserror::Error)]
pub enum XaiSourceError {
    #[error(transparent)]
    Probe(#[from] XaiProbeError),
}

/// A re-runnable ADE decision function: "given these inputs, what is the
/// verdict?". The only seam the perturbation engine needs.
#[allow(async_fn_in_trait)]
pub trait DecisionProbe {
    async fn probe(&self, focal: &Event, ctx: &EventContext) -> Result<AdeVerdict, XaiProbeError>;
}

/// One scored input unit (P2-internal; P4 maps it onto
/// `common::xai_types::SaliencyEntry`, adding `Refinement` from the P3
/// driver and the reserved `attention_score`).
#[derive(Debug, Clone)]
pub struct UnitScore {
    pub region: Region,
    pub unit_id: String,
    pub human_label: String,
    pub field_class: FieldClass,
    pub delta: SaliencyDelta,
    pub score: f64,
}

/// Hybrid-seam abstraction (plan §7). `PerturbationSource` is the v1
/// canonical implementation; an `AttentionSource` may be added later as
/// a corroborating source without reshaping callers.
#[allow(async_fn_in_trait)]
pub trait SaliencySource {
    async fn unit_scores<P: DecisionProbe>(
        &self,
        focal: &Event,
        ctx: &EventContext,
        baseline: &AdeVerdict,
        probe: &P,
    ) -> Result<Vec<UnitScore>, XaiSourceError>;
}

/// Black-box counterfactual saliency via input occlusion (the locked
/// canonical method).
#[derive(Debug, Clone)]
pub struct PerturbationSource {
    pub mode: common::xai_types::OcclusionMode,
    pub weights: SaliencyWeights,
}

impl Default for PerturbationSource {
    fn default() -> Self {
        Self {
            mode: common::xai_types::OcclusionMode::Drop, // Q1 default
            weights: DEFAULT_WEIGHTS,
        }
    }
}

impl PerturbationSource {
    pub fn new() -> Self {
        Self::default()
    }
}

fn severity_ordinal(s: AdeSeverity) -> u8 {
    // Exhaustive (no `_`): a new AdeSeverity variant must force a
    // deliberate ordinal review — it changes the saliency scale.
    match s {
        AdeSeverity::None => 0,
        AdeSeverity::Low => 1,
        AdeSeverity::Medium => 2,
        AdeSeverity::High => 3,
        AdeSeverity::Critical => 4,
    }
}

/// Plan §3.3 decision-delta of occluding a unit: `v0` is the baseline,
/// `vu` the verdict with the unit removed.
pub fn decision_delta(v0: &AdeVerdict, vu: &AdeVerdict) -> SaliencyDelta {
    let s0 = severity_ordinal(v0.severity) as f64;
    let su = severity_ordinal(vu.severity) as f64;
    SaliencyDelta {
        action_flip: if v0.verdict != vu.verdict { 1.0 } else { 0.0 },
        severity_shift: (s0 - su).abs() / SEVERITY_SPAN,
        confidence_delta: (v0.confidence - vu.confidence).abs(),
    }
}

/// Plan §3.3 composite: `w_a·flip + w_s·sev + w_c·conf`.
pub fn composite(d: &SaliencyDelta, w: &SaliencyWeights) -> f64 {
    w.w_action * d.action_flip
        + w.w_severity * d.severity_shift
        + w.w_confidence * d.confidence_delta
}

impl SaliencySource for PerturbationSource {
    async fn unit_scores<P: DecisionProbe>(
        &self,
        focal: &Event,
        ctx: &EventContext,
        baseline: &AdeVerdict,
        probe: &P,
    ) -> Result<Vec<UnitScore>, XaiSourceError> {
        let units = occlusion::enumerate(focal, ctx);
        let mut out = Vec::with_capacity(units.len());
        for u in units {
            let (f2, c2) = occlusion::occlude(focal, ctx, &u.addr, self.mode);
            let vu = probe.probe(&f2, &c2).await?;
            let delta = decision_delta(baseline, &vu);
            let score = composite(&delta, &self.weights);
            out.push(UnitScore {
                region: u.region,
                unit_id: u.unit_id,
                human_label: u.human_label,
                field_class: u.field_class,
                delta,
                score,
            });
        }
        // Intentionally NOT ranked here — enumerate() order is the
        // stable unit-id contract; ranking is a P3/P4 presentation step.
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::HostContext;
    use common::ade_types::{
        AdeAction, AdeMetadata, AdeVerdict, AlternativeExplanations, Evidence, FollowUp,
        FollowUpPolicy, MitreAttack, ReasoningSteps, RecommendedAction, ThreatClassification,
        ADE_SCHEMA_VERSION,
    };

    fn verdict(a: AdeAction, s: AdeSeverity, c: f64) -> AdeVerdict {
        AdeVerdict {
            schema_version: ADE_SCHEMA_VERSION.to_string(),
            trace_id: "00000000-0000-4000-8000-000000000000".to_string(),
            timestamp_utc: "2026-05-17T12:00:00Z".to_string(),
            language_used: "en".to_string(),
            verdict: a,
            severity: s,
            confidence: c,
            threat_classification: ThreatClassification {
                family: "test".to_string(),
                kind: "test".to_string(),
                novelty: 0.0,
            },
            reasoning: ReasoningSteps {
                step_1_extract: "x".to_string(),
                step_2_pattern_match: "x".to_string(),
                step_3_criticality: "x".to_string(),
                step_4_alternative_explanations: AlternativeExplanations {
                    legitimate_uses: vec!["x".to_string()],
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
                action: a,
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
                model_id: "mock".to_string(),
                model_quantization: "none".to_string(),
                backend: "mock".to_string(),
                host_id: "test".to_string(),
                agent_version: "0.0.1".to_string(),
                inference_latency_ms: 0,
            },
        }
    }

    fn ps(comm: &str, file: &str) -> Event {
        Event::ProcessSpawn {
            pid: 1000,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: comm.to_string(),
            filename: file.to_string(),
            timestamp_ns: 1,
        }
    }
    fn dns(q: &str) -> Event {
        Event::DnsQuery {
            pid: 1000,
            uid: 0,
            comm: "curl".to_string(),
            query_name: q.to_string(),
            query_type: 1,
            dns_server: [9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            family: 2,
            timestamp_ns: 1,
        }
    }
    fn fopen(file: &str) -> Event {
        Event::FileOpen {
            pid: 1000,
            uid: 0,
            gid: 0,
            comm: "bash".to_string(),
            filename: file.to_string(),
            flags: 0,
            timestamp_ns: 1,
        }
    }

    fn host() -> HostContext {
        HostContext {
            hostname: "h".to_string(),
            host_id: "id".to_string(),
            kernel_version: "6.8".to_string(),
            agent_version: "0.0.1".to_string(),
        }
    }

    /// Deterministic causal oracle: KILL iff (a recent DnsQuery's name
    /// contains "c2.evil") OR (focal is a ProcessSpawn with comm
    /// "miner"); ALLOW otherwise. Lets us assert exact attribution.
    struct CausalProbe;
    impl DecisionProbe for CausalProbe {
        async fn probe(
            &self,
            focal: &Event,
            ctx: &EventContext,
        ) -> Result<AdeVerdict, XaiProbeError> {
            let dns_c2 = ctx.recent_events.iter().any(|e| match e {
                Event::DnsQuery { query_name, .. } => query_name.contains("c2.evil"),
                _ => false,
            });
            let focal_miner = matches!(
                focal,
                Event::ProcessSpawn { comm, .. } if comm == "miner"
            );
            Ok(if dns_c2 || focal_miner {
                verdict(AdeAction::Kill, AdeSeverity::Critical, 0.95)
            } else {
                verdict(AdeAction::Allow, AdeSeverity::None, 0.10)
            })
        }
    }

    #[test]
    fn severity_ordinal_is_monotone() {
        assert!(
            severity_ordinal(AdeSeverity::None) < severity_ordinal(AdeSeverity::Low)
                && severity_ordinal(AdeSeverity::Low) < severity_ordinal(AdeSeverity::Critical)
        );
    }

    #[test]
    fn scoring_math_matches_plan_3_3() {
        let v0 = verdict(AdeAction::Kill, AdeSeverity::Critical, 0.95);
        let vu = verdict(AdeAction::Allow, AdeSeverity::None, 0.10);
        let d = decision_delta(&v0, &vu);
        assert_eq!(d.action_flip, 1.0);
        assert_eq!(d.severity_shift, 1.0); // |4-0|/4
        assert!((d.confidence_delta - 0.85).abs() < 1e-9);
        // 0.6*1 + 0.25*1 + 0.15*0.85 = 0.9775
        assert!((composite(&d, &DEFAULT_WEIGHTS) - 0.9775).abs() < 1e-9);

        // No change ⇒ zero everything.
        let z = decision_delta(&v0, &v0);
        assert_eq!(composite(&z, &DEFAULT_WEIGHTS), 0.0);
    }

    #[tokio::test]
    async fn faithfulness_correlated_cause_ranks_first() {
        // Benign focal; the SOLE cause of KILL is recent #1 (the c2 DNS).
        let focal = ps("bash", "/bin/bash");
        let ctx = EventContext {
            recent_events: vec![
                fopen("/etc/passwd"),
                dns("login.c2.evil.net"),
                fopen("/tmp/log"),
            ],
            host_context: host(),
        };
        let probe = CausalProbe;
        let baseline = probe.probe(&focal, &ctx).await.unwrap();
        assert_eq!(baseline.verdict, AdeAction::Kill); // sanity: cause present

        let scores = PerturbationSource::new()
            .unit_scores(&focal, &ctx, &baseline, &probe)
            .await
            .unwrap();

        // ProcessSpawn = 7 focal units + 3 correlated + 4 host = 14.
        assert_eq!(scores.len(), 14);

        let top = scores
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        assert_eq!(top.unit_id, "correlated:1", "the c2 DNS must rank #1");
        assert_eq!(top.delta.action_flip, 1.0);

        // An irrelevant correlated event and any host field move nothing.
        let c0 = scores.iter().find(|u| u.unit_id == "correlated:0").unwrap();
        assert_eq!(c0.score, 0.0);
        let hn = scores
            .iter()
            .find(|u| u.unit_id == "host:hostname")
            .unwrap();
        assert_eq!(hn.score, 0.0);
        // Focal comm is not the cause here ⇒ zero.
        let fc = scores.iter().find(|u| u.unit_id == "focal:comm").unwrap();
        assert_eq!(fc.score, 0.0);
    }

    #[tokio::test]
    async fn faithfulness_focal_field_cause_is_isolated() {
        // Now the cause is the focal comm "miner"; no recent events.
        let focal = ps("miner", "/tmp/x");
        let ctx = EventContext {
            recent_events: vec![],
            host_context: host(),
        };
        let probe = CausalProbe;
        let baseline = probe.probe(&focal, &ctx).await.unwrap();
        assert_eq!(baseline.verdict, AdeAction::Kill);

        let scores = PerturbationSource::new()
            .unit_scores(&focal, &ctx, &baseline, &probe)
            .await
            .unwrap();

        let top = scores
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        assert_eq!(
            top.unit_id, "focal:comm",
            "occluding the focal comm must flip the verdict"
        );
        assert_eq!(top.delta.action_flip, 1.0);
        // Occluding the filename (not the cause) changes nothing.
        let ff = scores
            .iter()
            .find(|u| u.unit_id == "focal:filename")
            .unwrap();
        assert_eq!(ff.score, 0.0);
    }

    #[tokio::test]
    async fn anonymise_mode_also_neutralises_the_cause() {
        // AnonymiseInPlace must still remove the c2 signal (slot kept).
        let focal = ps("bash", "/bin/bash");
        let ctx = EventContext {
            recent_events: vec![dns("a.c2.evil.org")],
            host_context: host(),
        };
        let probe = CausalProbe;
        let baseline = probe.probe(&focal, &ctx).await.unwrap();
        assert_eq!(baseline.verdict, AdeAction::Kill);

        let src = PerturbationSource {
            mode: common::xai_types::OcclusionMode::AnonymiseInPlace,
            weights: DEFAULT_WEIGHTS,
        };
        let scores = src
            .unit_scores(&focal, &ctx, &baseline, &probe)
            .await
            .unwrap();
        let c0 = scores.iter().find(|u| u.unit_id == "correlated:0").unwrap();
        assert_eq!(
            c0.delta.action_flip, 1.0,
            "anonymising the c2 DNS in place must still flip the verdict"
        );
    }
}
