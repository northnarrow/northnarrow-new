//! Tappa 6.9 — the coarse-to-fine saliency driver (plan §3.4, §3.6).
//!
//! [`explain_saliency`] turns a [`DecisionProbe`] + the explained inputs
//! into a ranked, refinement-tagged [`SaliencyEntry`] map plus a signed
//! honesty pair (`saliency_coverage`, [`XaiStatus`]), under a fail-closed
//! compute budget. It is the production saliency path; [`crate::xai::
//! source::PerturbationSource`] remains the flat reference scorer and the
//! §7 hybrid seam.
//!
//! ## Algorithm (plan §3.4)
//!
//! 1. **R-P3.1 preflight** — from [`occlusion::enumerate`] we know the
//!    *exact* per-region unit counts for THIS input, so we compute the
//!    exact worst-case inference count (not a loose bound) and refuse
//!    *before any model call* if it cannot fit the budget. "We knew and
//!    declined" is a cleaner regulatory posture than "we tried, ran out,
//!    and returned partial data" — both fail-closed.
//! 2. **Baseline `V0`** — one deterministic probe of the unperturbed
//!    inputs. The driver re-derives `V0` itself (it does NOT trust a
//!    production verdict) so the whole map is computed under one
//!    bit-reproducible regime (plan §3.2-R1); a production `AdeVerdict`
//!    is only the `ade_trace_id` FK, assembled in P4.
//! 3. **Stage A** — occlude each non-empty region as a block (one
//!    inference each) for region-level deltas.
//! 4. **Stage B** — a region is refined IFF `region_delta >=
//!    region_refine_threshold * max_region_delta`. Refined → per-unit
//!    occlusion (`Fine`), capped at `max_units` by a recency / class
//!    prior with the overflow folded into ONE subset-occluded `tail`
//!    (`Coarse`). Not refined → ONE block entry (`Coarse`, no extra
//!    inference). When every region delta is 0 the threshold is 0 and
//!    *all* regions refine — the honest fallback: no dominant region ⇒
//!    no basis to prune ⇒ full per-unit fidelity (a robust/redundant
//!    decision legitimately attributes 0 to every single unit).
//!
//! ## Budget: a two-tier fail-closed defence
//!
//! R-P3.1 refuses on the *estimated* cost before spending; the per-call
//! [`Clock`] guard refuses on *measured* elapsed time if the real model
//! is slower than the planning estimate. Both return
//! [`XaiUnavailable`] — never a partial chain.
//!
//! ## `Err` vs [`XaiStatus::Degraded`] (reconciliation — flagged for the
//! P4-gate audit)
//!
//! Plan §3.6 is binding: budget exceeded ⇒ `Err` ⇒ synthesis refuses
//! ("no XAI ⇒ no synthesis"). A timed-out partial map is therefore
//! discarded, not returned. [`XaiStatus::Degraded`] is reserved for a
//! run that **completed within budget** but is honestly partial-fidelity
//! (coarse regions / a bounded-K tail ⇒ `saliency_coverage < 1.0`); that
//! is a deployable, honest chain, not an "unavailable" one. The audit
//! checklist's "Degraded if mid-explanation timeout" is satisfied
//! structurally by [`XaiUnavailable::Timeout`] carrying the reason; P4
//! may persist a Degraded-status *audit-log* record from that `Err`
//! without ever feeding it to synthesis.
//!
//! ## Cost-envelope ledger (R-P3.2)
//!
//! See [`EST_INFERENCE_MS`]: the single assumed per-inference latency the
//! preflight uses, its provenance, and its PROVISIONAL status (the P4
//! `#[ignore]` candle bench measures and replaces it).

use std::cmp::Ordering;
use std::time::Instant;

use common::xai_types::{
    OcclusionMode, Refinement, Region, SaliencyDelta, SaliencyEntry, SaliencyWeights,
    XaiBaselineVerdict, XaiStatus, XAI_BUDGET_MS,
};
use common::Event;

use crate::ade::EventContext;
use crate::xai::occlusion::{self, FieldClass, PerturbableUnit, UnitAddr};
use crate::xai::source::{
    composite, decision_delta, DecisionProbe, XaiProbeError, DEFAULT_WEIGHTS,
};

/// ── Cost-envelope ledger (R-P3.2) ───────────────────────────────────
///
/// Assumed wall time of one model inference, used *only* by the R-P3.1
/// preflight estimate. This is a **planning estimate, not a
/// measurement**:
/// * value:      `5_000` ms
/// * provenance: `docs/TAPPA6_9_XAI_PLAN.md` §9 envelope — Foundation-Sec
///   -8B Q4_K_M, single-thread CPU path, deterministic decoding
///   (§3.2-R1). *Derived from the plan, not benchmarked here.*
/// * status:     **PROVISIONAL** — the P4 `#[ignore]` candle bench
///   measures the real p95 on the target host and replaces this const in
///   a dedicated commit whose message carries the fresh provenance
///   (host, date, model, thread count).
///
/// A model or hardware swap invalidates this number; changing it is a
/// deliberate commit with fresh provenance, never a silent tweak. It
/// only ever makes the preflight *more* conservative or less — it never
/// affects the measured-time [`Clock`] guard, which is the real
/// fail-closed backstop.
const EST_INFERENCE_MS: u64 = 5_000;

/// Region evaluation order. Fixed so every derived string (the
/// `Degraded` reason) and the pre-rank entry order are deterministic —
/// they feed `XaiEvidenceChain::canonical_bytes` (the signed form).
const REGION_ORDER: [Region; 3] = [Region::Focal, Region::Correlated, Region::Host];

/// Monotonic elapsed-time source. The driver checks it *before* every
/// inference so it never starts work it cannot afford. A test seam:
/// production uses [`MonotonicClock`]; tests drive a manual clock so the
/// timeout path is deterministic and fast (no real sleeping).
pub trait Clock {
    fn elapsed_ms(&self) -> u64;
}

/// Wall-clock [`Clock`] anchored at construction.
#[derive(Debug)]
pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// Driver tunables. Defaults are the plan's locked values; P4 records the
/// in-force values into `method` and the candle bench tunes them so the
/// *typical* case sits well inside [`XAI_BUDGET_MS`].
#[derive(Debug, Clone)]
pub struct SaliencyConfig {
    /// Bounded-K cap per refined region (plan §3.4, default 12).
    pub max_units: u32,
    /// Stage-B refine gate `region_delta >= t * max_region_delta`
    /// (plan §3.4-R3, default 0.3).
    pub region_refine_threshold: f64,
    /// Fail-closed ceiling (plan §3.6, default [`XAI_BUDGET_MS`]).
    pub budget_ms: u64,
    /// §3.3 scoring weights (default [`DEFAULT_WEIGHTS`]).
    pub weights: SaliencyWeights,
    /// Occlusion mode (gating Q1, default [`OcclusionMode::Drop`]).
    pub mode: OcclusionMode,
}

impl Default for SaliencyConfig {
    fn default() -> Self {
        Self {
            max_units: 12,
            region_refine_threshold: 0.3,
            budget_ms: XAI_BUDGET_MS,
            weights: DEFAULT_WEIGHTS,
            mode: OcclusionMode::Drop,
        }
    }
}

/// The driver's output: everything P4 needs to assemble + sign an
/// `XaiEvidenceChain` (it adds only model/method/snapshot/env-hash and
/// the signature; the reserved `attention_score` stays `None`).
#[derive(Debug, Clone)]
pub struct SaliencyRun {
    /// Ranked descending by `score`; ties broken by `unit_id` ascending
    /// (a deterministic total order — the map feeds the signed bytes).
    pub saliency_map: Vec<SaliencyEntry>,
    pub saliency_coverage: f64,
    pub status: XaiStatus,
    /// The deterministic `V0` the map is computed against (plan §3.3).
    pub baseline: XaiBaselineVerdict,
    /// Inferences actually spent (telemetry; P4 candle-bench input).
    pub inferences: u32,
    pub elapsed_ms: u64,
}

/// Why no usable explanation could be produced. Guardrail contract (plan
/// §3.6, §11): synthesis MUST treat **any** variant as "do not deploy
/// the rule". Fail-closed, no XAI ⇒ no synthesis.
#[derive(Debug, thiserror::Error)]
pub enum XaiUnavailable {
    /// R-P3.1: the exact worst-case inference cost for this input already
    /// exceeds the budget — refused before any model call.
    #[error(
        "preflight: worst-case {worst_inferences} inferences ≈ {est_ms} ms \
         exceeds budget {budget_ms} ms"
    )]
    PreflightBudgetExceeded {
        worst_inferences: u32,
        est_ms: u64,
        budget_ms: u64,
    },
    /// The budget was exhausted mid-explanation. The partial map is
    /// discarded by construction (a timed-out explanation is not a
    /// usable explanation).
    #[error(
        "timeout: {elapsed_ms} ms elapsed exceeds budget {budget_ms} ms \
         ({units_scored} units scored before stop)"
    )]
    Timeout {
        elapsed_ms: u64,
        budget_ms: u64,
        units_scored: u32,
    },
    /// The decision probe (model/backend) failed ⇒ no XAI ⇒ fail-closed.
    #[error(transparent)]
    Probe(#[from] XaiProbeError),
}

fn region_word(r: Region) -> &'static str {
    match r {
        Region::Focal => "focal",
        Region::Correlated => "correlated",
        Region::Host => "host",
    }
}

fn class_rank(c: FieldClass) -> u8 {
    match c {
        FieldClass::Semantic => 0,
        FieldClass::Identifier => 1,
        FieldClass::Temporal => 2,
    }
}

/// Bounded-K selection prior (plan §3.4 "most-recent / most-correlated
/// first"). No per-unit score exists yet — economising those inferences
/// is the entire point of bounded-K — so we order by a prior: threat
/// class first (`Semantic` > `Identifier` > `Temporal`), then for
/// correlated events the most-recent (highest stored index) first.
/// `sort_by` is stable, so focal/host keep their `enumerate` declaration
/// order within a class.
fn sort_by_priority(region: Region, v: &mut [&PerturbableUnit]) {
    v.sort_by(|a, b| {
        class_rank(a.field_class)
            .cmp(&class_rank(b.field_class))
            .then_with(|| match (region, &a.addr, &b.addr) {
                (Region::Correlated, UnitAddr::Correlated(ia), UnitAddr::Correlated(ib)) => {
                    ib.cmp(ia)
                }
                _ => Ordering::Equal,
            })
    });
}

fn budget_check<C: Clock>(
    clock: &C,
    budget_ms: u64,
    units_scored: u32,
) -> Result<(), XaiUnavailable> {
    let e = clock.elapsed_ms();
    if e >= budget_ms {
        Err(XaiUnavailable::Timeout {
            elapsed_ms: e,
            budget_ms,
            units_scored,
        })
    } else {
        Ok(())
    }
}

/// Deterministic, exhaustive partial-fidelity reason (signed via
/// `XaiStatus::Degraded`). Every coarse region AND every bounded-K tail
/// is listed: with a low `max_units` config more than one region can
/// overflow (e.g. focal's ≤9 fields and correlated both at K=3), and the
/// Article-13 dossier must name each, not just the last (F1).
fn degraded_reason(coarse: &[Region], tails: &[(Region, u32, u32)]) -> String {
    let mut s = String::from("partial fidelity: ");
    if !coarse.is_empty() {
        let names: Vec<&str> = coarse.iter().map(|r| region_word(*r)).collect();
        s.push_str(&format!(
            "region(s) [{}] at block granularity (below refine threshold)",
            names.join(", ")
        ));
    }
    for (i, (r, n, total)) in tails.iter().enumerate() {
        if !coarse.is_empty() || i > 0 {
            s.push_str("; ");
        }
        s.push_str(&format!(
            "bounded-K tail in {} ({} of {} units aggregated)",
            region_word(*r),
            n,
            total
        ));
    }
    s
}

/// Production entrypoint: a wall-clock-bounded coarse-to-fine saliency
/// run. See the module doc for the algorithm and the fail-closed
/// contract.
pub async fn explain_saliency<P: DecisionProbe>(
    cfg: &SaliencyConfig,
    focal: &Event,
    ctx: &EventContext,
    probe: &P,
) -> Result<SaliencyRun, XaiUnavailable> {
    explain_saliency_with_clock(cfg, focal, ctx, probe, &MonotonicClock::start()).await
}

/// [`explain_saliency`] with an injected [`Clock`] (test seam — drives a
/// deterministic timeout without real sleeping).
pub async fn explain_saliency_with_clock<P: DecisionProbe, C: Clock>(
    cfg: &SaliencyConfig,
    focal: &Event,
    ctx: &EventContext,
    probe: &P,
    clock: &C,
) -> Result<SaliencyRun, XaiUnavailable> {
    let units = occlusion::enumerate(focal, ctx);
    let total_units = units.len() as u32;

    let regions_present: Vec<Region> = REGION_ORDER
        .iter()
        .copied()
        .filter(|r| units.iter().any(|u| u.region == *r))
        .collect();

    // ── R-P3.1 preflight: exact worst-case for THIS input ──
    // worst = V0 + one block per region + (every region refined and, if
    // it overflows max_units, +1 tail).
    let mut worst = 1u32 + regions_present.len() as u32;
    for r in &regions_present {
        let n = units.iter().filter(|u| u.region == *r).count() as u32;
        worst += n.min(cfg.max_units) + u32::from(n > cfg.max_units);
    }
    let est_ms = worst as u64 * EST_INFERENCE_MS;
    if est_ms > cfg.budget_ms {
        return Err(XaiUnavailable::PreflightBudgetExceeded {
            worst_inferences: worst,
            est_ms,
            budget_ms: cfg.budget_ms,
        });
    }

    let mut infer: u32 = 0;
    let mut entries: Vec<SaliencyEntry> = Vec::new();

    // ── baseline V0 (deterministic; the driver re-derives it) ──
    budget_check(clock, cfg.budget_ms, 0)?;
    let v0 = probe.probe(focal, ctx).await?;
    infer += 1;

    // ── Stage A: region-block deltas ──
    let mut region_delta: Vec<(Region, SaliencyDelta, f64)> = Vec::with_capacity(3);
    for r in &regions_present {
        budget_check(clock, cfg.budget_ms, entries.len() as u32)?;
        let addrs: Vec<UnitAddr> = units
            .iter()
            .filter(|u| u.region == *r)
            .map(|u| u.addr.clone())
            .collect();
        let (f2, c2) = occlusion::occlude_units(focal, ctx, &addrs, cfg.mode);
        let vu = probe.probe(&f2, &c2).await?;
        infer += 1;
        let d = decision_delta(&v0, &vu);
        let s = composite(&d, &cfg.weights);
        region_delta.push((*r, d, s));
    }

    let max_rd = region_delta
        .iter()
        .map(|(_, _, s)| *s)
        .fold(0.0f64, f64::max);
    let thresh = cfg.region_refine_threshold * max_rd;

    // ── Stage B ──
    let mut coarse_regions: Vec<Region> = Vec::new();
    let mut tail_notes: Vec<(Region, u32, u32)> = Vec::new();
    for (r, rd, rs) in &region_delta {
        let mut region_units: Vec<&PerturbableUnit> =
            units.iter().filter(|u| u.region == *r).collect();

        // max_rd == 0 ⇒ thresh == 0 ⇒ every region refines (honest: no
        // dominant region, so nothing can be pruned away).
        if *rs < thresh {
            entries.push(SaliencyEntry {
                region: *r,
                unit_id: format!("{}:block", region_word(*r)),
                human_label: format!(
                    "{} block — {} field(s), below refine threshold",
                    region_word(*r),
                    region_units.len()
                ),
                score: *rs,
                refinement: Refinement::Coarse,
                delta: *rd,
                attention_score: None,
            });
            coarse_regions.push(*r);
            continue;
        }

        sort_by_priority(*r, &mut region_units);
        let cut = region_units.len().min(cfg.max_units as usize);
        let (fine_units, tail_units) = region_units.split_at(cut);

        for u in fine_units {
            budget_check(clock, cfg.budget_ms, entries.len() as u32)?;
            let (f2, c2) =
                occlusion::occlude_units(focal, ctx, std::slice::from_ref(&u.addr), cfg.mode);
            let vu = probe.probe(&f2, &c2).await?;
            infer += 1;
            let d = decision_delta(&v0, &vu);
            entries.push(SaliencyEntry {
                region: u.region,
                unit_id: u.unit_id.clone(),
                human_label: u.human_label.clone(),
                score: composite(&d, &cfg.weights),
                refinement: Refinement::Fine,
                delta: d,
                attention_score: None,
            });
        }

        if !tail_units.is_empty() {
            budget_check(clock, cfg.budget_ms, entries.len() as u32)?;
            let addrs: Vec<UnitAddr> = tail_units.iter().map(|u| u.addr.clone()).collect();
            let (f2, c2) = occlusion::occlude_units(focal, ctx, &addrs, cfg.mode);
            let vu = probe.probe(&f2, &c2).await?;
            infer += 1;
            let d = decision_delta(&v0, &vu);
            let n = tail_units.len() as u32;
            entries.push(SaliencyEntry {
                region: *r,
                // Region-namespaced (plan's illustrative `tail:N=<c>` is
                // not unique if >1 region overflows; a duplicate unit_id
                // in a signed forensic map is a real defect). With the
                // default max_units only `correlated` can overflow, but
                // the namespacing is correct for any config.
                unit_id: format!("tail:{}:N={}", region_word(*r), n),
                human_label: format!(
                    "tail: {} lower-priority {} unit(s); subset occlusion in \
                     one inference (not a sum/average)",
                    n,
                    region_word(*r)
                ),
                score: composite(&d, &cfg.weights),
                refinement: Refinement::Coarse,
                delta: d,
                attention_score: None,
            });
            tail_notes.push((*r, n, region_units.len() as u32));
        }
    }

    // ── deterministic rank: score desc, unit_id asc tie-break ──
    entries.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.unit_id.cmp(&b.unit_id))
    });

    // ── coverage + status (the honesty pair) ──
    let fine = entries
        .iter()
        .filter(|e| e.refinement == Refinement::Fine)
        .count() as u32;
    let coverage = if total_units == 0 {
        0.0
    } else {
        fine as f64 / total_units as f64
    };
    let status = if fine == total_units {
        XaiStatus::Complete
    } else {
        XaiStatus::Degraded(degraded_reason(&coarse_regions, &tail_notes))
    };

    Ok(SaliencyRun {
        saliency_map: entries,
        saliency_coverage: coverage,
        status,
        baseline: XaiBaselineVerdict {
            verdict: v0.verdict,
            severity: v0.severity,
            confidence: v0.confidence,
        },
        inferences: infer,
        elapsed_ms: clock.elapsed_ms(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::HostContext;
    use common::ade_types::{
        AdeAction, AdeMetadata, AdeSeverity, AdeVerdict, AlternativeExplanations, Evidence,
        FollowUp, FollowUpPolicy, MitreAttack, ReasoningSteps, RecommendedAction,
        ThreatClassification, ADE_SCHEMA_VERSION,
    };
    use std::cell::Cell;
    use std::rc::Rc;

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

    fn ps(comm: &str) -> Event {
        Event::ProcessSpawn {
            pid: 1000,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: comm.to_string(),
            filename: "/bin/bash".to_string(),
            timestamp_ns: 1,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            parent_is_kthread: false,
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
    fn host() -> HostContext {
        HostContext {
            hostname: "h".to_string(),
            host_id: "id".to_string(),
            kernel_version: "6.8".to_string(),
            agent_version: "0.0.1".to_string(),
        }
    }
    fn ctx(recent: Vec<Event>) -> EventContext {
        EventContext {
            recent_events: recent,
            host_context: host(),
        }
    }

    /// KILL iff any recent DnsQuery name contains "c2.evil"; ALLOW else.
    /// Counts its calls so tests can assert the inference budget.
    struct CausalProbe {
        calls: Rc<Cell<u32>>,
    }
    impl CausalProbe {
        fn new() -> Self {
            Self {
                calls: Rc::new(Cell::new(0)),
            }
        }
    }
    impl DecisionProbe for CausalProbe {
        async fn probe(
            &self,
            _focal: &Event,
            ctx: &EventContext,
        ) -> Result<AdeVerdict, XaiProbeError> {
            self.calls.set(self.calls.get() + 1);
            let kill = ctx.recent_events.iter().any(|e| match e {
                Event::DnsQuery { query_name, .. } => query_name.contains("c2.evil"),
                _ => false,
            });
            Ok(if kill {
                verdict(AdeAction::Kill, AdeSeverity::Critical, 0.95)
            } else {
                verdict(AdeAction::Allow, AdeSeverity::None, 0.10)
            })
        }
    }

    /// Verdict is constant regardless of input ⇒ every occlusion delta
    /// is exactly 0 (audit checklist #1: "what if all regions show ~0").
    struct ConstProbe;
    impl DecisionProbe for ConstProbe {
        async fn probe(&self, _f: &Event, _c: &EventContext) -> Result<AdeVerdict, XaiProbeError> {
            Ok(verdict(AdeAction::Monitor, AdeSeverity::Low, 0.5))
        }
    }

    /// Two independent causes (focal `comm == "miner"` and a recent c2
    /// DNS). Occluding either region alone still moves the verdict
    /// (Kill→Alert), so BOTH regions refine — and with a low `max_units`
    /// both can overflow, exercising the multi-tail reason (F1).
    struct MultiCauseProbe;
    impl DecisionProbe for MultiCauseProbe {
        async fn probe(
            &self,
            focal: &Event,
            ctx: &EventContext,
        ) -> Result<AdeVerdict, XaiProbeError> {
            let focal_bad = matches!(focal, Event::ProcessSpawn { comm, .. } if comm == "miner");
            let corr_bad = ctx.recent_events.iter().any(|e| {
                matches!(e, Event::DnsQuery { query_name, .. } if query_name.contains("c2.evil"))
            });
            Ok(match u8::from(focal_bad) + u8::from(corr_bad) {
                2 => verdict(AdeAction::Kill, AdeSeverity::Critical, 0.95),
                1 => verdict(AdeAction::Alert, AdeSeverity::Medium, 0.60),
                _ => verdict(AdeAction::Allow, AdeSeverity::None, 0.10),
            })
        }
    }

    struct ManualClock(Rc<Cell<u64>>);
    impl Clock for ManualClock {
        fn elapsed_ms(&self) -> u64 {
            self.0.get()
        }
    }

    /// Advances a shared clock by a fixed cost per inference — a
    /// deterministic stand-in for a slow model (no real sleeping).
    struct SlowProbe {
        clock: Rc<Cell<u64>>,
        per_ms: u64,
    }
    impl DecisionProbe for SlowProbe {
        async fn probe(&self, _f: &Event, _c: &EventContext) -> Result<AdeVerdict, XaiProbeError> {
            self.clock.set(self.clock.get() + self.per_ms);
            Ok(verdict(AdeAction::Allow, AdeSeverity::None, 0.1))
        }
    }

    // The synthesis-side guardrail contract (plan §3.6/§11): ANY Err ⇒
    // refuse; an Ok run (even Degraded) is a deployable honest chain.
    #[derive(PartialEq, Debug)]
    enum Gate {
        Refuse,
        Proceed,
    }
    fn synthesis_gate(r: &Result<SaliencyRun, XaiUnavailable>) -> Gate {
        match r {
            Err(_) => Gate::Refuse,
            Ok(_) => Gate::Proceed,
        }
    }

    fn live() -> MonotonicClock {
        MonotonicClock::start()
    }

    #[tokio::test]
    async fn preflight_refuses_before_any_inference() {
        // 16 correlated events ⇒ large worst-case; a 1 ms budget cannot
        // possibly fit it. Must refuse with ZERO probe calls.
        let recent: Vec<Event> = (0..16).map(|i| dns(&format!("q{i}"))).collect();
        let cfg = SaliencyConfig {
            budget_ms: 1,
            ..Default::default()
        };
        let probe = CausalProbe::new();
        let err = explain_saliency(&cfg, &ps("bash"), &ctx(recent), &probe)
            .await
            .unwrap_err();
        match err {
            XaiUnavailable::PreflightBudgetExceeded {
                worst_inferences,
                est_ms,
                budget_ms,
            } => {
                assert!(worst_inferences >= 4); // ≥ V0 + 3 region blocks
                assert!(est_ms > budget_ms);
                assert_eq!(budget_ms, 1);
            }
            other => panic!("expected preflight refusal, got {other:?}"),
        }
        assert_eq!(
            probe.calls.get(),
            0,
            "preflight must refuse before spending any inference"
        );
    }

    #[tokio::test]
    async fn mid_run_timeout_is_fail_closed() {
        // Budget fits the preflight estimate, but the real model is
        // slower than EST_INFERENCE_MS ⇒ the measured-time guard trips.
        // Budget is huge vs the preflight estimate (so R-P3.1 passes),
        // but each real inference costs more than the whole budget ⇒ the
        // measured-time guard trips a couple of inferences in.
        let tick = Rc::new(Cell::new(0u64));
        let clock = ManualClock(tick.clone());
        let probe = SlowProbe {
            clock: tick.clone(),
            per_ms: 600_000,
        };
        let cfg = SaliencyConfig {
            budget_ms: 1_000_000,
            ..Default::default()
        };
        let err = explain_saliency_with_clock(&cfg, &ps("bash"), &ctx(vec![]), &probe, &clock)
            .await
            .unwrap_err();
        match err {
            XaiUnavailable::Timeout {
                elapsed_ms,
                budget_ms,
                ..
            } => {
                assert!(elapsed_ms >= budget_ms);
                assert_eq!(budget_ms, 1_000_000);
            }
            other => panic!("expected timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn guardrail_contract_refuses_on_any_err_but_not_on_degraded() {
        // Timeout ⇒ refuse.
        let tick = Rc::new(Cell::new(0u64));
        let clock = ManualClock(tick.clone());
        let slow = SlowProbe {
            clock: tick.clone(),
            per_ms: 600_000,
        };
        let r1 = explain_saliency_with_clock(
            &SaliencyConfig {
                budget_ms: 1_000_000,
                ..Default::default()
            },
            &ps("bash"),
            &ctx(vec![]),
            &slow,
            &clock,
        )
        .await;
        assert_eq!(synthesis_gate(&r1), Gate::Refuse);
        assert!(matches!(r1, Err(XaiUnavailable::Timeout { .. })));

        // Preflight ⇒ refuse.
        let recent: Vec<Event> = (0..16).map(|i| dns(&format!("q{i}"))).collect();
        let r2 = explain_saliency(
            &SaliencyConfig {
                budget_ms: 1,
                ..Default::default()
            },
            &ps("bash"),
            &ctx(recent),
            &CausalProbe::new(),
        )
        .await;
        assert_eq!(synthesis_gate(&r2), Gate::Refuse);

        // A within-budget Degraded run is NOT "unavailable" ⇒ proceed.
        let probe = CausalProbe::new();
        let r3 = explain_saliency(
            &SaliencyConfig {
                max_units: 1,
                ..Default::default()
            },
            &ps("bash"),
            &ctx(vec![dns("a"), dns("login.c2.evil.net"), dns("b")]),
            &probe,
        )
        .await;
        assert_eq!(synthesis_gate(&r3), Gate::Proceed);
        assert!(matches!(r3.unwrap().status, XaiStatus::Degraded(_)));
    }

    #[tokio::test]
    async fn all_zero_delta_completes_with_full_coverage() {
        // No unit changes the verdict ⇒ max_rd == 0 ⇒ every region
        // refines ⇒ every unit Fine, every score 0, coverage 1.0.
        let probe = ConstProbe;
        let run = explain_saliency(
            &SaliencyConfig::default(),
            &ps("bash"),
            &ctx(vec![dns("a"), dns("b")]),
            &probe,
        )
        .await
        .unwrap();
        assert!(matches!(run.status, XaiStatus::Complete));
        assert_eq!(run.saliency_coverage, 1.0);
        assert!(run.saliency_map.iter().all(|e| e.score == 0.0));
        assert!(run
            .saliency_map
            .iter()
            .all(|e| e.refinement == Refinement::Fine));
        // ProcessSpawn 7 focal + 2 correlated + 4 host = 13 units.
        assert_eq!(run.saliency_map.len(), 13);
    }

    #[tokio::test]
    async fn below_threshold_region_is_coarse_block_and_cause_ranks_first() {
        // Only the correlated region carries the cause ⇒ focal & host
        // fall below the refine threshold and report as coarse blocks.
        let probe = CausalProbe::new();
        let recent = vec![dns("ok.example"), dns("login.c2.evil.net"), dns("cdn.x")];
        let run = explain_saliency(
            &SaliencyConfig::default(),
            &ps("bash"),
            &ctx(recent),
            &probe,
        )
        .await
        .unwrap();

        let focal_block = run
            .saliency_map
            .iter()
            .find(|e| e.unit_id == "focal:block")
            .expect("focal reported as a coarse block");
        assert_eq!(focal_block.refinement, Refinement::Coarse);
        assert!(run
            .saliency_map
            .iter()
            .any(|e| e.unit_id == "host:block" && e.refinement == Refinement::Coarse));

        let top = &run.saliency_map[0];
        assert_eq!(top.unit_id, "correlated:1", "the c2 DNS must rank #1");
        assert_eq!(top.delta.action_flip, 1.0);
        assert_eq!(top.refinement, Refinement::Fine);
        assert!(matches!(run.status, XaiStatus::Degraded(_)));
    }

    #[tokio::test]
    async fn bounded_k_caps_units_and_aggregates_one_tail() {
        // 6 correlated events, cap 3 ⇒ 3 Fine + 1 Coarse tail of 3, in
        // exactly 1 + 3(region) + 3(fine) + 1(tail) = 8 inferences.
        let probe = CausalProbe::new();
        let recent = vec![
            dns("a0"),
            dns("login.c2.evil.net"),
            dns("a2"),
            dns("a3"),
            dns("a4"),
            dns("a5"),
        ];
        let cfg = SaliencyConfig {
            max_units: 3,
            ..Default::default()
        };
        let run = explain_saliency(&cfg, &ps("bash"), &ctx(recent), &probe)
            .await
            .unwrap();

        let tail = run
            .saliency_map
            .iter()
            .find(|e| e.unit_id.starts_with("tail:"))
            .expect("an overflow tail entry");
        assert_eq!(tail.unit_id, "tail:correlated:N=3");
        assert_eq!(tail.refinement, Refinement::Coarse);

        let fine_corr = run
            .saliency_map
            .iter()
            .filter(|e| e.region == Region::Correlated && e.refinement == Refinement::Fine)
            .count();
        assert_eq!(fine_corr, 3, "exactly max_units fine correlated entries");
        assert_eq!(probe.calls.get(), 1 + 3 + 3 + 1);
        assert!(matches!(run.status, XaiStatus::Degraded(_)));
        assert!(run.saliency_coverage < 1.0 && run.saliency_coverage > 0.0);
    }

    #[tokio::test]
    async fn tail_subset_occlusion_is_not_sum_or_average() {
        // Two redundant c2 events: dropping EITHER alone still KILLs
        // (per-unit delta 0 each ⇒ a sum/average would be 0). Both sit
        // in the tail; the subset occlusion drops both at once and
        // correctly flips KILL→ALLOW ⇒ tail.action_flip == 1.0.
        let probe = CausalProbe::new();
        // recency-priority keeps the newest (idx 2 = benign) Fine; the
        // tail = {idx0 c2a, idx1 c2b}.
        let recent = vec![
            dns("a.c2.evil.org"),
            dns("b.c2.evil.org"),
            dns("benign.example"),
        ];
        let cfg = SaliencyConfig {
            max_units: 1,
            ..Default::default()
        };
        let run = explain_saliency(&cfg, &ps("bash"), &ctx(recent), &probe)
            .await
            .unwrap();

        let tail = run
            .saliency_map
            .iter()
            .find(|e| e.unit_id == "tail:correlated:N=2")
            .expect("tail of the two redundant c2 events");
        assert_eq!(
            tail.delta.action_flip, 1.0,
            "subset occlusion removes BOTH redundant causes and flips"
        );
        // The single Fine correlated unit kept (newest, benign) is inert.
        let fine = run
            .saliency_map
            .iter()
            .find(|e| e.region == Region::Correlated && e.refinement == Refinement::Fine)
            .unwrap();
        assert_eq!(fine.score, 0.0);
    }

    #[tokio::test]
    async fn coverage_and_degraded_reason_are_exact_and_deterministic() {
        let probe = CausalProbe::new();
        let recent = vec![dns("ok"), dns("login.c2.evil.net"), dns("cdn")];
        let cfg = SaliencyConfig {
            max_units: 2,
            ..Default::default()
        };
        let run = explain_saliency(&cfg, &ps("bash"), &ctx(recent), &probe)
            .await
            .unwrap();

        // ProcessSpawn 7 focal + 3 corr + 4 host = 14 total units.
        // Only correlated refines; 2 Fine + a tail of 1 ⇒ fine = 2.
        let fine = run
            .saliency_map
            .iter()
            .filter(|e| e.refinement == Refinement::Fine)
            .count();
        assert_eq!(fine, 2);
        assert!((run.saliency_coverage - 2.0 / 14.0).abs() < 1e-12);
        assert!(run.saliency_coverage <= 1.0 && run.saliency_coverage >= 0.0);
        match run.status {
            XaiStatus::Degraded(reason) => {
                assert_eq!(
                    reason,
                    "partial fidelity: region(s) [focal, host] at block \
                     granularity (below refine threshold); bounded-K tail \
                     in correlated (1 of 3 units aggregated)"
                );
            }
            XaiStatus::Complete => panic!("expected Degraded"),
        }
    }

    #[tokio::test]
    async fn multi_region_overflow_lists_every_tail_in_reason() {
        // F1 regression: focal (7 fields) AND correlated (5 events) both
        // overflow K=3 and both refine ⇒ the reason must name BOTH tails.
        let recent = vec![
            dns("ok0"),
            dns("login.c2.evil.net"),
            dns("ok2"),
            dns("ok3"),
            dns("ok4"),
        ];
        let cfg = SaliencyConfig {
            max_units: 3,
            ..Default::default()
        };
        let run = explain_saliency(&cfg, &ps("miner"), &ctx(recent), &MultiCauseProbe)
            .await
            .unwrap();

        assert!(run
            .saliency_map
            .iter()
            .any(|e| e.unit_id == "tail:focal:N=4" && e.refinement == Refinement::Coarse));
        assert!(run
            .saliency_map
            .iter()
            .any(|e| e.unit_id == "tail:correlated:N=2" && e.refinement == Refinement::Coarse));
        match run.status {
            XaiStatus::Degraded(reason) => assert_eq!(
                reason,
                "partial fidelity: region(s) [host] at block granularity \
                 (below refine threshold); bounded-K tail in focal \
                 (4 of 7 units aggregated); bounded-K tail in correlated \
                 (2 of 5 units aggregated)"
            ),
            XaiStatus::Complete => panic!("expected Degraded"),
        }
    }

    #[tokio::test]
    async fn ranking_is_a_deterministic_total_order() {
        let probe = CausalProbe::new();
        let mk = || ctx(vec![dns("ok"), dns("login.c2.evil.net")]);
        let a = explain_saliency(&SaliencyConfig::default(), &ps("bash"), &mk(), &probe)
            .await
            .unwrap();
        let b = explain_saliency(&SaliencyConfig::default(), &ps("bash"), &mk(), &probe)
            .await
            .unwrap();
        let ids_a: Vec<&str> = a.saliency_map.iter().map(|e| e.unit_id.as_str()).collect();
        let ids_b: Vec<&str> = b.saliency_map.iter().map(|e| e.unit_id.as_str()).collect();
        assert_eq!(ids_a, ids_b, "identical inputs ⇒ identical ranked order");
        // Non-increasing by score.
        assert!(a.saliency_map.windows(2).all(|w| w[0].score >= w[1].score));
        let _ = live(); // MonotonicClock smoke (production seam compiles).
    }
}
