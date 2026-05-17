//! Tappa 6.9 — XAI Saliency Mapping (standalone explainability subsystem).
//!
//! Top-level sibling of [`crate::ade`] (gating question Q4): `xai`
//! *consumes* an ADE decision via the existing `AdeEngine::evaluate` seam
//! and explains it; it never reaches into ADE internals, so ADE behaviour
//! is byte-identical when XAI is not invoked. The plan of record is
//! `docs/TAPPA6_9_XAI_PLAN.md` (P0.1, locked).
//!
//! ## Phase status
//!
//! - **P1 (this commit)** — the Article-13 evidence schema lives in
//!   [`common::xai_types`]; this crate provides the concrete Ed25519
//!   realisation of its crypto-free [`common::xai_types::EvidenceSigner`]
//!   seam plus offline verification ([`evidence`]). `common` stays
//!   dependency-light; the curve math lives here, exactly as
//!   `anti_tamper::admin_auth` owns it for the admin protocol.
//! - **P2 (this commit)** — `occlusion` (perturbable-unit taxonomy +
//!   the Drop/AnonymiseInPlace operator) and `source` (the
//!   `DecisionProbe` seam, decision-delta scoring, `PerturbationSource`,
//!   and the `SaliencySource` hybrid seam). Flat per-unit scoring +
//!   deterministic causal faithfulness oracle.
//! - **P3 (this commit)** — `saliency`: the coarse-to-fine driver
//!   (Stage-A region occlusion, `region_refine_threshold`, bounded-K +
//!   subset-occluded `tail`), the R-P3.1 cost preflight, the R-P3.2 cost
//!   ledger, and the two-tier fail-closed [`saliency::XaiUnavailable`]
//!   budget with its synthesis-refuses guardrail contract test.
//! - **P4+** — the `XaiEngine::explain` public entrypoint + evidence
//!   assembly/signing + `environment_hash` compute + the candle bench.
//!   Not in this commit (owner audits the P3 driver + budget enforcement
//!   before P4).

pub mod evidence;
pub mod occlusion;
pub mod saliency;
pub mod source;

pub use evidence::{verify_evidence, Ed25519EvidenceSigner, XaiVerifyError};
pub use saliency::{
    explain_saliency, explain_saliency_with_clock, Clock, MonotonicClock, SaliencyConfig,
    SaliencyRun, XaiUnavailable,
};
pub use source::{
    composite, decision_delta, DecisionProbe, PerturbationSource, SaliencySource, UnitScore,
    XaiProbeError, XaiSourceError, DEFAULT_WEIGHTS,
};
