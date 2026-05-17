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
//! - **P3+** — `saliency` (coarse-to-fine + `region_refine_threshold` +
//!   bounded-K + `tail` + fail-closed budget) and the
//!   `XaiEngine::explain` public entrypoint with the `XaiUnavailable`
//!   guardrail. Not in this commit (owner audits the occlusion algorithm
//!   + scoring before P3).

pub mod evidence;
pub mod occlusion;
pub mod source;

pub use evidence::{verify_evidence, Ed25519EvidenceSigner, XaiVerifyError};
pub use source::{
    composite, decision_delta, DecisionProbe, PerturbationSource, SaliencySource, UnitScore,
    XaiProbeError, XaiSourceError, DEFAULT_WEIGHTS,
};
