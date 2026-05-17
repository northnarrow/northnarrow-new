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
//! - **P4 (this commit)** — `engine`: the `XaiEngine::explain` public
//!   entrypoint + Article-13 chain assembly/signing, the
//!   `AdeEngine`→`DecisionProbe` adapter, `deterministic_ade_config`
//!   (R1 contract), the cached deployment `environment_hash`, and the
//!   opt-in `#[ignore]` candle latency bench (R-P3.2 instrument). One
//!   read-only ADE-surface addition: `AdeEngine::assembled_prompt`.
//! - **P5** — docs/audit closeout (stale `inference.rs` doc-fix,
//!   `ADE_DOCTRINE` cross-ref, final Art. 13 pass). Not in this commit.

pub mod engine;
pub mod evidence;
pub mod occlusion;
pub mod saliency;
pub mod source;

pub use engine::{
    compute_environment_hash, deterministic_ade_config, deterministic_inference_settings, AdeProbe,
    EnvironmentInputs, XaiEngine, XAI_DETERMINISTIC_SEED,
};
pub use evidence::{verify_evidence, Ed25519EvidenceSigner, XaiVerifyError};
pub use saliency::{
    explain_saliency, explain_saliency_with_clock, Clock, MonotonicClock, SaliencyConfig,
    SaliencyRun, XaiUnavailable,
};
pub use source::{
    composite, decision_delta, DecisionProbe, PerturbationSource, SaliencySource, UnitScore,
    XaiProbeError, XaiSourceError, DEFAULT_WEIGHTS,
};
