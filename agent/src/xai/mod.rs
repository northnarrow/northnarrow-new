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
//! - **P2+** — `occlusion`, `saliency` (coarse-to-fine + bounded-K +
//!   `tail`), `source` (perturbation now / attention seam later) and the
//!   `XaiEngine::explain` public entrypoint with the fail-closed
//!   `XaiUnavailable` guardrail. Not in this commit (the schema is
//!   owner-audited before P2 begins).

pub mod evidence;

pub use evidence::{verify_evidence, Ed25519EvidenceSigner, XaiVerifyError};
