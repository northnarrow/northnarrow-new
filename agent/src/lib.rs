//! NorthNarrow agent library.
//!
//! - [`sensors`]   — eBPF-driven event sources.
//! - [`decision`]  — deterministic rule engine (Tappa 2).
//! - [`response`]  — concrete executors (Tappa 3 + Tappa 5).
//! - [`ade`]       — Active Defense Engine, LLM second brain (Tappa 6).
//! - [`correlation`] — bounded buffer of recent events fed into ADE.
//! - [`rag`]       — retrieval-augmented generation knowledge base
//!   feeding ADE (Sub-tappa 6.7).

pub mod ade;
pub mod anti_tamper;
pub mod correlation;
pub mod decision;
pub mod posture;
pub mod rag;
pub mod response;
pub mod sensors;
