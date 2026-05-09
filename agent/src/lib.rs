//! NorthNarrow agent library.
//!
//! - [`sensors`]   — eBPF-driven event sources.
//! - [`decision`]  — deterministic rule engine (Tappa 2).
//! - [`response`]  — concrete executors (Tappa 3 + Tappa 5).
//! - [`ade`]       — Active Defense Engine, LLM second brain (Tappa 6).
//! - [`correlation`] — bounded buffer of recent events fed into ADE.

pub mod ade;
pub mod correlation;
pub mod decision;
pub mod posture;
pub mod response;
pub mod sensors;
