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
pub mod admin_cli;
pub mod admin_socket;
pub mod agent_id;
pub mod anti_tamper;
pub mod audit;
pub mod canary;
pub mod chainlog;
pub mod config;
pub mod correlation;
pub mod decision;
pub mod fim;
pub mod net;
pub mod posture;
pub mod rag;
pub mod response;
pub mod sd_notify;
pub mod sensors;
pub mod shutdown_marker;
pub mod xai;
