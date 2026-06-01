//! Shared types for the NorthNarrow XDR.
//!
//! Two layers live here:
//!
//! - [`wire`] holds Plain-Old-Data structs that cross the kernel↔userland
//!   boundary inside eBPF ringbuffers. It is `no_std`-compatible and used
//!   by the eBPF program (`agent-ebpf`) with `default-features = false`.
//! - The top level (gated on the `std` feature, default) holds the
//!   richer userland representation: [`Event`], [`Verdict`],
//!   [`ResponseAction`], [`Severity`].
//!
//! Keep `common` dependency-light: it is consumed by the agent, the CLI,
//! the eBPF program, and (eventually) the C2 backend.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate alloc;

pub mod wire;

/// Hard-coded kernel struct field offsets + the boot-time revalidation
/// table (BUG-036). `no_std`-clean (consts + a `&'static str` table, no
/// alloc) so the eBPF crate compiles the SAME values the agent
/// revalidates against. NOT `std`-gated — the eBPF half needs it with
/// `default-features = false`.
pub mod btf_offsets;

#[cfg(feature = "std")]
mod model;
#[cfg(feature = "std")]
pub use model::*;

/// Active Defense Engine (ADE) verdict schema (v1.0.0).
#[cfg(feature = "std")]
pub mod ade_types;

/// Adaptive Defensive Posture types (Sub-tappa 6.5).
#[cfg(feature = "std")]
pub mod posture_types;

/// RAG knowledge-base types (Sub-tappa 6.7).
#[cfg(feature = "std")]
pub mod rag_types;

/// XAI Saliency Mapping forensic evidence schema (Tappa 6.9, v1.0.0).
#[cfg(feature = "std")]
pub mod xai_types;
