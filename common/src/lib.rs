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

/// The uapi `bpf_cmd` numbers, one copy for the eBPF programs and the
/// agent (lab PR 215). NOT `std`-gated.
pub mod bpf_cmd;
/// Hard-coded kernel struct field offsets + the boot-time revalidation
/// table (BUG-036). `no_std`-clean (consts + a `&'static str` table, no
/// alloc) so the eBPF crate compiles the SAME values the agent
/// revalidates against. NOT `std`-gated — the eBPF half needs it with
/// `default-features = false`.
pub mod btf_offsets;
/// Exploit post-condition guard (lab PR 219): the decision model the eBPF
/// programs run and the agent tests. `no_std`, like [`btf_offsets`].
pub mod epg;
/// Per-hook fail-open counter slots of the deny hooks, shared by the eBPF
/// programs and the agent (lab PR 215). NOT `std`-gated.
pub mod fail_open;
/// Ring-buffer drop slots shared by eBPF producers and the agent.
pub mod ring_drops;

/// Journal-safe log values and lines (external audit, Wave 3: journal
/// line injection, lab PR 167).
#[cfg(feature = "std")]
pub mod log_escape;

#[cfg(feature = "std")]
mod model;
#[cfg(feature = "std")]
pub use model::*;

/// The DNS name walk and its decoder, apart from the event model so the
/// Kani gate on pull requests (`kani.yml`, external audit SUP-023) follows
/// this file alone. Re-exported at the crate root, as before.
#[cfg(feature = "std")]
mod dns_qname;
#[cfg(feature = "std")]
pub use dns_qname::{decode_dns_qname, qname_wire_end, QnameLabel, QnameLabels};

/// Lab PR 223 (EXPERIMENTAL): the exec quarantine's scanner protocol and
/// signed hash list.
#[cfg(feature = "std")]
pub mod execq;

/// Network addresses as the kernel records them, in canonical form
/// (external audit NET-001: IPv4-mapped IPv6).
#[cfg(feature = "std")]
pub mod netaddr;

/// Adaptive Defensive Posture types (Sub-tappa 6.5).
#[cfg(feature = "std")]
pub mod posture_types;

// Wave 4 restructure, R03 (lab PR 240): the admin protocol
// (`wire::admin_protocol`), the signed payloads
// (`wire::admin_signed_payload`), the quorum, the shutdown marker and the
// watchdog hold are nn-proto's (`crates/nn-proto`); `atomic_file` and
// `sd_notify` are northnarrow-antitamper-bpf's. No re-export here: both
// crates depend on this one.
