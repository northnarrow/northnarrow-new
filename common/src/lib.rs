//! Shared types for the NorthNarrow XDR.
//!
//! Two layers live here:
//!
//! - [`wire`] holds Plain-Old-Data structs that cross the kernel↔userland
//!   boundary inside eBPF ringbuffers. It is `no_std`-compatible and used
//!   by the eBPF program (`agent-ebpf`) with `default-features = false`.
//! - The `std` feature (default) adds the userland helpers of those
//!   layouts (`wire::cstr_lossy`, the name tables of `wire::execpol` and
//!   `wire::execq`, the bytemuck derives) and [`execq`]. The richer
//!   userland representation (`Event`, `Verdict`, `ResponseAction`,
//!   `Severity`) is nn-model's since the Wave 4 restructure's R02 (lab PR
//!   240).
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

/// Lab PR 223 (EXPERIMENTAL): the exec quarantine's scanner protocol and
/// signed hash list.
#[cfg(feature = "std")]
pub mod execq;

// Wave 4 restructure, R03 (lab PR 240): the admin protocol
// (`wire::admin_protocol`), the signed payloads
// (`wire::admin_signed_payload`), the quorum, the shutdown marker and the
// watchdog hold are nn-proto's (`crates/nn-proto`); `atomic_file` and
// `sd_notify` are northnarrow-antitamper-bpf's. R02 (lab PR 240): the event
// model (`model`, re-exported here), `posture_types`, `netaddr`,
// `log_escape` and the std types of `wire` (`FimEvent`, `NetFlowEvent`,
// `NetListenerEvent`, `TlsFingerprint`, …) are nn-model's, `dns_qname`
// nn-parse's. No re-export here: those crates depend on this one.
