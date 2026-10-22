//! Tappa 10 — Network Observability userland.
//!
//! Pure-userland half of the Tappa 10 network subsystem. The
//! kernel-side BPF programs land in `agent-ebpf/src/` (N2 commit);
//! this module hosts the userland tracker / DNS cache / TLS parser
//! that consume the BPF events + emit [`NetFlowEvent`] /
//! [`NetListenerEvent`] for the rule engine + audit chain.
//!
//! Commit landing order (per design §12):
//!   - N3 (this commit): [`flow_tracker`] — connect→close state
//!     machine + per-flow stable ID.
//!   - N4: `dns_cache` — PID-keyed 5-min TTL DNS-to-flow attribution.
//!   - N5: `tls_parser` — JA3/JA4/SNI/ALPN from ClientHello.
//!
//! [`NetFlowEvent`]: nn_model::telemetry::NetFlowEvent
//! [`NetListenerEvent`]: nn_model::telemetry::NetListenerEvent

pub mod blind_spots;
pub mod blocklist;
pub mod dns_cache;
pub mod drain;
pub mod flow_tracker;
pub mod limiter;
pub mod resolvers;
/// The ClientHello parser (JA3, JA4, SNI, ALPN): nn-parse's `tls` since R06
/// of the Wave 4 restructure (lab PR 242), re-exported at the path the fuzz
/// targets and `fuzz_api` name (until R17).
pub use nn_parse::tls as tls_parser;
