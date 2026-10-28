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

/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the operator's
/// blocklists are nn-core's, with the rules that read them; their loaders
/// take the host that reads a `.v1` (the agent's `LinuxHost`).
pub use nn_core::net::blocklist;
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the host's
/// configured DNS resolvers are nn-core's, with the rules that read them.
pub use nn_core::net::resolvers;
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the DNS
/// cache's state is nn-core's, with the rules that read it; the agent's
/// cache carries the DNS pump's ingest (lab PR 229), and the reply parsers
/// keep the path R06 (lab PR 242) left them. R09a (lab PR 253): the cache
/// carrying the ingest, and the ingest, are nn-linux's, with the decision
/// engine's host, which names them.
///
/// R09b (lab PR 254): the drain of the flow and listener rings with its two
/// signed logs, and the blind spots it reports, are nn-linux's; so are the
/// flow tracker (connect → close, the flow id, the open-flow snapshots;
/// R08b: nn-core's, its notifier, which the drain awaits, the host's) and
/// the netflow rows' gate to the rules (paced per uid; R08b: nn-core's,
/// with the rules and the correlation store they read) on the Linux host,
/// which the drain names.
pub use nn_linux::net::{blind_spots, dns_cache, dns_ingest, drain, flow_tracker, limiter};
/// The ClientHello parser (JA3, JA4, SNI, ALPN): nn-parse's `tls` since R06
/// of the Wave 4 restructure (lab PR 242), re-exported at the path the fuzz
/// targets and `fuzz_api` name (until R17).
pub use nn_parse::tls as tls_parser;
