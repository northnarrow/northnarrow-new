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
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the operator's
/// blocklists are nn-core's, with the rules that read them; their loaders
/// take the host that reads a `.v1` (the agent's `LinuxHost`).
pub use nn_core::net::blocklist;
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the DNS
/// cache's state is nn-core's, with the rules that read it; the agent's
/// cache carries the DNS pump's ingest ([`dns_ingest`], lab PR 229), and the
/// reply parsers keep the path R06 (lab PR 242) left them.
pub mod dns_cache {
    pub use nn_core::net::dns_cache::*;

    pub use crate::net::dns_ingest::{monotonic_ns, DnsIngest, IngestClaim, INGEST_WAIT};

    /// [`nn_core::net::dns_cache::DnsCache`] with the DNS pump's ingest.
    pub type DnsCache = nn_core::net::dns_cache::DnsCache<DnsIngest>;

    // ── DNS reply parser (nn-parse) ─────────────────────────────────
    //
    // R06 of the Wave 4 restructure (lab PR 242): the reply parser and its
    // tests moved to nn-parse's `dns_records`. Re-exported here for the
    // paths the fuzz targets and `fuzz_api` name (until R17).
    pub use nn_parse::dns_records::{parse_a_records, parse_aaaa_records};
}
pub mod dns_ingest;
pub mod drain;
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the flow
/// tracker (connect → close, the flow id, the open-flow snapshots) is
/// nn-core's; its notifier, which the drain awaits, is the agent's host's
/// (tokio's `Notify`).
pub mod flow_tracker {
    pub use nn_core::net::flow_tracker::*;

    /// [`nn_core::net::flow_tracker::FlowTracker`] on the agent's host.
    pub type FlowTracker =
        nn_core::net::flow_tracker::FlowTracker<crate::chain_host_linux::LinuxHost>;
}
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the netflow
/// rows handed to the rules, paced per uid, are nn-core's, with the rules
/// and the correlation store they read.
pub mod limiter {
    pub use nn_core::net::limiter::*;

    /// [`nn_core::net::limiter::RuleGate`] on the agent's host.
    pub type RuleGate = nn_core::net::limiter::RuleGate<crate::chain_host_linux::LinuxHost>;
}
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the host's
/// configured DNS resolvers are nn-core's, with the rules that read them.
pub use nn_core::net::resolvers;
/// The ClientHello parser (JA3, JA4, SNI, ALPN): nn-parse's `tls` since R06
/// of the Wave 4 restructure (lab PR 242), re-exported at the path the fuzz
/// targets and `fuzz_api` name (until R17).
pub use nn_parse::tls as tls_parser;
