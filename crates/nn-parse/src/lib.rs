//! `nn-parse` — parsers of attacker-written bytes: the TLS ClientHello (JA3),
//! DNS records and QNAMEs.
//!
//! Why a crate of its own: the leaf of the layout: no crate of this repository
//! below it, pure, fuzzed, the code the confined worker runs (R14b).
//! `common`'s QNAME walk moved here in R02 (lab PR 240); the agent's
//! `net/tls_parser` and `net/dns_cache`'s reply parser in R06 (lab PR 242).
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

extern crate alloc;

/// The DNS name walk and its decoder (Kani-proved; was `common`'s, re-exported
/// at its root, until R02, lab PR 240).
pub mod dns_qname;

/// The A and AAAA answers of a DNS response (was the agent's
/// `net::dns_cache` reply parser until R06, lab PR 242).
pub mod dns_records;

/// The TLS ClientHello: JA3, JA4, SNI, ALPN (its cursor Kani-proved; was the
/// agent's `net::tls_parser` until R06, lab PR 242).
pub mod tls;
