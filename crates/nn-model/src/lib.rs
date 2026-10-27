//! `nn-model` — the vocabulary: events, verdicts, response actions and
//! outcomes, ProcessKey, PostureKind, log escaping, network addresses, the OCSF
//! mapping.
//!
//! Why a crate of its own: shared by nn-proto, the export, the server, nn-admin
//! and the watchdog, which need no engine. `common`'s model, posture_types,
//! netaddr, log_escape and the std types of `wire` moved here in R02 (lab PR
//! 240), unchanged: the model's items are at this crate's root, as they were
//! at `common`'s.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

extern crate alloc;

/// Userland event/verdict model (was `common`'s `model`, re-exported at its
/// root).
mod event;
pub use event::*;

/// Journal-safe log values and lines (external audit, Wave 3: journal
/// line injection, lab PR 167).
pub mod log_escape;

/// Network addresses as the kernel records them, in canonical form
/// (external audit NET-001: IPv4-mapped IPv6).
pub mod netaddr;

/// The text of the paths the open sensor renders: cut and unread marks, an
/// exact host path, an unplaced path's device, mountinfo's escapes (was the
/// agent's `path_text`, R08a, lab PR 250).
pub mod path_text;

/// Adaptive Defensive Posture types (Sub-tappa 6.5).
pub mod posture_types;

/// The userland-decoded FIM, flow, listener and TLS records (the std types
/// of `common::wire`).
pub mod telemetry;

// R02 shims (plan §4.1 rule 2; removed in R17): the paths the moved files
// name, so they compile as they were in `common`.
/// `crate::wire::…`: the raw layouts, and the decoded records that were
/// beside them.
mod wire {
    pub(crate) use crate::telemetry::*;
    pub(crate) use common::wire::*;
}
/// `crate::epg::…`, the exploit guard's decision model.
use common::epg;
/// `crate::dns_qname::…`, the QNAME walk (nn-parse's).
use nn_parse::dns_qname;
