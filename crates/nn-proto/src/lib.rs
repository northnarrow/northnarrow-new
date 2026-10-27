//! `nn-proto` — the admin protocol, the signed payloads, the quorum, the
//! shutdown marker, the watchdog hold, and the core/worker IPC.
//!
//! Why a crate of its own: shared with the watchdog and nn-admin. `common`'s
//! admin_protocol, admin_signed_payload, admin_quorum, shutdown_marker and
//! watchdog_hold moved here in R03 (lab PR 240), unchanged; the wire formats
//! (postcard frames, CBOR payloads, JSON marker) are the same bytes.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

extern crate alloc;

/// nn-admin ↔ agent protocol carried over the Unix socket at
/// `/run/northnarrow/admin.sock` (was `common::wire::admin_protocol`).
pub mod admin_protocol;
/// Tappa 8 signed-payload value layer (operation code + nonce + ts +
/// agent_id + op-specific extra) plus the Ed25519 sign/verify pipeline
/// (was `common::wire::admin_signed_payload`).
pub mod admin_signed_payload;

pub mod admin_quorum;

pub mod shutdown_marker;

pub mod watchdog_hold;

/// The exec quarantine's agent ↔ scanner protocol and signed hash list (lab
/// PR 223, EXPERIMENTAL; was `common::execq`, lab PR 241).
pub mod execq;

// R03 shims (plan §4.1 rule 2; removed in R17): the paths the moved files
// name, so they compile as they were in `common`.
/// `crate::wire::admin_signed_payload`: the module was `common::wire`'s.
mod wire {
    pub(crate) use crate::admin_signed_payload;
}
/// `crate::posture_types::PostureKind` (`common`'s until R02, nn-model's).
pub(crate) use nn_model::posture_types;
