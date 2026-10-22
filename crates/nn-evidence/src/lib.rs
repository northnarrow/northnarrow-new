//! `nn-evidence` — the signed chains: canonical form, RowSeq, heads,
//! verification and payloads, behind a `Signer` trait.
//!
//! Why a crate of its own: verification without the engine, for nn-admin, the
//! gateway and third parties; no key lives here. chainlog, audit, chain_anchor,
//! chain_tail, anchored and verify_lines move here in R05.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]
