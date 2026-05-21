//! Tappa 10.5 (D1) — shared configuration loaders.
//!
//! Houses the generic `.v1` + `.local` overlay parser
//! ([`overlay`]) extracted from the Tappa 9 C7 FIM watched-paths
//! loader, plus the per-family comm-allowlist typed wrappers
//! ([`comm_allowlist`]) the Tappa 10.5 process + network rule
//! families consume. The FIM loader (`fim/paths_config.rs`) is now
//! a thin path-typed wrapper over [`overlay::load_flat_list`].

pub mod comm_allowlist;
pub mod overlay;
