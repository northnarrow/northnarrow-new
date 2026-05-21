//! Tappa 10.6 — correlation engine state.
//!
//! [`CorrelationStore`] (D3) is the engine's shared, bounded
//! correlation memory: typed precursor events keyed by a PID-reuse-safe
//! [`ProcKey`], with same-PID `has_recent` and N-event `has_sequence`
//! queries. D4 adds the cross-PID ancestry tree on top.
//!
//! Distinct from `crate::correlation` (the ADE-context ring buffer) —
//! this module is the deterministic chain-rule correlator.

pub mod store;

pub use store::{CorrelationStore, PrecursorKind, ProcKey, CORRELATION_WINDOW_NS};
