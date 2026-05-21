//! Tappa 10.6 — correlation engine state.
//!
//! [`CorrelationStore`] (D3) is the engine's shared, bounded
//! correlation memory: typed precursor events keyed by a PID-reuse-safe
//! [`ProcKey`], with same-PID `has_recent` and N-event `has_sequence`
//! queries. [`AncestryTree`] (D4) adds the cross-PID lineage on top, so
//! a precursor on an ancestor correlates with a trigger on a descendant.
//!
//! Distinct from `crate::correlation` (the ADE-context ring buffer) —
//! this module is the deterministic chain-rule correlator.

pub mod ancestry;
pub mod store;

pub use ancestry::AncestryTree;
pub use store::{CorrelationStore, PrecursorKind, ProcKey, CORRELATION_WINDOW_NS};
