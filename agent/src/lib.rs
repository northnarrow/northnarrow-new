//! NorthNarrow agent library.
//!
//! Tappa 2: sensors deliver events, the [`decision`] engine produces
//! verdicts. The `response` module is still a placeholder — Tappa 3
//! lands real executors (KillProcess first).

pub mod decision;
pub mod response {}
pub mod sensors;
