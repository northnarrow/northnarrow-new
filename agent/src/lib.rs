//! NorthNarrow agent library.
//!
//! Tappa 3: sensors deliver events, the [`decision`] engine produces
//! verdicts, and the [`response`] executor turns them into real
//! actions (currently `KillProcess` and `KillProcessTree`).

pub mod decision;
pub mod response;
pub mod sensors;
