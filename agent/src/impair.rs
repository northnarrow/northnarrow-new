//! R08b shim (Wave 4 restructure, lab PR 251; plan §4.1 rule 2, removed in
//! R17): defences switched off are nn-core's — the security-tool detector
//! the NN-L-EVA rules and the posture share, and its shipped list
//! (`nn_core::impair`). The detector takes its host as a type parameter:
//! the agent's `LinuxHost` gives it the process table, the
//! trusted-installer window's grant and the kernel's `DEFENDER_PIDS`
//! ([`DefenderMap`]). Here the detector is an alias on that host, and the
//! detector `status` and the detection records read is published as before
//! (the process-wide slot holds the agent's detector: it is the agent's,
//! cut verbatim from `impair`).

use std::sync::Arc;

use nn_model::Event;

use nn_linux::chain_host_linux::LinuxHost;

pub use nn_core::impair::*;

/// [`nn_core::impair::DefenseDetector`] on the agent's host.
pub type DefenseDetector = nn_core::impair::DefenseDetector<LinuxHost>;

/// The kernel map of the tools' processes ([`DefenseDetector::attach_map`]):
/// nn-linux's (R09a, lab PR 253: the decision engine's host names it).
pub use nn_linux::impair::DefenderMap;

/// The agent's detector, for `status` ([`publish`]).
static PUBLISHED: std::sync::OnceLock<Arc<DefenseDetector>> = std::sync::OnceLock::new();

/// Make `detector` the one `status` reports (`main.rs`, once).
pub fn publish(detector: &Arc<DefenseDetector>) {
    let _ = PUBLISHED.set(Arc::clone(detector));
}

/// The published detector's counters; `None` before [`publish`].
pub fn published_counts() -> Option<DefenseCounts> {
    PUBLISHED.get().map(|d| d.counts())
}

/// [`DefenseDetector::sanction_of`] on the published detector.
pub fn published_sanction(event: &Event) -> Option<String> {
    PUBLISHED.get().and_then(|d| d.sanction_of(event))
}

/// The trusted-installer window's sanction (cut from `impair`'s tests by
/// R08b, lab PR 251).
#[cfg(test)]
mod host_tests;
