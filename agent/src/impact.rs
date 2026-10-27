//! R08b shim (Wave 4 restructure, lab PR 251; plan §4.1 rule 2, removed in
//! R17): the ransomware signal is nn-core's — the tracker the NN-L-IMP
//! rules and the posture share, its programs' owners, the entropy signal's
//! vocabulary (`nn_core::impact`). The tracker takes its host as a type
//! parameter: the agent's `LinuxHost` gives it the package database's
//! `rpm`, the host's view of a path and the production sampler of the
//! host's files, which stays here ([`entropy::FsSampler`]). Here the tracker
//! and the owners are aliases on that host, and the tracker `status`
//! reports is published as before (the process-wide slot holds the agent's
//! tracker: it is the agent's, cut verbatim from `impact`).

use std::sync::Arc;

use crate::chain_host_linux::LinuxHost;

pub use nn_core::impact::*;

pub mod entropy;

/// [`nn_core::impact::RansomTracker`] on the agent's host.
pub type RansomTracker = nn_core::impact::RansomTracker<LinuxHost>;

/// Who installed a program file: nn-core's owners, on the agent's host.
pub mod trust {
    pub use nn_core::impact::trust::*;

    /// [`nn_core::impact::trust::ProgramOwners`] on the agent's host.
    pub type ProgramOwners =
        nn_core::impact::trust::ProgramOwners<crate::chain_host_linux::LinuxHost>;
}

/// The agent's tracker, for `status` ([`publish`]).
static PUBLISHED: std::sync::OnceLock<Arc<RansomTracker>> = std::sync::OnceLock::new();

/// Make `tracker` the one `status` reports (`main.rs`, once).
pub fn publish(tracker: &Arc<RansomTracker>) {
    let _ = PUBLISHED.set(Arc::clone(tracker));
}

/// The published tracker's counters; `None` before [`publish`].
pub fn published_counts() -> Option<RansomCounts> {
    PUBLISHED.get().map(|t| t.counts())
}

/// Copy-delete on real files, through the production sampler (cut from
/// `impact`'s tests by R08b, lab PR 251).
#[cfg(test)]
mod host_tests;
