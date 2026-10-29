//! R08b shim (Wave 4 restructure, lab PR 251; plan §4.1 rule 2, removed in
//! R17): the ransomware signal is nn-core's — the tracker the NN-L-IMP
//! rules and the posture share, its programs' owners, the entropy signal's
//! vocabulary (`nn_core::impact`). The tracker takes its host as a type
//! parameter: the agent's `LinuxHost` gives it the package database's
//! `rpm`, the host's view of a path and the production sampler of the
//! host's files ([`entropy::FsSampler`], nn-linux's since R09a, lab PR 253,
//! with the host: both named here by their crate). Here the tracker
//! and the owners are aliases on that host. R11c (lab PR 264): the tracker
//! `status` reports is the one the start gives the admin socket (it was
//! published in a process-wide slot).

use nn_linux::chain_host_linux::LinuxHost;

pub use nn_core::impact::*;

/// The production sampler of the host's files (R09a, lab PR 253:
/// nn-linux's, with the decision engine's host, which names it).
pub use nn_linux::impact::entropy;

/// [`nn_core::impact::RansomTracker`] on the agent's host.
pub type RansomTracker = nn_core::impact::RansomTracker<LinuxHost>;

/// Who installed a program file: nn-core's owners, on the agent's host.
pub mod trust {
    pub use nn_core::impact::trust::*;

    /// [`nn_core::impact::trust::ProgramOwners`] on the agent's host.
    pub type ProgramOwners =
        nn_core::impact::trust::ProgramOwners<nn_linux::chain_host_linux::LinuxHost>;
}

/// Copy-delete on real files, through the production sampler (cut from
/// `impact`'s tests by R08b, lab PR 251).
#[cfg(test)]
mod host_tests;
