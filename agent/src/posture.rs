//! R08a shim (Wave 4 restructure, lab PR 250; plan §4.1 rule 2, removed in
//! R17): the adaptive defensive posture is nn-core's — the state machine,
//! its triggers, the corroboration ledger, the lineage, the stack
//! exemption, the operator's two overlays (`nn_core::posture`).
//!
//! The agent keeps the paths it had. nn-core's posture takes its host as a
//! type parameter — the process table, the host's files and clocks it
//! reads, and what it consults in the agent's other modules
//! (`nn_core::posture::host`); the agent's is [`LinuxHost`]
//! (`posture_host_linux`). Here the machine, the triggers, the lineage
//! tracker and the stack exemption are aliases on it (an alias without a
//! parameter: one with a default would not apply where a value is built),
//! the release hook takes the agent's unlock token, and the two watchdog
//! lookups keep their names and signatures. Callers, tests, replays and
//! examples are unchanged.
//!
//! The posture's cross-module tests, which wire the agent's rules, ladder,
//! judges and audit log, and its golden replay (`posture::golden`, `cargo
//! xtask golden`) stay here.

use crate::chain_host_linux::LinuxHost;

pub use nn_core::posture::*;

/// [`nn_core::posture::PostureMachine`] on the agent's host.
pub type PostureMachine = nn_core::posture::PostureMachine<LinuxHost>;

/// [`nn_core::posture::CombatReleaseHook`], handed the agent's unlock token.
pub type CombatReleaseHook = nn_core::posture::CombatReleaseHook<
    <LinuxHost as nn_core::posture::host::PostureAgent>::UnlockToken,
>;

pub use exempt::{resolve_verified_watchdog_pid, sibling_watchdog_exe, ExemptPids};
pub use lineage::AuthSessionTracker;
pub use triggers::TriggerDetector;

/// The lineage, the agent's tracker reading the Linux host.
pub mod lineage {
    pub use nn_core::posture::lineage::*;

    /// [`nn_core::posture::lineage::AuthSessionTracker`] on the agent's host.
    pub type AuthSessionTracker =
        nn_core::posture::lineage::AuthSessionTracker<crate::chain_host_linux::LinuxHost>;
}

/// The stack exemption, the agent's reading the Linux host, and its two
/// watchdog lookups under their names and signatures.
pub mod exempt {
    use std::path::{Path, PathBuf};

    use crate::chain_host_linux::LinuxHost;

    pub use nn_core::posture::exempt::*;

    /// [`nn_core::posture::exempt::ExemptPids`] on the agent's host.
    pub type ExemptPids = nn_core::posture::exempt::ExemptPids<LinuxHost>;

    /// [`nn_core::posture::exempt::sibling_watchdog_exe`] on the agent's
    /// host.
    pub fn sibling_watchdog_exe(own_exe: Option<&Path>) -> PathBuf {
        nn_core::posture::exempt::sibling_watchdog_exe::<LinuxHost>(own_exe)
    }

    /// [`nn_core::posture::exempt::resolve_verified_watchdog_pid`] on the
    /// agent's host.
    pub fn resolve_verified_watchdog_pid(
        pidfile: &Path,
        expected_exe: &Path,
    ) -> WatchdogResolution {
        nn_core::posture::exempt::resolve_verified_watchdog_pid::<LinuxHost>(pidfile, expected_exe)
    }
}

/// The triggers, the agent's detector on the Linux host.
pub mod triggers {
    pub use nn_core::posture::triggers::*;

    /// [`nn_core::posture::triggers::TriggerDetector`] on the agent's host.
    pub type TriggerDetector =
        nn_core::posture::triggers::TriggerDetector<crate::chain_host_linux::LinuxHost>;
}

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;
