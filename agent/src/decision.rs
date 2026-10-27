//! R08b shim (Wave 4 restructure, lab PR 251; plan §4.1 rule 2, removed in
//! R17): the decision engine is nn-core's — the rules, the multi-match
//! combination, the signed per-rule policy, the held responses, the
//! replay, the ATT&CK mapping and the rule catalogue's table, the chain
//! rules' correlation state (`nn_core::decision`).
//!
//! The agent keeps the paths it had. nn-core's engine takes its host as a
//! type parameter — what its rules read of the machine and ask of it
//! (`nn_core::decision::host`; the posture's `PostureHost` and
//! `PostureAgent` below it); the agent's is [`LinuxHost`]
//! (`decision_host_linux`, `posture_host_linux`). Here the engine, the
//! correlation store and the ancestry tree are aliases on it (an alias
//! without a parameter: one with a default would not apply where a value is
//! built), and the default rule set and the offline replay keep their names
//! and signatures. Callers, tests and examples are unchanged.
//!
//! What names the agent's own records stays here: the golden replay of
//! recorded streams (`decision::golden`, `cargo xtask golden`: the exec
//! policy's records), the rule catalogue's renderer (`catalogue::render`:
//! the rules decided outside the engine, the docs it writes) and the
//! validation registry's checks (`decision::validation_registry`), and the
//! engine's tests that wire the agent's other modules (`host_tests`).

use crate::chain_host_linux::LinuxHost;

pub use nn_core::decision::*;

/// [`nn_core::decision::RuleEngine`] on the agent's host.
pub type RuleEngine = nn_core::decision::RuleEngine<LinuxHost>;

/// The rule catalogue: nn-core's table; its renderer stays here.
pub mod catalogue;

/// The chain rules' correlation state: nn-core's, on the agent's host.
pub mod correlation {
    pub use nn_core::decision::correlation::*;

    /// [`nn_core::decision::correlation::CorrelationStore`] on the agent's
    /// host.
    pub type CorrelationStore =
        nn_core::decision::correlation::CorrelationStore<crate::chain_host_linux::LinuxHost>;

    /// [`nn_core::decision::correlation::AncestryTree`] on the agent's host.
    pub type AncestryTree =
        nn_core::decision::correlation::AncestryTree<crate::chain_host_linux::LinuxHost>;

    /// The ancestry tree, on the agent's host.
    pub mod ancestry {
        pub use nn_core::decision::correlation::ancestry::*;

        /// [`nn_core::decision::correlation::AncestryTree`] on the agent's
        /// host.
        pub type AncestryTree = crate::decision::correlation::AncestryTree;
    }
}

/// The rules, and the default rule set on the agent's host.
pub mod rules {
    pub use nn_core::decision::rules::*;

    use crate::chain_host_linux::LinuxHost;

    /// [`nn_core::decision::rules::default_rules`] on the agent's host.
    pub fn default_rules() -> Vec<Box<dyn crate::decision::Rule>> {
        nn_core::decision::rules::default_rules::<LinuxHost>()
    }
}

/// The offline engine (the golden replay, `nn-admin policy test`), on the
/// agent's host, under its names and signatures.
pub mod replay {
    pub use nn_core::decision::replay::*;

    use std::path::Path;

    use nn_model::Event;
    use serde_json::Value;

    use crate::chain_host_linux::LinuxHost;

    /// [`nn_core::decision::replay::HostParts`] on the agent's host.
    pub type HostParts<'a> = nn_core::decision::replay::HostParts<'a, LinuxHost>;

    /// [`nn_core::decision::replay::engine`] on the agent's host.
    pub fn engine(host: HostParts<'_>) -> crate::decision::RuleEngine {
        nn_core::decision::replay::engine(host)
    }

    /// [`nn_core::decision::replay::decide`] on the agent's host.
    pub fn decide(
        engine: &crate::decision::RuleEngine,
        lineage: &crate::posture::lineage::AuthSessionTracker,
        event: &Event,
    ) -> Value {
        nn_core::decision::replay::decide(engine, lineage, event)
    }

    /// [`nn_core::decision::replay::policy_test`] on the agent's host.
    pub fn policy_test(
        policy: crate::decision::rule_policy::RulePolicy,
        events: &[Event],
        configs: &Path,
        proc_root: &Path,
    ) -> Vec<Value> {
        nn_core::decision::replay::policy_test::<LinuxHost>(policy, events, configs, proc_root)
    }
}

/// Lab PR 228: the golden replay of recorded event streams.
#[cfg(test)]
mod golden;
/// The engine's tests that need the agent's other modules (R08b, lab PR
/// 251).
#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod validation_registry;
