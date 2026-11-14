//! What this agent binary is: its version, the cargo features it was built
//! with, and how its BPF guard runs (external audit ATP-009, PROC-015).
//!
//! Wave 4 restructure, R04a (lab PR 241): `build_features` and
//! `LAB_FEATURES` were `crate::audit`'s. The audit chain's code leaves this
//! crate for nn-evidence (R05), where `cfg!(feature)` and `env!` would read
//! that crate's features and version (plan §4.1, rule 4); the agent fills
//! [`AgentBuild`] here and the boot rows take it by value.

use crate::audit::AgentBuild;

/// External audit ATP-009: the test and debug features this binary was
/// built with — none in a release build. Also printed by
/// `northnarrow-agent --build-features`, which the range bootstrap checks
/// before it installs a binary (external audit NN-AUD-211) and the release
/// workflow checks on every artefact it builds (external audit PROC-015).
pub fn build_features() -> Vec<&'static str> {
    LAB_FEATURES
        .iter()
        .chain(DEPENDENCY_TEST_FEATURES)
        .filter(|(_, built)| *built)
        .map(|(name, _)| *name)
        .collect()
}

/// Lot 349 (pre-alpha R090): the test features of the crates the agent
/// links, as they were compiled into this binary — on only where a test
/// build's dev-dependency asks for them (`cargo test`), never in a release
/// build (`cargo xtask build --release`). Named by [`build_features`], so the
/// release workflow's `--build-features` check (`none`) refuses a shipped
/// binary carrying one; xtask/tests/supply_chain.rs holds this list to every
/// such feature of the workspace.
pub const DEPENDENCY_TEST_FEATURES: &[(&str, bool)] = &[
    ("nn-core/test-util", nn_core::TEST_UTIL),
    ("nn-linux/test-util", nn_linux::TEST_UTIL),
];

/// External audit PROC-015 (NN-AUD-302): every cargo feature of this crate
/// (`agent/Cargo.toml`), with whether this binary was built with it. All
/// of them are test, debug or demo features, none is a default, and
/// `agent/tests/build_features_cli.rs` holds this list to the manifest, so
/// a new feature cannot be added without [`build_features`] naming it.
pub const LAB_FEATURES: &[(&str, bool)] = &[
    ("debug-trigger", cfg!(feature = "debug-trigger")),
    ("demo-tappa5", cfg!(feature = "demo-tappa5")),
    // POS-013, WDG-R02: builds `examples/posture_demo.rs` only.
    ("posture-demo", cfg!(feature = "posture-demo")),
    ("test-privileged", cfg!(feature = "test-privileged")),
];

/// The build facts of the `agent_boot` rows, read now: the agent's version,
/// [`build_features`] and the BPF guard's mode
/// ([`crate::anti_tamper::bpf_defense::enforce_mode`]).
pub fn agent_build() -> AgentBuild {
    AgentBuild {
        version: env!("CARGO_PKG_VERSION"),
        features: build_features(),
        bpf_guard_enforce: crate::anti_tamper::bpf_defense::enforce_mode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facts the boot rows take are this crate's: its version and the
    /// features [`LAB_FEATURES`] reads with this crate's `cfg!`.
    #[test]
    fn the_build_facts_are_the_agents() {
        let b = agent_build();
        assert_eq!(b.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(b.features, build_features());
        assert_eq!(
            b.features.contains(&"test-privileged"),
            cfg!(feature = "test-privileged")
        );
    }
}
