//! Settings of the on-host LLM advisor, removed in Wave 4 (lab PR 214).
//!
//! The advisor (the ADE: a GGUF model run inside the agent, its RAG
//! knowledge base and its XAI explanations) read its settings from the
//! command line and from the environment. It was removed: a multi-GB model
//! inside the root agent, fed with strings an attacker writes, was the
//! largest attack surface of the agent; its accuracy was never measured; it
//! cost gigabytes of RAM on a server. Detection is deterministic (rules,
//! correlation, posture, COMBAT).
//!
//! A unit, a drop-in or a wrapper written for an older agent can still set
//! those settings. They are accepted and ignored, and the agent names each
//! one it finds in a WARN at start: an upgrade never fails on them
//! (`docs/operator/UPGRADE_NOTES_WAVE4.md`).

use tracing::warn;

/// The command-line flags of the advisor. `--no-ade` takes no value, the
/// others take one (`main.rs` accepts them hidden).
pub const REMOVED_FLAGS: &[&str] = &[
    "--no-ade",
    "--ade-model",
    "--ade-timeout",
    "--ade-prompt",
    "--ade-threads",
];

/// The environment variables of the advisor, its knowledge base and its
/// tests.
pub const REMOVED_ENV: &[&str] = &[
    "NN_ADE_ENFORCE",
    "NN_ADE_ALLOW_MOCK",
    "NN_ADE_RAG_ENABLED",
    "NN_ADE_RAG_INDEX_DIR",
    "NN_ADE_RAG_JSONL_DIR",
    "NN_ADE_TOKENIZER",
];

/// What the WARN says about each setting.
pub const REMOVED_REASON: &str = "removed in Wave 4 (lab PR 214) with the on-host LLM advisor: \
     ignored, detection is deterministic (rules, correlation, posture, COMBAT); \
     drop it from the unit, its drop-ins and wrappers";

/// The variables of [`REMOVED_ENV`] that `is_set` reports set, in that
/// order.
pub fn removed_env_set(is_set: impl Fn(&str) -> bool) -> Vec<&'static str> {
    REMOVED_ENV.iter().copied().filter(|k| is_set(k)).collect()
}

/// The variables of [`REMOVED_ENV`] set in this process's environment.
pub fn removed_env_in_process() -> Vec<&'static str> {
    removed_env_set(|k| std::env::var_os(k).is_some())
}

/// One WARN per removed setting found: `flags` from the command line,
/// `env` from the environment.
pub fn warn_removed(flags: &[&'static str], env: &[&'static str]) {
    for flag in flags {
        warn!(flag = *flag, "command-line flag {flag} {REMOVED_REASON}");
    }
    for var in env {
        warn!(
            variable = *var,
            "environment variable {var} {REMOVED_REASON}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_removed_variables_that_are_set_are_named() {
        let set = ["NN_ADE_RAG_ENABLED", "NN_ADE_ENFORCE", "NN_DETECT_ONLY"];
        assert_eq!(
            removed_env_set(|k| set.contains(&k)),
            ["NN_ADE_ENFORCE", "NN_ADE_RAG_ENABLED"]
        );
        assert!(removed_env_set(|_| false).is_empty());
        assert_eq!(removed_env_set(|_| true), REMOVED_ENV);
    }

    #[test]
    fn every_removed_setting_is_named_after_the_advisor() {
        for f in REMOVED_FLAGS {
            assert!(f.starts_with("--") && f.contains("ade"), "{f}");
        }
        for v in REMOVED_ENV {
            assert!(v.starts_with("NN_ADE_"), "{v}");
        }
        assert!(REMOVED_REASON.contains("lab PR 214"));
    }
}
