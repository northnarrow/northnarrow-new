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
//! They are no longer accepted (pre-v0.2.0 cleanup; before it they were
//! accepted, ignored and named in a WARN). A unit, a drop-in or a wrapper
//! that still sets one makes the agent refuse to start, with a message that
//! names the setting and its removal (exit 2); `install.sh` refuses an
//! upgrade while a drop-in of the agent's unit holds one, before it changes
//! anything (`docs/operator/UPGRADE_NOTES_WAVE4.md`).

use std::ffi::OsStr;

/// The command-line flags of the advisor. `--no-ade` takes no value, the
/// others take one .
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

/// What the refusal says about each setting.
pub const REMOVED_REASON: &str = "was removed in Wave 4 (lab PR 214) with the on-host LLM advisor \
     and is no longer accepted: detection is deterministic (rules, correlation, posture, \
     COMBAT); drop it from the unit, its drop-ins and wrappers";

/// The variables of [`REMOVED_ENV`] that `is_set` reports set, in that
/// order.
pub fn removed_env_set(is_set: impl Fn(&str) -> bool) -> Vec<&'static str> {
    REMOVED_ENV.iter().copied().filter(|k| is_set(k)).collect()
}

/// The variables of [`REMOVED_ENV`] set in this process's environment.
pub fn removed_env_in_process() -> Vec<&'static str> {
    removed_env_set(|k| std::env::var_os(k).is_some())
}

/// The removed flags among `args` (the command line without the program's
/// name), also in their `--flag=value` form, in the order of
/// [`REMOVED_FLAGS`].
pub fn removed_flags_in<I, S>(args: I) -> Vec<&'static str>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<_> = args.into_iter().collect();
    REMOVED_FLAGS
        .iter()
        .copied()
        .filter(|flag| {
            args.iter().any(|a| {
                let a = a.as_ref().to_string_lossy();
                a == *flag || a.strip_prefix(*flag).is_some_and(|r| r.starts_with('='))
            })
        })
        .collect()
}

/// The refusal for a command line and an environment that still set a
/// removed setting: one line naming each and its removal, `None` when none
/// is set.
pub fn refusal(flags: &[&'static str], env: &[&'static str]) -> Option<String> {
    if flags.is_empty() && env.is_empty() {
        return None;
    }
    let mut out = String::from("northnarrow-agent: refusing to start:");
    for flag in flags {
        out.push_str(&format!("\n  command-line flag {flag} {REMOVED_REASON}"));
    }
    for var in env {
        out.push_str(&format!(
            "\n  environment variable {var} {REMOVED_REASON}"
        ));
    }
    Some(out)
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
    fn a_removed_flag_in_any_spelling_is_refused_with_its_removal_named() {
        let args = ["--detect-only", "--ade-model=/m.gguf", "--no-ade", "--ade-threads", "3"];
        let flags = removed_flags_in(args);
        assert_eq!(flags, ["--no-ade", "--ade-model", "--ade-threads"]);
        let msg = refusal(&flags, &["NN_ADE_ENFORCE"]).expect("a refusal");
        for named in ["--ade-model", "--no-ade", "NN_ADE_ENFORCE", "removed in Wave 4"] {
            assert!(msg.contains(named), "{named} in {msg}");
        }
        assert!(removed_flags_in(["--detect-only", "--ade"]).is_empty());
        assert!(refusal(&[], &[]).is_none());
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
