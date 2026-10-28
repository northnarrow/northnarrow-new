//! Lab PR 228: `cargo xtask golden [--update]` — the golden replay of the
//! decision engine (`agent/src/decision/golden.rs`); lab PR 243: and of the
//! posture and the COMBAT ladder (`agent/src/posture/golden.rs`); lab PR
//! 263: and the admin socket's verification table, the replies and signed
//! audit rows of every signed verb refused, accepted and rate-limited
//! (`agent/src/admin/pipeline_tests.rs`, `agent/tests/golden/admin/expected/`).
//!
//! Without `--update` it runs the replays' tests: every case of
//! `agent/tests/golden/cases/` gives its committed golden file of
//! `agent/tests/golden/expected/` byte for byte, every case of
//! `agent/tests/golden/posture/cases/` its file of
//! `agent/tests/golden/posture/expected/`, the same bytes on every run and
//! thread, and the cases cover what each replay set out to show. `cargo
//! test --workspace` runs the same tests, so a stale golden file fails CI.
//! With `--update` the tests write the golden files instead
//! (`NN_GOLDEN_UPDATE=1`) and the changed ones are listed: a maintainer
//! reads that diff, says in the pull request why the verdicts moved, and
//! commits it with the change that moved them
//! (`docs/validation/GOLDEN_REPLAY.md`). Refused when `CI` is set: CI
//! checks the golden files, it never writes them.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The variable the agent's golden tests read (`decision::golden::UPDATE_ENV`,
/// `posture::golden::UPDATE_ENV`).
pub const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";
/// The golden files, relative to the repository root: the decision
/// replay's, (lab PR 243) the posture and ladder replay's, and (lab PR 263)
/// the admin socket's verification table.
pub const EXPECTED_DIRS: [&str; 3] = [
    "agent/tests/golden/expected",
    "agent/tests/golden/posture/expected",
    "agent/tests/golden/admin/expected",
];
/// The agent's golden tests, by module (lab PR 243: one filter each).
const TEST_FILTERS: [&str; 3] = [
    "decision::golden::",
    "posture::golden::",
    "admin::pipeline_tests::",
];

/// The cargo arguments of the run.
fn cargo_args(locked: bool) -> Vec<&'static str> {
    let mut args = vec!["test", "--package", "northnarrow-agent", "--lib"];
    if locked {
        args.push("--locked");
    }
    args.push("--");
    args.extend(TEST_FILTERS);
    args
}

pub fn run(root: &Path, update: bool, locked: bool) -> Result<()> {
    if update && std::env::var_os("CI").is_some() {
        bail!(
            "`cargo xtask golden --update` with CI set: CI checks the golden files, a \
             maintainer rewrites them and reviews the diff"
        );
    }
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args(cargo_args(locked));
    crate::scrub_cargo_env(&mut cmd);
    if update {
        cmd.env(UPDATE_ENV, "1");
    } else {
        cmd.env_remove(UPDATE_ENV);
    }
    let status = cmd
        .status()
        .with_context(|| "failed to spawn cargo test for the golden replay")?;
    if !status.success() {
        bail!(
            "the golden replay failed ({status}){}",
            if update {
                ""
            } else {
                ": a decision, a posture transition, a ladder step or an admin socket's \
                 reply or row moved — if it is intended, `cargo xtask golden --update` and \
                 review the diff"
            }
        );
    }
    if update {
        let out = Command::new("git")
            .current_dir(root)
            .args(["status", "--short", "--"])
            .args(EXPECTED_DIRS)
            .output()
            .with_context(|| "git status")?;
        let changed = String::from_utf8_lossy(&out.stdout);
        if changed.trim().is_empty() {
            eprintln!("golden: no golden file changed");
        } else {
            eprintln!(
                "golden: changed golden files — review `git diff -- {}` and say in the pull \
                 request why each verdict, transition, step, reply or row moved:\n{changed}",
                EXPECTED_DIRS.join(" ")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_run_filters_the_agent_s_golden_tests() {
        assert_eq!(
            cargo_args(false),
            [
                "test",
                "--package",
                "northnarrow-agent",
                "--lib",
                "--",
                "decision::golden::",
                "posture::golden::",
                "admin::pipeline_tests::"
            ]
        );
        // `--locked` is cargo's, before the test filters
        assert_eq!(
            cargo_args(true),
            [
                "test",
                "--package",
                "northnarrow-agent",
                "--lib",
                "--locked",
                "--",
                "decision::golden::",
                "posture::golden::",
                "admin::pipeline_tests::"
            ]
        );
    }

    /// Lab PR 243: the update lists the changed files of every golden
    /// suite (lab PR 263: the admin socket's table too): the directories
    /// are there.
    #[test]
    fn both_replays_golden_directories_are_listed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for dir in EXPECTED_DIRS {
            assert!(root.join(dir).is_dir(), "{dir}");
        }
    }
}
