//! Lab PR 228: `cargo xtask golden [--update]` — the golden replay of the
//! decision engine (`agent/src/decision/golden.rs`).
//!
//! Without `--update` it runs the replay's tests: every case of
//! `agent/tests/golden/cases/` gives its committed golden file of
//! `agent/tests/golden/expected/` byte for byte, the same bytes on every
//! run and thread, and the cases cover the rules of lots 219–226. `cargo
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

/// The variable the agent's golden tests read (`decision::golden::UPDATE_ENV`).
pub const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";
/// The golden files, relative to the repository root.
pub const EXPECTED_DIR: &str = "agent/tests/golden/expected";

/// The cargo arguments of the run.
fn cargo_args(locked: bool) -> Vec<&'static str> {
    let mut args = vec!["test", "--package", "northnarrow-agent", "--lib"];
    if locked {
        args.push("--locked");
    }
    args.extend(["--", "decision::golden::"]);
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
                ": a decision moved — if it is intended, `cargo xtask golden --update` and \
                 review the diff"
            }
        );
    }
    if update {
        let out = Command::new("git")
            .current_dir(root)
            .args(["status", "--short", "--", EXPECTED_DIR])
            .output()
            .with_context(|| "git status")?;
        let changed = String::from_utf8_lossy(&out.stdout);
        if changed.trim().is_empty() {
            eprintln!("golden: no golden file changed");
        } else {
            eprintln!(
                "golden: changed golden files — review `git diff -- {EXPECTED_DIR}` and say in \
                 the pull request why each verdict moved:\n{changed}"
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
                "decision::golden::"
            ]
        );
        // `--locked` is cargo's, before the test filter
        assert_eq!(
            cargo_args(true),
            [
                "test",
                "--package",
                "northnarrow-agent",
                "--lib",
                "--locked",
                "--",
                "decision::golden::"
            ]
        );
    }
}
