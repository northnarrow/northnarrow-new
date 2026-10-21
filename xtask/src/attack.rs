//! Lab PR 221 (capability C16): `cargo xtask attack-coverage`.
//!
//! Runs the agent's `attack_coverage` example (`agent/examples/
//! attack_coverage.rs`), which renders `docs/detection/ATTACK_COVERAGE.md`,
//! `RULE_CATALOGUE.md` and `attack-navigator-layer.json` from the rules'
//! ATT&CK mapping and the catalogue table, or with `--check` compares
//! them; with `--pin-ids` it first rebuilds the pinned ATT&CK id list
//! (`docs/detection/attack-enterprise-20.0.tsv`) and its licence from a
//! local copy of MITRE's STIX bundle (`--mirror DIR`), checked against the
//! pinned SHA-256. Nothing here fetches: the example prints the pinned URLs
//! when the copy is missing. The agent's test
//! `decision::catalogue::tests::the_committed_documents_are_the_generated_ones`
//! holds `cargo test` to the same documents.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// What `cargo xtask attack-coverage` asks of the example.
pub struct Request<'a> {
    pub check: bool,
    pub pin_ids: Option<&'a [String]>,
    pub mirror: Option<&'a Path>,
}

/// The example's arguments for `req`, after `--`.
fn example_args(root: &Path, req: &Request<'_>) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec![
        if req.check { "--check" } else { "--write" }.into(),
        root.into(),
    ];
    if let Some(ids) = req.pin_ids {
        args.push("--pin-ids".into());
        args.push(ids.join(",").into());
    }
    if let Some(dir) = req.mirror {
        args.push("--mirror".into());
        args.push(dir.into());
    }
    args
}

pub fn run(root: &Path, req: &Request<'_>, locked: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args([
        "run",
        "--quiet",
        "--example",
        "attack_coverage",
        "--package",
        "northnarrow-agent",
        "--",
    ]);
    cmd.args(example_args(root, req));
    crate::lock_if(&mut cmd, locked);
    crate::scrub_cargo_env(&mut cmd);
    let status = cmd
        .status()
        .with_context(|| "failed to spawn the attack_coverage example")?;
    if !status.success() {
        bail!("attack_coverage exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_reaches_the_example() {
        let root = Path::new("/r");
        let plain = example_args(
            root,
            &Request {
                check: true,
                pin_ids: None,
                mirror: None,
            },
        );
        assert_eq!(plain, ["--check", "/r"]);
        let ids = ["T1053.003".to_string(), "DC0039".to_string()];
        let pin = example_args(
            root,
            &Request {
                check: false,
                pin_ids: Some(&ids),
                mirror: Some(Path::new("/m")),
            },
        );
        assert_eq!(
            pin,
            [
                "--write",
                "/r",
                "--pin-ids",
                "T1053.003,DC0039",
                "--mirror",
                "/m"
            ]
        );
    }
}
