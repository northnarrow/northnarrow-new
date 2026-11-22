//! Lot 387 (pre-alpha Phase 3d, F3d-1): the host's facts for the start's
//! judgement of the boots since the agent's last run
//! ([`nn_evidence::boot_gap::judge`]).
//!
//! - This boot's id: the kernel's (`/proc/sys/kernel/random/boot_id`), the
//!   one fact root cannot rewrite.
//! - The last run's boot id: the one its signed `agent_boot` row carries;
//!   for a row of an agent before the field, the state directory's
//!   `last_boot_id` (FIMR-008: written by the agent's file-integrity setup,
//!   after this judgement).
//! - The journal's boot list: `journalctl --list-boots`, the binary
//!   resolved in the system directories only and verified
//!   ([`crate::trusted_bin`]), with a fixed environment, killed past
//!   [`JOURNAL_LIST_TIMEOUT`] ([`crate::bounded_cmd`]). It is asked only
//!   when the boot changed: a restart within a boot runs nothing.
//!
//! No counter of the agent's own is kept: anything that keeps the agent
//! from starting keeps a counter unit of ours from starting too, and a
//! counter that did not move would say "the next boot" — a false clean,
//! worse than `unknown`. The journal is written by journald, which masking
//! our units does not stop.

use std::path::Path;
use std::time::Duration;

use nn_evidence::boot_gap::{self, BootContinuity, BootFacts};

/// How long the journal's boot list may take (a large journal on a loaded
/// host answers in a few seconds); past it the boots are `unknown`.
pub const JOURNAL_LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the last run's boot id was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviousBootSource {
    /// Its signed `agent_boot` row.
    Chain,
    /// The state directory's `last_boot_id` (a row before the field).
    StateFile,
    /// Neither.
    None,
}

/// What the start found: this boot's id, the judgement, and where the last
/// run's boot came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootsSince {
    pub boot_id: Option<String>,
    pub continuity: BootContinuity,
    pub previous_source: PreviousBootSource,
}

/// The facts of this host, judged: `previous_run` — the chain holds an
/// earlier run; `chain_boot` — the boot id its `agent_boot` signed;
/// `state_dir` — where `last_boot_id` is.
pub fn judge(previous_run: bool, chain_boot: Option<&str>, state_dir: &Path) -> BootsSince {
    judge_with(
        previous_run,
        chain_boot,
        state_dir,
        crate::fim::honeypot::current_boot_id(),
        journal_boots,
    )
}

/// [`judge`] with this boot's id and the journal's list given (tests).
pub fn judge_with(
    previous_run: bool,
    chain_boot: Option<&str>,
    state_dir: &Path,
    current: Option<String>,
    list_boots: impl FnOnce() -> Result<Vec<String>, String>,
) -> BootsSince {
    let state_file = || crate::fim::honeypot::last_boot_id(state_dir);
    let (previous, previous_source) = match chain_boot {
        Some(b) => (Some(b.to_string()), PreviousBootSource::Chain),
        None if previous_run => match state_file() {
            Some(b) => (Some(b), PreviousBootSource::StateFile),
            None => (None, PreviousBootSource::None),
        },
        None => (None, PreviousBootSource::None),
    };
    let continuity = boot_gap::judge(
        BootFacts {
            previous_run,
            previous_boot: previous.as_deref(),
            current_boot: current.as_deref(),
        },
        list_boots,
    );
    BootsSince {
        boot_id: current,
        continuity,
        previous_source,
    }
}

/// The journal's boot ids, oldest first (`journalctl --list-boots`).
pub fn journal_boots() -> Result<Vec<String>, String> {
    let bin = crate::trusted_bin::resolve("journalctl").map_err(|e| e.to_string())?;
    let mut cmd = bin.command();
    cmd.args(["--list-boots", "--no-pager", "--quiet"]);
    let out =
        crate::bounded_cmd::run_bounded(cmd, None, JOURNAL_LIST_TIMEOUT, "journalctl --list-boots")
            .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        let why: String = why.lines().next().unwrap_or("").chars().take(160).collect();
        return Err(format!("journalctl --list-boots: {} {why}", out.status));
    }
    Ok(boot_gap::parse_list_boots(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    const B: &str = "1111aaaa-2222-3333-4444-555566667777";
    const C: &str = "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0";

    fn ids(v: &[&str]) -> Result<Vec<String>, String> {
        Ok(v.iter().map(|s| boot_gap::normalize(s).unwrap()).collect())
    }

    /// The chain's boot id wins over the state file; the state file is read
    /// only for a run whose row has none.
    #[test]
    fn the_last_runs_boot_is_the_chains_then_the_state_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join(crate::fim::honeypot::BOOT_ID_FILE),
            format!("{C}\n"),
        )
        .unwrap();
        // the chain says A: the boot changed, B between → one boot without
        let got = judge_with(true, Some(A), d.path(), Some(C.into()), || ids(&[A, B, C]));
        assert_eq!(got.previous_source, PreviousBootSource::Chain);
        assert_eq!(
            got.continuity,
            BootContinuity::BootsWithoutAgent {
                count: 1,
                boot_ids: vec![boot_gap::normalize(B).unwrap()]
            }
        );
        assert_eq!(got.boot_id.as_deref(), Some(C));
        // a row before the field: the state file (C, this boot) — a restart
        let got = judge_with(true, None, d.path(), Some(C.into()), || {
            panic!("no journal for a restart")
        });
        assert_eq!(got.previous_source, PreviousBootSource::StateFile);
        assert_eq!(got.continuity, BootContinuity::SameBoot);
        // no earlier run: the state file is not read, nothing judged
        let got = judge_with(false, None, d.path(), Some(C.into()), || ids(&[]));
        assert_eq!(got.previous_source, PreviousBootSource::None);
        assert_eq!(got.continuity, BootContinuity::FirstRun);
    }

    /// Neither the chain nor the state file: unknown, never clean.
    #[test]
    fn no_record_of_the_last_runs_boot_is_unknown() {
        let d = tempfile::tempdir().unwrap();
        let got = judge_with(true, None, d.path(), Some(C.into()), || ids(&[A, C]));
        assert_eq!(got.previous_source, PreviousBootSource::None);
        assert!(
            matches!(got.continuity, BootContinuity::Unknown { .. }),
            "{got:?}"
        );
    }
}
