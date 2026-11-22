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
//! - The journal's boots before this one, asked one at a time, newest first
//!   (lot 389, F2h-1: `journalctl -b -<k>`, [`journal_boot_at`], once the
//!   journal's newest entry, its tail — which `-b -<k>` counts from — is of
//!   this boot, the kernel's id: [`journal_tail_boot`], [`anchored_walk`]
//!   — systemd 249's `--list-boots` stops at the first boot it meets twice,
//!   and on a long journal never reached this boot), then, when that walk
//!   does not reach the last run's boot, the journal's boot list
//!   (`journalctl --list-boots`); the binary resolved in the system
//!   directories only and verified ([`crate::trusted_bin`]), with a fixed
//!   environment, each question killed past its bound
//!   ([`crate::bounded_cmd`]: [`WALK_STEP_TIMEOUT`], the walk's
//!   [`WALK_TIMEOUT`], the list's [`JOURNAL_LIST_TIMEOUT`]). The journal is
//!   asked only when the boot changed: a restart within a boot runs nothing.
//!
//! No counter of the agent's own is kept: anything that keeps the agent
//! from starting keeps a counter unit of ours from starting too, and a
//! counter that did not move would say "the next boot" — a false clean,
//! worse than `unknown`. The journal is written by journald, which masking
//! our units does not stop.

use std::path::Path;
use std::time::Duration;

use nn_evidence::boot_gap::{self, BootBefore, BootContinuity, BootFacts};

/// How long the journal's boot list may take (a large journal on a loaded
/// host answers in a few seconds); past it the boots are `unknown`.
pub const JOURNAL_LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// Lot 389 (F2h-1): how long one question of the walk may take (systemd
/// 249 answered each in 15–230 ms on a 1.5 GB journal of 430 boots), and
/// past when no question is begun (the review of #597, P3-5: one begun
/// just before it may take its own bound, so the walk ends within
/// [`WALK_TIMEOUT`] + [`WALK_STEP_TIMEOUT`], 8 s); past either the list
/// judges.
pub const WALK_STEP_TIMEOUT: Duration = Duration::from_secs(2);
pub const WALK_TIMEOUT: Duration = Duration::from_secs(6);

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
        bounded_walk(
            std::time::Instant::now() + WALK_TIMEOUT,
            anchored_walk(journal_tail_boot, journal_boot_at),
        ),
        journal_boots,
    )
}

/// Lot 389 (F2h-1): the walk's questions `ask`, none begun past
/// `deadline` (the answer then: no answer).
pub fn bounded_walk(
    deadline: std::time::Instant,
    mut ask: impl FnMut(&str, usize) -> BootBefore,
) -> impl FnMut(&str, usize) -> BootBefore {
    move |current, k| {
        if std::time::Instant::now() >= deadline {
            return BootBefore::NoAnswer(format!(
                "the walk took longer than {} s",
                WALK_TIMEOUT.as_secs()
            ));
        }
        ask(current, k)
    }
}

/// Lot 389 (F2h-1): the `k`-th boot before this one as the journal counts
/// them back from its tail (`ask(k)`: `journalctl -b -<k>`), once the boot
/// of the journal's newest entry (`tail()`: `journalctl -n 1`, no `-b`) is
/// this very boot — the kernel's id, which the walk is given — asked at the
/// first question; otherwise no answer at all (a journal whose newest entry
/// is another boot's: a clock set back, a journal not flushed). The review
/// of #597 (P3-3): `-b 0` is no such check — systemd 249, 255 and 257
/// answer it with the kernel's current boot (`sd_id128_get_boot`), not the
/// tail's, so it proved only that this boot has entries. systemd 255
/// answers `-b <id>-<k>` with the boot `<id>` itself, the offset ignored
/// (lot 389's lab, ubuntu2404); `-b -<k>` is answered alike by 249, 255
/// and 257.
pub fn anchored_walk(
    mut tail: impl FnMut() -> BootBefore,
    mut ask: impl FnMut(usize) -> BootBefore,
) -> impl FnMut(&str, usize) -> BootBefore {
    let mut anchor: Option<Result<(), String>> = None;
    move |current, k| {
        let anchored = anchor.get_or_insert_with(|| match tail() {
            BootBefore::Boot(newest)
                if boot_gap::normalize(&newest) == boot_gap::normalize(current) =>
            {
                Ok(())
            }
            BootBefore::Boot(newest) => Err(format!(
                "the journal's newest entry is of boot {newest}, not this one"
            )),
            BootBefore::NoSuchBoot => Err("the journal holds no entry".into()),
            BootBefore::NoAnswer(why) => Err(why),
        });
        match anchored {
            Ok(()) => ask(k),
            Err(why) => BootBefore::NoAnswer(why.clone()),
        }
    }
}

/// [`judge`] with this boot's id, the journal's boots before it and its
/// list given (tests).
pub fn judge_with(
    previous_run: bool,
    chain_boot: Option<&str>,
    state_dir: &Path,
    current: Option<String>,
    boot_before: impl FnMut(&str, usize) -> BootBefore,
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
    let continuity = boot_gap::judge_walking(
        BootFacts {
            previous_run,
            previous_boot: previous.as_deref(),
            current_boot: current.as_deref(),
        },
        boot_before,
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

/// Lot 389 (F2h-1): the journal's `k`-th boot before its newest one:
/// `journalctl -b -<k> -n 1 -o json --output-fields=_BOOT_ID` — the boot of
/// the newest entry it shows ([`journal_boot_args`]). systemd 249 walks
/// back from the journal's tail, boot by boot, without the list's stop at
/// a boot met twice.
pub fn journal_boot_at(k: usize) -> BootBefore {
    journal_boot(Some(k))
}

/// The review of #597 (P3-3): the boot of the journal's newest entry, its
/// tail — the boot `-b -<k>` counts from: `journalctl -n 1 -o json
/// --output-fields=_BOOT_ID`, no `-b` ([`journal_boot_args`]).
pub fn journal_tail_boot() -> BootBefore {
    journal_boot(None)
}

/// The arguments of the walk's question: the boot of the newest entry of
/// the `k`-th boot back from the journal's tail (`Some(k)`, `-b -<k>`), or
/// of the journal itself (`None`: no `-b`).
pub fn journal_boot_args(k: Option<usize>) -> Vec<String> {
    let mut args: Vec<String> = match k {
        Some(k) => vec!["-b".into(), format!("-{k}")],
        None => Vec::new(),
    };
    args.extend(
        [
            "-n",
            "1",
            "-o",
            "json",
            "--output-fields=_BOOT_ID",
            "--no-pager",
            "--quiet",
        ]
        .map(String::from),
    );
    args
}

fn journal_boot(k: Option<usize>) -> BootBefore {
    let bin = match crate::trusted_bin::resolve("journalctl") {
        Ok(b) => b,
        Err(e) => return BootBefore::NoAnswer(e.to_string()),
    };
    let mut cmd = bin.command();
    cmd.args(journal_boot_args(k));
    let what = if k.is_some() {
        "journalctl -b -<k>"
    } else {
        "journalctl -n 1"
    };
    match crate::bounded_cmd::run_bounded(cmd, None, WALK_STEP_TIMEOUT, what) {
        Ok(out) => boot_before_of(
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(e) => BootBefore::NoAnswer(e.to_string()),
    }
}

/// Lot 389 (F2h-1): the walk's answer from journalctl's exit (`ok`), its
/// output (one JSON object a line, its `_BOOT_ID` — a field journald
/// writes, no client can) and its error text: a boot the journal does not
/// hold (an empty answer; 249's "is not available: No such boot ID", a
/// newer one's "No journal boot entry found") is [`BootBefore::NoSuchBoot`];
/// any other failure, or an answer without a boot id, no answer.
pub fn boot_before_of(ok: bool, stdout: &str, stderr: &str) -> BootBefore {
    let why = || -> String {
        stderr
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(160)
            .collect()
    };
    if !ok {
        let e = why();
        if e.contains("No such boot") || e.contains("No journal boot entry") {
            return BootBefore::NoSuchBoot;
        }
        return BootBefore::NoAnswer(format!("journalctl failed: {e}"));
    }
    let Some(line) = stdout.lines().find(|l| !l.trim().is_empty()) else {
        return BootBefore::NoSuchBoot;
    };
    match serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("_BOOT_ID")?.as_str().and_then(boot_gap::normalize))
    {
        Some(id) => BootBefore::Boot(id),
        None => BootBefore::NoAnswer("journalctl's answer names no boot id".into()),
    }
}

/// Lot 388 (the review of #595, P3-1): the boots without the agent the
/// start looks at in the journal at most, and how long each may take.
pub const RESCUE_CHECK_MAX: usize = 4;
pub const RESCUE_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Lot 388 (the review of #595, P3-1): which of `boot_ids` (the boots
/// without the agent, oldest first) the journal shows as a rescue or an
/// emergency boot — PID 1's records of `rescue.target` or
/// `emergency.target` in that boot. The first [`RESCUE_CHECK_MAX`] only,
/// each bounded; a boot the journal does not answer for is not named (its
/// cause stays one of the list the row gives). A fact for the row's
/// wording: the gap is signed High all the same.
pub fn rescue_boots(boot_ids: &[String]) -> Vec<String> {
    rescue_boots_with(boot_ids, journal_shows_rescue)
}

/// [`rescue_boots`] with the journal's answer given (tests).
pub fn rescue_boots_with(boot_ids: &[String], shows_rescue: impl Fn(&str) -> bool) -> Vec<String> {
    boot_ids
        .iter()
        .take(RESCUE_CHECK_MAX)
        .filter_map(|b| boot_gap::normalize(b))
        .filter(|b| shows_rescue(b))
        .collect()
}

/// Whether the journal holds PID 1's record of the rescue or emergency
/// target in boot `id` (32 hex digits).
fn journal_shows_rescue(id: &str) -> bool {
    let Ok(bin) = crate::trusted_bin::resolve("journalctl") else {
        return false;
    };
    let mut cmd = bin.command();
    cmd.args([
        "-b",
        id,
        "--no-pager",
        "--quiet",
        "-o",
        "cat",
        "-n",
        "1",
        "_PID=1",
        "UNIT=rescue.target",
        "UNIT=emergency.target",
    ]);
    crate::bounded_cmd::run_bounded(cmd, None, RESCUE_CHECK_TIMEOUT, "journalctl -b <id>")
        .is_ok_and(|out| out.status.success() && !out.stdout.trim_ascii().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 388 (the review of #595, P3-1): the journal is asked about the
    /// first boots without the agent only, by their normalized id; a boot
    /// it shows in rescue is named, the others are not.
    #[test]
    fn the_rescue_boots_are_the_journal_s_among_the_first_boots_without_the_agent() {
        let ids: Vec<String> = (0..6).map(|i| format!("{i:032x}")).collect();
        let asked = std::cell::RefCell::new(Vec::new());
        let got = rescue_boots_with(&ids, |b| {
            asked.borrow_mut().push(b.to_string());
            b.ends_with('1') || b.ends_with('5')
        });
        assert_eq!(got, vec![ids[1].clone()], "the sixth boot is past the cap");
        assert_eq!(asked.into_inner(), ids[..RESCUE_CHECK_MAX].to_vec());
        // the kernel's form (dashes) is asked in the journal's
        let got = rescue_boots_with(&[B.to_string(), "not a boot".into()], |_| true);
        assert_eq!(got, vec![boot_gap::normalize(B).unwrap()]);
    }

    const A: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    const B: &str = "1111aaaa-2222-3333-4444-555566667777";
    const C: &str = "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0";

    fn ids(v: &[&str]) -> Result<Vec<String>, String> {
        Ok(v.iter().map(|s| boot_gap::normalize(s).unwrap()).collect())
    }

    /// The journal's boots before this one as a list `v` (oldest first,
    /// this boot last) gives them, one at a time.
    fn walk(v: &[&str]) -> impl FnMut(&str, usize) -> BootBefore {
        let v: Vec<String> = ids(v).unwrap();
        move |current, k| {
            assert_eq!(v.last().map(String::as_str), Some(current));
            match v.len().checked_sub(k + 1) {
                Some(i) => BootBefore::Boot(v[i].clone()),
                None => BootBefore::NoSuchBoot,
            }
        }
    }

    fn no_walk(_: &str, _: usize) -> BootBefore {
        panic!("no journal for a restart")
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
        let got = judge_with(
            true,
            Some(A),
            d.path(),
            Some(C.into()),
            walk(&[A, B, C]),
            || panic!("the walk reached the last run's boot"),
        );
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
        let got = judge_with(true, None, d.path(), Some(C.into()), no_walk, || {
            panic!("no journal for a restart")
        });
        assert_eq!(got.previous_source, PreviousBootSource::StateFile);
        assert_eq!(got.continuity, BootContinuity::SameBoot);
        // no earlier run: the state file is not read, nothing judged
        let got = judge_with(false, None, d.path(), Some(C.into()), no_walk, || ids(&[]));
        assert_eq!(got.previous_source, PreviousBootSource::None);
        assert_eq!(got.continuity, BootContinuity::FirstRun);
    }

    /// Lot 389 (F2h-1): the journal's answer for a boot before this one —
    /// the `_BOOT_ID` of the JSON line systemd 249 printed (rc14's lab, the
    /// guest's journal of 430 boots), in either form; a boot it does not
    /// hold (249's and a newer systemd's words, or an empty answer); any
    /// other failure or an answer without a boot id, no answer — never a
    /// boot.
    #[test]
    fn the_journals_boot_before_this_one_is_read_from_its_json_line() {
        let line = r#"{"__CURSOR":"s=45c7;i=8a810;b=b75858b9851c4607968cb280123e262a","_BOOT_ID":"b75858b9851c4607968cb280123e262a","__MONOTONIC_TIMESTAMP":"76509213","__REALTIME_TIMESTAMP":"1795358282736275"}"#;
        assert_eq!(
            boot_before_of(true, &format!("{line}\n"), ""),
            BootBefore::Boot("b75858b9851c4607968cb280123e262a".into())
        );
        let dashed = r#"{"_BOOT_ID":"B75858B9-851C-4607-968C-B280123E262A"}"#;
        assert_eq!(
            boot_before_of(true, dashed, ""),
            BootBefore::Boot("b75858b9851c4607968cb280123e262a".into())
        );
        for err in [
            "Data from the specified boot (-3) is not available: No such boot ID in journal",
            "No journal boot entry found for the specified boot offset (-3).",
        ] {
            assert_eq!(
                boot_before_of(false, "", err),
                BootBefore::NoSuchBoot,
                "{err}"
            );
        }
        assert_eq!(boot_before_of(true, "\n", ""), BootBefore::NoSuchBoot);
        for (ok, out, err) in [
            (false, "", "Failed to open journal: Permission denied"),
            (
                true,
                r#"{"MESSAGE":"_BOOT_ID=b75858b9851c4607968cb280123e262a"}"#,
                "",
            ),
            (true, r#"{"_BOOT_ID":"not a boot"}"#, ""),
            (true, "_BOOT_ID=b75858b9851c4607968cb280123e262a", ""),
        ] {
            assert!(
                matches!(boot_before_of(ok, out, err), BootBefore::NoAnswer(_)),
                "{out} {err}"
            );
        }
    }

    /// Lot 389 (F2h-1): rc14's ubuntu2204 — systemd 249's boot list stops 39
    /// boots before this one (383 of 422) — judged by the walk: the boot
    /// right before this one is the last run's (a normal reboot), or one
    /// without the agent is between (a masked boot): signed, never
    /// `unknown` for want of the list.
    #[test]
    fn a_boot_list_that_stops_short_is_walked_past_from_this_boot() {
        let d = tempfile::tempdir().unwrap();
        let truncated = || -> Result<Vec<String>, String> {
            panic!("the walk reached the last run's boot: the list is not asked")
        };
        let got = judge_with(
            true,
            Some(A),
            d.path(),
            Some(C.into()),
            walk(&[A, C]),
            truncated,
        );
        assert_eq!(got.continuity, BootContinuity::NextBoot);
        let got = judge_with(
            true,
            Some(A),
            d.path(),
            Some(C.into()),
            walk(&[A, B, C]),
            truncated,
        );
        assert_eq!(
            got.continuity,
            BootContinuity::BootsWithoutAgent {
                count: 1,
                boot_ids: vec![boot_gap::normalize(B).unwrap()]
            }
        );
    }

    /// Lot 389 (F2h-1): the walk asks nothing past its deadline; before
    /// it, the journal's answer; and the start's judgement walks the journal
    /// first, with the question systemd 249 answers.
    #[test]
    fn the_walk_is_bounded_and_the_start_walks_first() {
        let mut asked = 0;
        let mut late = bounded_walk(std::time::Instant::now(), |_, _| {
            asked += 1;
            BootBefore::NoSuchBoot
        });
        assert!(matches!(late(A, 1), BootBefore::NoAnswer(w) if w.contains("longer than")));
        drop(late);
        assert_eq!(asked, 0);
        let mut on_time = bounded_walk(
            std::time::Instant::now() + std::time::Duration::from_secs(60),
            |_, k| BootBefore::Boot(format!("{k:032x}")),
        );
        assert_eq!(on_time(A, 3), BootBefore::Boot(format!("{:032x}", 3)));
        let code = include_str!("boots_since.rs");
        let judge =
            &code[code.find("pub fn judge(").unwrap()..code.find("pub fn bounded_walk(").unwrap()];
        assert!(
            judge.contains("anchored_walk(journal_tail_boot, journal_boot_at)")
                && judge.contains("journal_boots,"),
            "{judge}"
        );
        let asks = &code[code.find("pub fn journal_boot_at(").unwrap()
            ..code.find("pub fn boot_before_of(").unwrap()];
        assert!(
            asks.contains("journal_boot(Some(k))")
                && asks.contains("journal_boot(None)")
                && asks.contains("cmd.args(journal_boot_args(k));"),
            "{asks}"
        );
        let args = journal_boot_args(Some(3));
        assert_eq!(&args[..2], ["-b", "-3"]);
        for arg in ["-n", "1", "-o", "json", "--output-fields=_BOOT_ID"] {
            assert!(args.iter().any(|a| a == arg), "{arg}");
        }
    }

    /// The review of #597 (P3-3): the walk's anchor is the boot of the
    /// journal's tail — the newest entry, asked with no `-b` — against the
    /// kernel's id of this boot, never `-b 0`, which systemd 249, 255 and
    /// 257 answer with the kernel's current boot whatever the tail is; the
    /// walk's questions count back from that tail (`-b -<k>`).
    #[test]
    fn the_walk_s_anchor_is_the_journal_s_tail_never_b_0() {
        let tail = journal_boot_args(None);
        assert!(
            !tail.iter().any(|a| a == "-b" || a.starts_with("--boot")),
            "{tail:?}"
        );
        assert_eq!(
            tail,
            journal_boot_args(Some(0))[2..].to_vec(),
            "the tail's question is the walk's without its -b"
        );
        // the tail is another boot's (a clock set back, separate seqnum
        // chains): no question is asked, the walk has no answer — though
        // `-b -<k>` would answer
        let asked = std::cell::RefCell::new(Vec::new());
        let mut w = anchored_walk(
            || BootBefore::Boot(A.into()),
            |k| {
                asked.borrow_mut().push(k);
                BootBefore::Boot(B.into())
            },
        );
        assert!(matches!(w(C, 1), BootBefore::NoAnswer(why) if why.contains(A)));
        drop(w);
        assert!(asked.take().is_empty());
        // the tail is this boot's: the walk counts back from it
        let mut w = anchored_walk(
            || BootBefore::Boot(C.into()),
            |k| {
                asked.borrow_mut().push(k);
                BootBefore::Boot(B.into())
            },
        );
        assert_eq!(w(C, 1), BootBefore::Boot(B.into()));
        drop(w);
        assert_eq!(asked.take(), vec![1]);
    }

    /// Lot 389 (F2h-1): the walk counts from the journal's tail only once
    /// the tail's boot is this one (asked once, at the first question, in
    /// either form of the id; `usize::MAX` below marks the tail's question);
    /// a journal whose tail is another boot's, that holds no entry or does
    /// not answer gives no answer to any question.
    #[test]
    fn the_walk_counts_from_this_boot_only() {
        let asked = std::cell::RefCell::new(Vec::new());
        let tail = |newest: BootBefore| {
            let asked = &asked;
            move || {
                asked.borrow_mut().push(usize::MAX);
                newest.clone()
            }
        };
        let back = |k: usize| {
            asked.borrow_mut().push(k);
            BootBefore::Boot(format!("{k:032x}"))
        };
        let mut w = anchored_walk(tail(BootBefore::Boot(C.to_uppercase())), back);
        assert_eq!(w(C, 1), BootBefore::Boot(format!("{:032x}", 1)));
        assert_eq!(w(C, 2), BootBefore::Boot(format!("{:032x}", 2)));
        drop(w);
        assert_eq!(asked.take(), vec![usize::MAX, 1, 2]);
        for newest in [
            BootBefore::Boot(A.into()),
            BootBefore::NoSuchBoot,
            BootBefore::NoAnswer("killed past 2 s".into()),
        ] {
            let mut w = anchored_walk(tail(newest.clone()), back);
            assert!(matches!(w(C, 1), BootBefore::NoAnswer(_)), "{newest:?}");
            assert!(matches!(w(C, 2), BootBefore::NoAnswer(_)), "{newest:?}");
            drop(w);
            assert_eq!(asked.take(), vec![usize::MAX], "{newest:?}");
        }
    }

    /// Neither the chain nor the state file: unknown, never clean.
    #[test]
    fn no_record_of_the_last_runs_boot_is_unknown() {
        let d = tempfile::tempdir().unwrap();
        let got = judge_with(true, None, d.path(), Some(C.into()), walk(&[A, C]), || {
            ids(&[A, C])
        });
        assert_eq!(got.previous_source, PreviousBootSource::None);
        assert!(
            matches!(got.continuity, BootContinuity::Unknown { .. }),
            "{got:?}"
        );
    }
}
