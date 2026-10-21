//! The privileged-suite gate in a form a run can be judged by and a
//! maintainer can commit (lab PR 227).
//!
//! `cargo xtask gate-summary` reads the output of `deploy/lab/nn-lab.sh
//! test-ignored` on one guest — the CI job of `.github/workflows/lab-vm.yml`,
//! or a lab run saved with `tee` — and writes what ran: one entry per libtest
//! summary (a suite), the tests that failed, the expected failures of
//! `deploy/lab/expected-failures.tsv` that apply to the guest with their
//! outcome (listed, never folded into the totals' "passed" nor dropped), the
//! outcome of the workflow's steps and a verdict. The verdict passes only
//! when every step succeeded, at least one suite ran, nothing failed to
//! build, every test binary that failed printed its summary (a crash, a
//! kill or a timeout does not), and every failed test is an expected one;
//! an expected failure that passes or does not run fails it too, so the list
//! cannot go stale. Output: `gate-summary.json` (machine-readable) and
//! Markdown for the job summary.
//!
//! `cargo xtask gate-report` turns one or more of those summaries — a
//! directory from `gh run download <run id> -D DIR` holds one per guest — into
//! a Markdown table, one row per kernel, for `docs/validation/results/`. CI
//! never pushes: the maintainer commits the report.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Version of the JSON layout below.
pub const SCHEMA: u32 = 1;

/// The file `gate-summary` writes and `gate-report` looks for in a directory.
pub const SUMMARY_FILE: &str = "gate-summary.json";

/// The order of the lab's guests in a report (others follow by name).
const DISTRO_ORDER: [&str; 5] = ["ubuntu2404", "ubuntu2204", "debian12", "debian13", "alma9"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suite {
    /// The test target, from cargo's `Running …` line (`net_privileged_e2e`,
    /// a crate name for unit tests, `doctests <crate>`); `?` without one.
    pub name: String,
    /// What cargo said it runs (`tests/net_privileged_e2e.rs`, `unittests src/lib.rs`).
    pub source: String,
    /// libtest's status: `ok` or `FAILED`.
    pub status: String,
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
    pub measured: u64,
    pub filtered_out: u64,
    /// The failed tests the summary named.
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Totals {
    /// libtest summaries (`test result:` lines), as the lab counts suites.
    pub suites: u64,
    pub passed: u64,
    /// Every failed test, the expected ones included.
    pub failed: u64,
    /// Of `failed`, the ones `deploy/lab/expected-failures.tsv` lists for this guest.
    pub expected_failures: u64,
    pub ignored: u64,
    pub measured: u64,
    pub filtered_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailedTest {
    pub suite: String,
    pub test: String,
    pub expected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedFailure {
    pub suite: String,
    pub test: String,
    pub follow_up: String,
    /// `failed as expected`, `passed` or `did not run`.
    pub outcome: String,
}

/// One cargo run of `nn-lab.sh test-ignored`, between its `test-ignored run
/// <n>/<runs> start:` and `end: …: exit <status>` lines.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Run {
    /// `3/5`: the run's place among test-ignored's runs.
    pub index: String,
    pub label: String,
    /// Its exit status; none when the log ends inside it.
    pub exit: Option<i32>,
    /// Its libtest summaries, and how many of them failed.
    pub suites: u64,
    pub failed_suites: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    pub name: String,
    /// The workflow's `steps.<id>.outcome`: success, failure, cancelled, skipped.
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub schema: u32,
    pub distro: String,
    pub kernel: String,
    pub commit: String,
    pub run_url: String,
    pub generated_at: String,
    /// `pass` or `fail`.
    pub verdict: String,
    /// Why the verdict is `fail` (empty on a pass).
    pub reasons: Vec<String>,
    /// `nn-lab.sh test-ignored`'s exit status, when it finished.
    pub exit_status: Option<i32>,
    pub steps: Vec<Step>,
    pub runs: Vec<Run>,
    pub totals: Totals,
    pub failed_tests: Vec<FailedTest>,
    pub expected_failures: Vec<ExpectedFailure>,
    /// nn-lab.sh's own lines about what it left out (the tests
    /// `NN_LAB_IGNORED_SKIP` names).
    pub notes: Vec<String>,
    pub suites: Vec<Suite>,
}

impl Summary {
    pub fn passed(&self) -> bool {
        self.verdict == "pass"
    }
}

/// One line of `deploy/lab/expected-failures.tsv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedEntry {
    pub distro: String,
    pub suite: String,
    pub test: String,
    pub follow_up: String,
}

/// The expected failures: `distro<TAB>suite<TAB>test<TAB>follow-up` per line,
/// `#` comments and blank lines skipped. Any other shape is an error.
pub fn parse_expected(text: &str) -> Result<Vec<ExpectedEntry>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 || f.iter().any(|x| x.trim().is_empty() || x.trim() != *x) {
            bail!(
                "line {}: want four non-empty tab-separated fields (distro, suite, test, follow-up): {line:?}",
                n + 1
            );
        }
        out.push(ExpectedEntry {
            distro: f[0].to_string(),
            suite: f[1].to_string(),
            test: f[2].to_string(),
            follow_up: f[3].to_string(),
        });
    }
    Ok(out)
}

/// What one `nn-lab.sh test-ignored` log holds.
#[derive(Debug, Default)]
pub struct Parsed {
    pub suites: Vec<Suite>,
    pub runs: Vec<Run>,
    /// (suite, test) of every test libtest ran (an ignored one did not).
    pub ran: BTreeSet<(String, String)>,
    /// (suite, test) of every test that failed.
    pub failed: BTreeSet<(String, String)>,
    /// cargo's `error: test failed, to rerun pass …` lines: one per test
    /// binary that did not exit 0, with or without its summary.
    pub failed_binaries: u64,
    pub compile_errors: u64,
    /// nn-lab.sh's `ERROR:` lines (a `die`: no guest, no bpftool).
    pub lab_errors: Vec<String>,
    pub notes: Vec<String>,
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// `tests/x.rs (target/release/deps/x-0123abcd)` → (`x`, `tests/x.rs`).
fn running_suite(rest: &str) -> Option<(String, String)> {
    let open = rest.rfind(" (")?;
    let source = rest[..open].trim().to_string();
    let path = rest[open + 2..].strip_suffix(')')?;
    let file = path.rsplit('/').next()?;
    let name = match file.rsplit_once('-') {
        Some((stem, hash))
            if !stem.is_empty()
                && hash.len() >= 8
                && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            stem
        }
        _ => file,
    };
    Some((name.to_string(), source))
}

/// `ok. 3 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 1.2s`
fn parse_result(rest: &str) -> Option<Suite> {
    let (status, counts) = rest.split_once(". ")?;
    let mut s = Suite {
        status: status.trim().to_string(),
        ..Suite::default()
    };
    let mut seen = 0;
    for part in counts.split(';') {
        let mut w = part.split_whitespace();
        let (Some(n), Some(what)) = (w.next(), w.next()) else {
            continue;
        };
        let Ok(n) = n.parse::<u64>() else { continue };
        let slot = match what {
            "passed" => &mut s.passed,
            "failed" => &mut s.failed,
            "ignored" => &mut s.ignored,
            "measured" => &mut s.measured,
            "filtered" => &mut s.filtered_out,
            _ => continue,
        };
        *slot = n;
        seen += 1;
    }
    (seen >= 5).then_some(s)
}

/// The test names of libtest's closing `failures:` block (four spaces, one
/// name per line), or nothing when the block holds anything else.
fn failure_names(block: &[String]) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for l in block {
        if l.trim().is_empty() {
            continue;
        }
        let name = l.strip_prefix("    ")?;
        if name.is_empty() || name.contains(char::is_whitespace) {
            return None;
        }
        names.push(name.to_string());
    }
    Some(names)
}

pub fn parse_log(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut current: Option<(String, String)> = None;
    let mut started: Vec<String> = Vec::new();
    let mut failed_lines: Vec<String> = Vec::new();
    let mut block: Option<Vec<String>> = None;
    for raw in text.lines() {
        let line = strip_ansi(raw);
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("test result: ") {
            let mut suite = parse_result(rest).unwrap_or_else(|| Suite {
                status: "unreadable".to_string(),
                ..Suite::default()
            });
            let (name, source) = current
                .take()
                .unwrap_or_else(|| ("?".to_string(), String::new()));
            suite.name = name;
            suite.source = source;
            let mut failures: Vec<String> = block
                .take()
                .and_then(|b| failure_names(&b))
                .unwrap_or_default();
            for f in failed_lines.drain(..) {
                if !failures.contains(&f) {
                    failures.push(f);
                }
            }
            for t in started.drain(..) {
                p.ran.insert((suite.name.clone(), t));
            }
            for f in &failures {
                p.ran.insert((suite.name.clone(), f.clone()));
                p.failed.insert((suite.name.clone(), f.clone()));
            }
            suite.failures = failures;
            if let Some(run) = p.runs.last_mut().filter(|r| r.exit.is_none()) {
                run.suites += 1;
                if suite.status != "ok" {
                    run.failed_suites += 1;
                }
            }
            p.suites.push(suite);
            continue;
        }
        if let Some(rest) = t.strip_prefix("nn-lab: test-ignored run ") {
            if let Some((index, tail)) = rest.split_once(' ') {
                if let Some(label) = tail.strip_prefix("start: ") {
                    p.runs.push(Run {
                        index: index.to_string(),
                        label: label.to_string(),
                        ..Run::default()
                    });
                    continue;
                }
                if let Some((_, status)) = tail
                    .strip_prefix("end: ")
                    .and_then(|e| e.rsplit_once(": exit "))
                {
                    if let Some(run) = p
                        .runs
                        .iter_mut()
                        .rev()
                        .find(|r| r.index == index && r.exit.is_none())
                    {
                        run.exit = Some(status.trim().parse().unwrap_or(-1));
                    }
                    continue;
                }
            }
        }
        if let Some(rest) = t.strip_prefix("Running ") {
            if let Some(s) = running_suite(rest) {
                current = Some(s);
                started.clear();
                failed_lines.clear();
                block = None;
                continue;
            }
        }
        if let Some(krate) = t.strip_prefix("Doc-tests ") {
            current = Some((format!("doctests {krate}"), "doc-tests".to_string()));
            started.clear();
            failed_lines.clear();
            block = None;
            continue;
        }
        if t == "failures:" {
            block = Some(Vec::new());
            continue;
        }
        if let Some(b) = block.as_mut() {
            b.push(line.clone());
        }
        if let Some(rest) = line.strip_prefix("test ") {
            let rest = rest.trim_end();
            let (name, outcome) = match rest.split_once(" ... ") {
                Some((n, o)) => (n, o.trim()),
                None => (rest.strip_suffix(" ...").unwrap_or(""), ""),
            };
            // an ignored test did not run: it neither passes nor fails
            if !name.is_empty()
                && !name.contains(char::is_whitespace)
                && !outcome.starts_with("ignored")
            {
                started.push(name.to_string());
                if outcome.ends_with("FAILED") {
                    failed_lines.push(name.to_string());
                }
            }
        }
        if t.starts_with("error: test failed, to rerun pass") {
            p.failed_binaries += 1;
        } else if t.starts_with("error: could not compile") || t.starts_with("error[E") {
            p.compile_errors += 1;
        } else if let Some(m) = t.strip_prefix("nn-lab: ERROR: ") {
            p.lab_errors.push(m.to_string());
        } else if let Some(m) = t.strip_prefix("nn-lab: ") {
            if m.contains("skipping") {
                p.notes.push(m.to_string());
            }
        }
    }
    p
}

/// What `gate-summary` is told besides the log.
#[derive(Debug, Default, Clone)]
pub struct Inputs {
    pub distro: String,
    pub kernel: String,
    pub commit: String,
    pub run_url: String,
    pub exit_status: Option<i32>,
    /// (step, outcome) in the workflow's order.
    pub steps: Vec<(String, String)>,
}

/// The summary of one guest's run. `log` is None when there is no log.
pub fn evaluate(inputs: &Inputs, log: Option<&str>, expected: &[ExpectedEntry]) -> Summary {
    let parsed = log.map(parse_log).unwrap_or_default();
    let mut reasons = Vec::new();
    for (step, outcome) in &inputs.steps {
        if outcome != "success" {
            reasons.push(format!("step `{step}`: {outcome}"));
        }
    }
    if log.is_none() {
        reasons.push("no gate log: `nn-lab.sh test-ignored` did not run".to_string());
    } else if parsed.suites.is_empty() {
        reasons.push("no libtest summary in the gate log: no suite ran to its end".to_string());
    }
    if parsed.compile_errors > 0 {
        reasons.push(format!(
            "the build failed ({} compile error line(s))",
            parsed.compile_errors
        ));
    }
    for e in &parsed.lab_errors {
        reasons.push(format!("nn-lab.sh: {e}"));
    }
    let failed_suites = parsed.suites.iter().filter(|s| s.status != "ok").count() as u64;
    if parsed.failed_binaries > failed_suites {
        reasons.push(format!(
            "{} test binar{} failed without a libtest summary (crashed, killed or timed out)",
            parsed.failed_binaries - failed_suites,
            if parsed.failed_binaries - failed_suites == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }
    for s in &parsed.suites {
        if s.status == "unreadable" {
            reasons.push(format!(
                "suite `{}`: unreadable `test result:` line",
                s.name
            ));
        } else if s.status != "ok" && s.failures.is_empty() {
            reasons.push(format!(
                "suite `{}` failed without naming a failed test",
                s.name
            ));
        }
    }

    // test-ignored's cargo runs: each one finished, and one that failed
    // did so on a test (the failures themselves are judged below).
    for r in &parsed.runs {
        match r.exit {
            None => reasons.push(format!(
                "cargo run {} ({}) did not finish (killed, timed out, or the guest stopped answering)",
                r.index, r.label
            )),
            Some(rc) if rc != 0 && r.failed_suites == 0 => reasons.push(format!(
                "cargo run {} ({}) exited {rc} without a failed test summary: a build or cargo error (see gate.log)",
                r.index, r.label
            )),
            _ => {}
        }
    }
    if let Some(total) = parsed
        .runs
        .first()
        .and_then(|r| r.index.split_once('/'))
        .and_then(|(_, n)| n.parse::<usize>().ok())
    {
        if parsed.runs.len() < total {
            reasons.push(format!(
                "{} of test-ignored's {total} cargo runs started",
                parsed.runs.len()
            ));
        }
    }

    let mine: Vec<&ExpectedEntry> = expected
        .iter()
        .filter(|e| e.distro == inputs.distro)
        .collect();
    let is_expected =
        |suite: &str, test: &str| mine.iter().any(|e| e.suite == suite && e.test == test);
    let failed_tests: Vec<FailedTest> = parsed
        .failed
        .iter()
        .map(|(suite, test)| FailedTest {
            suite: suite.clone(),
            test: test.clone(),
            expected: is_expected(suite, test),
        })
        .collect();
    for f in failed_tests.iter().filter(|f| !f.expected) {
        reasons.push(format!("failed: `{}` › `{}`", f.suite, f.test));
    }
    let mut expected_failures = Vec::new();
    for e in &mine {
        let key = (e.suite.clone(), e.test.clone());
        let outcome = if parsed.failed.contains(&key) {
            "failed as expected"
        } else if parsed.ran.contains(&key) {
            reasons.push(format!(
                "`{}` › `{}` is expected to fail on {} and passed: the follow-up is fixed, remove its line from deploy/lab/expected-failures.tsv",
                e.suite, e.test, inputs.distro
            ));
            "passed"
        } else {
            if log.is_some() {
                reasons.push(format!(
                    "`{}` › `{}` (an expected failure on {}) did not run: renamed, skipped, or its suite did not finish",
                    e.suite, e.test, inputs.distro
                ));
            }
            "did not run"
        };
        expected_failures.push(ExpectedFailure {
            suite: e.suite.clone(),
            test: e.test.clone(),
            follow_up: e.follow_up.clone(),
            outcome: outcome.to_string(),
        });
    }
    match inputs.exit_status {
        Some(0) if !parsed.failed.is_empty() => reasons
            .push("`nn-lab.sh test-ignored` exited 0 with failed tests in its log".to_string()),
        Some(rc) if rc != 0 && parsed.failed.is_empty() && reasons.is_empty() => {
            reasons.push(format!(
                "`nn-lab.sh test-ignored` exited {rc} with no failed test in its log: see gate.log"
            ))
        }
        _ => {}
    }

    let mut totals = Totals {
        suites: parsed.suites.len() as u64,
        ..Totals::default()
    };
    for s in &parsed.suites {
        totals.passed += s.passed;
        totals.failed += s.failed;
        totals.ignored += s.ignored;
        totals.measured += s.measured;
        totals.filtered_out += s.filtered_out;
    }
    totals.expected_failures = failed_tests.iter().filter(|f| f.expected).count() as u64;

    Summary {
        schema: SCHEMA,
        distro: inputs.distro.clone(),
        kernel: inputs.kernel.trim().to_string(),
        commit: inputs.commit.clone(),
        run_url: inputs.run_url.clone(),
        generated_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        verdict: if reasons.is_empty() { "pass" } else { "fail" }.to_string(),
        reasons,
        exit_status: inputs.exit_status,
        steps: inputs
            .steps
            .iter()
            .map(|(name, outcome)| Step {
                name: name.clone(),
                outcome: outcome.clone(),
            })
            .collect(),
        runs: parsed.runs,
        totals,
        failed_tests,
        expected_failures,
        notes: parsed.notes,
        suites: parsed.suites,
    }
}

/// A Markdown table cell: one line, no `|`.
fn cell(s: &str) -> String {
    let s = s.replace(['\n', '\r'], " ").replace('|', "\\|");
    if s.is_empty() {
        "—".to_string()
    } else {
        s
    }
}

fn verdict_text(s: &Summary) -> String {
    let xf = s.totals.expected_failures;
    match (s.passed(), xf) {
        (true, 0) => "✅ pass".to_string(),
        (true, n) => format!(
            "✅ pass ({n} expected failure{})",
            if n == 1 { "" } else { "s" }
        ),
        (false, _) => "❌ fail".to_string(),
    }
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

const TABLE_HEAD: &str = "| distro | kernel | suites | passed | failed | expected failures | ignored | verdict |\n|---|---|---|---|---|---|---|---|\n";

fn table_row(s: &Summary) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
        cell(&s.distro),
        cell(&s.kernel),
        s.totals.suites,
        s.totals.passed,
        s.totals.failed,
        s.totals.expected_failures,
        s.totals.ignored,
        verdict_text(s)
    )
}

fn expected_lines(s: &Summary, with_distro: bool) -> String {
    let mut out = String::new();
    for e in &s.expected_failures {
        out.push_str(&format!(
            "- {}`{}` › `{}`: **{}**. {}\n",
            if with_distro {
                format!("{}: ", s.distro)
            } else {
                String::new()
            },
            e.suite,
            e.test,
            e.outcome,
            e.follow_up.replace('\n', " ")
        ));
    }
    out
}

/// The job summary of one guest's run.
pub fn job_markdown(s: &Summary) -> String {
    let mut out = format!(
        "### Privileged suites on a CI guest: `{}` — {}\n\n",
        s.distro,
        if s.passed() { "PASS" } else { "FAIL" }
    );
    out.push_str(TABLE_HEAD);
    out.push_str(&table_row(s));
    out.push('\n');
    if !s.expected_failures.is_empty() {
        out.push_str(
            "**Expected failures** (`deploy/lab/expected-failures.tsv`: recorded follow-ups; \
             the run fails if one passes or does not run):\n\n",
        );
        out.push_str(&expected_lines(s, false));
        out.push('\n');
    }
    if !s.reasons.is_empty() {
        out.push_str("**Why the run failed:**\n\n");
        for r in &s.reasons {
            out.push_str(&format!("- {}\n", r.replace('\n', " ")));
        }
        out.push('\n');
    }
    if !s.steps.is_empty() {
        let steps: Vec<String> = s
            .steps
            .iter()
            .map(|st| {
                let mark = match st.outcome.as_str() {
                    "success" => "✅",
                    "skipped" => "⏭",
                    _ => "❌",
                };
                format!("{} {mark}", st.name)
            })
            .collect();
        out.push_str(&format!("Steps: {}\n\n", steps.join(" · ")));
    }
    if !s.runs.is_empty() {
        let runs: Vec<String> = s
            .runs
            .iter()
            .map(|r| {
                format!(
                    "{} {}: {}",
                    r.index,
                    r.label,
                    r.exit
                        .map(|e| format!("exit {e}"))
                        .unwrap_or_else(|| "did not finish".to_string())
                )
            })
            .collect();
        out.push_str(&format!("Cargo runs: {}\n\n", runs.join(" · ")));
    }
    for n in &s.notes {
        out.push_str(&format!("Note: {n}\n\n"));
    }
    if !s.suites.is_empty() {
        out.push_str(&format!(
            "<details><summary>{} suites</summary>\n\n| suite | source | status | passed | failed | ignored | filtered out |\n|---|---|---|---|---|---|---|\n",
            s.suites.len()
        ));
        for x in &s.suites {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                cell(&x.name),
                cell(&x.source),
                cell(&x.status),
                x.passed,
                x.failed,
                x.ignored,
                x.filtered_out
            ));
        }
        out.push_str("\n</details>\n\n");
    }
    out.push_str(&format!(
        "Commit {}{}; `nn-lab.sh test-ignored` exit status {}.\n",
        if s.commit.is_empty() {
            "unknown".to_string()
        } else {
            format!("`{}`", short(&s.commit))
        },
        if s.run_url.is_empty() {
            String::new()
        } else {
            format!(", run {}", s.run_url)
        },
        s.exit_status
            .map(|r| r.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    out
}

fn distro_rank(d: &str) -> (usize, String) {
    (
        DISTRO_ORDER
            .iter()
            .position(|x| *x == d)
            .unwrap_or(DISTRO_ORDER.len()),
        d.to_string(),
    )
}

/// The Markdown a maintainer commits: one row per guest.
pub fn report_markdown(summaries: &[Summary]) -> String {
    let mut v: Vec<&Summary> = summaries.iter().collect();
    v.sort_by_key(|s| distro_rank(&s.distro));
    let commits: BTreeSet<&str> = v
        .iter()
        .map(|s| s.commit.as_str())
        .filter(|c| !c.is_empty())
        .collect();
    let runs: BTreeSet<&str> = v
        .iter()
        .map(|s| s.run_url.as_str())
        .filter(|u| !u.is_empty())
        .collect();
    let date = v
        .iter()
        .map(|s| s.generated_at.get(..10).unwrap_or(""))
        .min()
        .unwrap_or("");
    let commit_list: Vec<String> = commits.iter().map(|c| format!("`{}`", short(c))).collect();
    let mut out = format!(
        "# Privileged suites on CI guests — {date}{}\n\n",
        if commit_list.is_empty() {
            String::new()
        } else {
            format!(", {}", commit_list.join(", "))
        }
    );
    out.push_str(
        "Generated by `cargo xtask gate-report` from the `gate-summary.json` artefacts of \
         `.github/workflows/lab-vm.yml` (lab PR 227): each row is one guest, booted under KVM on a \
         GitHub-hosted runner, running `deploy/lab/nn-lab.sh test-ignored` — every privileged \
         suite, as root, single-threaded.",
    );
    if !runs.is_empty() {
        let r: Vec<&str> = runs.into_iter().collect();
        out.push_str(&format!(" Run: {}.", r.join(", ")));
    }
    out.push_str("\n\n");
    out.push_str(TABLE_HEAD);
    for s in &v {
        out.push_str(&table_row(s));
    }
    out.push('\n');
    let expected: String = v.iter().map(|s| expected_lines(s, true)).collect();
    if expected.is_empty() {
        out.push_str("Expected failures (`deploy/lab/expected-failures.tsv`): none.\n\n");
    } else {
        out.push_str(
            "Expected failures (`deploy/lab/expected-failures.tsv`, recorded follow-ups):\n\n",
        );
        out.push_str(&expected);
        out.push('\n');
    }
    let failing: Vec<&&Summary> = v.iter().filter(|s| !s.passed()).collect();
    if failing.is_empty() {
        out.push_str("Every guest passed.\n");
    } else {
        out.push_str("Failed:\n\n");
        for s in failing {
            for r in &s.reasons {
                out.push_str(&format!("- {}: {}\n", s.distro, r.replace('\n', " ")));
            }
        }
    }
    // one line per note, with the guests that printed it
    let mut notes: Vec<(String, Vec<String>)> = Vec::new();
    for s in &v {
        for n in &s.notes {
            match notes.iter_mut().find(|(text, _)| text == n) {
                Some((_, who)) => who.push(s.distro.clone()),
                None => notes.push((n.clone(), vec![s.distro.clone()])),
            }
        }
    }
    if !notes.is_empty() {
        out.push('\n');
        for (text, who) in notes {
            out.push_str(&format!("Note ({}): {text}\n", who.join(", ")));
        }
    }
    out
}

/// `gate-summary.json` files: the paths given, and those under a directory given.
pub fn find_summaries(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut stack = vec![p.clone()];
            while let Some(d) = stack.pop() {
                for e in fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
                    let path = e?.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.file_name().and_then(|n| n.to_str()) == Some(SUMMARY_FILE) {
                        out.push(path);
                    }
                }
            }
        } else {
            out.push(p.clone());
        }
    }
    out.sort();
    if out.is_empty() {
        bail!("no {SUMMARY_FILE} under {paths:?}");
    }
    Ok(out)
}

pub fn read_summary(path: &Path) -> Result<Summary> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let s: Summary =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if s.schema != SCHEMA {
        bail!(
            "{}: summary schema {} (this xtask reads {SCHEMA})",
            path.display(),
            s.schema
        );
    }
    Ok(s)
}

/// `step=outcome` from the command line.
pub fn parse_step(arg: &str) -> Result<(String, String)> {
    match arg.split_once('=') {
        Some((name, outcome)) if !name.is_empty() => {
            let outcome = if outcome.is_empty() {
                "not run"
            } else {
                outcome
            };
            Ok((name.to_string(), outcome.to_string()))
        }
        _ => bail!("--step wants NAME=OUTCOME, got {arg:?}"),
    }
}
