//! Lab PR 266 — nn-admin's output matrix, committed.
//!
//! Lab PRs 259 and 263 proved "nn-admin's output identical to `main`" with
//! a matrix of 1,964 cases run from a scratchpad, which a stopped session
//! deleted. This is that matrix rebuilt as a test of the tree: every case
//! runs the `nn-admin` binary of this build (the agent package's shim, on
//! the agent's host) in a directory of its own, and its stdout, stderr,
//! exit status, the files it wrote and the requests a mock agent received
//! are compared byte for byte with `agent/tests/golden/nn-admin/expected/`.
//! A change of a help text, an error, an exit code, a file nn-admin writes
//! or a request it sends is a diff of those files, in the pull request
//! that makes it (`docs/validation/GOLDEN_REPLAY.md`, §8).
//!
//! The areas (one golden file each, `cases.rs`): the help texts (every
//! subcommand, found by walking `--help`), clap's errors, `init`,
//! `verify-keys`, `host-check`, `audit read|verify`, `chain verify`,
//! `config overlay status|sign`, `policy show|test`, every socket verb
//! against the mock agent (its replies, the ten refusals, seven transport
//! faults, no socket and a socket nobody listens on), the key and identity
//! errors through every signed verb, closed pipes and the default paths.
//!
//! No root, no agent, no network: the mock agent is a thread of this test
//! (`mock.rs`), the keys are constant seeds, the chains are written with a
//! fixed clock, and what is inherently variable is normalised after it is
//! checked (`norm.rs`). `NN_GOLDEN_UPDATE=1` (`cargo xtask golden
//! --update`) writes the golden files instead; refused with `CI` set.
//!
//! The `debug-trigger` build (the lab's) has one more subcommand and other
//! help texts: the matrix is the release build's, and is not compiled with
//! that feature.

#![cfg(not(feature = "debug-trigger"))]
#![recursion_limit = "256"]

mod cases;
mod fixtures;
mod harness;
mod mock;
mod norm;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// The variable the golden tests read (xtask's `golden::UPDATE_ENV`).
const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";

fn expected_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("NN_REPO_ROOT"),
        "/agent/tests/golden/nn-admin/expected"
    ))
}

fn updating() -> bool {
    let update = std::env::var(UPDATE_ENV).as_deref() == Ok("1");
    if update && std::env::var_os("CI").is_some() {
        panic!("{UPDATE_ENV}=1 with CI set: CI checks the golden files, it never writes them");
    }
    update
}

/// The files the matrix writes keep the modes nn-admin asks for.
fn fixed_umask() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: umask(2) has no preconditions and cannot fail; it is set
    // once, before any case's directory or process exists.
    ONCE.call_once(|| unsafe {
        libc::umask(0o022);
    });
}

/// Every case, run on a few threads; the rendered text of each, in order.
fn run_all(cases: &[harness::Case]) -> Vec<String> {
    fixed_umask();
    let root = tempfile::Builder::new()
        .prefix("nnm")
        .tempdir_in("/tmp")
        .or_else(|_| tempfile::tempdir())
        .unwrap();
    let defaults = harness::host_defaults_absent();
    let out: Vec<Mutex<Option<String>>> = cases.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 8);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(case) = cases.get(i) else {
                    break;
                };
                let text = if case.host_defaults && !defaults {
                    None
                } else {
                    Some(harness::run(case, root.path()).text)
                };
                *out[i].lock().unwrap() = text;
            });
        }
    });
    if !defaults {
        eprintln!(
            "nn-admin matrix: {} of nn-admin's default directories exist on this host \
             ({}): the cases that read them were not run",
            harness::HOST_DEFAULT_DIRS
                .iter()
                .filter(|d| std::path::Path::new(d).exists())
                .count(),
            harness::HOST_DEFAULT_DIRS.join(", ")
        );
    }
    out.into_iter()
        .map(|m| m.into_inner().unwrap().unwrap_or_default())
        .collect()
}

/// The golden files: one per area, its cases in order. A stream or the
/// files of a case that are the same bytes as an earlier case's of the
/// area, and longer than four lines, name that case instead of being
/// written again (`policy test` gives one output for many inputs): a
/// change shows in the first case with those bytes, and in each case that
/// no longer shares them.
fn render(cases: &[harness::Case], texts: &[String]) -> BTreeMap<String, String> {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeMap<String, std::collections::HashMap<String, String>> = BTreeMap::new();
    for (c, t) in cases.iter().zip(texts) {
        let name = format!("{}.txt", c.area);
        let first = seen.entry(name.clone()).or_default();
        let t = dedupe(t, &c.id, first);
        files
            .entry(name)
            .or_insert_with(|| {
                format!(
                    "# nn-admin output matrix: {} (lab PR 266). Written by `cargo xtask golden \
                     --update`; never by hand. docs/validation/GOLDEN_REPLAY.md, §8.\n\n",
                    c.area
                )
            })
            .push_str(&t);
    }
    files
}

/// The sections of one case's text whose body an earlier case of the area
/// already has, as a reference to it.
fn dedupe(text: &str, id: &str, first: &mut std::collections::HashMap<String, String>) -> String {
    const SHARED: [&str; 3] = ["--- stdout\n", "--- stderr\n", "--- files\n"];
    let mut out = String::new();
    let mut section: Option<(&str, String)> = None;
    let flush = |out: &mut String,
                 section: &mut Option<(&str, String)>,
                 first: &mut std::collections::HashMap<String, String>| {
        if let Some((head, body)) = section.take() {
            out.push_str(head);
            let key = format!("{head}{body}");
            if body.lines().count() > 4 {
                if let Some(earlier) = first.get(&key) {
                    out.push_str(&format!("(the same bytes as in {earlier})\n"));
                    return;
                }
                first.insert(key, id.to_string());
            }
            out.push_str(&body);
        }
    };
    for line in text.split_inclusive('\n') {
        if line.starts_with("--- ") || line == "\n" {
            flush(&mut out, &mut section, first);
            if let Some(head) = SHARED.iter().find(|h| **h == line) {
                section = Some((head, String::new()));
                continue;
            }
            out.push_str(line);
            continue;
        }
        match &mut section {
            Some((_, body)) => body.push_str(line),
            None => out.push_str(line),
        }
    }
    flush(&mut out, &mut section, first);
    out
}

/// The blocks of a golden file, by case id.
fn blocks(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut id: Option<String> = None;
    let mut cur = String::new();
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("### ") {
            if let Some(i) = id.take() {
                out.insert(i, std::mem::take(&mut cur));
            }
            id = Some(rest.trim_end().to_string());
        }
        if id.is_some() {
            cur.push_str(line);
        }
    }
    if let Some(i) = id {
        out.insert(i, cur);
    }
    out
}

#[test]
fn nn_admin_output_matrix_matches_the_committed_files() {
    let started = std::time::Instant::now();
    let cases = cases::all();
    let ids: BTreeSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), cases.len(), "case ids are unique");
    let texts = run_all(&cases);
    let skipped: BTreeSet<String> = cases
        .iter()
        .zip(&texts)
        .filter(|(_, t)| t.is_empty())
        .map(|(c, _)| c.id.clone())
        .collect();
    let files = render(&cases, &texts);
    let dir = expected_dir();
    if updating() {
        assert!(
            skipped.is_empty(),
            "{UPDATE_ENV}=1 where nn-admin's default directories exist: {} case(s) not run; \
             update on a host without an installed agent",
            skipped.len()
        );
        std::fs::create_dir_all(&dir).unwrap();
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            if !files.contains_key(&e.file_name().to_string_lossy().into_owned()) {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        for (name, text) in &files {
            let path = dir.join(name);
            if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                std::fs::write(&path, text).unwrap();
            }
        }
        eprintln!(
            "nn-admin matrix: {} cases written in {:.1} s",
            cases.len(),
            started.elapsed().as_secs_f64()
        );
        return;
    }
    let mut problems = Vec::new();
    for e in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e} — run `cargo xtask golden --update`", dir.display()))
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if !files.contains_key(&name) {
            problems.push(format!("{name}: a golden file of no area"));
        }
    }
    for (name, text) in &files {
        let Ok(have) = std::fs::read_to_string(dir.join(name)) else {
            problems.push(format!("{name}: missing"));
            continue;
        };
        if &have == text {
            continue;
        }
        let want = blocks(text);
        let had = blocks(&have);
        let before = problems.len();
        for (id, b) in &want {
            match had.get(id) {
                None => problems.push(format!("{name}: case {id} is not in the golden file")),
                Some(h) if h != b => {
                    let line = h
                        .lines()
                        .zip(b.lines())
                        .find(|(x, y)| x != y)
                        .map(|(x, y)| format!("\n    golden: {x}\n    now:    {y}"))
                        .unwrap_or_else(|| "\n    (a line added or removed at the end)".into());
                    problems.push(format!("{name}: case {id} differs:{line}"));
                }
                _ => {}
            }
        }
        for id in had.keys() {
            if !want.contains_key(id) && !skipped.contains(id) {
                problems.push(format!(
                    "{name}: case {id} is in the golden file, no longer a case"
                ));
            }
        }
        let area_skipped = had.keys().any(|id| skipped.contains(id));
        if problems.len() == before && !area_skipped {
            problems.push(format!(
                "{name}: the header or the order of the cases differs"
            ));
        }
    }
    eprintln!(
        "nn-admin matrix: {} cases in {:.1} s",
        cases.len(),
        started.elapsed().as_secs_f64()
    );
    assert!(
        problems.is_empty(),
        "nn-admin's output moved ({} problem(s)) — if it is intended, `cargo xtask golden \
         --update` and review `git diff -- agent/tests/golden/nn-admin`:\n{}",
        problems.len(),
        problems
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// What the matrix covers, without running it: lab PR 259's areas, each
/// socket verb with every refusal and every transport fault.
#[test]
fn the_matrix_covers_lab_pr_259s_areas() {
    let cases = cases::all();
    let mut by_area: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &cases {
        *by_area.entry(c.area).or_default() += 1;
    }
    for (area, at_least) in cases::AREAS {
        let n = by_area.get(area).copied().unwrap_or(0);
        assert!(n >= *at_least, "{area}: {n} case(s), fewer than {at_least}");
    }
    for area in by_area.keys() {
        assert!(
            cases::AREAS.iter().any(|(a, _)| a == area),
            "{area}: not a listed area"
        );
    }
    cases::check_socket_coverage(&cases);
}
