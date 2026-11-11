//! Lot 314 (the third bug hunt, family F3 "state, windows and counts"):
//! the state machines' fragile patterns, held by a ratchet.
//!
//! 1. **The posture's state is written in one place.** In
//!    `crates/nn-core/src/posture/mod.rs` the state behind its lock is
//!    assigned only by `PostureMachine::commit`, which writes a transition
//!    row for every change of the kind or of COMBAT's lock, and the
//!    transition log is written only from there. BUG-84: a force to the
//!    current state rewrote the state before its no-op check — the decay
//!    timers re-armed, an unlocked COMBAT locked with no row.
//! 2. **A table of last-seen times has a cap.** In the production code of
//!    the security crates, a `HashMap`/`BTreeMap` of `Instant`s — the shape
//!    of a "once per window" memory — is built on `nn_core::decision::bounded`
//!    (`RepeatWindow`, `OncePerProcess`, `BoundedMap`), or listed in
//!    [`KNOWN`] with its count and what bounds it. BUG-125: the exec
//!    policy's repeat table grew with every distinct value a user put in an
//!    environment variable; BUG-83: a "once" rule had no memory at all.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

const POSTURE: &str = "crates/nn-core/src/posture/mod.rs";

/// The security crates' sources.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "watchdog/src",
    "crates/nn-admin/src",
    "crates/nn-evidence/src",
];

/// The helpers' own file.
const HELPERS: &str = "crates/nn-core/src/decision/bounded.rs";

/// Tables of last-seen times outside the helpers, with what bounds each.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-core/src/net/resolved.rs",
        1,
        "coverage_last: keyed by `CoverageCause`, an enum — one entry per variant",
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        1,
        "exited: the cached processes the sweep found gone, a subset of the spawn cache \
         (TRACKER_CAP, TRACKER_HARD_CAP), dropped with it",
    ),
];

/// The production code of `rel`, comments blanked and test items left out
/// (`None` for a test file).
fn production_of(rel: &str, text: &str) -> Option<String> {
    (!is_test_file(rel)).then(|| production(&strip_comments(text)))
}

/// Rule 1 over `code` (the posture machine's production code): what writes
/// the state or the transition log outside `fn commit`, by line.
fn state_writes_outside_commit(code: &str) -> Vec<String> {
    let commit = code.find("fn commit(");
    let commit_end = commit.map(|at| {
        let body = at + code[at..].find('{').expect("commit's body");
        body + support::matching_brace(&code[body..])
    });
    let inside = |at: usize| matches!((commit, commit_end), (Some(s), Some(e)) if at > s && at < e);
    let mut bad = Vec::new();
    for pat in [
        "*guard =",
        "*state =",
        ".state.write() =",
        "transitions.write()",
        "log_transition(",
    ] {
        for (at, _) in code.match_indices(pat) {
            let line = code[..at].matches('\n').count() + 1;
            let def = pat == "log_transition(" && code[..at].ends_with("fn ");
            let writer = pat == "transitions.write()" && {
                let f = code[..at].rfind("fn ").map(|f| &code[f..at]);
                f.is_some_and(|f| f.starts_with("fn log_transition("))
            };
            if !inside(at) && !def && !writer {
                bad.push(format!("{line}: `{pat}`"));
            }
        }
    }
    bad
}

/// Rule 2 over `code`: the tables of `Instant`s it declares, by line.
fn instant_tables(code: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for map in ["HashMap<", "BTreeMap<"] {
        for (at, _) in code.match_indices(map) {
            // the type's arguments, to the matching `>`
            let rest = &code[at + map.len()..];
            let mut depth = 1;
            let mut end = None;
            for (i, c) in rest.char_indices() {
                match c {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    ';' | '{' | '=' => break,
                    _ => {}
                }
            }
            let Some(end) = end else { continue };
            let args = rest[..end].trim_end();
            if args.ends_with(", Instant") || args.ends_with("::Instant") {
                out.push(code[..at].matches('\n').count() + 1);
            }
        }
    }
    out.sort_unstable();
    out
}

#[test]
fn the_posture_s_state_is_written_only_by_commit() {
    let text = std::fs::read_to_string(repo_root().join(POSTURE)).unwrap();
    let code = production_of(POSTURE, &text).unwrap();
    let bad = state_writes_outside_commit(&code);
    assert!(
        bad.is_empty(),
        "{POSTURE}: the posture's state or its transition log written outside \
         `PostureMachine::commit` (lot 314, BUG-84: every change of the kind or of COMBAT's \
         lock is a row, written there):\n{}",
        bad.join("\n")
    );
    // the one write, and the one row writer, are there
    let commit = &code[code.find("fn commit(").expect("PostureMachine::commit")..];
    let open = commit.find('{').unwrap();
    let body = &commit[open..open + support::matching_brace(&commit[open..])];
    assert!(body.contains("*state = next;"), "commit writes the state");
    assert!(body.contains("self.log_transition("), "commit writes the row");
}

#[test]
fn a_state_write_outside_commit_is_found() {
    let planted = "impl M {\n    fn commit(&self, state: &mut S, next: S) {\n        *state = next;\n        self.log_transition(a, b);\n    }\n    fn force(&self) {\n        let mut guard = self.inner.state.write();\n        *guard = next;\n    }\n    fn tick(&self) {\n        self.log_transition(a, b);\n    }\n    fn log_transition(&self) {\n        let mut log = self.inner.transitions.write();\n    }\n}\n";
    assert_eq!(
        state_writes_outside_commit(planted),
        vec!["8: `*guard =`".to_string(), "11: `log_transition(`".to_string()]
    );
}

#[test]
fn every_table_of_last_seen_times_has_a_cap() {
    let root = repo_root();
    let mut found: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for dir in SCAN {
        let mut files = Vec::new();
        rs_files(&root.join(dir), &mut files);
        for f in files {
            let rel = f.strip_prefix(&root).unwrap().display().to_string();
            if rel == HELPERS {
                continue;
            }
            let Some(code) = production_of(&rel, &std::fs::read_to_string(&f).unwrap()) else {
                continue;
            };
            let lines = instant_tables(&code);
            if !lines.is_empty() {
                found.insert(rel, lines);
            }
        }
    }
    let mut bad = Vec::new();
    for (rel, lines) in &found {
        match KNOWN.iter().find(|(k, _, _)| k == rel) {
            Some((_, n, _)) if *n == lines.len() => {}
            Some((_, n, _)) => bad.push(format!(
                "{rel}: {} table(s) of `Instant`s at lines {lines:?}, KNOWN says {n}",
                lines.len()
            )),
            None => bad.push(format!(
                "{rel}: a table of `Instant`s at lines {lines:?} — build it on \
                 nn_core::decision::bounded (RepeatWindow, OncePerProcess, BoundedMap), or list \
                 it in KNOWN with what bounds it"
            )),
        }
    }
    for (rel, _, _) in KNOWN {
        if !found.contains_key(*rel) {
            bad.push(format!("{rel}: listed in KNOWN, no longer has one: lower the table"));
        }
    }
    assert!(
        bad.is_empty(),
        "lot 314 (BUG-125, BUG-83): tables of last-seen times without a cap:\n{}",
        bad.join("\n")
    );
    // the helpers are where the memories are
    let helpers = std::fs::read_to_string(root.join(HELPERS)).unwrap();
    for t in ["pub struct BoundedMap", "pub struct RepeatWindow", "pub struct OncePerProcess"] {
        assert!(helpers.contains(t), "{HELPERS}: {t}");
    }
}

#[test]
fn a_table_of_instants_is_found() {
    let planted = "struct R {\n    seen: HashMap<String, Instant>,\n    other: HashMap<u32, u64>,\n    t: BTreeMap<(u32, u64), std::time::Instant>,\n}\n";
    assert_eq!(instant_tables(planted), vec![2, 4]);
    assert!(Path::new(HELPERS).extension().is_some());
}
