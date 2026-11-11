//! Lot 317 (third bug hunt, BUG-115): a fallback that lives only in an
//! unwinding build — a ratchet.
//!
//! The release profile aborts on a panic (`panic = "abort"` in the
//! workspace's `Cargo.toml`): in the agent that runs, a panic ends the
//! process and the watchdog starts it again. A `catch_unwind` in its code
//! guards a branch that exists only in the builds that unwind — the tests,
//! a debug build. The dispatcher of slow work had one
//! (`agent/src/pipeline/slow.rs`): it logged that the burst "is judged
//! without" its assessment, and dropped the event. It is gone; the panic
//! there is the decision thread's (a burst it cannot prepare, it could not
//! judge either).
//!
//! The rule: in the production code of the agent and the crates it is
//! built from (`agent/src`, `crates/*/src`, `watchdog/src`,
//! `antitamper-bpf/src`, `scan/src`; test files and `#[cfg(test)]` items
//! aside) `catch_unwind` is called only at the sites [`REVIEWED`] lists,
//! each with what its fallback does — never a claim that the work was done,
//! never the only place a piece of work goes. And the release profile
//! still aborts, the premise of all of it.

mod support;

use std::fs;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The `catch_unwind` calls of production code: (file, the function it
/// sits in, what its fallback does).
const REVIEWED: &[(&str, &str, &str)] = &[
    (
        "agent/src/cow/guard.rs",
        "fn spawn_threads",
        "the fanotify reader ended: the group is closed (no open waits on a guard without a \
         reader), the state says stopped, a signed degradation",
    ),
    (
        "agent/src/pipeline/dispatch.rs",
        "fn run_one",
        "an action that panicked: its outcome is Failed and its intent abandoned — never \
         reported done",
    ),
    (
        "crates/nn-linux/src/caps/errands.rs",
        "fn start",
        "a job that panicked loses its own answer (the caller reads `None`); the thread serves \
         the next",
    ),
    (
        "crates/nn-core/src/supervised.rs",
        "fn run<T>",
        "a job that panicked: counted lost and reported (\"that job's work is lost\")",
    ),
];

fn covered() -> Vec<(String, String)> {
    let root = repo_root();
    let mut dirs = vec![
        root.join("agent/src"),
        root.join("watchdog/src"),
        root.join("antitamper-bpf/src"),
        root.join("scan/src"),
    ];
    for e in fs::read_dir(root.join("crates")).unwrap() {
        let src = e.unwrap().path().join("src");
        if src.is_dir() {
            dirs.push(src);
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        let mut files = Vec::new();
        rs_files(&d, &mut files);
        for f in files {
            let rel = f.strip_prefix(&root).unwrap().display().to_string();
            if !is_test_file(&rel) {
                out.push((rel, fs::read_to_string(&f).unwrap()));
            }
        }
    }
    assert!(out.len() > 200, "only {} production files found", out.len());
    out
}

/// Each `catch_unwind` of `src`'s production code: (line, the nearest
/// `fn` above it).
fn calls(src: &str) -> Vec<(usize, String)> {
    let code = production(&strip_comments(src));
    let mut out = Vec::new();
    for (at, _) in code.match_indices("catch_unwind") {
        let line = code[..at].matches('\n').count() + 1;
        let func = code[..at]
            .lines()
            .rev()
            .map(str::trim)
            .find_map(|l| {
                let i = l.find("fn ")?;
                let head = &l[i..];
                Some(head[..head.find('(').unwrap_or(head.len())].to_string())
            })
            .unwrap_or_default();
        out.push((line, func));
    }
    out
}

fn check(rel: &str, src: &str, used: &mut [usize]) -> Vec<String> {
    let mut bad = Vec::new();
    for (line, func) in calls(src) {
        match REVIEWED
            .iter()
            .position(|(f, fun, _)| *f == rel && *fun == func)
        {
            Some(i) => used[i] += 1,
            None => bad.push(format!(
                "{rel}:{line}: catch_unwind in `{func}` — the release build aborts on a panic, so \
                 its fallback lives only in unwinding builds: make sure it claims nothing done and \
                 drops nothing, then list it in REVIEWED with what it does"
            )),
        }
    }
    bad
}

#[test]
fn catch_unwind_only_at_the_reviewed_sites() {
    let mut used = vec![0usize; REVIEWED.len()];
    let mut bad = Vec::new();
    for (rel, src) in covered() {
        bad.extend(check(&rel, &src, &mut used));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for (i, (file, func, _)) in REVIEWED.iter().enumerate() {
        assert_eq!(
            used[i], 1,
            "REVIEWED {file} `{func}`: {} catch_unwind, not one (moved or gone: update the list)",
            used[i]
        );
    }
    // BUG-115's site stays without one
    let slow = fs::read_to_string(repo_root().join("agent/src/pipeline/slow.rs")).unwrap();
    assert!(calls(&slow).is_empty());
}

/// The premise: the release profile aborts on a panic.
#[test]
fn the_release_build_aborts_on_a_panic() {
    let manifest = fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    let release = manifest
        .split("\n[")
        .find(|t| t.starts_with("profile.release]"))
        .expect("a [profile.release] table");
    assert!(
        release.lines().any(|l| l.trim() == "panic = \"abort\""),
        "[profile.release] no longer aborts on a panic: the fallbacks REVIEWED lists run in \
         the installed agent — review each again"
    );
}

/// The rule fails on a planted call, and passes test code and a reviewed
/// site. (The planted file's name is under no top-level directory:
/// `path_liveness.rs` checks every repository path an xtask test names.)
#[test]
fn a_planted_catch_unwind_fails_the_rule() {
    let mut used = vec![0usize; REVIEWED.len()];
    let planted = "fn run(s: &S) {\n    let r = std::panic::catch_unwind(|| s.work());\n}\n";
    let bad = check("planted/slow.rs", planted, &mut used);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].starts_with("planted/slow.rs:2:"), "{bad:?}");
    let test_only =
        "#[cfg(test)]\nmod tests {\n    fn t() { let _ = std::panic::catch_unwind(|| ()); }\n}\n";
    assert!(check("planted/slow.rs", test_only, &mut used).is_empty());
    let reviewed = "fn run<T>(s: &S<T>) {\n    let _ = std::panic::catch_unwind(|| ());\n}\n";
    assert!(check("crates/nn-core/src/supervised.rs", reviewed, &mut used).is_empty());
    assert!(!check("planted/supervised.rs", reviewed, &mut used).is_empty());
}
