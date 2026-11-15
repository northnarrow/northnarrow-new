//! Lot 353 (re-check 3 of #563, R3-4): a test that runs in a user and mount
//! namespace of its own never skips silently in CI.
//!
//! The harness of #563 (`agent/tests/fuse_stall.rs`) and the watchdog's
//! `by_path_bounds` "passed" in the CI test job in 0.00 s: Ubuntu's AppArmor
//! gives an unprivileged user namespace no capabilities there, the child's
//! mount was refused, and the test printed "skipped". So:
//!
//! 1. every file that calls an `in_userns(…)` hands each outcome to `ran(…)`
//!    (`nn_linux::fuse_testing::ran`, or the watchdog's copy): a skip on a
//!    developer's host, a FAILURE when `CI` is set — at least as many
//!    `ran(` calls as `in_userns(` calls, and no outcome matched by hand
//!    (`None | Some(99) =>`, `None => eprintln!`);
//! 2. ci.yml's test job enables unprivileged user namespaces before
//!    `cargo test`.
//!
//! Each rule is shown failing on a planted violation. Lexical, comments
//! blanked first.

mod support;

use support::{repo_root, rs_files, strip_comments};

/// The calls of `name(` in `code` that are not its definition (`fn name(`)
/// nor a method or a longer name ending in it.
fn calls(code: &str, name: &str) -> usize {
    let pat = format!("{name}(");
    code.match_indices(&pat)
        .filter(|&(i, _)| {
            let before = &code[..i];
            let prev = before.chars().last();
            let ident = prev.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.');
            !ident && !before.trim_end().ends_with("fn")
        })
        .count()
}

/// Rule 1's offences in one file's code (comments blanked).
fn offences(rel: &str, code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (spawns, judged) = (calls(code, "in_userns"), calls(code, "ran"));
    if spawns > judged {
        out.push(format!(
            "{rel}: {spawns} in_userns( call(s), {judged} ran( call(s): an outcome not judged by `ran`"
        ));
    }
    if spawns > 0 {
        for shape in [
            "None | Some(99) =>",
            "None | Some(98) =>",
            "None => eprintln!",
        ] {
            if code.contains(shape) {
                out.push(format!("{rel}: `{shape}` (a skip matched by hand)"));
            }
        }
    }
    out
}

#[test]
fn every_namespace_test_fails_instead_of_skipping_under_ci() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in ["crates", "agent", "watchdog", "antitamper-bpf"] {
        rs_files(&root.join(dir), &mut files);
    }
    let mut bad = Vec::new();
    let mut seen = 0;
    for f in &files {
        let code = strip_comments(&std::fs::read_to_string(f).unwrap());
        let rel = f.strip_prefix(&root).unwrap().display().to_string();
        if calls(&code, "in_userns") > 0 {
            seen += 1;
        }
        bad.extend(offences(&rel, &code));
    }
    assert!(seen >= 6, "the namespace tests were found ({seen} files)");
    assert!(
        bad.is_empty(),
        "namespace tests that may skip in CI:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_ci_test_job_enables_unprivileged_user_namespaces() {
    let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    let name = ci
        .find("- name: Unprivileged user namespaces")
        .expect("ci.yml's user namespaces step");
    let sysctl = ci[name..]
        .find("kernel.apparmor_restrict_unprivileged_userns=0")
        .map(|i| name + i)
        .expect("the step lifts AppArmor's restriction of unprivileged user namespaces");
    let test = ci
        .find("run: cargo test --workspace --exclude")
        .expect("ci.yml's workspace test step");
    assert!(
        sysctl < test,
        "the namespaces are enabled before the workspace tests"
    );
    assert!(
        ci[name..sysctl].contains("if: matrix.task == 'test'"),
        "the step is the test job's"
    );
}

#[test]
fn the_rule_finds_a_skip_planted_by_hand() {
    let plain = "fn t() { let rc = in_userns(|| 0); match rc { None => eprintln!(\"skipped\"), Some(rc) => assert_eq!(rc, 0) } }";
    assert_eq!(
        offences("p.rs", plain).len(),
        2,
        "{:?}",
        offences("p.rs", plain)
    );
    let by_99 = "fn t() { let rc = testing::in_userns(|| 0); if let Some(r) = ran(rc) {} match rc { None | Some(99) => {} _ => {} } }";
    assert_eq!(offences("p.rs", by_99).len(), 1);
    let ok = "pub fn in_userns() {} fn t() { if let Some(rc) = crate::fuse_testing::ran(in_userns(|| 0)) { assert_eq!(rc, 0) } }";
    assert!(
        offences("p.rs", ok).is_empty(),
        "{:?}",
        offences("p.rs", ok)
    );
    // a method or a longer name is not a call of either
    assert_eq!(calls("x.ran(1); were_ran(2); fn ran(rc: i32) {}", "ran"), 0);
}
