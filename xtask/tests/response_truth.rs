//! Lot 312 (external bug hunt, edition 1.4, family F2): the response and
//! the COMBAT guard never judge a cgroup path or an executable's name by a
//! suffix or a substring — a ratchet so they stay so.
//!
//! The bugs it keeps closed: a namesake of the agent's blocked scope in a
//! user's delegated subtree taken for the scope (`ends_with`, `contains`:
//! BUG-91, the throttle's twin of BUG-117), a container's nested
//! `ssh.service` taken for the host's (the deepest unit, `rsplit('/')`:
//! BUG-114), and a payload named `x (deleted)` taken for a binary gone
//! (the kernel's suffix: BUG-90). Where a path is is decided by its
//! components from the root (`nn_core::response::cgroup`); whether an
//! executable is gone, by `st_nlink` of the inode the agent holds
//! (`crates/nn-linux/src/response/inode.rs`).
//!
//! Rules, over the production code of `crates/nn-linux/src/response/`,
//! `crates/nn-linux/src/combat/`, `agent/src/cow/`,
//! `crates/nn-core/src/combat/offender.rs` and
//! `crates/nn-linux/src/decision_host_linux.rs` (comments blanked, test
//! items and test files left out; each line read with its whitespace
//! removed, so `.ends_with (` is `.ends_with(`):
//!
//! 1. the kernel's ` (deleted)` mark is spelled only in `inode.rs`;
//! 2. no `.ends_with(` outside `inode.rs`;
//! 3. no `.contains(` of a string (a literal, a `format!`, an
//!    `.as_str()`, `.as_ref()`, `.display()` or lossy conversion, a `&*`, a
//!    `&str` named after a path) — a set's `contains(&pid)` is not one;
//! 4. no last component cut off a path by hand: `rsplit('/')`,
//!    `rsplit_once('/')`, any `rsplitn(`, `strip_suffix(`;
//! 5. a `/proc/<pid>/cgroup` text is read through `unified_path`: no
//!    `"0::"` spelled here.
//!
//! Each rule is shown failing on the shape it forbids (main's code before
//! the lot, and the review of #543's spellings that passed the first
//! version). Lexical, so not a proof: the behaviour tests of the lot are
//! the guard, this keeps the shapes out.

mod support;

use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The directories the rules cover.
const DIRS: &[&str] = &[
    "crates/nn-linux/src/response",
    "crates/nn-linux/src/combat",
    "agent/src/cow",
];

/// Single files the rules cover too (review of #543, F7: the parsers that
/// feed the guard and the rule policy's exemptions).
const FILES: &[&str] = &[
    "crates/nn-core/src/combat/offender.rs",
    "crates/nn-linux/src/decision_host_linux.rs",
];

/// The helper that may spell the kernel's mark and take a suffix.
const HELPER: &str = "crates/nn-linux/src/response/inode.rs";

/// A violation: (rule, line number, the line).
type Violation = (&'static str, usize, String);

/// The violations of `code` (production code, comments blanked) of the
/// file `rel`.
fn violations(rel: &str, code: &str) -> Vec<Violation> {
    let helper = rel == HELPER;
    let mut out = Vec::new();
    for (i, line) in code.lines().enumerate() {
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let mut hit = |rule: &'static str| out.push((rule, i + 1, line.trim().to_string()));
        if !helper && compact.contains("(deleted)") {
            hit("1: the kernel's ` (deleted)` mark outside inode.rs");
        }
        if !helper && (compact.contains(".ends_with(") || compact.contains("::ends_with(")) {
            hit("2: `ends_with` on a path or a name");
        }
        // `contains` and `find` of a string: a substring judged
        let mut rest = compact.as_str();
        while let Some((at, len)) = [".contains(", ".find("]
            .iter()
            .filter_map(|t| rest.find(t).map(|i| (i, t.len())))
            .min()
        {
            let arg = &rest[at + len..];
            let arg = &arg[..arg.find(')').map_or(arg.len(), |e| e + 1)];
            if arg.starts_with('"')
                || arg.starts_with("&\"")
                || arg.starts_with("format!")
                || arg.starts_with("&format!")
                || arg.starts_with("&*")
                || [
                    ".as_str()",
                    ".as_ref()",
                    ".display()",
                    "to_string_lossy",
                    "to_str(",
                ]
                .iter()
                .any(|m| arg.contains(m))
                || [
                    "&rel", "&scope", "&path", "&exe", "&origin", "&cgroup", "&unit", "&name",
                    "&want", "&sub",
                ]
                .iter()
                .any(|p| arg.starts_with(p))
            {
                hit("3: `contains` or `find` of a string");
            }
            rest = &rest[at + 1..];
        }
        for cut in [
            "rsplit('/')",
            "rsplit_once('/')",
            ".rsplitn(",
            ".strip_suffix(",
        ] {
            if compact.contains(cut) {
                hit("4: a last component cut off a path by hand");
            }
        }
        if compact.contains("\"0::") {
            hit("5: a cgroup text parsed outside `unified_path`");
        }
    }
    out
}

/// Production `.rs` files of the covered directories, `(rel, code)`.
fn covered() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out = Vec::new();
    let mut all = Vec::new();
    for dir in DIRS {
        let mut files = Vec::new();
        rs_files(&root.join(dir), &mut files);
        assert!(!files.is_empty(), "{dir}: no source files (moved?)");
        all.extend(files);
    }
    for f in FILES {
        let p = root.join(f);
        assert!(p.is_file(), "{f}: moved?");
        all.push(p);
    }
    {
        let files = all;
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            out.push((rel, production(&strip_comments(&text))));
        }
    }
    out.sort();
    out
}

#[test]
fn no_suffix_or_substring_judges_a_cgroup_path_or_an_executable() {
    let files = covered();
    assert!(files.len() >= 10, "{} files", files.len());
    assert!(
        files.iter().any(|(rel, _)| rel == HELPER),
        "{HELPER} is gone: the rule's helper moved?"
    );
    assert!(
        repo_root()
            .join("crates/nn-core/src/response/cgroup.rs")
            .exists(),
        "the cgroup helper moved"
    );
    let mut bad = Vec::new();
    for (rel, code) in &files {
        for (rule, line, text) in violations(rel, code) {
            bad.push(format!("{rel}:{line}: rule {rule}: {text}"));
        }
    }
    assert!(
        bad.is_empty(),
        "decide by components (nn_core::response::cgroup) or by the held inode \
         (response::inode), never by a suffix or a substring:\n{}",
        bad.join("\n")
    );
}

/// Each rule on the shape it forbids — main's code before lot 312.
#[test]
fn each_rule_fails_on_the_shape_it_forbids() {
    let rel = "planted";
    let planted: &[(&str, &str)] = &[
        (
            "            Ok(p) if p.to_string_lossy().ends_with(\" (deleted)\") => return Ok(None),",
            "1",
        ),
        (
            "            path.trim_end() == format!(\"/{rel}\") || path.trim_end().ends_with(&format!(\"/{rel}\"))",
            "2",
        ),
        (
            "                .is_some_and(|path| path.contains(&format!(\"/{rel}/\")))",
            "3",
        ),
        (
            "                super::containment::origin_of(p).is_some_and(|c| c.ends_with(&scope_rel))",
            "2",
        ),
        ("    path.rsplit('/')", "4"),
        (
            "        .find_map(|l| l.strip_prefix(\"0::\").map(|p| p.trim_end().to_string()))",
            "5",
        ),
        ("        if c.contains(\"/blocked.scope\") {", "3"),
        ("    let unit = name.strip_suffix(\".service\")?;", "4"),
        // review of #543 (F7): the spellings the first version missed
        ("            p.ends_with (want.as_str())", "2"),
        ("            || p.contains(sub.as_str())", "3"),
        ("            || p.contains( &format!(\"/{rel}/\") )", "3"),
        ("            || p.rsplitn(3, '/').nth(1) == Some(\"blocked.scope\")", "4"),
        ("    let path = text.lines().find_map(|l| l.strip_prefix( \"0::\" ));", "5"),
        ("        if exe.to_string_lossy().ends_with (\" (deleted)\") {", "1"),
        // re-check of #543: the spellings that still passed
        ("            str::ends_with(p, want.as_str())", "2"),
        ("            || p.find(sub.as_str()).is_some()", "3"),
        ("            || p.find(\"/blocked.scope/\").is_some()", "3"),
    ];
    for (line, rule) in planted {
        let v = violations(rel, line);
        assert!(
            v.iter().any(|(r, _, _)| r.starts_with(rule)),
            "rule {rule} misses `{line}`: {v:?}"
        );
    }
    // what stays allowed: a set's `contains`, a component's prefix, the
    // helper's own suffix test
    for ok in [
        "    if protected.contains(&pid) {",
        "    SYSTEM_SLICES.contains(first)",
        "    SSH_UNIT_PREFIXES.iter().any(|p| unit.starts_with(p))",
        "    component.rsplit_once('.').map(|(_, t)| t)",
        "    if trimmed.contains(char::is_whitespace) || trimmed.contains('\\0') {",
        "    stat.rsplit_once(')')?",
        "    .find(|p| p.exists())",
        "    .find_map(|l| l.strip_prefix(\"Uid:\"))?",
    ] {
        assert_eq!(violations(rel, ok), Vec::new(), "{ok}");
    }
    assert_eq!(
        violations(HELPER, "        .ends_with(DELETED_MARK.as_bytes())"),
        Vec::new()
    );
    assert!(!violations(HELPER, "    x.contains(\"/a\")").is_empty());
    // the helper's path, as the scan names it
    assert!(Path::new(HELPER).is_relative());
}
