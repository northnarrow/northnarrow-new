//! Lot 373 (the review of #580, F1 and F3): what a package's `.list` and the
//! FIM marker's "one writer" may vouch for, a ratchet.
//!
//! 1. A dpkg `.list` says where a package put its files, and the package's
//!    own maintainer script, run as root, can append any path to it. The
//!    lineage's `is_package_file` reads it; every production caller is in
//!    [`LIST_READERS`] with its reason, and R012's — the only one — checks
//!    that the grant is a narrow capability (`package_may_lower`) before it
//!    asks the `.list`.
//! 2. NN-L-FIM-025 is wrapped in the package carve-out with its floor: a
//!    grant beyond the narrow set is not lowered by a package transaction.
//! 3. The eBPF marker's "one writer" is decided by the shared predicate
//!    (`common::wire::fim_one_writer_keeps`), given the writer's image.
//!
//! The scan is lexical (comments blanked, test items blanked). Rule 1 is
//! shown failing on a planted call.

mod support;

use std::collections::BTreeMap;

use support::{product_code, repo_root};

/// The production files that may ask the lineage whether a file is a
/// package's (`is_package_file`), with why.
const LIST_READERS: &[(&str, &str)] = &[
    ("crates/nn-core/src/posture/lineage.rs", "its definition"),
    (
        "crates/nn-core/src/decision/rules/r012_setcap_tooling.rs",
        "R012's package setcap, for a narrow capability only (package_may_lower first)",
    ),
];

/// The files outside [`LIST_READERS`] that call `is_package_file(`.
fn unlisted_readers(code: &BTreeMap<String, String>) -> Vec<String> {
    code.iter()
        .filter(|(_, text)| text.contains("is_package_file("))
        .map(|(rel, _)| rel.clone())
        .filter(|rel| !LIST_READERS.iter().any(|(f, _)| f == rel))
        .collect()
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) -> Result<(), String> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(format!("{n:?} not found after byte {at}")),
        }
    }
    Ok(())
}

/// The body of `fn name` in `code` (to its matching brace).
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .or_else(|| code.find(&format!("fn {name}<")))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    let len = support::matching_brace(&code[open..]);
    &code[open..open + len]
}

/// Named (the review of #580, F1): only R012 trusts a package's `.list`,
/// and only after it found the grant a narrow one.
#[test]
fn a_package_list_vouches_only_for_a_narrow_capability() {
    let code = product_code(&repo_root());
    assert_eq!(
        unlisted_readers(&code),
        Vec::<String>::new(),
        "a new reader of a package's .list: list it in LIST_READERS with its reason — the \
         package's own root script writes the .list"
    );
    for (f, _) in LIST_READERS {
        assert!(
            code.get(*f).is_some_and(|t| t.contains("is_package_file(")),
            "{f} no longer reads a package's .list: drop its entry"
        );
    }
    let r012 = &code["crates/nn-core/src/decision/rules/r012_setcap_tooling.rs"];
    in_order(
        body(r012, "package_setcap"),
        &[
            "maintainer_script_package(",
            "in_package_transaction(",
            "setcap_grants(argv)",
            "package_may_lower(grants)",
            "runs_programs(",
            "is_package_file(",
        ],
    )
    .unwrap();
}

/// Rule 1 fails on a planted reader.
#[test]
fn a_planted_package_list_reader_is_caught() {
    let mut code = BTreeMap::new();
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "r099_planted"),
        "fn f() { lineage.is_package_file(&p, f); }".to_string(),
    );
    code.insert(
        "crates/nn-core/src/decision/rules/r012_setcap_tooling.rs".to_string(),
        "fn g() { lineage.is_package_file(&p, f); }".to_string(),
    );
    assert_eq!(
        unlisted_readers(&code),
        vec![format!(
            "crates/nn-core/src/decision/rules/{}.rs",
            "r099_planted"
        )]
    );
}

/// Named (the review of #580, F1): NN-L-FIM-025 in a package transaction
/// keeps a grant beyond the narrow set High.
#[test]
fn fim025_s_package_carve_out_has_its_floor() {
    let code = product_code(&repo_root());
    let rules = &code["crates/nn-core/src/fim/rules.rs"];
    in_order(
        body(rules, "fim_rules_with_lineage"),
        &[
            "PackageManaged::new(",
            "NnLFim025FileCapabilityGranted::<H>::new(",
            ".with_floor(",
            "file_caps::grant_beyond_package(fe)",
        ],
    )
    .unwrap();
    assert!(
        !body(rules, "fim_rules_with_lineage").contains("admin(Box::new(NnLFim025"),
        "NN-L-FIM-025 behind the plain carve-out lowers every grant"
    );
}

/// Named (the review of #580, F3): the eBPF marker's one writer is the
/// shared predicate's, given the writer's image read at the write.
#[test]
fn the_fim_marker_s_one_writer_compares_the_image() {
    let code = support::strip_comments(
        &std::fs::read_to_string(repo_root().join("agent-ebpf/src/fim_watch.rs")).unwrap(),
    );
    in_order(
        body(&code, "try_fim_write_intent_observe"),
        &[
            "let start = crate::fork_parent::current_start();",
            "crate::bpf_defense::caller_exe_key()",
            "prev_writer = Some((prev.pid, prev.start, prev.exe_dev, prev.exe_ino));",
            "if !fim_one_writer_keeps(prev_writer, (pid, start, exe_dev, exe_ino)) {",
            "flags &= !u32::from(FIM_WRITE_ONE_WRITER);",
            "exe_dev,",
            "exe_ino,",
        ],
    )
    .unwrap();
}
