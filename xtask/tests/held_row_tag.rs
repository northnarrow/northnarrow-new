//! Lot 384 (pre-alpha Phase 3c, F3c-1): one rule writes and reads the
//! audit row a held integrity line names.
//!
//! `nn-admin status` prints `nn-admin integrity acknowledge --through <row>`
//! with the newest row its `integrity:` lines name, read back from their
//! text. On main the line that counts the findings past the cap named no
//! row, and the status's reader — its own `split("(audit row ")` — found
//! only the listed ones: the command it printed left the counted rows held,
//! and once only they were left it printed no command at all. The tag is
//! now written by `nn_evidence::held::row_tag` and read by
//! `nn_evidence::held::rows_named`, side by side in `held.rs`, whose tests
//! hold that the rows the lines name end at `Held::newest_row`.
//!
//! This scan keeps it one rule:
//!
//! - no other reader: outside `held.rs`, no source of the tree (tests
//!   included) holds the bare tag `"(audit row "` as a literal — a reader
//!   of its own (a `split`, a `find`) that could drift from the writer;
//! - no other writer: outside `held.rs`, no production source formats the
//!   tag (`(audit row {`) — a held line names its row through `row_tag`.
//!
//! Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;

use support::{product_code, repo_root, rs_files, string_literals, strip_comments};

const HELD: &str = "crates/nn-evidence/src/held.rs";

/// This scan, which names the tag to find it.
const SELF: &str = "xtask/tests/held_row_tag.rs";

/// The bare tag, as a reader splits on it.
const BARE_TAG: &str = "(audit row ";

/// A format string that writes the tag.
const FORMATTED_TAG: &str = "(audit row {";

/// The files (repository-relative) that hold the bare tag as a literal.
fn readers(sources: &BTreeMap<String, String>) -> Vec<String> {
    sources
        .iter()
        .filter(|(rel, _)| rel.as_str() != HELD && rel.as_str() != SELF)
        .filter(|(_, code)| string_literals(code).iter().any(|l| l == BARE_TAG))
        .map(|(rel, _)| rel.clone())
        .collect()
}

/// The production files (repository-relative) that format the tag.
fn writers(production: &BTreeMap<String, String>) -> Vec<String> {
    production
        .iter()
        .filter(|(rel, _)| rel.as_str() != HELD)
        .filter(|(_, code)| {
            string_literals(code)
                .iter()
                .any(|l| l.contains(FORMATTED_TAG))
        })
        .map(|(rel, _)| rel.clone())
        .collect()
}

/// Every `.rs` file of the tree, comments blanked.
fn all_sources() -> BTreeMap<String, String> {
    let root = repo_root();
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    files
        .into_iter()
        .filter_map(|f| {
            let rel = f
                .strip_prefix(&root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&f).ok()?;
            Some((rel, strip_comments(&text)))
        })
        .collect()
}

#[test]
fn the_held_lines_row_tag_has_one_writer_and_one_reader() {
    let sources = all_sources();
    assert!(
        sources.contains_key(HELD),
        "{HELD} not found: the scan reads nothing"
    );
    assert!(
        string_literals(&sources[HELD])
            .iter()
            .any(|l| l == BARE_TAG),
        "{HELD} no longer holds the tag: update this scan"
    );
    let readers = readers(&sources);
    assert!(
        readers.is_empty(),
        "these files read a held line's audit row with a tag of their own; use \
         nn_evidence::held::rows_named (lot 384, F3c-1):\n{}",
        readers.join("\n")
    );
    let production = product_code(&repo_root());
    let writers = writers(&production);
    assert!(
        writers.is_empty(),
        "these production files write a held line's audit row with a format of their own; \
         use nn_evidence::held::row_tag (lot 384, F3c-1):\n{}",
        writers.join("\n")
    );
}

/// Each rule, on a planted violation (the contents planted under real
/// paths); the helpers' own file and a test's full tag (`"(audit row 7)"`)
/// are not violations.
#[test]
fn a_planted_reader_or_writer_is_caught() {
    let planted = |rel: &str, code: &str| {
        BTreeMap::from([
            (rel.to_string(), code.to_string()),
            (
                HELD.to_string(),
                "pub const ROW_TAG: &str = \"(audit row \"; fn w(r: u64) -> String { \
                 format!(\"(audit row {r})\") }"
                    .to_string(),
            ),
            (
                "crates/nn-linux/src/host_hardening.rs".to_string(),
                "fn t() { assert!(l.contains(\"(audit row 7)\")); }".to_string(),
            ),
        ])
    };
    let reader = planted(
        "crates/nn-admin/src/cli.rs",
        "fn n(l: &str) { l.split(\"(audit row \").skip(1); }",
    );
    assert_eq!(readers(&reader), ["crates/nn-admin/src/cli.rs"]);
    assert!(writers(&reader).is_empty());
    let writer = planted(
        "crates/nn-linux/src/mount_attrs.rs",
        "fn l(r: u64) -> String { format!(\"… the newest (audit row {r})\") }",
    );
    assert_eq!(writers(&writer), ["crates/nn-linux/src/mount_attrs.rs"]);
    assert!(readers(&writer).is_empty());
}
