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
//!   included) holds the tag to cut a line by — `(audit row` with no
//!   number after it (a `split`, a `find`) — that could drift from the
//!   writer; a test's full tag (`(audit row 7)`) is no reader;
//! - no other writer: outside `held.rs`, no production source formats the
//!   tag (`(audit row {…}`) — a held line names its row through `row_tag`.
//!
//! Lot 1.7b (stage S1, item F12; the review of #592, P3-3): the sources are
//! read as Rust (`support::ast`). A text is any literal (decoded: an
//! escape is its character; a byte string), what a `concat!` joins, and
//! what a formatting macro or a `concat` makes of its parts
//! (`format!("(audit {} {r})", "row")`), compared without case and with
//! its spaces collapsed: `(audit row` with nothing closed after it is a
//! reader, with a placeholder after it a writer, and a text that ends with
//! `(audit` is a tag cut in two (`(audit rows 5, 6)` is another text). The lexical scan before it (kept in [`lexical`] only to show it:
//! the bare tag as a literal, the format as a literal) missed each spelling
//! planted in `the_lexical_bypasses_are_caught`.
//!
//! Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;

use support::ast::{self, Corpus};
use support::{repo_root, rs_files, string_literals};

const HELD: &str = "crates/nn-evidence/src/held.rs";

/// This scan, which names the tag to find it.
const SELF: &str = "xtask/tests/held_row_tag.rs";

/// The bare tag, as a reader splits on it.
const BARE_TAG: &str = "(audit row ";

/// The files the AST reader refuses (a macro it does not read), each with
/// why: their literals are read as text ([`string_literals`]).
const UNREAD: &[(&str, &str)] = &[(
    "xtask/tests/support/ast.rs",
    "the reader itself: `syn`'s `Token![…]` in its types, a macro in a type it refuses",
)];

/// What a text does with the tag: cut a line by it, write it, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Reader,
    Writer,
}

/// The uses of the tag in `text` (any case, spaces collapsed).
fn tag_uses(text: &str) -> Vec<Tag> {
    let t = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut out = Vec::new();
    for (at, m) in t.match_indices("(audit row") {
        let after = &t[at + m.len()..];
        // `(audit rows 5, 6)`: another text, which no reader cuts by
        if after.starts_with('s') {
            continue;
        }
        let rest = after.trim_start();
        let word = rest
            .split(|c: char| c.is_whitespace() || c == ')')
            .next()
            .unwrap_or("");
        if rest.starts_with('{') {
            out.push(Tag::Writer);
        } else if word.is_empty() || !rest[word.len()..].starts_with(')') {
            // the tag with nothing closed after it: what a line is cut by
            out.push(Tag::Reader);
        }
        // else a full tag (`(audit row 7)`, a test's `(audit row x)`)
    }
    if t.trim_end().ends_with("(audit") {
        out.push(Tag::Reader);
    }
    out
}

/// The macros, methods and functions that make a text of their parts.
const MAKERS: &[&str] = &[
    "__macro__format",
    "__macro__format_args",
    "__macro__write",
    "__macro__writeln",
    "__macro__print",
    "__macro__println",
    "__macro__eprint",
    "__macro__eprintln",
    "__macro__panic",
    "concat",
];

/// The texts of each file of `sources`: its literals, `concat!`'s joins,
/// and what each maker of a file that holds `audit` or `row` makes. `prod`:
/// the production code only.
fn texts(sources: &BTreeMap<String, String>, prod: bool) -> BTreeMap<String, Vec<String>> {
    let mut parsed = BTreeMap::new();
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (rel, text) in sources {
        match ast::try_parse(rel, text) {
            Ok(mut f) => {
                if prod {
                    ast::strip_tests(&mut f);
                }
                parsed.insert(rel.clone(), f);
            }
            Err(why) => {
                assert!(
                    UNREAD.iter().any(|(f, _)| f == rel),
                    "{why}\n(or list the file in UNREAD with why; its literals are read as text)"
                );
                out.insert(rel.clone(), string_literals(text));
            }
        }
    }
    let c = Corpus::of(sources, &parsed);
    for (rel, ix) in &c.files {
        let mut v: Vec<String> = ix.lits.iter().map(|l| l.value.clone()).collect();
        let lower = ix.text.to_lowercase();
        if lower.contains("audit") || lower.contains("row") {
            for call in &ix.calls {
                if MAKERS.contains(&call.name.as_str()) {
                    v.extend(c.values(rel, call.expr, call.scope));
                }
            }
        }
        out.insert(rel.clone(), v);
    }
    out
}

/// The files (repository-relative) that cut a line by the tag.
fn readers(sources: &BTreeMap<String, String>) -> Vec<String> {
    let scanned: BTreeMap<String, String> = sources
        .iter()
        .filter(|(rel, _)| rel.as_str() != HELD && rel.as_str() != SELF)
        .map(|(r, t)| (r.clone(), t.clone()))
        .collect();
    texts(&scanned, false)
        .into_iter()
        .filter(|(_, v)| v.iter().any(|t| tag_uses(t).contains(&Tag::Reader)))
        .map(|(rel, _)| rel)
        .collect()
}

/// The production files (repository-relative) that format the tag.
fn writers(sources: &BTreeMap<String, String>) -> Vec<String> {
    let scanned: BTreeMap<String, String> = sources
        .iter()
        .filter(|(rel, _)| rel.as_str() != HELD)
        .map(|(r, t)| (r.clone(), t.clone()))
        .collect();
    texts(&scanned, true)
        .into_iter()
        .filter(|(_, v)| v.iter().any(|t| tag_uses(t).contains(&Tag::Writer)))
        .map(|(rel, _)| rel)
        .collect()
}

/// Every `.rs` file of the tree.
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
            Some((rel, text))
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
    let held: BTreeMap<String, String> = [(HELD.to_string(), sources[HELD].clone())].into();
    assert!(
        texts(&held, true)[HELD].iter().any(|l| l == BARE_TAG),
        "{HELD} no longer holds the tag: update this scan"
    );
    for (f, why) in UNREAD {
        assert!(
            sources.contains_key(*f),
            "{f}: listed in UNREAD, not in the tree"
        );
        assert!(why.len() > 20, "{f}: say why");
    }
    let readers = readers(&sources);
    assert!(
        readers.is_empty(),
        "these files read a held line's audit row with a tag of their own; use \
         nn_evidence::held::rows_named (lot 384, F3c-1):\n{}",
        readers.join("\n")
    );
    let production = ast::product_sources(&repo_root());
    let writers = writers(&production);
    assert!(
        writers.is_empty(),
        "these production files write a held line's audit row with a format of their own; \
         use nn_evidence::held::row_tag (lot 384, F3c-1):\n{}",
        writers.join("\n")
    );
}

/// The files planted with `plant` at `rel`, the helpers' own file and a
/// test's full tag beside it.
fn planted(rel: &str, code: &str) -> BTreeMap<String, String> {
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
}

/// Each rule, on a planted violation (the contents planted under real
/// paths); the helpers' own file and a test's full tag (`"(audit row 7)"`)
/// are not violations.
#[test]
fn a_planted_reader_or_writer_is_caught() {
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
    // a writer only in a test is no production writer
    let test_writer = planted(
        "crates/nn-linux/src/mount_attrs.rs",
        "#[cfg(test)]\nmod tests { fn l(r: u64) -> String { format!(\"(audit row {r})\") } }",
    );
    assert!(writers(&test_writer).is_empty());
}

/// Lot 1.7b (the review of #592, P3-3, and the mini-hunt): the spellings
/// the lexical scan missed, each planted in a copy of `nn-admin`'s
/// `cli.rs`: the lexical scan finds no reader or writer, the AST scan
/// finds the file — a reader's tag without its space (the review's), joined
/// by a `concat!`, in another case, with an escape for its space, cut in two
/// (`split("(audit")` then `" row "`); a
/// writer whose tag a `format!` makes of its parts (the review's), or an
/// array's `concat`.
#[test]
fn the_lexical_bypasses_are_caught() {
    let host = "crates/nn-admin/src/cli.rs";
    let text = std::fs::read_to_string(repo_root().join(host)).unwrap();
    let one = |t: &str| BTreeMap::from([(host.to_string(), t.to_string())]);
    assert!(readers(&one(&text)).is_empty() && writers(&one(&text)).is_empty());
    for (plant, reader) in [
        (
            "fn planted(l: &str) -> usize { l.split(\"(audit row\").count() }",
            true,
        ),
        (
            "const TAG: &str = concat!(\"(audit \", \"row \");\nfn planted(l: &str) -> Option<&str> { l.split(TAG).nth(1) }",
            true,
        ),
        (
            "fn planted(l: &str) -> bool { l.to_lowercase().contains(\"(Audit Row \") }",
            true,
        ),
        (
            "fn planted(l: &str) -> Option<(&str, &str)> { l.split_once(\"(audit row\\u{20}\") }",
            true,
        ),
        (
            "fn planted(l: &str) -> Option<&str> { l.split(\"(audit\").nth(1)?.strip_prefix(\" row \") }",
            true,
        ),
        (
            "fn planted(r: u64) -> String { format!(\"(audit {} {r})\", \"row\") }",
            false,
        ),
        (
            "fn planted(r: u64) -> String { [\"(audit\", \" row \", &r.to_string(), \")\"].concat() }",
            false,
        ),
    ] {
        let copy = format!("{text}\n{plant}\n");
        assert!(
            lexical::readers(&one(&copy)).is_empty() && lexical::writers(&one(&copy)).is_empty(),
            "the lexical scan saw it: {plant}"
        );
        let found = if reader {
            readers(&one(&copy))
        } else {
            writers(&one(&copy))
        };
        assert_eq!(found, [host], "{plant}");
    }
}

/// The scan before lot 1.7b, kept only to show the spellings it missed: the
/// bare tag as a literal, a format holding `(audit row {` as a literal.
mod lexical {
    use std::collections::BTreeMap;

    use super::support::{production, string_literals, strip_comments};
    use super::{BARE_TAG, HELD, SELF};

    const FORMATTED_TAG: &str = "(audit row {";

    pub fn readers(sources: &BTreeMap<String, String>) -> Vec<String> {
        sources
            .iter()
            .filter(|(rel, _)| rel.as_str() != HELD && rel.as_str() != SELF)
            .filter(|(_, code)| {
                string_literals(&strip_comments(code))
                    .iter()
                    .any(|l| l == BARE_TAG)
            })
            .map(|(rel, _)| rel.clone())
            .collect()
    }

    pub fn writers(sources: &BTreeMap<String, String>) -> Vec<String> {
        sources
            .iter()
            .filter(|(rel, _)| rel.as_str() != HELD)
            .filter(|(_, code)| {
                string_literals(&production(&strip_comments(code)))
                    .iter()
                    .any(|l| l.contains(FORMATTED_TAG))
            })
            .map(|(rel, _)| rel.clone())
            .collect()
    }
}
