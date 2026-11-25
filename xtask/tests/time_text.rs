//! Lot 1.6 (F11): chrono → jiff, and one module for the time's text.
//!
//! chrono 0.4 is unmaintained (RUSTSEC-2026-0543). Its timestamps moved to
//! jiff with their text kept byte for byte: `crates/nn-evidence/src/time.rs`
//! writes and reads every time the product signs, sends, exports or prints,
//! and `crates/nn-evidence/tests/time_chrono_corpus.rs` pins it on chrono's
//! own outputs. Eight functions in three crates wrote the chains' format
//! string (six `format_ts`, the detection store's `now_ts`, the export's
//! `now_rfc3339`); one more copy that drifted by a digit would write rows
//! no verifier reads the same. This test keeps it so:
//!
//! - chrono is in no manifest, no lockfile, no source and no advisory
//!   exception;
//! - jiff is named by nn-evidence's manifest and xtask's only (the build's
//!   tooling): the product's crates take its types from `nn_evidence::time`;
//! - no product code but nn-evidence writes or reads a time's text: no
//!   format pattern, no jiff formatter or parser, no chrono-style call, no
//!   `format_ts` of its own.

mod support;

use std::fs;

use support::{product_code, repo_root, strip_comments, tracked_files};

/// This file: it names what it forbids.
const SELF: &str = "xtask/tests/time_text.rs";

/// The crate whose `time` module owns the text (its `audit::format_ts` is
/// the chains' name for `time::format_micros`).
const OWNER: &str = "crates/nn-evidence/";

/// The manifests that may name jiff.
const JIFF_MANIFESTS: &[&str] = &["crates/nn-evidence/Cargo.toml", "xtask/Cargo.toml"];

/// What product code outside [`OWNER`] may not hold (comments and test
/// items blanked): the time's text is written and read in one place.
const TEXT_OUTSIDE_TIME: &[&str] = &[
    "%Y",
    "%H:%M",
    "%.6f",
    "strftime",
    "strptime",
    "jiff::",
    "parse::<Timestamp>",
    "Timestamp::from_str",
    "to_rfc3339",
    "parse_from_rfc3339",
    "fn format_ts(",
    "}T{",
];

/// The debt, file by file: a writer of a time's text of its own that never
/// used chrono. nn-export's syslog frames write RFC 5424's TIMESTAMP (to the
/// millisecond) from a hand-written calendar; moving it to `nn_evidence::time`
/// is its lot's. A file leaves this list when it no longer needs it (the
/// test below fails until it does).
const KNOWN: &[&str] = &["crates/nn-export/src/syslog.rs"];

/// The lines of a TOML text that are not comments.
fn toml_code(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.split('#').next().unwrap_or("")))
}

fn names_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        let part = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        !part(before) && !part(after)
    })
}

/// The needles of [`TEXT_OUTSIDE_TIME`] in `code`, as `path:line: needle`.
fn text_outside_time(rel: &str, code: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (i, line) in code.lines().enumerate() {
        for n in TEXT_OUTSIDE_TIME {
            if line.contains(n) {
                bad.push(format!("{rel}:{}: `{n}`", i + 1));
            }
        }
    }
    bad
}

/// Named (lot 1.6): chrono is gone — from every manifest, lockfile, Rust
/// source and from the advisory exceptions.
#[test]
fn chrono_is_in_no_manifest_lockfile_source_or_exception() {
    let root = repo_root();
    let mut bad = Vec::new();
    let mut manifests = 0;
    let mut sources = 0;
    for rel in tracked_files() {
        let Ok(text) = fs::read_to_string(root.join(&rel)) else {
            continue;
        };
        if rel.ends_with("Cargo.toml") {
            manifests += 1;
            for (n, line) in toml_code(&text) {
                if names_word(line, "chrono") {
                    bad.push(format!("{rel}:{n}: names chrono"));
                }
            }
        } else if rel.ends_with("Cargo.lock") {
            if text.lines().any(|l| l.trim() == "name = \"chrono\"") {
                bad.push(format!("{rel}: locks chrono"));
            }
        } else if rel.ends_with(".rs") && rel != SELF {
            sources += 1;
            for (i, line) in strip_comments(&text).lines().enumerate() {
                if line.contains("chrono::")
                    || (names_word(line, "chrono") && line.contains("use "))
                {
                    bad.push(format!("{rel}:{}: uses chrono", i + 1));
                }
            }
        }
    }
    let audit = fs::read_to_string(root.join(".cargo/audit.toml")).unwrap();
    for (n, line) in toml_code(&audit) {
        if line.contains("RUSTSEC-2026-0543") {
            bad.push(format!(".cargo/audit.toml:{n}: chrono's exception"));
        }
    }
    assert!(
        manifests >= 15 && sources >= 500,
        "{manifests} manifests, {sources} sources"
    );
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Named (lot 1.6): jiff is a dependency of nn-evidence (and xtask's)
/// only; the product's crates take its types from `nn_evidence::time`.
#[test]
fn only_nn_evidence_names_jiff() {
    let root = repo_root();
    let mut bad = Vec::new();
    let mut owners = 0;
    for rel in tracked_files().iter().filter(|r| r.ends_with("Cargo.toml")) {
        let text = fs::read_to_string(root.join(rel)).unwrap();
        let names = toml_code(&text).any(|(_, l)| names_word(l, "jiff"));
        match (names, JIFF_MANIFESTS.contains(&rel.as_str())) {
            (true, true) => owners += 1,
            (true, false) => bad.push(format!("{rel}: names jiff")),
            _ => {}
        }
    }
    assert_eq!(owners, JIFF_MANIFESTS.len(), "{JIFF_MANIFESTS:?}");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Named (lot 1.6): no product code but nn-evidence writes or reads a
/// time's text.
#[test]
fn the_time_text_is_written_and_read_in_nn_evidence_only() {
    let root = repo_root();
    let code = product_code(&root);
    assert!(code.len() >= 300, "{} product files", code.len());
    assert!(
        code.contains_key("crates/nn-evidence/src/time.rs"),
        "the time module moved: update this test"
    );
    let bad: Vec<String> = code
        .iter()
        .filter(|(rel, _)| !rel.starts_with(OWNER) && !KNOWN.contains(&rel.as_str()))
        .flat_map(|(rel, c)| text_outside_time(rel, c))
        .collect();
    for rel in KNOWN {
        let c = code.get(*rel).map(String::as_str).unwrap_or("");
        assert!(
            !text_outside_time(rel, c).is_empty(),
            "{rel} no longer writes a time's text: drop it from KNOWN"
        );
    }
    assert!(
        bad.is_empty(),
        "a time's text outside nn_evidence::time (use its format_*/parse_* functions):\n{}",
        bad.join("\n")
    );
}

/// The scanners above catch what they are for (a planted copy of each
/// pattern they forbid), and leave the rest.
#[test]
fn the_scanners_catch_their_patterns() {
    let planted = concat!(
        "let s = t.format(\"%Y-%m-%dT%H:%M:%S%.6fZ\").to_string();\n",
        "let t = jiff::Timestamp::now().strftime(\"%F\");\n",
        "fn format_ts(t: Timestamp) -> String { todo!() }\n",
        "let u = s.parse::<Timestamp>();\n",
        "let n = nn_evidence::time::format_micros(t);\n",
        "format!(\"{y:04}-{m:02}-{d:02}T{:02}:{:02}\", h, m)\n",
    );
    let found = text_outside_time("x.rs", planted);
    for line in [1, 2, 3, 4, 6] {
        assert!(
            found
                .iter()
                .any(|f| f.starts_with(&format!("x.rs:{line}:"))),
            "line {line}: {found:?}"
        );
    }
    assert!(!found.iter().any(|f| f.starts_with("x.rs:5:")), "{found:?}");
    assert!(names_word("chrono = \"0.4\"", "chrono"));
    assert!(!names_word("synchronous = true", "chrono"));
    assert!(names_word("jiff = { version = \"1\" }", "jiff"));
    assert!(!names_word("jiffy = 1", "jiff"));
    assert_eq!(toml_code("# chrono\nx = 1 # jiff").count(), 2);
    assert!(!toml_code("# chrono\nx = 1 # jiff").any(|(_, l)| names_word(l, "chrono")));
}
