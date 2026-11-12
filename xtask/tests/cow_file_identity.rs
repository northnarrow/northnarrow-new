//! Lot 315 (external bug hunt 1.4, family F6; the triage's N2 and BUG-110):
//! in the copy-on-first-write guard a file is its device, its inode number
//! and its birth time — and a ratchet so it stays so.
//!
//! An inode number is given to the next file created once the old one is
//! gone: compared with the device alone, a new file of the owner's that
//! inherited the number of a file the attack deleted was "the attack's
//! renamed copy" and moved into the journal's evidence, then deleted by
//! its expiry (N2, data loss); `pick` merged two files into one entry
//! (BUG-110); a writer's copy of the old file stood for the new one; the
//! new file's write-opens counted as the old one's. `agent/src/cow/
//! identity.rs` holds the only comparisons (`FileId::may_be`, `==`,
//! `FileId::surely_is`) and the only key (`Slot`). One rule holds that:
//!
//! **None, by shape**: the production code of `agent/src/cow/` outside
//! `identity.rs` holds no comparison of an inode number (a line with an
//! `ino` or `st_ino` token and `==` or `!=`) and no `dev, ino` in a
//! parenthesised list (an element ending in `dev`/`st_dev` followed by one
//! ending in `ino`/`st_ino`: a key, a tuple compared, a pattern, the
//! arguments of a lookup by number) — but `FileId::new(dev, ino, btime)`,
//! which makes the identity.
//!
//! The scan is lexical (comments blanked, test items left out) over each
//! file as one stream of tokens — a tuple or a comparison that rustfmt
//! splits over lines is seen whole, and a comparison by method (`.eq(`,
//! `.cmp(` …), an array key `[dev, ino]` and an element that only holds the
//! number (`ino + 0`) count (the review of #542, F6, which bypassed a
//! per-line scan with each). The rule is shown failing on planted
//! violations.

mod support;

use std::path::Path;

use support::{production, repo_root, rs_files, strip_comments};

/// The one file of the guard that compares inode numbers.
const HELPER: &str = "agent/src/cow/identity.rs";

/// The tokens of `code` with their line: identifiers and numbers, the
/// two-character operators `==`, `!=`, `::`, `=>`, `->`, `&&`, `||`, and
/// single punctuation. The file is one stream: a statement or a tuple that
/// rustfmt splits over lines is scanned whole (the review of #542, F6).
fn tokens(code: &str) -> Vec<(String, usize)> {
    let b: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_alphanumeric() || c == '_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == '_') {
                i += 1;
            }
            out.push((b[start..i].iter().collect(), line));
        } else {
            let two: String = b[i..(i + 2).min(b.len())].iter().collect();
            if ["==", "!=", "::", "=>", "->", "&&", "||"].contains(&two.as_str()) {
                out.push((two, line));
                i += 2;
            } else {
                out.push((c.to_string(), line));
                i += 1;
            }
        }
    }
    out
}

fn is_ino(t: &str) -> bool {
    t == "ino" || t == "st_ino"
}

fn is_dev(t: &str) -> bool {
    t == "dev" || t == "st_dev"
}

/// A comparison by method: `.eq(`, `.ne(`, `.cmp(`, `.partial_cmp(`, …
fn compares_by_method(t: &[(String, usize)], k: usize) -> bool {
    k + 2 < t.len()
        && t[k].0 == "."
        && ["eq", "ne", "cmp", "partial_cmp", "lt", "le", "gt", "ge"].contains(&t[k + 1].0.as_str())
        && t[k + 2].0 == "("
}

/// The violations of one file's production code: `(line, what)`.
fn violations(code: &str) -> Vec<(usize, String)> {
    let t = tokens(&production(&strip_comments(code)));
    let mut out = Vec::new();
    // 1. a comparison in a piece (between `;`, `{`, `}`, `,`) that holds an
    //    inode number token
    let mut start = 0;
    for k in 0..=t.len() {
        let end = k == t.len() || [";", "{", "}", ","].contains(&t[k].0.as_str());
        if !end {
            continue;
        }
        let piece = &t[start..k];
        let ino = piece.iter().find(|(x, _)| is_ino(x));
        let cmp = piece.iter().any(|(x, _)| x == "==" || x == "!=")
            || (0..piece.len()).any(|j| compares_by_method(piece, j));
        if let (Some((_, line)), true) = (ino, cmp) {
            out.push((*line, "an inode number compared".to_string()));
        }
        start = k + 1;
    }
    // 2. `dev` then `ino` in a parenthesised or bracketed list (a key, a
    //    tuple compared, a pattern, a lookup by number) — but the
    //    constructor `FileId::new(dev, ino, btime)`
    for (k, (open, line)) in t.iter().enumerate() {
        let close = match open.as_str() {
            "(" => ")",
            "[" => "]",
            _ => continue,
        };
        let constructor =
            k >= 3 && t[k - 3].0 == "FileId" && t[k - 2].0 == "::" && t[k - 1].0 == "new";
        if constructor {
            continue;
        }
        let mut depth = 0i32;
        let mut elems: Vec<Vec<&str>> = vec![Vec::new()];
        for (u, _) in &t[k + 1..] {
            match u.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" if depth > 0 => depth -= 1,
                x if x == close && depth == 0 => break,
                ")" | "]" | "}" => break,
                "," if depth == 0 => {
                    elems.push(Vec::new());
                    continue;
                }
                _ => {}
            }
            elems.last_mut().unwrap().push(u.as_str());
        }
        let has = |e: &Vec<&str>, f: fn(&str) -> bool| e.iter().any(|x| f(x));
        if elems
            .windows(2)
            .any(|w| has(&w[0], is_dev) && has(&w[1], is_ino))
        {
            out.push((*line, "a (dev, ino) list".to_string()));
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn the_guard_compares_inode_numbers_in_one_place() {
    let dir = repo_root().join("agent/src/cow");
    let mut files = Vec::new();
    rs_files(&dir, &mut files);
    files.sort();
    assert!(
        files.len() >= 10,
        "{} files under agent/src/cow",
        files.len()
    );
    let mut bad = Vec::new();
    let mut helper_seen = false;
    for f in &files {
        let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
        let code = std::fs::read_to_string(f).unwrap();
        if rel == HELPER {
            helper_seen = true;
            // the helper does compare: the scan sees it
            assert!(
                !violations(&code).is_empty(),
                "{HELPER}: the scan sees nothing"
            );
            continue;
        }
        for (line, text) in violations(&code) {
            bad.push(format!("{rel}:{line}: `{text}`"));
        }
    }
    assert!(helper_seen, "{HELPER} not found");
    assert!(
        bad.is_empty(),
        "an inode number compared, or a (dev, ino) key built, outside {HELPER} — ask \
         FileId::may_be, ==, or FileId::surely_is (with the birth time), and key by \
         FileId::slot():\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_rule_fails_on_planted_violations() {
    for planted in [
        // the shapes main had (store.rs:605, :1001, :948; index.rs:212;
        // restore.rs:180; guard.rs:607)
        "fn f() { let ok = (x.file.dev, x.file.ino) == (e.file.dev, e.file.ino); }",
        "fn f() { if st.st_dev == dev && st.st_ino == ino { } }",
        "fn f() { if (st.st_dev, st.st_ino) != (cur.dev, cur.ino) { } }",
        "fn f() { self.by_inode.get(&(dev, ino)); }",
        "fn f() { let key = (e.file.dev, e.file.ino); }",
        "fn f() { let (dev, ino) = (st.st_dev, st.st_ino); }",
        "fn f() { let k = (m.dev(), m.ino()); }",
        "fn f() { if a.ino != b.ino { } }",
        "fn f() { let key = (job.file.dev, job.file.ino, job.writer); }",
        "fn f() { ix.has_entry_for(dev, ino, writer); }",
        // the review of #542 (F6): what a per-line scan missed
        "fn f() {\n    let k = (\n        a.st_dev,\n        a.st_ino,\n    );\n}",
        "fn f() {\n    if (\n        a.dev,\n        a.ino,\n    ) == key\n    {\n    }\n}",
        "fn f() { let k = (b.st_dev, b.st_ino + 0); }",
        "fn f() { if a.st_ino.eq(&b.st_ino) { } }",
        "fn f() { if a.ino.cmp(&b.ino).is_eq() { } }",
        "fn f() { let k = [a.st_dev, a.st_ino]; }",
        "fn f() {\n    let same = a.st_ino\n        == b.st_ino;\n}",
    ] {
        assert!(!violations(planted).is_empty(), "not seen: {planted}");
    }
    for clean in [
        "fn f() { let id = FileId::new(st.st_dev, st.st_ino, btime(fd, None)); }",
        "fn f() { let id = super::identity::FileId::new(f.dev, f.ino, None); }",
        "fn f() { if a.file.id().may_be(&b.file.id()) { } }",
        "fn f() { let s = FileState { dev: id.dev, ino: id.ino, size: 1 }; }",
        "fn f() { if m.dev() == dev { } }",
        "fn f() {\n    let c = Current {\n        regular: st.st_mode & libc::S_IFMT == libc::S_IFREG,\n        dev: st.st_dev,\n        ino: st.st_ino,\n    };\n}",
        "fn f() { let id = FileId::new(\n    st.st_dev,\n    st.st_ino,\n    None,\n); }",
        // test items are not production code
        "#[cfg(test)]\nmod tests { fn t() { assert!(a.ino == 2); } }",
    ] {
        assert!(violations(clean).is_empty(), "seen: {clean}");
    }
    assert!(Path::new(&repo_root().join(HELPER)).exists());
}
