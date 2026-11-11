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
//! The scan is lexical (comments blanked, test items left out). The rule is
//! shown failing on planted violations.

mod support;

use std::path::Path;

use support::{production, repo_root, rs_files, strip_comments};

/// The one file of the guard that compares inode numbers.
const HELPER: &str = "agent/src/cow/identity.rs";

/// Identifier tokens of `line`, with the punctuation between them.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in line.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
            continue;
        }
        if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if !c.is_whitespace() {
            out.push(c.to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn is_ino(t: &str) -> bool {
    t == "ino" || t == "st_ino"
}

fn is_dev(t: &str) -> bool {
    t == "dev" || t == "st_dev"
}

/// The violations of one file's production code: `(line, text)`.
fn violations(code: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in production(&strip_comments(code)).lines().enumerate() {
        let toks = tokens(line);
        let compares = line.contains("==") || line.contains("!=");
        let mut bad = compares && toks.iter().any(|t| is_ino(t));
        // a parenthesised pair: `( … dev , … ino )`
        for (k, t) in toks.iter().enumerate() {
            if t != "(" {
                continue;
            }
            let mut depth = 0i32;
            let mut elems: Vec<Vec<&str>> = vec![Vec::new()];
            for u in &toks[k + 1..] {
                match u.as_str() {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" if depth > 0 => depth -= 1,
                    ")" | "]" | "}" => break,
                    "," if depth == 0 => {
                        elems.push(Vec::new());
                        continue;
                    }
                    _ => {}
                }
                elems.last_mut().unwrap().push(u.as_str());
            }
            // the last identifier of an element, past a call's `(` `)`
            // (`x.ino()` ends in `ino`)
            fn ends_in(e: &[&str], f: fn(&str) -> bool) -> bool {
                e.iter()
                    .rev()
                    .find(|x| **x != ")" && **x != "(")
                    .is_some_and(|x| f(x))
            }
            let constructor = k >= 4 && toks[k - 4..k].join("") == "FileId::new";
            if !constructor
                && elems
                    .windows(2)
                    .any(|w| ends_in(&w[0], is_dev) && ends_in(&w[1], is_ino))
            {
                bad = true;
            }
        }
        if bad {
            out.push((i + 1, line.trim().to_string()));
        }
    }
    out
}

#[test]
fn the_guard_compares_inode_numbers_in_one_place() {
    let dir = repo_root().join("agent/src/cow");
    let mut files = Vec::new();
    rs_files(&dir, &mut files);
    files.sort();
    assert!(files.len() >= 10, "{} files under agent/src/cow", files.len());
    let mut bad = Vec::new();
    let mut helper_seen = false;
    for f in &files {
        let rel = f
            .strip_prefix(repo_root())
            .unwrap()
            .display()
            .to_string();
        let code = std::fs::read_to_string(f).unwrap();
        if rel == HELPER {
            helper_seen = true;
            // the helper does compare: the scan sees it
            assert!(!violations(&code).is_empty(), "{HELPER}: the scan sees nothing");
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
    ] {
        assert!(!violations(planted).is_empty(), "not seen: {planted}");
    }
    for clean in [
        "fn f() { let id = FileId::new(st.st_dev, st.st_ino, btime(fd, None)); }",
        "fn f() { let id = super::identity::FileId::new(f.dev, f.ino, None); }",
        "fn f() { if a.file.id().may_be(&b.file.id()) { } }",
        "fn f() { let s = FileState { dev: id.dev, ino: id.ino, size: 1 }; }",
        "fn f() { if m.dev() == dev { } }",
        // test items are not production code
        "#[cfg(test)]\nmod tests { fn t() { assert!(a.ino == 2); } }",
    ] {
        assert!(violations(clean).is_empty(), "seen: {clean}");
    }
    assert!(Path::new(&repo_root().join(HELPER)).exists());
}
