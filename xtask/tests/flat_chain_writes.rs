//! Lot 319 (lot 296's backlog): every chain row is appended by a writer that
//! knows a failed write — and a ratchet so it stays so.
//!
//! Lot 296 gave the audit log and the rotating chains the poisoned-writer
//! scheme: a write the disk stopped part-way (full) or whose fsync failed
//! leaves the file in a state the writer does not know, so the next row
//! reads the tail again first — the fragment cut and the cut signed, a row
//! written whole the tail. The flat chains of the agent's host (the canary
//! registry and access log, the FIM baseline, the listener log) still
//! appended with `write_all` on a file they opened themselves, and the next
//! row was glued to the fragment (lot 319's test
//! `chain_host_linux::tests::a_short_write_glues_no_row_in_the_flat_chains`).
//! They append through `crates/nn-linux/src/flat_chain.rs` now.
//!
//! The rule: a production file that holds a chain row (`entry_hash`) opens
//! no file to append (`.append(true)`, `O_APPEND`). Its rows go through
//! `nn_linux::flat_chain::FlatFile` (which names no row) or the chain
//! crate's own writers. [`KNOWN`] lists the files where both markers are
//! there and no flat chain is appended, with why; a new one fails until it
//! is moved to the writer or listed with its reason, and an entry whose
//! file no longer holds both fails until it is removed — the table is the
//! code's.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). The rule is shown failing on a planted violation. It sees an
//! append-open, not every append: a writer that opens with `.write(true)`
//! and seeks to the end, or writes at an offset (`pwrite`), passes it — the
//! review of #544 noted it; such a writer is a chain crate's own (the
//! manifest's repair writes in place through `ChainHost::write_all_at`).

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The files where a row's `entry_hash` and an append-open meet without a
/// flat chain's append, and why.
const KNOWN: &[(&str, &str)] = &[
    (
        "crates/nn-evidence/src/audit.rs",
        "the audit chain's own writer: lot 296's poisoned writer \
         (`recover_after_failed_append`), its append and fsync through the host \
         (`ChainHost::append_all`, `sync_all`)",
    ),
    (
        "crates/nn-evidence/src/chainlog.rs",
        "the rotating chains' writer: lot 296's poisoned writer (`active_poison`, \
         `manifest_poison`, `recover_active`), through the host",
    ),
    (
        "crates/nn-admin/src/admin_cli.rs",
        "`init` appends a public key to admin.pub; `entry_hash` is read from \
         the chains it verifies, never written",
    ),
];

/// A chain row: the field every chain's row carries.
const ROW: &str = "entry_hash";

/// An open to append.
const APPEND: &[&str] = &[".append(true)", "O_APPEND"];

/// The crates' sources scanned: every crate of the workspace.
const ROOTS: &[&str] = &[
    "crates",
    "agent/src",
    "watchdog/src",
    "common",
    "cli",
    "scan",
];

/// `true` when `code` (a production file's text) holds a row and an
/// append-open.
fn appends_rows(code: &str) -> bool {
    let code = production(&strip_comments(code));
    code.contains(ROW) && APPEND.iter().any(|m| code.contains(m))
}

/// Every production file that holds a row and an append-open, by path
/// relative to the repository root.
fn offenders(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    for dir in ROOTS {
        rs_files(&root.join(dir), &mut files);
    }
    let mut out = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&rel)
            || rel.contains("/tests/")
            || rel.contains("/benches/")
            || rel.contains("/examples/")
            || rel.contains("/target/")
            || rel.starts_with("crates/xtask")
        {
            continue;
        }
        let Ok(code) = std::fs::read_to_string(&f) else {
            continue;
        };
        if appends_rows(&code) {
            out.push(rel);
        }
    }
    out.sort();
    out
}

#[test]
fn chain_rows_are_appended_by_a_writer_that_knows_a_failed_write() {
    let root = repo_root();
    let found = offenders(&root);
    let known: BTreeMap<&str, &str> = KNOWN.iter().copied().collect();
    let new: Vec<&String> = found
        .iter()
        .filter(|f| !known.contains_key(f.as_str()))
        .collect();
    assert!(
        new.is_empty(),
        "a file holds a chain row and opens a file to append: {new:?}. A flat \
         chain's rows go through `nn_linux::flat_chain::FlatFile` (a failed write \
         poisons it; the next row reads the tail again, cuts the fragment and \
         signs the cut) — or list the file in KNOWN with why it appends no row"
    );
    let gone: Vec<&&str> = known
        .keys()
        .filter(|k| !found.iter().any(|f| f == *k))
        .collect();
    assert!(
        gone.is_empty(),
        "KNOWN lists files that no longer hold both markers: {gone:?} — remove them"
    );
}

/// The flat chains of the agent's host append through the writer: each
/// names it, and holds no append-open of its own.
#[test]
fn the_flat_chains_append_through_the_writer() {
    let root = repo_root();
    for f in [
        "crates/nn-linux/src/canary/access_log.rs",
        "crates/nn-linux/src/canary/registry.rs",
        "crates/nn-linux/src/fim/baseline.rs",
        "crates/nn-linux/src/net/drain.rs",
    ] {
        let code = std::fs::read_to_string(root.join(f)).unwrap();
        let code = production(&strip_comments(&code));
        assert!(
            code.contains("flat_chain::FlatFile") && code.contains(".heal("),
            "{f}: its rows are not appended through the flat chains' writer"
        );
        assert!(
            !APPEND.iter().any(|m| code.contains(m))
                && !code.contains(".write_all(")
                && !code.contains(".sync_all("),
            "{f}: appends or syncs a file of its own"
        );
    }
    let writer = std::fs::read_to_string(root.join("crates/nn-linux/src/flat_chain.rs")).unwrap();
    assert!(
        !production(&strip_comments(&writer)).contains(ROW),
        "the writer names no row: it is the chains' file side"
    );
}

/// The rule, shown failing on a planted violation (and passing what it
/// must pass).
#[test]
fn the_rule_finds_a_planted_flat_chain_append() {
    let planted = r#"
        pub fn append(&mut self, e: &Entry) -> Result<()> {
            let line = format!("{{\"entry_hash\":\"{}\"}}\n", e.entry_hash);
            let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
            f.write_all(line.as_bytes())?;
            Ok(())
        }
    "#;
    assert!(appends_rows(planted));
    // the open's flag spelled as a raw one
    assert!(appends_rows(
        "fn w(e: &E) { let _ = e.entry_hash; let f = libc::O_APPEND; }"
    ));
    // a row without an append-open, an append-open without a row
    assert!(!appends_rows("fn r(e: &E) -> &str { &e.entry_hash }"));
    assert!(!appends_rows(
        "fn w() { let f = OpenOptions::new().append(true).open(\"x\"); }"
    ));
    // in a comment or a test item: not production
    assert!(!appends_rows(
        "// entry_hash .append(true)\nfn x() {}\n#[cfg(test)]\nmod tests { fn t() { let _ = \"entry_hash\"; OpenOptions::new().append(true); } }"
    ));
}
