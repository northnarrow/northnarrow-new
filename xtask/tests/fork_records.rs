//! Lot 360 (pre-alpha Phase 4b, F4b-1): a kernel record that carries the
//! fork record of a process that executed nothing since its fork is taught
//! to the lineage by the pump that decodes it, before its events are sent.
//!
//! The record (`fork_start`, the process's own start, beside `fork_ppid`, its
//! forker) is the only identity such a process has: no exec record names it.
//! The connect's (`TcpConnectRaw`, lot 352) reached the chains' ancestry but
//! never the lineage, so a fork-only process was named from `/proc` — at the
//! connect, and in the judgement only while `/proc` still showed it. An
//! AppImage's zygote child that connected and exited at once drew
//! NN-L-NET-008 High as a staged image's, and a staged dropper's fork gone
//! before the pump read it was not named at all. Each wire struct with such
//! a record is listed here with the function of its pump that teaches it
//! (`ingest_kernel_fork` in its body, called in that file's production
//! code): a new one fails until it is taught and listed. The order — the
//! record taught before its events are sent — is pinned by the pumps' own
//! tests, not here.
//!
//! The review of #568 (F1): the teaching hands over the forker's start the
//! kernel read (`fork_parent_start`), so a forker's pid an earlier process
//! held lends that process's cached exec to no fork.

mod support;

use support::{matching_brace, product_code, repo_root};

/// Each wire struct carrying a fork record, its pump's file, and the
/// function there that teaches the record to the lineage.
const TAUGHT: &[(&str, &str, &str)] = &[
    // lot 340: a writer that never executed (a backup's receiver)
    (
        "OpenRecordRaw",
        "crates/nn-linux/src/sensors/open_sensor.rs",
        "teach_fork",
    ),
    // lot 344: a drift's writer
    (
        "FimDriftRaw",
        "crates/nn-linux/src/fim/drain.rs",
        "teach_fork",
    ),
    // lot 360: a connect's process (the AppImage zygote's child)
    (
        "TcpConnectRaw",
        "crates/nn-linux/src/sensors/multiplexer.rs",
        "teach_connect_fork",
    ),
];

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Byte offsets of `ident` in `code` as a whole identifier.
fn ident_uses(code: &str, ident: &str) -> Vec<usize> {
    code.match_indices(ident)
        .filter(|&(at, _)| {
            let before = code[..at].chars().next_back();
            let after = code[at + ident.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .map(|(at, _)| at)
        .collect()
}

/// The structs `code` defines with a `fork_start` field (the record of a
/// process that executed nothing since its fork).
fn structs_with_fork_records(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for at in ident_uses(code, "struct") {
        let rest = code[at + "struct".len()..].trim_start();
        let end = rest.find(|c: char| !is_ident(c)).unwrap_or(rest.len());
        let name = &rest[..end];
        let after = &rest[end..];
        // a struct with named fields: its body is the first `{` before a `;`
        let Some(open) = after.find('{') else {
            continue;
        };
        if after[..open].contains(';') {
            continue;
        }
        let body = &after[open..open + matching_brace(&after[open..])];
        if !ident_uses(body, "fork_start").is_empty() {
            out.push(name.to_string());
        }
    }
    out
}

/// `code` defines `fn name`, whose body names `ingest_kernel_fork` and the
/// forker's start (`fork_parent_start`), and calls `name(` outside that
/// definition.
fn teaches(code: &str, name: &str) -> bool {
    let mut defined = None;
    for at in ident_uses(code, name) {
        let before = code[..at].trim_end();
        if before.ends_with("fn") && !before[..before.len() - 2].ends_with(is_ident) {
            let open = at + code[at..].find('{').unwrap_or(code.len() - at);
            if open >= code.len() {
                return false;
            }
            defined = Some((at, open + matching_brace(&code[open..])));
        }
    }
    let Some((start, end)) = defined else {
        return false;
    };
    let body = &code[start..end];
    let ingests = !ident_uses(body, "ingest_kernel_fork").is_empty()
        && !ident_uses(body, "fork_parent_start").is_empty();
    let called = ident_uses(code, name)
        .into_iter()
        .filter(|&at| at < start || at >= end)
        .any(|at| code[at + name.len()..].trim_start().starts_with('('));
    ingests && called
}

/// The wire structs with a fork record, by name, from the production code
/// of `common/src/wire`.
fn wire_fork_records(code: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = code
        .iter()
        .filter(|(rel, _)| rel.starts_with("common/src/wire/"))
        .flat_map(|(_, c)| structs_with_fork_records(c))
        .collect();
    out.sort();
    out
}

#[test]
fn every_kernel_fork_record_is_taught_to_the_lineage() {
    let code = product_code(&repo_root());
    let found = wire_fork_records(&code);
    let mut listed: Vec<String> = TAUGHT.iter().map(|(s, _, _)| s.to_string()).collect();
    listed.sort();
    assert_eq!(
        found, listed,
        "a wire struct with a fork record (`fork_start`) is taught to the lineage \
         by its pump (`ingest_kernel_fork`) and listed in TAUGHT"
    );
    for (record, file, f) in TAUGHT {
        let src = code
            .get(*file)
            .unwrap_or_else(|| panic!("{record}: {file} not found"));
        assert!(
            teaches(src, f),
            "{record}: `{f}` in {file} must call `ingest_kernel_fork` with the forker's \
             start (`fork_parent_start`) and be called in that file (the pump's tests pin \
             that it runs before the record's events are sent)"
        );
    }
}

/// The checks fail on each planted shape: a new record not listed, a
/// teaching function that does not ingest, one that is never called, one
/// that is not there.
#[test]
fn a_fork_record_not_taught_fails_the_ratchet() {
    let wire = "pub struct XRaw {\n    pub pid: u32,\n    pub fork_start: u64,\n    pub fork_ppid: u32,\n}\n\
                pub struct YRaw {\n    pub fork_ppid: u32,\n}\npub struct Unit;\n";
    assert_eq!(structs_with_fork_records(wire), vec!["XRaw".to_string()]);
    let good = "fn teach(r: &XRaw, l: &L) {\n    l.ingest_kernel_fork(r.pid, 1, (2, r.fork_parent_start), 3, 4);\n}\n\
                fn pump(r: &XRaw, l: &L) {\n    teach(r, l);\n    send(r);\n}\n";
    assert!(teaches(good, "teach"));
    let no_ingest = "fn teach(r: &XRaw, l: &L) {\n    l.ingest_exec(r.pid);\n}\n\
                     fn pump(r: &XRaw, l: &L) {\n    teach(r, l);\n}\n";
    assert!(!teaches(no_ingest, "teach"));
    let never_called =
        "fn teach(r: &XRaw, l: &L) {\n    l.ingest_kernel_fork(r.pid, 1, (2, r.fork_parent_start), 3, 4);\n}\n\
                        fn pump(r: &XRaw) {\n    send(r);\n}\n";
    assert!(!teaches(never_called, "teach"));
    let no_start =
        "fn teach(r: &XRaw, l: &L) {\n    l.ingest_kernel_fork(r.pid, 1, (2, 0), 3, 4);\n}\n\
                    fn pump(r: &XRaw, l: &L) {\n    teach(r, l);\n}\n";
    assert!(!teaches(no_start, "teach"));
    let named_only = "fn pump(r: &XRaw, l: &L) {\n    let teach = 1;\n    l.ingest_kernel_fork(r.pid, 1, (2, r.fork_parent_start), 3, 4);\n}\n";
    assert!(!teaches(named_only, "teach"));
}
