//! Lot 310 (external bug hunt, edition 1.4: BUG-88): a path through a link
//! of `/proc` — `/proc/<pid>[/task/<tid>]/{fd,map_files}/…`, `exe`, `cwd`,
//! `root`, `/dev/fd/<n>`, `/dev/std{in,out,err}` — is matched in one place,
//! `crates/nn-core/src/posture/proc_link.rs`, and this ratchet keeps it so.
//!
//! R004 matched `/proc/self/fd/N`, `/proc/<pid>/fd/N` and `/dev/fd/N` by
//! hand beside lot 286's fuller reader of the posture, and
//! `/proc/thread-self/fd/N`, `/proc/self/task/<tid>/fd/N` and `/dev/stdin`
//! ran an unlinked file without its kill. A new site that matches such a
//! path by hand fails here until it calls the reader (`through_proc_link`,
//! `proc_link`, `reopens_a_descriptor`) or is listed in [`KNOWN`] with why it
//! matches nothing a caller wrote.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out) over the production code of the crates that judge events. What it
//! counts ([`MARKERS`]): a prefix test of a `/proc` or `/dev/fd` path, the
//! names only a `/proc` link holds (`thread-self`, `map_files`), the `/dev`
//! links to descriptors, and a slice pattern on a path's `proc` segment.
//! Building a path to the agent's own descriptor (`format!("/proc/self/fd/
//! {fd}")`) matches nothing and is not counted.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The one reader.
const READER: &str = "crates/nn-core/src/posture/proc_link.rs";

/// The production trees scanned.
const TREES: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "common/src",
    "watchdog/src",
];

/// What a `/proc` link matched by hand looks like.
const MARKERS: &[&str] = &[
    "strip_prefix(\"/proc",
    "starts_with(\"/proc",
    "strip_prefix(\"/dev/fd",
    "starts_with(\"/dev/fd",
    "strip_prefix(\"self/",
    "starts_with(\"self/",
    "\"thread-self",
    "\"map_files",
    "\"/dev/stdin\"",
    "\"/dev/stdout\"",
    "\"/dev/stderr\"",
    "[\"proc\",",
];

/// The files that hold markers: how many, and why none matches a path a
/// caller wrote.
const KNOWN: &[(&str, usize, &str)] = &[(
    "crates/nn-linux/src/response/quarantine.rs",
    1,
    "the restore's destination as the kernel resolved it: the agent's own descriptor of the \
     directory it opened through PID 1's root (`/proc/1/root/…`, `on_host_path`), read back \
     and mapped to the host's path — the kernel's answer, no path a caller wrote",
)];

fn count(text: &str) -> usize {
    MARKERS.iter().map(|m| text.matches(m).count()).sum()
}

fn which(text: &str) -> Vec<(&'static str, usize)> {
    MARKERS
        .iter()
        .map(|m| (*m, text.matches(m).count()))
        .filter(|(_, n)| *n > 0)
        .collect()
}

/// The production code of [`TREES`], comments and tests blanked, by file.
fn tree_code(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for t in TREES {
        let mut files = Vec::new();
        rs_files(&root.join(t), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) || rel.contains("/tests/") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            out.insert(rel, production(&strip_comments(&text)));
        }
    }
    out
}

fn violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut out = Vec::new();
    for (file, text) in code {
        if file == READER {
            continue;
        }
        let n = count(text);
        match known.get(file.as_str()) {
            None if n > 0 => out.push(format!(
                "{file}: {:?} — a `/proc` link matched by hand: read it with \
                 `posture::proc_link` (`through_proc_link`, `proc_link`, \
                 `reopens_a_descriptor`), or list the file in KNOWN with why it matches \
                 nothing a caller wrote",
                which(text)
            )),
            Some(&pin) if n > pin => out.push(format!(
                "{file}: {n} sites, {pin} known — {:?}: a new one",
                which(text)
            )),
            Some(&pin) if n < pin => out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            )),
            _ => {}
        }
    }
    for (file, _, _) in KNOWN {
        if !code.contains_key(*file) {
            out.push(format!("{file}: listed in KNOWN, not in the scan"));
        }
    }
    out
}

/// No `/proc` link is matched outside the reader.
#[test]
fn proc_links_are_matched_by_the_one_reader() {
    let code = tree_code(&repo_root());
    assert!(code.contains_key(READER), "the reader is scanned");
    // the reader holds what it is the only one to hold
    assert!(count(&code[READER]) > 0, "the reader's markers");
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// The ratchet fails on planted violations: R004's twin as it was (BUG-88)
/// and a per-thread name matched by hand; the agent's own descriptor's path
/// built (no match) and the reader itself are not counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
    let mut code = tree_code(&repo_root());
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "r004_twin"),
        "fn is_proc_fd_path(p: &str) -> bool { p.strip_prefix(\"/proc/\").is_some() || \
         p.starts_with(\"/dev/fd/\") }"
            .to_string(),
    );
    code.insert(
        format!("crates/nn-core/src/posture/{}.rs", "thread"),
        "fn t(p: &str) -> bool { p.contains(\"thread-self\") }".to_string(),
    );
    code.insert(
        format!("crates/nn-linux/src/{}.rs", "own_fd"),
        "fn o(fd: i32) -> String { format!(\"/proc/self/fd/{fd}\") }".to_string(),
    );
    code.get_mut(READER)
        .unwrap()
        .push_str("\nfn h(p: &str) -> bool { p.starts_with(\"/proc/\") }\n");
    let v = violations(&code);
    assert_eq!(v.len(), 2, "{v:#?}");
    assert!(v.iter().any(|x| x.contains("r004_twin.rs")));
    assert!(v.iter().any(|x| x.contains("thread.rs")));
}
