//! Lot 353 (the review of #563, F1): a mount over `/proc` cannot reach the
//! signed records.
//!
//! The signed logs were opened, at every append, through
//! `/proc/self/fd/<dirfd>/<name>` — the directory fd the anchor of review
//! entry 44 took, resolved through the `/proc` mounted at the time. A FUSE
//! over `/proc` held every signed append, the audit log's lock with it (the
//! High record of that very mount never written); a tmpfs over `/proc` made
//! every one fail with `ENOENT`, silently. The anchored names are now
//! resolved beneath the directory's descriptor (`openat2`, `renameat2`,
//! `unlinkat`: `nn_linux::anchored`), and a writer whose appends fail tells
//! its host (a degradation, the watchdog's `LoopProgress`).
//!
//! 1. No `/proc/self/fd/…` path is formed in the production code outside
//!    `kernel_roots` (which resolves it beneath the `/proc` root the start
//!    anchored) — except as the argument of a `kernel_roots` call.
//! 2. The anchor forms no `/proc` path; the agent's chain host and the flat
//!    chains' writer open their files through it.
//! 3. The chain writers ([`WRITERS`]: the audit log, the rotating chains)
//!    and the helpers they call make no file operation of their own: every
//!    one is their host's (`H::`, `K::Host::`), which the agent's host
//!    resolves beneath the anchored directory.
//! 4. Each writer tells its host when its appends fail and when they work
//!    again (`append_failed`).
//!
//! The scan is lexical (comments blanked, test items left out); each rule
//! is shown failing on a planted violation.

mod support;

use support::{matching_brace, production, repo_root, strip_comments};

fn code(rel: &str) -> String {
    production(&strip_comments(
        &std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    ))
}

/// The body of the item that starts at `head` (to its matching brace).
fn item<'a>(code: &'a str, rel: &str, head: &str) -> &'a str {
    let at = code
        .find(head)
        .unwrap_or_else(|| panic!("{rel}: `{head}` not found"));
    let rest = &code[at..];
    let brace = rest
        .find('{')
        .unwrap_or_else(|| panic!("{rel}: `{head}` has no body"));
    &rest[..brace + matching_brace(&rest[brace..])]
}

/// The file operations a writer may not make itself (its host's are
/// `H::open…`, `H::symlink_metadata`, `H::read_dir_names`, …); a call of
/// `std::fs` is any `fs::<function>(`.
const OWN_FILE_CALLS: &[&str] = &[
    "File::open(",
    "File::create(",
    "OpenOptions::new()",
    ".exists()",
    ".metadata()",
    ".read_dir()",
    "/proc/self/fd",
];

/// Whether `line` calls a function of `std::fs` (`fs::read_dir(`, not
/// the type `std::fs::File`).
fn calls_std_fs(line: &str) -> bool {
    line.match_indices("fs::").any(|(at, _)| {
        let rest = &line[at + 4..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '_')
            .collect();
        !name.is_empty() && rest[name.len()..].starts_with('(')
    })
}

/// What `body` does to a file itself, one line each.
fn own_file_calls(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| {
            calls_std_fs(l)
                || OWN_FILE_CALLS.iter().any(|c| {
                l.contains(c)
                    // an open file's own size (`f.metadata()`) asks no path
                    && !(*c == ".metadata()" && (l.contains("f.metadata()") || l.contains("file.metadata()")))
            })
        })
        .map(|l| l.trim().to_string())
        .collect()
}

/// The chain writers and the helpers of theirs that touch files.
const WRITERS: &[(&str, &[&str])] = &[
    (
        "crates/nn-evidence/src/audit.rs",
        &[
            "pub fn append(&mut self, draft: AuditEntryDraft)",
            "fn append_inner(",
            "fn write_line(",
            "fn recover_after_failed_append(",
            "pub fn scan_rows(",
        ],
    ),
    (
        "crates/nn-evidence/src/chainlog.rs",
        &[
            "fn append_line<H: ChainHost>(",
            "pub fn sync(&mut self)",
            "fn ensure_manifest(",
            "fn append_with(",
            "fn append_with_inner(",
            "fn write_active(",
            "fn reread_active(",
            "fn rotate(&mut self)",
            "fn finish_rotation(",
            "fn complete_interrupted_rotation(",
            "fn unattested_foreign_slots(",
            "fn taken_slots(",
            "fn is_own_archive(",
            "fn prior_link_or_genesis(",
            "fn reread_manifest(",
            "fn replace_torn_manifest_tail(",
            "pub fn open_with_clock(",
            "fn list_archive_seqs_in<H: ChainHost>(",
            "pub fn holds_line_ending_at_in<H: ChainHost>(",
            "pub fn holds_last_line_in<H: ChainHost>(",
            "pub fn sync_detached_in<H: ChainHost>(",
            "fn slot_kind<H: ChainHost>(",
            "fn create_fresh_active<H: ChainHost>(",
            "fn evict_excess_archives<H: ChainHost>(",
            "pub fn repair_torn_tail<H: ChainHost>(",
            "fn recover_tail<H: ChainHost>(",
            "fn truncate_file<H: ChainHost>(",
            "fn read_terminator_hash<H: ChainHost>(",
        ],
    ),
];

#[test]
fn the_chain_writers_touch_their_files_only_through_their_host() {
    let mut found = Vec::new();
    for (rel, items) in WRITERS {
        let text = code(rel);
        for head in *items {
            for call in own_file_calls(item(&text, rel, head)) {
                found.push(format!("{rel}: `{head}`: {call}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a chain writer opens, lists, stats or removes a file itself — through the live path \
         (a mount over /proc held it, one over the directory diverts it): use its host's \
         operation (H::open, H::symlink_metadata, H::read_dir_names, H::remove_file, …):\n{}",
        found.join("\n")
    );
}

/// The response journal's own reads and fsync of the actions chain (its
/// writer's companion): through the agent's host, never the by-path
/// readers'.
#[test]
fn the_journal_reads_its_chain_through_the_host() {
    let text = code("crates/nn-linux/src/response/journal.rs");
    for by_path in [
        "chainlog::holds_last_line(",
        "chainlog::holds_line_ending_at(",
        "chainlog::sync_detached(",
    ] {
        assert!(
            !text.contains(by_path),
            "journal.rs: `{by_path}` reads the chain by its path, not beneath its anchored \
             directory (the `_in::<LinuxHost>` form)"
        );
    }
    let flat: String = text.split_whitespace().collect();
    for host in [
        "holds_last_line_in::<crate::chain_host_linux::LinuxHost>(",
        "holds_line_ending_at_in::<crate::chain_host_linux::LinuxHost,>(",
        "sync_detached_in::<crate::chain_host_linux::LinuxHost>(",
    ] {
        assert!(flat.contains(host), "journal.rs: `{host}` expected");
    }
}

/// The writers that tell their host when their appends fail.
const TELLERS: &[(&str, &str)] = &[
    (
        "crates/nn-evidence/src/audit.rs",
        "pub fn append(&mut self, draft: AuditEntryDraft)",
    ),
    ("crates/nn-evidence/src/chainlog.rs", "fn append_with("),
    (
        "crates/nn-linux/src/flat_chain.rs",
        "pub fn append(&mut self, line: &[u8], sync: bool)",
    ),
];

#[test]
fn every_signed_writer_tells_its_failing_appends() {
    // the agent's start turns the degradations on (the tests' processes
    // leave them off)
    assert!(
        code("agent/src/boot/mod.rs").contains("nn_linux::chain_host_linux::tell_degradations();"),
        "the agent's start does not turn the signing degradations on"
    );
    for (rel, head) in TELLERS {
        let text = code(rel);
        let b = item(&text, rel, head);
        assert!(
            b.matches("append_failed(").count() >= 2,
            "{rel}: `{head}` does not tell its host both a failure and its end:\n{b}"
        );
    }
}

/// The files of the anchor and of the agent's chain host.
const ANCHORED: &[&str] = &[
    "crates/nn-linux/src/anchored.rs",
    "crates/nn-linux/src/chain_host_linux.rs",
    "crates/nn-linux/src/flat_chain.rs",
    "crates/nn-linux/src/combat/reconcile.rs",
];

#[test]
fn the_anchor_resolves_beneath_the_directory_never_through_proc() {
    let anchored = code("crates/nn-linux/src/anchored.rs");
    assert!(
        anchored.contains("libc::SYS_openat2") && anchored.contains("RESOLVE_NO_XDEV"),
        "the anchor opens beneath the directory with openat2, crossing no mount"
    );
    assert!(anchored.contains("libc::SYS_renameat2") && anchored.contains("libc::unlinkat("));
    for rel in ANCHORED {
        let text = code(rel);
        assert!(
            !text.contains("\"/proc/self/fd") && !text.contains("PROC_FD"),
            "{rel}: a /proc/self/fd path"
        );
        // the anchor's own open of a directory, by path, at the first call
        if *rel != "crates/nn-linux/src/anchored.rs" {
            assert!(
                !text.contains("OpenOptions::new()"),
                "{rel}: an open of its own (through crate::anchored::open)"
            );
        }
    }
    // the agent's host: each file operation of the trait through the anchor
    let host = code("crates/nn-linux/src/chain_host_linux.rs");
    let imp = item(&host, "chain_host_linux.rs", "impl ChainHost for LinuxHost");
    for op in [
        "fn open_read_nofollow(",
        "fn open_with_mode(",
        "fn open_with_mode_nofollow(",
        "fn open(",
        "fn symlink_metadata(",
        "fn exists(",
        "fn read_dir_names(",
        "fn remove_file(",
        "fn rename_noreplace(",
    ] {
        let b = item(imp, "LinuxHost", op);
        assert!(
            b.contains("crate::anchored::"),
            "LinuxHost::{op} is not resolved through the anchor:\n{b}"
        );
    }
}

/// Rule 1's violations in `text`: a `/proc/self/fd` path formed outside a
/// `kernel_roots` call.
fn proc_fd_paths(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        // a path formed in code (a string about one, `\"/proc/self/fd…\"`
        // in a description, is no walk)
        if !l.contains("\"/proc/self/fd") || l.contains("\\\"/proc/self/fd") {
            continue;
        }
        let statement = lines[i.saturating_sub(1)..=(i + 1).min(lines.len() - 1)].join(" ");
        if !statement.contains("kernel_roots::") {
            out.push(format!("{}: {}", i + 1, l.trim()));
        }
    }
    out
}

/// The files whose `/proc/self/fd` paths stay, and why.
const KNOWN: &[(&str, &str)] = &[(
    "crates/nn-linux/src/worker/mod.rs",
    "the workers' exec of the agent's image by its descriptor (`execve` of \
     /proc/self/fd/<n>), on the worker supervisor's own thread — never a signed record's, never \
     the runtime's; `execveat` would change the file name the exec sensor reports for the \
     agent's own worker launch (R004)",
)];

/// The production code's crates.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "crates/nn-evidence/src",
    "crates/nn-export/src",
    "crates/nn-admin/src",
    "agent/src",
    "watchdog/src",
    "antitamper-bpf/src",
];

#[test]
fn no_proc_self_fd_path_is_walked_through_the_live_proc() {
    let root = repo_root();
    let mut found = Vec::new();
    let mut scanned = 0;
    for dir in SCAN {
        let mut files = Vec::new();
        support::rs_files(&root.join(dir), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if support::is_test_file(&rel)
                || rel == "antitamper-bpf/src/kernel_roots.rs"
                || KNOWN.iter().any(|(k, _)| *k == rel)
            {
                continue;
            }
            scanned += 1;
            for v in proc_fd_paths(&code(&rel)) {
                found.push(format!("{rel}:{v}"));
            }
        }
    }
    assert!(scanned > 300, "scanned {scanned} files");
    assert!(
        found.is_empty(),
        "a /proc/self/fd path walked through the /proc mounted now (a FUSE over it holds the \
         call, a tmpfs makes it fail): resolve the descriptor beneath the anchored root \
         (kernel_roots::reopen_fd, chmod_fd, read_link) or use the descriptor itself:\n{}",
        found.join("\n")
    );
}

/// Each rule fails on a planted violation.
#[test]
fn a_planted_violation_of_each_rule_is_found() {
    assert_eq!(
        own_file_calls(
            "fn write_line(&self) {\n    let f = OpenOptions::new().append(true).open(&self.io_path);\n}"
        )
        .len(),
        1
    );
    assert_eq!(
        own_file_calls("fn list() {\n    let rd = fs::read_dir(dir)?;\n}").len(),
        1
    );
    assert_eq!(
        own_file_calls("fn m() {\n    if self.manifest_path.exists() {}\n}").len(),
        1
    );
    assert!(own_file_calls(
        "fn ok() -> Result<std::fs::File> {\n    let f = H::open(Open::new().read(true), p)?;\n    let n = f.metadata()?.len();\n}"
    )
    .is_empty());
    assert_eq!(
        proc_fd_paths("let via = format!(\"/proc/self/fd/{}\", f.as_raw_fd());").len(),
        1
    );
    assert!(
        proc_fd_paths("kernel_roots::read_link(format!(\"/proc/self/fd/{}\", f.as_raw_fd()))")
            .is_empty()
    );
}
