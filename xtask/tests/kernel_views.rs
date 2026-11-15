//! Lot 353 (pre-alpha Phase 3, case X6): the kernel's views — `/proc`,
//! `/sys` and the cgroup2 hierarchy — are read beneath the roots the
//! agent's start anchored (`antitamper_bpf::kernel_roots`), never by a path
//! walk that a mount laid over them can hold; and the rounds that read
//! them run off the runtime's workers. A FUSE mounted over `/sys/fs/cgroup`
//! that never answered held two of the agent's threads in the kernel —
//! the integrity round's read of its own `memory.max`, the kernel-state
//! round's open of the cgroup root — and every thread that looked up the
//! same names behind them: the admin socket stopped answering, the
//! watchdog's stuck recovery restarted an agent that had recorded nothing.
//!
//! 1. **None**, by name: the production code of the security crates
//!    ([`SCAN`]) calls no path API of the standard library or libc
//!    ([`PATH_CALLS`]) on a path literal under `/proc` or `/sys`, or on a
//!    constant whose value is one, in the statement (the line, the two
//!    before it and the two after it) — `kernel_roots` does (and the readers built on it:
//!    `state_read::read_state`, `mountinfo::read_bytes`).
//! 2. The shared readers go through it ([`ROUTED`]).
//! 3. The integrity round and the kernel-state round run off the runtime's
//!    worker (`off_the_runtime`), and the agent and the watchdog anchor the
//!    views at their start.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The security crates' sources.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "watchdog/src",
    "crates/nn-admin/src",
    "antitamper-bpf/src",
];

/// The module that reads the views (its own calls are the reads).
const KERNEL_ROOTS: &str = "antitamper-bpf/src/kernel_roots.rs";

/// The path calls a walk of the mount table makes, as written.
const PATH_CALLS: &[&str] = &[
    "fs::read(",
    "fs::read_to_string(",
    "fs::read_dir(",
    "fs::metadata(",
    "fs::symlink_metadata(",
    "fs::read_link(",
    "fs::canonicalize(",
    "fs::write(",
    "fs::create_dir(",
    "fs::create_dir_all(",
    "fs::remove_dir(",
    "File::open(",
    "OpenOptions::new()",
    ".exists()",
    ".is_dir()",
    ".is_file()",
    "libc::statfs(",
    "libc::stat(",
    "libc::lstat(",
    "libc::open(",
    "libc::access(",
];

/// A literal path under `/proc` or `/sys` (`"/proc/…"`, `"/sys"`).
fn names_a_view(text: &str) -> bool {
    ["\"/proc/", "\"/proc\"", "\"/sys/", "\"/sys\""]
        .iter()
        .any(|p| text.contains(p))
}

/// The constants of `code` whose value is a path under `/proc` or `/sys`.
fn view_constants(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for text in code.values() {
        for line in text.lines() {
            let t = line.trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
            let Some(rest) = t.strip_prefix("const ") else {
                continue;
            };
            let Some((name, value)) = rest.split_once(':') else {
                continue;
            };
            if value.contains("&str") && names_a_view(value) {
                out.push(name.trim().to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `word` occurs in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

/// Rule 1's violations in one file's production code: `line: text`.
fn walks(text: &str, constants: &[String]) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !PATH_CALLS.iter().any(|c| line.contains(c)) {
            continue;
        }
        // the statement: two lines before, and the lines after while it
        // goes on (a call whose argument starts on the next line)
        let mut end = i;
        while end < (i + 2).min(lines.len() - 1)
            && !lines[end].trim_end().ends_with([';', '{', '}'])
        {
            end += 1;
        }
        let statement = lines[i.saturating_sub(2)..=end].join(" ");
        if names_a_view(&statement) || constants.iter().any(|c| has_word(&statement, c)) {
            out.push(format!("{}: {}", i + 1, line.trim()));
        }
    }
    out
}

/// The production code of every file of [`SCAN`], by path.
fn scan_code(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for dir in SCAN {
        let mut files = Vec::new();
        rs_files(&root.join(dir), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            out.insert(rel, production(&strip_comments(&text)));
        }
    }
    out
}

/// The constants that name bpffs (`/sys/fs/bpf`: its pins are opened by
/// path through the bpf(2) object calls, a file system of its own the
/// integrity round watches — `PROTECTED_MOUNT_PREFIXES`, `MOUNT_WATCHED`)
/// and the kernel's BTF directory's watch: not views read here.
const NOT_VIEWS: &[&str] = &[
    "BPFFS_MOUNT",
    "BPFFS_ROOT",
    "DEFAULT_BPFFS_ROOT",
    "PIN_DIR",
    "PIN_ROOT",
    "UNIT",
];

/// The files whose walks by path stay, how many, and why: each takes the
/// anchored root when its process has one and walks only where none was
/// anchored (a test binary).
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-linux/src/sandbox/mod.rs",
        1,
        "a forked child's allocation-free count of its own threads: beneath the /proc root the \
         process anchored (`kernel_roots::proc_root_fd`, openat), by path only in a process \
         that anchored none",
    ),
    (
        "crates/nn-linux/src/worker/spawn.rs",
        1,
        "a forked worker's allocation-free write of its own oom_score_adj: beneath the /proc \
         root the core anchored, by path only in a process that anchored none",
    ),
];

#[test]
fn no_kernel_view_is_walked_by_path() {
    let code = scan_code(&repo_root());
    assert!(code.len() > 300, "scanned {} files", code.len());
    let constants: Vec<String> = view_constants(&code)
        .into_iter()
        .filter(|c| !NOT_VIEWS.contains(&c.as_str()))
        .collect();
    assert!(
        constants.iter().any(|c| c == "MOUNTINFO_HOST"),
        "the scan finds the view constants: {constants:?}"
    );
    let mut found = Vec::new();
    for (f, text) in code.iter().filter(|(f, _)| f.as_str() != KERNEL_ROOTS) {
        let w = walks(text, &constants);
        match KNOWN.iter().find(|(k, _, _)| k == f) {
            Some((_, n, _)) if w.len() == *n => {}
            Some((_, n, _)) => found.push(format!(
                "{f}: {} walks, {n} known (lower the pin when one goes): {w:?}",
                w.len()
            )),
            None => found.extend(w.into_iter().map(|l| format!("{f}:{l}"))),
        }
    }
    for (k, _, _) in KNOWN {
        assert!(
            code.contains_key(*k),
            "{k}: listed in KNOWN, not in the scan"
        );
    }
    assert!(
        found.is_empty(),
        "a path under /proc or /sys walked by path — a mount laid over the view holds it: read \
         it with antitamper_bpf::kernel_roots (read, read_to_string, read_dir, metadata, \
         read_link, open, write, create_dir…) or state_read::read_state:\n{}",
        found.join("\n")
    );
}

/// Rule 1 fails on a planted walk: a literal, a `format!`, a constant.
#[test]
fn a_planted_walk_of_a_view_is_found() {
    let constants = vec!["TAINTED".to_string()];
    for (planted, why) in [
        (
            "let x = std::fs::read_to_string(\"/proc/meminfo\");",
            "a literal",
        ),
        (
            "let x = std::fs::read(\n    format!(\"/proc/{pid}/stat\"),\n);",
            "a format! on the next line",
        ),
        (
            "let ok = Path::new(\"/sys/kernel/btf/vmlinux\").exists();",
            "exists",
        ),
        ("let t = fs::read_to_string(TAINTED);", "a constant"),
        (
            "let f = File::open(format!(\"/sys/fs/cgroup{cg}/memory.max\"));",
            "the cgroup tree",
        ),
    ] {
        assert!(!walks(planted, &constants).is_empty(), "{why}: {planted}");
    }
    for clean in [
        "let x = antitamper_bpf::kernel_roots::read_to_string(\"/proc/meminfo\");",
        "let x = std::fs::read_to_string(\"/etc/os-release\");",
        "let t = fs::read_to_string(TAINTED_NOT);",
    ] {
        assert!(walks(clean, &constants).is_empty(), "{clean}");
    }
    let code = BTreeMap::from([(
        "x.rs".to_string(),
        "pub const TAINTED: &str = \"/proc/sys/kernel/tainted\";\nconst N: u32 = 1;".to_string(),
    )]);
    assert_eq!(view_constants(&code), vec!["TAINTED".to_string()]);
}

/// The shared readers and the function each one's body must read through.
const ROUTED: &[(&str, &str, &str)] = &[
    (
        "crates/nn-linux/src/state_read.rs",
        "pub fn read_bounded(",
        "kernel_roots::read(",
    ),
    (
        "crates/nn-linux/src/state_read.rs",
        "pub fn read_file_bounded(",
        "kernel_roots::read_file_bounded(",
    ),
    (
        "crates/nn-linux/src/mountinfo.rs",
        "pub fn read_bytes(",
        "kernel_roots::read(",
    ),
    (
        "crates/nn-linux/src/own_cpus.rs",
        "pub fn open_source(",
        "kernel_roots::open(",
    ),
    (
        "crates/nn-linux/src/sysctl_cgroup.rs",
        "fn open_root_cgroup(",
        "kernel_roots::cgroup_root(",
    ),
    (
        "antitamper-bpf/src/config_read.rs",
        "pub fn read_config(",
        "kernel_roots::open(",
    ),
    (
        "antitamper-bpf/src/cgroup_guard.rs",
        "fn is_cgroup2(",
        "kernel_roots::open(",
    ),
];

/// The body of the function that starts at `head` in `code` (to its first
/// line that closes at column 0).
fn body<'a>(code: &'a str, rel: &str, head: &str) -> &'a str {
    let at = code
        .find(head)
        .unwrap_or_else(|| panic!("{rel}: `{head}` not found"));
    let rest = &code[at..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 3);
    &rest[..end]
}

#[test]
fn the_shared_readers_read_beneath_the_anchored_roots() {
    let root = repo_root();
    for (rel, head, call) in ROUTED {
        let text = production(&strip_comments(
            &std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
        ));
        let b = body(&text, rel, head);
        assert!(
            b.contains(call),
            "{rel}: `{head}` does not read through `{call}`:\n{b}"
        );
    }
}

/// The rounds that read the views, each run off the runtime's worker, and
/// the starts that anchor them.
const OFF_THE_RUNTIME: &[(&str, &str, &[&str])] = &[
    (
        "crates/nn-linux/src/self_integrity.rs",
        "tokio::time::sleep(Duration::from_secs(15)).await;",
        &[
            "off_the_runtime(|| checker.round(true))",
            "off_the_runtime(|| checker.round(false))",
        ],
    ),
    (
        "crates/nn-linux/src/kernel_state.rs",
        "pub fn spawn(",
        &[
            "off_the_runtime(||",
            "round(&mut w, Path::new(\"/\"), &known)",
        ],
    ),
    (
        "agent/src/boot/mod.rs",
        "forbid_core_dumps();",
        &["kernel_roots::init()"],
    ),
    (
        "watchdog/src/main.rs",
        "\"watchdog starting\"",
        &["kernel_roots::init()"],
    ),
];

#[test]
fn the_rounds_run_off_the_runtime_and_the_starts_anchor_the_views() {
    let root = repo_root();
    for (rel, head, calls) in OFF_THE_RUNTIME {
        let text = strip_comments(
            &std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
        );
        let at = text
            .find(head)
            .unwrap_or_else(|| panic!("{rel}: `{head}` not found"));
        let window: String = text[at..].lines().take(60).collect::<Vec<_>>().join("\n");
        for call in *calls {
            assert!(
                window.contains(call),
                "{rel}: `{call}` not within 60 lines of `{head}`"
            );
        }
    }
    // the kernel-state round's reads are inside the closure, not before it
    let ks = strip_comments(
        &std::fs::read_to_string(root.join("crates/nn-linux/src/kernel_state.rs")).unwrap(),
    );
    let spawn = &ks[ks.find("pub fn spawn(").unwrap()..];
    let off = spawn.find("off_the_runtime(||").unwrap();
    let round = spawn.find("round(&mut w, Path::new(\"/\")").unwrap();
    assert!(
        off < round,
        "the kernel-state round runs inside off_the_runtime"
    );
}

/// Lot 353 (the lab's round on 6.12): `std::thread::available_parallelism`
/// reads the cgroup's `cpu.max` by path (`/sys/fs/cgroup/<cgroup>/…`) — a
/// FUSE mounted over `/sys/fs/cgroup` held the thread that asked. The
/// production code counts CPUs with `kernel_roots::available_parallelism`
/// (or the affinity); the one call left is the non-Linux branch of the
/// audit log's parallel check.
#[test]
fn no_cpu_count_walks_the_cgroup_tree() {
    let code = scan_code(&repo_root());
    let mut found: BTreeMap<&str, usize> = BTreeMap::new();
    for (f, text) in &code {
        let n = text.matches("std::thread::available_parallelism").count()
            + text
                .matches("thread::available_parallelism()")
                .count()
                .saturating_sub(text.matches("std::thread::available_parallelism()").count());
        if n > 0 {
            found.insert(f.as_str(), n);
        }
    }
    assert_eq!(
        found,
        BTreeMap::from([("agent/src/config/overlay_floor.rs", 1)]),
        "std's CPU count walks /sys/fs/cgroup by path: use \
         antitamper_bpf::kernel_roots::available_parallelism"
    );
    let ov = strip_comments(
        &std::fs::read_to_string(repo_root().join("agent/src/config/overlay_floor.rs")).unwrap(),
    );
    let at = ov.find("std::thread::available_parallelism").unwrap();
    assert!(
        ov[..at]
            .rfind("#[cfg(not(target_os = \"linux\"))]")
            .is_some_and(|c| at - c < 200 && ov[c..at].matches('{').count() == 1),
        "the one call is the non-Linux branch"
    );
}
