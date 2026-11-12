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
//! `proc_link`, `reopens_a_descriptor`) or its file is listed in [`KNOWN`]
//! with why it matches nothing a caller wrote.
//!
//! Lot 310, the independent review of #539 (finding 9): the first ratchet
//! missed `contains("/proc/thread-self/fd/")`, a `const` holding the prefix
//! and a slice pattern `["", "proc", _, "fd", _]`. It scans every product
//! crate now ([`support::product_code`]) and counts ([`count`]):
//!
//! - every string literal naming a `/proc` or `/dev` link (`/fd`,
//!   `thread-self`, `map_files`, `/task/`, `/exe`, `/cwd`, `/root`,
//!   `/dev/std…`) without a `{` (a path the agent builds with `format!` to
//!   read its own process is no match) and without a space (prose, a
//!   message);
//! - every `"proc"` segment literal (a slice pattern on a path's segments);
//! - a prefix or substring test of `"/proc` or `"/dev/fd`.

mod support;

use std::collections::BTreeMap;

use support::{concat_literals, product_code, repo_root, string_literals};

/// The one reader.
const READER: &str = "crates/nn-core/src/posture/proc_link.rs";

/// The names only a `/proc` or `/dev` link holds.
const LINK_NAMES: &[&str] = &[
    "/fd",
    "thread-self",
    "map_files",
    "/task/",
    "/exe",
    "/cwd",
    "/root",
    "/dev/std",
];

/// A literal naming a link of `/proc` or `/dev`, or a path segment `proc`.
fn is_link_literal(s: &str) -> bool {
    if s == "proc" {
        return true;
    }
    !s.contains('{')
        && !s.contains(char::is_whitespace)
        && (s.starts_with("/proc") || s.starts_with("/dev") || s.contains("thread-self"))
        && LINK_NAMES.iter().any(|n| s.contains(n))
}

/// The tests of a path's text against `/proc` or `/dev/fd`.
const TESTS: &[&str] = &[
    "strip_prefix(\"/proc",
    "starts_with(\"/proc",
    "contains(\"/proc",
    "strip_prefix(\"/dev/fd",
    "starts_with(\"/dev/fd",
    "contains(\"/dev/fd",
];

fn count(text: &str) -> usize {
    // re-check 3: what `concat!` builds counts as a literal
    let literals = string_literals(text)
        .iter()
        .chain(concat_literals(text).iter())
        .filter(|l| is_link_literal(l))
        .count();
    let tests: usize = TESTS.iter().map(|t| text.matches(t).count()).sum();
    literals + tests
}

/// The files that hold sites: how many, and why none matches a path a
/// caller wrote.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-linux/src/response/quarantine.rs",
        2,
        "the restore's destination as the kernel resolved it: the agent's own descriptor of the \
         directory it opened through PID 1's root (`/proc/1/root/…`, `on_host_path`), read back \
         and mapped to the host's path — the kernel's answer, no path a caller wrote",
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        2,
        "the security-tool list's `proc` key (a field of the signed list), no path segment",
    ),
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        1,
        "the agent's own descriptors listed (`/proc/self/fd`): read, no match",
    ),
    (
        "agent/src/boot/attach.rs",
        3,
        "the agent's own image (`/proc/self/exe`): read, no match",
    ),
    (
        "crates/nn-linux/src/boot/checks.rs",
        2,
        "the agent's own image (`/proc/self/exe`): read, no match",
    ),
    (
        "crates/nn-linux/src/own_dropins.rs",
        1,
        "the agent's own image (`/proc/self/exe`): read, no match",
    ),
    (
        "crates/nn-linux/src/worker/mod.rs",
        1,
        "the agent's own image (`/proc/self/exe`) its worker is started from: read, no match",
    ),
    (
        "crates/nn-linux/src/anchored.rs",
        1,
        "the agent's own descriptor's path built (`/proc/self/fd/` and a descriptor it \
         opened), and known again when the agent's own code passes it back: no caller's path",
    ),
    (
        "crates/nn-linux/src/response/caps_preflight.rs",
        1,
        "the agent's own thread's status read (`/proc/thread-self/status`): no match",
    ),
    (
        "crates/nn-linux/src/canary/path_policy.rs",
        2,
        "PID 1's root (`/proc/1/root`), the host's view the agent reads its own paths through, \
         tested for and joined: no caller's path",
    ),
    (
        "crates/nn-linux/src/response/mod.rs",
        2,
        "PID 1's root (`/proc/1/root`), the host's view the agent acts through, tested for and \
         joined: no caller's path",
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        2,
        "PID 1's root (`/proc/1/root`), the host's view the agent checks its own files through: \
         no caller's path",
    ),
    (
        "crates/nn-linux/src/impact/entropy.rs",
        1,
        "PID 1's root (`/proc/1/root/`), the host's view the sampler reads files through, tested \
         for: no caller's path",
    ),
    (
        "agent/src/cow/journal.rs",
        1,
        "PID 1's root (`/proc/1/root/`), the host's view the copy guard writes through, tested \
         for: no caller's path",
    ),
    (
        "common/src/wire/execpol.rs",
        3,
        "the loader variables' staging prefixes the eBPF program compares in the kernel \
         (`/proc/`, `/dev/fd/`: a string prefix of an `LD_PRELOAD` entry, which the `mmap_file` \
         hook then judges on the file mapped), and their test (gated on `std`)",
    ),
    (
        "agent-ebpf/src/execpol.rs",
        1,
        "the same staging prefix as eight bytes in the eBPF program (`/dev/fd/`): the kernel \
         cannot call the reader; the `mmap_file` hook judges the file",
    ),
];

fn which(text: &str) -> String {
    let lits: Vec<String> = string_literals(text)
        .into_iter()
        .chain(concat_literals(text))
        .filter(|l| is_link_literal(l))
        .collect();
    let tests: Vec<&&str> = TESTS.iter().filter(|t| text.contains(**t)).collect();
    format!("literals {lits:?}; tests {tests:?}")
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
                "{file}: {n} site(s), {} — a `/proc` link matched by hand: read it with \
                 `posture::proc_link` (`through_proc_link`, `proc_link`, \
                 `reopens_a_descriptor`), or list the file in KNOWN with why it matches \
                 nothing a caller wrote",
                which(text)
            )),
            Some(&pin) if n > pin => out.push(format!(
                "{file}: {n} sites, {pin} known — {}: a new one",
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
    let code = product_code(&repo_root());
    assert!(code.contains_key(READER), "the reader is scanned");
    // the reader holds what it is the only one to hold
    assert!(count(&code[READER]) > 0, "the reader's markers");
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// Prints each file's count (`NN_PRINT_COUNTS=1`); a no-op without it.
#[test]
#[ignore = "prints the counts; NN_PRINT_COUNTS=1, run by hand when the table moves"]
fn print_the_counts() {
    if std::env::var_os("NN_PRINT_COUNTS").is_none() {
        return;
    }
    for (file, text) in product_code(&repo_root()) {
        let n = count(&text);
        if n > 0 && file != READER {
            println!("{n}\t{file}\t{}", which(&text));
        }
    }
}

/// The ratchet fails on planted violations: R004's twin as it was (BUG-88),
/// and the review of #539's — `contains("/proc/thread-self/fd/")`, a `const`
/// prefix and its test, a slice pattern on the `proc` segment; the agent's
/// own descriptor's path built (`format!`) and the reader itself are not
/// counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
    let mut code = product_code(&repo_root());
    let planted: &[(&str, &str)] = &[
        (
            "r004_twin",
            "fn a(p: &str) -> bool { p.strip_prefix(\"/proc/\").is_some() || \
             p.starts_with(\"/dev/fd/\") }",
        ),
        (
            "contains",
            "fn a(p: &str) -> bool { p.contains(\"/proc/thread-self/fd/\") }",
        ),
        (
            "konst",
            "const FD: &str = \"/proc/self/fd/\";\nfn a(p: &str) -> bool { p.starts_with(FD) }",
        ),
        (
            "slice",
            "fn a(s: &[&str]) -> bool { matches!(s, [\"\", \"proc\", _, \"fd\", _]) }",
        ),
        // re-check 3: the prefix built by `concat!`
        (
            "concat_proc",
            "const P: &str = concat!(\"/pr\", \"oc/self/fd/\");\nfn a(p: &str) -> bool { p.starts_with(P) }",
        ),
        (
            "concat_dev",
            "fn a(p: &str) -> bool { p.starts_with(concat!(\"/dev/\", \"fd/\")) }",
        ),
        (
            "concat_thread",
            "fn a(p: &str) -> bool { p.contains(concat!(\"/proc/\", \"thread\", \"-self/\")) }",
        ),
    ];
    for (name, body) in planted {
        code.insert(
            format!(
                "crates/nn-core/src/decision/rules/{}.rs",
                format_args!("twin_{name}")
            ),
            body.to_string(),
        );
    }
    code.insert(
        format!("crates/nn-linux/src/{}.rs", "own_fd"),
        "fn o(fd: i32) -> String { format!(\"/proc/self/fd/{fd}\") }".to_string(),
    );
    code.get_mut(READER)
        .unwrap()
        .push_str("\nfn h(p: &str) -> bool { p.starts_with(\"/proc/\") }\n");
    let v = violations(&code);
    assert_eq!(v.len(), planted.len(), "{v:#?}");
    for (name, _) in planted {
        assert!(
            v.iter().any(|x| x.contains(&format!("twin_{name}.rs"))),
            "{name}"
        );
    }
}
