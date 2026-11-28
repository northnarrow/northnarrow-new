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
//!
//! Lot 1.7a (stage S1, item F12): the scan reads the sources as Rust
//! (`support::ast`), not as text. The lexical scan matched
//! `starts_with("/proc` as characters, and a review's spelling passed it
//! each time: the call broken over lines by rustfmt, the prefix in a
//! `const` or a variable, in parentheses, an item of an array iterated, a
//! `format!` template, a byte string, the `str::starts_with(p, …)` form. A
//! test now is any call of `strip_prefix`, `starts_with` or `contains`
//! (method or path) whose argument can hold a string that starts with
//! `/proc` or `/dev/fd` ([`support::ast::Corpus::values`]); a literal is any
//! string, byte string or C string of the code, in a macro's body or an
//! attribute too (no doc comment), and what `concat!` joins. Each spelling
//! is planted in a copy of a product file below, and the lexical scan
//! (kept in [`lexical`] for that proof only) is shown missing it.

mod support;

use std::collections::BTreeMap;

use support::ast::{self, Corpus};
use support::repo_root;

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

/// The tests of a path's text: by its start, or a part of it.
const TESTS: &[&str] = &["strip_prefix", "starts_with", "contains"];

/// A value a test compares a path with that names `/proc` or `/dev/fd`.
fn is_link_prefix(v: &str) -> bool {
    v.starts_with("/proc") || v.starts_with("/dev/fd")
}

/// One site: its line, its item, what it is.
#[derive(Debug, Clone)]
struct Site {
    line: usize,
    item: String,
    what: String,
}

/// The sites of `rel` in `c`: its link literals, and its tests of a
/// path's text against `/proc` or `/dev/fd`, whatever holds the prefix.
fn sites(c: &Corpus<'_>, rel: &str) -> Vec<Site> {
    let ix = &c.files[rel];
    let mut out: Vec<Site> = ix
        .lits
        .iter()
        .filter(|l| !l.char && is_link_literal(&l.value))
        .map(|l| Site {
            line: l.line,
            item: l.item.clone(),
            what: format!("literal {:?}", l.value),
        })
        .collect();
    for call in &ix.calls {
        if !TESTS.contains(&call.name.as_str()) {
            continue;
        }
        let hit = call
            .args
            .iter()
            .flat_map(|a| c.values(rel, a, call.scope))
            .find(|v| is_link_prefix(v));
        if let Some(v) = hit {
            out.push(Site {
                line: call.line,
                item: call.item.clone(),
                what: format!("{}({v:?})", call.name),
            });
        }
    }
    out.sort_by_key(|s| s.line);
    out
}

/// The files that hold sites: how many, and why none matches a path a
/// caller wrote.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-core/src/anti_tamper/trusted_installer.rs",
        1,
        "lot 2.3b: the frozen set's own paths (`binfmt_misc` among them) compared with each other, \
         component by component, to tell which name is frozen in its parent — no link a caller \
         wrote is read or matched",
    ),
    (
        "crates/nn-linux/src/anti_tamper/pin_lock.rs",
        1,
        "lot 359: the agent's own `/proc/self/exe`, read beneath the `/proc` root, to run its own \
         binary in the transient unit that makes the pin directory's lock again — the kernel's \
         answer about this process, matched against nothing a caller wrote",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        3,
        "the restore's destination as the kernel resolved it: the agent's own descriptor of the \
         directory it opened through PID 1's root (`/proc/1/root/…`, `on_host_path`), read back \
         and mapped to the host's path — the kernel's answer, no path a caller wrote \
         — lot 1.7a: the AST scan also counts the deny list's test (`QUARANTINE_DENY_PREFIXES`, `/proc/` among them): a path under `/proc` is never quarantined, the stricter side",
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        2,
        "the security-tool list's `proc` key (a field of the signed list), no path segment",
    ),
    (
        "crates/nn-linux/src/anti_tamper/mount_guard.rs",
        6,
        "the review of #567 (F1, F2): a guarded namespace's own mount table, its namespace link \
         and its root (`/proc/<pid>/mountinfo`, `/proc/<pid>/ns/mnt`, `/proc/<pid>/root`) read for \
         the mount guard's registration: read, no match; lot 359: PID 1's root the points are \
         read beneath (`point_metadata`, the root's link followed) \
         — lot 1.7a: the AST scan also counts `not_canonical_in`'s test of a mount point (the kernel's mount table) against the kernel views' roots (`VIEW_TYPES`)",
    ),
    (
        "crates/nn-linux/src/posture_host_linux.rs",
        2,
        "lot 357's item 5: which reader a host file's identity takes — at once beneath a kernel \
         view, on the bounded host-file reader through PID 1's root (`/proc/1/root/…`, the \
         host's own files, out of the view): the reader chosen, no path a caller wrote matched",
    ),
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        1,
        "the agent's own descriptors listed (`/proc/self/fd`): read, no match",
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
        // re-check 1 of #563 (N3): 2 → 1, the root opened beneath the
        // anchored /proc root at once (no separate test of it)
        2,
        "PID 1's root (`/proc/1/root`), the host's view the agent writes its canaries through, \
         opened beneath the anchored /proc root: no caller's path \
         — lot 1.7a: the AST scan also counts the deny list's test (`CANARY_DENY_PREFIXES`, `/proc/` among them): a canary under `/proc` is refused whatever link it names, the stricter side",
    ),
    (
        "crates/nn-linux/src/response/mod.rs",
        2,
        "PID 1's root (`/proc/1/root`), the host's view the agent acts through, tested for and \
         joined: no caller's path",
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        4,
        "PID 1's root (`/proc/1/root`), the host's view the agent checks its own files through: \
         no caller's path; lot 353: `\"proc\"` is the file system type of the kernel's view at \
         `/proc` in the mount check (`KERNEL_VIEWS`), no path segment \
         — lot 1.7a: the AST scan also counts `over_kernel_view`'s test of a mount point (the kernel's mount table) against `/proc/` and `/sys/`",
    ),
    (
        "antitamper-bpf/src/kernel_roots.rs",
        10,
        "lot 353: `\"proc\"` is procfs's name in the table of the kernel's file systems \
         (`KERNEL_MAGICS`), no path segment, and `starts_with(\"/proc\")` asks whether a path is \
         under the `/proc` view at all (before the views are anchored); the module resolves the \
         magic links of `/proc` as the kernel does, matching none; `chmod_fd` and `reopen_fd` \
         (the review of #563, F2) and the walk's reopen (re-check 4, R4-1) open the thread's \
         own `thread-self/fd` directory beneath the anchored root to reach a descriptor they \
         hold, matching nothing a caller wrote; `current_exe` reads the process's own `/proc/self/exe` beneath the root (std read it by path) \
         — lot 1.7a: the AST scan also counts the tests of a path against a view's own root (`View::at`, a field one of whose literals is `/proc`: the anchored views themselves), no caller's path matched as a link",
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
        1,
        "the loader variables' staging prefixes the eBPF program compares in the kernel \
         (`/proc/`, `/dev/fd/`: a string prefix of an `LD_PRELOAD` entry, which the `mmap_file` \
         hook then judges on the file mapped); its test (gated on `std`) is a test item since \
         the review of #564",
    ),
    (
        "agent/src/cow/config.rs",
        1,
        "lot 1.7a (the AST scan; the lexical one missed the prefix passed to a helper): \
         `under`'s test of an operator's scope or journal path against \
         `REFUSED_SCOPE_PREFIXES` (`/proc` among them) — a configuration refused, the stricter \
         side, no link followed",
    ),
    (
        "crates/nn-core/src/posture/triggers.rs",
        2,
        "lot 1.7a (the AST scan; the lexical one missed the prefixes held in an array): the \
         mass-write carve-out's prefixes (`MASS_WRITE_CARVEOUT_PREFIXES`, `/proc/` among them) \
         tested on a path the kernel resolved, or on a caller's path only after the reader \
         ruled out a link (`is_mass_write_carveout_unresolved`: `through_proc_link`)",
    ),
    (
        "crates/nn-linux/src/sensors/open_sensor.rs",
        1,
        "lot 1.7a (the AST scan; the lexical one missed the prefixes held in an array): a home \
         of root's account file compared with the system trees (`SYSTEM_TREES`, `/proc` among \
         them) — a home is no link, and a match only drops a carve-out",
    ),
];

/// Today's sites the AST scan finds and the lexical one did not, that
/// match a path a caller wrote: `(file, item, what, the lot or stage that
/// removes it)` — one entry per site, never a pattern to follow (a new one
/// fails); the entry goes when its site does.
const DEBT: &[(&str, &str, &str, &str)] = &[];

/// The sites of the scan, by file, each debt entry taking its one site
/// out: `(sites counted, debt entries matched)`.
fn scan(c: &Corpus<'_>) -> (BTreeMap<String, Vec<Site>>, Vec<bool>) {
    let mut used = vec![false; DEBT.len()];
    let mut out = BTreeMap::new();
    for rel in c.files.keys() {
        if rel == READER {
            continue;
        }
        let mut s = sites(c, rel);
        s.retain(|site| {
            let debt = DEBT.iter().enumerate().position(|(n, (f, item, what, _))| {
                !used[n] && f == rel && *item == site.item && *what == site.what
            });
            if let Some(n) = debt {
                used[n] = true;
            }
            debt.is_none()
        });
        if !s.is_empty() {
            out.insert(rel.clone(), s);
        }
    }
    (out, used)
}

fn violations(c: &Corpus<'_>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let (found, used) = scan(c);
    let mut out = Vec::new();
    for (file, s) in &found {
        let n = s.len();
        match known.get(file.as_str()) {
            None => out.push(format!(
                "{file}: {n} site(s), {s:?} — a `/proc` link matched by hand: read it with \
                 `posture::proc_link` (`through_proc_link`, `proc_link`, \
                 `reopens_a_descriptor`), or list the file in KNOWN with why it matches \
                 nothing a caller wrote"
            )),
            Some(&pin) if n > pin => {
                out.push(format!("{file}: {n} sites, {pin} known — {s:?}: a new one"))
            }
            _ => {}
        }
    }
    for (file, pin, _) in KNOWN {
        let n = found.get(*file).map_or(0, Vec::len);
        if !c.files.contains_key(*file) {
            out.push(format!("{file}: listed in KNOWN, not in the scan"));
        } else if n < *pin {
            out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            ));
        }
    }
    for ((file, item, what, _), u) in DEBT.iter().zip(&used) {
        if !u {
            out.push(format!(
                "{file}: `{item}` {what}: in DEBT, no such site any more — remove the entry"
            ));
        }
    }
    out
}

/// No `/proc` link is matched outside the reader.
#[test]
fn proc_links_are_matched_by_the_one_reader() {
    let sources = ast::product_sources(&repo_root());
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    assert!(c.files.contains_key(READER), "the reader is scanned");
    // the reader holds what it is the only one to hold
    assert!(!sites(&c, READER).is_empty(), "the reader's markers");
    let v = violations(&c);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
    for (file, item, what, owner) in DEBT {
        assert!(
            !item.is_empty() && !what.is_empty() && owner.len() > 3,
            "{file}: name the item and who removes it"
        );
    }
}

/// Prints each file's sites, the lexical count beside them
/// (`NN_PRINT_COUNTS=1`); a no-op without it.
#[test]
#[ignore = "prints the counts; NN_PRINT_COUNTS=1, run by hand when the table moves"]
fn print_the_counts() {
    if std::env::var_os("NN_PRINT_COUNTS").is_none() {
        return;
    }
    let root = repo_root();
    let sources = ast::product_sources(&root);
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    let old = support::product_code(&root);
    for rel in c.files.keys() {
        let s = sites(&c, rel);
        let lex = old.get(rel).map_or(0, |t| lexical::count(t));
        if !s.is_empty() || lex > 0 {
            println!("{}\t(lexical {lex})\t{rel}", s.len());
            for site in &s {
                println!("\t{}:{} `{}` {}", rel, site.line, site.item, site.what);
            }
        }
    }
}

/// A corpus of the given files alone (a fixture, a planted copy).
fn fixture(files: &[(&str, &str)]) -> Vec<(String, String, syn::File)> {
    files
        .iter()
        .map(|(rel, text)| {
            (
                rel.to_string(),
                text.to_string(),
                ast::production(rel, text),
            )
        })
        .collect()
}

fn corpus(f: &[(String, String, syn::File)]) -> Corpus<'_> {
    Corpus::new(f.iter().map(|(r, t, p)| (r.as_str(), t.as_str(), p)))
}

/// The ratchet fails on planted violations: R004's twin as it was (BUG-88),
/// and the review of #539's — `contains("/proc/thread-self/fd/")`, a `const`
/// prefix and its test, a slice pattern on the `proc` segment; the agent's
/// own descriptor's path built (`format!`) and the reader itself are not
/// counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
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
    let mut files: Vec<(String, String)> = planted
        .iter()
        .map(|(name, body)| {
            (
                format!("crates/nn-core/src/decision/rules/twin_{name}.rs"),
                body.to_string(),
            )
        })
        .collect();
    files.push((
        "crates/nn-linux/src/own_fd.rs".into(),
        "fn o(fd: i32) -> String { format!(\"/proc/self/fd/{fd}\") }".into(),
    ));
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let f = fixture(&refs);
    let c = corpus(&f);
    let (found, _) = scan(&c);
    assert_eq!(found.len(), planted.len(), "{found:#?}");
    for (name, _) in planted {
        assert!(
            found
                .keys()
                .any(|x| x.ends_with(&format!("twin_{name}.rs"))),
            "{name}: {found:#?}"
        );
    }
    // the reader is not counted
    let r = fixture(&[(
        READER,
        "fn h(p: &str) -> bool { p.starts_with(\"/proc/\") }",
    )]);
    assert!(scan(&corpus(&r)).0.is_empty());
}

/// Lot 1.7a: an attribute's literal is read (`#[serde(rename = "proc")]`, a
/// key a struct's text holds, as the lexical scan read it), a doc comment's
/// prose is not, nor is a test module's code (`#[cfg(all(test, …))]`, a
/// `#[test]` function), while `#[cfg(any(test, unix))]` is a release's.
#[test]
fn attributes_are_read_doc_comments_and_tests_are_not() {
    let rel = "crates/nn-linux/src/attr_twin.rs";
    let n = |text: &str| sites(&corpus(&fixture(&[(rel, text)])), rel).len();
    assert_eq!(
        n("#[derive(Deserialize)]\nstruct S { #[serde(rename = \"proc\")] p: u8 }"),
        1
    );
    assert_eq!(
        n("/// reads /proc/self/fd/0 and /proc/thread-self/fd\nfn a() {}"),
        0
    );
    assert_eq!(
        n("#[cfg(all(test, feature = \"std\"))]\nmod t { const P: &str = \"/proc/self/fd/\"; }"),
        0
    );
    assert_eq!(n("#[test]\nfn t() { let _ = \"/proc/self/exe\"; }"), 0);
    assert_eq!(
        n("fn a() {\n    #[cfg(test)]\n    let _p = \"/proc/self/exe\";\n}"),
        0
    );
    assert_eq!(
        n("#[cfg(any(test, unix))]\nconst P: &str = \"/proc/self/exe\";"),
        1
    );
}

/// Lot 1.7a: the spellings that passed the lexical scan, each planted in
/// a copy of a product file (`boot/checks.rs`, one of KNOWN's): the lexical
/// scan counts nothing more, the AST scan one site more — the rustfmt
/// line break, a `const` and a variable holding the prefix, parentheses,
/// an array's item (an iterator closure's, a `for` loop's, an index), a
/// `format!` template, a byte string, the path form `str::starts_with`, a
/// `concat!` in a `const`, a prefix passed to a helper, a `matches!` guard,
/// a log macro's field.
#[test]
fn the_lexical_bypasses_are_caught() {
    let host = "crates/nn-linux/src/boot/checks.rs";
    let text = std::fs::read_to_string(repo_root().join(host)).unwrap();
    let base_lex = lexical::count(&support::production(&support::strip_comments(&text)));
    let base = fixture(&[(host, &text)]);
    let base_n = sites(&corpus(&base), host).len();
    for plant in [
        "fn planted(p: &str) -> bool {\n    p.starts_with(\n        \"/proc/\",\n    )\n}",
        "const PROC: &str = \"/proc/\";\nfn planted(p: &str) -> bool { p.starts_with(PROC) }",
        "fn planted(p: &str) -> bool { let pre = \"/proc\"; p.strip_prefix(pre).is_some() }",
        "fn planted(p: &str) -> bool { p.starts_with((\"/proc\")) }",
        "fn planted(p: &str) -> bool { [\"/proc/\", \"/sys/\"].iter().any(|x| p.starts_with(x)) }",
        "fn planted(p: &str) -> bool { for pre in [\"/proc\"] { if p.starts_with(pre) { return true; } } false }",
        "const PRE: [&str; 2] = [\"/sys\", \"/proc\"];\nfn planted(p: &str) -> bool { p.starts_with(PRE[1]) }",
        "fn planted(p: &str, pid: u32) -> bool { p.starts_with(&format!(\"/proc/{pid}/\")) }",
        "fn planted(p: &[u8]) -> bool { p.starts_with(b\"/proc/\") }",
        "fn planted(p: &str) -> bool { str::starts_with(p, \"/proc\") }",
        "const P: &str = concat!(\"/pr\", \"oc\");\nfn planted(p: &str) -> bool { p.starts_with(P) }",
        "fn under(p: &str, pre: &str) -> bool { p.contains(pre) }\nfn planted(p: &str) -> bool { under(p, \"/proc/\") }",
        "fn planted(p: &str) -> bool { matches!(p, x if x.starts_with(\n    \"/proc\")) }",
        "fn planted(p: &str) { tracing::warn!(link = %p.starts_with(\n    \"/proc\"), \"x\"); }",
        "fn planted(p: &std::path::Path) -> bool { p.strip_prefix(std::path::Path::new(\"/proc\").join(\"self\")).is_ok() }",
        // a `/dev/fd` prefix no literal holds whole
        "fn planted(p: &str) -> bool { p.starts_with(&format!(\"/dev/{}\", \"fd\")) }",
    ] {
        let copy = format!("{text}\n{plant}\n");
        let lex = lexical::count(&support::production(&support::strip_comments(&copy)));
        assert_eq!(lex, base_lex, "the lexical scan saw it: {plant}");
        let f = fixture(&[(host, &copy)]);
        let n = sites(&corpus(&f), host).len();
        assert_eq!(n, base_n + 1, "{plant}: {:#?}", sites(&corpus(&f), host));
    }
}

/// The lexical scan before lot 1.7a, kept only to show the spellings it
/// missed.
mod lexical {
    use super::support::{concat_literals, string_literals};

    const TESTS: &[&str] = &[
        "strip_prefix(\"/proc",
        "starts_with(\"/proc",
        "contains(\"/proc",
        "strip_prefix(\"/dev/fd",
        "starts_with(\"/dev/fd",
        "contains(\"/dev/fd",
    ];

    pub fn count(text: &str) -> usize {
        let literals = string_literals(text)
            .iter()
            .chain(concat_literals(text).iter())
            .filter(|l| super::is_link_literal(l))
            .count();
        let tests: usize = TESTS.iter().map(|t| text.matches(t).count()).sum();
        literals + tests
    }
}
