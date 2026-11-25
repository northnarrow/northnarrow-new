//! Lot 313 (external bug hunt, edition 1.4: BUG-85, N1, BUG-112): a shell,
//! an interpreter, busybox or a tool is recognised in the rules by what the
//! kernel executed, through one helper —
//! `crates/nn-core/src/decision/rules/program_identity.rs` — and this ratchet
//! keeps it so.
//!
//! R020 told a shell by the basename of the executed file (`cp /bin/bash
//! ~/x` was no shell, N1) and asked busybox for its program in `argv[0]`
//! only (`busybox sh`, `-sh`: BUG-85); R006 read socat's `EXEC:` program as
//! the first word of its argument against a list of its own (BUG-112). A new
//! site of that shape in the rules fails here until it asks the helper
//! (`shell_or_interpreter`, `image_kind`, `names_a_shell`,
//! `command_runs_a_shell`, `tool_named`, `kernel_image`) or is listed in
//! [`KNOWN`] with why it recognises no program by its name.
//!
//! The scan reads the production code of the rules as Rust (lot 1.7a,
//! stage S1, item F12: `support::ast`; test items and test files left
//! out). What it counts ([`sites`]): a program's name cut from a path by
//! hand (`rsplit`, `rsplitn`, `rsplit_once`, `rfind` on `/`, or a `split`
//! on `/` whose `last()`/`next_back()` is taken — the separator a literal,
//! a `const` or a variable), a path matched by its end (`ends_with`,
//! `strip_suffix`, a method or a path call), a shell's or busybox's name as
//! a literal (its name, `/…/name`, `-name`, what a `concat!` joins), and a
//! name helper defined again (`fn program_is`, `fn base_of`, generics or
//! not, or a closure bound to that name). A file's count may not grow above
//! its pin, and a count below it fails until the pin comes down — the
//! table is always the code's. The lexical scan before lot 1.7a (kept in
//! [`lexical`] only to show it) missed each spelling planted below.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::ast::{self, Corpus};
use support::{is_test_file, repo_root};

/// The one helper.
const HELPER: &str = "crates/nn-core/src/decision/rules/program_identity.rs";

/// The production trees scanned: the rules.
const TREES: &[&str] = &["crates/nn-core/src/decision/rules"];

/// A shell's or busybox's name.
const NAMES: &[&str] = &[
    "sh", "bash", "rbash", "dash", "ash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "busybox",
];

/// The helpers' names, defined again.
const HELPERS: &[&str] = &["program_is", "base_of"];

/// A literal naming a shell or busybox: its name, a path to it, a login
/// shell's `argv[0]` (`-bash`).
fn names_a_program(v: &str) -> bool {
    NAMES.iter().any(|n| {
        v == *n
            || v.strip_suffix(n).is_some_and(|head| head.ends_with('/'))
            || v.strip_prefix('-') == Some(n)
    })
}

/// One site: its line, its item, what it is.
#[derive(Clone)]
struct Site {
    line: usize,
    item: String,
    what: String,
}

impl std::fmt::Debug for Site {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: `{}` {}", self.line, self.item, self.what)
    }
}

/// The sites of `rel` in `c`.
fn sites(c: &Corpus<'_>, rel: &str) -> Vec<Site> {
    let ix = &c.files[rel];
    let mut out = Vec::new();
    for l in &ix.lits {
        if !l.char && names_a_program(&l.value) {
            out.push(Site {
                line: l.line,
                item: l.item.clone(),
                what: format!("name {:?}", l.value),
            });
        }
    }
    for call in &ix.calls {
        let name = call.name.as_str();
        let on_slash = || {
            call.args
                .iter()
                .any(|a| c.values(rel, a, call.scope).iter().any(|v| v == "/"))
        };
        let what = match name {
            "rsplit" | "rsplitn" | "rsplit_once" | "rsplit_terminator" | "rfind"
            | "rmatch_indices"
                if on_slash() =>
            {
                format!("{name}('/')")
            }
            "split" | "split_terminator" | "split_inclusive" if on_slash() => {
                let (_, chain, _) = ast::spine(call.expr, &call.anc);
                if !chain
                    .iter()
                    .any(|m| m.method == "last" || m.method == "next_back" || m.method == "rev")
                {
                    continue;
                }
                format!("{name}('/') … last")
            }
            "ends_with" | "strip_suffix" => format!("{name}(…)"),
            _ => continue,
        };
        out.push(Site {
            line: call.line,
            item: call.item.clone(),
            what,
        });
    }
    for f in &ix.fns {
        if HELPERS.contains(&f.name.as_str()) {
            out.push(Site {
                line: f.line,
                item: f.item.clone(),
                what: format!("fn {}", f.name),
            });
        }
        for (n, bs) in &f.bindings {
            if HELPERS.contains(&n.as_str())
                && bs
                    .iter()
                    .any(|b| matches!(ast::peel(b.expr), syn::Expr::Closure(_)))
            {
                out.push(Site {
                    line: f.line,
                    item: f.item.clone(),
                    what: format!("let {n} = |…|"),
                });
            }
        }
    }
    out.sort_by_key(|s| s.line);
    out
}

/// The files of the rules that hold sites: how many, and why none
/// recognises a shell, an interpreter or a tool by its name.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-core/src/decision/rules/kmod_invocation.rs",
        1,
        "a module tool's argument that names a module file by its suffix (`.ko`, `.ko.zst`): \
         a file's name, no program's",
    ),
    (
        "crates/nn-core/src/decision/rules/net.rs",
        2,
        "a host name's top-level domain (`BLOCKED_TLDS`): a domain, no program",
    ),
    (
        "crates/nn-core/src/decision/rules/r017_shell_from_nonstandard_path.rs",
        3,
        "R017's comms (`sh`, `bash`, `dash`, design §7.1): the rule judges WHERE a file the \
         process is named like a shell runs from (a copied shell kept its name), not what the \
         file is — a renamed copy with its stdio on a socket is R020's, by identity; a wider \
         list by name would kill a user's own zsh or fish",
    ),
    (
        "crates/nn-core/src/decision/rules/test_actions.rs",
        1,
        "the demo build's response rules (feature `demo-tappa5`, never in a release): their \
         trigger is a file name's suffix the lab chose",
    ),
];

/// The sources of [`TREES`] (test files left out).
fn tree_sources(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for t in TREES {
        for (rel, text) in ast::tree_sources(root, t) {
            if is_test_file(&rel) || rel.contains("/tests/") {
                continue;
            }
            out.insert(rel, text);
        }
    }
    out
}

fn violations(c: &Corpus<'_>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut out = Vec::new();
    for file in c.files.keys() {
        if file == HELPER {
            continue;
        }
        let s = sites(c, file);
        let n = s.len();
        match known.get(file.as_str()) {
            None if n > 0 => out.push(format!(
                "{file}: {s:?} — a program recognised by its name: ask \
                 `decision::rules::program_identity` (`shell_or_interpreter`, `image_kind`, \
                 `names_a_shell`, `command_runs_a_shell`, `tool_named`, `kernel_image`), or \
                 list the file in KNOWN with why it recognises no program by its name"
            )),
            Some(&pin) if n > pin => {
                out.push(format!("{file}: {n} sites, {pin} known — {s:?}: a new one"))
            }
            Some(&pin) if n < pin => out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            )),
            _ => {}
        }
    }
    for (file, _, _) in KNOWN {
        if !c.files.contains_key(*file) {
            out.push(format!("{file}: listed in KNOWN, not in the scan"));
        }
    }
    out
}

/// The site counts of every file of the scan, the lexical count beside
/// them (to fill [`KNOWN`]): a no-op unless `NN_PRINT_NAME_COUNTS=1`.
#[test]
#[ignore]
fn print_counts() {
    if std::env::var("NN_PRINT_NAME_COUNTS").as_deref() != Ok("1") {
        return;
    }
    let sources = tree_sources(&repo_root());
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    for (file, text) in &sources {
        let s = sites(&c, file);
        let lex = lexical::count(&support::production(&support::strip_comments(text)));
        if !s.is_empty() || lex > 0 {
            println!("{file}: {} (lexical {lex}) {s:?}", s.len());
        }
    }
}

/// No program is recognised by its name in the rules outside the helper.
#[test]
fn programs_are_recognised_by_the_one_helper() {
    let sources = tree_sources(&repo_root());
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    assert!(c.files.contains_key(HELPER), "the helper is scanned");
    // the helper holds what it is the only one to hold
    assert!(!sites(&c, HELPER).is_empty(), "the helper's markers");
    let v = violations(&c);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

fn corpus_of(
    files: &[(String, String)],
) -> (BTreeMap<String, String>, BTreeMap<String, syn::File>) {
    let sources: BTreeMap<String, String> = files.iter().cloned().collect();
    let parsed = ast::parse_all(&sources, true);
    (sources, parsed)
}

/// The ratchet fails on planted violations: R020's basename test as it was
/// (N1), busybox's applet read from `argv[0]` by hand (BUG-85), R006's
/// shell list (BUG-112); the helper itself is not counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
    let rules = "crates/nn-core/src/decision/rules";
    let mut files: Vec<(String, String)> = tree_sources(&repo_root()).into_iter().collect();
    files.push((
        format!("{rules}/r020_twin.rs"),
        "fn shell(image: &str) -> bool { let base = image.rsplit('/').next().unwrap(); \
         base == \"bash\" }"
            .to_string(),
    ));
    files.push((
        format!("{rules}/busybox_twin.rs"),
        "fn applet(exe: &str, argv0: &str) -> bool { exe.ends_with(\"/busybox\") && argv0 == \
         \"sh\" }"
            .to_string(),
    ));
    files.push((
        format!("{rules}/r006_twin.rs"),
        "const SHELLS: &[&str] = &[\"sh\", \"bash\", \"dash\"];".to_string(),
    ));
    for (rel, text) in &mut files {
        if rel == HELPER {
            text.push_str("\nfn h(p: &str) -> &str { p.rsplit('/').next().unwrap() }\n");
        }
    }
    let (sources, parsed) = corpus_of(&files);
    let c = Corpus::of(&sources, &parsed);
    let v = violations(&c);
    assert_eq!(v.len(), 3, "{v:#?}");
    for twin in ["r020_twin.rs", "busybox_twin.rs", "r006_twin.rs"] {
        assert!(v.iter().any(|x| x.contains(twin)), "{twin}: {v:#?}");
    }
}

/// Lot 1.7a: the spellings that passed the lexical scan, each planted in a
/// copy of a rule (`r017_shell_from_nonstandard_path.rs`, one of KNOWN's):
/// the lexical scan counts nothing more, the AST scan one site more — the
/// separator as a string, in a `const`, in a variable or broken over
/// lines; `rsplit_once`, `rsplitn`, `rfind`, `split('/').last()`; the path
/// form `str::ends_with`, `strip_suffix`; a shell's path or login name, a
/// name `concat!` joins; a helper defined again with generics, or as a
/// closure.
#[test]
fn the_lexical_bypasses_are_caught() {
    let host = "crates/nn-core/src/decision/rules/r017_shell_from_nonstandard_path.rs";
    let text = std::fs::read_to_string(repo_root().join(host)).unwrap();
    let lex = |t: &str| lexical::count(&support::production(&support::strip_comments(t)));
    let n = |t: &str| {
        let (sources, parsed) = corpus_of(&[(host.to_string(), t.to_string())]);
        let c = Corpus::of(&sources, &parsed);
        sites(&c, host).len()
    };
    let (base_lex, base) = (lex(&text), n(&text));
    for plant in [
        "fn planted(p: &str) -> &str { p.rsplit(\"/\").next().unwrap_or(p) }",
        "const SEP: char = '/';\nfn planted(p: &str) -> &str { p.rsplit(SEP).next().unwrap_or(p) }",
        "fn planted(p: &str) -> &str { let sep = '/'; p.rsplit(sep).next().unwrap_or(p) }",
        "fn planted(p: &str) -> &str {\n    p.rsplit(\n        '/',\n    )\n    .next()\n    .unwrap_or(p)\n}",
        "fn planted(p: &str) -> Option<&str> { p.rsplit_once('/').map(|(_, b)| b) }",
        "fn planted(p: &str) -> Option<&str> { p.rsplitn(2, '/').next() }",
        "fn planted(p: &str) -> Option<usize> { p.rfind('/') }",
        "fn planted(p: &str) -> Option<&str> { p.split('/').last() }",
        "fn planted(p: &str) -> bool { str::ends_with(p, \"/ksh93\") }",
        "fn planted(p: &str) -> bool { p.strip_suffix(\"/ksh93\").is_some() }",
        "fn planted(p: &str) -> bool { p == \"/usr/bin/bash\" }",
        "fn planted(argv0: &str) -> bool { argv0 == \"-zsh\" }",
        "fn planted(p: &str) -> bool { p == concat!(\"bas\", \"h\") }",
        "fn base_of<'a>(p: &'a str) -> &'a str { p }",
        "fn planted(p: &str) -> bool { let program_is = |n: &str| n == p; program_is(p) }",
    ] {
        let copy = format!("{text}\n{plant}\n");
        assert_eq!(lex(&copy), base_lex, "the lexical scan saw it: {plant}");
        assert_eq!(n(&copy), base + 1, "{plant}");
    }
}

/// The lexical scan before lot 1.7a, kept only to show the spellings it
/// missed.
mod lexical {
    /// What a program recognised by its name looks like.
    const MARKERS: &[&str] = &[
        // a name cut from a path by hand, a path matched by its end
        "rsplit('/')",
        ".ends_with(",
        // a shell's or busybox's name
        "\"sh\"",
        "\"bash\"",
        "\"rbash\"",
        "\"dash\"",
        "\"ash\"",
        "\"zsh\"",
        "\"ksh\"",
        "\"mksh\"",
        "\"fish\"",
        "\"csh\"",
        "\"tcsh\"",
        "\"busybox\"",
        // the helpers' names, defined again
        "fn program_is(",
        "fn base_of(",
    ];

    pub fn count(text: &str) -> usize {
        MARKERS.iter().map(|m| text.matches(m).count()).sum()
    }
}
