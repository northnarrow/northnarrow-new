//! Lot 310 (external bug hunt, edition 1.4: BUG-97, BUG-99, BUG-100, N3):
//! an interpreter's options are read in one place —
//! `crates/nn-core/src/posture/script_args.rs`, one reader over a table per
//! family — and this ratchet keeps it so.
//!
//! Every identity bug of the three hunts in this family (BUG-42, BUG-44,
//! BUG-97, BUG-99, BUG-100, N3) was an argv read by hand: an option with
//! the wrong arity, a spelling the hand-written reader did not know
//! (`-noprofile`, `--eval=`, `-ovi`), the script taken as "the first
//! argument". A new site of that shape fails here until it calls the reader
//! (`runs_of`, `ExecIdentity::of_exec`, `inline_program`) or is listed in
//! [`KNOWN`] with why it is no interpreter's option read.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out) over the production code of the crates that judge processes. What
//! it counts ([`MARKERS`]):
//!
//! - an interpreter's option that names or carries its program, or moves
//!   where it is read, as a string literal (`"-c"`, `"--eval"`, `"-norc"`
//!   …): a comparison with an argv element, or a command line built;
//! - a positional read of the first argument (`argv.get(1)`, `argv[1]`,
//!   `args.get(1)`), what "the script" was taken to be, and a search for an
//!   option (`argv.iter().position(`).
//!
//! A file's count may not grow above its pin, and a count below it fails
//! until the pin comes down — the table is always the code's.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The one reader.
const READER: &str = "crates/nn-core/src/posture/script_args.rs";

/// The production trees scanned.
const TREES: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "crates/nn-admin/src",
    "agent/src",
    "common/src",
    "watchdog/src",
];

/// What an interpreter's options read by hand look like.
const MARKERS: &[&str] = &[
    // the program inline, standard input, a module (python, perl, ruby,
    // node, the shells)
    "\"-c\"",
    "\"-e\"",
    "\"-E\"",
    "\"-m\"",
    "\"-s\"",
    "\"--eval\"",
    "\"--print\"",
    "\"--run\"",
    // bash's long options, one hyphen or two (BUG-97), and the shells' `-o`
    "\"-noprofile\"",
    "\"--noprofile\"",
    "\"-norc\"",
    "\"--norc\"",
    "\"-rcfile\"",
    "\"--rcfile\"",
    "\"--init-file\"",
    "\"--login\"",
    "\"-o\"",
    // "the script is the first argument"
    "argv.get(1)",
    "argv[1]",
    "args.get(1)",
    "args[1]",
    "argv.iter().position(",
];

/// The files that hold markers: how many, and why none is an interpreter's
/// option read.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-core/src/impair/mod.rs",
        6,
        "the option tables of the system tools a security tool is switched off with — pkill's \
         and killall's `-s` (a signal), `-o`, `-c`, systemctl's `-s`, `-o` (`kill_signal_is_probe`, \
         `pattern_args`, `service_targets`): their own options, not an interpreter's (the \
         external bug hunt's lot 7 gives them a reader of their own)",
    ),
    (
        "crates/nn-core/src/decision/rules/r013_namespace_escape_tooling.rs",
        1,
        "nsenter's `-m` (the mount namespace), not an interpreter's",
    ),
    (
        "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs",
        1,
        "an exact argv, `sh -c /bin/true` (a modprobe.d directive's `install x /bin/true`): \
         three words, every other argv is judged — no option read, and the reader would \
         accept more (`sh -i -c /bin/true` reads a startup file)",
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        1,
        "FP-2: npm's entrypoint as node's first argument exactly (`argv.get(1)`): stricter \
         than the reader, which would take it after a preload (`node -r x npm-cli.js`)",
    ),
    (
        "crates/nn-admin/src/heartbeat.rs",
        1,
        "builds `sh -c <command>` for `--from-cmd` (a command line made, none read)",
    ),
    (
        "crates/nn-linux/src/worker/hostile.rs",
        1,
        "builds `sh -c` for the hostile worker of the sandbox's tests (a command line made, \
         none read)",
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        2,
        "the probe's own child's argv (`argv[1]`: its flag, then its nonce): the agent's \
         command line, no interpreter's",
    ),
    (
        "crates/nn-linux/src/worker/serve.rs",
        1,
        "the agent's own worker command line (`--worker`), no interpreter's",
    ),
    (
        "agent/src/boot/mod.rs",
        1,
        "the agent's own command line (its first argument, logged), no interpreter's",
    ),
];

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
                "{file}: {:?} — an interpreter's options read by hand: read them with \
                 `posture::script_args` (`runs_of`, `ExecIdentity::of_exec`, `inline_program`), \
                 or list the file in KNOWN with why it is no interpreter's",
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

/// No interpreter's option is read outside the reader; the pins are the
/// code's.
#[test]
fn interpreter_options_are_read_by_the_one_reader() {
    let code = tree_code(&repo_root());
    assert!(code.contains_key(READER), "the reader is scanned");
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// The ratchet fails on planted violations: BUG-97's shape (bash's `-norc`
/// compared by hand), BUG-44's (the script taken as the first argument), a
/// known file with one more site and one with one fewer; the reader itself
/// is not counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
    let mut code = tree_code(&repo_root());
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "new_rule"),
        "fn f(a: &[String]) -> bool { a.iter().any(|x| x == \"-norc\") || \
         argv.get(1).is_some() }"
            .to_string(),
    );
    code.get_mut("crates/nn-core/src/impair/mod.rs")
        .unwrap()
        .push_str("\nfn g(w: &str) -> bool { w == \"-c\" }\n");
    let lineage = code
        .get_mut("crates/nn-core/src/posture/lineage.rs")
        .unwrap();
    let i = lineage.find("argv.get(1)").expect("npm's entrypoint");
    lineage.replace_range(i..i + 1, " ");
    code.get_mut(READER)
        .unwrap()
        .push_str("\nfn h(a: &[String]) -> bool { a.get(1).is_some() && argv[1] == \"-c\" }\n");
    let v = violations(&code);
    assert_eq!(v.len(), 3, "{v:#?}");
    assert!(v[0].contains("new_rule.rs") || v.iter().any(|x| x.contains("new_rule.rs")));
    assert!(v
        .iter()
        .any(|x| x.contains("\\\"-norc\\\"") && x.contains("argv.get(1)")));
    assert!(v
        .iter()
        .any(|x| x.contains("impair/mod.rs") && x.contains("a new one")));
    assert!(v
        .iter()
        .any(|x| x.contains("lineage.rs") && x.contains("lower the pin")));
}
