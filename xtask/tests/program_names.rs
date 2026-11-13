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
//! The scan is lexical (comments blanked, test items and test files left
//! out) over the production code of the rules. What it counts ([`MARKERS`]):
//! a program's name cut from a path by hand (`rsplit('/')`), a path matched
//! by its end (`.ends_with(`), a shell's or busybox's name as a string
//! literal, and a name helper defined again (`fn program_is(`, `fn
//! base_of(`). A file's count may not grow above its pin, and a count below
//! it fails until the pin comes down — the table is always the code's.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The one helper.
const HELPER: &str = "crates/nn-core/src/decision/rules/program_identity.rs";

/// The production trees scanned: the rules.
const TREES: &[&str] = &["crates/nn-core/src/decision/rules"];

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

/// The files of the rules that hold markers: how many, and why none
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
        if file == HELPER {
            continue;
        }
        let n = count(text);
        match known.get(file.as_str()) {
            None if n > 0 => out.push(format!(
                "{file}: {:?} — a program recognised by its name: ask \
                 `decision::rules::program_identity` (`shell_or_interpreter`, `image_kind`, \
                 `names_a_shell`, `command_runs_a_shell`, `tool_named`, `kernel_image`), or \
                 list the file in KNOWN with why it recognises no program by its name",
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

/// The site counts of every file of the scan (to fill [`KNOWN`]): a no-op
/// unless `NN_PRINT_NAME_COUNTS=1`.
#[test]
#[ignore]
fn print_counts() {
    if std::env::var("NN_PRINT_NAME_COUNTS").as_deref() != Ok("1") {
        return;
    }
    for (file, text) in tree_code(&repo_root()) {
        let n = count(&text);
        if n > 0 {
            println!("{file}: {n} {:?}", which(&text));
        }
    }
}

/// No program is recognised by its name in the rules outside the helper.
#[test]
fn programs_are_recognised_by_the_one_helper() {
    let code = tree_code(&repo_root());
    assert!(code.contains_key(HELPER), "the helper is scanned");
    // the helper holds what it is the only one to hold
    assert!(count(&code[HELPER]) > 0, "the helper's markers");
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// The ratchet fails on planted violations: R020's basename test as it was
/// (N1), busybox's applet read from `argv[0]` by hand (BUG-85), R006's
/// shell list (BUG-112); the helper itself is not counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
    let mut code = tree_code(&repo_root());
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "r020_twin"),
        "fn shell(image: &str) -> bool { let base = image.rsplit('/').next().unwrap(); \
         base == \"bash\" }"
            .to_string(),
    );
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "busybox_twin"),
        "fn applet(exe: &str, argv0: &str) -> bool { exe.ends_with(\"/busybox\") && argv0 == \
         \"sh\" }"
            .to_string(),
    );
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "r006_twin"),
        "const SHELLS: &[&str] = &[\"sh\", \"bash\", \"dash\"];".to_string(),
    );
    code.get_mut(HELPER)
        .unwrap()
        .push_str("\nfn h(p: &str) -> &str { p.rsplit('/').next().unwrap() }\n");
    let v = violations(&code);
    assert_eq!(v.len(), 3, "{v:#?}");
    for twin in ["r020_twin.rs", "busybox_twin.rs", "r006_twin.rs"] {
        assert!(v.iter().any(|x| x.contains(twin)), "{twin}: {v:#?}");
    }
}
