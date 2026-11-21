//! Lot 380 (the review of #587, F1 and F4): the reader of a credential file
//! is judged by the IDENTITY of the file the kernel executed, through one
//! door — and this ratchet keeps it so.
//!
//! The posture judged a packaged program's read of `/etc/passwd` (lot 380)
//! and a service account's read of `/etc/shadow`, `/etc/gshadow` or
//! `/etc/sudoers` (external audit POS-007) by the NAME of the executed file:
//! its basename against a list of tools. The name is not what runs: uutils'
//! multi-call file (Ubuntu 26.04) run through its `id` link with `argv[0]`
//! `cat` is `cat`, the dynamic loader runs its operand, `nawk` is a link to
//! `mawk`. Now:
//!
//! - a packaged program's class is
//!   `AuthSessionTracker::reads_files_it_is_told`
//!   (`crates/nn-core/src/posture/lineage.rs`): the executed file's own
//!   name, its identity against the installed tools' files, the loader by
//!   its operand;
//! - a service account's read of the shadow file is quiet only for the
//!   authentication stack and a packaged consumer, by the file the kernel
//!   executed (`runs_host_program` with `CREDENTIAL_CONSUMER_EXES`).
//!
//! Two rules:
//!
//! 1. **One door.** In the posture's production code the reader tools'
//!    names are used only by the door's own items ([`DOOR_ITEMS`]): the
//!    list, its name helper, the class and the installed files' identities.
//!    A class decided on a name anywhere else ([`MARKERS`]: the list, the
//!    helper, the old `reads_like_a_tool` and its list) fails.
//! 2. **No name in the two judgements.** The bodies of
//!    `sensitive_file_access` and `service_uid_credential_read`
//!    (`crates/nn-core/src/posture/triggers.rs`) cut no program's name from
//!    a path, read no image path, and compare no `comm` ([`NAME_CUTS`]):
//!    they ask the identity helpers.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;

use support::{matching_brace, product_code, repo_root};

/// The door: the lineage's file.
const DOOR: &str = "crates/nn-core/src/posture/lineage.rs";

/// The posture's judgements.
const TRIGGERS: &str = "crates/nn-core/src/posture/triggers.rs";

/// The posture's production tree, scanned by rule 1.
const POSTURE: &str = "crates/nn-core/src/posture/";

/// The door's own items, which use the names by design.
const DOOR_ITEMS: &[&str] = &[
    "pub const READER_TOOL_EXES",
    "const READER_INTERPRETER_EXTRAS",
    "fn names_a_reader_tool",
    "fn file_reads_what_it_is_told",
    "fn reader_tool_files",
];

/// A reader's class decided on its name.
const MARKERS: &[&str] = &[
    "READER_TOOL_EXES",
    "names_a_reader_tool(",
    "READER_INTERPRETER_EXTRAS",
    "reads_like_a_tool",
    "GENERIC_READER_EXES",
    "INTERPRETER_EXES",
];

/// The two judgements of rule 2.
const JUDGEMENTS: &[&str] = &[
    "fn sensitive_file_access<",
    "fn service_uid_credential_read<",
];

/// A program's name taken in a judgement: a basename cut from a path, an
/// image path read, a `comm` compared.
const NAME_CUTS: &[&str] = &[
    "rsplit('/')",
    ".file_name()",
    "base_of(",
    "image_path",
    "comm ==",
    "comm.as_str()",
    "comm.starts_with",
    "comm.ends_with",
];

fn count(text: &str, markers: &[&str]) -> usize {
    markers.iter().map(|m| text.matches(m).count()).sum()
}

/// `text` without the item starting at `head` (to its `;` for a constant,
/// else to the brace closing its body).
fn without_item(text: &str, head: &str) -> String {
    let at = text
        .find(head)
        .unwrap_or_else(|| panic!("the file holds `{head}`"));
    let end = if head.contains("const ") {
        at + text[at..].find("];").expect("a list ends") + 2
    } else {
        let open = at + text[at..].find('{').expect("a body");
        open + matching_brace(&text[open..])
    };
    let mut out = text.to_string();
    out.replace_range(at..end, "");
    out
}

/// The body of the function starting at `head` in `text`.
fn body<'a>(text: &'a str, head: &str) -> &'a str {
    let at = text
        .find(head)
        .unwrap_or_else(|| panic!("the file holds `{head}`"));
    let open = at + text[at..].find('{').expect("a body");
    &text[open..open + matching_brace(&text[open..])]
}

fn violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (file, text) in code.iter().filter(|(f, _)| f.starts_with(POSTURE)) {
        let rest = if file == DOOR {
            DOOR_ITEMS
                .iter()
                .fold(text.clone(), |t, item| without_item(&t, item))
        } else {
            text.clone()
        };
        let n = count(&rest, MARKERS);
        if n > 0 {
            out.push(format!(
                "{file}: {n} reader class(es) decided on a name — ask \
                 `AuthSessionTracker::reads_files_it_is_told` (the executed file's identity) or \
                 `runs_host_program` (a consumer by identity)"
            ));
        }
    }
    let triggers = code.get(TRIGGERS).expect("the judgements are scanned");
    for head in JUDGEMENTS {
        let n = count(body(triggers, head), NAME_CUTS);
        if n > 0 {
            out.push(format!(
                "{TRIGGERS}: `{head}…`: {n} program name(s) taken — judge the reader by the \
                 file the kernel executed"
            ));
        }
    }
    out
}

/// No reader of a credential file is judged by its name outside the door.
#[test]
fn a_credential_file_s_reader_is_judged_by_identity_through_one_door() {
    let code = product_code(&repo_root());
    let door = code.get(DOOR).expect("the door is scanned");
    for item in DOOR_ITEMS {
        assert!(door.contains(item), "{item}");
    }
    for helper in [
        "pub fn reads_files_it_is_told",
        "pub const CREDENTIAL_CONSUMER_EXES",
        "pub const READER_TOOL_DIRS",
    ] {
        assert!(door.contains(helper), "{helper}");
    }
    let triggers = &code[TRIGGERS];
    assert!(
        body(triggers, JUDGEMENTS[0]).contains("reads_files_it_is_told("),
        "the passwd arm asks the class by identity"
    );
    assert!(
        body(triggers, JUDGEMENTS[1]).contains("CREDENTIAL_CONSUMER_EXES"),
        "POS-007 asks the consumers by identity"
    );
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
}

/// A planted name test fails each rule.
#[test]
fn a_reader_judged_by_its_name_fails_the_ratchet() {
    let base = product_code(&repo_root());
    assert!(violations(&base).is_empty(), "{:#?}", violations(&base));
    // rule 1: the list or the helper used outside the door's items, the
    // old helper back
    for (file, plant) in [
        (
            TRIGGERS,
            "fn x(p: &str) -> bool { super::lineage::READER_TOOL_EXES.contains(&p) }",
        ),
        (
            "crates/nn-core/src/posture/exempt.rs",
            "fn reads_like_a_tool(p: &str) -> bool { p.is_empty() }",
        ),
        (
            DOOR,
            "fn by_name(p: &str) -> bool { names_a_reader_tool(p) }",
        ),
    ] {
        let mut code = base.clone();
        code.insert(file.into(), format!("{} {plant}", base[file]));
        let v = violations(&code);
        assert!(v.iter().any(|m| m.contains(file)), "{plant}: {v:#?}");
    }
    // rule 2: a name taken in either judgement
    for head in JUDGEMENTS {
        for cut in [
            "let _ = image.rsplit('/');",
            "let _ = auth.image_path_as(1, as_of);",
            "let _ = comm == \"id\";",
        ] {
            let text = &base[TRIGGERS];
            let at = text.find(head).unwrap();
            let open = at + text[at..].find('{').unwrap();
            let mut planted = text.clone();
            planted.insert_str(open + 1, cut);
            let mut code = base.clone();
            code.insert(TRIGGERS.into(), planted);
            let v = violations(&code);
            assert!(v.iter().any(|m| m.contains(head)), "{head} {cut}: {v:#?}");
        }
    }
}
