//! Wave 4 restructure, R12c (lab PR 270; plan §3.4): **no action without a
//! signed record** — the guard that fails when an action path could run
//! without its intent row before it and its outcome row after it.
//!
//! The record is the `actions` chain's (`nn_linux::response::journal`): an
//! `Intent` is the ticket of one action, made only by `ActionJournal::intent`
//! / `intents` after the signed intent row, and answered by
//! `Intent::finish` (or, dropped unanswered, by an abandoned outcome its
//! `Drop` writes). What this test holds:
//!
//! 1. **Every acting entry point takes a ticket** ([`TICKETED`]): the
//!    executor's, the low-level actions it calls, the isolator's engage —
//!    their signatures name `Intent`, so no caller compiles without one.
//! 2. **A ticket is made only by the journal**: `Intent`'s fields are
//!    private, and no code outside `journal.rs` builds one (no struct
//!    literal, no constructor of its own) — the tests' tickets come from a
//!    memory journal, the same rows.
//! 3. **The actions outside the ticketed entry points** ([`UNTICKETED`]: a
//!    signal the exec quarantine sends itself, the soft egress block's
//!    release, the copy-on-write guard's automatic restore) are called only
//!    from the files listed, each from a function that makes its ticket
//!    first (`.intent(`) and answers it (`.finish(`) — unconditionally
//!    (the review of #635, P3-1): no optional journal, no ticket made in a
//!    closure or a branch the action is not in, no caller passing `None`.
//! 4. **Every function that makes a ticket answers it**: in production code
//!    each function holding `.intent(`/`.intents(` holds `finish` too (or
//!    hands the tickets to a function that does, listed).
//!
//! The runtime half — each path writes both rows — is the dispatcher's,
//! the actuator's and the exec quarantine's own tests (the rows of a memory
//! journal), and the journal's (a crash between the two answered at the next
//! start). Lexical, as the decision path's guard: it reads the code's text,
//! comments blanked, test items left out.

mod support;

use std::path::Path;

use support::{matching_brace, production, repo_root, strip_comments};

/// The acting entry points that take a ticket: (file, the function's head).
const TICKETED: &[(&str, &str)] = &[
    (
        "crates/nn-linux/src/response/executor.rs",
        "pub fn execute_for(",
    ),
    (
        "crates/nn-linux/src/response/executor.rs",
        "pub fn execute_for_started(",
    ),
    (
        "crates/nn-linux/src/response/executor.rs",
        "pub fn execute(",
    ),
    (
        "crates/nn-linux/src/response/executor.rs",
        "pub fn execute_started(",
    ),
    (
        "crates/nn-linux/src/response/executor.rs",
        "pub fn execute_on(",
    ),
    (
        "crates/nn-linux/src/response/executor.rs",
        "pub fn quarantine_handle(",
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "pub fn kill_process(",
    ),
    ("crates/nn-linux/src/response/kill.rs", "pub fn kill_ref("),
    (
        "crates/nn-linux/src/response/kill.rs",
        "pub fn kill_process_tree(",
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "pub fn kill_process_tree_guarded(",
    ),
    ("crates/nn-linux/src/response/kill.rs", "pub fn kill_tree("),
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        "pub fn block_outbound_for_pid(",
    ),
    (
        "crates/nn-linux/src/response/throttle.rs",
        "pub fn throttle_pid(",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        "pub fn quarantine_process_binary(",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        "pub fn quarantine_handle(",
    ),
    ("crates/nn-linux/src/response/file_caps.rs", "pub fn strip("),
    (
        "crates/nn-linux/src/anti_tamper/network_isolate.rs",
        "pub fn engage(",
    ),
];

/// The actions not behind a ticketed entry point: the call, and the files
/// that may make it — each from a function that makes its ticket and
/// answers it (`None`: an operator's verb, signed by the admin socket's own
/// audit row — not an automated response).
/// The files that may make an untick action, each with the function that
/// must hold its ticket (`None`: see [`UNTICKETED`]).
type Sites = &'static [(&'static str, Option<&'static str>)];

const UNTICKETED: &[(&str, Sites)] = &[
    (
        ".signal(libc::SIGKILL)",
        &[
            // inside `kill_one`, reached only through the ticketed kills
            ("crates/nn-linux/src/response/kill.rs", None),
            // lot 317: the decision's and the owed kill's one helper (its
            // ticket made and answered there, as in `carry_out` before);
            // lot M4 (#633): shared by the controller and the stop's sweep
            ("agent/src/execq/release.rs", Some("fn kill_with_intent(")),
        ],
    ),
    (
        "release_blocked_pid(",
        &[
            (
                "crates/nn-linux/src/combat/actuator.rs",
                Some("fn soft_egress_clear("),
            ),
            // `nn-admin release`: the operator's verb, audited by the socket
            ("agent/src/admin/handlers/response.rs", None),
        ],
    ),
    (
        "&RestoreBy::Auto {",
        &[("agent/src/cow/mod.rs", Some("fn on_neutralized("))],
    ),
];

/// Functions that make tickets and hand them to another that answers them.
const HANDED_ON: &[(&str, &str, &str)] = &[(
    "agent/src/pipeline/dispatch.rs",
    "fn work(",
    "run_one(s, &t.job, intent)",
)];

fn code_of(rel: &str) -> String {
    let text =
        std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    production(&strip_comments(&text))
}

/// The function whose head is `head` in `code`, to its closing brace.
fn function<'a>(code: &'a str, head: &str) -> &'a str {
    let at = code
        .find(head)
        .unwrap_or_else(|| panic!("`{head}` not found"));
    let open = at + code[at..].find('{').expect("a body");
    &code[at..open + matching_brace(&code[open..])]
}

/// The function that holds byte `at` of `code` is a test (`#[test]` on it):
/// a test module the lexical blanking missed (a string with a lone brace)
/// is still a test's.
fn in_test_fn(code: &str, at: usize) -> bool {
    let f = enclosing(code, at);
    let start = f.as_ptr() as usize - code.as_ptr() as usize;
    let before = &code[..start];
    let from = before.rfind(['}', ';']).map_or(0, |i| i + 1);
    before[from..].contains("#[test]")
}

/// The function that holds byte `at` of `code`: the last `fn ` head before
/// it whose body covers it.
fn enclosing(code: &str, at: usize) -> &str {
    let mut best: Option<&str> = None;
    for (i, _) in code.match_indices("fn ") {
        if i > at {
            break;
        }
        let Some(rel) = code[i..].find('{') else {
            continue;
        };
        let open = i + rel;
        let end = open + matching_brace(&code[open..]);
        if at < end {
            best = Some(&code[i..end]);
        }
    }
    best.unwrap_or_else(|| panic!("no function holds byte {at}"))
}

/// The production `.rs` files of the crates whose code can act.
fn acting_code() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in [
        "agent/src",
        "crates/nn-linux/src",
        "crates/nn-core/src",
        "watchdog/src",
    ] {
        support::rs_files(&root.join(dir), &mut files);
    }
    files
        .into_iter()
        .filter_map(|f| {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (!support::is_test_file(&rel)).then(|| {
                let text = std::fs::read_to_string(&f).unwrap();
                (rel, production(&strip_comments(&text)))
            })
        })
        .collect()
}

/// Rule 1: every acting entry point takes a ticket.
fn untick_entry_points(code: &dyn Fn(&str) -> String) -> Vec<String> {
    let mut out = Vec::new();
    for (file, head) in TICKETED {
        let c = code(file);
        let Some(at) = c.find(head) else {
            out.push(format!("{file}: `{head}` not found"));
            continue;
        };
        let sig = &c[at..at + c[at..].find('{').unwrap_or(0)];
        if !sig.contains("Intent") {
            out.push(format!(
                "{file}: `{head}` acts without a ticket (`&Intent`)"
            ));
        }
    }
    out
}

#[test]
fn every_acting_entry_point_takes_a_ticket() {
    let v = untick_entry_points(&|f| code_of(f));
    assert!(v.is_empty(), "{v:#?}");
}

/// Rule 2: only the journal makes a ticket.
#[test]
fn only_the_journal_makes_a_ticket() {
    let journal = code_of("crates/nn-linux/src/response/journal.rs");
    let def = function(&journal, "pub struct Intent {");
    for line in def.lines().skip(1) {
        let l = line.trim();
        assert!(
            !l.starts_with("pub ") || l.starts_with("pub struct"),
            "an Intent field is public: `{l}`"
        );
    }
    // private fields: no struct literal compiles outside the journal; the
    // journal's own functions that give a ticket are the two intents' (and
    // the tests' door below)
    let givers: Vec<&str> = journal
        .match_indices("fn ")
        .filter_map(|(i, _)| {
            let head = &journal[i..i + journal[i..].find('{').unwrap_or(0)];
            (head.contains("-> Intent") || head.contains("-> Vec<Intent>"))
                .then(|| head.split('(').next().unwrap_or(head))
        })
        .collect();
    assert_eq!(
        givers,
        ["fn intent", "fn intents"],
        "the journal's ticket givers"
    );
    for (rel, text) in acting_code() {
        if rel == "crates/nn-linux/src/response/journal.rs" {
            continue;
        }
        assert!(
            !text.contains("impl Intent") && !text.contains("fn test_intent("),
            "{rel}: a ticket door outside the journal"
        );
    }
    // the tests' door is the journal's own and test-only
    let full = std::fs::read_to_string(repo_root().join("crates/nn-linux/src/response/journal.rs"))
        .unwrap();
    let door = full
        .find("pub(crate) fn test_intent(")
        .expect("the tests' door");
    assert!(
        full[..door].trim_end().ends_with("#[cfg(test)]"),
        "test-only"
    );
}

/// Rule 3: the actions outside the ticketed entry points are called only
/// where listed, each from a function that makes its ticket and answers it.
fn untick_actions(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (call, allowed) in UNTICKETED {
        for (rel, text) in files {
            for (at, _) in text.match_indices(call) {
                if text[..at].ends_with("fn ") || text[..at].ends_with("pub fn ") {
                    continue; // its definition
                }
                if in_test_fn(text, at) {
                    continue;
                }
                match allowed.iter().find(|(f, _)| f == rel) {
                    None => out.push(format!("{rel}: `{call}` outside the listed files")),
                    Some((_, None)) => {}
                    Some((_, Some(head))) => {
                        let f = enclosing(text, at);
                        let call_at = at - (f.as_ptr() as usize - text.as_ptr() as usize);
                        if !f.starts_with(head) {
                            out.push(format!("{rel}: `{call}` outside `{head}`"));
                        } else if !(f.contains(".intent(") && f.contains(".finish(")) {
                            out.push(format!(
                                "{rel}: `{call}` in `{head}` without its ticket made and answered"
                            ));
                        } else if let Some(why) = conditional_ticket(f, call_at) {
                            out.push(format!(
                                "{rel}: `{call}` in `{head}` with a ticket made conditionally: {why}"
                            ));
                        }
                    }
                }
            }
        }
        // a caller that passes no journal to a helper that makes the
        // ticket (the review of #635: `kill_with_intent(None, ..)`)
        for (_, head) in allowed.iter().filter_map(|(f, h)| h.map(|h| (f, h))) {
            let name = head.trim_start_matches("fn ");
            for (rel, text) in files {
                for (at, _) in text.match_indices(name) {
                    let args = text[at + name.len()..].trim_start();
                    if args.starts_with("None") && !in_test_fn(text, at) {
                        out.push(format!("{rel}: `{name}` called without a journal (`None`)"));
                    }
                }
            }
        }
    }
    out
}

/// The review of #635 (P3-1): why the ticket of the function `f` (its text
/// from its head), whose action is at byte `call_at`, is not made
/// unconditionally before the action — `None` when it is. A journal that
/// is an `Option` (a caller passes `None`, the action runs without its
/// intent row), a ticket made through `.map(..)`/`.and_then(..)` or in a
/// closure, or one made in a block deeper than the action's (a branch the
/// action does not need).
fn conditional_ticket(f: &str, call_at: usize) -> Option<String> {
    let open = f.find('{').unwrap_or(f.len());
    let optional = f.match_indices("Option<").any(|(i, _)| {
        let rest = &f[i + "Option<".len()..];
        let end = rest.find('>').unwrap_or(rest.len());
        rest[..end].contains("Journal")
    });
    if optional {
        return Some("an optional journal (`Option<..Journal>`)".into());
    }
    let action = depth_at(f, call_at);
    let mut made_before = false;
    for (at, _) in f.match_indices(".intent(") {
        if at < open {
            continue;
        }
        let from = f[..at].rfind([';', '{', '}']).map_or(0, |i| i + 1);
        let stmt = &f[from..at];
        if stmt.contains(".map(") || stmt.contains(".and_then(") || stmt.contains('|') {
            return Some(format!("made in a closure or a map: `{}`", stmt.trim()));
        }
        if at < call_at && depth_at(f, at) <= action {
            made_before = true;
        }
    }
    (!made_before).then(|| "not made before the action, at its depth or shallower".into())
}

/// The depth of byte `at` of `f` in braces (string and char literals
/// skipped).
fn depth_at(f: &str, at: usize) -> usize {
    let b = f.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < at.min(b.len()) {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    depth
}

#[test]
fn the_other_actions_are_ticketed_where_they_are() {
    let files = acting_code();
    let v = untick_actions(&files);
    assert!(v.is_empty(), "{v:#?}");
    // every listed site exists (a list that names nothing guards nothing)
    for (call, allowed) in UNTICKETED {
        for (f, _) in *allowed {
            let text = files
                .iter()
                .find(|(r, _)| r == f)
                .unwrap_or_else(|| panic!("{f}: not in the scan"));
            assert!(text.1.contains(call), "{f}: no `{call}` any more");
        }
    }
}

/// Rule 4: a function that makes a ticket answers it (or hands it on to one
/// that does, listed).
fn unanswered(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, text) in files {
        if rel == "crates/nn-linux/src/response/journal.rs" {
            continue;
        }
        for marker in [".intent(", ".intents("] {
            for (at, _) in text.match_indices(marker) {
                if in_test_fn(text, at) {
                    continue;
                }
                let f = enclosing(text, at);
                if f.contains(".finish(")
                    || f.contains("finish_deferred(")
                    || f.contains("Self::finish(")
                {
                    continue;
                }
                let handed = HANDED_ON
                    .iter()
                    .any(|(file, head, to)| file == rel && f.starts_with(head) && f.contains(to));
                // a helper that makes the ticket and returns it to its caller
                let returns =
                    f.contains("-> Intent") || f.contains("-> crate::response::journal::Intent");
                if !handed && !returns {
                    out.push(format!(
                        "{rel}: a ticket made in `{}` is never answered",
                        f.lines().next().unwrap_or("").trim()
                    ));
                }
            }
        }
    }
    out
}

#[test]
fn every_ticket_made_is_answered() {
    let files = acting_code();
    let v = unanswered(&files);
    assert!(v.is_empty(), "{v:#?}");
    // the helpers that return a ticket are answered by their callers
    for (rel, text) in &files {
        for helper in ["self.intent(", "Self::intent("] {
            for (at, _) in text.match_indices(helper) {
                if in_test_fn(text, at) {
                    continue;
                }
                let f = enclosing(text, at);
                if f.contains("-> Intent") || f.contains("journal::Intent {") {
                    continue;
                }
                assert!(
                    f.contains(".finish(") || f.contains("Self::finish("),
                    "{rel}: `{}` takes a ticket and never answers it",
                    f.lines().next().unwrap_or("").trim()
                );
            }
        }
    }
}

/// Each rule fails on a planted violation.
#[test]
fn the_rules_fail_on_planted_violations() {
    // 1: an entry point that drops its ticket
    let v = untick_entry_points(&|f| {
        let c = code_of(f);
        if f.ends_with("throttle.rs") {
            c.replacen("_intent: &super::journal::Intent,", "", 1)
        } else {
            c
        }
    });
    assert!(v.len() == 1 && v[0].contains("throttle_pid"), "{v:#?}");
    // 3: a SIGKILL sent from a new place, and one moved out of its function
    let mut files = acting_code();
    files.push((
        // (a planted file: its name built, so the path ratchet does not
        // look for it on disk)
        format!("agent/src/{}.rs", "new_response"),
        "fn f(p: &ProcRef) { let _ = p.signal(libc::SIGKILL); }".to_string(),
    ));
    let v = untick_actions(&files);
    assert!(v.len() == 1 && v[0].contains("new_response.rs"), "{v:#?}");
    let mut files = acting_code();
    let execq = files
        .iter_mut()
        .find(|(r, _)| r == "agent/src/execq/release.rs")
        .unwrap();
    execq
        .1
        .push_str("\nfn sneak(p: &ProcRef) { let _ = p.signal(libc::SIGKILL); }\n");
    let v = untick_actions(&files);
    assert!(
        v.len() == 1 && v[0].contains("outside `fn kill_with_intent(`"),
        "{v:#?}"
    );
    // 3, the review of #635 (P3-1): the kill's ticket made conditionally —
    // an optional journal (a caller passing `None`), a ticket in a map, a
    // ticket in a branch the kill is not in — each fails
    let plant = |from: &str, to: &str| {
        let mut files = acting_code();
        let release = files
            .iter_mut()
            .find(|(r, _)| r == "agent/src/execq/release.rs")
            .unwrap();
        assert!(release.1.contains(from), "the plant's anchor: `{from}`");
        release.1 = release.1.replacen(from, to, 1);
        untick_actions(&files)
    };
    let v = plant(
        "journal: &ActionJournal,\n    pr: &ProcRef,",
        "journal: Option<&ActionJournal>,\n    pr: &ProcRef,",
    );
    assert!(
        v.len() == 1 && v[0].contains("an optional journal"),
        "{v:#?}"
    );
    let v = plant(
        "let intent = journal.intent(",
        "let intent = Some(journal).map(|j| j.intent(",
    );
    assert!(
        v.len() == 1 && v[0].contains("in a closure or a map"),
        "{v:#?}"
    );
    let v = plant(
        "let intent = journal.intent(intent_named(\"KillProcess\", pid, path));",
        "if held { let _t = journal.intent(intent_named(\"KillProcess\", pid, path)); }",
    );
    assert!(
        v.len() == 1 && v[0].contains("not made before the action"),
        "{v:#?}"
    );
    // and a caller that passes no journal (the reviewer's plant)
    let mut files = acting_code();
    files.push((
        format!("agent/src/{}.rs", "no_journal"),
        "fn h(p: &ProcRef) { let _ = kill_with_intent(None, p, 1, \"x\", true); }".to_string(),
    ));
    let v = untick_actions(&files);
    assert!(
        v.len() == 1 && v[0].contains("no_journal.rs") && v[0].contains("without a journal"),
        "{v:#?}"
    );
    // 4: a ticket made and dropped
    let mut files = acting_code();
    files.push((
        format!("agent/src/{}.rs", "forgetful"),
        "fn g(j: &ActionJournal) { let t = j.intent(row); act(&t); }".to_string(),
    ));
    let v = unanswered(&files);
    assert!(v.len() == 1 && v[0].contains("forgetful.rs"), "{v:#?}");
    let _ = Path::new("");
}
