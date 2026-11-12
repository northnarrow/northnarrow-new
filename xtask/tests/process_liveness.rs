//! Lot 317 (third bug hunt, BUG-124): a capture that failed is not a
//! process that ended — a ratchet.
//!
//! `ProcRef::is_live()` is false for a process that has exited and for one
//! the agent could not capture (`pidfd_open` out of descriptors or memory,
//! a failure of the agent's). The exec quarantine read `!is_live()` as
//! "ended" (`agent/src/execq/controller.rs`, four sites): a held process it
//! could not capture got no `SIGCONT` and no `SIGKILL`, its pid left the
//! kernel's stopped map — nothing would ever resume it — and the record
//! said "ended while held" or "already ended". `ProcRef::liveness()` tells
//! the three answers apart (`Live`, `Gone`, `Uncaptured(errno)`), and a
//! `match` on it must handle the third.
//!
//! The rule: in the production code of the agent and the crates it is
//! built from (`agent/src`, `crates/*/src`, `watchdog/src`,
//! `antitamper-bpf/src`; test files and `#[cfg(test)]` items aside),
//! `is_live` is named only where it is defined, in
//! `crates/nn-linux/src/response/proc_ref.rs` (the helper), and at the
//! sites [`REVIEWED`] lists with why the answer there cannot come from a
//! failed capture. Every other caller asks `liveness()`. An entry whose
//! site is gone fails too, and the rule is shown failing on a planted
//! violation. The scan is lexical (comments blanked, strings kept).
//!
//! The review of #541 (F4): the same confusion, spelled with the new type —
//! `liveness() != Liveness::Live`, `!matches!(…, Liveness::Live)`, `if let
//! Liveness::Live = …` with an `else` — passed the rule. So `Liveness::Live`
//! is named only as the pattern of a `match` arm (`Liveness::Live =>`, with a
//! guard, in an or-pattern or a tuple), never in a comparison, `matches!` or
//! `if let`; no `Liveness` variant is compared with `!=` (two answers read as
//! one); the sites [`REVIEWED`] lists aside. The re-check of #541: nor does a
//! `match` with a `Liveness` arm end in a catch-all (`_ =>`, or a bare
//! binding), which folds `Uncaptured` into whatever it does.

mod support;

use std::fs;
use std::path::Path;

use support::{is_test_file, matching_brace, production, repo_root, rs_files, strip_comments};

/// The helper's file: `is_live`, `liveness` and the methods built on them.
const HELPER: &str = "crates/nn-linux/src/response/proc_ref.rs";

/// The sites outside the helper that still name `is_live`: (file, the
/// text on the line, why a failed capture cannot be the answer there).
const REVIEWED: &[(&str, &str, &str)] = &[
    (
        "crates/nn-linux/src/combat_host_linux.rs",
        "ProcRef::is_live(self)",
        "the adapter of nn-core's `Capture` trait to `ProcRef`: the same answer, under the \
         trait's name",
    ),
    (
        "crates/nn-core/src/combat/mod.rs",
        "r.has_fd() && !r.is_live()",
        "`close_exited`: a capture that holds its descriptor was captured — not running is \
         exited there; the descriptor is dropped, the identity kept",
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "root.liveness() == super::proc_ref::Liveness::Live",
        "the tree kill's root: only a live root takes the kill cgroup's path; any other goes \
         process by process, whose outcome carries the capture's error (a root not captured is \
         `Failed`, never `AlreadyGone`: the privileged test `a_tree_kill_whose_root_was_not_\
         captured_reports_its_error`)",
    ),
];

/// The production files the rule covers, repository-relative.
fn covered() -> Vec<(String, String)> {
    let root = repo_root();
    let mut dirs = vec![
        root.join("agent/src"),
        root.join("watchdog/src"),
        root.join("antitamper-bpf/src"),
    ];
    for e in fs::read_dir(root.join("crates")).unwrap() {
        let src = e.unwrap().path().join("src");
        if src.is_dir() {
            dirs.push(src);
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        let mut files = Vec::new();
        rs_files(&d, &mut files);
        for f in files {
            let rel = f.strip_prefix(&root).unwrap().display().to_string();
            if is_test_file(&rel) {
                continue;
            }
            out.push((rel, fs::read_to_string(&f).unwrap()));
        }
    }
    assert!(out.len() > 200, "only {} production files found", out.len());
    out
}

/// The lines of `src` (production code of file `rel`) that name `is_live`
/// outside a definition (`fn is_live`): (line number, the line trimmed).
fn uses(src: &str) -> Vec<(usize, String)> {
    let code = production(&strip_comments(src));
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (at, _) in code.match_indices("is_live") {
        let before = at.checked_sub(1).map(|i| b[i]);
        let after = b.get(at + "is_live".len()).copied();
        if before.is_some_and(ident) || after.is_some_and(ident) {
            continue;
        }
        let pre = code[..at].trim_end();
        if pre.ends_with("fn") && !pre[..pre.len() - 2].bytes().last().is_some_and(ident) {
            continue;
        }
        let start = code[..at].rfind('\n').map_or(0, |i| i + 1);
        let end = code[at..].find('\n').map_or(code.len(), |i| at + i);
        let line = code[..at].matches('\n').count() + 1;
        out.push((line, code[start..end].trim().to_string()));
    }
    out
}

/// Review F4: the lines of `src` (production code) that name a `Liveness`
/// variant other than as a `match` arm's pattern (`Liveness::Live`), or
/// compare one with `!=`: (line number, the line trimmed).
fn variant_uses(src: &str) -> Vec<(usize, String)> {
    let code = production(&strip_comments(src));
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (at, _) in code.match_indices("Liveness::") {
        if at > 0 && ident(b[at - 1]) {
            continue;
        }
        let name_at = at + "Liveness::".len();
        let name_len = code[name_at..].bytes().take_while(|c| ident(*c)).count();
        let variant = &code[name_at..name_at + name_len];
        let start = code[..at].rfind('\n').map_or(0, |i| i + 1);
        let end = code[at..].find('\n').map_or(code.len(), |i| at + i);
        // the path's own head: `super::proc_ref::Liveness::Live`
        let head = code[start..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .map_or(start, |i| start + i + 1);
        let pre = code[start..head].trim_end();
        let rest = code[name_at + name_len..end].trim_start();
        let line = code[..at].matches('\n').count() + 1;
        let text = code[start..end].trim().to_string();
        if pre.ends_with("!=") {
            out.push((line, text));
            continue;
        }
        if variant != "Live" {
            continue;
        }
        let pattern = !pre.contains("matches!(")
            && !pre.ends_with("let")
            && !pre.ends_with("==")
            && (rest.starts_with("=>")
                || rest.starts_with("if ")
                || rest.starts_with('|')
                || ((rest.starts_with(',') || rest.starts_with(')')) && rest.contains("=>")));
        if !pattern {
            out.push((line, text));
        }
    }
    out
}

/// The re-check of #541: the `match` blocks of `src` (production code) that
/// name a `Liveness` variant in an arm and have a catch-all arm — `_`, or a
/// bare binding — at their top level: (line of the `match`, its first line).
fn catch_all_matches(src: &str) -> Vec<(usize, String)> {
    let code = production(&strip_comments(src));
    let b = code.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    for (at, _) in code.match_indices("match ") {
        if at > 0 && ident(b[at - 1]) {
            continue;
        }
        let Some(open) = code[at..].find('{').map(|i| at + i) else {
            continue;
        };
        let block = &code[open..open + matching_brace(&code[open..])];
        let inner = &block[1..block.len().saturating_sub(1)];
        if !inner.contains("Liveness::") {
            continue;
        }
        if arm_patterns(inner).iter().any(|p| {
            let p = p.split(" if ").next().unwrap_or(p).trim();
            // `_`, or a bare binding (`other`): lower-case, digits, `_`
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                && !p.as_bytes()[0].is_ascii_digit()
        }) {
            let line = code[..at].matches('\n').count() + 1;
            let end = code[at..].find('\n').map_or(code.len(), |i| at + i);
            out.push((line, code[at..end].trim().to_string()));
        }
    }
    out
}

/// The top-level arm patterns of a `match` block's inside (string and char
/// literals skipped; brackets nested).
fn arm_patterns(inner: &str) -> Vec<String> {
    let b = inner.as_bytes();
    let (mut depth, mut i) = (0i32, 0usize);
    let mut out = Vec::new();
    let mut pat_start: Option<usize> = Some(0);
    let mut in_body = false;
    while i < b.len() {
        let c = b[i];
        match c {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth -= 1,
            b'}' => {
                depth -= 1;
                if depth == 0 && in_body {
                    // a block body closed: the next arm follows
                    in_body = false;
                    pat_start = Some(i + 1);
                }
            }
            b'=' if depth == 0 && !in_body && b.get(i + 1) == Some(&b'>') => {
                if let Some(s) = pat_start.take() {
                    out.push(
                        inner[s..i]
                            .trim()
                            .trim_start_matches(',')
                            .trim()
                            .to_string(),
                    );
                }
                in_body = true;
                i += 1;
            }
            b',' if depth == 0 && in_body => {
                in_body = false;
                pat_start = Some(i + 1);
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// The rule on one file: what it breaks, and the [`REVIEWED`] entries it
/// uses (by index).
fn check(rel: &str, src: &str, used: &mut [usize]) -> Vec<String> {
    if rel == HELPER {
        return Vec::new();
    }
    let mut bad = Vec::new();
    for (line, text) in catch_all_matches(src) {
        bad.push(format!(
            "{rel}:{line}: `{text}` — a `match` on `Liveness` with a catch-all arm folds \
             `Uncaptured` (a process the agent could not capture) into another answer: give it \
             an arm of its own"
        ));
    }
    for (line, text) in variant_uses(src) {
        match REVIEWED
            .iter()
            .position(|(f, snippet, _)| *f == rel && text.contains(snippet))
        {
            Some(i) => used[i] += 1,
            None => bad.push(format!(
                "{rel}:{line}: `{text}` — a `Liveness` read as two answers: `Live` against the \
                 rest takes a process not captured for one that ended. Match on all three (an arm \
                 for `Uncaptured`), or compare with `Liveness::Gone` (or list the site in \
                 REVIEWED with why)"
            )),
        }
    }
    for (line, text) in uses(src) {
        match REVIEWED
            .iter()
            .position(|(f, snippet, _)| *f == rel && text.contains(snippet))
        {
            Some(i) => used[i] += 1,
            None => bad.push(format!(
                "{rel}:{line}: `{text}` — `is_live()` is false for a process the agent could \
                 not capture too: ask `liveness()` and handle `Liveness::Uncaptured` (or list the \
                 site in REVIEWED with why a failed capture cannot be the answer there)"
            )),
        }
    }
    bad
}

#[test]
fn a_process_is_taken_for_ended_only_through_liveness() {
    let mut used = vec![0usize; REVIEWED.len()];
    let mut bad = Vec::new();
    let mut helper = false;
    for (rel, src) in covered() {
        helper |= rel == HELPER && src.contains("pub fn liveness(&self) -> Liveness");
        bad.extend(check(&rel, &src, &mut used));
    }
    assert!(helper, "{HELPER} no longer defines `liveness()`");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for (i, (file, snippet, _)) in REVIEWED.iter().enumerate() {
        assert_eq!(
            used[i], 1,
            "REVIEWED `{snippet}` in {file}: found {} time(s), not once (moved or gone: update \
             the list)",
            used[i]
        );
        assert!(
            Path::new(&repo_root().join(file)).is_file(),
            "{file}: no such file"
        );
    }
}

/// The exec quarantine's controller — where BUG-124 was — asks
/// `liveness()` at each of the sites that read `is_live()` on main: the
/// gate, the decision, the boot's recovery and the stop.
#[test]
fn the_exec_quarantine_asks_liveness_at_its_sites() {
    let src = fs::read_to_string(repo_root().join("agent/src/execq/controller.rs")).unwrap();
    let code = production(&strip_comments(&src));
    assert!(uses(&src).is_empty(), "{:?}", uses(&src));
    for (what, needle) in [
        (
            "the gate",
            "let gone = proc_ref.liveness() == Liveness::Gone;",
        ),
        (
            "the decision, the stop",
            "fn recheck(capture: &mut Capture, p: &mut Pending) -> Liveness",
        ),
        ("the owed decisions", "fn pay_owed(&mut self, now: Instant)"),
        ("the recovery", "match pr.liveness() {"),
    ] {
        assert!(code.contains(needle), "{what}: `{needle}` not found");
    }
}

/// The rule fails on a planted violation, and passes `liveness()`, the
/// definition and the reviewed spelling. (The planted files' names are
/// under no top-level directory: `path_liveness.rs` checks that every
/// repository path an xtask test names exists.)
#[test]
fn a_planted_violation_fails_the_rule() {
    let mut used = vec![0usize; REVIEWED.len()];
    let planted = "fn decide(p: &ProcRef) -> &str {\n    if !p.proc_ref.is_live() { \"ended\" } else { \"ok\" }\n}\n";
    let bad = check("planted/execq.rs", planted, &mut used);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].starts_with("planted/execq.rs:2:"), "{bad:?}");
    let as_fn =
        "fn f(v: &[ProcRef]) -> usize { v.iter().filter(|r| ProcRef::is_live(r)).count() }\n";
    assert_eq!(check("planted/x.rs", as_fn, &mut used).len(), 1);
    let path = "fn f(v: Vec<ProcRef>) -> Vec<ProcRef> { v.into_iter().filter(ProcRef::is_live).collect() }\n";
    assert_eq!(check("planted/x.rs", path, &mut used).len(), 1);
    let fine = "fn f(p: &ProcRef) -> bool { p.liveness() == Liveness::Gone }\nfn is_live(&self) -> bool { true }\nfn is_lively() {}\n";
    assert!(check("planted/x.rs", fine, &mut used).is_empty());
    let test_only =
        "#[cfg(test)]\nmod tests {\n    fn t(p: &ProcRef) { assert!(p.is_live()); }\n}\n";
    assert!(check("planted/x.rs", test_only, &mut used).is_empty());
    assert!(check(HELPER, planted, &mut used).is_empty(), "the helper");
    let reviewed = "fn close(r: &P) { if r.has_fd() && !r.is_live() {} }\n";
    assert!(check("crates/nn-core/src/combat/mod.rs", reviewed, &mut used).is_empty());
    assert!(
        !check("planted/combat.rs", reviewed, &mut used).is_empty(),
        "a reviewed spelling in another file"
    );
}

/// Review F4: the confusion spelled with `Liveness` fails the rule — a
/// negated `Live`, `matches!`, an `if let` with an `else`, a `Live` compared
/// with `==`, any `!=`; the arms of a `match` and a comparison with `Gone`
/// pass.
#[test]
fn a_planted_negation_of_liveness_fails_the_rule() {
    let mut used = vec![0usize; REVIEWED.len()];
    for planted in [
        "fn f(p: &ProcRef) -> bool { p.liveness() != Liveness::Live }\n",
        "fn f(p: &ProcRef) -> bool { !matches!(p.liveness(), Liveness::Live) }\n",
        "fn f(p: &ProcRef) -> bool { matches!(p.liveness(), Liveness::Live) }\n",
        "fn f(p: &ProcRef) -> &str { if let Liveness::Live = p.liveness() { \"a\" } else { \"ended\" } }\n",
        "fn f(p: &ProcRef) -> &str { if p.liveness() == Liveness::Live { \"a\" } else { \"ended\" } }\n",
        "fn f(p: &ProcRef) -> bool { p.liveness() != Liveness::Gone }\n",
        "fn f(p: &ProcRef) -> bool { p.liveness() != super::proc_ref::Liveness::Live }\n",
    ] {
        let bad = check("planted/liveness.rs", planted, &mut used);
        assert_eq!(bad.len(), 1, "{planted}: {bad:?}");
    }
    let fine = "fn f(p: &ProcRef) -> u8 {\n    match p.liveness() {\n        Liveness::Live if p.ok() => 1,\n        Liveness::Live | Liveness::Gone => 2,\n        Liveness::Uncaptured(_) => 3,\n    }\n}\nfn g(p: &ProcRef, a: A) -> u8 {\n    match (p.liveness(), a) {\n        (Liveness::Live, A::K) => 1,\n        (A::R, Liveness::Live) => 2,\n        (Liveness::Uncaptured(_), _) | (Liveness::Gone, _) => 3,\n    }\n}\nfn h(p: &ProcRef) -> bool { p.liveness() == Liveness::Gone }\nfn i(p: &ProcRef) -> bool { matches!(p.liveness(), Liveness::Uncaptured(_)) }\n";
    assert!(
        check("planted/liveness.rs", fine, &mut used).is_empty(),
        "{:?}",
        check("planted/liveness.rs", fine, &mut used)
    );
    let reviewed =
        "fn k(root: &ProcRef) { if root.liveness() == super::proc_ref::Liveness::Live {} }\n";
    assert!(check("crates/nn-linux/src/response/kill.rs", reviewed, &mut used).is_empty());
    assert_eq!(check("planted/kill.rs", reviewed, &mut used).len(), 1);
}

/// The re-check of #541: a `match` on `Liveness` that ends in a catch-all
/// fails the rule — `_`, a guard on it, a bare binding; full matches, a
/// tuple's `_` inside a pattern and a nested `match` on something else pass.
#[test]
fn a_planted_catch_all_arm_fails_the_rule() {
    let mut used = vec![0usize; REVIEWED.len()];
    for planted in [
        "fn f(p: &ProcRef) -> bool {\n    match p.liveness() {\n        Liveness::Live => false,\n        _ => true,\n    }\n}\n",
        "fn f(p: &ProcRef) -> bool {\n    match p.liveness() {\n        Liveness::Live => { false }\n        other => { log(other); true }\n    }\n}\n",
        "fn f(p: &ProcRef) -> u8 {\n    match p.liveness() { Liveness::Gone => 1, _ if p.x() => 2, Liveness::Live => 3, Liveness::Uncaptured(_) => 4 }\n}\n",
    ] {
        let bad = check("planted/arms.rs", planted, &mut used);
        assert_eq!(bad.len(), 1, "{planted}: {bad:?}");
    }
    let fine = "fn f(p: &ProcRef, a: A) -> u8 {\n    match (p.liveness(), a) {\n        (Liveness::Uncaptured(_), _) => 1,\n        (Liveness::Live, A::K) => match a { A::K => 2, _ => 3 },\n        (Liveness::Live, _) | (Liveness::Gone, _) => { let s = \"{,}=>\"; s.len() as u8 }\n    }\n}\nfn g(x: Option<u8>) -> u8 { match x { Some(v) => v, _ => 0 } }\n";
    let bad = check("planted/arms.rs", fine, &mut used);
    assert!(bad.is_empty(), "{bad:?}");
}
