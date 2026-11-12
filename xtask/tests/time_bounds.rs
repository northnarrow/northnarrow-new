//! Lot 319 (external bug hunt BUG12's partial, and its mini-hunt): a time
//! bound held as `u64` is never cast to `i64` with `as` — and a ratchet so
//! it stays so.
//!
//! `u64::MAX as i64` is -1. Lot 295 compared the heartbeat verifier's
//! silence and stall bounds without the cast (`heartbeat::past`); the skew
//! bound kept it (`cfg.max_skew_secs as i64`: `--max-skew-secs
//! 18446744073709551615` read a beat stamped this very second as a clock
//! running ahead), and so did two read verbs' `since`/`until` (`unix_ts as
//! i64`, `s as i64`: a bound of 2^63 or more kept every row instead of
//! none). Each compares or converts without the cast now (`past`,
//! `i64::try_from`).
//!
//! The rule: in production code, no value named for a time or a bound is
//! cast `as i64` — a name (`…secs…`, `ts`, `…_ts…`, `…_ns`, `…unix…`,
//! `since`, `until`, `…skew…`, `…silence…`, `…bound…`, `…ttl…`,
//! `…deadline…`, `…timeout…`, `…millis…`, `…nanos…`, `…timestamp…`), a
//! call whose method says one (`d.as_secs() as i64`), a parenthesised
//! expression that names one (`(hours * 3600) as i64`), and a closure's
//! variable cast in `.map(|s| s as i64)` on a receiver that names one (the
//! review of #544, F4: `extra.since_unix_ts.map(|s| s as i64)`, the cast
//! the rule was written for, passed it). The scan is lexical (comments
//! blanked, test items and test files left out), over every crate's
//! sources; it is shown failing on planted violations.

mod support;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The sources scanned: every crate of the workspace.
const ROOTS: &[&str] = &[
    "crates",
    "agent/src",
    "watchdog/src",
    "common",
    "cli",
    "scan",
];

/// Whether an identifier says a time or a bound.
fn is_time_name(ident: &str) -> bool {
    const WORDS: &[&str] = &[
        "secs",
        "unix",
        "since",
        "until",
        "skew",
        "silence",
        "bound",
        "ttl",
        "deadline",
        "timeout",
        "millis",
        "nanos",
        "timestamp",
    ];
    let id = ident.to_ascii_lowercase();
    WORDS.iter().any(|w| id.contains(w))
        || id == "ts"
        || id.starts_with("ts_")
        || id.ends_with("_ts")
        || id.contains("_ts_")
        || id.ends_with("_ns")
}

fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The identifier chain (`a.b.c`) that ends `head`.
fn trailing_chain(head: &str) -> &str {
    let start = head
        .rfind(|c: char| !(ident_char(c) || c == '.'))
        .map_or(0, |i| i + 1);
    &head[start..]
}

/// The casts the rule finds in `code` (see the module doc).
fn time_casts(code: &str) -> Vec<String> {
    let code = production(&strip_comments(code));
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(" as i64") {
        let end = from + at;
        from = end + " as i64".len();
        let head = code[..end].trim_end();
        let found = if let Some(call) = head.strip_suffix("()") {
            // a call with no argument: the method names it
            let chain = trailing_chain(call);
            chain
                .split('.')
                .any(is_time_name)
                .then(|| format!("{chain}() as i64"))
        } else if head.ends_with(')') {
            // a parenthesised expression: any identifier in it
            let open = matching_open(head);
            let inner = &head[open..];
            let named = inner
                .split(|c: char| !ident_char(c))
                .any(|w| !w.is_empty() && is_time_name(w));
            let callee = trailing_chain(&head[..open]);
            (named && callee.is_empty()).then(|| format!("{inner} as i64"))
        } else {
            let chain = trailing_chain(head);
            if chain.split('.').next_back().is_some_and(is_time_name) {
                Some(format!("{chain} as i64"))
            } else {
                closure_on_time(head, chain)
                    .map(|recv| format!("{recv}.map(|{chain}| {chain} as i64)"))
            }
        };
        out.extend(found);
    }
    out
}

/// The byte index of the `(` that opens the `)` ending `head`.
fn matching_open(head: &str) -> usize {
    let mut depth = 0i32;
    for (i, c) in head.char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    0
}

/// `head` ends `….map(|var| var` on a receiver whose name says a time: the
/// receiver.
fn closure_on_time<'a>(head: &'a str, var: &str) -> Option<&'a str> {
    if var.is_empty() || var.contains('.') {
        return None;
    }
    let before = head.strip_suffix(var)?.trim_end();
    let before = before.strip_suffix('|')?.trim_end();
    let before = before.strip_suffix(var)?.trim_end();
    let before = before.strip_suffix('|')?.trim_end();
    let before = before.strip_suffix('(')?.trim_end();
    let recv = before
        .strip_suffix(".map")
        .or_else(|| before.strip_suffix(".and_then"))
        .or_else(|| before.strip_suffix(".map_or"))?;
    let chain = trailing_chain(recv);
    chain
        .split('.')
        .next_back()
        .is_some_and(is_time_name)
        .then_some(chain)
}

#[test]
fn no_time_bound_is_cast_to_i64() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in ROOTS {
        rs_files(&root.join(dir), &mut files);
    }
    let mut found = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&rel)
            || rel.contains("/tests/")
            || rel.contains("/benches/")
            || rel.contains("/target/")
        {
            continue;
        }
        let Ok(code) = std::fs::read_to_string(&f) else {
            continue;
        };
        for c in time_casts(&code) {
            found.push(format!("{rel}: {c}"));
        }
    }
    assert!(
        found.is_empty(),
        "a time bound cast `as i64` (`u64::MAX as i64` is -1): {found:?} — compare \
         without the cast (`heartbeat::past`) or convert with `i64::try_from`"
    );
}

#[test]
fn the_rule_finds_a_planted_cast() {
    assert_eq!(
        time_casts("fn f(cfg: &C, d: i64) -> bool { d > cfg.max_skew_secs as i64 }"),
        ["cfg.max_skew_secs as i64"]
    );
    assert_eq!(
        time_casts("fn g(unix_ts: u64) { let _ = ts(unix_ts as i64); }"),
        ["unix_ts as i64"]
    );
    assert_eq!(
        time_casts("fn h(x: Option<u64>) { let _ = x.map(|since| since as i64); }"),
        ["since as i64"]
    );
    // the review of #544 (F4): the cast the rule was written for
    assert_eq!(
        time_casts("fn d(e: &E) { let _ = e.since_unix_ts.map(|s| s as i64); }"),
        ["e.since_unix_ts.map(|s| s as i64)"]
    );
    assert_eq!(
        time_casts("fn d(e: &E) { let _ = e.until.map(|v| v as i64); }"),
        ["e.until.map(|v| v as i64)"]
    );
    // a call naming a time
    assert_eq!(
        time_casts("fn n(d: Duration) -> i64 { d.as_secs() as i64 }"),
        ["d.as_secs() as i64"]
    );
    assert_eq!(
        time_casts("fn n(d: Duration) -> i64 { d.as_millis() as i64 }"),
        ["d.as_millis() as i64"]
    );
    // names: ts, …_ns, ttl, deadline, timeout
    for (code, want) in [
        ("fn a(ts: u64) -> i64 { ts as i64 }", "ts as i64"),
        (
            "fn a(r: R) -> i64 { r.timestamp_ns as i64 }",
            "r.timestamp_ns as i64",
        ),
        ("fn a(c: C) -> i64 { c.ttl as i64 }", "c.ttl as i64"),
        (
            "fn a(deadline: u64) -> i64 { deadline as i64 }",
            "deadline as i64",
        ),
        (
            "fn a(c: C) -> i64 { c.timeout_ms as i64 }",
            "c.timeout_ms as i64",
        ),
    ] {
        assert_eq!(time_casts(code), [want], "{code}");
    }
    // a parenthesised expression naming one
    assert_eq!(
        time_casts("fn p(c: C) -> i64 { (c.retention_secs * 2) as i64 }"),
        ["(c.retention_secs * 2) as i64"]
    );
    // a count, a closure over a count, a call's argument, a comment, a
    // test item: not the rule's
    assert!(time_casts("fn k(n: usize) -> i64 { n as i64 }").is_empty());
    assert!(time_casts("fn k(v: Vec<u64>) { let _ = v.len().map(|s| s as i64); }").is_empty());
    assert!(time_casts("fn k(x: u32) -> i64 { f(x.counts) as i64 }").is_empty());
    assert!(time_casts("fn k(p: P) -> i64 { p.parts as i64 }").is_empty());
    assert!(time_casts("// skew_secs as i64\nfn x() {}").is_empty());
    assert!(time_casts(
        "fn x() {}\n#[cfg(test)]\nmod tests { fn t(secs: u64) { let _ = secs as i64; } }"
    )
    .is_empty());
}
