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
//! The rule: in production code, no value named for a time or a bound
//! (`…secs…`, `…_ts…`, `…unix…`, `since`, `until`, `…skew…`,
//! `…silence…`, `…bound…`) is cast `as i64`. The scan is lexical (comments
//! blanked, test items and test files left out); it is shown failing on a
//! planted violation.

mod support;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The casts the rule finds in `code`: `<name> as i64` (the name possibly
/// closed by a call's `)`), where the name says a time or a bound.
fn time_casts(code: &str) -> Vec<String> {
    const WORDS: &[&str] = &[
        "secs", "_ts", "unix", "since", "until", "skew", "silence", "bound",
    ];
    let code = production(&strip_comments(code));
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(" as i64") {
        let end = from + at;
        from = end + " as i64".len();
        let head = code[..end].trim_end_matches(')');
        let start = head
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .map_or(0, |i| i + 1);
        let name = &head[start..];
        let last = name.rsplit('.').next().unwrap_or(name);
        if WORDS.iter().any(|w| last.contains(w)) {
            out.push(format!("{name} as i64"));
        }
    }
    out
}

#[test]
fn no_time_bound_is_cast_to_i64() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in ["crates", "agent/src", "watchdog/src"] {
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
    // a count, a comment, a test item: not the rule's
    assert!(time_casts("fn k(n: usize) -> i64 { n as i64 }").is_empty());
    assert!(time_casts("// skew_secs as i64\nfn x() {}").is_empty());
    assert!(time_casts(
        "fn x() {}\n#[cfg(test)]\nmod tests { fn t(secs: u64) { let _ = secs as i64; } }"
    )
    .is_empty());
}
