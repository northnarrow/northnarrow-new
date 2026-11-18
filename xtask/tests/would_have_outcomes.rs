//! Lot 370 (F10-1): **no outcome is "done" when nothing was executed** — a
//! ratchet so a would-have (the no-enforcement gate: the `alpha` profile,
//! `--detect-only`) never again counts as a success or a containment.
//!
//! The bug it keeps closed: under `alpha` COMBAT's NEUTRALIZE killed and
//! quarantined nothing, yet the actuator counted the executor's
//! `WouldExecute` as containment (`Killed | AlreadyGone | WouldExecute` in
//! one `matches!`), and the ladder signed `combat_outcome` `success`, "N
//! contained", and logged "threat NEUTRALIZED and verified contained". The
//! action chain's tree count did the same with a descendant.
//!
//! Rules, over the production code of every product crate (comments
//! blanked, test items and test files left out; read with its whitespace
//! removed):
//!
//! 1. a would-have variant is never an alternative of the same pattern as a
//!    "done" one — `ExecutionOutcome::WouldExecute` with `Killed`,
//!    `AlreadyGone`, `Blocked`, `BlockedNewOnly`, `Quarantined`,
//!    `QuarantinedInPlace`, `Throttled`, `CapabilityStripped`;
//!    `NeutralizeOutcome::WouldHaveContained` with `Contained`;
//!    `Containment::WouldHave` with `Contained`; `OutcomeResult::WouldHave`
//!    and `ActionResult::WouldExecute` with `Success`;
//! 2. a match arm on a would-have variant never yields a done value:
//!    `…::Success`, `"success"`, `Containment::Contained`,
//!    `NeutralizeOutcome::Contained`, `SoftBlock::Blocked`.
//! 3. (the review of #578, N6) a `match` over a type with a would-have
//!    variant that never names it does not yield a done value from its
//!    `_ =>` arm — the would-have would fall into it unnamed;
//! 4. (the same) a negated `matches!` over such a type's variants that are
//!    none of them done names its would-have — `!matches!(o, Failed { .. } |
//!    Refused { .. })` is true for `WouldExecute`.
//!
//! Each rule is shown failing on main's shapes. Lexical, so not a proof: the
//! behaviour tests of the lot (nn-core's `no_combat_outcome_is_a_success_
//! with_a_held_action`, the actuator's and the agent's detect-only tests,
//! the posture golden's `detect-only` case) are the guard; this keeps the
//! shapes out.

mod support;

use support::{product_code, repo_root};

/// A would-have variant (the last path segment) and the done variants it
/// never shares a pattern with.
const PAIRS: &[(&str, &[&str])] = &[
    (
        "WouldExecute",
        &[
            "Killed",
            "AlreadyGone",
            "Blocked",
            "BlockedNewOnly",
            "Quarantined",
            "QuarantinedInPlace",
            "Throttled",
            "CapabilityStripped",
            "Success",
        ],
    ),
    ("WouldHaveContained", &["Contained"]),
    ("WouldHave", &["Contained", "Success"]),
];

/// What a would-have arm never yields.
const DONE_VALUES: &[&str] = &[
    "::Success",
    "\"success\"",
    "Containment::Contained",
    "NeutralizeOutcome::Contained",
    "SoftBlock::Blocked",
];

/// The review of #578 (N6): the types with a would-have variant, and that
/// variant (rules 3 and 4).
const WOULD_HAVE_OF: &[(&str, &str)] = &[
    ("ExecutionOutcome", "WouldExecute"),
    ("ActionResult", "WouldExecute"),
    ("NeutralizeOutcome", "WouldHaveContained"),
    ("Containment", "WouldHave"),
    ("OutcomeResult", "WouldHave"),
    ("IsolateOutcome", "WouldHave"),
];

/// The would-have variants of the types `text` names a variant of
/// (`Type::Variant`).
fn would_haves_named_in(text: &str) -> Vec<&'static str> {
    WOULD_HAVE_OF
        .iter()
        .filter(|(t, _)| {
            text.match_indices(&format!("{t}::")).any(|(i, _)| {
                i == 0 || !path_char(text.as_bytes()[i - 1]) || text.as_bytes()[i - 1] == b':'
            })
        })
        .map(|(_, w)| *w)
        .collect()
}

/// `text` names the variant `w` (a path's last segment).
fn names_variant(text: &str, w: &str) -> bool {
    text.match_indices(w).any(|(i, _)| {
        let b = text.as_bytes();
        let after = i + w.len();
        (i == 0 || !path_char(b[i - 1]) || b[i - 1] == b':')
            && (after >= b.len() || !path_char(b[after]))
    })
}

/// The arms of a match body (its braces' inside, whitespace removed):
/// each one's pattern (with its guard) and its body.
fn arms(b: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let mut depth = 0i32;
        let mut k = i;
        let mut arrow = None;
        while k + 1 < b.len() {
            match b[k] {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                b'=' if depth == 0 && b[k + 1] == b'>' => {
                    arrow = Some(k);
                    break;
                }
                _ => {}
            }
            k += 1;
        }
        let Some(a) = arrow else {
            break;
        };
        let start = a + 2;
        let end = if start < b.len() && b[start] == b'{' {
            close_of(b, start)
        } else {
            let mut depth = 0i32;
            let mut k = start;
            while k < b.len() {
                match b[k] {
                    b'{' | b'(' | b'[' => depth += 1,
                    b'}' | b')' | b']' => depth -= 1,
                    b',' if depth == 0 => break,
                    _ => {}
                }
                k += 1;
            }
            k
        };
        out.push((
            String::from_utf8_lossy(&b[i..a]).into_owned(),
            String::from_utf8_lossy(&b[start..end.min(b.len())]).into_owned(),
        ));
        i = end;
        if i < b.len() && b[i] == b',' {
            i += 1;
        }
    }
    out
}

/// The review of #578 (N6): rules 3 and 4 over `code` (comments blanked,
/// whitespace kept: a `match` is found by its keyword).
fn wildcard_violations(code: &str) -> Vec<(&'static str, String, String)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    // 3: a match naming a would-have type's variants but not its would-have,
    // whose `_` arm yields a done value
    for (at, _) in code.match_indices("match") {
        let before_ok = at == 0 || !path_char(bytes[at - 1]);
        let after = at + "match".len();
        let after_ok = after < bytes.len() && bytes[after].is_ascii_whitespace();
        if !before_ok || !after_ok {
            continue;
        }
        // the body: the first `{` outside brackets after the scrutinee
        let mut depth = 0i32;
        let mut k = after;
        let open = loop {
            if k >= bytes.len() {
                break None;
            }
            match bytes[k] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b'{' if depth == 0 => break Some(k),
                b';' if depth == 0 => break None,
                _ => {}
            }
            k += 1;
        };
        let Some(open) = open else {
            continue;
        };
        let close = close_of(bytes, open);
        let inside: Vec<u8> = bytes[open + 1..close.saturating_sub(1).max(open + 1)]
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let arms = arms(&inside);
        let patterns: String = arms.iter().map(|(p, _)| p.as_str()).collect();
        for w in would_haves_named_in(&patterns) {
            if names_variant(&patterns, w) {
                continue;
            }
            for (p, body) in &arms {
                if (p == "_" || p.starts_with("_if"))
                    && DONE_VALUES.iter().any(|v| body.contains(v))
                {
                    out.push((
                        "3: a would-have falls unnamed into a wildcard arm that is done",
                        w.to_string(),
                        body.clone(),
                    ));
                }
            }
        }
    }
    // 4: a negated `matches!` over a would-have type's variants that does
    // not name its would-have
    let compact: Vec<u8> = code.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let text = String::from_utf8_lossy(&compact).into_owned();
    for (at, _) in text.match_indices("!matches!(") {
        let open = at + "!matches!".len();
        let close = close_of(&compact, open);
        let inner = &text[open + 1..close.saturating_sub(1).max(open + 1)];
        // the pattern: past the scrutinee's top-level comma
        let mut depth = 0i32;
        let comma = inner.bytes().position(|c| {
            match c {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                _ => {}
            }
            c == b',' && depth == 0
        });
        let Some(comma) = comma else {
            continue;
        };
        let pattern = &inner[comma + 1..];
        for w in would_haves_named_in(pattern) {
            // negating done outcomes leaves the would-have not done: fine
            let done = PAIRS
                .iter()
                .find(|(x, _)| *x == w)
                .map_or(&[][..], |(_, d)| *d);
            if done.iter().any(|d| names_variant(pattern, d)) {
                continue;
            }
            if !names_variant(pattern, w) {
                out.push((
                    "4: a negated matches! is true for an unnamed would-have",
                    w.to_string(),
                    pattern.to_string(),
                ));
            }
        }
    }
    out
}

fn path_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b':'
}

/// The index past the bracket that closes the one at `open` (`{`, `(`,
/// `[`), or `s.len()`.
fn close_of(s: &[u8], open: usize) -> usize {
    let mut depth = 0i32;
    for (i, &c) in s.iter().enumerate().skip(open) {
        match c {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    s.len()
}

/// The index of the bracket that opens the one closing at `close - 1`.
fn open_of(s: &[u8], close: usize) -> usize {
    let mut depth = 0i32;
    let mut i = close;
    while i > 0 {
        i -= 1;
        match s[i] {
            b'}' | b')' | b']' => depth += 1,
            b'{' | b'(' | b'[' => {
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

/// The last segment of the path `s[from..to]` (`ExecutionOutcome::Killed`
/// → `Killed`).
fn last_segment(s: &[u8], from: usize, to: usize) -> String {
    let p = String::from_utf8_lossy(&s[from..to]).into_owned();
    p.rsplit("::").next().unwrap_or("").to_string()
}

/// The alternatives of the pattern holding the path that starts at
/// `start` and ends at `end` (its fields, if any, follow): each one's last
/// segment, and the index past the whole pattern.
fn alternatives(s: &[u8], start: usize, end: usize) -> (Vec<String>, usize) {
    let mut alts = Vec::new();
    // forward: this one's fields, then `|` alternatives
    let mut i = end;
    if i < s.len() && (s[i] == b'{' || s[i] == b'(') {
        i = close_of(s, i);
    }
    while i + 1 < s.len() && s[i] == b'|' && s[i + 1] != b'|' && (i == 0 || s[i - 1] != b'|') {
        let a = i + 1;
        let mut b = a;
        while b < s.len() && path_char(s[b]) {
            b += 1;
        }
        if b == a {
            break;
        }
        alts.push(last_segment(s, a, b));
        i = b;
        if i < s.len() && (s[i] == b'{' || s[i] == b'(') {
            i = close_of(s, i);
        }
    }
    let past = i;
    // backward: `|` alternatives before it
    let mut j = start;
    while j >= 2 && s[j - 1] == b'|' && s[j - 2] != b'|' {
        let mut b = j - 1;
        if b > 0 && (s[b - 1] == b'}' || s[b - 1] == b')') {
            b = open_of(s, b);
        }
        let mut a = b;
        while a > 0 && path_char(s[a - 1]) {
            a -= 1;
        }
        if a == b {
            break;
        }
        alts.push(last_segment(s, a, b));
        j = a;
    }
    (alts, past)
}

/// The body of the match arm whose pattern ends at `past` (when `=>`
/// follows it, an `if` guard skipped).
fn arm_body(s: &[u8], past: usize) -> Option<String> {
    let rest = &s[past..];
    let arrow = if rest.starts_with(b"=>") {
        past + 2
    } else if rest.starts_with(b"if") {
        let mut depth = 0i32;
        let mut k = past;
        loop {
            if k + 1 >= s.len() {
                return None;
            }
            match s[k] {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                b'=' if depth == 0 && s[k + 1] == b'>' => break k + 2,
                b',' | b';' if depth <= 0 => return None,
                _ => {}
            }
            k += 1;
        }
    } else {
        return None;
    };
    let end = if arrow < s.len() && (s[arrow] == b'{' || s[arrow] == b'(') {
        close_of(s, arrow)
    } else {
        let mut depth = 0i32;
        let mut k = arrow;
        while k < s.len() {
            match s[k] {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' if depth == 0 => break,
                b'}' | b')' | b']' => depth -= 1,
                b',' if depth == 0 => break,
                _ => {}
            }
            k += 1;
        }
        k
    };
    Some(String::from_utf8_lossy(&s[arrow..end]).into_owned())
}

/// The violations of `code` (production code, comments blanked): (rule,
/// the would-have variant, what it was found with).
fn violations(code: &str) -> Vec<(&'static str, String, String)> {
    let compact: Vec<u8> = code.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < compact.len() {
        if !path_char(compact[i]) || (i > 0 && path_char(compact[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i;
        while end < compact.len() && path_char(compact[end]) {
            end += 1;
        }
        i = end;
        let seg = last_segment(&compact, start, end);
        let Some((_, done)) = PAIRS.iter().find(|(w, _)| *w == seg) else {
            continue;
        };
        let (alts, past) = alternatives(&compact, start, end);
        for a in &alts {
            if done.contains(&a.as_str()) {
                out.push((
                    "1: a would-have shares a pattern with a done outcome",
                    seg.clone(),
                    a.clone(),
                ));
            }
        }
        if let Some(body) = arm_body(&compact, past) {
            for v in DONE_VALUES {
                if body.contains(v) {
                    out.push((
                        "2: a would-have arm yields a done value",
                        seg.clone(),
                        body.clone(),
                    ));
                }
            }
        }
    }
    out
}

#[test]
fn no_would_have_counts_as_done() {
    let code = product_code(&repo_root());
    assert!(code.len() > 100, "{} files", code.len());
    // the shapes the rules read are still where they were
    let actuator = &code["crates/nn-linux/src/combat/actuator.rs"];
    assert!(
        actuator.contains("WouldExecute"),
        "the actuator's would-have moved"
    );
    assert!(
        code["crates/nn-core/src/combat/actuator.rs"].contains("WouldHaveContained"),
        "the ladder's would-have moved"
    );
    let mut bad = Vec::new();
    for (rel, text) in &code {
        for (rule, would, with) in violations(text)
            .into_iter()
            .chain(wildcard_violations(text))
        {
            bad.push(format!("{rel}: rule {rule}: {would} with {with}"));
        }
    }
    assert!(
        bad.is_empty(),
        "an action the gate held is a would-have — never a success, never contained:\n{}",
        bad.join("\n")
    );
}

/// Each rule on the shape it forbids — main's code before lot 370.
#[test]
fn each_rule_fails_on_the_shape_it_forbids() {
    let planted: &[(&str, &str)] = &[
        // main's `SystemActuator::contained`
        (
            "matches!(outcome, ExecutionOutcome::Killed { .. }\n    | ExecutionOutcome::AlreadyGone { .. }\n    | ExecutionOutcome::WouldExecute { .. })",
            "1",
        ),
        // main's `journal_outcome` descendant count
        (
            "!matches!(o, ExecutionOutcome::Killed { .. } | ExecutionOutcome::AlreadyGone { .. } | ExecutionOutcome::WouldExecute { .. })",
            "1",
        ),
        // the would-have first
        ("matches!(o, X::WouldExecute { pid } | X::Blocked { pid })", "1"),
        ("match o { NeutralizeOutcome::WouldHaveContained | NeutralizeOutcome::Contained => {} }", "1"),
        ("match c { Containment::Contained | Containment::WouldHave => true, _ => false }", "1"),
        ("match r { OutcomeResult::Success | OutcomeResult::WouldHave => \"success\" }", "1"),
        // arms
        ("ExecutionOutcome::WouldExecute { .. } => (R::Success, None),", "2"),
        ("ExecutionOutcome::WouldExecute { .. } => SoftBlock::Blocked,", "2"),
        ("O::WouldExecute { .. } if dry => Containment::Contained,", "2"),
        ("NeutralizeOutcome::WouldHaveContained => { success = true; ActionResult::Success }", "2"),
        ("OutcomeResult::WouldHave => \"success\".to_string(),", "2"),
    ];
    for (code, rule) in planted {
        let v = violations(code);
        assert!(
            v.iter().any(|(r, _, _)| r.starts_with(rule)),
            "rule {rule} misses `{code}`: {v:?}"
        );
    }
    // the review of #578 (N6, named; its probe): a would-have folded into
    // "done" through a wildcard arm, or a negated `matches!` — the lexical
    // rules 1 and 2 passed both
    let wildcard: &[(&str, &str)] = &[
        (
            "pub fn p(o: &ExecutionOutcome) -> Containment {\n    match o {\n        ExecutionOutcome::Failed { .. }\n        | ExecutionOutcome::PermissionDenied { .. }\n        | ExecutionOutcome::Refused { .. } => Containment::NotContained,\n        _ => Containment::Contained,\n    }\n}",
            "3",
        ),
        (
            "let r = match outcome { OutcomeResult::Failure => \"failure\", _ => \"success\" };",
            "3",
        ),
        (
            "let done = !matches!(o, ExecutionOutcome::Failed { .. } | ExecutionOutcome::Refused { .. });",
            "4",
        ),
    ];
    for (code, rule) in wildcard {
        assert!(
            violations(code).is_empty(),
            "rules 1 and 2 were lexical: {code}"
        );
        let v = wildcard_violations(code);
        assert!(
            v.iter().any(|(r, _, _)| r.starts_with(rule)),
            "rule {rule} misses `{code}`: {v:?}"
        );
    }
    for ok in [
        "match o { ExecutionOutcome::Failed { .. } => Containment::NotContained, ExecutionOutcome::WouldExecute { .. } => Containment::WouldHave, _ => Containment::Contained }",
        "match o { ExecutionOutcome::Failed { .. } => Containment::NotContained, _ => Containment::NotContained }",
        "match kind { Kind::A => \"a\", _ => \"success\" }",
        "let failed = matches!(o, ExecutionOutcome::Failed { .. } | ExecutionOutcome::Refused { .. });",
        "let done = !matches!(o, ExecutionOutcome::Failed { .. } | ExecutionOutcome::WouldExecute { .. });",
        "let x = !matches!(k, Kind::A | Kind::B);",
        // the descendants not contained: a would-have among them
        "let left = !matches!(o, ExecutionOutcome::Killed { .. } | ExecutionOutcome::AlreadyGone { .. });",
    ] {
        assert_eq!(wildcard_violations(ok), Vec::new(), "{ok}");
    }
    // what stays allowed: a would-have with the outcomes that are not done,
    // its own arm, a constructor
    for ok in [
        "matches!(o, ExecutionOutcome::Failed { .. } | ExecutionOutcome::PermissionDenied { .. } | ExecutionOutcome::WouldExecute { .. })",
        "ExecutionOutcome::WouldExecute { .. } => (R::WouldExecute, Some(x)),",
        "ExecutionOutcome::WouldExecute { .. } => SoftBlock::NotNeeded(\"detect-only\"),",
        "return ExecutionOutcome::WouldExecute { pid };",
        "ExecutionOutcome::Killed { .. } | ExecutionOutcome::AlreadyGone { .. } => Containment::Contained,\nExecutionOutcome::WouldExecute { .. } => Containment::WouldHave,",
        "OutcomeResult::WouldHave => format!(\"would_have: {}\", s),",
        "if a || b { x } else if c || d { y }",
    ] {
        assert_eq!(violations(ok), Vec::new(), "{ok}");
    }
}
