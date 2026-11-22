//! Lot 379 (the review of #586, P2-1): every kind of `integrity_drift` row
//! the product signs has an explicit class in `nn_evidence::held`.
//!
//! The status held every signed finding of a kind its tables did not name
//! as a degradation (`hold_of`'s default): an admin key left on the host,
//! the operator's own signed sysctl opt-out, strict overcommit, a stalled agent loop
//! made every default install `sensors: DEGRADED`, which hid a real
//! degradation behind it. Each kind is now in one table of
//! `crates/nn-evidence/src/held.rs` — evidence, a death, an event of the
//! run, a degradation, an advisory, or not held (and why) — and this scan
//! fails when a kind the product signs is in none.
//!
//! The scan reads the production code (comments blanked, test items left
//! out) at every place a kind is written:
//!
//! - a `kind:` field or a `"kind":` key — its string literals, and the
//!   `&str` constants it names (resolved through their `const`);
//! - the third argument of `ChainFinding::new` (the chains' findings);
//! - an expression that is neither (a variable, a field, a call) must be one
//!   of [`DYNAMIC`]: where its kinds come from — a producer function, whose
//!   literals and constants are read the same way, a kind passed through
//!   from one read at its construction, or a row that is no
//!   `integrity_drift` (its kinds then in [`OTHER_ROWS`]).
//!
//! Each rule is shown failing on a planted violation.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::{matching_brace, product_code, repo_root, string_literals};

const HELD: &str = "crates/nn-evidence/src/held.rs";

/// Kinds written at a kind position by rows that are no `integrity_drift`
/// (their op is another), and why each is not classified by `held`.
const OTHER_ROWS: &[(&str, &str)] = &[
    (
        "posture_trigger",
        "a posture transition's cause (op posture_*)",
    ),
    (
        "admin_force_posture",
        "a posture transition's cause (op posture_*)",
    ),
    (
        "debug_force_posture",
        "a posture transition's cause (op posture_*)",
    ),
    (
        "deferred",
        "the exec quarantine's controller rows (op execq_*)",
    ),
    (
        "recovered_at_boot",
        "the exec quarantine's controller rows (op execq_*)",
    ),
    (
        "stopping",
        "the exec quarantine's controller rows (op execq_*)",
    ),
    ("exec", "an exec policy record's subject (op execpol_*)"),
    ("map", "an exec policy record's subject (op execpol_*)"),
    ("record", "an exec policy record's subject (op execpol_*)"),
    ("ns", "a known resolver's record kind (DNS, no audit row)"),
    ("technique", "a contract's entry kind (no audit row)"),
    ("parse", "a worker's kind (no audit row)"),
    // the witness's notes and a key's certification: op `witness`
    // (`nn_linux::witness::WITNESS_OP`), never an `integrity_drift` row
    ("witness_key_certified", "signed under op witness, a note"),
    ("witness_note", "signed under op witness, a note"),
    ("watchdog_succession", "signed under op witness, a note"),
    ("roles_released", "signed under op witness, a note"),
    // lot 388: the watchdog's clean stop in the host's shutdown, a window or
    // the agent's own stop (`self_integrity::watchdog_exit_finding`)
    ("watchdog_stopped", "signed under op witness, a note"),
];

/// Where the kinds of a kind position that is no literal and no constant
/// come from.
enum Source {
    /// The literals and constants of this function (file, its head).
    Producer(&'static str, &'static str),
    /// A kind read at the construction of what it re-signs.
    PassThrough(&'static str),
    /// Not the kind of an `integrity_drift` row.
    NotDrift(&'static str),
}

/// The kind positions that are no literal and no constant: (file, the
/// expression as written, where its kinds come from).
const DYNAMIC: &[(&str, &str, Source)] = &[
    (
        "crates/nn-linux/src/self_integrity.rs",
        "f.kind",
        Source::PassThrough("record_once: a `Finding`'s kind, read at its construction"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "f.kind",
        Source::PassThrough("record_detected: a `Finding`'s kind, read at its construction"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "f.kind",
        Source::PassThrough("record_cleared: a `Finding`'s kind, read at its construction"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "f.kind",
        Source::PassThrough("record_note: a `Finding`'s kind, read at its construction"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "f.kind",
        Source::PassThrough(
            "note_once (lot 389): a `Finding`'s kind, read at its construction \
             (`shutdown_remount::RUN_EXEC_KIND`)",
        ),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "f.kind",
        Source::PassThrough("report_event: a `Finding`'s kind, read at its construction"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "s.kind",
        Source::PassThrough("the sysctl guard's finding (`kind:` literals of sysctl_guard.rs)"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "kind (shorthand)",
        Source::Producer(
            "crates/nn-linux/src/self_integrity.rs",
            "pub fn watchdog_holds(path: &Path)",
        ),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "kind (shorthand)",
        Source::Producer(
            "crates/nn-linux/src/self_integrity.rs",
            "fn observe(&mut self, now: &[(String, String)]",
        ),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "kind (shorthand)",
        Source::PassThrough("the per-kind cap re-signs the kinds of the round's findings"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "kind (shorthand)",
        Source::PassThrough("the per-kind cap's count, of a kind of the round's findings"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "kind (shorthand)",
        Source::Producer("crates/nn-linux/src/own_dropins.rs", "pub fn record(&self)"),
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "kind (shorthand)",
        Source::Producer(
            "crates/nn-linux/src/anti_tamper/pin_lock.rs",
            "pub fn round(",
        ),
    ),
    (
        "crates/nn-linux/src/witness.rs",
        "kind (shorthand)",
        Source::Producer("crates/nn-linux/src/witness.rs", "pub fn import_kind("),
    ),
    (
        "agent/src/boot/tasks.rs",
        "v.kind()",
        Source::Producer("crates/nn-linux/src/witness.rs", "pub fn kind(&self)"),
    ),
    (
        "agent/src/boot/canary.rs",
        "kind",
        Source::Producer("agent/src/boot/canary.rs", "let kind = |s: DecoyState|"),
    ),
    (
        "crates/nn-evidence/src/chain_anchor.rs",
        "self.kind",
        Source::PassThrough("a `ChainFinding`'s kind, read at `ChainFinding::new`"),
    ),
    (
        "crates/nn-evidence/src/chain_anchor.rs",
        "finding.0",
        Source::Producer(
            "crates/nn-evidence/src/chain_anchor.rs",
            "fn report_head<H: ChainHost>(",
        ),
    ),
    (
        "crates/nn-evidence/src/held.rs",
        "kind.to_string()",
        Source::PassThrough("the held finding of a signed row"),
    ),
    (
        "agent/src/admin/audit.rs",
        "kind",
        Source::NotDrift("an overlay's keyword in its `config_overlay_set` row"),
    ),
    (
        "agent/src/config/overlay_auth.rs",
        "kind.keyword()",
        Source::NotDrift("an overlay's keyword in its `config_overlay_accepted` row"),
    ),
    (
        "agent/src/config/overlay_floor.rs",
        "kind.keyword().to_string()",
        Source::NotDrift("an overlay's keyword in the floor's anchor"),
    ),
    (
        "agent/src/boot/manifest.rs",
        "w.kind.name().to_string()",
        Source::NotDrift("a worker's kind in the capability manifest"),
    ),
    (
        "agent/src/execpol/record.rs",
        "e.kind.clone()",
        Source::NotDrift("an exec policy record's subject"),
    ),
    (
        "agent/src/posture/golden.rs",
        "kind",
        Source::NotDrift("the posture golden's event kind"),
    ),
    (
        "crates/nn-linux/src/sensors/bus.rs",
        "c.kind",
        Source::NotDrift("an event bus flood key"),
    ),
    (
        "crates/nn-linux/src/worker/serve.rs",
        "a.kind",
        Source::NotDrift("a worker's kind"),
    ),
    (
        "crates/nn-core/src/bus.rs",
        "p.kind",
        Source::NotDrift("an event bus flood key"),
    ),
    (
        "crates/nn-core/src/posture/entry.rs",
        "t.event_kind",
        Source::NotDrift("a posture trigger's event kind"),
    ),
    (
        "crates/nn-core/src/posture/triggers.rs",
        "event_kind(event)",
        Source::NotDrift("a posture trigger's event kind"),
    ),
    (
        "agent/src/decision/catalogue/render.rs",
        "cells[1].to_string()",
        Source::NotDrift("a rule catalogue cell"),
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "info.map_type().ok()",
        Source::NotDrift("a BPF map's type"),
    ),
    (
        "crates/nn-linux/src/verifier_check.rs",
        "le_u32(elf, b + 4)?",
        Source::NotDrift("an ELF section's type"),
    ),
    (
        "scan/src/elf.rs",
        "u32_at(d, b)?",
        Source::NotDrift("an ELF section's type"),
    ),
    (
        "scan/src/elf.rs",
        "u32_at(d, b)?",
        Source::NotDrift("an ELF section's type"),
    ),
    (
        "scan/src/elf.rs",
        "u32_at(d, b.checked_add(4)?)?",
        Source::NotDrift("an ELF section's type"),
    ),
    (
        "scan/src/elf.rs",
        "u32_at(d, b.checked_add(4)?)?",
        Source::NotDrift("an ELF section's type"),
    ),
    (
        "agent-ebpf/src/epg.rs",
        "kind_",
        Source::NotDrift("a kernel event's kind (eBPF)"),
    ),
    (
        "agent-ebpf/src/epg.rs",
        "k",
        Source::NotDrift("a kernel event's kind (eBPF)"),
    ),
    (
        "crates/nn-core/src/contract/mod.rs",
        "ident => $class:expr",
        Source::NotDrift("a macro's pattern"),
    ),
    (
        "watchdog/src/witness.rs",
        "kind.to_string()",
        Source::NotDrift(
            "a row of the watchdog's own witness chain (imported by the agent as witness_*)",
        ),
    ),
];

/// A kind as the product writes them: snake_case.
fn kind_like(s: &str) -> bool {
    !s.is_empty()
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The kinds `held.rs` classifies: the snake_case literals of its
/// `*_KINDS` tables (a reason has spaces).
fn classified(held: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut from = 0;
    while let Some(at) = held[from..].find("pub const ") {
        let start = from + at;
        let line_end = held[start..].find('\n').map_or(held.len(), |i| start + i);
        let head = &held[start..line_end];
        from = line_end;
        let name = head["pub const ".len()..]
            .split(':')
            .next()
            .unwrap_or("")
            .trim();
        if !name.ends_with("_KINDS") {
            continue;
        }
        let end = held[start..].find("];").map_or(held.len(), |i| start + i);
        out.extend(
            string_literals(&held[start..end])
                .into_iter()
                .filter(|s| kind_like(s)),
        );
        from = end;
    }
    out
}

/// `const NAME: &str = "value";` (or `= path::OTHER;`) of every file:
/// NAME → (file, value or the constant it names).
fn consts(code: &BTreeMap<String, String>) -> BTreeMap<String, Vec<(String, String)>> {
    let mut out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (rel, text) in code {
        let mut from = 0;
        while let Some(at) = text[from..].find("const ") {
            let start = from + at + "const ".len();
            from = start;
            let Some(colon) = text[start..].find(':') else {
                break;
            };
            let name = text[start..start + colon].trim();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let rest = &text[start + colon + 1..];
            let Some(semi) = rest.find(';') else { continue };
            let decl = &rest[..semi];
            let Some((ty, value)) = decl.split_once('=') else {
                continue;
            };
            if !matches!(ty.trim(), "&str" | "&'static str") {
                continue;
            }
            let value = value.trim();
            let value = if let Some(lit) = value.strip_prefix('"') {
                lit.trim_end_matches('"').to_string()
            } else {
                format!("@{}", value.rsplit("::").next().unwrap_or(value).trim())
            };
            out.entry(name.to_string())
                .or_default()
                .push((rel.clone(), value));
        }
    }
    out
}

/// The values of constant `name` as file `rel` names it: its own, else
/// every one of that name (the safe side), one alias followed.
fn resolve(
    consts: &BTreeMap<String, Vec<(String, String)>>,
    rel: &str,
    name: &str,
    depth: u8,
) -> Vec<String> {
    let Some(all) = consts.get(name) else {
        return Vec::new();
    };
    let own: Vec<&(String, String)> = all.iter().filter(|(f, _)| f == rel).collect();
    let pick: Vec<&(String, String)> = if own.is_empty() {
        all.iter().collect()
    } else {
        own
    };
    let mut out = Vec::new();
    for (f, v) in pick {
        match v.strip_prefix('@') {
            Some(alias) if depth < 3 => out.extend(resolve(consts, f, alias, depth + 1)),
            Some(_) => {}
            None => out.push(v.clone()),
        }
    }
    out
}

/// The SCREAMING_CASE names in `expr` (a path's last segment).
fn const_names(expr: &str) -> Vec<String> {
    expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| {
            w.len() > 1
                && w.starts_with(|c: char| c.is_ascii_uppercase())
                && w.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_string)
        .collect()
}

/// The end of the expression that starts at `s`: the first `,` `;` or
/// closing bracket at depth 0 (string literals skipped).
fn expr_end(s: &str) -> usize {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            b',' | b';' if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// A type, an enum's variant or a number at a kind position: no string kind.
fn not_a_string(expr: &str) -> bool {
    let e = expr.trim();
    if e.starts_with('&') || e.starts_with('?') || e.starts_with(|c: char| c.is_ascii_digit()) {
        return true;
    }
    let path: String = e
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    let first = path.split("::").next().unwrap_or("");
    if matches!(
        first,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "usize"
            | "i32"
            | "i64"
            | "bool"
            | "char"
            | "String"
            | "Option"
            | "Vec"
            | "Box"
    ) {
        return true;
    }
    // a CamelCase segment: a type or an enum's variant
    path.split("::").any(|seg| {
        seg.starts_with(|c: char| c.is_ascii_uppercase())
            && seg.chars().any(|c| c.is_ascii_lowercase())
    })
}

/// One place a kind is written.
#[derive(Debug)]
struct Position {
    rel: String,
    line: usize,
    expr: String,
}

/// The kind positions of one file's production code.
fn positions(rel: &str, code: &str) -> Vec<Position> {
    let mut out = Vec::new();
    let b = code.as_bytes();
    let line_of = |at: usize| code[..at].matches('\n').count() + 1;
    // `kind:` / `"kind":`
    let mut from = 0;
    while let Some(at) = code[from..].find("kind") {
        let at = from + at;
        from = at + 4;
        let quoted = at > 0 && b[at - 1] == b'"' && b.get(at + 4) == Some(&b'"');
        if !quoted {
            let before = at.checked_sub(1).map(|i| b[i]);
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.') {
                continue;
            }
            if b.get(at + 4)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                continue;
            }
        }
        let after = if quoted { at + 5 } else { at + 4 };
        let rest = &code[after..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with(':') || trimmed.starts_with("::") {
            // `Finding { kind, …` — the field's shorthand
            if !quoted && (trimmed.starts_with(',') || trimmed.starts_with('}')) {
                let head = code[..at].trim_end();
                let open =
                    head.ends_with('{') && head[..head.len() - 1].trim_end().ends_with("Finding");
                if open {
                    out.push(Position {
                        rel: rel.to_string(),
                        line: line_of(at),
                        expr: "kind (shorthand)".to_string(),
                    });
                }
            }
            continue;
        }
        let start = after + (rest.len() - trimmed.len()) + 1;
        let end = start + expr_end(&code[start..]);
        out.push(Position {
            rel: rel.to_string(),
            line: line_of(at),
            expr: code[start..end].trim().to_string(),
        });
    }
    // `ChainFinding::new(chain, path, kind, detail)`
    let mut from = 0;
    while let Some(at) = code[from..].find("ChainFinding::new(") {
        let open = from + at + "ChainFinding::new".len();
        from = open;
        let close = open + matching_paren(&code[open..]);
        let args = split_args(&code[open + 1..close.saturating_sub(1)]);
        if let Some(kind) = args.get(2) {
            out.push(Position {
                rel: rel.to_string(),
                line: line_of(open),
                expr: kind.trim().to_string(),
            });
        }
    }
    out
}

/// The length up to and including the `)` closing `s`'s first `(`.
fn matching_paren(s: &str) -> usize {
    let mut depth = 0i32;
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    s.len()
}

fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.trim().is_empty() {
        let end = expr_end(rest);
        out.push(rest[..end].to_string());
        rest = rest.get(end + 1..).unwrap_or("");
    }
    out
}

/// `text` with each `matches!(…)` blanked: its constants are patterns.
fn without_patterns(text: &str) -> String {
    let mut out = text.to_string();
    let mut from = 0;
    while let Some(at) = out[from..].find("matches!(") {
        let open = from + at + "matches!".len();
        let close = open + matching_paren(&out[open..]);
        out.replace_range(open..close, &" ".repeat(close - open));
        from = close;
    }
    out
}

/// The kinds written in `text` (a kind position's expression, or a
/// producer's body): its snake_case literals that are no JSON key, and the
/// values of the constants it names that are not a match arm's pattern. In
/// a producer (`producer`), a literal a method is called on is a value it
/// computes with, not a kind it returns.
fn kinds_in(
    text: &str,
    rel: &str,
    consts: &BTreeMap<String, Vec<(String, String)>>,
    producer: bool,
) -> BTreeSet<String> {
    let text = &without_patterns(text);
    let mut out = BTreeSet::new();
    let mut rest = text.as_str();
    for lit in string_literals(text) {
        let quoted = format!("\"{lit}\"");
        let Some(at) = rest.find(&quoted) else {
            continue;
        };
        let after = rest[at + quoted.len()..].trim_start();
        rest = &rest[at + quoted.len()..];
        let value = producer && after.starts_with('.');
        if kind_like(&lit) && !after.starts_with(':') && !after.starts_with("=>") && !value {
            out.insert(lit);
        }
    }
    for name in const_names(text) {
        // a match arm's pattern (`NAME =>`, `NAME |`) is no kind written
        let arm = text.match_indices(name.as_str()).all(|(i, _)| {
            let after = text[i + name.len()..].trim_start();
            after.starts_with("=>") || after.starts_with('|')
        });
        if arm {
            continue;
        }
        out.extend(
            resolve(consts, rel, &name, 0)
                .into_iter()
                .filter(|v| kind_like(v)),
        );
    }
    out
}

/// The body of the item at `head` in `code` (to its matching brace).
fn item<'a>(code: &'a str, rel: &str, head: &str) -> &'a str {
    let at = code
        .find(head)
        .unwrap_or_else(|| panic!("{rel}: `{head}` not found"));
    let rest = &code[at..];
    let brace = rest
        .find('{')
        .unwrap_or_else(|| panic!("{rel}: `{head}` has no body"));
    &rest[..brace + matching_brace(&rest[brace..])]
}

/// Every kind of `integrity_drift` row the product writes, with where, and
/// the kind positions [`DYNAMIC`] does not name.
fn inventory(code: &BTreeMap<String, String>) -> (BTreeMap<String, String>, Vec<String>) {
    let consts = consts(code);
    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    let mut unknown = Vec::new();
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut add = |set: BTreeSet<String>, at: String| {
        for k in set {
            kinds.entry(k).or_insert_with(|| at.clone());
        }
    };
    for (rel, text) in code {
        for p in positions(rel, text) {
            let at = format!("{}:{}", p.rel, p.line);
            if not_a_string(&p.expr) {
                continue;
            }
            let found = kinds_in(&p.expr, rel, &consts, false);
            if !found.is_empty() || !const_names(&p.expr).is_empty() {
                add(found, at);
                continue;
            }
            if string_literals(&p.expr).iter().any(|l| !l.is_empty()) {
                // a literal that is no kind (a sentence): no kind written
                continue;
            }
            *seen.entry((p.rel.clone(), p.expr.clone())).or_insert(0) += 1;
            if !DYNAMIC.iter().any(|(f, e, _)| *f == p.rel && *e == p.expr) {
                unknown.push(format!("{at}: `{}`", p.expr));
            }
        }
    }
    // as many entries as places: a new place of a known spelling is named too
    for ((rel, expr), n) in &seen {
        let named = DYNAMIC
            .iter()
            .filter(|(f, e, _)| f == rel && e == expr)
            .count();
        if named > 0 && named != *n {
            unknown.push(format!(
                "{rel}: `{expr}` is written at {n} place(s), DYNAMIC names {named}"
            ));
        }
    }
    for (rel, _, source) in DYNAMIC {
        if let Source::Producer(file, head) = source {
            let text = code
                .get(*file)
                .unwrap_or_else(|| panic!("{file} (the producer of {rel}) not found"));
            let body = item(text, file, head);
            add(
                kinds_in(body, file, &consts, true),
                format!("{file} `{head}`"),
            );
        }
    }
    (kinds, unknown)
}

fn product() -> BTreeMap<String, String> {
    product_code(&repo_root())
}

fn held_code() -> String {
    std::fs::read_to_string(repo_root().join(HELD)).unwrap_or_else(|e| panic!("{HELD}: {e}"))
}

/// The kinds signed that `held` does not classify.
fn unclassified(kinds: &BTreeMap<String, String>, classified: &BTreeSet<String>) -> Vec<String> {
    kinds
        .iter()
        .filter(|(k, _)| {
            !classified.contains(k.as_str()) && !OTHER_ROWS.iter().any(|(o, _)| o == k)
        })
        .map(|(k, at)| format!("{k} (at {at})"))
        .collect()
}

/// Every kind the product writes into an `integrity_drift` row has its
/// class in `held.rs`, and every kind position is read.
#[test]
fn every_integrity_kind_the_product_signs_has_a_class() {
    let code = product();
    let (kinds, unknown) = inventory(&code);
    assert!(
        unknown.is_empty(),
        "kind positions this scan cannot read — name their source in DYNAMIC:\n{}",
        unknown.join("\n")
    );
    let missing = unclassified(&kinds, &classified(&held_code()));
    assert!(
        missing.is_empty(),
        "integrity_drift kinds with no class in {HELD} (evidence, a death, an event, a \
         degradation, an advisory, or not held — and why):\n{}",
        missing.join("\n")
    );
    // the scan reads what it must: the kinds the review named
    for k in [
        "admin_key_on_host",
        "agent_stalled",
        "sysctl_strict",
        "sysctl_opted_out",
        "quarantine_index_rebuilt",
        "unit_dropin_harmful",
        "config_overlay",
        "unauthorized_overlay",
        "chain_truncated",
        "witness_row_uncertified",
        "own_dropin_weakening",
        "pin_lock_missing",
        "watchdog_hold",
        "limit_appeared",
        "canary_decoy_missing",
    ] {
        assert!(kinds.contains_key(k), "{k} not read: {kinds:?}");
    }
}

/// Every [`DYNAMIC`] entry names a kind position that exists (a stale one
/// would let a new one of the same spelling through unread).
#[test]
fn every_dynamic_kind_position_exists() {
    let code = product();
    for (rel, expr, source) in DYNAMIC {
        let text = code.get(*rel).unwrap_or_else(|| panic!("{rel} not found"));
        assert!(
            positions(rel, text).iter().any(|p| p.expr == *expr),
            "{rel}: no kind position `{expr}`"
        );
        // each says where its kinds come from
        match source {
            Source::PassThrough(why) | Source::NotDrift(why) => {
                assert!(!why.trim().is_empty(), "{rel}: `{expr}`: no reason")
            }
            Source::Producer(file, head) => {
                assert!(
                    code.get(*file).is_some_and(|t| t.contains(head)),
                    "{file}: {head}"
                )
            }
        }
    }
    // the rows that are no integrity_drift: a reason each, none classified
    let classified = classified(&held_code());
    for (kind, why) in OTHER_ROWS {
        assert!(!why.trim().is_empty(), "{kind}");
        assert!(
            !classified.contains(*kind),
            "{kind} is classified and in OTHER_ROWS"
        );
    }
}

/// The scan fails on a planted kind with no class — a literal, a constant,
/// a producer's arm — and on a kind position it cannot read.
#[test]
fn the_scan_fails_on_a_planted_kind_without_class() {
    let classified = classified(&held_code());
    assert!(classified.contains("chain_truncated"), "{classified:?}");
    assert!(classified.contains("admin_key_on_host"), "{classified:?}");
    let mut code = product();
    let planted = [
        (
            "k379-planted-a",
            "fn a() -> Finding { Finding { kind: \"k379_planted_literal\", detail: d } }",
            "k379_planted_literal",
        ),
        (
            "k379-planted-b",
            "pub const K379_PLANTED: &str = \"k379_planted_const\";\n\
             fn b() { json!({ \"kind\": K379_PLANTED, \"detail\": d }); }",
            "k379_planted_const",
        ),
        (
            "k379-planted-c",
            "fn c() { ChainFinding::new(\"audit\", p, \"k379_planted_chain\", \"x\"); }",
            "k379_planted_chain",
        ),
    ];
    for (rel, text, kind) in planted {
        code.insert(rel.to_string(), text.to_string());
        let (kinds, _) = inventory(&code);
        let missing = unclassified(&kinds, &classified);
        assert!(
            missing.iter().any(|m| m.starts_with(kind)),
            "{kind}: {missing:?}"
        );
        code.remove(rel);
    }
    // a new arm of a producer
    let file = "crates/nn-linux/src/own_dropins.rs";
    let text = code[file].replace(
        "(\"own_dropin_weakening\", true)",
        "(\"k379_planted_arm\", true)",
    );
    assert_ne!(text, code[file]);
    code.insert(file.to_string(), text);
    let (kinds, _) = inventory(&code);
    assert!(unclassified(&kinds, &classified)
        .iter()
        .any(|m| m.starts_with("k379_planted_arm")));
    // a kind position the scan cannot read
    code.insert(
        "k379-planted-d".to_string(),
        "fn d(k: &str) { json!({ \"kind\": k.trim(), \"detail\": d }); }".to_string(),
    );
    let (_, unknown) = inventory(&code);
    assert!(
        unknown.iter().any(|u| u.contains("k379-planted-d")),
        "{unknown:?}"
    );
}
