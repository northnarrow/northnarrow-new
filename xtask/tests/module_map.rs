//! The module ratchet of the Wave 4 restructure (R00, lab PR 239).
//!
//! `docs/architecture/module-map.toml` sends every module of `agent/src`
//! and `common/src` to the crate it is headed for, and says which crates
//! each crate may depend on. A module that names a module of a crate its
//! own crate may not depend on (a `crate::`, `super::`, `self::`,
//! `common::` or `northnarrow_agent::` path, or the name of another crate
//! of the repository, outside tests and Kani proofs) is a violation: the arc R04 has to cut before the module can move
//! (rule 3 of the plan's §4.1, "extract from the bottom"). The count of
//! each crate may not grow above its `[ratchet]` ceiling, and a count
//! below it fails too until the ceiling comes down to it — so the number
//! in the file is always the number of the tree.
//!
//! `[shims.<tree>]` (R05, lab PR 241) names the paths a tree keeps, without
//! a file, for modules that moved to a crate (plan §4.1 rule 2): a
//! reference to one counts for that crate.
//!
//! The scan is lexical, not a compiler's: comments, strings and char
//! literals are blanked first, `#[cfg(test)]` and `#[cfg(kani)]` items and
//! the files they declare are dropped, and `use` groups are expanded. It
//! sees no macro expansion and no glob import's names; it does not need
//! to, to keep a count from growing.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use support::{module_map, repo_root, rs_files, ModuleMap};

/// The source trees the map covers: (map key, directory, extern crate
/// name others use for it).
const SOURCES: &[(&str, &str, &str)] = &[
    ("agent", "agent/src", "northnarrow_agent"),
    ("common", "common/src", "common"),
];

/// Extern crates of the repository named from these trees, mapped
/// directly to their package. R03 (lab PR 240): the crates of `crates/`
/// too — a module that moves out of `common` is named by its new crate,
/// and the reference must still count (`verify_lines` →
/// `nn_proto::admin_protocol` is the nn-evidence → nn-proto arc it was
/// as `common::wire::admin_protocol`).
const EXTERN: &[(&str, &str)] = &[
    ("antitamper_bpf", "northnarrow-antitamper-bpf"),
    ("northnarrow_antitamper_bpf", "northnarrow-antitamper-bpf"),
    ("northnarrow_scan", "northnarrow-scan"),
    ("nn_parse", "nn-parse"),
    ("nn_model", "nn-model"),
    ("nn_proto", "nn-proto"),
    ("nn_evidence", "nn-evidence"),
    ("nn_core", "nn-core"),
    ("nn_linux", "nn-linux"),
    ("nn_admin", "nn-admin"),
];

// ── lexing ────────────────────────────────────────────────────────────────

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `src` with comments, string, byte-string, raw-string and char literals
/// blanked (spaces, newlines kept), so braces and paths inside them do not
/// count.
fn blank(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank_range = |out: &mut Vec<u8>, from: usize, to: usize| {
        for x in out.iter_mut().take(to).skip(from) {
            if *x != b'\n' {
                *x = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            let end = b[i..]
                .iter()
                .position(|&x| x == b'\n')
                .map_or(b.len(), |p| i + p);
            blank_range(&mut out, i, end);
            i = end;
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            let (mut depth, mut j) = (0usize, i);
            while j < b.len() {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank_range(&mut out, i, j);
            i = j;
            continue;
        }
        let prev_ident = i > 0 && is_ident(b[i - 1]);
        // raw strings: r"…", r#"…"#, br"…"
        if !prev_ident && (c == b'r' || (c == b'b' && next == Some(b'r'))) {
            let mut j = i + if c == b'b' { 2 } else { 1 };
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&b'"') {
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let body = j + 1;
                let end = b[body..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(b.len(), |p| body + p + close.len());
                blank_range(&mut out, i, end);
                i = end;
                continue;
            }
        }
        if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            blank_range(&mut out, i, (j + 1).min(b.len()));
            i = j + 1;
            continue;
        }
        if c == b'\'' {
            // a char literal ('x', '\n', '\'', '\u{…}', 'é'), not a lifetime
            if next == Some(b'\\') {
                let mut j = i + 3;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                blank_range(&mut out, i, (j + 1).min(b.len()));
                i = j + 1;
                continue;
            }
            if let Some(n) = next {
                let len = match n {
                    0x00..=0x7f => 1,
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    _ => 4,
                };
                if b.get(i + 1 + len) == Some(&b'\'') {
                    blank_range(&mut out, i, i + 2 + len);
                    i += 2 + len;
                    continue;
                }
            }
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanking keeps UTF-8")
}

/// The end of the item that starts at `from` (after its attributes): its
/// `;` or its `{…}` block, at the outer depth.
fn item_end(b: &[u8], from: usize) -> usize {
    let mut depth = 0i32;
    let mut i = from;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' if depth == 0 => return i + 1,
            b'{' if depth == 0 => {
                let mut braces = 0i32;
                while i < b.len() {
                    match b[i] {
                        b'{' => braces += 1,
                        b'}' => {
                            braces -= 1;
                            if braces == 0 {
                                return i + 1;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                return b.len();
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// Whether a `#[cfg(…)]` keeps its item out of the shipped build: `test`
/// or `kani`, not under `not(…)`.
fn test_only(cfg: &str) -> bool {
    let words: Vec<&str> = cfg
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .collect();
    (words.contains(&"test") || words.contains(&"kani")) && !words.contains(&"not")
}

/// `text` (already blanked) with its test-only items blanked, and the
/// names of the `mod x;` files they declare.
fn drop_test_items(text: &str) -> (String, Vec<String>) {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut test_mods = Vec::new();
    let mut i = 0;
    while let Some(off) = text[i..].find("#[cfg(") {
        let at = i + off;
        let attr_end = item_end_attr(b, at);
        let cfg = &text[at..attr_end];
        if !test_only(cfg) {
            i = attr_end;
            continue;
        }
        // further attributes, then the item
        let mut j = attr_end;
        loop {
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if b.get(j) == Some(&b'#') && b.get(j + 1) == Some(&b'[') {
                j = item_end_attr(b, j);
            } else {
                break;
            }
        }
        let end = item_end(b, j);
        let item = text[j..end].trim();
        let words: Vec<&str> = item
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();
        if item.ends_with(';') {
            if let Some(p) = words.iter().position(|w| *w == "mod") {
                if let Some(name) = words.get(p + 1) {
                    test_mods.push(name.to_string());
                }
            }
        }
        for x in out.iter_mut().take(end).skip(at) {
            if *x != b'\n' {
                *x = b' ';
            }
        }
        i = end;
    }
    (String::from_utf8(out).unwrap(), test_mods)
}

/// The end of the attribute `#[…]` that starts at `at`.
fn item_end_attr(b: &[u8], at: usize) -> usize {
    let mut depth = 0i32;
    let mut i = at + 1;
    while i < b.len() {
        match b[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

// ── paths ─────────────────────────────────────────────────────────────────

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn ident_at(b: &[u8], i: usize) -> Option<(String, usize)> {
    let start = i;
    let mut j = i;
    if b.get(j) == Some(&b'r') && b.get(j + 1) == Some(&b'#') {
        j += 2;
    }
    while j < b.len() && is_ident(b[j]) {
        j += 1;
    }
    (j > start && !b[start].is_ascii_digit())
        .then(|| (String::from_utf8_lossy(&b[start..j]).replace("r#", ""), j))
}

/// The paths of the use tree (or expression path) that starts at `i`,
/// after `prefix`.
fn parse_tree(b: &[u8], i: usize, prefix: &[String], out: &mut Vec<Vec<String>>) -> usize {
    let mut path = prefix.to_vec();
    let mut i = skip_ws(b, i);
    loop {
        if b.get(i) == Some(&b'{') {
            i += 1;
            loop {
                i = skip_ws(b, i);
                if b.get(i) == Some(&b'}') {
                    return i + 1;
                }
                i = parse_tree(b, i, &path, out);
                i = skip_ws(b, i);
                match b.get(i) {
                    Some(b',') => i += 1,
                    Some(b'}') => return i + 1,
                    _ => return i,
                }
            }
        }
        if b.get(i) == Some(&b'*') {
            out.push(path);
            return i + 1;
        }
        let Some((id, j)) = ident_at(b, i) else {
            out.push(path);
            return i;
        };
        if id != "self" {
            path.push(id);
        }
        let k = skip_ws(b, j);
        if b.get(k) == Some(&b':') && b.get(k + 1) == Some(&b':') {
            let after = skip_ws(b, k + 2);
            if b.get(after) == Some(&b'<') {
                out.push(path);
                return after;
            }
            i = after;
            continue;
        }
        out.push(path);
        return j;
    }
}

/// Where a path points: a source tree and its module path, or a crate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Module(String, Vec<String>),
    Crate(String),
}

/// The paths of a blanked, test-free file of module `module` in tree
/// `source` (`bin`: a binary root, whose `crate::` is itself).
fn references(text: &str, source: &str, module: &[String], bin: bool) -> BTreeSet<Target> {
    let b = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if !(is_ident(b[i]) && (i == 0 || !is_ident(b[i - 1]))) {
            i += 1;
            continue;
        }
        let Some((id, j)) = ident_at(b, i) else {
            i += 1;
            continue;
        };
        let preceded_by_path = i >= 2 && &b[i - 2..i] == b"::";
        let k = skip_ws(b, j);
        let is_path = b.get(k) == Some(&b':') && b.get(k + 1) == Some(&b':');
        if preceded_by_path || !is_path {
            i = j;
            continue;
        }
        let base: Option<(String, Vec<String>)> = match id.as_str() {
            "crate" if bin => None,
            "crate" => Some((source.to_string(), Vec::new())),
            "self" => Some((source.to_string(), module.to_vec())),
            "super" => {
                // super::super::…
                let mut up = 1;
                let mut m = k + 2;
                loop {
                    let n = skip_ws(b, m);
                    match ident_at(b, n) {
                        Some((s, e)) if s == "super" => {
                            let e2 = skip_ws(b, e);
                            if b.get(e2) == Some(&b':') && b.get(e2 + 1) == Some(&b':') {
                                up += 1;
                                m = e2 + 2;
                                continue;
                            }
                            break;
                        }
                        _ => break,
                    }
                }
                let keep = module.len().saturating_sub(up);
                let mut paths = Vec::new();
                let end = parse_tree(b, m, &module[..keep], &mut paths);
                for p in paths {
                    out.insert(Target::Module(source.to_string(), p));
                }
                i = end.max(j);
                continue;
            }
            "common" if source != "common" => Some(("common".to_string(), Vec::new())),
            "northnarrow_agent" if source == "agent" => Some(("agent".to_string(), Vec::new())),
            other => {
                if let Some((_, pkg)) = EXTERN.iter().find(|(n, _)| *n == other) {
                    out.insert(Target::Crate(pkg.to_string()));
                }
                None
            }
        };
        let Some((tree, prefix)) = base else {
            i = j;
            continue;
        };
        let mut paths = Vec::new();
        let end = parse_tree(b, k + 2, &prefix, &mut paths);
        for p in paths {
            out.insert(Target::Module(tree.clone(), p));
        }
        i = end.max(j);
    }
    out
}

// ── the map ───────────────────────────────────────────────────────────────

/// The entry of the longest mapped prefix of `path` in tree `source`, with
/// the root's aliases; `None` when nothing maps it.
fn crate_of(map: &ModuleMap, source: &str, path: &[String]) -> Option<(String, String)> {
    let modules = map.modules.get(source)?;
    let shims = map.shims.get(source);
    for n in (1..=path.len()).rev() {
        let key = path[..n].join("::");
        if let Some(c) = modules
            .get(&key)
            .or_else(|| shims.and_then(|s| s.get(&key)))
        {
            return Some((key, c.clone()));
        }
    }
    if let (Some(first), Some(aliases)) = (path.first(), map.aliases.get(source)) {
        if let Some(m) = aliases.get(first).or_else(|| aliases.get("*")) {
            if let Some(c) = modules.get(m) {
                return Some((m.clone(), c.clone()));
            }
        }
    }
    modules.get("lib").map(|c| ("lib".to_string(), c.clone()))
}

/// The module path of a file of a source tree (`fim/drain.rs` →
/// `fim::drain`, `fim/mod.rs` → `fim`, `lib.rs` → `lib`).
fn module_of(rel: &Path) -> Vec<String> {
    let mut parts: Vec<String> = rel
        .with_extension("")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.last().is_some_and(|p| p == "mod") {
        parts.pop();
    }
    parts
}

struct Scan {
    /// crate → violations as "file → module (crate)".
    violations: BTreeMap<String, Vec<String>>,
    /// files with no entry in the map.
    unmapped: Vec<String>,
    /// files scanned, references resolved.
    files: usize,
    refs: usize,
}

fn scan(map: &ModuleMap) -> Scan {
    let root = repo_root();
    let mut s = Scan {
        violations: BTreeMap::new(),
        unmapped: Vec::new(),
        files: 0,
        refs: 0,
    };
    for (source, dir, _) in SOURCES {
        let base = root.join(dir);
        let mut files = Vec::new();
        rs_files(&base, &mut files);
        // the files a test-only `mod x;` declares, and everything under them
        let mut texts = BTreeMap::new();
        let mut test_files: BTreeSet<Vec<String>> = BTreeSet::new();
        for f in &files {
            let rel = f.strip_prefix(&base).unwrap();
            let module = module_of(rel);
            let raw = std::fs::read_to_string(f).unwrap();
            let (text, test_mods) = drop_test_items(&blank(&raw));
            for m in test_mods {
                // a child of this module: `<module>::m` (lib/main declare
                // children of the root)
                let mut child: Vec<String> = if module == ["lib"] || module == ["main"] {
                    Vec::new()
                } else {
                    module.clone()
                };
                child.push(m);
                test_files.insert(child);
            }
            texts.insert(f.clone(), (module, text));
        }
        for (f, (module, text)) in &texts {
            let rel = f.strip_prefix(&root).unwrap().display().to_string();
            if test_files
                .iter()
                .any(|t| module.len() >= t.len() && module[..t.len()] == t[..])
            {
                continue;
            }
            s.files += 1;
            let Some((_, own)) =
                crate_of(map, source, module).filter(|(k, _)| k != "lib" || *module == ["lib"])
            else {
                s.unmapped
                    .push(format!("{rel} (module `{}`)", module.join("::")));
                continue;
            };
            let bin = *module == ["main"] || module.first().is_some_and(|m| m == "bin");
            let rule = &map.crates[&own];
            let mut seen = BTreeSet::new();
            for t in references(text, source, module, bin) {
                let (what, target) = match &t {
                    Target::Crate(c) => (c.clone(), c.clone()),
                    Target::Module(tree, path) => {
                        let Some((k, c)) = crate_of(map, tree, path) else {
                            continue;
                        };
                        (format!("{tree}::{k}"), c)
                    }
                };
                s.refs += 1;
                if target == own || rule.allowed.contains(&target) {
                    continue;
                }
                if seen.insert(what.clone()) {
                    s.violations
                        .entry(own.clone())
                        .or_default()
                        .push(format!("{rel} → {what} ({target})"));
                }
            }
        }
    }
    s
}

#[test]
fn every_source_file_is_mapped_to_a_crate() {
    let map = module_map();
    let s = scan(&map);
    // A floor against a scan that finds nothing, not a count: the agent's
    // files leave for the crates lot by lot (R08b, lab PR 251: the
    // engine's, 196 files left before it; R09b, lab PR 254: the sensors',
    // the FIM's and the drains', 91 left after the sensors).
    assert!(s.files > 50, "the scan found {} files", s.files);
    assert!(
        s.unmapped.is_empty(),
        "docs/architecture/module-map.toml: map these modules to the crate they are headed for:\n{}",
        s.unmapped.join("\n")
    );
    // every entry names a module that exists
    let root = repo_root();
    for (source, dir, _) in SOURCES {
        for key in map.modules[*source].keys() {
            let rel = key.replace("::", "/");
            let found = root.join(dir).join(format!("{rel}.rs")).is_file()
                || root.join(dir).join(&rel).join("mod.rs").is_file();
            assert!(
                found,
                "module-map.toml [modules.{source}] `{key}`: no {dir}/{rel}.rs or {rel}/mod.rs"
            );
        }
        // a shim is a path the tree keeps without a file (R05, lab PR 241)
        for key in map.shims.get(*source).into_iter().flat_map(|m| m.keys()) {
            let rel = key.replace("::", "/");
            let file = root.join(dir).join(format!("{rel}.rs")).is_file()
                || root.join(dir).join(&rel).join("mod.rs").is_file();
            assert!(
                !file && !map.modules[*source].contains_key(key),
                "module-map.toml [shims.{source}] `{key}`: a shim has no file and no \
                 [modules.{source}] entry"
            );
        }
    }
}

#[test]
fn layer_violations_only_go_down() {
    let map = module_map();
    let s = scan(&map);
    assert!(s.refs > 1000, "the scan resolved {} references", s.refs);
    let mut bad = Vec::new();
    let mut crates: BTreeSet<&String> = s.violations.keys().collect();
    crates.extend(map.ratchet.keys());
    for c in crates {
        let have = s.violations.get(c).map_or(0, Vec::len) as i64;
        let ceiling = map.ratchet.get(c).copied().unwrap_or(0);
        if have > ceiling {
            bad.push(format!(
                "{c}: {have} violations, the ceiling is {ceiling} — a module now names a crate \
                 {c} may not depend on:\n  {}",
                s.violations[c].join("\n  ")
            ));
        } else if have < ceiling {
            bad.push(format!(
                "{c}: {have} violations, below the ceiling {ceiling}: lower `[ratchet] {c} = \
                 {have}` in docs/architecture/module-map.toml"
            ));
        }
    }
    if std::env::var_os("NN_MODULE_MAP_REPORT").is_some() {
        for (c, v) in &s.violations {
            eprintln!("== {c}: {}", v.len());
            for line in v {
                eprintln!("  {line}");
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The lexer and the path parser on the shapes the tree uses.
#[test]
fn the_scan_reads_paths_the_way_rust_does() {
    let m = |s: &str| s.split("::").map(str::to_string).collect::<Vec<_>>();
    let src = r##"
        use crate::fim::{self, drain::Drain, rules::{A, B}};
        use super::sibling::X;
        use common::{wire::admin_protocol::Frame, Event};
        // use crate::commented::Out;
        let s = "crate::in_string::No";
        let r = r#"crate::in_raw::No"#;
        let c = '{';
        fn f<'a>(x: &'a str) { crate::audit::log(x); }
        #[cfg(test)]
        mod tests { use crate::test_only::No; }
        #[cfg(test)]
        mod more_tests;
        #[cfg(not(test))]
        use crate::shipped::Yes;
        let t = crate::net::Tracker::<u8>::new();
        antitamper_bpf::pin();
        const _: usize = nn_proto::admin_protocol::MAX_FRAME_BODY;
    "##;
    let (text, test_mods) = drop_test_items(&blank(src));
    assert_eq!(test_mods, vec!["more_tests".to_string()]);
    let refs = references(&text, "agent", &m("posture::lineage"), false);
    let got: BTreeSet<Target> = refs;
    let want: BTreeSet<Target> = [
        Target::Module("agent".into(), m("fim")),
        Target::Module("agent".into(), m("fim::drain::Drain")),
        Target::Module("agent".into(), m("fim::rules::A")),
        Target::Module("agent".into(), m("fim::rules::B")),
        Target::Module("agent".into(), m("posture::sibling::X")),
        Target::Module("common".into(), m("wire::admin_protocol::Frame")),
        Target::Module("common".into(), m("Event")),
        Target::Module("agent".into(), m("audit::log")),
        Target::Module("agent".into(), m("shipped::Yes")),
        Target::Module("agent".into(), m("net::Tracker")),
        Target::Crate("northnarrow-antitamper-bpf".into()),
        Target::Crate("nn-proto".into()),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
    // the root's aliases: an item of a tree's root is its module's (R00's
    // `common::Event` → model; common has no root item since R02, lab PR
    // 240, and no alias table)
    let mut map = module_map();
    assert!(map.aliases.get("common").is_none_or(|a| a.is_empty()));
    assert_eq!(
        crate_of(&map, "common", &m("wire::FimDriftRaw")).map(|(_, c)| c),
        Some("northnarrow-common".to_string())
    );
    map.aliases.insert(
        "common".into(),
        [("Event".to_string(), "wire".to_string())].into(),
    );
    assert_eq!(
        crate_of(&map, "common", &m("Event")).map(|(k, _)| k),
        Some("wire".to_string())
    );
    assert_eq!(
        crate_of(&map, "agent", &m("fim::drain::Drain")).map(|(k, _)| k),
        Some("fim".to_string())
    );
}
