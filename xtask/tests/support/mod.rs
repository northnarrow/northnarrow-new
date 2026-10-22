//! What the repository tests share (Wave 4 restructure R00, lab PR 239):
//! the workspace members from `cargo metadata` instead of a parse of the
//! `members = […]` line, and `docs/architecture/module-map.toml`.
//!
//! A directory of `tests/`, not a test target: each test file that needs
//! it says `mod support;`, and uses what it needs of it.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root (xtask lives one level below it).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

/// One workspace member, as `cargo metadata --no-deps` gives it.
#[derive(Debug, Clone)]
pub struct Member {
    /// The package name (`northnarrow-agent`).
    pub name: String,
    /// The package directory, relative to the repository root (`agent`,
    /// `crates/nn-core`).
    pub dir: String,
    /// The features the manifest declares.
    pub features: Vec<String>,
    /// The package's dependencies: (name, kind, path dependency or not).
    /// `kind` is `normal`, `dev` or `build`.
    pub deps: Vec<Dep>,
}

/// One declared dependency of a member.
#[derive(Debug, Clone)]
pub struct Dep {
    /// The package it names (after any `package = "…"` rename).
    pub name: String,
    pub kind: String,
    /// A path dependency (a crate of this repository).
    pub path: bool,
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// `cargo metadata` of the workspace, with `args` added. Offline: it reads
/// only the manifests (and, without `--no-deps`, the lockfile and the
/// already downloaded packages; CI's test job builds before it tests).
pub fn cargo_metadata(args: &[&str]) -> serde_json::Value {
    let out = Command::new(cargo())
        .current_dir(repo_root())
        .args(["metadata", "--format-version", "1", "--offline"])
        .args(args)
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata {args:?} failed (build the workspace once, or `cargo fetch --locked`):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("cargo metadata JSON")
}

/// The workspace members, sorted by name.
pub fn members() -> Vec<Member> {
    let meta = cargo_metadata(&["--no-deps"]);
    let root = repo_root();
    let ids: Vec<&str> = meta["workspace_members"]
        .as_array()
        .expect("workspace_members")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    let mut out: Vec<Member> = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|p| ids.contains(&p["id"].as_str().unwrap_or("")))
        .map(|p| {
            let manifest = Path::new(p["manifest_path"].as_str().expect("manifest_path"));
            let dir = manifest
                .parent()
                .expect("package directory")
                .strip_prefix(&root)
                .expect("a member under the repository root")
                .to_string_lossy()
                .into_owned();
            let features = p["features"]
                .as_object()
                .map(|f| f.keys().cloned().collect())
                .unwrap_or_default();
            let deps = p["dependencies"]
                .as_array()
                .expect("dependencies")
                .iter()
                .map(|d| Dep {
                    name: d["name"].as_str().expect("dependency name").to_string(),
                    kind: d["kind"].as_str().unwrap_or("normal").to_string(),
                    path: d.get("path").is_some_and(|v| v.is_string()),
                })
                .collect();
            Member {
                name: p["name"].as_str().expect("name").to_string(),
                dir,
                features,
                deps,
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(
        out.len() >= 8 && out.iter().any(|m| m.name == "northnarrow-agent"),
        "cargo metadata lists {} members: {:?}",
        out.len(),
        out.iter().map(|m| &m.name).collect::<Vec<_>>()
    );
    out
}

/// Every `.rs` file under `dir`, `target/` directories skipped.
pub fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out.sort();
}

// ── docs/architecture/module-map.toml ─────────────────────────────────────

/// The map, relative to the repository root.
pub const MODULE_MAP: &str = "docs/architecture/module-map.toml";

/// A value of the TOML subset the map is written in.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Bool(bool),
    Int(i64),
    List(Vec<String>),
}

impl Value {
    pub fn str(&self) -> &str {
        match self {
            Value::Str(s) => s,
            v => panic!("{MODULE_MAP}: a string expected, found {v:?}"),
        }
    }
    pub fn bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            v => panic!("{MODULE_MAP}: true or false expected, found {v:?}"),
        }
    }
    pub fn int(&self) -> i64 {
        match self {
            Value::Int(i) => *i,
            v => panic!("{MODULE_MAP}: an integer expected, found {v:?}"),
        }
    }
    pub fn list(&self) -> &[String] {
        match self {
            Value::List(l) => l,
            v => panic!("{MODULE_MAP}: a list of strings expected, found {v:?}"),
        }
    }
}

/// `[table]` → key → value. Valid TOML, read by the subset parser below
/// (no TOML crate in the tree for one file): `[a.b]` headers, `key = …`
/// with a bare or quoted key, values a string, true/false, an integer or a
/// list of strings (over several lines allowed); `#` comments. Anything
/// else is refused, so the map cannot say something the tests misread.
pub type Tables = BTreeMap<String, BTreeMap<String, Value>>;

fn unquote(s: &str, at: usize) -> String {
    let s = s.trim();
    assert!(
        s.len() >= 2 && s.starts_with('"') && s.ends_with('"') && !s[1..s.len() - 1].contains('"'),
        "{MODULE_MAP}:{at}: a \"string\" expected, found `{s}`"
    );
    assert!(
        !s.contains('\\'),
        "{MODULE_MAP}:{at}: no escapes in this file: `{s}`"
    );
    s[1..s.len() - 1].to_string()
}

/// The text before a `#` that is not inside a string.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

pub fn parse_tables(text: &str) -> Tables {
    let mut tables = Tables::new();
    let mut current: Option<String> = None;
    let mut lines = text.lines().enumerate();
    while let Some((i, raw)) = lines.next() {
        let at = i + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(h) = line.strip_prefix('[') {
            let h = h
                .strip_suffix(']')
                .unwrap_or_else(|| panic!("{MODULE_MAP}:{at}: `{line}`"));
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
                "{MODULE_MAP}:{at}: a [table.name] of bare keys expected: `{line}`"
            );
            assert!(!tables.contains_key(h), "{MODULE_MAP}:{at}: [{h}] twice");
            tables.insert(h.to_string(), BTreeMap::new());
            current = Some(h.to_string());
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{MODULE_MAP}:{at}: `key = value` expected: `{line}`"));
        let k = k.trim();
        let key = if k.starts_with('"') {
            unquote(k, at)
        } else {
            assert!(
                !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)),
                "{MODULE_MAP}:{at}: a bare key expected: `{k}`"
            );
            k.to_string()
        };
        let mut v = v.trim().to_string();
        let value =
            if v.starts_with('[') {
                while !v.ends_with(']') {
                    let (_, more) = lines
                        .next()
                        .unwrap_or_else(|| panic!("{MODULE_MAP}:{at}: an unclosed list"));
                    v.push(' ');
                    v.push_str(strip_comment(more).trim());
                    v = v.trim().to_string();
                }
                let inner = &v[1..v.len() - 1];
                Value::List(
                    inner
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| unquote(s, at))
                        .collect(),
                )
            } else if v == "true" || v == "false" {
                Value::Bool(v == "true")
            } else if v.starts_with('"') {
                Value::Str(unquote(&v, at))
            } else {
                Value::Int(v.replace('_', "").parse().unwrap_or_else(|_| {
                    panic!("{MODULE_MAP}:{at}: `{v}`: not a value this file uses")
                }))
            };
        let table = current
            .as_ref()
            .unwrap_or_else(|| panic!("{MODULE_MAP}:{at}: a key before any [table]"));
        let t = tables.get_mut(table).unwrap();
        assert!(
            t.insert(key.clone(), value).is_none(),
            "{MODULE_MAP}:{at}: `{key}` twice in [{table}]"
        );
    }
    tables
}

/// One crate of the layered layout (`[crates.<package>]`).
#[derive(Debug, Clone)]
pub struct CrateRule {
    pub name: String,
    /// The crates of this repository it may depend on (any kind of
    /// dependency).
    pub allowed: Vec<String>,
    /// Not a workspace member yet (a crate of a later lot).
    pub planned: bool,
    /// Portable core: no OS interface (no `libc`, `nix`, `aya`, `procfs`,
    /// `tokio`, no `std::os`, no `cfg(target_os)`); checked by the CI job
    /// `portable-core` for the non-Linux targets.
    pub pure: bool,
    /// `#![forbid(unsafe_code)]` at the crate root.
    pub forbid_unsafe: bool,
}

/// The module map: the crate rules, the module → crate tables and the
/// ratchet's ceilings.
#[derive(Debug)]
pub struct ModuleMap {
    pub crates: BTreeMap<String, CrateRule>,
    /// `[modules.<source>]`: module path → crate, for each source tree
    /// (`agent`, `common`).
    pub modules: BTreeMap<String, BTreeMap<String, String>>,
    /// `[aliases.<source>]`: an item of the crate root → the module that
    /// defines it (a `pub use` at the root).
    pub aliases: BTreeMap<String, BTreeMap<String, String>>,
    /// `[ratchet]`: crate → the most violations it may have.
    pub ratchet: BTreeMap<String, i64>,
}

pub fn module_map() -> ModuleMap {
    let path = repo_root().join(MODULE_MAP);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{MODULE_MAP}: {e}"));
    let tables = parse_tables(&text);
    let mut map = ModuleMap {
        crates: BTreeMap::new(),
        modules: BTreeMap::new(),
        aliases: BTreeMap::new(),
        ratchet: BTreeMap::new(),
    };
    for (name, t) in &tables {
        if let Some(krate) = name.strip_prefix("crates.") {
            for k in t.keys() {
                assert!(
                    ["allowed", "planned", "pure", "forbid_unsafe", "about"].contains(&k.as_str()),
                    "{MODULE_MAP}: [{name}] {k}: not a key of a crate rule"
                );
            }
            let flag = |k: &str| t.get(k).map(Value::bool).unwrap_or(false);
            map.crates.insert(
                krate.to_string(),
                CrateRule {
                    name: krate.to_string(),
                    allowed: t
                        .get("allowed")
                        .map(|v| v.list().to_vec())
                        .unwrap_or_default(),
                    planned: flag("planned"),
                    pure: flag("pure"),
                    forbid_unsafe: flag("forbid_unsafe"),
                },
            );
        } else if let Some(src) = name.strip_prefix("modules.") {
            let m = t
                .iter()
                .map(|(k, v)| (k.clone(), v.str().to_string()))
                .collect();
            map.modules.insert(src.to_string(), m);
        } else if let Some(src) = name.strip_prefix("aliases.") {
            let m = t
                .iter()
                .map(|(k, v)| (k.clone(), v.str().to_string()))
                .collect();
            map.aliases.insert(src.to_string(), m);
        } else if name == "ratchet" {
            map.ratchet = t.iter().map(|(k, v)| (k.clone(), v.int())).collect();
        } else if name != "map" {
            panic!("{MODULE_MAP}: [{name}]: not a table of this file");
        }
    }
    for rule in map.crates.values() {
        for a in &rule.allowed {
            assert!(
                map.crates.contains_key(a),
                "{MODULE_MAP}: [crates.{}] allows `{a}`, which has no [crates.{a}]",
                rule.name
            );
        }
    }
    for (src, m) in &map.modules {
        for (module, krate) in m {
            assert!(
                map.crates.contains_key(krate),
                "{MODULE_MAP}: [modules.{src}] `{module}` → `{krate}`, which has no [crates.{krate}]"
            );
        }
    }
    map
}
