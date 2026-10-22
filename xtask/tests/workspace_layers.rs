//! The layer gate between crates of the Wave 4 restructure (R01, lab PR
//! 239). The layout of `docs/architecture/module-map.toml` (plan §2.1)
//! against the real workspace, from `cargo metadata`:
//!
//! - every member has its `[crates.<package>]` rule, and a rule without
//!   `planned` is a member;
//! - every dependency of a member on a crate of this repository, normal,
//!   build or dev, is one its rule `allowed`, and the allowed graph has no
//!   cycle (so neither has the workspace's);
//! - a pure crate depends on no OS interface (directly: libc, nix, rustix,
//!   aya, procfs, tokio, …; through its normal dependencies: aya, tokio,
//!   procfs, nix), names no `std::os` and no `cfg(target_os)`, `cfg(unix)`
//!   or `cfg(windows)`, and the CI job `portable-core` checks exactly the
//!   pure crates for the five other targets of the plan;
//! - a crate whose rule says `forbid_unsafe` forbids it at its root;
//! - every member inherits `[workspace.lints]`, but the two whose own
//!   table is the same;
//! - each crate of `crates/` is a `[workspace.dependencies]` entry.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use serde_yaml_ng::Value as Yaml;
use support::{cargo_metadata, members, module_map, repo_root, rs_files};

/// What no pure crate may depend on directly: the OS interfaces and the
/// async runtime (plan §2.1: no libc/nix/aya/procfs/tokio).
const FORBIDDEN_DIRECT: &[&str] = &[
    "libc",
    "nix",
    "rustix",
    "procfs",
    "caps",
    "landlock",
    "seccompiler",
];
/// Prefixes no pure crate may depend on, directly or not.
const FORBIDDEN_ANYWHERE: &[&str] = &["aya", "tokio", "procfs", "nix"];
/// Source text no pure crate may hold (outside comments).
const FORBIDDEN_TEXT: &[&str] = &[
    "std::os::",
    "target_os",
    "target_family",
    "cfg(unix)",
    "cfg(windows)",
    "libc::",
];
/// The targets of `portable-core` (plan R01): the core builds for six,
/// x86_64 Linux being every other job's.
const PORTABLE_TARGETS: &[&str] = &[
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];
/// Members with a `[lints]` table of their own, the workspace's rust table
/// in it (the reasons are at `[workspace.lints]` in Cargo.toml).
const OWN_LINTS: &[&str] = &["northnarrow-agent", "northnarrow-common"];

fn forbidden_anywhere(name: &str) -> bool {
    FORBIDDEN_ANYWHERE
        .iter()
        .any(|p| name == *p || name.starts_with(&format!("{p}-")))
}

#[test]
fn every_member_has_its_rule_and_every_rule_its_member() {
    let map = module_map();
    let names: BTreeSet<String> = members().into_iter().map(|m| m.name).collect();
    let mut bad = Vec::new();
    for n in &names {
        match map.crates.get(n) {
            None => bad.push(format!("{n}: a member without [crates.{n}]")),
            Some(r) if r.planned => bad.push(format!("{n}: a member, its rule says planned")),
            Some(_) => {}
        }
    }
    for (n, r) in &map.crates {
        if !r.planned && !names.contains(n) {
            bad.push(format!("[crates.{n}]: not planned, and no member"));
        }
    }
    assert!(
        bad.is_empty(),
        "docs/architecture/module-map.toml:\n{}",
        bad.join("\n")
    );
}

#[test]
fn every_dependency_between_crates_is_one_the_layers_allow() {
    let map = module_map();
    let ms = members();
    let names: BTreeSet<&str> = ms.iter().map(|m| m.name.as_str()).collect();
    let mut edges = 0;
    let mut bad = Vec::new();
    for m in &ms {
        let rule = &map.crates[&m.name];
        for d in m.deps.iter().filter(|d| d.path) {
            edges += 1;
            assert!(
                names.contains(d.name.as_str()),
                "{}: path dependency {} is no member",
                m.name,
                d.name
            );
            if !rule.allowed.contains(&d.name) {
                bad.push(format!(
                    "{} → {} ({} dependency): not in [crates.{}] allowed",
                    m.name, d.name, d.kind, m.name
                ));
            }
        }
    }
    assert!(edges >= 6, "only {edges} dependencies between members");
    assert!(
        bad.is_empty(),
        "a crate depends on one above it or beside it (docs/architecture/module-map.toml):\n{}",
        bad.join("\n")
    );

    // the allowed graph is a DAG: Kahn's algorithm consumes every crate
    let mut indeg: BTreeMap<&str, usize> = map.crates.keys().map(|k| (k.as_str(), 0)).collect();
    for r in map.crates.values() {
        for a in &r.allowed {
            assert_ne!(a, &r.name, "[crates.{}] allows itself", r.name);
        }
        *indeg.get_mut(r.name.as_str()).unwrap() += r.allowed.len();
    }
    let mut ready: Vec<&str> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(k, _)| *k)
        .collect();
    let mut done = 0;
    while let Some(n) = ready.pop() {
        done += 1;
        for r in map.crates.values() {
            if r.allowed.iter().any(|a| a == n) {
                let d = indeg.get_mut(r.name.as_str()).unwrap();
                *d -= 1;
                if *d == 0 {
                    ready.push(r.name.as_str());
                }
            }
        }
    }
    let cyclic: Vec<&str> = indeg
        .iter()
        .filter(|(_, d)| **d > 0)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(
        done,
        map.crates.len(),
        "the allowed graph has a cycle through {cyclic:?}"
    );
    // the plan's fixed points
    let allowed = |a: &str, b: &str| map.crates[a].allowed.iter().any(|x| x == b);
    assert!(
        !allowed("northnarrow-agent", "nn-server"),
        "nn-server is never in the agent"
    );
    assert!(
        !allowed("northnarrow-watchdog", "nn-core"),
        "the watchdog needs no engine"
    );
    for pure in map.crates.values().filter(|r| r.pure) {
        assert!(
            !allowed(&pure.name, "nn-linux"),
            "{}: a pure crate above nn-linux",
            pure.name
        );
    }
}

/// The text of `src` without `//` comments (doc comments included).
fn code_lines(src: &str) -> impl Iterator<Item = (usize, &str)> {
    src.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.split("//").next().unwrap_or("")))
}

#[test]
fn pure_crates_reach_no_os_interface() {
    let map = module_map();
    let ms = members();
    let pure: Vec<&support::Member> = ms.iter().filter(|m| map.crates[&m.name].pure).collect();
    assert!(
        pure.len() >= 5,
        "pure members: {:?}",
        pure.iter().map(|m| &m.name).collect::<Vec<_>>()
    );
    let mut bad = Vec::new();
    // direct dependencies
    for m in &pure {
        for d in m.deps.iter().filter(|d| d.kind != "dev") {
            if FORBIDDEN_DIRECT.contains(&d.name.as_str()) || forbidden_anywhere(&d.name) {
                bad.push(format!("{} depends on {} ({})", m.name, d.name, d.kind));
            }
        }
    }
    // normal dependencies, transitively, as resolved for the shipped
    // platform
    let meta = cargo_metadata(&["--locked", "--filter-platform", "x86_64-unknown-linux-gnu"]);
    let nodes = meta["resolve"]["nodes"].as_array().expect("resolve.nodes");
    let name_of: BTreeMap<&str, &str> = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["id"].as_str().unwrap(), p["name"].as_str().unwrap()))
        .collect();
    let normal_deps: BTreeMap<&str, Vec<&str>> = nodes
        .iter()
        .map(|n| {
            let deps = n["deps"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| {
                    d["dep_kinds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|k| k["kind"].is_null())
                })
                .map(|d| d["pkg"].as_str().unwrap())
                .collect();
            (n["id"].as_str().unwrap(), deps)
        })
        .collect();
    for m in &pure {
        let id = name_of
            .iter()
            .find(|(_, n)| **n == m.name)
            .map(|(id, _)| *id)
            .expect("the member in the resolve");
        let mut seen = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if x != id && forbidden_anywhere(name_of[x]) {
                bad.push(format!(
                    "{} reaches {} through its dependencies",
                    m.name, name_of[x]
                ));
            }
            stack.extend(normal_deps.get(x).into_iter().flatten());
        }
    }
    // the sources
    let root = repo_root();
    for m in &pure {
        let mut files = Vec::new();
        rs_files(&root.join(&m.dir), &mut files);
        assert!(!files.is_empty(), "{}: no source", m.name);
        for f in files {
            let text = fs::read_to_string(&f).unwrap();
            for (n, code) in code_lines(&text) {
                for t in FORBIDDEN_TEXT {
                    if code.contains(t) {
                        bad.push(format!(
                            "{}:{n}: `{t}` in a pure crate",
                            f.strip_prefix(&root).unwrap().display()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "the pure crates must build anywhere (docs/architecture/module-map.toml):\n{}",
        bad.join("\n")
    );
}

#[test]
fn portable_core_checks_every_pure_crate_for_the_other_targets() {
    let map = module_map();
    let pure: BTreeSet<String> = members()
        .into_iter()
        .filter(|m| map.crates[&m.name].pure)
        .map(|m| m.name)
        .collect();
    let wf: Yaml = serde_yaml_ng::from_str(
        &fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap(),
    )
    .unwrap();
    let job = wf
        .get("jobs")
        .and_then(|j| j.get("portable-core"))
        .expect("ci.yml has the portable-core job");
    let runs: Vec<String> = job
        .get("steps")
        .and_then(|s| s.as_sequence())
        .expect("steps")
        .iter()
        .filter_map(|s| s.get("run").and_then(|r| r.as_str()).map(str::to_string))
        .collect();
    let all = runs.join("\n");
    let words: Vec<&str> = all.split_whitespace().collect();
    let checked: BTreeSet<String> = words
        .windows(2)
        .filter(|w| w[0] == "-p")
        .map(|w| w[1].to_string())
        .collect();
    assert_eq!(
        checked, pure,
        "ci.yml portable-core: `-p` must be the pure crates of the map"
    );
    for t in PORTABLE_TARGETS {
        assert!(
            words.iter().filter(|w| w.trim_matches('"') == *t).count() >= 1,
            "ci.yml portable-core: no target {t}"
        );
    }
    assert!(
        all.contains("cargo check --locked --target"),
        "ci.yml portable-core: `cargo check --locked --target <t>`"
    );
    assert!(
        all.contains("rustup target add"),
        "ci.yml portable-core: the targets are installed"
    );
}

#[test]
fn crate_roots_forbid_unsafe_code_where_the_map_says() {
    let map = module_map();
    let root = repo_root();
    let mut bad = Vec::new();
    for m in members() {
        if !map.crates[&m.name].forbid_unsafe {
            continue;
        }
        let dir = root.join(&m.dir).join("src");
        let roots: Vec<_> = ["lib.rs", "main.rs"]
            .iter()
            .map(|f| dir.join(f))
            .filter(|p| p.is_file())
            .collect();
        assert!(!roots.is_empty(), "{}: no crate root", m.name);
        for r in roots {
            let text = fs::read_to_string(&r).unwrap();
            if !text.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]") {
                bad.push(format!("{}: no #![forbid(unsafe_code)]", r.display()));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn members_inherit_the_workspace_lints() {
    let root = repo_root();
    let cargo = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let kani = "unexpected_cfgs = { level = \"warn\", check-cfg = ['cfg(kani)'] }";
    assert!(
        cargo.contains(&format!("[workspace.lints.rust]\n{kani}")),
        "Cargo.toml: [workspace.lints.rust] declares cfg(kani)"
    );
    let mut bad = Vec::new();
    for m in members() {
        let manifest = fs::read_to_string(root.join(&m.dir).join("Cargo.toml")).unwrap();
        let inherits = manifest.contains("\n[lints]\nworkspace = true\n");
        if OWN_LINTS.contains(&m.name.as_str()) {
            if inherits || !manifest.contains(&format!("[lints.rust]\n{kani}")) {
                bad.push(format!(
                    "{}: its own [lints.rust], the workspace's table",
                    m.name
                ));
            }
        } else if !inherits {
            bad.push(format!("{}: `[lints]` `workspace = true`", m.name));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn the_crates_of_crates_dir_are_workspace_dependencies() {
    let cargo = fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    let deps = cargo
        .split("[workspace.dependencies]")
        .nth(1)
        .and_then(|s| s.split("\n[").next())
        .expect("Cargo.toml: [workspace.dependencies]");
    let ms = members();
    let in_crates: Vec<_> = ms.iter().filter(|m| m.dir.starts_with("crates/")).collect();
    assert!(
        in_crates.len() >= 7,
        "{} members under crates/",
        in_crates.len()
    );
    for m in in_crates {
        let want = format!("{} = {{ path = \"{}\" }}", m.name, m.dir);
        assert!(
            deps.lines().any(|l| l.trim() == want),
            "Cargo.toml [workspace.dependencies]: `{want}`"
        );
        assert_eq!(
            m.dir,
            format!("crates/{}", m.name),
            "{}: crates/<package>",
            m.name
        );
    }
}
