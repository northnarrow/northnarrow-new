//! The guardrails of the Wave 4 restructure, R00 (lab PR 239): what names
//! a path or a package must name something that exists, so moving a file or
//! a module between crates cannot switch a check off without a failure.
//!
//! - every `paths:` / `paths-ignore:` filter of every workflow matches a
//!   tracked file (a filter on a moved file never starts its workflow);
//! - every `cargo kani -p <pkg> --harness <h>` of the workflows names a
//!   workspace member and a `#[kani::proof]` of that member's sources;
//! - every `-p <pkg>` / `--package <pkg>`, `<pkg>/<feature>` and the
//!   `--features` of a single `-p` in the workflows and the lab and CI
//!   scripts name a member and a feature it declares;
//! - every repository file the xtask tests name (`"agent/src/…/x.rs"`)
//!   exists (a scan of a moved file must not read nothing and pass);
//! - no member reaches a file outside itself through a path relative to
//!   the including file or to its manifest (`include_str!("../…")`,
//!   `CARGO_MANIFEST_DIR/..`): `NN_REPO_ROOT` (`.cargo/config.toml`) says
//!   where the repository is, at any depth and in any crate.

mod support;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_yaml_ng::Value as Yaml;
use support::{members, repo_root, rs_files};

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The files git tracks, repository-relative.
fn tracked() -> Vec<String> {
    let out = Command::new("git")
        .current_dir(repo_root())
        .args(["ls-files", "-z"])
        .output()
        .expect("git ls-files runs");
    assert!(out.status.success(), "git ls-files failed");
    let files: Vec<String> = out
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    assert!(
        files.len() > 500,
        "git ls-files lists {} files",
        files.len()
    );
    files
}

fn workflows() -> Vec<(String, Yaml)> {
    let dir = repo_root().join(".github/workflows");
    let mut out: Vec<(String, Yaml)> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p| {
            let rel = format!(
                ".github/workflows/{}",
                p.file_name().unwrap().to_string_lossy()
            );
            let y = serde_yaml_ng::from_str(&fs::read_to_string(&p).unwrap())
                .unwrap_or_else(|e| panic!("{rel}: {e}"));
            (rel, y)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(out.len() >= 4, "{} workflows", out.len());
    out
}

/// The `run:` texts of every step of every job.
fn run_texts(wf: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(jobs) = wf.get("jobs").and_then(|j| j.as_mapping()) {
        for (_, job) in jobs {
            if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                for s in steps {
                    if let Some(r) = s.get("run").and_then(|r| r.as_str()) {
                        out.push(r.to_string());
                    }
                }
            }
        }
    }
    out
}

/// A GitHub path filter: `**/` (any directories, none included), `**`
/// (anything), `*` (anything but `/`), `?`, the rest literal.
fn glob(pat: &[u8], path: &[u8]) -> bool {
    if let Some(rest) = pat.strip_prefix(b"**/") {
        return glob(rest, path)
            || path
                .iter()
                .enumerate()
                .any(|(i, &c)| c == b'/' && glob(rest, &path[i + 1..]));
    }
    if let Some(rest) = pat.strip_prefix(b"**") {
        return (0..=path.len()).any(|i| glob(rest, &path[i..]));
    }
    match pat.first() {
        None => path.is_empty(),
        Some(b'*') => (0..=path.len())
            .take_while(|&i| i == 0 || path[i - 1] != b'/')
            .any(|i| glob(&pat[1..], &path[i..])),
        Some(b'?') => !path.is_empty() && path[0] != b'/' && glob(&pat[1..], &path[1..]),
        Some(&c) => path.first() == Some(&c) && glob(&pat[1..], &path[1..]),
    }
}

#[test]
fn the_glob_reads_github_filters() {
    // (no real repository path here: the literal scan below would read it)
    assert!(glob(b"a/**", b"a/b/c.x"));
    assert!(glob(b"a/b-c/**", b"a/b-c/d.sh"));
    assert!(!glob(b"a/**", b"a-b/c/d.x"));
    assert!(glob(b"**/*.toml", b"a/Cargo.toml"));
    assert!(glob(b"**/*.toml", b"Cargo.toml"));
    assert!(glob(b"*.md", b"README.md"));
    assert!(!glob(b"*.md", b"x/README.md"));
    assert!(glob(b"a/b/c.x", b"a/b/c.x"));
    assert!(!glob(b"a/b/c.x", b"a/b/c.x.orig"));
    assert!(glob(b"a/?.x", b"a/b.x") && !glob(b"a/?.x", b"a//.x"));
}

/// Every path filter of every workflow matches a tracked file.
#[test]
fn every_workflow_path_filter_matches_a_tracked_file() {
    let files = tracked();
    let mut seen = 0;
    let mut bad = Vec::new();
    for (rel, wf) in workflows() {
        let Some(on) = wf.get("on").and_then(|o| o.as_mapping()) else {
            continue;
        };
        for (event, cfg) in on {
            for key in ["paths", "paths-ignore"] {
                let Some(list) = cfg.get(key).and_then(|p| p.as_sequence()) else {
                    continue;
                };
                for p in list {
                    let p = p.as_str().unwrap_or_else(|| panic!("{rel}: {p:?}"));
                    seen += 1;
                    let pat = p.strip_prefix('!').unwrap_or(p);
                    if !files.iter().any(|f| glob(pat.as_bytes(), f.as_bytes())) {
                        bad.push(format!(
                            "{rel}: on.{}.{key}: `{p}` matches no tracked file",
                            event.as_str().unwrap_or("?")
                        ));
                    }
                }
            }
        }
    }
    assert!(seen > 20, "only {seen} path filters found");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The `#[kani::proof]` functions under `dir`.
fn proofs(dir: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    rs_files(dir, &mut files);
    let mut out = BTreeSet::new();
    for f in files {
        let text = fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if l.trim() != "#[kani::proof]" {
                continue;
            }
            if let Some(name) = lines[i + 1..].iter().find_map(|l| {
                let l = l.trim();
                let rest = l
                    .strip_prefix("fn ")
                    .or_else(|| l.strip_prefix("pub fn "))?;
                rest.split('(').next().map(str::to_string)
            }) {
                out.insert(name);
            }
        }
    }
    out
}

/// One cargo invocation of a script or a step: its subcommand (or `+…`
/// toolchain and then the subcommand) and its arguments, quotes stripped,
/// up to the end of the shell command.
fn cargo_calls(text: &str) -> Vec<Vec<String>> {
    let joined = text.replace("\\\n", " ");
    let mut out = Vec::new();
    for line in joined.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let line = line.replace("&&", ";").replace("||", ";").replace('|', ";");
        for segment in line.split(';') {
            let tokens: Vec<String> = segment
                .split_whitespace()
                .map(|t| {
                    t.trim_matches(|c| c == '"' || c == '\'' || c == '\\')
                        .to_string()
                })
                .collect();
            if let Some(at) = tokens
                .iter()
                .position(|t| t == "cargo" || t.ends_with("/cargo"))
            {
                out.push(tokens[at + 1..].to_vec());
            }
        }
    }
    out
}

/// (package, feature or `None`) named by one cargo call; `$…` skipped.
fn packages_and_features(args: &[String]) -> Vec<(String, Option<String>)> {
    let mut pkgs = Vec::new();
    let mut feats = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let value = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        if a == "-p" || a == "--package" {
            pkgs.push(value(i));
            i += 2;
            continue;
        }
        if let Some(p) = a.strip_prefix("--package=") {
            pkgs.push(p.to_string());
        } else if a == "--features" || a == "-F" {
            feats.extend(value(i).split(',').map(str::to_string));
            i += 2;
            continue;
        } else if let Some(f) = a.strip_prefix("--features=") {
            feats.extend(f.split(',').map(str::to_string));
        } else if a == "--" {
            break;
        }
        i += 1;
    }
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for p in &pkgs {
        if !p.contains('$') && !p.is_empty() {
            out.push((p.clone(), None));
        }
    }
    for f in feats {
        if f.contains('$') || f.is_empty() {
            continue;
        }
        match f.split_once('/') {
            Some((p, f)) => out.push((p.to_string(), Some(f.to_string()))),
            None if pkgs.len() == 1 && !pkgs[0].contains('$') => {
                out.push((pkgs[0].clone(), Some(f)))
            }
            None => {}
        }
    }
    out
}

/// The shell scripts that build or test packages: the lab's and CI's.
fn scripts() -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["deploy/lab", ".github/scripts"] {
        let mut v: Vec<String> = fs::read_dir(repo_root().join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "sh"))
            .map(|p| format!("{dir}/{}", p.file_name().unwrap().to_string_lossy()))
            .collect();
        v.sort();
        out.extend(v);
    }
    assert!(out.iter().any(|s| s == "deploy/lab/nn-lab.sh"), "{out:?}");
    out
}

#[test]
fn every_package_and_feature_the_ci_and_the_lab_name_exists() {
    let members = members();
    let find = |name: &str| members.iter().find(|m| m.name == name);
    let mut texts: Vec<(String, String)> = Vec::new();
    for (rel, wf) in workflows() {
        for r in run_texts(&wf) {
            texts.push((rel.clone(), r));
        }
    }
    for s in scripts() {
        texts.push((s.clone(), read(&s)));
    }
    let mut checked = 0;
    let mut bad = Vec::new();
    for (rel, text) in &texts {
        for call in cargo_calls(text) {
            for (pkg, feat) in packages_and_features(&call) {
                checked += 1;
                let Some(m) = find(&pkg) else {
                    bad.push(format!(
                        "{rel}: `cargo {}`: `{pkg}` is no workspace member",
                        call.join(" ")
                    ));
                    continue;
                };
                if let Some(f) = feat {
                    if !m.features.contains(&f) {
                        bad.push(format!("{rel}: `{pkg}` declares no feature `{f}`"));
                    }
                }
            }
        }
    }
    assert!(
        checked > 25,
        "only {checked} package and feature names found"
    );
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn every_kani_step_names_a_member_and_one_of_its_proofs() {
    let members = members();
    let mut steps = 0;
    let mut bad = Vec::new();
    for (rel, wf) in workflows() {
        for r in run_texts(&wf) {
            for call in cargo_calls(&r) {
                if call.first().map(String::as_str) != Some("kani") {
                    continue;
                }
                let arg = |flag: &str| {
                    call.iter()
                        .position(|a| a == flag)
                        .and_then(|i| call.get(i + 1))
                        .cloned()
                };
                let Some(h) = arg("--harness") else {
                    continue; // `cargo kani setup`
                };
                steps += 1;
                let pkg = arg("-p").or_else(|| arg("--package")).unwrap_or_default();
                let Some(m) = members.iter().find(|m| m.name == pkg) else {
                    bad.push(format!(
                        "{rel}: `cargo kani -p {pkg}`: no such workspace member"
                    ));
                    continue;
                };
                if !proofs(&repo_root().join(&m.dir)).contains(&h) {
                    bad.push(format!(
                        "{rel}: `--harness {h}`: no #[kani::proof] fn {h} in {} ({pkg})",
                        m.dir
                    ));
                }
            }
        }
    }
    assert!(steps >= 4, "only {steps} kani harness steps found");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The top-level entries of the repository a literal path can start with.
fn top_level() -> BTreeSet<String> {
    fs::read_dir(repo_root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "target" && n != ".git")
        .collect()
}

/// Every repository file named by a string literal of xtask's tests and
/// sources (a path with a file extension under a top-level directory)
/// exists.
#[test]
fn every_file_the_xtask_tests_name_exists() {
    let root = repo_root();
    let tops = top_level();
    let mut files = Vec::new();
    rs_files(&root.join("xtask"), &mut files);
    let mut checked = 0;
    let mut bad = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        for lit in text.split('"').skip(1).step_by(2) {
            let ok_chars = lit
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-/".contains(c));
            let Some((top, _)) = lit.split_once('/') else {
                continue;
            };
            let last = lit.rsplit('/').next().unwrap_or("");
            if !ok_chars || !tops.contains(top) || !last.contains('.') || last.ends_with('.') {
                continue;
            }
            checked += 1;
            if !root.join(lit).exists() {
                bad.push(format!(
                    "{}: \"{lit}\" does not exist",
                    f.strip_prefix(&root).unwrap().display()
                ));
            }
        }
    }
    assert!(checked > 40, "only {checked} literal paths found");
    // the files the scans of lab_scripts.rs and operator_docs.rs read
    for known in [
        "crates/nn-linux/src/anti_tamper/mod.rs",
        "crates/nn-linux/src/host_hardening.rs",
    ] {
        assert!(root.join(known).is_file(), "{known}");
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The places a member may still reach the repository by its own
/// position: xtask lives at the root by definition; common's sources are
/// the eBPF object's source closure (an edit rebuilds the object) and
/// common stays where it is (nn-wire). The build script that embeds the
/// object moved with the sensors to nn-linux (R09b, lab PR 254) and reads
/// `NN_REPO_ROOT` since.
const DEPTH_RELATIVE_ALLOWED: &[&str] = &["xtask/", "common/src/"];

#[test]
fn members_reach_the_repository_through_nn_repo_root() {
    let config = read(".cargo/config.toml");
    let env_line = config
        .lines()
        .map(|l| l.split('#').next().unwrap().trim())
        .find(|l| l.starts_with("NN_REPO_ROOT"))
        .expect(".cargo/config.toml: [env] NN_REPO_ROOT");
    assert_eq!(
        env_line.split_whitespace().collect::<String>(),
        "NN_REPO_ROOT={value=\".\",relative=true}",
        ".cargo/config.toml"
    );
    let root = repo_root();
    let mut bad = Vec::new();
    let mut uses = 0;
    for m in members() {
        let mut files = Vec::new();
        rs_files(&root.join(&m.dir), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&f).unwrap();
            uses += text.matches("env!(\"NN_REPO_ROOT\")").count();
            if DEPTH_RELATIVE_ALLOWED.iter().any(|a| rel.starts_with(a)) {
                continue;
            }
            for (n, line) in text.lines().enumerate() {
                if line.contains("include_str!(\"../") || line.contains("include_bytes!(\"../") {
                    bad.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
            }
            // CARGO_MANIFEST_DIR, then `..` or `.parent()` before the end of
            // the statement
            for (at, _) in text.match_indices("CARGO_MANIFEST_DIR") {
                let rest = &text[at..];
                let stmt = &rest[..rest.find(';').unwrap_or(rest.len()).min(400)];
                if stmt.contains("\"..")
                    || stmt.contains("\"/..")
                    || stmt.contains("/../")
                    || stmt.contains(".parent()")
                {
                    let line = text[..at].matches('\n').count() + 1;
                    bad.push(format!(
                        "{rel}:{line}: CARGO_MANIFEST_DIR outside the crate"
                    ));
                }
            }
        }
    }
    assert!(uses > 30, "only {uses} uses of NN_REPO_ROOT found");
    assert!(
        bad.is_empty(),
        "reach the repository with concat!(env!(\"NN_REPO_ROOT\"), \"/…\") (.cargo/config.toml), \
         not from where the file sits:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_cargo_call_reader_finds_packages_and_features() {
    let calls = cargo_calls(
        "set -e\n# cargo test -p commented-out\ncargo test --locked -p a --features x,b/y \\\n  -- --ignored | tee log\n\
         vcargo \"cargo build -p c -p d 2>&1 | grep -v x\"\nssh -p 22 host\ncargo +nightly fuzz build\n",
    );
    let got: Vec<Vec<(String, Option<String>)>> =
        calls.iter().map(|c| packages_and_features(c)).collect();
    let s = |v: &str| v.to_string();
    assert_eq!(
        got,
        vec![
            vec![
                (s("a"), None),
                (s("a"), Some(s("x"))),
                (s("b"), Some(s("y")))
            ],
            vec![(s("c"), None), (s("d"), None)],
            vec![],
        ]
    );
}
