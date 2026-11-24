//! Lot 276 (the restructure plan's §3.1, the brief's "never in the root
//! core"): the export's OCSF mapping, its sinks and TLS run in the export
//! worker only — the unprivileged, sandboxed process
//! (`agent/src/export/worker.rs`, `nn_linux::sandbox::Profile::export`).
//! The core's side of the export reads the chains and keeps the cursors
//! (`nn_export::wal`, `nn_export::config`) and nothing else of nn-export.
//!
//! The production sources of the core — the agent, nn-linux, nn-core,
//! nn-evidence — name rustls, and nn-export's worker-side modules (`ocsf`,
//! `jsonl`, `syslog`, `net`, `tls`, `worker`), only in the export worker's
//! entry; that entry is reached only as the argument of the worker mode of
//! `main` (`worker::serve::main(`); and in nn-export itself rustls is named
//! by `tls` and `net` alone.

mod support;

use std::fs;
use std::path::PathBuf;

use support::{production, repo_root, strip_comments};

const TREES: &[&str] = &[
    "agent/src",
    "crates/nn-linux/src",
    "crates/nn-core/src",
    "crates/nn-evidence/src",
];

/// The export worker's entry: the one file of the core's trees that may
/// name what runs in the worker.
const ENTRY: &str = "agent/src/export/worker.rs";

/// What runs in the worker only.
const WORKER_ONLY: &[&str] = &[
    "rustls",
    "nn_export::ocsf",
    "nn_export::jsonl",
    "nn_export::syslog",
    "nn_export::net",
    "nn_export::tls",
    "nn_export::worker",
];

fn rs_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    support::rs_files(dir, &mut out);
    out.sort();
    out
}

fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "tests.rs" || name.ends_with("_tests.rs") || rel.contains("/tests/")
}

/// What a production source of the core names of the worker's side.
fn reaches_the_worker(code: &str) -> Vec<String> {
    let mut out: Vec<String> = WORKER_ONLY
        .iter()
        .filter(|w| code.contains(**w))
        .map(|w| format!("names {w}"))
        .collect();
    let entry = code.matches("export::worker::").count();
    let as_argument = code.matches("export::worker::main,").count();
    if entry > as_argument {
        out.push("reaches the export worker's entry beyond the worker mode of main".into());
    }
    out
}

#[test]
fn the_core_runs_nothing_of_the_export_worker() {
    let mut bad = Vec::new();
    let mut entry_seen = false;
    for tree in TREES {
        for f in rs_files(&repo_root().join(tree)) {
            let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
            if is_test_file(&rel) {
                continue;
            }
            let code = production(&strip_comments(&fs::read_to_string(&f).unwrap()));
            if rel == ENTRY {
                entry_seen = true;
                assert!(
                    code.contains("sandbox::Profile::export(") && code.contains("serve::run("),
                    "{ENTRY}: the worker enters its sandbox through serve::run"
                );
                continue;
            }
            bad.extend(
                reaches_the_worker(&code)
                    .into_iter()
                    .map(|w| format!("{rel}: {w}")),
            );
        }
    }
    assert!(entry_seen, "{ENTRY} is gone: update this guard");
    assert!(
        bad.is_empty(),
        "the core runs the export worker's code:\n{}",
        bad.join("\n")
    );
    // the worker mode of main hands it on, once
    let boot = production(&strip_comments(
        &fs::read_to_string(repo_root().join("agent/src/boot/mod.rs")).unwrap(),
    ));
    assert_eq!(
        boot.matches("northnarrow_agent::export::worker::main,")
            .count(),
        1,
        "agent/src/boot/mod.rs passes the export worker's entry to serve::main"
    );
}

#[test]
fn rustls_is_named_by_the_tls_client_alone() {
    let mut bad = Vec::new();
    for f in rs_files(&repo_root().join("crates/nn-export/src")) {
        let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
        if is_test_file(&rel) {
            continue;
        }
        let code = production(&strip_comments(&fs::read_to_string(&f).unwrap()));
        let allowed = rel.ends_with("/tls.rs") || rel.ends_with("/net.rs");
        if code.contains("rustls") && !allowed {
            bad.push(rel);
        }
    }
    assert!(bad.is_empty(), "rustls outside tls.rs and net.rs: {bad:?}");
}

#[test]
fn a_planted_call_in_the_core_fails() {
    for planted in [
        "fn f(v: &[u8]) { let _ = nn_export::ocsf::to_line(&serde_json::json!(v)); }\n",
        "use rustls::ClientConfig;\n",
        "fn f(a: &Args) -> i32 { northnarrow_agent::export::worker::main(a) }\n",
    ] {
        let code = production(&strip_comments(planted));
        assert!(!reaches_the_worker(&code).is_empty(), "{planted}");
    }
    let fine = "nn_linux::worker::serve::main(&args, northnarrow_agent::export::worker::main,)\n";
    assert!(reaches_the_worker(&production(&strip_comments(fine))).is_empty());
}

/// One `[[package]]` of a Cargo.lock: its name, its version and its
/// `dependencies` entries (`"name"`, or `"name version"` when the lockfile
/// holds two versions of it).
struct LockedPackage {
    name: String,
    version: String,
    deps: Vec<String>,
}

fn locked_packages(lock: &str) -> Vec<LockedPackage> {
    let field = |block: &str, key: &str| {
        block.lines().find_map(|l| {
            l.strip_prefix(key)
                .map(|v| v.trim().trim_matches('"').to_string())
        })
    };
    lock.split("[[package]]")
        .skip(1)
        .map(|block| {
            let deps = block
                .split_once("dependencies = [")
                .map(|(_, rest)| rest.split(']').next().unwrap_or(""))
                .unwrap_or("")
                .lines()
                .map(|l| l.trim().trim_end_matches(',').trim_matches('"').to_string())
                .filter(|d| !d.is_empty())
                .collect();
            LockedPackage {
                name: field(block, "name = ").unwrap_or_default(),
                version: field(block, "version = ").unwrap_or_default(),
                deps,
            }
        })
        .collect()
}

/// The packages of `lock` that depend on `name` (any version).
fn dependents_of<'a>(lock: &'a [LockedPackage], name: &str) -> Vec<&'a str> {
    lock.iter()
        .filter(|p| {
            p.deps
                .iter()
                .any(|d| d.split_whitespace().next() == Some(name))
        })
        .map(|p| p.name.as_str())
        .collect()
}

/// The lockfiles the agent is built from (the workspace, the fuzz harness).
const AGENT_LOCKS: [&str; 2] = ["Cargo.lock", "fuzz/Cargo.lock"];

/// Lot 398: rustls-rustcrypto 0.1.0-pre.0 has no copy of rustls-webpki
/// (0.0.2-alpha pinned 0.102 for its `alg_id` constants, now taken from
/// rustls-pki-types), and the five advisories against that copy
/// (RUSTSEC-2026-0049/-0098/-0099/-0104/-0382, lot 276's exceptions in
/// `.cargo/audit.toml`) left with it. Each lockfile locks ONE
/// rustls-webpki — rustls' own, which verifies the receiver's chain — at
/// 0.103 or later, and nothing else depends on it: a second copy coming
/// back (a provider release, another TLS crate) fails here, by name,
/// before `cargo audit` meets its advisories.
#[test]
fn one_rustls_webpki_and_only_rustls_own() {
    for lock in AGENT_LOCKS {
        let text = fs::read_to_string(repo_root().join(lock)).unwrap();
        let packages = locked_packages(&text);
        let webpki: Vec<&str> = packages
            .iter()
            .filter(|p| p.name == "rustls-webpki")
            .map(|p| p.version.as_str())
            .collect();
        assert_eq!(webpki.len(), 1, "{lock}: rustls-webpki locked {webpki:?}");
        let mut v = webpki[0].split('.').map(|n| n.parse::<u64>().unwrap_or(0));
        let (major, minor) = (v.next().unwrap_or(0), v.next().unwrap_or(0));
        assert!(
            (major, minor) >= (0, 103),
            "{lock}: rustls-webpki {} (0.102 and older: the advisories of lot 276)",
            webpki[0]
        );
        assert_eq!(
            dependents_of(&packages, "rustls-webpki"),
            vec!["rustls"],
            "{lock}: rustls-webpki is rustls' own only"
        );
        let provider = packages
            .iter()
            .find(|p| p.name == "rustls-rustcrypto")
            .unwrap_or_else(|| panic!("{lock}: rustls-rustcrypto is locked"));
        assert!(
            provider.deps.iter().any(|d| d == "rustls-pki-types"),
            "{lock}: the provider's alg_id constants come from rustls-pki-types"
        );
    }
}

#[test]
fn a_second_rustls_webpki_is_seen() {
    // the lockfile's shape on main before lot 398: two copies, the
    // provider depending on the old one
    let before = "[[package]]\nname = \"rustls\"\nversion = \"0.23.46\"\ndependencies = [\n \"rustls-webpki 0.103.16\",\n]\n\n\
                  [[package]]\nname = \"rustls-rustcrypto\"\nversion = \"0.0.2-alpha\"\ndependencies = [\n \"rustls\",\n \"rustls-webpki 0.102.8\",\n]\n\n\
                  [[package]]\nname = \"rustls-webpki\"\nversion = \"0.102.8\"\n\n\
                  [[package]]\nname = \"rustls-webpki\"\nversion = \"0.103.16\"\n";
    let p = locked_packages(before);
    assert_eq!(p.iter().filter(|p| p.name == "rustls-webpki").count(), 2);
    assert_eq!(
        dependents_of(&p, "rustls-webpki"),
        vec!["rustls", "rustls-rustcrypto"]
    );
    assert_eq!(p[1].deps, vec!["rustls", "rustls-webpki 0.102.8"]);
}
