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

/// Lot 276 (`.cargo/audit.toml`, RUSTSEC-2026-0049/-0098/-0099/-0104/-0382):
/// the five advisories against rustls-webpki 0.102 are recorded as not
/// reached because rustls-rustcrypto takes nothing of that copy but its
/// `alg_id` constants — this test reads the provider's locked sources and
/// fails the day it takes more.
#[test]
fn the_provider_takes_only_alg_ids_of_its_webpki() {
    let meta = support::cargo_metadata(&[]);
    let pkg = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "rustls-rustcrypto")
        .expect("rustls-rustcrypto is locked");
    assert_eq!(
        pkg["version"], "0.0.2-alpha",
        "re-check the advisories' entries for a new release"
    );
    let src = PathBuf::from(pkg["manifest_path"].as_str().unwrap())
        .parent()
        .unwrap()
        .join("src");
    let mut uses = Vec::new();
    for f in rs_files(&src) {
        let code = strip_comments(&fs::read_to_string(&f).unwrap());
        for (i, _) in code.match_indices("webpki") {
            let rest = &code[i..];
            let what: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            uses.push((f.display().to_string(), what));
        }
    }
    assert!(!uses.is_empty(), "the provider names webpki");
    let other: Vec<_> = uses
        .iter()
        .filter(|(_, w)| w != "webpki::alg_id" && w != "webpki")
        .collect();
    assert!(
        other.is_empty(),
        "rustls-rustcrypto uses more of rustls-webpki 0.102 than its alg_id constants: {other:?}"
    );
    // `webpki` alone: its Cargo.toml's dependency name, in a `use` path only
    let bare = uses.iter().filter(|(_, w)| w == "webpki").count();
    assert_eq!(bare, 0, "{uses:?}");
}
