//! External audit NN-AUD-211: `northnarrow-agent --build-features` is the
//! positive marker the range bootstrap (`deploy/adversarial/
//! bootstrap-target-prod.sh`) checks before it installs a binary. It must
//! name exactly the test and debug features this build carries, and print
//! `none` for a release build. Runs unprivileged: the flag exits before
//! any eBPF or root work.
//!
//! External audit PROC-015 (NN-AUD-302): the release workflow checks the
//! same answer on every artefact it builds, so the list it reads is held
//! here to the crate's manifest.

use std::collections::BTreeSet;
use std::process::Command;

use northnarrow_agent::audit::LAB_FEATURES;

fn expected() -> String {
    let mut features = Vec::new();
    if cfg!(feature = "debug-trigger") {
        features.push("debug-trigger");
    }
    if cfg!(feature = "demo-tappa5") {
        features.push("demo-tappa5");
    }
    if cfg!(feature = "posture-demo") {
        features.push("posture-demo");
    }
    if cfg!(feature = "test-privileged") {
        features.push("test-privileged");
    }
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

#[test]
fn build_features_flag_names_the_compiled_lab_features() {
    let out = Command::new(env!("CARGO_BIN_EXE_northnarrow-agent"))
        .arg("--build-features")
        .output()
        .expect("run northnarrow-agent --build-features");
    assert!(out.status.success(), "exit status {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // One line, nothing else: the bootstrap compares it verbatim.
    assert_eq!(stdout, format!("{}\n", expected()));
}

/// The `[features]` table of a Cargo manifest: the value of `default`, and
/// every other feature's name. One `name = …` per line, as cargo writes it.
fn manifest_features(manifest: &str) -> (Option<String>, BTreeSet<String>) {
    let mut in_features = false;
    let mut default = None;
    let mut names = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        if name == "default" {
            default = Some(value.trim().replace(' ', ""));
        } else {
            names.insert(name.to_string());
        }
    }
    (default, names)
}

/// External audit PROC-015 (NN-AUD-302): every feature `agent/Cargo.toml`
/// declares is one `--build-features` names, and none is on by default. A
/// release build (`cargo xtask build --release`, no `--features`) then
/// carries none, and a feature added later cannot be compiled into a
/// release unseen: this test fails until `audit::LAB_FEATURES` lists it.
#[test]
fn every_cargo_feature_is_named_by_build_features() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let manifest = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let (default, declared) = manifest_features(&manifest);
    assert_eq!(
        default.as_deref(),
        Some("[]"),
        "agent/Cargo.toml: no feature may be a default (a release build passes no --features)"
    );
    assert!(
        declared.len() >= 4,
        "the manifest's [features] were not read: {declared:?}"
    );
    let named: BTreeSet<String> = LAB_FEATURES.iter().map(|(n, _)| n.to_string()).collect();
    assert_eq!(
        declared, named,
        "agent/Cargo.toml [features] vs audit::LAB_FEATURES: add the new feature to both"
    );
    // Each entry says what cargo compiled: the list cannot claim a feature
    // off while this build has it on.
    let built: Vec<&str> = LAB_FEATURES
        .iter()
        .filter(|(_, on)| *on)
        .map(|(n, _)| *n)
        .collect();
    let expected = expected();
    let expected: Vec<&str> = if expected == "none" {
        Vec::new()
    } else {
        expected.split(',').collect()
    };
    assert_eq!(built, expected);
}

#[test]
fn manifest_features_reads_the_features_table_only() {
    let toml = "[package]\nname = \"x\"\n\n[features]\n# a comment\ndefault = [ ]\n\
                a = []\nb = [\"dep/b\"]\n\n[dependencies]\nc = \"1\"\n";
    let (default, names) = manifest_features(toml);
    assert_eq!(default.as_deref(), Some("[]"));
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        vec!["a".to_string(), "b".to_string()]
    );
}
