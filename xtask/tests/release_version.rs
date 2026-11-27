//! Lot 383 (the alpha's version): one version, from Cargo.toml to the tag.
//!
//! The workspace said `0.0.1` while the release was to be tagged
//! `v0.1.0-alpha`: the tag would have published 0.0.1 artefacts, and the
//! CHANGELOG had only `[Unreleased]`. This ratchet holds together what
//! names the version: the workspace version, every crate's (the ones that
//! do not inherit it included), the three lockfiles' entries of our crates,
//! the CHANGELOG's top section, the packages' versions and file names
//! (`deploy/release/mk-packages.sh`), and the tag check of release.yml
//! (`verify-release-tag.sh version`).

mod support;

use std::path::Path;
use std::process::Command;

use support::{repo_root, tracked_files};

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `[workspace.package] version` of the root Cargo.toml.
fn workspace_version() -> String {
    let text = read("Cargo.toml");
    let mut in_section = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t == "[workspace.package]";
            continue;
        }
        if in_section {
            if let Some(v) = t.strip_prefix("version = ") {
                return v.trim_matches('"').to_string();
            }
        }
    }
    panic!("Cargo.toml has no [workspace.package] version")
}

/// The `version` of a manifest's `[package]`: `Some("workspace")` when it
/// inherits it.
fn package_version(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if t.replace(' ', "") == "version.workspace=true" {
            return Some("workspace".into());
        }
        if let Some(v) = t.strip_prefix("version = ") {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

/// The crates whose version is not the product's, and why.
const NOT_VERSIONED: &[(&str, &str)] = &[(
    "fuzz/Cargo.toml",
    "cargo-fuzz's harness, never built into an artefact nor published (`publish = false`): 0.0.0",
)];

#[test]
fn the_workspace_is_the_alpha() {
    assert_eq!(workspace_version(), "0.1.1-alpha");
}

#[test]
fn every_crate_carries_the_workspace_version() {
    let ws = workspace_version();
    let manifests: Vec<String> = tracked_files()
        .into_iter()
        .filter(|f| f == "Cargo.toml" || f.ends_with("/Cargo.toml"))
        .collect();
    assert!(manifests.len() > 15, "{manifests:?}");
    let mut bad = Vec::new();
    for rel in &manifests {
        if rel == "Cargo.toml" {
            continue;
        }
        let Some(v) = package_version(&read(rel)) else {
            bad.push(format!("{rel}: no [package] version"));
            continue;
        };
        if let Some((_, why)) = NOT_VERSIONED.iter().find(|(f, _)| f == rel) {
            assert_eq!(v, "0.0.0", "{rel} ({why})");
            continue;
        }
        if v != "workspace" && v != ws {
            bad.push(format!("{rel}: version {v}, the workspace's is {ws}"));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    // the eBPF crate is its own project (nightly, bpfel): it cannot inherit
    assert_eq!(
        package_version(&read("agent-ebpf/Cargo.toml")).as_deref(),
        Some(ws.as_str())
    );
}

/// The packages of a lockfile that are ours: path packages (no `source`).
fn our_locked(lock: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |k: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{k} = ")))
                .map(|v| v.trim_matches('"').to_string())
        };
        if field("source").is_none() {
            out.push((field("name").unwrap(), field("version").unwrap()));
        }
    }
    out
}

#[test]
fn the_lockfiles_carry_the_workspace_version_of_our_crates() {
    let ws = workspace_version();
    for lock in ["Cargo.lock", "agent-ebpf/Cargo.lock", "fuzz/Cargo.lock"] {
        let ours = our_locked(&read(lock));
        assert!(ours.len() >= 2, "{lock}: {ours:?}");
        for (name, v) in ours {
            let want = if name == "northnarrow-fuzz" {
                "0.0.0"
            } else {
                ws.as_str()
            };
            assert_eq!(v, want, "{lock}: {name}");
        }
    }
}

/// The first `## ` heading of the CHANGELOG that is not `[Unreleased]`.
fn top_release_section(changelog: &str) -> &str {
    changelog
        .lines()
        .filter(|l| l.starts_with("## "))
        .find(|l| *l != "## [Unreleased]")
        .expect("CHANGELOG.md has a release section")
}

#[test]
fn the_changelog_opens_with_the_workspace_versions_section() {
    let ws = workspace_version();
    let changelog = read("CHANGELOG.md");
    let head = top_release_section(&changelog);
    let date = head
        .strip_prefix(&format!("## [{ws}] - "))
        .unwrap_or_else(|| panic!("the top release section is `{head}`, not `## [{ws}] - …`"));
    let dated = date.len() == 10
        && date.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        });
    assert!(
        dated || date == "unreleased",
        "`{head}`: the date is YYYY-MM-DD (the tag's day), or `unreleased` until the commit before the tag"
    );
    // the section is the only one of its version
    let n = changelog
        .lines()
        .filter(|l| l.starts_with(&format!("## [{ws}]")))
        .count();
    assert_eq!(n, 1, "{ws} has {n} sections");
}

#[test]
fn the_changelog_check_reads_the_first_release_section() {
    let with_unreleased = "# Changelog\n\n## [Unreleased]\n\n- x\n\n## [1.0.0] - 2026-01-01\n";
    assert_eq!(
        top_release_section(with_unreleased),
        "## [1.0.0] - 2026-01-01"
    );
    let plain = "# Changelog\n\n## [0.1.1-alpha] - unreleased\n\n## [0.1.0-alpha] - 2026-11-23\n";
    assert_eq!(top_release_section(plain), "## [0.1.1-alpha] - unreleased");
}

fn mk_packages_versions(release: &str) -> Vec<(String, String)> {
    let out = Command::new("bash")
        .arg(repo_root().join("deploy/release/mk-packages.sh"))
        .env("NN_PKG_PRINT_VERSIONS", "1")
        .env("NN_PKG_RELEASE", release)
        .output()
        .expect("bash runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn the_packages_carry_the_pre_release_with_a_tilde_and_the_files_with_a_dash() {
    let got = mk_packages_versions("3");
    let want: Vec<(String, String)> = [
        ("version", "0.1.1-alpha"),
        ("package", "0.1.1~alpha"),
        ("deb", "0.1.1~alpha-3"),
        ("rpm", "0.1.1~alpha 3"),
        ("deb_file", "northnarrow_0.1.1-alpha-3_amd64.deb"),
        ("rpm_file", "northnarrow-0.1.1-alpha-3.x86_64.rpm"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(got, want);
    // no `~` in a release asset's name; rpm refuses `-` in a Version
    let script = read("deploy/release/mk-packages.sh");
    for needle in [
        "Version: ${pkgver}-${REL}",
        "Version:        ${pkgver}",
        "pkg=\"$OUT/northnarrow_${ver}-${REL}_amd64.deb\"",
        "pkg=\"$OUT/northnarrow-${ver}-${REL}.x86_64.rpm\"",
    ] {
        assert!(script.contains(needle), "mk-packages.sh: `{needle}`");
    }
    let tarball = read("deploy/release/mk-tarball.sh");
    assert!(tarball.contains("name=\"northnarrow-${ver}-${arch}-linux\""));
}

/// dpkg orders the alpha before its release and after 0.0.1 (the
/// packages' upgrade path), and each alpha after the one before it (the
/// upgrade from the published `0.1.0~alpha`). Where dpkg is absent the
/// order is the release workflow's to check (its package job checks dpkg's
/// and rpm's).
#[test]
fn dpkg_sorts_the_alpha_between_0_0_1_and_0_1_0() {
    let cmp = |a: &str, op: &str, b: &str| {
        Command::new("dpkg")
            .args(["--compare-versions", a, op, b])
            .status()
            .map(|s| s.success())
    };
    let Ok(lt) = cmp("0.1.0~alpha-1", "lt", "0.1.0-1") else {
        eprintln!("no dpkg here: the release workflow checks the order");
        return;
    };
    assert!(lt, "0.1.0~alpha-1 < 0.1.0-1");
    assert!(cmp("0.1.0~alpha-1", "gt", "0.0.1-9").unwrap());
    assert!(cmp("0.1.0~alpha-2", "gt", "0.1.0~alpha-1").unwrap());
    // lot R1: the second alpha upgrades the published first one, and sorts
    // before its own release
    assert!(cmp("0.1.1~alpha-1", "gt", "0.1.0~alpha-1").unwrap());
    assert!(cmp("0.1.1~alpha-1", "gt", "0.1.0-1").unwrap());
    assert!(cmp("0.1.1~alpha-1", "lt", "0.1.1-1").unwrap());
}

#[test]
fn a_tag_is_released_only_as_the_workspace_version_with_its_dated_section() {
    let root = repo_root();
    let ws = workspace_version();
    let release = read(".github/workflows/release.yml");
    assert!(
        release.contains(".github/scripts/verify-release-tag.sh version \"$TAG\""),
        "release.yml's verify-tag runs the version check"
    );
    for needle in [
        "NN_PKG_PRINT_VERSIONS=1 deploy/release/mk-packages.sh",
        "--version | head -1",
        "dpkg --compare-versions",
        "rpm.vercmp",
    ] {
        assert!(
            release.contains(needle),
            "release.yml's package job: `{needle}`"
        );
    }

    // the check, on this tree's Cargo.toml and on its CHANGELOG once dated
    let dir = std::env::temp_dir().join(format!("nn383-changelog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let changelog = read("CHANGELOG.md");
    let head = top_release_section(&changelog).to_string();
    let dated = changelog.replacen(&head, &format!("## [{ws}] - 2026-11-21"), 1);
    let dated_path = dir.join("CHANGELOG.md");
    std::fs::write(&dated_path, dated).unwrap();
    let run = |tag: &str, changelog: &Path| {
        Command::new("bash")
            .arg(root.join(".github/scripts/verify-release-tag.sh"))
            .args(["version", tag])
            .arg(root.join("Cargo.toml"))
            .arg(changelog)
            .output()
            .expect("bash runs")
    };
    let ok = run(&format!("v{ws}"), &dated_path);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    // the release without its pre-release, an earlier tag (the published
    // first alpha among them), the version without its `v`, a longer
    // pre-release
    let plain = ws.split('-').next().unwrap();
    for tag in [
        format!("v{plain}"),
        "v0.1.0".to_string(),
        "v0.1.0-alpha".to_string(),
        "v0.0.1".to_string(),
        ws.clone(),
        format!("v{ws}.1"),
    ] {
        let r = run(&tag, &dated_path);
        assert_eq!(r.status.code(), Some(1), "{tag} was accepted");
    }
    std::fs::remove_dir_all(&dir).ok();
    // the tree as it is: dated, or refused until the date is written
    let as_is = run(&format!("v{ws}"), &root.join("CHANGELOG.md"));
    if head.ends_with(" - unreleased") {
        assert_eq!(as_is.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&as_is.stderr).contains("write the day of the tag"));
    } else {
        assert!(as_is.status.success());
    }
}
