//! Host prerequisites the install paths carry (lab follow-up, lab PR 165).
//! The agent's per-process outbound block (a BlockOutbound verdict, the
//! COMBAT soft egress block of INVESTIGATE) is an nftables rule applied
//! with `nft`, and Debian 12's cloud image ships without it: the packages
//! depend on nftables, `install.sh` refuses a host without it unless told,
//! and every lab guest installs it. Each test reads committed files only.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The .deb pre-depends on nftables (dpkg refuses before the pre-unpack
/// hook stops the running agent) and the .rpm requires it.
#[test]
fn the_packages_depend_on_nftables() {
    let text = read("deploy/release/mk-packages.sh");
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("the .deb control has no {name} line"))
            .split(',')
            .map(|d| d.trim().to_string())
            .collect::<Vec<_>>()
    };
    assert!(
        field("Pre-Depends:").iter().any(|d| d == "nftables"),
        "the .deb must pre-depend on nftables"
    );
    assert!(
        !field("Depends:").iter().any(|d| d.starts_with("nftables")),
        "nftables belongs in Pre-Depends, not Depends"
    );
    assert!(
        text.lines()
            .any(|l| l.split_whitespace().eq(["Requires:", "nftables"])),
        "the .rpm spec must require nftables"
    );
}

/// Every lab guest template installs nftables.
#[test]
fn every_lab_guest_installs_nftables() {
    let dir = repo_root().join("deploy/lab");
    let mut templates: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("readable directory entry").path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("user-data") && n.ends_with(".tmpl"))
        })
        .collect();
    templates.sort();
    assert!(templates.len() >= 3, "{templates:?}");
    for t in templates {
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&fs::read_to_string(&t).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", t.display()));
        let packages = doc
            .get("packages")
            .and_then(|p| p.as_sequence())
            .unwrap_or_else(|| panic!("{}: no packages list", t.display()));
        assert!(
            packages.iter().any(|p| p.as_str() == Some("nftables")),
            "{} must install nftables",
            t.display()
        );
    }
}

/// `install.sh` takes `--without-nftables`, checks for `nft` before it
/// changes the host, and records the flag in the install manifest.
#[test]
fn install_sh_refuses_a_host_without_nft_unless_told() {
    let text = read("deploy/install.sh");
    assert!(text.contains("--without-nftables) WITHOUT_NFT=1 ;;"));
    assert!(text.contains("\"prerequisite_overrides\": $(prereq_overrides_json)"));
    let def = text
        .find("require_nft() {")
        .expect("require_nft is defined");
    let call = text
        .match_indices("\nrequire_nft\n")
        .map(|(i, _)| i)
        .find(|&i| i > def)
        .expect("require_nft is called");
    // before the running-install stop and the first copy
    for later in [
        "stop_nn_unit \"$u\"",
        "install -m 755 -o root -g root \"$AGENT_BIN\"",
    ] {
        let at = text.rfind(later).unwrap_or_else(|| panic!("{later}"));
        assert!(call < at, "require_nft must run before `{later}`");
    }
}
