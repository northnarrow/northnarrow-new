//! Lot M10 (external-audit quick wins): the development override of the
//! boot manifest check, `NN_ALLOW_UNVERIFIED_BINARY=1`, exists only in a
//! build with the `dev-allow-unverified` cargo feature. A release build has
//! no code that reads the variable, so it cannot be set to skip the check;
//! `self_integrity` still names it in `WEAKENING_ENV`, so a host where
//! someone set it shows a signed `weakening_env` row.
//!
//! The release has no such feature: `supply_chain.rs` holds the resolved
//! features of the release build to none of `TEST_ONLY_FEATURES`, which
//! lists this one, and the agent's `--build-features` names it.

mod support;

use support::{product_code, repo_root};

const FEATURE: &str = "dev-allow-unverified";
const NAME: &str = "NN_ALLOW_UNVERIFIED_BINARY";

/// Where the variable's name may appear in product code: its constant and
/// the weakening list that reports it.
const NAME_FILES: &[&str] = &[
    "crates/nn-linux/src/install_manifest.rs",
    "crates/nn-linux/src/self_integrity.rs",
];

/// Product files that read the environment under the constant.
fn reads_of(code: &std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (file, text) in code {
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if l.contains("ALLOW_UNVERIFIED_ENV") && (l.contains("env::var") || l.contains("var_os"))
            {
                // the nearest preceding non-blank lines, back to the `fn`
                let mut ctx = String::new();
                for p in lines[..i].iter().rev().take(4) {
                    ctx.push_str(p);
                    ctx.push('\n');
                }
                out.push((file.clone(), ctx));
            }
        }
    }
    out
}

fn problems(code: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    let mut bad = Vec::new();
    for (file, text) in code {
        if text.contains(&format!("\"{NAME}\"")) && !NAME_FILES.contains(&file.as_str()) {
            bad.push(format!("{file}: names {NAME} outside its constant and WEAKENING_ENV"));
        }
    }
    let reads = reads_of(code);
    if reads.is_empty() {
        bad.push("no read of the override found: the ratchet is blind".into());
    }
    for (file, ctx) in reads {
        if !ctx.contains(&format!("#[cfg(feature = \"{FEATURE}\")]")) {
            bad.push(format!("{file}: reads {NAME} outside `cfg(feature = \"{FEATURE}\")`"));
        }
    }
    bad
}

#[test]
fn the_unverified_binary_override_is_read_only_in_a_dev_build() {
    let code = product_code(&repo_root());
    let bad = problems(&code);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // the report of a set variable stays in every build
    let si = &code["crates/nn-linux/src/self_integrity.rs"];
    assert!(
        si.contains(&format!("(\"{NAME}\", is_one)")),
        "self_integrity must keep reporting {NAME} as a weakening variable"
    );
}

#[test]
fn a_planted_unguarded_read_fails_the_rule() {
    let mut code = product_code(&repo_root());
    let checks = "crates/nn-linux/src/boot/checks.rs".to_string();
    let ok = code[&checks].clone();
    let planted = ok.replace(
        &format!("#[cfg(feature = \"{FEATURE}\")]\nfn allow_unverified_from_env"),
        "fn allow_unverified_from_env",
    );
    assert_ne!(ok, planted, "the guarded read is where the test expects it");
    code.insert(checks, planted);
    assert!(!problems(&code).is_empty());
}

#[test]
fn the_feature_is_off_by_default_and_named_by_the_build() {
    let linux = std::fs::read_to_string(repo_root().join("crates/nn-linux/Cargo.toml")).unwrap();
    assert!(linux.contains(&format!("{FEATURE} = []")));
    assert!(!linux.contains("default ="), "nn-linux has no default feature");
    let agent = std::fs::read_to_string(repo_root().join("agent/Cargo.toml")).unwrap();
    assert!(agent.contains("default = []"));
    let info = std::fs::read_to_string(repo_root().join("agent/src/build_info.rs")).unwrap();
    assert!(info.contains("\"dev-allow-unverified\""));
}
