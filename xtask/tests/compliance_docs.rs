//! Licence notices and the security policy (external audit, Wave 3, lab PR
//! 209: SUP-019 NN-AUD-403, SUP-020 NN-AUD-404). The licence the manifests
//! and the packages declare is the one of `LICENSE`; `NOTICES.md` names the
//! third-party material the tree holds (every file of `LICENSES/`, every
//! vendored crate with its licence, the eBPF object's own declaration) and
//! the model it does not distribute, and quotes the ATT&CK designation
//! verbatim; `SECURITY.md` has the support period, the reporting channel,
//! the regulatory reporting procedure and an embargo limit; and
//! `.well-known/security.txt` follows RFC 9116, names the same channel and
//! has not expired.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};

/// The contact SECURITY.md and security.txt name: GitHub Security
/// Advisories, the repository's private vulnerability reporting.
const ADVISORIES: &str = "https://github.com/northnarrow/northnarrow-new/security/advisories/new";
const POLICY_URL: &str = "https://github.com/northnarrow/northnarrow-new/blob/main/SECURITY.md";

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

/// `text` with every run of whitespace made one space (the needles below
/// do not depend on where a paragraph wraps).
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn dir_names(rel: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(repo_root().join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

/// The SPDX identifier of the licence text in `LICENSE`.
fn license_file_spdx() -> &'static str {
    let text = read("LICENSE");
    let head = text.trim_start();
    if head.starts_with("Apache License") && head.contains("Version 2.0, January 2004") {
        "Apache-2.0"
    } else {
        panic!("LICENSE: not a licence text this test knows — update compliance_docs.rs")
    }
}

/// The value of the first `key = "value"` line of a manifest's section.
fn manifest_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            in_section = t == section;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn workspace_members() -> Vec<String> {
    let text = read("Cargo.toml");
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("members"))
        .expect("Cargo.toml: members");
    let list = &line[line.find('[').unwrap() + 1..line.rfind(']').unwrap()];
    list.split(',')
        .map(|m| m.trim().trim_matches('"').to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

/// The text under a `## ` heading that starts with `title`, to the next
/// one, whitespace made single spaces.
fn section(text: &str, title: &str) -> String {
    let start = text
        .find(&format!("\n## {title}"))
        .unwrap_or_else(|| panic!("no `## {title}` section"));
    let body = &text[start + 1..];
    let end = body[3..].find("\n## ").map_or(body.len(), |i| i + 3);
    flat(&body[..end])
}

#[test]
fn licence_declarations_agree_with_the_license_file() {
    let spdx = license_file_spdx();
    let root = read("Cargo.toml");
    assert_eq!(
        manifest_value(&root, "[workspace.package]", "license").as_deref(),
        Some(spdx),
        "Cargo.toml [workspace.package] license"
    );
    for m in workspace_members() {
        let manifest = read(&format!("{m}/Cargo.toml"));
        assert!(
            manifest.contains("license.workspace = true")
                && manifest_value(&manifest, "[package]", "license").is_none(),
            "{m}/Cargo.toml: inherits the workspace licence (license.workspace = true)"
        );
    }
    assert_eq!(
        manifest_value(&read("agent-ebpf/Cargo.toml"), "[package]", "license").as_deref(),
        Some(spdx),
        "agent-ebpf/Cargo.toml (not a workspace member)"
    );
    let rpm_license = read("deploy/release/mk-packages.sh")
        .lines()
        .find_map(|l| l.strip_prefix("License:").map(|v| v.trim().to_string()))
        .expect("mk-packages.sh: no `License:` in the spec");
    assert_eq!(rpm_license, spdx, "the .rpm's License:");
    let notices = flat(&read("NOTICES.md"));
    assert!(
        notices.contains("licensed under the Apache License, Version 2.0 (`LICENSE`)"),
        "NOTICES.md: the licence of NorthNarrow's own code"
    );
}

#[test]
fn notices_name_the_third_party_material_the_tree_holds() {
    let notices = read("NOTICES.md");

    // The ATT&CK designation, verbatim from the pinned Terms of Use.
    let tou = read("LICENSES/MITRE_ATTACK_ToU.md");
    let designation = tou
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("\"©") && l.ends_with('"'))
        .expect("MITRE_ATTACK_ToU.md: the quoted designation");
    assert!(
        notices.contains(designation),
        "NOTICES.md does not quote the ATT&CK designation verbatim: {designation}"
    );

    for f in dir_names("LICENSES") {
        assert!(
            notices.contains(&format!("`LICENSES/{f}`")),
            "NOTICES.md: LICENSES/{f}"
        );
    }

    for crate_dir in dir_names("vendor") {
        let manifest = read(&format!("vendor/{crate_dir}/Cargo.toml"));
        let license = manifest_value(&manifest, "[package]", "license")
            .unwrap_or_else(|| panic!("vendor/{crate_dir}: no licence"));
        let version = manifest_value(&manifest, "[package]", "version").unwrap();
        let notes = section(&notices, crate_dir.as_str());
        for needle in [
            format!("`vendor/{crate_dir}/`"),
            license.clone(),
            version.clone(),
        ] {
            assert!(
                notes.contains(&needle),
                "NOTICES.md `## {crate_dir}`: `{needle}`"
            );
        }
        assert!(
            repo_root()
                .join(format!("vendor/{crate_dir}/LICENSE"))
                .is_file()
                && notes.contains(&format!("`vendor/{crate_dir}/LICENSE`")),
            "vendor/{crate_dir}: its licence text, named in NOTICES.md"
        );
    }

    // The eBPF object's own declaration, as the source writes it.
    let ebpf = read("agent-ebpf/src/main.rs");
    let at = ebpf
        .find("static LICENSE")
        .expect("agent-ebpf: LICENSE section");
    let decl = ebpf[at..]
        .split_once("*b\"")
        .and_then(|(_, r)| r.split_once("\\0\""))
        .map(|(d, _)| d.to_string())
        .expect("agent-ebpf: the license string");
    assert!(
        section(&notices, "Licence declarations").contains(&format!("`{decl}`")),
        "NOTICES.md, Licence declarations: the eBPF object's `{decl}`"
    );

    // The model: not distributed, its licence recorded (SUP-019 narrowed).
    let model = section(&notices, "Model (not distributed)");
    let config = read("agent/src/ade/config.rs");
    let default_model = config
        .split("DEFAULT_MODEL_PATH: &'static str =")
        .nth(1)
        .and_then(|r| r.split('"').nth(1))
        .and_then(|p| p.rsplit('/').next())
        .expect("ade/config.rs: DEFAULT_MODEL_PATH");
    for needle in [
        default_model,
        "Foundation-Sec-8B-Reasoning",
        "huggingface.co/fdtn-ai/",
        "Llama 3.1 Community License",
        "Acceptable Use Policy",
        "Pin:",
        "What the operator takes on",
    ] {
        assert!(model.contains(needle), "NOTICES.md, Model: `{needle}`");
    }
    assert!(
        flat(&read("docs/ADE_BACKEND_NOTES.md"))
            .contains("`NOTICES.md`, \"Model (not distributed)\""),
        "ADE_BACKEND_NOTES.md points to the model's notice"
    );

    // LOLBAS: the reason given matches the licence the tree is under.
    assert!(
        !notices.to_lowercase().contains("proprietary"),
        "NOTICES.md: NorthNarrow is distributed under Apache-2.0, not proprietary terms"
    );
    assert!(notices.contains("LOLBAS is deliberately excluded"));
}

#[test]
fn security_policy_has_what_a_reporter_and_a_regulator_need() {
    let policy = read("SECURITY.md");
    let supported = section(&policy, "Supported versions");
    assert!(
        supported.contains("**Support period.**"),
        "SECURITY.md: support period"
    );
    assert!(
        supported.contains("until the next tag is published"),
        "SECURITY.md: the support period of a 0.0.x tag, stated in time"
    );
    let reporting = section(&policy, "Reporting a vulnerability");
    assert!(
        reporting.contains(ADVISORIES),
        "SECURITY.md: the advisories URL"
    );
    assert!(reporting.contains(".well-known/security.txt"));
    let regulatory = section(&policy, "Regulatory reporting");
    for needle in [
        "2024/2847",
        "Article 14",
        "11 September 2026",
        "single reporting platform",
        "ENISA",
        "CSIRT",
        "24 hours",
        "72 hours",
        "14 days after a corrective or mitigating measure",
        "one month after the 72-hour notification",
    ] {
        assert!(
            regulatory.contains(needle),
            "SECURITY.md, regulatory reporting: `{needle}`"
        );
    }
    assert!(
        section(&policy, "Disclosure").contains("**90 days**"),
        "SECURITY.md: an embargo limit"
    );
}

/// The `Name: value` fields of a security.txt, comments and blanks skipped.
fn security_txt_fields(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once(':')
                .unwrap_or_else(|| panic!("security.txt: not a field: {l}"));
            (k.trim().to_ascii_lowercase(), v.trim().to_string())
        })
        .collect()
}

/// RFC 9116 checks; `now` is a parameter so the test below can move it.
fn security_txt_problems(text: &str, policy: &str, now: DateTime<Utc>) -> Vec<String> {
    const KNOWN: [&str; 9] = [
        "acknowledgments",
        "canonical",
        "contact",
        "encryption",
        "expires",
        "hiring",
        "policy",
        "preferred-languages",
        "csaf",
    ];
    let fields = security_txt_fields(text);
    let mut bad = Vec::new();
    for (k, _) in &fields {
        if !KNOWN.contains(&k.as_str()) {
            bad.push(format!("unknown field `{k}`"));
        }
    }
    let contacts: Vec<&str> = fields
        .iter()
        .filter(|(k, _)| k == "contact")
        .map(|(_, v)| v.as_str())
        .collect();
    match contacts.first() {
        Some(&first) if first == ADVISORIES => {}
        _ => bad.push(format!("the first Contact must be {ADVISORIES}")),
    }
    for c in &contacts {
        if !(c.starts_with("https://") || c.starts_with("mailto:") || c.starts_with("tel:")) {
            bad.push(format!(
                "Contact `{c}` is not a URI (https:, mailto:, tel:)"
            ));
        }
        if !policy.contains(c.trim_start_matches("mailto:")) {
            bad.push(format!("Contact `{c}` is not in SECURITY.md"));
        }
    }
    let expires: Vec<&str> = fields
        .iter()
        .filter(|(k, _)| k == "expires")
        .map(|(_, v)| v.as_str())
        .collect();
    if expires.len() != 1 {
        bad.push(format!(
            "{} Expires fields (RFC 9116: exactly one)",
            expires.len()
        ));
    }
    if let Some(e) = expires.first() {
        match DateTime::parse_from_rfc3339(e) {
            Err(err) => bad.push(format!("Expires `{e}`: not RFC 3339 ({err})")),
            Ok(t) => {
                let t = t.with_timezone(&Utc);
                if t <= now {
                    bad.push(format!(
                        "Expires {e} has passed: renew it (less than a year ahead) in .well-known/security.txt"
                    ));
                }
                if t > now + Duration::days(366) {
                    bad.push(format!(
                        "Expires {e} is more than a year ahead (RFC 9116 §2.5.5)"
                    ));
                }
            }
        }
    }
    let policies: Vec<&str> = fields
        .iter()
        .filter(|(k, _)| k == "policy")
        .map(|(_, v)| v.as_str())
        .collect();
    if policies != [POLICY_URL] {
        bad.push(format!("Policy must be {POLICY_URL}"));
    }
    bad
}

#[test]
fn security_txt_follows_rfc_9116_and_names_the_policy_channel() {
    let bad = security_txt_problems(
        &read(".well-known/security.txt"),
        &read("SECURITY.md"),
        Utc::now(),
    );
    assert!(
        bad.is_empty(),
        ".well-known/security.txt:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_security_txt_check_refuses_an_expired_or_foreign_file() {
    let policy = read("SECURITY.md");
    let good = read(".well-known/security.txt");
    let now = Utc::now();
    assert!(security_txt_problems(&good, &policy, now).is_empty());
    // A year and a day later the same file is stale.
    assert!(!security_txt_problems(&good, &policy, now + Duration::days(367)).is_empty());
    let foreign = format!(
        "Contact: mailto:someone@example.invalid\nContact: {ADVISORIES}\nExpires: 2999-01-01T00:00:00Z\nPolicy: {POLICY_URL}\nFoo: bar\n"
    );
    let bad = security_txt_problems(&foreign, &policy, now);
    assert_eq!(bad.len(), 4, "{bad:#?}"); // unknown field, first Contact, Contact not in the policy, Expires too far
}
