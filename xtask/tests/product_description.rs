//! Lot 393 (the founder's decision of 2026-11-23): NorthNarrow is an EDR
//! in the alpha, "NorthNarrow — endpoint detection and response for
//! Linux". The parts an XDR adds to an EDR (a backend, identity, cloud,
//! network detection) are at level 0 in
//! `docs/roadmap/CAPABILITY_PROGRAM.md`, so nothing that describes the
//! product as it is calls it an XDR: the packages' summary and description
//! (`deploy/release/`), the units' `Description=`, a binary's `--help` (the
//! golden files, every clap `about`), the crates' manifests and root docs,
//! the messages and help of `install.sh` and `uninstall.sh`, the README,
//! SECURITY.md, CONTRIBUTING.md, the operator guides and the issue forms.
//!
//! What keeps the word: the history (the CHANGELOG's earlier entries, the
//! design, strategy and audit records, a comment that quotes what an
//! earlier release shipped), the long-term XDR goal, and identifiers such as
//! `docs/XDR_ROADMAP_TAPPE_NEW.md` (`_` is part of a word here).

use std::fs;

mod support;

use support::{repo_root, tracked_files};

/// The product's one-line description (the founder's wording).
const ONE_LINE: &str = "NorthNarrow — endpoint detection and response for Linux";

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `line` names an XDR: `xdr` in any case, as a whole word (a letter, a
/// digit or `_` on either side makes it part of another word), or spelled
/// out ("extended detection and response").
fn names_xdr(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let b = lower.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    lower
        .match_indices("xdr")
        .any(|(i, _)| (i == 0 || !word(b[i - 1])) && b.get(i + 3).is_none_or(|c| !word(*c)))
        || lower.contains("extended detection and response")
}

/// The comment block a shell script opens with (after the shebang):
/// `uninstall.sh --help` prints it.
fn script_header(text: &str) -> Vec<&str> {
    text.lines()
        .skip(1)
        .take_while(|l| l.starts_with('#'))
        .collect()
}

/// A line and the file it is in.
type Placed = (String, String);

/// Every line that describes the product as it is, as (where, line), and
/// how many lines each kind of place gave (so a moved file cannot make the
/// check pass on nothing).
fn current_descriptions() -> (Vec<Placed>, Vec<(&'static str, usize)>) {
    let files = tracked_files();
    let mut lines = Vec::new();
    let mut counts = Vec::new();
    let mut take = |kind: &'static str, rel: &str, picked: Vec<&str>| {
        if let Some(c) = counts.iter_mut().find(|(k, _)| *k == kind) {
            c.1 += picked.len();
        } else {
            counts.push((kind, picked.len()));
        }
        lines.extend(picked.into_iter().map(|l| (rel.to_string(), l.to_string())));
    };
    for rel in &files {
        let under = |dir: &str| rel.starts_with(dir);
        // a key in base64 (the release's rpm key) describes nothing
        if rel.ends_with(".asc") {
            continue;
        }
        let whole = under("deploy/systemd/")
            || under("deploy/release/")
            || under("agent/tests/golden/")
            || under("watchdog/tests/golden/")
            || under("docs/operator/")
            || under(".github/ISSUE_TEMPLATE/")
            || ["README.md", "SECURITY.md", "CONTRIBUTING.md"].contains(&rel.as_str());
        if whole {
            let kind = if under("deploy/systemd/") {
                "units"
            } else if under("deploy/release/") {
                "packages"
            } else if rel.contains("/tests/golden/") {
                "golden output and help"
            } else {
                "documents"
            };
            let text = read(rel);
            take(kind, rel, text.lines().collect());
        } else if rel == "Cargo.toml" || rel.ends_with("/Cargo.toml") {
            let text = read(rel);
            let picked = text
                .lines()
                .filter(|l| l.trim_start().starts_with("description"))
                .collect();
            take("crate descriptions", rel, picked);
        } else if rel.ends_with(".rs") {
            let text = read(rel);
            let about = text
                .lines()
                .filter(|l| l.contains("about = \"") || l.contains("about=\""))
                .collect();
            take("clap about", rel, about);
            if rel.ends_with("src/lib.rs") || rel.ends_with("src/main.rs") {
                let docs = text
                    .lines()
                    .take_while(|l| l.starts_with("//!") || l.starts_with("#!"))
                    .collect();
                take("crate root docs", rel, docs);
            }
        } else if rel == "deploy/install.sh" || rel == "deploy/uninstall.sh" {
            let text = read(rel);
            take("script headers", rel, script_header(&text));
            let code = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect();
            take("script messages", rel, code);
        }
    }
    (lines, counts)
}

#[test]
fn the_word_is_found_only_as_a_word() {
    for yes in [
        "NorthNarrow XDR agent",
        "Description=NorthNarrow XDR (the agent)",
        "an XDR's sensor",
        "(XDR)",
        "NorthNarrow-XDR",
        "xdr",
        "a primary Xdr use case",
        "Extended Detection and Response for Linux",
    ] {
        assert!(names_xdr(yes), "{yes}");
    }
    for no in [
        "updates/dkms/vboxdrv.ko",
        "docs/XDR_ROADMAP_TAPPE_NEW.md",
        "XDRs",
        "maxdrops",
        "rpc_xdr",
        "NorthNarrow EDR agent",
        "endpoint detection and response",
    ] {
        assert!(!names_xdr(no), "{no}");
    }
    let header = "#!/usr/bin/env bash\n# one\n#\n# two\nset -e\n# later\n";
    assert_eq!(script_header(header), ["# one", "#", "# two"]);
}

#[test]
fn no_description_of_the_product_as_it_is_says_xdr() {
    let (lines, counts) = current_descriptions();
    for (kind, fewest) in [
        ("units", 4),
        ("packages", 50),
        ("golden output and help", 100),
        ("documents", 100),
        ("crate descriptions", 15),
        ("clap about", 4),
        ("crate root docs", 15),
        ("script headers", 10),
        ("script messages", 1000),
    ] {
        let n = counts.iter().find(|(k, _)| *k == kind).map_or(0, |c| c.1);
        assert!(n >= fewest, "{kind}: {n} lines read, {fewest} at least");
    }
    let bad: Vec<String> = lines
        .iter()
        .filter(|(_, l)| names_xdr(l))
        .map(|(rel, l)| format!("{rel}: {}", l.trim()))
        .collect();
    assert!(
        bad.is_empty(),
        "NorthNarrow is an EDR in the alpha (\"{ONE_LINE}\"); the XDR is the goal, \
         named only in the roadmap, the strategy and the history:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_packages_the_units_and_the_help_carry_the_one_line_description() {
    // the .deb's synopsis and the .rpm's Summary
    let pkg = read("deploy/release/mk-packages.sh");
    assert!(
        pkg.lines().any(|l| l == format!("SUMMARY=\"{ONE_LINE}\"")),
        "mk-packages.sh's SUMMARY"
    );
    for needle in ["Description: ${SUMMARY}", "Summary:        ${SUMMARY}"] {
        assert!(pkg.contains(needle), "mk-packages.sh: `{needle}`");
    }
    // the release workflow checks what the built packages carry
    let release = read(".github/workflows/release.yml");
    for needle in [
        "dpkg-deb -f \"$deb\" Description | head -1",
        "rpm -qp --qf '%{SUMMARY}' \"$rpm\"",
    ] {
        assert!(
            release.contains(needle),
            "release.yml's package job: `{needle}`"
        );
    }
    // each unit (and the slice) is NorthNarrow EDR's
    let units: Vec<String> = tracked_files()
        .into_iter()
        .filter(|f| f.starts_with("deploy/systemd/") && !f.ends_with(".md"))
        .filter(|f| f.ends_with(".service") || f.ends_with(".slice"))
        .collect();
    assert!(units.len() >= 4, "{units:?}");
    for unit in &units {
        let text = read(unit);
        let desc: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("Description="))
            .collect();
        assert_eq!(desc.len(), 1, "{unit}: {desc:?}");
        assert!(
            desc[0].starts_with("NorthNarrow EDR"),
            "{unit}: {}",
            desc[0]
        );
    }
    // the agent's --help and uninstall.sh's help open with it
    let help = read("agent/tests/golden/help/northnarrow-agent.txt");
    assert!(
        help.starts_with(&format!("{ONE_LINE}: ")),
        "{:?}",
        help.lines().next()
    );
    let uninstall = read("deploy/uninstall.sh");
    assert_eq!(
        script_header(&uninstall).first().copied(),
        Some(format!("# {ONE_LINE}: uninstall.").as_str())
    );
}
