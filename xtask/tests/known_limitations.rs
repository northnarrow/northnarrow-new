//! Lot 364 (pre-alpha Phase 9, part 2: no public claim without a linked
//! proof). Every limitation `docs/operator/KNOWN_LIMITATIONS.md` states
//! names where it was shown, and what it names exists: a test function (or
//! test module) of the tree, a case of the `nn-admin` golden matrix, a file
//! of the tree (a lab script), a lot of the CHANGELOG, or one of the named
//! internal checks (the pre-alpha phases, which are not published).
//!
//! The alpha tester guide's scenarios each expect a rule of the catalogue
//! at a severity that rule has, and the issue forms the guide sends a
//! tester to exist and are the ones it names.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

mod support;

use support::repo_root;

const LIMITS: &str = "docs/operator/KNOWN_LIMITATIONS.md";
const GUIDE: &str = "docs/operator/ALPHA_TESTER_GUIDE.md";
const CATALOGUE: &str = "docs/detection/RULE_CATALOGUE.md";
const FORMS: &str = ".github/ISSUE_TEMPLATE";
/// The pre-alpha phases a limitation may cite as an internal check.
const PHASES: [&str; 10] = ["0", "1", "2", "2b", "2c", "3", "4", "4b", "8", "8b"];
const EVIDENCE: &str = "*Evidence:*";

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The top-level items of the page's sections (after its first `## `):
/// each `- ` at the start of a line, with the indented lines and blank
/// lines that follow it.
fn items(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut in_sections = false;
    let mut open = false;
    for (n, line) in text.lines().enumerate() {
        if line.starts_with("## ") {
            in_sections = true;
            open = false;
            continue;
        }
        if !in_sections {
            continue;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            out.push((n + 1, rest.to_string()));
            open = true;
        } else if open && (line.is_empty() || line.starts_with(' ')) {
            let last = out.last_mut().unwrap();
            last.1.push('\n');
            last.1.push_str(line);
        } else {
            open = false;
        }
    }
    out
}

/// A pointer to another section, not a claim ("see \"Containers\" below").
fn is_cross_reference(item: &str) -> bool {
    item.len() < 80 && item.contains("see \"") && item.trim_end().ends_with("below.")
}

/// The backticked words of `text`.
fn ticked(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// The lots a text cites: `lot 359`, `lots 357 and 359`, `lot 273b`.
fn lots(text: &str) -> Vec<String> {
    let flat = text.replace('\n', " ");
    let words: Vec<&str> = flat.split_whitespace().collect();
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if *w == "lot" || *w == "lots" {
            for next in &words[i + 1..] {
                let t = next.trim_end_matches([',', ';', '.', ')']);
                if t == "and" {
                    continue;
                }
                if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    out.push(t.to_string());
                    if *w == "lot" || next.ends_with(['.', ';', ')']) {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }
    out
}

/// The phases a text cites: `Phase 3`, `Phases 2, 2b and 2c`.
fn phases(text: &str) -> Vec<String> {
    let flat = text.replace('\n', " ");
    let words: Vec<&str> = flat.split_whitespace().collect();
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if *w == "Phase" {
            if let Some(next) = words.get(i + 1) {
                out.push(next.trim_end_matches([',', ';', '.', ')']).to_string());
            }
        }
    }
    out
}

/// What the tree has that evidence may name.
struct Tree {
    fns: BTreeSet<String>,
    golden: BTreeSet<String>,
    changelog: String,
}

fn tree() -> Tree {
    let mut files = Vec::new();
    support::rs_files(&repo_root(), &mut files);
    let mut fns = BTreeSet::new();
    for f in files {
        let Ok(src) = fs::read_to_string(&f) else {
            continue;
        };
        for line in src.lines() {
            let l = line.trim_start();
            for kw in ["fn ", "mod "] {
                if let Some(at) = l.find(kw) {
                    let before = &l[..at];
                    if !before.is_empty() && !before.ends_with(' ') && !before.ends_with('(') {
                        continue;
                    }
                    let name: String = l[at + kw.len()..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        fns.insert(name);
                    }
                }
            }
        }
    }
    let mut golden = BTreeSet::new();
    let gold = repo_root().join("agent/tests/golden/nn-admin/expected");
    for e in fs::read_dir(&gold).unwrap() {
        let text = fs::read_to_string(e.unwrap().path()).unwrap();
        for line in text.lines() {
            if let Some(name) = line.strip_prefix("### ") {
                golden.insert(name.trim().to_string());
            }
        }
    }
    Tree {
        fns,
        golden,
        changelog: read("CHANGELOG.md").to_lowercase(),
    }
}

/// The page's problems: an item with no evidence, or evidence that names
/// nothing the tree has.
fn problems(text: &str, t: &Tree) -> Vec<String> {
    let mut out = Vec::new();
    for (line, item) in items(text) {
        let head: String = item.chars().take(60).collect();
        let Some(at) = item.find(EVIDENCE) else {
            if !is_cross_reference(&item) {
                out.push(format!("{LIMITS}:{line}: no {EVIDENCE} — {head}"));
            }
            continue;
        };
        let ev = &item[at + EVIDENCE.len()..];
        let mut named = 0;
        for w in ticked(ev) {
            if w.contains('/') {
                named += 1;
                if !repo_root().join(&w).exists() {
                    out.push(format!("{LIMITS}:{line}: no file `{w}` in the tree"));
                }
            } else if w.contains('.') {
                named += 1;
                if !t.golden.contains(&w) {
                    out.push(format!("{LIMITS}:{line}: no golden case `{w}`"));
                }
            } else if w.contains('_')
                && w.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                named += 1;
                if !t.fns.contains(&w) {
                    out.push(format!("{LIMITS}:{line}: no test `{w}` in the tree"));
                }
            }
        }
        for lot in lots(ev) {
            named += 1;
            let needle = format!("lot {}", lot.to_lowercase());
            let found = t.changelog.match_indices(&needle).any(|(i, _)| {
                !t.changelog[i + needle.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
            });
            if !found {
                out.push(format!("{LIMITS}:{line}: no lot {lot} in the CHANGELOG"));
            }
        }
        for p in phases(ev) {
            named += 1;
            if !PHASES.contains(&p.as_str()) {
                out.push(format!("{LIMITS}:{line}: no internal check \"Phase {p}\""));
            }
        }
        if ev.contains("Phases") {
            out.push(format!(
                "{LIMITS}:{line}: cite one phase at a time (\"Phase 2b\"), so each is checked"
            ));
        }
        if named == 0 {
            out.push(format!(
                "{LIMITS}:{line}: the evidence names no test, file, golden case, lot or phase — {head}"
            ));
        }
    }
    out
}

#[test]
fn every_known_limitation_names_evidence_that_exists() {
    let text = read(LIMITS);
    let t = tree();
    let n = items(&text).len();
    assert!(
        n >= 60,
        "{LIMITS}: {n} items read: the parser lost the list"
    );
    let p = problems(&text, &t);
    assert!(
        p.is_empty(),
        "KNOWN_LIMITATIONS.md: every limitation ends with its evidence, and the evidence exists:\n  {}",
        p.join("\n  ")
    );
}

/// The checker sees what it checks: a page without evidence, with a test,
/// a golden case, a lot or a phase the tree does not have, fails.
#[test]
fn the_checker_refuses_missing_or_dead_evidence() {
    let t = tree();
    let ok = "intro\n\n## A\n\n- **One.** It does a thing. *Evidence:*\n  `the_checker_refuses_missing_or_dead_evidence`; lot 359; internal check\n  Phase 8b §5.\n- **Container runtimes**: see \"Containers\" below.\n";
    assert!(problems(ok, &t).is_empty(), "{:?}", problems(ok, &t));
    for (bad, want) in [
        ("## A\n\n- **One.** It does a thing.\n", "no *Evidence:*"),
        (
            "## A\n\n- **One.** *Evidence:* `no_such_test_anywhere_xyz`.\n",
            "no test",
        ),
        (
            "## A\n\n- **One.** *Evidence:* `no.such-golden-case`.\n",
            "no golden case",
        ),
        (
            "## A\n\n- **One.** *Evidence:* `deploy/no-such-script.sh`.\n",
            "no file",
        ),
        (
            "## A\n\n- **One.** *Evidence:* lot 99999.\n",
            "no lot 99999",
        ),
        (
            "## A\n\n- **One.** *Evidence:* internal check Phase 12 §1.\n",
            "Phase 12",
        ),
        (
            "## A\n\n- **One.** *Evidence:* internal check Phases 2 and 3.\n",
            "one phase at a time",
        ),
        (
            "## A\n\n- **One.** *Evidence:* trust us.\n",
            "names no test",
        ),
    ] {
        let p = problems(bad, &t);
        assert!(
            p.iter().any(|l| l.contains(want)),
            "{bad:?} gave {p:?}, not {want:?}"
        );
    }
    assert_eq!(lots("lots 357 and 359; lot 273b."), ["357", "359", "273b"]);
    assert_eq!(
        phases("Phase 3 §7.1; internal check Phase 2c §7."),
        ["3", "2c"]
    );
}

/// A rule id of the catalogue's summary table and its severities.
fn catalogue() -> Vec<(String, String)> {
    read(CATALOGUE)
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("| [`")?;
            let id = rest.split('`').next()?.to_string();
            let severity = l.split('|').nth(3)?.trim().to_string();
            Some((id, severity))
        })
        .collect()
}

/// The guide's scenarios: (heading, the rules and severities it expects).
fn scenarios(guide: &str) -> Vec<(String, Vec<(String, String)>)> {
    let sec = guide
        .split("\n## 6.")
        .nth(1)
        .and_then(|s| s.split("\n## 7.").next())
        .expect("the guide's section 6");
    sec.split("\n### 6.")
        .skip(1)
        .map(|part| {
            let head = part.lines().next().unwrap_or_default().to_string();
            let expect = part
                .split("Record to expect:")
                .nth(1)
                .map(|s| {
                    s.split("\n\n")
                        .next()
                        .unwrap_or_default()
                        .replace('\n', " ")
                })
                .unwrap_or_default();
            let mut rules = Vec::new();
            let mut rest = expect.as_str();
            while let Some(i) = rest.find('`') {
                let after = &rest[i + 1..];
                let Some(j) = after.find('`') else { break };
                let id = &after[..j];
                let tail = &after[j + 1..];
                if let Some(sev) = tail
                    .trim_start()
                    .strip_prefix('(')
                    .and_then(|s| s.split(')').next())
                {
                    rules.push((id.to_string(), sev.to_string()));
                }
                rest = tail;
            }
            (head, rules)
        })
        .collect()
}

#[test]
fn the_tester_guide_s_scenarios_expect_catalogue_rules_at_their_severities() {
    let guide = read(GUIDE);
    let cat = catalogue();
    assert!(
        cat.len() >= 90,
        "the catalogue's table: {} rules read",
        cat.len()
    );
    let sc = scenarios(&guide);
    assert!(
        (5..=8).contains(&sc.len()),
        "the guide has {} scenarios: 5 to 8 (the plan)",
        sc.len()
    );
    for (head, rules) in &sc {
        assert!(
            !rules.is_empty(),
            "scenario 6.{head}: no `rule` (Severity) to expect"
        );
        for (id, sev) in rules {
            let Some((_, has)) = cat.iter().find(|(c, _)| c == id) else {
                panic!("scenario 6.{head}: {id} is not a rule of the catalogue");
            };
            assert!(
                has.split(", ").any(|s| s == sev),
                "scenario 6.{head}: {id} at {sev}, the catalogue gives it {has}"
            );
        }
    }
}

#[test]
fn the_issue_forms_are_the_ones_the_guide_names() {
    let guide = read(GUIDE);
    let dir = repo_root().join(FORMS);
    for (file, name) in [
        ("bug_report.yml", "Bug report"),
        ("false_positive.yml", "False positive"),
        ("detection_gap.yml", "Detection gap"),
    ] {
        let path = dir.join(file);
        let form: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            &fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
        )
        .unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(form["name"].as_str(), Some(name), "{file}'s name");
        assert!(form["description"].as_str().is_some_and(|d| !d.is_empty()));
        let body = form["body"].as_sequence().expect("a form body");
        assert!(
            body.iter().any(|b| b["type"] == "checkboxes"
                && b["attributes"]["options"].as_sequence().is_some_and(|o| o
                    .iter()
                    .any(|x| x["label"]
                        .as_str()
                        .is_some_and(|l| l.contains("personal data"))))),
            "{file}: a required check that personal data was removed"
        );
        assert!(
            guide.contains(&format!("**{name}**")),
            "the guide names the form {name}"
        );
    }
    let config: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&read(&format!("{FORMS}/config.yml"))).unwrap();
    assert!(
        config["contact_links"]
            .as_sequence()
            .is_some_and(|l| l.iter().any(|c| c["url"]
                .as_str()
                .is_some_and(|u| u.ends_with("/security/advisories/new")))),
        "config.yml sends a vulnerability to private reporting"
    );
    assert!(Path::new(&repo_root().join(GUIDE)).exists());
}
