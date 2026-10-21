//! Lab PR 221 (capability C16): the ATT&CK mapping and the catalogue held
//! to the rule set, to the pinned ATT&CK Enterprise 20.0 ids and to the
//! committed documents.
//!
//! - every rule the agent can record declares at least one ATT&CK
//!   reference and has one catalogue entry, and no entry names another id;
//! - every technique a rule names is in the pinned list, active (not
//!   revoked, not deprecated), and the tactic it is filed under is one of
//!   its tactics in 20.0; every data component an entry names is in the
//!   list and active;
//! - the list is the one the header says (version, designation, licence
//!   file, `NOTICES.md`), holds the 15 tactics as [`Tactic`] names them,
//!   and every id the V2 technique rows name (revoked ones included, with
//!   what replaced them);
//! - every test an entry cites exists, and the severities an entry gives
//!   agree with the V2 Critical sub-gate;
//! - `docs/detection/` holds what [`render::render`] writes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use common::Severity;

use super::render::{self, parse_pinned, parse_tsv, Pinned, PinnedRow, ShippedRule};
use super::{docs, RuleDoc};
use crate::decision::attack::{AttackRef, Tactic, ATTACK_IDS_FILE, ATTACK_VERSION};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn pinned() -> Pinned {
    parse_pinned(&read(ATTACK_IDS_FILE)).unwrap_or_else(|e| panic!("{e}"))
}

/// What is wrong with `refs` of rule `id` against the pinned list.
fn reference_problems(id: &str, refs: &[AttackRef], p: &Pinned) -> Vec<String> {
    let mut bad = Vec::new();
    if refs.is_empty() {
        bad.push(format!("{id}: no ATT&CK reference (Rule::attack is empty)"));
    }
    let mut seen = BTreeSet::new();
    for r in refs {
        let t = r.technique.as_str();
        if !seen.insert((t, r.tactic)) {
            bad.push(format!("{id}: {t} under {} twice", r.tactic.name()));
        }
        let Some(row) = p.rows.get(t) else {
            bad.push(format!(
                "{id}: {t} is not in {ATTACK_IDS_FILE} — check it in ATT&CK {ATTACK_VERSION} and \
                 add it with `cargo xtask attack-coverage --pin-ids {t}`"
            ));
            continue;
        };
        if row.status != "active" {
            bad.push(format!(
                "{id}: {t} is {} in ATT&CK {ATTACK_VERSION}{}",
                row.status,
                row.replaced_by
                    .as_ref()
                    .map(|n| format!(" (revoked by {n})"))
                    .unwrap_or_default()
            ));
        }
        let kind = if r.technique.is_subtechnique() {
            "subtechnique"
        } else {
            "technique"
        };
        if row.kind != kind {
            bad.push(format!(
                "{id}: {t} is a {} in the list, not a {kind}",
                row.kind
            ));
        }
        if !row.tactics.iter().any(|s| s == r.tactic.shortname()) {
            bad.push(format!(
                "{id}: {t} is not a {} technique in ATT&CK {ATTACK_VERSION} (its tactics: {})",
                r.tactic.name(),
                row.tactics.join(", ")
            ));
        }
    }
    bad
}

#[test]
fn every_shipped_rule_declares_a_valid_attack_mapping() {
    let p = pinned();
    let rules = render::shipped_rules();
    assert_eq!(
        rules.len(),
        82 + 1,
        "the rules v2-rules.tsv counts, and NN-L-EXECQ-001 (lab PR 223, not in it)"
    );
    let bad: Vec<String> = rules
        .iter()
        .flat_map(|r| reference_problems(r.id, r.attack, &p))
        .collect();
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn a_revoked_deprecated_unknown_or_misfiled_id_is_refused() {
    let p = pinned();
    // T1562.001 Disable or Modify Tools was revoked in v19 (now T1685).
    const REVOKED: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1562.001")];
    let bad = reference_problems("X", REVOKED, &p);
    assert!(
        bad.iter()
            .any(|b| b.contains("revoked") && b.contains("T1685")),
        "{bad:?}"
    );
    const UNKNOWN: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1999")];
    assert!(reference_problems("X", UNKNOWN, &p)[0].contains("not in"));
    // T1685 is a Defense Impairment technique, not a Stealth one.
    const MISFILED: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1685")];
    assert!(reference_problems("X", MISFILED, &p)[0].contains("not a Stealth technique"));
    assert!(reference_problems("X", &[], &p)[0].contains("no ATT&CK reference"));
    // A deprecated id, as the list would carry one.
    let mut with_deprecated = p.clone();
    with_deprecated.rows.insert(
        "T1999".into(),
        PinnedRow {
            kind: "technique".into(),
            status: "deprecated".into(),
            name: "x".into(),
            tactics: vec!["execution".into()],
            replaced_by: None,
        },
    );
    assert!(reference_problems("X", UNKNOWN, &with_deprecated)[0].contains("deprecated"));
}

#[test]
fn the_pinned_list_is_the_one_its_header_names() {
    let p = pinned();
    assert_eq!(p.version, ATTACK_VERSION);
    assert_eq!(p.source, "https://github.com/mitre-attack/attack-stix-data");
    assert_eq!(
        p.file,
        format!("enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json")
    );
    assert_eq!(p.commit.len(), 40, "a commit, not a tag");
    assert_eq!(p.sha256.len(), 64);
    // The Terms of Use of the same commit, verbatim, with the designation
    // the list quotes; NOTICES.md names both and quotes it too.
    let licence = format!("LICENSES/MITRE_ATTACK_ToU-{ATTACK_VERSION}.md");
    assert!(
        read(&licence).contains(&format!("\"{}\"", p.designation)),
        "{licence}: the designation the list quotes"
    );
    let notices = read("NOTICES.md");
    for needle in [
        p.designation.as_str(),
        ATTACK_IDS_FILE,
        &format!("`{licence}`"),
        &p.commit,
    ] {
        assert!(notices.contains(needle), "NOTICES.md: `{needle}`");
    }
    // The 15 tactics, as the enum names them.
    for t in Tactic::ALL {
        let row = p
            .rows
            .get(t.id())
            .unwrap_or_else(|| panic!("{}: not in the list", t.id()));
        assert_eq!(
            (row.kind.as_str(), row.status.as_str(), row.name.as_str()),
            ("tactic", "active", t.name()),
            "{}",
            t.id()
        );
        assert_eq!(row.tactics, [t.shortname()], "{}", t.id());
    }
    assert_eq!(
        p.rows.values().filter(|r| r.kind == "tactic").count(),
        Tactic::ALL.len()
    );
}

/// The ids the mapping, the catalogue and the V2 technique rows use, with
/// the parents of their sub-techniques and the tactics: the list holds
/// these and nothing else (a minimal extract), and a revoked id it holds
/// names an id it also holds.
#[test]
fn the_pinned_list_holds_exactly_the_ids_in_use() {
    let p = pinned();
    let mut used: BTreeSet<String> = Tactic::ALL.iter().map(|t| t.id().to_string()).collect();
    for r in render::shipped_rules() {
        used.extend(r.attack.iter().map(|a| a.technique.as_str().to_string()));
    }
    for d in docs() {
        used.extend(d.data_components.iter().map(|s| s.to_string()));
    }
    for r in parse_tsv(&read(render::TECHNIQUES_TSV)) {
        used.insert(r["technique"].clone());
    }
    let mut closure = used.clone();
    for id in &used {
        if let Some(row) = p.rows.get(id) {
            closure.extend(row.replaced_by.clone());
        }
    }
    for id in closure.clone() {
        if let Some((parent, _)) = id.split_once('.') {
            closure.insert(parent.to_string());
        }
    }
    let listed: BTreeSet<String> = p.rows.keys().cloned().collect();
    let missing: Vec<&String> = closure.difference(&listed).collect();
    let extra: Vec<&String> = listed.difference(&closure).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{ATTACK_IDS_FILE}: missing {missing:?} (add them with `cargo xtask attack-coverage \
         --pin-ids <ids>`), not in use {extra:?} (delete the file and pin the ids in use again)"
    );
    for (id, row) in &p.rows {
        assert_eq!(
            row.status == "revoked",
            row.replaced_by.is_some(),
            "{id}: a revoked id, and only one, names its replacement"
        );
    }
}

/// A cited test: `path::function` (a Rust file must contain `fn
/// function(`) or `path::text` (any other file must contain `text`).
fn check_cited(cite: &str, ctx: &str) -> Option<String> {
    let Some((path, anchor)) = cite.split_once("::") else {
        return Some(format!("{ctx}: `{cite}` is not path::anchor"));
    };
    if path.contains("..") || path.starts_with('/') {
        return Some(format!(
            "{ctx}: `{path}` must be a path inside the repository"
        ));
    }
    let Ok(text) = std::fs::read_to_string(root().join(path)) else {
        return Some(format!("{ctx}: {path} does not exist"));
    };
    let needle = if path.ends_with(".rs") {
        format!("fn {anchor}(")
    } else {
        anchor.to_string()
    };
    (!text.contains(&needle)).then(|| format!("{ctx}: {path} has no `{needle}`"))
}

fn entry_problems(d: &RuleDoc, p: &Pinned) -> Vec<String> {
    let mut bad = Vec::new();
    let ctx = d.id;
    for (what, empty) in [
        ("severities", d.severities.is_empty()),
        ("actions", d.actions.is_empty()),
        ("sensors", d.sensors.is_empty()),
        ("data_components", d.data_components.is_empty()),
        ("observes", d.observes.trim().is_empty()),
        ("false_positives", d.false_positives.trim().is_empty()),
        ("how_to_test", d.how_to_test.trim().is_empty()),
        ("tests", d.tests.is_empty()),
    ] {
        if empty {
            bad.push(format!("{ctx}: empty {what}"));
        }
    }
    let mut sev = d.severities.to_vec();
    sev.sort_by_key(|s| std::cmp::Reverse(rank(*s)));
    sev.dedup();
    if sev != d.severities {
        bad.push(format!("{ctx}: severities not distinct, the highest first"));
    }
    for dc in d.data_components {
        match p.rows.get(*dc) {
            Some(r) if r.kind == "data-component" && r.status == "active" => {}
            Some(r) => bad.push(format!("{ctx}: {dc} is a {} {} id", r.status, r.kind)),
            None => bad.push(format!(
                "{ctx}: data component {dc} is not in {ATTACK_IDS_FILE}"
            )),
        }
    }
    for t in d.tests {
        bad.extend(check_cited(t, ctx));
    }
    bad
}

fn rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

#[test]
fn the_catalogue_has_one_complete_entry_per_shipped_rule() {
    let p = pinned();
    let shipped: Vec<ShippedRule> = render::shipped_rules();
    let ids: BTreeSet<&str> = shipped.iter().map(|r| r.id).collect();
    let mut seen = BTreeMap::new();
    let mut bad = Vec::new();
    for d in docs() {
        if seen.insert(d.id, ()).is_some() {
            bad.push(format!("{}: two catalogue entries", d.id));
        }
        if !ids.contains(d.id) {
            bad.push(format!("{}: a catalogue entry for no shipped rule", d.id));
        }
        bad.extend(entry_problems(d, &p));
    }
    for id in &ids {
        if !seen.contains_key(id) {
            bad.push(format!(
                "{id}: no catalogue entry (agent/src/decision/catalogue/)"
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The catalogue's severities agree with the V2 registry's gate: a rule
/// that can issue a Critical verdict is in the Critical sub-gate (or out
/// of it with its reason, as NN-L-NET-003 until BUG-025), and a sub-gate
/// rule that design §13 Q1 does not name is there because it can.
#[test]
fn the_catalogue_severities_agree_with_the_critical_sub_gate() {
    const OUT_OF_THE_SUB_GATE: &[&str] = &["NN-L-NET-003_BadJa3"];
    let mut bad = Vec::new();
    for r in parse_tsv(&read(render::RULES_TSV)) {
        let id = r["rule_id"].as_str();
        let Some(d) = super::doc(id) else { continue };
        let critical = d.severities.contains(&Severity::Critical);
        let gate = r["gate"] == "critical";
        let q1 = r["q1"] == "yes";
        if critical && !gate && !OUT_OF_THE_SUB_GATE.contains(&id) {
            bad.push(format!(
                "{id}: Critical in the catalogue, outside the sub-gate"
            ));
        }
        if gate && !q1 && !critical {
            bad.push(format!(
                "{id}: in the sub-gate (not by Q1) but never Critical here"
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn a_missing_test_or_data_component_is_reported() {
    let p = pinned();
    let d = RuleDoc {
        id: "X",
        severities: &[Severity::Medium, Severity::High],
        actions: &[common::ResponseAction::Log],
        sensors: &[crate::detection_store::Sensor::Exec],
        data_components: &["DC0999"],
        observes: "x",
        false_positives: "x",
        how_to_test: "x",
        tests: &[
            "agent/src/decision/attack.rs::no_such_test",
            "deploy/lab/none.sh::x",
            "nopath",
        ],
        attack_note: "",
    };
    let bad = entry_problems(&d, &p);
    assert_eq!(bad.len(), 5, "{bad:?}");
}

#[test]
fn the_committed_documents_are_the_generated_ones() {
    let root = root();
    let mut stale = Vec::new();
    for (rel, want) in render::render(Path::new(&root)).unwrap_or_else(|e| panic!("{e}")) {
        let have = std::fs::read_to_string(root.join(rel)).unwrap_or_default();
        if have != want {
            stale.push(rel);
        }
    }
    assert!(
        stale.is_empty(),
        "{stale:?} differ from what the mapping and the catalogue render: run \
         `cargo xtask attack-coverage` and commit the result"
    );
}

#[test]
fn the_navigator_layer_is_a_4_5_layer_of_the_mapped_techniques() {
    let layer: serde_json::Value =
        serde_json::from_str(&read(render::LAYER_JSON)).expect("the layer is JSON");
    assert_eq!(layer["domain"], "enterprise-attack");
    assert_eq!(layer["versions"]["layer"], "4.5");
    assert_eq!(
        layer["versions"]["attack"],
        ATTACK_VERSION.split('.').next().unwrap()
    );
    let mut want = BTreeSet::new();
    for r in render::shipped_rules() {
        for a in r.attack {
            want.insert((
                a.technique.as_str().to_string(),
                a.tactic.shortname().to_string(),
            ));
        }
    }
    let have: BTreeSet<(String, String)> = layer["techniques"]
        .as_array()
        .expect("techniques")
        .iter()
        .map(|t| {
            (
                t["techniqueID"].as_str().unwrap().to_string(),
                t["tactic"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(have, want);
}
