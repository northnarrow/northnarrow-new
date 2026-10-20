//! External audit NN-AUD-217, NN-AUD-218, NN-AUD-235 (LAB-012, LAB-013,
//! TST-019): the V2 validation campaign fixes its denominator before it
//! runs, and the 100 % Critical sub-gate says where each rule's proof
//! lives. These tests hold `docs/validation/` to the code:
//!
//! - `v2-rules.tsv` lists exactly the rules the agent can record;
//! - every rule design §13 Q1 names is in the Critical sub-gate, and a
//!   rule taken out of it stays in the denominator with its reason;
//! - every sub-gate rule has one row in matrix.md's evidence table, no cell
//!   is empty, and every test, probe or evidence file a cell cites exists;
//! - the version, row count and sha256 matrix.md records for each frozen
//!   file match the file, so a change to the denominator is a visible new
//!   version, never a silent edit;
//! - the technique and control rows cite shipped rules and existing probes;
//! - (external audit NN-AUD-444, LAB-028, the guard only — lab PR 209) the
//!   campaign's state is told the same way everywhere: while the V2 sweep
//!   document says HALT there is no result to report; once it no longer
//!   does, matrix.md holds a data row and an evidence directory holds a
//!   run, and every row cites a run directory that exists, with its
//!   `SHA256SUMS`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use super::rules;
use super::Rule;

const RULES_TSV: &str = "docs/validation/v2-rules.tsv";
const TECHNIQUES_TSV: &str = "docs/validation/v2-techniques.tsv";
const CONTROLS_TSV: &str = "docs/validation/v2-controls.tsv";
const MATRIX_MD: &str = "docs/validation/matrix.md";
const NO_PROOF: &str = "no proof";

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// A registry file: its `# version:` line and its rows, keyed by the
/// header's column names. Lines starting with `#` are comments.
struct Tsv {
    version: Option<u32>,
    rows: Vec<BTreeMap<String, String>>,
}

fn parse_tsv(rel: &str) -> Tsv {
    let text = read(rel);
    let mut version = None;
    let mut header: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if let Some(comment) = line.strip_prefix('#') {
            if let Some(v) = comment.trim().strip_prefix("version:") {
                version = Some(
                    v.trim()
                        .parse()
                        .unwrap_or_else(|_| panic!("{rel}:{}: bad version", n + 1)),
                );
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<String> = line.split('\t').map(|c| c.trim().to_string()).collect();
        match &header {
            None => header = Some(cells),
            Some(h) => {
                assert_eq!(
                    cells.len(),
                    h.len(),
                    "{rel}:{}: {} cells, the header has {}",
                    n + 1,
                    cells.len(),
                    h.len()
                );
                assert!(
                    cells.iter().all(|c| !c.is_empty()),
                    "{rel}:{}: empty cell (write - instead)",
                    n + 1
                );
                rows.push(h.iter().cloned().zip(cells).collect());
            }
        }
    }
    Tsv { version, rows }
}

/// The data rows of the first table under the matrix.md heading that
/// starts with `heading` (header and separator rows dropped), each cell
/// trimmed.
fn md_table(heading: &str) -> Vec<Vec<String>> {
    let text = read(MATRIX_MD);
    let mut in_section = false;
    let mut seen_header = false;
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            if in_section {
                break;
            }
            in_section = title.starts_with(heading);
            continue;
        }
        if !in_section {
            continue;
        }
        let line = line.trim();
        if !line.starts_with('|') {
            if seen_header && !rows.is_empty() {
                break;
            }
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect();
        if !seen_header {
            seen_header = true;
            continue;
        }
        if cells.iter().all(|c| c.chars().all(|ch| ch == '-')) {
            continue;
        }
        rows.push(cells);
    }
    assert!(
        !rows.is_empty(),
        "{MATRIX_MD}: no table under '## {heading}'"
    );
    rows
}

fn strip_md(cell: &str) -> &str {
    cell.trim_matches(|c| c == '`' || c == '*')
}

/// Every rule id the agent can record, with where it is issued: the
/// production engine's rules (built as main.rs builds them, with empty
/// operator state), NN-L-AT-001 and NN-L-EPG-001/002, which
/// `process_event` issues outside the engine.
fn shipped_rule_ids() -> BTreeMap<String, &'static str> {
    use crate::config::comm_allowlist::CommAllowlist;
    use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
    let engine = rules::default_rules_with_net(
        Arc::new(NetBlocklist::default()),
        Arc::new(Ja3Blocklist::default()),
        Arc::new(Mutex::new(rules::net::DnsBurstWindow::default())),
        Arc::new(CommAllowlist::default()),
        Arc::new(CommAllowlist::default()),
        Arc::new(Mutex::new(rules::net::BeaconWindow::default())),
        Arc::new(crate::net::dns_cache::DnsCache::default()),
        crate::anti_tamper::trusted_installer::TrustedInstallerOverride::inert_arc(),
        crate::posture::lineage::AuthSessionTracker::default(),
        crate::canary::readers::CanaryReaders::default(),
        Arc::new(Mutex::new(
            crate::decision::correlation::CorrelationStore::new(),
        )),
        rules::net::NetRuleConfig::default(),
    );
    let mut ids = BTreeMap::new();
    for r in &engine {
        // One id may be registered twice on purpose: R007 (lab PR 140) kills
        // on an exact miner name and records a name fragment, from a second
        // registration after the process kills. Any other repeat is a bug.
        if ids.insert(r.id().to_string(), "engine").is_some() {
            assert_eq!(r.id(), "R007_CryptoMiner", "duplicate rule id {}", r.id());
        }
    }
    let direct = rules::anti_tamper::NnLAt001AntiTamperDenial;
    assert!(ids.insert(direct.id().to_string(), "direct").is_none());
    // Lab PR 219: the exploit guard's rules, issued outside the engine too.
    let guard: [&dyn crate::decision::Rule; 2] = [
        &rules::epg::NnLEpg001CredentialPostcondition,
        &rules::epg::NnLEpg002NamespaceRootPostcondition,
    ];
    for r in guard {
        assert!(ids.insert(r.id().to_string(), "direct").is_none());
    }
    ids
}

/// The Critical FIM rules design §13 Q1 names. They were read from the
/// LLM advisor's prompt templates (`ade::fim_template`), which routed the
/// same rules; the list stayed here when the advisor was removed in Wave 4
/// (lab PR 214).
const Q1_CRITICAL_FIM_RULE_IDS: &[&str] = &[
    "NN-L-FIM-001_SystemBinaryModified",
    "NN-L-FIM-002_NewSuidBinary",
    "NN-L-FIM-008_KernelModuleModified",
    "NN-L-FIM-010_RansomwareExtensionRename",
    "NN-L-FIM-021_PamModuleModified",
    "NN-L-FIM-022_LdSoPreloadModified",
];

/// The rules design §13 Q1 names, from the code: the Critical FIM rules
/// ([`Q1_CRITICAL_FIM_RULE_IDS`]) and every chain rule ("all CHAIN-*").
fn q1_rule_ids() -> BTreeSet<String> {
    let chains = rules::chain::chain_rule_set();
    Q1_CRITICAL_FIM_RULE_IDS
        .iter()
        .map(|s| s.to_string())
        .chain(
            chains
                .head
                .iter()
                .chain(&chains.tail)
                .map(|r| r.id().to_string()),
        )
        .collect()
}

fn registry() -> Vec<BTreeMap<String, String>> {
    parse_tsv(RULES_TSV).rows
}

fn registry_ids_where(column: &str, value: &str) -> BTreeSet<String> {
    registry()
        .into_iter()
        .filter(|r| r[column] == value)
        .map(|r| r["rule_id"].clone())
        .collect()
}

/// A cell citing proof: `path::anchor`. In a Rust file the anchor is a
/// function (`fn anchor(` must be there); in any other file it is text the
/// file must contain. A path with no anchor (an evidence file) must exist.
fn check_reference(cell: &str, ctx: &str) {
    let cell = strip_md(cell);
    let (path, anchor) = match cell.split_once("::") {
        Some((p, a)) => (p, Some(a)),
        None => (cell, None),
    };
    assert!(
        !path.contains("..") && !path.starts_with('/'),
        "{ctx}: '{path}' must be a path inside the repository"
    );
    assert!(repo_path(path).exists(), "{ctx}: {path} does not exist");
    if let Some(anchor) = anchor {
        let needle = if path.ends_with(".rs") {
            format!("fn {anchor}(")
        } else {
            anchor.to_string()
        };
        assert!(
            read(path).contains(&needle),
            "{ctx}: {path} has no `{needle}`"
        );
    }
}

fn check_rule_list(cell: &str, known: &BTreeSet<String>, ctx: &str) -> usize {
    if cell == "-" {
        return 0;
    }
    let ids: Vec<&str> = cell.split(',').map(str::trim).collect();
    for id in &ids {
        assert!(known.contains(*id), "{ctx}: {id} is not in {RULES_TSV}");
    }
    ids.len()
}

#[test]
fn registry_lists_exactly_the_rules_the_agent_ships() {
    let shipped = shipped_rule_ids();
    let mut listed = BTreeMap::new();
    for r in registry() {
        let id = r["rule_id"].clone();
        assert!(
            matches!(r["where"].as_str(), "engine" | "direct"),
            "{id}: where"
        );
        assert!(matches!(r["gate"].as_str(), "critical" | "-"), "{id}: gate");
        assert!(matches!(r["q1"].as_str(), "yes" | "-"), "{id}: q1");
        let status = r["status"].as_str();
        assert!(
            status == "in"
                || status
                    .strip_prefix("n/a:")
                    .is_some_and(|why| !why.trim().is_empty()),
            "{id}: status must be `in` or `n/a:<reason>`"
        );
        assert!(
            listed.insert(id.clone(), r["where"].clone()).is_none(),
            "{id} listed twice"
        );
    }
    let missing: Vec<String> = shipped
        .iter()
        .filter(|(id, _)| !listed.contains_key(*id))
        .map(|(id, w)| format!("{id}\t<family>\t{w}\t<gate>\t<q1>\tin"))
        .collect();
    let extra: Vec<&String> = listed
        .keys()
        .filter(|id| !shipped.contains_key(*id))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{RULES_TSV} differs from the rules the agent ships — a new version is due \
         (matrix.md, 'Frozen denominator').\nmissing rows:\n{}\nrows for no shipped rule: {extra:?}",
        missing.join("\n")
    );
    for (id, w) in &shipped {
        assert_eq!(&listed[id], w, "{id}: where");
    }
}

#[test]
fn every_rule_q1_names_is_in_the_critical_sub_gate() {
    let q1 = q1_rule_ids();
    assert_eq!(
        registry_ids_where("q1", "yes"),
        q1,
        "the q1 column must mark exactly the rules design §13 Q1 names"
    );
    let gate = registry_ids_where("gate", "critical");
    let outside: Vec<&String> = q1.difference(&gate).collect();
    assert!(
        outside.is_empty(),
        "Q1 rules outside the sub-gate: {outside:?}"
    );
}

#[test]
fn every_critical_rule_has_an_evidence_row_with_no_empty_cell() {
    const COLUMNS: [&str; 8] = [
        "rule_id", "Q1", "unit", "e2e", "lab", "campaign", "status", "notes",
    ];
    const PROOF: [usize; 4] = [2, 3, 4, 5];
    let gate = registry_ids_where("gate", "critical");
    let q1 = registry_ids_where("q1", "yes");
    let mut seen = BTreeSet::new();
    for row in md_table("Critical sub-gate") {
        assert_eq!(row.len(), COLUMNS.len(), "evidence row {row:?}");
        let id = strip_md(&row[0]).to_string();
        let ctx = format!("{MATRIX_MD}, evidence row {id}");
        assert!(seen.insert(id.clone()), "{ctx}: listed twice");
        assert!(gate.contains(&id), "{ctx}: not a gate = critical rule");
        let want_q1 = if q1.contains(&id) { "yes" } else { "-" };
        assert_eq!(row[1], want_q1, "{ctx}: Q1 column");
        for (i, cell) in row.iter().enumerate() {
            assert!(!cell.is_empty(), "{ctx}: empty {} cell", COLUMNS[i]);
        }
        for i in PROOF {
            if row[i] != NO_PROOF {
                check_reference(&row[i], &format!("{ctx}, {}", COLUMNS[i]));
            }
        }
        let has = |i: usize| row[i] != NO_PROOF;
        match row[6].as_str() {
            "campaign" => assert!(has(5), "{ctx}: status campaign without a campaign cell"),
            "e2e" | "e2e-event" | "e2e-flaky" => {
                assert!(has(3), "{ctx}: status {} without an e2e cell", row[6])
            }
            "unit" => assert!(has(2), "{ctx}: status unit without a unit cell"),
            NO_PROOF => assert!(
                PROOF.iter().all(|&i| !has(i)),
                "{ctx}: status `no proof` but a proof cell cites something"
            ),
            other => panic!("{ctx}: unknown status {other}"),
        }
    }
    let missing: Vec<&String> = gate.difference(&seen).collect();
    assert!(
        missing.is_empty(),
        "gate = critical rules with no evidence row in {MATRIX_MD}: {missing:?}"
    );
}

#[test]
fn recorded_versions_and_hashes_match_the_frozen_files() {
    let mut files = BTreeSet::new();
    for row in md_table("Frozen denominator") {
        assert_eq!(row.len(), 5, "frozen-file row {row:?}");
        // `[`v2-rules.tsv`](v2-rules.tsv)` → v2-rules.tsv
        let name = row[0]
            .split(['[', ']', '`'])
            .find(|s| s.ends_with(".tsv"))
            .unwrap_or_else(|| panic!("frozen-file row {row:?}: no .tsv name"))
            .to_string();
        let rel = format!("docs/validation/{name}");
        let tsv = parse_tsv(&rel);
        let text = read(&rel).replace("\r\n", "\n");
        let sha = hex::encode(Sha256::digest(text.as_bytes()));
        let (version, rows, recorded) = (
            row[2].parse::<u32>().ok(),
            row[3].parse::<usize>().ok(),
            strip_md(&row[4]),
        );
        assert_eq!(
            tsv.version, version,
            "{rel}: version recorded in {MATRIX_MD}"
        );
        assert_eq!(
            Some(tsv.rows.len()),
            rows,
            "{rel}: rows recorded in {MATRIX_MD}"
        );
        assert_eq!(
            recorded, sha,
            "{rel} changed: a new version, with this hash and a change-log line in {MATRIX_MD}"
        );
        files.insert(rel);
    }
    let want: BTreeSet<String> = [RULES_TSV, TECHNIQUES_TSV, CONTROLS_TSV]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(files, want, "{MATRIX_MD} must record each frozen file once");
}

/// Rules that can issue a Critical verdict but are out of the sub-gate,
/// each with what brings it back: the reason `matrix.md` must give.
/// Lab PR 163 (registry version 2): NN-L-NET-003 cannot fire until BUG-025
/// gives it a TLS fingerprint producer.
const OUT_OF_THE_SUB_GATE: &[(&str, &str)] = &[("NN-L-NET-003_BadJa3", "BUG-025")];

/// A rule out of the sub-gate is a decision recorded with its reason, not a
/// way out of the campaign: it stays in the denominator (a miss of it
/// counts against the headline), and `matrix.md` says why it is out.
#[test]
fn a_rule_out_of_the_sub_gate_stays_in_the_denominator_with_its_reason() {
    let rows = registry();
    let matrix = read(MATRIX_MD);
    for (id, why) in OUT_OF_THE_SUB_GATE {
        let r = rows
            .iter()
            .find(|r| r["rule_id"] == *id)
            .unwrap_or_else(|| panic!("{id} is not in {RULES_TSV}"));
        assert_eq!(r["gate"], "-", "{id}: out of the sub-gate");
        assert_eq!(
            r["status"], "in",
            "{id}: out of the sub-gate, not out of the denominator"
        );
        assert!(
            matrix.lines().any(|l| l.contains(id) && l.contains(why)),
            "{MATRIX_MD} must say why {id} is out of the sub-gate ({why})"
        );
    }
}

#[test]
fn family_roll_up_counts_match_the_registry() {
    let rows = registry();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in &rows {
        *counts.entry(r["family"].clone()).or_default() += 1;
    }
    counts.insert("Total".into(), rows.len());
    counts.insert(
        "Critical sub-gate".into(),
        rows.iter().filter(|r| r["gate"] == "critical").count(),
    );
    let mut seen = BTreeSet::new();
    for row in md_table("Family coverage roll-up") {
        // "`chain` (NN-L-CHAIN-001..008)" → chain; "**Total**" → Total
        let key = match row[0].split('`').nth(1) {
            Some(k) => k.to_string(),
            None => strip_md(&row[0]).to_string(),
        };
        let want = counts
            .get(&key)
            .unwrap_or_else(|| panic!("roll-up row '{key}' is not a family of {RULES_TSV}"));
        assert_eq!(
            strip_md(&row[1]).parse::<usize>().ok(),
            Some(*want),
            "roll-up {key}"
        );
        seen.insert(key);
    }
    let missing: Vec<&String> = counts.keys().filter(|k| !seen.contains(*k)).collect();
    assert!(missing.is_empty(), "roll-up rows missing: {missing:?}");
}

#[test]
fn technique_and_control_rows_cite_shipped_rules_and_existing_probes() {
    let known: BTreeSet<String> = registry()
        .into_iter()
        .map(|r| r["rule_id"].clone())
        .collect();
    let families: BTreeSet<String> = registry()
        .into_iter()
        .map(|r| r["family"].clone())
        .collect();

    let mut ids = BTreeSet::new();
    for r in parse_tsv(TECHNIQUES_TSV).rows {
        let ctx = format!("{TECHNIQUES_TSV}, {}", r["id"]);
        assert!(ids.insert(r["id"].clone()), "{ctx}: id listed twice");
        assert!(r["technique"].starts_with('T'), "{ctx}: technique");
        for part in r["source"].split('+') {
            assert!(
                matches!(part, "code" | "design" | "audit" | "v2-draft" | "registry"),
                "{ctx}: source {part}"
            );
        }
        let n = check_rule_list(&r["rules"], &known, &ctx);
        match r["expected"].as_str() {
            "rule" => assert!(n > 0, "{ctx}: expected rule, no rule listed"),
            "denial" | "drift" | "known-gap" => {
                assert_eq!(n, 0, "{ctx}: {} row lists rules", r["expected"])
            }
            other => panic!("{ctx}: expected {other}"),
        }
        if r["probe"] != "-" {
            check_reference(&r["probe"], &ctx);
        }
    }

    let mut ids = BTreeSet::new();
    let mut kinds: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in parse_tsv(CONTROLS_TSV).rows {
        let ctx = format!("{CONTROLS_TSV}, {}", r["id"]);
        assert!(ids.insert(r["id"].clone()), "{ctx}: id listed twice");
        assert!(
            families.contains(&r["family"]),
            "{ctx}: family {}",
            r["family"]
        );
        assert!(
            matches!(r["kind"].as_str(), "evasion" | "benign"),
            "{ctx}: kind"
        );
        let n = check_rule_list(&r["rules"], &known, &ctx);
        match r["expected"].as_str() {
            "fire" | "denied" => assert!(n > 0, "{ctx}: no rule listed"),
            "no-kill" | "no-verdict" => {}
            other => panic!("{ctx}: expected {other}"),
        }
        if r["probe"] != "-" {
            check_reference(&r["probe"], &ctx);
        }
        kinds
            .entry(r["family"].clone())
            .or_default()
            .insert(r["kind"].clone());
    }
    for family in &families {
        let k = kinds.get(family).cloned().unwrap_or_default();
        assert!(
            k.contains("evasion") && k.contains("benign"),
            "{CONTROLS_TSV}: family {family} needs an evasion and a benign row"
        );
    }
}

/// External audit NN-AUD-444 (LAB-028): the V2 sweep document, whose HALT
/// line says the campaign has not been approved to run.
const SWEEP_MD: &str = "docs/adversarial/V2_ATOMIC_RED_TEAM_SWEEP.md";
const HALT: &str = "**HALT.**";
/// Where a run's evidence lands (design §11): `docs/validation/evidence/`,
/// which matrix.md's `evidence/<run-id>/` cells name. The sweep's open item
/// 3 also proposes `docs/adversarial/evidence/`; a run there counts too.
const EVIDENCE_DIRS: [&str; 2] = ["docs/validation/evidence", "docs/adversarial/evidence"];

/// The data rows of matrix.md's `## Matrix` table: the template row (cells
/// holding only `<!-- … -->` comments, or empty) is not one.
fn matrix_data_rows(matrix: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut in_matrix = false;
    let mut header_seen = false;
    for line in matrix.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            in_matrix = title.trim() == "Matrix";
            continue;
        }
        let line = line.trim();
        if !in_matrix || !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect();
        if !header_seen {
            header_seen = true;
            continue;
        }
        if cells
            .iter()
            .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        }
        let rule_id = &cells[0];
        if rule_id.is_empty() || rule_id.starts_with("<!--") {
            continue;
        }
        rows.push(cells);
    }
    rows
}

/// One run directory: its name and whether it holds `SHA256SUMS`.
struct RunDir {
    name: String,
    has_sums: bool,
}

fn run_dirs() -> Vec<RunDir> {
    let mut out = Vec::new();
    for dir in EVIDENCE_DIRS {
        let Ok(entries) = std::fs::read_dir(repo_path(dir)) else {
            continue;
        };
        for e in entries {
            let e = e.unwrap_or_else(|e| panic!("{dir}: {e}"));
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                out.push(RunDir {
                    name: e.file_name().to_string_lossy().into_owned(),
                    has_sums: e.path().join("SHA256SUMS").is_file(),
                });
            }
        }
    }
    out
}

/// What is inconsistent in the campaign's state (empty: nothing).
fn campaign_state_problems(sweep: &str, matrix: &str, runs: &[RunDir]) -> Vec<String> {
    let rows = matrix_data_rows(matrix);
    let mut bad = Vec::new();
    if !sweep.contains(HALT) {
        if rows.is_empty() {
            bad.push(format!(
                "{SWEEP_MD} no longer says {HALT}, but {MATRIX_MD} has no data row"
            ));
        }
        if runs.is_empty() {
            bad.push(format!(
                "{SWEEP_MD} no longer says {HALT}, but no run directory exists under {}",
                EVIDENCE_DIRS.join(" or ")
            ));
        }
    }
    for run in runs.iter().filter(|r| !r.has_sums) {
        bad.push(format!(
            "evidence run {} has no SHA256SUMS (design §11)",
            run.name
        ));
    }
    for row in &rows {
        // rule_id | mitre | tool | expected | result | latency_ms | evidence | notes
        let evidence = row.get(6).map(|c| strip_md(c)).unwrap_or("");
        let run = evidence
            .strip_prefix("evidence/")
            .and_then(|r| r.split('/').next())
            .unwrap_or("");
        if run.is_empty() || !runs.iter().any(|r| r.name == run) {
            bad.push(format!(
                "{MATRIX_MD}: the row of {} cites `{evidence}`, not an existing evidence/<run-id>/",
                row[0]
            ));
        }
    }
    bad
}

#[test]
fn the_campaign_state_is_consistent_until_the_sweep_runs() {
    let bad = campaign_state_problems(&read(SWEEP_MD), &read(MATRIX_MD), &run_dirs());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn removing_the_halt_alone_fails_the_campaign_guard() {
    let sweep = read(SWEEP_MD);
    let matrix = read(MATRIX_MD);
    assert!(
        sweep.contains(HALT),
        "{SWEEP_MD}: the HALT line this guard reads"
    );
    assert!(
        campaign_state_problems(&sweep, &matrix, &[]).is_empty(),
        "today: HALT, no row, no run"
    );
    let unhalted = sweep.replace(HALT, "Approved.");
    assert_eq!(campaign_state_problems(&unhalted, &matrix, &[]).len(), 2);

    // A run with its evidence and a row citing it: consistent.
    let row = "| NN-L-FIM-022_LdSoPreloadModified | T1574.006 | probe | Critical | PASS | 12 | `evidence/2026-11-01T10-00_fim_family/` | - |";
    let with_row = matrix.replace(
        "| <!-- e.g. NN-L-FIM-022_LdSoPreloadModified -->",
        &format!("{row}\n| <!-- e.g. NN-L-FIM-022_LdSoPreloadModified -->"),
    );
    assert_eq!(matrix_data_rows(&with_row).len(), 1);
    let run = |sums| RunDir {
        name: "2026-11-01T10-00_fim_family".into(),
        has_sums: sums,
    };
    assert!(campaign_state_problems(&unhalted, &with_row, &[run(true)]).is_empty());
    // The run without SHA256SUMS, or the row citing a run that is not there.
    assert_eq!(
        campaign_state_problems(&unhalted, &with_row, &[run(false)]).len(),
        1
    );
    let other = RunDir {
        name: "2026-11-02T10-00_net_family".into(),
        has_sums: true,
    };
    assert_eq!(
        campaign_state_problems(&unhalted, &with_row, &[other]).len(),
        1
    );
}
