//! Lab PR 221 (capability C16): the generator behind `cargo xtask
//! attack-coverage`.
//!
//! ```text
//! attack_coverage --write <repo root> [--pin-ids <ids> --mirror <dir>]
//! attack_coverage --check <repo root>
//! ```
//!
//! - `--write` renders `docs/detection/ATTACK_COVERAGE.md`,
//!   `RULE_CATALOGUE.md` and `attack-navigator-layer.json` from the rules'
//!   ATT&CK mapping and the catalogue table
//!   (`northnarrow_agent::decision::catalogue::render`); `--check` writes
//!   nothing and exits 1 when a committed document differs.
//! - `--pin-ids <ids> --mirror <dir>` first rebuilds the pinned id list
//!   (`docs/detection/attack-enterprise-20.0.tsv`) and the ATT&CK Terms of
//!   Use (`LICENSES/MITRE_ATTACK_ToU-20.0.md`) from `<dir>/`
//!   [`BUNDLE_FILE`] and `<dir>/`[`LICENSE_FILE`], the files of
//!   mitre-attack/attack-stix-data at [`COMMIT`], refused unless their
//!   SHA-256 is the pinned one. The ids kept: those the list holds, `<ids>`
//!   (comma-separated, may be empty), what a revoked one is revoked by, the
//!   parents of sub-techniques and every tactic. To drop an id no longer in
//!   use, delete the list and pin the ids in use again (the agent's tests
//!   name them).
//!
//! No eBPF, no root, no network: it reads the repository and the mirror.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use northnarrow_agent::decision::attack::ATTACK_IDS_FILE;
use northnarrow_agent::decision::catalogue::render;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The ATT&CK release pinned: its version, the repository and commit the
/// files are taken from, and their SHA-256.
const VERSION: &str = "20.0";
const SOURCE: &str = "https://github.com/mitre-attack/attack-stix-data";
const COMMIT: &str = "20664a889568dce884a1dac0ec7b12ae3a199f51";
const BUNDLE_PATH: &str = "enterprise-attack/enterprise-attack-20.0.json";
const BUNDLE_FILE: &str = "enterprise-attack-20.0.json";
const BUNDLE_SHA256: &str = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352";
const LICENSE_FILE: &str = "LICENSE.txt";
const LICENSE_SHA256: &str = "738144f7fb054722a4ef9d3367c51710341dc12fc574c6ac3a41daaaecd8bf5e";
/// Where the Terms of Use go, verbatim.
const LICENSE_OUT: &str = "LICENSES/MITRE_ATTACK_ToU-20.0.md";

fn raw_url(path: &str) -> String {
    format!("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{COMMIT}/{path}")
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("attack_coverage: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let usage = "usage: attack_coverage --write|--check <repository root> \
                 [--pin-ids <ids> --mirror <dir>]";
    let (mode, root, rest) = match args.as_slice() {
        [m, r, rest @ ..] if m == "--write" || m == "--check" => {
            (m.as_str(), PathBuf::from(r), rest)
        }
        _ => return Err(usage.into()),
    };
    let (mut pin, mut mirror) = (None, None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pin-ids" => pin = Some(it.next().ok_or(usage)?.clone()),
            "--mirror" => mirror = Some(PathBuf::from(it.next().ok_or(usage)?)),
            _ => return Err(usage.into()),
        }
    }
    match (pin, mirror) {
        (Some(ids), Some(dir)) if mode == "--write" => pin_ids(&root, &dir, &ids)?,
        (None, None) => {}
        _ => {
            return Err(format!(
                "--pin-ids and --mirror go together, with --write\n{usage}"
            ))
        }
    }
    let mut stale = Vec::new();
    for (rel, contents) in render::render(&root)? {
        let path = root.join(rel);
        if std::fs::read_to_string(&path).is_ok_and(|have| have == contents) {
            continue;
        }
        if mode == "--check" {
            stale.push(rel);
            continue;
        }
        write(&path, contents.as_bytes())?;
        eprintln!("attack_coverage: wrote {rel}");
    }
    if !stale.is_empty() {
        eprintln!(
            "attack_coverage: {} differ from the rendered documents: run `cargo xtask \
             attack-coverage` and commit the result",
            stale.join(", ")
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

/// `<dir>/<name>`, refused unless its SHA-256 is `sha256`.
fn pinned_file(dir: &Path, name: &str, url_path: &str, sha256: &str) -> Result<Vec<u8>, String> {
    let p = dir.join(name);
    let bytes = std::fs::read(&p).map_err(|e| {
        format!(
            "read {}: {e} — fetch {} into {} first",
            p.display(),
            raw_url(url_path),
            dir.display()
        )
    })?;
    let got = hex::encode(Sha256::digest(&bytes));
    if got != sha256 {
        return Err(format!(
            "{}: SHA-256 {got} is not the pinned {sha256} — not the file of commit {COMMIT}",
            p.display()
        ));
    }
    Ok(bytes)
}

/// The quoted `"© …"` line of the Terms of Use, which every copy carries.
fn designation(terms: &str) -> Result<String, String> {
    terms
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("\"©").and_then(|r| r.strip_suffix('"')))
        .map(|r| format!("©{r}"))
        .ok_or_else(|| "the ATT&CK Terms of Use quote no \"© …\" designation".into())
}

fn pin_ids(root: &Path, mirror: &Path, add: &str) -> Result<(), String> {
    let list_path = root.join(ATTACK_IDS_FILE);
    let mut ids = match std::fs::read_to_string(&list_path) {
        Ok(t) => listed_ids(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(format!("read {}: {e}", list_path.display())),
    };
    ids.extend(
        add.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
    let license = pinned_file(mirror, LICENSE_FILE, LICENSE_FILE, LICENSE_SHA256)?;
    let terms = String::from_utf8(license.clone()).map_err(|_| "Terms of Use not UTF-8")?;
    let designation = designation(&terms)?;
    let raw = pinned_file(mirror, BUNDLE_FILE, BUNDLE_PATH, BUNDLE_SHA256)?;
    let bundle: Value =
        serde_json::from_slice(&raw).map_err(|e| format!("parse {BUNDLE_FILE}: {e}"))?;
    let list = render_list(&index(&bundle)?, &ids, &designation)?;
    write(&list_path, list.as_bytes())?;
    write(&root.join(LICENSE_OUT), &license)?;
    eprintln!("attack_coverage: wrote {ATTACK_IDS_FILE} and {LICENSE_OUT}");
    Ok(())
}

// ── the STIX bundle ─────────────────────────────────────────────────

/// The ids a list file names (its first column).
fn listed_ids(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split('\t').next())
        .filter(|id| *id != "id")
        .map(str::to_string)
        .collect()
}

fn external_id(o: &Value) -> Option<&str> {
    o.get("external_references")?
        .as_array()?
        .iter()
        .find(|r| r.get("source_name").and_then(Value::as_str) == Some("mitre-attack"))?
        .get("external_id")?
        .as_str()
}

fn flag(o: &Value, key: &str) -> bool {
    o.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn text<'a>(o: &'a Value, key: &str) -> &'a str {
    o.get(key).and_then(Value::as_str).unwrap_or("")
}

/// The bundle's tactics, techniques and data components by ATT&CK id; the
/// tactics in matrix order; what each revoked id is revoked by; the
/// collection's version and date.
struct Index<'a> {
    by_id: BTreeMap<&'a str, &'a Value>,
    matrix: Vec<&'a str>,
    revoked_by: BTreeMap<&'a str, &'a str>,
    version: &'a str,
    modified: &'a str,
}

fn index(bundle: &Value) -> Result<Index<'_>, String> {
    let objects = bundle
        .get("objects")
        .and_then(Value::as_array)
        .ok_or("a STIX bundle without objects")?;
    let mut by_stix: BTreeMap<&str, &Value> = BTreeMap::new();
    let mut by_id = BTreeMap::new();
    let (mut version, mut modified) = ("", "");
    for o in objects {
        by_stix.insert(text(o, "id"), o);
        match text(o, "type") {
            "attack-pattern" | "x-mitre-tactic" | "x-mitre-data-component" => {
                if let Some(id) = external_id(o) {
                    if by_id.insert(id, o).is_some() {
                        return Err(format!("{id}: two objects in the bundle"));
                    }
                }
            }
            "x-mitre-collection" => {
                version = text(o, "x_mitre_version");
                modified = text(o, "modified");
            }
            _ => {}
        }
    }
    let mut matrix = Vec::new();
    let mut revoked_by = BTreeMap::new();
    for o in objects {
        match text(o, "type") {
            "x-mitre-matrix" => {
                for r in o
                    .get("tactic_refs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let t = by_stix
                        .get(r.as_str().unwrap_or(""))
                        .and_then(|t| external_id(t))
                        .ok_or_else(|| format!("the matrix names an unknown tactic {r}"))?;
                    matrix.push(t);
                }
            }
            "relationship" if text(o, "relationship_type") == "revoked-by" => {
                let src = by_stix
                    .get(text(o, "source_ref"))
                    .and_then(|s| external_id(s));
                let dst = by_stix
                    .get(text(o, "target_ref"))
                    .and_then(|s| external_id(s));
                if let (Some(src), Some(dst)) = (src, dst) {
                    revoked_by.insert(src, dst);
                }
            }
            _ => {}
        }
    }
    if version != VERSION {
        return Err(format!(
            "the bundle is ATT&CK {version}, not the pinned {VERSION}"
        ));
    }
    if matrix.is_empty() {
        return Err("the bundle has no matrix".into());
    }
    Ok(Index {
        by_id,
        matrix,
        revoked_by,
        version,
        modified,
    })
}

/// One row of the list: id, kind, status, name, tactics, replaced_by.
fn row(ix: &Index<'_>, id: &str) -> Result<[String; 6], String> {
    let o = ix
        .by_id
        .get(id)
        .ok_or_else(|| format!("{id} is not in ATT&CK Enterprise {VERSION}"))?;
    let kind = match text(o, "type") {
        "x-mitre-tactic" => "tactic",
        "x-mitre-data-component" => "data-component",
        _ if flag(o, "x_mitre_is_subtechnique") || id.contains('.') => "subtechnique",
        _ => "technique",
    };
    let status = if flag(o, "revoked") {
        "revoked"
    } else if flag(o, "x_mitre_deprecated") {
        "deprecated"
    } else {
        "active"
    };
    let tactics = match kind {
        "tactic" => text(o, "x_mitre_shortname").to_string(),
        "data-component" => "-".to_string(),
        _ => {
            let phases: Vec<&str> = o
                .get("kill_chain_phases")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|p| text(p, "kill_chain_name") == "mitre-attack")
                .map(|p| text(p, "phase_name"))
                .collect();
            if phases.is_empty() {
                "-".to_string()
            } else {
                phases.join(",")
            }
        }
    };
    let name = text(o, "name");
    if name.is_empty() || name.contains(['\t', '\n']) {
        return Err(format!("{id}: a name the list cannot hold ({name:?})"));
    }
    Ok([
        id.to_string(),
        kind.to_string(),
        status.to_string(),
        name.to_string(),
        tactics,
        ix.revoked_by.get(id).unwrap_or(&"-").to_string(),
    ])
}

/// The list file for `ids`, what revoked ones are revoked by, the parents
/// of sub-techniques and every tactic.
fn render_list(
    ix: &Index<'_>,
    ids: &BTreeSet<String>,
    designation: &str,
) -> Result<String, String> {
    let mut wanted: BTreeSet<String> = ids.clone();
    loop {
        let mut more = BTreeSet::new();
        for id in &wanted {
            if let Some(next) = ix.revoked_by.get(id.as_str()) {
                more.insert(next.to_string());
            }
            if let Some((parent, _)) = id.split_once('.') {
                more.insert(parent.to_string());
            }
        }
        if more.is_subset(&wanted) {
            break;
        }
        wanted.extend(more);
    }
    let mut rows = Vec::new();
    for t in &ix.matrix {
        rows.push(row(ix, t)?);
        wanted.remove(*t);
    }
    let (dcs, techniques): (Vec<String>, Vec<String>) =
        wanted.into_iter().partition(|id| id.starts_with("DC"));
    for id in techniques.iter().chain(&dcs) {
        let r = row(ix, id)?;
        if r[1] == "tactic" {
            return Err(format!("{id}: a tactic outside the matrix"));
        }
        rows.push(r);
    }
    let mut out = format!(
        "# MITRE ATT&CK® Enterprise {version}: the identifiers NorthNarrow's rule mapping uses\n\
         # (lab PR 221). Written by `cargo xtask attack-coverage --pin-ids <ids> --mirror <dir>`\n\
         # (agent/examples/attack_coverage.rs) from the pinned bundle; edit it there.\n\
         # \"{designation}\"\n\
         # Terms: {LICENSE_OUT}, verbatim from the same commit (NOTICES.md).\n\
         # source: {SOURCE}\n\
         # file: {BUNDLE_PATH}\n\
         # commit: {COMMIT}\n\
         # sha256: {BUNDLE_SHA256}\n\
         # version: {version} (collection modified {modified})\n\
         #\n\
         # Columns (tab-separated):\n\
         #   id           TA#### tactic, T#### technique, T####.### sub-technique, DC#### data component\n\
         #   kind         tactic | technique | subtechnique | data-component\n\
         #   status       active | revoked | deprecated, in this version\n\
         #   name         the ATT&CK name\n\
         #   tactics      a technique's tactics (kill-chain phase short names, comma-separated);\n\
         #                a tactic's own short name; - for a data component\n\
         #   replaced_by  the id a revoked object is revoked by; - otherwise\n\
         id\tkind\tstatus\tname\ttactics\treplaced_by\n",
        version = ix.version,
        modified = ix.modified,
    );
    for r in rows {
        out.push_str(&r.join("\t"));
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> Value {
        serde_json::json!({
            "type": "bundle",
            "objects": [
                {"type": "x-mitre-collection", "id": "x-mitre-collection--1",
                 "x_mitre_version": "20.0", "modified": "2026-10-13T17:53:10.145Z"},
                {"type": "x-mitre-tactic", "id": "x-mitre-tactic--p", "name": "Persistence",
                 "x_mitre_shortname": "persistence",
                 "external_references": [{"source_name": "mitre-attack", "external_id": "TA0003"}]},
                {"type": "x-mitre-tactic", "id": "x-mitre-tactic--s", "name": "Stealth",
                 "x_mitre_shortname": "stealth",
                 "external_references": [{"source_name": "mitre-attack", "external_id": "TA0005"}]},
                {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1",
                 "tactic_refs": ["x-mitre-tactic--p", "x-mitre-tactic--s"]},
                {"type": "attack-pattern", "id": "attack-pattern--cron", "name": "Cron",
                 "x_mitre_is_subtechnique": true,
                 "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T1053.003"}]},
                {"type": "attack-pattern", "id": "attack-pattern--stj", "name": "Scheduled Task/Job",
                 "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T1053"}]},
                {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Impair Defenses",
                 "revoked": true,
                 "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}],
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T1562"}]},
                {"type": "attack-pattern", "id": "attack-pattern--new", "name": "Disable or Modify Tools",
                 "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}],
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T1685"}]},
                {"type": "relationship", "id": "relationship--1", "relationship_type": "revoked-by",
                 "source_ref": "attack-pattern--old", "target_ref": "attack-pattern--new"},
                {"type": "x-mitre-data-component", "id": "x-mitre-data-component--1",
                 "name": "File Creation",
                 "external_references": [{"source_name": "mitre-attack", "external_id": "DC0039"}]}
            ]
        })
    }

    #[test]
    fn the_list_holds_the_tactics_parents_replacements_and_status_of_the_ids() {
        let b = bundle();
        let ix = index(&b).unwrap();
        let ids: BTreeSet<String> = ["T1053.003", "T1562", "DC0039"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let list = render_list(&ix, &ids, "© 2026 X.").unwrap();
        let rows: Vec<&str> = list.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            rows,
            [
                "id\tkind\tstatus\tname\ttactics\treplaced_by",
                "TA0003\ttactic\tactive\tPersistence\tpersistence\t-",
                "TA0005\ttactic\tactive\tStealth\tstealth\t-",
                "T1053\ttechnique\tactive\tScheduled Task/Job\tpersistence\t-",
                "T1053.003\tsubtechnique\tactive\tCron\tpersistence\t-",
                "T1562\ttechnique\trevoked\tImpair Defenses\tstealth\tT1685",
                "T1685\ttechnique\tactive\tDisable or Modify Tools\tstealth\t-",
                "DC0039\tdata-component\tactive\tFile Creation\t-\t-",
            ]
        );
        assert!(list.contains("# \"© 2026 X.\"\n"));
        assert!(list.contains(&format!("# commit: {COMMIT}\n")));
        assert_eq!(listed_ids(&list).len(), 7);
        // What the agent's tests parse.
        let p = render::parse_pinned(&list).unwrap();
        assert_eq!(p.version, VERSION);
        assert_eq!(p.current("T1562"), "T1685");
        assert_eq!(p.display_name("T1053.003"), "Scheduled Task/Job: Cron");
    }

    #[test]
    fn an_unknown_id_another_version_or_another_file_is_refused() {
        let b = bundle();
        let ix = index(&b).unwrap();
        assert!(render_list(&ix, &["T9999".to_string()].into(), "x").is_err());
        let mut other = bundle();
        other["objects"][0]["x_mitre_version"] = "19.2".into();
        assert!(index(&other).is_err());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LICENSE_FILE), b"not the licence").unwrap();
        let e = pinned_file(dir.path(), LICENSE_FILE, LICENSE_FILE, LICENSE_SHA256).unwrap_err();
        assert!(e.contains("is not the pinned"), "{e}");
        let e = pinned_file(dir.path(), BUNDLE_FILE, BUNDLE_PATH, BUNDLE_SHA256).unwrap_err();
        assert!(e.contains(&raw_url(BUNDLE_PATH)), "{e}");
    }

    #[test]
    fn the_designation_is_read_verbatim() {
        assert_eq!(
            designation("x\n\"© 2026 The MITRE Corporation. Y.\"\n").unwrap(),
            "© 2026 The MITRE Corporation. Y."
        );
        assert!(designation("no designation").is_err());
    }
}
