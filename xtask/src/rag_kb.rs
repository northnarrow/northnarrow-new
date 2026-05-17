//! Tappa 6.9.7 P2 — sovereign RAG knowledge-base acquisition pipeline.
//!
//! Acquires the pinned corpus (MITRE ATT&CK Enterprise v18.1 + SigmaHQ
//! Linux rules), distils each source into the **8-key canonical record**
//! (owner ruling 2026-05-17 — `author` first, always present), writes
//! deterministic canonical JSONL dumps (sorted by `id`, sorted keys,
//! LF), per-source provenance sidecars (plan §4.2.2), the top-level
//! `kb_index_hash` (plan §3.1.1), verbatim `LICENSES/`, and `NOTICES.md`.
//!
//! Build-time mode fetches the pinned refs over HTTPS (ureq, rustls —
//! no FFI); install-time mode (`--mirror DIR`) reads the same artifacts
//! from a customer-controlled mirror. The agent itself never fetches —
//! this is build/release tooling only.
//!
//! Bulky JSONL dumps land in the gitignored `out` dir; the auditable
//! anchor (per-source `canonical_dump_sha256` + `kb_index_hash`) is
//! committed in `docs/kb-sources/`. LOLBAS is deliberately absent
//! (GPL-3.0 — plan §4.2.3).

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── pinned refs (Q1/Q2 rulings; §4.2 / §4.2.3) ─────────────────────────

const ATTACK_SOURCE_ID: &str = "mitre-attack-stix-data";
const ATTACK_REPO_URL: &str = "https://github.com/mitre-attack/attack-stix-data";
const ATTACK_PIN: &str = "v18.1";
const ATTACK_COMMIT: &str = "7ad8a86f41edc91dd37de0487b0c2f44ae3a3af7";
const ATTACK_BUNDLE_URL: &str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.1/enterprise-attack/enterprise-attack-18.1.json";
const ATTACK_LICENSE_URL: &str =
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.1/LICENSE.txt";
const ATTACK_BUNDLE_FILE: &str = "enterprise-attack-18.1.json";
const ATTACK_LICENSE_FILE: &str = "LICENSES/MITRE_ATTACK_ToU.md";

const SIGMA_SOURCE_ID: &str = "sigma-hq-rules";
const SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma";
const SIGMA_PIN: &str = "master";
const SIGMA_COMMIT: &str = "df5c6a6ecc149e05cb4dea306012668fb2ae5a12";
const SIGMA_TARBALL_URL: &str =
    "https://codeload.github.com/SigmaHQ/sigma/tar.gz/df5c6a6ecc149e05cb4dea306012668fb2ae5a12";
const SIGMA_TARBALL_FILE: &str = "sigma-df5c6a6e.tar.gz";
// DRL 1.1 lives in a SEPARATE repo (the sigma-repo root LICENSE is only
// an index pointing here — P1.3 verification finding).
const SIGMA_LICENSE_URL: &str =
    "https://raw.githubusercontent.com/SigmaHQ/Detection-Rule-License/master/LICENSE.Detection.Rules.md";
const SIGMA_LICENSE_FILE: &str = "LICENSES/SIGMA_DRL-1.1.md";

/// §3.1.1 domain separator (versioned; a layout change bumps `-v1`).
const KB_CANON_DOMAIN: &[u8] = b"NN-RAG-KB-CANON-v1\0";

/// Defence-in-depth cap on any single fetched artifact (ATT&CK v18.1
/// bundle is ~48 MB; Sigma tarball ~7 MB).
const MAX_FETCH_BYTES: u64 = 256 * 1024 * 1024;

// ── the 8-key canonical record (owner ruling, 2026-05-17) ──────────────

/// One canonical KB line. Field order is **alphabetical** and matches
/// the serialised JSON key order exactly (`serde` emits struct fields in
/// declaration order); every key is always present (never omitted) so
/// every line has an identical key set — maximal hash determinism.
/// `author` is `null` except for Sigma rules (DRL-1.1 modified-form
/// per-rule attribution).
#[derive(Debug, Clone, Serialize)]
struct CanonRecord {
    author: Option<Vec<String>>,
    category: String,
    content: String,
    id: String,
    platform: String,
    severity: String,
    source_ref: String,
    title: String,
}

/// Provenance sidecar — plan §4.2.2 (owner verbatim ARTIFACT 3) schema.
#[derive(Debug, Serialize)]
struct Provenance {
    source: String,
    url: String,
    pin: String,
    commit_sha: String,
    acquired_at_utc: String,
    canonical_dump_sha256: String,
    license: String,
    license_file: String,
}

// ── fetch / mirror ─────────────────────────────────────────────────────

fn http_get(url: &str) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(600))
        .user_agent("northnarrow-xtask-rag-kb/0.0.1")
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| anyhow!("HTTP GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_FETCH_BYTES)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading body of {url}"))?;
    if buf.is_empty() {
        bail!("empty body from {url}");
    }
    Ok(buf)
}

/// Obtain `url` (build-time) or `<mirror>/<file>` (install-time). Same
/// bytes ⇒ same canonicalisation ⇒ same hashes either way (Q5 = both).
fn obtain(mirror: Option<&Path>, url: &str, mirror_file: &str) -> Result<Vec<u8>> {
    match mirror {
        Some(dir) => {
            let p = dir.join(mirror_file);
            std::fs::read(&p).with_context(|| format!("mirror read {}", p.display()))
        }
        None => http_get(url),
    }
}

// ── MITRE ATT&CK (STIX 2.1) ────────────────────────────────────────────

#[derive(Deserialize)]
struct StixBundle {
    #[serde(default)]
    objects: Vec<StixObject>,
}

#[derive(Deserialize)]
struct StixObject {
    #[serde(rename = "type", default)]
    otype: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    revoked: bool,
    #[serde(rename = "x_mitre_deprecated", default)]
    deprecated: bool,
    #[serde(default)]
    external_references: Vec<StixExtRef>,
    #[serde(rename = "x_mitre_platforms", default)]
    platforms: Vec<String>,
    #[serde(default)]
    kill_chain_phases: Vec<StixKillChainPhase>,
}

#[derive(Deserialize)]
struct StixExtRef {
    #[serde(default)]
    source_name: String,
    #[serde(default)]
    external_id: String,
}

#[derive(Deserialize)]
struct StixKillChainPhase {
    #[serde(default)]
    kill_chain_name: String,
    #[serde(default)]
    phase_name: String,
}

fn parse_attack(bytes: &[u8]) -> Result<Vec<CanonRecord>> {
    let bundle: StixBundle =
        serde_json::from_slice(bytes).context("parsing ATT&CK STIX bundle")?;
    let mut out = Vec::new();
    for o in &bundle.objects {
        if o.otype != "attack-pattern" || o.revoked || o.deprecated {
            continue;
        }
        let Some(ext_id) = o
            .external_references
            .iter()
            .find(|r| r.source_name == "mitre-attack" && !r.external_id.is_empty())
            .map(|r| r.external_id.clone())
        else {
            continue;
        };
        let tactics: Vec<&str> = o
            .kill_chain_phases
            .iter()
            .filter(|p| p.kill_chain_name == "mitre-attack")
            .map(|p| p.phase_name.as_str())
            .collect();
        let mut content = o.description.trim().to_string();
        if !o.platforms.is_empty() {
            content.push_str(&format!("\nPlatforms: {}", o.platforms.join(", ")));
        }
        if !tactics.is_empty() {
            content.push_str(&format!("\nTactics: {}", tactics.join(", ")));
        }
        out.push(CanonRecord {
            author: None, // MITRE attribution is wholesale via NOTICES.md
            category: "mitre_technique".to_string(),
            content,
            id: format!("attack:{ext_id}"),
            platform: o.platforms.join(", "),
            severity: String::new(),
            source_ref: format!("attack:{ext_id}"),
            title: o.name.trim().to_string(),
        });
    }
    if out.is_empty() {
        bail!("ATT&CK parse yielded 0 techniques (schema drift?)");
    }
    Ok(out)
}

// ── SigmaHQ (YAML rules, Linux logsource subset) ───────────────────────

#[derive(Deserialize)]
struct SigmaRule {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    author: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    logsource: Option<SigmaLogSource>,
}

#[derive(Deserialize)]
struct SigmaLogSource {
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    service: Option<String>,
}

/// Normalise Sigma's `author` (string, comma-list, or YAML sequence)
/// into a trimmed list. `None`/empty ⇒ `None` (still serialised, as
/// `null`, by the canonical record).
fn normalize_authors(v: Option<&serde_yaml_ng::Value>) -> Option<Vec<String>> {
    let split = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    };
    let list: Vec<String> = match v {
        Some(serde_yaml_ng::Value::String(s)) => split(s),
        Some(serde_yaml_ng::Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|e| e.as_str().map(str::to_string))
            .flat_map(|s| split(&s))
            .collect(),
        _ => Vec::new(),
    };
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

fn parse_sigma(tarball_gz: &[u8]) -> Result<Vec<CanonRecord>> {
    let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(tarball_gz));
    let mut ar = tar::Archive::new(dec);
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for entry in ar.entries().context("reading Sigma tarball")? {
        let mut entry = entry.context("Sigma tar entry")?;
        let path = entry
            .path()
            .context("Sigma entry path")?
            .to_string_lossy()
            .into_owned();
        if !(path.contains("/rules") && path.ends_with(".yml")) {
            continue;
        }
        let mut raw = String::new();
        if entry.read_to_string(&mut raw).is_err() {
            skipped += 1;
            continue;
        }
        // Sigma is overwhelmingly single-document; correlation/global
        // and multi-doc files (a minority) fail this and are skipped
        // (counted, never silently dropped).
        let Ok(rule) = serde_yaml_ng::from_str::<SigmaRule>(&raw) else {
            skipped += 1;
            continue;
        };
        let is_linux = rule
            .logsource
            .as_ref()
            .and_then(|l| l.product.as_deref())
            == Some("linux");
        if !is_linux {
            continue;
        }
        let Some(id) = rule.id.filter(|s| !s.is_empty()) else {
            skipped += 1;
            continue;
        };
        let ls = rule.logsource.as_ref();
        let ls_str = format!(
            "linux/{}/{}",
            ls.and_then(|l| l.category.as_deref()).unwrap_or("-"),
            ls.and_then(|l| l.service.as_deref()).unwrap_or("-"),
        );
        let level = rule.level.unwrap_or_default();
        let mut content = rule.description.unwrap_or_default().trim().to_string();
        content.push_str(&format!("\nLogsource: {ls_str}"));
        if !level.is_empty() {
            content.push_str(&format!("\nLevel: {level}"));
        }
        out.push(CanonRecord {
            author: normalize_authors(rule.author.as_ref()),
            category: "sigma_rule".to_string(),
            content,
            id: format!("sigma:{id}"),
            platform: "linux".to_string(),
            severity: level,
            source_ref: format!("sigma:{id}"),
            title: rule.title.unwrap_or_default().trim().to_string(),
        });
    }
    if out.is_empty() {
        bail!("Sigma parse yielded 0 Linux rules (filter/schema drift?)");
    }
    eprintln!("  sigma: {} linux rules, {skipped} non-rule/unparsed skipped", out.len());
    Ok(out)
}

// ── canonicalisation + hashing (plan §4.1 / §3.1.1) ────────────────────

/// §4.1: sort records by `id` (byte order), dedup by `id` (keep first),
/// one compact JSON object per line, LF, single trailing `\n`.
fn canonical_jsonl(mut records: Vec<CanonRecord>) -> Result<Vec<u8>> {
    records.sort_by(|a, b| a.id.cmp(&b.id));
    let mut seen = BTreeSet::new();
    let mut buf = String::new();
    for r in &records {
        if !seen.insert(r.id.clone()) {
            continue; // duplicate id ⇒ keep first (deterministic post-sort)
        }
        buf.push_str(&serde_json::to_string(r).context("serialising canonical record")?);
        buf.push('\n');
    }
    Ok(buf.into_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())
}

fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Per-source input to the §3.1.1 `kb_index_hash`.
struct IndexSource {
    source_id: String,
    url: String,
    pin: String,
    dump_sha256: [u8; 32],
}

/// §3.1.1: domain-separated, length-prefixed, sources sorted by
/// `source_id`. Fixed 32-byte digests + u32-BE length prefixes ⇒
/// unambiguous preimage (same discipline as the 6.9 `environment_hash`).
fn kb_index_hash(mut sources: Vec<IndexSource>) -> String {
    sources.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    let mut h = Sha256::new();
    h.update(KB_CANON_DOMAIN);
    h.update((sources.len() as u32).to_be_bytes());
    for s in &sources {
        h.update((s.source_id.len() as u32).to_be_bytes());
        h.update(s.source_id.as_bytes());
        h.update((s.url.len() as u32).to_be_bytes());
        h.update(s.url.as_bytes());
        h.update((s.pin.len() as u32).to_be_bytes());
        h.update(s.pin.as_bytes());
        h.update(s.dump_sha256);
    }
    hex_lower(&h.finalize())
}

// ── orchestration ──────────────────────────────────────────────────────

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

#[allow(clippy::too_many_arguments)]
fn write_provenance(
    root: &Path,
    source: &str,
    url: &str,
    pin: &str,
    commit: &str,
    acquired: &str,
    dump_sha: &str,
    license: &str,
    license_file: &str,
) -> Result<()> {
    let p = Provenance {
        source: source.to_string(),
        url: url.to_string(),
        pin: pin.to_string(),
        commit_sha: commit.to_string(),
        acquired_at_utc: acquired.to_string(),
        canonical_dump_sha256: dump_sha.to_string(),
        license: license.to_string(),
        license_file: license_file.to_string(),
    };
    let json = serde_json::to_string_pretty(&p).context("serialising provenance")?;
    write_file(
        &root.join("docs/kb-sources").join(source).join("provenance.json"),
        format!("{json}\n").as_bytes(),
    )
}

fn build_notices(authors: &BTreeSet<String>) -> String {
    let mut s = String::new();
    s.push_str("# NOTICES — Tappa 6.9.7 RAG knowledge base\n\n");
    s.push_str(
        "This product's RAG knowledge base is distilled from the pinned \
         third-party sources below. LOLBAS is deliberately excluded \
         (GPL-3.0 — incompatible with proprietary distribution; plan \
         §4.2.3). Verbatim license texts are in `LICENSES/`.\n\n",
    );
    s.push_str("## MITRE ATT&CK® (Enterprise)\n\n");
    s.push_str(&format!(
        "- Source: {ATTACK_REPO_URL}\n- Pin: {ATTACK_PIN} (commit {ATTACK_COMMIT})\n\
         - License: MITRE ATT&CK Terms of Use — `{ATTACK_LICENSE_FILE}`\n\
         - Attribution: \"© The MITRE Corporation. ATT&CK® is reproduced \
         and distributed with the permission of The MITRE Corporation.\"\n\n",
    ));
    s.push_str("## SigmaHQ detection rules (Linux subset, distilled)\n\n");
    s.push_str(&format!(
        "- Source: {SIGMA_REPO_URL}\n- Pin: {SIGMA_PIN} (commit {SIGMA_COMMIT})\n\
         - License: Detection Rule License (DRL) 1.1 — `{SIGMA_LICENSE_FILE}`\n\
         - Rules are distilled (modified form); per-rule `author` \
         attribution is preserved in the canonical dump's `author` field.\n\
         - Aggregate rule authors (DRL-1.1 attribution):\n\n",
    ));
    for a in authors {
        s.push_str(&format!("  - {a}\n"));
    }
    s.push('\n');
    s
}

/// P2 entrypoint. `root` = repo root; `mirror` = install-time source
/// dir or `None` for build-time fetch; `out` = gitignored dump dir.
pub fn build(root: &Path, mirror: Option<&Path>, out: &Path) -> Result<()> {
    let acquired = chrono::Utc::now().to_rfc3339();
    let out = if out.is_absolute() {
        out.to_path_buf()
    } else {
        root.join(out)
    };
    eprintln!("xtask rag-kb: acquiring pinned corpus (mode: {})", if mirror.is_some() { "mirror" } else { "fetch" });

    // ── MITRE ATT&CK ──
    eprintln!("  attack: obtaining {ATTACK_PIN} bundle…");
    let attack_bytes = obtain(mirror, ATTACK_BUNDLE_URL, ATTACK_BUNDLE_FILE)?;
    let attack_records = parse_attack(&attack_bytes)?;
    eprintln!("  attack: {} techniques", attack_records.len());
    let attack_dump = canonical_jsonl(attack_records)?;
    let attack_dump_sha = sha256_hex(&attack_dump);
    write_file(&out.join("mitre-attack.jsonl"), &attack_dump)?;

    // ── SigmaHQ ──
    eprintln!("  sigma: obtaining pinned tarball…");
    let sigma_gz = obtain(mirror, SIGMA_TARBALL_URL, SIGMA_TARBALL_FILE)?;
    let sigma_records = parse_sigma(&sigma_gz)?;
    let mut authors = BTreeSet::new();
    for r in &sigma_records {
        if let Some(list) = &r.author {
            for a in list {
                authors.insert(a.clone());
            }
        }
    }
    let sigma_dump = canonical_jsonl(sigma_records)?;
    let sigma_dump_sha = sha256_hex(&sigma_dump);
    write_file(&out.join("sigma.jsonl"), &sigma_dump)?;

    // ── verbatim LICENSES/ (from the exact pinned refs) ──
    let attack_license = obtain(mirror, ATTACK_LICENSE_URL, "MITRE_ATTACK_ToU.md")?;
    write_file(&root.join(ATTACK_LICENSE_FILE), &attack_license)?;
    let sigma_license = obtain(mirror, SIGMA_LICENSE_URL, "SIGMA_DRL-1.1.md")?;
    write_file(&root.join(SIGMA_LICENSE_FILE), &sigma_license)?;

    // R4 license re-verification (owner standing flag-before-commit
    // rule): the MITRE source moved to attack-stix-data — confirm it is
    // still the commercial-use ATT&CK ToU, not a surprise license.
    let attack_lic_txt = String::from_utf8_lossy(&attack_license);
    if !(attack_lic_txt.contains("ATT&CK") && attack_lic_txt.contains("commercial")) {
        bail!(
            "R4 FLAG: attack-stix-data@{ATTACK_PIN} LICENSE.txt does not \
             read as the ATT&CK Terms of Use (commercial-use grant). \
             STOP — re-rule Q5/Q8 before the P2 commit."
        );
    }

    // ── provenance sidecars (plan §4.2.2) ──
    write_provenance(
        root, ATTACK_SOURCE_ID, ATTACK_REPO_URL, ATTACK_PIN, ATTACK_COMMIT,
        &acquired, &attack_dump_sha, "MITRE ATT&CK Terms of Use", ATTACK_LICENSE_FILE,
    )?;
    write_provenance(
        root, SIGMA_SOURCE_ID, SIGMA_REPO_URL, SIGMA_PIN, SIGMA_COMMIT,
        &acquired, &sigma_dump_sha, "DRL-1.1", SIGMA_LICENSE_FILE,
    )?;

    // ── kb_index_hash (plan §3.1.1) ──
    let kb_hash = kb_index_hash(vec![
        IndexSource {
            source_id: ATTACK_SOURCE_ID.to_string(),
            url: ATTACK_REPO_URL.to_string(),
            pin: ATTACK_PIN.to_string(),
            dump_sha256: sha256_raw(&attack_dump),
        },
        IndexSource {
            source_id: SIGMA_SOURCE_ID.to_string(),
            url: SIGMA_REPO_URL.to_string(),
            pin: SIGMA_PIN.to_string(),
            dump_sha256: sha256_raw(&sigma_dump),
        },
    ]);
    let index_doc = serde_json::json!({
        "domain": "NN-RAG-KB-CANON-v1",
        "kb_index_hash": kb_hash,
        "sources": [
            { "source": ATTACK_SOURCE_ID, "pin": ATTACK_PIN, "canonical_dump_sha256": attack_dump_sha },
            { "source": SIGMA_SOURCE_ID, "pin": SIGMA_PIN, "canonical_dump_sha256": sigma_dump_sha },
        ],
        "note": "LOLBAS excluded (GPL-3.0, plan §4.2.3). 6.7 in-repo notes merged at index build (P3/P4), not acquired here.",
    });
    write_file(
        &root.join("docs/kb-sources/kb_index.json"),
        format!("{}\n", serde_json::to_string_pretty(&index_doc)?).as_bytes(),
    )?;

    // ── NOTICES.md ──
    write_file(&root.join("NOTICES.md"), build_notices(&authors).as_bytes())?;

    eprintln!("xtask rag-kb: DONE");
    eprintln!("  attack dump sha256 = {attack_dump_sha}");
    eprintln!("  sigma  dump sha256 = {sigma_dump_sha}");
    eprintln!("  kb_index_hash      = {kb_hash}");
    eprintln!("  dumps (gitignored) = {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, author: Option<Vec<String>>) -> CanonRecord {
        CanonRecord {
            author,
            category: "sigma_rule".to_string(),
            content: "c".to_string(),
            id: id.to_string(),
            platform: "linux".to_string(),
            severity: "high".to_string(),
            source_ref: id.to_string(),
            title: "t".to_string(),
        }
    }

    #[test]
    fn canonical_line_is_8_key_alpha_sorted_with_author_array_or_null() {
        let with = serde_json::to_string(&rec("sigma:a", Some(vec!["X".into(), "Y".into()])))
            .unwrap();
        assert_eq!(
            with,
            r#"{"author":["X","Y"],"category":"sigma_rule","content":"c","id":"sigma:a","platform":"linux","severity":"high","source_ref":"sigma:a","title":"t"}"#
        );
        let without = serde_json::to_string(&rec("attack:T1", None)).unwrap();
        assert!(without.starts_with(r#"{"author":null,"category":"#));
    }

    #[test]
    fn canonical_jsonl_sorts_by_id_dedups_and_trails_newline() {
        let bytes = canonical_jsonl(vec![
            rec("sigma:b", None),
            rec("sigma:a", None),
            rec("sigma:b", None), // dup id ⇒ dropped
        ])
        .unwrap();
        let s = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(r#""id":"sigma:a""#));
        assert!(lines[1].contains(r#""id":"sigma:b""#));
        assert!(s.ends_with('\n'));
        // Determinism: same input ⇒ identical bytes.
        let again = canonical_jsonl(vec![rec("sigma:a", None), rec("sigma:b", None)]).unwrap();
        assert_eq!(s.as_bytes(), again.as_slice());
    }

    #[test]
    fn normalize_authors_handles_string_list_and_seq() {
        use serde_yaml_ng::Value;
        assert_eq!(
            normalize_authors(Some(&Value::String("Florian Roth, Nasreddine B".into()))),
            Some(vec!["Florian Roth".to_string(), "Nasreddine B".to_string()])
        );
        let seq = Value::Sequence(vec![Value::String("A".into()), Value::String("B, C".into())]);
        assert_eq!(
            normalize_authors(Some(&seq)),
            Some(vec!["A".to_string(), "B".to_string(), "C".to_string()])
        );
        assert_eq!(normalize_authors(None), None);
        assert_eq!(normalize_authors(Some(&Value::String("  ".into()))), None);
    }

    #[test]
    fn kb_index_hash_is_byte_locked_and_tamper_sensitive() {
        let mk = |sha: [u8; 32]| {
            vec![
                IndexSource {
                    source_id: "mitre-attack-stix-data".into(),
                    url: "https://github.com/mitre-attack/attack-stix-data".into(),
                    pin: "v18.1".into(),
                    dump_sha256: [0xAA; 32],
                },
                IndexSource {
                    source_id: "sigma-hq-rules".into(),
                    url: "https://github.com/SigmaHQ/sigma".into(),
                    pin: "master".into(),
                    dump_sha256: sha,
                },
            ]
        };
        let h1 = kb_index_hash(mk([0xBB; 32]));
        // Locks the §3.1.1 preimage encoding; an accidental change to
        // the domain/layout/order flips this and fails CI.
        assert_eq!(
            h1,
            "918782f072a02db9378db7c9027ecceae900b20f477bd3b6ae8e813ce8f5c8c9",
            "§3.1.1 preimage drift — if intentional, bump KB_CANON_DOMAIN \
             and update this lock with a rationale in the commit body"
        );
        assert_ne!(h1, kb_index_hash(mk([0xBC; 32])), "tamper ⇒ different hash");
    }
}
