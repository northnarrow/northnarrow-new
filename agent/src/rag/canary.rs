//! Tappa 6.9.7 P5 — env-driven RAG canary (default OFF, beta-safe).
//!
//! The ADE↔RAG seam already exists from 6.7 (`AdeEngine::with_rag`).
//! P5 only decides, from the environment, whether to wire a BM25
//! `RagEngine` into the single production `AdeEngine` (main.rs), with a
//! graceful no-RAG fallback so the §13 canary-parity guarantee holds
//! even when RAG is requested but the corpus cannot be opened.
//!
//! External audit XAI-001/XAI-009/XAI-002: RAG starts only over the
//! corpus the manifest built into the binary pins. A missing corpus
//! (no directory, an empty one, a pinned dump absent) and an altered one
//! (an unlisted `*.jsonl`, another digest) are [`RagCanary::Refused`]: a
//! WARN, no RAG, and the reason for main.rs to record in the signed audit
//! log. It no longer runs on the ~36 seed notes alone while logging "RAG
//! enabled". `NN_ADE_RAG_INDEX_DIR` is ignored: the index is built in
//! memory at every start.
//!
//! Split: [`env_truthy`] / [`rag_canary`] are pure (no global env —
//! race-free unit tests); [`open_index_from_env`] is the thin glue
//! main.rs calls.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use super::kb_manifest::{KbManifest, KbRefusal};
use super::retrieval::RagEngine;

/// Turns the canary on (see [`env_truthy`]).
pub const ENABLED_ENV: &str = "NN_ADE_RAG_ENABLED";
/// The directory holding the pinned dumps.
pub const JSONL_DIR_ENV: &str = "NN_ADE_RAG_JSONL_DIR";
/// Formerly the on-disk index directory; ignored with a WARN.
pub const INDEX_DIR_ENV: &str = "NN_ADE_RAG_INDEX_DIR";
/// Default for [`JSONL_DIR_ENV`].
pub const DEFAULT_JSONL_DIR: &str = "/var/lib/northnarrow/rag/jsonl";

/// `NN_ADE_RAG_ENABLED` truthy set (case-insensitive, trimmed):
/// `1`/`true`/`yes`/`on`. Anything else — including unset, `0`,
/// `false`, `no`, `off`, garbage — is OFF (beta-safe default per the
/// §13 default-flip checklist).
pub fn env_truthy(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `true` iff `NN_ADE_RAG_ENABLED` is set to a truthy value.
pub fn env_rag_enabled() -> bool {
    std::env::var(ENABLED_ENV)
        .map(|v| env_truthy(&v))
        .unwrap_or(false)
}

/// What the canary decided.
#[derive(Debug)]
pub enum RagCanary {
    /// `NN_ADE_RAG_ENABLED` off or unset: the canary-parity path.
    Off,
    /// RAG on, over the verified corpus.
    On(RagEngine),
    /// RAG requested but not started. The text names the cause, for the
    /// signed audit log.
    Refused(String),
}

impl RagCanary {
    /// The engine to wire, if any.
    pub fn into_engine(self) -> Option<RagEngine> {
        match self {
            Self::On(rag) => Some(rag),
            Self::Off | Self::Refused(_) => None,
        }
    }

    /// Why RAG was requested but not started.
    pub fn refusal(&self) -> Option<&str> {
        match self {
            Self::Refused(why) => Some(why),
            Self::Off | Self::On(_) => None,
        }
    }
}

/// Pure canary decision against the pinned manifest (no env read):
/// `enabled=false` ⇒ [`RagCanary::Off`]; `enabled=true` ⇒ verify the
/// dumps in `jsonl_dir` and build the BM25 index, [`RagCanary::On`] on
/// success, [`RagCanary::Refused`] otherwise (graceful degradation — the
/// no-RAG path is the safety net, so RAG-off XAI determinism is never
/// broken by a bad corpus). Logs at each branch.
pub fn rag_canary(enabled: bool, jsonl_dir: &Path) -> RagCanary {
    canary(enabled, jsonl_dir, KbManifest::pinned)
}

/// [`rag_canary`] against `manifest` instead of the pinned one (tests).
pub fn rag_canary_with_manifest(
    enabled: bool,
    jsonl_dir: &Path,
    manifest: &KbManifest,
) -> RagCanary {
    canary(enabled, jsonl_dir, || Ok(manifest.clone()))
}

fn canary(
    enabled: bool,
    jsonl_dir: &Path,
    manifest: impl FnOnce() -> Result<KbManifest, KbRefusal>,
) -> RagCanary {
    if !enabled {
        info!("RAG disabled (NN_ADE_RAG_ENABLED off/unset) — canary-parity path (rag: None)");
        return RagCanary::Off;
    }
    let opened = manifest()
        .map_err(anyhow::Error::from)
        .and_then(|m| RagEngine::open_index_with_manifest(jsonl_dir, &m));
    match opened {
        Ok(rag) => {
            info!(
                docs = rag.document_count(),
                jsonl_dir = %jsonl_dir.display(),
                corpus_fingerprint = rag.corpus_fingerprint(),
                "RAG enabled"
            );
            RagCanary::On(rag)
        }
        Err(e) => {
            let cause = match e.downcast_ref::<KbRefusal>() {
                Some(r) if r.is_missing() => "the canonical corpus is missing",
                Some(_) => "the knowledge base failed its integrity check",
                None => "the knowledge base could not be opened",
            };
            warn!(
                error = %format!("{e:#}"),
                jsonl_dir = %jsonl_dir.display(),
                "RAG requested but {cause} — running without RAG (rag: None)"
            );
            RagCanary::Refused(format!(
                "ADE RAG requested but not started: {cause} ({e:#})"
            ))
        }
    }
}

/// Env glue main.rs calls in the single `AdeEngine` construction site.
/// `NN_ADE_RAG_JSONL_DIR` (default `/var/lib/northnarrow/rag/jsonl`).
pub fn open_index_from_env() -> RagCanary {
    canary_from_vars(|k| std::env::var(k).ok(), KbManifest::pinned)
}

/// [`open_index_from_env`] over a variable lookup (race-free tests).
fn canary_from_vars(
    var: impl Fn(&str) -> Option<String>,
    manifest: impl FnOnce() -> Result<KbManifest, KbRefusal>,
) -> RagCanary {
    let set = |k: &str| var(k).filter(|v| !v.trim().is_empty());
    if let Some(dir) = set(INDEX_DIR_ENV) {
        warn!(
            index_dir = %dir,
            "NN_ADE_RAG_INDEX_DIR is ignored: the RAG index is built in memory from the \
             verified corpus at every start, nothing on disk is read"
        );
    }
    let jsonl = set(JSONL_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_JSONL_DIR));
    let enabled = var(ENABLED_ENV).is_some_and(|v| env_truthy(&v));
    canary(enabled, &jsonl, manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rag::retrieval::RagQuery;

    const LINE: &str = r#"{"author":null,"category":"mitre_technique","content":"zqxjmarker powershell execution","id":"attack:T1059.001","platform":"","severity":"","source_ref":"attack:T1059.001","title":"PowerShell"}"#;

    /// A dump directory holding `fix.jsonl`, and the manifest pinning it.
    fn fixture() -> (tempfile::TempDir, KbManifest) {
        let jl = tempfile::tempdir().unwrap();
        let dump = format!("{LINE}\n");
        std::fs::write(jl.path().join("fix.jsonl"), &dump).unwrap();
        let m = KbManifest::for_dumps(&[("fix.jsonl", dump.as_bytes())]);
        (jl, m)
    }

    #[test]
    fn env_truthy_parses_the_documented_sets() {
        for on in ["1", "true", "TRUE", "Yes", " on ", "On"] {
            assert!(env_truthy(on), "{on:?} must be truthy");
        }
        for off in ["", "0", "false", "no", "off", "OFF", "2", "enable", "y"] {
            assert!(!env_truthy(off), "{off:?} must be falsy (beta-safe)");
        }
    }

    #[test]
    fn canary_off_yields_none() {
        // enabled=false ⇒ no RAG regardless of paths (parity path).
        let c = rag_canary(false, Path::new("/nonexistent"));
        assert!(matches!(c, RagCanary::Off));
        assert!(c.refusal().is_none());
    }

    #[test]
    fn canary_on_with_valid_paths_opens_bm25_engine() {
        let (jl, m) = fixture();
        let rag = rag_canary_with_manifest(true, jl.path(), &m)
            .into_engine()
            .expect("pinned fixture ⇒ Some");
        assert!(rag.document_count() >= 1);
    }

    /// External audit XAI-009: an empty dump directory used to give
    /// `Some` over the ~36 seed notes, logged as "RAG enabled".
    #[test]
    fn canary_on_with_empty_jsonl_dir_falls_back_to_none() {
        let empty = tempfile::tempdir().unwrap();
        let c = rag_canary(true, empty.path());
        let why = c.refusal().expect("refused").to_string();
        assert!(why.contains("canonical corpus is missing"), "{why}");
        assert!(c.into_engine().is_none());
        // Same for a directory that does not exist.
        let c = rag_canary(true, &empty.path().join("absent"));
        assert!(c.refusal().is_some_and(|w| w.contains("missing")));
    }

    /// External audit XAI-001: a dump whose bytes differ from the pinned
    /// digest is refused (it used to be indexed as is).
    #[test]
    fn tampered_dump_refused() {
        let (jl, m) = fixture();
        let forged = LINE.replace("PowerShell\"}", "Benign admin tool\"}");
        std::fs::write(jl.path().join("fix.jsonl"), format!("{forged}\n")).unwrap();
        let c = rag_canary_with_manifest(true, jl.path(), &m);
        let why = c.refusal().expect("refused");
        assert!(why.contains("integrity check"), "{why}");
        assert!(why.contains("fix.jsonl"), "{why}");
    }

    /// External audit XAI-001: any other `*.jsonl` dropped next to the
    /// pinned dumps is refused (it used to be indexed too).
    #[test]
    fn unlisted_jsonl_refused() {
        let (jl, m) = fixture();
        std::fs::write(jl.path().join("extra.jsonl"), format!("{LINE}\n")).unwrap();
        let c = rag_canary_with_manifest(true, jl.path(), &m);
        let why = c.refusal().expect("refused");
        assert!(
            why.contains("integrity check") && why.contains("extra.jsonl"),
            "{why}"
        );
    }

    /// External audit XAI-002: an index directory holding a forged marker
    /// and an index built elsewhere used to be opened as is. It is ignored;
    /// the results come from the verified records.
    #[test]
    fn planted_index_dir_ignored() {
        use crate::rag::index_tantivy::{
            analyzer, build_schema, load_verified_records, source_fingerprint, SEC_ANALYZER,
        };
        let (jl, m) = fixture();
        // The planted index: the same schema, a document under the same id
        // with another title, and the marker the old open path trusted,
        // holding the fingerprint of the genuine records.
        let planted = tempfile::tempdir().unwrap();
        let (schema, f) = build_schema();
        let index = tantivy::Index::create_in_dir(planted.path(), schema).unwrap();
        index.tokenizers().register(SEC_ANALYZER, analyzer());
        let mut w = index.writer(50_000_000).unwrap();
        let mut d = tantivy::TantivyDocument::new();
        for (field, v) in [
            (f.author, ""),
            (f.category, "mitre_technique"),
            (f.content, "zqxjmarker powershell execution"),
            (f.id, "attack:T1059.001"),
            (f.platform, ""),
            (f.severity, ""),
            (f.source_ref, "attack:T1059.001"),
            (f.title, "Planted benign admin tool"),
        ] {
            d.add_text(field, v);
        }
        w.add_document(d).unwrap();
        w.commit().unwrap();
        let genuine =
            load_verified_records(jl.path(), &crate::rag::kb_seed::seed_documents(), &m).unwrap();
        std::fs::write(
            planted.path().join(".nn_kb_source_sha256"),
            source_fingerprint(&genuine),
        )
        .unwrap();

        let vars = [
            (ENABLED_ENV, "1".to_string()),
            (JSONL_DIR_ENV, jl.path().display().to_string()),
            (INDEX_DIR_ENV, planted.path().display().to_string()),
        ];
        let lookup = |k: &str| {
            vars.iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.clone())
        };
        let rag = canary_from_vars(lookup, || Ok(m.clone()))
            .into_engine()
            .expect("verified corpus ⇒ Some");
        let r = rag.retrieve(RagQuery {
            query_text: "zqxjmarker",
            top_k: 3,
            // No floor (`0.0` would mean the default, external audit XAI-008).
            min_similarity: f32::MIN_POSITIVE,
        });
        let titles: Vec<&str> = r.documents.iter().map(|d| d.title.as_str()).collect();
        assert_eq!(titles.first(), Some(&"PowerShell"), "{titles:?}");
        assert!(!titles.iter().any(|t| t.contains("Planted")), "{titles:?}");
        assert_eq!(rag.corpus_fingerprint(), source_fingerprint(&genuine));
    }
}
