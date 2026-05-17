//! Tappa 6.9.7 P5 — env-driven RAG canary (default OFF, beta-safe).
//!
//! The ADE↔RAG seam already exists from 6.7 (`AdeEngine::with_rag`).
//! P5 only decides, from the environment, whether to wire a BM25
//! `RagEngine` into the single production `AdeEngine` (main.rs), with a
//! graceful no-RAG fallback so the §13 canary-parity guarantee holds
//! even when RAG is requested but the index cannot be opened.
//!
//! Split: [`env_truthy`] / [`rag_canary`] are pure (no global env —
//! race-free unit tests); [`open_index_from_env`] is the thin glue
//! main.rs calls.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use super::retrieval::RagEngine;

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
    std::env::var("NN_ADE_RAG_ENABLED")
        .map(|v| env_truthy(&v))
        .unwrap_or(false)
}

fn env_path(key: &str, default: &str) -> PathBuf {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

/// Pure canary decision (no env read — testable without global state):
/// `enabled=false` ⇒ `None` (canary-parity path); `enabled=true` ⇒
/// open/lazy-build the BM25 index, returning `Some` on success or
/// `None` on failure (graceful degradation — the no-RAG path is the
/// safety net, so RAG-off XAI determinism is never broken by a bad
/// index dir). Logs at each branch.
pub fn rag_canary(enabled: bool, jsonl_dir: &Path, index_dir: &Path) -> Option<RagEngine> {
    if !enabled {
        info!("RAG disabled (NN_ADE_RAG_ENABLED off/unset) — canary-parity path (rag: None)");
        return None;
    }
    match RagEngine::open_index(jsonl_dir, index_dir) {
        Ok(rag) => {
            info!(
                docs = rag.document_count(),
                jsonl_dir = %jsonl_dir.display(),
                index_dir = %index_dir.display(),
                "RAG enabled"
            );
            Some(rag)
        }
        Err(e) => {
            warn!(
                error = %e,
                jsonl_dir = %jsonl_dir.display(),
                index_dir = %index_dir.display(),
                "RAG construction failed — falling back to no-rag path (canary parity preserved)"
            );
            None
        }
    }
}

/// Env glue main.rs calls in the single `AdeEngine` construction site.
/// `NN_ADE_RAG_JSONL_DIR` (default `/var/lib/northnarrow/rag/jsonl`)
/// and `NN_ADE_RAG_INDEX_DIR` (default `/var/lib/northnarrow/rag/index`).
pub fn open_index_from_env() -> Option<RagEngine> {
    let jsonl = env_path("NN_ADE_RAG_JSONL_DIR", "/var/lib/northnarrow/rag/jsonl");
    let index = env_path("NN_ADE_RAG_INDEX_DIR", "/var/lib/northnarrow/rag/index");
    rag_canary(env_rag_enabled(), &jsonl, &index)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(rag_canary(false, Path::new("/nonexistent"), Path::new("/nonexistent")).is_none());
    }

    #[test]
    fn canary_on_with_unopenable_index_falls_back_gracefully() {
        // index_dir whose parent is a regular file ⇒ create_dir_all
        // fails ⇒ open_index Err ⇒ graceful None (no panic).
        let f = tempfile::NamedTempFile::new().unwrap();
        let bad_index = f.path().join("idx"); // parent is a file ⇒ ENOTDIR
        let jl = tempfile::tempdir().unwrap();
        assert!(
            rag_canary(true, jl.path(), &bad_index).is_none(),
            "unopenable index must degrade to None, not panic"
        );
    }

    #[test]
    fn canary_on_with_valid_paths_opens_bm25_engine() {
        let jl = tempfile::tempdir().unwrap();
        std::fs::write(
            jl.path().join("fix.jsonl"),
            "{\"author\":null,\"category\":\"mitre_technique\",\"content\":\"zqxjmarker powershell execution\",\"id\":\"attack:T1059.001\",\"platform\":\"\",\"severity\":\"\",\"source_ref\":\"attack:T1059.001\",\"title\":\"PowerShell\"}\n",
        )
        .unwrap();
        let ix = tempfile::tempdir().unwrap();
        let rag = rag_canary(true, jl.path(), ix.path()).expect("valid paths ⇒ Some");
        assert!(rag.document_count() >= 1);
    }
}
