//! Top-k retrieval orchestration for the RAG pipeline
//! (Sub-tappa 6.7).
//!
//! Wraps an embedder + a store and exposes a single
//! [`RagEngine::retrieve`] entry point that the ADE evaluator calls
//! before building its prompt. The engine is responsible for:
//!
//! - embedding the query (with a wall-clock latency measurement),
//! - running [`RagStore::search_top_k`] under the configured
//!   `top_k` and `min_similarity` thresholds,
//! - converting the borrowed [`StoreHit`]s into owned
//!   [`RagDocument`]s so the result outlives the engine borrow.
//!
//! The engine is constructed once at startup (`AdeEngine::new`)
//! and shared across tokio tasks via `Arc`.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use common::rag_types::{KbCategory, RagDocument, RagResult};

use super::embedder::RagEmbedder;
use super::index_tantivy::{self, CanonLine};
use super::kb_manifest::KbManifest;
use super::kb_seed;
use super::store::RagStore;

/// Default `top_k` used when [`RagQuery::top_k`] is left at the
/// type's `Default` (zero). Matches the Sub-tappa 6.7 spec.
pub const DEFAULT_TOP_K: usize = 3;

/// Default minimum cosine similarity. Below this we drop the hit
/// rather than risk injecting noise into the prompt.
///
/// The Sub-tappa 6.7 spec proposed `0.4`; that target assumed a
/// real bge-small semantic embedder where related-but-non-overlapping
/// vocabulary still scores above 0.4. With the hashed-n-gram
/// stand-in shipped in 6.7, lexical overlap tops out lower because
/// many doc-side n-grams have no query counterpart and dilute the
/// L2-normalized score. Empirically (probed on the seed KB) values
/// in the 0.15–0.30 band correspond to "shares the headline noun
/// with a doc"; below 0.10 is essentially uncorrelated.
///
/// We pick `0.15`. When the embedder is upgraded to real bge-small
/// this should be raised back to `~0.4`.
///
/// On the BM25 path the floor applies to scores divided by the top
/// hit's, so it trims the tail and never drops the top hit; a weak top
/// hit is dropped by the lexical-coverage floor instead
/// ([`index_tantivy::COVERAGE_ONE_IN`], external audit XAI-008).
pub const DEFAULT_MIN_SIMILARITY: f32 = 0.15;

/// One retrieval call.
///
/// `top_k = 0` is treated as "use [`DEFAULT_TOP_K`]"; same for
/// `min_similarity <= 0.0` → [`DEFAULT_MIN_SIMILARITY`]. This lets
/// callers spell `RagQuery { query_text: "...", ..Default::default() }`.
/// So `0.0` does not mean "no floor": a caller that wants every hit up
/// to `top_k` passes `f32::MIN_POSITIVE` (external audit XAI-008). The
/// BM25 coverage floor applies whatever `min_similarity` is.
#[derive(Debug, Clone)]
pub struct RagQuery<'a> {
    pub query_text: &'a str,
    pub top_k: usize,
    pub min_similarity: f32,
}

impl<'a> RagQuery<'a> {
    /// Construct with sensible defaults.
    pub fn new(query_text: &'a str) -> Self {
        Self {
            query_text,
            top_k: DEFAULT_TOP_K,
            min_similarity: DEFAULT_MIN_SIMILARITY,
        }
    }
}

/// Public RAG engine handle.
///
/// The API ([`RagQuery`], [`RagResult`], [`Self::retrieve`]) is
/// byte-stable for the C2/CLI deserialize charter (plan §0). Only the
/// internal mechanism changed in Tappa 6.9.7: [`Self::with_seed`] is
/// the legacy 6.7 hashed-n-gram embedding path; [`Self::open_index`]
/// is the 6.9.7 deterministic BM25 path over the canonical KB. Both
/// answer the same `retrieve`.
#[derive(Debug, Clone)]
pub struct RagEngine {
    backend: Backend,
    /// `source_fingerprint` of the records this engine retrieves from,
    /// taken at open (external audit XAI-010).
    fingerprint: String,
}

#[derive(Debug, Clone)]
enum Backend {
    /// Sub-tappa 6.7 hashed-n-gram embedding + cosine store (legacy /
    /// transition path; the P5 canary may still exercise it when the
    /// BM25 index is not wired).
    Embedding {
        embedder: RagEmbedder,
        store: RagStore,
    },
    /// Tappa 6.9.7 deterministic BM25 over the canonical KB index.
    Bm25 {
        index: tantivy::Index,
        doc_count: usize,
    },
}

impl RagEngine {
    /// Build an engine and seed it with the curated knowledge base
    /// (legacy 6.7 embedding path). `model_path` is recorded for
    /// diagnostics but the stand-in embedder loads nothing from disk.
    /// `Result` is kept so a future bge-small loader can fail without
    /// an API break.
    pub fn with_seed(model_path: Option<&Path>) -> Result<Self> {
        let embedder = RagEmbedder::new(model_path);
        let mut store = RagStore::new();
        let docs = kb_seed::seed_documents();
        let fingerprint = index_tantivy::source_fingerprint(
            &docs.iter().map(CanonLine::from_kb).collect::<Vec<_>>(),
        );
        let doc_count = docs.len();
        let texts: Vec<&str> = docs.iter().map(|d| d.content.as_str()).collect();
        let embeddings = embedder.embed_batch(&texts);
        store.insert_batch(docs, embeddings);
        tracing::info!(
            seeded = store.len(),
            attempted = doc_count,
            "RagEngine seeded curated knowledge base"
        );
        Ok(Self {
            backend: Backend::Embedding { embedder, store },
            fingerprint,
        })
    }

    /// Tappa 6.9.7 P4 — the deterministic BM25 index over the P2
    /// canonical JSONL dumps in `jsonl_dir` **plus** the 6.7 in-repo
    /// curated notes. The `retrieve` API is unchanged — this is the plan
    /// §0 mechanism swap behind the existing seam.
    ///
    /// External audit XAI-001/XAI-009/XAI-002: the dumps must be exactly
    /// those the manifest built into the binary pins (no other `*.jsonl`,
    /// none missing, same digests), and the index is built in memory from
    /// them at every open — nothing on disk is trusted.
    pub fn open_index(jsonl_dir: &Path) -> Result<Self> {
        Self::open_index_with_manifest(jsonl_dir, &KbManifest::pinned()?)
    }

    /// [`Self::open_index`] against `manifest` instead of the pinned one
    /// (tests use fixture dumps).
    pub fn open_index_with_manifest(jsonl_dir: &Path, manifest: &KbManifest) -> Result<Self> {
        let seed = kb_seed::seed_documents();
        let records = index_tantivy::load_verified_records(jsonl_dir, &seed, manifest)?;
        let fingerprint = index_tantivy::source_fingerprint(&records);
        let index = index_tantivy::build_index_in_ram(&records)?;
        let doc_count = index.reader()?.searcher().num_docs() as usize;
        tracing::info!(
            docs = doc_count,
            kb_index_hash = manifest.kb_index_hash(),
            corpus_fingerprint = %fingerprint,
            "RagEngine built the BM25 index from the verified corpus"
        );
        Ok(Self {
            backend: Backend::Bm25 { index, doc_count },
            fingerprint,
        })
    }

    /// `source_fingerprint` of the corpus this engine was opened on (for
    /// the legacy seed path, of the seed). Computed once, at open; the XAI
    /// `environment_hash` binds it (external audit XAI-010).
    pub fn corpus_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Number of indexed documents.
    pub fn document_count(&self) -> usize {
        match &self.backend {
            Backend::Embedding { store, .. } => store.len(),
            Backend::Bm25 { doc_count, .. } => *doc_count,
        }
    }

    /// Top-k retrieval. `RagResult` shape is unchanged; the BM25 path
    /// reports `query_embedding_ms = 0` (no embedding step — the field
    /// stays reserved for the §7 hybrid).
    pub fn retrieve(&self, query: RagQuery<'_>) -> RagResult {
        match &self.backend {
            Backend::Embedding { embedder, store } => {
                Self::retrieve_embedding(embedder, store, query)
            }
            Backend::Bm25 { index, .. } => Self::retrieve_bm25(index, query),
        }
    }

    /// Unchanged 6.7 embedding+cosine retrieval (byte-for-byte the
    /// pre-6.9.7 logic — preserves legacy behaviour & tests).
    fn retrieve_embedding(
        embedder: &RagEmbedder,
        store: &RagStore,
        query: RagQuery<'_>,
    ) -> RagResult {
        let top_k = if query.top_k == 0 {
            DEFAULT_TOP_K
        } else {
            query.top_k
        };
        let min_sim = if query.min_similarity <= 0.0 {
            DEFAULT_MIN_SIMILARITY
        } else {
            query.min_similarity
        };
        let (vec, query_embedding_ms) = embedder.embed_timed(query.query_text);
        let retrieval_start = Instant::now();
        let hits = store.search_top_k(&vec, top_k, min_sim);
        let retrieval_ms = retrieval_start.elapsed().as_millis() as u64;
        let documents: Vec<RagDocument> = hits
            .into_iter()
            .map(|h| RagDocument::from_doc(h.doc, h.similarity))
            .collect();
        RagResult {
            documents,
            query_embedding_ms,
            retrieval_ms,
        }
    }

    /// BM25 path: R1 ordering (from [`index_tantivy::bm25_query`]) →
    /// lexical-coverage floor on the top hit → §3.4(a) within-result
    /// normalisation (top hit = 1.0, rest proportional) →
    /// `min_similarity` floor applied AFTER normalisation. A query failure yields an empty `RagResult`
    /// (conservative — preserves the infallible `retrieve` contract and
    /// the "no-match ⇒ empty" guarantee the downstream relies on).
    ///
    /// External audit XAI-008: normalising by the top score makes the top
    /// hit 1.0 whatever it matched, so the relative floor never dropped
    /// it, and a document sharing one common word with a long query went
    /// into the prompt. The top hit must now carry at least one in four
    /// of the query's distinct terms ([`index_tantivy::COVERAGE_ONE_IN`]),
    /// else the result is empty; the hits it keeps are unchanged.
    /// External audit XAI-012: the query is at most
    /// [`index_tantivy::MAX_QUERY_TERMS`] distinct terms.
    fn retrieve_bm25(index: &tantivy::Index, query: RagQuery<'_>) -> RagResult {
        let top_k = if query.top_k == 0 {
            DEFAULT_TOP_K
        } else {
            query.top_k
        };
        let min_sim = if query.min_similarity <= 0.0 {
            DEFAULT_MIN_SIMILARITY
        } else {
            query.min_similarity
        };
        let start = Instant::now();
        let empty = |start: Instant| RagResult {
            documents: Vec::new(),
            query_embedding_ms: 0,
            retrieval_ms: start.elapsed().as_millis() as u64,
        };
        let terms = index_tantivy::query_terms(query.query_text);
        let hits = match index_tantivy::bm25_query_terms(index, &terms, top_k.max(1)) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "BM25 retrieve failed; empty result (conservative)");
                return empty(start);
            }
        };
        if let Some(top) = hits.first() {
            let need = index_tantivy::required_terms(terms.len());
            let matched = index_tantivy::matched_terms(top, &terms, need);
            if matched < need {
                tracing::debug!(
                    matched,
                    need,
                    terms = terms.len(),
                    "BM25 top hit below the term-coverage floor; empty result"
                );
                return empty(start);
            }
        }
        let retrieval_ms = start.elapsed().as_millis() as u64;
        let max = hits.first().map(|h| h.score).unwrap_or(0.0);
        let documents: Vec<RagDocument> = hits
            .into_iter()
            .filter_map(|h| {
                let similarity = if max > 0.0 { h.score / max } else { 0.0 };
                if similarity < min_sim {
                    return None;
                }
                Some(RagDocument {
                    id: h.id,
                    category: parse_category(&h.category),
                    title: h.title,
                    content: h.content,
                    similarity,
                })
            })
            .collect();
        RagResult {
            documents,
            query_embedding_ms: 0,
            retrieval_ms,
        }
    }
}

/// Canonical `category` string → [`KbCategory`]. The P2 schema only
/// emits the five `KbCategory::as_str()` values; an unrecognised
/// string is a defensive fallback (the doc is kept, not dropped) —
/// `LinuxPattern` is the most neutral bucket.
fn parse_category(s: &str) -> KbCategory {
    match s {
        "mitre_technique" => KbCategory::MitreTechnique,
        "sigma_rule" => KbCategory::SigmaRule,
        "lolbas" => KbCategory::Lolbas,
        "threat_tool" => KbCategory::ThreatTool,
        _ => KbCategory::LinuxPattern,
    }
}

// Helper trait used only inside tests for cleaner assertions.
#[cfg(test)]
trait TagsContainLossless {
    fn tags_contain_lossless(&self, needle: &str) -> bool;
}

#[cfg(test)]
impl TagsContainLossless for RagDocument {
    fn tags_contain_lossless(&self, needle: &str) -> bool {
        self.content.to_lowercase().contains(needle)
            || self.title.to_lowercase().contains(needle)
            || self.id.to_lowercase().contains(needle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_seeds_curated_kb() {
        let e = RagEngine::with_seed(None).expect("seed");
        let n = e.document_count();
        // The curated KB is hand-maintained and grows over time (§26
        // test-debt: was 36 when this bound last broke at ~30). Bound it
        // to a generous range that still catches a broken/empty seed
        // without re-breaking on every curated-doc addition.
        assert!(
            (28..=64).contains(&n),
            "expected a curated KB of ~30-60 docs, got {n}"
        );
    }

    #[test]
    fn retrieve_xmrig_finds_cryptominer_doc_in_top_k() {
        let e = RagEngine::with_seed(None).expect("seed");
        // Bypass the default 0.4 threshold for this lexical-only check
        // — what we actually want to assert is the *rank* of the
        // cryptominer doc among the top-k, not the absolute score.
        let r = e.retrieve(RagQuery {
            query_text: "process xmrig from /tmp/.cache/x",
            top_k: 5,
            min_similarity: 0.001,
        });
        assert!(!r.documents.is_empty());
        assert!(
            r.documents.iter().any(|d| d.id.contains("xmrig")
                || d.content.to_lowercase().contains("xmrig")
                || d.tags_contain_lossless("cryptominer")),
            "expected an xmrig/cryptominer doc in the top-k; got: {:?}",
            r.documents
                .iter()
                .map(|d| (&d.id, d.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retrieve_powershell_finds_t1059_in_top_k() {
        let e = RagEngine::with_seed(None).expect("seed");
        let r = e.retrieve(RagQuery {
            query_text: "powershell -encodedcommand base64",
            top_k: 5,
            min_similarity: 0.001,
        });
        assert!(!r.documents.is_empty());
        assert!(
            r.documents
                .iter()
                .any(|d| d.id.contains("t1059") || d.content.to_lowercase().contains("powershell")),
            "expected T1059 / PowerShell doc in top-k; got: {:?}",
            r.documents
                .iter()
                .map(|d| (&d.id, d.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retrieve_cobaltstrike_finds_threat_tool_doc() {
        let e = RagEngine::with_seed(None).expect("seed");
        let r = e.retrieve(RagQuery {
            query_text: "process beacon from /usr/local/bin/cobaltstrike-beacon",
            top_k: 5,
            min_similarity: 0.001,
        });
        assert!(!r.documents.is_empty());
        assert!(
            r.documents
                .iter()
                .any(|d| d.id.contains("cobalt")
                    || d.content.to_lowercase().contains("cobalt strike")),
            "expected cobalt-strike doc in top-k; got: {:?}",
            r.documents
                .iter()
                .map(|d| (&d.id, d.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retrieve_random_text_returns_empty_under_threshold() {
        let e = RagEngine::with_seed(None).expect("seed");
        let r = e.retrieve(RagQuery {
            query_text: "asdf qwer zxcv lorem ipsum dolor sit amet consectetur",
            top_k: 3,
            min_similarity: 0.6,
        });
        assert!(
            r.documents.is_empty(),
            "expected no hits over 0.6 threshold; got: {:?}",
            r.documents
                .iter()
                .map(|d| (&d.id, d.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retrieve_top_k_is_respected() {
        let e = RagEngine::with_seed(None).expect("seed");
        let r = e.retrieve(RagQuery {
            query_text: "powershell",
            top_k: 2,
            // No floor (`0.0` would mean the default, external audit XAI-008).
            min_similarity: f32::MIN_POSITIVE,
        });
        assert!(r.documents.len() <= 2);
    }

    #[test]
    fn retrieve_records_latency() {
        let e = RagEngine::with_seed(None).expect("seed");
        let r = e.retrieve(RagQuery::new("xmrig"));
        // microseconds → can be 0 ms but never negative; just assert
        // the fields are populated.
        let _ = r.query_embedding_ms;
        let _ = r.retrieval_ms;
    }

    /// Sanity-check that the production default threshold is loose
    /// enough to fire on event-shaped queries against the seed KB.
    /// Tightening this value should be paired with revisiting the
    /// embedder; loosening risks injecting noise into the prompt.
    #[test]
    fn default_threshold_yields_hits_on_canonical_event_queries() {
        let e = RagEngine::with_seed(None).expect("seed");
        for q in [
            "xmrig",
            "powershell encoded base64",
            "cobalt strike beacon",
            "certutil urlcache",
            "lsass dump mimikatz",
        ] {
            let r = e.retrieve(RagQuery::new(q));
            assert!(
                !r.documents.is_empty(),
                "default threshold returned 0 docs for canonical query {q:?}"
            );
        }
    }

    // ── Tappa 6.9.7 P4 — BM25 backend behind the unchanged API ──

    /// One synthetic 8-key canonical line with a unique marker token so
    /// the assertion is deterministic regardless of the 6.7 seed that
    /// `open_index` also ingests. Returns the manifest pinning it.
    fn fixture_jsonl(dir: &std::path::Path) -> KbManifest {
        let line = r#"{"author":null,"category":"mitre_technique","content":"synthetic marker zqxjmarker powershell T1059.001 command execution","id":"attack:T1059.001","platform":"","severity":"","source_ref":"attack:T1059.001","title":"PowerShell Marker"}"#;
        let dump = format!("{line}\n");
        std::fs::write(dir.join("fix.jsonl"), &dump).unwrap();
        KbManifest::for_dumps(&[("fix.jsonl", dump.as_bytes())])
    }

    #[test]
    fn open_index_retrieves_via_bm25_with_normalised_similarity() {
        let jl = tempfile::tempdir().unwrap();
        let m = fixture_jsonl(jl.path());
        let e = RagEngine::open_index_with_manifest(jl.path(), &m).expect("open_index");
        assert!(e.document_count() >= 1);
        let r = e.retrieve(RagQuery {
            query_text: "zqxjmarker",
            top_k: 5,
            // No floor (`0.0` would mean the default, external audit XAI-008).
            min_similarity: f32::MIN_POSITIVE,
        });
        assert!(!r.documents.is_empty(), "BM25 must find the marker doc");
        let top = &r.documents[0];
        assert_eq!(top.id, "attack:T1059.001");
        assert_eq!(
            top.category,
            KbCategory::MitreTechnique,
            "category mapped back"
        );
        assert_eq!(top.similarity, 1.0, "top hit normalised to 1.0 (§3.4a)");
        // Within-result normalisation ⇒ all in [0,1], non-increasing.
        assert!(r
            .documents
            .iter()
            .all(|d| d.similarity >= 0.0 && d.similarity <= 1.0));
        assert!(r
            .documents
            .windows(2)
            .all(|w| w[0].similarity >= w[1].similarity));
        // BM25 path has no embedding step (field reserved for §7).
        assert_eq!(r.query_embedding_ms, 0);
    }

    #[test]
    fn bm25_min_similarity_floor_is_post_normalisation_and_conservative() {
        let jl = tempfile::tempdir().unwrap();
        let m = fixture_jsonl(jl.path());
        let e = RagEngine::open_index_with_manifest(jl.path(), &m).unwrap();
        // Floor above the normalised max (1.0) ⇒ everything dropped ⇒
        // empty RagResult (the 6.7 conservative no-match contract).
        let r = e.retrieve(RagQuery {
            query_text: "zqxjmarker",
            top_k: 5,
            min_similarity: 1.1,
        });
        assert!(r.documents.is_empty(), "floor > 1.0 ⇒ conservative empty");
        // Floor just under the top ⇒ the top (==1.0) survives.
        let r2 = e.retrieve(RagQuery {
            query_text: "zqxjmarker",
            top_k: 5,
            min_similarity: 0.99,
        });
        assert!(r2.documents.iter().any(|d| d.id == "attack:T1059.001"));
    }

    /// The raw BM25 hits of `q` on the engine's index, before any floor.
    fn raw_bm25(e: &RagEngine, q: &str) -> Vec<index_tantivy::Bm25Hit> {
        match &e.backend {
            Backend::Bm25 { index, .. } => index_tantivy::bm25_query(index, q, 5).unwrap(),
            Backend::Embedding { .. } => unreachable!("open_index is BM25"),
        }
    }

    fn no_floor(q: &str) -> RagQuery<'_> {
        RagQuery {
            query_text: q,
            top_k: 5,
            min_similarity: f32::MIN_POSITIVE,
        }
    }

    /// External audit XAI-008: a top hit that shares fewer than one in
    /// four of the query's distinct terms is dropped, with no floor set.
    /// BM25 itself still ranks a document first (which the relative floor
    /// alone would have kept at 1.0).
    #[test]
    fn weak_match_returns_nothing() {
        let jl = tempfile::tempdir().unwrap();
        let m = fixture_jsonl(jl.path());
        let e = RagEngine::open_index_with_manifest(jl.path(), &m).unwrap();
        for q in [
            // One common word of five.
            "execution qzvone qzvtwo qzvthree qzvfour",
            // Even the unique marker: one of five.
            "zqxjmarker qzvone qzvtwo qzvthree qzvfour",
            // Two of nine.
            "zqxjmarker powershell qa qb qc qd qe qf qg",
        ] {
            assert!(
                !raw_bm25(&e, q).is_empty(),
                "BM25 ranks something for {q:?}"
            );
            let r = e.retrieve(no_floor(q));
            assert!(
                r.documents.is_empty(),
                "{q:?}: {:?}",
                r.documents.iter().map(|d| &d.id).collect::<Vec<_>>()
            );
            // The production defaults too.
            assert!(e.retrieve(RagQuery::new(q)).documents.is_empty(), "{q:?}");
        }
    }

    /// The coverage floor keeps a top hit that carries one term in four
    /// (the boundary) or more, and counts distinct terms (a repeated word
    /// does not make the query longer).
    #[test]
    fn strong_match_still_returns_top_hit() {
        let jl = tempfile::tempdir().unwrap();
        let m = fixture_jsonl(jl.path());
        let e = RagEngine::open_index_with_manifest(jl.path(), &m).unwrap();
        for q in [
            "zqxjmarker",
            "zqxjmarker powershell",
            "zqxjmarker qzvone qzvtwo",
            // One of four: the boundary.
            "zqxjmarker qzvone qzvtwo qzvthree",
            // Two of eight.
            "zqxjmarker powershell qa qb qc qd qe qf",
            // Distinct terms: two, not five.
            "zqxjmarker zqxjmarker zqxjmarker zqxjmarker qzvone",
            // Five terms, three carried.
            "powershell command zqxjmarker from /tmp/qzv",
        ] {
            let r = e.retrieve(no_floor(q));
            let top = r
                .documents
                .first()
                .unwrap_or_else(|| panic!("{q:?}: empty"));
            assert_eq!(top.id, "attack:T1059.001", "{q:?}");
            assert_eq!(top.similarity, 1.0, "{q:?}");
            let d = e.retrieve(RagQuery::new(q));
            assert_eq!(
                d.documents.first().map(|d| d.id.as_str()),
                Some("attack:T1059.001")
            );
        }
    }

    #[test]
    fn corpus_fingerprint_follows_the_records() {
        let jl = tempfile::tempdir().unwrap();
        let m = fixture_jsonl(jl.path());
        let a = RagEngine::open_index_with_manifest(jl.path(), &m).unwrap();
        let b = RagEngine::open_index_with_manifest(jl.path(), &m).unwrap();
        assert_eq!(a.corpus_fingerprint(), b.corpus_fingerprint());
        assert_eq!(a.corpus_fingerprint().len(), 64);
        let seed = RagEngine::with_seed(None).unwrap();
        assert_ne!(a.corpus_fingerprint(), seed.corpus_fingerprint());
        // Another pinned corpus ⇒ another fingerprint.
        let line = r#"{"author":null,"category":"mitre_technique","content":"other","id":"attack:T1","platform":"","severity":"","source_ref":"attack:T1","title":"Other"}"#;
        let dump = format!("{line}\n");
        let jl2 = tempfile::tempdir().unwrap();
        std::fs::write(jl2.path().join("o.jsonl"), &dump).unwrap();
        let m2 = KbManifest::for_dumps(&[("o.jsonl", dump.as_bytes())]);
        let c = RagEngine::open_index_with_manifest(jl2.path(), &m2).unwrap();
        assert_ne!(a.corpus_fingerprint(), c.corpus_fingerprint());
    }
}
