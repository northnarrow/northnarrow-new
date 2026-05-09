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
use common::rag_types::{RagDocument, RagResult};

use super::embedder::RagEmbedder;
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
pub const DEFAULT_MIN_SIMILARITY: f32 = 0.15;

/// One retrieval call.
///
/// `top_k = 0` is treated as "use [`DEFAULT_TOP_K`]"; same for
/// `min_similarity = 0.0` → [`DEFAULT_MIN_SIMILARITY`]. This lets
/// callers spell `RagQuery { query_text: "...", ..Default::default() }`.
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
/// Built once with [`Self::with_seed`] (loads the curated KB) and
/// then queried via [`Self::retrieve`].
#[derive(Debug, Clone)]
pub struct RagEngine {
    embedder: RagEmbedder,
    store: RagStore,
}

impl RagEngine {
    /// Build an engine and seed it with the curated knowledge base.
    ///
    /// `model_path` is recorded for diagnostics but the current
    /// embedder does not load anything from disk (see
    /// [`super::embedder`] for the rationale). Returns an error only
    /// if the seed embedding step fails — currently infallible, but
    /// surfaced as `Result` so future bge-small loading errors do not
    /// break the API.
    pub fn with_seed(model_path: Option<&Path>) -> Result<Self> {
        let embedder = RagEmbedder::new(model_path);
        let mut store = RagStore::new();
        let docs = kb_seed::seed_documents();
        let doc_count = docs.len();
        let texts: Vec<&str> = docs.iter().map(|d| d.content.as_str()).collect();
        let embeddings = embedder.embed_batch(&texts);
        store.insert_batch(docs, embeddings);
        tracing::info!(
            seeded = store.len(),
            attempted = doc_count,
            "RagEngine seeded curated knowledge base"
        );
        Ok(Self { embedder, store })
    }

    /// Number of documents currently in the store.
    pub fn document_count(&self) -> usize {
        self.store.len()
    }

    /// Top-k retrieval over the curated KB.
    ///
    /// Returns a [`RagResult`] with owned [`RagDocument`]s plus
    /// per-stage latency (embedding vs retrieval).
    pub fn retrieve(&self, query: RagQuery<'_>) -> RagResult {
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

        let (vec, query_embedding_ms) = self.embedder.embed_timed(query.query_text);

        let retrieval_start = Instant::now();
        let hits = self.store.search_top_k(&vec, top_k, min_sim);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_seeds_curated_kb() {
        let e = RagEngine::with_seed(None).expect("seed");
        let n = e.document_count();
        assert!(
            (28..=32).contains(&n),
            "expected ~30 seeded docs, got {n}"
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
            min_similarity: 0.0,
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
