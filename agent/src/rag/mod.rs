//! Retrieval-Augmented Generation (RAG) pipeline for ADE
//! (Sub-tappa 6.7).
//!
//! ADE's base model is frozen at training time and does not know
//! about post-cutoff CVEs, IoCs, MITRE technique additions, or new
//! threat tooling. This module ships a lightweight RAG layer so the
//! agent can recall recent cyber-threat knowledge from a curated,
//! local knowledge base and inject it into the structured prompt
//! **before** inference, biasing the verdict toward evidence rather
//! than vibes.
//!
//! ## Sub-tappa 6.7 scope (MINIMAL)
//!
//! The goal here is the architecture, not the corpus:
//!
//! - 30 hand-curated documents covering 5 categories (MITRE
//!   technique, Sigma rule, LOLBAS, Linux pattern, threat tool).
//! - In-memory vector store with cosine similarity over L2-
//!   normalized 384-dim vectors.
//! - Hashed-character-n-gram embedder as a stand-in for a future
//!   bge-small-en-v1.5 candle backend (see [`embedder`]).
//!
//! Wiring into ADE happens in `ade::structured_prompt`, which gains
//! a `=== RELEVANT CYBERSEC KNOWLEDGE ===` block surfacing the top-k
//! retrievals.
//!
//! ## Sub-tappa 6.9.7 — production path (CURRENT)
//!
//! 6.7's 30-doc hashed-n-gram embedding store is the **legacy /
//! transition** path. The production path is the deterministic BM25
//! index ([`index_tantivy`]) over the pinned canonical KB (MITRE
//! ATT&CK v18.1 + SigmaHQ Linux, acquired by `cargo xtask rag-kb`)
//! **plus** the retained 6.7 [`kb_seed`] notes. The swap is behind the
//! unchanged [`RagEngine`] / [`RagQuery`] / `RagResult` API (plan §0):
//! [`RagEngine::with_seed`] = legacy embedding; [`RagEngine::open_index`]
//! = BM25. `rag: None` still reproduces pre-6.7 behaviour byte-for-byte
//! (canary-parity guarantee).
//!
//! ## Future deltas
//!
//! - §7 hybrid seam: re-introduce a candle bge-small embedding
//!   re-rank *over* BM25 candidates (the embedder/store stay dormant,
//!   `RagResult.query_embedding_ms` reserved for it).
//! - LOLBAS is intentionally absent (GPL-3.0 — plan §4.2.3); GTFOBins
//!   is a post-beta corpus-extension research task.

pub mod bench;
pub mod canary;
pub mod embedder;
pub mod index_tantivy;
pub mod kb_seed;
pub mod retrieval;
pub mod store;

pub use bench::{golden_cases, run_bench, run_golden, BenchReport, GoldenReport, LatencyStats};
pub use canary::{env_rag_enabled, env_truthy, open_index_from_env, rag_canary};
pub use embedder::{cosine_similarity, RagEmbedder};
pub use index_tantivy::{
    analyze, bm25_query, bm25_search, build_index, load_records, open_or_build,
    source_fingerprint, Bm25Hit, CanonLine, SEC_ANALYZER,
};
pub use retrieval::{RagEngine, RagQuery, DEFAULT_MIN_SIMILARITY, DEFAULT_TOP_K};
pub use store::{RagStore, StoreHit};

#[cfg(test)]
mod tests;
