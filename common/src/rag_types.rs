//! RAG knowledge-base types (Sub-tappa 6.7).
//!
//! These structs are the serializable surface of the Retrieval-Augmented
//! Generation pipeline shipped in Sub-tappa 6.7. They are kept in
//! `common` (rather than `agent`) so future consumers — CLI tooling,
//! C2 backend, audit log shipper — can deserialize a RAG context
//! bundle without depending on the heavy agent crate.
//!
//! ## Categories
//!
//! [`KbCategory`] partitions the seed knowledge base into five buckets:
//!
//! - `MitreTechnique`  → ATT&CK technique descriptions (T1059.001, …)
//! - `SigmaRule`       → Sigma detection rule excerpts
//! - `Lolbas`          → Living-Off-the-Land binary abuse patterns
//! - `LinuxPattern`    → Linux-specific suspicious behaviour patterns
//! - `ThreatTool`      → Famous post-exploitation tooling profiles
//!
//! The category survives end-to-end into [`KbDocument::category`] and
//! the structured prompt block, so the model can weight evidence by
//! source.
//!
//! ## Embedding dimension
//!
//! [`KB_EMBEDDING_DIM`] is the vector dimension used by the seed
//! knowledge base. Sub-tappa 6.7 ships a 384-dimensional hashed
//! n-gram embedder as a stand-in for a future bge-small-en-v1.5
//! candle backend; both produce 384-dim vectors so the store stays
//! stable across backend swaps.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Vector dimension of every embedding stored in the knowledge base.
///
/// Matches `bge-small-en-v1.5` so the store layout survives a future
/// switch from the hashed n-gram stand-in to a real BERT backend.
pub const KB_EMBEDDING_DIM: usize = 384;

/// Coarse category attached to every [`KbDocument`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KbCategory {
    MitreTechnique,
    SigmaRule,
    Lolbas,
    LinuxPattern,
    ThreatTool,
}

impl KbCategory {
    /// Stable string id used in prompts and serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            KbCategory::MitreTechnique => "mitre_technique",
            KbCategory::SigmaRule => "sigma_rule",
            KbCategory::Lolbas => "lolbas",
            KbCategory::LinuxPattern => "linux_pattern",
            KbCategory::ThreatTool => "threat_tool",
        }
    }
}

impl core::fmt::Display for KbCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One curated knowledge-base entry.
///
/// `id` is a stable handle (`mitre_t1059_001`, `tool_cobaltstrike`, …)
/// suitable for citing in verdicts and audit logs. `tags` is a flat
/// keyword list useful for downstream filtering and explainability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KbDocument {
    pub id: String,
    pub category: KbCategory,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
}

/// A retrieval result: one [`KbDocument`] plus its similarity score
/// against the query.
///
/// `similarity` semantics depend on the active `RagEngine` backend;
/// the field, type and range (`[0.0, 1.0]`) are stable either way
/// (no struct change — C2/CLI deserialize charter):
/// * **6.7 embedding path** — cosine similarity on L2-normalized
///   vectors (theoretically `[-1.0, 1.0]`; the bag-of-grams seed is
///   non-negative so in practice `[0.0, 1.0]`).
/// * **6.9.7 BM25 path** — the raw BM25 score (unbounded ≥ 0)
///   **normalised within the result**: `score / max_score_in_result`,
///   so the top hit is exactly `1.0` and the rest are proportionally
///   lower (plan §3.4(a)). It is a *within-result* ranking signal,
///   not an absolute cross-query magnitude.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RagDocument {
    pub id: String,
    pub category: KbCategory,
    pub title: String,
    pub content: String,
    pub similarity: f32,
}

impl RagDocument {
    pub fn from_doc(doc: &KbDocument, similarity: f32) -> Self {
        Self {
            id: doc.id.clone(),
            category: doc.category,
            title: doc.title.clone(),
            content: doc.content.clone(),
            similarity,
        }
    }
}

/// Result envelope returned by the RAG retrieve API.
///
/// Latency fields are in milliseconds; we keep them on the result
/// itself (rather than logging them inside the engine) so callers can
/// surface them in higher-level traces — ADE attaches them to the
/// verdict metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RagResult {
    pub documents: Vec<RagDocument>,
    pub query_embedding_ms: u64,
    pub retrieval_ms: u64,
}

impl RagResult {
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}
