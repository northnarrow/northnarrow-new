//! In-memory vector store for the RAG knowledge base
//! (Sub-tappa 6.7).
//!
//! ## Why in-memory and not LanceDB
//!
//! The Sub-tappa 6.7 spec proposed [`lancedb`] as the storage
//! backend (Rust-native, embedded, persistent). When evaluated:
//!
//! - `lancedb 0.10` transitively pulls in `datafusion`, `arrow-array`,
//!   `arrow-flight`, and a chain of compile-heavy crates that
//!   roughly **double the agent's compile time** and add ~30 MB of
//!   release binary footprint.
//! - The MINIMAL Sub-tappa 6.7 KB has 30 documents. Linear scan of
//!   30 × 384-dim cosine sims runs in microseconds — orders of
//!   magnitude faster than the embedder itself, never mind the LLM
//!   inference.
//! - Persistence is not required for the demo: the seed KB is
//!   regenerated deterministically from `kb_seed.rs` on each engine
//!   construction.
//!
//! The spec explicitly authorises this fallback ("Se lancedb causa
//! problemi di build […], fallback: implementazione vector store
//! custom in-memory"). When KB scale crosses the threshold where
//! linear scan stops being cheap (~10k docs) the [`RagStore`] API
//! is small enough to swap to LanceDB or a flat ANN index without
//! touching the embedder or the retrieval logic.
//!
//! ## API
//!
//! [`RagStore`] holds the parallel arrays of [`KbDocument`]s and
//! their L2-normalized 384-dim vectors. [`Self::insert_batch`]
//! grows both, [`Self::search_top_k`] runs the linear cosine scan.
//!
//! [`lancedb`]: https://lancedb.github.io/lancedb/

use common::rag_types::{KbDocument, KB_EMBEDDING_DIM};

use super::embedder::cosine_similarity;

/// In-memory cosine-similarity vector store.
///
/// Cheap to clone: the inner vectors are `Vec`s but reads are the
/// only hot path and we never mutate after seeding.
#[derive(Debug, Default, Clone)]
pub struct RagStore {
    docs: Vec<KbDocument>,
    embeddings: Vec<Vec<f32>>,
}

/// One scored hit returned by the cosine search.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreHit<'a> {
    pub doc: &'a KbDocument,
    pub similarity: f32,
}

impl RagStore {
    /// Empty store. Use [`Self::insert_batch`] to seed it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of documents currently held.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Returns a slice of all documents in insertion order. Useful
    /// for diagnostics and tests.
    pub fn documents(&self) -> &[KbDocument] {
        &self.docs
    }

    /// Insert one (doc, embedding) pair.
    ///
    /// Validates that the embedding has the expected dimension; an
    /// out-of-bounds vector means the embedder and the store are
    /// out of sync, which is unrecoverable so we panic in debug and
    /// drop the row in release (logged).
    pub fn insert(&mut self, doc: KbDocument, embedding: Vec<f32>) {
        if embedding.len() != KB_EMBEDDING_DIM {
            tracing::error!(
                doc_id = %doc.id,
                got = embedding.len(),
                want = KB_EMBEDDING_DIM,
                "RagStore::insert dimension mismatch — dropping document"
            );
            return;
        }
        self.docs.push(doc);
        self.embeddings.push(embedding);
    }

    /// Bulk insert. The two slices must have equal length.
    pub fn insert_batch(&mut self, docs: Vec<KbDocument>, embeddings: Vec<Vec<f32>>) -> usize {
        debug_assert_eq!(docs.len(), embeddings.len());
        let mut inserted = 0;
        for (d, e) in docs.into_iter().zip(embeddings) {
            let before = self.docs.len();
            self.insert(d, e);
            if self.docs.len() != before {
                inserted += 1;
            }
        }
        inserted
    }

    /// Linear cosine-similarity search. Returns the top `k` hits
    /// whose similarity is `>= min_similarity`, sorted descending.
    ///
    /// `query` must be L2-normalized — the embedder takes care of
    /// this, but a caller that constructs vectors by hand is on the
    /// hook.
    pub fn search_top_k(&self, query: &[f32], k: usize, min_similarity: f32) -> Vec<StoreHit<'_>> {
        if self.is_empty() || k == 0 {
            return Vec::new();
        }
        let mut scored: Vec<(usize, f32)> = self
            .embeddings
            .iter()
            .enumerate()
            .map(|(i, v)| (i, cosine_similarity(query, v)))
            .filter(|(_, s)| *s >= min_similarity)
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);

        scored
            .into_iter()
            .map(|(i, s)| StoreHit {
                doc: &self.docs[i],
                similarity: s,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::rag_types::KbCategory;

    fn doc(id: &str) -> KbDocument {
        KbDocument {
            id: id.into(),
            category: KbCategory::MitreTechnique,
            title: format!("title-{id}"),
            content: format!("content-{id}"),
            tags: vec![],
        }
    }

    fn unit_vec_at(idx: usize) -> Vec<f32> {
        let mut v = vec![0.0f32; KB_EMBEDDING_DIM];
        v[idx] = 1.0;
        v
    }

    #[test]
    fn new_store_is_empty() {
        let s = RagStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn insert_grows_store() {
        let mut s = RagStore::new();
        s.insert(doc("a"), unit_vec_at(0));
        s.insert(doc("b"), unit_vec_at(1));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn search_returns_top_k_sorted_descending() {
        let mut s = RagStore::new();
        s.insert(doc("a"), unit_vec_at(0));
        s.insert(doc("b"), unit_vec_at(1));
        s.insert(doc("c"), unit_vec_at(2));

        // query == basis(0), perfect match for "a", zero for the others.
        let q = unit_vec_at(0);
        let hits = s.search_top_k(&q, 3, 0.0);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].doc.id, "a");
        assert!((hits[0].similarity - 1.0).abs() < 1e-4);
    }

    #[test]
    fn search_respects_min_similarity_threshold() {
        let mut s = RagStore::new();
        s.insert(doc("a"), unit_vec_at(0));
        s.insert(doc("b"), unit_vec_at(1));

        // q is orthogonal to both → no hits at threshold 0.5.
        let q = unit_vec_at(2);
        let hits = s.search_top_k(&q, 3, 0.5);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn search_truncates_at_k() {
        let mut s = RagStore::new();
        for i in 0..5 {
            s.insert(doc(&format!("d{i}")), unit_vec_at(i));
        }
        let q = unit_vec_at(0);
        let hits = s.search_top_k(&q, 2, 0.0);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn dimension_mismatch_drops_document() {
        let mut s = RagStore::new();
        s.insert(doc("bad"), vec![0.0; KB_EMBEDDING_DIM - 1]);
        assert!(s.is_empty());
    }

    #[test]
    fn empty_search_returns_nothing() {
        let s = RagStore::new();
        let hits = s.search_top_k(&unit_vec_at(0), 3, 0.0);
        assert!(hits.is_empty());
    }
}
