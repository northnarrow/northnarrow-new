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
//! ## Future deltas (Sub-tappa 6.7+)
//!
//! - Real candle-loaded bge-small embedder.
//! - Persistent on-disk store (LanceDB once its dependency footprint
//!   is acceptable; otherwise a custom Arrow-flavoured layout).
//! - Live ingestion from MITRE GitHub, Sigma, LOLBAS.

pub mod embedder;

pub use embedder::{cosine_similarity, RagEmbedder};

#[cfg(test)]
mod tests;
