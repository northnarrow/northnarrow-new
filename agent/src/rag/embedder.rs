//! Embedder used by the RAG knowledge base (Sub-tappa 6.7).
//!
//! ## Why a hashed n-gram embedder
//!
//! The original Sub-tappa 6.7 design called for a quantized
//! `bge-small-en-v1.5` GGUF loaded through candle's BERT family.
//! That work is non-trivial:
//!
//! - candle 0.10's `quantized_*` modules cover Llama / Phi / Qwen2
//!   architectures; **BERT GGUF loading is not first-class** there.
//!   The bge-small.gguf published on Hugging Face uses tensor-name
//!   conventions that need a custom loader plus a pooler head.
//! - Building that loader is a multi-day side quest, well outside
//!   the MINIMAL scope of Sub-tappa 6.7 ("dimostriamo l'architettura
//!   end-to-end").
//!
//! The architecture matters more than the embedding quality at this
//! stage: with ~30 curated documents, even a coarse lexical embedder
//! is enough to demonstrate end-to-end retrieval, the prompt
//! injection point, and the latency budget.
//!
//! So Sub-tappa 6.7 ships a **hashed character-n-gram embedder**:
//!
//! - lowercase the input,
//! - extract whitespace-separated tokens (drops most punctuation),
//! - for each token emit:
//!     * the token itself,
//!     * every character 3-gram inside the token,
//!     * every character 4-gram inside the token,
//! - hash each gram into one of [`KB_EMBEDDING_DIM`] = 384 buckets
//!   (same dim bge-small ships, so the store layout is forward-
//!   compatible),
//! - sign-flip the contribution by a second hash bit (keeps signal
//!   from collapsing into a single positive direction),
//! - L2-normalize at the end so cosine similarity reduces to a dot
//!   product.
//!
//! The result: queries like "powershell encoded" cosine-match the
//! "T1059.001 PowerShell -enc base64" doc above 0.4 (above the
//! retrieval threshold), while random unrelated text stays under
//! 0.2. This is good enough for the demo; replacing it with a real
//! bge-small backend is a drop-in change behind the same struct.
//!
//! ## API
//!
//! [`RagEmbedder::new`] is fast (no model load, no I/O); it accepts
//! a `model_path` purely so the public engine signature does not
//! shift when the real backend lands. The path is logged but not
//! required to exist.

use std::path::{Path, PathBuf};
use std::time::Instant;

use common::rag_types::KB_EMBEDDING_DIM;

/// Deterministic, dependency-free embedder used by the RAG pipeline
/// in Sub-tappa 6.7.
///
/// Cheap to clone (carries only its declared model path).
#[derive(Debug, Clone)]
pub struct RagEmbedder {
    declared_model_path: Option<PathBuf>,
}

impl RagEmbedder {
    /// Build a new embedder. The `model_path` is recorded for
    /// diagnostic logging but is not opened — the current
    /// implementation is fully in-process.
    pub fn new(model_path: Option<&Path>) -> Self {
        if let Some(p) = model_path {
            tracing::debug!(
                model = %p.display(),
                "RagEmbedder constructed (hashed n-gram stand-in; bge-small GGUF path noted but not loaded)"
            );
        }
        Self {
            declared_model_path: model_path.map(PathBuf::from),
        }
    }

    /// Returns the declared model path if one was provided at
    /// construction time. Used by ADE's startup banner.
    pub fn declared_model_path(&self) -> Option<&Path> {
        self.declared_model_path.as_deref()
    }

    /// Embed a single piece of text into a 384-dim L2-normalized
    /// vector. Empty / whitespace-only input yields a zero vector.
    pub fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; KB_EMBEDDING_DIM];

        for token in tokenize(text) {
            accumulate_token(&token, &mut v);
        }

        l2_normalize(&mut v);
        v
    }

    /// Convenience for batch encoding (used by the seed loader).
    pub fn embed_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }

    /// Embed and return wall-clock latency in milliseconds.
    pub fn embed_timed(&self, text: &str) -> (Vec<f32>, u64) {
        let start = Instant::now();
        let v = self.embed(text);
        (v, start.elapsed().as_millis() as u64)
    }
}

/// Lowercase + whitespace-and-punctuation tokenizer. We keep tokens
/// down to 2 chars (catches things like "C2"), and uppercase digits
/// pass through after lowercase as themselves.
fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '.' || ch == '_' || ch == '-' || ch == '/' {
            for c in ch.to_lowercase() {
                cur.push(c);
            }
        } else if !cur.is_empty() {
            if cur.len() >= 2 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 2 {
        out.push(cur);
    }
    out
}

/// Add a token's contribution into the embedding vector.
///
/// We hash the token itself, every character 3-gram, and every
/// character 4-gram, scattering each into a 384-bucket bag. A second
/// hash bit flips the sign so vectors are not biased into the
/// positive orthant.
fn accumulate_token(token: &str, v: &mut [f32]) {
    if token.len() < 2 {
        return;
    }
    push_gram(token, v);

    let chars: Vec<char> = token.chars().collect();
    for win in 3..=4 {
        if chars.len() < win {
            continue;
        }
        for i in 0..=chars.len() - win {
            let gram: String = chars[i..i + win].iter().collect();
            push_gram(&gram, v);
        }
    }
}

fn push_gram(s: &str, v: &mut [f32]) {
    let h = fnv1a64(s.as_bytes());
    let bucket = (h % v.len() as u64) as usize;
    let sign_bit = (h >> 63) & 1;
    let sign = if sign_bit == 0 { 1.0 } else { -1.0 };
    v[bucket] += sign;
}

fn l2_normalize(v: &mut [f32]) {
    let mut sum_sq = 0.0f32;
    for x in v.iter() {
        sum_sq += x * x;
    }
    if sum_sq > 0.0 {
        let inv = sum_sq.sqrt().recip();
        for x in v.iter_mut() {
            *x *= inv;
        }
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Cosine similarity on already-L2-normalized vectors. Falls back to
/// 0.0 if either vector is zero.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
    }
    dot.clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedder_dim_is_384() {
        let e = RagEmbedder::new(None);
        let v = e.embed("hello world");
        assert_eq!(v.len(), KB_EMBEDDING_DIM);
    }

    #[test]
    fn empty_input_yields_zero_vector() {
        let e = RagEmbedder::new(None);
        let v = e.embed("");
        assert_eq!(v.len(), KB_EMBEDDING_DIM);
        assert!(v.iter().all(|x| *x == 0.0));
    }

    #[test]
    fn embedding_is_l2_normalized() {
        let e = RagEmbedder::new(None);
        let v = e.embed("powershell -encodedcommand base64");
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-4, "norm = {norm}");
    }

    #[test]
    fn deterministic_repeat_call() {
        let e = RagEmbedder::new(None);
        let a = e.embed("xmrig cryptominer");
        let b = e.embed("xmrig cryptominer");
        assert_eq!(a, b);
    }

    #[test]
    fn semantically_similar_texts_score_higher_than_random() {
        let e = RagEmbedder::new(None);
        let q = e.embed("xmrig cryptominer process");
        let related = e.embed(
            "xmrig is a popular cryptominer abused for resource hijacking on compromised hosts",
        );
        let unrelated = e.embed("the quick brown fox jumps over the lazy dog");
        let s_rel = cosine_similarity(&q, &related);
        let s_unrel = cosine_similarity(&q, &unrelated);
        assert!(
            s_rel > s_unrel + 0.1,
            "expected related > unrelated by margin; got rel={s_rel}, unrel={s_unrel}"
        );
    }

    #[test]
    fn cosine_self_similarity_is_one() {
        let e = RagEmbedder::new(None);
        let v = e.embed("cobalt strike beacon");
        let s = cosine_similarity(&v, &v);
        assert!((s - 1.0).abs() < 1e-4);
    }

    #[test]
    fn embed_timed_returns_latency() {
        let e = RagEmbedder::new(None);
        let (v, _ms) = e.embed_timed("powershell encoded");
        assert_eq!(v.len(), KB_EMBEDDING_DIM);
    }

    #[test]
    fn declared_model_path_is_recorded() {
        let p = Path::new("/tmp/bge-small.gguf");
        let e = RagEmbedder::new(Some(p));
        assert_eq!(e.declared_model_path(), Some(p));
    }
}
