//! ADE configuration knobs (model path, sampling, language, timeout).
//!
//! Defaults match Sub-tappa 6.1 expectations: Foundation-Sec-8B
//! Reasoning Q4_K_M living at
//! `/home/forty/models/foundation-sec-8b-reasoning-q4_k_m.gguf`,
//! Italian outputs, 15 s hard timeout. CLI overrides arrive in
//! `agent/src/main.rs`.
//!
//! The Gemma 4 GGUF stays accessible via `--ade-model PATH` for
//! comparative benchmarks but is not the default any more — Llama
//! 3.1 family has native candle support, gemma4 does not (yet).

use std::path::PathBuf;
use std::time::Duration;

/// Tunables for the Active Defense Engine.
#[derive(Debug, Clone)]
pub struct AdeConfig {
    pub model_path: PathBuf,
    pub system_prompt_path: PathBuf,
    pub max_context_tokens: usize,
    pub max_output_tokens: usize,
    pub temperature: f32,
    pub top_p: f32,
    pub language: String,
    pub timeout: Duration,
    pub host_role: Option<String>,
}

impl AdeConfig {
    /// Default model path used by Sub-tappa 6.1 — Foundation-Sec-8B
    /// Reasoning Q4_K_M (Llama 3.1 architecture, full candle support).
    pub const DEFAULT_MODEL_PATH: &'static str =
        "/home/forty/models/foundation-sec-8b-reasoning-q4_k_m.gguf";

    /// Default system prompt path (relative to repo root).
    pub const DEFAULT_SYSTEM_PROMPT_PATH: &'static str = "dataset/system_prompt_v1.md";

    /// Returns a [`AdeConfig`] with the model path overridden.
    pub fn with_model_path(mut self, path: PathBuf) -> Self {
        self.model_path = path;
        self
    }

    /// Returns a [`AdeConfig`] with the timeout overridden.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Default for AdeConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::from(Self::DEFAULT_MODEL_PATH),
            system_prompt_path: PathBuf::from(Self::DEFAULT_SYSTEM_PROMPT_PATH),
            max_context_tokens: 2048,
            max_output_tokens: 1500,
            temperature: 0.3,
            top_p: 0.9,
            language: "it-IT".to_string(),
            timeout: Duration::from_secs(15),
            host_role: None,
        }
    }
}
