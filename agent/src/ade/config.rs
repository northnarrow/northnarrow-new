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
    /// Sub-tappa 6.8: how many threads candle's CPU kernels are
    /// allowed to use. `None` lets [`AdeConfig::effective_threads`]
    /// pick a sensible default based on the host's physical-core
    /// count; `Some(n)` overrides it explicitly via the
    /// `--ade-threads` CLI flag.
    pub num_threads: Option<usize>,
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

    /// Resolved thread count for candle's CPU kernels.
    ///
    /// When `num_threads` is `Some(n)`, returns `n` clamped to a
    /// minimum of 1. When `None`, falls back to
    /// `physical_cores - 1` (also clamped to ≥ 1) so the OS keeps a
    /// core for housekeeping. On the Hetzner CCX23 reference host
    /// (4 vCPU / 2 physical) the default is 1; on a 16-core
    /// workstation it would be 15.
    pub fn effective_threads(&self) -> usize {
        match self.num_threads {
            Some(n) => n.max(1),
            None => {
                let cores = num_cpus::get_physical();
                cores.saturating_sub(1).max(1)
            }
        }
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
            num_threads: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_threads_default_is_at_least_one() {
        let cfg = AdeConfig::default();
        let n = cfg.effective_threads();
        assert!(n >= 1, "effective_threads must always be >= 1, got {n}");
    }

    #[test]
    fn effective_threads_honours_explicit_override() {
        let cfg = AdeConfig {
            num_threads: Some(4),
            ..AdeConfig::default()
        };
        assert_eq!(cfg.effective_threads(), 4);
    }

    #[test]
    fn effective_threads_clamps_zero_to_one() {
        let cfg = AdeConfig {
            num_threads: Some(0),
            ..AdeConfig::default()
        };
        assert_eq!(cfg.effective_threads(), 1);
    }
}
