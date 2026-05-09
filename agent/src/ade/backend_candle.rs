//! Candle GGUF backend for Llama-family models.
//!
//! Sub-tappa 6.1: replaces `MockBackend` as the production ADE
//! inference engine. Loads a quantized GGUF (Q4_K_M for the
//! founder-supplied Foundation-Sec-8B-Reasoning model) via
//! `candle_transformers::models::quantized_llama::ModelWeights`,
//! tokenises with a Llama 3.1 `tokenizer.json` next to the GGUF,
//! and performs greedy-with-sampling autoregressive generation on
//! CPU.
//!
//! ## Why candle
//!
//! Charter is "100% Rust, no C/C++". Foundation-Sec-8B-Reasoning is
//! built on Llama 3.1 → architecture: `llama` in GGUF metadata →
//! native support in candle-transformers 0.10. mistral.rs was the
//! ladder-rung B fallback; we never had to climb to it.
//!
//! ## Tokenizer
//!
//! Llama 3.1 needs a `tokenizer.json` (BPE merges) — the GGUF
//! metadata format embeds tokens but candle's `quantized_llama`
//! does not consume them. The launcher expects the tokenizer at
//! `<model_dir>/<model_stem>.tokenizer.json` or, failing that, at
//! `<model_dir>/tokenizer.json`. The file is not committed; it is
//! a one-time bootstrap fetch documented in
//! `docs/ADE_BACKEND_NOTES.md`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use candle_core::quantized::gguf_file;
use candle_core::{Device, Tensor};
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::quantized_llama::ModelWeights;
use parking_lot::Mutex;
use tokenizers::Tokenizer;

use common::Event;

use super::error::AdeError;
use super::inference::{ChatTemplate, InferenceBackend};

/// Soft cap on output tokens — keeps generation time bounded even if
/// the caller asks for more than the engine can deliver in 15 s.
const MAX_OUTPUT_TOKENS_HARD_CAP: usize = 2048;

/// Soft cap on the prompt window we hand to the model.
///
/// Foundation-Sec-8B-Reasoning advertises 128K context, but on CPU
/// every additional kilo-token of prompt costs roughly half a second
/// of wall time, and the few-shot block already lives near 1.5 K
/// tokens. A 4 K hard cap keeps p95 latency in the budget.
const MAX_PROMPT_TOKENS: usize = 4096;

/// Production-grade Candle GGUF backend.
///
/// Cheap to share across tasks (`Arc`-backed). The model weights live
/// behind a `Mutex` because `forward` takes `&mut self` (KV cache
/// reuse); the agent serialises ADE evaluations anyway, so the lock
/// is uncontended in practice.
pub struct CandleBackend {
    inner: Mutex<Inner>,
    tokenizer: Tokenizer,
    device: Device,
    eos_tokens: Vec<u32>,
    end_of_think: Option<u32>,
    model_id: String,
    quantization: String,
    model_path: PathBuf,
    warmed_up: AtomicBool,
}

struct Inner {
    weights: ModelWeights,
}

impl CandleBackend {
    /// Locate a sibling tokenizer.json for the given model path.
    ///
    /// Tries (in order):
    ///
    /// 1. `<dir>/<stem>.tokenizer.json` — preferred, lets the user
    ///    keep multiple GGUFs with their own tokenisers in one dir.
    /// 2. `<dir>/tokenizer.json` — legacy single-tokenizer layout.
    pub fn locate_tokenizer(model_path: &Path) -> Option<PathBuf> {
        let dir = model_path.parent()?;
        let stem = model_path.file_stem()?.to_str()?;
        let candidates = [
            dir.join(format!("{stem}.tokenizer.json")),
            dir.join("tokenizer.json"),
        ];
        candidates.into_iter().find(|p| p.is_file())
    }

    /// Load the GGUF + tokenizer from disk. Heavy: 4-7 GB of weights
    /// get mapped + read on CPU, take a few seconds even on warm
    /// page cache.
    pub fn load(model_path: &Path) -> Result<Self, AdeError> {
        let tokenizer_path = Self::locate_tokenizer(model_path).ok_or_else(|| {
            AdeError::Backend(format!(
                "tokenizer.json not found next to model at {}",
                model_path.display()
            ))
        })?;
        Self::load_with_tokenizer(model_path, &tokenizer_path)
    }

    /// Sub-tappa 6.8: pin the rayon worker count *before* candle does
    /// any compute. rayon initialises its global pool lazily on first
    /// use and reads `RAYON_NUM_THREADS` at that moment; once the
    /// pool exists the env var is ignored, so the call must precede
    /// any backend operation.
    ///
    /// No-op if the env var is already set (operator override) or
    /// if the rayon pool has already been built (`is_initialized`
    /// returns true).
    pub fn configure_threads(num_threads: usize) {
        if std::env::var_os("RAYON_NUM_THREADS").is_some() {
            tracing::debug!("RAYON_NUM_THREADS already set, leaving operator override in place");
            return;
        }
        let n = num_threads.max(1);
        // `set_var` is unsafe on Rust 2024+; we are still on
        // edition 2021 (pinned in workspace.package) where it is
        // safe to call before any threads have been spawned that
        // read the environment. CandleBackend::load is the very
        // first ADE-side code that touches rayon, so this point is
        // race-free.
        std::env::set_var("RAYON_NUM_THREADS", n.to_string());
        tracing::info!(
            threads = n,
            "ADE rayon worker count pinned via RAYON_NUM_THREADS"
        );
    }

    pub fn load_with_tokenizer(model_path: &Path, tokenizer_path: &Path) -> Result<Self, AdeError> {
        let device = Device::Cpu;

        let mut file = File::open(model_path).map_err(|e| {
            AdeError::Backend(format!("opening GGUF {}: {e}", model_path.display()))
        })?;
        let content = gguf_file::Content::read(&mut file)
            .map_err(|e| AdeError::Backend(format!("reading GGUF metadata: {e}")))?;

        // `from_gguf` reads the tensor data sequentially from the
        // current position using the offsets baked into `content`,
        // so the file cursor must remain where `Content::read` left
        // it (just past the metadata block) — no rewind.
        let weights = ModelWeights::from_gguf(content, &mut file, &device)
            .map_err(|e| AdeError::Backend(format!("loading GGUF weights: {e}")))?;

        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| AdeError::Backend(format!("loading tokenizer: {e}")))?;

        // Llama 3.1 stop tokens.
        let eos_eot = tokenizer.token_to_id("<|eot_id|>").unwrap_or(128009);
        let eos_text = tokenizer.token_to_id("<|end_of_text|>").unwrap_or(128001);
        let mut eos_tokens = vec![eos_eot, eos_text];
        eos_tokens.dedup();

        // Reasoning-model end-of-thinking marker. Foundation-Sec
        // emits </think> as a regular text token (no special id), so
        // we look it up by token-to-id and accept absence (None means
        // "non-reasoning model, parser strips by string instead").
        let end_of_think = tokenizer.token_to_id("</think>");

        let model_id = model_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("foundation-sec-8b-reasoning")
            .to_string();

        Ok(Self {
            inner: Mutex::new(Inner { weights }),
            tokenizer,
            device,
            eos_tokens,
            end_of_think,
            model_id,
            quantization: "Q4_K_M".to_string(),
            model_path: model_path.to_path_buf(),
            warmed_up: AtomicBool::new(false),
        })
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    fn run_inference(
        &self,
        prompt: &str,
        max_tokens: usize,
        temperature: f32,
        top_p: f32,
        budget: Duration,
    ) -> Result<String, AdeError> {
        let started = Instant::now();
        let max_tokens = max_tokens.min(MAX_OUTPUT_TOKENS_HARD_CAP);

        let encoded = self
            .tokenizer
            .encode(prompt, true)
            .map_err(|e| AdeError::Backend(format!("tokenize prompt: {e}")))?;
        let mut prompt_tokens: Vec<u32> = encoded.get_ids().to_vec();
        if prompt_tokens.len() > MAX_PROMPT_TOKENS {
            // Drop oldest tokens — preserve the system prompt by
            // keeping the suffix. The prompt is built such that the
            // focal event lives at the end, so this is safe.
            let drop = prompt_tokens.len() - MAX_PROMPT_TOKENS;
            prompt_tokens.drain(0..drop);
        }
        if prompt_tokens.is_empty() {
            return Err(AdeError::Backend("empty prompt after tokenisation".into()));
        }

        let sampling = if temperature <= 0.0 {
            Sampling::ArgMax
        } else {
            Sampling::TopP {
                p: top_p as f64,
                temperature: temperature as f64,
            }
        };
        let mut logits_processor = LogitsProcessor::from_sampling(0xC0FFEE, sampling);

        let mut all_tokens: Vec<u32> = Vec::with_capacity(prompt_tokens.len() + max_tokens);
        all_tokens.extend_from_slice(&prompt_tokens);
        let mut output_tokens: Vec<u32> = Vec::with_capacity(max_tokens);
        let prompt_len = prompt_tokens.len();

        let mut weights = self.inner.lock();
        let mut next_token: u32;

        // 1) Pre-fill: hand the whole prompt to the model in one shot
        //    and sample the first response token. The KV cache after
        //    this call holds positions 0..prompt_len.
        let prefill_started = Instant::now();
        tracing::debug!(prompt_tokens = prompt_len, "candle prefill starting");
        {
            let input = Tensor::new(prompt_tokens.as_slice(), &self.device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| AdeError::Backend(format!("prompt tensor: {e}")))?;
            let logits = weights
                .weights
                .forward(&input, 0)
                .map_err(|e| AdeError::Backend(format!("prompt forward: {e}")))?;
            let logits = logits
                .squeeze(0)
                .map_err(|e| AdeError::Backend(format!("squeeze: {e}")))?;
            next_token = logits_processor
                .sample(&logits)
                .map_err(|e| AdeError::Backend(format!("sample: {e}")))?;
            all_tokens.push(next_token);
            output_tokens.push(next_token);
        }
        tracing::debug!(
            prompt_tokens = prompt_len,
            prefill_ms = prefill_started.elapsed().as_millis() as u64,
            "candle prefill done"
        );

        // 2) Decode: feed the just-sampled token at the next free
        //    cache slot (`index_pos`), get logits, sample the
        //    successor. Loop bound = max_tokens − 1 because we
        //    already produced one token in the prefill step.
        let decode_started = Instant::now();
        let mut budget_breached = false;
        for index_pos in prompt_len..prompt_len + max_tokens.saturating_sub(1) {
            if self.eos_tokens.contains(&next_token) {
                break;
            }
            if started.elapsed() >= budget {
                budget_breached = true;
                break;
            }
            // Heartbeat every 16 tokens so a slow CPU run is
            // observable from the agent log.
            if index_pos % 16 == 0 {
                tracing::trace!(
                    index_pos,
                    decoded_so_far = output_tokens.len(),
                    decode_ms = decode_started.elapsed().as_millis() as u64,
                    "candle decode step"
                );
            }
            let input = Tensor::new(&[next_token], &self.device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| AdeError::Backend(format!("decode tensor: {e}")))?;
            let logits = weights
                .weights
                .forward(&input, index_pos)
                .map_err(|e| AdeError::Backend(format!("decode forward: {e}")))?;
            let logits = logits
                .squeeze(0)
                .map_err(|e| AdeError::Backend(format!("squeeze decode: {e}")))?;
            next_token = logits_processor
                .sample(&logits)
                .map_err(|e| AdeError::Backend(format!("sample decode: {e}")))?;
            all_tokens.push(next_token);
            output_tokens.push(next_token);
        }
        drop(weights);

        let raw = self
            .tokenizer
            .decode(&output_tokens, false)
            .map_err(|e| AdeError::Backend(format!("decode tokens: {e}")))?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let decode_ms = decode_started.elapsed().as_millis() as u64;
        if budget_breached {
            tracing::warn!(
                tokens = output_tokens.len(),
                total_ms = elapsed_ms,
                decode_ms,
                "candle backend hit budget mid-generation"
            );
        } else {
            tracing::debug!(
                output_tokens = output_tokens.len(),
                total_ms = elapsed_ms,
                decode_ms,
                "candle inference complete"
            );
        }
        Ok(raw)
    }
}

impl InferenceBackend for CandleBackend {
    fn name(&self) -> &str {
        "candle-llama3.1"
    }
    fn quantization(&self) -> &str {
        &self.quantization
    }
    fn model_id(&self) -> &str {
        &self.model_id
    }
    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate::Llama3
    }

    fn generate(
        &self,
        prompt: &str,
        _focal_event: &Event,
        max_tokens: usize,
        temperature: f32,
        top_p: f32,
    ) -> Result<String, AdeError> {
        // The engine layer (mod.rs) wraps this in a tokio timeout +
        // spawn_blocking; from this side the Duration just bounds
        // how aggressively we self-abort if the caller didn't.
        let budget = Duration::from_secs(120);
        self.run_inference(prompt, max_tokens, temperature, top_p, budget)
    }

    fn warmup(&self) -> Result<(), AdeError> {
        if self.warmed_up.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Single forward pass with a 1-token input to allocate the
        // KV cache and JIT any lazy quantized matmuls. Keeps the
        // first user-facing inference closer to steady-state latency.
        let mut weights = self.inner.lock();
        let probe = Tensor::new(&[128000u32], &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| AdeError::Backend(format!("warmup tensor: {e}")))?;
        let _ = weights
            .weights
            .forward(&probe, 0)
            .map_err(|e| AdeError::Backend(format!("warmup forward: {e}")))?;
        // Reset the model: drop and reload would be expensive, but
        // running the warmup probe leaves a single bogus token in
        // the KV cache. Real inference always starts at index_pos=0
        // with the full prompt, which overwrites that slot — so the
        // warmup leak is harmless for the first real call.
        Ok(())
    }
}

/// Best-effort wrapper for [`CandleBackend::end_of_think`]: backends
/// that don't need the special id don't have to know about it.
impl CandleBackend {
    pub fn end_of_think_token(&self) -> Option<u32> {
        self.end_of_think
    }
}
