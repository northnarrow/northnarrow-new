//! Active Defense Engine (ADE).
//!
//! ADE is the LLM-driven "second brain" wired in as a fallback for
//! events the deterministic [`crate::decision::RuleEngine`] cannot
//! classify. The engine:
//!
//! 1. Builds a structured prompt from the focal event + the most
//!    recent correlated events + host context.
//! 2. Hands the prompt to an [`InferenceBackend`] (in Tappa 6 the
//!    only shipped impl is [`MockBackend`]; see
//!    `inference.rs` for the rationale).
//! 3. Parses the output through [`VerdictParser`] (14 schema rules).
//! 4. On parse failure, synthesises an Escalate Tier1 verdict via
//!    [`escalate::transform_to_escalate`] so the agent always has a
//!    structured decision.
//! 5. Updates [`AdeStats`] (counters + p50/p95/p99 latency).
//!
//! All public types are re-exported from this module.

pub mod config;
pub mod context;
pub mod error;
pub mod escalate;
pub mod inference;
pub mod parser;
pub mod prompt;
pub mod stats;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use common::ade_types::AdeVerdict;
use common::Event;
use uuid::Uuid;

pub use config::AdeConfig;
pub use context::{EventContext, HostContext};
pub use error::AdeError;
pub use escalate::{transform_to_escalate, EscalateMeta};
pub use inference::{InferenceBackend, MockBackend};
pub use parser::{ValidationError, VerdictParser};
pub use stats::{AdeStats, AdeStatsSnapshot};

/// Public Active Defense Engine handle.
///
/// Cheap to clone (everything is `Arc`-backed). Construct once at
/// startup and share across tokio tasks.
#[derive(Clone)]
pub struct AdeEngine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    config: AdeConfig,
    backend: Arc<dyn InferenceBackend>,
    parser: VerdictParser,
    system_prompt: prompt::SystemPrompt,
    host: HostContext,
    stats: AdeStats,
    warmup_latency_ms: u64,
}

impl AdeEngine {
    /// Loads the model + tokenizer + system prompt and runs a small
    /// warmup. Returns an error if the model file is missing or the
    /// system prompt cannot be read.
    pub async fn new(config: AdeConfig) -> Result<Self, AdeError> {
        let backend = build_default_backend(&config)?;
        Self::new_with_backend(config, backend).await
    }

    /// Same as [`Self::new`] but with an explicit backend (used in
    /// tests and for future native engines).
    pub async fn new_with_backend(
        config: AdeConfig,
        backend: Arc<dyn InferenceBackend>,
    ) -> Result<Self, AdeError> {
        if !config.model_path.exists() {
            return Err(AdeError::ModelMissing {
                path: config.model_path.clone(),
            });
        }

        let system_prompt = prompt::SystemPrompt::load(&config.system_prompt_path)?;
        let host = HostContext::discover();

        let warmup_start = Instant::now();
        backend.warmup()?;
        let warmup_latency_ms = warmup_start.elapsed().as_millis() as u64;

        let inner = EngineInner {
            config,
            backend,
            parser: VerdictParser::new(),
            system_prompt,
            host,
            stats: AdeStats::default(),
            warmup_latency_ms,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Run inference on the focal event with a context bundle.
    ///
    /// Always returns a schema-valid [`AdeVerdict`]: parse failures
    /// are folded into an Escalate Tier1 verdict, timeouts and
    /// backend errors are surfaced as `AdeError`.
    pub async fn evaluate(
        &self,
        event: &Event,
        context: &EventContext,
    ) -> Result<AdeVerdict, AdeError> {
        let prompt = prompt::build_event_prompt(
            &self.inner.system_prompt,
            &self.inner.config,
            event,
            context,
        );

        let backend = self.inner.backend.clone();
        let event_owned = event.clone();
        let max_tokens = self.inner.config.max_output_tokens;
        let temp = self.inner.config.temperature;
        let top_p = self.inner.config.top_p;

        let start = Instant::now();
        let raw_result = tokio::time::timeout(
            self.inner.config.timeout,
            tokio::task::spawn_blocking(move || {
                backend.generate(&prompt, &event_owned, max_tokens, temp, top_p)
            }),
        )
        .await;

        let raw = match raw_result {
            Err(_) => {
                self.inner.stats.record_timeout();
                return Err(AdeError::Timeout {
                    seconds: self.inner.config.timeout.as_secs(),
                });
            }
            Ok(Err(join_err)) => {
                self.inner.stats.record_backend_error();
                return Err(AdeError::BackendJoin(join_err.to_string()));
            }
            Ok(Ok(Err(e))) => {
                self.inner.stats.record_backend_error();
                return Err(e);
            }
            Ok(Ok(Ok(s))) => s,
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;

        match self.inner.parser.parse(&raw) {
            Ok(mut v) => {
                v.metadata.model_id = self.inner.backend.model_id().to_string();
                v.metadata.model_quantization = self.inner.backend.quantization().to_string();
                v.metadata.backend = self.inner.backend.name().to_string();
                v.metadata.host_id = self.inner.host.host_id.clone();
                v.metadata.agent_version = self.inner.host.agent_version.clone();
                v.metadata.inference_latency_ms = elapsed_ms;
                v.timestamp_utc = Utc::now().to_rfc3339();
                if v.trace_id == "00000000-0000-4000-8000-000000000000" {
                    v.trace_id = Uuid::new_v4().to_string();
                }
                self.inner.stats.record_success(elapsed_ms);
                Ok(v)
            }
            Err(parse_err) => {
                self.inner.stats.record_malformed(elapsed_ms);
                let meta = EscalateMeta {
                    model_id: self.inner.backend.model_id(),
                    model_quantization: self.inner.backend.quantization(),
                    backend: self.inner.backend.name(),
                    host: &self.inner.host,
                    language: &self.inner.config.language,
                    inference_latency_ms: elapsed_ms,
                };
                Ok(transform_to_escalate(
                    event,
                    &parse_err.to_string(),
                    Some(&raw),
                    &meta,
                ))
            }
        }
    }

    pub fn config(&self) -> &AdeConfig {
        &self.inner.config
    }

    pub fn stats(&self) -> AdeStatsSnapshot {
        self.inner.stats.snapshot()
    }

    pub fn warmup_latency_ms(&self) -> u64 {
        self.inner.warmup_latency_ms
    }

    pub fn host(&self) -> &HostContext {
        &self.inner.host
    }

    pub fn backend_name(&self) -> &str {
        self.inner.backend.name()
    }

    pub fn is_ready(&self) -> bool {
        true
    }
}

fn build_default_backend(config: &AdeConfig) -> Result<Arc<dyn InferenceBackend>, AdeError> {
    // Tappa 6 ships only `MockBackend`. The model path must still
    // exist so the metadata accurately advertises the founder's
    // GGUF; future native backends will swap themselves in here.
    if !config.model_path.exists() {
        return Err(AdeError::ModelMissing {
            path: config.model_path.clone(),
        });
    }
    Ok(Arc::new(MockBackend::from_model_path(&config.model_path)))
}
