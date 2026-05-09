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

pub mod backend_candle;
pub mod config;
pub mod context;
pub mod dual_verify;
pub mod error;
pub mod escalate;
pub mod inference;
pub mod parser;
pub mod prompt;
pub mod sanitize;
pub mod sanity_check;
pub mod stats;
pub mod structured_prompt;

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
pub use dual_verify::{
    is_critical_action, CriticalActionVerifier, DeterministicVerifier, VerificationResult,
};
pub use error::AdeError;
pub use escalate::{transform_to_escalate, EscalateMeta};
pub use inference::{InferenceBackend, MockBackend};
pub use parser::{ValidationError, VerdictParser};
pub use sanitize::{sanitize_event_for_ade, InjectionFlag, SanitizedEvent};
pub use sanity_check::{verify_verdict_coherence, SanityCheckResult};
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
    ///
    /// Sub-tappa 6.6 wraps the inference call in four hardening
    /// layers:
    ///
    /// 1. **Sanitize** the event before it reaches the prompt
    ///    builder. If the [`SanitizedEvent::injection_score`] crosses
    ///    [`HIGH_INJECTION_SCORE_REJECT`] the engine bypasses the
    ///    LLM entirely and returns a synthetic Escalate.
    /// 2. Build a **structured prompt** that splits trusted context
    ///    from untrusted event data with explicit XML-style markers.
    /// 3. **Sanity-check** the parsed verdict for obvious
    ///    contradictions (high injection score + Allow, severe MITRE
    ///    tactic + Allow, severe IoC + Low severity, …). On
    ///    anomaly we replace the verdict with Escalate Tier1.
    /// 4. For verdicts that map to a destructive executor action,
    ///    run a [`DeterministicVerifier`] second-opinion. Rejection
    ///    yields a Tier3 escalation.
    pub async fn evaluate(
        &self,
        event: &Event,
        context: &EventContext,
    ) -> Result<AdeVerdict, AdeError> {
        let sanitized = sanitize::sanitize_event_for_ade(event);
        if sanitized.injection_score >= HIGH_INJECTION_SCORE_REJECT {
            tracing::warn!(
                score = sanitized.injection_score,
                flags = %sanitized.flags_summary(),
                "high injection score, escalating without ADE call"
            );
            return Ok(make_escalate_for_injection(
                event,
                &sanitized,
                self.escalate_meta(0),
            ));
        }

        let parts = structured_prompt::build_structured_prompt(
            &self.inner.system_prompt,
            &self.inner.config,
            &sanitized,
            context,
        );
        let prompt = match self.inner.backend.chat_template() {
            inference::ChatTemplate::Llama3 => parts.into_llama3_chat(),
            inference::ChatTemplate::Plain => parts.into_plain_text(),
        };

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

                // Layer 3: sanity check.
                match sanity_check::verify_verdict_coherence(&v, &sanitized) {
                    SanityCheckResult::Coherent => {}
                    SanityCheckResult::AnomalyDetected {
                        reason,
                        forced_verdict,
                    } => {
                        tracing::warn!(?reason, "ADE sanity check anomaly: forcing Escalate");
                        v = *forced_verdict;
                    }
                    SanityCheckResult::InconsistencyFlagged { reason } => {
                        tracing::info!(?reason, "ADE verdict flagged inconsistent (kept)");
                    }
                }

                // Layer 4: critical-action dual verification.
                if dual_verify::is_critical_action(v.verdict) {
                    let verifier = dual_verify::DeterministicVerifier;
                    match verifier.verify(&v, event) {
                        VerificationResult::Confirmed => {}
                        VerificationResult::Rejected { reason } => {
                            tracing::warn!(
                                ?reason,
                                action = %v.verdict,
                                "critical-action verifier rejected verdict; escalating Tier3"
                            );
                            v = make_escalate_for_verifier(
                                event,
                                &v,
                                &reason,
                                self.escalate_meta(elapsed_ms),
                            );
                        }
                        VerificationResult::Inconclusive => {
                            tracing::info!(
                                action = %v.verdict,
                                "critical-action verifier inconclusive (kept)"
                            );
                        }
                    }
                }

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

    fn escalate_meta(&self, latency_ms: u64) -> EscalateMeta<'_> {
        EscalateMeta {
            model_id: self.inner.backend.model_id(),
            model_quantization: self.inner.backend.quantization(),
            backend: self.inner.backend.name(),
            host: &self.inner.host,
            language: &self.inner.config.language,
            inference_latency_ms: latency_ms,
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

/// Injection score at-or-above this threshold causes
/// [`AdeEngine::evaluate`] to skip the LLM entirely and return a
/// synthetic Escalate. Ratchet up if you see false positives in the
/// audit log, but never above 0.95 — the sanity check is the second
/// safety net.
pub const HIGH_INJECTION_SCORE_REJECT: f32 = 0.90;

/// Synthetic Escalate verdict produced when the input event is so
/// suspicious we refuse to spend an inference round-trip on it.
///
/// We re-use [`escalate::transform_to_escalate`] for schema validity
/// and stamp the injection flags into the escalation package's
/// `key_questions` so the analyst sees what tripped the alarm.
fn make_escalate_for_injection(
    event: &Event,
    sanitized: &SanitizedEvent,
    meta: EscalateMeta<'_>,
) -> AdeVerdict {
    let mut v = transform_to_escalate(
        event,
        &format!(
            "input rejected pre-inference (injection_score={:.2})",
            sanitized.injection_score
        ),
        None,
        &meta,
    );
    if let Some(pkg) = v.escalation_package.as_mut() {
        pkg.summary = format!(
            "Pre-inference rejection: injection_score={:.2}, flags={}",
            sanitized.injection_score,
            sanitized.flags_summary()
        );
        pkg.key_questions
            .insert(0, "Was this filename adversarial?".into());
    }
    v.evidence
        .primary_indicators
        .push(format!("injection_flags:{}", sanitized.flags_summary()));
    v
}

/// Synthetic Escalate when the deterministic verifier rejects a
/// destructive verdict.
fn make_escalate_for_verifier(
    event: &Event,
    rejected: &AdeVerdict,
    reason: &str,
    meta: EscalateMeta<'_>,
) -> AdeVerdict {
    let mut v = transform_to_escalate(
        event,
        &format!("verifier rejected {} action: {reason}", rejected.verdict),
        Some(&serde_json::to_string(rejected).unwrap_or_default()),
        &meta,
    );
    if let Some(tier) = v.escalation_tier.as_mut() {
        *tier = common::ade_types::EscalationTier::Tier3Review;
    }
    v
}

/// Build the production backend with a graceful fallback chain.
///
/// Order: Candle (Llama 3.1 GGUF) → Mock (last resort).
///
/// Sub-tappa 6.1 ships the Candle path as the production backend.
/// If candle fails for any reason (missing tokenizer, GGUF parse
/// error, OOM during weight load) we log loudly and fall back to
/// `MockBackend` so the agent stays alive and the rule engine still
/// runs. CI runs without a model and naturally rejects ahead of
/// this branch via `ModelMissing`.
fn build_default_backend(config: &AdeConfig) -> Result<Arc<dyn InferenceBackend>, AdeError> {
    if !config.model_path.exists() {
        return Err(AdeError::ModelMissing {
            path: config.model_path.clone(),
        });
    }

    match backend_candle::CandleBackend::load(&config.model_path) {
        Ok(backend) => {
            tracing::info!(
                backend = "candle-llama3.1",
                model = %config.model_path.display(),
                "ADE backend loaded"
            );
            return Ok(Arc::new(backend));
        }
        Err(e) => {
            tracing::warn!(
                ?e,
                model = %config.model_path.display(),
                "candle backend failed to load, falling back to MockBackend"
            );
        }
    }

    Ok(Arc::new(MockBackend::from_model_path(&config.model_path)))
}
