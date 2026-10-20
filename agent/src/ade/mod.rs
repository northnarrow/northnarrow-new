//! Active Defense Engine (ADE).
//!
//! ADE is the LLM-driven "second brain" wired in as a fallback for
//! events the deterministic [`crate::decision::RuleEngine`] cannot
//! classify. The engine:
//!
//! 1. Builds a structured prompt from the focal event + the most
//!    recent correlated events + host context.
//! 2. Hands the prompt to an [`InferenceBackend`] — the real candle
//!    Llama-3.1 backend ([`backend_candle`]) is the default since
//!    Sub-tappa 6.1; [`MockBackend`] is the CI / load-failure
//!    fallback (see `inference.rs`).
//! 3. Parses the output through [`VerdictParser`] (14 schema rules).
//! 4. On parse failure, synthesises an Escalate Tier1 verdict via
//!    [`escalate::transform_to_escalate`] so the agent always has a
//!    structured decision.
//! 5. Updates [`AdeStats`] (counters + p50/p95/p99 latency).
//!
//! All public types are re-exported from this module.

pub mod advisory;
pub mod backend_candle;
pub mod chain_template;
pub mod config;
pub mod context;
pub mod dual_verify;
pub mod error;
pub mod escalate;
pub mod exec_pairing;
pub mod fim_template;
pub mod inference;
pub mod mem_guard;
pub mod model_trust;
pub mod parser;
pub mod process_template;
pub mod prompt;
pub mod rag_integration;
pub mod sanitize;
pub mod sanity_check;
pub mod slot;
pub mod stats;
pub mod streaming_parser;
pub mod structured_prompt;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tokenizer_golden;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use common::ade_types::AdeVerdict;
use common::rag_types::RagResult;
use common::Event;
use uuid::Uuid;

pub use config::AdeConfig;
pub use context::{EventContext, HostContext};
pub use dual_verify::{
    is_critical_action, CriticalActionVerifier, DeterministicVerifier, VerificationResult,
};
pub use error::AdeError;
use escalate::truncate_on_char_boundary;
pub use escalate::{transform_to_escalate, EscalateMeta};
pub use inference::{InferenceBackend, MockBackend, StreamControl};
pub use mem_guard::{check_ade_memory, AdeMemCheck};
pub use parser::{ValidationError, VerdictParser};
pub use rag_integration::{build_rag_query, format_rag_block};
pub use sanitize::{sanitize_event_for_ade, InjectionFlag, SanitizedEvent};
pub use sanity_check::{verify_verdict_coherence, SanityCheckResult};
pub use stats::{AdeStats, AdeStatsSnapshot};
pub use streaming_parser::StreamingJsonDetector;

use crate::rag::{RagEngine, RagQuery};
use sanitize::SanitizedCorrelated;

/// External audit LLMR-019: what [`AdeEngine::evaluate_recorded`] returns,
/// the verdict and the digest of the prompt it was decided on.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub verdict: AdeVerdict,
    /// [`prompt_sha256`] of the prompt the backend was given; `None` when
    /// none was (an injection short-circuit, a prompt over the window).
    pub prompt_sha256: Option<String>,
}

/// Lower-case hex SHA-256 of a prompt: the digest `evaluate_recorded`
/// returns and the XAI chain's `prompt_sha256`, one function for both.
pub fn prompt_sha256(prompt: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(prompt.as_bytes()))
}

/// What [`AdeEngine::prepare`] makes of an event.
enum Prepared {
    /// The sanitizer's score keeps the event from the model.
    Rejected(SanitizedEvent),
    /// The prompt the backend gets, fitted to its window, and the
    /// sanitized inputs (all the correlated events, sent or not).
    Prompt {
        prompt: String,
        sanitized: SanitizedEvent,
        correlated: SanitizedCorrelated,
    },
    /// External audit LLMR-008: the system prompt, the focal event and the
    /// task alone exceed the window.
    TooLong { tokens: usize, window: usize },
}

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
    /// Optional RAG engine wired in Sub-tappa 6.7. When `Some`, every
    /// `evaluate` call runs a top-k retrieval before inference and
    /// splices the curated knowledge into the structured prompt.
    /// `None` reproduces the pre-6.7 behaviour byte-for-byte (existing
    /// tests assume this).
    rag: Option<Arc<RagEngine>>,
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
            rag: None,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Returns a fresh handle wired with a [`RagEngine`].
    ///
    /// The previous handle is left untouched (Arc-shared `EngineInner`
    /// would be cheap to clone, but a caller that still holds the no-RAG
    /// variant keeps it).
    pub fn with_rag(self, rag: Arc<RagEngine>) -> Self {
        let prev = &self.inner;
        let inner = EngineInner {
            config: prev.config.clone(),
            backend: prev.backend.clone(),
            parser: VerdictParser::new(),
            system_prompt: prev.system_prompt.clone(),
            host: prev.host.clone(),
            stats: AdeStats::default(),
            warmup_latency_ms: prev.warmup_latency_ms,
            rag: Some(rag),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Whether this engine has a RAG knowledge base wired in.
    pub fn has_rag(&self) -> bool {
        self.inner.rag.is_some()
    }

    /// The fingerprint of the corpus the wired RAG engine retrieves from,
    /// `None` without RAG. The XAI `environment_hash` binds it (external
    /// audit XAI-010).
    pub fn rag_fingerprint(&self) -> Option<&str> {
        self.inner.rag.as_deref().map(RagEngine::corpus_fingerprint)
    }

    /// Run inference on the focal event with a context bundle.
    ///
    /// Parse failures, and a prompt that does not fit the model's window
    /// even without its correlated events, are folded into an Escalate
    /// Tier1 verdict. Timeouts and backend errors are surfaced as
    /// `AdeError`, so that a caller can tell them from a verdict (the XAI
    /// probe does); the agent records them through
    /// [`Self::escalate_for_error`] (external audit LLMR-003).
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
        self.evaluate_inner(event, context, &mut None).await
    }

    /// External audit LLMR-019: [`Self::evaluate`], with the digest of the
    /// prompt the backend was given beside the verdict
    /// ([`Evaluation::prompt_sha256`]), for `XaiEngine::explain` to check
    /// that it explains that prompt and not one rebuilt from other inputs.
    /// The schema-v1 verdict is unchanged.
    pub async fn evaluate_recorded(
        &self,
        event: &Event,
        context: &EventContext,
    ) -> Result<Evaluation, AdeError> {
        let mut prompt_sha256 = None;
        let verdict = self
            .evaluate_inner(event, context, &mut prompt_sha256)
            .await?;
        Ok(Evaluation {
            verdict,
            prompt_sha256,
        })
    }

    /// The body of [`Self::evaluate`] and [`Self::evaluate_recorded`]:
    /// `sent` is set to the digest of the prompt once it is built, before
    /// the backend runs.
    async fn evaluate_inner(
        &self,
        event: &Event,
        context: &EventContext,
        sent: &mut Option<String>,
    ) -> Result<AdeVerdict, AdeError> {
        let (prompt, sanitized, correlated) = match self.prepare(event, context) {
            Prepared::Rejected(sanitized) => {
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
            Prepared::TooLong { tokens, window } => {
                tracing::warn!(
                    tokens,
                    window,
                    "ADE prompt exceeds the model window without correlated events, escalating"
                );
                self.inner.stats.record_backend_error();
                let err = AdeError::PromptExceedsWindow { tokens, window };
                return Ok(self.escalate_for_error(event, &err));
            }
            Prepared::Prompt {
                prompt,
                sanitized,
                correlated,
            } => {
                *sent = Some(prompt_sha256(&prompt));
                (prompt, sanitized, correlated)
            }
        };

        let backend = self.inner.backend.clone();
        let event_owned = event.clone();
        let max_tokens = self.inner.config.max_output_tokens;
        let temp = self.inner.config.temperature;
        let top_p = self.inner.config.top_p;

        let start = Instant::now();
        // Sub-tappa 6.8: stream the decode through a brace-tracking
        // detector and signal Stop the moment the verdict JSON
        // closes. Backends without per-token streaming (MockBackend)
        // get a single end-of-output callback via the trait's
        // default impl — same observable behaviour, just no early
        // termination saving.
        // External audit LLMR-002: set when the timeout fires, so that the
        // generation stops at its next token.
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let mut generation = tokio::task::spawn_blocking(move || {
            let mut detector = StreamingJsonDetector::new();
            backend.generate_streaming(
                &prompt,
                &event_owned,
                max_tokens,
                temp,
                top_p,
                Box::new(move |chunk: &str| {
                    if stop.load(Ordering::Relaxed) || detector.feed(chunk) {
                        inference::StreamControl::Stop
                    } else {
                        inference::StreamControl::Continue
                    }
                }),
            )
        });
        let raw_result = tokio::time::timeout(self.inner.config.timeout, &mut generation).await;

        let raw = match raw_result {
            Err(_) => {
                // External audit LLMR-002: dropping the handle of a
                // blocking task does not stop it. It ran on, holding the
                // model's weights, up to the backend's own budget (then
                // 120 s), while the next evaluations queued behind it and
                // timed out in turn. Stop it at its next token, and give
                // the backend back before reporting the timeout.
                cancelled.store(true, Ordering::Relaxed);
                let _ = generation.await;
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
                // External audit LLMP-005 (NN-AUD-319): the recommended
                // action is the verdict. Nothing decides on the field
                // (`requires_execution`, `to_response_action` and the
                // advisory switch on `verdict`), but a model that wrote
                // `Kill` there under an `Alert` left a record that said
                // both.
                if v.recommended_action.action != v.verdict {
                    tracing::debug!(
                        verdict = %v.verdict,
                        recommended = %v.recommended_action.action,
                        "ADE recommended action differs from the verdict: aligned on the verdict"
                    );
                    v.recommended_action.action = v.verdict;
                }
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

                // Layer 3: sanity check. External audit LLMP-002: an
                // injection attempt in the correlated events weighs like
                // one in the focal event.
                let weighed = sanitize::SanitizedEvent {
                    injection_score: sanitized.injection_score.max(correlated.max_score),
                    ..sanitized.clone()
                };
                match sanity_check::verify_verdict_coherence(&v, &weighed) {
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
                        // External audit LLMR-006: no confirmation, no
                        // destructive action — escalated like a rejection.
                        VerificationResult::Inconclusive => {
                            tracing::warn!(
                                action = %v.verdict,
                                "critical-action verifier inconclusive; escalating Tier3"
                            );
                            v = make_escalate_for_verifier(
                                event,
                                &v,
                                "verifier inconclusive",
                                self.escalate_meta(elapsed_ms),
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

    /// Read-only forensic seam (Tappa 6.9 XAI / EU AI Act Art. 13): the
    /// exact assembled model prompt `evaluate` would send the backend
    /// for `(event, context)` — WITHOUT running inference and WITHOUT
    /// any state change. It shares evaluate's
    /// sanitize→structured-prompt→chat-template path verbatim, so the
    /// `XaiInputSnapshot.prompt_sha256` binds the literal prompt. ADE
    /// behaviour is byte-identical whether or not this is ever called
    /// (it is invoked only by `XaiEngine`). Returns `None` when the
    /// sanitiser would short-circuit `evaluate` to an injection
    /// Escalate, or when the prompt does not fit the model's window
    /// (external audit LLMR-008) — in those paths no prompt is produced.
    pub fn assembled_prompt(&self, event: &Event, context: &EventContext) -> Option<String> {
        match self.prepare(event, context) {
            Prepared::Prompt { prompt, .. } => Some(prompt),
            Prepared::Rejected(_) | Prepared::TooLong { .. } => None,
        }
    }

    /// The prompt for `(event, context)`, fitted to the backend's window:
    /// the one path from the event to the model, shared by
    /// [`Self::evaluate`] and [`Self::assembled_prompt`] so that the XAI
    /// `prompt_sha256` binds the prompt the model saw.
    ///
    /// External audit LLMR-008: the backend cut an over-long prompt from the
    /// front, which is where the system prompt is. The fit drops the oldest
    /// correlated events first (those that share no key with the focal
    /// event before the others, external audit XAI-013), then the RAG
    /// block; the system prompt, the focal event and the task are never
    /// cut. If they alone do not fit, no prompt is produced
    /// ([`Prepared::TooLong`]).
    fn prepare(&self, event: &Event, context: &EventContext) -> Prepared {
        let sanitized = sanitize::sanitize_event_for_ade(event);
        if sanitized.injection_score >= HIGH_INJECTION_SCORE_REJECT {
            return Prepared::Rejected(sanitized);
        }

        // Sub-tappa 6.7: optional RAG retrieval before prompt build. The
        // query is built from the sanitized strings (external audit
        // LLMR-011).
        let mut rag_result: Option<RagResult> = self.inner.rag.as_ref().map(|rag| {
            let query_text = build_rag_query(&sanitized);
            let r = rag.retrieve(RagQuery::new(&query_text));
            tracing::debug!(
                hits = r.documents.len(),
                embed_ms = r.query_embedding_ms,
                retrieve_ms = r.retrieval_ms,
                "ADE RAG retrieval"
            );
            r
        });

        // External audit LLMP-002: the correlated events are sanitized
        // like the focal one, and go in their own untrusted block.
        let correlated = sanitize::sanitize_correlated(event, &context.recent_events);
        let mut fitted = correlated.clone();
        let window = self.inner.backend.prompt_window();
        loop {
            let parts = structured_prompt::build_structured_prompt_with_rag(
                &self.inner.system_prompt,
                &self.inner.config,
                &sanitized,
                &fitted,
                context,
                rag_result.as_ref(),
            );
            let prompt = match self.inner.backend.chat_template() {
                inference::ChatTemplate::Llama3 => parts.into_llama3_chat(),
                inference::ChatTemplate::Plain => parts.into_plain_text(),
            };
            let over = window.and_then(|window| {
                self.inner
                    .backend
                    .prompt_tokens(&prompt)
                    .filter(|&tokens| tokens > window)
                    .map(|tokens| (tokens, window))
            });
            let Some((tokens, window)) = over else {
                let dropped = correlated.events.len() - fitted.events.len();
                if dropped > 0 {
                    tracing::debug!(
                        dropped,
                        kept = fitted.events.len(),
                        "ADE prompt fitted to the model window: least related correlated events dropped"
                    );
                }
                // The sanity check weighs every correlated event the
                // sanitizer saw, sent or not.
                return Prepared::Prompt {
                    prompt,
                    sanitized,
                    correlated,
                };
            };
            // External audit XAI-013: the oldest nearby event goes first,
            // a keyed one (a possible precursor) only after them.
            if fitted.drop_least_related() {
                continue;
            }
            if rag_result.take().is_some() {
                continue;
            }
            return Prepared::TooLong { tokens, window };
        }
    }

    /// External audit LLMR-003: the verdict the agent records when
    /// [`Self::evaluate`] fails (a timeout, a backend or join error). It
    /// used to log a warning and drop the event: an unknown binary that
    /// timed out the model left no detection. Escalate Tier1, kind
    /// `ade_unavailable`, the error in the package; no response follows.
    pub fn escalate_for_error(&self, event: &Event, err: &AdeError) -> AdeVerdict {
        let latency_ms = match err {
            AdeError::Timeout { .. } => self.inner.config.timeout.as_millis() as u64,
            _ => 0,
        };
        let mut v = transform_to_escalate(
            event,
            &err.to_string(),
            None,
            &self.escalate_meta(latency_ms),
        );
        v.threat_classification.kind = "ade_unavailable".into();
        v.reasoning.step_1_extract =
            "Synthetic escalation: the ADE model gave no verdict for this event.".into();
        v.reasoning.step_2_pattern_match = "n/a — no model verdict".into();
        v.reasoning.step_4_alternative_explanations.legitimate_uses =
            vec!["slow or overloaded host".into()];
        v.reasoning.step_5_decision = format!("Escalate Tier1Review. ADE unavailable: {err}");
        v.evidence.primary_indicators = vec![format!("ade_unavailable: {err}")];
        v.recommended_action.justification = "No model verdict; escalating to Tier1 review".into();
        if let Some(pkg) = v.escalation_package.as_mut() {
            pkg.summary = truncate_on_char_boundary(&format!("ADE unavailable: {err}"), 280).into();
            pkg.key_questions = vec![
                "Was the process benign?".into(),
                "Is the host too slow or too busy for the model?".into(),
            ];
        }
        v
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

/// Build the production backend: Candle (Llama 3.1 GGUF).
///
/// If candle fails (missing tokenizer, GGUF parse error, OOM during weight
/// load, an untrusted file) the error goes back to the caller and the agent
/// runs on its rules alone. The mock backend answers instead only when
/// asked for with `NN_ADE_ALLOW_MOCK=1` (external audit LLMR-005; it used
/// to be the silent fallback). CI runs without a model and rejects ahead
/// of this branch via `ModelMissing`.
fn build_default_backend(config: &AdeConfig) -> Result<Arc<dyn InferenceBackend>, AdeError> {
    if !config.model_path.exists() {
        return Err(AdeError::ModelMissing {
            path: config.model_path.clone(),
        });
    }

    // Sub-tappa 6.8: candle's worker count is pinned in RAYON_NUM_THREADS
    // before any thread exists (`main`, external audit LLMR-009); here it is
    // only said, a WARN when nothing pinned it.
    backend_candle::log_kernel_threads();

    match backend_candle::CandleBackend::load(&config.model_path) {
        // External audit LLMR-002: a generation never outlives the
        // engine's timeout by more than a token.
        Ok(backend) => {
            let backend = backend.with_budget(config.timeout);
            tracing::info!(
                backend = "candle-llama3.1",
                model = %config.model_path.display(),
                "ADE backend loaded"
            );
            return Ok(Arc::new(backend));
        }
        // External audit LLMR-004: a model or tokenizer someone other than
        // root could have written leaves the ADE off — the agent runs on
        // its rules — never on the mock backend.
        Err(e @ AdeError::ModelUntrusted(_)) => return Err(e),
        // External audit LLMR-005: the mock is a substring match on comm
        // and the exec path — strings the process observed chooses
        // (`Allow` at 0.97 for a `cargo` or `git`, a tree kill for a name
        // holding `miner`). A model that fails to load leaves the ADE off;
        // the mock answers only when asked for (`NN_ADE_ALLOW_MOCK=1`:
        // demos, benchmarks on an unsupported architecture).
        Err(e) if !mock_allowed() => return Err(e),
        Err(e) => {
            tracing::warn!(
                ?e,
                model = %config.model_path.display(),
                "candle backend failed to load, falling back to MockBackend (NN_ADE_ALLOW_MOCK=1)"
            );
        }
    }

    Ok(Arc::new(MockBackend::from_model_path(&config.model_path)))
}

/// `NN_ADE_ALLOW_MOCK=1`: a model that fails to load falls back to the mock
/// backend (external audit LLMR-005).
fn mock_allowed() -> bool {
    std::env::var_os("NN_ADE_ALLOW_MOCK").is_some_and(|v| v == "1")
}
