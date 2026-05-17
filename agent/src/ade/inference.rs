//! Inference backend abstraction + the `MockBackend` used by CI.
//!
//! ## Why an abstraction
//!
//! The trait lets the real LLM and a deterministic stub share one
//! call path. `MockBackend` produces deterministic, schema-valid
//! outputs regardless of input, keeping CI fast (no GGUF, no FFI) and
//! letting parser / escalate / stats / wiring be exercised end-to-end
//! on every push.
//!
//! ## Which backend ships (current state)
//!
//! Since **Sub-tappa 6.1** the default is the real candle Llama-3.1
//! backend ([`super::backend_candle`], Foundation-Sec-8B-Reasoning
//! Q4_K_M GGUF) — see that module's header for the authoritative
//! rationale (the earlier gemma4 blocker is historical: the model
//! choice moved to a Llama-3.1-architecture model with native candle
//! support). [`MockBackend`] is now the CI / load-failure fallback
//! only, NOT the production default. `build_default_backend` in
//! [`super`] selects candle and falls back to the mock if the GGUF
//! cannot be loaded.

use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;

use common::ade_types::{
    AdeAction, AdeMetadata, AdeSeverity, AdeVerdict, AlternativeExplanations, EscalationPackage,
    EscalationTier, Evidence, FollowUp, FollowUpPolicy, MitreAttack, ReasoningSteps,
    RecommendedAction, ThreatClassification, ADE_SCHEMA_VERSION,
};
use common::Event;

use super::error::AdeError;

/// Chat template a backend wants the engine to apply when assembling
/// the prompt. The engine uses [`super::prompt::PromptParts`] as the
/// canonical split; this enum just selects the wrapper format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatTemplate {
    /// Plain `system\n\nuser` concatenation. Used by `MockBackend`
    /// (which ignores prompt content anyway) and any backend whose
    /// model wasn't trained with a chat template.
    Plain,
    /// Llama 3.1 `<|begin_of_text|>` + `<|start_header_id|>` markers.
    Llama3,
}

/// Token-streaming control returned from a `generate_streaming`
/// callback (Sub-tappa 6.8). The backend checks this after every
/// decoded token and stops the loop when `Stop` is returned, freeing
/// the engine to terminate inference as soon as the verdict JSON is
/// complete instead of running to `max_tokens`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamControl {
    Continue,
    Stop,
}

/// Pluggable inference backend.
///
/// Implementations must be `Send + Sync` so the engine can hand out
/// `Arc<dyn InferenceBackend>` across tokio tasks. `generate` is
/// expected to block; the engine wraps it in `spawn_blocking`.
pub trait InferenceBackend: Send + Sync {
    /// Display name (`"mock"`, `"candle-llama3.1"`, …).
    fn name(&self) -> &str;

    /// Quantization label exposed in metadata (`"Q4_K_M"`, `"f16"`, …).
    fn quantization(&self) -> &str;

    /// Model identifier exposed in metadata.
    fn model_id(&self) -> &str;

    /// Chat template format the backend expects. Defaults to plain.
    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate::Plain
    }

    /// Synchronous text-completion. Returns the raw model output
    /// without any post-processing (the engine's parser strips
    /// `<think>` blocks and code fences).
    fn generate(
        &self,
        prompt: &str,
        focal_event: &Event,
        max_tokens: usize,
        temperature: f32,
        top_p: f32,
    ) -> Result<String, AdeError>;

    /// Streaming text-completion (Sub-tappa 6.8).
    ///
    /// Calls `on_token` once per decoded token chunk and stops the
    /// decode loop the moment the callback returns
    /// [`StreamControl::Stop`]. The default implementation falls
    /// back to [`Self::generate`] and emits the full output as a
    /// single callback at the end — every backend stays compatible
    /// without overriding, only `CandleBackend` actually streams
    /// per-token.
    ///
    /// Returns the full text generated up to (and including) the
    /// terminating chunk, regardless of how the loop ended.
    fn generate_streaming(
        &self,
        prompt: &str,
        focal_event: &Event,
        max_tokens: usize,
        temperature: f32,
        top_p: f32,
        mut on_token: Box<dyn FnMut(&str) -> StreamControl + Send>,
    ) -> Result<String, AdeError> {
        let raw = self.generate(prompt, focal_event, max_tokens, temperature, top_p)?;
        // Emit the entire output as one chunk so callers that fold
        // a streaming JSON detector still see every byte. We ignore
        // the returned StreamControl: there is nothing else to feed.
        let _ = on_token(&raw);
        Ok(raw)
    }

    /// Best-effort warmup. Default impl is a no-op; backends that
    /// have a measurable cold start should override it.
    fn warmup(&self) -> Result<(), AdeError> {
        Ok(())
    }
}

/// Deterministic, schema-valid backend used in CI and dev.
///
/// The decision tree mirrors the system prompt's few-shot patterns so
/// the demo run produces meaningful verdicts without an actual model.
/// All outputs are JSON strings that the parser will accept.
pub struct MockBackend {
    model_id: String,
    quantization: String,
    /// `Some` when constructed via `from_model_path`, used only for
    /// diagnostic logging.
    declared_path: Option<PathBuf>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            model_id: "mock-deterministic".into(),
            quantization: "none".into(),
            declared_path: None,
        }
    }

    /// Builds a MockBackend that *advertises* the GGUF the user
    /// configured even though it never reads it. This keeps the
    /// metadata field accurate for the demo run.
    pub fn from_model_path(path: &Path) -> Self {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("gemma-4-E4B-it-Q4_K_M")
            .to_string();
        Self {
            model_id: id,
            quantization: "Q4_K_M".into(),
            declared_path: Some(path.to_path_buf()),
        }
    }

    pub fn declared_path(&self) -> Option<&Path> {
        self.declared_path.as_deref()
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InferenceBackend for MockBackend {
    fn name(&self) -> &str {
        "mock"
    }

    fn quantization(&self) -> &str {
        &self.quantization
    }

    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn generate(
        &self,
        _prompt: &str,
        focal_event: &Event,
        _max_tokens: usize,
        _temperature: f32,
        _top_p: f32,
    ) -> Result<String, AdeError> {
        // Sleep a tiny bit so latency histograms show non-zero values
        // and the demo log reads naturally. Skip in test builds so
        // unit tests stay fast.
        #[cfg(not(test))]
        std::thread::sleep(std::time::Duration::from_millis(120));

        let verdict = synth_verdict(focal_event, self.model_id(), self.quantization());
        serde_json::to_string(&verdict)
            .map_err(|e| AdeError::Backend(format!("mock serialise: {e}")))
    }
}

/// Heuristic synthesis used by `MockBackend`. Pattern-matches the
/// classic few-shot examples from `dataset/system_prompt_v1.md`.
fn synth_verdict(event: &Event, model_id: &str, quantization: &str) -> AdeVerdict {
    let now = Utc::now().to_rfc3339();
    let trace_id = Uuid::new_v4().to_string();

    let pid_for_pkg;
    let filename_for_pkg;
    let mut category = MockCategory::Unknown;

    match event {
        Event::ProcessSpawn {
            pid,
            comm,
            filename,
            ..
        } => {
            pid_for_pkg = *pid;
            filename_for_pkg = filename.clone();
            category = classify_process(comm, filename);
        }
        Event::FileOpen { pid, filename, .. } => {
            pid_for_pkg = *pid;
            filename_for_pkg = filename.clone();
            category = MockCategory::Unknown;
        }
        Event::ExecCheck { pid, filename, .. } => {
            pid_for_pkg = *pid;
            filename_for_pkg = filename.clone();
            category = MockCategory::Unknown;
        }
        Event::TcpConnect { pid, comm, .. } | Event::DnsQuery { pid, comm, .. } => {
            pid_for_pkg = *pid;
            filename_for_pkg = comm.clone();
        }
        // FsProtectDenial is short-circuited before ADE in main.rs.
        // Unreachable in practice; kept for exhaustiveness.
        Event::FsProtectDenial { pid, operation, .. } => {
            pid_for_pkg = *pid;
            filename_for_pkg = format!("fs_protect_denial:{operation}");
        }
    }

    let metadata = AdeMetadata {
        model_id: model_id.into(),
        model_quantization: quantization.into(),
        backend: "mock".into(),
        host_id: "runtime".into(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        inference_latency_ms: 120,
    };

    match category {
        MockCategory::DevActivity => allow_verdict(trace_id, now, metadata),
        MockCategory::Cryptominer => kill_verdict(trace_id, now, metadata),
        MockCategory::Ransomware => killtree_verdict(trace_id, now, metadata),
        MockCategory::Recon => alert_verdict(trace_id, now, metadata),
        MockCategory::Unknown => {
            escalate_verdict(trace_id, now, metadata, pid_for_pkg, filename_for_pkg)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MockCategory {
    DevActivity,
    Cryptominer,
    Ransomware,
    Recon,
    Unknown,
}

fn classify_process(comm: &str, filename: &str) -> MockCategory {
    let c = comm.to_ascii_lowercase();
    let f = filename.to_ascii_lowercase();
    if c == "xmrig" || f.contains("xmrig") || c.contains("miner") {
        return MockCategory::Cryptominer;
    }
    if c.starts_with("lockbit") || c.contains("ransom") || c == "wannacry" {
        return MockCategory::Ransomware;
    }
    if c == "nmap" || c == "masscan" || c == "rustscan" {
        return MockCategory::Recon;
    }
    if c == "cargo"
        || c == "rustc"
        || c == "go"
        || c == "make"
        || c == "git"
        || f.contains("/.cargo/")
        || f.contains("/.rustup/")
    {
        return MockCategory::DevActivity;
    }
    MockCategory::Unknown
}

fn allow_verdict(trace_id: String, ts: String, metadata: AdeMetadata) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.into(),
        trace_id,
        timestamp_utc: ts,
        language_used: "it-IT".into(),
        verdict: AdeAction::Allow,
        severity: AdeSeverity::None,
        confidence: 0.97,
        threat_classification: ThreatClassification {
            family: "dev_activity".into(),
            kind: "process_spawn".into(),
            novelty: 0.05,
        },
        reasoning: ReasoningSteps {
            step_1_extract: "Tool di sviluppo standard, path utente, comportamento di build."
                .into(),
            step_2_pattern_match: "Pattern benigno noto, nessun MITRE rilevante.".into(),
            step_3_criticality: "Nessun danno irreversibile.".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["build di sviluppo".into(), "CI locale".into()],
                assessment: "Altamente plausibile.".into(),
            },
            step_5_decision: "Allow.".into(),
        },
        evidence: Evidence {
            primary_indicators: vec!["dev tool comm".into()],
            secondary_indicators: vec![],
            correlation_window_s: None,
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0002".into()],
            technique: vec![],
        },
        recommended_action: RecommendedAction {
            action: AdeAction::Allow,
            justification: "Attività di sviluppo legittima.".into(),
            side_effects: vec![],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::None,
            monitoring_duration_s: None,
        },
        escalation_tier: None,
        escalation_package: None,
        metadata,
    }
}

fn kill_verdict(trace_id: String, ts: String, metadata: AdeMetadata) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.into(),
        trace_id,
        timestamp_utc: ts,
        language_used: "it-IT".into(),
        verdict: AdeAction::Kill,
        severity: AdeSeverity::High,
        confidence: 0.94,
        threat_classification: ThreatClassification {
            family: "cryptominer".into(),
            kind: "process_spawn".into(),
            novelty: 0.10,
        },
        reasoning: ReasoningSteps {
            step_1_extract: "Eseguibile con signature di cryptominer noto (xmrig).".into(),
            step_2_pattern_match: "Famiglia xmrig, T1496 Resource Hijacking.".into(),
            step_3_criticality: "Reversibile via SIGKILL, ma costoso lasciato girare.".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["mining personale autorizzato".into()],
                assessment: "Improbabile in contesto enterprise.".into(),
            },
            step_5_decision: "Kill, severity High.".into(),
        },
        evidence: Evidence {
            primary_indicators: vec!["xmrig comm".into()],
            secondary_indicators: vec![],
            correlation_window_s: None,
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0040".into()],
            technique: vec!["T1496".into()],
        },
        recommended_action: RecommendedAction {
            action: AdeAction::Kill,
            justification: "Cryptominer noto, basso rischio di falso positivo.".into(),
            side_effects: vec!["interruzione del processo".into()],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::Monitor,
            monitoring_duration_s: Some(300),
        },
        escalation_tier: None,
        escalation_package: None,
        metadata,
    }
}

fn killtree_verdict(trace_id: String, ts: String, metadata: AdeMetadata) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.into(),
        trace_id,
        timestamp_utc: ts,
        language_used: "it-IT".into(),
        verdict: AdeAction::KillTree,
        severity: AdeSeverity::Critical,
        confidence: 0.98,
        threat_classification: ThreatClassification {
            family: "ransomware".into(),
            kind: "process_spawn".into(),
            novelty: 0.10,
        },
        reasoning: ReasoningSteps {
            step_1_extract: "Comm corrispondente a famiglia ransomware nota.".into(),
            step_2_pattern_match: "T1486 Data Encrypted for Impact.".into(),
            step_3_criticality: "IRREVERSIBILE: cifratura attiva.".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["test di sicurezza in sandbox".into()],
                assessment: "Esclusa: host produttivo.".into(),
            },
            step_5_decision: "KillTree immediato.".into(),
        },
        evidence: Evidence {
            primary_indicators: vec!["ransomware comm".into()],
            secondary_indicators: vec![],
            correlation_window_s: Some(30),
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0040".into()],
            technique: vec!["T1486".into()],
        },
        recommended_action: RecommendedAction {
            action: AdeAction::KillTree,
            justification: "Cifratura in corso.".into(),
            side_effects: vec!["possibile perdita dei file già cifrati".into()],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::Recheck,
            monitoring_duration_s: Some(60),
        },
        escalation_tier: None,
        escalation_package: None,
        metadata,
    }
}

fn alert_verdict(trace_id: String, ts: String, metadata: AdeMetadata) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.into(),
        trace_id,
        timestamp_utc: ts,
        language_used: "it-IT".into(),
        verdict: AdeAction::Alert,
        severity: AdeSeverity::Medium,
        confidence: 0.65,
        threat_classification: ThreatClassification {
            family: "recon".into(),
            kind: "process_spawn".into(),
            novelty: 0.20,
        },
        reasoning: ReasoningSteps {
            step_1_extract: "Tool di scansione di rete dual-use.".into(),
            step_2_pattern_match: "Pattern T1595, dual-use legittimo/malevolo.".into(),
            step_3_criticality: "Reversibile, rumore di rete.".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["pentest autorizzato".into(), "inventory IT".into()],
                assessment: "Plausibile in contesti IT.".into(),
            },
            step_5_decision: "Alert, monitoraggio attivo.".into(),
        },
        evidence: Evidence {
            primary_indicators: vec!["scanner comm".into()],
            secondary_indicators: vec![],
            correlation_window_s: Some(600),
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0007".into()],
            technique: vec!["T1595.002".into()],
        },
        recommended_action: RecommendedAction {
            action: AdeAction::Alert,
            justification: "Strumento dual-use, contesto incerto.".into(),
            side_effects: vec![],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::Monitor,
            monitoring_duration_s: Some(600),
        },
        escalation_tier: None,
        escalation_package: None,
        metadata,
    }
}

fn escalate_verdict(
    trace_id: String,
    ts: String,
    metadata: AdeMetadata,
    pid: u32,
    filename: String,
) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.into(),
        trace_id,
        timestamp_utc: ts,
        language_used: "it-IT".into(),
        verdict: AdeAction::Escalate,
        severity: AdeSeverity::Medium,
        confidence: 0.35,
        threat_classification: ThreatClassification {
            family: "unknown".into(),
            kind: "process_spawn".into(),
            novelty: 0.85,
        },
        reasoning: ReasoningSteps {
            step_1_extract: format!("Eseguibile pid={pid} filename={filename}"),
            step_2_pattern_match: "Nessun pattern noto, nome ignoto al catalogo.".into(),
            step_3_criticality: "Indeterminato senza analisi del binario.".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec![
                    "tool interno custom".into(),
                    "build artifact aziendale".into(),
                ],
                assessment: "Plausibile, serve conferma operativa.".into(),
            },
            step_5_decision: "Escalate Tier1 per mancanza di segnali.".into(),
        },
        evidence: Evidence {
            primary_indicators: vec!["nome ignoto".into()],
            secondary_indicators: vec![],
            correlation_window_s: None,
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0002".into()],
            technique: vec![],
        },
        recommended_action: RecommendedAction {
            action: AdeAction::Escalate,
            justification: "Confidence sotto soglia.".into(),
            side_effects: vec!["latenza analista".into()],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::None,
            monitoring_duration_s: None,
        },
        escalation_tier: Some(EscalationTier::Tier1Review),
        escalation_package: Some(EscalationPackage {
            summary: "Binario sconosciuto, fuori da pattern noti.".into(),
            key_questions: vec![
                "È un artefatto di build interno?".into(),
                "Chi ha creato il binario?".into(),
            ],
            raw_model_output: None,
            source_event_pid: Some(pid),
            source_event_filename: Some(filename),
        }),
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::parser::VerdictParser;

    fn run_mock(event: Event) -> AdeVerdict {
        let backend = MockBackend::new();
        let raw = backend.generate("prompt", &event, 1024, 0.3, 0.9).unwrap();
        let parser = VerdictParser::new();
        parser.parse(&raw).expect("mock output is always valid")
    }

    #[test]
    fn mock_classifies_xmrig_as_kill() {
        let v = run_mock(Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "xmrig".into(),
            filename: "/tmp/.cache/x".into(),
            timestamp_ns: 0,
        });
        assert_eq!(v.verdict, AdeAction::Kill);
        assert_eq!(v.severity, AdeSeverity::High);
    }

    #[test]
    fn mock_classifies_cargo_as_allow() {
        let v = run_mock(Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "cargo".into(),
            filename: "/home/dev/.cargo/bin/cargo".into(),
            timestamp_ns: 0,
        });
        assert_eq!(v.verdict, AdeAction::Allow);
        assert_eq!(v.severity, AdeSeverity::None);
    }

    #[test]
    fn mock_classifies_lockbit_as_killtree() {
        let v = run_mock(Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "lockbit3".into(),
            filename: "/tmp/lock.elf".into(),
            timestamp_ns: 0,
        });
        assert_eq!(v.verdict, AdeAction::KillTree);
        assert_eq!(v.severity, AdeSeverity::Critical);
    }

    #[test]
    fn mock_classifies_unknown_as_escalate() {
        let v = run_mock(Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "zk23x".into(),
            filename: "/opt/internal/zk23x".into(),
            timestamp_ns: 0,
        });
        assert_eq!(v.verdict, AdeAction::Escalate);
        assert_eq!(v.escalation_tier, Some(EscalationTier::Tier1Review));
        assert!(v.escalation_package.is_some());
    }

    #[test]
    fn mock_classifies_nmap_as_alert() {
        let v = run_mock(Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "nmap".into(),
            filename: "/usr/bin/nmap".into(),
            timestamp_ns: 0,
        });
        assert_eq!(v.verdict, AdeAction::Alert);
        assert_eq!(v.severity, AdeSeverity::Medium);
    }
}
