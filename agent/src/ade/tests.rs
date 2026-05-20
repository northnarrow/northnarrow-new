//! End-to-end ADE tests using the deterministic `MockBackend`.
//!
//! These tests do NOT need a GGUF model file; they only require the
//! `dataset/system_prompt_v1.md` to be readable from the workspace
//! root, which is always true when `cargo test` runs from there.
//!
//! Anything that wants to exercise the (future) native LLM backend
//! should be `#[ignore]`d so the default test run remains hermetic.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::ade_types::AdeAction;
use common::Event;
use tempfile::NamedTempFile;

use super::*;

fn write_temp_prompt() -> NamedTempFile {
    use std::io::Write;
    let mut f = NamedTempFile::new().expect("temp file");
    writeln!(f, "# stub prompt for tests\nmodel must produce valid JSON.").unwrap();
    f
}

fn write_temp_model() -> NamedTempFile {
    NamedTempFile::new().expect("temp model")
}

fn cfg_with(prompt: &Path, model: &Path) -> AdeConfig {
    AdeConfig {
        model_path: model.to_path_buf(),
        system_prompt_path: prompt.to_path_buf(),
        ..AdeConfig::default()
    }
}

#[tokio::test]
async fn engine_evaluates_and_returns_valid_verdict() {
    let prompt = write_temp_prompt();
    let model = write_temp_model();
    let cfg = cfg_with(prompt.path(), model.path());
    let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::new());
    let engine = AdeEngine::new_with_backend(cfg, backend).await.unwrap();

    let event = Event::ProcessSpawn {
        // Use a non-system pid so the dual-verifier confirms the Kill
        // (Sub-tappa 6.6 rejects Kill against pid < 1000).
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "xmrig".into(),
        filename: "/tmp/x".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };
    let v = engine.evaluate(&event, &ctx).await.unwrap();
    assert_eq!(v.verdict, AdeAction::Kill);
    assert_eq!(v.metadata.backend, "mock");
    assert!(v.metadata.inference_latency_ms < 5000);

    let snap = engine.stats();
    assert_eq!(snap.total_inferences, 1);
    assert_eq!(snap.successful_verdicts, 1);
}

#[tokio::test]
async fn engine_synthesises_escalate_on_malformed_output() {
    use super::error::AdeError;

    struct BrokenBackend;
    impl InferenceBackend for BrokenBackend {
        fn name(&self) -> &str {
            "broken"
        }
        fn quantization(&self) -> &str {
            "none"
        }
        fn model_id(&self) -> &str {
            "broken-model"
        }
        fn generate(
            &self,
            _: &str,
            _: &Event,
            _: usize,
            _: f32,
            _: f32,
        ) -> Result<String, AdeError> {
            Ok("not even close to JSON".into())
        }
    }

    let prompt = write_temp_prompt();
    let model = write_temp_model();
    let cfg = cfg_with(prompt.path(), model.path());
    let engine = AdeEngine::new_with_backend(cfg, Arc::new(BrokenBackend))
        .await
        .unwrap();

    let event = Event::ProcessSpawn {
        pid: 1,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "x".into(),
        filename: "/tmp/x".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };

    let v = engine.evaluate(&event, &ctx).await.unwrap();
    // Malformed → synthetic Escalate
    assert_eq!(v.verdict, AdeAction::Escalate);
    let snap = engine.stats();
    assert_eq!(snap.total_inferences, 1);
    assert_eq!(snap.malformed_outputs, 1);
}

#[tokio::test]
async fn engine_surfaces_timeout_as_error() {
    use std::time::Duration;

    use super::error::AdeError;

    struct SlowBackend;
    impl InferenceBackend for SlowBackend {
        fn name(&self) -> &str {
            "slow"
        }
        fn quantization(&self) -> &str {
            "none"
        }
        fn model_id(&self) -> &str {
            "slow-model"
        }
        fn generate(
            &self,
            _: &str,
            _: &Event,
            _: usize,
            _: f32,
            _: f32,
        ) -> Result<String, AdeError> {
            std::thread::sleep(Duration::from_secs(2));
            Ok("ignored".into())
        }
    }

    let prompt = write_temp_prompt();
    let model = write_temp_model();
    let mut cfg = cfg_with(prompt.path(), model.path());
    cfg.timeout = Duration::from_millis(200);
    let engine = AdeEngine::new_with_backend(cfg, Arc::new(SlowBackend))
        .await
        .unwrap();

    let event = Event::ProcessSpawn {
        pid: 1,
        ppid: 1,
        uid: 0,
        gid: 0,
        comm: "x".into(),
        filename: "/x".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };
    let err = engine.evaluate(&event, &ctx).await.unwrap_err();
    matches!(err, AdeError::Timeout { .. });
    let snap = engine.stats();
    assert_eq!(snap.timeouts, 1);
}

#[tokio::test]
async fn engine_rejects_missing_model_file() {
    let prompt = write_temp_prompt();
    let cfg = AdeConfig {
        model_path: PathBuf::from("/nonexistent/model.gguf"),
        system_prompt_path: prompt.path().to_path_buf(),
        ..AdeConfig::default()
    };
    let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::new());
    let res = AdeEngine::new_with_backend(cfg, backend).await;
    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected ModelMissing error"),
    };
    assert!(matches!(err, AdeError::ModelMissing { .. }));
}

#[tokio::test]
async fn engine_rejects_missing_system_prompt() {
    let model = write_temp_model();
    let cfg = AdeConfig {
        model_path: model.path().to_path_buf(),
        system_prompt_path: PathBuf::from("/nonexistent/prompt.md"),
        ..AdeConfig::default()
    };
    let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::new());
    let res = AdeEngine::new_with_backend(cfg, backend).await;
    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected SystemPromptLoad error"),
    };
    assert!(matches!(err, AdeError::SystemPromptLoad { .. }));
}

/// Tappa 3 regression: an event that the rule engine matches MUST be
/// killed by the rule path before ADE is ever consulted. ADE is
/// strictly a fallback — `engine.evaluate(&event).is_some()` short
/// circuits the main loop, mirroring `agent/src/main.rs::process_event`.
#[tokio::test]
async fn rule_engine_short_circuits_before_ade_for_tmp_payload() {
    use crate::decision::RuleEngine;

    let rule_engine = RuleEngine::with_default_rules();

    // /tmp/nn-test-payload is the canonical Tappa 3 regression event.
    let event = Event::ProcessSpawn {
        pid: 12345,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "nn-test-payload".into(),
        filename: "/tmp/nn-test-payload".into(),
        timestamp_ns: 0,
    };

    let v = rule_engine
        .evaluate(&event)
        .expect("R001 must fire on /tmp/* exec");
    assert_eq!(v.rule_id, "R001_ExecFromTmp");
    assert_eq!(
        v.action,
        common::ResponseAction::KillProcess,
        "Tappa 3 regression: R001 must still kill /tmp/nn-test-payload"
    );
    // The main loop short-circuits when `evaluate` returns Some(_),
    // so ADE is never invoked. The assertion is structural: the rule
    // path returns first.
}

// ---- ignored: requires the founder's GGUF + a real backend.
//
// These are wired up so they compile in CI but stay opt-in. Run with:
//   cargo test --workspace -- --ignored ade::tests::ignored_
#[tokio::test]
#[ignore]
async fn ignored_ade_loads_real_model_path() {
    let cfg = AdeConfig::default();
    if !cfg.model_path.exists() {
        eprintln!(
            "skipping: model not present at {}",
            cfg.model_path.display()
        );
        return;
    }
    if !cfg.system_prompt_path.exists() {
        eprintln!("skipping: prompt not present");
        return;
    }
    let backend: Arc<dyn InferenceBackend> =
        Arc::new(MockBackend::from_model_path(&cfg.model_path));
    let _engine = AdeEngine::new_with_backend(cfg, backend).await.unwrap();
}

/// Sub-tappa 6.1 — exercises the real Candle backend if the
/// founder's GGUF is on disk. Skipped silently when the model is
/// missing (CI). Run with:
///     cargo test -p northnarrow-agent --release \
///         -- --ignored ade::tests::ignored_candle_real_inference
#[tokio::test]
#[ignore]
async fn ignored_candle_real_inference() {
    use crate::ade::backend_candle::CandleBackend;

    let cfg = AdeConfig::default();
    if !cfg.model_path.exists() {
        eprintln!(
            "skipping: model not present at {}",
            cfg.model_path.display()
        );
        return;
    }
    if CandleBackend::locate_tokenizer(&cfg.model_path).is_none() {
        eprintln!("skipping: tokenizer.json not present next to model");
        return;
    }
    if !cfg.system_prompt_path.exists() {
        eprintln!("skipping: prompt not present");
        return;
    }

    let backend = CandleBackend::load(&cfg.model_path).expect("candle load");
    let backend: Arc<dyn InferenceBackend> = Arc::new(backend);
    let engine = AdeEngine::new_with_backend(cfg, backend).await.unwrap();

    let event = Event::ProcessSpawn {
        pid: 9999,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "xmrig".into(),
        filename: "/tmp/.cache/x".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };
    let v = engine.evaluate(&event, &ctx).await.expect("real inference");
    eprintln!("verdict={} confidence={:.2}", v.verdict, v.confidence);
    assert_eq!(v.metadata.backend, "candle-llama3.1");
}

/// Sub-tappa 6.7: end-to-end smoke test that the engine evaluates
/// successfully when wired with a [`RagEngine`]. Uses the
/// deterministic `MockBackend` so the test is hermetic.
#[tokio::test]
async fn engine_with_rag_evaluates_successfully() {
    let prompt = write_temp_prompt();
    let model = write_temp_model();
    let cfg = cfg_with(prompt.path(), model.path());
    let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::new());
    let engine = AdeEngine::new_with_backend(cfg, backend).await.unwrap();

    let rag = Arc::new(crate::rag::RagEngine::with_seed(None).expect("seed kb"));
    let engine = engine.with_rag(rag);
    assert!(engine.has_rag(), "engine should expose has_rag = true");

    let event = Event::ProcessSpawn {
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "xmrig".into(),
        filename: "/tmp/.cache/x".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };
    let v = engine.evaluate(&event, &ctx).await.unwrap();
    assert_eq!(v.verdict, AdeAction::Kill);
}

/// Sub-tappa 6.8 wiring smoke test.
///
/// Two backends emit the same JSON payload but through different
/// trait methods: `WholeBlobBackend` returns it from `generate`,
/// while `ChunkingBackend` streams it byte-by-byte through
/// `generate_streaming`. The engine must produce the same verdict
/// in both cases — streaming is a wall-time optimisation, not a
/// schema change.
#[tokio::test]
async fn evaluate_produces_identical_verdict_with_or_without_streaming() {
    use super::inference::StreamControl;

    const RAW: &str = r#"{
        "schema_version": "1.0.0",
        "trace_id": "00000000-0000-4000-8000-000000000000",
        "timestamp_utc": "2026-05-09T00:00:00Z",
        "language_used": "it-IT",
        "verdict": "Kill",
        "severity": "High",
        "confidence": 0.94,
        "threat_classification": {"family":"x","kind":"process_spawn","novelty":0.1},
        "reasoning": {
            "step_1_extract": "x",
            "step_2_pattern_match": "x",
            "step_3_criticality": "x",
            "step_4_alternative_explanations": {"legitimate_uses": [], "assessment": "x"},
            "step_5_decision": "Kill"
        },
        "evidence": {"primary_indicators": ["x"], "secondary_indicators": []},
        "mitre_attack": {"tactic": ["TA0040"], "technique": ["T1496"]},
        "recommended_action": {"action":"Kill","justification":"x","side_effects":[]},
        "follow_up": {"policy":"Monitor","monitoring_duration_s": 300},
        "metadata": {
            "model_id": "test",
            "model_quantization": "none",
            "backend": "test",
            "host_id": "h",
            "agent_version": "0.0.1",
            "inference_latency_ms": 0
        }
    }"#;

    struct WholeBlobBackend;
    impl InferenceBackend for WholeBlobBackend {
        fn name(&self) -> &str {
            "whole-blob"
        }
        fn quantization(&self) -> &str {
            "none"
        }
        fn model_id(&self) -> &str {
            "whole"
        }
        fn generate(
            &self,
            _p: &str,
            _e: &Event,
            _m: usize,
            _t: f32,
            _tp: f32,
        ) -> Result<String, error::AdeError> {
            Ok(RAW.to_string())
        }
    }

    struct ChunkingBackend;
    impl InferenceBackend for ChunkingBackend {
        fn name(&self) -> &str {
            "chunking"
        }
        fn quantization(&self) -> &str {
            "none"
        }
        fn model_id(&self) -> &str {
            "chunk"
        }
        fn generate(
            &self,
            _p: &str,
            _e: &Event,
            _m: usize,
            _t: f32,
            _tp: f32,
        ) -> Result<String, error::AdeError> {
            // Should never be called — the engine uses
            // generate_streaming, and we override that below.
            Ok(RAW.to_string())
        }
        fn generate_streaming(
            &self,
            _p: &str,
            _e: &Event,
            _m: usize,
            _t: f32,
            _tp: f32,
            mut on_token: Box<dyn FnMut(&str) -> StreamControl + Send>,
        ) -> Result<String, error::AdeError> {
            // Stream one byte at a time — exercises the detector's
            // progressive-feed path. Bail out as soon as the
            // detector says Stop, mirroring CandleBackend behaviour.
            let mut buf = String::new();
            for ch in RAW.chars() {
                let mut tmp = [0u8; 4];
                let s = ch.encode_utf8(&mut tmp);
                buf.push_str(s);
                if let StreamControl::Stop = on_token(s) {
                    return Ok(buf);
                }
            }
            Ok(buf)
        }
    }

    let prompt = write_temp_prompt();
    let model = write_temp_model();

    let cfg_a = cfg_with(prompt.path(), model.path());
    let engine_a = AdeEngine::new_with_backend(cfg_a, Arc::new(WholeBlobBackend))
        .await
        .unwrap();

    let cfg_b = cfg_with(prompt.path(), model.path());
    let engine_b = AdeEngine::new_with_backend(cfg_b, Arc::new(ChunkingBackend))
        .await
        .unwrap();

    let event = Event::ProcessSpawn {
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "xmrig".into(),
        filename: "/tmp/x".into(),
        timestamp_ns: 0,
    };
    let ctx = || EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };

    let va = engine_a.evaluate(&event, &ctx()).await.unwrap();
    let vb = engine_b.evaluate(&event, &ctx()).await.unwrap();

    assert_eq!(va.verdict, vb.verdict);
    assert_eq!(va.severity, vb.severity);
    assert_eq!(
        va.threat_classification.family,
        vb.threat_classification.family
    );
    assert_eq!(va.recommended_action.action, vb.recommended_action.action);
}

/// Tappa 6.9.7 P4 item 6 / §13 canary-default-flip checklist #1 —
/// **6.7 canary-parity guarantee.** With no `RagEngine` wired
/// (`rag: None`, the `new_with_backend` default), the assembled prompt
/// MUST NOT contain the RAG block: the prompt-build path is then
/// byte-identical to pre-6.7. This is what guarantees every XAI
/// evidence chain produced WITHOUT RAG stays reproducible by an
/// auditor running RAG-off. (RAG-on splices a
/// `=== RELEVANT CYBERSEC KNOWLEDGE ... ===` block — see
/// `ade::rag_integration::format_rag_block`.)
#[tokio::test]
async fn rag_none_prompt_is_byte_identical_to_pre_6_7() {
    let prompt = write_temp_prompt();
    let model = write_temp_model();
    let cfg = cfg_with(prompt.path(), model.path());
    // new_with_backend ⇒ rag: None (no with_rag) — the pre-6.7 path.
    let engine = AdeEngine::new_with_backend(cfg, Arc::new(MockBackend::new()))
        .await
        .unwrap();
    let event = Event::ProcessSpawn {
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "xmrig".into(),
        filename: "/tmp/x".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };
    let assembled = engine
        .assembled_prompt(&event, &ctx)
        .expect("a prompt is produced (no high-injection short-circuit)");
    assert!(
        !assembled.contains("RELEVANT CYBERSEC KNOWLEDGE"),
        "rag:None must NOT splice the RAG block — pre-6.7 parity broken"
    );
    // And the decision path is unaffected (deterministic MockBackend).
    let v = engine.evaluate(&event, &ctx).await.unwrap();
    assert_eq!(v.verdict, AdeAction::Kill);
}

/// Tappa 6.9.7.1 P5.1 — **Phase-A/B/C/D format contract (frozen).**
/// AMENDS the P5 Q4(a) freeze: production conforms to the compact
/// `RAG_CONTEXT:` training format (Phase A already trained, 100% PASS;
/// Phase B/C/D off-repo). This byte-exact snapshot IS the contract —
/// any drift here is a deliberate breaking commit requiring dataset
/// regeneration. The 3-doc input exercises Sigma severity recovery
/// (`\nLevel: high` ⇒ "high severity"), MitreTechnique and ThreatTool
/// (the generic `Intel:` line). Same ids/titles/similarities as the
/// retired P5 `..._phase_c_contract` test, for continuity.
#[test]
fn format_rag_block_byte_stable_phase_abcd_contract() {
    use common::rag_types::{KbCategory, RagDocument, RagResult};
    let result = RagResult {
        documents: vec![
            RagDocument {
                id: "attack:T1059.001".into(),
                category: KbCategory::MitreTechnique,
                title: "PowerShell".into(),
                content: "Adversaries may abuse PowerShell for execution.".into(),
                similarity: 1.0,
            },
            RagDocument {
                id: "sigma:abc-123".into(),
                category: KbCategory::SigmaRule,
                title: "Suspicious Curl Usage".into(),
                content: "Detects curl adding a file to a web request.\nLevel: high".into(),
                similarity: 0.73,
            },
            RagDocument {
                id: "tool_cobaltstrike".into(),
                category: KbCategory::ThreatTool,
                title: "Cobalt Strike".into(),
                content: "Commercial post-exploitation C2 framework.".into(),
                similarity: 0.41,
            },
        ],
        query_embedding_ms: 0,
        retrieval_ms: 0,
    };
    let out = format_rag_block(&result).expect("non-empty result ⇒ Some");
    let expected = "RAG_CONTEXT:\nIntel: PowerShell.\nSigma Intel (high severity): Suspicious Curl Usage.\nIntel: Cobalt Strike.\n\n";
    assert_eq!(
        out, expected,
        "format_rag_block drifted from the frozen Phase-A/B/C/D contract — \
         a deliberate change requires dataset regeneration"
    );
}

/// Tappa 6.9.7.1 P5.1 — locks the **Sigma severity fallback** path:
/// a SigmaRule whose `content` has no standalone `Level:`/`Severity:`
/// line degrades to the title-only `Sigma Intel:` form (never a
/// false-positive substring match on prose).
#[test]
fn format_rag_block_sigma_fallback_when_severity_absent() {
    use common::rag_types::{KbCategory, RagDocument, RagResult};
    let result = RagResult {
        documents: vec![RagDocument {
            id: "sigma:no-level".into(),
            category: KbCategory::SigmaRule,
            title: "Suspicious Curl Usage".into(),
            // Inline-prose "Severity: high." is NOT a standalone line.
            content: "Detection: curl adds a file. Severity: high. FP: none.".into(),
            similarity: 0.66,
        }],
        query_embedding_ms: 0,
        retrieval_ms: 0,
    };
    let out = format_rag_block(&result).expect("non-empty result ⇒ Some");
    assert_eq!(out, "RAG_CONTEXT:\nSigma Intel: Suspicious Curl Usage.\n\n");
}

/// P5 task-3 (AMENDED Tappa 6.9.7.1 P5.1) — env ON + valid index ⇒
/// the RAG block IS spliced into the assembled prompt (the canary-on
/// path). Complements the P4 `rag_none_prompt_is_byte_identical_to
/// _pre_6_7` (canary-off). P5.1: asserts the compact `RAG_CONTEXT:`
/// header + the rendered summary line; the per-doc **id is by design
/// no longer in the prompt** (delegated to the Tappa 13 backend log).
#[tokio::test]
async fn with_rag_splices_block_into_assembled_prompt() {
    use std::sync::Arc;
    let prompt = write_temp_prompt();
    let model = write_temp_model();
    let cfg = cfg_with(prompt.path(), model.path());
    let engine = AdeEngine::new_with_backend(cfg, Arc::new(MockBackend::new()))
        .await
        .unwrap();

    // Fixture KB whose content matches the ProcessSpawn-derived rag
    // query ("process {comm} from {filename}").
    let jl = tempfile::tempdir().unwrap();
    std::fs::write(
        jl.path().join("fix.jsonl"),
        "{\"author\":null,\"category\":\"mitre_technique\",\"content\":\"zqxjproc suspicious process technique\",\"id\":\"attack:T9999\",\"platform\":\"\",\"severity\":\"\",\"source_ref\":\"attack:T9999\",\"title\":\"ZQXJ Proc\"}\n",
    )
    .unwrap();
    let ix = tempfile::tempdir().unwrap();
    let rag =
        super::super::rag::rag_canary(true, jl.path(), ix.path()).expect("valid paths ⇒ Some");
    let engine = engine.with_rag(Arc::new(rag));

    let event = Event::ProcessSpawn {
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "zqxjproc".into(),
        filename: "/tmp/zqxjproc".into(),
        timestamp_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };
    let assembled = engine
        .assembled_prompt(&event, &ctx)
        .expect("prompt produced");
    assert!(
        assembled.contains("RAG_CONTEXT:\n"),
        "RAG-on must splice the compact knowledge block"
    );
    assert!(
        assembled.contains("Intel: ZQXJ Proc."),
        "the retrieved fixture doc's summary line must appear in the spliced block"
    );
}
