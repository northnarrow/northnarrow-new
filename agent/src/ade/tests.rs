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
        pid: 42,
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
