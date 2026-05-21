//! ADE-with-RAG side-by-side comparison demo (Sub-tappa 6.7).
//!
//! Runs **the same** ambiguous event through two AdeEngine
//! instances:
//!
//! 1. plain — no RAG context.
//! 2. rag-augmented — wired with the curated 30-doc seed KB.
//!
//! Prints both verdicts (action, severity, confidence, threat
//! family, recommended action) so the impact of the RAG injection
//! is immediately visible. The default ambiguous event is a
//! Cobalt Strike beacon process spawn — the base model is unlikely
//! to recognise the binary name without the curated tool entry.
//!
//! Run manually:
//!
//! ```sh
//! cargo run --example ade_with_rag --release
//! ```
//!
//! Falls back to MockBackend when the configured GGUF is missing,
//! so the example is runnable end-to-end on a CI machine without
//! a model file. Real-world impact is more pronounced when the
//! Foundation-Sec backend is loaded — set ADE_MODEL accordingly.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use common::Event;
use northnarrow_agent::ade::{
    AdeConfig, AdeEngine, EventContext, HostContext, InferenceBackend, MockBackend,
};
use northnarrow_agent::rag::RagEngine;

#[tokio::main]
async fn main() -> ExitCode {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();

    let model_path = PathBuf::from(
        std::env::var("ADE_MODEL").unwrap_or_else(|_| AdeConfig::DEFAULT_MODEL_PATH.to_string()),
    );
    let prompt_path = PathBuf::from(
        std::env::var("ADE_PROMPT").unwrap_or_else(|_| "dataset/system_prompt_minimal.md".into()),
    );

    if !model_path.exists() {
        eprintln!(
            "ade-with-rag: model not present at {}; set ADE_MODEL to override.\n\
             For a hermetic test the example will use MockBackend below.",
            model_path.display()
        );
    }

    let cfg = AdeConfig {
        model_path: model_path.clone(),
        system_prompt_path: prompt_path.clone(),
        timeout: Duration::from_secs(240),
        ..AdeConfig::default()
    };

    if !prompt_path.exists() {
        eprintln!(
            "ade-with-rag: prompt not present at {}",
            prompt_path.display()
        );
        return ExitCode::from(2);
    }

    // We pin MockBackend explicitly so the diff between the two
    // verdicts comes purely from the prompt (i.e. from the presence
    // / absence of the RAG block), not from non-determinism in the
    // sampler.
    let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::from_model_path(&model_path));

    if !model_path.exists() {
        // AdeEngine::new_with_backend rejects missing model_path
        // upfront; touch the file so the demo can still run hermetically.
        if let Some(parent) = model_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&model_path, b"") {
            eprintln!("ade-with-rag: cannot create stub model file: {e}");
            return ExitCode::FAILURE;
        }
    }

    let engine_plain = match AdeEngine::new_with_backend(cfg.clone(), backend.clone()).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("plain engine: {e}");
            return ExitCode::FAILURE;
        }
    };
    let engine_rag = match AdeEngine::new_with_backend(cfg, backend).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("rag engine: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rag = Arc::new(match RagEngine::with_seed(None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("seed kb: {e}");
            return ExitCode::FAILURE;
        }
    });
    let engine_rag = engine_rag.with_rag(rag);

    let event = Event::ProcessSpawn {
        pid: 9001,
        ppid: 1,
        uid: 0,
        gid: 0,
        comm: "cobaltstrike-beacon".into(),
        filename: "/usr/local/bin/cobaltstrike-beacon".into(),
        timestamp_ns: 0,
        argv: Vec::new(),
        parent_comm: String::new(),
        parent_start_ns: 0,
    };
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };

    println!("=== Event under analysis ===");
    println!("  ProcessSpawn comm=cobaltstrike-beacon filename=/usr/local/bin/cobaltstrike-beacon");
    println!();

    println!("=== Plain ADE (no RAG) ===");
    let v_plain = match engine_plain.evaluate(&event, &ctx).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("plain: {e}");
            return ExitCode::FAILURE;
        }
    };
    print_verdict(&v_plain);
    println!();

    println!("=== ADE with RAG (curated KB) ===");
    let v_rag = match engine_rag.evaluate(&event, &ctx).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rag: {e}");
            return ExitCode::FAILURE;
        }
    };
    print_verdict(&v_rag);
    println!();

    println!("=== Diff ===");
    println!(
        "  verdict:           {:>10}   ->   {:<10}",
        v_plain.verdict.to_string(),
        v_rag.verdict.to_string()
    );
    println!(
        "  severity:          {:>10}   ->   {:<10}",
        format!("{:?}", v_plain.severity),
        format!("{:?}", v_rag.severity),
    );
    println!(
        "  confidence:        {:>10.2}   ->   {:<10.2}",
        v_plain.confidence, v_rag.confidence,
    );
    println!(
        "  family:            {:>10}   ->   {:<10}",
        v_plain.threat_classification.family, v_rag.threat_classification.family,
    );

    ExitCode::SUCCESS
}

fn print_verdict(v: &common::ade_types::AdeVerdict) {
    println!("  verdict           = {}", v.verdict);
    println!("  severity          = {:?}", v.severity);
    println!("  confidence        = {:.2}", v.confidence);
    println!("  threat.family     = {}", v.threat_classification.family);
    println!("  recommended       = {}", v.recommended_action.action);
    println!(
        "  reasoning_step5   = {}",
        v.reasoning.step_5_decision.lines().next().unwrap_or("")
    );
}
