//! Minimal candle backend smoke test for Sub-tappa 6.1.
//!
//! Loads the Foundation-Sec-8B-Reasoning GGUF, sends a 30-token
//! prompt, asks for at most 4 output tokens, and prints prefill +
//! decode timing. This bypasses the system prompt + full event
//! formatting so the floor of per-prompt latency on the dev VM
//! (no AVX2/FMA) can actually be measured.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use common::Event;
use northnarrow_agent::ade::backend_candle::CandleBackend;
use northnarrow_agent::ade::inference::InferenceBackend;

#[tokio::main]
async fn main() -> ExitCode {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();

    let model_path =
        PathBuf::from(std::env::var("ADE_MODEL").unwrap_or_else(|_| {
            "/home/forty/models/foundation-sec-8b-reasoning-q4_k_m.gguf".into()
        }));
    if !model_path.exists() {
        eprintln!("smoke: model not at {}", model_path.display());
        return ExitCode::from(2);
    }

    println!("loading {} ...", model_path.display());
    let load_started = Instant::now();
    let backend = match CandleBackend::load(&model_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("load failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let load_ms = load_started.elapsed().as_millis();
    println!("loaded in {load_ms} ms");
    println!("running warmup...");
    let warmup_started = Instant::now();
    backend.warmup().expect("warmup");
    let warmup_ms = warmup_started.elapsed().as_millis();
    println!("warmup_ms={warmup_ms}");

    let prompt = "Tell me one word.";
    let dummy_event = Event::ProcessSpawn {
        pid: 1,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "x".into(),
        filename: "/x".into(),
        timestamp_ns: 0,
        argv: Vec::new(),
        parent_comm: String::new(),
        parent_start_ns: 0,
    };

    println!("\nrunning a 4-token decode on a 5-word prompt...");
    let started = Instant::now();
    let res = backend.generate(prompt, &dummy_event, 4, 0.0, 1.0);
    let total_ms = started.elapsed().as_millis();
    match res {
        Ok(text) => {
            println!("OK total_ms={total_ms} output={text:?}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("ERR total_ms={total_ms} {e}");
            ExitCode::FAILURE
        }
    }
}
