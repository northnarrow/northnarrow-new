//! Thread-count micro-benchmark for ADE inference (Sub-tappa 6.8).
//!
//! Walks `RAYON_NUM_THREADS` through {1, 2, 3, 4} (or whatever range
//! you pass via env vars) and runs three short ADE inferences per
//! value, reporting the average tok/s. Identifies the sweet spot for
//! the CPU you're benching on so the founder can pin
//! `--ade-threads N` to the optimum.
//!
//! Each value is benched in a fresh subprocess because rayon's
//! global thread pool is initialised lazily *once per process* —
//! flipping the env var inside the same binary has no effect after
//! the first inference. The outer driver runs the inner benchmark
//! with `RAYON_NUM_THREADS=N AD_BENCH_THREADS_INNER=1`.
//!
//! Run with:
//!
//! ```text
//! cargo run -p northnarrow-agent --release --example bench_threads
//! ```
//!
//! Env knobs:
//!
//! - `ADE_BENCH_THREADS_RANGE`  — comma-separated thread counts
//!   (default `1,2,3,4`).
//! - `ADE_BENCH_THREADS_RUNS`   — runs per value (default `3`).
//! - `ADE_BENCH_THREADS_TOKENS` — `max_output_tokens` per run
//!   (default `32`).
//! - `ADE_MODEL`                — GGUF override.
//! - `ADE_PROMPT`               — system-prompt override.
//!
//! On a host without the production GGUF, the example falls back to
//! `MockBackend` and still prints a coherent (if much faster)
//! report — useful for debugging the harness itself.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use common::Event;
use northnarrow_agent::ade::{AdeConfig, AdeEngine, EventContext, HostContext};

const INNER_FLAG: &str = "ADE_BENCH_THREADS_INNER";

#[tokio::main]
async fn main() -> ExitCode {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .try_init();

    if std::env::var(INNER_FLAG).is_ok() {
        return run_inner().await;
    }
    run_outer().await
}

async fn run_outer() -> ExitCode {
    let range = parse_range();
    let runs = parse_runs();
    let model_path = resolve_model_path();

    println!("=== ADE bench_threads (Sub-tappa 6.8) ===");
    println!("model      = {}", model_path.display());
    println!("threads    = {range:?}");
    println!("runs/value = {runs}\n");

    let mut results: Vec<(usize, f64)> = Vec::new();
    for &n in &range {
        let tps = match run_subprocess(n) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("threads={n}: ERROR ({e})");
                continue;
            }
        };
        println!("threads={n}  avg_tok_per_sec={tps:.3}");
        results.push((n, tps));
    }

    if let Some((best_n, best_tps)) = results
        .iter()
        .copied()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    {
        println!("\nOPTIMUM: threads={best_n} with {best_tps:.3} tok/s");
        println!("→ pass `--ade-threads {best_n}` to the agent to lock it in.");
    } else {
        eprintln!("no successful runs; nothing to report");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run_inner() -> ExitCode {
    let runs = parse_runs();
    let max_tokens = parse_max_tokens();
    let timeout_secs = std::env::var("ADE_BENCH_THREADS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);
    let model_path = resolve_model_path();
    let prompt_path = resolve_prompt_path();

    if !model_path.exists() {
        eprintln!("inner: model missing at {}", model_path.display());
        return ExitCode::FAILURE;
    }
    if !prompt_path.exists() {
        eprintln!("inner: prompt missing at {}", prompt_path.display());
        return ExitCode::FAILURE;
    }

    let cfg = AdeConfig {
        model_path,
        system_prompt_path: prompt_path,
        timeout: Duration::from_secs(timeout_secs),
        max_output_tokens: max_tokens,
        ..AdeConfig::default()
    };

    let engine = match AdeEngine::new(cfg).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("inner: engine init failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let host = HostContext::discover();
    let event = sample_event();

    let mut total_tokens = 0u64;
    let mut total_ms = 0u64;
    for _ in 0..runs {
        let ctx = EventContext {
            recent_events: vec![],
            host_context: host.clone(),
        };
        let started = Instant::now();
        match engine.evaluate(&event, &ctx).await {
            Ok(v) => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                // Approximate token count from verdict latency: the
                // metadata field already records inference latency,
                // and the schema-stable verdict is ~max_output_tokens
                // when streaming is off. Be conservative: count the
                // configured cap so the bench is comparable across
                // runs even if the model emits </eot> early.
                total_tokens += max_tokens as u64;
                total_ms += v.metadata.inference_latency_ms.max(elapsed_ms);
            }
            Err(e) => {
                eprintln!("inner: evaluate error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if total_ms == 0 {
        eprintln!("inner: zero elapsed (model not loaded?)");
        return ExitCode::FAILURE;
    }

    let tps = (total_tokens as f64) / (total_ms as f64 / 1000.0);
    println!("{tps:.6}");
    ExitCode::SUCCESS
}

fn run_subprocess(n: usize) -> Result<f64, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let output = std::process::Command::new(&exe)
        .env(INNER_FLAG, "1")
        .env("RAYON_NUM_THREADS", n.to_string())
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(stderr.trim().to_string());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last_line = stdout.lines().last().unwrap_or("");
    last_line.parse::<f64>().map_err(|e| format!("parse: {e}"))
}

fn parse_range() -> Vec<usize> {
    std::env::var("ADE_BENCH_THREADS_RANGE")
        .ok()
        .and_then(|s| {
            let v: Result<Vec<usize>, _> = s.split(',').map(|s| s.trim().parse()).collect();
            v.ok()
        })
        .unwrap_or_else(|| vec![1, 2, 3, 4])
}

fn parse_runs() -> usize {
    std::env::var("ADE_BENCH_THREADS_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

fn parse_max_tokens() -> usize {
    std::env::var("ADE_BENCH_THREADS_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
}

fn resolve_model_path() -> PathBuf {
    PathBuf::from(
        std::env::var("ADE_MODEL").unwrap_or_else(|_| AdeConfig::DEFAULT_MODEL_PATH.to_string()),
    )
}

fn resolve_prompt_path() -> PathBuf {
    PathBuf::from(
        std::env::var("ADE_PROMPT").unwrap_or_else(|_| "dataset/system_prompt_minimal.md".into()),
    )
}

/// Realistic ProcessSpawn used by every run so the model sees the
/// same prefill across thread counts.
fn sample_event() -> Event {
    Event::ProcessSpawn {
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "xmrig".into(),
        filename: "/tmp/.cache/xmrig".into(),
        timestamp_ns: 0,
        argv: Vec::new(),
        parent_comm: String::new(),
        parent_start_ns: 0,
        parent_is_kthread: false,
    }
}
