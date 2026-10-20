//! ADE demo and latency snapshot for Tappa 6 (`cargo xtask ade-demo`).
//!
//! Runs ten synthetic events through `AdeEngine::new`, the production
//! load: the Candle backend on the model at `ADE_MODEL` (default
//! [`AdeConfig::DEFAULT_MODEL_PATH`]). Prints each verdict, then the
//! engine's p50/p95/p99 latencies with the backend that produced them.
//!
//! It is not hermetic (external audit WDG-R15): without a model file it
//! exits 2; a model that fails to load is an error, unless
//! `NN_ADE_ALLOW_MOCK=1` lets the engine fall back to `MockBackend`. The
//! mock's verdicts follow from the event alone (a name match, the prompt
//! is never read) and its latency is a fixed sleep, so a run on it
//! measures neither the model nor its speed; the report says so. No CI
//! job runs this example.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use common::Event;
use northnarrow_agent::ade::backend_candle::{pin_threads_before_runtime, ThreadPin};
use northnarrow_agent::ade::stats::AdeStatsSnapshot;
use northnarrow_agent::ade::{AdeConfig, AdeEngine, EventContext, HostContext};

fn main() -> ExitCode {
    // External audit LLMR-009: candle's worker count is pinned while the
    // process is single-threaded (the ADE load no longer writes the
    // environment), then the runtime `#[tokio::main]` built.
    let pin = pin_threads_before_runtime(AdeConfig::default().effective_threads());
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run(pin))
}

async fn run(pin: ThreadPin) -> ExitCode {
    // Surface backend load + warmup messages so we can tell at a
    // glance whether the real Candle backend or the Mock fallback
    // is in use. Without this the runtime falls back silently.
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
    pin.log();

    let model_path = PathBuf::from(
        std::env::var("ADE_MODEL").unwrap_or_else(|_| AdeConfig::DEFAULT_MODEL_PATH.to_string()),
    );
    // The demo defaults to the minimal prompt (~600 tokens) so even
    // a CPU-only VM without AVX2 can complete the full 10-inference
    // bench in a reasonable wall time. Set ADE_PROMPT to the full
    // few-shot prompt for quality benchmarks on AVX2/GPU machines.
    let prompt_path = PathBuf::from(
        std::env::var("ADE_PROMPT").unwrap_or_else(|_| "dataset/system_prompt_minimal.md".into()),
    );

    if !model_path.exists() {
        eprintln!(
            "ade-demo: model not present at {}\n\
             (set ADE_MODEL=/path/to/model.gguf to override; the demo runs the\n\
              real backend and has no hermetic mode)",
            model_path.display()
        );
        return ExitCode::from(2);
    }
    if !prompt_path.exists() {
        eprintln!(
            "ade-demo: prompt not present at {}\n\
             (set ADE_PROMPT=/path/to/prompt.md to override)",
            prompt_path.display()
        );
        return ExitCode::from(2);
    }

    // Tunable via env vars for the latency bench. Defaults are
    // generous enough that an 8B Q4 model on a CPU without AVX2
    // (~1-2 tok/s) can still complete within the wall-time budget.
    let timeout_secs: u64 = std::env::var("ADE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(240);
    let max_output_tokens: usize = std::env::var("ADE_MAX_OUTPUT_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let cfg = AdeConfig {
        model_path: model_path.clone(),
        system_prompt_path: prompt_path,
        timeout: Duration::from_secs(timeout_secs),
        max_output_tokens,
        ..AdeConfig::default()
    };
    // `AdeEngine::new` routes through `build_default_backend`, which
    // loads the real Candle backend; it falls back to `MockBackend` when
    // the GGUF cannot load only with `NN_ADE_ALLOW_MOCK=1` (external audit
    // LLMR-005). The demo does not lock down the choice — whatever the
    // runtime picks is what we measure.
    let engine = match AdeEngine::new(cfg).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("ade-demo: engine init failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "ADE engine ready (backend={}, warmup_ms={})\n",
        engine.backend_name(),
        engine.warmup_latency_ms()
    );

    let host = HostContext::discover();
    let mut events = synthetic_events();
    if let Ok(n) = std::env::var("ADE_DEMO_LIMIT") {
        if let Ok(n) = n.parse::<usize>() {
            events.truncate(n);
        }
    }

    for (label, event) in &events {
        let ctx = EventContext {
            recent_events: vec![],
            host_context: host.clone(),
        };
        match engine.evaluate(event, &ctx).await {
            Ok(v) => {
                println!(
                    "[{label:>11}] verdict={} severity={} confidence={:.2} action={:?} latency_ms={}",
                    v.verdict,
                    v.severity,
                    v.confidence,
                    v.to_response_action(),
                    v.metadata.inference_latency_ms
                );
            }
            Err(e) => {
                println!("[{label:>11}] ERROR: {e}");
            }
        }
    }

    print!(
        "{}",
        stats_report(engine.backend_name(), &model_path, &engine.stats())
    );

    ExitCode::SUCCESS
}

/// The final stats, with the backend and model they were measured on
/// (external audit WDG-R15: the backend was printed only in the preamble).
fn stats_report(backend: &str, model: &Path, snap: &AdeStatsSnapshot) -> String {
    let mut out = format!(
        "\nADE stats (backend={backend}, model={}):\n\
         \ttotal_inferences   = {}\n\
         \tsuccessful_verdicts= {}\n\
         \tmalformed_outputs  = {}\n\
         \ttimeouts           = {}\n\
         \tbackend_errors     = {}\n\
         \tavg_latency_ms     = {:.2}\n\
         \tp50_latency_ms     = {} (backend={backend})\n\
         \tp95_latency_ms     = {} (backend={backend})\n\
         \tp99_latency_ms     = {} (backend={backend})\n",
        model.display(),
        snap.total_inferences,
        snap.successful_verdicts,
        snap.malformed_outputs,
        snap.timeouts,
        snap.backend_errors,
        snap.avg_latency_ms,
        snap.p50_latency_ms,
        snap.p95_latency_ms,
        snap.p99_latency_ms,
    );
    if backend == "mock" {
        out.push_str(
            "\nbackend=mock (NN_ADE_ALLOW_MOCK=1 after a failed model load): the verdicts \
             come from a name match that never reads the prompt, the latencies from a fixed \
             sleep; neither measures the model.\n",
        );
    }
    out
}

fn synthetic_events() -> Vec<(&'static str, Event)> {
    let mk = |pid, comm: &str, filename: &str| Event::ProcessSpawn {
        pid,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: comm.to_string(),
        filename: filename.to_string(),
        timestamp_ns: 0,
        argv: Vec::new(),
        parent_comm: String::new(),
        parent_start_ns: 0,
        start_ns: 0,
        parent_is_kthread: false,
        exe: Default::default(),
        argv_truncated: false,
        filename_truncated: false,
    };
    vec![
        ("xmrig", mk(1001, "xmrig", "/tmp/.cache/x")),
        ("cargo", mk(1002, "cargo", "/home/dev/.cargo/bin/cargo")),
        ("nmap", mk(1003, "nmap", "/usr/bin/nmap")),
        ("lockbit", mk(1004, "lockbit3", "/tmp/lock.elf")),
        ("zk23x", mk(1005, "zk23x", "/opt/internal/zk23x")),
        (
            "strangename",
            mk(1006, "strangename_xyz123", "/tmp/strangename_xyz123"),
        ),
        (
            "rustc",
            mk(
                1007,
                "rustc",
                "/home/dev/.rustup/toolchains/stable/bin/rustc",
            ),
        ),
        ("masscan", mk(1008, "masscan", "/usr/local/bin/masscan")),
        ("xmrig2", mk(1009, "xmrig", "/var/tmp/.x")),
        ("opaque", mk(1010, "obfuscated", "/srv/data/obfuscated")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit WDG-R15 (NN-AUD-438): the latency figures name their
    /// backend, and a mock run says that it measures nothing.
    #[test]
    fn the_stats_name_their_backend() {
        let snap = AdeStatsSnapshot {
            total_inferences: 10,
            successful_verdicts: 10,
            malformed_outputs: 0,
            timeouts: 0,
            backend_errors: 0,
            avg_latency_ms: 120.4,
            p50_latency_ms: 120,
            p95_latency_ms: 121,
            p99_latency_ms: 121,
        };
        let model = Path::new("/var/lib/northnarrow/models/m.gguf");
        let mock = stats_report("mock", model, &snap);
        assert!(
            mock.contains("p50_latency_ms     = 120 (backend=mock)"),
            "{mock}"
        );
        assert!(mock.contains("neither measures the model"), "{mock}");
        let real = stats_report("candle-llama3.1", model, &snap);
        assert!(real.contains("p99_latency_ms     = 121 (backend=candle-llama3.1)"));
        assert!(real.contains("model=/var/lib/northnarrow/models/m.gguf"));
        assert!(!real.contains("neither measures"), "{real}");
    }
}
