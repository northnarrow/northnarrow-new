//! Hermetic ADE demo for Tappa 6.
//!
//! Runs ten synthetic events through `AdeEngine` using the
//! deterministic MockBackend so the verdict stream is reproducible.
//! Prints each verdict + final p50/p95/p99 stats. Useful both as a
//! smoke check (`cargo xtask ade-demo`) and as the end-of-Tappa
//! latency snapshot.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use common::Event;
use northnarrow_agent::ade::{
    AdeConfig, AdeEngine, EventContext, HostContext, InferenceBackend, MockBackend,
};

#[tokio::main]
async fn main() -> ExitCode {
    let model_path = PathBuf::from(
        std::env::var("ADE_MODEL").unwrap_or_else(|_| AdeConfig::DEFAULT_MODEL_PATH.to_string()),
    );
    let prompt_path = PathBuf::from(
        std::env::var("ADE_PROMPT")
            .unwrap_or_else(|_| AdeConfig::DEFAULT_SYSTEM_PROMPT_PATH.to_string()),
    );

    if !model_path.exists() {
        eprintln!(
            "ade-demo: model not present at {}\n\
             (set ADE_MODEL=/path/to/model.gguf to override; the file is\n\
              never read by the mock backend, only its presence is checked)",
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

    let cfg = AdeConfig {
        model_path: model_path.clone(),
        system_prompt_path: prompt_path,
        timeout: Duration::from_secs(15),
        ..AdeConfig::default()
    };
    let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::from_model_path(&model_path));
    let engine = match AdeEngine::new_with_backend(cfg, backend).await {
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
    let events = synthetic_events();

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

    let snap = engine.stats();
    println!(
        "\nADE stats:\n\
         \ttotal_inferences   = {}\n\
         \tsuccessful_verdicts= {}\n\
         \tmalformed_outputs  = {}\n\
         \ttimeouts           = {}\n\
         \tbackend_errors     = {}\n\
         \tavg_latency_ms     = {:.2}\n\
         \tp50_latency_ms     = {}\n\
         \tp95_latency_ms     = {}\n\
         \tp99_latency_ms     = {}",
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

    ExitCode::SUCCESS
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
