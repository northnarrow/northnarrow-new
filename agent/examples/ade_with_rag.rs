//! ADE-with-RAG side-by-side comparison demo (Sub-tappa 6.7).
//!
//! Runs **the same** ambiguous event through two AdeEngine
//! instances that share one backend:
//!
//! 1. plain — no RAG context.
//! 2. rag-augmented — wired with the curated 30-doc seed KB.
//!
//! The default ambiguous event is a Cobalt Strike beacon process
//! spawn — the base model is unlikely to recognise the binary name
//! without the curated tool entry.
//!
//! What it shows (external audit WDG-R03):
//!
//! - **The prompt delta**, always: the `RAG_CONTEXT:` block the RAG
//!   engine splices into the prompt, read through
//!   [`AdeEngine::assembled_prompt`] (no inference). The example exits 1
//!   when the two prompts are equal (no retrieval hit, the block dropped
//!   to fit the model's window, or broken wiring) or differ by anything
//!   else than that block.
//! - **The verdict delta**, only with a backend that reads the prompt.
//!   With the model at `ADE_MODEL` (default
//!   [`AdeConfig::DEFAULT_MODEL_PATH`]) both engines run on the real
//!   backend (`AdeEngine::new`, loaded once; the mock only after a failed
//!   load with `NN_ADE_ALLOW_MOCK=1`). Without a model they run on
//!   `MockBackend`, which never reads the prompt: the two verdicts are
//!   equal by construction and the example says that their diff measures
//!   nothing.
//!
//! Without a model the engines need a file to point at: an empty stub in
//! a temporary directory, removed on exit. The configured model path is
//! never written (external audit WDG-012: run as root, the example left a
//! 0-byte file where the production model belongs).
//!
//! Run manually (from the repository root, for the default prompt path):
//!
//! ```sh
//! cargo run -p northnarrow-agent --example ade_with_rag --release
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use common::ade_types::AdeVerdict;
use common::Event;
use northnarrow_agent::ade::backend_candle::{pin_threads_before_runtime, ThreadPin};
use northnarrow_agent::ade::{AdeConfig, AdeEngine, EventContext, HostContext, MockBackend};
use northnarrow_agent::rag::RagEngine;

/// The header of the block `format_rag_block` splices into the prompt.
const RAG_MARKER: &str = "RAG_CONTEXT:\n";

/// `MockBackend::name()`.
const MOCK_BACKEND: &str = "mock";

fn main() -> ExitCode {
    // External audit LLMR-009: candle's worker count is pinned while the
    // process is single-threaded, then the runtime built.
    let pin = pin_threads_before_runtime(AdeConfig::default().effective_threads());
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(run(pin)),
        Err(e) => {
            eprintln!("ade-with-rag: tokio runtime: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(pin: ThreadPin) -> ExitCode {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
    pin.log();

    let requested = PathBuf::from(
        std::env::var("ADE_MODEL").unwrap_or_else(|_| AdeConfig::DEFAULT_MODEL_PATH.to_string()),
    );
    let prompt_path = PathBuf::from(
        std::env::var("ADE_PROMPT").unwrap_or_else(|_| "dataset/system_prompt_minimal.md".into()),
    );
    if !prompt_path.exists() {
        eprintln!(
            "ade-with-rag: prompt not present at {}",
            prompt_path.display()
        );
        return ExitCode::from(2);
    }

    // Held until `run` returns: the stub's directory, if one was made.
    let model = match choose_model(&requested) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ade-with-rag: {e}");
            return ExitCode::FAILURE;
        }
    };
    if model.stub.is_some() {
        eprintln!(
            "ade-with-rag: model not present at {}; the engines run on MockBackend, with an \
             empty stub at {} (removed on exit). Set ADE_MODEL to compare verdicts.",
            requested.display(),
            model.path.display()
        );
    }

    let cfg = AdeConfig {
        model_path: model.path.clone(),
        system_prompt_path: prompt_path,
        timeout: Duration::from_secs(240),
        ..AdeConfig::default()
    };
    let (engine_plain, engine_rag) = match build_engines(cfg, model.stub.is_some()).await {
        Ok(engines) => engines,
        Err(e) => {
            eprintln!("ade-with-rag: {e}");
            return ExitCode::FAILURE;
        }
    };
    let backend = engine_plain.backend_name().to_string();

    let event = cobalt_strike_event();
    let ctx = EventContext {
        recent_events: vec![],
        host_context: HostContext::discover(),
    };

    println!("=== Event under analysis ===");
    println!("  ProcessSpawn comm=cobaltstrike-beacon filename=/usr/local/bin/cobaltstrike-beacon");
    println!("  backend: {backend} | model: {}", model.path.display());
    println!();

    // External audit WDG-R03: what the RAG engine changes is the prompt.
    println!("=== Prompt delta (what RAG changes) ===");
    match prompt_delta(&engine_plain, &engine_rag, &event, &ctx) {
        Ok(d) => print!("{}", d.report()),
        Err(e) => {
            eprintln!("ade-with-rag: {e}");
            return ExitCode::FAILURE;
        }
    }
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

    println!("=== Verdict diff ===");
    print!("{}", verdict_diff(&backend, &v_plain, &v_rag));

    ExitCode::SUCCESS
}

/// The model file the engines point at.
struct ModelChoice {
    path: PathBuf,
    /// The temporary directory of an empty stub, when no model was at the
    /// requested path; dropping it removes the stub.
    stub: Option<tempfile::TempDir>,
}

/// External audit WDG-012 (NN-AUD-361): the requested path if a model is
/// there; otherwise an empty stub in a new temporary directory. Nothing is
/// created at, or above, the requested path.
fn choose_model(requested: &Path) -> Result<ModelChoice, String> {
    if requested.exists() {
        return Ok(ModelChoice {
            path: requested.to_path_buf(),
            stub: None,
        });
    }
    let dir = tempfile::Builder::new()
        .prefix("nn-ade-with-rag-")
        .tempdir()
        .map_err(|e| format!("cannot create a temporary directory for the stub model: {e}"))?;
    let path = dir.path().join("stub-model.gguf");
    std::fs::write(&path, b"").map_err(|e| format!("cannot create the stub model: {e}"))?;
    Ok(ModelChoice {
        path,
        stub: Some(dir),
    })
}

/// The plain engine and its RAG twin, on one backend: the real one through
/// `AdeEngine::new` (the production load and its trust checks), the mock
/// with a stub.
async fn build_engines(cfg: AdeConfig, stub: bool) -> Result<(AdeEngine, AdeEngine), String> {
    let plain = if stub {
        let backend = Arc::new(MockBackend::from_model_path(&cfg.model_path));
        AdeEngine::new_with_backend(cfg, backend).await
    } else {
        AdeEngine::new(cfg).await
    }
    .map_err(|e| format!("engine: {e}"))?;
    let rag = RagEngine::with_seed(None).map_err(|e| format!("seed kb: {e}"))?;
    let with_rag = plain.clone().with_rag(Arc::new(rag));
    Ok((plain, with_rag))
}

/// The RAG block of the prompt and the sizes around it.
#[derive(Debug)]
struct PromptDelta {
    plain_bytes: usize,
    rag_bytes: usize,
    block: String,
}

impl PromptDelta {
    fn report(&self) -> String {
        let mut out = format!(
            "  plain prompt: {} bytes\n  RAG prompt:   {} bytes (+{}), the only difference is \
             this block:\n",
            self.plain_bytes,
            self.rag_bytes,
            self.rag_bytes - self.plain_bytes
        );
        for line in self.block.lines() {
            out.push_str(&format!("    | {line}\n"));
        }
        out
    }
}

/// External audit WDG-R03 (NN-AUD-369): the two prompts, which must
/// differ by exactly one `RAG_CONTEXT:` block — the one thing RAG adds.
/// An error otherwise: then the comparison would measure nothing.
fn prompt_delta(
    plain: &AdeEngine,
    rag: &AdeEngine,
    event: &Event,
    ctx: &EventContext,
) -> Result<PromptDelta, String> {
    let p = plain.assembled_prompt(event, ctx).ok_or(
        "the plain engine built no prompt (injection short-circuit, or over the model's window)",
    )?;
    let r = rag.assembled_prompt(event, ctx).ok_or(
        "the RAG engine built no prompt (injection short-circuit, or over the model's window)",
    )?;
    if p == r {
        return Err(
            "the two prompts are equal: the RAG block did not reach the prompt (no \
                    retrieval hit, the block dropped to fit the model's window, or no RAG \
                    engine wired)"
                .into(),
        );
    }
    if p.contains(RAG_MARKER) {
        return Err("the plain prompt carries a RAG_CONTEXT: block".into());
    }
    let start = r
        .find(RAG_MARKER)
        .ok_or("the prompts differ, but the RAG prompt has no RAG_CONTEXT: block")?;
    let end = r[start..]
        .find("\n\n")
        .map(|i| start + i + 2)
        .ok_or("the RAG_CONTEXT: block has no end")?;
    if format!("{}{}", &r[..start], &r[end..]) != p {
        return Err("the prompts differ beyond the RAG_CONTEXT: block".into());
    }
    Ok(PromptDelta {
        plain_bytes: p.len(),
        rag_bytes: r.len(),
        block: r[start..end].to_string(),
    })
}

/// The verdict diff, and what it is worth on `backend`.
fn verdict_diff(backend: &str, plain: &AdeVerdict, rag: &AdeVerdict) -> String {
    let mut out = String::new();
    let mut row = |name: &str, a: String, b: String| {
        out.push_str(&format!("  {name:<18} {a:>10}   ->   {b:<10}\n"));
    };
    row(
        "verdict:",
        plain.verdict.to_string(),
        rag.verdict.to_string(),
    );
    row(
        "severity:",
        format!("{:?}", plain.severity),
        format!("{:?}", rag.severity),
    );
    row(
        "confidence:",
        format!("{:.2}", plain.confidence),
        format!("{:.2}", rag.confidence),
    );
    row(
        "family:",
        plain.threat_classification.family.clone(),
        rag.threat_classification.family.clone(),
    );
    let same = plain.verdict == rag.verdict
        && plain.severity == rag.severity
        && plain.confidence.to_bits() == rag.confidence.to_bits()
        && plain.threat_classification.family == rag.threat_classification.family;
    if backend == MOCK_BACKEND {
        out.push_str(
            "\n  backend=mock: MockBackend never reads the prompt, so the two verdicts are equal \
             by construction and this diff measures nothing about RAG. The prompt delta above \
             is the result; set ADE_MODEL to a model to compare verdicts.\n",
        );
    } else if same {
        out.push_str(&format!(
            "\n  backend={backend}: no verdict difference on this event (the RAG block reached \
             the prompt, see above).\n"
        ));
    } else {
        out.push_str(&format!(
            "\n  backend={backend}: the verdicts differ, with the RAG block the only \
             difference between the two prompts.\n"
        ));
    }
    out
}

fn cobalt_strike_event() -> Event {
    Event::ProcessSpawn {
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
        start_ns: 0,
        parent_is_kthread: false,
        exe: Default::default(),
        argv_truncated: false,
        filename_truncated: false,
    }
}

fn print_verdict(v: &AdeVerdict) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../dataset/system_prompt_minimal.md")
    }

    fn ctx() -> EventContext {
        EventContext {
            recent_events: vec![],
            host_context: HostContext::discover(),
        }
    }

    async fn mock_engines() -> (ModelChoice, AdeEngine, AdeEngine) {
        let root = tempfile::tempdir().unwrap();
        let model = choose_model(&root.path().join("absent.gguf")).unwrap();
        let cfg = AdeConfig {
            model_path: model.path.clone(),
            system_prompt_path: prompt(),
            ..AdeConfig::default()
        };
        let (plain, rag) = build_engines(cfg, true).await.unwrap();
        (model, plain, rag)
    }

    /// External audit WDG-012 (NN-AUD-361): with no model at the requested
    /// path nothing is created there or above it, and the stub goes with
    /// its directory. On the base code the example created the parents
    /// and a 0-byte file at the requested path (by default
    /// `AdeConfig::DEFAULT_MODEL_PATH`).
    #[tokio::test]
    async fn the_stub_never_touches_the_configured_model_path() {
        let root = tempfile::tempdir().unwrap();
        let requested = root.path().join("var/lib/northnarrow/models/model.gguf");
        let model = choose_model(&requested).unwrap();
        assert!(!requested.exists());
        assert!(!root.path().join("var").exists());
        assert!(model.path.exists());
        assert!(!model.path.starts_with(root.path()));
        let cfg = AdeConfig {
            model_path: model.path.clone(),
            system_prompt_path: prompt(),
            ..AdeConfig::default()
        };
        let (plain, _) = build_engines(cfg, true).await.unwrap();
        assert_eq!(plain.backend_name(), MOCK_BACKEND);
        assert!(!requested.exists());
        let stub = model.path.clone();
        drop(model);
        assert!(!stub.exists(), "the stub outlived its directory");

        // A model in place is used as it is.
        std::fs::create_dir_all(requested.parent().unwrap()).unwrap();
        std::fs::write(&requested, b"gguf").unwrap();
        let model = choose_model(&requested).unwrap();
        assert_eq!(model.path, requested);
        assert!(model.stub.is_none());
    }

    /// External audit WDG-R03 (NN-AUD-369): the RAG block reaches the
    /// prompt, and it is the only difference between the two prompts.
    #[tokio::test]
    async fn the_rag_block_is_the_whole_prompt_delta() {
        let (_model, plain, rag) = mock_engines().await;
        let d = prompt_delta(&plain, &rag, &cobalt_strike_event(), &ctx()).unwrap();
        assert!(d.block.starts_with(RAG_MARKER), "{:?}", d.block);
        assert!(d.block.ends_with("\n\n"));
        assert!(
            d.block.lines().count() >= 2,
            "no retrieved line: {:?}",
            d.block
        );
        assert_eq!(d.rag_bytes - d.plain_bytes, d.block.len());
        assert!(d.report().contains("    | RAG_CONTEXT:"));
    }

    /// Two prompts without the RAG block (the seed KB left out) fail the
    /// comparison instead of printing a diff of nothing.
    #[tokio::test]
    async fn equal_prompts_fail_the_comparison() {
        let (_model, plain, _) = mock_engines().await;
        let err = prompt_delta(&plain, &plain.clone(), &cobalt_strike_event(), &ctx()).unwrap_err();
        assert!(err.contains("the two prompts are equal"), "{err}");
    }

    /// On the mock the verdict diff is declared void, never presented as
    /// the impact of RAG.
    #[tokio::test]
    async fn the_mock_verdict_diff_is_declared_void() {
        let (_model, plain, rag) = mock_engines().await;
        let event = cobalt_strike_event();
        let a = plain.evaluate(&event, &ctx()).await.unwrap();
        let b = rag.evaluate(&event, &ctx()).await.unwrap();
        assert_eq!((a.verdict, a.severity), (b.verdict, b.severity));
        let text = verdict_diff(plain.backend_name(), &a, &b);
        assert!(
            text.contains("this diff measures nothing about RAG"),
            "{text}"
        );
        let real = verdict_diff("candle", &a, &b);
        assert!(real.contains("no verdict difference"), "{real}");
        assert!(!real.contains("measures nothing"), "{real}");
    }
}
