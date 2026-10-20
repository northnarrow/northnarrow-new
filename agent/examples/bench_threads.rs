//! Thread-count micro-benchmark for ADE inference (Sub-tappa 6.8).
//!
//! Walks candle's worker count (`RAYON_NUM_THREADS`) through {1, 2, 3, 4}
//! (or whatever range you pass via env vars) and times three
//! evaluations of one fixed event per value, at a fixed output cap: the
//! thread choice only needs the latency of the same work at each count.
//! It reports what it measures — milliseconds per evaluation (the wall
//! time of `AdeEngine::evaluate`: prompt, prefill, decode, parse; mean,
//! min, max) and evaluations per second — and how many outputs closed a
//! verdict before the cap. It identifies the sweet spot for the CPU
//! you're benching on so the founder can pin `--ade-threads N` to the
//! optimum.
//!
//! External audit WDG-R12: it printed `avg_tok_per_sec`, computed as the
//! configured cap times the runs over the time — the inverse of the
//! latency scaled by a constant, not tokens decoded (the decode stops at
//! the verdict's close or at end of text). The verdict schema carries no
//! output-token count, and the choice does not need one.
//!
//! Each value is benched in a fresh subprocess because rayon's
//! global thread pool is initialised lazily *once per process* —
//! flipping the env var inside the same binary has no effect after
//! the first inference. The outer driver runs the inner benchmark
//! with `RAYON_NUM_THREADS=N ADE_BENCH_THREADS_INNER=1`; the inner one
//! reports the count candle's kernels use, and the driver refuses a
//! result taken at another count. A subprocess is killed after
//! (runs + 1) × the engine timeout plus [`LOAD_ALLOWANCE`] (model load
//! and warmup).
//!
//! Run with:
//!
//! ```text
//! cargo run -p northnarrow-agent --release --example bench_threads
//! ```
//!
//! Env knobs:
//!
//! - `ADE_BENCH_THREADS_RANGE`   — comma-separated thread counts
//!   (default `1,2,3,4`).
//! - `ADE_BENCH_THREADS_RUNS`    — runs per value (default `3`).
//! - `ADE_BENCH_THREADS_TOKENS`  — `max_output_tokens` per run
//!   (default `32`: every run decodes up to the same cap).
//! - `ADE_BENCH_THREADS_TIMEOUT` — engine timeout per run, seconds
//!   (default `120`).
//! - `ADE_MODEL`                 — GGUF override.
//! - `ADE_PROMPT`                — system-prompt override.
//!
//! The production GGUF is required: without it every subprocess exits
//! non-zero at once and the driver reports no optimum. There is no mock
//! fallback (external audit LLMR-005 removed the silent one; the mock's
//! latency is a fixed sleep), and a run whose engine fell back to the mock
//! (`NN_ADE_ALLOW_MOCK=1`) is refused.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use common::Event;
use northnarrow_agent::ade::{AdeConfig, AdeEngine, EventContext, HostContext};

const INNER_FLAG: &str = "ADE_BENCH_THREADS_INNER";

/// The inner run's result line on stdout.
const REPORT_PREFIX: &str = "BENCH ";

/// What a subprocess gets, beyond its runs, to load the model and warm up.
const LOAD_ALLOWANCE: Duration = Duration::from_secs(300);

/// `MockBackend::name()`.
const MOCK_BACKEND: &str = "mock";

fn main() -> ExitCode {
    use tracing_subscriber::EnvFilter;
    // stderr: stdout carries the inner run's report line.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    if std::env::var_os(INNER_FLAG).is_some() {
        // RAYON_NUM_THREADS comes from the driver, set before this process
        // started (external audit LLMR-009: never written at run time).
        return match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(run_inner()),
            Err(e) => {
                eprintln!("inner: tokio runtime: {e}");
                ExitCode::FAILURE
            }
        };
    }
    run_outer()
}

fn run_outer() -> ExitCode {
    let range = parse_range();
    let runs = parse_runs();
    let timeout = parse_timeout();
    let limit = subprocess_limit(runs, timeout);
    let model_path = resolve_model_path();

    println!("=== ADE bench_threads (Sub-tappa 6.8) ===");
    println!("model       = {}", model_path.display());
    println!("threads     = {range:?}");
    println!("runs/value  = {runs}");
    println!("output cap  = {} tokens", parse_max_tokens());
    println!(
        "limits      = {} s per evaluation, {} s per subprocess\n",
        timeout.as_secs(),
        limit.as_secs()
    );

    let mut results: Vec<(usize, InnerReport)> = Vec::new();
    for &n in &range {
        let report = match run_subprocess(n, limit) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("threads={n}: ERROR ({e})");
                continue;
            }
        };
        if report.candle_threads != n {
            eprintln!(
                "threads={n}: ERROR (candle's kernels ran on {} threads; result discarded)",
                report.candle_threads
            );
            continue;
        }
        println!("threads={n}  {}", report.summary());
        results.push((n, report));
    }

    let Some((best_n, best)) = optimum(&results) else {
        eprintln!("no successful runs; nothing to report");
        return ExitCode::FAILURE;
    };
    println!(
        "\nOPTIMUM: threads={best_n} at {:.1} ms per evaluation ({:.3} evaluations/s)",
        best.mean_ms,
        best.evaluations_per_sec()
    );
    println!("→ pass `--ade-threads {best_n}` to the agent to lock it in.");
    ExitCode::SUCCESS
}

async fn run_inner() -> ExitCode {
    let runs = parse_runs();
    let model_path = resolve_model_path();
    let prompt_path = resolve_prompt_path();
    if let Err(e) = check_inputs(&model_path, &prompt_path) {
        eprintln!("inner: {e}");
        return ExitCode::FAILURE;
    }

    let cfg = AdeConfig {
        model_path,
        system_prompt_path: prompt_path,
        timeout: parse_timeout(),
        max_output_tokens: parse_max_tokens(),
        ..AdeConfig::default()
    };

    let engine = match AdeEngine::new(cfg).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("inner: engine init failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if engine.backend_name() == MOCK_BACKEND {
        eprintln!("inner: the engine fell back to the mock backend (fixed latency); refused");
        return ExitCode::FAILURE;
    }

    let host = HostContext::discover();
    let event = sample_event();
    let mut samples_ms = Vec::with_capacity(runs);
    for i in 0..runs {
        let ctx = EventContext {
            recent_events: vec![],
            host_context: host.clone(),
        };
        let started = Instant::now();
        if let Err(e) = engine.evaluate(&event, &ctx).await {
            eprintln!("inner: evaluate error: {e}");
            return ExitCode::FAILURE;
        }
        let elapsed = started.elapsed();
        // An injection short-circuit or a prompt over the window answers
        // without the model: such a run would time nothing.
        let snap = engine.stats();
        if snap.successful_verdicts + snap.malformed_outputs != i as u64 + 1 {
            eprintln!("inner: evaluation {} did not run the model", i + 1);
            return ExitCode::FAILURE;
        }
        samples_ms.push(elapsed.as_secs_f64() * 1000.0);
    }

    let Some(report) = InnerReport::from_samples(
        candle_core::utils::get_num_threads(),
        &samples_ms,
        engine.stats().successful_verdicts as usize,
    ) else {
        eprintln!("inner: no run timed");
        return ExitCode::FAILURE;
    };
    println!("{}", report.to_line());
    ExitCode::SUCCESS
}

/// The model and the prompt must exist: the inner run exits at once
/// otherwise (no fallback).
fn check_inputs(model: &Path, prompt: &Path) -> Result<(), String> {
    if !model.exists() {
        return Err(format!("model missing at {}", model.display()));
    }
    if !prompt.exists() {
        return Err(format!("prompt missing at {}", prompt.display()));
    }
    Ok(())
}

/// One thread count's measurement.
#[derive(Debug, Clone, PartialEq)]
struct InnerReport {
    /// `candle_core::utils::get_num_threads()` in the run.
    candle_threads: usize,
    runs: usize,
    /// Outputs that parsed as a verdict (the decode closed the object, or
    /// the model ended its text, before the cap); the others were cut at
    /// the cap.
    complete: usize,
    mean_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

impl InnerReport {
    fn from_samples(candle_threads: usize, samples_ms: &[f64], complete: usize) -> Option<Self> {
        if samples_ms.is_empty() {
            return None;
        }
        let sum: f64 = samples_ms.iter().sum();
        Some(Self {
            candle_threads,
            runs: samples_ms.len(),
            complete,
            mean_ms: sum / samples_ms.len() as f64,
            min_ms: samples_ms.iter().copied().fold(f64::INFINITY, f64::min),
            max_ms: samples_ms.iter().copied().fold(0.0, f64::max),
        })
    }

    fn evaluations_per_sec(&self) -> f64 {
        if self.mean_ms > 0.0 {
            1000.0 / self.mean_ms
        } else {
            0.0
        }
    }

    fn to_line(&self) -> String {
        format!(
            "{REPORT_PREFIX}candle_threads={} runs={} complete={} mean_ms={:.3} min_ms={:.3} \
             max_ms={:.3}",
            self.candle_threads, self.runs, self.complete, self.mean_ms, self.min_ms, self.max_ms
        )
    }

    /// The last report line of the inner run's stdout.
    fn parse(stdout: &str) -> Result<Self, String> {
        let line = stdout
            .lines()
            .rev()
            .find_map(|l| l.strip_prefix(REPORT_PREFIX))
            .ok_or("no report line")?;
        let field = |key: &str| -> Result<&str, String> {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
                .ok_or(format!("report without {key}: {line:?}"))
        };
        let int = |key: &str| -> Result<usize, String> {
            field(key)?
                .parse()
                .map_err(|e| format!("{key}: {e} in {line:?}"))
        };
        let float = |key: &str| -> Result<f64, String> {
            let v: f64 = field(key)?
                .parse()
                .map_err(|e| format!("{key}: {e} in {line:?}"))?;
            if v.is_finite() && v >= 0.0 {
                Ok(v)
            } else {
                Err(format!("{key}: {v} in {line:?}"))
            }
        };
        Ok(Self {
            candle_threads: int("candle_threads")?,
            runs: int("runs")?,
            complete: int("complete")?,
            mean_ms: float("mean_ms")?,
            min_ms: float("min_ms")?,
            max_ms: float("max_ms")?,
        })
    }

    fn summary(&self) -> String {
        format!(
            "ms/evaluation mean={:.1} min={:.1} max={:.1}  evaluations/s={:.3}  \
             verdict before the cap: {}/{}",
            self.mean_ms,
            self.min_ms,
            self.max_ms,
            self.evaluations_per_sec(),
            self.complete,
            self.runs
        )
    }
}

/// The thread count with the lowest mean latency.
fn optimum(results: &[(usize, InnerReport)]) -> Option<&(usize, InnerReport)> {
    results
        .iter()
        .min_by(|a, b| a.1.mean_ms.total_cmp(&b.1.mean_ms))
}

/// External audit WDG-R12: a subprocess gets the warmup and its runs, each
/// bounded by the engine timeout, and the load.
fn subprocess_limit(runs: usize, timeout: Duration) -> Duration {
    LOAD_ALLOWANCE
        + timeout.saturating_mul(u32::try_from(runs).unwrap_or(u32::MAX).saturating_add(1))
}

fn run_subprocess(n: usize, limit: Duration) -> Result<InnerReport, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut cmd = Command::new(&exe);
    cmd.env(INNER_FLAG, "1")
        .env("RAYON_NUM_THREADS", n.to_string());
    let stdout = run_bounded(cmd, limit)?;
    InnerReport::parse(&stdout)
}

/// Runs `cmd` to its end, killed at `limit` (external audit WDG-R12: the
/// wait had no bound). Its stdout on success; on failure, the end of its
/// stderr.
fn run_bounded(mut cmd: Command, limit: Duration) -> Result<String, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "killed after {} s without a result",
                    limit.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("wait: {e}")),
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    if !status.success() {
        let tail: Vec<&str> = stderr.trim().lines().rev().take(5).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!("{status}: {}", tail.join(" | ")));
    }
    Ok(stdout)
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

fn parse_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("ADE_BENCH_THREADS_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    )
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
        start_ns: 0,
        parent_is_kthread: false,
        exe: Default::default(),
        argv_truncated: false,
        filename_truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit WDG-R12 (NN-AUD-378): the figures are the timed
    /// latencies, whatever the output cap; no token rate is claimed. On
    /// the base code the rate was the cap × runs over the time.
    #[test]
    fn the_report_is_the_measured_latency() {
        let r = InnerReport::from_samples(3, &[100.0, 200.0, 300.0], 1).unwrap();
        assert_eq!((r.runs, r.complete, r.candle_threads), (3, 1, 3));
        assert_eq!((r.mean_ms, r.min_ms, r.max_ms), (200.0, 100.0, 300.0));
        assert_eq!(r.evaluations_per_sec(), 5.0);
        let line = r.to_line();
        assert_eq!(InnerReport::parse(&line).unwrap(), r);
        for text in [line, r.summary()] {
            assert!(!text.contains("tok"), "{text}");
        }
        assert!(r.summary().contains("verdict before the cap: 1/3"));
        assert!(InnerReport::from_samples(3, &[], 0).is_none());
    }

    #[test]
    fn the_inner_report_is_read_from_the_last_line() {
        let stdout = "WARN something\nBENCH candle_threads=2 runs=3 complete=0 \
                      mean_ms=1500.5 min_ms=1400 max_ms=1600\n";
        let r = InnerReport::parse(stdout).unwrap();
        assert_eq!(r.candle_threads, 2);
        assert_eq!(r.mean_ms, 1500.5);
        for bad in [
            "",
            "0.94\n",
            "BENCH candle_threads=2 runs=3 complete=0 mean_ms=1 min_ms=1",
            "BENCH candle_threads=2 runs=3 complete=0 mean_ms=NaN min_ms=1 max_ms=1",
            "BENCH candle_threads=x runs=3 complete=0 mean_ms=1 min_ms=1 max_ms=1",
        ] {
            assert!(InnerReport::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_optimum_is_the_lowest_latency() {
        let at = |ms: f64| InnerReport::from_samples(1, &[ms], 0).unwrap();
        let results = vec![
            (1, at(900.0)),
            (2, at(500.0)),
            (3, at(450.0)),
            (4, at(600.0)),
        ];
        assert_eq!(optimum(&results).unwrap().0, 3);
        assert!(optimum(&[]).is_none());
    }

    /// External audit WDG-R12: a subprocess that never ends is killed at
    /// its limit.
    #[test]
    fn a_subprocess_is_killed_at_its_limit() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let started = Instant::now();
        let err = run_bounded(cmd, Duration::from_millis(300)).unwrap_err();
        assert!(err.contains("killed after"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));

        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err >&2"]);
        assert_eq!(run_bounded(cmd, Duration::from_secs(10)).unwrap(), "out\n");
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo why >&2; exit 3"]);
        let err = run_bounded(cmd, Duration::from_secs(10)).unwrap_err();
        assert!(err.contains("why"), "{err}");

        assert_eq!(
            subprocess_limit(3, Duration::from_secs(120)),
            LOAD_ALLOWANCE + Duration::from_secs(480)
        );
    }

    /// Without the model the inner run stops before loading anything.
    #[test]
    fn a_missing_model_fails_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = dir.path().join("p.md");
        std::fs::write(&prompt, "p").unwrap();
        let err = check_inputs(&dir.path().join("absent.gguf"), &prompt).unwrap_err();
        assert!(err.starts_with("model missing at"), "{err}");
        let err = check_inputs(&prompt, &dir.path().join("absent.md")).unwrap_err();
        assert!(err.starts_with("prompt missing at"), "{err}");
        assert!(check_inputs(&prompt, &prompt).is_ok());
    }
}
