//! Tappa 6.9.7 P6 — validation layer: latency bench, golden retrieval
//! suite, end-to-end format re-confirm.
//!
//! The harness fns are pure/`pub` (callable from an xtask later); the
//! gate-relevant runs need the real P2 corpus (`target/kb/*.jsonl`
//! from `cargo xtask rag-kb`) + the 6.7 `kb_seed`, so the heavy tests
//! are `#[ignore]` (the established real-corpus pattern). Budgets:
//! `retrieve` p95 ≤ 50 ms, cold `open_index` ≤ 5 s, golden ≥ 90 %.

use std::path::Path;
use std::time::Instant;

use super::retrieval::{RagEngine, RagQuery};

/// p50/p95/p99 over a sample (microseconds).
#[derive(Debug, Clone, Copy)]
pub struct LatencyStats {
    pub n: usize,
    pub p50_us: u128,
    pub p95_us: u128,
    pub p99_us: u128,
    pub max_us: u128,
}

fn percentiles(mut samples: Vec<u128>) -> LatencyStats {
    samples.sort_unstable();
    let n = samples.len();
    let at = |p: f64| -> u128 {
        if n == 0 {
            return 0;
        }
        let idx = (((n as f64) * p).ceil() as usize).clamp(1, n) - 1;
        samples[idx]
    };
    LatencyStats {
        n,
        p50_us: at(0.50),
        p95_us: at(0.95),
        p99_us: at(0.99),
        max_us: *samples.last().unwrap_or(&0),
    }
}

/// Resident set size (KiB) from `/proc/self/status` (Linux; agent is
/// Linux-first). `None` if unavailable.
pub fn vm_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// The representative query set the latency bench exercises (mix of
/// ATT&CK / Sigma / seed / cross-source shapes).
pub fn bench_queries() -> &'static [&'static str] {
    &[
        "T1059.001 powershell encoded command",
        "/etc/shadow credential access",
        "xmrig cryptocurrency mining",
        "certutil download remote payload",
        "process injection T1055",
        "cobalt strike beacon c2",
    ]
}

/// Cold `open_index` time + warm `retrieve` p50/p95/p99 over the real
/// corpus, `n` iterations per query.
pub struct BenchReport {
    pub open_cold: std::time::Duration,
    pub retrieve: LatencyStats,
    pub rss_delta_kib: i64,
    pub doc_count: usize,
}

pub fn run_bench(jsonl_dir: &Path, index_dir: &Path, n: usize) -> anyhow::Result<BenchReport> {
    let rss0 = vm_rss_kib().unwrap_or(0);
    let t = Instant::now();
    let engine = RagEngine::open_index(jsonl_dir, index_dir)?;
    let open_cold = t.elapsed();
    let rss1 = vm_rss_kib().unwrap_or(0);
    let mut samples = Vec::with_capacity(n * bench_queries().len());
    for q in bench_queries() {
        for _ in 0..n {
            let s = Instant::now();
            let _ = engine.retrieve(RagQuery::new(q));
            samples.push(s.elapsed().as_micros());
        }
    }
    Ok(BenchReport {
        open_cold,
        retrieve: percentiles(samples),
        rss_delta_kib: rss1 as i64 - rss0 as i64,
        doc_count: engine.document_count(),
    })
}

// ── golden retrieval suite ─────────────────────────────────────────────

/// One golden case. `want` = ids that MUST appear in top-`k` (exact —
/// used for the *deterministic* `attack:`/`kb_seed` ids). `want_sigma`
/// = at least one `sigma:` id must appear (Sigma UUIDs are opaque /
/// corpus-evolving — a prefix-presence assertion is the durable
/// contract, not a brittle pinned UUID). `forbid` must NOT appear.
pub struct Golden {
    pub q: &'static str,
    pub want: &'static [&'static str],
    pub want_sigma: bool,
    pub forbid: &'static [&'static str],
}

/// 24 hand-curated cases (deterministic ids only; queries use the
/// target docs' own discriminating vocabulary — honest retrieval, not
/// gamed). Durable across future mechanism swaps.
pub fn golden_cases() -> Vec<Golden> {
    macro_rules! g {
        ($q:expr, [$($w:expr),*], $s:expr) => {
            Golden { q: $q, want: &[$($w),*], want_sigma: $s, forbid: &[] }
        };
    }
    vec![
        // ── ATT&CK technique queries (exact, deterministic ids) ──
        g!("powershell encoded command execution", ["attack:T1059.001"], false),
        g!("/etc/shadow /etc/passwd credential dumping linux", ["attack:T1003.008"], false),
        g!("cryptocurrency mining resource hijacking", ["attack:T1496"], false),
        g!("process injection into another process", ["attack:T1055"], false),
        g!("ingress tool transfer download file", ["attack:T1105"], false),
        g!("exploit public-facing application", ["attack:T1190"], false),
        g!("valid accounts legitimate credentials", ["attack:T1078"], false),
        g!("scheduled task job persistence", ["attack:T1053"], false),
        g!("command and scripting interpreter unix shell", ["attack:T1059.004"], false),
        g!("data encrypted for impact ransomware", ["attack:T1486"], false),
        // ── Sigma rule queries (sigma: prefix presence) ──
        g!("access to /etc/shadow sensitive file", [], true),
        g!("certutil download urlcache", [], true),
        g!("suspicious curl wget to web request", [], true),
        g!("base64 encoded shell command decode", [], true),
        g!("reverse shell /dev/tcp bash", [], true),
        g!("crontab persistence modification", [], true),
        // ── 6.7 kb_seed queries (exact seed ids) ──
        g!("xmrig miner pool stratum", ["sigma_xmrig_detection"], false),
        g!("cobalt strike beacon malleable c2", ["tool_cobaltstrike"], false),
        g!("certutil lolbas living off the land", ["lolbas_certutil"], false),
        g!("powershell -enc base64 obfuscation", ["sigma_powershell_encoded"], false),
        g!("empire post-exploitation agent", ["tool_empire"], false),
        // ── cross-source (ATT&CK + Sigma together) ──
        g!("powershell credential dump lsass", ["attack:T1003.001"], true),
        g!("linux shadow file unauthorized read", ["attack:T1003.008"], true),
        g!("scripting interpreter powershell abuse", ["attack:T1059.001"], true),
    ]
}

pub struct GoldenReport {
    pub total: usize,
    pub passed: usize,
    pub failures: Vec<String>,
}

impl GoldenReport {
    pub fn rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.passed as f64 / self.total as f64
        }
    }
}

/// Run the golden suite against an open engine (top-`k` = 10).
pub fn run_golden(engine: &RagEngine) -> GoldenReport {
    let mut passed = 0;
    let mut failures = Vec::new();
    let cases = golden_cases();
    for c in &cases {
        let r = engine.retrieve(RagQuery {
            query_text: c.q,
            top_k: 10,
            min_similarity: 0.0,
        });
        let ids: Vec<&str> = r.documents.iter().map(|d| d.id.as_str()).collect();
        let want_ok = c.want.iter().all(|w| ids.contains(w));
        let sigma_ok = !c.want_sigma || ids.iter().any(|i| i.starts_with("sigma:"));
        let forbid_ok = !c.forbid.iter().any(|f| ids.contains(f));
        if want_ok && sigma_ok && forbid_ok {
            passed += 1;
        } else {
            failures.push(format!(
                "q={:?} want={:?} sigma={} got_top5={:?}",
                c.q,
                c.want,
                c.want_sigma,
                ids.iter().take(5).collect::<Vec<_>>()
            ));
        }
    }
    GoldenReport {
        total: cases.len(),
        passed,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_kb() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/kb")
    }

    #[test]
    fn percentiles_are_monotone() {
        let s = percentiles((1..=100).map(|x| x as u128).collect());
        assert!(s.p50_us <= s.p95_us && s.p95_us <= s.p99_us && s.p99_us <= s.max_us);
        assert_eq!(s.n, 100);
    }

    #[test]
    fn golden_suite_has_at_least_20_cases() {
        assert!(golden_cases().len() >= 20, "owner requires ≥20 golden cases");
    }

    /// Latency budget gate — `retrieve` p95 ≤ 50 ms, cold open ≤ 5 s.
    /// `NN_RAG_BENCH_N` (default 1000) iterations/query.
    #[test]
    #[ignore = "needs target/kb (cargo xtask rag-kb); release-gate bench"]
    fn latency_bench_real_corpus() {
        let n: usize = std::env::var("NN_RAG_BENCH_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0)
            .unwrap_or(1000);
        let ix = tempfile::tempdir().unwrap();
        let rep = run_bench(&real_kb(), ix.path(), n).unwrap();
        eprintln!(
            "BENCH docs={} open_cold={:?} retrieve(n={}) p50={}us p95={}us p99={}us max={}us rss_delta={}KiB",
            rep.doc_count, rep.open_cold, rep.retrieve.n, rep.retrieve.p50_us,
            rep.retrieve.p95_us, rep.retrieve.p99_us, rep.retrieve.max_us, rep.rss_delta_kib,
        );
        assert!(
            rep.retrieve.p95_us <= 50_000,
            "retrieve p95 {}us exceeds the 50ms budget",
            rep.retrieve.p95_us
        );
        assert!(
            rep.open_cold.as_secs() < 5,
            "cold open_index {:?} exceeds the 5s budget",
            rep.open_cold
        );
    }

    /// Golden retrieval gate — pass rate ≥ 90 %.
    #[test]
    #[ignore = "needs target/kb (cargo xtask rag-kb); release-gate golden"]
    fn golden_suite_real_corpus() {
        let ix = tempfile::tempdir().unwrap();
        let engine = RagEngine::open_index(&real_kb(), ix.path()).unwrap();
        let rep = run_golden(&engine);
        eprintln!(
            "GOLDEN {}/{} = {:.1}%",
            rep.passed,
            rep.total,
            rep.rate() * 100.0
        );
        for f in &rep.failures {
            eprintln!("  FAIL {f}");
        }
        assert!(
            rep.rate() >= 0.90,
            "golden pass rate {:.1}% < 90% — STOP + owner ruling",
            rep.rate() * 100.0
        );
    }

    /// End-to-end Phase-C format re-confirm: real retrieval → the
    /// frozen `format_rag_block` shape (structural, content is
    /// corpus-dependent so not byte-exact — that is the P5 hermetic
    /// snapshot's job).
    #[test]
    #[ignore = "needs target/kb (cargo xtask rag-kb)"]
    fn end_to_end_format_rag_block_real_corpus() {
        let ix = tempfile::tempdir().unwrap();
        let engine = RagEngine::open_index(&real_kb(), ix.path()).unwrap();
        let r = engine.retrieve(RagQuery {
            query_text: "powershell encoded command",
            top_k: 3,
            min_similarity: 0.0,
        });
        assert!(!r.documents.is_empty(), "expected real hits");
        let block = crate::ade::format_rag_block(&r).expect("non-empty ⇒ Some");
        assert!(block.starts_with("=== RELEVANT CYBERSEC KNOWLEDGE (retrieved from local KB, trusted) ===\n"));
        assert!(block.trim_end().ends_with("=== END RELEVANT KNOWLEDGE ==="));
        for d in &r.documents {
            assert!(block.contains(&format!("Id: {}", d.id)));
            assert!(block.contains(&format!("Category: {}", d.category)));
            assert!(block.contains(&format!("Similarity: {:.2}", d.similarity)));
        }
    }
}
