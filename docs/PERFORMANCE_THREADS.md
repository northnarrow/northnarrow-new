# ADE — Thread tuning (Sub-tappa 6.8)

How to find the optimal `--ade-threads N` for your deployment.

## Why this matters

Candle's CPU kernels parallelise quantised matmul through rayon. If
the rayon pool is sized incorrectly for the host:

- **Too few**: idle physical cores, slower decode than necessary.
- **Too many**: hyperthread contention, the lockstep matmul stalls
  on shared L2/L3 cache lines, and tok/s drops below the
  single-thread baseline.

The sweet spot is host-specific. On the CCX23 reference host
(2 physical / 4 logical) we expect 2-3; on a 16-core workstation
the bench would land closer to 12-14.

## The bench harness

`agent/examples/bench_threads.rs` walks `RAYON_NUM_THREADS` through
{1, 2, 3, 4} (configurable) and runs three short ADE inferences per
value, each with a 32-token cap (configurable). Each thread count is
benched in a fresh subprocess because rayon's global pool is
initialised lazily *once per process* — flipping the env var inside
the same binary has no effect after the first inference.

```bash
# Default: 1..4, 3 runs/value, 32 tokens/run
cargo run -p northnarrow-agent --release --example bench_threads

# Custom range, more runs, longer outputs (e.g. for a workstation):
ADE_BENCH_THREADS_RANGE=1,2,4,6,8,12,16 \
ADE_BENCH_THREADS_RUNS=5 \
ADE_BENCH_THREADS_TOKENS=64 \
cargo run -p northnarrow-agent --release --example bench_threads
```

## Reading the output

```text
=== ADE bench_threads (Sub-tappa 6.8) ===
model      = /home/forty/models/foundation-sec-8b-reasoning-q4_k_m.gguf
threads    = [1, 2, 3, 4]
runs/value = 3

threads=1  avg_tok_per_sec=0.94
threads=2  avg_tok_per_sec=1.61
threads=3  avg_tok_per_sec=1.83
threads=4  avg_tok_per_sec=1.62

OPTIMUM: threads=3 with 1.83 tok/s
→ pass `--ade-threads 3` to the agent to lock it in.
```

(The numbers above are illustrative — the founder will run the bench
manually on the CCX23 host and update this file with the real
figure once the production GGUF is in place.)

## Caveats

- The bench currently approximates tok/s by dividing
  `max_output_tokens × runs` by the engine's measured inference
  latency. Streaming early-termination (Strato 4) can lower the
  effective decoded count; rerun the bench after the streaming
  patch lands so the numbers reflect post-streaming wall-time.
- The first run after a cold cache is slower (mmap of the GGUF + KV
  alloc); the warmup pass inside `AdeEngine::new` mitigates that
  but cold I/O still dominates the first inference. Three runs per
  value smooths it out, ~5 runs is better when bench-quality
  matters.
- On hosts without the production GGUF, the example falls back to
  `MockBackend`. Numbers there are meaningless for tuning (mock is
  effectively constant-time) — useful only to debug the harness.
