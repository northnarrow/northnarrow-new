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
{1, 2, 3, 4} (configurable) and times three ADE evaluations of the same
event per value, each with a 32-token cap (configurable). Each thread
count is benched in a fresh subprocess because rayon's global pool is
initialised lazily *once per process* — flipping the env var inside
the same binary has no effect after the first inference. The
subprocess reports the worker count candle's kernels used; a result
taken at another count is discarded. A subprocess is killed after
(runs + 1) × the engine timeout (`ADE_BENCH_THREADS_TIMEOUT`, default
120 s) plus 300 s for the model load.

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
model       = /var/lib/northnarrow/models/foundation-sec-8b-reasoning-q4_k_m.gguf
threads     = [1, 2, 3, 4]
runs/value  = 3
output cap  = 32 tokens
limits      = 120 s per evaluation, 780 s per subprocess

threads=1  ms/evaluation mean=<m1> min=<…> max=<…>  evaluations/s=<1000/m1>  verdict before the cap: 0/3
threads=2  ms/evaluation mean=<m2> min=<…> max=<…>  evaluations/s=<1000/m2>  verdict before the cap: 0/3
threads=3  ms/evaluation mean=<m3> min=<…> max=<…>  evaluations/s=<1000/m3>  verdict before the cap: 0/3
threads=4  ms/evaluation mean=<m4> min=<…> max=<…>  evaluations/s=<1000/m4>  verdict before the cap: 0/3

OPTIMUM: threads=<N> at <lowest mean> ms per evaluation (<…> evaluations/s)
→ pass `--ade-threads <N>` to the agent to lock it in.
```

(The shape of the output, no figures: the founder will run the bench
manually on the CCX23 host and update this file with the real
figures once the production GGUF is in place.)

## Caveats

- What is measured is the wall time of `AdeEngine::evaluate` for one
  fixed event: prompt build, prefill, decode up to the cap, parse. It
  is not a decode rate: the verdict schema carries no output-token
  count, and the decode stops early when the verdict object closes or
  the model ends its text (external audit WDG-R12: the bench used to
  print `avg_tok_per_sec`, the cap × runs over the time). With the
  default 32-token cap no verdict closes ("verdict before the cap:
  0/3"): every run decodes the same number of tokens, which is what the
  comparison between thread counts needs. With a large cap, compare
  thread counts only when that column is the same for all.
- The first run after a cold cache is slower (mmap of the GGUF + KV
  alloc); the warmup pass inside `AdeEngine::new` mitigates that
  but cold I/O still dominates the first inference. Three runs per
  value smooths it out, ~5 runs is better when bench-quality
  matters; the `min` column shows the warm figure.
- The bench needs the production GGUF: without it every subprocess
  exits non-zero at once and no optimum is printed. There is no mock
  fallback, and a run whose engine fell back to `MockBackend`
  (`NN_ADE_ALLOW_MOCK=1` after a failed load) is refused: the mock's
  latency is a fixed sleep.
