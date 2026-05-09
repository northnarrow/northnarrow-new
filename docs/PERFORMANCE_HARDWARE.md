# ADE — Hardware baseline (Sub-tappa 6.8)

Snapshot of the deployment host the founder runs ADE on. Captured by
`cargo run -p northnarrow-agent --release --example diag_hw`. Re-run
the diagnostic on every new host before wiring ADE into production
to keep this document accurate.

## Host: Hetzner CCX23 (founder workstation)

```text
=== ADE Hardware Diagnostic (Sub-tappa 6.8) ===

CPU:
  model         = AMD EPYC-Milan Processor
  logical_cores = 4 (physical=2)
  isa_flags     = avx, avx2, fma, f16c, ssse3, sse4_1, sse4_2, bmi2

Memory:
  total         =  15.24 GiB
  available     =  13.67 GiB
  free          =   4.48 GiB

Compute benchmark (single-thread):
  matmul f32 1024x1024  ~19.25 GFLOPS

Memory benchmark:
  sequential read 1 GB  ~36.38 GB/s

Verdict:
  AVX2 detected — candle will use 256-bit SIMD
  bottleneck   = COMPUTE-BOUND (compute_per_byte=0.53 GFLOPS/GB/s)
  suggested ade-threads = 1 (physical_cores - 1)
```

## Reading

- **CPU**: AMD EPYC-Milan (Zen 3 server) virtualised down to 4 vCPU
  / 2 physical cores. AVX2 + FMA + F16C are present, **AVX-512 is
  not** — the hypervisor doesn't expose it. Candle's CPU kernels will
  default to 256-bit SIMD lanes; `target-cpu=native` (Sub-tappa 6.8
  Strato 2) will let LLVM emit FMA fused instructions instead of
  separate mul/add pairs.
- **Memory**: 15.24 GiB total, 13.67 GiB available. Foundation-Sec
  8B Q4_K_M is ~5 GiB resident; we have ~9 GiB headroom for the
  agent, posture, RAG, and OS page cache. No swap pressure expected.
- **Compute baseline**: 19.25 GFLOPS single-thread. With 2 physical
  cores the host caps near ~38 GFLOPS aggregate (best case, perfect
  scaling). For comparison: a desktop Zen 4 with AVX-512 hits
  ~80-120 GFLOPS/core.
- **Memory bandwidth**: 36.38 GB/s sequential read on warm cache.
  This is the L3-resident path — DRAM-resident bandwidth on a CCX23
  is closer to ~12-18 GB/s, so the 36 GB/s figure is optimistic for
  the LLM decode loop which streams quantised weights from RAM.
- **Bottleneck verdict**: marked **COMPUTE-BOUND** by the
  compute-per-byte ratio (0.53), but treat that with a grain of salt
  — the matmul micro-bench fits in cache while the LLM decode loop
  spills to DRAM. Real-world ADE inference is **memory-bound** on
  this host, which is why thread count matters less than expected
  past 2-3 threads.
- **Thread hint**: the diagnostic suggests 1 worker (physical_cores
  − 1). For Foundation-Sec 8B on this CPU we still expect a measured
  optimum of 2-3 threads — the heuristic is conservative.
  Re-confirm with `bench_threads` (Strato 3d).

## Implications for Sub-tappa 6.8

- `target-cpu=native` will unlock FMA on this exact CPU → ~1.3-1.5×
  on candle matmuls.
- LTO `fat` is safe (15 GiB RAM is comfortable for the linker).
- Thread tuning will plateau early (2-3 threads); benching all four
  values is still useful to lock in the optimum.
- Streaming early termination is the largest lever — it cuts decode
  tokens, which on a memory-bound host is a direct wall-time saving.

## How to refresh

```bash
cargo run -p northnarrow-agent --release --example diag_hw \
    > docs/PERFORMANCE_HARDWARE.md.new
# review, then replace the "Host:" block in this file.
```

The diagnostic is read-only and safe to run on a busy production
host (1 GB scratch buffer, ~1 second of CPU).
