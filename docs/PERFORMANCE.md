> Historical: the on-host LLM advisor was removed in Wave 4, lab PR 214.
> The build settings of §1 (`target-cpu=x86-64-v2` by default, `lto = "fat"`,
> `panic = "abort"`, the `release-bench` profile) still apply to the agent;
> their candle-specific reasons and every figure below do not.

# ADE Performance — Sub-tappa 6.8

Three tuning knobs ship in Sub-tappa 6.8. Each addresses a distinct
bottleneck in the CPU-only inference path on the founder's Hetzner
CCX23 reference host (see [`PERFORMANCE_HARDWARE.md`](PERFORMANCE_HARDWARE.md)).

## 1. Build flags (`target-cpu` + LTO fat)

Sub-tappa 6.8 made `target-cpu=native` the workspace default. Since
external audit SUP-017 the default in `/.cargo/config.toml` is the ISA the
release ships, so no build is tied to the host that compiled it:

```toml
[build]
rustflags = ["-C", "target-cpu=x86-64-v2"]
```

A build that only ever runs on the host that compiles it (the reference
host benchmarks below) opts into `native` for the x86_64 target, which
leaves the eBPF build's flags alone and which `cargo xtask build` passes on:

```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native" cargo xtask build --release
```

…and `Cargo.toml` upgrades the release profile from `lto = "thin"`
to `lto = "fat"`:

```toml
[profile.release]
opt-level = 3
codegen-units = 1
lto = "fat"
panic = "abort"
strip = "symbols"
```

A second profile, `release-bench`, inherits release but keeps debug
symbols so `perf record` / flame graphs can name candle internals
when the founder runs the bench scripts against the real model:

```bash
cargo build --profile release-bench -p northnarrow-agent --example bench_threads
```

### Expected impact

- `target-cpu=native` lets LLVM emit FMA on AVX2 hosts and the wider
  AVX-512 lanes when present. Foundation-Sec 8B Q4_K_M is dominated
  by quantised matmul; expected ~1.3-1.5× on candle CPU kernels.
- `lto = "fat"` allows cross-crate inlining between candle's hot
  `forward` path and the engine's `spawn_blocking` caller. Expected
  ~1.05-1.20× on top.
- `panic = "abort"` removes unwind tables from the release binary.
  No measurable speed impact, slightly smaller binary.

### Trade-offs

- Build time goes from ~30 s (LTO thin) to ~160 s (LTO fat) on the
  CCX23 reference host. CI currently builds the workspace once per
  job, so the cost is amortised.
- Peak linker RAM during LTO fat is ~6-8 GiB. The CCX23 host has
  15 GiB so headroom is ample; downgrade to `lto = "thin"` if a
  smaller deployment OOMs at link time.
- `target-cpu=native` makes the binary non-portable: it only runs on
  the build host's exact ISA or newer (review 64: a release built on an
  AVX-512 runner died with SIGILL elsewhere). Releases, packages, the lab
  and the range therefore build for x86-64-v2, and the figures measured
  there are for that ISA; the `native` figures below need the opt-in.

## 2. Thread tuning (`--ade-threads N`)

Candle uses rayon for parallelisation under the hood. `AdeConfig`
exposes a `num_threads: Option<usize>` field; when `None`,
`effective_threads()` returns `physical_cores - 1` clamped to a
minimum of 1. The CLI flag `--ade-threads N` overrides the
auto-detection.

The agent's `main` sets `RAYON_NUM_THREADS` from the resolved value
before it builds the tokio runtime, while the process has one thread
(`ade::backend_candle::pin_threads_before_runtime`; external audit
LLMR-009: setting it at the ADE load, inside the runtime, raced the
other threads' reads of the environment). The rayon global pool starts
sized correctly, and candle-core, which reads the variable again to
split its kernels, uses the same count. A `RAYON_NUM_THREADS` already
in the environment wins; the journal says which (`ADE rayon worker
count pinned via RAYON_NUM_THREADS`, or the operator override).

### How to find the optimum

```bash
cargo run -p northnarrow-agent --release --example bench_threads
```

This walks N ∈ {1, 2, 3, 4} on a short prompt and prints the count
with the lowest latency per evaluation (milliseconds per evaluation and
evaluations/s at a fixed output cap; external audit WDG-R12: the
`tok/s` it printed was the cap over the time, not tokens decoded). On
the CCX23 reference host the expected sweet spot is 2-3
threads — beyond that, hyperthread contention on the 2-physical-core
CPU starts costing more than it gains.

## 3. Streaming + early JSON termination

Foundation-Sec is configured with `max_output_tokens = 1500`. In
practice the verdict JSON closes around token 400-500; the remaining
~1000 tokens are either `<|eot_id|>` (good) or model rambling
(wasted decode).

Sub-tappa 6.8 adds:

- An optional **`generate_streaming(...)`** method on
  `InferenceBackend` that delivers tokens through a callback and
  accepts a [`StreamControl::Stop`] return to terminate the decode
  loop early.
- A **`StreamingJsonDetector`** (in `agent/src/ade/streaming_parser.rs`)
  that tracks brace depth across a token stream — string-aware,
  escape-aware — and reports completion the moment the outermost
  object closes. It reads the stream as the parser reads the output:
  a `<think> … </think>` block first, then the first `{`, ignoring
  every character before it (external audit LLMP-010: a `}` or an odd
  quote there lost the early stop, and braces in the reasoning stopped
  the decode before the verdict).
- Wiring in `AdeEngine::evaluate` that combines the two: as soon as
  the JSON object terminates, `evaluate` calls `Stop` and the
  decoder returns whatever's already buffered.

### Expected impact

- Average decoded tokens per inference drops from ~1500 (configured
  cap) to ~400-500 (verdict size). On a memory-bound CPU host,
  every token saved is roughly a constant wall-time saving, so this
  is the largest lever in the pass — expected ~3-4× end-to-end on
  realistic prompts.

### Compatibility

- The trait method has a default implementation that wraps
  `generate` and emits the entire output as a single callback at
  the end. `MockBackend` keeps that default; only `CandleBackend`
  implements true per-token streaming.
- The verdict schema is unchanged. The parser sees the same JSON
  string whether streaming was used or not — the only difference is
  wall time.

## 4. Persistent backend (verified)

`AdeEngine::new` is called **once** in `agent/src/main.rs:129`,
before the event loop starts, and the resulting `Arc<AdeEngine>` is
shared into `process_event` for every event. Model weights,
tokenizer, KV-cache state machine, and the rayon pool are all
loaded once and amortised across the agent's lifetime.

This is verified — no fix needed in 6.8. The construction site
carries a load-bearing comment so a future change that moves the
call into the hot path fails the next audit instead of silently
re-paying the ~5 GiB GGUF mmap per event. Re-audit if `process_event`
ever grows a path that constructs a new engine on the hot path.

## Combined target

The pre-6.8 baseline on CCX23 is ~0.94 tok/s decode → ~25 minutes
for a 1500-token output. The pass targets:

- target-cpu=native + LTO fat: ~1.5×
- thread tuning at the measured optimum: ~1.2×
- streaming early termination: ~3-4×

Combined: **~5×** end-to-end. Target wall time for a typical ADE
verdict on CCX23: ~5 minutes.

These figures are theoretical; measure on your host before reporting
absolute numbers. The bench scripts in `agent/examples/` exercise
each lever in isolation.

## Out of scope (Sub-tappa 6.9+)

- GPU / Metal / CUDA backends.
- Schema redesign for compact output (would obviate streaming
  termination by simply emitting fewer tokens).
- Smaller model — Foundation-Sec 8B stays the production choice.
- Speculative decoding / draft models.

## Empirical Measurements — May 2026 (post Sub-tappa 6.8)

Hardware: Hetzner CCX23 (AMD EPYC, 2 physical cores + SMT, AVX2+FMA, 16 GB RAM)
Model: Foundation-Sec-8B-Reasoning Q4_K_M (4.6 GB)
Build: target-cpu=native + LTO fat
Threads: 2 (--ade-threads 2)

| Metric        | Baseline (pre-6.8) | Post-6.8 | Speedup |
|---------------|--------------------|---------|---------|
| Load model    | 6,700 ms           | 5,943 ms | ×1.13   |
| Warmup        | 750 ms             | 123 ms   | ×6.10   |
| Decode rate   | 0.94 tok/s         | 3.69 tok/s | ×3.93 |

Estimated end-to-end speedup with streaming JSON early termination: ~×8-10.
Typical ADE inference: from ~25 min to ~3-5 min.
