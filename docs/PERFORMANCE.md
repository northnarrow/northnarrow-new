# ADE Performance — Sub-tappa 6.8

Three tuning knobs ship in Sub-tappa 6.8. Each addresses a distinct
bottleneck in the CPU-only inference path on the founder's Hetzner
CCX23 reference host (see [`PERFORMANCE_HARDWARE.md`](PERFORMANCE_HARDWARE.md)).

## 1. Build flags (`target-cpu=native` + LTO fat)

`/.cargo/config.toml` opts every crate in this workspace into:

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
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
  the build host's exact ISA or newer. Acceptable because we ship
  per-host builds, not pre-compiled tarballs.

## 2. Thread tuning (`--ade-threads N`)

Candle uses rayon for parallelisation under the hood. `AdeConfig`
exposes a `num_threads: Option<usize>` field; when `None`,
`effective_threads()` returns `physical_cores - 1` clamped to a
minimum of 1. The CLI flag `--ade-threads N` overrides the
auto-detection.

`CandleBackend::load` sets `RAYON_NUM_THREADS` from the resolved
value before any candle code runs, so the rayon global pool starts
sized correctly.

### How to find the optimum

```bash
cargo run -p northnarrow-agent --release --example bench_threads
```

This walks N ∈ {1, 2, 3, 4} on a short prompt and prints the best
tok/s. On the CCX23 reference host the expected sweet spot is 2-3
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
  object closes.
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

`AdeEngine::new` is called **once** in `agent/src/main.rs`, before
the event loop starts, and the resulting `Arc<AdeEngine>` is shared
into `process_event` for every event. Model weights, tokenizer, and
KV-cache state machine are all loaded once and amortised across the
agent's lifetime.

This is verified — no fix needed in 6.8. Re-audit if `process_event`
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
