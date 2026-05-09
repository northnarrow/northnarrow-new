# ADE Inference Backend — Tappa 6 Notes

## Status as of Tappa 6 closure

The Active Defense Engine ships behind a trait
([`InferenceBackend`](../agent/src/ade/inference.rs)) with a single
production implementation: `MockBackend`. The Mock is deterministic,
schema-valid, and pattern-matches the five canonical few-shot
examples from `dataset/system_prompt_v1.md` so the rest of the
pipeline (parser, escalate, stats, wiring) can be exercised without
a GGUF dependency.

No real LLM backend is wired in. The reasoning is below; the next
sub-tappa picks one and replaces `build_default_backend` in
`agent/src/ade/mod.rs`.

## The model

The founder pre-supplied
`/home/forty/models/gemma-4-E4B-it-Q4_K_M.gguf` (Unsloth quant of
`google/gemma-4-E4B-it`). GGUF metadata reports:

- `general.architecture = "gemma4"`
- 42 layers, 128K context, sliding window 512
- GQA with `head_count=8`, `head_count_kv=2`
- `shared_kv_layers = 18`
- final-logit soft-capping (Gemma feature)
- Q4_K_M quantization, ~4.5 GB on disk

The novelties (`shared_kv_layers`, mixed sliding-window/global
attention, soft-cap on logits) make Gemma 4 architecturally distinct
from Gemma 2 / Gemma 3 — generic Gemma-2 inference code WILL NOT
work.

## Rust ecosystem snapshot (May 2026)

| Engine               | Gemma support                        | Verdict |
| -------------------- | ------------------------------------ | ------- |
| `candle-transformers 0.7+` | gemma, gemma2, gemma3 (NOT gemma4) | rejected — would require a custom port mirroring sliding-window + shared_kv |
| `mistral.rs 0.3`     | gemma3n claimed; gemma4 untested     | candidate, but adds a heavy dep tree (Send/Sync/threadpool/etc.) and untested with the founder's GGUF |
| `llama-cpp-2`        | full gemma4 support                  | works, but pulls a C++ build dep that contradicts the "100% Rust" charter |

## Decision

**Ship `MockBackend` for Tappa 6 closure, defer real backend to a
follow-up sub-tappa.**

The Mock is:

- deterministic — CI hash-stable, no flake
- schema-valid — exercises every parser code path on every push
- pattern-aware — produces the right verdict class for the canonical
  test events (xmrig → Kill, lockbit → KillTree, cargo → Allow,
  nmap → Alert, anything else → Escalate)
- fast — adds ~120 ms of synthetic latency per call so latency
  percentiles look realistic in the demo

## Migration plan

When picking up the next sub-tappa, drop a new struct that implements
`InferenceBackend` next to `MockBackend` and route to it via
`build_default_backend` in `agent/src/ade/mod.rs`. No other module
needs to change.

Recommended order:

1. **First attempt: mistral.rs**
   - Pro: pure Rust, gemma3n landed; gemma4 GGUF can be tried with
     `--gemma3n` heuristic
   - Risk: shared_kv_layers handling may produce garbage tokens
2. **If that fails: pin to a Gemma 3 1B/4B GGUF (`google/gemma-3-4b-it`)**
   - Pro: candle 0.7 supports this architecture today
   - Cost: smaller model, slightly worse reasoning quality
   - Latency target: p50 < 3 s on CPU, p95 < 8 s
3. **Last resort: `llama-cpp-2` behind a `ade-llamacpp` feature flag**
   - Document as tech debt with a TODO pointing back to options 1 / 2

## What `MockBackend` does NOT exercise

The follow-up sub-tappa MUST verify:

- real model load (warmup latency, RAM ceiling)
- prompt context truncation when the input exceeds 2048 tokens
- token streaming (currently all-at-once)
- hard timeout under genuinely slow CPU inference (the Mock returns
  in ~120 ms, never exercising the 15 s timeout)
- malformed real-world outputs (the Mock can't actually generate
  invalid JSON)

Track these with `#[ignore]`d integration tests gated on the model
file's existence.
