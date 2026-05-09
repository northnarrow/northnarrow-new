# ADE Inference Backend — Status Notes

## Status

- **Tappa 6 base** — closed with `MockBackend` only. Trait surface
  in place, parser/escalate/wiring exercised end-to-end.
- **Sub-tappa 6.1 (this document's commit)** — `CandleBackend` ships
  as the production backend. Foundation-Sec-8B-Reasoning Q4_K_M
  GGUF (architecture `llama`) loads natively via candle 0.10's
  `quantized_llama::ModelWeights`. `MockBackend` retained as a
  graceful fallback when the model is missing or fails to load (CI,
  --no-ade, dev workstations without the GGUF).

## Backend choice (Sub-tappa 6.1)

Tried in spec order; stopped at the first that worked.

| Option | Engine | Verdict | Why |
|--------|--------|---------|-----|
| A      | candle 0.10 (Llama 3.1) | ✅ shipped | native Llama support, 100% Rust, charter preserved |
| B      | mistral.rs | ⏭️ skipped | not needed |
| C      | llama-cpp-2 | ⏭️ skipped | not needed |

Foundation-Sec-8B-Reasoning is built on Llama 3.1 with continual
pretraining + RLVR for cybersecurity. Its GGUF metadata advertises
`general.architecture = "llama"`, `block_count = 32`,
`embedding_length = 4096`, `context_length = 131072`. Candle 0.10's
`quantized_llama::ModelWeights::from_gguf` consumes it without
modification.

## Model files

- `/home/forty/models/foundation-sec-8b-reasoning-q4_k_m.gguf`
  (~4.92 GB) — production model.
- `/home/forty/models/foundation-sec-8b-reasoning-q4_k_m.tokenizer.json`
  (~17 MB) — Llama 3.1 BPE tokenizer, fetched once from
  `huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/resolve/main/tokenizer.json`.
  The backend's `locate_tokenizer` looks for either
  `<stem>.tokenizer.json` (preferred) or `tokenizer.json`.
- `/home/forty/models/gemma-4-E4B-it-Q4_K_M.gguf` (~4.64 GB) — kept
  for comparative benchmarks; pass via `--ade-model PATH`. Architecture
  `gemma4` is NOT supported by candle 0.10 — Mock fallback applies.

## Prompt + chat template

The system prompt (`dataset/system_prompt_v1.md`) stays
model-agnostic — it documents the schema, the 5-step procedure, and
five few-shot examples in plain markdown.

`PromptParts { system, user }` is the canonical split. Backends pick
their template via `InferenceBackend::chat_template`:

- `ChatTemplate::Plain` — `system\n\nuser` concat. Used by Mock.
- `ChatTemplate::Llama3` — `<|begin_of_text|>` +
  `<|start_header_id|>{role}<|end_header_id|>` markers + `<|eot_id|>`
  separators. Used by `CandleBackend`.

## Reasoning-model output handling

Foundation-Sec-Reasoning emits a `<think>...</think>` reasoning chain
before the JSON answer. The parser strips it before `serde_json`
parsing:

```
<think>let me consider the alternatives...</think>
{ "schema_version": "1.0.0", ... }
```

If the model exhausts its output budget mid-`<think>` (no closing
tag), the parser returns `MalformedJson("model opened <think> but
never produced </think>...")` and the engine folds it into a Tier1
Escalate verdict — the safe default for indeterminate state.

The parser also extracts the first balanced `{ ... }` from the
remaining text, so the model can wrap its JSON in prose without
breaking validation.

## Prompt window + output budget

- `MAX_PROMPT_TOKENS = 4096` — Foundation-Sec advertises 128 K
  context, but on CPU each kilo-token of prompt costs roughly half a
  second of prefill time. 4 K is the sweet spot for the 5-example
  few-shot block + correlated events + focal event.
- `MAX_OUTPUT_TOKENS_HARD_CAP = 2048` — bounded so the engine's
  15 s timeout actually fires when the model misbehaves.

If the assembled prompt exceeds the cap, the backend truncates from
the **front** to preserve the focal event (which is appended last in
`build_event_prompt`).

## Performance — measured

Run on the dev VM (CPU-only, AVX2). See the closing demo log of the
Sub-tappa 6.1 commit chain for the canonical run:

- model load (cold disk): ~7 s
- warmup (1-token forward pass): ~1.4 s
- p50 inference latency: see report
- p95 inference latency: see report
- peak resident set size: see report

## Future work

- **GPU support**: feature flag `ade-gpu` enabling candle's `cuda` or
  `metal` features. Drop-in for the same `CandleBackend`.
- **Streaming output**: today the engine waits for the full
  generation; emitting tokens as they arrive would let the agent
  start logging the verdict before the model finishes thinking.
- **mistral.rs alternative**: keep on the table if candle ever
  regresses on Llama 3.1.
- **Gemma 4 support**: when candle picks up `gemma4` architecture
  natively, `build_default_backend` can choose the right backend by
  reading `general.architecture` from the GGUF metadata.
