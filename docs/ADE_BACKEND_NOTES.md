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

Where the agent looks by default (external audit LLMR-004; it was a user's
home): `/var/lib/northnarrow/models/foundation-sec-8b-reasoning-q4_k_m.gguf`
and its tokenizer next to it. The agent loads a model and a tokenizer only
when they — and every directory above them — are root's and not writable
by group or others (a sticky directory excepted), the file a regular one;
otherwise it runs on its rules alone and says why. To install:

```sh
install -d -o root -g root -m 0755 /var/lib/northnarrow/models
install -o root -g root -m 0644 foundation-sec-8b-reasoning-q4_k_m.gguf \
    foundation-sec-8b-reasoning-q4_k_m.tokenizer.json /var/lib/northnarrow/models/
```

(The state directory is immutable while the agent runs: create `models/`
inside a trusted-installer window, or before the first start.)

Neither file is in the repository or the release: their source, the
revisions read, the licence (Llama 3.1 Community License for the Llama 3.1
part, Apache-2.0 for Cisco's changes) and what an operator who installs or
passes them on takes on are in `NOTICES.md`, "Model (not distributed)".

The development box keeps them in a home, used through `--ade-model` by
tools run as that user:

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
parsing, when it opens before the first `{` of the output (external
audit WDG-R14: a `<think>` inside the verdict object, e.g. in a file
name the model quotes, is text; the streaming detector reads the
output the same way):

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

- Positions: candle's quantized Llama precomputes its rotary table for
  `MAX_SEQ_LEN = 4096` positions, prompt and output together (the
  model's advertised 128 K does not apply). A position past it fails
  the forward pass.
- `MAX_PROMPT_TOKENS = 4096 - 768 = 3328` — the prompt window
  (`InferenceBackend::prompt_window`); 768 positions stay for the
  output (a verdict takes about 450 tokens), and the decode stops at
  the last position the table covers.
- `MAX_OUTPUT_TOKENS_HARD_CAP = 2048` — bounded so the engine's
  15 s timeout actually fires when the model misbehaves.
- Prefill in chunks of 256 tokens, the time budget checked between
  them (external audit LLMR-017): it overruns the budget by at most
  one chunk instead of holding the weights for the whole prompt.

External audit LLMR-008: the backend used to cut an over-long prompt
from the **front**, which is where the system prompt is. Now the
engine fits the prompt (`AdeEngine::prepare`, shared by `evaluate` and
the XAI `assembled_prompt`): it drops the oldest correlated events,
then the RAG block; the system prompt, the focal event and the task
are never cut. If they alone do not fit, the event is escalated
("prompt exceeds the model window"). The backend refuses a prompt over
the window (`AdeError::PromptExceedsWindow`) and never drains it.

The v1.1 system prompt (three few-shot examples, 7.7 KB) is estimated
at 1.9–2.4 K tokens, leaving the user turn about 0.9–1.4 K. These are
estimates (no tokenizer on the dev host): measure on a model host with
`cargo test -p northnarrow-agent --release -- --ignored --nocapture
ade::tests::ignored_model_host_prompt_tokens`.

## Performance — measured on the dev VM

Hardware: AMD Ryzen 9 3900XT VM exposing **only SSE4** to userspace
(no AVX2, no FMA, no F16C). Candle's quantized matmul falls back to
its scalar code path; per-token throughput is ~10× slower than on a
native AVX2 CPU.

Reproduce with `cargo run --release --example ade_smoke` (5-word
prompt, 4-token decode):

| Phase                        | Time    |
| ---------------------------- | ------- |
| GGUF load (cold disk)        | 17.8 s  |
| Warmup forward pass          | 1.71 s  |
| Prefill (6 prompt tokens)    | 8.83 s  |
| Decode (4 tokens)            | 5.07 s  |
| Total inference              | 13.9 s  |
| Total wall (load+warmup+inf) | 34.2 s  |
| Peak RSS                     | 7.0 GB  |

Per-token rates on this VM:

- Prefill: ~1.47 s/token (linear in prompt length)
- Decode: ~1.27 s/token

For the production prompt (`system_prompt_v1.md` + correlated events
+ focal event JSON ≈ 1500-2500 tokens) the same VM would need roughly
35-60 s of prefill alone — outside the brief's 15 s timeout. The
agent's `build_default_backend` fallback to `MockBackend` keeps
everything functional in that case.

A CPU with AVX2 (Ryzen 5xxx+, Intel Coffee Lake+) would bring the
prefill rate to roughly 0.05 s/token — ~30× faster — and the
canonical 1500-token prompt would prefill in ~75 s on top of ~5 s of
decode, well under the 15 s timeout once the prompt is trimmed to
~1000 tokens. GPU (CUDA / Metal) would push this further to <2 s.

## Production deployment notes

- **Hardware floor**: AVX2-capable CPU. Without AVX2, fall back to
  `MockBackend` (the trait surface and the cascade in
  `build_default_backend` already do this automatically when
  candle's load fails or returns an error mid-generation).
- **Memory floor**: 8 GB RAM (model + agent + slack). RSS peaks at
  ~7 GB during steady-state inference for the founder's 8B Q4_K_M.
- **Disk**: 5 GB for the GGUF + 17 MB for the tokenizer.

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
