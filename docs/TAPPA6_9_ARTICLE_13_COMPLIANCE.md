# Tappa 6.9 — EU AI Act Article 13 Compliance Dossier (XAI Saliency)

Status: **SHIPPED** · Schema `XAI_SCHEMA_VERSION = "1.0.0"` ·
Plan of record: `docs/TAPPA6_9_XAI_PLAN.md` ·
Commit range: `5a7e45b..HEAD` (P0→P5; phase ledger §7).

This is the regulatory hand-off artifact: when an auditor asks "show me
how the XAI evidence chain satisfies Article 13", this document maps
each clause to its implementation and the test that locks it. It
describes the *standalone* XAI capability + the Article-13 evidence
chain; the consumer (Battle-Time Synthesis, Tappa 10.5) is out of scope
and not yet built.

---

## 1. Scope

In scope: the `XaiEvidenceChain` forensic artifact and the
`XaiEngine::explain` seam that produces, signs, and makes it verifiable
offline. Out of scope (documented boundaries, not gaps): Article 13(2)
operating *instructions* (a separate operator runbook references this
doc); the customer-admin key chain (Tappa 8/10.5 — 6.9 ships an
ephemeral-key signer + the byte-abstract seam); the hybrid
attention-corroboration source (seam defined, impl deferred); the
golden-fixture regression set (P6, deferred — §6).

---

## 2. Article 13 conformance matrix

Clauses follow the plan §4.1 mapping (locked at P0.1). "Implementation"
cites file + stable symbol; "Verification" cites the test that locks it.

| Art. 13 clause | Requirement (paraphrase) | Implementation | Verification (test) |
|---|---|---|---|
| **13(1)** operational transparency | deployer can interpret and appropriately use the output | `common/src/xai_types.rs` — `XaiEvidenceChain.input_snapshot` (anonymised focal/recent/host JSON + literal-prompt SHA-256) + `saliency_map` (ranked causal attribution) + `method` | `agent/src/xai/engine.rs` — `explain_assembles_signs_and_verifies_a_full_chain` |
| **13(2)** operating instructions | concise/complete/correct instructions for use | *Out of scope of 6.9.* The chain is the **evidence** artifact; the operator runbook (separate) references this dossier. | n/a — documented scope boundary |
| **13(3)(a)** provider identity | identity of the provider | `XaiModelRef` (model_id/quantization/backend, from `AdeMetadata`) + `environment_hash` (agent binary ‖ model ‖ combat-rules ‖ host ‖ build-SHA) | `agent/src/xai/engine.rs` — `environment_hash_is_deterministic_and_tamper_sensitive` |
| **13(3)(b)(i)** intended purpose | the system's intended purpose | `method.kind = "perturbation/occlusion"` + `ADE_DOCTRINE.md` / plan cross-ref | `common/src/xai_types.rs` — `enum_canonical_tags_are_locked` |
| **13(3)(b)(iv)** performance & accuracy | level of accuracy / known limitations | `saliency_coverage` + `status` (`Complete` / `Degraded(reason)` honesty pair, never silent); `method.inference_settings` (R1 deterministic decoding recorded verbatim) | `agent/src/xai/saliency.rs` — `coverage_and_degraded_reason_are_exact_and_deterministic` |
| **13(3)(c)** identifiable output | the output is identifiable | `xai_trace_id` (UUIDv4) + `ade_trace_id` FK → `AdeVerdict.trace_id` | `agent/src/xai/engine.rs` — `explain_assembles_signs_and_verifies_a_full_chain` (asserts FK) |
| **13(3)(d)** human oversight prerequisite | enable effective human oversight | Mandatory guardrail: any `Err(XaiUnavailable)` ⇒ synthesis disabled — an unexplained rule can never deploy (fail-closed) | `agent/src/xai/saliency.rs` — `guardrail_contract_refuses_on_any_err_but_not_on_degraded`, `preflight_refuses_before_any_inference`, `mid_run_timeout_is_fail_closed` |

---

## 3. Reproducibility (the cross-cutting Art. 13 basis)

An auditor re-executing `input_snapshot` against `model.model_id` under
the recorded `method.inference_settings` obtains a **bit-identical**
`saliency_map`. This rests on:

- **Deterministic decoding (R1).** `agent/src/xai/engine.rs` —
  `deterministic_ade_config` (temperature 0 ⇒ greedy `Sampling::ArgMax`,
  `top_p = 1.0`, single-thread CPU kernels) and
  `deterministic_inference_settings` (recorded verbatim: temperature 0,
  top_k 1 ≡ greedy, the fixed candle seed
  `backend_candle::CANDLE_LOGITS_SEED`, single-thread). Multi-thread
  float reduction is non-associative and is forbidden on this path.
- **A signed canonical form.** `common/src/xai_types.rs` —
  `XaiEvidenceChain::canonical_bytes` (hand-rolled, domain-separated,
  length-prefixed, field-ordered, signature-excluded) signed with
  Ed25519 (`agent/src/xai/evidence.rs` — `Ed25519EvidenceSigner` /
  `verify_evidence`, `verify_strict`). Locked by
  `xai_types::canonical_bytes_byte_locked_for_sample` and
  `evidence.rs::{sign_then_verify_roundtrips,
  tampering_any_signed_field_breaks_verification}`.

> Note (audit P4 #2): a *full-pipeline* canonical byte-lock is
> deliberately NOT attempted — `environment_hash` includes the running
> binary's own SHA-256, and `timestamp_utc` / `xai_trace_id` are
> non-deterministic by design. The deterministic byte-lock therefore
> lives at the schema layer (the fixture above); the end-to-end test
> locks the meaningful invariant (assemble → sign → verify → round-trip
> → tamper-detection). A true full byte-lock would require an injected
> fixed timestamp/UUID/env-hash seam — recommended for P6.

---

## 4. Fail-closed guarantee

"If XAI is unavailable, synthesis is disabled" (roadmap, non-negotiable)
is enforced structurally: `XaiEngine::explain` returns
`Result<XaiEvidenceChain, XaiUnavailable>`; every `XaiUnavailable`
variant (`PreflightBudgetExceeded`, `Timeout`, `Probe`) is a hard stop.
Two-tier defence: the R-P3.1 cost preflight refuses *before any model
call* on the estimate; the per-call `Clock` guard refuses on *measured*
elapsed time if the real model is slower. A timed-out partial map is
discarded, never returned (`agent/src/xai/saliency.rs`).

---

## 5. Deployment & data-controller posture (audit F5)

`input_snapshot` carries anonymised but potentially host-identifying
fields (hostname, host_id, paths). Posture:

- **On-premise, local-only signing (default).** The chain never leaves
  the customer estate; the customer is the data controller. PII
  retention is the customer's policy; evidence-chain binding retention
  is **1 week** (roadmap). No anonymisation layer required.
- **Cloud-exported chain (NOT in 6.9).** Any path that exports a chain
  off-estate (e.g. SaaS console, Tappa 13) MUST first pass it through an
  anonymisation layer: SHA-256 the hostname, redact `host_id`, scrub
  absolute paths. This layer is **flagged for V1.0**, explicitly out of
  scope here, and synthesis/console export must not assume it exists yet.
- **Resource budget.** The XAI path requires a **dedicated, determinism
  -pinned `AdeEngine`** (built via `deterministic_ade_config`) separate
  from the production engine — production sampling may differ and must
  not be perturbed. Cost: roughly **+16 GB** model footprint for the
  second Foundation-Sec-8B Q4_K_M instance; **lazy-load on first XAI
  invocation** (synthesis is COMBAT-only and rare) so steady-state
  non-COMBAT deployments pay nothing.

---

## 6. Known limitations / deferred (honest disclosure)

- **P6 — golden saliency regression fixtures (deferred, separate
  phase).** Byte-stable `input/verdict/saliency` fixtures per Event
  family; the schema-evolution governance anchor. Tracked, not shipped.
- **Hybrid attention corroboration (deferred).** `SaliencyEntry.
  attention_score` is reserved (`None` in v1); perturbation is the
  canonical Art-13 source. Adding attention later is non-breaking.
- **R1 is a construction contract (audit P4 #1).** `XaiEngine` consumes
  ADE via the `evaluate` seam only and cannot *verify* the wrapped
  engine is deterministic — callers MUST build it through
  `deterministic_ade_config`. Recorded settings reflect that contract.
- **Perturbation ≠ formal causal proof.** Drop-occlusion *is* the legal
  "but-for" counterfactual and the strongest available black-box
  attribution given a quantized GGUF exposes no attention/gradients; the
  method, weights, and settings are recorded in-chain for scrutiny.

---

## 7. Phase ledger (commit SHAs)

| Phase | Commit | Content |
|---|---|---|
| P0 | `5a7e45b` | plan of record |
| P0.1 | `b23b072` | gating Q1–Q4 + refinements R1–R5 locked |
| P1 | `a5963b7` (+`a0e145b`,`f718f6c`,`ea470f2`) | Art-13 schema + `canonical_bytes` + signer seam + byte-lock |
| P2 | `0865133` | occlusion taxonomy + scoring + faithfulness oracle |
| P3 | `54ea836` (+`b3e4b4f`) | coarse-to-fine driver + bounded-K + tail + fail-closed budget |
| P4 | `1cde064` | `XaiEngine::explain` + chain assembly/signing + `environment_hash` + candle bench |
| P5 | `eeec43f` + this commit | audit-finding closeout + this dossier |
| P6 | — | golden regression fixtures — **deferred** (separate phase) |
