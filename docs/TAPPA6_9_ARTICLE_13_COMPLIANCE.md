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
| **13(3)(a)** provider identity | identity of the provider | `XaiModelRef` (model_id/quantization/backend, from `AdeMetadata`) + `environment_hash` (agent binary ‖ model ‖ combat-rules ‖ host ‖ build-SHA ‖ RAG corpus fingerprint, empty with RAG off — §8) | `agent/src/xai/engine.rs` — `environment_hash_is_deterministic_and_tamper_sensitive` |
| **13(3)(b)(i)** intended purpose | the system's intended purpose | `method.kind = "perturbation/occlusion"` + `ADE_DOCTRINE.md` / plan cross-ref | `common/src/xai_types.rs` — `enum_canonical_tags_are_locked` |
| **13(3)(b)(iv)** performance & accuracy | level of accuracy / known limitations | `saliency_coverage` + `status` (`Complete` / `Degraded(reason)` honesty pair, never silent); `method.inference_settings` (R1 deterministic decoding recorded verbatim); the known limits of the production ADE's input and evaluation: §6, §10 | `agent/src/xai/saliency.rs` — `coverage_and_degraded_reason_are_exact_and_deterministic` |
| **13(3)(c)** identifiable output | the output is identifiable | `xai_trace_id` (UUIDv4) + `ade_trace_id` FK → `AdeVerdict.trace_id` | `agent/src/xai/engine.rs` — `explain_assembles_signs_and_verifies_a_full_chain` (asserts FK) |
| **13(3)(d)** human oversight prerequisite | enable effective human oversight | Mandatory guardrail: any `Err(XaiUnavailable)` ⇒ synthesis disabled — an unexplained rule can never deploy (fail-closed). The ADE is advisory: a verdict that names a response is recorded as a recommendation for the operator and not executed (§9) | `agent/src/xai/saliency.rs` — `guardrail_contract_refuses_on_any_err_but_not_on_degraded`, `preflight_refuses_before_any_inference`, `mid_run_timeout_is_fail_closed`; `agent/src/ade/advisory.rs` — `disposition` tests |

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
variant (`PreflightBudgetExceeded`, `Timeout`, `Probe`,
`InjectionShortCircuit`, `PromptExceedsWindow`) is a hard stop.
Two-tier defence: the R-P3.1 cost preflight refuses *before any model
call* on the estimate; the per-call `Clock` guard refuses on *measured*
elapsed time if the real model is slower. A timed-out partial map is
discarded, never returned (`agent/src/xai/saliency.rs`). The preflight
lowers the bounded-K cap to the largest value whose worst case fits the
budget, recorded in `method.max_units`, and refuses only when not even
K = 1 fits (external audit XAI-005). An event ADE never shows the model
(injection short-circuit, or a prompt over the model window) is refused
before any probe: there is no decision of the model to explain
(external audit XAI-011).

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
- **XAI is not wired to production verdicts.** Its consumer (Tappa 10.5)
  is not built; no chain has been produced in production. What the
  production ADE does with a verdict is §9; what it shows the model is
  §10.
- **One evaluation slot, taken by the parent's view of an exec.** The ADE
  evaluates one event at a time (external audit LLMR-002, lab PR 82); an
  exec that arrives while one runs is judged by the rules only and
  counted. For each exec the `ExecCheck`, which carries the parent's comm,
  takes the slot, and the child's `ProcessSpawn` microseconds later is
  counted and dropped, so the model judges the exec under its parent's
  name. Found in the lab (lab PR 144); a follow-up in
  `docs/audit/EXTERNAL_AUDIT_16f7563.md`, to be improved.
- **Model behaviour not re-measured after the audit's prompt changes.**
  The window budget of §10 rests on token estimates; the real count of the
  v1.1 prompt (`ignored_model_host_prompt_tokens`), `ade_attacks` before
  and after (the off-repo LoRA was trained on the old prompt format) and
  the golden of the production tokenizer
  (`ignored_real_tokenizer_matches_its_golden`) are owed on a host that
  has the model.

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

---

## 8. Two-artifact traceability model (added Tappa 6.9.7 P7; corrected 2026-10-15)

Tappa 6.9.7 wired a local RAG knowledge base into the ADE prompt. RAG
is off by default (`NN_ADE_RAG_ENABLED` unset); everything in this
section applies only to a deployment that turns it on. The Article-13
traceability story is **two artifacts**, by deliberate design (plan §5
Option A — `XAI_SCHEMA_VERSION` stays 1.0.0, no schema mutation):

**(a) Signed XAI evidence chain — 6.9, IMPLEMENTED.** Answers *"what
did the AI explain, and why"*. Ed25519-signed; `prompt_sha256` binds
the **entire assembled prompt**. With RAG on, that prompt includes the
`RAG_CONTEXT:` block produced by `format_rag_block`
(`agent/src/ade/rag_integration.rs`): one line per retrieved document,
holding only its title and, for a Sigma rule, the severity read from
its `Level:` line — `Sigma Intel (<severity> severity): <title>.`,
`Sigma Intel: <title>.` or `Intel: <title>.`. The rest of each
document — its body, identifier and retrieval score — never reaches
the model; its category shows only as the `Sigma Intel` / `Intel`
prefix. So `prompt_sha256` commits
everything retrieval put in front of the model, and nothing else: it
does not say which documents produced those lines. Two documents with
the same title and severity give the same line, and a change to a
document's body that leaves the retrieved lines unchanged leaves the
hash unchanged (the model's input is then unchanged too).

The corpus behind the block is pinned and bound ex ante (external
audit XAI-001, XAI-002, XAI-009, XAI-010; lab PR 145):

- The agent opens RAG only over the canonical dumps that
  `docs/kb-sources/kb_index.json` names, each with its SHA-256; that
  file is built into the agent binary. A dump that is missing or
  altered, or any other `*.jsonl` in the corpus directory, means RAG is
  not started: a WARN, and an `integrity_drift` entry of kind
  `subsystem_degraded` naming the cause in the agent's signed audit log.
  The agent never runs RAG on a partial corpus.
- The search index is rebuilt in memory from the verified dumps at
  every start; no index stored on disk is read.
- `environment_hash` (§2, 13(3)(a)) includes the fingerprint of the
  corpus actually loaded (the pinned dumps plus the built-in seed
  notes), and an empty field with RAG off. Two chains with the same
  `environment_hash` were produced over the same knowledge base, and a
  RAG-off chain never shares its `environment_hash` with a RAG-on one.
  The value is computed once, when the XAI engine is built; the corpus
  is opened once, at agent start.

Consequence (intentional, not a regression): a RAG-on chain is
reproducible only RAG-on, by the agent build at the recorded
`environment_hash` over the same pinned corpus (`kb_index_hash`); the
`rag: None` canary path keeps every RAG-off chain reproducible.

**(b) Hash-chained RAG retrieval log — Tappa 13 SaaS Backend
follow-on, NOT YET BUILT.** Answers *"which documents were retrieved
at decision time, with what scores"*: a separate, unsigned,
append-only hash-chained log of `{ade_trace_id, kb_index_hash,
retrieved doc ids + scores, prev_entry_sha256}`. It gives per-query,
per-document retrieval provenance *separable* from the signed prompt
without mutating the closed XAI schema. Scope/justification: plan §5.1
(explicitly a Tappa 13 deliverable). Until it ships, the agent does
not record per-document identity: the signed chain binds the
retrieved titles (and Sigma severities) through `prompt_sha256` and the
loaded corpus through `environment_hash`, not the identity of each
retrieved document.

Net Art. 13(3)(c): the signed chain carries *"what the AI explained"*
and the exact retrieval context the model saw; *"which documents were
retrieved"* is covered **only in part** until the Tappa 13 log ships.
The two artifacts will be cross-linked by `ade_trace_id`. (A per-line
document digest in the prompt was considered and declined: the
`RAG_CONTEXT:` line shape is a training contract locked by
`format_rag_block_byte_stable_phase_abcd_contract`.)

---

## 9. ADE decisions are advisory (lab PR 134, 2026-10-15)

The model's input includes strings an attacker controls (command
lines, file names, DNS names), and no prompt hardening makes it safe
to let such a verdict act on its own. Since 2026-10-15 the ADE is
therefore a consultant (`agent/src/ade/advisory.rs`):

- A verdict that names a response (`Kill`, `KillTree`, `Quarantine`,
  `BlockNetwork`, `Isolate`) is recorded as a recommendation — a
  detection carrying the model's reasoning, with the response field
  `advisory: <action> recommended by the model, not executed` — and
  nothing is executed. Verdicts that name no response (`Allow`,
  `Monitor`, `Alert`, `Escalate`) are recorded as before (`Allow` is
  not a detection).
- Responses stay with the deterministic detection rules and the COMBAT
  ladder, which can be verified.
- `NN_ADE_ENFORCE=1` (also `true` or `yes`) lets ADE verdicts execute
  their response again. It is a weakening setting: at every start the
  agent records it in its signed audit log (an `integrity_drift` entry
  of kind `weakening_env`).

For Article 13 this means that, by default, an ADE output — and so
what an XAI chain explains — is a recommendation to a human operator,
who decides whether to act on it (13(3)(d)). A deployer who sets
`NN_ADE_ENFORCE` takes that decision away from the operator, and the
signed audit log shows that it did.

## 10. What the model is shown (external audit, lab PRs 132, 133, 144)

The input an operator reads in a recommendation, and that an XAI chain
would explain, is bounded and built the same way for both: one engine
helper (`prepare`) serves `evaluate` and `assembled_prompt`, so the signed
`prompt_sha256` binds what the model saw (LLMR-008).

- **Window.** The prompt must fit 4,096 − 768 = 3,328 tokens (768 left to
  the verdict: candle's quantized Llama precomputes 4,096 positions,
  prompt and output together). To fit, the engine drops the oldest
  correlated events, then the RAG block, and never the system prompt; an
  event whose system prompt, focal event and task alone do not fit is a
  synthetic Escalate ("prompt exceeds the model window") and nothing
  reaches the model (`PromptExceedsWindow` for XAI, §4). The prefill runs
  in 256-token chunks and stops at the time budget; a timeout or a
  backend error is recorded as an Escalate of kind `ade_unavailable`
  (LLMR-008, LLMR-017, LLMR-003; lab PR 133).
- **System prompt v1.1.** Observed strings — event fields, correlated
  events, RAG titles — are evidence, never instructions; a string that
  tries to steer the verdict is an indicator and never lowers severity;
  decide on behaviour. Three few-shot examples in the production format
  instead of five (LLMP-013, lab PR 133). The prompt is built into the
  agent (lab PR 105).
- **Correlated context.** At most 20 events and 4 KiB: up to half go to
  events sharing the process, its parent or the file with the focal event,
  within 5 minutes, then nearby events; the window fit drops nearby events
  before keyed ones. The focal event is not repeated as untrusted
  correlated data. An event left out for its injection score takes no
  slot (XAI-004, XAI-013; lab PR 144).
- **Sanitization.** Correlated events are sanitized and printed as JSON
  strings inside an untrusted block (LLMP-002, lab PR 81). Each string is
  scored once on its deduplicated flags; one strong signal forces an
  Escalate, a high injection score overrides any verdict but Escalate, a
  severe indicator with an Allow is escalated, decoded ROT13 text is never
  echoed, and a confidence or novelty outside [0, 1] is a parse error
  (LLMP-003, LLMP-004, LLMP-006, LLMP-011, LLMR-010; lab PR 132). An
  event the model never sees (injection short-circuit, prompt over the
  window) is refused by XAI before any probe (§4).
- **RAG.** Only from the pinned corpus, indexed in memory at start (§8).

For Article 13 this is the content of 13(3)(b)(iv): the known limits of
what the model can weigh (20 correlated events, the window, the fields
the agent sends), stated here rather than discovered in a chain.

## 11. Change log

- **2026-05-17 — initial (Tappa 6.9 P0→P5).** §1–§7 above.
- **2026-05-17 (Tappa 6.9.7 P7).** RAG-local-KB integration
  documented; §8 two-artifact traceability model defined (Option A
  frozen — XAI 1.0.0 untouched; hash-chained RAG log scoped to
  Tappa 13 per plan §5.1). No change to the §2 conformance matrix or
  the §3 reproducibility basis.
- **2026-10-15 (external audit XAI-018, with XAI-001/002/009/010; lab
  PR 145).** §8 corrected: the prompt has carried the compact
  `RAG_CONTEXT:` block (titles and Sigma severity only) since Tappa
  6.9.7.1 P5.1, not the retired `=== RELEVANT CYBERSEC KNOWLEDGE ===`
  block with document text; the earlier claim that every retrieved
  snippet was committed, and that Art. 13(3)(c) was fully covered, is
  withdrawn. §8 now describes the pinned corpus, the in-memory index and
  the RAG corpus fingerprint in `environment_hash` (§2 row 13(3)(a)
  updated); that preimage gained one length-prefixed field, before any
  chain had been produced in production (XAI is not wired yet, Tappa
  10.5). New §9: the ADE is advisory (lab PR 134); §2 row 13(3)(d)
  updated. The former §9 is now §10.
- **2026-10-16 (after Wave 2 of the external audit).** New §10, what the
  model is shown (window, system prompt v1.1, correlated context,
  sanitization; lab PRs 132, 133, 144). §6 gains three limitations: XAI
  not wired to production verdicts, the single evaluation slot taken by
  the exec's `ExecCheck` (lab PR 144), and the model's behaviour not
  re-measured. The change log is now §11.
