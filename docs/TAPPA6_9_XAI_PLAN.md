# Tappa 6.9 — XAI Saliency Mapping — Implementation Plan

Status: **DRAFT FOR REVIEW** (plan-first; no code until approved)
Author: Claude (staff-eng) · Date: 2026-05-17 · Driver: EU AI Act Art. 13, pre-beta blocker
Decisions locked with owner: saliency method = **Hybrid (perturbation canonical now, attention seam later)**; approach = **plan-first**.

---

## 1. Scope & non-goals

### In scope (this tappa, ~1–3 wk; roadmap line-item "XAI evidence chain binding: 1 week")
1. A standalone **XAI saliency engine** that, given the exact inputs of an ADE
   decision (focal `Event`, `EventContext.recent_events`, `HostContext`) and the
   resulting `AdeVerdict`, produces a **faithful, human-auditable saliency map**
   over the *semantic input units* that drove the decision.
2. An **Article-13 forensic evidence-chain artifact** (`XaiEvidenceChain`) that
   binds: the saliency map, the anonymized input snapshot, the verdict, model
   identity/version, timestamps, environment hash, and a **canonical signable
   byte form** (Ed25519, reusing `ed25519_dalek`).
3. The **mandatory guardrail interface**: `explain()` returns
   `Result<XaiEvidenceChain, XaiUnavailable>`; the (future) synthesis path is
   contractually required to treat `Err`/timeout as a hard stop ("if XAI is
   unavailable, synthesis is disabled" — roadmap, non-negotiable).
4. A **hybrid seam**: a `SaliencySource` trait so attention-based attribution
   can be added later as a *corroborating* signal without reshaping the schema.

### Explicitly NOT in scope (later tappe)
- Battle-Time rule **synthesis** itself (Tappa 10.5 / 8–10 wk post-Beta).
- Digital-twin validation, TTL engine, operator console (other §6.9 line items).
- Customer-admin-key-chain signing *infrastructure* (Tappa 8). 6.9 produces the
  canonical signable bytes + a `Signer` seam; tests use an ephemeral keypair
  (same pattern as `admin_auth.rs` tests, line ~263).
- Patching/vendoring candle to expose attention (the hybrid seam is *defined*
  now, the attention impl is deferred — see §7).

---

## 2. Why perturbation/occlusion (recap of the locked decision)

- Stock `candle_transformers::models::quantized_llama::ModelWeights.forward()`
  returns logits only — **no attention exposed**. Attention saliency would
  require forking candle against a quantized model (fragile, ongoing burden).
- Gradient/Integrated-Gradients needs autodiff through a GGUF quant model —
  effectively infeasible in candle.
- Perturbation is **black-box**: it re-invokes the existing `AdeEngine::evaluate`
  seam with one input unit neutralised and measures the decision delta. It is
  backend-agnostic (deterministic with `MockBackend` in CI, real with Candle in
  prod), and is **causally faithful** — the strongest Art. 13 story ("removing
  *this* correlated event flips KILL→ALERT and drops confidence 0.94→0.41").

---

## 3. The saliency algorithm

### 3.1 Perturbable-unit taxonomy
The decision's inputs decompose into semantic units (NOT tokens):

| Region        | Unit                                   | Source |
|---------------|----------------------------------------|--------|
| `focal`       | each field of the focal `Event` variant (e.g. ProcessSpawn{filename, comm, argv-ish, pid…}) | the event passed to `evaluate` |
| `correlated`  | each element of `recent_events` (≤20)  | `EventContext.recent_events` |
| `host`        | each `HostContext` field               | `EventContext.host_context` |

Total units `K` ≈ (focal fields) + min(20, |recent|) + (host fields) ≈ 25–35.

### 3.2 Occlusion operator
Per unit, produce a **neutralised** copy of the input set:
- correlated event → **drop** the event (most faithful: "what if this hadn't
  happened"); also support **anonymise-in-place** mode for fields whose presence
  is structural.
- focal/host field → replace with a typed neutral sentinel (`""`, `0`,
  `0.0.0.0`, `unknown`) so the prompt stays schema-valid (avoids the model
  reacting to malformed input rather than to the *absence* of the signal).
- Occlusion is applied to the **already-sanitised** prompt path (`ade/sanitize.rs`);
  XAI introduces **no new untrusted input surface** (defends the §6.9
  "synthesis as prompt-injection vector" anti-pattern).

### 3.3 Decision-delta metric
Baseline verdict `V0 = evaluate(inputs)`. For unit `u`, `Vu = evaluate(inputs \ u)`.
Saliency score `s(u)` is a weighted composite of:
- `action_flip`   : `1.0` if `Vu.verdict != V0.verdict` else `0` (dominant term)
- `severity_shift`: normalised ordinal distance `|sev(Vu) - sev(V0)|`
- `confidence_delta`: `|Vu.confidence - V0.confidence|`

`s(u) = w_a·action_flip + w_s·severity_shift + w_c·confidence_delta`
(default weights `w_a=0.6, w_s=0.25, w_c=0.15`, config-pinned & recorded into
the evidence chain for reproducibility). Map is the ranked, normalised `s(u)`.

### 3.4 Coarse-to-fine + bounded-K (the latency-control core)
8B Q4_K_M CPU inference is multi-second; naive `(1+K)×infer` ≈ minutes/rule.
Synthesis hard-cap is ≤5 rules / 60 s, so a multi-minute XAI/rule is unviable.

**Stage A — region occlusion (3 inferences):** occlude each whole region
(`focal`, `correlated`, `host`) as a block. Identifies the dominant region(s).
**Stage B — refine only dominant region(s):** unit-level occlusion *within* the
region(s) whose Stage-A delta exceeds `region_refine_threshold`. Non-dominant
regions are reported at block granularity with an explicit
`refinement: coarse` marker (Art. 13 honesty: never imply finer attribution
than was computed).
**Bounded-K:** within a refined region, cap at `max_units` (default 12,
most-recent / most-correlated first); remainder summarised as one
`tail` unit. The evidence chain records `saliency_coverage` =
units_explained / units_total (a signed, auditable honesty field).

Worst case ≈ `1 + 3 + max_units` ≈ 16 inferences (vs ~30) — tunable.

### 3.5 KV-cache prefix reuse (optimisation seam, NOT v1)
System prompt + host block are a constant prefix across perturbations; a future
candle-backend hook can cache that prefix's KV state. Documented as a seam; v1
treats `evaluate` as opaque for correctness-first delivery.

### 3.6 Fail-safe timeout (the mandatory guardrail)
`XaiConfig.total_budget` (default 90 s). On exceed → return
`Err(XaiUnavailable::Timeout)`. **Contract:** synthesis MUST map any `Err` to
"do not deploy rule". This is the regulatory fail-closed: no XAI ⇒ no synthesis.

---

## 4. Article-13 evidence-chain schema (`common/src/xai_types.rs`)

`XaiEvidenceChain` (versioned `XAI_SCHEMA_VERSION = "1.0.0"`, mirrors
`ADE_SCHEMA_VERSION` discipline):

```
schema_version, xai_trace_id, ade_trace_id (FK → AdeVerdict.trace_id),
timestamp_utc,
model: { model_id, model_quantization, backend }        // from AdeMetadata
method: { kind: "perturbation/occlusion", weights, max_units,
          region_refine_threshold, total_budget_ms }      // reproducibility
input_snapshot: { focal_event, recent_events (anonymised),
                  host_context, prompt_sha256 }            // what was explained
baseline_verdict: { verdict, severity, confidence }        // V0
saliency_map: [ { region, unit_id, human_label, score,
                  refinement: fine|coarse,
                  delta: {action_flip, severity_shift, confidence_delta} } ]
saliency_coverage: f64                                     // honesty field
environment_hash: String                                   // customer env id
status: complete | degraded(reason)                        // never silent
signature: Option<Ed25519>                                 // §5
```

Roadmap-mandated forensic fields (line 39) → schema mapping is documented
inline in the source so an auditor can trace each Art. 13 requirement.

---

## 5. Signing seam (reuse Tappa 8 crypto)

- `fn canonical_bytes(&self) -> Vec<u8>` — deterministic, field-ordered,
  signature-excluded serialization (the *only* thing ever signed).
- `trait EvidenceSigner { fn sign(&self, msg: &[u8]) -> Signature; }` —
  6.9 ships an ephemeral-key test impl; the real customer-admin-key-chain
  signer is wired by Tappa 8/10.5. Reuses `ed25519_dalek` (already a dep).
- Verification helper for the auditor/console side.

---

## 6. Module / file layout

```
common/src/xai_types.rs            // XaiEvidenceChain, schema, canonical_bytes
agent/src/xai/mod.rs               // XaiEngine, XaiConfig, XaiUnavailable, public API
agent/src/xai/occlusion.rs         // perturbable-unit taxonomy + neutralise ops
agent/src/xai/saliency.rs          // coarse-to-fine driver, scoring, bounded-K
agent/src/xai/evidence.rs          // chain assembly + canonical_bytes + signer seam
agent/src/xai/source.rs            // SaliencySource trait (Perturbation; Attention=future)
agent/src/xai/tests.rs             // deterministic via MockBackend
docs/TAPPA6_9_XAI_PLAN.md          // this doc
```
Public seam for Tappa 10.5:
`XaiEngine::explain(focal: &Event, ctx: &EventContext, verdict: &AdeVerdict, eval: &AdeEngine) -> Result<XaiEvidenceChain, XaiUnavailable>`.
`xai` is a sibling of `ade` (not inside it) — it *consumes* `AdeEngine` via the
existing `evaluate` seam; no ADE internals touched (zero hot-path risk; ADE
behaviour byte-identical when XAI is not invoked).

---

## 7. Hybrid attention seam (future, defined now)

`trait SaliencySource { fn scores(&self, …) -> Vec<UnitScore>; }`
- `PerturbationSource` — v1, canonical, the Art. 13 source of truth.
- `AttentionSource` — deferred; when/if a vendored candle exposes per-layer
  attention, it plugs in as a **secondary corroborating** column in
  `saliency_map` (`attention_score: Option<f64>`), never replacing the
  causal perturbation score. Schema reserves the optional field now so adding
  it later is non-breaking.

---

## 8. Test strategy

- **Deterministic core**: `MockBackend` maps event categories → fixed verdicts,
  so occlusion deltas are exactly predictable → assert exact saliency ranking,
  coverage, coarse/fine markers, timeout fail-closed, schema round-trip,
  `canonical_bytes` stability, sign/verify.
- **Faithfulness oracle**: construct a scenario where one correlated event is
  the sole cause of a KILL (mock); assert that event ranks #1 and its removal
  flips the verdict; assert an irrelevant host field ranks ~0.
- **Guardrail test**: force timeout → `Err(XaiUnavailable)` → assert the
  documented "synthesis must refuse" contract via a stub consumer.
- **No privileged/Hetzner requirement** (black-box, MockBackend) — runs in CI.
- Real-candle latency characterisation: a `#[ignore]` bench (opt-in, needs the
  GGUF) recording p50/p95 inferences-per-explanation, fed back into defaults.

---

## 9. Performance envelope

| | inferences/explanation | est. wall (5 s/infer) |
|--|--|--|
| naive | ~30 | ~150 s ❌ |
| coarse-to-fine + bounded-K (defaults) | ~16 | ~80 s ⚠️ within 90 s budget |
| + KV-prefix reuse (future) | ~16 (cheaper each) | target <40 s |

Budget is **fail-closed**: exceeding it disables synthesis rather than shipping
an unexplained rule. Tunables (`max_units`, thresholds, budget) are config and
recorded into every evidence chain for audit reproducibility.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|--|--|
| Latency makes XAI the synthesis bottleneck | coarse-to-fine, bounded-K, fail-closed budget; KV-reuse seam |
| "Perturbation ≠ true causal attribution" challenge | drop-occlusion *is* counterfactual; document method + weights in-chain; hybrid attention corroboration later |
| Schema churn breaks Tappa 10.5 | versioned schema, reserved optional attention field, FK to `ade_trace_id` |
| Occluded prompt becomes malformed → model reacts to noise | typed neutral sentinels keep prompt schema-valid; drop-mode for events |
| Stale `inference.rs:11-33` doc misleads future devs | plan + a one-line doc-fix PR note that real backend is default since 6.1 |

---

## 11. Phased delivery (fits the "~1 wk evidence binding" + buffer)

- **P1 (≈2 d)** `xai_types.rs` schema + `canonical_bytes` + signer seam + round-trip/sign tests. *Reviewable artifact: the Art. 13 schema.*
- **P2 (≈3 d)** occlusion taxonomy + perturbation source + scoring; deterministic MockBackend faithfulness tests.
- **P3 (≈3 d)** coarse-to-fine driver + bounded-K + fail-closed budget + guardrail contract test.
- **P4 (≈2 d)** `XaiEngine::explain` public seam + evidence assembly + the Tappa-10.5 integration contract doc + `#[ignore]` candle bench.
- **P5 (≈1 d)** docs, stale-doc fix, ADE_DOCTRINE cross-ref, final audit pass.

Each Pn lands as its own atomic commit; P1 schema is reviewed before P2.

---

## 12. Open questions for the owner (pre-P1)

1. **Occlusion default for correlated events**: drop (max faithfulness) vs
   anonymise-in-place (preserves sequence structure). Plan defaults to **drop**
   with anonymise as a config alt — confirm.
2. **Budget number**: 90 s default acceptable as the fail-closed ceiling, or
   tie it to `AdeConfig.timeout × max_inferences` dynamically?
3. **`environment_hash` source**: reuse an existing host/deploy identity
   (is there a deployment-manifest hash already?) or define one in 6.9?
4. Confirm `xai` as a top-level `agent/src/` sibling of `ade/` (vs nested).
```
```
