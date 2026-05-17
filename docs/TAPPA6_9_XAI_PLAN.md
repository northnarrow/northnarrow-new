# Tappa 6.9 — XAI Saliency Mapping — Implementation Plan

Status: **REVIEWED & LOCKED — P0.1** (4 gating questions RESOLVED §12; refinements
R1–R4 applied; R5 scoped as separate P6). P1 may begin.
Author: Claude (staff-eng) · Created 2026-05-17 · P0 anchor commit: see `git log -- docs/TAPPA6_9_XAI_PLAN.md` (5a7e45b)
Driver: EU AI Act Art. 13, pre-beta blocker.
Locked decisions: saliency = **Hybrid (perturbation canonical now, attention seam later)**; approach = plan-first.

---

## 1. Scope & non-goals

### In scope (this tappa; roadmap line-item "XAI evidence chain binding: 1 week" + hardening buffer)
1. A standalone **XAI saliency engine**: given the exact inputs of an ADE
   decision (focal `Event`, `EventContext.recent_events`, `HostContext`) and the
   resulting `AdeVerdict`, produce a **faithful, human-auditable saliency map**
   over the *semantic input units* that drove the decision.
2. An **Article-13 forensic evidence-chain artifact** (`XaiEvidenceChain`)
   binding: the saliency map, the anonymized input snapshot, the verdict, model
   identity/version, deterministic inference settings, timestamps, an
   `environment_hash`, and a **canonical signable byte form** (Ed25519, reusing
   `ed25519_dalek`).
3. The **mandatory guardrail interface**: `explain()` →
   `Result<XaiEvidenceChain, XaiUnavailable>`; the (future) synthesis path is
   contractually required to treat `Err`/timeout as a hard stop ("if XAI is
   unavailable, synthesis is disabled" — roadmap, non-negotiable).
4. A **hybrid seam**: a `SaliencySource` trait so attention-based attribution
   can be added later as a *corroborating* signal without reshaping the schema.

### Explicitly NOT in scope (later tappe)
- Battle-Time rule **synthesis** itself (Tappa 10.5 / roadmap 8–10 wk post-Beta).
- Digital-twin validation, TTL engine, operator console.
- Customer-admin-key-chain signing *infrastructure* (Tappa 8). 6.9 produces the
  canonical signable bytes + a `Signer` seam; tests use an ephemeral keypair
  (same pattern as `admin_auth.rs` tests, ~line 263).
- Patching/vendoring candle to expose attention (hybrid seam *defined* now,
  attention impl deferred — §7).

---

## 2. Why perturbation/occlusion (the locked decision)

- Stock `candle_transformers::models::quantized_llama::ModelWeights.forward()`
  returns logits only — **no attention exposed**. Attention saliency would
  require forking candle against a quantized model (fragile, ongoing burden).
- Gradient/Integrated-Gradients needs autodiff through a GGUF quant model —
  effectively infeasible in candle.
- Perturbation is **black-box**: re-invokes the existing `AdeEngine::evaluate`
  seam with one input unit neutralised and measures the decision delta.
  Backend-agnostic (deterministic `MockBackend` in CI, real Candle in prod) and
  **causally faithful** — the strongest Art. 13 story ("removing *this*
  correlated event flips KILL→ALERT and drops confidence 0.94→0.41").

---

## 3. The saliency algorithm

### 3.1 Perturbable-unit taxonomy
Inputs decompose into semantic units (NOT tokens):

| Region        | Unit                                        | Source |
|---------------|---------------------------------------------|--------|
| `focal`       | each field of the focal `Event` variant     | event passed to `evaluate` |
| `correlated`  | each element of `recent_events` (≤20)       | `EventContext.recent_events` |
| `host`        | each `HostContext` field                    | `EventContext.host_context` |

Total units `K` ≈ (focal fields) + min(20,|recent|) + (host fields) ≈ 25–35.

### 3.2 Occlusion operator
Per unit, produce a **neutralised** copy of the input set:
- correlated event → **DROP the event** (default; the legal "but-for"
  counterfactual — canonical for Art. 13 defensibility). Configurable
  **anonymise-in-place** alternative for models/scenarios where sequence
  *positional encoding* is dominant (dropping perturbs position as a
  confound; anonymising preserves the slot). `occlusion.rs` MUST carry a
  doc-comment stating exactly when to prefer each mode (default = drop;
  anonymise only when positional structure is the analysis target).
- focal/host field → replace with a typed neutral sentinel (`""`, `0`,
  `0.0.0.0`, `unknown`) so the prompt stays schema-valid (the model must react
  to the *absence of signal*, not to malformed input).
- Applied to the **already-sanitised** prompt path (`ade/sanitize.rs`); XAI
  introduces **no new untrusted input surface** (defends the §6.9
  "synthesis as prompt-injection vector" anti-pattern).

**Determinism (R1 — Art. 13 reproducibility, MANDATORY).** The XAI inference
path uses fixed deterministic decoding regardless of production ADE settings:
`temperature = 0`, `top_k = 1`, `top_p = 1.0`, explicit `seed` (recorded even
though greedy ignores it — future-proofs sampling methods), and
single-thread / deterministic-reduce for candle's CPU kernels (multi-thread
float reduction is non-associative → non-reproducible). Production
`AdeEngine::evaluate` MAY differ; `XaiEngine::explain` MUST be bit-reproducible
even at a latency cost. **All** of these are recorded in
`method.inference_settings` so an auditor re-executing `input_snapshot`
against `model.model_id` obtains a **bit-identical** `saliency_map`.

### 3.3 Decision-delta metric
Baseline `V0 = evaluate(inputs)`. For unit `u`, `Vu = evaluate(inputs \ u)`.
`s(u) = w_a·action_flip + w_s·severity_shift + w_c·confidence_delta`
- `action_flip`    = 1.0 if `Vu.verdict != V0.verdict` else 0 (dominant)
- `severity_shift` = normalised ordinal distance `|sev(Vu)-sev(V0)|`
- `confidence_delta`= `|Vu.confidence - V0.confidence|`

Default weights `w_a=0.6, w_s=0.25, w_c=0.15`, config-pinned and recorded in
`method` for reproducibility. Map = ranked, normalised `s(u)`.

### 3.4 Coarse-to-fine + bounded-K (latency-control core)
Naive `(1+K)×infer` ≈ minutes/rule vs the ≤5-rules/60 s synthesis cap.

**Stage A — region occlusion (3 inferences):** occlude each region
(`focal`,`correlated`,`host`) as a block; gives region-level deltas.
**Stage B — refine only dominant region(s):** unit-level occlusion within
regions selected by the threshold below.

**`region_refine_threshold: f64` (default 0.3) [R3].** A region is refined in
Stage B IFF `region_delta >= region_refine_threshold * max_region_delta`.
Example: Stage-A deltas `[focal=0.8, correlated=0.6, host=0.15]`;
`max=0.8`, threshold `=0.3*0.8=0.24` → focal (0.8) refined, correlated (0.6)
refined, host (0.15) NOT refined → reported at block granularity with
`refinement: coarse`. Tunable; recorded in `method.region_refine_threshold`.

**Bounded-K:** within a refined region cap at `max_units` (default 12,
most-recent / most-correlated first). `saliency_coverage =
units_explained / units_total` is a signed honesty field.

**`tail` aggregation rule [R4].** When `max_units` is exceeded in a refined
region, remaining units aggregate into ONE `tail` unit:
- `tail.delta`      = delta from **subset occlusion** — occlude ALL tail units
  together in **one** additional inference ("what if NONE of these had
  happened"). NOT a sum, NOT an average (those would be fabricated
  attribution; subset occlusion is the directly measurable counterfactual).
- `tail.score`      = `max(score of remaining units)` *after* the subset
  inference attributes the block (the block delta bounds the unit scores).
- `tail.unit_id`    = `"tail:N=<count>"`,  `tail.refinement = "coarse"`.
- Cost: +1 inference per refined region that overflows (worst case +3).

### 3.5 KV-cache prefix reuse (optimisation seam, NOT v1)
System prompt + host block are a constant prefix across perturbations; a future
candle hook can cache that prefix's KV state. Seam documented; v1 treats
`evaluate` as opaque (correctness-first).

### 3.6 Fail-safe timeout (the mandatory guardrail)
`XAI_BUDGET_MS` (fixed const, §4 — **90 000 ms**, NOT derived from
`AdeConfig.timeout`: hidden coupling is bad for regulatory predictability).
On exceed → `Err(XaiUnavailable::Timeout)`. **Contract:** synthesis MUST map
any `Err` to "do not deploy rule". Regulatory fail-closed: no XAI ⇒ no
synthesis. The deterministic-decoding settings (§3.2 R1) are part of this
path's contract and are themselves recorded into every chain.

---

## 4. Article-13 evidence-chain schema (`common/src/xai_types.rs`)

`XaiEvidenceChain` (versioned `XAI_SCHEMA_VERSION = "1.0.0"`, mirrors the
`ADE_SCHEMA_VERSION` discipline). `XAI_BUDGET_MS: u64 = 90_000` lives here as a
`const` with an extended rationale doc-comment (5-rules/60 s synthesis cap +
coarse-to-fine ~16–19 inferences × ~5 s worst case + margin; future bumps via
dedicated commit + rationale, never dynamic).

```
schema_version, xai_trace_id, ade_trace_id (FK → AdeVerdict.trace_id),
timestamp_utc,
model:  { model_id, model_quantization, backend }          // from AdeMetadata
method: { kind: "perturbation/occlusion",
          weights {w_a,w_s,w_c}, max_units, region_refine_threshold,
          total_budget_ms,                                  // = XAI_BUDGET_MS
          occlusion_mode: drop|anonymise_in_place,
          inference_settings {                              // R1, reproducibility
            temperature, top_k, top_p, seed, thread_mode } }
input_snapshot: { focal_event, recent_events (anonymised),
                  host_context, prompt_sha256 }
environment_hash: String                                    // Q3, see below
baseline_verdict: { verdict, severity, confidence }         // V0
saliency_map: [ { region, unit_id, human_label, score,
                  refinement: fine|coarse,
                  delta {action_flip, severity_shift, confidence_delta},
                  attention_score: Option<f64> } ]           // reserved (§7)
saliency_coverage: f64                                       // honesty field
status: complete | degraded(reason)                          // never silent
signature: Option<XaiSignature{ sig:64B, signer_pubkey:32B }>
```

**`environment_hash` definition (Q3 — defined here in 6.9; no prior manifest):**
```
environment_hash = sha256(
    agent_binary_sha256  ||
    model_file_sha256    ||
    combat_rules_sha256  ||
    hostname_canonical   ||   // `hostname --fqdn`, fallback `hostname`
    agent_build_commit_sha    // git rev-parse HEAD at build (BUILD_SHA env)
)
```
Computed once at `AdeEngine` init, cached, embedded in every chain.
Forward-compatible: Tappa 14.x TEE attestation may evolve the *contents*
while preserving the field name (schema versioning covers the transition).

### 4.1 Article 13 → `XaiEvidenceChain` mapping [R2]

The regulatory dossier carries this table (in-source comments alone are
insufficient for the EU compliance package):

| Art. 13 clause | Requirement                         | Schema field(s) |
|----------------|-------------------------------------|------------------|
| 13(1)          | sufficient operational transparency | `input_snapshot` + `method` |
| 13(2)          | operating instructions              | out of scope — separate operator runbook references this doc |
| 13(3)(a)       | provider identity                   | `model.model_id`, `environment_hash` |
| 13(3)(b)(i)    | intended purpose                    | `method.kind` + `ADE_DOCTRINE` cross-ref |
| 13(3)(b)(iv)   | performance + accuracy              | `saliency_coverage`, `status`, `signature` |
| 13(3)(c)       | identifiable output                 | `xai_trace_id`, `ade_trace_id` (FK) |
| 13(3)(d)       | human-oversight prerequisite        | guardrail: synthesis disabled if `XaiUnavailable` |

---

## 5. Signing seam (reuse Tappa 8 crypto)

- `fn canonical_bytes(&self) -> Vec<u8>` — deterministic, field-ordered,
  **signature-excluded** serialization (the only thing ever signed). Invariant:
  all collections are `Vec`/ordered (no map types), field order = declaration
  order; documented as the canonical-form contract.
- `trait EvidenceSigner { fn sign(&self, msg:&[u8]) -> Signature; }` +
  `fn verify(chain, pubkey) -> bool` helper. 6.9 ships an ephemeral-key test
  impl; the real customer-admin-key-chain signer is Tappa 8/10.5. Reuses
  `ed25519_dalek` (already a workspace dep via the agent crate).

---

## 6. Module / file layout

```
common/src/xai_types.rs            // XaiEvidenceChain, schema, consts, canonical_bytes, signer seam
agent/src/xai/mod.rs               // XaiEngine, XaiConfig, XaiUnavailable, public API
agent/src/xai/occlusion.rs         // perturbable-unit taxonomy + neutralise ops (+ mode doc-comment)
agent/src/xai/saliency.rs          // coarse-to-fine driver, scoring, bounded-K, tail
agent/src/xai/evidence.rs          // chain assembly + canonical_bytes wiring + signer seam
agent/src/xai/source.rs            // SaliencySource trait (Perturbation; Attention=future)
agent/src/xai/tests.rs             // deterministic via MockBackend
docs/TAPPA6_9_XAI_PLAN.md          // this doc
```
Q4 RESOLVED: `agent/src/xai/` is a **top-level sibling of `agent/src/ade/`**
(decoupled from ADE internals, can explain non-LLM decisions later, matches the
Tappa 10.5 consumer pattern). Public seam:
`XaiEngine::explain(focal:&Event, ctx:&EventContext, verdict:&AdeVerdict, eval:&AdeEngine) -> Result<XaiEvidenceChain, XaiUnavailable>`.
`xai` *consumes* `AdeEngine` via the existing `evaluate` seam only — no ADE
internals touched (ADE behaviour byte-identical when XAI is not invoked).

---

## 7. Hybrid attention seam (future, defined now)

`trait SaliencySource { fn scores(&self, …) -> Vec<UnitScore>; }`
- `PerturbationSource` — v1, canonical, the Art. 13 source of truth.
- `AttentionSource` — deferred; if a vendored candle later exposes per-layer
  attention it plugs in as a **secondary corroborating** column
  (`saliency_map[].attention_score: Option<f64>`, reserved now), never
  replacing the causal perturbation score. Adding it is non-breaking.

---

## 8. Test strategy

- **Deterministic core** via `MockBackend` (category→fixed verdict): assert
  exact saliency ranking, coverage, coarse/fine markers, tail subset-occlusion
  value, timeout fail-closed, schema round-trip, `canonical_bytes` stability,
  sign/verify, tamper-detection.
- **Faithfulness oracle**: scenario where one correlated event is the sole
  cause of KILL → assert it ranks #1, its drop flips the verdict, an
  irrelevant host field ranks ~0.
- **Guardrail test**: force timeout → `Err(XaiUnavailable)` → stub consumer
  asserts the "synthesis must refuse" contract.
- CI-only (black-box, MockBackend) — no privileged/Hetzner requirement.
- `#[ignore]` real-candle bench (opt-in, needs GGUF) records
  inferences-per-explanation + wall time → tunes defaults.

---

## 9. Performance envelope

`XAI_BUDGET_MS = 90 000` (fixed, Q2). Inference count:

| | inferences/explanation | est. wall @ ~5 s/infer |
|--|--|--|
| naive | ~30 | ~150 s ❌ |
| coarse-to-fine, **typical** (1 region refined, no tail) | 1+3+≤12 ≈ 8–16 | ~40–80 s ✅ |
| coarse-to-fine, **worst** (3 regions, all overflow tails) | 1+3+12+3 ≈ 19 | ~95 s — exceeds budget → **fail-closed** |

Worst case breaching 90 s is **correct behaviour, not a bug**: it returns
`XaiUnavailable` ⇒ synthesis refuses the rule (regulatory fail-closed). The
P4 `#[ignore]` candle bench tunes `max_units` / `region_refine_threshold`
against the real model so the *typical* case sits comfortably inside budget;
`XAI_BUDGET_MS` itself stays fixed (future bumps = dedicated commit + rationale).

---

## 10. Risks & mitigations

| Risk | Mitigation |
|--|--|
| Latency makes XAI the synthesis bottleneck | coarse-to-fine, bounded-K, fail-closed budget; KV-reuse seam |
| "Perturbation ≠ causal attribution" challenge | drop-occlusion *is* the but-for counterfactual; method+weights+settings in-chain; hybrid attention corroboration later |
| Non-reproducible inference voids Art. 13 | R1 deterministic decoding, recorded in `method.inference_settings`; auditor re-exec must be bit-identical |
| Schema churn breaks Tappa 10.5 | versioned schema, reserved `attention_score`, FK to `ade_trace_id`, golden regression set (P6) |
| Occluded prompt malformed → model reacts to noise | typed neutral sentinels keep prompt schema-valid; drop-mode for events |
| Stale `inference.rs:11-33` doc misleads devs | P5 one-line doc-fix (real backend default since 6.1) |

---

## 11. Phased delivery (atomic commits; P1 schema reviewed before P2)

- **P1 (≈2 d)** `common/src/xai_types.rs`: schema + `XAI_SCHEMA_VERSION` +
  `XAI_BUDGET_MS` const + `method.inference_settings` + `environment_hash`
  field + `canonical_bytes` + signer seam + round-trip/canonical-stability/
  sign-verify/tamper tests. **→ owner schema audit before P2.**
- **P2 (≈3 d)** occlusion taxonomy + `PerturbationSource` + scoring;
  deterministic MockBackend faithfulness tests; occlusion-mode doc-comment.
- **P3 (≈3 d)** coarse-to-fine driver + `region_refine_threshold` + bounded-K
  + `tail` subset-occlusion + fail-closed budget + guardrail contract test.
- **P4 (≈2 d)** `XaiEngine::explain` seam + evidence assembly +
  `environment_hash` computation/caching + Tappa-10.5 integration contract
  doc + `#[ignore]` candle bench + default tuning.
- **P5 (≈1 d)** docs, stale-`inference.rs` doc-fix, `ADE_DOCTRINE` cross-ref,
  final Art. 13 audit pass. *(docs/audit closeout only — kept clean.)*
- **P6 (≈1 d) — golden saliency regression dataset [R5, DECISION: separate
  phase].** `tests/fixtures/xai_golden/` with N=5–10 scenarios (one per
  `Event` variant family + 1–2 multi-event correlation cases); each =
  `input.json` / `verdict.json` / `saliency.json` (canonical
  `XaiEvidenceChain`). Test asserts MockBackend output **byte-identical** to
  fixture. Regression anchor for schema evolution: a v2.0.0 weight/taxonomy
  change MUST update fixtures with rationale + audit-log entry in the commit
  body.
  *R5 rationale (owner deferred to my judgment): P6 is a distinct deliverable
  type (regression-anchor test infra) vs P5's docs/audit closeout; it depends
  on the P1–P4 pipeline being frozen (it captures the full canonical output);
  a separate phase keeps atomic-phase discipline and gives the golden fixtures
  their own reviewable commit carrying the schema-evolution governance rule.
  Folding it into P5 would mix concerns and double an otherwise-clean
  closeout. Cost identical (~1 d); sequencing cleaner.*

Total ≈ 12 d core (within the roadmap "1 wk evidence binding" + hardening
buffer the owner allotted at 2–3 wk).

---

## 12. Gating questions — RESOLVED (owner, 2026-05-17)

- **Q1 occlusion default — RESOLVED: DROP.** Max counterfactual faithfulness;
  the legal "but-for" canonical for Art. 13. Anonymise-in-place = configurable
  alt for positional-encoding-dominant cases. `occlusion.rs` carries the
  when-to-prefer doc-comment (§3.2).
- **Q2 fail-closed budget — RESOLVED: FIXED `const XAI_BUDGET_MS: u64 =
  90_000;`** in `common/src/xai_types.rs` with rationale doc-comment. NOT
  derived from `AdeConfig.timeout` (hidden coupling harms regulatory
  predictability). Future bumps = dedicated commit + rationale.
- **Q3 `environment_hash` — RESOLVED: DEFINE in 6.9** (no prior manifest hash).
  Composition + lifecycle in §4. TEE-attestation-forward-compatible via schema
  versioning.
- **Q4 module placement — RESOLVED: top-level `agent/src/xai/`**, sibling of
  `ade/` (§6) — decoupled, future non-LLM explainability, Tappa-10.5 consumer
  pattern.
- **R5 golden dataset — RESOLVED (my call): separate P6** (rationale in §11).
```
```
