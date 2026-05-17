# Tappa 6.9.7 — RAG Local Knowledge Base — Implementation Plan

Status: **DRAFT — awaiting owner review** (gating questions §12 + the
Article-13 schema ruling §5 are BLOCKING; no P2+ code until ruled).
Author: Claude (staff-eng) · Created 2026-05-17 · Branch:
`tappa-6.9.7-rag-kb-plan`.
Driver: pulled pre-beta so **Phase C (RAG-trust calibration training)**
can run pre-beta alongside Phase B — epistemic resilience + EU AI Act
Art. 13(3)(b)(ii) robustness. Sovereign-principle play (ADE_DOCTRINE
"data processing is EU-sovereign", 100%-Rust/no-FFI charter).
Predecessor: Tappa 6.9 XAI **CLOSED** at `1726ace` (the chain that will
eventually bind retrieval provenance — see §5).

---

## 0. The single most important fact: this is a *swap*, not a greenfield

Sub-tappa **6.7 already shipped the RAG architecture and the entire
ADE integration seam.** 6.9.7 replaces the retrieval *mechanism* and
scales the *corpus* **behind that existing seam**. Blast radius is
deliberately small; the plan is organised around preserving it.

| Layer | 6.7 shipped (today) | 6.9.7 changes | Stays unchanged |
|---|---|---|---|
| Corpus | 30 hand-curated docs (`rag/kb_seed.rs`) | pinned MITRE/Sigma/LOLBAS snapshots (10³–10⁴ docs) | `KbCategory` 5 buckets (`common/src/rag_types.rs`) |
| Retrieval | hashed-n-gram 384-dim embed + cosine over in-mem store (`rag/embedder.rs`,`rag/store.rs`) | **deterministic BM25 via `tantivy`**, on-disk mmap index | `RagEngine::retrieve(RagQuery)->RagResult` **signature** |
| Schema | `RagDocument{id,category,title,content,similarity:f32}`, `RagResult` | `similarity` semantics: cosine → normalised BM25 (doc-comment fix) | `RagDocument`/`RagResult`/`RagQuery` **shape** (in `common`, kept for the C2/CLI deserialize charter) |
| ADE wiring | `AdeEngine::with_rag(Arc<RagEngine>)`, `EngineInner.rag: Option<_>` (default `None`), `build_structured_prompt_with_rag`, `format_rag_block`, the `=== RELEVANT CYBERSEC KNOWLEDGE ===` block; `assembled_prompt` (6.9 P4) already includes it | **nothing structural** — only construct `RagEngine::open_index(...)` and pass it to the *existing* `with_rag`, behind a canary flag | the whole prompt-splice path; the `rag: None ⇒ byte-identical to pre-6.7` invariant |

**Consequence:** "P5 — ADE integration" is mostly a 6.7 asset we reuse;
the real engineering is P2 (KB acquisition) + P3 (tantivy index) + P4
(BM25 retrieval keeping the API) + P6 (bench/golden). The plan must
*protect* the existing seam, not rebuild it.

---

## 1. Scope & non-goals

### In scope (≈1.5 wk)
1. A **sovereign, deterministic, on-disk BM25 retrieval layer** that
   drop-in replaces the 6.7 embedding store *behind the unchanged
   `RagEngine::retrieve` API*.
2. A **pinned-snapshot KB acquisition pipeline** (xtask) for
   MITRE ATT&CK / Sigma / LOLBAS, with per-source SHA-256 provenance
   and a single content-addressed **KB index hash**.
3. A **canary-gated ADE activation** (`NN_ADE_RAG_ENABLED=1`) reusing
   the existing `with_rag` seam, for A/B before any default flip.
4. **Latency + golden-retrieval** bench/tests (≤50 ms p95 target).
5. An **Article-13 retrieval-provenance decision** (§5 — owner ruling),
   *documented*, implemented only after the ruling.

### Explicitly NOT in scope
- **Phase C training itself** (next tappa) — 6.9.7 only guarantees the
  retrieval signal Phase C trains on is the one production will use.
- Re-enabling embedding/ANN retrieval (deferred hybrid seam, §7).
- Live internet ingestion (forbidden — sovereign constraint 1).
- Volatile IoC feeds in V1 (determinism/immutability conflict — §4, Q3).
- Mutating the **XAI 1.0.0** schema *unless* the §5 ruling says so
  (standing audit trigger #1 from the 6.9 closure: any
  `XAI_SCHEMA_VERSION` change is a deliberate breaking commit).

---

## 2. Why BM25 / `tantivy` (the recommendation — confirm in §12 Q1)

The user pre-stated the preference; here is the defensible rationale,
and the alternatives weighed:

- **`tantivy`**: mature pure-Rust full-text engine (Lucene-class BM25),
  embedded (no server), `mmap` on-disk segments, fast. **No FFI** — the
  same 100%-Rust charter that rejected `llama-cpp-2` in Tappa 6 and
  forced perturbation-over-attention in 6.9. Deterministic scoring for
  a fixed index. **Recommended.**
- *Keep/scale the 6.7 hashed-n-gram embedder* — rejected: opaque
  similarity, not auditable, no provenance story, poor recall at scale.
- *bge-small-en-v1.5 candle ANN* — rejected **for V1 beta**: adds an
  embedding-model dependency + load cost, weaker auditability, and
  cross-build determinism risk. Kept as the **deferred hybrid** (§7) —
  `KB_EMBEDDING_DIM=384` and the store layout were chosen by 6.7 to
  survive this exact future swap.
- *SQLite FTS5 / Lucene-via-FFI* — rejected: C dependency, violates the
  no-FFI charter.
- *Hand-rolled BM25* — rejected: tantivy already solves
  segmenting/codec/mmap/tie-breaking; NIH risk for a 1.5 wk tappa.

---

## 3. Retrieval design

### 3.1 Determinism (the Phase-C + Art-13 hard requirement)
Same query + same KB index ⇒ **identical ranked top-K**, always.
- BM25 is deterministic for a fixed index + analyzer. **Pin the
  `tantivy` version** (a scoring/codec change is a deliberate
  index-rebuild commit).
- **Tie-break (R1, refinement — confirm §12):** equal BM25 scores MUST
  be broken by a stable key (`doc.id` ascending), never by internal
  `DocId`/segment order (which can shift on rebuild). The retrieval
  layer sorts `(-bm25, id)`.
- **Index reproducibility:** same pinned source snapshots + same
  tantivy version + same analyzer config ⇒ byte-reproducible index, or
  at minimum a stable **KB index hash** = `sha256` over the
  *canonicalised source dump* (not the tantivy segment bytes, which may
  embed timestamps — R2, confirm). The hash is the auditable identity.

### 3.2 Index schema (tantivy fields)
Proposed document schema (maps onto the existing 5 `KbCategory`):
`id` (STRING, stored, indexed-raw) · `category` (STRING/facet, stored) ·
`title` (TEXT, stored) · `content` (TEXT, stored) ·
`source_ref` (STRING, stored — e.g. `attack:T1059.001`,
`sigma:<rule-id>`, `lolbas:<bin>`) · `severity`/`platform` (STRING,
stored, optional). Tokeniser: default `en` + lowercase; **no
stemming/stopwords by default** (R3, confirm — security tokens like
`xmrig`, `T1059.001`, `/etc/passwd` must survive intact; a custom
analyzer that keeps dotted/slashed identifiers is likely needed).

### 3.3 Query construction
Reuse the existing `ade::rag_integration::build_rag_query_from_event`
(6.7) so Phase C trains on the *same* query derivation production uses.
The BM25 query is a should-match over the derived terms; `top_k` /
`min_score` defaults come from `RagQuery` (today
`DEFAULT_TOP_K`/`DEFAULT_MIN_SIMILARITY`). **`min_similarity` semantics
change** (cosine→BM25) — see 3.4.

### 3.4 Scoring & the `similarity` field (schema-touch — §12 Q4)
`RagDocument.similarity: f32` is documented in `common/src/rag_types.rs`
as cosine ∈ [0,1]. BM25 is unbounded ≥ 0. Options:
- **(a)** Reuse the field, store a **normalised** BM25
  (`score / max_score_in_result` ∈ [0,1]); update the doc-comment.
  Zero schema churn (good for the C2/CLI deserialize charter); but the
  number is now relative-within-result, not an absolute. **Recommended.**
- **(b)** Add `RagDocument.bm25_raw: Option<f32>` alongside.
  Additive, but a `common` schema change rippling to every consumer.
Conservative no-match (sovereign constraint, Phase-C input):
`min_score` floor ⇒ **empty `RagResult`** (the 6.7 `is_empty()` path is
already handled conservatively downstream — preserve it).

---

## 4. KB content sources (pinned snapshots; proposals — §12 Q2/Q3)

All **pinned to an immutable ref**, SHA-256 per source, mapped into the
existing `KbCategory`. Sovereign: fetched by xtask at *build/release*
time from the upstream (or a customer-controlled mirror at install —
§12 Q5), never by the agent at runtime.

| Source | Pin | → KbCategory | Distilled fields | License (VERIFY — R4/risk) |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise STIX 2.1 (`mitre/cti`) | a tagged ATT&CK release | `MitreTechnique` | technique id, name, description, platforms, data-sources | MITRE ATT&CK Terms of Use (attribution) |
| SigmaHQ `sigma` (`rules/linux/**`, `rules/**/builtin` subset) | a pinned commit | `SigmaRule` | rule id, title, logsource, distilled detection summary (NOT raw YAML) | Detection Rule License (DRL 1.1) |
| LOLBAS-Project | a pinned commit | `Lolbas` | binary, description, sample command, ATT&CK mapping | MIT |
| (existing 6.7 curated Linux/tooling notes) | in-repo | `LinuxPattern`,`ThreatTool` | keep as-is, re-indexed | in-repo |
| **IoC feeds** | — | — | **DEFERRED in V1** (Q3): volatile feeds break determinism/immutability; conflict with the audit story. Options: (i) none in V1 *(recommended)*; (ii) pinned curated snapshot w/ explicit staleness caveat; (iii) customer-mirror at install (sovereign seam, later). | — |

Acquisition output: a **canonical JSON dump** (one stable schema,
sorted keys, LF) per source → the input the tantivy index is built
from and the input the KB index hash is taken over (decouples
provenance from tantivy's binary format).

---

## 5. ⚠️ Article-13 compatibility — SCHEMA QUESTION (BLOCKING owner ruling)

**Question (verbatim from the assignment):** add a
`retrieved_snippets_sha256` field to the XAI chain, *or* rely on the
existing `prompt_sha256`?

**Facts that bound the ruling:**
- 6.9 P4's `AdeEngine::assembled_prompt` already splices the RAG block,
  so `XaiInputSnapshot.prompt_sha256` **already binds the retrievals
  transitively** — integrity/tamper-evidence is covered today, no
  schema change.
- What `prompt_sha256` does NOT give: *separable* retrieval provenance
  — "which KB docs + which KB index hash drove this verdict",
  independently auditable from the rest of the prompt.
- Standing audit trigger #1 (6.9 closure): any `XAI_SCHEMA_VERSION`
  change is a **deliberate breaking commit with migration notes** +
  `canonical_bytes` update + byte-lock re-derivation.

**Options (owner picks; I implement only after the ruling):**
- **Option A — rely on `prompt_sha256`.** XAI stays frozen at 1.0.0
  (honours the standing trigger by *not* tripping it). Retrieval
  provenance lives in a *separate, unsigned* RAG retrieval log
  (`kb_index_hash` + retrieved `id`s + scores) outside the signed XAI
  schema. **Recommended** for V1: maximal provenance, zero XAI-schema
  risk, clean Phase-C story.
- **Option B — extend `XaiInputSnapshot`** with optional
  `retrieved_snippets_sha256: Option<String>` (+ likely
  `kb_index_hash: Option<String>`). Stronger single-artifact story, but
  bumps `XAI_SCHEMA_VERSION` 1.0.0→1.1.0, touches `canonical_bytes`,
  re-derives the P1.1 byte-lock, needs migration notes — a deliberate
  breaking change to a *closed, shipped* regulatory artifact.

**No implementation of either until the owner rules.** (Defaulting to A
in the plan only as the recommendation; not code.)

---

## 6. Module / file layout & integration

```
agent/src/rag/index_tantivy.rs   // NEW: tantivy schema, build, open, BM25 search
agent/src/rag/retrieval.rs       // RagEngine: add open_index(); keep retrieve() API
agent/src/rag/kb_dump.rs         // NEW: canonical JSON dump model + KB index hash
xtask/ (new subcommand)          // KB acquisition: pinned fetch → canonical dump → tantivy build
agent/src/rag/embedder.rs        // 6.7 — retained, dormant (hybrid seam §7)
agent/src/rag/store.rs           // 6.7 — retained, dormant
common/src/rag_types.rs          // doc-comment fix only (3.4a) — NO shape change
docs/TAPPA6_9_7_RAG_KB_PLAN.md   // this doc
```
**Placement decision (§12 Q6):** keep `agent/src/rag/` (sibling of
`ade/`, exactly where 6.7 put it and where `with_rag` already wires).
Promoting it is unnecessary churn — recommend KEEP.
**Integration point:** agent startup constructs
`RagEngine::open_index(kb_path)` and calls the *existing*
`AdeEngine::with_rag(...)` iff `NN_ADE_RAG_ENABLED=1`. No change to
`evaluate`, `assembled_prompt`, `structured_prompt`, or the prompt
block. The `rag: None ⇒ byte-identical to pre-6.7` invariant is a
*release gate*, not a nice-to-have (preserves XAI determinism when RAG
is off).

---

## 7. Deferred hybrid seam (future, not 6.9.7)

The 6.7 embedder/store are retained dormant. A future tappa may add an
embedding re-rank *over BM25 candidates* (BM25 recall → bge-small
re-rank) once a sovereign candle bge-small backend exists. `RagResult`
already carries `query_embedding_ms` (0 under BM25-only) so adding it is
non-breaking — the same "reserve the field" discipline as XAI's
`attention_score`.

---

## 8. Test strategy

- **Determinism:** same query+index ⇒ identical ranked ids, twice
  (incl. the R1 tie-break on synthetic equal-score docs).
- **KB index hash stability:** canonical dump → hash is stable across
  runs/hosts; changing one source byte changes it (tamper-sensitive,
  mirrors the 6.9 `environment_hash` test pattern).
- **Golden retrieval:** 20–30 known eBPF-event scenarios (xmrig spawn,
  `/etc/shadow` open, LOLBAS `certutil` download, base64 piped to sh,
  …) → asserted expected top-snippet `id`(s). The Phase-C calibration
  anchor.
- **Canary parity (release gate):** `NN_ADE_RAG_ENABLED` unset ⇒ ADE
  output byte-identical to no-RAG (the 6.7 invariant; protects XAI).
- **No-match conservatism:** below-floor query ⇒ empty `RagResult`,
  verdict path unchanged.
- **Bench (#[ignore]-able or fast):** `NN_RAG_BENCH_N` (default 30,
  mirroring `NN_XAI_BENCH_N`); cold (first mmap) + warm p50/p95.
- Hermetic: index built from a tiny fixture corpus in CI; full corpus
  build is an xtask, not a unit test.

## 9. Performance envelope

Target **≤50 ms p95** retrieval (constraint 3). tantivy BM25 over
10³–10⁴ docs is typically sub-ms warm; the real costs are first-call
mmap/segment open (mitigated by **lazy-load once on first RAG
evaluate**, same discipline as the XAI dedicated-engine lazy-load) and
query analysis. Bench reports cold vs warm separately. Interaction with
the XAI R-P3.2 ledger: RAG latency is *additive to ADE `evaluate`*,
which the XAI budget already measures end-to-end via `evaluate` timing —
so no separate XAI-budget change, but the plan notes it explicitly and
the bench records evaluate-with-RAG vs without.

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Corpus license incompat. with packaging | R4: verify MITRE ToU / Sigma DRL-1.1 / LOLBAS-MIT before P2 ships; attribution file; flag in §12 if any blocks shipping-with-agent (then → install-from-mirror) |
| tantivy version drift changes scores | pin exact version; rebuild = deliberate commit + new KB index hash + golden refresh |
| Index size bloats the agent artifact | measure in P3; if large → install-time build from customer mirror (Q5) rather than ship-prebuilt |
| Corpus staleness vs immutability | deliberate: V1 indexes *stable taxonomic* knowledge (ATT&CK/Sigma/LOLBAS), not volatile IoCs (Q3); KB version pinned to agent version |
| Security identifiers lost to tokeniser | R3 custom analyzer preserving dotted/slashed/`T####` tokens; golden tests guard it |
| RAG perturbs XAI determinism | canary-off parity is a release gate; RAG is itself deterministic so RAG-on is still reproducible |
| Scope creep into Phase C | Phase C is explicitly out (§1); 6.9.7 ends at "production-equivalent retrieval signal exists + golden-locked" |

## 11. Phased delivery (plan-first; owner gate between phases, as 6.9)

- **P1 — this doc.** Owner reviews; rules §5 + §12. *(current)*
- **P2 — KB acquisition pipeline** (xtask): pinned fetch → canonical
  JSON dump → per-source SHA-256 + KB index hash. Atomic commit.
  → owner gate.
- **P3 — tantivy index build**: schema (§3.2), analyzer (R3), persist,
  lazy `open`. → owner gate.
- **P4 — BM25 retrieval**: `RagEngine::open_index` + BM25 search +
  R1 tie-break + 3.4 scoring, *keeping `retrieve()` API*. Determinism
  + golden tests. → owner gate (audit retrieval correctness).
- **P5 — ADE canary integration**: wire existing `with_rag` behind
  `NN_ADE_RAG_ENABLED`; canary-off parity gate. → owner gate.
- **P6 — bench + golden**: latency p50/p95, 20–30 golden cases,
  index-hash stability. → owner gate.
- **P7 — docs closeout**: ADE_DOCTRINE + XDR_ROADMAP annotation; the
  §5 Art-13 artifact *iff* the ruling requires it; memory closure.

Each phase: atomic commit, push, notify, STOP at the gate (the 6.9
iteration pattern the owner endorsed). `clippy --workspace
--all-targets -D warnings 0/0` is a per-phase release gate.

## 12. Gating questions — RULINGS REQUESTED (blocking, like 6.9 §12)

- **Q1 — engine:** confirm `tantivy` (pin which version?) vs any
  alternative. *(rec: tantivy, latest stable, pinned)*
- **Q2 — corpus set:** MITRE ATT&CK + Sigma + LOLBAS as proposed? Which
  exact pins (ATT&CK release tag, Sigma/LOLBAS commit)?
- **Q3 — IoC feeds:** V1 = none *(rec)* / pinned-snapshot / mirror-seam?
- **Q4 — `similarity` field:** (a) reuse w/ normalised BM25 + doc-fix
  *(rec)* vs (b) add `bm25_raw` to the `common` schema.
- **Q5 — KB packaging:** ship pre-built index *with* the agent vs build
  at install from a customer-controlled mirror (sovereign; depends on
  index size from P3 + Q2 licenses).
- **Q6 — module placement:** keep `agent/src/rag/` *(rec)* vs promote.
- **Q7 — Article-13 (§5):** Option A (rely on `prompt_sha256`, XAI
  frozen, separate unsigned RAG log) *(rec)* vs Option B (extend
  `XaiInputSnapshot`, bump `XAI_SCHEMA_VERSION`).
- **Q8 — corpus licenses (R4):** confirm MITRE ToU / Sigma DRL-1.1 /
  LOLBAS-MIT permit shipping-with-agent; else mandate install-from-mirror.
- **Q9 — canary default-flip criteria:** what A/B evidence flips
  `NN_ADE_RAG_ENABLED` to default-on (a later tappa, not 6.9.7)?
- **Refinements proposed:** R1 stable tie-break `(-bm25,id)`; R2 KB
  index hash over canonical dump (not segment bytes); R3 security-token
  -preserving analyzer; R4 license verification before P2 ships.

---

*Plan of record once approved. No P2+ code until §5 + §12 are ruled.*
