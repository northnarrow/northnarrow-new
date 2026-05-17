# Tappa 6.9.7 — RAG Local Knowledge Base — Implementation Plan

Status: **P1.2 — all four rulings folded; P2 GREENLIT.** RULED: §5/Q7 =
**Option A** (§5.1); Q1 = `tantivy =0.25.0` (+bump-if-verified clause,
§12.1); Q2 = ATT&CK **v18.1** + Sigma/LOLBAS **HEAD@P2**; plus the P1.1
rulings (Q3 no-IoC, Q4a, Q5 both modes, Q8 NOTICES/LICENSES).
**P2 commit is HARD-GATED on Q8/R4 license verification** (owner: any
MITRE-ToU / Sigma-DRL-1.1 / LOLBAS-MIT incompatibility with
ship-with-agent ⇒ FLAG before P2 commit ⇒ re-rule Q5 → install-only).
⚠️ **Recurring transmission gap (3rd turn):** the owner's "verbatim"
artifacts — §5 5-point rationale, the Cargo.toml comment template, the
provenance JSON template, and the §13 8-point checklist — were
*described but not included*. CC has rendered each faithfully to the
owner's stated structure and **flagged each as CC-authored-to-spec,
not owner-verbatim**; §13 stays a CC DRAFT (non-blocking for P2).
Author: Claude (staff-eng) · Created 2026-05-17 · Rev P1.2 ·
Branch: `tappa-6.9.7-rag-kb-plan`.
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
  tantivy version + same analyzer config ⇒ stable **KB index hash**
  taken over the *canonicalised source dump* (NOT tantivy segment
  bytes, which embed build timestamps/segment UUIDs — R2, confirmed by
  condition 7). The hash is the auditable KB identity, referenced by
  Article-13 provenance (§5).

#### 3.1.1 KB index hash — normative spec (condition 7)

The canonical dump (§4.1) is the single hashed preimage. The hash is
domain-separated and order-deterministic:

```text
kb_index_hash = lower_hex(sha256(
    b"NN-RAG-KB-CANON-v1\0"                         ||  # domain sep (versioned)
    u32_be(num_sources) ||
    for each source in SORTED(source_id):                # lexicographic by source_id
        u32_be(len(source_id))   || source_id_utf8   ||  # "attack" | "sigma" | "lolbas" | ...
        u32_be(len(upstream_url))|| upstream_url_utf8 ||
        u32_be(len(pin))         || pin_utf8          ||  # commit hash / release tag
        sha256(canonical_source_dump_bytes)               # 32 raw bytes; dump = §4.1 format
))
```

Fixed 32-byte digests + u32-BE length prefixes on every variable field
⇒ unambiguous preimage (the same discipline as the 6.9
`environment_hash`, audit F3). The `-v1` domain tag versions the hash
encoding; a layout change is a deliberate bump (mirrors XAI
`CANON_DOMAIN`).

Worked example (3 sources, illustrative digests):

```text
sources (sorted): attack, lolbas, sigma
  attack: url=https://github.com/mitre/cti pin=ATTACK-vXX
          sha256(dump)=aa..aa (32B)
  lolbas: url=https://github.com/LOLBAS-Project/LOLBAS pin=<commit>
          sha256(dump)=bb..bb
  sigma:  url=https://github.com/SigmaHQ/sigma pin=<commit>
          sha256(dump)=cc..cc
preimage = "NN-RAG-KB-CANON-v1\0" || u32_be(3)
         || u32_be(6)||"attack" || u32_be(31)||"https://github.com/mitre/cti"
            || u32_be(10)||"ATTACK-vXX" || aa..aa
         || u32_be(6)||"lolbas" || ... || bb..bb
         || u32_be(5)||"sigma"  || ... || cc..cc
kb_index_hash = lower_hex(sha256(preimage))   # 64 hex chars
```

A P2 unit test locks this with fixture digests (tamper-sensitive, like
`canonical_bytes_byte_locked_for_sample`).

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

## 4. KB content sources — RULED (Q3, Q4a, Q5, Q8)

All **pinned to an immutable ref**, SHA-256 per source, mapped into the
existing `KbCategory`. Sovereign: acquired by `xtask` at build/release
time from upstream, OR at install from a customer-controlled mirror —
**both modes (Q5 RULED = both; condition 4)**, never by the agent at
runtime. `RagDocument.similarity` reused with normalised BM25 + a
doc-comment fix (**Q4 RULED = (a)**); no `common` schema shape change.

| Source | Pin (⚠ owner to specify — Q2) | → KbCategory | Distilled fields | License |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise STIX 2.1 (`github.com/mitre/cti`) | release tag — **Q2 owner pick** | `MitreTechnique` | technique id, name, description, platforms, data-sources | MITRE ATT&CK Terms of Use (attribution req.) |
| SigmaHQ `sigma` (`rules/linux/**`, builtin subset) | commit — **Q2 owner pick** | `SigmaRule` | rule id, title, logsource, distilled detection summary (NOT raw YAML) | Detection Rule License 1.1 |
| LOLBAS-Project | commit — **Q2 owner pick** | `Lolbas` | binary, description, sample command, ATT&CK mapping | MIT |
| existing 6.7 curated notes (in-repo) | repo HEAD | `LinuxPattern`,`ThreatTool` | kept, re-indexed | in-repo |
| **IoC feeds** | — | — | **EXCLUDED in V1 — Q3 RULED, condition 6.** No IoC source ships in 6.9.7. The install-from-mirror seam (Q5) is the future path if/when IoCs are revisited. | — |

> **Q2 still owner-blocking:** P2 *cannot* pin sources without the
> exact ATT&CK release tag + Sigma/LOLBAS commits. Pinning is the whole
> determinism story — CC will not pick arbitrary refs.

### 4.1 Canonical dump format (condition 5)

One stable schema per source; the dump is the hashed preimage (§3.1.1)
and the tantivy build input — decoupling provenance from tantivy's
binary format. Rules:

- **Encoding:** UTF-8, `\n` (LF) line endings, **no trailing
  whitespace**, file ends with a single `\n`.
- **Structure:** one JSON object per line (**JSONL**), one line per KB
  document, lines **sorted by `id` ascending** (byte order).
- **Per-line object:** keys **lexicographically sorted**, compact
  (no insignificant whitespace), schema:
  `{"category","content","id","platform","severity","source_ref","title"}`
  (string fields; absent optionals serialised as `""`, never omitted —
  keeps the line schema fixed for the hash).
- **Per-source provenance sidecar** `<<source>>.provenance.json`:
  `{"acquired_utc","canonical_dump_sha256","pin","source_id","upstream_url"}`
  (sorted keys). `canonical_dump_sha256` = `sha256` of the JSONL bytes;
  it feeds §3.1.1.

### 4.2 Attribution & licensing (Q8 RULED — conditions 1–3)

- **`NOTICES.md`** (repo root): per-source attribution block —
  source name, upstream URL, pin, license name, required attribution
  text (esp. MITRE ATT&CK ToU, Sigma DRL-1.1 notice).
- **`LICENSES/`**: verbatim license file per source
  (`LICENSES/MITRE_ATTACK_TERMS.txt`, `LICENSES/SIGMA_DRL-1.1.txt`,
  `LICENSES/LOLBAS_MIT.txt`).
- **Documented per source** (conditions 3): canonical upstream URL,
  specific pin (commit/tag), acquisition date (UTC), SHA-256 of the
  canonical dump — all live in the `.provenance.json` sidecars AND are
  summarised in `NOTICES.md`. R4 license-permits-shipping verification
  is a P2 acceptance gate (§11).

---

## 5. Article-13 compatibility — RULED: **Option A** (owner, P1.2)

> **RULED = Option A** — rely on `prompt_sha256`; XAI stays frozen at
> 1.0.0; retrieval provenance lives in a *separate, hash-chained,
> unsigned* RAG retrieval log. Unblocks P5/P7.
>
> ⚠️ **Verbatim-text gap (flagged):** the owner directed "add the
> 5-point ruling rationale verbatim" but the verbatim text was **not
> transmitted** with the ruling — only the five pillar *labels*
> (cryptographic completeness · standing trigger · separate
> hash-chained log design · methodological tradeoff · V2.0+ future
> path). §5.1 below is **CC's faithful rendering of each named
> pillar**, to be replaced if the owner has specific wording. The
> *decision* (Option A) is unambiguous and is treated as final.

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

### 5.1 Ruling rationale — Option A (5 pillars; CC rendering, verbatim pending)

1. **Cryptographic completeness.** 6.9 P4's `assembled_prompt` already
   splices the RAG block, so `XaiInputSnapshot.prompt_sha256` *already*
   binds every retrieved snippet under the existing Ed25519 signature.
   Integrity and tamper-evidence of the retrievals are therefore
   *already complete* — Option B would add no integrity, only
   separability, at schema-mutation cost.
2. **Standing trigger.** The 6.9-closure standing audit trigger #1
   mandates that any `XAI_SCHEMA_VERSION` change be a deliberate
   breaking commit. Option A *honours it by not tripping it*: the
   closed, shipped XAI 1.0.0 regulatory artifact stays byte-frozen
   (no `canonical_bytes` touch, no P1.1 byte-lock re-derivation).
3. **Separate hash-chained log design.** Retrieval provenance lives in
   a dedicated **append-only, hash-chained** RAG retrieval log: each
   entry = `{ts, ade_trace_id, kb_index_hash, retrieved:[{id,score}],
   prev_entry_sha256}` with `entry_sha256` chaining the previous entry
   (tamper-evident without signing, sovereign-local). It references the
   XAI chain by `ade_trace_id`, giving separable, independently
   auditable retrieval provenance *outside* the signed schema.
4. **Methodological tradeoff (accepted).** Option A trades the
   "single signed artifact contains everything" story for schema
   stability + provenance completeness. Accepted: the hash-chain gives
   tamper-evidence; the FK cross-links the two artifacts; the
   regulatory dossier (§7/P7) documents the two-artifact model
   explicitly so an auditor follows `ade_trace_id` between them.
5. **V2.0+ future path.** Option B is not rejected forever — it is
   deferred to the *next deliberate XAI schema major* (a V2.0+ that
   already pays the standing-trigger cost for other reasons), at which
   point `retrieved_snippets_sha256` + `kb_index_hash` fold into
   `XaiInputSnapshot` natively. The hash-chained log is forward
   -compatible with that migration (same fields).

**Consequence for phases:** P5 wires the hash-chained log alongside the
existing `with_rag` path; P7's Art-13 closeout documents the
two-artifact model. XAI 1.0.0 is **not** touched (Option B's schema
mutation is explicitly NOT done).

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

- **P1 — this doc** (rev P1.1). Owner reviews; still owes Q1, Q2,
  §5/Q7, and the §13 8-point list. *(current)*
- **P2 — KB acquisition pipeline** (xtask). **Unblock requires Q1 N/A
  (P2 is pre-tantivy) but Q2 exact pins + Q8 license-OK.** Commit
  acceptance = ALL of (owner conditions 1–7, verbatim):
  1. `NOTICES.md` with per-source attribution (Q8).
  2. `LICENSES/` populated with verbatim license files.
  3. Each source documents: canonical upstream URL · specific pin
     (commit/tag) · acquisition date (UTC) · SHA-256 of the
     canonical dump (in `.provenance.json` + `NOTICES.md`).
  4. xtask supports BOTH build-time acquisition (default,
     ship-with-agent) AND install-time acquisition (customer-mirror,
     future seam).
  5. canonical dump format documented + implemented per §4.1
     (JSONL, sorted lines by id, sorted keys, LF).
  6. NO IoC sources (Q3).
  7. `kb_index_hash` per §3.1.1 implemented + byte-lock test.
  Plus: R4 license-permits-shipping verified (else mode-4 install-only).
  Atomic commit. → **owner gate audit, then P3.**
- **P3 — tantivy index build** (needs Q1 tantivy version pinned).
  Schema §3.2; **R3 custom analyzer DESIGN + golden test fixtures
  proving the owner's security tokens survive tokenisation:
  `T1059.001`, `/etc/shadow`, `xmrig`, `certutil`, base64-blob, dotted/
  slashed identifiers** (explicit owner P3 requirement). Persist +
  lazy `open`. → owner gate.
- **P4 — BM25 retrieval**: `RagEngine::open_index` + BM25 + R1
  `(-bm25,id)` tie-break + §3.4(a) normalised similarity, **keeping
  `retrieve()` API byte-stable**. Determinism + golden tests.
  → owner gate (retrieval-correctness audit).
- **P5 — ADE canary integration** (hard-blocked by §5/Q7): wire the
  *existing* `with_rag` behind `NN_ADE_RAG_ENABLED`; canary-off parity
  is a release gate. **Q4(a) verification step (owner-mandated):**
  confirm production `format_rag_block` output matches the
  **already-generated Forge v2 Phase-C dataset (5K examples)** format.
  On misalignment: **FLAG before training**, then either adjust
  `format_rag_block` to match the dataset OR regenerate the dataset
  with the corrected format (owner decides which). → owner gate.
- **P6 — bench + golden**: latency p50/p95 (`NN_RAG_BENCH_N`), 20–30
  golden cases, `kb_index_hash` stability; re-confirm the P5 Phase-C
  format alignment holds end-to-end. → owner gate.
- **P7 — docs closeout**: ADE_DOCTRINE + XDR_ROADMAP annotation; the
  §5 Art-13 artifact *iff* Option B is ruled; memory closure.

Each phase: atomic commit, push, notify, STOP at the gate (the 6.9
iteration pattern the owner endorsed). `clippy --workspace
--all-targets -D warnings 0/0` is a per-phase release gate.

## 12. Gating questions — RULINGS REQUESTED (blocking, like 6.9 §12)

**RULED in P1.2 (all four):**
- **Q1 — engine/version:** RULED = `tantivy = "=0.25.0"` (exact pin).
  Bump-if-verified clause: may move to `=0.26.0` *only* after a
  deliberate determinism re-verification (golden + `kb_index_hash`
  unchanged) in its own commit. Cargo.toml comment = §12.1 (CC-authored
  to the owner's stated rule; the "template included" was not
  transmitted).
- **Q2 — corpus pins:** RULED = MITRE **ATT&CK v18.1** (fixed tag);
  **Sigma & LOLBAS = repo HEAD captured at P2 acquisition time**, the
  exact commit recorded into the provenance sidecar (§4.1). Provenance
  template = the §4.1 schema (the owner's "template included" was not
  transmitted; the already-specified §4.1 sidecar schema is used).
- **Q7 / §5 — Article-13:** RULED = **Option A** (§5/§5.1).
- **§13 — canary checklist:** ⚠️ **owner-authoritative 8 points STILL
  not transmitted** (3rd consecutive turn the verbatim list/templates
  were described but not included). §13 remains a clearly-marked CC
  DRAFT; it governs a *later* tappa and does **not** block P2.

**RULED (folded into this revision):**
- **Q3 — IoC feeds:** RULED = none in V1 (condition 6).
- **Q4 — `similarity` field:** RULED = (a) reuse + normalised BM25 +
  doc-comment fix; no `common` shape change.
- **Q5 — KB packaging:** RULED = **both** modes (condition 4) — xtask
  build-time (default) + install-time mirror seam.
- **Q6 — module placement:** keep `agent/src/rag/` (uncontested;
  treated as accepted — owner object if not).
- **Q8 — licenses/attribution:** RULED = ship with `NOTICES.md` +
  `LICENSES/` + per-source provenance (conditions 1–3); R4
  license-permits-shipping is a P2 acceptance gate.
- **Q9 — canary default-flip:** RULED to exist as **§13** (content
  pending owner's 8 points).
- **Refinements (all accepted into the plan):** R1 stable tie-break
  `(-bm25,id)`; R2 `kb_index_hash` over canonical dump (§3.1.1); R3
  security-token-preserving analyzer (P3 golden fixtures mandated by
  owner); R4 license verification before P2 ships.

### 12.1 `tantivy` pin — Cargo.toml comment (CC-authored to the Q1 rule)

The owner's "comment template included" was not transmitted; this is
CC's rendering of the stated rule (exact pin + bump-if-verified):

```toml
# Tappa 6.9.7 RAG: tantivy is EXACT-pinned. BM25 scoring + segment
# codec must be byte-stable for deterministic retrieval + a stable
# kb_index_hash (Art-13). A version move (e.g. =0.26.0) is allowed
# ONLY in a dedicated commit that re-verifies: golden retrieval green
# AND kb_index_hash unchanged AND the P3 analyzer golden tokens still
# survive. Never a passive `^`/`~` range.
tantivy = "=0.25.0"
```

---

## 13. Canary default-flip criteria (Q9) — ⚠️ CC DRAFT, NOT the owner's ruling

> **GAP FLAGGED (3rd consecutive turn).** "Include the 8-point
> checklist from my Q9 ruling" — the 8 points were **not in the
> message** (same pattern as the §13 list last turn and the §5/Q1/Q2
> "verbatim/templates" this turn). To avoid fabricating-then
> -attributing a ruling, the list below is a **CC-proposed draft** for
> the owner to replace/confirm. Non-blocking for P2: the flip is a
> *later tappa*; 6.9.7 only ships the canary OFF by default + the
> measurement harness.

`NN_ADE_RAG_ENABLED` flips to default-on only when ALL hold (draft):

1. **Retrieval determinism locked** — golden retrieval + tie-break
   tests green; `kb_index_hash` byte-locked.
2. **Latency** — RAG-on ADE `evaluate` p95 within the XAI R-P3.2
   budget; retrieval p95 ≤ 50 ms (constraint 3).
3. **Phase-C alignment proven** — production `format_rag_block` ==
   the Phase-C training format (the P5/P6 verification passed).
4. **Quality A/B** — RAG-on verdict accuracy ≥ RAG-off on the eBPF
   golden set, no regression on the no-match-conservative cases.
5. **No-match safety** — below-floor queries yield empty `RagResult`
   and never degrade a RAG-off verdict.
6. **Canary-off parity** — with the flag unset, ADE output is
   byte-identical to pre-6.7 (release gate, every phase).
7. **Provenance** — the §5 Art-13 ruling (A or B) is implemented and
   retrieval provenance is auditable (`kb_index_hash` reachable).
8. **Licensing clear** — `NOTICES.md`/`LICENSES/` complete; R4
   shipping-permission verified for every pinned source.

---

*Plan of record (P1.2). All gating rulings folded — **P2 is GREENLIT**.
The only P2-commit gate is Q8/R4 license verification (BLOCKING:
incompatibility ⇒ FLAG before commit ⇒ re-rule Q5 → install-only).
§13's owner-authoritative 8-point list is still pending but is
non-blocking for P2. Subsequent phases: atomic commit + owner gate +
clippy 0/0 + tests green; no multi-phase mega-commits.*
