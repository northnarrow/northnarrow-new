# Tappa 6.9.7 — RAG Local Knowledge Base — Implementation Plan

Status: **P1.5 frozen · P2✅ P3✅ P4✅ P5✅ P6✅ P7✅ COMPLETE (merged `75855c6`) · P5.1✅ DELIVERED (Tappa 6.9.7.1 amendment — pending owner gate).**
P5.1 (2026-05-19): AMENDS the P5 Q4(a) freeze — `format_rag_block`
flipped to the compact `RAG_CONTEXT:` format the off-repo Phase
A/B/C/D datasets actually use (the freeze rested on a now-invalidated
"no Phase-C dataset" assumption). Deterministic Sigma severity
recovery from `content`; byte-lock renamed `..._phase_abcd_contract`.
Charter/scope invariants held; `Option<String>` kept (reconciled).
See §5.2.1 + §11. (Earlier P2–P7 status follows.)
P7: docs closeout (docs-only — no code/tests/Cargo; clippy 0/0 and the
test suite trivially unchanged, no Rust touched). ADE_DOCTRINE +
XDR_ROADMAP + Art-13 dossier (two-artifact model) annotated;
CLAUDE_BRIEFING lines 96/427 Phase-C drift reconciled (minimal-touch);
plan §11 + this header folded; final AS-BUILT closure recorded at the
end of this plan. (Earlier P2–P6 status follows.)
Prior — **P1.5 frozen · P2✅ P3✅ P4✅ P5✅ P6✅ DELIVERED (P6 pending owner gate).**
P6: bench/golden/e2e validation over the real 964-doc corpus —
`retrieve` p95 **2.2 ms** (≤50 ms), cold open **707 ms** (≤5 s),
golden **22/24 = 91.7 %** (≥90 %; 2 documented cross-source
`want_sigma` misses), `kb_index_hash` reproduced byte-identical to the
P2 anchor, e2e format matches the frozen P5 contract. clippy 0/0; no
regressions. (Earlier P2–P5 status follows.)
Prior — **P1.5 frozen · P2✅ P3✅ P4✅ P5✅ DELIVERED (P5 pending owner gate).**
P5: env-driven RAG canary (`NN_ADE_RAG_ENABLED` default OFF + graceful
fallback) wired at the single main.rs `AdeEngine::new`; Q4(a) RULED
freeze-as-contract — `format_rag_block` byte-frozen as the Phase-C
contract (production = source of truth; repo↔memory Phase-C drift
tracked for P7, briefing untouched); XAI invariant held (no
xai_types/xai changes); clippy 0/0; rag 39+1, ade 109+2. (Earlier
P2–P4 status follows.)
Prior — **P1.5 frozen · P2 ✅ P3 ✅ P4 ✅ DELIVERED (P4 pending owner gate).**
P4: `RagEngine::open_index` BM25 swap behind the byte-stable
`retrieve`/`RagQuery`/`RagResult` API (Backend enum; 6.7 embedding
retained); R1 `(-score,id-asc)` tie-break; §3.4(a) within-result
normalisation + post-norm `min_similarity` floor; 6.7 canary-parity
test (`rag:None`⇒pre-6.7); F-P3-1/F-P3-2 folded; clippy 0/0; rag:: 35
+1. (Earlier P2/P3 status follows.)
Prior — **P1.5 frozen · P2 ✅ + P3 ✅ DELIVERED (P3 pending owner gate).**
P3: `agent/src/rag/index_tantivy.rs` — 8-field tantivy schema + R3
`nn_sec` security-token analyzer + persist/rebuild-on-change; `tantivy
=0.25.0 default-features=false` (🚩 charter: default `zstd-sys` C-FFI
excluded — see §3.2/agent Cargo.toml note); clippy 0/0; 5 hermetic
tests + real-corpus smoke (964 recs) all green. (Original P2 status
line follows.)
Prior — **P1.5 frozen + ✅ P2 DELIVERED (pending owner gate audit).**
All owner verbatim folded (§5.1/§12.1/§4.2.2/§13/§4.2.3/§10-row) +
the 8-key-schema ruling (§4.1/§4.2/§3.1.1, folded into the P2 commit
per owner instruction — no separate P1.6). **P2 shipped:** `cargo
xtask rag-kb` acquired **691 ATT&CK v18.1 techniques + 243 Sigma Linux
rules**; R4 MITRE re-verification on `attack-stix-data@v18.1` PASSED
(ATT&CK ToU commercial-use grant — no incompat flag); clippy 0/0
workspace; xtask tests 4/4; `kb_index_hash 4d335aed…`. Bulky JSONL
dumps gitignored (`/target/kb`); auditable anchor (provenance +
`kb_index.json` + `LICENSES/` + `NOTICES.md`) committed. **V1 corpus =
MITRE ATT&CK Enterprise v18.1 + SigmaHQ Sigma (Linux subset) + 6.7
in-repo notes; LOLBAS DROPPED (GPL-3.0, §4.2.3).** (Prior P1.2 status
follows.)

Prior — P1.2: all four rulings folded; P2 was greenlit pre-verification. RULED: §5/Q7 =
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

> **8-key schema confirmation (P2):** the §4.1 7→8 key change does NOT
> affect this spec. The preimage consumes the canonical-dump *bytes*
> (`sha256(canonical_source_dump_bytes)`); 8 vs 7 keys only changes
> each line's content, not the JSONL format or this length-prefixed
> structure. Implemented + byte-locked in `xtask/src/rag_kb.rs`
> (`kb_index_hash_is_byte_locked_and_tamper_sensitive`).

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

### 3.2 Index schema (tantivy fields) — AS BUILT (P3, `agent/src/rag/index_tantivy.rs`)

8-field schema, one field per canonical-record key (the 8-key ruling):
- `title`, `content`, `author` — **TEXT**, R3 analyzer (`nn_sec`),
  `WithFreqsAndPositions`, stored. `author` is analysed text so
  "rules by Florian Roth" queries work.
- `id`, `category`, `source_ref`, `severity`, `platform` — **STRING**
  (raw, exact-match), stored.

**Deviations from the original proposal (documented per P3 item 6):**
1. `author` added (8th field) — the 8-key ruling.
2. `category` is **STRING** (raw, stored), not a facet — exact-match is
   all that's needed; simpler, no facet machinery. (Maps onto the 5
   `KbCategory` strings verbatim.)
3. **R3 analyzer = `nn_sec`** (custom `Tokenizer` + `LowerCaser`), NOT
   the stock `en` tokenizer. Token rule: a token is a maximal run of
   `alphanumeric | . / - _ :`; everything else splits; leading
   `([{"'` and trailing `.,;:!?)]}"'` are trimmed (sentence
   punctuation) while *internal* `. / - _` are kept. This keeps
   `T1059.001`, `/etc/shadow`, `cmd.exe`, `192.168.1.1`,
   `CVE-2024-1234`, `v18.1`, long hex whole; prose still splits on
   whitespace. Applied identically index- and query-side.
4. Retrieval is an analyzer-applied `BooleanQuery` of per-field
   `TermQuery` (tantivy default similarity = BM25), **not**
   `QueryParser` — avoids `QueryParser` syntax pitfalls with `/ : .`
   in security identifiers, and exercises R3 on the query side too.
5. Charter: `tantivy` `default-features=false` — the default
   `columnar-zstd-compression` pulls `zstd-sys` (C-FFI), forbidden;
   pure-Rust `mmap`+`lz4-compression` used (verified `cargo tree`).
6. On-disk persistence (MmapDirectory) + a source fingerprint marker
   (`NN-RAG-KB-INDEX-SRC-v1`, dedup-by-id, order-independent) drives
   lazy **rebuild-on-source-change**; the 6.7 `kb_seed` notes are
   ingested alongside the P2 JSONL dumps. (The 6.7 seed retains an
   in-repo curated `lolbas_certutil`-style note — that is the
   repo-licensed seed, NOT the dropped GPL-3.0 LOLBAS upstream.)

Validated end-to-end: real-corpus smoke over 964 records (691 ATT&CK
v18.1 + 243 Sigma Linux + 30 seed) — the owner's 5 golden queries all
return strong cross-source hits.

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

**AS BUILT (P4, `agent/src/rag/retrieval.rs::retrieve_bm25`):** Q4=(a)
ruled — `similarity = score / max_score_in_result` (top hit = exactly
`1.0`, rest proportional); empty result skips normalisation. The
`min_similarity` floor (the existing `RagQuery` field — kept verbatim
for API stability; "min_score" in spec prose = this field) is applied
**after** normalisation, on the [0,1] scale; all-below-floor ⇒ empty
`RagResult` (6.7 conservative contract preserved). A BM25 query error
also yields an empty `RagResult` (the infallible `retrieve` contract
is kept — no `Result` in the signature). `common/src/rag_types.rs`
doc-comment updated (DOC ONLY — no struct change; C2/CLI charter).
Ordering is R1 (`(-score, id-asc)`, from `bm25_query`) so equal-score
retrieval is deterministic. `query_embedding_ms = 0` on this path
(reserved for the §7 hybrid).

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
| MITRE ATT&CK Enterprise STIX 2.1 (`github.com/mitre/cti`) | tag `ATT&CK-v18.1` = `605ed54…` (peeled `421deac…`) ✅verified | `MitreTechnique` | technique id, name, description, platforms, data-sources | ATT&CK Terms of Use ✅ ship-OK + attribution |
| SigmaHQ `sigma` (`rules/linux/**`, builtin subset) | HEAD@P2 `df5c6a6e…` ✅captured | `SigmaRule` | rule id, title, logsource, distilled detection summary (NOT raw YAML) | DRL 1.1 ✅ ship-OK + per-rule author attribution (DRL lives in `SigmaHQ/Detection-Rule-License`) |
| ~~LOLBAS-Project~~ | HEAD@P2 `fe42806…` | ~~`Lolbas`~~ | — | 🛑 **GPL-3.0 — incompatible with ship-with-agent; EXCLUDED pending §4.2 ruling (rec: drop V1)** |
| existing 6.7 curated notes (in-repo) | repo HEAD | `LinuxPattern`,`ThreatTool` | kept, re-indexed | in-repo |
| **IoC feeds** | — | — | **EXCLUDED in V1 — Q3 RULED, condition 6.** | — |

> **Q2 status:** ATT&CK pinned to **v18.1** (verified to exist) + Sigma
> HEAD@P2 captured. **LOLBAS removed from the active set** (GPL-3.0,
> §4.2). V1 corpus = MITRE ATT&CK v18.1 + Sigma + the in-repo notes.

### 4.1 Canonical dump format (condition 5)

One stable schema per source; the dump is the hashed preimage (§3.1.1)
and the tantivy build input — decoupling provenance from tantivy's
binary format. Rules:

- **Encoding:** UTF-8, `\n` (LF) line endings, **no trailing
  whitespace**, file ends with a single `\n`.
- **Structure:** one JSON object per line (**JSONL**), one line per KB
  document, lines **sorted by `id` ascending** (byte order).
- **Per-line object (8-key schema — owner ruling 2026-05-17, was 7):**
  keys **lexicographically sorted**, compact (no insignificant
  whitespace), alphabetical key order:
  `{"author","category","content","id","platform","severity","source_ref","title"}`.
  `author` is `Vec<String>` **or `null`**, **always present** (never
  omitted) so every line has an identical key set — maximal hash
  determinism. The other seven are strings; absent optionals serialised
  as `""`, never omitted. **Motivation for the 8th key:** DRL-1.1
  modified-form attribution requires per-rule author retention *in the
  canonical record* (§4.2 Sigma row); a structured `author` field
  (vs. embedding in `content`) keeps it one-glance auditable, leaves
  BM25 scoring undistorted, and future-proofs the schema. The 7→8 bump
  is zero-cost: no canonical dump existed yet (no hash to invalidate,
  no shipped artifact to migrate). Per-source `author` population:
  Sigma = parsed `author` (comma/sequence split, trimmed); MITRE =
  `null` (wholesale attribution via `NOTICES.md`); 6.7 notes = `null`.
- **Per-source provenance sidecar:** schema is **§4.2.2 (owner
  verbatim, ARTIFACT 3)** — authoritative; it supersedes the ad-hoc
  field list earlier drafts used. `canonical_dump_sha256` = `sha256`
  of the JSONL bytes; it feeds §3.1.1. The §3.1.1 `kb_index_hash`
  preimage field labels are aligned to the §4.2.2 names
  (`source` sort key; `url`, `pin`, `canonical_dump_sha256`).

### 4.2 Attribution & licensing — Q8/R4 VERIFICATION RESULT (P1.3, 2026-05-17)

> 🛑 **P2 IS BLOCKED. Verification (from the exact pinned refs) caught a
> real incompatibility — exactly why the owner made this a hard gate,
> and it corrects a factual error in my own P1 plan.**

| Source | Pinned ref captured | Real license @pin | Ship-with-agent verdict |
|---|---|---|---|
| MITRE ATT&CK | tag `ATT&CK-v18.1` = `605ed54…`, peeled commit `421deac…` | ATT&CK® Terms of Use (`mitre/cti/LICENSE.txt`, 2311 B, fetched verbatim) | ✅ OK with the required ATT&CK attribution string in `NOTICES.md` |
| Sigma | HEAD@P2 `df5c6a6e…` | **DRL 1.1 lives in a SEPARATE repo** `SigmaHQ/Detection-Rule-License` (sigma-repo root `LICENSE` is only an index pointing there). DRL 1.1 = MIT-like ("deal in the Rules without restriction… distribute, sublicense, sell") **subject to retaining author attribution** | ✅ OK — DRL fetched from `SigmaHQ/Detection-Rule-License`. **Per-rule author preservation is in the canonical line's dedicated `author` field (§4.1, 8-key schema), NOT embedded in `content` text** (distillation = DRL "modified form" ⇒ structured attribution mandatory); `NOTICES.md` additionally aggregates the corpus-wide author set for discoverability |
| ~~LOLBAS~~ | n/a | **GPL-3.0** (verified `NOTICE.md`@pin + 35 149 B GPLv3 `LICENSE`) | 🚫 **DROPPED from V1 — RULED §4.2.3.** Not fetched/canonicalised/indexed/referenced. P1's "LOLBAS=MIT" was a verified error; the Q8/R4 gate worked. |

**LOLBAS — RULED: dropped from V1 (owner, §4.2.3 below).** The Q2/Q5
re-ruling is made; the option analysis (drop / mirror / bare-facts /
accept-GPL) is resolved to **drop**. P2 proceeds with **MITRE ATT&CK
v18.1 + Sigma + the 6.7 in-repo notes ONLY**; LOLBAS is not fetched,
canonicalised, indexed, or referenced in any artifact.

<<<VERBATIM — Owner: Fortunato Milani via Claude Opus 4.7, 2026-05-17>>>

### §4.2.3 — LOLBAS drop ruling (Q2/Q5 re-ruling, post-P1.3 verification)

RULED: drop LOLBAS from the V1 corpus.

Trigger: P1.3 license verification proved LOLBAS-Project is licensed
under GPL-3.0, not MIT as the P1 plan asserted. The P1 assertion was
verified-and-disproved by the Q8/R4 blocking gate — the gate worked
as designed.

V1 corpus is therefore:
  - MITRE ATT&CK Enterprise v18.1
  - SigmaHQ sigma rules (HEAD@P2, Linux subset)
  - Tappa 6.7 in-repo curated notes (rag/kb_seed.rs, retained)

LOLBAS is NOT fetched, NOT canonicalised, NOT indexed by the V1
xtask. No LOLBAS files appear in NOTICES.md, LICENSES/, or
docs/kb-sources/.

Rationale:
1. NorthNarrow agent ships proprietary closed-source (ADE_DOCTRINE).
   GPL-3.0 copyleft is incompatible with this distribution model.
   Distillation of LOLBAS entries into a canonical dump is arguably
   derivative work — accepting GPL-3.0 would force the entire agent
   under GPL-3.0 via linkage/distribution, killing the commercial
   business.
2. Install-from-mirror (the original Q5 fallback) does not cleanly
   cure copyleft: a customer mirror is still a distribution channel,
   and distilled entries remain derivative. Mirror+legal sign-off
   (option b from P1.4 §4.2) is not pursued for V1 due to legal
   delay risk against beta timeline.
3. Bare-facts-only extraction (option c) is rejected because BM25
   retrieval requires description text for term matching; pure
   technique-ID extraction has no semantic value for the retrieval
   layer and would not serve Phase C training.
4. The agent is Linux-first (Windows agent deferred to Tappe 11-12,
   memory 12). LOLBAS is Windows-centric (cmd.exe, certutil.exe,
   mshta, etc.). Coverage loss for the pre-beta Linux-focused
   product is acceptable: ATT&CK technique coverage and Sigma Linux
   rules carry the V1 detection vocabulary.

Future research task (NOT 6.9.7 scope, NOT scheduled):
GTFOBins (https://gtfobins.github.io/) is the Linux equivalent of
LOLBAS and a natural corpus addition for OS-binary-abuse patterns.
License verification required before any adoption. Tracked as a
post-beta corpus extension consideration, not as a 6.9.7 deliverable
and not as a beta-launch dependency.

<<<END VERBATIM>>>

### 4.2.1 Attribution & licensing requirements (Q8, conditions 1–3)

- **`NOTICES.md`** (repo root): per-source attribution — source, upstream
  URL, pin, license, required attribution text (ATT&CK ToU string; Sigma
  per-rule `author` credit; "distilled/adapted, not verbatim rules").
- **`LICENSES/`**: verbatim license file per *included* source —
  `LICENSES/MITRE_ATTACK_TERMS.txt` (from `mitre/cti@v18.1`),
  `LICENSES/SIGMA_DRL-1.1.txt` (from **`SigmaHQ/Detection-Rule-License`**,
  NOT the sigma repo). **No `LOLBAS_*` file unless (b)/(c) is ruled.**
- **Documented per source** (conditions 3): canonical upstream URL,
  specific pin (commit/tag), acquisition date (UTC), SHA-256 of the
  canonical dump — all live in the `.provenance.json` sidecars AND are
  summarised in `NOTICES.md`. R4 license-permits-shipping verification
  is a P2 acceptance gate (§11).

### 4.2.2 Provenance sidecar schema — owner verbatim (ARTIFACT 3, §12.2)

Mandatory P2 deliverable; one per included corpus source, stored at
`docs/kb-sources/<source>/`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$comment": "<<<VERBATIM — Owner ruling §12.2, 2026-05-17>>> Per-corpus-source provenance sidecar, mandatory P2 deliverable per Tappa 6.9.7 plan §4.2. Stored next to each canonical JSONL dump in docs/kb-sources/<source>/.",
  "type": "object",
  "required": ["source", "url", "pin", "commit_sha", "acquired_at_utc", "canonical_dump_sha256", "license", "license_file"],
  "properties": {
    "source": {
      "type": "string",
      "description": "Canonical source identifier, e.g. 'mitre-attack-stix-data', 'sigma-hq-rules'.",
      "examples": ["mitre-attack-stix-data", "sigma-hq-rules"]
    },
    "url": {
      "type": "string",
      "format": "uri",
      "description": "Upstream canonical repository URL."
    },
    "pin": {
      "type": "string",
      "description": "The pin form: release tag (e.g. 'v18.1') or branch name (e.g. 'master')."
    },
    "commit_sha": {
      "type": "string",
      "pattern": "^[0-9a-f]{40}$",
      "description": "Full git commit SHA-1 of the pinned ref at acquisition time. Captured by xtask via `git rev-parse HEAD`."
    },
    "acquired_at_utc": {
      "type": "string",
      "format": "date-time",
      "description": "RFC3339 UTC timestamp of acquisition."
    },
    "canonical_dump_sha256": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$",
      "description": "SHA-256 of the canonical JSONL dump (sorted lines by id, sorted keys, LF). The input to the KB index hash."
    },
    "license": {
      "type": "string",
      "description": "License name + SPDX identifier if applicable, e.g. 'MITRE ATT&CK Terms of Use', 'DRL-1.1', 'MIT'."
    },
    "license_file": {
      "type": "string",
      "description": "Relative path within the repo to the verbatim LICENSE file copy, e.g. 'LICENSES/MITRE_ATTACK_ToU.md'."
    }
  }
}
```

Example instance (owner verbatim):

```json
{
  "$comment": "<<<VERBATIM — example instance, 2026-05-17>>>",
  "source": "mitre-attack-stix-data",
  "url": "https://github.com/mitre-attack/attack-stix-data",
  "pin": "v18.1",
  "commit_sha": "605ed54...",
  "acquired_at_utc": "2026-05-XX T XX:XX:XX Z",
  "canonical_dump_sha256": "<filled by xtask>",
  "license": "MITRE ATT&CK Terms of Use",
  "license_file": "LICENSES/MITRE_ATTACK_ToU.md"
}
```

> ⚠️ **CC reconciliation flag (NOT overriding the verbatim):** the
> verbatim example names the MITRE source repo as
> **`github.com/mitre-attack/attack-stix-data`** with `pin: "v18.1"`.
> CC's P1.3 Q8/R4 verification was run against the *legacy*
> **`github.com/mitre/cti`** (tag `ATT&CK-v18.1`, commit `605ed54…`).
> These are two different MITRE repos; `attack-stix-data` is the
> current STIX-2.1 home and matches the owner's intent. **At P2 the
> pipeline targets `mitre-attack/attack-stix-data@v18.1` and the
> MITRE license must be RE-VERIFIED against THAT repo** (the legacy
> `mitre/cti` ToU result does not automatically transfer). The §4
> source table will be reconciled to the owner-specified repo at P2.
> `commit_sha "605ed54..."` in the example is the `mitre/cti`
> v18.1 SHA; the `attack-stix-data` v18.1 SHA is captured at P2.

---

## 5. Article-13 compatibility — RULED: **Option A** (owner, P1.2)

> **RULED = Option A** — rely on `prompt_sha256`; XAI stays frozen at
> 1.0.0. ✅ **P1.4: the owner's verbatim §5.1 rationale is now folded
> (ARTIFACT 1)** — the prior CC rendering is replaced. Per the verbatim
> ruling the hash-chained RAG log is **OUT of 6.9.7 scope** (a Tappa 13
> Backend-SaaS follow-on); 6.9.7 makes **zero changes to
> `common/src/xai_types.rs` or `agent/src/xai/`**. §11 P5/P7 updated to
> match.

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

<<<VERBATIM — Owner: Fortunato Milani via Claude Opus 4.7, 2026-05-17>>>

### §5.1 — Ruling rationale (Option A: XAI 1.0.0 frozen)

RULED: rely on `XaiInputSnapshot.prompt_sha256` for retrieval
provenance. XAI_SCHEMA_VERSION remains 1.0.0. No bump.

Five pillars of the rationale:

1. **Cryptographic completeness already exists.** `prompt_sha256`
   (introduced in 6.9 P4) binds the entire assembled prompt
   including the `=== RELEVANT CYBERSEC KNOWLEDGE ===` block produced
   by 6.7's `format_rag_block`. Every RAG snippet that influences the
   verdict is already cryptographically committed via the prompt
   hash. Adding `retrieved_snippets_sha256` would be redundant to
   this binding.

2. **Standing audit trigger #1 (6.9 closure) preserved.** The trigger
   established at Tappa 6.9 closure (HEAD 1726ace) requires that any
   `XAI_SCHEMA_VERSION` change be a deliberate breaking commit with
   migration notes. Bumping the schema in the very next tappa for
   provenance already covered by `prompt_sha256` is exactly the
   churn the trigger exists to prevent.

3. **Retrieval provenance lives in a separate hash-chained RAG log.**
   Design (NOT scope of 6.9.7 — flagged as Tappa 13 Backend SaaS
   follow-on): each log entry contains `ade_trace_id` (cross-key to
   signed XAI chain), `kb_index_hash`, retrieved doc ids + BM25
   scores, and `prev_entry_sha256` (Merkle chain integrity).
   Reproducibility cross-check: an auditor recomputes
   `assembled_prompt` from `XaiInputSnapshot` against the agent at
   recorded `environment_hash`, hashes it, verifies equals
   `prompt_sha256` — any tampering with the unsigned log produces a
   hash mismatch.

4. **Methodological tradeoff (acknowledged).** The XAI `saliency_map`
   does NOT enumerate retrieved snippets as perturbable units. If a
   snippet is the decisive cause, attribution flows transitively:
   occluding an input that drove the RAG query also removes that
   snippet from the prompt. This captures functional causality but
   not snippet-level granularity. Acceptable for beta because (a)
   `prompt_sha256` + `assembled_prompt` reproducibility permits
   snippet-level deepdive off-chain; (b) Phase C training increases
   the model's principled use of retrievals but doesn't require
   schema-level attribution; (c) snippet-level perturbation would be
   a new `Region::Knowledge` in the occlusion taxonomy — V2.0+
   architectural extension, not beta scope.

5. **Future path (V2.0+, NOT 6.9.7 scope).** If post-beta empirical
   audit data demonstrates transitive attribution is insufficient,
   the defined breaking-change path is: new `Region::Knowledge` enum
   variant + `UnitAddr::RetrievedSnippet(snippet_id)` in occlusion
   taxonomy + deliberate `XAI_SCHEMA_VERSION` bump to 2.0.0 +
   migration notes + `canonical_bytes` update + P1.1 byte-lock
   re-derivation. This is the defined breaking-change path, not a
   stealth-bump.

Implementation impact on 6.9.7: zero changes to
`common/src/xai_types.rs` or `agent/src/xai/`. The hash-chained RAG
retrieval log is a Tappa 13 deliverable referenced in P7 docs
closeout as a follow-on.

<<<END VERBATIM>>>

### 5.2 AS BUILT (P5) — Option A confirmed + Q4(a) format freeze

- **Option A confirmed AS-BUILT.** P5 makes **zero** changes to
  `common/src/xai_types.rs` or `agent/src/xai/*` (XAI 1.0.0 schema
  untouched). The RAG block is part of the assembled prompt, so it is
  already bound by `XaiInputSnapshot.prompt_sha256` (the Ed25519
  signature from 6.9 P4). Consequence (by design, NOT a regression):
  a RAG-**on** evidence chain can only be reproduced by an auditor
  running RAG-**on** with the same `kb_index_hash`; a RAG-off auditor
  cannot — the RAG block IS part of the prompt being explained. The
  `rag:None` canary-parity path keeps every RAG-off chain reproducible.
- **§5.1 follow-on unchanged:** the hash-chained RAG retrieval log
  stays a Tappa 13 deliverable — explicitly NOT built in P5.
- **Q4(a) RULED = freeze-as-contract (owner, 2026-05-17).** The
  Phase-C dataset is not in-repo and the briefing has Phase C as
  deferred/spec-only (repo↔memory drift caught — tracked for P7 docs
  reconciliation, briefing NOT touched in P5). Production
  `format_rag_block` IS the source of truth: its byte-stable output is
  frozen by `format_rag_block_byte_stable_phase_c_contract` +
  documented as the contract in a doc-comment above the fn. **Future
  Phase-C (Tappa 6.9.5 / the post-6.9.7 Phase-B+C training cycle) is
  generated to conform to production — not vice versa.** No byte-diff
  against nonexistent/stale Colab data; `format_rag_block` unmodified.

### 5.2.1 AMENDED (P5.1, Tappa 6.9.7.1, 2026-05-19) — contract flip

- **Q4(a) assumption INVALIDATED.** P5 froze the verbose structured
  block under the (mistaken) belief no Phase-C dataset existed. The
  2026-05-19 dataset inventory corrected this: Phase B (30K), C (5K),
  D (2K) exist off-repo (PC Fisso Downloads, ~37K) and are coherent
  with the already-trained Phase A (50K, 100% PASS) on the **compact
  `RAG_CONTEXT:\n<summary>` natural-language format**. Empirical ground
  truth: the Forge v2 generator templates (`forge_v2.py:804 + 919 +
  987`). Production must conform to training data, not vice versa
  (regenerating 37K examples = negative ROI).
- **AS-BUILT P5.1.** `format_rag_block` rewritten to emit
  `RAG_CONTEXT:\n<line per doc>\n\n`: `Sigma Intel ({sev} severity):
  {title}.` for SigmaRule (severity deterministically recovered from
  the `Level:`/`Severity:` standalone line the P2 builder appends —
  `xtask/src/rag_kb.rs:317-321` — typed `SigmaSeverity`; graceful
  title-only fallback, zero false positives), `Intel: {title}.` for
  the other four `KbCategory` variants. Top-K → one line per doc
  (Option B; multi-line is OOD vs single-line training but canary
  defaults OFF + pre-beta validation pre-flip mitigates).
- **Phase C is orthogonal by design.** Phase C (customer-context
  whitelisting / RAG-trust resilience training) uses a pattern
  production retrieval does not emit — intentional resilience framing,
  NOT a format mismatch; it does not constrain this contract.
- **Charter / scope held.** Zero `xai_types`/`xai/*` touches;
  `RagDocument` schema unchanged (severity recovered from `content`,
  never a new field — any propagation would be a separate 6.9.7.2);
  no new deps; canary OFF default + `rag:None` byte-identical
  preserved. **`Option<String>` signature deliberately kept** (the
  FINAL "return `String::new()`" wording reconciled to `None`-for-
  empty: it preserves the original brief's "existing empty-result
  behavior preserved", the no-new-public-API invariant, and the
  `.expect("…⇒ Some")` call sites in `tests.rs`/`bench.rs` — flagged
  at the owner gate).
- Byte-lock test renamed `format_rag_block_byte_stable_phase_c
  _contract` → `..._phase_abcd_contract`; `bench.rs` e2e + the P5
  `with_rag_splices_block_into_assembled_prompt` splice test re-pointed
  to the compact contract (the two non-enumerated old-format call
  sites — flagged). clippy 0/0; all P5.1 tests green (the unrelated
  pre-existing `admin_socket::server_recreates_stale_socket_on_startup`
  flaky is out of scope — fails identically on clean `75855c6`).

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
**AS BUILT (P2–P4) — deviations from the sketch above (documented):**
- No `agent/src/rag/kb_dump.rs`: the canonical-dump model + the
  `kb_index_hash` (§3.1.1) live in **`xtask/src/rag_kb.rs`** (the P2
  acquisition tool — that is where canonicalisation happens); the
  agent only *parses* a canonical JSONL line, via
  `index_tantivy::CanonLine::from_json` (serde_json::Value, no serde
  derive — avoided an agent Cargo.toml dep change).
- `xtask/ (new subcommand)` realised as `cargo xtask rag-kb`
  (build-time fetch | `--mirror` install).
- `retrieval.rs` (P4): `RagEngine` is now a `Backend` enum —
  `with_seed` ⇒ legacy 6.7 embedding; `open_index` ⇒ 6.9.7 BM25;
  `retrieve`/`RagQuery`/`RagResult` byte-stable (the §0 swap). The
  6.7 embedder/store stay dormant for the §7 hybrid.

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
| Corpus coverage gap on OS-binary-abuse patterns (LOLBAS dropped due to GPL-3.0) | V1 acceptable: ATT&CK techniques cover execution/persistence/defense-evasion semantics; Sigma Linux rules cover binary-abuse detection. GTFOBins evaluation flagged as post-beta separate research task. Watched as a recall-gap in golden retrieval tests; if specific eBPF event classes (e.g. abusive use of standard Linux utilities) fail to retrieve useful snippets in P6 golden suite, the gap is documented as a known limitation rather than papered over. |

*(The LOLBAS-coverage-gap row above is owner-verbatim, ARTIFACT §10, 2026-05-17.)*

## 11. Phased delivery (plan-first; owner gate between phases, as 6.9)

- **P1 — this doc** (rev **P1.5**). Fully ruled; Q8/R4 verified;
  LOLBAS dropped (§4.2.3). *(complete)*
- **P2 — KB acquisition pipeline** (xtask) — ✅ **DELIVERED (this
  commit) — pending owner gate audit.** `cargo xtask rag-kb`
  (build/fetch + `--mirror` install modes); live run produced **691
  ATT&CK v18.1 techniques + 243 Sigma Linux rules**; R4 MITRE
  re-verification on `attack-stix-data@v18.1` **PASSED** (ATT&CK ToU,
  commercial-use grant — no flag). `kb_index_hash` =
  `4d335aed…cd5fd98`. **V1 corpus = MITRE ATT&CK Enterprise v18.1 +
  SigmaHQ Sigma (Linux subset) + 6.7 in-repo notes. NO LOLBAS.**
  Commit acceptance
  = ALL of (owner conditions 1–7, verbatim):
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
- **P3 — tantivy index build** — ✅ **DELIVERED (this commit) —
  pending owner gate audit.** `agent/src/rag/index_tantivy.rs`:
  8-field schema (§3.2 as-built), R3 `nn_sec` analyzer (security
  tokens survive — tested), `tantivy =0.25.0`
  `default-features=false` (🚩 charter: default pulls `zstd-sys`
  C-FFI — excluded; pure-Rust `mmap`+`lz4`), MmapDirectory persist +
  fingerprint rebuild-on-change, ingests P2 JSONL + 6.7 seed. 5
  hermetic tests (analyzer / golden previews / persistence /
  fingerprint / rebuild) + 1 `#[ignore]` real-corpus smoke (964 recs,
  all 5 owner golden queries pass). clippy 0/0; bump-if-verified:
  0.26.1 is GA but stays a deliberate future commit (Q1). → owner gate.
- **P4 — BM25 retrieval** — ✅ **DELIVERED (this commit) — pending
  owner gate audit.** `RagEngine` → `Backend` enum;
  `RagEngine::open_index(jsonl_dir,index_dir)` (loads P2 JSONL + 6.7
  seed → `open_or_build`); `retrieve`/`RagQuery`/`RagResult`
  **byte-stable** (C2/CLI charter — no `common` struct change, doc
  only). R1 `(-score,id-asc)` tie-break; §3.4(a) within-result
  normalisation (top=1.0); `min_similarity` floor post-normalisation;
  conservative empty on error/no-match (infallible `retrieve` kept);
  `query_embedding_ms=0`. 6.7 embedding path retained for `with_seed`.
  +3 rag tests (tie-break, normalised open_index, post-norm floor) +
  the **6.7 canary-parity test** (`rag:None` ⇒ no RAG block ⇒ pre-6.7
  prompt — §13 checklist #1). F-P3-1 (mod.rs doc) + F-P3-2 (`stopwords`
  dropped, verified) folded. clippy 0/0; rag:: 35+1; xai/xtask
  unaffected. → owner gate (retrieval-correctness audit).
- **P5 — ADE canary integration** — ✅ **DELIVERED (this commit) —
  pending owner gate audit.** `rag::canary` (pure `rag_canary` core +
  `open_index_from_env` glue) wired into the single `main.rs`
  `AdeEngine::new` site behind `NN_ADE_RAG_ENABLED` (default OFF,
  beta-safe) / `NN_ADE_RAG_JSONL_DIR` / `NN_ADE_RAG_INDEX_DIR`;
  graceful no-RAG fallback on open_index failure (canary parity
  preserved); `tracing::info`/`warn` at each branch. **Q4(a) RULED
  freeze-as-contract** (§5.2): `format_rag_block` byte-frozen by
  `format_rag_block_byte_stable_phase_c_contract` + contract
  doc-comment; production is the source of truth, future Phase-C
  conforms to it (no byte-diff vs nonexistent data; the repo↔memory
  Phase-C drift is tracked for P7 — briefing NOT touched). **XAI
  invariant held:** zero `xai_types`/`xai/*` changes (xai:: 33+1
  unaffected); RAG-on chains need RAG-on reproduction *by design*.
  +6 tests (4 `rag::canary` env/3-state, format snapshot, with_rag
  splice) + the P4 canary-parity (rag:None). clippy 0/0; rag:: 39+1;
  ade:: 109+2. → owner gate.
- **P6 — bench + golden** — ✅ **DELIVERED (this commit) — pending
  owner gate audit.** `agent/src/rag/bench.rs`: latency harness
  (`NN_RAG_BENCH_N`, default 1000) + 24-case golden suite + e2e
  format re-confirm; heavy runs `#[ignore]` (real-corpus pattern).
  **Results over the real 964-doc corpus (n=6000 retrieves):**
  - Latency: cold `open_index` **707 ms** (≤ 5 s ✅); `retrieve`
    **p50 1.6 ms / p95 2.2 ms / p99 2.4 ms** (≤ 50 ms ✅, ~23× margin);
    RSS Δ ≈ 50 MiB (tantivy mmap, reasonable).
  - Golden: **22/24 = 91.7 %** (≥ 90 % ✅). The 2 misses are the
    `want_sigma` half of two cross-source cases ("powershell
    credential dump lsass", "scripting interpreter powershell abuse")
    — the exact ATT&CK ids *were* retrieved; no Linux-Sigma rule
    co-ranked top-10 for these Windows-flavoured credential phrasings
    (the Sigma corpus is the Linux subset; LOLBAS dropped). Documented
    future-improvement, consistent with the §10 coverage-gap row — not
    a defect; corpus-quality, post-beta hybrid/GTFOBins addresses it.
  - `kb_index_hash`: an independent P6 re-run of `cargo xtask rag-kb`
    reproduced `4d335aed…6cd5fd98` **byte-identical** to the
    P2-committed anchor (full-pipeline reproducibility ✓; tamper-
    sensitivity is the committed P2 unit byte-lock).
  - e2e Phase-C format: real retrieval → `format_rag_block` matches
    the frozen P5 contract shape ✓.
  Release-gate alignment: satisfies §13 checklist #3 (latency) and the
  golden-determinism precondition. → owner gate.
- **P7 — docs closeout** — ✅ **DELIVERED (this commit) — pending
  owner final audit → ship.** Docs-only (no code/tests/Cargo).
  Touched: `ADE_DOCTRINE.md` (new "Tappa 6.9.7 — RAG-Local Knowledge
  Base — SHIPPED" section w/ operational metrics); `XDR_ROADMAP_TAPPE
  _NEW.md` (6.9.7 ✅ DELIVERED + V1.0 cross-refs + Phase-C pre-beta
  status; inline, no per-tappa board); `TAPPA6_9_ARTICLE_13
  _COMPLIANCE.md` (§8 two-artifact traceability model + §9 change
  log — signed XAI chain = "what explained"; hash-chained RAG log =
  "what retrieved", a **Tappa 13** follow-on per §5.1; XAI 1.0.0
  untouched); `CLAUDE_BRIEFING.md` (lines 96/427 reconciled
  minimal-touch — the P5 repo↔memory Phase-C drift RESOLVED). Aux
  RAG-staleness scan: `IDEAS`/`PERFORMANCE_HARDWARE` are context not
  status, README has no RAG mention — none touched (minimal scope).
  Plan §11 + header folded. **Branch ready for merge to main after
  this audit.**
- **P5.1 — format contract amendment (Tappa 6.9.7.1)** — ✅
  **DELIVERED — pending owner gate audit.** AMENDS the P5 Q4(a)
  freeze (§5.2.1): `format_rag_block` flipped from the verbose
  structured block to the compact `RAG_CONTEXT:\n<summary>\n\n`
  format the off-repo Phase A/B/C/D datasets (~37K, Forge v2
  `forge_v2.py:804/919/987`) actually use. Deterministic Sigma
  severity recovery from `content` (`SigmaSeverity` enum + `Level:`/
  `Severity:` whole-line parse per `rag_kb.rs:317-321`; title-only
  fallback). Edits: `rag_integration.rs` (fn + doc-comment + in-file
  unit tests inc. 6 new `extract_sigma_severity` cases), `ade/tests.rs`
  (byte-lock renamed `..._phase_abcd_contract` + new fallback test +
  P5 splice test re-pointed), `rag/bench.rs` (e2e re-pointed),
  `CLAUDE_BRIEFING.md`, this plan (§5.2.1 + §11 + header). XAI/
  `RagDocument`/deps/canary-OFF/`rag:None` invariants held;
  `Option<String>` signature kept (reconciled — see §5.2.1). clippy
  0/0; P5.1 tests green (pre-existing unrelated `admin_socket` flaky
  excluded). → owner gate.

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
- **Q2 — corpus pins:** RULED. MITRE **ATT&CK Enterprise v18.1** via
  `mitre-attack/attack-stix-data@v18.1` (§4.2.2; re-verify license vs
  that repo during P2). **Sigma HEAD@P2 `df5c6a6e…` (Linux subset).**
  **LOLBAS DROPPED — §4.2.3 (Q2/Q5 re-ruling complete).** Provenance
  schema = §4.2.2 (owner verbatim).
- **Q8 / R4 — VERIFIED (P1.3) + RESOLVED (P1.5):** MITRE ATT&CK ✅
  ship-OK (+attribution; re-verify on `attack-stix-data` at P2); Sigma
  DRL-1.1 ✅ ship-OK (+author attribution; DRL text in the **separate**
  `SigmaHQ/Detection-Rule-License` repo — plan path corrected); **LOLBAS
  = GPL-3.0 ⇒ DROPPED (§4.2.3).** The blocking gate worked exactly as
  designed (caught P1's wrong "LOLBAS=MIT"). No incompatibility remains
  in the V1 corpus.
- **Q7 / §5 — Article-13:** RULED = **Option A** (§5/§5.1).
- **§13 — canary checklist:** ⚠️ **owner-authoritative 8 points STILL
  not transmitted** (3rd consecutive turn the verbatim list/templates
  were described but not included). §13 remains a clearly-marked CC
  DRAFT; it governs a *later* tappa and does **not** block P2.

**RULED (folded into this revision):**
- **Q3 — IoC feeds:** RULED = none in V1 (condition 6).
- **Q4 — `similarity` field:** RULED = (a) reuse + normalised BM25 +
  doc-comment fix; no `common` shape change.
- **Q5 — KB packaging:** RULED = **both** modes (condition 4). The
  GPL-3.0/LOLBAS interaction is now moot — §4.2.3 drops LOLBAS rather
  than mirroring it (install-from-mirror does not cure copyleft).
- **Q6 — module placement:** keep `agent/src/rag/` (uncontested;
  treated as accepted — owner object if not).
- **Q8 — licenses/attribution:** RULED requirements stand
  (`NOTICES.md` + `LICENSES/` + provenance, conditions 1–3). **R4
  verification EXECUTED (P1.3) + RESOLVED (P1.5): MITRE ✅ / Sigma ✅ /
  LOLBAS dropped (§4.2.3). No incompatibility remains; P2 GREENLIT.**
- **Q9 — canary default-flip:** RULED to exist as **§13** (content
  pending owner's 8 points).
- **Refinements (all accepted into the plan):** R1 stable tie-break
  `(-bm25,id)`; R2 `kb_index_hash` over canonical dump (§3.1.1); R3
  security-token-preserving analyzer (P3 golden fixtures mandated by
  owner); R4 license verification before P2 ships.

### 12.1 `tantivy` pin — Cargo.toml comment (owner verbatim, ARTIFACT 2, P1.4)

Insert this verbatim where the `tantivy` dependency is added (P3):

```toml
# <<<VERBATIM — Owner ruling §12.1, 2026-05-17>>>
# Tappa 6.9.7: tantivy is pinned exact-version to ensure deterministic
# BM25 scoring across rebuilds. A version bump invalidates the golden
# retrieval test suite and the KB index format compatibility, so it is
# a deliberate commit with golden-test refresh and KB rebuild, never a
# silent cargo update. Bump-if-verified path: 0.26.0 may be adopted if
# `cargo search tantivy` confirms GA (not RC) AND no breaking BM25
# scoring changes vs 0.25.x are noted in the changelog.
tantivy = "=0.25.0"
# <<<END VERBATIM>>>
```

---

<<<VERBATIM — Owner: Fortunato Milani via Claude Opus 4.7, 2026-05-17>>>

## §13 — Canary default-flip checklist (8 points)

The default value of `NN_ADE_RAG_ENABLED` will be flipped from `0`
(off) to `1` (on) in a future deliberate commit, AFTER Tappa 6.9.7
ships and AFTER the Phase B + Phase C training tappa completes. The
flip is NOT part of 6.9.7 scope.

The flip commit body MUST cite all 8 of the following points with a
verification reference (test name, log file, doc commit SHA, or
similar). The flip cannot be merged unless every point passes.

1. **Canary parity test passing.** `NN_ADE_RAG_ENABLED` unset (RAG
   off) produces ADE output byte-identical to pre-6.7 baseline. The
   6.7 invariant `rag: None ⇒ byte-identical to pre-6.7` is verified
   structurally and via a regression test. This protects retroactive
   XAI determinism: every XAI evidence chain generated before the
   flip remains reproducible by an auditor running RAG-off.

2. **Phase B + Phase C LoRA trained and validated.** The fine-tuned
   model has been trained on the SAME RAG retrieval signal that
   production will produce, as verified by the P5/P6 Forge-v2
   `format_rag_block` alignment check. The validation suite
   demonstrates that the trained model uses RAG retrievals more
   discriminately than the untrained baseline.

3. **Latency budget met.** `evaluate-with-RAG` p95 ≤ XAI_BUDGET_MS
   (90s) with documented headroom; RAG retrieval p95 ≤ 50 ms
   (constraint 3 of §1). Measurements recorded with provenance per
   the R-P3.2 ledger discipline (host, date, KB index hash, sample
   count, percentile values).

4. **Golden retrieval suite passing.** The 20-30 known eBPF event
   scenarios documented in §8 produce the expected top-snippet doc
   ids deterministically. The R3 security-token-preserving analyzer
   correctly handles every golden case including T1059.001,
   /etc/shadow, xmrig, certutil, and the other tokens specified in
   the analyzer test fixtures.

5. **Customer-mode integration smoke test passing.** End-to-end
   deployment scenario tested on staging: agent boot → KB index
   lazy-load → RAG canary enabled → ADE evaluate → XAI explain →
   signed evidence chain produced → offline verify succeeds. No
   regression detected in any layer.

6. **24-hour soak test passing on staging.** Canary on, realistic
   event load. No memory leaks, no file descriptor leaks, no latency
   drift outside p95 envelope, no index corruption. Soak log
   reviewed and approved.

7. **XAI evidence chain integrity preserved.** RAG-on chains verify
   correctly via Ed25519. `prompt_sha256` is reconstructible by
   recomputing `assembled_prompt` from `XaiInputSnapshot` against the
   agent built at recorded `environment_hash`. The end-to-end
   audit-reproducibility property holds with RAG enabled.

8. **Article 13 dossier update committed.** `docs/TAPPA6_9_ARTICLE_
   13_COMPLIANCE.md` §3 (reproducibility) is extended to explicitly
   cover RAG retrieval determinism (BM25 over a pinned KB index
   produces identical top-K). §5 (deployment posture) is amended for
   the canary-on default state. The commit SHA is recorded.

<<<END VERBATIM>>>

---

*Plan of record (**P1.5 — FROZEN; P1 complete**). All owner verbatim
artifacts folded (§5.1, §12.1, §4.2.2, §13, §4.2.3, §10-row) — no CC
placeholders, no open rulings. **✅ P2 GREENLIT.** V1 corpus = MITRE
ATT&CK Enterprise v18.1 (`mitre-attack/attack-stix-data@v18.1`) +
SigmaHQ Sigma (HEAD@P2, Linux subset) + 6.7 in-repo notes; **LOLBAS
dropped (GPL-3.0, §4.2.3)**. One P2-internal acceptance step (not a
pre-P2 blocker): re-verify the MITRE license against
`attack-stix-data@v18.1` and FLAG before the P2 commit if it differs
from the ATT&CK ToU. Subsequent phases: atomic commit + owner gate +
clippy 0/0 + tests green; no multi-phase mega-commits.*

---

## AS-BUILT — Tappa 6.9.7 closure (P7, 2026-05-17)

**Status: P1→P7 COMPLETE. Branch `tappa-6.9.7-rag-kb-plan` ready for
merge to `main`.** Recorded against the P7 docs-closeout commit; supersedes
the P1.5-era plan-of-record note above.

**What shipped (AS-BUILT, vs plan of record):**

- **P2** — sovereign KB acquisition (`cargo xtask rag-kb`): MITRE
  ATT&CK Enterprise **v18.1** (691 techniques) + SigmaHQ Linux (243
  rules) + 6.7 in-repo `kb_seed`; LOLBAS **dropped** (GPL-3.0, §4.2.3);
  MITRE ATT&CK ToU re-verified on `attack-stix-data@v18.1` (commercial
  grant — no incompat). Provenance anchored in `docs/kb-sources/`.
- **P3** — `tantivy =0.25.0 default-features=false` (no `zstd-sys`
  C-FFI — 100%-Rust/no-FFI charter held); 8-field schema + R3 `nn_sec`
  security-token analyzer; persist + rebuild-on-change.
- **P4** — BM25 `RagEngine::open_index` swapped **behind the
  byte-stable `retrieve`/`RagQuery`/`RagResult` API** (plan §0
  mechanism swap); R1 `(-score,id-asc)` tie-break; §3.4(a)
  within-result normalisation + post-norm `min_similarity` floor;
  `rag:None` byte-identical to pre-6.7 (XAI-determinism protected).
- **P5** — env canary `NN_ADE_RAG_ENABLED` (default **OFF**,
  beta-safe; graceful fallback) at the single `AdeEngine::new`;
  Q4(a) **`format_rag_block` byte-frozen** as the Phase-C training
  contract; XAI 1.0.0 schema untouched.
- **P6** — real 964-doc corpus: `retrieve` p95 **2.2 ms** (≤50 ms,
  ~23× margin), cold `open_index` **707 ms** (≤5 s), golden
  **22/24 = 91.7 %** (≥90 %; the 2 misses are documented §10
  cross-source `want_sigma` co-retrieval coverage gaps, not gamed),
  `kb_index_hash` reproduced byte-identical to the P2 anchor, e2e
  matches the frozen P5 contract. clippy 0/0; no regressions.
- **P7** — docs closeout (this commit, docs-only): ADE_DOCTRINE
  "RAG-Local Knowledge Base — SHIPPED" section w/ operational metrics;
  XDR_ROADMAP 6.9.7 ✅ DELIVERED + V1.0 cross-refs; Art-13 dossier §8
  two-artifact traceability model + §9 change log; CLAUDE_BRIEFING
  lines 96/427 reconciled (the P5-flagged repo↔memory Phase-C drift
  **RESOLVED**); plan §11 + header folded. Aux RAG-staleness scan:
  no stale status statement in `docs/*.md` (PERFORMANCE_HARDWARE /
  IDEAS mentions are context; README has no RAG mention) — none
  touched (minimal scope). No code/test/Cargo changes.

**Sovereign + Article-13 posture (AS-BUILT):** 100% local KB, zero
external fetch at agent runtime; `kb_index_hash` byte-reproducible
(auditable provenance). Article-13 traceability is the **two-artifact
model** (dossier §8): the signed XAI 1.0.0 chain binds the RAG block
transitively via `prompt_sha256` (Option A frozen — §5); the separate
hash-chained RAG retrieval log is a **Tappa 13** SaaS-Backend follow-on
(§5.1, NOT built in 6.9.7).

**V1.0 forward work (not in 6.9.7):** hybrid candle bge-small re-rank
over BM25 candidates (§7); GTFOBins corpus extension (§4.2.3,
post-beta); the hash-chained RAG retrieval log (Tappa 13, §5.1).

**Merge declaration:** P1.5 frozen; P2–P7 delivered; owner gates
passed P2–P6; P6 audit PASS (zero findings); P7 docs-only with no
code/test/Cargo/clippy delta. Pending only the P7 owner audit gate,
after which `tappa-6.9.7-rag-kb-plan` merges to `main`, Tappa 6.9.7
**SHIPS**, and the Phase B+C training cycle (3–5 days) begins —
training against the byte-frozen `format_rag_block` (Q4(a)). Tappa
6.9.5 Phase C is **PROMOTED pre-beta** (17 May 2026 ruling); its
dataset is generated post-6.9.7 and will conform to the frozen
contract.
