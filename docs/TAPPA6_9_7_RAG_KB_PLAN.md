# Tappa 6.9.7 — RAG Local Knowledge Base — Implementation Plan

Status: **P1.4 — all 4 owner verbatim artifacts folded; P2 BLOCKED on
ONE decision (LOLBAS).** §5.1 (ARTIFACT 1), §12.1 (ARTIFACT 2), §4.2.2
(ARTIFACT 3), §13 (ARTIFACT 4) inserted verbatim — no CC placeholders
remain. **🛑 P2 still blocked solely on the LOLBAS Q2/Q5 re-ruling**
(Q8/R4 verification proved LOLBAS = GPL-3.0, incompatible with
proprietary ship-with-agent — P1's "MIT" was a verified error; CC rec:
DROP LOLBAS from V1, §4.2). Non-blocking flag: §4.2.2's verbatim example
names the MITRE repo `mitre-attack/attack-stix-data@v18.1`, not the
legacy `mitre/cti@ATT&CK-v18.1` CC verified — MITRE license re-verified
against the owner-named repo at P2. MITRE/Sigma otherwise clear. (Prior
P1.2 status follows.)

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
- **Per-line object:** keys **lexicographically sorted**, compact
  (no insignificant whitespace), schema:
  `{"category","content","id","platform","severity","source_ref","title"}`
  (string fields; absent optionals serialised as `""`, never omitted —
  keeps the line schema fixed for the hash).
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
| Sigma | HEAD@P2 `df5c6a6e…` | **DRL 1.1 lives in a SEPARATE repo** `SigmaHQ/Detection-Rule-License` (sigma-repo root `LICENSE` is only an index pointing there). DRL 1.1 = MIT-like ("deal in the Rules without restriction… distribute, sublicense, sell") **subject to retaining author attribution** | ✅ OK — must fetch DRL from `SigmaHQ/Detection-Rule-License`, retain per-rule `author` attribution (distillation = "modified form" ⇒ attribution mandatory) |
| LOLBAS | HEAD@P2 `fe42806…` | **GPL-3.0** — `NOTICE.md` @pin states verbatim *"The LOLBAS Project is licensed under GPL 3.0"*; full GPLv3 `LICENSE` (35 149 B) confirmed. **No data/code carve-out — the whole project incl. the YAML entries.** | 🛑 **INCOMPATIBLE with proprietary ship-with-agent (copyleft).** P1's "LOLBAS = MIT" was WRONG. |

**LOLBAS remediation — owner ruling required (re-rule of Q2/Q5 for
LOLBAS only):**
- **(a) DROP LOLBAS from the V1 corpus — RECOMMENDED.** MITRE ATT&CK +
  Sigma are the high-value sovereign corpus; the agent is **Linux-first**
  and LOLBAS is Windows-binary-centric, so its pre-beta marginal value
  is low. Cleanest; zero copyleft exposure; revisit post-beta with legal.
- (b) install-from-mirror for LOLBAS only — note: GPLv3 reciprocity
  attaches to *distribution* and *derivative works*; a mirror is still
  distribution and the distilled entries may be a derivative. Does **not
  reliably cure** copyleft without a legal determination.
- (c) use only non-copyrightable bare facts (binary names) — thin value,
  legal-grey; not recommended.
- (d) accept GPLv3 obligations for the LOLBAS slice — unacceptable for a
  commercial agent.

Until ruled, **P2 proceeds (if at all) with MITRE + Sigma ONLY**; no
LOLBAS acquisition/commit.

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

- **P1 — this doc** (rev **P1.3**). Rulings folded; Q8/R4 verified.
  *(current)*
- **P2 — KB acquisition pipeline** (xtask) — 🛑 **BLOCKED:** Q8/R4
  found LOLBAS = GPL-3.0 (§4.2); awaiting the owner's LOLBAS Q2/Q5
  re-ruling. Once ruled, **V1 corpus = MITRE ATT&CK v18.1 + Sigma +
  in-repo notes (NO LOLBAS)**. Commit acceptance = ALL of (owner
  conditions 1–7, verbatim):
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
- **P5 — ADE canary integration** (§5/Q7 RULED Option A ⇒ unblocked;
  zero `xai_types`/`xai` changes; NO hash-chained log here — that is a
  Tappa 13 follow-on per §5.1): wire the *existing* `with_rag` behind
  `NN_ADE_RAG_ENABLED`; canary-off parity is a release gate.
  **Q4(a) verification step (owner-mandated):**
  confirm production `format_rag_block` output matches the
  **already-generated Forge v2 Phase-C dataset (5K examples)** format.
  On misalignment: **FLAG before training**, then either adjust
  `format_rag_block` to match the dataset OR regenerate the dataset
  with the corrected format (owner decides which). → owner gate.
- **P6 — bench + golden**: latency p50/p95 (`NN_RAG_BENCH_N`), 20–30
  golden cases, `kb_index_hash` stability; re-confirm the P5 Phase-C
  format alignment holds end-to-end. → owner gate.
- **P7 — docs closeout**: ADE_DOCTRINE + XDR_ROADMAP annotation;
  Art-13 dossier documents the **two-artifact model** (signed XAI
  chain + the separate hash-chained RAG log) and **references the
  hash-chained RAG retrieval log as a Tappa 13 Backend-SaaS
  follow-on** (per §5.1 — NOT built in 6.9.7); memory closure. (No
  XAI schema artifact — Option A ruled; Option B is the V2.0+ path.)

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
- **Q2 — corpus pins:** RULED = MITRE **ATT&CK v18.1** (✅ tag verified
  `605ed54…`/peeled `421deac…`); **Sigma HEAD@P2 `df5c6a6e…` captured**.
  **LOLBAS pin `fe42806…` captured but LOLBAS is REMOVED** (GPL-3.0,
  §4.2) — needs a Q2/Q5 re-ruling. Provenance template = the §4.1
  schema (owner's "template included" not transmitted).
- **Q8 / R4 — VERIFIED (P1.3), the BLOCKING gate, result:** MITRE
  ATT&CK v18.1 ✅ ship-OK (+attribution); Sigma DRL-1.1 ✅ ship-OK
  (+author attribution; DRL text is in the **separate**
  `SigmaHQ/Detection-Rule-License` repo — plan path corrected);
  **LOLBAS 🛑 GPL-3.0 — incompatible with proprietary ship-with-agent.
  P1's "LOLBAS=MIT" was a verified error.** Per the owner's
  pre-authorised path: **FLAGGED before P2 commit; P2 BLOCKED until
  the LOLBAS Q2/Q5 re-ruling.** Recommendation: **drop LOLBAS from V1**
  (Linux-first agent ⇒ low Windows-LOLBAS value pre-beta; zero copyleft
  exposure); install-from-mirror does NOT reliably cure GPLv3 copyleft.
- **Q7 / §5 — Article-13:** RULED = **Option A** (§5/§5.1).
- **§13 — canary checklist:** ⚠️ **owner-authoritative 8 points STILL
  not transmitted** (3rd consecutive turn the verbatim list/templates
  were described but not included). §13 remains a clearly-marked CC
  DRAFT; it governs a *later* tappa and does **not** block P2.

**RULED (folded into this revision):**
- **Q3 — IoC feeds:** RULED = none in V1 (condition 6).
- **Q4 — `similarity` field:** RULED = (a) reuse + normalised BM25 +
  doc-comment fix; no `common` shape change.
- **Q5 — KB packaging:** RULED = **both** modes (condition 4). ⚠️ Note
  from Q8/R4: the install-from-mirror mode does **not** cure GPL-3.0
  copyleft for LOLBAS (mirror = distribution; distilled entries may be
  derivative) — so the owner's pre-stated "re-rule Q5 → install-only"
  remedy is, for GPLv3 specifically, insufficient without legal sign-off;
  hence the §4.2 recommendation to **drop LOLBAS** rather than mirror it.
- **Q6 — module placement:** keep `agent/src/rag/` (uncontested;
  treated as accepted — owner object if not).
- **Q8 — licenses/attribution:** RULED requirements stand
  (`NOTICES.md` + `LICENSES/` + provenance, conditions 1–3). **R4
  verification EXECUTED (P1.3): MITRE ✅ / Sigma ✅ / LOLBAS 🛑 GPL-3.0
  — P2 BLOCKED, see §4.2 + Q2/Q8 above.**
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

*Plan of record (**P1.4**). All four owner verbatim artifacts folded
(§5.1, §12.1, §4.2.2, §13) — no CC placeholders remain; the recurring
verbatim-gap is CLOSED. **🛑 P2 remains BLOCKED on exactly ONE owner
decision: the LOLBAS Q2/Q5 re-ruling** (verification proved LOLBAS =
GPL-3.0; CC recommends **drop LOLBAS from V1**). Second, non-blocking
flag: the owner's authoritative provenance example (§4.2.2) names the
MITRE repo `mitre-attack/attack-stix-data@v18.1`, NOT the legacy
`mitre/cti@ATT&CK-v18.1` CC verified in P1.3 — **the MITRE license must
be re-verified against `attack-stix-data` at P2** (same ATT&CK ToU
expected, but not assumed). MITRE & Sigma otherwise clear. No P2
code/commit until the LOLBAS ruling. Subsequent phases: atomic commit
+ owner gate + clippy 0/0 + tests green; no multi-phase mega-commits.*
