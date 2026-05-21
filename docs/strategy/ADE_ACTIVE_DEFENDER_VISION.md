# ADE Active Defender — Canonical Vision

> *"The defender that knows the ground, prepares it, and watches it — without ever surrendering it."*

**Status:** CANONICAL VISION (strategic). Captures the ADE Active
Defender direction articulated by Forty (owner), 21 May 2026, as the
governing Phase-2 / release-V1.5 strategic context. Companion to
`docs/ADE_DOCTRINE.md` (the DDACD five-phase doctrine) and the
`docs/XDR_ROADMAP_TAPPE_NEW.md` roadmap delta.
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-21.
**Scope:** strategy + architecture intent only — **no code, no wire,
no rule changes**. This doc states *what* the Active Defender is and
*why*; tappa-level *how* is the V1.5 plan in §4 and the future design
docs it points to.

**Reconciliation decisions baked into this doc (owner-ruled
2026-05-21):**

1. **Sovereignty model — separate ingestion component.** The runtime
   agent's charter *"the agent never fetches at runtime"*
   (`ADE_DOCTRINE.md` l.228) is **preserved, not reversed**. Autonomous
   inbound threat-intel pull is a **distinct sovereign-side Knowledge
   Ingestion Service**, not the agent (§3).
2. **Release labelling — V1.5, mapped to DDACD phases.** The build-out
   is the post-Beta **release window V1.5**; each component maps to its
   DDACD doctrine phase. "Phase 2" in this doc means *release stage 2 /
   post-Beta*, never *DDACD Phase 2 (Strategic Positioning)* — the two
   are explicitly disambiguated to avoid the collision flagged in the
   strategic audit (§8).
3. **Cross-reference amendments** land in `ADE_DOCTRINE.md` + the
   roadmap delta, not a new `XDR_ROADMAP.md` (§8).

---

## 1. Vision summary

### 1.1 The Active Defender principle

T10.5 closed with ADE wired as **passive enrichment**: the
deterministic engine fires, ADE adds a second-opinion to the audit
chain (D8 `fim_template` / `chain_template`), and ADE never gates the
response. That is correct for the Beta — but it is *not the ceiling of
the vision*.

The **Active Defender** reframes ADE from *"an LLM that comments on
verdicts"* to *"an environmental defender that knows the ground it
holds, prepares that ground before contact, watches the adversary
inside it, and proves what happened afterward — while never letting
customer data leave the tenant."*

This is the operational expression of the DDACD doctrine's
*Si vis pacem, para bellum*: the Active Defender is the agent's
realisation of **Knowledge Superiority (DDACD Phase 1)** and
**Strategic Positioning (DDACD Phase 2)** as *live, adaptive,
environment-aware* capabilities rather than build-time constants.

### 1.2 Five-component architecture (overview)

| # | Component | One-line | DDACD phase | Release |
|---|---|---|---|---|
| C1 | **Environmental Awareness Module** | knows the host intimately — asset inventory, topology, baselines | Ph1 + Ph2 | V1.5 (foundation, first) |
| C2 | **Vulnerability Intelligence** | maps host software ↔ CVE/KEV, knows the host's *falle* | Ph1 | V1.5 |
| C3 | **Adaptive Deception Layer** | env-aware canary + honeypot placement (extends T9.5) | Ph2 | V1.5 |
| C4 | **Panopticon Forensic Chamber** | captures the attacker, Ed25519-signed forensic dossier | Ph2 + Ph5 | T11.5 (roadmapped) |
| C5 | **NorthNarrow as Threat-Intel Producer** | federated, privacy-preserving outbound IoC contribution | Ph1 + Ph5 | V2.0+ |

Cross-cutting and **enabling all five**: an autonomous **Knowledge
Ingestion Service** (§3) that pulls curated *public* threat
intelligence inbound, so ADE *self-instructs daily* — without the agent
fetching anything and without any customer data going outbound.

### 1.3 The sovereignty distinction (the load-bearing idea)

The Active Defender is **agentic and self-updating** yet **sovereign**.
These are reconciled by one distinction the rest of this doc returns to
repeatedly:

> **Inbound public knowledge ≠ outbound customer data.**
>
> - **Inbound** (allowed, autonomous): curated, *public, non-sensitive*
>   threat intelligence (MITRE ATT&CK, CISA KEV, NVD, abuse.ch,
>   MalwareBazaar, SigmaHQ) flows *into* the tenant over cert-pinned
>   HTTPS, signed and verified.
> - **Outbound** (forbidden by construction): customer telemetry,
>   asset inventory, vulnerability posture, captured-attacker
>   artifacts — **never** leave the tenant. No exception, no
>   "anonymized-but-just-this-once."

A defender reading the latest CISA KEV every morning is not a privacy
risk; a defender shipping your asset inventory to a vendor cloud is.
The Active Defender does the first and refuses the second.

---

## 2. The five-component architecture

### C1 — Environmental Awareness Module *(DDACD Ph1 + Ph2)*

**What it is.** ADE builds and continuously maintains an intimate model
of the host it defends:

- **Install-time inventory:** installed packages + versions, running
  services, listening sockets, user/group/sudo topology, kernel +
  module set, scheduled jobs, container/namespace layout.
- **Continuous baseline:** process-spawn behaviour, network topology
  (who talks to whom), privileged process trees, file-access patterns
  — the "normal" against which anomaly is judged.
- **Topology for positioning:** identifies high-yield observation
  points (shared service accounts, privileged trees) that inform where
  C3 places deception and where sensors matter most.

**Why it matters.** Every other component is downstream of knowing the
ground. Vulnerability intel (C2) needs the inventory; deception (C3)
needs the topology; forensics (C4) needs the baseline to say what was
abnormal. This is why C1 is the **V1.5 foundation, built first**.

**Builds on:** DDACD Phase 1 "customer environment fingerprinting" +
Phase 2 "sensor placement optimization" (today: doctrine concepts, no
tappa). Consumes existing sensor channels — no new sensors.

### C2 — Vulnerability Intelligence *(DDACD Ph1)*

**What it is.** ADE maps the C1 software inventory against the inbound
CVE/KEV/NVD corpus (§3) to know *the host's falle* — which installed
components are vulnerable, which vulnerabilities are
known-exploited (CISA KEV), and therefore which adversary techniques
are *most likely against this specific host*.

**The hard boundary — ADE knows, ADE does not modify.** The Active
Defender **does not patch, does not modify the kernel, does not change
installed software.** Knowing a host has a vulnerable `sudo` does not
license the agent to upgrade it (that would be exactly the
"catastrophic autonomous action in an unvalidated environment" the
doctrine forbids — `ADE_DOCTRINE.md` "No silent autonomous
self-healing in beta"). Instead C2 **prepares defenses contextually**:
it raises the relevance weight of detection rules for the techniques
that target the host's actual vulnerabilities, and tells C3 where to
place traps. Vulnerability awareness drives *defensive posture*, never
*offensive or mutating action on the host*.

**Builds on:** DDACD Phase 1 RAG corpus already lists "CVE, CWE,
RustSec" (`ADE_DOCTRINE.md` l.41) — C2 makes that corpus *live and
host-correlated* via §3 ingestion.

### C3 — Adaptive Deception Layer *(DDACD Ph2)*

**What it is.** Tappa 9.5 ships static canaries. C3 makes placement
**environment-aware**: using C1's topology and C2's vulnerability map,
ADE positions canary files, fake credentials, and honeypot artifacts
where *this host's likely adversary* will actually go — decoy SSH keys
near real ones, fake cloud creds in the paths LaZagne reads, honey-DBs
in plausible service directories. Placement adapts as the environment
and threat picture change.

**Builds on:** **Tappa 9.5 Deception Layer (shipped)** +
`Event::CanaryTripped` + the T10.5 `NN-L-CHAIN-003` canary→egress chain
rule. C3 is *placement intelligence over an existing trip mechanism* —
no new canary primitive required, which is why it is a V1.5 extension
rather than a ground-up tappa.

### C4 — Panopticon Forensic Chamber *(DDACD Ph2 + Ph5)*

**What it is.** When the posture machine escalates, the Panopticon
captures the adversary's activity in depth — full packet capture,
process/file/network timeline — and assembles an **Ed25519-signed
forensic dossier** (court-admissible, Article-13-aligned), preserved
*inside the tenant*.

**Builds on:** **already roadmapped as Tappa 11.5** — the full
user-space pcap-writer + Panopticon namespace, deferred from Tappa 10
(`TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md` §7; chained signed
`netflow.jsonl` is the T10 trigger seam). Signing reuses the **Tappa 8
Ed25519 infrastructure**. C4 is therefore *named here for architectural
completeness*; its delivery vehicle is the existing T11.5 line, not a
new V1.5 tappa.

### C5 — NorthNarrow as Threat-Intel Producer *(DDACD Ph1 + Ph5, V2.0+)*

**What it is.** The long-horizon inversion: NorthNarrow tenants
*contribute* to the threat picture, not just consume it — federated,
privacy-preserving sharing of *anonymized* IoCs (JA3/JA4 fingerprints,
attack patterns) so the fleet learns faster than any single tenant
could. This is the **outbound** direction and therefore the one bound
by the strictest sovereignty mechanism (§7 Q4 — the federated-privacy
question is explicitly open).

**Builds on:** DDACD Phase 1 "anonymized cross-tenant IoC sharing
(Tappa 14.x)" + Phase 5 doctrine evolution. **Deferred to V2.0+** — it
is not part of the V1.5 build-out and requires the Backend SaaS (T13)
and a ruled federated-privacy mechanism first.

---

## 3. Sovereignty constraints

This section is the canonical statement of how the Active Defender is
**autonomous and self-updating yet sovereign**. It is the part a
customer CISO and an EU regulator will read most closely.

### 3.1 Legal framework

- **GDPR Art. 44+ (international transfers).** Customer personal data
  must not transfer outside its lawful jurisdiction. The Active
  Defender's outbound-forbidden rule means there is *no transfer to
  assess* — telemetry, inventory, and forensic artifacts never leave
  the tenant.
- **DORA** (financial-sector operational resilience) and **NIS2**
  (essential-entity security): both demand auditable control over data
  flows and third-party dependencies. The cert-pinned, signed,
  audit-logged inbound pipeline (§3.3) is a *named, bounded, verifiable*
  dependency — not an opaque cloud call.
- **EU AI Act Art. 13** (transparency): the ingestion + application of
  intel is logged such that every defensive change is explainable —
  *which* intel, *from where*, *when*, *what it changed* (§3.4).

### 3.2 Architectural rules (non-negotiable)

1. **Customer data NEVER egresses.** Telemetry, C1 inventory, C2
   vulnerability posture, C4 captured-attacker artifacts stay in the
   tenant. This is enforced architecturally, not by policy promise.
2. **The runtime agent never fetches** (charter preserved —
   `ADE_DOCTRINE.md` l.228). All inbound pull is performed by a
   **separate Knowledge Ingestion Service**, not the agent.
3. **Inbound is public-only + curated.** The ingestion service pulls
   only from a **fixed, curated endpoint whitelist** of *public,
   non-sensitive* sources: **MITRE ATT&CK, CISA KEV, NVD, abuse.ch,
   MalwareBazaar, SigmaHQ.** No arbitrary URLs, ever.
4. **Cert-pinned + signature-verified.** Each endpoint is TLS
   cert-pinned; each fetched artifact is signature/hash-verified before
   it is admitted to the KB (reusing the T6.9.7 `kb_index_hash`
   byte-stable provenance model).
5. **Audit-logged.** Every pull and every resulting KB/posture change
   is recorded in a hash-chained ingestion log (the §3.4 narrative).

### 3.3 The Knowledge Ingestion Service (how inbound works without the agent fetching)

```
   PUBLIC INTERNET                 │  SOVEREIGN TENANT BOUNDARY
   (curated whitelist only)        │
   MITRE / CISA KEV / NVD /        │   ┌──────────────────────────┐
   abuse.ch / MalwareBazaar /      │   │ Knowledge Ingestion Svc  │
   SigmaHQ                         │   │ (sovereign-side, NOT the │
        │  cert-pinned HTTPS       │   │  runtime agent)          │
        │  signature-verified      │   │                          │
        └─────────  inbound  ──────┼──▶│ pull → verify → build    │
                                   │   │ Ed25519-signed KB bundle │
                                   │   └──────────┬───────────────┘
                                   │              │ local, signed
                                   │              ▼
                                   │   ┌──────────────────────────┐
                                   │   │ Runtime agent / ADE      │
                                   │   │ consumes LOCAL KB only   │
                                   │   │ (never fetches) — T6.9.7 │
                                   │   │ cargo xtask rag-kb seam  │
                                   │   └──────────────────────────┘
   ── outbound customer data: ✗ NONE, by construction ──
```

- **Daily self-instruction.** The ingestion service refreshes on a
  schedule (default daily). The agent picks up the new **local**
  signed KB through the existing T6.9.7 update path — so *ADE
  effectively self-instructs every day* while the agent itself remains
  fetch-free at runtime. The doctrine's "or from a customer mirror"
  clause (l.229) is the seam this formalises: the ingestion service
  *is* an automated, sovereign customer mirror.

### 3.4 Air-gapped deployment path

Air-gapped tenants (defense, classified, isolated critical infra)
receive the **identical** intelligence as an **offline Ed25519-signed
bundle**, transferred by the customer's existing approved media
process. Same KB format, same signature verification, same
`kb_index_hash` provenance — only the transport differs (sneakernet
instead of cert-pinned HTTPS). The air-gapped path is a first-class
mode, not a degraded fallback: it is *proof* that inbound intel is
decoupled from any live agent connection.

### 3.5 The CISO audit narrative

The Active Defender lets a customer security officer state, with
evidence from the hash-chained ingestion log:

> *"On <date> at <time>, the Knowledge Ingestion Service pulled CISA
> KEV revision <hash> and NVD feed <hash> over cert-pinned HTTPS,
> verified their signatures, and applied <N> posture/relevance changes
> (e.g. raised detection weight for T1068 because installed
> `<pkg>@<ver>` matches CVE-XXXX-YYYY, a known-exploited vuln). Zero
> bytes of customer data left the tenant in the process."*

That sentence — *"pulled X from Y at T, applied Z, zero customer data
exfil"* — is the sovereignty story rendered auditable.

---

## 4. V1.5 implementation plan (post-Beta build-out)

**Release positioning.** Beta (Phase-1, ~80% complete) → **V1.0
commercial** → **V1.5 Active Defender build-out** → **V2.0+**. V1.5
delivers C1–C3 + the Knowledge Ingestion Service; C4 rides the existing
T11.5 line; C5 is V2.0+. *("Phase 2" = release stage 2 / post-Beta —
NOT DDACD Phase 2.)*

### 4.1 Component sequencing (dependency-ordered)

```
  C1 Environmental Awareness ──┬──▶ C2 Vulnerability Intelligence ──┐
   (foundation, first)         │     (needs C1 inventory)           │
                               └──▶ C3 Adaptive Deception ◀─────────┘
                                     (needs C1 topology + C2 map)
        Knowledge Ingestion Service ── enables ──▶ C2 (CVE/KEV), C3 (TTP intel)
        C4 Panopticon ── via existing T11.5 ;  C5 Producer ── V2.0+
```

1. **C1 first** — nothing downstream works without the host model.
2. **Knowledge Ingestion Service** in parallel with C1 — C2 is inert
   without the inbound CVE/KEV corpus.
3. **C2** once C1 inventory + ingestion exist.
4. **C3** once C1 topology + C2 vulnerability map exist.

### 4.2 Tentative tappa breakdown (PROVISIONAL — numbering open, §7 Q5)

> ⚠️ Numbering is **provisional** pending roadmap reconciliation: the
> roadmap delta already uses "Tappa 10.5" for *Battle-Time Synthesis*,
> which collides with the shipped *Detection Rules at Scale* T10.5
> (§8). New numbers below are placeholders to be ratified when the
> consolidated roadmap is built.

| Component | Provisional tappa | Est. | Hard dependencies |
|---|---|---|---|
| Knowledge Ingestion Service | T14.2-ingest | 3–4 wk | T13 Backend SaaS (sovereign infra) |
| C1 Environmental Awareness | T14.2-env | 3–4 wk | shipped sensors (T1–10), T13 |
| C2 Vulnerability Intelligence | T14.2-vuln | 2–3 wk | C1 + ingestion + T6.9.7 RAG |
| C3 Adaptive Deception | T9.6 (extends 9.5) | 2 wk | T9.5 + C1 + C2 |
| C4 Panopticon | **T11.5 (existing)** | per T11.5 | T8 Ed25519, T10 netflow seam |
| C5 Threat-Intel Producer | T14.x (V2.0+) | TBD | T13 + federated-privacy ruling |

### 4.3 Dependencies on Phase-1 Beta tappe (T7–T13)

- **T7 anti-tamper** — the Active Defender's knowledge + traps are only
  trustworthy on a self-protecting agent (DDACD Phase 3 precondition).
- **T8 Ed25519** — signs the C4 dossier *and* the ingestion bundles.
- **T9.5 deception** — the substrate C3 makes adaptive.
- **T6.9 XAI / T6.9.7 RAG** — the explainability + local-KB seam C2 and
  the ingestion service plug into.
- **T13 Backend SaaS (EU-sovereign)** — hosts the sovereign-side
  ingestion service; **a hard prerequisite for the inbound pipeline.**

---

## 5. Marketing positioning differential

### 5.1 Competitive analysis

| Capability | CrowdStrike / SentinelOne / MS Defender | Wazuh | **NorthNarrow Active Defender** |
|---|---|---|---|
| Telemetry residency | US-hosted cloud processing | self-host (DIY) | **EU-sovereign; customer data never egresses** |
| Threat-intel updates | vendor cloud push (data flows both ways) | manual ruleset | **autonomous inbound pull, zero outbound** |
| Environment awareness | cloud-correlated | none | **local host-intimate model, in-tenant** |
| Deception | add-on / none | none | **adaptive, env-aware, zero-FP-by-design** |
| Forensic dossier | cloud-stored | logs | **in-tenant, Ed25519-signed, Art-13** |
| Air-gapped parity | limited/none | partial | **first-class signed-bundle path** |

The structural point: competitors achieve "intelligence" by *moving
your data to their cloud*. The Active Defender achieves it by *moving
public knowledge into your tenant* — the inverse data-flow direction.

### 5.2 Tagline

**"Sovereign Agentic XDR"** — agentic (it self-instructs, adapts, and
acts within doctrine) *and* sovereign (your data never leaves; only
public knowledge comes in). The existing DDACD one-liner
("Doctrine-Driven Adaptive Cyber-Defense") is the *how*; "Sovereign
Agentic XDR" is the *what you buy*.

### 5.3 Customer narrative

- **EU regulated banks (DORA):** an XDR that is intelligent *and*
  passes the data-transfer audit because there is no transfer to audit.
- **Defense / classified (air-gap):** the same daily-fresh intelligence
  as connected tenants, via signed offline bundle — no agent ever
  touches a network it shouldn't.
- **Critical infrastructure (NIS2):** host-intimate vulnerability
  awareness that *prepares* defenses without ever modifying the
  controlled system — knows the falle, touches nothing.

---

## 6. Forward-compatibility audit of Phase-1 tappe

**Conclusion up front: the Active Defender requires NO retroactive code
change to T7–T10.5.** It hooks exclusively into *existing,
designed-for-extension* seams.

### 6.1 No retroactive changes required

T7–T10.5 are append-only-compatible with the vision: the agent's
runtime contract (fetch-free, local-KB-consuming, deterministic engine
+ ADE-as-enrichment) is *unchanged*. The Active Defender adds
*sovereign-side* and *placement-intelligence* layers above it.

### 6.2 Architectural extension points (already present)

- **T8 admin protocol — opcodes APPENDED.** New Active-Defender admin
  operations (e.g. trigger an ingestion refresh, query the C2
  vulnerability map) append to the existing `OperationCode` set;
  immutable IDs, no renumbering — the same append-only discipline T10.5
  honoured for wire types.
- **T6.9.7 RAG corpus update path.** `cargo xtask rag-kb` +
  byte-stable `kb_index_hash` + the "or from a customer mirror" clause
  *is already* the seam the Knowledge Ingestion Service drives. C2's
  CVE/KEV corpus is a corpus extension, not a new mechanism.
- **Config `.v1` + `.local` overlay pattern.** C1 inventory thresholds,
  C3 placement policy, and the ingestion endpoint whitelist all express
  as `.v1` defaults + operator `.local` overrides — the shipped
  T9-C7 / T10.5-D1 pattern, LSM-protected.
- **`Event::CanaryTripped` + `NN-L-CHAIN-003`.** C3 adaptive placement
  reuses the shipped trip + chain mechanism; no new event variant.
- **T10 netflow signed-`jsonl` seam.** C4 Panopticon's capture path is
  the trigger T10 already laid down for T11.5.

### 6.3 Where Phase-2 hooks in

Active Defender is a **superstructure**, not a refactor: C1/C2 read
existing sensor events + the RAG seam; C3 writes through the existing
deception substrate; C4 is the already-planned T11.5; the Knowledge
Ingestion Service lives entirely on the T13 sovereign backend. The
runtime agent binary's contract does not move.

---

## 7. Open questions for owner ruling

1. **V1.5 calendar window.** When does the Active Defender build-out
   start relative to V1.0 commercial and the T13 backend? (Recommend:
   sequence *after* T13 ships, since the ingestion service depends on
   sovereign backend infra.)
2. **Threat-intel curation responsibility.** Who curates the inbound
   whitelist + validates source integrity — NorthNarrow team, a
   community-maintained list, or a partnership/commercial feed? Affects
   trust model + liability.
3. **Cloud Pro subscription pricing.** Is the autonomous ingestion +
   Active Defender a paid tier (Cloud Pro), and how is air-gapped
   (no-cloud) priced relative to it?
4. **Federated threat-sharing privacy mechanism (C5, V2.0+).** What is
   the privacy-preserving mechanism for *outbound* anonymized IoC
   contribution — differential privacy, secure aggregation, k-anonymity
   thresholds? This is the one outbound path and needs the strictest
   ruling before any C5 design.
5. **Roadmap numbering reconciliation.** The audit found *two* "Tappa
   10.5" (Battle-Time Synthesis in the delta vs the shipped Detection
   Rules at Scale). Before V1.5 tappa numbers (§4.2) are ratified, the
   consolidated `XDR_ROADMAP.md` should resolve the collision and fix a
   canonical numbering. (Surfaced by this audit; not in the original
   brief.)

---

## 8. Glossary + cross-references

### 8.1 Mapping to existing tappe

| Tappa | Relevance to Active Defender |
|---|---|
| **T6.9** XAI saliency (shipped) | explainability seam for C2 defensive-change justification (Art-13) |
| **T6.9.7** RAG-Local KB (shipped) | the local-KB + `cargo xtask rag-kb` + `kb_index_hash` seam the Ingestion Service drives; corpus home for C2 |
| **T8** Ed25519 admin protocol (shipped) | signs C4 dossiers + ingestion bundles; opcodes append for Active-Defender admin ops |
| **T9.5** Deception Layer (shipped) | substrate C3 makes environment-adaptive |
| **T10.5** Detection Rules at Scale (shipped) | the 61-rule engine C2 re-weights by host vulnerability; `NN-L-CHAIN-003` canary→egress underpins C3 |
| **T11.5** Panopticon (roadmapped) | the delivery vehicle for C4 Forensic Chamber (full pcap, deferred from T10) |
| **T13** Backend SaaS, EU-sovereign (roadmapped) | hosts the sovereign-side Knowledge Ingestion Service — hard prerequisite |
| **T14.x** Threat-Intel Collection (roadmapped) | C5 outbound producer direction; today's *outbound* IoC-sharing concept |
| **T15.4** Adversarial loop (roadmapped) | hardens the detection model the Active Defender re-weights |

### 8.2 Companion documents + memory

- `docs/ADE_DOCTRINE.md` — the DDACD five-phase doctrine; **amended by
  this vision** (sovereignty l.228 boundary clarified — see commit).
- `docs/XDR_ROADMAP_TAPPE_NEW.md` — roadmap delta; **amended** with a
  Phase-2/V1.5 pointer to this doc.
- `docs/XDR_ROADMAP.md` — *referenced but does not yet exist*; the
  consolidated roadmap to be authored when §7 Q5 numbering is resolved.
- `docs/ADE_SUITE_VISION.md` — *referenced by ADE_DOCTRINE l.264 but
  does not yet exist* (model architecture ADE-Defense + ADE-Forge).
- `docs/TAPPA6_9_7_RAG_KB_PLAN.md` — the KB/ingestion seam of record.
- `docs/design/TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md` §7 — the T11.5
  Panopticon trigger seam.

### 8.3 Compliance frameworks referenced

GDPR Art. 44+ (transfers) · DORA · NIS2 · EU AI Act Art. 13
(transparency/explainability).

### 8.4 Term disambiguation

- **"Phase 2 / V1.5"** in this doc = *release stage 2, post-Beta build
  window*. **NOT** *DDACD Phase 2 (Strategic Positioning)*. Component
  → DDACD-phase mapping is given per component in §2.
- **Inbound knowledge** = public threat intel pulled *into* the tenant.
  **Outbound data** = customer data leaving the tenant (forbidden). The
  Active Defender does the former, refuses the latter (§1.3).

---

*Document version: 1.0 — initial canonical Active Defender vision,
21 May 2026. Pending owner sign-off. Companion to `docs/ADE_DOCTRINE.md`.*
