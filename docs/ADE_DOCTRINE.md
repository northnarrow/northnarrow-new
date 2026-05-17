# ADE Doctrine — Doctrine-Driven Adaptive Cyber-Defense

> *"Endpoint security is a sustained campaign, not a sequence of isolated detections."*

## Executive Summary

NorthNarrow's defensive philosophy is structured as a **five-phase military doctrine** that treats endpoint protection as a continuous campaign rather than reactive event-by-event response. Each phase is an explicit strategic posture with corresponding technical capabilities. Together they form what we call **Doctrine-Driven Adaptive Cyber-Defense (DDACD)**.

This document is the canonical statement of that doctrine. It serves three audiences:

- **Engineering**: every Tappa in the XDR Roadmap maps to one or more phases; design decisions are framed by which phase they serve.
- **Product and marketing**: the doctrine is the pitch — the strategic narrative differentiating NorthNarrow from per-event signature-based EDR vendors.
- **Compliance and regulatory**: each phase carries explicit constraints (legal, ethical, EU AI Act Article 13) that bind capability to responsibility.

The marketing one-liner: **"Doctrine-Driven Adaptive Cyber-Defense"**.

---

## Strategic Philosophy

Traditional endpoint detection and response (EDR) operates on a stimulus-response model: an event occurs, the agent classifies it, the agent acts. This model has three structural weaknesses.

It is reactive by design — protection begins only when an attack has already started. It treats every event as isolated, with no memory of strategic context, no escalation logic across the kill chain. And it places the entire detection burden on signature-based or rule-based classification — opaque to the customer, brittle to novel threats, regulatory-fragile under the EU AI Act.

NorthNarrow rejects this model. Instead, ADE operates as a defending force with doctrine: prepared positions, sustained intelligence, stateful escalation, and codified recovery procedures. The Latin military principle *Si vis pacem, para bellum* — "if you want peace, prepare for war" — is the operational philosophy.

The doctrine has five phases. They are not strictly sequential in time (multiple may be active simultaneously), but they are sequential in the operational sense of a campaign: each phase has prerequisites established by the prior phase, and each phase enables the capabilities of the next.

---

## The Five Phases

### Phase 1 — Knowledge Superiority

**Operational posture**: pre-conflict intelligence gathering and continuous learning.

**Strategic intent**: ensure ADE knows more about the threat landscape and the customer environment than the adversary knows about the defense.

**Technical capabilities**:

- RAG corpus over MITRE ATT&CK, CVE, CWE, RustSec, IoC, and TTP mappings — the structured threat knowledge base, indexed in Tantivy and queried at decision time.
- Customer environment fingerprinting — process behavior baselines, network topology mapping, sensor placement optimization.
- Threat intelligence feeds — anonymized cross-tenant IoC sharing (Tappa 14.x), JA3/JA4 TLS fingerprint correlation.
- Adversarial training — continuous exposure to red-team-generated attack patterns (Tappa 15.4 + 15.6) to harden the detection model against novel variants.

**Roadmap mapping**: Tappa 6.1 (ADE Foundation-Sec backend), Tappa 6.4 (RAG corpus expansion), Tappa 14.x (Threat Intelligence Collection — the legal hack-back alternative), Tappa 15.4 (Adversarial loop ADE vs MAL), Tappa 15.6 (Red Team Qwen 3B continuous attack generation).

**Doctrinal principle**: ignorance is the most expensive vulnerability. ADE invests heavily upfront in knowledge so that runtime decisions are informed rather than improvised.

---

### Phase 2 — Strategic Positioning

**Operational posture**: pre-conflict placement of sensors and deception artifacts.

**Strategic intent**: shape the battlefield so that any adversary action triggers a detectable signal.

**Technical capabilities**:

- Sensor multiplexer — process spawn, file ops, network connect, exec, DNS, ptrace — coverage of all primary adversary action vectors.
- Deception layer (Tappa 9.5) — canary files in plausible locations, fake credentials in plausible files, honey-traps for lateral movement reconnaissance, expected zero false-positive rate by design.
- Sensor placement optimization — endpoint topology analysis to identify high-yield observation points (shared service accounts, privileged process trees).

**Roadmap mapping**: Tappa 1-5 (FASE 1 Core Detection sensors), Tappa 9.5 (Deception Layer).

**Doctrinal principle**: position before conflict. Sensors and traps placed during peacetime are far more valuable than those deployed reactively after an attack begins.

---

### Phase 3 — Pre-built Fortifications

**Operational posture**: the defenses built before the adversary acts, designed to survive contact.

**Strategic intent**: maximize the cost of any adversary action — every attack must overcome multiple independent barriers, each codified in technical capability.

**Technical capabilities**:

- Posture state machine (Tappa 6.5) — four-state escalation (OBSERVING → ALERTED → ENGAGED → COMBAT), each state expanding ADE's response authority. State transitions are based on stateful threat assessment, not isolated event classification.
- Hardening layer (Tappa 6.6) — four-layer defense against adversarial inputs targeting the AI engine (sanitize → structured prompt → sanity check → dual verify).
- Anti-tamper substrate (Tappa 7) — kernel-level LSM hooks that protect the agent from termination, prevent tampering with detection state, and survive across agent restart via pin-based reuse pattern.
- Detection rules engine (Tappa 10) — sandbox-isolated rule evaluation, hot-reload, versioned ruleset.

**Roadmap mapping**: Tappa 6.5 (Posture state machine), Tappa 6.6 (Prompt Injection Hardening), Tappa 7 (Anti-tamper LSM + Watchdog), Tappa 10 (Detection rules engine).

**Doctrinal principle**: every fortification must function under attack, not only in pristine condition. Self-protection (anti-tamper) is a precondition for the rest of the doctrine: a compromised defender cannot execute any of the other phases.

---

### Phase 4 — Battle-Time Defense Synthesis

**Operational posture**: in-combat dynamic adaptation. Synthesize new defenses in response to ongoing attack patterns that pre-built fortifications cannot fully cover.

**Strategic intent**: extend defensive capability beyond what was anticipated at build time, while binding adaptation to strict guardrails to prevent runaway behavior.

**Technical capabilities** (Tappa 10.5):

- Dynamic rule synthesis — ADE in COMBAT state generates candidate detection rules based on observed attack patterns.
- Digital Twin pre-validation (Tappa 14.4.5 — prerequisite) — every synthesized rule is tested against a shadow-mode digital twin of the customer environment before deployment, eliminating false positives that would harm production.
- Hard cap on rules per window — maximum 5 synthesized rules per 60-second window, preventing rule explosion.
- Immutable whitelist — medical, industrial control system, aviation, and regulated subsystems are never affected by synthesized rules.
- Time-bounded lifetime (TTL) — each synthesized rule expires automatically after a configurable window (default: 1 hour) unless explicitly promoted to permanent rule by admin operator.
- XAI forensic chain — every synthesized rule carries an evidence chain: the observed attack pattern, the model's reasoning, the digital twin validation outcome. Court-admissible under AI Act EU Article 13 requirements.

**Roadmap mapping**: Tappa 10.5 (Battle-Time Defense Synthesis) — V1.0 commercial, post-beta. Requires Tappa 14.4.5 (Digital Twin Shadow Mode) as non-negotiable prerequisite.

**Doctrinal principle**: adaptation under fire is necessary, but uncontrolled adaptation is more dangerous than no adaptation. Battle-time synthesis is the doctrine's highest-risk phase and therefore the one with the strictest non-negotiable guardrails.

**Beta constraint**: this phase ships only in V1.0 commercial. The beta release does NOT include Battle-Time Synthesis — the risk of false positives in a customer environment without Digital Twin validation is unacceptable.

---

### Phase 5 — Recovery and Doctrine Evolution

**Operational posture**: post-engagement recovery, forensic preservation, and doctrine update for the next campaign.

**Strategic intent**: an attack survived without learning from it is wasted. Every engagement must improve the doctrine.

**Technical capabilities**:

- Cryptographic recovery (Tappa 8) — Ed25519 admin protocol with challenge-response. Only authorized operators can release the agent from COMBAT state. No silent recovery, no automated rollback that could be exploited by the adversary.
- Adversarial training loop (Tappa 15.4) — ADE-Defense vs MAL adversarial play, neutral JUDGE arbiter, continuous improvement of detection capability.
- Red Team continuous attack generation (Tappa 15.6) — Qwen 3B red team model generates novel attack chains with diversity penalty, exposing ADE-Defense to attacks not yet seen in real engagements.
- Doctrine evolution — periodic review of post-engagement evidence chains. Rules that proved effective are promoted to permanent ruleset; rules that proved ineffective are deprecated.

**Roadmap mapping**: Tappa 8 (Ed25519 admin protocol — shipped), Tappa 15.4 (Adversarial loop), Tappa 15.6 (Red Team Qwen 3B).

**Doctrinal principle**: recovery is the prerequisite for doctrine evolution. An adversary who learns from each engagement faster than the defender will eventually win. NorthNarrow's recovery protocols are designed to maximize learning extraction from each event.

---

## Mapping Phases to Customer Value

The five phases map to what the customer sees and pays for:

| Phase | Customer-Facing Value | Pitch Hook |
|---|---|---|
| 1 — Knowledge Superiority | Your defender knows what's out there better than the attacker does | AI-native, EU sovereign threat intelligence |
| 2 — Strategic Positioning | Sensors and traps placed where they catch the most | Deception layer with zero false positives by design |
| 3 — Pre-built Fortifications | Defenses built to survive contact, including the most sophisticated tampering | Hardest-to-kill agent on the market |
| 4 — Battle-Time Synthesis | Adaptive rule generation during attack, with safety guardrails compliant with EU AI Act | Court-admissible forensic chain for every adaptive decision |
| 5 — Recovery and Evolution | Cryptographic recovery, continuous improvement, no silent state changes | Ed25519 admin protocol — your agent only listens to you |

---

## Differentiation vs. Competitors

NorthNarrow's doctrine produces structural differences from CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, and Sophos.

**Stateful escalation**: competitors operate per-event; NorthNarrow operates per-state (Phase 3 posture machine). No commercial EDR in 2026 has dynamic stateful posture.

**Autonomous COMBAT**: competitors require operator approval for network isolation; NorthNarrow's COMBAT state autonomously drops network traffic with cryptographically-signed audit trail (Phase 3 + 5).

**Anti-tamper survivability**: competitors rely on userland protection; NorthNarrow uses kernel-level LSM with link pinning that survives agent process death (Phase 3 + 5).

**AI Act compliance**: competitors face regulatory exposure in EU markets; NorthNarrow's XAI saliency mapping and forensic evidence chain are designed against Article 13 from the start (Phase 4 + 5).

**EU sovereign data residency**: competitors process telemetry in US-hosted cloud; NorthNarrow's backend is EU-sovereign by design (Tappa 13 Backend SaaS).

The marketing position is **not** "we are better than CrowdStrike at the same game." It is **"we play a structurally different game — doctrine-driven instead of stimulus-response."**

---

## What NorthNarrow Does NOT Do

Doctrine includes explicit refusals — what the agent will never do, regardless of customer request or attacker provocation.

**No hack-back, no offensive counter-action**. Illegal under EU, Italian, and US law. The legal alternative is Threat Intelligence Collection (Tappa 14.x): JA3/JA4 packet capture, IoC extraction, anonymized cross-tenant sharing.

**No silent autonomous self-healing in beta**. The risk of catastrophic false positives in unvalidated environments is unacceptable. V2.0+ may introduce semantic self-healing once Digital Twin coverage is comprehensive.

**No "invulnerable agent" marketing**. At Ring 0 parity, sufficiently sophisticated malware can disable any EDR. NorthNarrow's marketing position is "hardest to kill + forensic evidence on kill + cryptographic recovery" — honest, defensible, and accurate.

**No Sub-OS / UEFI agent without partner**. Building below the OS requires hardware-vendor partnership (e.g., Eclypsium). Founder-solo Sub-OS development is a red flag for investors and a fragility for customers. Deferred to V3.0+ with explicit partner.

**No founder-solo decentralized mesh in V1**. Original NorthNarrow design included a 5-pillar mesh architecture for decentralized coordination. Deferred to V3.0+: mesh networks are an N+1-engineer problem, not a founder-solo problem.

---

## Compliance and Regulatory Framing

The doctrine aligns with EU AI Act Article 13 (transparency and explainability) and the Network and Information Security Directive (NIS 2) requirements.

**Article 13**: every defensive action, especially Phase 4 Battle-Time Synthesis, carries an XAI saliency map and evidence chain. The customer (and regulator) can reconstruct why each rule was generated, which input tokens drove the model's reasoning, and which RAG documents informed the verdict.

**NIS 2**: the Ed25519 admin protocol provides cryptographic audit trail for all administrative actions. COMBAT state changes are signed and timestamped; recovery requires cryptographic challenge-response, eliminating spoofed administrative commands.

**GDPR**: data processing is EU-sovereign (Tappa 13). Customer telemetry never leaves jurisdiction. The deception layer's canary artifacts are designed to be GDPR-neutral (no personal data, no PII bait).

### Tappa 6.9 — XAI Saliency (Article 13 evidence chain) — SHIPPED

The Article 13 commitment above is now realised as a concrete,
verifiable artifact. Plan of record: `docs/TAPPA6_9_XAI_PLAN.md`;
regulatory dossier: `docs/TAPPA6_9_ARTICLE_13_COMPLIANCE.md` (the
clause-by-clause hand-off, with implementation `file:symbol` and the
test that locks each). Standalone capability — its consumer (Phase 4
Battle-Time Synthesis, Tappa 10.5) is not yet built.

Phase ledger: P0 `5a7e45b` · P0.1 `b23b072` · P1 `a5963b7` · P2
`0865133` · P3 `54ea836` · P4 `1cde064` · P5 `eeec43f`+closeout.
**P6 (golden saliency regression fixtures) is deferred — a separate
later phase, tracked, not shipped.**

**Production contract (loud, non-negotiable).** The XAI path MUST run a
*dedicated* `AdeEngine` built through
`xai::engine::deterministic_ade_config` (temperature 0 ⇒ greedy, single
-thread) — production sampling may differ and must never be perturbed.
Determinism is a *construction* contract: `XaiEngine` consumes ADE via
the `evaluate` seam only and cannot enforce it at call time. The chain
records the exact decoding settings so an auditor reproduces the
saliency map bit-for-bit. Deployment cost: ≈ +16 GB for the second
Foundation-Sec-8B Q4_K_M instance, **lazy-loaded on first XAI
invocation** (synthesis is COMBAT-only/rare ⇒ steady-state cost zero).
Fail-closed is absolute: no XAI ⇒ no synthesis (`XaiUnavailable` is a
hard stop, never a partial chain).

### Tappa 6.9.7 — RAG-Local Knowledge Base — SHIPPED

A sovereign, deterministic retrieval layer that biases ADE verdicts
toward curated evidence. Plan of record:
`docs/TAPPA6_9_7_RAG_KB_PLAN.md` (delivered 2026-05-17).

- **Architecture.** `tantivy` BM25 (pinned `=0.25.0`,
  `default-features=false` — no `zstd-sys` C-FFI; the 100%-Rust/no-FFI
  charter holds) over a canonical KB: pinned **MITRE ATT&CK v18.1** +
  **SigmaHQ Linux** rules + the 6.7 `kb_seed` notes. An R3
  security-token analyzer keeps identifiers (`T1059.001`,
  `/etc/shadow`, `cmd.exe`, `CVE-…`) intact.
- **Sovereign.** The agent never fetches at runtime; the KB is
  acquired build/release-time (or from a customer mirror) by
  `cargo xtask rag-kb`. `kb_index_hash` is byte-stable and reproduced
  identically across independent rebuilds (auditable provenance in
  `docs/kb-sources/`). LOLBAS is excluded (GPL-3.0 — incompatible with
  proprietary distribution).
- **Integration.** Behind the byte-stable `RagEngine::retrieve`
  (C2/CLI deserialize charter — plan §0 mechanism swap, §3.4
  within-result normalisation); canary-gated via `NN_ADE_RAG_ENABLED`
  (default **OFF**, beta-safe — §13 default-flip checklist). `rag:None`
  is byte-identical to pre-6.7 (protects RAG-off XAI determinism).
- **Article 13.** The RAG block is part of the assembled prompt, so it
  is already bound by the signed `prompt_sha256` (XAI 1.0.0 schema
  untouched — plan §5 Option A); the separate hash-chained RAG
  retrieval log is a Tappa 13 follow-on.
- **Operational metrics** (real 964-doc corpus): `retrieve` p95
  **2.2 ms** (≤ 50 ms budget, ~23× margin), cold `open_index`
  **707 ms** (≤ 5 s). Golden suite 22/24 (cross-source Sigma
  co-retrieval gap documented — post-beta hybrid re-rank / GTFOBins).

---

## Conclusion

NorthNarrow's strategic position is not technological in the narrow sense. The AI engine, the eBPF sensors, the Ed25519 admin protocol, the deception layer — these are individually impressive but collectively replicable by a sufficiently funded competitor.

What is not replicable is the doctrine itself: the coherent five-phase framework that organizes engineering decisions, marketing language, regulatory positioning, and customer expectations into a single strategic narrative.

Every Tappa in the XDR Roadmap should be traceable to one or more phases of this doctrine. If a proposed feature does not map to a doctrinal phase, the question is not "should we build it differently?" — it is "should we build it at all?"

The doctrine is the spec. The Tappe are the implementation.

---

*Document version: 1.0 — initial canonical statement, May 17, 2026.*
*Companion document: `docs/XDR_ROADMAP.md` — Tappa-level implementation map.*
*Companion document: `docs/ADE_SUITE_VISION.md` — model architecture (ADE-Defense + ADE-Forge) supporting this doctrine.*
