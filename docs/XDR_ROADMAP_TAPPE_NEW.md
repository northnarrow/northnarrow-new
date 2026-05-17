# XDR Roadmap — New Tappe (Delta for Merge into XDR_ROADMAP.md)

This document specifies two new Tappe to be merged into `docs/XDR_ROADMAP.md`:

- **Tappa 10.5: Battle-Time Defense Synthesis** (V1.0 commercial, post-beta)
- **Tappa 15.6: Red Team Continuous Attack Generation (Qwen 3B)** (V1.0+, post-beta)

Both tappe map to the ADE Doctrine framework defined in `docs/ADE_DOCTRINE.md` — specifically Phase 4 (Battle-Time Defense Synthesis) and Phase 1+5 (Knowledge Superiority and Doctrine Evolution).

---

## Tappa 10.5 — Battle-Time Defense Synthesis

**Phase mapping**: ADE Doctrine Phase 4 (Battle-Time Defense Synthesis).

**Position in roadmap**: V1.0 commercial — months 12-18 after Tappa 16 Beta launch. **NOT in beta release.**

**Prerequisites** (non-negotiable):

- Tappa 14.4.5 (Digital Twin Shadow Mode) — Battle-Time Synthesis without Digital Twin validation is unacceptable risk.
- Tappa 6.9 (XAI Saliency Mapping) — required for the forensic chain on every synthesized rule. **✅ SHIPPED** (commits `5a7e45b..eeec43f`+P5 closeout). The standalone XAI capability + Article-13 evidence chain are complete and verifiable; EU AI Act Article 13 conformance: **✅ SHIPPED** (dossier: `docs/TAPPA6_9_ARTICLE_13_COMPLIANCE.md`). P6 (golden saliency regression fixtures) is a deferred separate phase — does not block this prerequisite. (This roadmap file is the Tappa 10.5 spec and carries no per-tappa status board; status annotated inline here.)
- Tappa 10 (Detection rules engine) — synthesized rules emit into this engine.
- Tappa 13 (Backend SaaS) — for cross-tenant correlation of synthesis triggers (telemetry to security operations console).

### Capability summary

ADE in COMBAT state generates candidate detection rules based on observed attack patterns. Each candidate is pre-validated against a shadow-mode digital twin of the customer environment before being deployed to production. Rules carry a time-bounded TTL and a complete forensic evidence chain compliant with EU AI Act Article 13.

### Functional specification

When ADE enters COMBAT state and observes attack patterns not fully covered by existing detection rules, the Battle-Time Synthesis subsystem activates.

**Step 1 — Pattern observation**: ADE-Defense correlates the active attack across sensor streams (process, file, network, ptrace). The pattern is anonymized (no customer-identifying fields) and forwarded to the synthesis engine.

**Step 2 — Candidate generation**: The synthesis engine generates one or more candidate rules expressed in the standard detection rule format (Tappa 10 schema). Generation is constrained to the rule grammar defined for the deployed rule engine — the model cannot emit rules outside the established grammar.

**Step 3 — Digital Twin pre-validation** (Tappa 14.4.5 prerequisite): Each candidate is loaded into a shadow-mode digital twin of the customer environment. The shadow twin replays the last N minutes of telemetry (configurable, default 60min) against the candidate. The candidate must satisfy three conditions: trigger on the actual attack pattern (true positive), not trigger on any benign baseline activity (zero false positive in the replay window), and not trigger against the immutable whitelist (medical, industrial control, aviation, regulated subsystems).

**Step 4 — Promotion**: Candidates that pass validation are promoted to the live rule engine with a TTL (default: 1 hour). The forensic evidence chain is bound to the rule and includes the observed attack pattern (anonymized telemetry), the synthesis engine's XAI attention map (which inputs drove the model's reasoning), the digital twin replay outcome (true positive evidence, zero false positive evidence), timestamp, customer environment hash, ADE-Defense model version, and cryptographic Ed25519 signature tied to the customer's admin key chain.

**Step 5 — Auto-expiry**: TTL-bound rules expire automatically. An admin operator can promote a TTL-rule to permanent status via `nn-admin` CLI before expiry; promotion creates a new audit record.

### Non-negotiable guardrails

These guardrails CANNOT be disabled by customer configuration, by admin operator command, or by any in-band signal.

**Hard cap per window**: maximum 5 synthesized rules per 60-second window. Excess candidates are dropped with telemetry to the security operations center.

**Immutable whitelist**: medical devices, industrial control systems, aviation systems, and regulated subsystems are never affected by synthesized rules. The whitelist is signed and is part of the deployment manifest. Modification requires re-signing by a customer admin key plus a vendor-side review (manual gate).

**TTL ceiling**: synthesized rules cannot exist for more than 24 hours without explicit admin promotion. After 24 hours, any unpromoted rule is automatically deprecated.

**Digital Twin validation is mandatory**: a candidate that has NOT passed digital twin validation cannot deploy to production. If digital twin is unavailable, Battle-Time Synthesis is automatically disabled.

**XAI forensic chain is mandatory**: a rule without complete evidence chain cannot deploy. If XAI is unavailable, synthesis is disabled.

**Cryptographic signing**: every synthesized rule carries an Ed25519 signature derived from the customer's admin key chain. Unsigned rules cannot deploy.

### Anti-patterns to avoid

This capability is the doctrine's highest-risk phase. Specific anti-patterns are explicitly defended against.

**Cascade synthesis**: a synthesized rule triggers further synthesis on its own telemetry. Mitigated by flagging synthesized rules in the rule engine and having the synthesis subsystem explicitly ignore telemetry from them.

**Runaway rule generation**: synthesis engine produces large rule volumes under attack saturation. Mitigated by hard cap per window plus telemetry to alert operator if cap is hit repeatedly.

**Silent rule deployment**: rules deploy without operator visibility. Mitigated by every synthesized rule emitting an immediate notification to the security operations console; customer ops can disable any rule from the console.

**Synthesized rule survives without justification**: TTL ceiling plus auto-deprecation prevents long-lived unjustified rules.

**Rule synthesis becomes vector for prompt injection**: the synthesis engine's input is anonymized telemetry, not raw natural language. The prompt injection hardening from Tappa 6.6 applies to this input path.

### Engineering estimate

Synthesis engine core: 3 weeks (depends on ADE-Defense model maturity post-Phase B).
Digital Twin integration: 1-2 weeks (depends on Tappa 14.4.5 completion).
Rule TTL plus auto-deprecation: 1 week.
XAI evidence chain binding: 1 week.
Cryptographic signing integration: 3 days (uses existing Ed25519 infrastructure from Tappa 8).
Operator console integration for visibility: 1 week.
Anti-pattern test suite (cascade synthesis, runaway, etc.): 1-2 weeks.
Documentation and customer onboarding materials: 1 week.

**Total**: approximately 8-10 weeks of focused engineering, scheduled post-Tappa 16 Beta and post-Tappa 14.4.5 Digital Twin.

### Marketing position

**One-liner**: "Adaptive defense generation under attack, with EU AI Act compliant forensic chain on every rule."

**Differentiation**: no commercial EDR in 2026 has dynamic rule synthesis during active defense. Competitors require either operator approval for new rules (slow) or rely on pre-built signature updates (lagging). Battle-Time Synthesis closes the gap between attack and adaptive response — within strict guardrails that satisfy EU regulatory requirements.

**Beta caution**: position this as V1.0 commercial capability, not beta. Customers in the beta program will see the doctrine framework but the synthesis subsystem is gated behind V1.0 release.

---

## Tappa 15.6 — Red Team Continuous Attack Generation (Qwen 3B)

**Phase mapping**: ADE Doctrine Phase 1 (Knowledge Superiority) and Phase 5 (Doctrine Evolution).

**Position in roadmap**: V1.0+ — post-beta, parallel with V1.0 commercial work. Continuous operation thereafter.

**Prerequisites**:

- Phase B training complete (ADE-Defense fluent in eBPF dialect).
- Tappa 15.4 (Adversarial loop ADE vs MAL with JUDGE arbiter) — Tappa 15.6 plugs into this loop as the MAL agent.
- Tappa 14.3 (ADE-Cloud Coordinator Swarm AI) — for distributed red team operations across multiple sandbox environments.

### Capability summary

A dedicated red team model (Qwen 3B), trained adversarially against ADE-Defense, continuously generates novel attack patterns to expose ADE-Defense to scenarios not seen in production engagements. The red team operates in an isolated sandbox environment, with output feeding back into ADE-Defense training and doctrine evolution.

### Functional specification

**Model architecture**: base model is Qwen 2.5 3B — small enough for cost-efficient continuous operation on RTX 5070 Ti, large enough for sophisticated attack chain reasoning. Fine-tuning is adversarial training against ADE-Defense Phase A + Phase B adapter, using a distinct dataset focused on MITRE ATT&CK technique implementations (T1003 Credential Dumping, T1055 Process Injection, T1059 Command Line, T1078 Valid Accounts), real-world malware behavior patterns (anonymized from public threat intelligence), and defense-evasion techniques (anti-debug, anti-sandbox, signature-evasion). Output format is structured attack chain in JSON, with discrete steps that map to observable telemetry events.

**Attack generation engine**: the red team operates in three modes.

Single-stage attack generation produces a single-step attack pattern (e.g., a specific T1059 command-line invocation with a specific obfuscation strategy). Used for narrow capability probing of ADE-Defense.

Multi-stage attack chains produce a 3-7 step attack chain crossing the MITRE ATT&CK kill chain (initial access → execution → persistence → lateral movement → exfiltration). Each step is conditioned on the prior step's success; failure at any step terminates the chain.

Diversity-penalized generation applies a recurrence penalty to attack patterns the red team has used before. The diversity penalty grows with repetition, forcing the model to explore novel attack space rather than reuse the same techniques. The penalty function is parameterized by attack technique (MITRE T-number), specific implementation variant (e.g., command-line obfuscation method), and time since last use (decay function — older patterns can be reused).

**Adversarial training loop integration** (Tappa 15.4): the red team operates as the MAL agent in the Tappa 15.4 adversarial loop. The red team generates an attack, ADE-Defense (BLUE) attempts detection, JUDGE (neutral arbiter — Claude/GPT API or local model) scores the engagement. Outcomes feed back into both models' training. ADE-Defense gets a reinforcement signal on successful detection. The red team gets a reinforcement signal on successful evasion plus a diversity bonus for novel patterns. Stalemates (neither side decisively wins) are logged for human review.

**Sandbox environment**: red team operations occur in an isolated sandbox to prevent any real-world impact. Virtual customer environments simulate common enterprise deployments. Network isolation ensures no outbound connectivity from the sandbox. Disposable VMs are rebuilt after each engagement. Telemetry is captured for replay analysis.

### Hardware and cost estimate

Hardware: RTX 5070 Ti (existing — same as Phase A training hardware).
Training compute: approximately $150 for initial fine-tuning (similar profile to Phase A).
Continuous operation: approximately $30/month electricity for sustained adversarial play.

**Total V1.0+ cost**: under $1000 in the first year, scaling with engagement volume.

### Engineering estimate

Dataset curation: 2-3 weeks (red team training corpus).
Fine-tuning Qwen 3B: 1 week (similar profile to ADE-Defense Phase A).
Attack generation engine integration: 1 week.
Diversity penalty mechanism: 1 week.
Sandbox environment: 2 weeks.
Adversarial loop integration with Tappa 15.4: 1-2 weeks.
Telemetry capture and replay analysis: 1 week.

**Total**: approximately 9-11 weeks of focused engineering, post-Tappa 16 Beta.

### Marketing position

**One-liner**: "ADE-Defense is continuously sharpened by an adversarial AI red team — every day your defender sees attacks no real adversary has yet attempted."

**Differentiation**: competitors update signature databases periodically (weekly to monthly). NorthNarrow's red team operates continuously, exposing ADE-Defense to thousands of novel attack patterns per day. By the time a real-world adversary deploys a technique, ADE-Defense has likely already seen variants of it in training.

**Beta caution**: this is a V1.0+ capability, not a beta promise. The pitch in beta materials should reference Tappa 15.6 as a planned post-beta capability, not as a live feature.

### Anti-patterns to avoid

**Red team escapes the sandbox**: mitigated by VM-level network isolation plus disposable infrastructure.

**Red team patterns become a leakage vector**: anonymized attack patterns are public threat intelligence material; the red team's own model weights are not exposed externally.

**Red team overfits ADE-Defense**: diversity penalty prevents the red team from reusing the same patterns; JUDGE arbiter prevents collapse to a single dominant attack.

**Red team generates real-world-actionable attacks**: attacks are scoped to the sandbox environment; output is not directly executable against production targets.

---

## Integration with ADE Doctrine

These two Tappe complete the ADE Doctrine framework.

Tappa 10.5 instantiates Phase 4 (Battle-Time Defense Synthesis). Without it, the doctrine is reactive only — pre-built fortifications respond to known patterns but cannot adapt under fire to novel attacks.

Tappa 15.6 strengthens Phase 1 (Knowledge Superiority) and Phase 5 (Doctrine Evolution). Without it, the doctrine cannot self-improve at the pace required by an evolving threat landscape — ADE-Defense would degrade in relative capability against adversaries who adapt continuously.

Both Tappe are post-beta. The beta release ships the doctrine framework (Phase 1-3, partial Phase 5 via Tappa 8 cryptographic recovery), with Phase 4 and the continuous Phase 5 evolution arriving in V1.0 commercial.

---

*Document version: 1.0 — initial specification, May 17, 2026.*
*To be merged into `docs/XDR_ROADMAP.md` as new sections after Tappa 10 and Tappa 15.4 respectively.*
*Companion document: `docs/ADE_DOCTRINE.md` — strategic narrative for both Tappe.*
