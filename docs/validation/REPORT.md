# NorthNarrow — Adversarial Validation Report

> **SKELETON.** Assembled in V6 (metrics) and finalised in V8 (publication
> per §13 Q8). Sections below are stubs; do not treat empty sections as
> "nothing found". Source of truth for raw results: [`matrix.md`](matrix.md)
> + [`evidence/`](evidence/).

## 1. Executive summary
_<one paragraph: what was validated, headline coverage %, notable gaps. Filled V8.>_

## 2. Environment
- Target: **northnarrowdev**, production mode, **69-rule** engine (BUG-042 unit), kernel 6.8.0.
- Attacker: **kalidev** — Atomic Red Team, Sliver, Metasploit, LaZagne, Pupy (+ Caldera optional).
- Isolation: `intnet-adversarial` (10.10.10.0/24), no NAT/Tailscale during runs — C2-containment invariant.
- Snapshots: target `clean-prod`, attacker `armed`. Revert cadence per §6.1 / §13 Q10.
- Methodology delta (§5): real systemd unit + real eBPF/LSM attach + real iptables COMBAT — the path the test suite cannot exercise.

## 3. Coverage matrix (§8.1)
_<roll-up from [`matrix.md`](matrix.md): PASS/PARTIAL/FAIL/N/A per MITRE tactic and per family; overall coverage %. Filled V6.>_

## 4. Detection latency (§8.2)
_<event→verdict p50/p95/p99 histogram, from the audit-chain timestamps. Filled V6.>_

## 5. False-positive analysis (§8.3)
_<verdicts during the legitimate-Kali baseline window (V5), normalised per hour; baseline-vs-attack signal delta. Filled V6.>_

## 6. Production-readiness / overhead (§5.2)
_<CPU/mem/event-loop latency, idle vs under concurrent C2 beacon + Atomic sweep.>_

## 7. EDR comparison (§8.4 / §13 Q7)
_<descriptive framework vs a reference EDR; not a formal benchmark unless §13 Q7 is revisited.>_

## 8. Gaps & follow-ups
- **Detection gaps (rule-logic):** _<→ §13 Q5 hot-fixes, addressed in V7>_
- **Sensor gaps:** _<→ T10.6 backlog, NOT counted as T10.7 FAILs (§4 N/A)>_
- **Config gaps:** _<allowlist/watch-path fixes + re-run>_

## Appendix — evidence index
_<run-id → rule_ids → evidence files (+ sha256), generated from [`evidence/`](evidence/).>_
