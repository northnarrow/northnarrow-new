# NorthNarrow — Adversarial Validation Report

> **SKELETON.** Assembled in V6 (metrics) and finalised in V8 (publication
> per §13 Q8). Sections below are stubs; do not treat empty sections as
> "nothing found". Source of truth for raw results: [`matrix.md`](matrix.md)
> + [`evidence/`](evidence/). No coverage percentage goes into external
> material until this report is filled (external audit NN-AUD-235).

## 1. Executive summary
_<one paragraph: what was validated, the three figures of §3 (rule coverage, Critical sub-gate, technique coverage), notable gaps. Filled V8.>_

## 2. Environment
- Target: **northnarrowdev**, production mode, kernel 6.8.0, BUG-042 unit. Agent build: _<git commit + build hash>_.
- Denominator: the frozen files of [`matrix.md`](matrix.md) ("Frozen denominator"), version _<n>_ and sha256 of each — version 1 is 77 rules (the 76 of the production engine and NN-L-AT-001), 59 technique rows, 16 controls. Every version used, and what changed, is listed here.
- Attacker: **kalidev** — Atomic Red Team, Sliver, Metasploit, LaZagne, Pupy (+ Caldera optional).
- Isolation: `intnet-adversarial` (10.10.10.0/24), no NAT/Tailscale during runs — C2-containment invariant.
- Snapshots: target `clean-prod`, attacker `armed`. Revert cadence per §6.1 / §13 Q10.
- Methodology delta (§5): real systemd unit + real eBPF/LSM attach + real iptables COMBAT — the path the test suite cannot exercise.

## 3. Coverage matrix (§8.1)
Three figures, reported separately, computed as [`matrix.md`](matrix.md) ("Gate formulas") defines them:

- **Rule coverage (headline, gate ≥ 80 %):** _<PASS ÷ rules of `v2-rules.tsv` with status `in`; PARTIAL, FAIL (sensor gaps included) and NOT RUN count against it; the N/A count beside it.>_
- **Critical sub-gate (gate 100 %):** _<PASS ÷ `gate = critical` rules, with the rule list and, for each, its evidence directory; a rule without campaign proof is a miss.>_
- **ATT&CK technique coverage (no gate):** _<covered techniques ÷ techniques of `v2-techniques.tsv`, with the `known-gap` rows listed by name.>_

_<roll-up per family and per MITRE tactic: PASS/PARTIAL/FAIL/NOT RUN/N/A, plus the evasion and benign control rows of `v2-controls.tsv`. Filled V6.>_

## 4. Detection latency (§8.2)
_<event→verdict p50/p95/p99 histogram, from the audit-chain timestamps. Filled V6.>_

## 5. False-positive analysis (§8.3)
_<verdicts during the legitimate-Kali baseline window (V5), normalised per hour; baseline-vs-attack signal delta; the benign control rows of `v2-controls.tsv` and what each drew. Filled V6.>_

## 6. Production-readiness / overhead (§5.2)
_<CPU/mem/event-loop latency, idle vs under concurrent C2 beacon + Atomic sweep.>_

## 7. EDR comparison (§8.4 / §13 Q7)
_<descriptive framework vs a reference EDR; not a formal benchmark unless §13 Q7 is revisited.>_

## 8. Gaps & follow-ups
- **Detection gaps (rule-logic):** _<→ §13 Q5 hot-fixes, addressed in V7>_
- **Sensor gaps:** _<→ T10.6 backlog; counted as FAILs in §3 (class `sensor-gap`), never left out of the denominator>_
- **Config gaps:** _<allowlist/watch-path fixes + re-run>_

## Appendix — evidence index
_<run-id → rule_ids → evidence files (+ sha256), generated from [`evidence/`](evidence/).>_
