# Tappa 10.7 — Rule × Tool validation matrix

One row per executed test. Schema = design §4.1. Denominator = the **69
live production rules** (see `../../RANGE_SETUP.md` for the 61→68→69
reconciliation). Empty by design — V2–V4 populate it.

## Result semantics (§4.1)

- **PASS** — fires with the exact expected severity, action, and posture transition.
- **PARTIAL** — fires but with a mismatch (severity/action/posture).
- **FAIL** — trigger genuinely met, nothing fired (a real detection gap).
- **N/A** — cannot be exercised here for a documented reason (DNS-blocked,
  argv-dependent → T10.6, sensor not in scope). Excluded from coverage denominator (§13 Q1).

## Triage class (for non-PASS, §6.3)

`rule-logic` · `sensor-gap → T10.6` · `config-gap`

## Matrix

| rule_id | mitre | tool (cmd / atomic-id) | expected (sev + action + posture) | result | latency_ms | evidence | notes |
|---|---|---|---|---|---|---|---|
| <!-- e.g. NN-L-FIM-022_LdSoPreloadModified --> | <!-- TA0003 / T1574.006 --> | | | | | <!-- evidence/<run-id>/… --> | |

## Family coverage roll-up (filled in V6)

| Family | Rules | PASS | PARTIAL | FAIL | N/A | Coverage % |
|---|---|---|---|---|---|---|
| Chain (NN-L-CHAIN-001..008) | 8 | | | | | |
| Process R001–R010 | 10 | | | | | |
| Process R011–R017 | 7 | | | | | |
| Module-load R018 | 1 | | | | | |
| FIM (NN-L-FIM-001..024) | 24 | | | | | |
| Canary (NN-L-CANARY-001..004) | 4 | | | | | |
| Net (NN-L-NET-*) | 15 | | | | | |
| **Total** | **69** | | | | | |
