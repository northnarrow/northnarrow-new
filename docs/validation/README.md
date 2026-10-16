# Adversarial Validation — evidence & report workspace

Artifacts produced by the Tappa 10.7 adversarial validation campaign.
Design of record: [`../design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`](../design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md).
Range setup + run procedure: [`../../RANGE_SETUP.md`](../../RANGE_SETUP.md).

| Path | What it is | Filled by |
|---|---|---|
| `matrix.md` | the per-rule test matrix (§4.1 row schema) | V2–V4 (one row per executed test) |
| `v2-rules.tsv`, `v2-techniques.tsv`, `v2-controls.tsv` | the frozen denominator: rules, ATT&CK technique rows, evasion and benign controls (versions and hashes in `matrix.md`) | fixed before V2; changed only as a new version |
| `templates/result.md` | the per-result capture template (§6.2) | copied per test into `evidence/<run-id>/` |
| `REPORT.md` | the assembled validation report skeleton (§8) | V6 (metrics), V8 (publication) |
| `evidence/<run-id>/` | logs, screencaps, PCAP, hashes per run | every executed test |

**Scope note (§7 / §13):** the matrix is the *progressive product* of
V2–V4 — it ships empty here (schema + headers only) and grows one row per
executed test. The denominator does not: it is fixed before V2 runs, in
`v2-rules.tsv` (external audit NN-AUD-217) — every rule the agent can
record, 77 in version 1 (the 76 rules of the production engine and
NN-L-AT-001). A miss counts as a FAIL whatever its triage class, a sensor
gap included, and a rule never run counts against the headline. ATT&CK
technique coverage is measured on the rows of `v2-techniques.tsv` and
reported apart (NN-AUD-218). `matrix.md` holds the gate formulas and,
for the 100 % Critical sub-gate, where each rule's proof lives today
(NN-AUD-235). `agent/src/decision/validation_registry.rs` checks all of
this against the code.
