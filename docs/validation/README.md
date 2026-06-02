# Adversarial Validation — evidence & report workspace

Artifacts produced by the Tappa 10.7 adversarial validation campaign.
Design of record: [`../design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`](../design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md).
Range setup + run procedure: [`../../RANGE_SETUP.md`](../../RANGE_SETUP.md).

| Path | What it is | Filled by |
|---|---|---|
| `matrix.md` | the per-rule test matrix (§4.1 row schema) | V2–V4 (one row per executed test) |
| `templates/result.md` | the per-result capture template (§6.2) | copied per test into `evidence/<run-id>/` |
| `REPORT.md` | the assembled validation report skeleton (§8) | V6 (metrics), V8 (publication) |
| `evidence/<run-id>/` | logs, screencaps, PCAP, hashes per run | every executed test |

**Scope note (§7 / §13):** the matrix is the *progressive product* of
V2–V4 — it ships empty here (schema + headers only) and grows one row per
executed test. The denominator is the **69 live production rules** (the
T10.5-era "61" is stale — see RANGE_SETUP.md). N/A rows (DNS-payload
NET-015, argv-dependent TTPs routed to T10.6) are excluded from the
coverage denominator per §13 Q1.
