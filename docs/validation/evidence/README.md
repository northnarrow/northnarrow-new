# evidence/

One directory per run: `evidence/<run-id>/` where `<run-id>` is
`<UTC-timestamp>_<family>` (e.g. `2026-06-05T14-22_fim_family`).

Per run directory (design §11):
```
<run-id>/
  <rule_id>.md         # filled copy of ../templates/result.md
  <rule_id>.png        # screen capture of the verdict/posture surface
  <rule_id>.log.jsonl  # agent audit-chain + journald slice for the verdict window
  <rule_id>.pcap       # NET + CHAIN families only (selective PCAP, §13 Q6)
  SHA256SUMS           # sha256 of every artefact in this dir (integrity, §11)
```

Evidence is pulled off the target via the **read-only shared folder**
(RANGE_SETUP.md §evidence) and hashed on arrival — never edited in place.
Pure FIM/process rows skip PCAP (log + screencap suffice, §13 Q6).
