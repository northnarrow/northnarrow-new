<!--
Per-result capture template (design §6.2). Copy into
docs/validation/evidence/<run-id>/<rule_id>.md and fill. The one-line
summary becomes the corresponding row in ../../matrix.md.
-->
# <rule_id> — <short rule name>

- **Run ID:** <run-id, e.g. 2026-06-05T14-22_fim_family>
- **Snapshot generation:** target `clean-prod` @ <gen>, attacker `armed` @ <gen>
- **MITRE:** <tactic TAxxxx / technique Txxxx[.xxx]>
- **Result:** PASS | PARTIAL | FAIL | N/A
- **Triage class (if non-PASS):** rule-logic | sensor-gap→T10.6 | config-gap
- **Detection latency:** <event_ts → verdict_ts> = <N> ms

## (a) Exact trigger
```
# tool + command, or Atomic Red Team test id
<command / atomic-id>
```

## (b) Agent verdict (log snippet)
```
# journalctl --namespace=northnarrow -u northnarrow-agent.service \
#   | grep -v event=ProcessSpawn   (window around the verdict)
<paste verdict line(s): rule=… severity=… action=… + any posture transition>
```

## (c) Evidence
- Screen capture: `./<rule_id>.png` (verdict/posture surface)
- PCAP (NET/CHAIN only): `./<rule_id>.pcap`
- Log slice: `./<rule_id>.log.jsonl`  sha256: `<hash>`

## (d) Expected vs observed
| | Severity | ResponseAction | Posture transition |
|---|---|---|---|
| Expected | | | |
| Observed | | | |

## Notes
<for PARTIAL/FAIL: what mismatched, triage reasoning, follow-up (§13 Q5 hot-fix or T10.6)>
