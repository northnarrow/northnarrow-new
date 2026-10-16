# Evidence chains: verification and what to do when it fails

The agent keeps its evidence in signed, hash-chained files: the audit log
(`/etc/northnarrow/audit.log`), the canary registry and access log, and the
rotating detection, triage-status, netflow and FIM drift logs under
`/var/lib/northnarrow` (each with numbered archives and a
`.manifest.jsonl`). From lab PR 160 the agent also proves that rows were
not removed: rows carry their position (`seq`), the head of every chain is
anchored in `/etc/northnarrow/chain_heads.json`, and the rotating logs
checkpoint their active file in their manifest. Design:
`docs/design/EVIDENCE_CHAIN_COMPLETENESS_DESIGN.md`.

## What runs, and where to look

| When | What | Where the result goes |
|---|---|---|
| every start, before anything opens | anchored heads and checkpoints compared with the files | ERROR `chain integrity: evidence missing or altered` + signed `integrity_drift` |
| every start, at open | canary registry rows (all), canary access rows (last 256), audit row numbers | same |
| after the start, in the background | last 4 MiB of each rotating log | signed `chain_verify` (`ok`/`broken`) + `integrity_drift` `chain_verify_failed` |
| every `nn-admin detections` | the rows served | rows that do not verify are left out; ERROR + `chain_lines_unverified` |
| on demand | `sudo nn-admin chain verify` | `OK`/`BROKEN` per chain, exit 8 on any problem |

Signed findings: `sudo nn-admin audit read | grep integrity_drift`. The
journal: `journalctl --namespace=northnarrow -u northnarrow-agent`.

Forward the journal off the host: each anchored head is an INFO line
(`chain head anchored`, with `chain`, `seq`, `bytes`, `entry_hash`). With
one of those kept elsewhere, `sudo nn-admin audit verify --from
/etc/northnarrow/audit.log --expect-head <entry_hash>` (or `--min-seq N`)
exits 8 if the audit chain no longer reaches it — the check that still
works when every file on the host was rolled back together.

## When a check fails

1. **Keep the evidence first.** Do not reinstall, restore or delete
   anything yet. Copy off the host: `/etc/northnarrow/audit.log`,
   `/etc/northnarrow/agent.sig.pub`, `/etc/northnarrow/chain_heads.json`,
   `/var/lib/northnarrow/*.jsonl*`, `/var/lib/northnarrow/detections/`
   and the journal (`journalctl --namespace=northnarrow -o export`).
2. **See the whole picture.** `sudo nn-admin chain verify`; note every
   `BROKEN` line. Off the host, the same command on the copies with
   `--state-dir`, `--audit-log`, `--heads` and `--agent-pubkey <hex of
   agent.sig.pub>`.
3. **Read the kind** (the `kind` of the `integrity_drift`, or the text of
   the `BROKEN` line):

   | Kind | Meaning |
   |---|---|
   | `chain_truncated` | the file is shorter than its anchored head or checkpoint: rows were cut from its end (an emptied file too) |
   | `chain_missing` | the file is gone |
   | `chain_rewritten` | long enough, but the anchored line is not where it was: the file was rewritten |
   | `chain_archives_missing` | a rotating log has fewer archives than when it was anchored |
   | `active_file_missing` | a rotating log's active file was deleted after a rotation |
   | `chain_sequence_broken` | a row is missing or was inserted before the end (`seq` out of place, or a link broken) |
   | `chain_lines_unverified` | rows whose hash or signature does not verify (forged or altered); they are not applied or served |
   | `chain_verify_failed` | the background check of a rotating log failed; the detail names the line |
   | `chain_heads_unverified` | the anchor file holds no genuine snapshot (replaced or altered) |
   | `chain_heads_missing` | the anchor file was removed after anchoring had started |

4. **Find the window.** These files can only be changed with the
   anti-tamper hooks out of the way: look in the audit chain, just before
   the finding, for a `trusted_installer_grant`, an `agent_boot` whose
   `previous_run` says `abrupt`, other `integrity_drift` entries, and for
   the time the rows went missing (the anchored head's `seq` and the
   `chain.head` journal lines say what was there).
5. **Treat it as an incident.** Missing evidence means someone with root
   and a degraded window wanted it gone. Investigate the host as
   compromised; the rows that remain still verify and are still evidence.

## What the agent did about it

- The finding is written once, at the start that found it; the anchor then
  records the files as they are, so the next start is quiet. The signed
  `integrity_drift` stays in the audit chain.
- A rotating log whose checkpoint is unreachable keeps failing
  `nn-admin chain verify` until that generation leaves retention (the
  evidence is still missing; that is the point).
- Audit chain cut or anchor replaced: the overlay rollback floor was reset
  (`nn-admin config overlay status` shows it); an overlay signed before the reset
  is not loaded — re-sign it with `nn-admin config overlay set|sign`.
- Audit history lost (cut, row-number break, anchor removed): the one-key
  admin bootstrap is closed for good; key changes need the usual two
  signatures.
- A canary registry row that does not verify is not applied: a forged
  `Burn` leaves the canary armed.

## Expected once, not an attack

- Restoring the state directory or the audit log from a backup, or wiping
  `/var/lib/northnarrow`, is a rollback: the next start reports it
  (`chain_truncated`, `chain_missing` or `chain_heads_missing`). Record why.
- A deliberately regenerated agent key (the old `agent.sig.key` removed)
  makes every earlier signature unverifiable, the anchor's included:
  `chain_heads_unverified` once, and `chain verify` fails on the old rows.
  Archive the old chains with the old public key before reusing the host.
- After an upgrade from a version before lab PR 160 the audit chain gets a
  `chain_numbering_started` entry; older rows keep verifying as before.
- Use the `nn-admin` shipped with the agent: an older one reports numbered
  rows as broken. Downgrading the agent is not supported.
