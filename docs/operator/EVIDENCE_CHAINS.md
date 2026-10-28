# Evidence chains: verification and what to do when it fails

The agent keeps its evidence in signed, hash-chained files: the audit log
(`/etc/northnarrow/audit.log`), the canary registry and access log, and the
rotating detection, triage-status, netflow and FIM drift logs under
`/var/lib/northnarrow` (each with numbered archives and a
`.manifest.jsonl`). From lab PR 160 the agent also proves that rows were
not removed: rows carry their position (`seq`), the head of every chain is
anchored in `/etc/northnarrow/chain_heads.json`, and the rotating logs
checkpoint their active file in their manifest. Design (source
repository, not shipped with the release):
<https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EVIDENCE_CHAIN_COMPLETENESS_DESIGN.md>.

## What runs, and where to look

| When | What | Where the result goes |
|---|---|---|
| every start, before anything opens | anchored heads and checkpoints compared with the files | ERROR `chain integrity: evidence missing or altered` + signed `integrity_drift` |
| every start, at open | canary registry rows (all), canary access rows (last 256), audit row numbers | same |
| every start, after the canary chains open | the access log's first-trip rows of the canaries the registry holds armed (lab PR 260) | a trip the registry does not record: ERROR `canary: a trip the registry did not record` + signed `canary_trip_recovered` + a `trip` row; the canary stays tripped |
| a start refused while the audit log cannot take the refusal (it is the gate: not writable, its chain broken) | the refusal signed with the agent's key in `boot-refusals.jsonl` beside the pid file, `/run/northnarrow` (lab PR 262; `BOOT_INTEGRITY.md` §7) | ERROR `refused boot recorded in the fallback chain`; `sudo nn-admin audit verify --from /run/northnarrow/boot-refusals.jsonl` |
| every start, once the audit log is open | that fallback chain, verified with the agent's key | a signed `boot_refusals_recovered` (`recorded`, or `refused` with why for a file that does not verify) before the boot's `agent_boot`; the file removed |
| after the start, in the background | last 4 MiB of each rotating log's active file | signed `chain_verify` (`ok`/`broken`, each broken log with its `class`) + `integrity_drift` `chain_verify_failed`, at every start while the lines are there |
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

The agent's unit lets journald keep up to 50000 of its lines per 30 s
(`LogRateLimitBurst=`, external audit DEP-017; journald's default is 10000
and drops the rest of a burst, head lines included). A line journald did
drop shows as `Suppressed N messages from northnarrow-agent.service` in
the same journal. Sealing (optional): `sudo journalctl --setup-keys` writes
the host's sealing key (`/var/log/journal/<machine-id>/fss`); journald,
the `northnarrow` namespace's instance included, then seals each persistent
file it opens afterwards — the next one after `sudo journalctl
--namespace=northnarrow --rotate` (`Seal=` is on by default and does
nothing without a key). Keep the verification key it prints off the host,
and check with `journalctl --namespace=northnarrow --verify
--verify-key=<key>`. Sealing shows a file changed after the fact; it does
not stop root from removing the files, which is what the forwarded copy is
for.

## Exit codes of the verifiers

Stable (scripts may rely on them; external audit MAIN-014, EVD-017, lab
PR 190):

| Command | 0 | 1 | 8 |
|---|---|---|---|
| `nn-admin chain verify` | every chain verifies (and the anchor, when there is one) | the agent public key could not be loaded | at least one `BROKEN` line; every chain is still reported, one damaged chain does not hide the others |
| `nn-admin audit verify --from F` | the chain is intact (a missing or empty file is 0 rows) | `F` or the key cannot be read (I/O, permissions) | the first row that does not verify, or the first line that is not a row, with its line number and the rows verified before it; or `--expect-head`/`--min-seq` not reached |
| `nn-admin audit read` | every line was a row | the log cannot be read, or stdout was closed | some lines are not audit rows: each is named on stderr (`audit: line N of F skipped: …`, the first 100, then the count), and every row before and after them was printed |

What the verifiers report instead of stopping (before lab PR 190 they
aborted or stopped at the first bad line):

- **A line that is not a row** — cut short (`the last line, cut short (no
  newline)`), not JSON, not UTF-8, or longer than 16 MiB (`… bytes, longer
  than 16777216 bytes: not read`; no row the agent writes comes near it,
  and such a line is never read into memory). `audit verify` and `chain
  verify` report a broken chain at that line (`line N: not an audit row
  (…); K row(s) verified before it` for the audit chain, `malformed line
  N` for the rotating logs and their manifests, N counted from 0 there);
  `audit read` skips it and prints the rest — read the rows after it,
  they may be the ones that matter.
- **A sealed archive without its terminator** (`archive N (…) has no
  terminator: it is empty or was cut before its last line`): that rotating
  log is `BROKEN`; the next chains are verified and reported as usual.
- **Archives past seq 999,999** are named with seven or more digits
  (`detections.jsonl.1000000`) and are listed, rotated out and verified
  like the others. Any other spelling of a number (`.00099`, `.0123456`)
  is not an archive of the log.

The verifiers read one line at a time: a large chain costs the memory of
its longest line, not of the file. `audit read` does not verify signatures;
use `audit verify` or `chain verify` for that.

Signatures are checked strictly (Ed25519 `verify_strict`; external audit
FIMP-013, lab PR 197) by every verifier of these chains — `nn-admin audit
verify` and `chain verify`, the agent's checks at open and in the
background, the head anchor, the FIM baseline: a public key or a signature
`R` of small order is refused. Every row the agent signed passes; the rows
and their pre-images did not change. A `--agent-pubkey` of small order makes
the first row fail (`agent_sig invalid`): check that the key given is the
agent's (`agent.sig.pub`, or the hex kept off the host).

## Line formats: what a signature covers (lab PR 204)

One agent key signs every chain. What its signature binds, per chain (external
audit EVD-007, EVD-008, EVD-023):

| Lines | Pre-image signed | The bytes on disk |
|---|---|---|
| rotating logs (detections, status events, netflow, FIM drift): data lines, terminators and manifest rows with `fmt_ver` 3 — every line this version writes | `SHA-256("northnarrow/chainlog/<log>/<line type>/v3\0" ‖ prev_hash ‖ line)`, `<log>` one of `detections`, `status_events`, `netflow`, `fim_drift`, `<line type>` `data`, `terminator` or `manifest` | must be the canonical serialisation of the line |
| the same logs, lines without `fmt_ver` or with `fmt_ver` 2 (written before this version) | `SHA-256(prev_hash ‖ line)`, the same for every log and line type | not checked; counted |
| `audit.log`, `canaries.jsonl`, `canary_access.jsonl`, numbered rows (`seq`, lab PR 160 on) | `SHA-256("northnarrow/audit/v2\0"` (or `canary-registry`, `canary-access`) `‖ prev_hash ‖ row)` | must be the canonical serialisation of the row |
| the same files, rows without `seq` | `SHA-256(prev_hash ‖ row)` | not checked; counted |
| FIM baseline, `netflow_listeners.jsonl` | `SHA-256(prev_hash ‖ row)` | not checked |

*Canonical* means: the verifier decodes the line, serialises it again (hash and
signature included) and finds the same bytes. The hash is computed over the
decoded line, so before this version a line with a key the agent never writes
(`"injected":"x"`), its keys in another order, spaces, or a value spelled with an
escape (`\u0072ecord`) decoded to the same line and verified. Such a v3 line or
numbered row is now refused; an older line still verifies as it always did and is
named in the summary.

What `nn-admin chain verify` / `audit verify` print for it (exit 8):

- `file F: entry N: a v3 line not in its canonical form (the bytes on disk are
  not what the agent wrote: a key added, reordered or re-spelled)` — a rotating
  log, its archives or manifest (N counted from 0, empty lines included).
- `entry N: a numbered row not in its canonical form (…)` — the audit chain or a
  canary chain (N counted from 0 over the rows).
- `file F: entry N: a line in the old format (v1/v2, untagged pre-image) after v3
  lines` — the agent writes v3 only; an old-format line after the first v3 line
  of a log (or of its manifest) was put there.
- `file F: malformed line N: fmt_ver K: a format this reader does not know (it
  reads up to 3)` — a line from a newer agent, or a forged version.
- `entry_hash mismatch` at a line that decodes fine: a line signed for another
  log or another line type (a manifest copied from another log, a line moved
  between logs) recomputes to another hash.

On a host upgraded from an earlier build the `OK` lines say what is still in
the old format: `…, 12 line(s) in the old format (untagged pre-image) before the
v3 ones` for a rotating log, `…, 3 old-format row(s) not in canonical form
(bytes the signature does not cover)` when some of those were rewritten. The
old lines leave with retention (the rotating logs) or stay (the flat chains,
which are not rotated); they are the residual: an old line can still be moved
between two logs of the same shape, or rewritten in bytes, without breaking its
signature. The agent's checks at open (the tail of a rotating log, the canary
chains, the head anchor) apply the same rules: a v3 line not in canonical form
is not a head, is cut from a torn tail like a line whose hash fails, and a
canary row in that state is not applied.

**Readers older than the agent.** Upgrade `nn-admin` with the agent
(`install.sh --upgrade` and the packages do). An `nn-admin` built before this
version reports every rotating log that holds a v3 line `BROKEN` (`entry_hash
mismatch` at its first v3 line or manifest row, exit 8); the flat chains are
unaffected. `nn-admin` 0.0.1 has no reader of the rotating logs (its `audit
verify` already needs the newer `nn-admin` since lab PR 160). An agent older
than this version, put back over v3 files, does not verify v3 lines: at its
start it cuts up to 16 trailing v3 lines of an active file or manifest that
still ends in old-format lines (attested as `torn_tail_repaired` in the
manifest), or keeps the tail as `tail_unverified`; its background check reports
`chain_verify_failed`; its read verbs leave v3 rows out. Downgrading the agent
after this version has written is not supported.

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
   | `chain_verify_failed` | the background check of a rotating log failed; the detail names the class and where (below) |
   | `chain_heads_unverified` | the anchor file holds no genuine snapshot (replaced or altered) |
   | `chain_heads_missing` | the anchor file was removed after anchoring had started |
   | `agent_id_changed` | the agent signs as another `agent_id` than the chain's last row (`from`, `to`): `/etc/northnarrow/agent_id` was removed, replaced or unusable while the agent was stopped (`source`: `minted`, `loaded`, `unavailable`) |

4. **Find the window.** These files can only be changed with the
   anti-tamper hooks out of the way: look in the audit chain, just before
   the finding, for a `trusted_installer_grant`, an `agent_boot` whose
   `previous_run` says `abrupt`, other `integrity_drift` entries, and for
   the time the rows went missing (the anchored head's `seq` and the
   `chain.head` journal lines say what was there).
5. **Treat it as an incident.** Missing evidence means someone with root
   and a degraded window wanted it gone. Investigate the host as
   compromised; the rows that remain still verify and are still evidence.

### What `chain_verify_failed` says (lab PR 256)

The detail starts with `the last 4194304 bytes do not verify:` and names
the file, then one of these classes (the `class` of the log's entry in the
signed `chain_verify`):

| `class` | The detail | Meaning |
|---|---|---|
| `signed_by_another_key` | `K of the M lines checked are signed by another key, from <first> to <last>: each one's entry_hash recomputes and its link to the line before it is intact, but its signature does not verify with this agent's key (agent.sig.pub <8 hex>…)` | the lines are as they were written and in their place, but this agent's key did not sign them: a regenerated agent key, another agent process with its own key writing this file — or forged lines. Every such line of the window is counted |
| `content_altered` | `<line>: its entry_hash does not recompute (…)` | the line was changed after it was written |
| `link_broken` | `<line>: its prev_hash … is not the entry_hash … of the line before it` | a line was removed, inserted or moved |
| `malformed`, `not_canonical`, `legacy_after_v3` | `<line>: a malformed line (…)`, … | not a line this agent writes there (see the line formats above) |
| `unreadable` | `cannot be read: …` | the file could not be read |

A line is placed as `line N (byte B, ts T)`: `B` is the offset of its first
byte in the active file, `N` its line number (from 1) when the file is
shorter than the window, `T` its `ts` when that is a plain timestamp. In a
longer file the window starts inside it and only the offset is given (`the
line at byte B`): earlier versions counted `entry N` from the window's first
line, which was not the line's place in the file. The classes other than
`signed_by_another_key` stop the check at the first line, as before, and
add how many lines another key signed before it. Each class is a
`chain_verify_failed`; the file's truncation, removal or rewrite are the
start's own findings (`chain_truncated`, …) and are reported apart.

**Lines signed by another key.** What to do:

1. `sudo nn-admin chain verify`: every chain, the manifests included (the
   first failing line of each, `signature invalid (its entry_hash
   recomputes: …)`), exit 8.
2. Compare the key: `head -c 8 /etc/northnarrow/agent.sig.pub` against the
   `agent.sig.pub` the detail names; a regenerated key is the case below
   ("Expected once"): every older line fails, from the first line of the
   file.
3. Find the writer: a writer that met this agent's tail recorded a
   `tail_unverified` row, signed by its own key, in the log's
   `.manifest.jsonl` (`sudo grep tail_unverified
   /var/lib/northnarrow/detections/detections.jsonl.manifest.jsonl`); the
   `ts` of the first and last line give the window. Look in the audit chain
   and the journal of that window for what ran as root.
4. On a lab or CI host, the privileged e2e suites ran as root before lab PR
   256 with agents of their own key that wrote the installed agent's logs
   (lot 255): rows in that window from the suites' rules and fixtures
   (`bpftool`, `fim_child_…`) are theirs. Any other case is an incident
   (step 5 above).

## What the agent did about it

- A start's own findings (`chain_truncated`, `chain_missing`,
  `chain_rewritten`, …) are written once, at the start that found them;
  the anchor then records the files as they are, so the next start is
  quiet. The signed `integrity_drift` stays in the audit chain.
- `chain_verify_failed` is written at every start while the failing lines
  are in the last 4 MiB of the active file — the evidence is still bad —
  and `nn-admin chain verify` keeps failing until their generation leaves
  retention. The agent removes nothing: do not edit or cut the files (that
  is a rewrite, and evidence lost). Moving the state directory aside (kept
  for the investigation) is a rollback: the next start reports it once
  (below).
- `chain_lines_unverified` is written each time a read verb leaves out
  another number of rows of a file than the last time; the ERROR is in the
  journal every time.
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
  `Burn` leaves the canary armed. A canary access row that does not
  verify (or a copy of one, out of the place it was signed with) trips
  nothing at the next start (lab PR 260).

## Expected once, not an attack

- Restoring the state directory or the audit log from a backup, or wiping
  `/var/lib/northnarrow`, is a rollback: the next start reports it
  (`chain_truncated`, `chain_missing` or `chain_heads_missing`). Record why.
- A deliberately regenerated agent key (the old `agent.sig.key` removed)
  makes every earlier signature unverifiable, the anchor's included:
  `chain_heads_unverified` once, and `chain verify` fails on the old rows;
  the background check reports `signed_by_another_key` from the first line
  of each rotating log at every start until those lines leave the last
  4 MiB of its active file. Archive the old chains with the old public key
  before reusing the host.
- A deliberately removed or restored `agent_id` (a re-mint, a backup put
  back) is `agent_id_changed` once; the first start of an install signs
  `agent_id_minted` only. Overlays and admin signatures made for the old
  id no longer verify: sign them again for the new one.
- After an upgrade from a version before lab PR 160 the audit chain gets a
  `chain_numbering_started` entry; older rows keep verifying as before.
- Use the `nn-admin` shipped with the agent: an older one reports numbered
  rows, and the rotating logs' v3 lines (lab PR 204), as broken. Downgrading
  the agent is not supported.
