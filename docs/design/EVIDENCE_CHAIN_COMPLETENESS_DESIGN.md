# Evidence chain completeness: row numbers, heads, anchors

External audit NN-AUD-108, NN-AUD-109, NN-AUD-112, NN-AUD-174 (EVD-002,
EVD-003, EVD-009, DEC-018); lab PR 160. Code: `agent/src/chain_anchor.rs`,
`agent/src/chainlog.rs`, `agent/src/audit.rs`, `agent/src/canary/`.

## Problem

Every signed chain (`audit.log`, the canary registry and access log, the
rotating detection, status, netflow and FIM drift logs) links each row to
the one before by hash and signs it with the agent key. That proves the
rows present were not changed. It did not prove that none were removed:

- a chain cut at its end, or deleted and restarted from genesis, verified
  (EVD-002, DEC-018);
- `verify_log_set` accepted a missing or emptied active file (EVD-003);
- nothing verified a chain in production: `verify_log_set` had no caller,
  the canary chains were only parsed at open, and the detections read path
  served any well-formed JSON line (EVD-009, DEC-018);
- the four chains share one key with no domain separation (DEC-018).

The fix is one format for all chains, designed once.

## Format

**Row numbers (flat chains).** `audit.log`, `canaries.jsonl` and
`canary_access.jsonl` rows written from lab PR 160 on carry `seq`, the
row's 0-based position in the file (`#[serde(default, skip_serializing_if
= "Option::is_none")]`, just before `prev_hash`). Rows written before have
none and keep their exact bytes. Numbering starts at the number of rows
already present, so the first numbered row also proves that no older row
was removed. The verifiers require `seq == position` from the first
numbered row on, and refuse a row without `seq` after it (`RowSeq`). An
unreadable line still takes a position (an inserted line is a break).

**Domain separation.** A numbered row is hashed as
`SHA-256(domain ‖ prev_hash ‖ row)`, the domain being
`northnarrow/audit/v2\0`, `northnarrow/canary-registry/v2\0` or
`northnarrow/canary-access/v2\0`. A row without `seq` keeps
`SHA-256(prev_hash ‖ row)`. Removing `seq` from a numbered row changes its
hash, so a row cannot be downgraded to the old pre-image. The rotating
logs took the same step with their format v3 (lab PR 204, external audit
EVD-008): data lines, terminators and manifest rows with `fmt_ver` 3 are
hashed as `SHA-256("northnarrow/chainlog/<log>/<line type>/v3\0" ‖
prev_hash ‖ line)` (`chainlog::chain_domain`, `ChainPayload::KIND`); lines
without `fmt_ver` or with 2 keep `SHA-256(prev_hash ‖ line)`, and none may
follow a v3 line.

**Canonical bytes** (lab PR 204, EVD-007). The hash is computed over the
decoded row, so it covers the modelled fields only. A numbered row and a v3
line must also be byte-equal to their own re-serialisation (hash and
signature included); an older row that is not is counted, not refused. The
writers' rows are canonical by construction (`serde_json` with struct order,
`float_roundtrip` for floats); the round-trip tests hold every payload type
to it.

**File head.** `(bytes, tail_hash, seq?)`: the offset just past the last
complete line that verifies, and that line's `entry_hash`. Checking a head
reads one window before `bytes`: the file must be at least that long and
the line ending there must carry that hash (`check_head`: intact, missing,
shorter, changed). The agent's own repairs never cut below a head: a torn
last write is never a complete line, and the NN-AUD-110 tail repair only
cuts lines that fail their hash.

**Manifest checkpoint (rotating logs).** `ManifestEvent::ActiveCheckpoint
{seq, bytes, tail_hash}` in the log's signed manifest: the active file of
generation `seq` (the archive number it becomes when sealed) held a line
with `tail_hash` ending at `bytes`. Written every 1000 records, every 10
minutes while records arrive, and when the log opens a non-empty active
file it has not checkpointed yet. The manifest is created inside the `+i`
dance when missing.

**Head anchor.** `/etc/northnarrow/chain_heads.json`, next to the audit
log it anchors (write-denied like `audit.log`; an agent run with its own
audit log, as the privileged tests do, gets its own): a signed snapshot of the heads of every chain and every
rotating log's manifest, with each active file's generation, and the
sticky ATP-004 flag (a second admin key was added). Two fixed 8 KiB slots
written in turn (`counter % 2`) and fsynced: a write cut short leaves the
previous snapshot, and the file never grows. Signed over
`SHA-256(northnarrow/chain-heads/v1\0 ‖ snapshot)`. Written when the agent
starts (before it appends anything), every 5 minutes when a head moved,
and when it stops (after `agent_stop`). Each anchored head is also an INFO
line in the journal (`chain.head` target) for operators who forward the
journal off the host.

**Start record.** Once the first snapshot is on disk, the agent appends
`chain_numbering_started` to the audit chain: the head of every flat chain
at that point (the legacy rows) and the anchor's path. Its presence says
the anchor must exist.

## Consumers

- **Boot check** (`chain_anchor::boot_check`, before the attach, before any
  writer opens): every head of the last snapshot, the newest checkpoint of
  every rotating log, and a rotating log's active file missing after a
  recorded rotation. O(window) per file. Findings are signed
  `integrity_drift` entries (`chain_truncated`, `chain_rewritten`,
  `chain_missing`, `chain_archives_missing`, `active_file_missing`,
  `chain_heads_unverified`, then `chain_heads_missing` once the audit log
  says anchoring had started) and journal ERRORs. An audit chain shorter
  than its head, or an anchor replaced, resets the overlay rollback floor
  (LLMR-014: the rows that raised it may be gone); that, a removed anchor
  or a row-number break in the audit chain closes the one-key bootstrap
  (ATP-004: the rows may have held the second key's add).
- **Open of each chain.** `AuditLog::open` checks the row numbers of the
  whole file (no signature work; it already walked it). `Registry::open`
  verifies every row (hash, signature, link, number): a row that does not
  verify is not applied — an unsigned `Burn` no longer retires a canary —
  and the chain continues from the last genuine row.
  `CanaryAccessDb::open` verifies the last 256 rows. Findings:
  `chain_lines_unverified`, `chain_sequence_broken`.
- **Boot verification** (background, after the start): every rotating
  log's last 4 MiB (`verify_recent`: hash, signature, link), one signed
  `chain_verify` entry with the result, `chain_verify_failed` drift per
  failure.
- **Read path.** `nn-admin detections` serves only rows whose hash and
  signature verify; a row left out is an ERROR and a signed
  `chain_lines_unverified` (once per count per file).
- **Offline.** `nn-admin chain verify` checks every chain in full
  (`verify_log_set` with checkpoints and `ActiveMissing`, the flat chains
  with their numbers) and every head against the anchor; exit 8 on any
  problem. `nn-admin audit verify --expect-head <hash> --min-seq N` checks
  that the audit chain still reaches a head recorded elsewhere.

## Compatibility

- Existing chains open and verify unchanged; no migration, no rewrite.
  Numbering, domain tags, checkpoints and the anchor start at the first
  start of this version; the start record names the switch point.
- An older `nn-admin` cannot verify numbered rows (it drops `seq` when it
  re-serialises a row, so the hash no longer recomputes): use the
  `nn-admin` shipped with the agent. An older agent downgraded onto these
  files reads numbered rows but its NN-AUD-110 tail check refuses the new
  manifest rows: downgrades are not supported. The same holds for the v3
  lines of lab PR 204: an older `nn-admin` reports them as `entry_hash
  mismatch`, an older agent's tail check cuts up to 16 of them from an
  active file or manifest that ends in old-format lines.
- Cost at start: unchanged O(file) walk of `audit.log` and of the canary
  chains (as before), O(1) per head and checkpoint; signature work bounded
  (registry rows, 256 access rows, 4 MiB per rotating log in the
  background). Disk: 16 KiB for the anchor, one manifest row per checkpoint.

## Residual

- Between two anchors (5 minutes, or the last checkpoint) a cut is not
  found if the agent was killed rather than stopped (no stop snapshot).
- An attacker who can write the state files can put back an older genuine
  snapshot together with chains cut back to it, or roll everything back to
  before this version numbered anything; and the netflow listener log and
  the FIM baseline are not anchored yet. On the host that cannot be told
  from the real past: compare with the `chain.head` journal lines kept off
  the host (`audit verify --expect-head`). A key that never leaves a TPM
  and heads anchored off the host are the follow-up (at-authz-2).
- `fim report`, `net flows`, `canary list` serve rows without checking
  their signatures (`nn-admin chain verify` does).
