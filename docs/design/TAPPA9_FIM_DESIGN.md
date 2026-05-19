# Tappa 9 — File Integrity Monitoring (FIM) Design

**Status:** RFC / design only — no production code in this branch.
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-19.
**Prerequisite track:** Tappa 7 (anti-tamper LSM + watchdog) and
Tappa 8 (signed admin overrides + audit log) are SHIPPED. Tappa 9
builds on three Tappa-7/8 layers that already exist:
- The `inode_*` BPF-LSM hook framework (Tappa 7 task 5,
  `agent-ebpf/src/inode_protect.rs`) — Tappa 9 reuses the same
  attach + ringbuffer + denial-record primitives.
- The `PROTECTED_INODES` map (Tappa 7 task 5 + Tappa 8 A14) — Tappa
  9 introduces a parallel `WATCHED_PATHS` map for "observe-don't-
  deny" semantics.
- The Tappa 6 ADE + posture machine — Tappa 9 FIM events flow into
  the same `Event` channel the decision engine + ADE already
  consume.

This doc is reviewable as a PR. Implementation begins after owner
ruling on the open questions in §13.

---

## 1. Purpose & scope

**File Integrity Monitoring (FIM) is the customer-visible Phase 1
detection feature.** Existing competitors (Carbon Black, CrowdStrike
Falcon, SentinelOne, Wazuh) all ship FIM as a headline capability —
"tell me when /etc/passwd changes, alert on a new binary in
/usr/local/bin/, notify on `chmod 4755 /tmp/<file>`". NorthNarrow
must match this baseline to be a credible XDR competitor.

The Tappa 9 FIM scope:

1. **Hash-baseline a configured set of critical paths** at agent
   install + on operator demand, store SHA-256s in a tamper-evident
   on-disk DB (chained signed entries like the Tappa 8 audit log).
2. **Watch for drift** continuously via two complementary sensors:
   - **BPF-LSM** (`inode_setattr`, `inode_create`, `inode_unlink`,
     `inode_rename`, `inode_link`, `file_open` with write intent) —
     synchronous, kernel-side, sees every modification at the moment
     the syscall is dispatched.
   - **inotify** (userland, fallback for paths the LSM hook can't
     resolve — bind-mounted FUSE filesystems, etc.) — asynchronous,
     handles wildcard recursion.
3. **9 detection rules** (NN-L-FIM-001 through NN-L-FIM-009) that
   classify drift events into decision-engine verdicts: critical
   system-binary modification, new SUID binary, sensitive-config
   tampering, log truncation, etc.
4. **ADE handoff** — FIM events with `severity = Critical` route to
   the LLM second-brain for context-aware analysis; everything else
   stays in the deterministic-rule path.
5. **Operator CLI** — `nn-admin fim baseline`, `nn-admin fim status`,
   `nn-admin fim report` (the last is an audit-log-style chained
   export of every drift event since the last baseline).

### 1.1 Out of scope for Tappa 9

- **Real-time integrity attestation** (TPM-anchored boot-chain
  measurement) — Tappa 13 / 14 hardware-root-of-trust track.
- **Centralised baseline distribution** (operator pushes a baseline
  from a backend to N agents) — Tappa 11 backend-SaaS feature.
- **Diff display in the CLI** (`nn-admin fim diff <path>` showing
  the actual byte-level change) — V1.1 ergonomic; the V1.0 surface
  reports "path P at hash H1 changed to H2 at time T by uid U pid
  P comm C".
- **Recursive baseline of /home/** or other large/volatile trees —
  the V1.0 watched-paths list is curated to ~100 paths (system
  binaries + critical configs + log roots). Wildcard recursive
  scanning is V1.1.

### 1.2 Threat model

The attacker is root on the host, has bypassed Tappa 7's anti-tamper
LSM (somehow — assume best case for them), and modifies files to:

- Install a backdoor (drop a new binary in `/usr/local/bin/`, add
  an authorized_key to `/root/.ssh/authorized_keys`).
- Tamper with a daemon binary (overwrite `/usr/sbin/sshd` with a
  trojan that exfiltrates credentials).
- Cover tracks (truncate `/var/log/auth.log`).
- Escalate latently (drop a SUID-root binary in `/tmp/`).

Tappa 9 FIM does NOT prevent the modification (Tappa 7 task 5 is the
prevention layer for the few paths under `PROTECTED_INODES`). FIM
*detects* the modification, classifies its severity, and surfaces it
to the operator + ADE within seconds.

The FIM baseline DB itself is protected by Tappa 8 A14 (LSM-extended
`/etc/northnarrow/`) — see §6.4.

---

## 2. Current state inventory (IMPLEMENTED vs TODO)

### 2.1 IMPLEMENTED

- BPF-LSM `inode_*` hook framework (`agent-ebpf/src/inode_protect.rs`,
  Tappa 7 task 5) — Tappa 9 attaches additional read-only observation
  programs to the same hook points without touching the existing
  deny-on-`PROTECTED_INODES` logic.
- `PROTECTED_INODES` map + caller-side PROTECTED_PIDS exemption
  (Tappa 7 task 5 + Tappa 8 A14 / PHASE_D_002) — Tappa 9's
  `WATCHED_PATHS` map mirrors the layout exactly.
- `FsProtectDenialRaw` ringbuffer + `FS_PROTECT_EVENTS` map —
  Tappa 9 introduces `FimDriftRaw` + `FS_FIM_EVENTS` for drift
  events.
- Posture machine + `Event::Fim` channel — the decision engine
  consumes Tappa 9 events the same way it consumes Tappa 1 sensor
  events.
- Tappa 8 B1 audit log primitives (`agent/src/audit.rs`) — Tappa 9's
  baseline + drift report DB reuses the SHA-256 chain + per-entry
  Ed25519 signature primitives without duplicating them.

### 2.2 TODO (gaps this design addresses)

- **No baseline DB.** No on-disk hash baseline for any path.
- **No drift detection.** `inode_setattr` / `inode_create` /
  `inode_unlink` fire on PROTECTED_INODES targets only; everything
  else passes through unobserved.
- **No FIM CLI surface.** `nn-admin` has no `fim` subcommand.
- **No FIM rules.** The decision engine has 12 rules
  (`R001_..R012_`); none cover file-drift events.

### 2.3 Test surface that already exists

- `agent-ebpf/src/inode_protect.rs::tests` — pointer-chase helpers
  + deny-decision unit tests. Tappa 9 will add parallel
  observation-decision tests.
- `agent/src/anti_tamper/filesystem.rs::tests` — userland inode
  registration tests. Tappa 9 will mirror the pattern for
  WATCHED_PATHS.
- `agent/src/audit.rs::tests` — hash chain + per-entry signature
  primitives. Tappa 9's baseline DB tests will exercise the same
  primitives.
- `agent/tests/privileged_e2e.rs` — the R009-aware
  `install_to_priv_bin` pattern (PHASE_D_003) is reusable for FIM
  privileged tests.

---

## 3. Architecture

```text
                  ┌─────────────────────────────────┐
                  │  Operator workstation           │
                  │  (nn-admin fim {baseline|       │
                  │            status|report})      │
                  └──────────────┬──────────────────┘
                                 │  Unix socket
                                 │  (signed AdminMessage, Tappa 8)
                  ┌──────────────▼──────────────────┐
                  │  agent/src/admin_socket.rs      │
                  │  + dispatch_fim_baseline/etc.   │
                  └──────┬──────────────┬───────────┘
                         │              │
        ┌────────────────▼──┐  ┌────────▼──────────┐
        │ agent/src/fim/    │  │ agent/src/audit.rs│
        │ baseline.rs       │  │ (Tappa 8 B1)      │
        │   compute()       │  │                   │
        │   load()/save()   │  │ Reused for the    │
        │   verify()        │  │ baseline DB +     │
        └────────┬──────────┘  │ drift report.     │
                 │             └───────────────────┘
                 │ writes
                 ▼
        ┌───────────────────────┐
        │ /var/lib/northnarrow/ │
        │   fim_baseline.jsonl  │  ← Tappa 7 LSM-protected
        │   fim_drift.jsonl     │  ← Tappa 7 LSM-protected
        └───────────────────────┘
                 ▲
                 │ append-on-drift
                 │
        ┌────────┴──────────┐
        │ agent/src/fim/    │   Drains FS_FIM_EVENTS ringbuf →
        │ drain.rs          │   constructs FimEvent →
        │   drain_loop()    │   resolves path via i_dentry →
        └────────┬──────────┘   re-hashes target →
                 │               compares against baseline →
                 ▼               emits Event::Fim
        ┌───────────────────┐
        │ Decision engine   │
        │ (Tappa 2 rules    │   NN-L-FIM-001..009 classifications.
        │  + ADE for crit.) │   Posture transitions on Critical.
        └───────────────────┘

   ┌──────────────────────────────────────────────────┐
   │ Kernel BPF programs (agent-ebpf/src/fim_watch.rs)│
   │                                                  │
   │  inode_setattr_observe → if WATCHED_PATHS hit, emit
   │  inode_create_observe  → on-create event into
   │  inode_unlink_observe  → FS_FIM_EVENTS ringbuf
   │  inode_rename_observe  │
   │  inode_link_observe    │
   │  file_open_observe     → only when O_WRONLY|O_RDWR|O_TRUNC
   │                                                  │
   │  Maps: WATCHED_PATHS (HashMap<InodeKey, u8>),    │
   │        FS_FIM_EVENTS (RingBuf, 256 KiB).         │
   │                                                  │
   │  Observation-only — NEVER returns -EPERM. Existing
   │  deny-on-PROTECTED_INODES logic stays untouched. │
   └──────────────────────────────────────────────────┘
```

Tappa 9 introduces a **second class** of file-watching: deny-based
(Tappa 7 task 5 `PROTECTED_INODES`) and **observe-based** (Tappa 9
`WATCHED_PATHS`). The two maps are distinct; a path can be in one,
both, or neither.

---

## 4. Data model

### 4.1 `FimEvent` (userland decoded shape, common::wire)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimEvent {
    /// Monotonic-clock ns since boot — same source as the existing
    /// `ProcessSpawn.timestamp_ns` field.
    pub timestamp_ns: u64,
    /// The watched path that drifted. UTF-8 lossy — non-UTF-8
    /// paths get a `\xNN` escaped representation rather than
    /// being dropped.
    pub path: String,
    /// What the kernel observed.
    pub op: FimOp,
    /// The (re-hashed) SHA-256 of the file's content AFTER the
    /// modification. `None` for unlink/rename events where the
    /// post-modification target is gone.
    pub new_sha256: Option<[u8; 32]>,
    /// The baseline SHA-256 the drift event diverged from.
    /// `None` if the path was just added to the watch set and no
    /// baseline exists yet (operator forgot to re-baseline).
    pub baseline_sha256: Option<[u8; 32]>,
    /// `/proc/<pid>/exe` of the modifying process, if resolvable.
    pub modifier_exe: Option<String>,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FimOp {
    Modified,    // setattr or write-then-close
    Created,     // new file in a watched dir
    Deleted,     // unlink
    Renamed,     // rename (the path SIDE of the watched set that moved)
    Linked,      // hardlink (rare but a known evasion technique)
}
```

### 4.2 `BaselineEntry` (on-disk JSONL row)

Persisted to `/var/lib/northnarrow/fim_baseline.jsonl` (Tappa 7
LSM-protected). Same hash-chain + signature shape as the Tappa 8
audit log so verification reuses `audit::verify_chain` logic.

```json
{
  "ts": "2026-05-19T08:14:02.123456Z",
  "path": "/usr/bin/sshd",
  "sha256": "e3b0...",
  "mode": "0o755",
  "uid": 0,
  "gid": 0,
  "size_bytes": 980728,
  "agent_id": "1f8a...",
  "prev_hash": "abc...",
  "entry_hash": "def...",
  "agent_sig": "..."
}
```

### 4.3 `RuleMatch` (decision-engine verdict)

The decision engine's existing `VerdictRecord` shape (Tappa 2) is
sufficient; a FIM rule produces a `VerdictRecord` with
`evidence_source = "fim"` and the original `FimEvent` carried in
the `evidence_json` field.

---

## 5. LSM hook integration

### 5.1 Programs

Six new BPF-LSM programs in `agent-ebpf/src/fim_watch.rs`,
attached to the same kernel hooks the deny programs use. Distinct
program names so verifier-side conflict is impossible:

| Program | Hook | Trigger |
|---|---|---|
| `fim_setattr_observe` | `inode_setattr` | chmod, chown, truncate |
| `fim_create_observe` | `inode_create` | new file in watched dir |
| `fim_unlink_observe` | `inode_unlink` | rm |
| `fim_rename_observe` | `inode_rename` | mv |
| `fim_link_observe` | `inode_link` | ln (hardlink) |
| `fim_file_open_observe` | `file_open` | write-intent open |

Each program:
1. Resolves target inode (same `inode_from_dentry` helper as Tappa 7
   task 5).
2. Looks up `(dev, ino)` in `WATCHED_PATHS` — fast return 0 on miss.
3. Reserves a `FimDriftRaw` slot in `FS_FIM_EVENTS` ringbuf.
4. Populates: timestamp_ns, op, target (dev, ino), modifier (pid,
   uid, comm).
5. Submits + returns 0 (never -EPERM — observation only).

### 5.2 Resource budget

- `WATCHED_PATHS` capacity: 4096 entries (well above the 100-path
  V1.0 baseline; headroom for future operator expansion).
- `FS_FIM_EVENTS` ringbuf: 256 KiB (~3600 events at 72 B each).
  Higher than Tappa 7 task 5's deny ringbuf because drift events
  are bursty (a yum/apt upgrade can generate dozens in a second).
- Per-program verifier complexity: ~50 instructions each
  (lookup + reserve + memcpy + submit). Well under aya 0.13's
  1M instruction limit.

---

## 6. Userland: baseline + drain + emit

### 6.1 Baseline computation

`agent/src/fim/baseline.rs::compute_baseline(paths) -> Vec<BaselineEntry>`:
walks each path, computes SHA-256, captures mode + uid + gid +
size. Symlinks resolved (we baseline the *target*; rebaselining the
symlink itself is a separate operator decision).

Computation is parallel (rayon par_iter over paths) — a 100-path
baseline takes ~200 ms cold-cache on an SSD.

### 6.2 Baseline storage

JSONL at `/var/lib/northnarrow/fim_baseline.jsonl`. New entries
APPENDED; rebaselining a single path appends a new entry with the
new SHA, the old entry stays as audit history. Chain integrity:
same `prev_hash` / `entry_hash` / `agent_sig` triple as Tappa 8 B1
audit log.

Loading at agent startup: read whole file, take the LAST entry per
path as the "current baseline" for that path. Older entries are
historical (visible in `nn-admin fim report --history <path>`).

### 6.3 Drift drain loop

`agent/src/fim/drain.rs::drain_loop(ringbuf, baseline_db, event_tx)`:
- Tokio task on the agent's main runtime.
- Drains `FS_FIM_EVENTS` via aya's `RingBuf::poll`.
- For each `FimDriftRaw`:
  - Resolve `(dev, ino)` → absolute path via the userland inode→path
    map built at baseline time (no kernel-side path resolution).
  - Re-hash the file from userland (for `Modified` op).
  - Compare against baseline; emit `Event::Fim(FimEvent)` only if
    the SHA actually differs (the kernel hook fires on every
    setattr, including no-op `touch -t`).
- Append a `FimDriftEntry` to `/var/lib/northnarrow/fim_drift.jsonl`
  with chain integrity (Tappa 8 B1 primitives).

### 6.4 Storage protection

Two new files join the Tappa 8 A14 `ETC_PROTECTED_FILES` analogue
under `/var/lib/northnarrow/`:

- `fim_baseline.jsonl`
- `fim_drift.jsonl`

Same LSM caller-side exemption (PROTECTED_PIDS) means the agent can
append while every other root caller is denied.

---

## 7. Detection rules — NN-L-FIM-001 through NN-L-FIM-009

Port reference: the old-repo commit `62c5331` implemented Phase-1 FIM
detection in the pre-NorthNarrow codebase under different rule IDs
(`F001..F009`). Tappa 9 renames to the `NN-L-FIM-NNN` scheme
consistent with the existing `R001_..R012_` rule namespace.

| ID | Title | FimOp | Severity | Action |
|---|---|---|---|---|
| **NN-L-FIM-001** | System binary modified | Modified | Critical | KillProcessTree (modifier) + posture→COMBAT |
| **NN-L-FIM-002** | New SUID-root binary appeared | Created+Linked | Critical | KillProcessTree (modifier) + posture→COMBAT |
| **NN-L-FIM-003** | Sensitive config modified (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`) | Modified | High | KillProcess (modifier) + posture→ENGAGED |
| **NN-L-FIM-004** | `authorized_keys` modified | Modified | High | KillProcess + posture→ENGAGED |
| **NN-L-FIM-005** | Log file truncated (size went DOWN) | Modified | High | posture→ENGAGED + log-only (don't kill — operators do truncate logs intentionally) |
| **NN-L-FIM-006** | Binary in `/usr/local/bin/`, `/opt/` modified | Modified | Medium | posture→ALERTED |
| **NN-L-FIM-007** | cron drop-in created (`/etc/cron.d/*`, `/var/spool/cron/*`) | Created | High | KillProcess + posture→ENGAGED |
| **NN-L-FIM-008** | Kernel module file modified (`/lib/modules/*`) | Modified | Critical | KillProcessTree + posture→COMBAT |
| **NN-L-FIM-009** | `systemd` unit file dropped or modified (`/etc/systemd/system/*`, `/lib/systemd/system/*`) | Created+Modified | High | KillProcess + posture→ENGAGED |

Each rule has the same structure as the existing `R001_..R012_`
rules: a `match_event(&Event) -> Option<VerdictRecord>` method that
inspects `Event::Fim(FimEvent)`, checks the path against the rule's
allow/deny set, and returns a `VerdictRecord` carrying the
severity + action + reasoning string.

---

## 8. ADE handoff

`severity = Critical` FIM events route to the LLM second-brain per
the existing Tappa 6 ADE pipeline. The ADE prompt template gets a
new `fim_event` field carrying the `FimEvent` JSON; the LLM is
asked to:

- Cross-reference recent process activity (was this part of a known
  package upgrade?).
- Cross-reference recent network activity (did the modifier
  egress before the modification?).
- Recommend posture (defer to deterministic rule's recommendation
  unless explicit override with rationale).

`severity = High` / `Medium` events stay in the deterministic-rule
path — same gate the rest of Tappa 6 uses to avoid LLM cost on
low-severity events.

---

## 9. Wire protocol

NO new `AdminMessage` variants. FIM operations use the existing
signed-payload + role-allowlist machinery from Tappa 8:

- New `OperationCode::FimBaseline = 7`.
- New `OperationCode::FimReport = 8`.
- New `Role::FimManage = 6` (for `fim baseline` / `fim
  rebaseline-path`).
- New `Role::FimRead = 7` (for `fim status` / `fim report`;
  defaults to operators with `audit-read` since FIM read is the
  same trust level).

The `nn-admin fim` CLI flows mirror `nn-admin audit` exactly:
challenge → SignedPayload → submit → reply. No transport changes.

---

## 10. Systemd / deploy

No new systemd units. The FIM drain loop runs inside the agent's
existing tokio runtime (one new `tokio::spawn` in `main.rs`,
spawned post-attach alongside the existing sensor pumps).

Install changes: `deploy/install.sh` adds two empty bootstrap
files at install time (`/var/lib/northnarrow/fim_baseline.jsonl`,
`/var/lib/northnarrow/fim_drift.jsonl`, mode 0644) so the LSM
inode registration finds something to register at first agent
boot. Same pattern as Tappa 8 B4's `bootstrap_audit_log`.

The default V1.0 watched-paths list is committed in
`configs/fim-paths.v1` — a YAML list of ~100 paths the agent reads
at boot and registers into `WATCHED_PATHS`. Operators override via
`/etc/northnarrow/fim-paths.local` (additive — never narrows the
default list).

---

## 11. Testing strategy

### 11.1 Unit tests

- `agent-ebpf/src/fim_watch.rs::tests` — hook-decision unit tests:
  given a synthetic `(dev, ino)` + WATCHED_PATHS state, assert
  emit/skip decision matches the rule (~15 tests).
- `agent/src/fim/baseline.rs::tests` — SHA-256 computation +
  file-stat capture + JSONL round-trip + chain integrity
  (~10 tests).
- `agent/src/fim/drain.rs::tests` — event decode + path resolution
  + baseline diff + Event::Fim emission (~8 tests).
- `agent/src/decision/rules/fim.rs::tests` — one positive + one
  negative test per rule, plus a path-allowlist edge case
  (~20 tests total: 9 rules × 2 + edges).

### 11.2 Privileged e2e

Three privileged tests reusing the PHASE_D_003 `install_to_priv_bin`
pattern + the `--fim-baseline-file` / `--fim-drift-file` CLI flags
(introduced alongside the test-privileged hooks):

1. `fim_baseline_round_trip` — `nn-admin fim baseline` of a
   curated tempdir; verify `fim_baseline.jsonl` has the expected
   chained entries.
2. `fim_drift_detection_e2e` — baseline a tempdir, modify a
   tracked file, observe the drift event lands in `fim_drift.jsonl`
   AND the corresponding `Event::Fim` is observed by the decision
   engine (instrumented via a test-only channel tap).
3. `fim_report_signed_export` — drive 3-4 mixed FIM events, then
   `nn-admin fim report --since <ts>` returns a signed JSONL chain
   that `audit verify` (extended to recognize FIM rows) accepts.

---

## 12. Effort estimate — commit-by-commit plan

Numbered against the §2.1/§2.2 inventory. Re-uses existing
`agent-ebpf`, `agent/src/audit.rs`, `agent/src/admin_socket.rs`
infrastructure. Estimated commit-by-commit; total ~35–45 hours.

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **C1** | `feat(common): FimEvent + FimOp + FimDriftRaw wire types + Role::FimManage / FimRead + OperationCode::FimBaseline / FimReport` | New wire types + role/op-code additions. Tests: 6 (round-trip + variant ordering + role parse). | 3 |
| **C2** | `feat(agent-ebpf): WATCHED_PATHS map + 6 fim_*_observe LSM programs + FS_FIM_EVENTS ringbuf` | New BPF programs alongside Tappa 7 task 5's deny ones. Observation-only — never -EPERM. Verifier complexity audit. Tests: 8 (decision tests + verifier-passes assertion). | 6 |
| **C3** | `feat(agent): fim/baseline.rs — compute + persist + chained on-disk DB` | SHA-256 baseline + JSONL writer reusing audit.rs primitives. Tests: 10. | 5 |
| **C4** | `feat(agent): fim/drain.rs — RingBuf drain + path-resolve + baseline diff + Event::Fim emit` | Tokio task drains FS_FIM_EVENTS, resolves (dev,ino)→path, re-hashes, diffs, emits. Tests: 8. | 4 |
| **C5** | `feat(decision): 9 fim rules NN-L-FIM-001..009 + path-allowlist parser + posture transitions` | One rule per system-binary / SUID / config / log / cron / kmod / systemd category. Tests: 20 (per-rule + edges). | 6 |
| **C6** | `feat(admin_cli): nn-admin fim baseline / status / report subcommands + signed-payload wiring + audit emission` | CLI surface + dispatch_fim_baseline / dispatch_fim_report. Mirrors A12 audit CLI pattern. Tests: 10. | 5 |
| **C7** | `feat(deploy): default fim-paths.v1 + install.sh bootstrap + LSM widening of fim_baseline.jsonl + fim_drift.jsonl` | ~100-path V1.0 list + install.sh changes + ETC_PROTECTED_FILES analogue. Tests: 4. | 3 |
| **C8** | `test(privileged_e2e): fim baseline round-trip + drift detection + signed report export` | New `agent/tests/fim_privileged_e2e.rs` file. Reuses PHASE_D_003 install_to_priv_bin pattern. Tests: 3 privileged. | 4 |
| **C9** *(optional)* | `feat(ade): FimEvent ADE prompt template + cross-reference with recent process/network activity` | Tappa 6 ADE integration for `Critical` FIM events. Tests: 4. | 4 |
| | **TOTAL** | | **~35–45 hours** ≈ 1.5 working weeks with CC pair-programming (C9 optional pushes to upper end). |

Phase-1 ships at C8 (CLI + detection + audit-grade reporting).
C9 is the ADE enrichment that elevates Tappa 9 from "FIM
parity with competitors" to "FIM with LLM context that they
don't have" — a Tappa 10+ differentiator the design positions
for but doesn't strictly require for the customer-visible
feature.

---

## 13. RFC items / open questions for owner ruling

1. **Q1 — Symlink baseline policy.** Baseline the target (current
   recommendation) OR the link itself OR both? Targeting follows
   the principle of least surprise (a `cp -L`-style operator
   mental model) but means a malicious target-swap on a symlinked
   binary path goes undetected until the next baseline. Owner
   preference?
2. **Q2 — Hardlink detection semantics.** A new hardlink to a
   watched file doesn't change the watched inode's content — it
   just creates a SECOND path pointing at the same data. Should
   NN-L-FIM-002 flag this as "new SUID binary appeared" if the
   new link is a SUID-root file? Recommendation: yes, surface via
   `fim_link_observe`; rule decides.
3. **Q3 — Recursive watch directories.** A naive recursive watch of
   `/usr/bin/` would register ~3000 inodes — well under the 4096
   `WATCHED_PATHS` capacity but still chatty. V1.0 ships a curated
   ~100-path list (system binaries by-name + critical configs).
   V1.1 could add wildcard recursion under operator opt-in. Owner
   ruling: confirm the V1.0 curated approach.
4. **Q4 — Drift event rate-limiting.** A `yum upgrade` can drift
   dozens of paths in a few seconds. Should the drain emit one
   `Event::Fim` per drift (current spec) OR batch into one event
   per N drifts within a sliding window? Recommendation:
   per-drift (simplest semantics; the decision engine + ADE batch
   already if they're slow consumers).
5. **Q5 — Baseline-on-install vs first-boot.** Should
   `deploy/install.sh` compute the initial baseline (operator gets
   a populated DB on first agent run) OR should the agent's first
   boot compute it (faster install, slower first-boot)? Tradeoff:
   install.sh would need to ship the SHA-256 helper without the
   agent binary AND would block the install on a 200ms walk.
   Recommendation: first-boot, log "computing initial baseline
   (one-time, ~200ms)" so operators know what they're seeing.
6. **Q6 — Drift report quorum.** Should `nn-admin fim report
   --acknowledge` (mark drift events as operator-acknowledged in
   the DB) require a quorum like `shutdown`? Recommendation: no
   — acknowledgement is an operator-UX hint, not an authorisation
   gate; single-sig with the `fim-manage` role.
7. **Q7 — fim-paths.local conflict resolution.** Default
   `fim-paths.v1` ships with the V1.0 curated list. Operator
   override at `/etc/northnarrow/fim-paths.local` is ADDITIVE
   only (the design line) — what if the operator wants to REMOVE a
   default path (e.g., `/usr/sbin/sshd` because they don't run
   sshd)? Recommendation: V1.0 keeps additive-only; V1.1
   introduces a `disable:` list in the local file.
8. **Q8 — Baseline rotation / pruning policy.** `fim_baseline.jsonl`
   grows monotonically. After 5 years of yearly OS upgrades a
   single agent could have ~500 entries per watched binary
   (multiple rebaselines on each upgrade). When/how to prune?
   Recommendation: V1.0 keeps the full chain (audit value);
   V1.1 introduces a signed `fim-rotate` op that exports +
   truncates with chain-of-chains continuation (same shape as
   audit-rotate in Tappa 8's §14 Q9).
9. **Q9 — ADE prompt cost ceiling.** Critical FIM events route to
   ADE (§8). One LLM call per critical event could be costly under
   an active intrusion. Cap at N calls per minute? Recommendation:
   cap at 10/min via the existing ADE rate-limit knob; events
   beyond the cap are still emitted to the deterministic-rule path
   (which already fires the kill + posture transition).
10. **Q10 — Tappa-13 backend mirror.** Should the agent stream
    `fim_drift.jsonl` appends to the backend in addition to the
    local file (parallel to Tappa 8 §14 Q10's audit-log mirror)?
    Tappa-13 design concern; deferred. Local file + signed
    `nn-admin fim report --json` export is V1.0.

---

## Appendix A — Cross-references

- Tappa 7 task 5 design — `agent-ebpf/src/inode_protect.rs` (the
  prior-art for `inode_*` hook attach + ringbuf events).
- Tappa 8 §9 (audit log) — `agent/src/audit.rs` chain primitives
  Tappa 9 baseline DB reuses.
- Tappa 6 ADE design (`docs/design/TAPPA6_ADE_*.md`) — the LLM
  prompt envelope Tappa 9 extends with `fim_event`.
- PHASE_D_003 — `agent/tests/privileged_e2e.rs` `install_to_priv_bin`
  pattern Tappa 9's privileged tests reuse.
- Old-repo commit `62c5331` — Phase-1 FIM detection rules in the
  pre-NorthNarrow codebase; Tappa 9 NN-L-FIM-001..009 are the
  renamed + refined ports.

## Appendix B — Threat-model recap

| Attack | Detection layer |
|---|---|
| Drop a backdoor binary in `/usr/local/bin/` | NN-L-FIM-002 (SUID) or NN-L-FIM-006 (Medium) — depending on mode |
| Trojan `/usr/sbin/sshd` | NN-L-FIM-001 (system binary modified, Critical) |
| Add a key to `~root/.ssh/authorized_keys` | NN-L-FIM-004 (authorized_keys modified, High) |
| `truncate /var/log/auth.log` to cover tracks | NN-L-FIM-005 (log truncation, High — log-only since legit too) |
| Drop a malicious `/etc/cron.d/<name>` | NN-L-FIM-007 (cron drop-in, High) |
| Load a malicious kernel module | NN-L-FIM-008 (kernel module file modified, Critical) |
| Drop a malicious systemd unit | NN-L-FIM-009 (systemd unit dropped, High) |
| Symlink swap on a watched binary | Detected at next baseline; NOT real-time per Q1 |
| Hardlink a SUID-root binary into a watched dir | NN-L-FIM-002 if Q2 = yes |

Every attack in the table is detected within seconds of the file
operation completing, with `severity = High` or `Critical` events
routing to ADE for contextual analysis. The agent's deterministic
rule fires the kill + posture transition regardless of ADE
verdict — the LLM is enrichment, not a gate.
