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
  "is_symlink": false,
  "agent_id": "1f8a...",
  "prev_hash": "abc...",
  "entry_hash": "def...",
  "agent_sig": "..."
}
```

**Q1 resolution — `is_symlink: bool` field (NEW, `#[serde(default)]`
for forward-compat).** When a watched path is itself a symlink, the
baseline computer emits **TWO** `BaselineEntry` rows:

- One with `is_symlink: true`, whose `sha256` is the SHA-256 of the
  target *string* (the bytes `readlink(2)` returns) concatenated
  with the `lstat` metadata struct. Catches "symlink target swap"
  attacks where the attacker changes where the link points.
- One with `is_symlink: false`, whose `sha256` is the SHA-256 of
  the resolved target *content*. Catches "modify the file the
  symlink resolves to" attacks.

Auto-resolution depth is **capped at 1 hop** — if a watched symlink
points at another symlink, only the immediate target is auto-added;
deeper rebinds (e.g., Debian's `/etc/alternatives/*` chain) rely on
the target's normal watch entry firing NN-L-FIM-001 if it's also
in the watched-paths list.

The `#[serde(default)]` attribute means pre-resolution
`fim_baseline.jsonl` rows lacking the field deserialise to
`is_symlink: false` automatically — V1.0 ships the field, but
upgrades from a hypothetical pre-resolution chain stay verifiable.

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

- `WATCHED_PATHS` capacity: **8192 entries** (bumped from the
  initial 4096 estimate per Q1 + Q3 + Q7 resolutions —
  ~100 curated base + ~10 Q1 symlink-target rows + headroom
  for Q7's per-deployment `add:` lists + Q3's V1.1 recursive
  watch opt-in).
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

### 6.5 Drift rate-limiting (Q4 resolution)

Storm protection between the drain loop's `Event::Fim` emit
and the decision engine, implemented as a **hierarchical
token-bucket per rule**:

| Severity tier | Default rate | Configurable |
|---|---|---|
| Critical | **NO LIMIT** | No — tampering with the cap itself would defeat the protection |
| High | 50 events / minute / rule | Yes (`fim.rate_limit.high_per_min` in `/etc/northnarrow/config.toml`) |
| Medium | 100 events / minute / rule | Yes (`fim.rate_limit.medium_per_min`) |

When a rule's bucket is exhausted, the drain loop:

1. **Always appends the `FimDriftEntry` to `fim_drift.jsonl`** —
   evidence preservation is non-negotiable. The chain captures
   every kernel-observed drift regardless of bucket state.
2. **Sets `decision_engine_skipped: true`** on the persisted
   entry. NEW schema field, `#[serde(default)]` for forward-
   compat (older rows deserialise to `false` automatically).
3. **Skips the `Event::Fim` emission** to the decision engine
   for the suppressed event.
4. **Logs once per bucket-exhaustion window**:
   `WARN fim: drift rate-limit hit (M events suppressed for
   rule R, window resets at T)`.

`nn-admin fim status` surfaces the current bucket state
(`<rule>: 47/50 tokens remaining, window resets in 23s`) so
operators can see throttling as it happens.

**Rationale for per-rule buckets:** a yum-upgrade flood of
Medium-severity drift on `/usr/local/bin/` should NOT starve
Critical-severity tokens for `/usr/sbin/sshd`. Per-rule
isolation means an attacker can't exhaust the Critical bucket
by flooding low-severity paths.

**Rationale for Critical-uncapped:** every Critical event is
either a documented evasion technique (Q2 hardlink-create on
SUID) or a system-binary tamper. Throttling them would defeat
the security property they're enforcing. Acceptable because
the *deterministic* rule path (kill + posture transition) is
also untouched — even if ADE batching (Q9) kicks in, the
agent still fires the local response.

`FimDriftEntry` schema addition:

```json
{
  // ... existing fields per §4.1 + chain integrity ...
  "decision_engine_skipped": false,  // NEW, Q4 resolution
  "skip_reason": null                 // NEW; populated to
                                      // "rate_limit:rule_<R>"
                                      // when skipped=true
}
```

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

**Cross-cutting rule note (Q2 + Q4 lock-in):** every `Critical`-
severity rule above is **never throttled by §6.5's drift rate
limiter**. NN-L-FIM-001, NN-L-FIM-002, and NN-L-FIM-008 fire on
every kernel-observed event regardless of bucket state — the
events they catch (system-binary tamper, SUID-hardlink-evasion,
kernel module modification) are documented evasion techniques and
must not be suppressible. High / Medium tiers DO honour their
buckets per §6.5.

**NN-L-FIM-002 hardlink semantics (Q2 resolution):** the rule
fires on EITHER `Created` op (new file with SUID bit) OR `Linked`
op (new hardlink to an existing SUID-root inode). For the
hardlink case the *new link path* is what matters — Critical
severity when that path is under `/tmp/*`, `/var/tmp/*`,
`/dev/shm/*`, or `/home/*` (user-writable directories). Callers
in `PROTECTED_PIDS` are exempted (PHASE_D_002 caller-side
pattern); operator-tunable allowlist of package-manager
basenames (`dpkg`, `rpm`, `docker`) skips legitimate hardlink
workflows.

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

### 8.1 ADE prompt cost ceiling (Q9 resolution) — TIERED CAP

Production LLM budget protection without sacrificing signal
density during multi-event incidents. **Two-tier cap:**

- **10 individual ADE prompts / minute** — one per Critical
  `FimEvent` until the cap. Each prompt carries the full event
  context for fine-grained LLM analysis.
- **1 batched overflow prompt / minute** — fired when the
  individual cap is exhausted. Carries the full list of
  suppressed `FimEvent` JSON objects in a single prompt context
  so the LLM still sees signal density without N separate API
  calls. Upper bound: **11 ADE calls / minute** total.

The DETERMINISTIC rule path (kill + posture transition) is
**never throttled by the ADE cap** — it fires on every Critical
event regardless of whether ADE saw the event individually or
in the batch. ADE is enrichment, not a gate.

`fim.ade.individual_cap_per_min` (default 10) and
`fim.ade.batched_overflow_per_min` (default 1) are runtime-
tuneable in `/etc/northnarrow/config.toml`. Setting overflow to
0 disables the batched tier — useful for cost-sensitive
deployments that prefer the simple cap.

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

## 13. RFC resolutions

All 10 RFC items resolved 2026-05-19 (owner-accepted engineering
recommendations). C1 implementation now unblocked. Each block
below: **Decision**, **Rationale**, **Implementation note**
(where in this doc / commit plan the decision manifests),
**Reversibility cost**.

### Q1 — Symlink baseline policy

- **Decision:** baseline BOTH the symlink (its target string +
  lstat metadata) AND auto-resolve to baseline the resolved
  target's content as a SECOND entry. Auto-resolution depth
  capped at 1 hop.
- **Rationale:** security-deep question; coverage > operator
  surprise. Cost is small (~10 extra rows for symlinks in the
  V1.0 curated list). One operator decision (path in
  fim-paths) → both attack vectors covered without operator
  having to think.
- **Implementation note:** §4.2 `BaselineEntry.is_symlink: bool`
  schema field (`#[serde(default)]` for forward-compat) +
  C3 `baseline.rs` emits two entries per symlinked watched path.
- **Reversibility:** medium — schema field commits to disk;
  flipping policy means an operator-driven rebaseline pass.
  Acceptable because the field is additive from day one.

### Q2 — Hardlink detection semantics

- **Decision:** YES — NN-L-FIM-002 fires on hardlink creation
  when the new link points at a SUID-root file from a user-
  writable directory (`/tmp/*`, `/var/tmp/*`, `/dev/shm/*`,
  `/home/*`). Surfaced via `fim_link_observe`; rule decides
  based on the new link path (not the source path).
- **Rationale:** documented evasion technique. Cost is one extra
  rule check per hardlink syscall — negligible. Caller
  exemption via `PROTECTED_PIDS` + operator-tunable package-
  manager allowlist (`dpkg`, `rpm`, `docker`) handles
  legitimate workflows.
- **Implementation note:** §7 rule-table footer + C2
  `fim_link_observe` BPF program + C5 NN-L-FIM-002 rule logic.
- **Reversibility:** easy (rule logic only; no schema or wire
  impact).

### Q3 — Recursive watch directories

- **Decision:** CONFIRM V1.0 CURATED ~100-path list. V1.1 adds
  recursive opt-in via `recurse: true` in `fim-paths.local`
  per-entry. `WATCHED_PATHS` map capacity bumped from 4096 →
  **8192** in V1.0 (cheap insurance for Q1 + Q7 cross-cutting
  additions).
- **Rationale:** perf-coverage tradeoff weighs toward
  predictability. A `yum upgrade` of `glibc` generates ~5-10
  drift events with the curated list vs ~50-100 with
  recursive `/usr/bin/`. The 10× difference matters during
  active-intrusion conditions when every other system is
  noisy.
- **Implementation note:** §5.2 capacity bump + C7
  `fim-paths.v1` ships the curated list; V1.1 adds the
  recursion logic to C2's WATCHED_PATHS populator.
- **Reversibility:** easy (no schema change; V1.1 recursion
  only adds the populator logic).

### Q4 — Drift event rate-limiting

- **Decision:** PER-DRIFT to audit chain (always — evidence
  preservation is non-negotiable) + HIERARCHICAL TOKEN-BUCKET
  per rule on `Event::Fim` emission to the decision engine.
  Defaults: 100/min Medium, 50/min High, **NO LIMIT
  Critical**. Suppressed events get
  `decision_engine_skipped: true` on the persisted entry.
- **Rationale:** most consequential rate-limit decision —
  needs to protect the decision pipeline from upgrade noise
  WITHOUT giving an attacker a suppression window for
  Critical events. Per-rule buckets prevent low-severity
  flooding from starving Critical tokens. Mirrors Tappa 7
  task_kill's 5-in-60s tamper ceiling pattern.
- **Implementation note:** §6.5 NEW subsection + §7 rule-
  table footer (Critical-uncapped lock-in) + C4 drain loop
  implements the bucket between diff and emit; C5 rules
  declare their severity tier so the bucket allocator knows
  which to pick.
- **Reversibility:** medium — `decision_engine_skipped: true`
  schema field commits to disk; bucket parameters are
  runtime-tuneable. Schema additive from day one.

### Q5 — Baseline-on-install vs first-boot

- **Decision:** FIRST-BOOT baseline. Document the TOFU (trust-
  on-first-use) assumption explicitly in
  `docs/operator/TAPPA9_FIM_TRUST_MODEL.md`. V1.1 adds
  `nn-admin fim seed-from-file <known-good-shas.txt>` so
  paranoid customers can OOB-distribute a trusted manifest.
- **Rationale:** UX-simplicity rule applies. Install-time
  baseline forces shipping a SHA-256 helper without the
  agent binary, adds a 200ms install block, and STILL
  doesn't solve "system might already be compromised"
  honestly. First-boot + explicit TOFU disclosure is the
  honest tradeoff.
- **Implementation note:** C3 baseline auto-runs on first
  boot when `fim_baseline.jsonl` is empty; C7 ships the
  operator TOFU trust-model doc.
- **Reversibility:** easy (operators can manually run
  `nn-admin fim rebaseline-all` post-install at any time;
  V1.1 `seed-from-file` is additive).

### Q6 — Drift report acknowledge quorum

- **Decision:** NO QUORUM — single-sig with `fim-manage`
  role. Audit chain records the acknowledgement (who, when,
  which event hashes) for later attribution.
- **Rationale:** workflow gates are single-sig; security-
  affecting ops are quorum. Acknowledging is a workflow
  gate ("operator saw this"), not an authorisation gate
  (doesn't unlock any new capability). The audit chain
  provides retrospective accountability without operational
  friction.
- **Implementation note:** C6 `nn-admin fim report
  --acknowledge` invokes the existing 1-of-N
  `verify_signed_payload_quorum(min_distinct=1)` with
  `Role::FimManage`.
- **Reversibility:** easy (add `--require-quorum` later;
  existing acks remain valid).

### Q7 — fim-paths.local conflict resolution

- **Decision:** V1.0 supports BOTH `add:` AND `disable:`
  lists in `/etc/northnarrow/fim-paths.local` (override
  original design rec). Disabled-default paths log `WARN
  fim: default path <P> disabled by operator config` at
  every agent boot. Disabling a path requires `fim-manage`
  role.
- **Rationale:** the additive-only constraint forces operators
  into baseline-noise workarounds for unused services. Cost
  is one extra YAML field + one boot-log line. Boot-time
  WARN ensures operators can't silently hide a regression.
- **Implementation note:** §10 deploy + C7 `fim-paths.local`
  parser + boot-time WARN; C6 `nn-admin fim status
  --show-disabled` surfaces the disabled set.
- **Reversibility:** easy (additive-only is a strict subset
  of "add + disable" — V1.1 could drop `disable:` with
  operator migration if it proves misused).

### Q8 — Baseline rotation / pruning policy

- **Decision:** V1.0 KEEPS FULL CHAIN. V1.1 ships signed
  `fim-rotate` op with chain-of-chains continuation (same
  shape as Tappa 8 §14 Q9 audit-rotate).
- **Rationale:** a 500-entry chain is ~100KB on disk —
  trivial. Audit value of the full chain (compliance, post-
  incident forensics) > storage savings. Pruning policy
  belongs in V1.1 once we have customer feedback on actual
  growth rates.
- **Implementation note:** no V1.0 implementation work;
  documented as deferred follow-up.
- **Reversibility:** easy (V1.1 rotate is additive; un-
  rotated chains stay verifiable forever).

### Q9 — ADE prompt cost ceiling

- **Decision:** TIERED CAP — 10 individual ADE prompts /
  min + 1 batched overflow prompt / min summarising
  suppressed events. Total upper bound: **11 ADE calls /
  minute**. Deterministic-rule path is NEVER throttled by
  the ADE cap.
- **Rationale:** override original simple-cap rec by adding
  the batched-overflow tier. 10/min works in steady state
  but a multi-stage attack with 50 critical events in 30s
  would lose 40 events of LLM context. Batching preserves
  signal density at one extra API call/minute.
- **Implementation note:** §8.1 + C9 (optional) ADE
  integration; if C9 ships, the rate-limit knob lives in
  `agent/src/ade/rate_limit.rs` alongside the existing
  Tappa 6 ADE-rate-limit knob.
- **Reversibility:** easy (runtime-tuneable; batched-
  overflow disabled by setting overflow cap to 0).

### Q10 — Tappa-13 backend mirror

- **Decision:** DEFER TO TAPPA 13. V1.0 local
  `fim_drift.jsonl` + signed `nn-admin fim report --json`
  export is the audit-grade primitive; remote mirroring is
  an additive future feature.
- **Rationale:** mirroring requires backend-SaaS
  architecture decisions out of Tappa 9 scope. The on-disk
  format Tappa 9 ships IS the streaming protocol Tappa 13
  will consume.
- **Implementation note:** no V1.0 implementation work.
- **Reversibility:** easy (additive future feature; no V1.0
  commitment to preclude).

### Cross-cutting consistency (lock-ins captured above)

1. **Q1 (both) + Q3 (curated) compound on `WATCHED_PATHS`
   size** → §5.2 capacity bumped to 8192.
2. **Q2 (hardlink → Critical) + Q4 (Critical uncapped)** →
   §7 rule-table footer documents the never-throttled
   coupling explicitly.
3. **Q5 (TOFU) + Q7 (disable list)** both expose operator-
   trust assumptions → single
   `docs/operator/TAPPA9_FIM_TRUST_MODEL.md` covers both;
   referenced from C7's deploy work.
4. **Q6 (no-quorum ack) + Q8 (signed fim-rotate)** →
   workflow gates are single-sig, security-affecting ops are
   quorum. Principle recorded as the consistent role-
   allocation policy.
5. **Q4 (audit chain captures all) + Q10 (defer backend
   mirror)** → local file is the source of truth for
   everything (including throttled-but-recorded events);
   Tappa 13 backend mirror inherits that property by
   construction.

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
