# Tappa 10.6 — Detection Depth Refit Design

**Status:** RFC RESOLVED 2026-05-21 (§13 — all 10 owner-accepted
engineering recommendations applied verbatim as resolved decision
blocks). D1 (wire APPEND) unblocked; sequenced per the §12 commit chain
(D1 → D2 → … → D10). Wire-compat boundary clarified: `ProcessSpawnRaw`
is `bytemuck::Pod` (kernel↔userland, atomic rebuild — strict APPEND
mandatory, no reorder); postcard applies only to the admin protocol
(§6/§9). The audit-surfaced `ppid`-hard-coded-0 (§1/§2.1) is fixed in
D2.
**Author:** Claude Code (architecture).
**Date:** 2026-05-21.
**Classification:** **Beta blocker.** T10.5 closeout accepted two
architectural limits explicitly deferred to T10.6; both must close
before Beta.
**Prerequisite track:** Tappe 2, 6, 7, 8, 9, 9.5, 10, 10.5 SHIPPED and
100% verified on northnarrowdev (kernel 6.8.0-117). **T4.1** (DNS
observability refit) merged on `main` (tip `a2ef43a`) — the production
engine ships **62 rules**. T10.7 (adversarial validation) is in flight
and consumes this work: its triage classifies argv-dependent TTPs as
**"sensor gap → T10.6"** rather than rule FAILs.

This doc is reviewable as a PR. It is the **design kickoff** — Step 1
audit findings are folded into §2 and §4; the RFC (§13) carries
engineering recommendations for each open question.

**The two combined deliverables (T10.5-deferred):**

1. **ProcessSpawn argv + parent context refit** — the wire+BPF change
   that gives the engine `argv` and resolved parent identity, unblocking
   richer process detection beyond the current
   `comm + filename + uid/gid` predicates.
2. **Correlation engine** — N-event (chains > 2 steps) and **cross-PID**
   (parent → child → grandchild kill chains) correlation, lifting the
   T10.5 chain rules out of their single-trigger, same-PID, 2-event box.

The two are **coupled**: cross-PID correlation needs the ancestry that
deliverable 1 supplies (today's `Event` shape cannot link a parent to a
child — §4).

---

## 1. Purpose & scope

### 1.1 Goals

- **G1 — argv capture.** Every `Event::ProcessSpawn` carries the
  process's argument vector so rules can discriminate *how* a binary
  was invoked (`curl … | bash`, `bash -c <payload>`, `insmod
  /lib/modules/evil.ko`), not just *which* binary ran.
- **G2 — parent identity.** Every spawn carries a populated `ppid`
  (today always `0` — §2.1) plus the **resolved parent `comm`**, so a
  shell's provenance (`sshd` vs `cron` vs `nginx`) is a first-class
  predicate.
- **G3 — N-event correlation.** The correlation engine supports
  ordered chains longer than two steps within a window.
- **G4 — cross-PID correlation.** Chains span a process tree
  (parent → child → grandchild), keyed on the ancestry from G2.
- **G5 — detection content.** Enrich R011–R017 with argv predicates,
  extend CHAIN-001..003 with cross-PID variants, and add a small set of
  multi-step kill-chain rules (CHAIN-004+).
- **G6 — bounded + verifier-clean.** No unbounded memory; no new
  verifier-rejection risk; the kernel↔userland ABI stays append-only.

### 1.2 Non-goals (explicit)

- **Process-behaviour tracing** (per-syscall, file/network activity
  attributed to a long-lived process) — T11+.
- **Full DTrace-style syscall correlation** — out of scope; the
  correlation engine works over the existing semantic `Event` stream,
  not raw syscalls.
- **envp capture** — environment variables are larger, noisier, and
  carry secrets; out of scope (argv is the detection-valuable half).
- **New sensors for non-exec events** — this refit enriches the
  existing `sched_process_exec` channel only.

### 1.3 Acceptance

- The 62-rule engine's R001–R017 + CHAIN-001..003 evaluate correctly
  against the **enriched** event shape (no regression on the existing
  `comm/filename/pid/uid` predicates).
- argv + parent_comm are populated on a live kernel (priv-e2e proof).
- ≥1 cross-PID kill-chain reproduction fires end-to-end (priv-e2e).
- Foundation laid for **T10.6.x** extension rules that lean on argv.

### 1.4 Threat-model delta

T10.5 detects on *identity* (which binary, which path, which uid). Real
intrusions hide in *invocation* and *lineage*: a living-off-the-land
`bash -c 'curl … | sh'` is invisible to a comm/filename predicate, and a
`sshd → bash → curl` exfil chain is three different PIDs. T10.6 closes
both blind spots.

---

## 2. ProcessSpawn wire + BPF refit

### 2.1 Current state (Step 1 audit)

`common/src/wire/mod.rs` — `ProcessSpawnRaw` (a `#[repr(C)]`
`bytemuck::Pod` struct, **not** postcard-serialized — see §6):

```rust
pub struct ProcessSpawnRaw {
    pub pid: u32,
    pub ppid: u32,                     // PRESENT but ALWAYS 0 (see below)
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],     // 16
    pub filename: [u8; FILENAME_LEN],  // 256
    pub timestamp_ns: u64,
}
```

Producer: the **`sched_process_exec` tracepoint** in
`agent-ebpf/src/main.rs`. Audit findings:

- **`ppid` is never populated** — `main.rs:110` sets it to `0` with the
  comment *"populated below if cheap; left 0 otherwise"*, and it never
  is. So today there is **no parent linkage at all** in the event
  stream. (This is why the T10.5 chain rules are same-PID only — §4.)
- **No argv.** The `sched_process_exec` tracepoint **format has no
  argv field** (only `__data_loc filename`, `pid`, `old_pid`). argv is
  simply not reachable from this tracepoint's context.
- `comm` is the **post-exec** comm (correct — the new image's name),
  read via `bpf_get_current_comm`.
- A *separate* program, `exec_check.rs` (`sys_enter_execve`
  tracepoint → `ExecCheckRaw`), fires pre-exec and **does** have an
  `argv` pointer at context offset 24 — but it produces a different
  event and its `comm` is the *old* (pre-exec) image. It is not the
  R001–R017 driver.

So the gaps to close: **populate ppid**, **add resolved parent_comm**,
and **add argv** — all onto the `sched_process_exec` → `ProcessSpawnRaw`
path that actually drives the process rules.

### 2.2 Proposed wire extension (APPEND-only)

```rust
pub struct ProcessSpawnRaw {
    // ── existing (unchanged order) ──
    pub pid: u32,
    pub ppid: u32,                       // NOW populated (real_parent->tgid)
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
    // ── T10.6 APPENDED (never reorder the above) ──
    pub parent_comm: [u8; TASK_COMM_LEN],   // real_parent->comm
    pub parent_start_ns: u64,               // real_parent start (PID-reuse-safe key, Q2)
    pub argv: [u8; ARGV_LEN],               // NUL-separated blob (Q1)
    pub argv_len: u16,                      // bytes written into argv
    pub argc: u16,                          // NUL count (capped)
    pub _pad: [u8; 4],
}
```

`ARGV_LEN` is the Q1 decision variable. **Recommendation: a single
`512`-byte NUL-separated blob** (not a 16×64 2-D array): one bounded
`bpf_probe_read_user` of the `[arg_start, arg_end)` region, userland
splits on `NUL`. Rationale in §13 Q1.

### 2.3 BPF program changes

Two new reads in `try_sched_process_exec`, both off the **current
task_struct** (obtained via `bpf_get_current_task`), all via
`bpf_probe_read_kernel` against validated byte offsets (the project's
no-CO-RE pattern — §3):

1. **Parent identity (G2).**
   - `parent = *(task + REAL_PARENT_OFFSET)` → parent `task_struct*`.
   - `ppid = *(parent + TASK_STRUCT_TGID_OFFSET)` (offset **2492**
     already validated in `btf_offsets.rs`).
   - `parent_comm = parent + TASK_COMM_OFFSET` (16-byte kernel read).
   - `parent_start_ns = *(parent + TASK_START_TIME_OFFSET)`.

2. **argv (G1).** At `sched_process_exec` the new `mm` is installed and
   `mm->arg_start .. mm->arg_end` bracket the argv string block
   (NUL-separated) in the new process's user stack:
   - `mm = *(task + TASK_MM_OFFSET)`.
   - `arg_start = *(mm + MM_ARG_START_OFFSET)`,
     `arg_end = *(mm + MM_ARG_END_OFFSET)`.
   - `n = min(arg_end - arg_start, ARGV_LEN)` clamped to a compile-time
     constant for the verifier.
   - one `bpf_probe_read_user` of `n` bytes from `arg_start` into
     `argv`; count NULs (capped) for `argc`.

   This is **user** memory (the args block lives in the user stack), so
   the read is `bpf_probe_read_user` — exactly the pattern the
   exec/file/DNS sensors already use. The `mm` and parent fields are
   kernel memory (`bpf_probe_read_kernel`).

### 2.4 Verifier discipline

- The argv read length is clamped to `ARGV_LEN` (a const) before the
  helper call — a variable-length user read with a constant upper bound,
  the verified pattern from the T4.1 DNS refit.
- No unbounded loops: NUL-counting for `argc` is a bounded
  `for i in 0..ARGV_LEN` over the already-copied blob.
- Parent deref is a single pointer hop (`task → real_parent`), then
  fixed-offset reads — no list walking.

---

## 3. BTF offset validation requirements

Per the project's no-CO-RE constraint (bpf-linker emits no BTF, so every
kernel field read goes through a hardcoded byte offset in
`btf_offsets.rs` + a userland revalidation step), T10.6 must validate
the following on 6.8.0-117 via `bpftool btf dump file
/sys/kernel/btf/vmlinux format raw` **before D2 writes code**, citing
the BTF query path for each (the N2 / T4.1 pattern):

| Field | Struct | Status |
|---|---|---|
| `task_struct.real_parent` | `task_struct` | **NEW — validate** |
| `task_struct.comm` | `task_struct` | **NEW — validate** (parent_comm) |
| `task_struct.tgid` | `task_struct` | **already 2492** (T7), reuse for ppid |
| `task_struct.start_time` | `task_struct` | **NEW — validate** (parent_start_ns) |
| `task_struct.mm` | `task_struct` | **NEW — validate** |
| `mm_struct.arg_start` | `mm_struct` | **NEW — validate** |
| `mm_struct.arg_end` | `mm_struct` | **NEW — validate** |

**Path choice (Q9).** Two candidate argv sources:

- **`task->mm->arg_start/arg_end`** (recommended) — single program
  (`sched_process_exec`), post-exec timing (correct `comm`), one bounded
  user read of a contiguous blob.
- **`linux_binprm`** — requires the `bprm_check_security` LSM hook,
  which bpf-linker **cannot** CO-RE-relocate at load (the exact reason
  `exec_check.rs` uses a tracepoint, not the LSM hook). **Rejected.**

`sys_enter_execve` (offset-24 argv pointer) is a fallback if the `mm`
path proves verifier-hostile, but it splits argv onto a different
event/timing and is not preferred. §13 Q9.

---

## 4. Correlation engine architecture

### 4.1 Current state (Step 1 audit)

`agent/src/decision/rules/chain.rs` (T10.5 D5) — `ChainCorrelationBuffer`:

```rust
pub struct ChainCorrelationBuffer { per_pid: HashMap<u32, VecDeque<u64>> }
```

- **Per-PID, timestamp-only.** Each chain rule owns one
  `Arc<Mutex<ChainCorrelationBuffer>>` recording *its* precursor kind's
  timestamps; the trigger event calls `has_recent(pid, ts)`.
- **Same-PID only.** The doc itself states cross-PID *"need[s] the
  resolved parent comm / ancestry the current `Event` shape lacks and
  are deferred to T10.6"* — exactly this work.
- **2-event, single-trigger.** Precursor → trigger; no notion of an
  ordered N-step sequence.
- Bounds: `CHAIN_WINDOW_NS = 300s`, `CHAIN_MAX_SAMPLES_PER_PID = 16`,
  `CHAIN_MAX_TRACKED_PIDS = 4096`, TTL-pruned + stale-first eviction.
- Fits the single-event `Rule::evaluate(&Event) -> Option<Verdict>`
  contract via interior mutability (the `DnsBurstWindow` / `BeaconWindow`
  precedent). The engine is first-match-wins; chain rules register
  FIRST and return `None` on a precursor (record-only) so it still falls
  through to the precursor's own rule.

### 4.2 New design — ancestry-aware correlation store

Replace the per-rule timestamp deque with a **shared, ancestry-aware
`CorrelationStore`** (one instance, `Arc<Mutex<_>>`, injected into the
chain rules), carrying:

- **Process tree.** A bounded `HashMap<ProcKey, ProcNode>` where
  `ProcKey = (pid, start_ns)` (start_ns disambiguates PID reuse — why
  G2 captures `parent_start_ns`). `ProcNode` holds `parent: ProcKey`,
  `comm`, and a small bounded ring of **typed precursor events**
  `{ kind, ts_ns }` (kind ∈ {CredRead, TmpExec, CanaryTrip, …}).
- **Ancestry walk.** `has_recent_in_lineage(pid, kind, window)` walks
  `pid → parent → … ` up to `MAX_ANCESTRY_DEPTH` (e.g. 8) looking for a
  matching precursor in-window — this is cross-PID (G4).
- **N-event chains (G3).** A chain rule declares an ordered
  `&[PrecursorKind]`; the store answers
  `lineage_matches_sequence(pid, &kinds, window)` by checking each kind
  appears (in order, in-window) along the PID's lineage.

### 4.3 Two-pass vs single-pass (Q3)

**Recommendation: single-pass with a deferred shared store** (not a
two-pass engine). Rationale:

- Preserves the `Rule::evaluate` contract and the
  first-match + register-chain-rules-first ordering already proven in
  T10.5 — no engine rewrite.
- The `ProcessSpawn` event itself feeds the tree (the store observes
  spawns to learn `pid→parent`), so ancestry is available by the time a
  trigger arrives — no second pass needed.
- A two-pass engine (collect all events in a window, then correlate)
  adds latency and a buffering layer with no detection win for these
  chains. §13 Q3.

### 4.4 Bounds (unchanged philosophy)

`MAX_TRACKED_PROCS` (e.g. 8192), per-node precursor ring capped (e.g.
8), `MAX_ANCESTRY_DEPTH` (e.g. 8), TTL = per-chain window, stale-first
eviction. Memory is `O(tracked procs)`, independent of event rate.

---

## 5. Detection rules enabled by the refit

### 5.1 R011–R017 argv enrichment (in-place — Q7)

Tighten existing process rules with additive argv confidence (IDs
**unchanged** — immutable-ID contract; argv is a predicate refinement,
not a new rule):

- **R011 (kernel-module tooling)** + argv contains `/lib/modules/` or a
  `.ko` path → high-confidence module load vs a bare `insmod --help`.
- **R013 (namespace-escape tooling)** + argv `nsenter -t 1 -m` /
  `unshare` flags → escape attempt vs benign use.
- **R015 (encoding tooling)** + argv shows `base64 -d` piped → decode
  of a payload.
- **R005/R006 (netcat / reverse-shell)** + argv `-e /bin/sh` / `-c`
  with shell metacharacters.

### 5.2 parent_comm-aware posture

Same TTP, different posture by provenance:
- shell spawned by `sshd` (interactive) vs by `cron`/`nginx`
  (anomalous → higher severity).

### 5.3 Cross-PID extensions of CHAIN-001..003

Add cross-PID variants (lineage walk, §4.2) so a credential read in a
child and an egress in a sibling/parent within the tree correlate.

### 5.4 New multi-step kill chains (CHAIN-004+ — Q6)

**Recommendation: 5 new rules** (CHAIN-004..008), the highest-value
cross-PID sequences, e.g.:
- **CHAIN-004** parent spawns child → child reads creds → child egress
  (3-step exfil).
- **CHAIN-005** `sshd → shell → download-tool → exec from /tmp`.
- **CHAIN-006** web-server → shell (webshell) → recon/egress.
- **CHAIN-007** cron → shell → persistence drop (FIM) — cross-PID.
- **CHAIN-008** module-load tooling (R011) → outbound (rootkit C2).

Estimate: **5 new chain rules + R011–R017 argv enrichment** → engine
**62 → 67** (final count is an RFC outcome, Q6).

---

## 6. Wire compatibility strategy

**Audit correction (important).** The prompt frames this as "postcard
discriminant preservation". That pattern applies to the **admin
protocol** (`common/src/wire/admin_protocol.rs`, the only postcard user)
— **not** to `ProcessSpawnRaw`. There are two distinct boundaries:

1. **Kernel ↔ userland (`ProcessSpawnRaw`, `bytemuck::Pod`).** The
   multiplexer pump does `bytemuck::try_from_bytes::<T>(bytes)`, which
   **rejects on any size mismatch**. The eBPF object is **embedded in
   the agent binary and rebuilt atomically with it** — both sides always
   agree. APPENDING fields changes `size_of` and both sides recompile
   together; there is no on-the-wire version negotiation here and none
   is needed. **Strict APPEND, no reorder** (Q5).

2. **Serialized boundaries (serde).** `Event`/`Verdict` and the admin
   protocol are serde types that may cross version boundaries (operator
   CLI ↔ agent, persisted `*.jsonl`). New fields there get
   `#[serde(default)]` so an older reader tolerates a newer writer
   (forward-compat). This is where Q10 (mixed fleet) actually lives.

So: APPEND to `ProcessSpawnRaw` (Pod, atomic), and add the corresponding
`Event::ProcessSpawn` fields with `#[serde(default)]` for any serialized
path. No schema break, no version bump (Q5).

---

## 7. RAG corpus updates (offline)

Extend the RAG knowledge base (offline data job, no agent change — the
retrieval path is unchanged):
- argv-aware ATT&CK technique mappings (T1059.x sub-techniques keyed on
  shell invocation pattern; T1105 ingress-tool by `curl`/`wget` argv).
- parent_comm context strings for ADE prompt enrichment.
Delivered via the existing `xtask rag-kb` offline workflow (D10), shipped
as a corpus data extension — decoupled from the code commits.

## 8. ADE template extension

- Reuse the `fim_template` / `chain_template` patterns.
- **`process_template`** — deferred from T10.5 D8 *because there was no
  argv to enrich with*; argv now makes it worthwhile, so fold it in here
  (D7, Q8). Critical-tier process/chain verdicts get an argv- and
  lineage-aware ADE second opinion.

## 9. Wire protocol (no schema break — APPEND only)

Per §6: `ProcessSpawnRaw` grows by APPEND (Pod, atomic rebuild); the
`Event::ProcessSpawn` serde fields are `#[serde(default)]`. No enum
discriminant changes. Existing serialization + priv-e2e tests are the
regression guard.

## 10. Deployment

- **No new config files** — argv predicates reuse the existing
  `process-comm-allowlist.v1` overlay machinery.
- **Schema migration** — forward-compat via `#[serde(default)]` on new
  `Event` fields (§6); the Pod boundary needs no migration (atomic).
- **Operator-visible** — VERDICT logs gain argv + parent_comm context
  (e.g. `reasoning="… argv=[bash -c curl|sh] parent=sshd"`).
- **LSM widening** — none expected (argv via `mm`, not an LSM hook); D8
  is a no-op unless §3 validation forces the `sys_enter_execve` fallback.

## 11. Testing strategy

- **Unit** — argv NUL-blob parser (bounded length, truncation, empty,
  embedded-NUL edge cases); `CorrelationStore` (ancestry walk, N-event
  ordered match, PID-reuse via start_ns, eviction + TTL bounds);
  per-rule positive + negative + cross-PID variant.
- **Privileged e2e** — argv + parent_comm populated on a live kernel
  (assert a known `bash -c` argv + `parent_comm` round-trips); a
  parent→child→egress kill-chain reproduction fires CHAIN-004.
- **Verifier compliance** — eBPF builds + loads + attaches on
  6.8.0-117 (the bounded argv read is the risk surface).
- **BTF revalidation** — a userland test asserting the §3 offsets
  against the running kernel's BTF (the safety contract).

## 12. Effort estimate — commit-by-commit plan

Total **~30–50 h** across **10 commits** (D1–D10). Band reflects the
argv-bound choice (Q1), chain-rule count (Q6), and verifier iteration.

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **D1** | `feat(wire): ProcessSpawnRaw argv + parent context (APPEND)` | wire struct + `Event` fields + serde(default) + serialization tests | 3 |
| **D2** | `feat(ebpf): argv (mm->arg_start) + parent_comm/ppid + BTF offsets` | BTF validation, BPF reads, btf_offsets additions, bounded user read | 8 |
| **D3** | `feat(decision): CorrelationStore — ancestry tree + N-event match` | shared store, process-tree ingest, N-event API + tests | 6 |
| **D4** | `feat(decision): cross-PID lineage correlation` | lineage walk, depth bound, cross-PID variants of CHAIN-001..003 | 5 |
| **D5** | `feat(decision): R011–R017 argv enrichment` | in-place argv predicates + per-rule tests | 5 |
| **D6** | `feat(decision): CHAIN-004..008 multi-step kill chains` | 5 new chain rules + count test bump + tests | 6 |
| **D7** | `feat(ade): process_template (argv-aware, T10.5 D8 fold-in)` | ADE template + sanitize + tests | 4 |
| **D8** | `chore(deploy): LSM/sensor wiring (no-op unless §3 fallback)` | deploy verification; likely minimal | 2 |
| **D9** | `test(e2e): argv + parent_comm + cross-PID kill-chain priv-e2e` | live-kernel proof, per-family smoke | 5 |
| **D10** | `chore(rag): argv-aware ATT&CK corpus extension (offline)` | offline data job; separate operator workflow | 3 |
| | **TOTAL** | | **~30–47 h** |

Cadence: D1→D2 (wire+BPF foundation) gate the rest; D3→D4 (engine),
D5→D6 (content), D7 (ADE), D9 (proof). D10 is independent/offline.

## 13. RFC resolutions

**RESOLVED 2026-05-21.** All 10 engineering recommendations accepted by
the owner verbatim. The §12 commit chain (D1 → D10) is unblocked. Each
block below is the locked decision; the prose recommendations are
retained as the rationale.

### Q1 — argv capture bound

- **Decision:** a single **512-byte NUL-separated blob**
  (`ARGV_LEN = 512`) plus an `argv_len: u16`; not a 16×64 / 32×128
  2-D array.
- **Rationale:** one bounded `bpf_probe_read_user` of
  `[arg_start, arg_end)`; userland splits on NUL. 512 B covers the
  overwhelming majority of real command lines. A 2-D array bloats the
  Pod struct + ringbuf occupancy for marginal detection gain.
- **Implementation note:** truncate at 512 B; `argv_len` records bytes
  written so userland knows if it was clamped. `argc` is **not** a wire
  field — userland derives it by counting NULs (avoids a redundant
  kernel-side loop).
- **Reversibility:** easy — `ARGV_LEN` is one constant; growing it is a
  later APPEND (the trailing field is the blob).
- **Date resolved:** 2026-05-21.

### Q2 — parent context depth

- **Decision:** `parent_comm: [u8; 16]` + **populate the existing
  `ppid`** (today hard-coded 0 — §1/§2.1) + `parent_start_ns: u64`.
  Drop `puid`/`pgid`.
- **Rationale:** `parent_start_ns` is the PID-reuse-safe key the
  cross-PID correlation store needs (§4.2 — `ProcKey = (pid,
  start_ns)`); `puid`/`pgid` add little detection value.
- **Implementation note:** D1 APPENDs `parent_comm` + `parent_start_ns`
  to the wire (kept zero until D2 wires the BPF reads); `ppid` is an
  existing field, so D1 changes no layout for it — D2 populates it.
- **Reversibility:** `puid`/`pgid` can be a later APPEND if a rule needs
  them.
- **Date resolved:** 2026-05-21.

### Q3 — engine shape

- **Decision:** single-pass with a **deferred shared
  `CorrelationStore`** — no two-pass engine.
- **Rationale:** keeps the `Rule::evaluate(&Event) -> Option<Verdict>`
  contract and the T10.5 register-chain-rules-first ordering; the
  ProcessSpawn stream feeds the ancestry tree, so ancestry is present
  by the time a trigger arrives. Two-pass adds latency + buffering for
  no win.
- **Implementation note:** §4.2/§4.3 — `Arc<Mutex<CorrelationStore>>`
  injected into the chain rules.
- **Reversibility:** moderate — a future two-pass mode could wrap the
  same store.
- **Date resolved:** 2026-05-21.

### Q4 — correlation window

- **Decision:** **300s default, configurable per chain rule.**
- **Rationale:** multi-step chains (CHAIN-005+) may want a longer
  lookback than a 2-step; per-rule windows avoid one global compromise.
- **Implementation note:** each chain rule owns its window const; the
  store's TTL prune uses the querying rule's window.
- **Reversibility:** trivial (per-rule constants).
- **Date resolved:** 2026-05-21.

### Q5 — wire compat

- **Decision:** **strict APPEND, no break, no version bump.**
- **Rationale:** the kernel↔userland boundary is `bytemuck::Pod`,
  validated by the pump's size-checked `try_from_bytes`, and the eBPF
  object is **embedded in and rebuilt atomically with** the agent — both
  sides always agree, so APPEND is safe and no on-the-wire version
  negotiation exists or is needed (§6). Reordering existing fields is
  **forbidden** (it would silently corrupt the Pod cast).
- **Implementation note:** new fields APPEND after `timestamp_ns`;
  explicit trailing padding keeps the Pod free of implicit padding
  bytes (a `bytemuck::Pod` derive requirement).
- **Reversibility:** N/A (additive).
- **Date resolved:** 2026-05-21.

### Q6 — new chain rule count

- **Decision:** **5 new rules — CHAIN-004..008** (§5.4).
- **Rationale:** author the highest-value cross-PID sequences; let
  T10.7 adversarial validation reveal which others matter rather than
  over-authoring up front. Engine 62 → ~67.
- **Implementation note:** D6; update both rule-count assertions.
- **Reversibility:** additive; more can follow as T10.6.x.
- **Date resolved:** 2026-05-21.

### Q7 — argv-aware R011–R017

- **Decision:** **modify in place, keep IDs** (no R011a/b fork).
- **Rationale:** argv is additive confidence on an existing predicate,
  not a new detection; forking IDs would violate the immutable-ID
  contract and double the test surface.
- **Implementation note:** D5; argv predicates are additional `&&`
  conditions, gated to no-op when `argv` is empty (mixed-fleet/older
  BPF that emits no argv must not regress the existing match).
- **Reversibility:** predicates are local edits.
- **Date resolved:** 2026-05-21.

### Q8 — process_template fold-in

- **Decision:** **in scope (D7).**
- **Rationale:** the T10.5 D8 deferral reason was "no argv to enrich
  with"; T10.6 removes that, so this is the natural home.
- **Implementation note:** mirror `chain_template.rs`; argv- and
  lineage-aware context for Critical-tier process/chain verdicts.
- **Reversibility:** template is operator-gated per §8.
- **Date resolved:** 2026-05-21.

### Q9 — BTF path for argv

- **Decision:** **`task->mm->arg_start/arg_end`**; reject
  `linux_binprm`.
- **Rationale:** single program (`sched_process_exec`), correct
  post-exec timing, one bounded user read of a contiguous blob.
  `linux_binprm` needs the `bprm_check_security` LSM hook bpf-linker
  cannot CO-RE-relocate (the reason `exec_check.rs` is a tracepoint).
- **Implementation note:** D2 validates the §3 offsets on 6.8.0-117
  before writing code; the `sys_enter_execve` offset-24 argv pointer is
  a documented fallback only.
- **Reversibility:** the fallback path is pre-analysed if the `mm` read
  proves verifier-hostile.
- **Date resolved:** 2026-05-21.

### Q10 — mixed-fleet backward compat

- **Decision:** **best-effort via `#[serde(default)]`** on serialized
  boundaries; the kernel↔userland Pod boundary is **N/A** (atomic
  rebuild).
- **Rationale:** a strict requirement would only matter for
  cross-version admin-protocol / persisted-row (`*.jsonl`) reads, which
  `serde(default)` handles gracefully (an older reader tolerates a newer
  writer's appended fields).
- **Implementation note:** every new `Event::ProcessSpawn` field carries
  `#[serde(default)]`; the multiplexer decodes zeroed Pod fields into
  sane defaults (empty argv, `parent_comm = ""`).
- **Reversibility:** N/A.
- **Date resolved:** 2026-05-21.

---

## Appendix A — Cross-references

- `common/src/wire/mod.rs` — `ProcessSpawnRaw` (§2.1).
- `agent-ebpf/src/main.rs` — `sched_process_exec` producer (§2.1, §2.3).
- `agent-ebpf/src/exec_check.rs` — `sys_enter_execve` argv-ptr fallback
  (§3 Q9).
- `agent-ebpf/src/btf_offsets.rs` — offset table + revalidation pattern
  (§3); `TASK_STRUCT_TGID_OFFSET = 2492` reused for `ppid`.
- `agent/src/decision/rules/chain.rs` — `ChainCorrelationBuffer` (§4.1).
- `agent/src/sensors/multiplexer.rs` — `pump<T>` bytemuck boundary (§6).
- `common/src/wire/admin_protocol.rs` — the actual postcard boundary
  (§6 audit correction).

## Appendix B — MITRE coverage delta (target)

| Capability | New/Enriched detections |
|---|---|
| T1059.x (command interpreters by invocation) | R005/R006/R015 argv |
| T1105 (ingress tool transfer) | argv `curl`/`wget` patterns |
| T1611 (escape to host) | R013 argv `nsenter`/`unshare` |
| T1547 / T1053 (persistence, cross-PID) | CHAIN-007 (cron→shell→FIM) |
| T1041 (exfil over C2, multi-step) | CHAIN-004 (parent→child→egress) |

---

## Sub-task T10.6.5 — R004 systemd-executor exemption

**Status:** IN PROGRESS 2026-05-22 (hot-fix; branch
`tappa10-6-5-r004-systemd-executor-exemption`). **Effort:** 2–4 h.
**Origin:** surfaced while bootstrapping the agent for T10.7 V2 (issue
tracking the R004 false-positive). **Severity:** Beta blocker — broke
clean systemd supervision.

**Problem.** systemd ≥ 254 launches every unit via `systemd-executor`,
which `fexecve()`s an `O_CLOEXEC` fd; the kernel surfaces the exec as
`/proc/self/fd/<n>`, identical by path to a memfd/fileless exec. With the
agent live, `R004_ExecFromProcSelfFd` (Critical → KillProcessTree) fired
on **every** service launch — killing the agent's own systemd restart,
its watchdog, and any service started after it. Verified deterministically
with `systemd-run /bin/sleep` on Ubuntu 24.04 / systemd 255.

**Fix.** Exempt R004 when the exec is a legitimate systemd launch:
`(ppid == 1 || parent_comm == "systemd") && argv[0] is systemd-executor`.
Both signals required (AND, not OR) so a daemon re-parented to init
cannot memfd-exec freely and a forged `argv[0]` alone is rejected.
Residual evasion (re-parent to PID 1 *and* forge argv[0]) is the domain of
the §4 ancestry correlation / fd-target resolution — tracked, not closed
here. Implemented in `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs`
(unit tests for the full matrix + priv-e2e: `systemd-run` exempt,
user-shell `/proc/self/fd` fires, memfd T1620 fires).

**This is the inverse of §5.1** — the refit uses argv/parent context to
*enrich* detections; here it *suppresses* a false-positive. Same
mechanism, recorded here so the two uses stay coherent.
