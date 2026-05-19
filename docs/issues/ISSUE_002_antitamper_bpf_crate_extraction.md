# ISSUE_002 — Extract anti-tamper aya code into a `northnarrow-antitamper-bpf` workspace crate

**Status:** ✅ **RESOLVED 2026-05-19** — extraction shipped on
branch `issue-002-antitamper-bpf-crate-extraction`. Watchdog
implementation (per `docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md`
§2.2 / commit W1) is unblocked: it can `northnarrow-antitamper-bpf
= { workspace = true }` and pick up `attach_lsm`, `prepare_pin_root`,
`fresh_attach_and_pin`, `read_proc_comm`, etc. without dragging
the agent's tokio/ADE/posture/RAG dependency tree.

## Resolution summary

- **What moved:** `DEFAULT_BPFFS_ROOT`, `prepare_pin_root`,
  `is_bpffs` (private), `read_self_comm`, `read_proc_comm`,
  `lsm_pin_paths`, `purge_stale_pin`, `fresh_attach_and_pin`,
  `attach_transient`, `attach_lsm` → `antitamper-bpf/src/lib.rs`.
  Their 4 unit tests moved with them; 3 supplementary tests added
  (`lsm_pin_paths_uses_hook_name_for_both_pins`,
  `purge_stale_pin_swallows_not_found`,
  `purge_stale_pin_removes_regular_file`).
- **What stayed in `agent/src/anti_tamper/mod.rs`:** the agent
  eBPF-object-specific constants (`PROTECTED_PIDS_MAP`,
  `TASK_KILL_PROGRAM`, `PTRACE_PROGRAM`, hook names), the
  `attach()` orchestrator (calls into the extracted helpers with
  the agent-specific names), `register_protected_pids`, and
  `evict_stale_pids`. These all use the agent's `Ebpf` instance
  via `&mut` and know which programs / maps the agent loads —
  they belong with the agent.
- **Public-API stability:** `agent/src/anti_tamper/mod.rs` adds a
  `pub use antitamper_bpf::{…}` block that re-exports every
  extracted name. Existing consumers
  (`crate::anti_tamper::attach_lsm`,
  `crate::anti_tamper::prepare_pin_root`, etc.) compile
  byte-identically — sensors/multiplexer.rs, filesystem.rs,
  main.rs all unchanged.
- **Deviation from §5 acceptance criterion** "agent/Cargo.toml no
  longer lists `aya` as a direct dep": NOT met, intentionally.
  `agent/src/sensors/multiplexer.rs` and `agent/src/sensors/exec.rs`
  use aya directly (the sensor multiplexer is the agent's
  primary aya consumer). Per the user task brief override
  ("sensors stay"), sensors keep their direct aya usage; agent
  Cargo.toml therefore keeps `aya = { workspace = true }`. The
  ISSUE_002 §5 criterion was written before the refactor scope
  was bounded to "anti-tamper code only"; this resolution
  notes the deviation and treats it as the correct call.
- **Watchdog enabler property held:** the watchdog binary will
  depend on `antitamper-bpf` (which pulls aya + libc + tracing +
  anyhow — total ~6 transitive deps) and NOT on `agent` (which
  would pull tokio, candle, tantivy, ade, posture, decision,
  rag, …). The dependency-light watchdog binary footprint
  ISSUE_002 was about is achieved.

## Live verification

- **Pre-extraction baseline:** 432 agent lib + 61 common lib + 4
  integration = 497 tests.
- **Post-extraction:** 428 agent lib (432 - 4 moved) + 7
  antitamper-bpf lib (4 moved + 3 new) + 61 common lib + 4
  integration = 500 tests. Net **+3 tests, zero regressions**.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo build --release --workspace`: clean.
- No production code path's behaviour changed (the extracted
  functions are byte-identical to their pre-extraction bodies;
  only the home crate moved).

---

## Historical context (kept for posterity)

**Status:** OPEN — deferred refactor, blocking gate for Watchdog
implementation start.
**Filed:** 2026-05-19.
**Severity:** architectural / pre-implementation enabler. No
production functional change implied — pure refactor.
**Owner action:** schedule before Watchdog crate (commit W1 in
`docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md` §12).

---

## 1. Why this exists

The Watchdog daemon design
(`docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md`) is built around a
small, narrow-purpose binary that **must not import the whole
agent crate** — doing so would drag in tokio sensors, ADE,
decision engine, posture machine, RAG, XAI, and ~50+ transitive
deps into a binary whose entire job is `pidfd_open` →
`bpf_map_delete_elem` on agent death.

Watchdog needs **just** the anti-tamper aya plumbing:
- Open the pinned `PROTECTED_PIDS` map by bpffs path.
- Insert / evict / contains by PID.
- Read `/proc/<pid>/comm` for sanity checks.

That's the shared surface. Today it lives inside
`agent/src/anti_tamper/mod.rs` and `agent/src/anti_tamper/filesystem.rs`,
fused with the agent's `Ebpf` ownership and load lifecycle.

The Watchdog design §2.2 explicitly assumes the existence of a
crate called `northnarrow-antitamper-bpf` exposing a
`ProtectedPidsHandle` with `open` / `insert` / `evict` / `contains`
methods (design §6.3). That crate does not exist on main today.

---

## 2. Prior art

The original Tappa 7 task 6 #2 sprint produced a single WIP commit
`53ecae7` (branch `tappa-7-task6-bpf-pinning-WIP`) that **did**
extract a crate called `northnarrow-antitamper-bpf` alongside its
pin/reuse work. That branch was **closed as superseded 2026-05-19**
because the pin/reuse functionality shipped on main in-place via a
different decomposition (`916f1a4` + `56362c4` + `07cccda` + harness
follow-ups — see `docs/CLAUDE_BRIEFING.md` §"Task 6 BPF pinning
sprint" for the full list).

The crate-extraction architectural insight from `53ecae7` is still
sound, but the rebase is not viable (the pin/reuse code now lives
in a different shape on main). This issue captures the refactor as
**fresh work on top of current main**, using `53ecae7` as
inspiration / API-shape reference only.

---

## 3. Scope

### In scope

**New workspace crate `antitamper-bpf/`** (`northnarrow-antitamper-bpf`):

- Extracts from `agent/src/anti_tamper/mod.rs`:
  - `DEFAULT_BPFFS_ROOT`, `BPF_FS_MAGIC`, `PIN_ROOT_MODE`
  - `prepare_pin_root()`
  - `is_bpffs()`
  - `read_self_comm()`, `read_proc_comm()`
  - `lsm_pin_paths()`, `purge_stale_pin()`
  - `fresh_attach_and_pin()`, `attach_transient()`, `attach_lsm()`
- Extracts from `agent/src/anti_tamper/filesystem.rs`:
  - `stat_dev_to_kernel_dev()` (Bug #5 fix helper) if it's
    semantically standalone.
- New `ProtectedPidsHandle` public surface (per Watchdog design
  §6.3):
  ```rust
  pub struct ProtectedPidsHandle { /* opens pinned map by path */ }
  impl ProtectedPidsHandle {
      pub fn open(bpffs_root: &Path) -> Result<Self>;
      pub fn insert(&mut self, pid: u32) -> Result<()>;
      pub fn evict(&mut self, pid: u32) -> Result<()>;
      pub fn contains(&self, pid: u32) -> Result<bool>;
  }
  ```
  Internally wraps `aya::maps::HashMap<MapData, u32, u8>` opened
  via `MapData::from_pin(...)` — no `Ebpf` instance required, so
  the Watchdog (which never loads any program) can use it.
- Agent's existing call sites in `mod.rs` switch from internal
  helpers to the crate's public surface (re-export the names so
  the rest of `agent/` compiles without further changes —
  minimal `agent/src/anti_tamper/mod.rs` patch).

### Out of scope (for this issue)

- Watchdog binary itself — that's the post-extraction work tracked
  in `TAPPA7_TASK6_WATCHDOG_DESIGN.md` §12 commits W1–W8.
- Any behavioural change to pin/reuse semantics — pure code
  movement.
- Tappa 8 changes — independent track.

### Hard constraints

- **Zero functional change** to the agent. Same maps pinned at
  same paths, same disposition log strings (`reused pinned LSM
  link`, `purged stale pin and freshly attached`, `LSM hook
  freshly attached + pinned`), same start-up sequence. The
  `verify-2b.sh` harness must pass byte-identically before and
  after.
- **Cargo workspace member list** grows to
  `["agent", "antitamper-bpf", "common", "cli", "xtask"]`.
- `agent` crate gains a workspace dep on
  `antitamper-bpf = { path = "antitamper-bpf" }` (or via the
  `workspace.dependencies` mechanism that `53ecae7` proposed).
- aya stays out of `agent/Cargo.toml`'s direct deps once the
  extraction completes — `antitamper-bpf` is the only crate
  importing `aya`.

---

## 4. Estimated effort

| Phase | Description | Hours |
|---|---|---|
| 4.1 | Stand up the new `antitamper-bpf/` crate (Cargo.toml, lib.rs skeleton, workspace member registration, aya dep move). | 0.5 |
| 4.2 | Move the BPF-FS helpers (`prepare_pin_root`, `is_bpffs`, `BPF_FS_MAGIC`, `PIN_ROOT_MODE`, `DEFAULT_BPFFS_ROOT`) + their tests. | 0.5 |
| 4.3 | Move the `/proc` helpers (`read_self_comm`, `read_proc_comm`) + tests. | 0.3 |
| 4.4 | Move the LSM pin/attach machinery (`lsm_pin_paths`, `purge_stale_pin`, `fresh_attach_and_pin`, `attach_transient`, `attach_lsm`) + tests. The largest piece — many call sites need updating in `agent/src/anti_tamper/mod.rs` to use the new public path. | 1.5 |
| 4.5 | Implement the new `ProtectedPidsHandle` (the Watchdog-facing API). 4 unit tests (open / insert / evict / contains). | 1.0 |
| 4.6 | Update `agent/src/anti_tamper/mod.rs` + `filesystem.rs` + `sensors/multiplexer.rs` to consume the crate. Make sure re-exports keep the rest of `agent/` compiling. | 1.0 |
| 4.7 | Run `cargo clippy --workspace -- -D warnings`, fix any drift. | 0.3 |
| 4.8 | Run `cargo test --release --workspace`, fix any test reorg. | 0.3 |
| 4.9 | Run `verify-2b.sh` on a BPF-LSM host (Hetzner or local VM with `bpf` in lsm chain). Compare verdict JSON pre/post extraction — must be GREEN with identical assertion list. | 0.5 |
| 4.10 | PR + commit message that references this issue and the prior-art SHA `53ecae7`. | 0.1 |
| **Total** | | **~6 h** |

The 4-6 h estimate from the closeout note tracks this; the upper
end accounts for unforeseen aya / re-export surprises in 4.6.

---

## 5. Acceptance criteria

- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo test --release --workspace` — all currently-passing tests
  still pass, count is **higher** (new `ProtectedPidsHandle` tests
  add ~4–6 tests).
- `agent/Cargo.toml` no longer lists `aya` or `aya-log` as direct
  dependencies (only transitive via `antitamper-bpf`).
- `agent/src/anti_tamper/mod.rs` shrinks meaningfully; functions
  named above are no longer defined locally but `pub use`d from
  the crate.
- `verify-2b.sh` GREEN on a BPF-LSM kernel, with the **same number
  of assertions** as pre-extraction and **identical assertion
  names**.
- No change to `configs/combat-rules.v4`, `agent-ebpf/src/`, or any
  posture / decision-engine / ADE code.

---

## 6. Scheduling

**Schedule before**: Watchdog commit W1
(`feat(antitamper-bpf): public ProtectedPidsHandle for external
openers`) per `docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md` §12.
W1 is essentially "land the public surface this issue creates."
With this issue completed first, W1 reduces from a 3 h commit to a
~30 min sanity check.

**Don't schedule before** the open PR for the R009 fix / Task 7
SHIPPED (branch `tappa7-task7-r009-fix-eni-shipped`, PR #4) merges
— that PR doesn't touch `agent/src/anti_tamper/` so no real
conflict, but landing it first keeps the diff space clear.

---

## 7. Cross-references

- `docs/CLAUDE_BRIEFING.md` § "Task 6 BPF pinning sprint (#2a/#2b/
  verify) — SHIPPED" (the closeout note that filed this issue).
- `docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md` §2.2 (the
  consumer that requires this crate to exist) and §6.3 (the API
  shape).
- Superseded WIP branch: `tappa-7-task6-bpf-pinning-WIP`,
  commit `53ecae7` (prior-art reference for the API shape, NOT a
  rebase target — see closeout note for why).
- In-place implementations that shipped instead of the WIP:
  `916f1a4`, `56362c4`, `07cccda`, `17cccf8`, `d6de54d`,
  `954537a`, `989c292`, `6e746c6`, `a52d0b6`, `86f5f41`.
- `agent/src/anti_tamper/mod.rs:75-555` — current home of the
  code to be extracted.
- `docs/verify-2b.sh` — the gating verification harness for the
  acceptance run.
