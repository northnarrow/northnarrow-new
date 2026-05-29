# Tappa 7 Task 6 — Watchdog Daemon Design

**Status:** RFC / design only — no production code in this branch.
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-19.
**Prerequisite track:** branch `tappa-7-task6-bpf-pinning-WIP`
(commits `63ed872` "#1" PROTECTED_PIDS HashMap; `53ecae7` "#2" bpffs
pinning of maps/programs/links). The watchdog is the missing **"#3"**
of that sprint plus the surrounding daemon scaffolding.

This doc is reviewable as a PR. Implementation begins after owner
ruling on the open questions in §13.

---

## 1. Purpose & scope

The watchdog (`northnarrow-watchdog`) is a small, narrow-purpose,
non-eBPF Rust daemon that **observes the agent's liveness and the
integrity of the kernel-side anti-tamper artefacts**, and acts in
exactly two ways when something breaks:

1. **Closes the recycled-PID window on agent death** by deleting the
   agent's PID key from the pinned `PROTECTED_PIDS` map at
   microsecond latency (this is the "layer 2 SIGCHLD-driven evict"
   referenced in the commit message of `53ecae7`; layer 1 is
   `evict_stale_pids` on the new agent's startup).
2. **Restarts the agent process** with the canonical CLI, under a
   bounded exponential-backoff policy, after first re-asserting any
   pin/map invariants that the dying agent might have left in a
   degraded state.

### Explicitly NOT in scope

- **No security decisions.** The watchdog is liveness-only. It does
  not consume telemetry, does not run rules, does not consult ADE,
  does not touch the posture state machine. Decision authority stays
  with the agent.
- **No iptables / NetworkIsolator manipulation.** COMBAT entry/exit
  is the agent's job; if the agent dies in COMBAT, the in-kernel
  iptables rules persist (they're kernel state, not process state) —
  the new agent inherits them on restart and decides what to do.
- **No ADE invocation.** The watchdog does not load models, does
  not read prompts, does not import the `ade/` crate.
- **No log analysis or alerting.** Forensic exfiltration is the
  agent's responsibility via its existing telemetry path. The
  watchdog logs its own actions through `tracing`/journald and
  nothing more.
- **No admin authentication.** Watchdog never accepts admin
  commands; the admin socket stays on the agent. The Ed25519 trust
  chain (Tappa 8) is orthogonal.

This narrowness is load-bearing: the smaller the watchdog's surface,
the harder it is to attack and the simpler it is to audit. The whole
point is to be the thing that survives when the agent does not.

---

## 2. Architecture

### 2.1 Binary placement

A new workspace crate **`watchdog/`** producing a single binary
**`northnarrow-watchdog`**, sibling to `agent/` and `cli/`. The
workspace `Cargo.toml` members list grows from
`["agent", "common", "cli", "xtask"]` to
`["agent", "common", "cli", "watchdog", "xtask"]`. After the BPF
pinning sprint merges, also `"antitamper-bpf"`.

### 2.2 Crate dependencies

- `northnarrow-common` (wire types, posture enum for read-only
  understanding of the agent's startup args).
- `northnarrow-antitamper-bpf` — the shared crate introduced in
  commit `53ecae7` that owns aya. The watchdog re-uses
  `PROTECTED_PIDS` map open/insert/delete via this crate's public
  surface; it does **not** import aya directly. This keeps the
  watchdog binary lean (target footprint ≤ 6 MB stripped release).
- `tokio` runtime, single-threaded flavor (`flavor = "current_thread"`)
  — the watchdog has at most three concurrent waits at any moment
  (agent pidfd, SIGTERM/SIGINT, periodic heartbeat). No reason to
  pay for the multi-thread scheduler.
- `tracing` + `tracing-journald` for logs.
- `nix` for `pidfd_open(2)`, `signalfd`, `prctl(PR_SET_DUMPABLE, 0)`,
  `prctl(PR_SET_NAME)`.
- `anyhow` for top-level errors, `thiserror` for typed errors at the
  module boundary.

### 2.3 Init strategy — three options compared

**Option (a): Watchdog forks/execs the agent (watchdog is parent).**
- Pros: SIGCHLD is direct; `waitpid(2)` gives exit status for free;
  PID 1 reparenting cannot orphan us.
- Cons: Forces a process-tree shape that conflicts with the
  systemd-native deployment we want. systemd's `Restart=` of the
  watchdog would also restart the agent under it, doubling restart
  policy. The agent's own existing PID-file pattern
  (`agent/src/main.rs` `write_pid_file`) becomes redundant.

**Option (b): systemd-managed unit pair (agent + watchdog,
both `Type=notify` to PID 1).**
- Pros: idiomatic Linux deployment; `systemctl status` works for
  both; journald gets logs without configuration; `Restart=` policy
  per unit; `After=` ordering enforced; cgroup boundary per unit.
  systemd already handles the "kernel OOM killed the agent" case via
  `WatchdogSec=` and the unit-restart cycle.
- Cons: Now two independent processes with no parent-child
  relationship; SIGCHLD is unavailable; agent-death detection must
  be done via `pidfd_open` (Linux 5.3+) or `/proc/<pid>` polling.
  Two restart policies to keep coherent (systemd's and the
  watchdog's).

**Option (c): Watchdog spawned by agent at agent startup
(agent is parent).**
- Pros: agent guarantees watchdog exists during steady-state.
- Cons: **dies with the agent**. If agent crashes during startup
  before spawning the watchdog, no protection at all. systemd
  ordering inverts (agent is the supervisor of its own supervisor).
  Nonsensical for the use case.

**Chosen: Option (b).** systemd unit pair, `Type=notify` for both,
`After=northnarrow-agent.service` on the watchdog unit so it starts
after the agent's first attach. Agent-death detection via
`pidfd_open` on the agent's PID (read from
`/run/northnarrow/agent.pid`, written by the existing
`write_pid_file` path). Restart policy lives **only** in the
watchdog — the agent's systemd unit uses `Restart=no` and delegates
respawn to the watchdog. This avoids restart-policy split-brain.

### 2.4 Process-tree shape (steady state)

```
PID 1 (systemd)
├── northnarrow-agent.service    →  /usr/local/bin/northnarrow-agent
│                                   PID file: /run/northnarrow/agent.pid
└── northnarrow-watchdog.service →  /usr/local/bin/northnarrow-watchdog
                                    PID file: /run/northnarrow/watchdog.pid
```

Both run as `root` (required for bpf(2) and iptables). Both are
registered into `PROTECTED_PIDS` (see §6). Neither is the parent of
the other; `pidfd_open` bridges that.

---

## 3. IPC with agent — heartbeat mechanism

### 3.1 Candidates compared

| Mechanism | Liveness signal | Death latency | Failure shape | Verdict |
|---|---|---|---|---|
| **(α) Unix socket ping/pong**, agent sends `HEARTBEAT` every N s | last-receive timestamp | N + timeout | False-negative under load (agent slow ≠ agent dead); requires agent to thread heartbeat into its main loop | reject — too much intrusion on agent |
| **(β) `pidfd_open` + `epoll`/`tokio::Async`** on the agent's pidfd | kernel POLLIN on death | ~µs (kernel signals immediately) | None — kernel-driven, race-free | **PRIMARY signal** |
| **(γ) `/proc/<pid>/status` polling** | `State: Z` or absent | poll interval | PID-recycle race in the polling window | secondary fallback only |
| **(δ) eventfd shared between agent+watchdog** | counter increment | depends on cadence | Requires agent participation; doesn't fire on crash | reject — same problem as α |
| **(ε) shared memory + atomic counter** | counter staleness | depends on read cadence | Same as α/δ | reject |
| **(ζ) Lightweight `STATUS` Unix-socket ping** (watchdog → agent's admin socket) on a slow cadence | reply or timeout | N | Distinguishes "agent stuck/wedged" from "agent dead" | **SECONDARY signal**, slow cadence |

### 3.2 Chosen: (β) primary + (ζ) secondary

- **Primary — pidfd:** `pidfd_open(agent_pid, 0)` returns a file
  descriptor that becomes `POLLIN`-readable the moment the kernel
  reaps the agent task. This is the modern Linux answer (5.3+,
  Ubuntu 6.8 has it) and is **race-free**: no polling window, no
  PID-recycle exposure (the pidfd is bound to the kernel task
  struct, not the numeric PID). Latency from `do_exit` to wakeup is
  on the order of microseconds.

  Rust path: `nix::sys::pidfd::pidfd_open` → wrap in
  `tokio::io::unix::AsyncFd` → `readable().await` resolves on
  agent death. No syscall on the steady-state path.

- **Secondary — admin-socket `STATUS` ping:** every **30 s** the
  watchdog sends a single `STATUS` frame over the agent's existing
  Unix admin socket (`/run/northnarrow/admin.sock`, opened by
  `agent/src/anti_tamper/admin_auth.rs` companion code) and expects
  a reply within **2 s**. This catches the **agent alive but stuck**
  case (e.g. ADE deadlocked, tokio runtime wedged) that pidfd alone
  misses. Two consecutive timeouts in a row promote "stuck" to
  "dead" and trigger the restart path.

  The `STATUS` frame is the same frame the existing `nn-admin
  status` CLI uses today — no new protocol surface.

### 3.3 Wire protocol (`STATUS` ping) — references existing surface

The watchdog speaks the existing admin protocol already shipped by
`agent/src/anti_tamper/admin_auth.rs` (the `nn-admin` CLI's
`status` subcommand). Concretely:

- Frame: length-prefixed JSON `{ "cmd": "status" }`.
- Reply: length-prefixed JSON with `posture`, `network_isolation_engaged`,
  `uptime_secs`, etc.
- The watchdog inspects only **reply latency**, not contents. It is
  **not** an admin and does **not** sign anything. The admin-pubkey
  Ed25519 verification on the agent side is bypassed for `status`
  (the existing CLI works without a key for read-only commands —
  re-confirm during implementation).

If a future hardening step requires Ed25519 on `status`, the
watchdog gets its own pubkey under
`/etc/northnarrow/watchdog.pub` and the agent's pubkey set widens
accordingly. The watchdog's keypair is generated at install time
and stored alongside the admin pubkey.

### 3.4 No new protocol surface

The watchdog does **not** open its own listening socket in this
design — it is a pure client of the agent's admin socket plus a
pidfd reader. Anything that wants to talk *to* the watchdog
(`systemctl status`, journal queries) goes through systemd, not a
custom socket. Smaller surface, less to harden, less to audit.

---

## 4. Heartbeat protocol — numbers

| Parameter | Value | Rationale |
|---|---|---|
| `pidfd_open` poll | continuous (kernel-driven) | no choice — that's the whole point |
| `STATUS` ping interval | **30 s** | balances detection latency for "stuck" agents against socket-load noise. Agent's own `tracing` heartbeat is already at 60 s in the sensors layer; 30 s gives ≤1-cycle skew detection. |
| `STATUS` reply timeout | **2 s** | conservative cap on healthy reply (the admin socket handler runs on the agent's tokio runtime; under steady state replies are sub-100 ms). 2 s tolerates pathological GC pauses, page-fault storms, brief schedlatency. |
| Consecutive timeout threshold | **2** | one timeout could be a CPU steal spike or runaway ADE inference; two in a row (60 s gap) is strong evidence the agent's main loop is not making progress. |
| Clock-skew tolerance | use `CLOCK_MONOTONIC` everywhere | wall-clock jumps (NTP step, RTC drift) must never trigger a false restart. |

### 4.1 Failure-mode disambiguation

| Watchdog observes | Interpretation | Action |
|---|---|---|
| pidfd POLLIN | agent dead (crash, OOM, panic, signal-induced exit) | restart path (§5) immediately after PID eviction (§6) |
| STATUS reply timeout × 2 | agent stuck / deadlocked | **send SIGINT** (the only hook-passing stop, per `docs/verify-2b.sh:48-51`), wait `HARDKILL_GRACE` = 5 s, then if still alive, evict its own PID from `PROTECTED_PIDS` (race-free hard-kill recipe from `verify-2b.sh:57-63`) and `SIGKILL`. The subsequent pidfd POLLIN then triggers the restart path. |
| STATUS reply timeout × 1 only | transient | log WARN, continue |
| pidfd POLLIN within 5 s of watchdog startup | agent never came up | restart with backoff but ALERT loudly — the agent failed to boot, not crashed mid-run |

The "stuck → SIGINT → unprotect → SIGKILL" recipe is **the same
sequence** the verify harness uses (`docs/verify-2b.sh:361-386`)
because it is the only sequence that works against a healthy
LSM-protected agent. Reusing it keeps one canonical kill path.

---

## 5. Restart policy

### 5.1 Backoff

- First restart: **immediate** (within ~10 ms after pidfd POLLIN,
  bounded by `evict_pid` + `Command::spawn` latency).
- Restart attempts 2..5: exponential backoff `100 ms × 2^(n-1)`
  capped at 5 s — so 100 ms, 200 ms, 400 ms, 800 ms.
- After **5 failed restarts within a 60 s window**: stop restarting,
  log `ERROR`, emit a **"tamper suspected"** journal record, set
  systemd's `Result=failure` and let the unit go into the
  `failed` state. The watchdog itself stays alive so an
  operator can inspect; `systemctl reset-failed northnarrow-agent`
  followed by `systemctl start northnarrow-agent` (manual recovery)
  is the documented out.

The 5-in-60s ceiling matches the human-operator-visible threshold
for "this isn't a transient crash, something is actively attacking
the agent" — at that point continuing to thrash hides the signal
from the journal.

### 5.2 Posture preservation on restart

- The agent's COMBAT state is **kernel-resident**, not process-
  resident: iptables rules in the `NORTHNARROW_COMBAT` chain
  survive the death (kernel state), and the pinned anti-tamper
  artefacts in `/sys/fs/bpf/northnarrow/` survive (bpffs pins).
- The new agent re-reads its own state by inspecting the iptables
  chain at startup; if `NORTHNARROW_COMBAT` carries DROP rules at
  boot, the agent's `NetworkIsolator` initialises in COMBAT
  posture rather than OBSERVING.
  **This is an agent-side change** required by the watchdog story
  but **not in this design doc's scope** — flagged in §13.
- Watchdog does **not** decide posture on restart. It just respawns.

### 5.3 CLI for the respawn

The watchdog persists the **first launch's argv** as the canonical
respawn command. On systemd-managed deployment this is exactly
`ExecStart=` of `northnarrow-agent.service` (the watchdog reads it
once via `systemctl show northnarrow-agent.service --property=ExecStart`
at startup) — the watchdog does not hardcode flags.

If the agent crashes during its own argv parsing (e.g. malformed
`--combat-rules`), the restart loop will keep tripping the 5-in-60s
ceiling, which is the desired behaviour (operator sees `failed`
state and the journal explains why).

### 5.4 What the new PID gets registered as

After spawn, the watchdog waits for the new agent's
`/run/northnarrow/agent.pid` file to appear (existing pattern —
`agent/src/main.rs:172-202`), reads it, and inserts the new PID
into `PROTECTED_PIDS`. The agent's own `attach_anti_tamper` call
also inserts the same PID; both writes are idempotent (`BPF_ANY`
upsert, see `register_protected_pids` at `anti_tamper/mod.rs:283`).
The duplication is **load-bearing**: it closes the brief window
between "new agent process spawned" and "new agent finished its own
anti_tamper setup".

---

## 6. PID tracking & PROTECTED_PIDS — the layer-2 SIGCHLD evict

This is the load-bearing security delta versus the BPF pinning
sprint alone. The pinning sprint extends LSM coverage across the
death→respawn gap, but **does not close the recycled-PID hole** —
that's explicitly deferred to "commit #3" (= this watchdog) in
both `63ed872`'s commit message and `53ecae7`'s commit message.

### 6.1 The race the watchdog closes

1. Agent dies at T+0 with PID P.
2. Kernel may reassign PID P to a fresh process at T+ε on a
   churning host. The pinned `PROTECTED_PIDS` map still carries
   `(P → 1)`, so the reassigned process inherits LSM protection
   (unkillable by root, ptrace-proof) until either:
   - the new agent's `evict_stale_pids` runs (layer 1) — bounded
     by agent startup latency, typically 100–500 ms;
   - **the watchdog's `bpf_map_delete_elem(P)` runs (layer 2)** —
     bounded by pidfd wakeup latency, typically ≤ 50 µs.

Layer 2 reduces the recycle window from ~hundreds-of-ms to
microseconds, which on a busy host (think CI runner, build server,
container host) is the difference between "essentially never hits"
and "demonstrable PoC".

### 6.2 Sequence on agent death

```
T+0   :  agent process P exits
T+~µs :  pidfd POLLIN fires for watchdog
T+~µs :  watchdog opens pinned PROTECTED_PIDS via shared crate
T+~µs :  bpf_map_delete_elem(PROTECTED_PIDS, key=P)
T+~µs :  watchdog emits INFO log: "evicted dead agent PID from PROTECTED_PIDS pid=<P>"
T+~ms :  watchdog enters restart-backoff (§5)
T+~50ms (typical):  new agent process spawned, PID P'
T+~200ms:  new agent's evict_stale_pids confirms no work to do
T+~200ms:  new agent's register_protected_pids inserts (P' → 1)
T+~210ms:  watchdog reads /run/northnarrow/agent.pid → P', upserts (P' → 1) defensively
```

### 6.3 Shared-crate API used

Watchdog calls (proposed signatures, to be added to the
`northnarrow-antitamper-bpf` crate from commit `53ecae7`):

```rust
pub struct ProtectedPidsHandle { /* opens pinned map by path */ }
impl ProtectedPidsHandle {
    pub fn open(bpffs_root: &Path) -> Result<Self>;
    pub fn insert(&mut self, pid: u32) -> Result<()>;   // BPF_ANY upsert
    pub fn evict(&mut self, pid: u32) -> Result<()>;    // best-effort delete
    pub fn contains(&self, pid: u32) -> Result<bool>;   // for diagnostic
}
```

These are thin wrappers around the existing `register_protected_pids`
/ `evict_stale_pids` logic in `agent/src/anti_tamper/mod.rs:283..334`,
extracted into the shared crate so the watchdog reuses them without
linking the rest of the agent. **The extraction is a small
agent-side refactor that should land in commit #2's neighbourhood;
the watchdog assumes it is present.**

### 6.4 Why not just delete the agent's eviction loop?

Both layers stay. Layer 1 (agent on startup) handles the case where
the watchdog itself was down or restarting at the moment of agent
death — defence in depth. The two layers are cheap enough that
keeping both is the right answer.

---

## 7. Self-protection (watchdog's own anti-tamper)

### 7.1 Watchdog in PROTECTED_PIDS

**Yes.** The watchdog inserts its own PID into `PROTECTED_PIDS` at
startup, **before** opening the pidfd on the agent. This is the
existing pattern already drafted in
`agent/src/main.rs:152`:

> "The PID set + allowed-comm set are scoped to the agent for now;
> Tappa 7 task 6 commit #4 will widen both to include the
> watchdog (PID read from `/run/northnarrow/watchdog.pid`)."

The agent's startup path is widened to read
`/run/northnarrow/watchdog.pid` if present and pass `&[agent_pid,
watchdog_pid]` to `attach_anti_tamper`. The watchdog does the
symmetric insertion on its own side (idempotent).

Both PIDs go into `allowed_comms = {"northnarrow-age",
"northnarrow-wat"}` (the kernel's `TASK_COMM_LEN`-truncated forms;
`anti_tamper::evict_stale_pids` already gates on the comm
allowlist). The truncation behaviour is documented in the BPF
pinning sprint and `read_proc_comm` already returns the truncated
form.

### 7.2 Mutual monitoring?

**No, not in V1.** Adding "agent watches watchdog" creates a
two-headed restart-policy problem (which one restarts which?) and
introduces a deadlock surface (mutual SIGCHLD races). The
**asymmetric** design — agent is the protected process, watchdog
is the supervisor — is simpler to reason about and good enough
for the threat model. The watchdog's own death is handled by
**systemd's `Restart=on-failure`** of the
`northnarrow-watchdog.service` unit; PID 1 restarts the watchdog.

If a future Tappa raises the threat model to "attacker can kill
PID 1's reaper" we revisit — but that's a hostile-kernel scenario
that this whole design assumes against.

### 7.3 What if the watchdog crashes?

1. systemd reaps it, restarts per `Restart=on-failure RestartSec=2s`.
2. New watchdog instance starts. Its first action is
   `pidfd_open(agent_pid)` on the (still-live, still-protected)
   agent. The kernel keeps LSM protection on the agent throughout
   — there is no gap.
3. New watchdog re-registers its own (new) PID into PROTECTED_PIDS,
   evicts the old watchdog PID via the same evict path.

The "dead watchdog PID lingers in PROTECTED_PIDS until next
restart" window is bounded by systemd's RestartSec (2 s) and is
**not security-relevant** — the LSM hook fires for the lingering
PID, but nothing else is using it (a recycled PID landing there
is the same recycle race we already accept for the brief layer-1
window).

### 7.4 `prctl` hardening on watchdog startup

- `prctl(PR_SET_DUMPABLE, 0)` — no core dumps, no /proc/<pid>/mem
  read by other root processes (defence against the
  `inode_setattr`/`ptrace` LSM gap before our own protection
  registers).
- `prctl(PR_SET_NAME, "northnarrow-wat")` — comm stamped
  deterministically (avoids comm-truncation surprises in
  `evict_stale_pids`).
- No `setuid` games — we stay root, but explicitly drop nothing
  we don't need (`CAP_NET_ADMIN` is not needed; `CAP_BPF` +
  `CAP_SYS_ADMIN` for map open are needed; capability minimisation
  is a follow-up, NOT V1 scope).

---

## 8. Integration with the BPF pinning sprint

### 8.1 Hard dependency

The watchdog **assumes** the BPF pinning sprint
(`tappa-7-task6-bpf-pinning-WIP`) has merged to `main` before
implementation begins. Specifically it assumes:

- The `northnarrow-antitamper-bpf` crate exists (commit `53ecae7`)
  and its public surface is extended with the
  `ProtectedPidsHandle` described in §6.3.
- `PROTECTED_PIDS` is a `HashMap<u32, u8>` (commit `63ed872`, not
  the single-slot `Array<u32>(1)` of the original Tappa 7 task 1).
- Maps and LSM links are pinned at
  `/sys/fs/bpf/northnarrow/PROTECTED_PIDS` and
  `/sys/fs/bpf/northnarrow/link_<hook>` so the watchdog can open
  them by path without holding a reference to the agent's `Ebpf`
  loader instance.

### 8.2 Merge order

**Recommendation:** merge `tappa-7-task6-bpf-pinning-WIP` to `main`
first; then this watchdog work goes onto a fresh branch from main.
The two tracks were intentionally separated in the original sprint
plan (commit messages reference "commit #3" — the watchdog — as a
follow-on, not stacked WIP).

### 8.3 Fallback if pinning never merges

If the owner decides to defer the pinning sprint indefinitely, the
watchdog can be implemented against a **transient** (non-pinned)
agent eBPF object, with two consequences:
- Layer-2 evict only works while the agent is alive (the map dies
  with the agent), defeating the whole purpose. So the watchdog
  in that mode does **only** restart, not evict — which means we
  re-open the recycled-PID race the watchdog was supposed to close.
- This is **not recommended.** The watchdog without pinning is
  ~half the value; do them as one shippable unit.

---

## 9. Failure modes & edge cases

| # | Scenario | Watchdog response | Risk if mishandled |
|---|---|---|---|
| F1 | Watchdog crashes | systemd `Restart=on-failure` (RestartSec=2 s); see §7.3 | gap of ~2 s with no recycled-PID closure; bounded |
| F2 | Agent + watchdog die together (OOM-killer, kernel panic, `init 0`) | nothing — both go down. systemd brings both back on reboot/recovery; pinned LSM artefacts survive | recycle race window opens until both restart; expected behaviour at host shutdown |
| F3 | Agent in netns A, watchdog in netns B | watchdog's admin-socket ping fails — would false-positive "stuck" | mitigate: deploy both in the **root netns**, document, refuse to start watchdog if it's in a non-root netns |
| F4 | Recycled-PID race during respawn | already handled by layer 2 eviction (§6.2); secondary mitigation by allowed-comms gate on layer 1 | covered |
| F5 | File-descriptor leak in watchdog | pidfd is one fd; `STATUS` socket is opened-per-ping and closed. Steady-state fd count: 4 (stdin/out/err + pidfd). Audit constraint: any code path that opens an fd must close it in the same scope. | leak would eventually `EMFILE` and crash the watchdog → §F1 |
| F6 | Watchdog `OOM` due to runaway allocation | systemd unit sets `MemoryMax=64M`; cgroup kills, F1 path triggers | bounded |
| F7 | Steady-state CPU > 1% | systemd `CPUQuota=10%` ceiling; alert if breached | bounded |
| F8 | systemd dies (PID 1 replaced) | the kernel does the systemd-replace dance; watchdog stays running, eventually re-parented; new systemd resumes management | extremely rare; out of practical scope |
| F9 | bpffs unmounted at runtime | `ProtectedPidsHandle::evict` fails with `ENOENT`; watchdog logs ERROR, continues. Agent's own anti-tamper has degraded path; same here | logged, not fatal |
| F10 | Agent's admin socket missing (newer build doesn't write it) | STATUS pings fail; secondary signal degrades to pidfd-only. pidfd is sufficient for the security invariant; STATUS is only for stuck-detection | acceptable degrade |
| F11 | Watchdog started before agent | pidfd_open returns `ESRCH`; watchdog retries every 100 ms for up to 30 s; if still nothing, logs FATAL and exits → systemd restart loop | covered |
| F12 | Agent restart loop interacts with watchdog restart loop | both share systemd; the agent's unit has `Restart=no`, so no cross-loop; only the watchdog's 5-in-60s ceiling can stop the cycle | covered |

### Resource ceiling (V1 targets)

- **RSS:** ≤ 10 MB steady state. The whole binary is a tokio runtime
  + one pidfd + an aya map handle. No model, no rules, no telemetry
  buffers.
- **CPU:** ≤ 0.1% steady state. Nothing happens until the agent
  dies or 30 s elapses.
- **Disk:** zero. Watchdog writes only journal entries (via stdout
  → systemd → journald) and `/run/northnarrow/watchdog.pid`.

---

## 10. Init system integration — systemd units

### 10.1 `northnarrow-agent.service` (modified — agent-side change)

```ini
[Unit]
Description=NorthNarrow XDR agent
Documentation=https://github.com/northnarrow/northnarrow-new
After=network-online.target sys-fs-bpf.mount
Wants=network-online.target
Requires=sys-fs-bpf.mount
# Agent must NOT be auto-restarted by systemd — the watchdog owns
# restart policy. systemd treats agent death as a normal exit so the
# watchdog's bookkeeping is the sole source of truth.
ConditionPathIsMountPoint=/sys/fs/bpf

[Service]
Type=notify
ExecStart=/usr/local/bin/northnarrow-agent \
    --combat-rules /etc/northnarrow/combat-rules.v4 \
    --admin-pub /etc/northnarrow/admin.pub \
    --admin-socket /run/northnarrow/admin.sock \
    --pid-file /run/northnarrow/agent.pid
Restart=no
RuntimeDirectory=northnarrow
RuntimeDirectoryMode=0700
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/northnarrow /var/lib/northnarrow /sys/fs/bpf/northnarrow
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
```

### 10.2 `northnarrow-watchdog.service` (new)

```ini
[Unit]
Description=NorthNarrow XDR watchdog (anti-tamper supervisor)
Documentation=docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md
After=northnarrow-agent.service
BindsTo=northnarrow-agent.service
Requires=sys-fs-bpf.mount

[Service]
Type=notify
ExecStart=/usr/local/bin/northnarrow-watchdog \
    --agent-pidfile /run/northnarrow/agent.pid \
    --admin-socket /run/northnarrow/admin.sock \
    --pidfile /run/northnarrow/watchdog.pid \
    --bpffs-root /sys/fs/bpf/northnarrow
Restart=on-failure
RestartSec=2s
# Resource ceilings (see §9)
MemoryMax=64M
CPUQuota=10%
TasksMax=8
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/northnarrow /sys/fs/bpf/northnarrow
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
```

`BindsTo=northnarrow-agent.service` means: if the agent unit is
**stopped** (not crashed — explicitly stopped via `systemctl stop`),
the watchdog stops too. This avoids the watchdog endlessly
restarting an agent the operator wants down.

### 10.3 Non-systemd init (sysvinit, OpenRC, runit, s6, …)

Out of scope for V1. Linux-first deployment target is Ubuntu LTS
(systemd). A V2 packaging story for non-systemd distros adds an
s6/runit script pair with a `runsv`-style supervision tree — that's
much the same architecture (parent process supervises child),
delivered differently. Not blocking.

---

## 11. Telemetry & observability

### 11.1 What the watchdog logs

All logs go through `tracing` → `tracing-journald` → systemd
journal. **No private log file.** Single source of truth.

Log lines emitted (and only these):

| Event | Level | Fields |
|---|---|---|
| watchdog started | INFO | `watchdog_pid`, `bpffs_root`, `agent_pid` (if already up), `version` |
| registered self in PROTECTED_PIDS | INFO | `watchdog_pid` |
| pidfd opened on agent | INFO | `agent_pid`, `pidfd` |
| STATUS ping ok | DEBUG | `latency_ms`, `posture` (from reply) |
| STATUS ping timeout (single) | WARN | `consecutive_timeouts` |
| STATUS ping timeout (escalating to stuck) | ERROR | `consecutive_timeouts=2`, `last_ok_ago_ms` |
| agent died (pidfd POLLIN) | ERROR | `agent_pid`, `pidfd_latency_µs`, `restart_count`, `time_since_last_restart_ms` |
| evicted dead agent PID | INFO | `agent_pid`, `evict_latency_µs` |
| respawned agent | INFO | `new_agent_pid`, `spawn_latency_ms`, `attempt` |
| respawn failed (backing off) | WARN | `attempt`, `next_backoff_ms`, `error` |
| restart ceiling hit (tamper suspected) | ERROR | `restart_count`, `window_secs=60`, `last_5_exit_codes` |
| watchdog stopping | INFO | `reason` (sigterm/sigint/error) |

### 11.2 How an admin queries health

- `systemctl status northnarrow-watchdog.service` — green/red,
  uptime, last journal line.
- `journalctl --namespace=northnarrow -u northnarrow-watchdog.service -f` — live tail.
- `journalctl --namespace=northnarrow -u northnarrow-watchdog.service -p err` — only the
  load-bearing failures.
- `northnarrow status` (the existing CLI under `cli/`) — extended
  with a "watchdog" field that reads
  `/run/northnarrow/watchdog.pid`, opens its own pidfd against
  that, and reports `alive` / `dead`. **CLI change is a small
  follow-on commit, not V1 watchdog code.**

### 11.3 No new metrics endpoint

Watchdog does **not** expose Prometheus/OTLP in V1. Journald is
the V1 telemetry surface. A backend SaaS metrics path is Tappa 13.

---

## 12. Effort estimate — commit-by-commit plan

Follows the sprint-style decomposition that the BPF pinning track
used (`#1`, `#2`, `#3`...). The watchdog is itself ~5 commits.

| # | Title | Scope | Est. (hours) |
|---|---|---|---|
| **W1** | `feat(antitamper-bpf): public ProtectedPidsHandle for external openers` | Extract `register_protected_pids`/`evict_stale_pids` from `agent/src/anti_tamper/mod.rs` into the shared crate as the typed handle API (§6.3). Agent's existing call sites switch to the new handle. Tests: 4 unit (open/insert/evict/contains) + agent regression. | 3 |
| **W2** | `feat(watchdog): scaffold workspace crate + tokio main + systemd Type=notify` | New `watchdog/` crate. Bare-bones `main()` that parses CLI, hardens via `prctl`, opens pidfd on agent PID (retry loop), notifies systemd `READY=1`. No restart logic yet. Tests: 3 unit (CLI parse, prctl noop on cfg(test), pidfd-open mock). | 4 |
| **W3** | `feat(watchdog): pidfd-driven agent death detection + layer-2 PROTECTED_PIDS evict` | The load-bearing one. `tokio::AsyncFd<PidFd>` → on readable, evict via W1 handle, log latencies. No respawn yet (the agent stays dead in this commit; verified via journal + bpftool dump). Tests: 5 unit + 1 privileged integration test on Hetzner that kills a fake "agent" sentinel and asserts evict latency < 1 ms. | 6 |
| **W4** | `feat(watchdog): respawn with bounded exponential backoff + 5-in-60s ceiling` | Adds `Command::spawn` of agent via parsed systemd `ExecStart=`. Backoff state machine. PID-file readiness wait. New PID reinsertion. Tests: 6 unit on the backoff state machine + 1 integration test cycling 3 restarts. | 5 |
| **W5** | `feat(watchdog): STATUS-ping secondary stuck detection + stuck-agent SIGINT recovery` | Adds the 30 s admin-socket ping path with the 2-timeout escalation. Implements the `SIGINT → unprotect+SIGKILL` recovery using the W1 handle. Tests: 4 unit (timeout state machine) + 1 integration test wedging a sleep(99999) "agent" and asserting unstuck-then-restart. | 4 |
| **W6** | `feat(agent): pass watchdog PID through attach_anti_tamper; widen allowed_comms` | Tiny agent-side change. Reads `/run/northnarrow/watchdog.pid` if present, includes the PID in the slice passed to `register_protected_pids`, adds `"northnarrow-wat"` to allowed_comms. No-op if file missing (deployment without watchdog still works). Tests: 2 unit. | 2 |
| **W7** | `chore(deploy): systemd units + install layout` | The two unit files (§10), a tiny `install.sh` skeleton, `docs/integration-test-runbook.md` extension covering the unit pair. No Rust code. | 2 |
| **W8** | `test(watchdog): privileged e2e — kill-and-respawn round-trip on Hetzner` | Mirrors the existing `agent/tests/privileged_e2e.rs` style. Brings up unit pair, SIGINTs the agent, asserts watchdog restarts it within 1 s with new PID and PROTECTED_PIDS holds only the new PID. Gated by `--features test-privileged`. | 4 |
| | **TOTAL** | | **~30 hours** = ~1 working week with CC pair-programming, similar to the BPF pinning sprint pacing. |

This estimate assumes the BPF pinning sprint has already merged. If
it has not, add ~2 days for the merge resolution.

---

## 13. Open questions / RFC items (owner ruling needed)

1. **Q1 — Restart-policy ownership.** This design puts respawn in
   the watchdog only (`Restart=no` on agent). Alternative: leave
   `Restart=on-failure` on the agent for the *first 3* failures
   before the watchdog escalates. Cleaner-feeling but introduces
   the split-brain we want to avoid. **Recommendation: stay with
   watchdog-only.** Owner ruling?
2. **Q2 — Posture-on-restart inheritance.** §5.2 notes that the
   *new* agent should inspect iptables `NORTHNARROW_COMBAT` chain
   at boot and resume COMBAT posture if rules are present. This is
   an **agent-side** change, not watchdog scope. Should it be:
   - (a) bundled into W6 (agent change for watchdog integration)?
   - (b) split into a separate task labelled "Task 6 #X — agent
     posture inheritance on restart"?
   - (c) deferred to Tappa 7 polish post-merge?
   **Recommendation: (b)** — distinct concern, distinct review.
3. **Q3 — Pubkey for watchdog `STATUS` ping.** Today's agent admin
   socket accepts `status` without Ed25519. Verify this in
   implementation. If a future hardening tappe gates `status`,
   watchdog needs its own keypair under `/etc/northnarrow/`;
   provisioning becomes an install-time concern. Confirm?
4. **Q4 — Tappa 8 interaction.** Tappa 8 (Ed25519 admin override)
   may write capability tokens into `KILL_OVERRIDE` to allow a
   signed admin to kill the agent. Should the watchdog *honour* a
   signed kill (i.e., not restart the agent after a signed shutdown)?
   - Yes, almost certainly. Mechanism TBD: maybe the agent leaves
     a `/run/northnarrow/agent.shutdown_authorised` marker when it
     exits in response to a signed `shutdown` command.
   - Out of scope for V1; flag for Tappa 8 design.
5. **Q5 — Watchdog crash → recycled-PID race for the WATCHDOG.**
   We close the agent recycle race but the watchdog's own death
   leaves a brief window where its old PID could be recycled into
   `PROTECTED_PIDS`. systemd-RestartSec bounds the window to
   ~2 s. Is that acceptable, or do we want a separate auto-evict
   on watchdog-restart? **Recommendation: accept** — the watchdog
   is a smaller target than the agent and the systemd bound is
   tight enough.
6. **Q6 — Non-systemd packaging.** Confirm Linux-first → Ubuntu LTS
   only for V1; defer s6/runit pairing to V2 packaging?
7. **Q7 — Test environment.** Privileged tests (W3, W5, W8) run
   only on the Hetzner box per existing convention. CI compiles
   via `cargo test --no-run`. Same gating? Confirm.

---

## Appendix A — Cross-references

- `agent/src/anti_tamper/mod.rs:8` (userland anti-tamper module
  docstring, already mentions the watchdog by name).
- `agent/src/anti_tamper/mod.rs:36-37` ("watchdog's
  `bpf_map_delete_elem` on SIGCHLD closes [the recycled-PID
  window] during the death itself").
- `agent/src/anti_tamper/mod.rs:72` ("watchdog and `nn-admin`
  enumerate the pinned set by listing it").
- `agent/src/anti_tamper/mod.rs:197-201` (`pids` is a slice so the
  watchdog can register multiple PIDs in one call).
- `agent/src/main.rs:145-160` (Tappa 7 anti-tamper bring-up;
  comment on widening to include the watchdog).
- `agent/src/sensors/multiplexer.rs:133` (`pids` slice plumbing).
- `docs/verify-2b.sh:14-73` (canonical signal/stop semantics —
  watchdog reuses the SIGINT-then-unprotect-then-SIGKILL recipe).
- `docs/TAPPA7_PREREQ.md:149-152` (original Task 6 spec — "Daemon
  separato, Rust standard (non eBPF). Monitora agent principale.
  Riavvia se cade.").
- `docs/CLAUDE_BRIEFING.md:107` (status: Task 6 TODO).
- Branch `tappa-7-task6-bpf-pinning-WIP`, commits `63ed872`,
  `53ecae7` — BPF pinning sprint that this design depends on.

---

## Appendix B — Threat model recap (one paragraph)

The watchdog defends against: agent killed by root despite the LSM
hook being bypassed (kernel exploit, hostile module load that
detaches the BPF link), agent crashing on its own (panic, OOM,
ADE wedge), and PID-recycle race on a churning host between agent
death and either layer-1 eviction or admin recovery. It does **not**
defend against: hostile kernel module that disables BPF entirely
(then nothing in this stack works — that's a UEFI/Tappa 17+ story),
hostile init/PID 1 that refuses to honour `Restart=on-failure` on
the watchdog (systemd is in the trusted base), or attacker who
already has the customer admin Ed25519 key (out of scope by
definition).
