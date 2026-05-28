# Anti-tamper trust model (BUG-010 + BUG-011 + BUG-013)

**Status.** Design for PHASE 15.1 implementation. Closes the trust-model gap
called out in `docs/backlog/BUG_CATALOG_DESIGN.md` §15.1: the V1 anti-tamper
model has no concept of "trusted local controller / observer / authority,"
which makes legitimate restart, legitimate observation, and legitimate
bootstrap all indistinguishable from attacks.

## Threat model recap

The agent's PID is in `PROTECTED_PIDS`; the BPF-LSM `task_kill` and
`ptrace_access_check` hooks deny any signal or `/proc/<pid>/*` read targeting
that PID — even from `root`. That is correct against the V1 adversary
("post-compromise root tries to silence the defender"), but it locks out
three legitimate principals:

| Principal | Wants to | V1 blocks via |
|---|---|---|
| systemd | SIGTERM the agent for `systemctl restart` | `task_kill` LSM |
| watchdog | read `/proc/<agent>/exe` to reconstruct argv | `ptrace_access_check` LSM |
| operator | issue first `rotate-keys add` on a single-key install | 2-of-N quorum bootstrap |

The fix is **not** "weaken the LSM hook." The fix is **add explicit
trust-anchored carve-outs** that an attacker with root cannot self-grant.

The three carve-outs share a common shape:

> Every carve-out has a **principal** (who is allowed), an **authentication
> mechanism** (how we know it's them), and a **scope** (what the carve-out
> permits). All three must be verifiable from agent-owned state — never
> from attacker-controllable inputs.

## BUG-010 — `KILL_OVERRIDE`: legitimate restart

**Goal.** `systemctl restart northnarrow-agent` succeeds (systemd's SIGTERM
lands); a root attacker's direct `kill -TERM <agent_pid>` is still denied.

**The chicken-and-egg in the catalog's original sketch.** The catalog
suggested "the agent's SIGTERM handler writes the override before draining."
That can't work: the LSM hook denies SIGTERM *before* it reaches userland,
so the agent never gets to run a handler in the first place. The override
must be ARMED proactively, before the signal arrives.

**Mechanism.** Two pinned `Array<u32, 1>` maps, both written only by the
agent. The hook allows SIGTERM/SIGKILL when (a) the caller is PID 1 (the
host's init / systemd), AND (b) `KILL_OVERRIDE[0] == AGENT_SESSION[0]` and
both are non-zero.

### Authentication — why PID 1 is the right gate

PID 1 is structurally unspoofable. The kernel assigns PID 1 to the init
process at boot; no userspace operation can give a different process that
TGID. A root attacker can `kill -TERM` from their own PID (denied — caller
isn't PID 1), or `systemctl stop` (which routes through PID 1 — allowed,
but observable). The carve-out narrows the universe of authorized callers
from "everyone on the host with CAP_KILL" to "the host's init process,"
which is exactly the trust delegation `systemctl` already assumes.

### Authentication — why the session nonce on top

If the rule were ONLY "caller PID == 1 ⇒ allow," every pinned-map / kernel
state would already enforce that and the `KILL_OVERRIDE` map would be
inert. Adding the nonce gate gives the agent an off-switch: an agent that
chooses to refuse systemd-issued kills (e.g. a hardening flag) simply
doesn't arm the override. It also rules out the "stale pinned map across
agent reinstall with different trust posture" failure mode — the new
agent's session nonce won't match the prior agent's, so a leftover override
slot from a prior install is effectively dead.

**The kernel attack: root writes the pinned map directly.**

A root attacker can read `AGENT_SESSION[0]` and write the matching value
into `KILL_OVERRIDE[0]`. But once they have that level of access, they can
also just unpin the LSM hook with `bpf(BPF_OBJ_GET) + bpf(BPF_PROG_DETACH)`.
The kernel-side guarantee is V1-scope best-effort: persistent attestation
is V2 measured-boot territory. What the design DOES defend against:
non-root attackers (can't write BPF maps), and root attackers who choose
the SIGTERM path without bothering with raw BPF (because they don't
realize the LSM is there) — both denied.

### Concrete decision

Two-map design, pinned in bpffs:

- `KILL_OVERRIDE: Array<u32, 1>` (existing stub, repurposed). Holds the
  current boot's session nonce when the carve-out is armed.
- `AGENT_SESSION: Array<u32, 1>` (NEW). Holds the same per-boot session
  nonce. Agent writes both ONCE at boot, before LSM attach completes; same
  value in both. The carve-out stays armed for the agent's lifetime.

Kernel hook logic in `task_kill`:

```rust
let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
if caller_tgid == 1 {
    let ovr = KILL_OVERRIDE[0]; let ses = AGENT_SESSION[0];
    if ovr != 0 && ovr == ses { return 0; }  // allow PID 1
}
// fall through to PROTECTED_PIDS check + deny
```

### Layered defense

The watchdog (BUG-011 fix) observes pidfd POLLIN on agent death and
respawns. A `systemctl stop` without a corresponding shutdown marker is
recorded as TAMPER_SUSPECTED (existing audit path) — so an attacker who
abuses the legitimate-restart path still leaves an audit trail and gets
respawned. The carve-out is not "you can silently kill us," it is "you
can request a restart, and we'll come back."

## BUG-011 — `PROTECTED_OBSERVERS`: legitimate observation

**Goal.** The watchdog's reads of `/proc/<agent>/exe` succeed; an attacker
trying to do the same does not.

**Mechanism.** A new `HashMap<u32, u8>` pinned BPF map (parallel to
`PROTECTED_PIDS`). `ptrace_access_check` already has a "caller in
`PROTECTED_PIDS` ⇒ allow" carve-out for mutual agent/watchdog access; we
extend with "caller in `PROTECTED_OBSERVERS` ⇒ allow." The semantic
difference: `PROTECTED_PIDS` grants both immunity (kill/ptrace deny) AND
observer rights; `PROTECTED_OBSERVERS` grants ONLY observer rights, no
kill/ptrace immunity.

### Authentication

How the watchdog registers itself: **the agent reads
`/proc/<watchdog_pid>/exe` (kernel-resolved, not forgeable) and verifies
it matches `DEFAULT_WATCHDOG_EXE`**. This is exactly the pattern
`agent/src/posture/exempt.rs::resolve_verified_watchdog_pid` already uses
for the posture-trigger exemption. Re-use that helper.

**The kernel attack: can an attacker self-register?**

The map is populated by the **agent**, not the watchdog. An attacker
process cannot register itself — the only writer is the agent, and the
agent only registers a PID whose `/proc/<pid>/exe` matches the installed
watchdog binary.

**Can an attacker substitute themselves at the watchdog PID?**

No — `/proc/<pid>/exe` is a kernel-resolved symlink, set at `execve` time,
and not modifiable from userspace. An attacker running at the watchdog's
recycled PID would have a different exe and fail the check.

**Can a root attacker write to the pinned `PROTECTED_OBSERVERS` map
directly?**

Yes (same kernel-side reality as `KILL_OVERRIDE`). Same mitigations apply:
this is V1 scope, and a root attacker who can mutate pinned BPF maps can
also unpin LSM hooks; persistent attestation is V2.

### Concrete decision

- `PROTECTED_OBSERVERS: HashMap<u32, u8>, pinned, max_entries=8`.
- Agent registers watchdog PID after `resolve_verified_watchdog_pid` returns
  `Verified(pid)`. Refresh path goes through the same timer
  (`spawn_watchdog_exempt_refresh`); when the verification flips back to
  unverified, the PID is evicted.
- `ptrace_access_check` LSM hook adds: `if PROTECTED_OBSERVERS.get(caller_tgid).is_some() { return 0; }`.
  Read-only carve-out — `task_kill` is NOT extended (an observer is not
  a controller).
- Stale-entry eviction follows the same pattern as `PROTECTED_PIDS`
  (existing `evict_stale_pids` extended to walk this map too).

**Re-enabling the watchdog.** The watchdog service was disabled in this
session as a BUG-011 mitigation. With this fix the watchdog can start
again; the boot-order coordination is: agent boots first (registers itself
in `PROTECTED_PIDS`, pins the map), watchdog boots (publishes
`/run/northnarrow/watchdog.pid`), agent's refresh timer picks it up,
verifies the exe, registers it in `PROTECTED_OBSERVERS`. The watchdog
then reads `/proc/<agent>/exe` successfully.

## BUG-013 — `BOOTSTRAP_MODE`: legitimate bootstrap

**Goal.** A fresh single-admin-key install can call `rotate-keys add` once
(1-of-N) to mint the second key, then permanent 2-of-N takes over.

**Mechanism.** A filesystem sentinel `/etc/northnarrow/.bootstrap`
(root-owned 0600). While present, `dispatch_rotate_keys_add` accepts
1-of-N quorum. A successful 1-of-N add removes the sentinel atomically;
subsequent calls require the full 2-of-N.

### Authentication

The sentinel is **filesystem-anchored**, not kernel-anchored. The principal
is "the operator who ran `install.sh` and has root on the host." That's
the same trust domain as "the operator who has the only admin key" —
both can write to `/etc/northnarrow/`. The sentinel encodes
"install.sh just ran; the operator has not yet completed the second-key
mint." Once the second key is in place, the sentinel is removed and
cannot legitimately reappear.

### Preventing the downgrade attack (RE-ACTIVATION)

This is the security-critical part. After the sentinel has been removed,
a root attacker could just `touch /etc/northnarrow/.bootstrap` and revert
to 1-of-N. Three defenses, layered:

1. **Sentinel content matters, not just existence.** The sentinel stores
   a SHA-256 over (`admin.pub` content snapshot at install time + a
   per-install random nonce). The agent computes the same SHA-256 on the
   CURRENT `admin.pub` content. The sentinel is only honored if (a) the
   nonce matches a value the agent computed at install (stored in
   `agent_id.json` alongside the install UUID — already an
   agent-owned-only file), AND (b) the `admin.pub` content has not
   changed since the sentinel was written.

   A root attacker who creates a fresh `.bootstrap` would not know the
   per-install nonce. A root attacker who copies the sentinel from an
   install snapshot would find `admin.pub` has changed (a second key
   was added).

2. **Sentinel is checked at boot AND at every `rotate-keys add` dispatch.**
   The agent re-computes the SHA-256 fresh each time — no in-memory
   caching that an attacker could poison.

3. **Removal is one-way at the agent level.** Once the agent observes
   "2+ keys in `admin.pub`," it permanently sets an in-memory flag and
   atomically unlinks the sentinel. The next call ignores any sentinel
   present. This single-agent-process behavior means even if the
   attacker writes a fake sentinel BEFORE the agent boots, the agent's
   first key-count check sees 2 keys, removes the sentinel, and stays
   in permanent mode.

**Worked example of an attempted downgrade attack:**

- Install: `admin.pub` has key A. Sentinel written with content =
  `SHA256(install_nonce_N || pubA)`. `agent_id.json` stores `install_nonce_N`.
- Operator runs `rotate-keys add` adding key B. Agent verifies sentinel
  (`SHA256(N || pubA)` matches), accepts 1-of-N, writes key B to
  `admin.pub`, removes sentinel.
- Attacker with root post-compromise: writes a new `.bootstrap` with any
  content. Agent boots, observes `admin.pub` has 2 keys, removes the
  sentinel without honoring it. Even if the agent didn't reboot, the
  next `rotate-keys add` dispatch sees the sentinel, re-computes
  `SHA256(N || pubA||pubB)` (current `admin.pub` snapshot), compares
  against the attacker's fake content — mismatch ⇒ ignore sentinel,
  enforce 2-of-N.

### Concrete decision

- Sentinel format: hex-encoded SHA-256, single line, root-owned 0600.
- Per-install nonce: 32 random bytes, stored in
  `agent_id.json` next to the install UUID. Created by `install.sh`
  (which already writes `agent_id.json` for the install UUID).
- Check logic in `dispatch_rotate_keys_add`:
  1. Read `admin.pub` line count (existing `auth.key_count()` if any —
     otherwise re-parse).
  2. If count ≥ 2: ignore sentinel, enforce 2-of-N. Best-effort unlink
     of sentinel if present (cleanup).
  3. If count == 1 AND sentinel present AND sentinel content matches
     `SHA256(install_nonce || admin.pub content)`: accept 1-of-N
     (this dispatch only).
  4. Otherwise: enforce 2-of-N (fail with `QuorumNotMet` as today).
- On successful 1-of-N add: atomic unlink of sentinel after the
  `admin.pub` rewrite (sentinel removal is the last step, so a crash
  between rewrite and removal leaves the sentinel — but the next
  attempt sees count ≥ 2 and removes it via step 2's cleanup path).

### Why `shutdown` is NOT bootstrap-relaxed

Only `rotate-keys add` gets the 1-of-N carve-out. `shutdown` stays 2-of-N
unconditionally. The bootstrap UX problem is "can't mint the second key";
once the second key exists, the operator can shutdown normally. Relaxing
shutdown's quorum during bootstrap would widen the attack surface
unnecessarily — bootstrap mode is for KEY MINTING, not for arbitrary
admin operations.

(BUG-010's commentary suggests `nn-admin shutdown` as the graceful-stop
path, which works once the operator has minted the second key — i.e.
post-bootstrap. The bootstrap window itself is short enough that
`sudo systemctl stop` via the new `KILL_OVERRIDE` is the canonical
in-bootstrap stop path.)

## Implementation surface summary

| Component | Files touched |
|---|---|
| BUG-010 | `agent-ebpf/src/task_kill.rs` (add `AGENT_SESSION`, real check); `agent/src/anti_tamper/mod.rs` (write `AGENT_SESSION` at boot); `agent/src/main.rs` (SIGTERM handler writes `KILL_OVERRIDE`) |
| BUG-011 | `agent-ebpf/src/ptrace_check.rs` (add `PROTECTED_OBSERVERS` check); new `agent-ebpf/src/protected_observers.rs` map declaration (or in-place in `ptrace_check.rs`); `agent/src/anti_tamper/mod.rs` (register watchdog via `resolve_verified_watchdog_pid`); `agent/src/main.rs` (re-enable the watchdog registration path); systemd unit `northnarrow-watchdog.service` enabled |
| BUG-013 | `agent/src/anti_tamper/admin_auth.rs` (sentinel-aware quorum gate, per-install nonce in `agent_id.json`); `agent/src/admin_socket.rs::dispatch_rotate_keys_add` (relax quorum when bootstrap is honored); `deploy/install.sh` (write sentinel + nonce at install) — install.sh change deferred; the agent-side check works with operator-created sentinels in tests |

All three additions are **agent-owned writers** (kernel maps written only
by agent; sentinel written by install.sh and validated by agent against
an agent-owned nonce). No attacker-controllable input is trusted.
