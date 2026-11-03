# Anti-tamper trust model (BUG-010 + BUG-011 + BUG-013)

**Status.** Design for PHASE 15.1 implementation. Closes the trust-model gap
called out in `docs/backlog/BUG_CATALOG_DESIGN.md` §15.1: the V1 anti-tamper
model has no concept of "trusted local controller / observer / authority,"
which makes legitimate restart, legitimate observation, and legitimate
bootstrap all indistinguishable from attacks.

## Threat model recap

The agent's PID is in `PROTECTED_PIDS`; the BPF-LSM `task_kill` and
`ptrace_access_check` hooks deny any signal or `/proc/<pid>/*` read targeting
that PID — even from `root`. (Until 2026-10-08 the `task_kill` hook actually
policed only SIGKILL and SIGTERM, so `kill -INT`/`-HUP`/`-QUIT`/`-STOP` from a
root shell stopped or froze the agent — `task-kill-signals-1`. The hook is now
deny-by-default: every userspace signal towards a protected PID is refused
unless it is signal 0, a self-signal, a signal from another protected PID
(watchdog ↔ agent), or PID 1 under the grant described below.) That is correct against the V1 adversary
("post-compromise root tries to silence the defender"), but it locks out
three legitimate principals:

| Principal | Wants to | V1 blocks via |
|---|---|---|
| systemd | SIGTERM the agent for `systemctl restart` (since EBPF-001: inside a signed trusted-installer window only) | `task_kill` LSM |
| watchdog | read `/proc/<agent>/exe` to reconstruct argv | `ptrace_access_check` LSM |
| operator | issue first `rotate-keys add` on a single-key install | 2-of-N quorum bootstrap |
| a restarted agent or watchdog | open the agent's pinned maps before it is a protected pid (since EBPF-002: only while its role is vacant) | `bpf_map` LSM (BPF self-defence) |

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

### As built, after the external audit (EBPF-001)

The carve-out above was armed at boot for the agent's whole life, with no
bound on the signal, the target or the time: any root shell could stop or
kill the agent and the watchdog with `systemctl stop`/`kill` — systemd only
relays root's request, and a `systemctl stop` of both units left no
respawn. `KILL_OVERRIDE` is gone. PID 1 now passes the hook in two cases
only:

- **A grant** (`KILL_GRANT`, one pinned slot of `{nonce, sig_mask,
  expires_ns}`), written by the agent when a signed trusted-installer
  window opens and withdrawn when it closes: the stop signals (SIGTERM, the
  SIGCONT after it, SIGKILL), until the window ends, under this boot's
  session nonce. `install.sh --upgrade`, `uninstall.sh` and an operator
  restart open the window first.
- **The final stage of a shutdown**: PID 1's comm is `systemd-shutdown`
  AND its executable is the `systemd-shutdown` the agent recorded
  (`SHUTDOWN_EXE`, refreshed every minute so a systemd upgrade is
  followed). Only PID 1 can set its own comm; the executable check means a
  comm set by `ptrace` of PID 1 is not enough, and exec'ing the real
  `systemd-shutdown` ends in a halt or reboot.

The units refuse a manual stop (`RefuseManualStop=yes`; without it systemd
ignored the EPERM and reported the units dead while they ran), and
`SendSIGKILL=no` keeps systemd from starting a second instance beside a
running one. A stop as a dependency (shutdown) ends after at most
`TimeoutStopSec=5s` with the processes running; the agent keeps detecting
until the final stage. Maintenance
inside the window is `systemctl kill -s SIGTERM`.

A refused signal whose sender is PID 1 raises `RelayedTamperAttempt`
(ENGAGED), not the Decisive `AntiTamperDenial`: systemd is the relay, and a
COMBAT with init as the offender could only end in ISOLATE (the lab's first
refused `systemctl kill` isolated the host that way). Init is never a COMBAT
offender, and while systemd reports the host as `stopping` the refusal of
its stop job is expected and not reported.

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
`crates/nn-core/src/posture/exempt.rs::resolve_verified_watchdog_pid` (the
agent's since R08a, lab PR 250, bound to its Linux host) already uses
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

**As built, after the external audit (ATP-004).** The nonce is a plain
file, `/etc/northnarrow/.install_nonce`, not a field of `agent_id.json`,
and `install.sh` writes neither it nor the sentinel: root can read the
nonce and write a matching sentinel, so defense 1 alone does not stop a
root attacker. The downgrade is closed by what the agent holds:

- The gate counts the keys the agent **loaded**
  (`AdminAuth::loaded_admin_pub`, the bytes the in-memory key set came
  from), not `admin.pub` as it reads at the request. A rewrite, or a bind
  mount over `/etc/northnarrow`, that shows one key while two are loaded
  does not arm it. Defense 2's "no in-memory caching" is reversed on
  purpose: the in-memory key set is the one signatures are verified
  against.
- The bootstrap's use is recorded in the **signed audit chain** (a
  successful `rotate_keys_add`), read at boot, and set in memory right
  after the add. From then on no sentinel is honored, whatever
  `admin.pub` holds — defense 3's one-way flag, kept across restarts.

Before the bootstrap is used, the gate still opens on files root can
write. The one signature it then requires, from a key with the
`rotate-keys` role, is what guards the first add.

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
`sudo systemctl stop` inside a trusted-installer window is the canonical
in-bootstrap stop path.)

## EBPF-002 — `ROLE_TGIDS`: the legitimate successor

**Goal.** An agent (or watchdog) that replaces one that exited opens the
pinned maps it shares with its predecessor before it is a protected pid —
the guard of the dead agent is still attached through its pinned link — and
nothing else gets the same right.

**What it replaced.** The guard exempted every process whose executable was
one of the agent's binaries (agent, watchdog, `nn-admin`), by inode, from
both halves of the BPF self-defence. The executable is not the code that
runs: root could start `nn-admin`, or a second agent or watchdog, with
`LD_PRELOAD` (or `ptrace` it before it registered) and take
`PROTECTED_PIDS`, `KILL_GRANT` or the mode map, or detach every LSM hook.

### Authentication

- **Principal:** the process that runs the agent's or the watchdog's binary
  (`OWN_EXE_INODES`, now valued by role: 1 watchdog, 2 agent; `nn-admin` is
  not registered — it talks to the agent over its socket).
- **Mechanism:** the role is vacant. `ROLE_TGIDS` (pinned, two slots) holds
  the tgid of the live watchdog and agent; each records itself once it is a
  protected pid (the agent also records the watchdog it verifies), and
  `role_exit` — a raw tracepoint on `sched_process_exit` whose link is
  pinned (`link_role_exit`), so it outlives the agent that attached it —
  empties the slot when that process's main thread exits. A second
  instance started beside the live one, preloaded or not, gets nothing.
- **Scope:** write handles on the agent's maps only (never a link handle),
  from the process's main thread (a thread's `start_time` is its own: a
  process could keep a window open by spawning threads), during the first
  minute after the process started. `ptrace_access_check` refuses access to
  a process running either binary before it registers, so a fresh successor
  cannot be injected into.

### Residual

While a role is vacant — at boot, between the agent's start and the
watchdog's registration, and in the respawn gap after a crash — a root
process already running could start a preloaded binary of that role. It
needs root present at that moment; the same gap exists wherever a defender
restarts. If the liveness watch cannot be attached (logged as an ERROR),
the slots are never claimed and the window is bounded by age only.

## Implementation surface summary

| Component | Files touched |
|---|---|
| BUG-010 | `agent-ebpf/src/task_kill.rs` (add `AGENT_SESSION`, real check); `agent/src/anti_tamper/mod.rs` (write `AGENT_SESSION` at boot); `agent/src/main.rs` (SIGTERM handler writes `KILL_OVERRIDE`) |
| BUG-011 | `agent-ebpf/src/ptrace_check.rs` (add `PROTECTED_OBSERVERS` check); new `agent-ebpf/src/protected_observers.rs` map declaration (or in-place in `ptrace_check.rs`); `agent/src/anti_tamper/mod.rs` (register watchdog via `resolve_verified_watchdog_pid`); `agent/src/main.rs` (re-enable the watchdog registration path); systemd unit `northnarrow-watchdog.service` enabled |
| BUG-013 | `agent/src/anti_tamper/admin_auth.rs` (sentinel-aware quorum gate, per-install nonce in `agent_id.json`); `agent/src/admin_socket.rs::dispatch_rotate_keys_add` (relax quorum when bootstrap is honored); `deploy/install.sh` (write sentinel + nonce at install) — install.sh change deferred; the agent-side check works with operator-created sentinels in tests |

All three additions are **agent-owned writers** (kernel maps written only
by agent; sentinel written by install.sh and validated by agent against
an agent-owned nonce). No attacker-controllable input is trusted.

## EVD-001 — the signing key is closed to readers

The agent's Ed25519 key (`/etc/northnarrow/agent.sig.key`) signs every
evidence chain: `audit.log`, the detections, netflow, FIM drift, canary
access. The `file_open` deny hook refused writes to it but let any read
through, so root could copy it and rebuild any chain offline with valid
signatures. It is now `FS_PROTECT_READ`: any open, read-only included, by a
process outside the agent's family is refused (`EPERM`, a `FsProtectDenial`
with `op=read`, the NN-L-AT-001 detection, `SensitiveFileAccess` — ALERTED,
not the decisive tamper trigger: a backup of `/etc` meets it too). The
trusted-installer window lifts it like the other denies.

The common read path stays cheap: the hook matches a read-only open against
the inode numbers in `READ_PROTECTED_INOS` (a 4-slot pinned array) before any
map lookup; only a match pays for `deny_if_protected`.

The public half is published by the agent at `agent.sig.pub` (0444,
write-denied); `nn-admin audit verify` reads it, and never mints a key. On a
restart the previous instance's pinned hooks close the key to the new process
until it registers — since EBPF-015 it registers through the pinned map
before it reads anything (below); if that fails, the loads after the attach
read it.

Not closed: root with the means to bypass the LSM altogether (a kernel
module, the disk read from another OS). A key that never leaves a TPM or the
kernel keyring, and chain heads anchored off-host, are the follow-up
(at-authz-2).

## EBPF-015 — no new entry in the agent's directories

**Goal.** Only the agent's family, or a signed trusted-installer window,
adds an entry to the directories the agent owns or changes an extended
attribute of a protected inode — the same principals that may already
remove or rename one.

**What it closed.** The deny set refused unlink, rmdir, rename, setattr, the
flag ioctls and write-opens, keyed by inode: root could still add a file, a
link, a symlink, a device node or a directory to `/etc/northnarrow`, to the
state directory's chain sub-directory, to the agent's drop-in directory or
to the pin root (a decoy overlay, a second key file, a name planted where
the agent would create one, a new drop-in, a pin), and set or remove
extended attributes of any protected inode.

### Mechanism

- **Flag:** `FS_PROTECT_NOCREATE` (bit 3 of the `PROTECTED_INODES` value),
  set by userland only on the agent's own directories:
  `/etc/northnarrow`, `/var/lib/northnarrow` and `detections/`, the
  Debian drop-in directory (`NOCREATE_UNIT_DIRS`), the pin root. Never on
  a directory the agent shares with the host (`/usr/local/bin`,
  `/etc/systemd/system`), where only its own files are registered.
- **Hooks:** `inode_create`, `inode_mkdir`, `inode_mknod`, `inode_symlink`
  (parent directory, arg 0) and `inode_link` (arg 1) refuse a new entry in
  a NOCREATE directory (`FS_OP_CREATE`, `MKDIR`, `MKNOD`, `SYMLINK`,
  `LINK`); a bpffs pin is created through `inode_create`, and an
  `O_TMPFILE` file gets its name through `inode_link`. `inode_setxattr` and
  `inode_removexattr` (dentry, arg 1; name, arg 2, after the
  `user_namespace` / `mnt_idmap` argument of 5.12+) refuse any attribute
  but `security.selinux` on a MUTATE inode (`FS_OP_XATTR`); on 6.2+ a POSIX
  ACL no longer passes `inode_setxattr`, so `inode_set_acl` /
  `inode_remove_acl` are attached where the kernel's BTF has them and
  skipped, not counted missing, where it has not.
- **Exemptions:** the existing ones of `deny_if_protected` — the window
  (`FS_GRANT`), then `PROTECTED_PIDS` — and nothing else. The source of a
  hard link is not checked: the denies follow the inode to every name.
- **Cost:** one program per hook, one map lookup like `inode_unlink`, no
  loop (≈ 410 instructions each, ≈ 480 for the xattr ones, which read the
  name once into a 24-byte stack buffer).

### Boot order

A restarted agent runs under its predecessor's pinned hooks until it
registers. It used to create its missing files (key, `audit.log`,
`agent_id`, a chain log) before registering, and the eBPF load pins any
map whose pin is missing in the pin root: with NOCREATE these would be
refused — a missing map pin would keep the agent from starting until a
reboot. The agent now inserts itself into the pinned `PROTECTED_PIDS`
first thing (`anti_tamper::preregister_self`: from its main thread, in its
first minute, the successor right of EBPF-002), and the registration in
`attach` stays the authoritative one.

### Residual

- A process already in the agent's family, or anything inside the window,
  is not refused: the window is the install path.
- Where the agent's drop-in directory does not exist, a drop-in made with
  it lives in `/etc/systemd/system`, which cannot be NOCREATE; it is
  reported by the integrity check (`unit_dropin`).
- Kernel-internal attribute writes (IMA/EVM fix-ups through
  `__vfs_setxattr_noperm`) do not reach the hook; they are the kernel's.

## Lot 273 — the units' cgroups: kill, freeze and moves

**Goal.** Outside a signed trusted-installer window no process — PID 1
included — kills or freezes the agent's or the watchdog's cgroup, or moves
one of their processes out of it. Inside a window the operator's flows
(upgrade, uninstall, a restart) work as before.

**What it closed.** The `task_kill` hook sees the signals userland sends
(`kill(2)`, `tgkill`, `rt_sigqueueinfo`, `pidfd_send_signal`); the kernel
can end or stop a whole cgroup without one:

- a write of `1` to the cgroup's `cgroup.kill` (5.14+) is a SIGKILL of
  every process in it, sent by the kernel (`cgroup_kill()`), which no
  `security_task_kill()` call sees;
- a write of `1` to `cgroup.freeze` (5.2+) stops every process in it, and
  a process moved into a frozen cgroup is frozen on arrival;
- a protected process moved to another cgroup (a write of its pid to that
  cgroup's `cgroup.procs`) can then be killed or frozen there, through a
  cgroup nobody protects.

Any root shell could do all three on every lab kernel (5.15 to 7.0).
systemd made the first one the answer to `systemctl kill -s SIGKILL`:

| systemd | `systemctl kill -s SIGKILL <unit>` (`unit_kill()`, `--kill-whom=all`) |
|---|---|
| 249, 252, 255, 256 | `kill(2)` of the main process, then `cg_kill_recursive()` of the rest with a set and a log function — `kill(2)` again, process by process: every one refused by `task_kill` ("Access denied") |
| 257 and later | the same `kill(2)` of the main process (refused), then, for SIGKILL, `cg_kill_kernel_sigkill()`: a write to the unit's `cgroup.kill` — "Killed unit cgroup with SIGKILL on client request", the agent dead; 258 added `--kill-whom=cgroup` and `--kill-subgroup=`, the same write |

`systemctl stop` and `restart` were never the way in: `RefuseManualStop=yes`
refuses the job in `bus_unit_queue_job()` on every version (249 to 259 in
the lab: "Operation refused, … may be requested by dependency only").
The deviation the R14 lab saw for tamper case C33 on Debian 13 was C31's:
C31's `systemctl kill -s SIGKILL` had killed the agent through
`cgroup.kill`, the watchdog had started a new one, and C33 compared against
the agent it had read before C31. No unit setting refuses `systemctl
kill` (`RefuseManualStop=` covers jobs, not `KillUnit`; root passes
polkit): the refusal has to be the kernel's.

### Mechanism

- **The entries** (`antitamper_bpf::cgroup_guard`, shared by the agent
  and the watchdog): for each protected process in a systemd *service*
  cgroup (`/<slice>.slice/…/<unit>.service`, cgroup v2), its unit's
  directory, its `cgroup.kill`, `cgroup.freeze`, `cgroup.procs` and
  `cgroup.threads`, and each ancestor slice's `cgroup.kill` and
  `cgroup.freeze`, go into `PROTECTED_INODES` (`lstat`: a link is never
  followed, a control file that is not a regular file refuses the
  registration):

  | entry | flags | refused outside a window, by any caller outside the family |
  |---|---|---|
  | the unit's directory | `MUTATE`, `NOCREATE`, `INIT_RMDIR` (bit 4) | a child cgroup (`inode_mkdir`), `chown`/`chmod`, a rename, an xattr, an `rmdir` — but PID 1's |
  | its `cgroup.kill` | `MUTATE`, `WRITE`, `CGROUP_KILL` (bit 5) | a write-open (`file_open`), signed `cgroup_kill` |
  | its `cgroup.freeze` | `MUTATE`, `WRITE`, `CGROUP_FREEZE` (bit 6) | a write-open, signed `cgroup_freeze` |
  | its `cgroup.procs`, `cgroup.threads` | `MUTATE` | `chown`/`chmod` (a delegation) |
  | each ancestor slice's `cgroup.kill`, `cgroup.freeze` | as the unit's | a write-open: a kill or freeze of the slice kills or freezes the unit with it |

  The bits 5 and 6 only name the refusal (`fs_protect_denied_op`); bit 4
  is the one exemption the deny adds (`fs_protect_init_may`): systemd
  removes a unit's cgroup once its processes are gone — the kernel refuses
  to remove a populated one (`EBUSY`) — and `systemd-shutdown` trims the
  tree at the end of a shutdown. Refusing PID 1 there would leave the
  directory behind and sign a refused attempt at every restart, for no
  protection: an `rmdir` never removes a cgroup with a process in it.
- **The move guard** (`agent-ebpf/src/cgroup_guard.rs`). A move is a write
  to the *destination's* `cgroup.procs` — any cgroup's — and no LSM hook
  names the moved task. The migration's permission check does run one:
  `__cgroup_procs_write()` finds the task (`cgroup_procs_write_start()`),
  then checks write access to the `cgroup.procs` of the source's and the
  destination's common ancestor (`cgroup_attach_permissions()` →
  `cgroup_may_write()` → `inode_permission(MAY_WRITE)`), in the writer's
  thread, before anything moves. `cgroup_move_stash` (fexit
  `cgroup_procs_write_start`, the returned task in the fourth context
  slot) records, for the writing thread, a protected tgid that a caller
  outside the family moves outside a window; `cgroup_move_deny` (LSM
  `inode_permission`) refuses that thread's next write check — the
  migration's —, once, within a second, and signs it (`cgroup_move`,
  rate-limited per caller like a signal). Every other permission check
  returns at the mask test or one lookup in a map that holds only refused
  moves. `cgroup.threads` goes through the same function; `CLONE_INTO_CGROUP`
  creates a process, it moves none. The guard is an optional deny pair:
  attached where the kernel's BTF has `cgroup_procs_write_start` with three
  parameters returning a `struct task_struct *` (5.14 to 7.0: the third
  parameter, the lock state, changed type, not place), counted in
  `deny_expected` there; elsewhere not attached and signed degraded.
- **When.** The agent registers its own unit cgroup at its earliest start
  (into the pinned map, under its predecessor's hooks, as
  `preregister_self` does for its pid), again at the attach (the boot's
  keys, kept by the stale-key prune) with the live watchdog's (the
  `PROTECTED_PIDS` entry that survived the stale scan), and the watchdog's
  again whenever its refresh verifies a new watchdog pid; the watchdog
  registers its own at its start, once it is in `PROTECTED_PIDS`.
- **Who.** A refused attempt is an `NN-L-AT-001` detection (`operation`
  `cgroup_kill`, `cgroup_freeze`, `cgroup_move`, `rmdir`, `mkdir`,
  `setattr`), its principal the pid, comm and uid the kernel recorded, its
  `exe` the caller's executable as `/proc/<pid>/exe` named it when the
  writer signed the row (while that pid still ran the recorded comm). A
  caller that is PID 1 is systemd relaying `systemctl kill` / `freeze`:
  `RelayedTamperAttempt` (ENGAGED); any other caller `AntiTamperDenial`
  (COMBAT).
- **Host shutdown.** Untouched: systemd's stop job sends signals (refused
  until `systemd-shutdown`, as before), `systemd-shutdown` kills with
  `kill(2)` (its carve-out) and its cgroup trim is PID 1's `rmdir`. No
  `cgroup.kill` or `cgroup.freeze` is written on that path (systemd 249 to
  259).

### Residual

- **Resource limits — refused since lot 273b (below).** The resource files of the
  units and of their slices (`memory.max`, `memory.high`, `cpu.max`,
  `cpu.idle`, `pids.max`, ...) are not refused, and they are not "only
  reported" either: some of them stop the agent as surely as a kill or a
  freeze.
  - `memory.max` below the unit's use is an OOM kill inside the write
    itself (the kernel reclaims and OOM-kills in `memory_max_write`): the
    agent dies before it can sign a row, and systemd writes the same value
    again when it restarts the unit. On `system.slice` it is a persistent
    OOM loop that also kills every new watchdog.
  - `cpu.max` (a minimal quota), `cpu.idle` and `pids.max` starve the
    agent the way a freeze does — on a slice, the watchdog with it.
    `pids.max` also refuses the agent's new threads, the worker's restart
    and the actuators' execs (`nft`, `iptables`): a response fails without
    noise.

  A change the agent survives is reported (`integrity_drift`,
  `limit_changed`; tamper case C12). systemd writes these files as PID 1
  whenever it realises a unit (a start, a `set-property`), which is why
  lot 273 did not refuse them. Lot 273b refuses their writes by any
  caller but PID 1 outside a window, lets PID 1 write back only the value
  the file held at the registration (a `set-property` is refused),
  protects the units' drop-in directories, and refuses writes to the
  protected pids' `oom_score_adj`.
- **cgroup v1 — refused since lot 273b where systemd runs the unified
  hierarchy; confirmed in the lab (below).** Only the v2
  hierarchy is protected, and the gap is not limited to hybrid hosts. The
  v1 controllers that no v2 hierarchy binds — `freezer`, `devices`,
  `net_cls`, `net_prio`, `perf_event` (hierarchy 0 in `/proc/cgroups`) —
  can be mounted by root on a pure v2 host too, unless it booted with
  `cgroup_no_v1=all`. A root can then move the agent's and the watchdog's
  pids into a v1 `freezer` cgroup and write `FROZEN` to its
  `freezer.state`: the v1 `cgroup.procs` path (`__cgroup1_procs_write`)
  checks the uid and no inode, so the move guard does not see the move,
  and v1's freeze file is not in the protected set. The effect is the
  freeze lot 273 refuses on v2 (the processes stay in their v2 unit
  cgroup, so systemd still shows the unit running). Lot 273b confirms it
  in the lab and adds the defence: refuse write-opens on a v1 cgroup
  superblock (`CGROUP_SUPER_MAGIC`) outside a window on hosts booted
  without v1 hierarchies, and say in the capability manifest whether v1
  controllers are mountable. On a pure v2 host an operator can refuse the
  mount itself today with `cgroup_no_v1=all` on the kernel command line.
  A process in no v2 cgroup, or a host without one, is a signed
  degradation.
- **Handles opened earlier — refused at the write since lot 273b
  (below).** The deny is at
  open, as for every protected file, so a write descriptor opened before
  the inode was registered keeps working. That is one of a unit's
  `cgroup.kill` opened inside a window or in a fresh cgroup's first
  milliseconds, and — wider — one of `system.slice/cgroup.kill` (or
  `cgroup.freeze`) opened at any time before the agent's first start (for
  example by a unit ordered before it): the slice outlives every restart
  of the agent, so that descriptor stays usable for the whole boot. Lot
  273b: refuse the write itself on the registered inodes in
  `file_permission` (one map lookup per write, not per path walk).
- **Thaw.** A thaw is a write-open of `cgroup.freeze` too: outside a
  window it is refused like a freeze (lot 273b: but PID 1's thaw, a write
  of `0`, goes through — systemd 254 and 255 thaw the slices at every
  start and stop of every unit, below). A unit frozen inside a window must
  be thawed inside one. systemd 249 and 252 mark the unit `freezing` (or
  `thawing`) before they write and keep that state when the write is
  refused: nothing is frozen, but their next `systemctl freeze`/`thaw`
  answers "Previously requested freezer operation … still in progress"
  until the cgroup's next freezer event (a reboot with the unit in that
  state was clean in the lab); 255 and later write again or skip a thaw
  of a running cgroup.
- **Cost.** `inode_permission` runs for every permission check of a path
  walk; with the guard attached the lab's open microbenchmark lost about
  10 % of its throughput (Ubuntu 24.04, A/B with the guard's links
  detached and attached in turn; wopen about 8 %). No cheaper attach point
  exists in the migration's path: no LSM hook names the moved task, and
  the functions there are not `fmod_ret` targets.
- **The fresh cgroup at a restart.** systemd makes a new unit cgroup for
  every start; until the new agent's earliest registration (its first
  milliseconds; on a first boot, until its attach) that cgroup is not
  protected. The watchdog's: until its own registration at its start.
  With a descriptor opened in that interval (an `inotify` on the slice
  sees the `mkdir`) it is the case above, closed by the same
  `file_permission` refusal.

## Lot 273b — what stops the agent without a signal: limits, cgroup v1, earlier descriptors, the OOM score

**Goal.** The residuals the review of #489 measured in lot 273 (R1, R2
and the descriptors opened before a registration), closed by the deny
hooks outside a signed trusted-installer window, and the move guard made
to hold without its assumptions: no record that outlives its write, a map
that never evicts, a guard proved to run at every boot.

**What it closes.**

- **Resource limits** of the agent's and the watchdog's unit cgroups and
  of their ancestor slices. A low `memory.max` is an OOM kill inside the
  write itself (the kernel reclaims and OOM-kills in `memory_max_write`):
  the agent dies before it signs anything, and on `system.slice` the OOM
  loop also kills every new watchdog. `cpu.max`, `cpu.idle`,
  `cpu.weight`, `cpu.weight.nice` starve the agent as a freeze does;
  `pids.max` also refuses the actuators' execs and the worker's restart;
  `cgroup.max.descendants` / `cgroup.max.depth` on a slice keep the next
  start from making its cgroup; `memory.oom.group` on a slice turns one
  OOM into the kill of every unit in it; `io.max` throttles the agent's
  writes to nothing. A change was reported (`integrity_drift`, C12), not
  refused.
- **cgroup v1, on pure v2 hosts too.** The v1 controllers no v2
  hierarchy binds — `freezer`, `devices`, `net_cls`, `net_prio`,
  `perf_event` — can be mounted by root on a host booted without
  `cgroup_no_v1=all`; a root could move the agent and the watchdog into a
  v1 `freezer` cgroup and write `FROZEN` to its `freezer.state`. The v1
  `cgroup.procs` path (`__cgroup1_procs_write`) checks the writer's uid,
  no inode: the move guard never saw it. Confirmed in the lab with lot
  273's code (tamper cases C83 and C83b) on the five guests (5.15, 6.1,
  6.8, 6.12, 7.0), all booted without `cgroup_no_v1=`: root mounted a v1
  `freezer` at `/run/nn-lab-v1`, moved the agent's pid into a child of it
  and wrote `FROZEN` to its `freezer.state` — the agent frozen, nothing
  refused or signed.
- **Descriptors opened before a registration.** The deny was at the
  open: a write descriptor of `system.slice/cgroup.kill` opened at any time
  before the agent's first start (a unit ordered before it), or one of a
  unit's opened inside a window or in a fresh cgroup's first milliseconds,
  kept working.
- **The OOM score.** `/proc/<pid>/oom_score_adj` (or
  `/proc/<pid>/task/<tid>/oom_score_adj`, `oom_adj`) of a protected
  process set to `1000` made it the OOM killer's first victim, whose
  SIGKILL no `task_kill` hook sees. It was reported (`limit_unexpected`,
  C18), not refused.
- **The move guard's three weak points** (the review's §2): a stashed move
  that never reached its permission check (a v1 write, a check the DAC
  refused first — an unprivileged writer in a delegated subtree writing
  the agent's pid) refused the thread's next write check within a second
  and signed a false `cgroup_move`; the stash was an LRU map, whose
  per-CPU free lists may evict a live record before the map is full; and
  a guard attached where the BTF has the function in its shape is not a
  guard that runs (an `.isra` clone, an LTO build).

### Mechanism

- **The write deny** (`protected_write_deny`, LSM `file_permission`, a
  deny hook of its own: seventeen deny hooks). `file_permission` runs for
  every `write(2)`-family call (`rw_verify_area`; io_uring's writes,
  `splice` and `copy_file_range` too) before anything is written. A write
  to a `FS_PROTECT_WRITE` inode by a caller outside the family, outside a
  window, is refused as its open is (and signed by its effect:
  `cgroup_kill`, `cgroup_freeze`, `write`), rate-limited per caller like a
  signal (a loop of writes on one descriptor is one record a second). The
  same program judges the files below at the write (`cgroup_files.rs`).
  Reads return at the mask test; a write pays one `PROTECTED_INODES`
  lookup and the superblock's magic. A shared writable mapping opened
  before the registration is not a write call: see the residual.
- **The resource files** (`common::cgroup_limits`, shared by the eBPF
  programs and the agent). The unit's directory and every ancestor
  slice's go into `PROTECTED_INODES` with `FS_PROTECT_LIMIT_DIR` (bit 7,
  the last; a slice's directory carries nothing else: other units'
  cgroups are made and removed in it). A write-open (`file_open`) or a
  write (`file_permission`) of a file of that directory whose name is one
  of `memory.max`, `memory.high`, `pids.max`, `cgroup.max.descendants`,
  `cgroup.max.depth`, `cpu.weight`, `cpu.max`, `cpu.idle`,
  `memory.oom.group`, `cpu.weight.nice`, `io.max` is refused to every
  caller outside the family but PID 1 — by name, under the registered
  directory, so a file that appears later (a controller enabled after the
  registration: the watchdog's `CPUQuota=` enables `cpu` in
  `system.slice` after the agent registered) is protected from its first
  write. The name and the directory are the file's kernfs node's (its
  `name`, its parent node's `id`, the directory's inode number), not its
  dentry's: a file reopened through a handle (`name_to_handle_at`, the
  dentries dropped, `open_by_handle_at`) has a disconnected dentry, named
  `/` and its own parent (the review of #490, B; tamper case C88). A file
  whose value was registered is recognised by its inode as well; without
  the node's offsets in the kernel's BTF the dentry is read, a signed
  degradation. PID 1 writes these files whenever it realises a unit (a start, a
  `set-property`, a reload): its open is let through and its write judged
  — the bytes the `write(2)` / `pwrite64(2)` carries, read from the
  syscall's arguments (`bpf_task_pt_regs`, x86-64), one trailing newline
  cleared (systemd appends one: `write_string_file()` without
  `WRITE_STRING_FILE_AVOID_NEWLINE`), must be the value the file held when
  its cgroup was registered (`LIMIT_VALUES`, pinned: the file's text, its
  newline cut, at most 31 bytes), or the kernel's default for a file that
  has none (`max`, `max 100000` for `cpu.max`, `cpu.weight` 100, `0`).
  Four word compares: an earlier version parsed the value and let PID 1
  raise a limit, and its loops made the verifier walk a million
  instructions (6.12). systemd writing back the unit's values at a reload
  or a re-exec goes through; any other value — a `set-property` lowering
  or raising a limit, another call (`writev`), more than 31 bytes — is a
  change of the unit, made inside a window. A change made inside one
  stays: when the window closes (its grant zeroed first) the agent
  registers again the values the files of every unit it registered hold
  then (`cgroup_guard::refresh_values`), so systemd's next write-back of
  the new value is not refused. Refused, either is signed
  `cgroup_limit` — PID 1's as the `systemctl set-property` it relays
  (`RelayedTamperAttempt`, ENGAGED), any other caller's as a tamper
  (`AntiTamperDenial`, COMBAT).
- **The units' `set-property` drop-ins.** A refused cgroup write would
  still come back: `set-property` writes a drop-in
  (`/run/systemd/system.control/<unit>.d/50-<Property>.conf`, or under
  `/etc/systemd/system.control` without `--runtime`) that systemd applies
  to the fresh cgroup of every later start, before the agent is there to
  refuse it — an OOM kill or a starvation at each start. The agent's unit
  makes the four `system.control` directories of the two units (empty)
  before every start (`ExecStartPre=+/bin/mkdir -p …`), and the agent
  registers them with `NOCREATE` like its other drop-in directories: a new
  drop-in there is refused outside a window (signed `create`).
  `uninstall.sh` removes them. `systemctl set-property` answers success
  whatever was refused (below). The review of #490 (A): a drop-in written
  by hand reaches the next start the same way, so the watchdog's drop-in
  directories (`/etc/systemd/system/northnarrow-watchdog.service.d`, its
  `/run` twin) and the `northnarrow-.service.d` prefix ones — whose
  drop-ins systemd (246 and later) applies to both units — are made by the
  agent's unit and registered `NOCREATE` too (tamper case C87).
- **cgroup v1.** At the attach the agent decides from the host
  (`antitamper_bpf::cgroup_guard::v1_policy`): where `/sys/fs/cgroup` is
  the v2 hierarchy and no `name=systemd` v1 hierarchy is mounted (systemd
  runs the unified hierarchy only: every lab guest), it sets
  `CGROUP_POLICY_V1_REFUSE` in the pinned `CGROUP_POLICY`, and every write
  — at the open and at the write — of a file of a cgroup v1 superblock
  (`CGROUP_SUPER_MAGIC`: a v1 `cgroup.procs`, `tasks`, `freezer.state`,
  any controller's file) by a caller outside the family, outside a
  window, is refused and signed `cgroup_v1`. v1 hierarchies mounted at the
  attach are named in the journal; their writers are refused from then
  on. On a hybrid or legacy host (systemd writes its own v1 hierarchy)
  nothing v1 is refused, and that is a signed degradation. The host
  hardening table gains `cgroup_v1`: which of the five controllers root
  can mount, `ok` with `cgroup_no_v1=all` (the recommendation: it refuses
  the mount itself, before the agent is there).
- **The OOM score.** A write-open or a write of a procfs file named
  `oom_score_adj` or `oom_adj` whose process — `proc_inode->pid`'s task,
  its tgid (a thread's file included) — is protected, by a caller outside
  the family, outside a window, is refused and signed `oom_adj`
  (rate-limited). The agent sets its own value (it is exempt); systemd
  sets `OOMScoreAdjust=` in the child before the exec, before the pid is
  protected. Without the four proc offsets in the kernel's BTF the deny is
  not armed (the offsets are optional).
- **systemd's own writes, let through (a regression of lot 273: the
  xattrs on every version, the thaw on 254 and 255).** systemd 254 and 255 thaw a unit's slices at every start and stop
  of every unit (`unit_start()` / `unit_stop()` call
  `unit_cgroup_freezer_action(u, FREEZER_THAW)`, which writes `0` to each
  slice's `cgroup.freeze` up the tree, unconditionally there; 249 and 252
  write only to a cgroup they hold frozen — one whose freeze was refused
  too, which they keep `freezing`: measured on 252, a thaw at the stop
  after the tamper check's refused freezes; 256 and later reworked it),
  and every version rewrites the xattrs of a slice's unit cgroups when it
  realises a sibling (`main`'s C12 and C85, a `set-property`, signed a PID
  1 `xattr` refusal on all five guests). With lot 273's entries, each `systemctl restart` of any service of
  `system.slice` on Ubuntu 24.04 logged "Failed to thaw slice system.slice
  of unit: Operation not permitted" and signed a PID 1 `cgroup_freeze` (and
  an `xattr`) refusal (`RelayedTamperAttempt`, ENGAGED). Now PID 1's
  write-open of a protected `cgroup.freeze` goes on to its write, where
  `0` (a thaw) is let through and `1` (a freeze) refused and signed
  (`fs_protect_init_may_open`, `fs_protect_thaw_value`); PID 1's xattrs
  on a unit's cgroup directory are let through like its `rmdir`
  (`fs_protect_init_may`). A root shell's thaw and xattrs are refused as
  before. Tamper case C86 checks that a unit started and stopped in the
  agent's slice signs nothing.
- **The move guard, made to hold.**
  - A third program, `cgroup_move_clear` (fentry
    `cgroup_procs_write_finish`), drops the thread's record when the
    write ends — whatever it did: the move done, refused (by the guard or
    by the DAC), failed, on v2 and on v1. A record lives only from the
    lookup to the end of the write.
  - The refusal consumes a record only on the file a migration's
    permission check is made on: a `cgroup.procs` (or `cgroup.threads`) of
    a cgroup v2 hierarchy (`s_magic`, a regular file, its kernfs name).
  - The stash is a plain hash map of 64 entries that never evicts; an
    insert it refuses is counted (`DENY_FAIL_OPEN`, the lookup half's
    slot) and the move goes through undecided. Every migration runs under
    `cgroup_mutex` (`cgroup_kn_lock_live()` before the lookup): at most
    one record is live at a time, so neither the review's one-entry map
    (R3) nor two concurrent movers can push a live record out.
  - The guard needs both functions in the kernel's BTF
    (`cgroup_procs_write_finish` too); without one it is not attached and
    the absence is signed.
  - **The boot's self-test** (`agent/src/boot/deny_selftest.rs`): right
    after the signal self-test, a child of the agent's binary, registered
    as a worker (protected, not exempt), and a second one, not registered,
    which writes the first one's pid to the `cgroup.procs` of a throwaway
    cgroup at the hierarchy's root (`northnarrow-move-selftest`). The move
    must be refused (`EPERM`): "move guard self-test: … refused — the move
    guard runs". A move done is the guard attached and not run, signed as
    a degradation (`move_guard_self_test`), as is an unmeasured test; the
    start goes on (the guard is an optional deny set). Its refusal is the
    boot's measurement, taken before the posture like the signal's.
- **What the attach does, in order:** the agent and the live watchdog
  registered (the watchdog's cgroup from the `PROTECTED_PIDS` entry that
  runs the installed binary, `cgroup_guard::cgroup_pids`), the values of
  their resource files with them (`LIMIT_VALUES`), the v1 policy armed, the FS deny hooks (the
  write deny among them), the move guard (refusal half, end-of-write
  clear, lookup half), the stale keys and values of earlier boots pruned.

### Systemd and the flows

Measured on the five lab guests (Ubuntu 22.04 / 249, Debian 12 / 252,
Ubuntu 24.04 / 255, Debian 13 / 257, Ubuntu 26.04 / 259; the lab script
`k273b-flows.sh` and the tamper check):

| flow, outside a window unless said | what systemd does | with lot 273b |
|---|---|---|
| `systemctl set-property --runtime` of a limit (raise or lower) | answers 0 and prints nothing on every version; logs the refused cgroup write at debug level only; sets its own copy of the property first (`systemctl show`: the new value) | the cgroup keeps its value (`cgroup_limit`), the drop-in is not written (`create`), both signed as one relayed attempt; systemd's copy stays until the next `daemon-reload` (residual) |
| the same, persistent (C85) | as above, under `/etc/systemd/system.control` | refused the same |
| `set-property` inside a window | applied, the drop-in written | stays after the window: the values are registered again at its close, systemd's next write-back is let through; taken back in another window |
| `daemon-reload` | 249, 252, 255 and 259 write every unit's attributes again (the unit's values, a newline appended); 257 writes none | let through (the value the file held, its newline cleared) |
| `daemon-reexec` | as a reload | let through |
| a unit of the agent's slice started and stopped (C86) | 254 and 255 thaw the slices (`0` to `system.slice/cgroup.freeze`); every version rewrites the siblings' xattrs | let through (lot 273 refused them) |
| a transient scope with the agent's pid (C77a: `StartTransientUnit`, `PIDs=`) | answers with a job | the move refused (`cgroup_move`, lot 273's guard); the agent stays in its unit |
| `AttachProcessesToUnit` with the agent's pid (C77b) | | refused the same |
| a unit with `Conflicts=northnarrow-agent.service` started (C78a) | queues the agent's stop job | its signals refused; the agent keeps running, systemd records the unit stopped (residual) |
| `systemctl isolate` of a target without the units (C78b) | 249 and 259 queued their stop jobs (the unit recorded dead, the agent running); 255 and 257 did not | no stop job (`IgnoreOnIsolate=yes`) |
| `systemctl soft-reboot` (254 and later) | stops the units, signals the rest itself | refused; both survive, the new userspace's systemd does not start them again: `failed` on 255 and 257 (residual, unchanged since before lot 273); on 259 the stop jobs record them stopped and the soft-reboot waits about 90 s |
| re-key (`uninstall.sh`, then `install.sh` with a new key) | | as before (`uninstall-check`, `install`) |

### Cost

Measured on Ubuntu 24.04 (6.8, the lab guest, 4 vCPU), the lot's code
installed, real workloads with every program attached (A) and with the
move guard's three links (B1) or the write deny's link (B2) removed inside
a window, three alternated rounds, medians:

| workload | A | B1 (no move guard) | B2 (no write deny) |
|---|---|---|---|
| `git status` ×10 on the lab's source tree | 109 ms | 88 ms | 96 ms |
| `find /usr -xdev` ×3 | 833 ms | 795 ms | 799 ms |
| a 2,000-file package installed and removed (`dpkg`) | 1,232 ms | 1,273 ms | 1,134 ms |

Per call (`kernel.bpf_stats_enabled`, `run_time_ns` / `run_cnt` over one
round of the workloads): `cgroup_move_deny` (`inode_permission`) 58.5 ns
over 417,739 calls, `protected_write_deny` (`file_permission`) 95.6 ns
over 102,132, `protected_open_deny` (`file_open`, lot 273b's resource
files added) 219.5 ns over 55,108. The move guard costs path-heavy work
(`git status` +24 %; `find` +5 %, the rounds' spread), the write deny
write-heavy work (the package +9 %); the incremental build the script
timed did not run on the guest (`--offline`: 12–23 ms), and is not
counted. The microbenchmark (`nn-lab.sh overhead 2`, agent off/on): open
+41.0 %, wopen +40.9 % (lot 273: +37.0 %, +36.3 %), exec, connect, udp,
dns within the noise. Signed in the capability manifest with the
`fs_protect` source's terms (`overhead`).

### Residual

- **A refused `set-property` still changes systemd's own copy of the
  property.** systemd sets the unit's property in memory before it writes
  the drop-in and the cgroup; both refused, `systemctl show` reports the
  new value until the next `daemon-reload`, and the unit's next start
  applies it to the fresh cgroup, before the agent is there to refuse it
  (measured on 252 and 257: `MemoryHigh=2G` refused, the agent restarted
  inside a window got `memory.high` 2 GiB). Outside a window nothing
  restarts a unit (its stop and its kill are refused) but a crash or an
  operator's maintenance; a reboot, a soft-reboot or any `daemon-reload`
  (no window needed) takes systemd's copy back. The refusal is signed
  (`cgroup_limit`, `create`: a relayed attempt), and the operator's step
  is a `daemon-reload` before the next restart
  (`INSTALL_UPGRADE_UNINSTALL.md` §3.7); a unit that already restarted
  with the value keeps it on 257, whose reload writes no attribute, until
  it is restarted again inside a window after the reload. Lot 273c could have the agent
  answer the refusal with that reload itself.
- **A soft-reboot** (`systemctl soft-reboot`, systemd 254 and later) is
  not a shutdown: no `systemd-shutdown` runs, PID 1 stops the units and
  signals the rest itself, and the hooks refuse it. The agent and the
  watchdog survive it with their pids, their pins and their links (no
  gap in the protection), and the new userspace's systemd does not start
  either unit again. On 255 and 257 both are `failed` ("Will not start
  SendSIGKILL=no service … while processes exist": `SendSIGKILL=no`, by
  design never a second instance beside the running one), the watchdog's
  unit retried with a failure record each time. On 259 the stop jobs
  record both units stopped with their processes running ("Deactivated
  successfully") and the soft-reboot waits about 90 s on the refused
  final signals (1 min 35 s in all); the lab guest's units are not
  enabled there, so the new userspace did not try to start them. Measured on 255 and 257 the same with the code before lot 273
  (#482's merge), with lot 273 and with this lot: it comes from external
  audit EBPF-001's refusal of PID 1's signals, not from the cgroup guard.
  A reboot ends it cleanly.
  Lot 273c: the agent and the watchdog end themselves at a soft-reboot's
  stop job, as at a shutdown, or survive it the way systemd provides
  (`SurviveFinalKillSignal=`), measured per version.
- **A stop systemd propagates from another unit** (one with
  `Conflicts=northnarrow-agent.service`, tamper case C78a; a stop of
  `system.slice`, C78c, is the same job and was not run on the lab:
  the guests' `sshd` is in that slice). It is not a manual stop, so
  `RefuseManualStop=` does not refuse it: its signals and its cgroup
  kill are refused and the agent keeps running, but systemd records the
  unit as stopped and will not start it again while its processes exist
  (measured on 255 and 257). The agent detects and refuses as before;
  `systemctl status` says `inactive`; the next start is the operator's,
  inside a window, after the process ends.
- **Other controller files.** `cpuset.cpus` / `cpuset.mems` (the agent
  pinned to one busy CPU), `cpu.uclamp.max`, `memory.swap.max`,
  `memory.low` / `memory.min` of a sibling, `io.weight` and the like are
  not in the set: none kills the agent or stops it; some slow it. They
  are neither refused nor read by the integrity round (which reads the
  agent's `memory.max`, `memory.high`, `pids.max`, `cpu.max` and
  `cgroup.freeze`).
- **A hybrid or legacy host** (systemd writes its own v1 hierarchy): no
  v1 write is refused, a signed degradation; `cgroup_no_v1=all` does not
  apply there. **Another architecture than x86-64**: the syscall's
  arguments are not read, so every PID 1 write of a resource file is
  refused (systemd logs its failed write of its own value at a reload), a
  signed degradation.
- **A shared writable mapping** of a protected regular file opened before
  its registration writes through the page cache, not through a write
  call: `file_permission` does not see it. Only a process that ran before
  the agent's first start could hold one (the cgroup files cannot be
  mapped).
- **The fresh cgroup at a restart** (lot 273's residual, narrowed): a
  descriptor opened in the interval is refused at its write now; a write
  made in the interval itself (the new watchdog's first milliseconds,
  before it registers its cgroup) is not.
- **The move guard's cost** on path-heavy work stays (lot 273: about
  −10 % on the open microbenchmark): no cheaper attach point exists in
  the migration's path.
- **The lab script's C08** puts PID 1 back out of `PROTECTED_PIDS` after
  the lab's observe-mode BPF guard let the case's `bpftool map update`
  through (a release build refuses it); its `--selftest` does not check
  that restore (mutation MD9): the lab does — without it C12 deviates.

## Lot 273c — another process's limits and priorities, PID 1's memory, floors, systemd's copy, the host's drop-ins

**Goal.** What the review of #490 found beyond lot 273b's scope: ways to
stop or starve the agent that no cgroup file and no signal carries, the
trust lot 273b put in PID 1's write-backs, and what a registration takes
for granted.

### What it closes

- **Another process's change of the agent's limits and priorities.**
  Between two root processes the kernel checks no capability: `prlimit
  --pid <agent> --cpu=1:1` set a hard `RLIMIT_CPU` below what the agent
  had used, and the kernel's own SIGKILL — no `task_kill` hook sees it —
  ended it; `--nofile=0`, `--memlock=0`, a small `--as` break it;
  `chrt --idle`, `taskset` to one CPU, `renice +19`, `ionice -c 3`
  starve it. Four new deny hooks refuse them outside a window
  (`agent-ebpf/src/task_limits.rs`): `task_setrlimit` (`prlimit`),
  `task_setscheduler` (`sched_setattr`, `sched_setscheduler`,
  `sched_setaffinity`, `timerslack_ns`), `task_setnice` (`setpriority`)
  and `task_setioprio` (`ioprio_set`) — when the target is protected (or
  runs the agent's binary), the caller neither exempt nor the target
  itself (a process sets its own: the agent's workers do), signed
  `rlimit`, `sched`, `nice`, `ioprio`. A refused limit is decisive
  (COMBAT, as a kill); a refused priority is an impairment (ENGAGED): a
  tuning daemon (`tuned`, `numad`) applying a host-wide profile meets it
  too, and the ladder must not kill it. Twenty-one deny hooks.
- **PID 1's memory.** Lot 273b lets PID 1 write back a unit's resource
  values and thaw a slice on the bytes its `write(2)` carries, read in
  `file_permission`; the kernel copies them again afterwards. A PID 1
  whose memory root could write — a tracer, `/proc/1/mem`,
  `process_vm_writev` — could swap them in between. The ptrace hook now
  refuses attach-mode access to PID 1 outside a window (signed `ptrace`,
  target 1); read-mode access (`ps`, `/proc/1/environ`, `/proc/1/maps`)
  is untouched, and a window lets a debugger attach.
- **Floors.** A registration took the value a file held as the one PID 1
  may write back: at a start, the fresh cgroup's (systemd fills it from
  its own copy of the unit — a refused `set-property` stays there, in
  memory, until a reload); at a window's close, whatever was written
  inside it. Now a value below its floor is not registered: the floor is
  registered first, then written to the file, then read back (PID 1 cannot
  put the hostile value back in between, its write is no longer the
  registered one), and the restoration is a signed drift
  (`limit_floor_restored`; `antitamper-bpf/src/cgroup_floors.rs`). The
  floors: the agent's unit at least 512 MiB of memory, 256 tasks, half a
  CPU; the watchdog's what its unit sets (32 MiB, 8 tasks, 10 % of a CPU);
  a slice 1 GiB, 1024 tasks, one CPU, room for 4096 cgroups 8 deep;
  everywhere `cpu.weight` 100, `cpu.weight.nice` 0, no `cpu.idle`, no
  `memory.oom.group`, no `io.max` limit, an I/O weight of 100; a unit's
  `cpuset.*` its parent's. The watchdog applies them to the agent's fresh
  cgroup at its start and after every respawn — a `memory.max` that
  OOM-kills the agent before its attach is the watchdog's to restore.
- **systemd's copy of a refused `set-property`.** The agent asks systemd
  for a `daemon-reload` — a SIGHUP to PID 1, once PID 1 is found serving
  systemd's private socket (`SO_PEERCRED`); signed `systemd_reload` —
  when PID 1's write of a protected resource file or its new drop-in is
  refused (at most one every 30 s, a later one kept for after the
  interval, not dropped; one per target per 10 minutes: a unit whose own
  file sets a value below a floor would loop), when a window opens
  (before the maintenance restarts a unit). Not `Manager.Reload()` on the private socket: systemd lets a
  caller reload at once only with `CAP_SYS_ADMIN`, which the agent's unit
  does not grant, and asks polkit for any other — the lab's round 4
  (Ubuntu 24.04, systemd 255) saw each call wait its whole 30 s timeout,
  and systemd reload only when the agent closed the connection ("Failed
  to send queued message … Transport endpoint is not connected", 30
  times). Root signals PID 1 without a capability.
- **The host's drop-ins, judged by their value for our units** (the
  review of #492, C1). `service.d/*.conf` reaches every service, ours too;
  `slice.d` and `system.slice.d` the slice they run in — from every
  directory of the unit search path. What is there is the host's
  configuration for every other service as well (a global `LimitNOFILE`, a
  Kubernetes node's `system.slice` reservation, a hardening
  `SystemCallFilter`, an allocator's `LD_PRELOAD`), so nothing there is
  moved, written or deleted (`crates/nn-linux/src/host_dropins.rs`): the
  integrity round judges each directive by what its value does to our
  units — a resource limit below their floors (the floors table above: a
  service drop-in against both units', a slice drop-in against the
  slice's), a finite CPU / address-space / data / file-size limit, fewer
  than 1024 open files or 64 KiB of locked memory, a nice value above 0,
  an idle scheduling or I/O class, a narrower CPU set, a kill or OOM
  semantics other than ours, a condition that fails (or one not evaluated
  here), an exec line, an `NN_` / `LD_` / `RUST_` / `MALLOC_` / `GLIBC_`
  variable, another slice or user, another root, a mount over our paths —
  and signs each such directive as `unit_dropin_harmful` while it is
  there. Our units' values are held meanwhile by the deny hooks (PID 1's
  write of a value other than the registered one is refused) and put back
  to their floors at every registration. Any other drop-in there is the
  `unit_dropin` alert, as before (now `slice.d` and `system.slice.d` too).
  A drop-in the host had before the install is judged the same and never
  touched; moving one would take a signed overlay listing what may be
  quarantined — the only opt-in the design allows, not part of this lot.
  The lot's first version moved every drop-in that named one of ~95
  directives whatever the value, and asked a reload: on a customer host
  that stripped the host's configuration from every service. While a
  harmful one is on disk, the agent asks systemd for no reload (signed
  `systemd_reload` `withheld`): a reload would load it into systemd's
  copy, and inside a trusted-installer window — where PID 1's writes are
  let through — onto our units' cgroups. The lab's round 7 measured it:
  with a `MemoryMax=4K` on `system.slice.d` still on disk, the reload the
  agent asked at a window's opening set the slice to 4 KiB, and the
  agent, the watchdog and journald were killed.
- **cgroup v1, narrowed.** Lot 273b refused every v1 write where systemd
  runs the unified hierarchy, an old container's `name=systemd` hierarchy
  too. Now only a hierarchy that binds a controller (`subsys_mask`, read
  through the superblock's kernfs root: six optional BTF offsets) and
  only its `cgroup.procs`, `tasks` and `freezer.state` — what moves or
  freezes a process. A named hierarchy moves and freezes nothing.
- **More resource files.** `cpuset.cpus`, `cpuset.mems`,
  `cpuset.cpus.partition` (the agent pinned to one CPU a real-time hog
  owns), `memory.reclaim` (a forced reclaim, repeated: a thrash; never
  PID 1's either), `io.weight`, `io.bfq.weight`.
- **The write deny's cost.** `file_permission` leaves at once on a
  socket, a pipe or a tty — most writes of a busy host — before its map
  lookup: no protected file, cgroup file or proc file is anything but a
  regular file.
- **PID 1's verdict and the files' classification, judged on the host.**
  The review's own mutations of lot 273b's write deny that no host test
  saw: a `return false` before PID 1's comparison (P2: PID 1 writes any
  value; only the lab's `set-property` flow, C85, caught it) and the
  superblock's magic masked to 16 bits (P3: every cgroup and proc file
  left unjudged). Both decisions are now the shared module's pure
  functions, which the eBPF program calls and the host's tests judge
  (`northnarrow_common::cgroup_limits::init_write_lets_through`,
  `special_fs`), and `xtask/tests/cgroup_guard.rs` pins PID 1's arm whole
  and the magic read as it goes to the classification: P2 and P3, and
  three variants of each, are caught.

### Systemd and the flows

Measured on the five lab guests (Ubuntu 22.04 / 249, Debian 12 / 252,
Ubuntu 24.04 / 255, Debian 13 / 257, Ubuntu 26.04 / 259; rounds 4 and 5
of the lot, the tamper check):

| flow, outside a window unless said | with lot 273c |
|---|---|
| `prlimit --pid <agent>` (`--cpu`, `--nofile`, `--as`, `--memlock`), `renice`, `chrt`, `taskset`, `ionice` of a protected process (C89–C94) | refused (`rlimit`, `nice`, `sched`, `ioprio`), signed; any other process unchanged; the agent's workers set their own |
| a tracer on PID 1, `/proc/1/mem` for writing (C95, C96) | refused (`ptrace`, target 1); inside a window the tracer attaches (C95b) |
| `ps`, `top`, `lsof`, `/proc/1/environ`, `/proc/1/maps`, `/proc/1/fd` | untouched (read mode) |
| `/proc/1/stack`, `/proc/1/syscall`, `process_vm_readv` and `pidfd_getfd` on PID 1 | attach mode in the kernel: refused outside a window, like a tracer |
| `daemon-reexec`, a systemd package upgrade (its maintainer script reexecs) | let through: PID 1's exec is not refused (residual) |
| `systemctl set-property` of the agent outside a window (C100) | refused at the cgroup file and the drop-in, as in lot 273b; systemd's copy taken back by the agent's reload (a SIGHUP to PID 1): systemd's `MemoryHigh` back to the unit's own value before the case's 75 s on the five (`systemd_reload` signed; on #490's head it stayed at 2 GiB) |
| `set-property` inside a window, the window closed (C98) | the value kept if at or above its floor; `memory.high` 100 MiB restored to 512 MiB at the close, signed `limit_floor_restored` |
| the agent restarted inside a window with systemd's copy below the floor (C102) | the fresh cgroup restored to the floor, by the watchdog's check of the respawned agent or by the agent's registration, signed: OK on the five (Debian 13 in round 6); the agent's own registration restored it first each time. On #490's head the fresh cgroup kept 100 MiB, the agent throttled — not up within the case's minute |
| a window opened | systemd reloaded (`systemd_reload`, "a trusted-installer window opened"); withheld while a harmful host drop-in is on disk |
| the host's drop-ins (C97): `LimitNOFILE=1048576` and `SystemCallFilter=~@obsolete` in `service.d`, `MemoryMax=4K` in `system.slice.d`, the host's `daemon-reload`, then a window opened | the three left in place; the slice's 4K refused at its `memory.max` (PID 1's write), signed `unit_dropin_harmful` within a round; the other two an alert only (`unit_dropin`); the agent's reloads withheld, the window's too: the slice keeps its value inside it |
| an operator's own `daemon-reload` inside a window, a harmful host drop-in on disk | applied (PID 1's writes are let through inside a window): remove the drop-in first (residual) |
| a named cgroup v1 hierarchy (`name=…`, no controller; C99) | a move in it let through (lot 273b refused it); a freezer hierarchy refused (C83) |
| `memory.reclaim` of the agent's unit (C101) | refused (`cgroup_limit`), PID 1's too |

### Cost

Measured on Ubuntu 24.04 (6.8, the lab guest, 4 vCPU), lot 273b's script
with `kernel.bpf_stats_enabled=0` for the timed rounds (the review of
#490: the stats add two clock reads to every call, and lot 273b's rounds
had them on): every program attached (A), the move guard's three links
removed (B1), the write deny's link removed (B2), three alternated rounds,
medians:

| workload | A | B1 (no move guard) | B2 (no write deny) |
|---|---|---|---|
| `git status` ×10 on the lab's source tree | 98 ms | 87 ms | 85 ms |
| `find /usr -xdev` ×3 | 770 ms | 752 ms | 754 ms |
| a 2,000-file package installed and removed (`dpkg`) | 1,123 ms | 1,102 ms | 1,076 ms |

The rounds' spread is of the same order (A's `git status`: 83–100 ms):
the move guard costs about +13 % on `git status` (lot 273b, the stats on:
+24 %), `find` +2 % (+5 %); the write deny the package +4 % (+9 %). Per
call (the stats on for one round only, `run_time_ns` / `run_cnt`):
`cgroup_move_deny` 61.9 ns over 418,082 calls, `protected_write_deny`
96.3 ns over 102,218, the FIM's `fim_write_intent_observe` on the same
hook 95.8 ns, `protected_open_deny` 266.4 ns over 55,134. The write
deny's new exit on a file that is not a regular one, measured on its
own (the stats on, `k273c-pipe.sh`: 400,000 to 880,000 calls each): a
write to a pipe 100.3 ns, to a socket 90.7 ns, to a regular file 221.7 ns
(the lookup and the magic); the FIM's program on the same calls, which
has no such exit, 178.4, 153.9 and 167.4 ns. The four
task hooks run only on a `prlimit`, `setpriority`, `sched_set*` or
`ioprio_set` (802–809 instructions each), nothing on the hot path.

Not done, and why:

- **One program for the write deny and the FIM's on `file_permission`**
  (the review's second suggestion). The write deny is a deny hook: pinned,
  its link removed and restored only by a window, its absence a refused
  start, its self-test at every boot. The FIM's program follows the FIM
  sensor's configuration (a host without FIM paths, a sensor turned off).
  One program would either tie a deny hook's presence to the FIM's
  configuration or keep the FIM's observation attached where it is off,
  for at most one trampoline entry and one `f_inode` read a call.
- **A signed "workstation" policy that detaches the move guard** (the
  review's desktop recommendation: the guard on by default, an explicit
  opt-out, a recovery at `cgroup_procs_write_finish` instead). It needs a
  new signed overlay kind, its `nn-admin` verbs, the kernel recovery path
  (the destination protected at once, the process moved back) and its
  own review; the guard stays on everywhere, and the cost above is what
  it costs.

### Residual

- **`daemon-reexec` into a modified systemd binary** is not refused:
  refusing PID 1's exec leaves the host without an init. The binary
  (`/usr/lib/systemd/systemd`) is in the FIM's default watch list
  (`configs/fim-paths.v1`), and a root that replaces it can do what PID 1
  does: write back the values registered for the units, no other.
- **PID 1's memory before the agent's first attach** (the initrd, the
  early boot) is not protected; the attach-mode refusal begins with the
  agent's start.
- **A tuning daemon's host-wide profile** (`tuned`, `numad`, `irqbalance`'s
  affinities) does not reach the protected processes: refused and signed
  each time (ENGAGED, never COMBAT); every other process takes it.
- **A harmful host drop-in and an operator's reload inside a window.**
  The agent withholds its own reloads while one is on disk, but an
  operator's `daemon-reload` (or a unit's restart) inside a window applies
  it to our units' cgroups, the slice's included: remove it before the
  maintenance. Lot 273d: floors held inside a window too, and
  `northnarrow.slice`.
- **A harmful host drop-in stays on disk.** Its value is refused at our
  units' cgroup files and put back to the floors at every registration,
  but a process setting (a `LimitNOFILE`, a `Nice`, an `ExecStartPre`) or a
  slice value at boot reaches our units' next start before the agent is
  there: the signed `unit_dropin_harmful` says so each round, and the
  operator removes it (inside a window, for a drop-in of ours). Lot 273d:
  a slice of the units' own (`northnarrow.slice`), which `system.slice.d`
  no longer reaches, and the signed opt-in list for a quarantine.
- **The reload is asked, not awaited.** systemd reloads after the SIGHUP
  (about a quarter of a second on the lab); a second refusal within 30 s
  waits for the interval, a refusal of the same file within 10 minutes
  asks none (a unit whose own file sets a value below a floor would
  loop): systemd's copy of a repeated `set-property` can stay until the
  next reload or window, and the fresh cgroup of a restart in between
  takes it — the floors still apply (the watchdog's check after a
  respawn, the agent's registration at its start).
- **Other controller files.** `cpu.uclamp.max`, `memory.swap.max`,
  `memory.low` / `memory.min` of a sibling are still not refused: none
  kills the agent or stops it; some slow it.
- **Starvation from outside the units' settings** — real-time hogs on
  every CPU, a saturated disk — is not a setting of the agent's: the
  watchdog's supervision and the integrity round's stall check
  (`STALL_SLACK_SECS`) see it, no hook refuses it.
- **A hybrid v1 host** (systemd writes its own v1 hierarchy): no v1 write
  is refused there, signed as an `anti_tamper` degradation in the
  capability manifest at every start (lot 273b's, unchanged); the
  narrowing above applies where systemd runs the unified hierarchy.
- **A soft-reboot** behaves as lot 273b measured it (outside this lot).
- **Fail-open.** A task hook that cannot read its target's tgid lets the
  change through, counted in its `DENY_FAIL_OPEN` slot and signed.

## Lot 277 — an exemption by cgroup is the cgroup's start, not its membership

The per-rule policy may exempt an actor from a rule by its cgroup v2 path
or its systemd unit (`docs/operator/RULE_POLICY.md` §2.1). Membership of a
cgroup is not identity: root writes its own pid into an exempt service's
`cgroup.procs` (or starts a child there with `clone3(CLONE_INTO_CGROUP)`)
and is then "in" the service — exempt from the rule, killed by nothing.
Since lot 277 such an exemption holds only for a process **started** in
the cgroup: spawned into it by systemd, or forked from a process that
was.

### Mechanism

The kernel decides, not a walk of the lineage afterwards. A walk cannot
tell a process that a moved process forked and left (reparented to PID 1:
the orphan of the review of 03/11) from a forking daemon's own child. The
eBPF programs of `agent-ebpf/src/cgroup_join.rs` keep the pinned map
`CGROUP_JOINED` (thread-group id → its leader's start time, how, by whom):

- `cgroup_join_mark` (BTF tracepoint `cgroup_attach_task`, which fires
  after a move through `cgroup.procs` / `cgroup.threads` went through)
  marks the moved process, unless the move is systemd's placement. That
  is a move PID 1 makes, or the move a child of PID 1 makes of itself
  while it still runs PID 1's image (the same `mm->exe_file` as its parent:
  it executed nothing since the fork; a reparented orphan of another
  process does not share it). It does not mark a move that changes
  nothing: `cgroup_join_src` (fexit `cgroup_procs_write_start`) records,
  for a process moving itself, its cgroup before the move. The agent's
  family is not marked: it moves processes into its containment cgroups,
  which no exemption may name.
- `cgroup_join_born` (fentry `cgroup_post_fork`) marks a child started by
  `CLONE_INTO_CGROUP` by anyone but PID 1, before it runs.
- `cgroup_join_fork` (BTF tracepoint `sched_process_fork`) marks a new
  process forked by a marked one, before its first wake-up. The parent's
  mark counts only with its leader's start time: a dead process's mark at
  a reused id passes on nothing.
- `cgroup_join_exit` (BTF tracepoint `sched_process_exit`) removes the mark
  when the group's last thread exits (`signal->live` 0), not with its
  leader, which may exit first.

The exemption check (`nn_core::decision::rule_policy::exempt`) asks
`ActorFacts::started_in_cgroup` once a cgroup or a unit matched. The
agent's answer (`nn_linux::cgroup_join`, on the errands thread) is the
map's: not marked, marked, or not known. Not known means no tracker on
this kernel, a mark the map could not take, or a failed lookup. Marked and
not known refuse the exemption. A move into a cgroup an exemption names
(the policy's cgroup paths and unit names, hashed into
`CGROUP_EXEMPT_NAMES`) is signed as NN-L-AT-001 `cgroup_join`. It is not
refused, and the posture is not raised: the move is no tamper with the
agent, and what the moved process does is judged without the exemption.

Every move runs under `cgroup_mutex` and `cgroup_threadgroup_rwsem`, from
the lookup to the tracepoint, and a fork takes the rwsem: a fork after a
move sees the mark.

### Residual

- **Root changes the unit itself.** A drop-in that rewrites `ExecStart=`,
  a transient unit given the exempt unit's name where none is loaded,
  systemd asked over D-Bus to attach a process (`AttachProcessesToUnit`):
  these are systemd's placements, and the unit exemption trusts the
  unit's definition. An exemption by `exe … sha256` binds to the program.
- **A move while no agent runs** (before its first start, between a stop
  and the next start): the programs are attached by the agent, not
  pinned. The marks are pinned and outlive a restart; the start removes
  those of processes gone meanwhile.
- **A start by `CLONE_INTO_CGROUP` is marked, not signed**: the fork path
  gives no destination path to match.
- **A full map** (32768 live marked processes; container runtimes' and
  user managers' processes are marked too) refuses every exemption by
  cgroup or unit until the host reboots: the counter is pinned, so no
  mark is lost in silence.
- **systemd 255 without `CLONE_INTO_CGROUP`** (a glibc older than 2.39):
  PID 1 moves the executor it spawned, a placement. If the executor's own
  move came first, the executor had already executed: that move marks
  it, so the unit's processes lose their exemption (fail closed, a false
  refusal). Not measured in this lot: its guests ran systemd 249
  (Ubuntu 22.04, the fork path) and 257 (Debian 13, `CLONE_INTO_CGROUP`),
  and both kept the exemption of a unit systemd started.
- **A container or workload context**: any future exemption by container
  or workload follows the same rule. A process counts as the workload's
  when the workload's runtime started it there, never because its cgroup
  says so.
