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

## Lot 273d — the units' own slice, a confirmed reload, systemd's copy before a respawn, our drop-ins at a window's close, the critical sysctls

**Goal.** The follow-ups of the review of #492 and of its focused re-check:
what lot 273c left to the next registration or to an operator, and the
precision its first judge of the host's drop-ins lacked.

### What it closes

- **A slice of the units' own** (`deploy/systemd/northnarrow.slice`; both
  units `Slice=northnarrow.slice`). `system.slice.d/*.conf` — the host's
  settings for its system services, a node's reservation, a limit an
  attacker drops there — no longer reaches the agent and the watchdog; a
  slice's `slice.d` still does (every slice), judged as before. The
  slice's own drop-in directories (`/etc`, `/run`, both `system.control`)
  are made empty by the agent's unit and registered NOCREATE like the
  units'; the slice file is protected like the unit files; the slice
  refuses a manual stop and ignores an isolate (`RefuseManualStop=`,
  `IgnoreOnIsolate=`: `systemctl stop northnarrow.slice` would stop both
  units). Evaluated sound: the protections are registered by walking the
  unit's cgroup path upwards (the slice is the units' parent wherever it
  is), the floors follow the directory's name (a slice's floors), the
  properties read from systemd name the agent unit's `Slice=`, COMBAT's
  spared system units accept the slice's path, and an upgrade leaves no
  stale registration of `system.slice` — every boot prunes the keys it
  did not register. `install.sh` stages, switches and rolls back the slice
  with the units; `uninstall.sh` and the packages carry it.
- **A confirmed reload** (`antitamper_bpf::systemd_bus::reload_verified`,
  shared with the watchdog). The SIGHUP is sent on a connection to the
  private socket opened before it — subscribed to the manager's signals
  without asking — and the reload counts once systemd's `Reloading(false)`
  arrives; none within 30 s (systemd refuses a reload with less than 16 MB
  free on `/run`, and from 253 past its `ReloadLimit*`) is a signed
  `failed` and a degradation (`systemd_reload`), never "requested".
- **systemd's copy read back** (`antitamper_bpf::unit_props`: the units'
  and the slice's `MemoryMax`, `MemoryHigh`, `TasksMax`,
  `CPUQuotaPerSecUSec`, `CPUWeight`, `IOWeight`, over D-Bus without
  authorization, against the floors). A second refusal of the same file
  within the 10-minute quiet is verified instead of skipped: a copy still
  below the floors is reloaded (after the 30-second interval), unless a
  confirmed reload already found it set by the units' own files — the
  loop the quiet was for, now a signed degradation while it holds.
- **The watchdog before each respawn** (`check_systemds_copy`). A
  `memory.max` of one page in systemd's copy killed the agent at its exec,
  before any check of its fresh cgroup, and the next respawn took it
  again. Now the watchdog reads systemd's copy of our units before the
  start that applies it; a copy below the floors is reloaded (confirmed,
  read again) unless a harmful host drop-in is on disk, and what it found
  is a hold record the agent signs (`systemd_copy_below_floor`).
- **Back to the configured value after a floor.** A file restored to its
  floor kept it until the next window's close (its configured value, an
  11 GiB `memory.max`, was a refused write meanwhile). After a confirmed
  reload — systemd's copy is the units' files again — each file at its
  floor whose configured value is not below the floor is written with it
  and its unit's values registered again
  (`cgroup_guard::back_to_configured`).
- **Our own drop-ins at a window's close** (`crates/nn-linux/src/own_dropins.rs`).
  A drop-in made or changed inside a window in our units' or slice's
  directories (a `set-property` writes `50-<Property>.conf` under
  `system.control`) stayed after it, and a reload applied it. At the
  close each is judged as the host's are, against its own unit's floors
  and semantics: a harmful one is moved to the quarantine — these are our
  units' files, not the host's — the move is in the window's signed close
  record (`dropins_quarantined`), and systemd reloads (at most one every
  30 s: the review's rate limit, which the host's drop-ins no longer
  need — they are never moved). `install.sh`'s own drop-ins are known by
  their content and left. The review of #497 (D4): an entry is selected
  by its ctime (no `touch -d` sets it back; a new hard link or a rename
  moves it), never by its mtime; a symlink (systemd follows it to a target
  outside our directories), a hard link and an `EnvironmentFile=` outside
  `/etc/northnarrow/` are quarantined whatever they set (a symlink kept as
  its target's name, the target never touched); and the integrity round
  judges our directories again outside a window, the same way, each move
  a signed `own_dropin_moved` and a reload asked. The unit now makes
  `/etc/systemd/system/northnarrow-agent.service.d` too (NOCREATE on every
  host; it was install.sh's on Debian or with `--cow-guard` only). The
  re-review of #497:
  - **RR1, a kept drop-in is write-protected.** The directories are
    NOCREATE, which refuses a new entry but not a rewrite of one already
    there: a harmless `50-CPUQuota.conf` kept at a close could become
    `ExecStartPre=…` outside a window and be applied at the next boot,
    before the agent runs. Every entry a close or a round keeps (a
    regular file with one name), and the file an `EnvironmentFile=` of it
    names under `/etc/northnarrow/`, get `FS_PROTECT_WRITE |
    FS_PROTECT_MUTATE` in the pinned protected-inode map, added to what
    the key had (`own_dropins::Protector`); a window lifts it as it lifts
    every protected file's. A key a pass registered whose path no longer
    names it is taken out at the pass's end, so a freed inode number never
    protects another file (keys the boot registered are never taken out
    by a pass). An `EnvironmentFile=` under `/etc/northnarrow/` counts
    only when its file is a regular file with one name, there, and its
    protection registered (`..` never leads out of the directory);
    otherwise the drop-in is quarantined like one outside it.
  - **RR2, an operator's drop-in is never moved silently.** The round
    judges only what changed (ctime) since the agent was installed — its
    binary's ctime (`own_dropins::install_time`; the binary is a
    protected file) — so a drop-in the operator had before the install
    is never moved by it. `install.sh` (full mode) asks the new agent
    which existing drop-ins it would quarantine (`northnarrow-agent
    --own-dropins check`, read-only, run where the tree's `--version` is:
    inside the window, or with no agent to judge the exec), lists them
    and refuses before anything changes, unless the operator passes
    `--accept-dropin-quarantine` (the agent's `--own-dropins quarantine`
    moves them, each move printed). A package upgrade runs no check: the
    round leaves those drop-ins, the integrity round reports them.
  - **A drop-in of ours written inside a window no longer costs its
    writer's life** (round 17's C111). NN-L-FIM-009 killed whoever wrote
    under `/etc/systemd/system/` except our unit files themselves, even
    inside a signed window — an operator's `systemctl edit
    northnarrow-agent` or a `cp` back from the quarantine was killed. Its
    §15.1 exemption now covers our units' drop-ins too
    (`is_own_unit_dropin`: `<unit dir>/<one of our four .d
    directories>/<name>.conf`, one level, no `.`): inside an open window a
    Log/Low, judged at the close; outside one, or another unit's drop-in,
    still a kill. The short re-check of #497: the rule reads the window
    when it runs (`is_active_at(now)`), not at the event (NB4) — an event
    queued past the close kills a writer the window allowed, and one just
    before the opening is a Log — the same as for our unit files. The
    exemption covers the vendor directory too (`/usr/lib/systemd/system/
    <ours>.d/`, NB3): there the close and the round cannot move anything
    (`ProtectSystem=strict` keeps `/usr` read-only to the agent: signed
    `own_dropin_not_moved`), and that directory is not NOCREATE (the
    package's own) — a drop-in written there inside a window stays.
  - **The short re-check of #497.** A harmful drop-in from before the
    install — a package's configure step runs the check only as a warning
    (`install.sh --package-configure`) — is never moved by the round, and
    each one is now a signed `own_dropin_preinstall_harmful` with the
    remedy (RB1). Without the protected-inode map a `Protector` holds
    nothing, fail-closed (an environment file under `/etc/northnarrow/` is
    then not held, its drop-in quarantined; a map that cannot be opened is
    the signed `own_dropins_unprotected` degradation), and a round that
    cannot read the install time says so, signed (`own_dropin_round_skipped`)
    — NB6. A relabel of the agent's binary (SELinux `restorecon`, a
    `chcon`) changes its ctime, so the round's "since the install" moves
    forward: drop-ins changed between the install and the relabel are no
    longer judged by the round — the pre-install report names the harmful
    ones (declared). **`NN_` settings are configuration** (the
    coordinator's decision): in our units' drop-ins an `NN_` variable is
    no longer harmful — the drop-in is kept (and write-protected) and the
    agent signs each setting (`own_dropin_setting`; a weakening switch,
    the agent's own list plus a sensor's fallback and `NN_EXEC_POLICY=off`
    in `WEAKENING_DROPIN_EXTRA`, a High `own_dropin_weakening`); a loader
    variable stays harmful, and `install.sh` lists `NN_` settings as kept
    configuration. The last review of #497: the system tools the agent
    runs (`iptables-restore`, `rpm`, … through `SystemBin`) get a fixed
    minimal environment (the unit's `PATH`, `LANG=C`), never the agent's —
    and `XTABLES_LIBDIR`, `IPTABLES_LIB_DIR`, `RPM_CONFIGDIR` and
    `NOTIFY_SOCKET` are harmful in any drop-in that reaches our units
    (RC1); every `NN_` variable of the command line is classified as a
    weakening switch or a neutral setting, a test reads them (RC2, NC4);
    the exec policy names our slice `northnarrow.slice` (NC2). The units'
    own slice is a service tier for the exec
    policy, as `system.slice` was for them (`EXECPOL_SLICES[OURS]`, NB5: a
    regression of this lot's slice, fixed).
- **The judge, precise** (the re-check of #492). A slice's floors follow
  the host: memory a quarter of it, between 544 MiB (the agent's and the
  watchdog's together) and 1 GiB; a CPU share an eighth of the online
  CPUs, between half a CPU and one; tasks a quarter of the host's limit,
  between 264 and 1024 — a small VM's `MemoryHigh=80%`, a `CPUQuota=50%`
  are not below. Only `NN_` variables and `LD_PRELOAD`, `LD_AUDIT`,
  `LD_LIBRARY_PATH` are harmful (`MALLOC_ARENA_MAX`, `RUST_LOG`,
  `GLIBC_TUNABLES` are tuning). `CPUAffinity=` and `AllowedCPUs=` are
  compared with the online CPUs. The conditions are evaluated on their
  merits — `Virtualization` (systemd's own, over D-Bus), `Host`,
  `KernelCommandLine`, `Architecture`, `Security`,
  `ControlGroupController`, `User`, `Group`, `Capability`, `FirstBoot`,
  the path ones — and one not evaluated here is an alert, not harmful. A
  file's last assignment of a key is the one judged (a list's add up, an
  empty one resets them).
- **"Would break the agent"**, a separate signed warning
  (`unit_dropin_breaks_agent`), for the sandbox and capability settings
  of `service.d` that take what the agent uses: a `SystemCallFilter=`
  allow list (systemd merges it into the agent's deny list, in that
  list's mode: its calls are denied to the agent) or a deny list with
  `bpf`, `perf_event_open` or a group the agent needs; a
  `CapabilityBoundingSet=~` with one of its capabilities, or an empty one;
  `ProtectControlGroups=`, `ProtectKernelTunables=`, `ProtectProc=`,
  `ProcSubset=pid`, `PrivateNetwork=`, `PrivateUsers=`, `PrivatePIDs=`; a
  `RestrictAddressFamilies=` without `AF_UNIX`, `AF_NETLINK`, `AF_INET`,
  `AF_INET6`; `IPAddressDeny=any`. The reloads go on.
- **Visible while it holds.** A harmful host drop-in and a withheld or
  unconfirmed reload are degradations (`host_dropins`, `systemd_reload`)
  in `nn-admin status --key`, the capability manifest and the heartbeat —
  a false positive, which withholds the agent's reloads, is seen too — and
  are withdrawn when the condition ends (their signed records stay).
- **The warning at the grant.** A window granted while a harmful drop-in
  is on disk: `nn-admin trusted-installer-grant` reads the agent's signed
  status right after the grant (the agent judges the drop-ins at the
  grant) and prints, before the operator works, that a `daemon-reload`
  inside the window will kill the agent, the watchdog and journald — the
  case lot 273c's round 7 measured. A key without `telemetry-read` or
  `audit-read` gets a hint to look.
- **`io.prio.class`** (5.14 and later) is a protected resource file
  (`idle` starves the audit log's writes under contention; floor
  `no-change`).
- **The critical sysctls** (`common::cgroup_limits::SYSCTL_FILES`,
  `crates/nn-linux/src/sysctl_guard.rs`). `vm.overcommit_memory=2` with a
  ratio below 50 (or `overcommit_kbytes` below 1 GiB) makes the agent's
  next allocation fail; a `kernel.pid_max` below 32768, a
  `kernel.threads-max` below 8192 or a `vm.max_map_count` below 65530
  stop it creating what it runs; real-time throttling off — a
  `kernel.sched_rt_runtime_us` of -1, or a runtime at or past 99 % of the
  period — lets a real-time hog own the CPUs. The choice, both: the write
  deny refuses a write of one of them outside a window when its value is
  harmful (judged by name on procfs and on the bytes written,
  `sysctl_write_harmful`; signed `sysctl`, ENGAGED), so the operator's
  tuning that harms nothing — a raised limit, overcommit 0 or 1 — stays
  possible; and the integrity round puts back what the kernel could not
  refuse — a value set at boot (`sysctl.d`) or inside a window — to a safe
  one (`sysctl_restored`), leaving strict overcommit with a ratio of 50 or
  more to the operator (`sysctl_strict`, signed). A harmful value set
  inside a window lasts until the window's close (every guarded sysctl is
  checked there) or the round's next pass, not past it. The review of
  #497: a value the kernel reads in another base than 10 — a leading `0`
  before a digit (octal: `040000` is 16384), `0x` (hex) — is refused, never
  judged as the decimal it looks like (D1); `kernel.sched_rt_period_us`
  is refused whatever it carries, as `ftrace_enabled` (a period at the
  runtime switches throttling off as `-1` does), and the round judges the
  runtime against the host's own period (`rt_throttling_off`, both files;
  the write deny, which cannot read the period, against the default 1 s),
  putting it back to 95 % of the period (D3).
- **`kernel.ftrace_enabled`** (R1 of the external review of 04/11; P0). On
  6.0 to 7.2 a `0` turns every call site ftrace manages back into a NOP,
  with no error: the BPF trampolines stop — the fentry/fexit sensors, the
  kprobes on ftrace and, by the kernel's code, the BPF-LSM programs, every
  deny hook of this document. The lab measured it (C106c, on 6.1, 6.8, 6.12 and 7.0): with the
switch at 0 our BPF-LSM programs, kprobes and fentry programs ran 0 times
under a load that ran them thousands of times at 1 (tracepoint programs
kept running); on 5.15 the write was `EBUSY`. It is the eighth guarded
  sysctl (`SYSCTL_FTRACE_ENABLED`), and the one of which every write is
  refused outside a window, whatever it carries (`sysctl_refuses_every_write`,
  the coordinator's decision of 04/11): no legitimate use of writing it
  is known — upstream deprecates it and refuses it from 7.3, and a `1`
  over a `1` changes nothing — and with no value to judge the hook reads
  no byte, so the race below does not reach it. The agent's own restore
  passes by its identity (`caller_may`, the agent's family), never by an
  exception for the name (`sysctl_write_refused`). The switch is also read at every build of the capability
  manifest (`sysctl_guard::note_ftrace`, 5 s): `0` or unreadable is a
  signed `ftrace_enabled` degradation while it holds, so the verifier says
  `DEGRADED`. A `0` set inside a window or at boot is put back to `1` at
  the window's close (the close record's `sysctls`, a check that now runs
  for every guarded sysctl) and by the integrity round.
- **Our own drop-in directories, writable to the agent.** The close's
  quarantine of a harmful drop-in of ours failed in the installed unit:
  `ProtectSystem=strict` left `/etc/systemd/system*/northnarrow-*.d` and
  `/run/systemd/system*/northnarrow-*.d` read-only to the agent, and the
  signed close record said `NOT moved (Read-only file system)` (the lab's
  round 11 on Debian 13, C105). The agent's unit lists the fourteen
  directories in a second `ReadWritePaths=` (each `-`: made by the
  `ExecStartPre=+` lines); they stay NOCREATE to every other pid.

### Operator notes

- **Debugging PID 1 takes a window**: `gdb -p 1`, `strace -p 1`,
  `ltrace -p 1`, `gcore 1`, reading `/proc/1/mem` (forensic memory tools),
  `/proc/1/stack`, `/proc/1/syscall`, `process_vm_readv` and
  `pidfd_getfd` on PID 1 are attach mode (lot 273c). Read mode — `ps`,
  `lsof`, `/proc/1/environ`, `/proc/1/maps`, `nsenter -t 1`, `perf -p 1`
  — needs none.
- **A window ends with the agent that opened it**, by design
  (fail-closed): at its start the agent zeroes the pinned grants
  (`FS_GRANT`, `KILL_GRANT`). A maintenance that restarts the agent asks
  for a new grant before its next protected step; `install.sh --upgrade`
  does — its rollback, once the new agent runs, opens the new agent's own
  window with the same key (`open_trusted_installer_window` in the
  rollback path) — and after the restart it only checks the units'
  health.
- **PID 1's memory through a uprobe** (`bpf_probe_write_user` from a
  program attached to PID 1) is not refused here: it depends on wave 1's
  refusal of foreign BPF programs and of the rootkit helpers (the BPF
  guard), which is what keeps PID 1's write-backs trustworthy on that
  path.

### Residual

- **Accepted residual (the coordinator's decision): an operator's
  `daemon-reload` inside a window applies a harmful host drop-in already
  on disk.** Whoever opens a signed window is trusted, and the grant warns
  before the work (`nn-admin trusted-installer-grant`, the `host_dropins`
  degradation). What the agent records of it: the drop-in itself is a
  signed `unit_dropin_harmful` at every integrity round and a
  `host_dropins` degradation while it is on disk; at the window's close
  our units' and slice's values below their floors are put back and each
  restoration is signed (`limit_floor_restored`). There is no signed
  record that names the drop-in as *applied* inside the window — only
  those two. When the value it applies ends the agent inside the window
  (lot 273c's round 7: a 4 KiB slice), no close runs: the next agent's
  registration restores the floors at its start (signed the same) and the
  finding comes back at its first round. The floors are not held inside a
  window.
- Not in this lot (Wave 2 backlog, the coordinator's decision): putting
  back in systemd's memory only our units' properties instead of a whole
  reload — it needs a thread with `CAP_SYS_ADMIN`, against R14's
  capabilities per thread.
- A write of a guarded sysctl whose bytes the hook does not read is
  refused, as PID 1's unread write is — such a tool needs a window: a
  `writev`, an io_uring write the submitter's `io_uring_enter` runs inline
  (the registers name that call, not a write), and — the review of #497
  (D2) — one an io-wq worker runs: a worker carries its creator's
  registers (`copy_thread`), so its `IORING_OP_WRITE` would have been
  judged on another write's bytes; a task with `PF_IO_WORKER` or
  `PF_KTHREAD` is never read (`regs_are_the_writes`), its write refused and
  signed.
- **Declared residual (the coordinator's decision of 04/11): the seven
  sysctls judged by value are judged on the bytes the hook reads, before
  the kernel copies them** (`file_permission` runs before the sysctl's
  handler copies the buffer). A root writer with a second thread that
  changes the bytes in between can put a harmful value in. The lab measured it (C106r: `kernel.sched_rt_runtime_us`, `950000` written
2,000 times while a second thread flipped one byte to make it `990000`):
72 to 210 of the 2,000 writes put the harmful value in on 5.15, 6.1, 6.8,
6.12 and 7.0 (49 to 228 were refused), and the agent put one back after
12.6 to 33.8 s — its round's next pass.
  It is seen, not silent: each write the hook reads as harmful is a
  signed `sysctl` refusal, and the integrity round puts a harmful value
  back at its next pass (30 s, ±20 %), signed `sysctl_restored`. Lot 280
  ("the switches that blind") closes it, as its first item: a
  `cgroup/sysctl` program on the root cgroup, which reads the value the
  kernel already copied (`bpf_sysctl_get_new_value`) and is not carried
  by ftrace, verified on 5.15 and 6.8, with its link protected from a
  detach outside a window and this hook kept as the second layer. **Closed
  by lot 280a where that program is attached** (§ Lot 280a below: the same
  race, 0 of 2,000 writes in on 6.8); the residual stays on a host where it
  is not (the fallback, signed).
  `ftrace_enabled` is outside this residual: no write of it is judged by
  value.
- `kernel.ftrace_enabled=0` silences the trampolines until it is put back
  (the manifest's next build signs it, the window's close or the round
  restores it): what fired nothing meanwhile is not recovered.
- The window closed by an agent's restart is not judged for our own
  drop-ins (no close ran): the next window's close does it, and the
  floors hold meanwhile.
- **Our drop-ins' round and a window opened during it** (the re-review of
  #497, NR4). The round reads whether a window is open, then judges and
  moves: a window opened in between can see a file the operator is
  writing in it moved by that pass (the operator copies it back inside
  the window; the close judges it).
- **A generator's drop-in for our units** (NR4): the round looks in every
  unit directory, the generators' (`/run/systemd/generator*`) among them.
  A generator that wrote a harmful drop-in for our units would have it
  moved at every round and written again at every reload — a loop held to
  one reload every 30 s. None is known.
- **The RT runtime between the hook and the round** (NR3): the write deny
  judges a runtime against the default 1 s period (990000 µs), since it
  refuses every write of the period and cannot read it; the round judges
  it against the host's period. With a shorter period set inside a
  window, a runtime at 99 % of it passes the hook and is put back at the
  next round — to 95 % of the period, never 0 (for a 1 µs period, the
  kernel's defaults: the period to 1 s, then the runtime to 950 ms).
- `cpu.uclamp.max`, `memory.swap.max`, a sibling's `memory.low` /
  `memory.min` are still not refused.

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
  when the task to move is the writing thread itself, its cgroup before
  the move, and the move is a no-op only for that thread and that cgroup
  (the review of #494, B1: a thread writing its process's leader into
  `cgroup.threads` stays where it is, the leader moves — the first version
  compared the writer's cgroup and took that for no move). The agent's
  family is not marked: it moves processes into its containment slice
  (`/northnarrow.slice`), and no exemption by cgroup or unit applies
  there — the policy's parser refuses a `cgroup` under it and a `unit`
  `blocked.scope` or `throttled.scope`, and the check skips a process in
  it whatever the policy says (the review of #494, N1).
- `cgroup_join_born` (fentry `cgroup_post_fork`), for every fork of a new
  thread group: what the maps hold at its tgid goes first — a dead group's,
  since the pid was free (a move of a group already exiting marks it after
  its exit, and any user can make one on its own pids: the review of #494,
  N5). Then it marks a child started by `CLONE_INTO_CGROUP` by anyone but
  PID 1, before it runs. No move can come between the pid's allocation and
  this: the fork holds `cgroup_threadgroup_rwsem` for reading from
  `cgroup_can_fork` to the end of `cgroup_post_fork`.
- `cgroup_join_fork` (BTF tracepoint `sched_process_fork`) marks a new
  process forked by a marked one, before its first wake-up. The parent's
  mark counts only with its leader's start time: a dead process's mark at
  a reused id passes on nothing.
- `cgroup_join_exit` (BTF tracepoint `sched_process_exit`) removes the mark
  when the group's last thread exits (`signal->live` 0), not with its
  leader, which may exit first. Two threads exiting together may both read
  0; a second remove finds nothing.

The exemption check (`nn_core::decision::rule_policy::exempt`) asks
`ActorFacts::started_in_cgroup` once a cgroup or a unit matched. The
agent's answer (`nn_linux::cgroup_join`, on the errands thread) is the
map's: not marked, marked, or not known. Not known means no tracker on
this kernel, a mark the kernel could not keep for **this** group, or a
failed lookup. Marked and not known refuse the exemption.

A mark the kernel could not keep (the insert failed, the leader's start
time unread, a clone's flags unread, the writing thread's own tgid
unread) sets the group's byte in the pinned `CGROUP_JOIN_LOST`
(preallocated: one byte for each of the 4,194,304 possible tgids, 4 MiB)
to 1; a fork of a group whose byte is set sets the child's. The byte is
set to 0 at the tgid's next fork (`cgroup_join_born`), before the new
group runs and before any move can reach it — the only clear (a clear at
the exit could run for two threads that both read `signal->live` 0).
Both writes are plain stores, never a read-modify-write (the re-review of
#494, R1). The review's version kept a bit a tgid, set with a test and an
atomic add, on the claim that one event at a time touched a group's bit;
that was false: `sched_process_fork` comes after `cgroup_post_fork` lets
go of `cgroup_threadgroup_rwsem` (v5.15 `fork.c:2594` after
`cgroup.c:6145`, v6.8 `fork.c:2912` after `cgroup.c:6498`), so a move of
the new child by another process can mark it on another CPU at the same
time. Two adds of the same bit left it clear — the child neither marked
nor not known, exempt — and carried into the next tgid's. A store of 1
by any number of CPUs leaves the byte 1, and no store reaches another
tgid's byte. The first version (the review of #494, D2) counted a lost
mark in a host-wide counter that refused every exemption by cgroup or
unit until a reboot, and a preallocated map of 32,768 marks any user's
fork storm under a marked parent could fill. The marks are now a hash map
allocated as it is filled (`BPF_F_NO_PREALLOC`), its size set when it
is made — the first start of the boot, or a reset — to `kernel.pid_max`
capped by `kernel.threads-max` (32,768 to 4,194,304): the live thread groups, one mark each at most, are at most
`threads-max` (a fork past it fails) and at most `pid_max`. Not
`pid_max` alone: the hash's bucket array is allocated whole, 16 bytes a
bucket — 64 MiB at the 4,194,304 systemd sets — where `threads-max`
(about 250,000 on a 32 GiB host) needs 4 MiB. What fills it past that is
dead groups' marks (the move of a group already exiting); those go at
the pid's next fork, and a mark the full map refuses only makes that
group not known, refused as a mark is. A move into a cgroup an exemption names
(the policy's cgroup paths and unit names, hashed into
`CGROUP_EXEMPT_NAMES`) is signed as NN-L-AT-001 `cgroup_join`. It is not
refused, and the posture is not raised: the move is no tamper with the
agent, and what the moved process does is judged without the exemption.

Every move runs under `cgroup_mutex`, from the lookup to the tracepoint,
and every move of another task under `cgroup_threadgroup_rwsem` held for
writing too; a fork holds the rwsem for reading from `cgroup_can_fork` to
the end of `cgroup_post_fork`: a fork after a move sees the mark. A write
of `0` into `cgroup.threads` (the writing thread moves itself) does not
take the rwsem (`*threadgroup_locked = pid || threadgroup`, v6.8
`kernel/cgroup/cgroup.c:2916`; the review of #494, N6): the moved thread is
the writer, and a fork by another thread of its process starts its child
in that thread's cgroup.

The programs' links are pinned (`prog_cgroup_join_*`,
`link_cgroup_join_*`, the review of #494, D6), as the other anti-tamper
programs are: a stopped agent leaves the tracker marking. Their pins and
the four maps' (`CGROUP_JOINED`, `CGROUP_JOIN_LOST`, `CGROUP_JOIN_STATS`,
`CGROUP_JOIN_EPOCH`) are in a directory of the tracker's own **beside**
the pin root, not in it (the re-review of #494, R2):
`/sys/fs/bpf/northnarrow-cgroup-join-v<schema>_<generation>` (no dot: bpffs refuses one in a name, `bpf_lookup`; the third review's first lab run found it, the directory refused with EPERM and the tracker absent).
`install.sh --upgrade` purges the pin root so that every LSM program
detaches (`purge_pin_root`); the review's version had the tracker's pins
there, so an upgrade dropped every mark. Now the purge leaves the
tracker's directory: its programs go on marking through the upgrade, and
the new agent swaps them for its own, one by one, attach before purge
(`cgroup_join_mark` before `cgroup_join_src`: the new `mark` reads the new,
empty source slot until the new `src` runs, so it marks more meanwhile,
never less — the re-review's N-f). The agent lists the tracker's programs
as `kept` in `/run/northnarrow/bpf-own-ids`: the upgrade does not wait for
them to unload; `uninstall.sh` removes the directory with the pin root and
waits for every program.

**What a start adopts** (the third review of #494, R2-a and R2-b). A start
registers its pins in `/run/northnarrow/cgroup-join-pins` — the boot's
id, the directory, each map's id and entries — and the agent protects
that file like its other files (`register_agent_file`: no write, unlink or
rename by a foreign caller outside the trusted-installer window), and the
directory like the pin root (`register_bpffs_pins`). The next start
adopts only that directory, and only when each of its maps is the one
registered — `BPF_OBJ_GET_INFO_BY_FD` on a read-only handle: the id, and
this schema's kind, key and value sizes and flags (a hash with
`BPF_F_NO_PREALLOC` and nothing else for the marks; never an LRU hash, a
preallocated one, or one read-only to programs) — with no other file in
the directory. Anything else is a **reset**: new maps in the next
generation's directory, the old directory removed once the new programs
run, a signed degradation "cgroup exemptions: marks reset …" — the
registered directory gone between two agents ("marks lost between
agents": the third review's point 3, the window between an upgrade's purge
of the pin root, with which the deny hooks detach, and the new agent's
start), maps not the registered ones (a directory planted, before the
first start or inside the window, with a map whose writer keeps an fd), a
directory no start of this boot registered, an older schema's (not
migrated: this is the first schema). A directory that is a symbolic link
is refused, and removed without being followed (R2-d). A tracker
directory beside adopted pins that nobody registered (planted under the
name of a later generation) is removed, signed.

**A reset fails closed** (R2-a). The review's version named the
directory by the marks' size too, so a `sysctl kernel.threads-max` before
a restart was a reset, and a reset gave every marked process its
exemption back. The size is now a capacity fixed when the marks are made:
a host that asks for more later keeps the map — a signed note, and a
process past it is not known. A reset writes its instant into
`CGROUP_JOIN_EPOCH` (`[monotonic, boot time]` ns) once the new programs
run: a process started before it is not known to the agent (its leader's
start, `/proc/<pid>/stat`, against the boot-time instant), and a fork of
one — by anyone but PID 1, whose forks are systemd's placement, and the
family — makes a child that is not known (`before_epoch`, the leader's
monotonic start against the monotonic instant). Written after the
attach, it leaves nothing unseen: a process forked before it started
before it. The exempt services are then refused until they are restarted
(`UPGRADE_NOTES_WAVE4.md` §8).
A kernel that refuses the tracker removes its pins; a host without bpffs
attaches the programs for the agent's life and warns.

**Code injected into an exempt process** (lot 281). The same marks carry
the code a process runs: two more programs of the tracker, BPF LSM
programs that never refuse, taint a process's mark when another gains
code-injection access to it — `cgroup_join_inject` on `ptrace_access_check`
(attach mode only; the access is read from the caller's own registers,
`bpf_task_pt_regs`: `process_vm_readv` and a read-only open of a procfs
file are reads, everything else in attach mode, a call that cannot be
read included, is an injection — `common::cgroup_join::injection`) and
`cgroup_join_traceme` on `ptrace_traceme` (the parent gets the access). A
caller of the family, PID 1 and the protected processes are left out. The
taint is passed on at a fork and kept through a move; an exemption by
executable, cgroup or unit no longer holds for a tainted process
(`RULE_POLICY.md` §2.3), a uid's does. The first taint is recorded
(`FS_OP_EXEMPT_INJECT`, the task denials' budget); the agent signs it
(NN-L-AT-001 `exempt_injection`, High or Critical) when an exemption
covered the process. They are pinned with the tracker's other programs:
they taint during an upgrade's gap too. The marks' layout changed with
the taint bits: schema 2, so an upgrade from schema 1 is a signed reset.

**Kept from tampering** (lot 281, #494's notes N1 and N2). The re-review
of #494 found two ways to the marks that are not root's in a window:

- N1 — a new generation's directory was made before the load and the
  loader pinned the maps by name in it, taking any map already at a pin's
  path (aya opens an existing pin first): a root watching the bpffs could
  plant one between the two and keep a handle on it. Now a new
  generation's maps are made by the load, unpinned, frozen, and pinned
  after it in a directory the start makes then (one that exists is a
  plant); `BPF_OBJ_PIN`'s `EEXIST` at a pin's path, or anything else in
  the directory, moves the maps to the next generation, signed, the plant
  removed with its directory (never followed, a few levels deep). An
  adoption's maps are checked after the load against the ids verified
  before it.
- N2 — a handle on the tracker's maps taken in a window or an upgrade's
  gap stayed good after it: the maps are the only ones an upgrade keeps.
  Now all four are frozen (`BPF_MAP_FREEZE`) as soon as they exist: no
  handle writes them, the agent's own included; an adopted map that was
  not frozen (none a start of this version made) is frozen at its
  adoption and signed. A map's frozen state is read from its descriptor's
  fdinfo (`frozen: 1`) before the call: a second freeze answers `EPERM`
  (`map_freeze` checks the descriptor's write right, which a frozen map
  has lost, before its frozen state) — lot 281's lab found every adoption
  leaving the tracker absent while the call alone decided. A reset's instant is asked for in a per-load map
  (`CGROUP_JOIN_EPOCH_RT`) the fork program takes into the pinned epoch,
  forward only (the agent forks once to take it in at once); the agent
  reads the later of the two. The start's sweep of dead groups' marks is
  gone (a dead group's mark goes at its tgid's next fork).
- No exemption by executable, cgroup or unit is honoured until the
  tracker is **armed**: its pins and their record protected
  (`register_bpffs_pins`, `register_agent_file`); not protected, it is
  never armed this boot (signed). The start logs the time from its plan
  to the arming (the lab's measure: `CAPABILITY_PROGRAM.md`, lot 281).

### Residual

- **Root changes the unit itself.** A drop-in that rewrites `ExecStart=`,
  a transient unit given the exempt unit's name where none is loaded,
  systemd asked over D-Bus to attach a process (`AttachProcessesToUnit`):
  these are systemd's placements, and the unit exemption trusts the
  unit's definition. An exemption by `exe … sha256` binds to the program.
- **A root that writes PID 1's memory** — or its pre-exec child's
  (systemd up to 254) — with `ptrace` or `/proc/1/mem`: what PID 1 does is
  systemd's placement (the review of #494, N3).
- **Code injected into a running exempt process**: revoked since lot 281
  (above). Not seen: an injection before the agent's first start since the
  host booted, or while `kernel.ftrace_enabled` is 0 (a window only: the
  trampolines stop; the epoch is reset when ftrace runs again); a shared
  library or an `LD_PRELOAD` the exempt program loads, a writable mapping
  shared with another process (no `ptrace` check); a BPF program of root's
  own that names a tracker map (a read-only handle is enough for a
  program to write a map, frozen or not; the `bpf()` observer records the
  load, it does not refuse it). An io_uring worker's attach-mode access
  (its registers are not its call) is taken for an injection: a false
  refusal, fail closed.
- **A move before the agent's first start** since the host booted: no
  program ran. While no agent runs, the last agent's and watchdog's pids
  stay the family in the pinned `PROTECTED_PIDS` until the next start's
  stale scan: a process given one of them moves unmarked (the re-review's
  N-e; it needs that pid reused while no agent runs). A `cgroup_join`
  record of a move made then reaches no journal; the mark is made.
- **Inside the trusted-installer window** (a signed, audited grant), or
  between an upgrade's purge of the pin root and the new agent's start
  (the deny hooks detach with the purge), root can replace both the
  tracker's pins and their record in `/run/northnarrow`: a planted map
  registered by a forged record is adopted — with the marks root put in
  it, frozen at the adoption (lot 281: signed, "were not frozen"), so a
  handle kept from then writes nothing after. The window trusts its
  holder. The pins removed then are signed ("marks lost between agents"),
  and a reboot removes them with every process. Before lot 281 a handle on
  the tracker's maps taken in the window or the gap wrote the marks after
  it (#494's N2): closed by the freeze.
- **A downgrade to a version before lot 277** leaves the tracker's
  programs attached and marking — harmless, nothing reads the marks —
  until `uninstall.sh` or a reboot. (No release pinned them in the pin
  root itself.)
- **cgroup's `favordynmods`** (kernel 6.18+, `cgroup_enable_per_threadgroup_rwsem`,
  v6.18 `kernel/cgroup/cgroup.c:1344-1356`, `:3096-3103`): a move takes
  only the target group's rwsem and looks the pid up before it; the
  fork-time clear of a dead group's mark (N5) no longer excludes a move of
  that dead group, which can mark the tgid after the new owner's fork — a
  false refusal for that process. Neither systemd 255 nor 257 mounts
  cgroup2 with `favordynmods`; it takes a remount by root or
  `CONFIG_CGROUP_FAVOR_DYNMODS` (the re-review's N-a).
- **A probe that cannot read a task's tgid** (`tgid_of`, a live task's own
  field: not seen to fail): the writer's own is set not known, another
  task's — a moved one, a forked child — is only counted, with no group
  to set (the re-review's N-b).
- **The marks' size is the first start's of the boot**: `kernel.pid_max`
  or `kernel.threads-max` raised later leave the map as it was, a signed
  note at each start (the third review's R2-a: never a reset); a fork
  storm past `threads-max` by the number of CPUs (the check comes before
  the fork completes) and dead groups' marks take entries too. In every
  case only the groups that ask for a mark become not known — a service
  systemd starts asks for none (the re-review's N-g).
- **After a reset**, every process started before it — the exempt
  services among them, and what they fork — is refused an exemption by
  cgroup or unit until it exits: restart the exempt services. That is the
  price of failing closed; a reset is signed.
- **A non-leader thread rewriting its own process into its cgroup**
  (`cgroup.procs` with its tgid, or `0`): the leader moves, not the
  writing thread, so it is marked — a false refusal for a multi-threaded
  service that does so (the re-review's N-d).
- **The `cgroup_join` records share the task denials' budget** (one a
  caller and operation a second, 50 a second per CPU): any user moving its
  own processes into a cgroup of its session named like an exempt unit
  (`…/app.slice/backup.service`) makes High records — noise in the
  denials' budget, not a way around the tracker (the re-review's N-h).
- **A start by `CLONE_INTO_CGROUP` is marked, not signed**: the fork path
  gives no destination path to match.
- **False refusals, fail-closed**: a `Delegate=yes` service that moves its
  own processes into its sub-cgroups, a container runtime (runc writes the
  pid, with the systemd cgroup driver too), a move in a cgroup v1
  hierarchy of a hybrid host (the policy reads the `0::` cgroup only):
  those processes are marked and lose a `unit` exemption (the review of
  #494, N2, N4).
- **systemd 255** does not use `CLONE_INTO_CGROUP` (256 does): PID 1
  `posix_spawn`s `systemd-executor`, `posix_spawn` returns after its
  exec, and PID 1 moves it at once (`cg_attach`, v255 `execute.c`): a
  placement. The executor moves itself much later (v255
  `exec-invoke.c`), into the cgroup it is in: a no-op. If PID 1 stayed
  off the CPU long enough for the executor's move to come first, that
  move would be the executor's — it executed — and mark the unit's
  process (a false refusal). The first version of this section said 255
  used `CLONE_INTO_CGROUP` with a recent glibc (the review of #494, D4):
  wrong. Measured on Ubuntu 24.04 (systemd 255) in the review's lab:
  `docs/roadmap/CAPABILITY_PROGRAM.md`, lot 277.
- **A container or workload context**: any future exemption by container
  or workload follows the same rule. A process counts as the workload's
  when the workload's runtime started it there, never because its cgroup
  says so.

## Lot 280a — the guarded sysctls judged on the kernel's copy; the signed per-sysctl opt-out

**What it closes.** The residual lot 273d declared: the write deny
(`file_permission`) judges the bytes of a write of a guarded sysctl in the
writer's memory, before the kernel copies them, and a second thread of the
writer can change them in between.

**The judge** (`agent-ebpf/src/sysctl_guard.rs`, `crates/nn-linux/src/
sysctl_cgroup.rs`, the verdict `common::sysctl_judge`). A `cgroup/sysctl`
program linked to the root cgroup of the unified hierarchy. The kernel runs
it inside `proc_sys_call_handler`, after it duplicated the user buffer and
before the sysctl's handler parses that same copy; the program reads it
with `bpf_sysctl_get_new_value` and parses it with `bpf_strtol` in base 0,
as the handler does (`proc_get_long` → `strtoul_lenient(…, 0, …)`: `040000`
is 16384, `0x4000` too, leading blanks skipped). The floors are the write
deny's (one function, `cgroup_limits::sysctl_value_harmful`);
`kernel.ftrace_enabled` and `kernel.sched_rt_period_us` are refused
whatever they carry, a value that is no integer (or longer than 63
characters, or past `i64`) is refused. The agent's family and a signed
trusted-installer window pass, by the same checks as every deny hook (the
writer's tgid read from its task: the 5.15 helpers of this program type
have no `bpf_get_current_pid_tgid`). A refusal is `EPERM` and a signed
NN-L-AT-001 `sysctl_value` (the sysctl and the value the kernel would have
stored; ENGAGED, as lot 273d's `sysctl`). The write deny stays the first
layer: it refuses a non-decimal spelling unread, and what it lets through
is judged again on the kernel's copy.

**A child cgroup's program cannot get around it.** The agent attaches it
with `BPF_LINK_CREATE` and no flag: the kernel attaches a cgroup link
`BPF_F_ALLOW_MULTI` (`cgroup_bpf_link_attach`), the one mode in which the
root's programs stay in every descendant's effective array, whatever mode a
child attaches with (`compute_effective_progs`); the legacy
`BPF_PROG_ATTACH`, whose flags could say `BPF_F_ALLOW_OVERRIDE`, is never
used. The array runs a child's programs before the root's and makes any
program's 0 the write's `EPERM`; a child's `bpf_sysctl_set_new_value`
rewrites the very copy the root's program then reads. The start checks
what the kernel reports for the root (`BPF_PROG_QUERY`: multi, our program
among the root's) and refuses the judge otherwise. The lab's S5 attaches,
in a child cgroup, a program that lets every write through and rewrites the
value, with no flag, `override` and `multi`.

**Its link** is pinned with the program in `/sys/fs/bpf/northnarrow-sysctl`,
beside the pin root (protected like it: no unlink or rename by a foreign
caller outside a window), and held open by the agent: the BPF guard
registers it as one of the agent's links (a foreign handle by id or by its
pin, a `LINK_DETACH`, a `LINK_UPDATE` refused in enforce mode). It outlives
an agent stop and `install.sh --upgrade` (which purges the pin root only):
while no agent runs the judge goes on refusing, with the maps it was loaded
with — a window the stopped agent granted holds until its deadline, and a
refusal's record goes to that agent's ring, which nobody reads (the deny
hooks' own case). The next start links its own program first, then removes
the prior link. `uninstall.sh` removes the directory (the link's last
reference: the judge leaves the root cgroup).

**Fallback.** Where the judge cannot be linked — no cgroup v2 mount of the
hierarchy's root (a v1-only host), a mount point that is not the root
cgroup (inode 1: a cgroup namespace's view), a kernel or a root mode that
refuses it — the write deny judges alone, with lot 273d's residual: a
signed `anti_tamper` degradation, and the manifest's attach point
`sysctl_judge` names the fallback (`fs_protect`'s `why`).

**The signed per-sysctl opt-out.** `sysctl-allow <sysctl> <value>|<min>..<max>`
in the per-rule policy (`RULE_POLICY.md` §2.2): a guarded sysctl but
`kernel.ftrace_enabled`, by its `sysctl(8)` name. The agent writes it to the
kernel (`SYSCTL_OPTOUT`, one slot a sysctl, bound to the boot's session
nonce: a slot an earlier agent wrote is dead after a restart until the new
one writes it) only from a policy whose signature it verified for the very
text it applies (`OverlayGate::signs`) or from a signed `policy set`; an
unsigned policy loaded through `NN_OVERLAY_ALLOW_UNSIGNED=1` has its other
lines applied and its `sysctl-allow` withheld, signed degraded. A write the
range allows and the floors would refuse goes through, recorded every time
(NN-L-AT-001 `sysctl_opt_out`, Low, no posture trigger; by the judge on the
kernel's copy, or by the write deny where the judge is not attached); the
integrity round leaves such a value (`sysctl_opted_out`, signed).

**What stays open.**
- A `cgroup/sysctl` program attached at the ROOT cgroup after ours runs
  after it (same cgroup, attach order) and can rewrite the value it judged.
  It takes a root that loads BPF; the BPF guard records the load and the
  attach (`bpf_syscall`), the start names any other program it finds there
  (a signed degradation), and the integrity round puts a harmful value back
  at its next pass. Lot 280b: such an attach is refused outside a window
  (the `bpf` hook), and one made inside a window or before the start is
  found by the kernel-state round and signed (§ Lot 280b).
- An opt-out names a sysctl and its values, not a program: while it is in
  force, any root process may write a value in its range.
- `bpf_strtol` reads up to 63 characters where the kernel reads 21: a value
  the kernel would refuse (`EINVAL`) may be judged — refused or let
  through, the kernel then refuses it; a write longer than 63 bytes (many
  leading blanks) is refused, which the kernel would have read.
- The writer's tgid is read from its task; a read that fails is no one's
  (not the agent's family): such a write is judged, never let through by
  identity.

## Lot 280b — the switches that blind the sensors

**What it closes.** The kernel switches that silence the agent's hooks
without touching them, which lots 273d and 280a left open or only read.

**`kernel.ftrace_enabled=0` inside a window** (the short re-check of #497,
NB1). Outside a window every write of it is refused (lot 273d); inside one
it can be set to `0`, and on 6.0 to 7.2 the fentry/fexit programs, the
kprobes on ftrace and the BPF-LSM programs stop while the BTF tracepoints
go on. The start-in-cgroup tracker (lot 277) marks a birth by
`clone3(CLONE_INTO_CGROUP)` in its fentry on `cgroup_post_fork`: with the
switch at `0` such a birth into an exempt cgroup was not marked and stayed
exempt after the window. Now:
- the fentry records each new thread group it sees (`CGROUP_JOIN_BORN`,
  per load) and the fork's tracepoint (`sched_process_fork`, `tp_btf`)
  checks it: a new thread group the fentry did not see, for a child started
  after the agent armed the check (`CGROUP_JOIN_SILENT`: armed once the
  start's programs run, so the swap of a prior boot's programs is never a
  miss), is "not known" at once — its byte in `CGROUP_JOIN_LOST`, passed on
  to what it forks: refused every exemption by cgroup or unit — and
  counted with its instant. That is the check channel: it tells "silent
  because ftrace is off" from "silent because nothing happened", and it
  works while no agent runs (the programs are pinned);
- at every build of the capability manifest (5 s) the switch at `0`, or
  unreadable, or a birth counted since the last read opens a signed
  `cgroup_join_marks` degradation naming when the loss began; once the
  switch reads `1` and no birth was missed since the last read, the marks'
  epoch is reset (`CGROUP_JOIN_EPOCH`: every process started before is not
  known until it exits, fail closed) and the period is signed — the loss's
  line leaves, the reset's stays.
A move is judged by the tracker's tracepoint on `cgroup_attach_task`, which
goes on: with the fexit on `cgroup_procs_write_start` silent its source
slot is stale, which can only make a move count as one, never hide it.

**The kprobes' switches.** `/sys/kernel/debug/kprobes/enabled` at `0`
disarms every kprobe of the host (the agent's `tcp_connect`, `udp_send_skb`
and the others stay registered and silent); `debug.kprobes-optimization` at
`0` turns every optimised kprobe back into a breakpoint trap (a cost on each
probed call, not a blindness). The sysctl joins the guarded ones: every
write refused outside a window (the write deny and the `cgroup/sysctl`
judge), never opted out, a `0` put back by the integrity round and at a
window's close. The debugfs file is no sysctl: the write deny's
`file_open` / `file_permission` find it by the superblock's magic
(`DEBUGFS_MAGIC`) and the names (`enabled` in `kprobes`), refuse every write
of it outside the family and a window (NN-L-AT-001 `kprobes`, ENGAGED), and
the round puts a `0` back to `1` (signed `sysctl_restored`, "blinds the
agent's hooks").

**Lockdown.** `/sys/kernel/security/lockdown` is refused the same way, on
securityfs (`lockdown`): a raise to `confidentiality` takes from every BPF
program loaded after it the helpers that read kernel memory, so the
agent's next start (an upgrade, a restart) would load without the programs
that use them (`KERNEL_COMPATIBILITY.md`, "Lockdown", as measured); raising
the mode is an operator's act at boot (`lockdown=`), or inside a window.
The host check warns on `[confidentiality]` with its own fix (integrity
keeps every protection against rewriting the kernel).

**The kernel's code.** The capability manifest records the taint mask, its
letters and each livepatch with its state (`kernel_code`): a change is a
signed revision, a flag or a livepatch more a worse one (signed at once).
The kernel-state round (5 s, `crates/nn-linux/src/kernel_state.rs`) signs a
flag of code entering the kernel that appears while the agent runs
(`common::kernel_taint::CODE_ENTRY`: P, F, R, C, O, E, K, X, N) as
NN-L-AT-001 `kernel_taint` — Critical for an unsigned module or anything
forced (E, F, R), High otherwise (an out-of-tree or proprietary module, a
livepatch): not a refusal, so no posture trigger; the module-load sensor's
rules judge the load itself. The flags set before the start are the
manifest's, not news.

**A foreign program on the root's sysctl slot** (lot 280a's residual). The
`bpf` hook refuses `BPF_PROG_ATTACH` and `BPF_LINK_CREATE` of a
`cgroup/sysctl` program whose target descriptor is the cgroup v2 root
(its kernfs inode 1, read through the caller's file table) by anyone
outside the agent's family, a fresh instance of it and a window — a target
it cannot read refused too (that attach type only, fail closed) —
NN-L-AT-001 `sysctl_root_attach`, ENGAGED. One attached inside a window or
before the start is found by the kernel-state round (`BPF_PROG_QUERY` of
the root) and signed once per program (`sysctl_root_prog`, High); a root
the judge's attach no longer finds as it left it (our program gone, the
mode no longer multi) is a signed degradation while it holds.

**What stays open.**
- A birth the fentry missed is not known, and the marks' epoch is reset
  once ftrace runs again: every exempt service's processes started before
  the reset lose their exemption until they exit (restart them). The
  reset waits for a read with ftrace on and no birth missed since the last
  one (5 to 10 s).
- The other fentry/fexit sensors and the kprobes stay silent while
  `ftrace_enabled` is `0` inside a window; what they did not see is not
  recovered (the degradations say when).
- The BPF guard refuses the root attach only in enforce mode (a production
  build); a lab build observes.
- A taint flag set before the agent's start is in the manifest, not a
  detection; a module's load itself is the module-load rules' (the lab's
  `insmod` of an unsigned module outside a window was killed by them).
- A program attached to the root inside a window stays after it until it
  is detached; the round signs it within 5 s, it is not detached by the
  agent (another tool's program, the operator's to judge).


## Lot 290 — foreign BPF: the rootkit-grade program types, the agent's objects off limits, a light cross-view

**What it closes.** Three residuals: a root BPF program that names one of
the agent's maps (lot 281: the start-in-cgroup tracker's), a foreign
`cgroup/sysctl` program and the `bpf` hook's root refusal holding in
enforce mode only (lots 280a and 280b), and the BPF programs a root can load
beside the agent's hooks at all — the vehicles of `bpf_probe_write_user`,
`bpf_override_return`, `bpf_send_signal` and of a hook's replacement.

**The agent's objects are off limits** outside a trusted-installer window
to every process outside its family (the agent and the watchdog once
protected pids; a fresh instance of either before it is one): `EPERM` on
- `BPF_MAP_GET_FD_BY_ID` of one of its maps (read-write or read-only),
  `BPF_PROG_GET_FD_BY_ID` of one of its programs, `BPF_LINK_GET_FD_BY_ID`
  of one of its links (the ids it registers in `OWN_BPF_IDS`, by kind);
- `BPF_OBJ_GET` of a path that starts with `/sys/fs/bpf/northnarrow` —
  the pin root and the directories kept beside it (`-cgroup-join-v*`,
  `-sysctl`, `-module-writes`);
- a handle reached otherwise (a relative path, `..`, a symlink, a bind
  mount of the bpffs) is judged on the object it opens: the `bpf_map` hook
  refuses any handle on one of its maps (a read handle too; a write handle
  stays refused inside a window as before) and the new `bpf_prog` hook any
  handle on one of its programs; a link pin keeps its final-name match and
  the detach/update refusal of lot 215.
Records: NN-L-AT-001 `bpf_handle` (the kind and the id; ENGAGED: a
`bpftool prog list` of an administrator meets it) and `bpf_link`, `bpf_map`
as before. The refusals of handles follow the guard's mode (observe in a
lab build: its fixtures evict pids with `bpftool map delete`).

A program is loaded against a map only through a descriptor of it, and
`freplace` of one of the agent's functions needs a descriptor of its
program: with neither obtainable, lot 281's residual is closed. **The paths
that remain:** a descriptor inherited from the agent or passed over
`SCM_RIGHTS` by it (the agent passes none, and spawns its workers and
scanner without its BPF descriptors), and `pidfd_getfd` on the agent, which
needs ptrace access to it — refused by the agent's `ptrace_access_check`
deny.

**The rootkit-grade types.** Outside a window a `BPF_PROG_LOAD` of `kprobe`,
`tracepoint`, `perf_event`, `raw_tracepoint`, `raw_tracepoint_writable`
(each can call `bpf_probe_write_user` and `bpf_send_signal`), `tracing`
(fentry, fexit, fmod_ret, iterators), `struct_ops`, `ext` and `lsm` by a
caller outside the family is refused (`EPERM`, NN-L-AT-001
`bpf_prog_type`, High, ENGAGED) — **in every mode**: the observe mode
relaxes only the guard of the agent's own objects. Lot 280b's root
`cgroup/sysctl` attach refusal holds in every mode too now. The other types
are let through and recorded (`BpfSyscall` records, one a second per loader
and type); inside a window everything is. The signed per-loader opt-out
(`bpf-loader-allow <executable> <types>`, `RULE_POLICY.md` §2.5) lets a
named executable — matched by the device and inode its path named when the
policy was applied — load the named types outside a window, each load
recorded (`bpf_prog_opt_out`, Low).

**Freeze.** The configuration maps written once per load are frozen right
after their write (`BPF_MAP_FREEZE`; a frozen map's state read from its
descriptor's fdinfo first, as lot 281 learned): `BPF_DEFENSE_MODE`,
`OWN_EXE_INODES`, `OWN_PIN_NAMES` (at the registration),
`SYSCTL_KERNEL_JUDGE` (when the judge is linked), `DNS_EXEMPT_UIDS` (the DNS
budget's resolvers) and `NET_CONNECT_DENY_MODE` (when the connect deny is
armed). Frozen before this lot: `BTF_OFFSETS`, `EXECPOL_CONF`,
`EXECQ_CONF`, the start-in-cgroup tracker's pinned maps. Every other map of
the object is written again while the agent runs (policies, registrations,
modes, rings, counters) and is guarded by the handle refusals above.

**The light cross-view.** The agent's unit has no `CAP_SYS_ADMIN` (BUG-042),
which `BPF_PROG_GET_NEXT_ID` and `BPF_LINK_GET_NEXT_ID` need; it enumerates
with its own BPF iterators instead (`iter/bpf_prog`, 5.10+;
`iter/bpf_link` where the kernel has it), which `CAP_BPF` and
`CAP_PERFMON` load. Every kernel-state round (5 s) it reads every program
(id, type, expected attach type, tag, name, attach function) and link (id,
type, program), and compares them with what its `bpf` hook saw loading
since its start: a load the hook lets through marks its thread, and the
`bpf_prog` hook — called when the load hands out the new program's
descriptor, its id assigned — records that id with its loader
(`SEEN_PROGS`). An object that is not the agent's and was never seen
loading is
- the **baseline** when it was there at the first enumeration (loaded while
  the agent was not running: at boot before it, in a restart's or an
  upgrade's gap) — each signed once, NN-L-AT-001 `bpf_baseline`, Low, High
  for one of the refused types; Low again for the kernel's own programs —
  one loaded before user space started (its `load_time` before PID 1's
  start), or one the kernel loads from a module's init, by its name and the
  function it is attached to (`common::bpf_prog_class::KERNEL_PROGRAMS`:
  HID-BPF's `hid_tail_call` on `__hid_bpf_tail_call`, a `tracing` program,
  prog id 2 on the 6.8 guest, loaded when udev loads `hid` in the
  initramfs — the lab's rounds signed it High at every start;
  `bpf_preload`'s iterators); the same name attached elsewhere is not one;
- **unseen** when it appears later — loaded through a path the hook does not
  see, or hidden from it: NN-L-AT-001 `bpf_unseen`, High, with its type,
  name, tag and attach point.
An object is judged once it is in two enumerations in a row: a program of
the agent's prior run whose release is pending, or one whose load is
recorded between the two reads, is no finding. A link is judged through its
program; one whose program the program enumeration does not show is judged
itself. No finding raises the posture (the kernel's record, like lot 280b's).
`/run/northnarrow/bpf-foreign` lists each round the foreign objects, their
state, and every load the hook saw since the start with its loader and
type: the host's inventory of foreign BPF.

**Operator notes.**
- `bpftool prog|map|link show` outside a window stops at the first
  NorthNarrow object (its `*_GET_FD_BY_ID` refused, bpftool gives up the
  listing) and its `pids` column is gone (its iterator, a `tracing`
  program, is refused); inside a window both work. The agent's own
  programs are listed in `/run/northnarrow/bpf-own-ids`, the foreign ones
  in `/run/northnarrow/bpf-foreign`.
- A tool that loads the refused types outside a window needs a signed
  `bpf-loader-allow` line; bpftrace, Falco, Tetragon and Cilium's agent are
  such tools.

**What stays open.**
- The refusals of handles hold in enforce mode only — a production build's
  default (a release build without `debug-trigger`, the unit setting no
  `NN_BPF_DEFENSE_OBSERVE`); `NN_BPF_DEFENSE_OBSERVE=1` is a signed
  weakening that refuses the start without the degraded-mode override; the
  lab's `debug-trigger` build observes them unless `NN_BPF_DEFENSE_ENFORCE=1`.
  The type refusal holds in every mode.
- `tracepoint`, `raw_tracepoint`, `raw_tracepoint_writable` and
  `perf_event` are refused with the others (the coordinator's decision
  after the benign corpus, whose workloads loaded none of the nine): a
  profiler or tracer that loads them outside a window (bpftrace's
  `tracepoint:` and `interval:` probes, perf-event profilers) stops there
  unless a signed `bpf-loader-allow` names it — the cost accepted for
  `bpf_probe_write_user` and `bpf_send_signal` from a root process.
- A program that lives less than a round is not seen by the cross-view
  (the light part of it); one loaded while the agent was stopped is in the
  baseline, signed at the next start, not refused.
- The `bpf` and `bpf_prog` hooks are not pinned: while no agent runs (a
  restart's or an upgrade's gap, which only a window opens) nothing refuses
  a load; the next start's baseline signs what it left.
- A program pinned under another path through a bind mount of the bpffs is
  refused on its object (maps, programs); a link pin through it is matched
  by its final name only, behind the detach/update refusal.

## Lot 293 — a signal through a file's owner (external bug hunt, editions 1.2/1.3)

**Goal.** No root process kills or stops the agent, the watchdog or a worker
with a signal the kernel delivers through a file's owner; every refusal
signed. The other self-defence findings of the hunt that this lot closes
are listed at the end.

**What it closed (BUG14, P0).** A file's owner — set by `fcntl(F_SETOWN)`,
`F_SETOWN_EX` (a thread, a process or a process group), `FIOSETOWN` or
`SIOCSPGRP` on a socket — receives a signal when the file is ready for I/O
in asynchronous mode (`O_ASYNC` through `F_SETFL`, or `FIOASYNC`): SIGIO,
or the signal `F_SETSIG` chose, SIGKILL included. A lease break, a dnotify
event and out-of-band data (SIGURG) signal the owner the same way. The
kernel delivers these from `send_sigio_to_task()` / `send_sigurg_to_task()`
(`fs/fcntl.c`), which ask `sigio_perm()`: the owner's credentials (an euid
of 0 passes) and `security_file_send_sigiotask()` — never
`security_task_kill()`. So `fcntl(r, F_SETOWN, <agent>)`, `O_ASYNC` and one
byte written into the pipe killed the agent from a root shell (the default
action of SIGIO terminates), with no refusal and no record: the `task_kill`
hook, deny-by-default since `task-kill-signals-1`, never saw it.

### Mechanism

A BPF-LSM deny program on `file_send_sigiotask`
(`agent-ebpf/src/sigio_guard.rs`, `file_send_sigiotask_deny`, the 22nd deny
hook): towards a protected tgid (`PROTECTED_PIDS`: the agent, the watchdog,
a worker; the task the hook is asked about is each thread or each member
of a process group in turn, so `F_OWNER_TID` and `F_OWNER_PGRP` are judged
by the same tgid) every such signal is refused, `-EPERM` from the hook, and
`sigio_perm()` drops it.

- **No exemption by caller.** The hook runs in the context of the process
  whose I/O completed — for a socket, whatever process a softirq
  interrupted. Neither "the target itself" nor "the agent's family" tells
  anything there: an attacker's socket armed on the agent would be fired by
  the agent's own write to it. The agent, the watchdog and the workers
  never arm a file's owner (`xtask/tests/self_defense.rs` reads their
  code: no `O_ASYNC`, `FASYNC`, `F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`,
  `FIOASYNC`, `FIOSETOWN`, `SIOCSPGRP`, `F_SETLEASE`, `F_NOTIFY`).
- **The window.** Inside a signed trusted-installer window the window's
  signal grant (`KILL_GRANT`: SIGTERM, SIGCONT, SIGKILL, until its
  deadline, under this boot's session nonce) lets those signals through
  this path too — the test `task_kill` asks for PID 1
  (`task_kill::kill_grant_allows`). Root may already stop the agent inside
  a window with `systemctl kill`, which PID 1 relays, so this widens
  nothing; the plain SIGIO, SIGURG and every other signal stay refused
  inside a window. PID 1 is not asked for: this path has no sender.
- **The record.** `FS_OP_SIGIO` (`sigio`, NN-L-AT-001, High, Log):
  `target_ino` the tgid, `target_dev` the signal as it would have been
  delivered (29, SIGIO, for the plain one — the hook receives 0), behind
  the task denials' dedup (one record per caller and operation a second)
  and budget. The process the record names raised the I/O; it did not
  necessarily arm the file. The posture raises `DefenseImpairment`
  (ENGAGED) for it, whatever that process is (PID 1 included), never the
  decisive `AntiTamperDenial`: a socket's softirq must not steer the
  ladder at an innocent process.
- **A pidfd.** `pidfd_send_signal()` goes through `kill_pid_info_type()` →
  `check_kill_permission()` → `security_task_kill()`: the `task_kill` hook
  refuses it (the lab's signal cases already send through a pidfd; the
  privileged e2e checks EPERM).
- **Fail-open.** A target whose tgid cannot be read is let through and
  counted (`deny_fail_open`, slot `file_send_sigiotask`). The hook is a
  deny hook: not attached, the start is refused unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`.

### The other findings of the lot

- **BUG37 (P2): the per-attempt refusals had no budget.** A protected
  inode's unlink, rename, change, new entry, write-open or read-open, and a
  protected cgroup file's open, wrote a record at every attempt: a root
  loop of `rm` filled the 64 KiB `fs_protect` ring and every other denial
  record — a refused `kill`, a refused ptrace — was lost with it (counted,
  not kept). They now go behind a per-CPU budget of their own
  (`ATTEMPT_DENIAL_RATE`, 50 a second per CPU, no dedup by caller), never
  the task denials' (`TASK_DENIAL_RATE`); one held back is counted in
  `RING_DROPS` (`denial_rate`), a security ring: signed, and telemetry loss
  past the threshold. The refusal never depends on the record. The BPF
  guard's refusals (`bpf_handle`, `bpf_prog_type`, `bpf_map`, `bpf_link`)
  are not behind it: lot 290 records one per object on purpose (a
  `bpftool prog list` outside a window is a burst of them); their budget is
  a follow-up with its own measure.
- **BUG05 (P2):** `BPF_RAW_TRACEPOINT_OPEN` (17) attaches a program — a raw
  tracepoint, and through it `tp_btf`, `fentry`/`fexit` and LSM programs —
  and the `bpf` hook did not look at it: an attach that way left no record
  (the load's stayed). It is observed now (`raw_tracepoint_open`),
  NN-L-BPF-001 judges it as an attach, and the flood cap never holds it.
- **BUG71 (P1, `common::epg`):** `setgroups` was in the exploit guard's
  table of the calls that may change the ids: an id gain made through
  `commit_creds` while the thread is inside `setgroups` (a kernel write
  timed against a userns that allows it) was no anomaly. `setgroups`
  changes only the supplementary groups, which the guard does not compare;
  it is out of the table (x86-64, x32, both ia32 numbers).
- **BUG68 (P2, `common::wire`):** io_uring's `READV_FIXED` and
  `WRITEV_FIXED` (60, 61, 6.15) are file reads and writes, `RECV_ZC` (58)
  a socket receive — they were "other", and NN-L-IOU-002 missed the file
  or the network half.
- **BUG54 (documentation):** `RANSOMWARE_DECISIVE.md` promised the rename
  counter "never counts the renames of an atomic write"; an atomic save
  whose temporary carries its own extension (`data.tmp → data.json`) is
  counted — an encryptor's staging (`a.pdf.tmp → a.pdf.locked`) has that
  shape, so the code stays and the document says it (a burst of such
  saves gives no verdict: no `RenameExtension` signal).
- **BUG21 (P2):** the supervisor killed a worker it ended from the thread
  that ended it — the export thread for the export worker, which has no
  CAP_KILL over the worker's uid: EPERM, ignored, and a worker that
  ignored its channel's close stayed alive and protected. `bury`, which the
  supervisor's tick runs, kills a graveyard worker still alive again.
- **BUG03 (P2):** a byte that is not UTF-8 in `admin.pub` (an ISO-8859-1
  comment) failed the whole file and disabled the admin socket; it costs
  its own line now (nothing in a comment, the key in a key line), the
  bootstrap gate counts the lines of any bytes, and rotate-keys keeps such
  a comment byte for byte.
- **BUG35 (P2):** `run_bounded` joined its stdin writer without a bound: a
  descendant that inherited the pipe and never read it held the response
  chain. Past a grace the child's process group is killed (the writer gets
  EPIPE); a holder outside the group is not waited for past a second grace.
- **BUG33 (P3):** a worker's escaped stderr line could reach 206 bytes
  against its 200; the cut mark is inside the bound now, never in the
  middle of a `\xHH`.
- **BUG13 (P0)** was closed by lot 290 (#514); the enforce-mode privileged
  e2e also asks a read-only handle through the `PROTECTED_PIDS` pin now
  (EPERM).

### Residual

- The record names the process whose I/O raised the signal; the process
  that armed the file is not known to the hook (`fown_struct` keeps its
  credentials, not its pid). The armed descriptor is one whose owner is a
  protected pid: `/proc/<pid>/fdinfo/<fd>` of the suspects (`flags` with
  `O_ASYNC`, 020000) finds it.
- Other kernel-sent signals no `task_kill` hook sees stay out of this hook:
  a tty's job-control and hangup signals reach a process only in a session
  with that controlling terminal (the units have none); a child's exit
  signal and `PR_SET_PDEATHSIG` are a parent's and a child's own; the
  limits, the OOM score and the cgroup files are lot 273's, 273b's and
  273c's.
