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

- **Resource limits.** `memory.max`, `memory.high`, `cpu.max`, `pids.max`
  of the units are not refused: systemd writes them whenever it realises a
  unit (a start, a `set-property`), and a refusal there would sign
  systemd's own maintenance. A change is reported (`integrity_drift`,
  `limit_changed`; tamper case C12). `memory.max` set below the agent's
  use ends in an OOM kill of the unit — a follow-up: refuse the writers
  that are not PID 1, and make `set-property` of the units a detection.
- **Thaw.** A thaw is a write-open of `cgroup.freeze` too: outside a
  window it is refused like a freeze. A unit frozen inside a window must
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
- **cgroup v1.** Only the v2 hierarchy is protected; a v1 `freezer` or
  `name=systemd` hierarchy (a hybrid host) is not, and its `cgroup.procs`
  path checks no inode, so the move guard does not see it. A process in no
  v2 cgroup, or a host without one, is a signed degradation.
- **Handles opened earlier.** A descriptor of `cgroup.kill` opened for
  writing inside a window (or before the agent registered a fresh unit
  cgroup) keeps working: the deny is at open, as for every protected file.
- **The fresh cgroup at a restart.** systemd makes a new unit cgroup for
  every start; until the new agent's earliest registration (its first
  milliseconds; on a first boot, until its attach) that cgroup is not
  protected. The watchdog's: until its own registration at its start.
