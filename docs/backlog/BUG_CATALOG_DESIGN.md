# Session Bug Catalog — Pre-Beta Findings

**Status:** Catalog. NOT implementation. Read-only design document.
**Session date:** 2026-05-27 → 2026-05-28.
**Branch context:** `benchmark/cc-t7-13-fix` on commits `5a0d736` (T7.13 lineage) and `1c15300` (tactical fix sweep). Phase B design doc at `docs/design/POSTURE_FSM_V2_REDESIGN.md` (commit `592bf7f`).
**Total findings:** 13 (6 fixed this session, 5 architectural deferred, 2 cosmetic deferred).

This document is the authoritative session-findings record. Each entry is
self-contained (ID, severity, status, symptom, root cause, reproducer, fix or
fix-path, references). After the per-bug entries, §15 clusters the findings
by architectural pattern and links into the Phase B redesign and per-cluster
recommended fix directions.

---

## Table of Contents

| # | ID | Title | Severity | Status |
|---|---|---|---|---|
| 1 | BUG-008 | R011 kworker FP via parent_comm (historical) | Beta-blocker | **Fixed** (P-2), then **obsoleted** by P-7 |
| 2 | BUG-008' | R011 kworker exemption bypassable via forged `parent_comm` | Beta-blocker (security HIGH 9/10) | **Fixed** (P-7) |
| 3 | BUG-009 | systemd `ReadWritePaths` missing `/etc/northnarrow` | Beta-blocker | **Tactical fix shipped** (P-1); architectural deferred |
| 4 | BUG-010 | Anti-tamper blocks `systemctl restart` (own SIGTERM denied) | Beta-blocker architectural | **Deferred** |
| 5 | BUG-011 | Watchdog ptrace deadlock — cannot observe protected agent | Beta-blocker architectural | **Deferred** (watchdog disabled as mitigation) |
| 6 | BUG-012 | FIM noise — tmux/sshd reading `/etc/passwd`/`shadow`/`login.defs` | Cosmetic | **Deferred** |
| 7 | BUG-013 | Single-admin install cannot graceful-stop (2-of-N chicken-and-egg) | Beta-blocker architectural | **Deferred** |
| 8 | BUG-014 | Mass-write FP on sysfs/cgroup writes (PID 1 systemd at boot) | Beta-blocker | **Fixed** (P-6) |
| 9 | BUG-015 | Silent posture transitions — firing trigger absent from journal | V1.0-blocker (observability) | **Fixed** (P-5) |
| 10 | BUG-016 | Mass-write attribution log fires per-FileOpen, not per-edge | Cosmetic | **Deferred** (resolves organically post-BUG-014) |
| 11 | BUG-017 | Claude Code Bun-pool I/O trips mass-write threshold | Beta-blocker (dev-env only) | **Fixed** (P-8) |
| 12 | BUG-018 | `systemd-user` lineage gap — `uid=1000` helpers not auth-mediated | Beta-blocker architectural | **Deferred** |
| 13 | P-7 RESIDUAL | R011 `/proc/<ppid>/exe` TOCTOU over-fire on transient kworkers | Cosmetic | **Deferred** (subsumed by PF_KTHREAD-via-BPF) |

---

## 1. BUG-008 — R011 kworker FP via `parent_comm` *(historical, obsoleted)*

- **Severity:** Beta-blocker (at time of identification).
- **Status:** Fixed in P-2 (session-internal), then **obsoleted** by P-7 fix in commit `1c15300`. Documented here for the historical record only — the P-2 comm-based fix was security-insufficient.

**Symptom.** On every fresh boot, before agent attach to LSM hooks, the kernel's async module-loader (`request_module() → call_usermodehelper`) spawned `/sbin/modprobe` to probe hardware (e.g. `nfnetlink-subsys-10`). Once the agent attached, R011_KernelModuleTooling fired on the captured ProcessSpawn event, escalating posture toward Combat:

```
WARN VERDICT (rule) rule=R011_KernelModuleTooling
     action=KillProcess severity=High target_pid=NNNN
     target_filename=/sbin/modprobe parent_comm="kworker/u12:2"
```

**Root cause.** R011 unconditionally fired on `comm ∈ {insmod, modprobe, kmod}` with no signal to distinguish actor-driven module loads from kernel-driven (`request_module`) ones. Every Linux host boot includes legitimate kernel module-load activity.

**Reproducer (Phase 2.5 style).**
1. `sudo systemctl stop northnarrow-agent` (or fresh install).
2. Trigger a hardware/netlink action that the kernel handles via `request_module`. Easiest: `sudo modprobe -r some_safe_module && sudo modprobe some_safe_module` is NOT this case (direct user invocation). The kernel-driven case is exercised by any boot or by `sudo systemctl restart systemd-networkd`-class events that touch kernel-module-backed protocol handlers.
3. `sudo systemctl start northnarrow-agent`.
4. Within ~10 s: `sudo journalctl -u northnarrow-agent -n 50 | grep R011_KernelModuleTooling` — pre-P-2 yields one or more verdicts with parent_comm beginning with `kworker/`.

**Fix applied (P-2, then obsoleted).** Added `parent_comm.starts_with("kworker/")` exemption in `evaluate()`. Functional, but `parent_comm` is sourced from `task_struct->comm` via BPF probe — that field is writable from userspace via `prctl(PR_SET_NAME, …)`. A root attacker installing a rootkit could `prctl(PR_SET_NAME, "kworker/0:1")` and then `execve("/sbin/modprobe", …)` to bypass the exemption. The bypass was identified by the `/security-review` sub-task at HIGH confidence 9/10 → became BUG-008' (entry 2).

**References.**
- Obsoleted by BUG-008'.
- See `agent/src/posture/exempt.rs:15-26` for the established codebase rationale (comm is forgeable).
- POSTURE_FSM_V2_REDESIGN.md §2.4 — convergent FP class.

---

## 2. BUG-008' — R011 kworker exemption bypassable via forged `parent_comm`

- **Severity:** Beta-blocker. `/security-review` HIGH, confidence 9/10. MITRE T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions) defense bypass.
- **Status:** **Fixed** in P-7, commit `1c15300`. Residual TOCTOU over-fire captured as entry 13.

**Symptom.** Theoretical, not observed in the wild during this session (this is a defense-bypass surface, not a false-positive). A root attacker installing a kernel rootkit can defeat R011_KernelModuleTooling by:

```c
prctl(PR_SET_NAME, "kworker/0:1");
fork();
/* child: */ execve("/sbin/modprobe", (char*[]){"modprobe","evil_rootkit",NULL}, envp);
```

The kernel emits `sched_process_exec` for the child; BPF reads `parent_task->comm` = `"kworker/0:1"` → P-2 fix returned `None` → no KillProcess → malicious module loaded.

**Root cause.** P-2 used `parent_comm` (attacker-controllable via `prctl(PR_SET_NAME, …)`) as the kthread indicator. The codebase already documents this exact hazard in `agent/src/posture/exempt.rs:15-26`:

> *"`comm` is attacker-controllable (`prctl(PR_SET_NAME, …)`), so exempting by comm would let any process rename itself `sudo` to gain trigger immunity"*

P-2 violated that established invariant.

**Reproducer (security-test style).**
1. As root on a test VM:
   ```c
   /* paste-in PoC; compile and run */
   #include <sys/prctl.h>
   #include <unistd.h>
   #include <stdlib.h>
   int main() {
       prctl(PR_SET_NAME, "kworker/0:1");
       if (fork() == 0) {
           execl("/sbin/modprobe", "modprobe", "snd-pcm", NULL);
       }
       wait(NULL);
       return 0;
   }
   ```
2. Run the PoC. Under P-2: `journalctl -u northnarrow-agent | grep R011` shows no verdict (bypass successful). Under P-7: verdict fires with KillProcess (bypass closed).

**Fix applied.** Gate R011's kthread exemption on `/proc/<ppid>/exe` absence, not on `parent_comm`. `/proc/<pid>/exe` is kernel-resolved (mm->exe_file symlink), not forgeable from userspace. Kernel threads have no executable image and readlink returns `ENOENT`; userspace processes return a real path. Implementation:

- `agent/src/decision/rules/r011_kernel_module_tooling.rs:58-78` — new method `parent_is_kernel_thread(ppid: u32) -> bool`. Failsafe direction: parent gone, EACCES, or unexpected error → **return false → R011 fires** (over-fire is preferred to a missed rootkit install).
- `agent/src/decision/rules/r011_kernel_module_tooling.rs:39-46` — injectable `proc_root: PathBuf` so unit tests use a tempdir fixture.
- Regression test at `agent/src/decision/rules/r011_kernel_module_tooling.rs::tests::forged_kworker_comm_is_not_exempt` — builds a fake `/proc/<ppid>/exe → /home/evil/rootkit_installer` symlink and asserts R011 fires (closes the bypass). Plus `real_kthread_parent_is_exempt`, `normal_userspace_parent_fires`, `parent_gone_fails_safe_and_fires`.

**References.**
- See entry 13 (P-7 RESIDUAL) for the TOCTOU caveat.
- Phase B POSTURE_FSM_V2_REDESIGN.md §9.6 — PF_KTHREAD-via-BPF upgrade noted.

---

## 3. BUG-009 — systemd `ReadWritePaths` missing `/etc/northnarrow`

- **Severity:** Beta-blocker (cascades to broken signed-payload admin auth, FIM/canary/netflow subsystems disabled).
- **Status:** **Tactical fix shipped** (P-1 drop-in, applied at runtime on the dev host, NOT in repo). **Architectural fix DEFERRED** to V1.0 — split runtime state from config.

**Symptom.** On first boot of a fresh install, the agent failed to bootstrap several runtime-state files because `/etc/northnarrow/` was read-only under the unit's `ProtectSystem=strict`:

```
WARN agent signing key bootstrap failed pre-attach — audit log will be unsigned this boot
     error=creating signing-key tmpfile /etc/northnarrow/agent.sig.key.tmp
WARN audit log bootstrap failed pre-attach
     error=creating audit log /etc/northnarrow/audit.log
WARN pre-attach agent_id bootstrap failed — falling back to zero UUID;
     signed-payload admin operations will reject all clients
WARN fim baseline DB needs the agent signing key — load failed
WARN canary subsystem needs agent signing key — load failed
WARN netflow DB open failed — net drain loop will not spawn
```

Cascading impact: agent_id zero-UUID meant nn-admin signed payloads would be rejected → COMBAT unrecoverable.

**Root cause.** The shipped unit at `deploy/systemd/northnarrow-agent.service:94` lists `ReadWritePaths=/run/northnarrow /var/lib/northnarrow` — `/etc/northnarrow` is missing. The agent has runtime-state files in `/etc/northnarrow/` (`agent_id`, `agent.sig.key`, `audit.log`) mixed with operator-config files (`admin.pub`, `combat-rules.v4`, FIM/netflow blocklists). Under `ProtectSystem=strict`, only the listed paths are writable.

**Reproducer.**
1. Fresh install via `deploy/install.sh` on a host where `/etc/northnarrow/` does not pre-exist.
2. `sudo systemctl start northnarrow-agent`.
3. `sudo journalctl -u northnarrow-agent -b | grep -E "agent_id bootstrap failed|signing key bootstrap"` — pre-fix shows the cascade.
4. `sudo /usr/local/bin/nn-admin status --json | jq -r .last_admin_action_secs_ago` is `null`, and signed admin operations (`nn-admin shutdown`, `unlock`, `force-posture`) reject all clients because agent_id is zero UUID.

**Tactical fix shipped (P-1).** Drop-in at `/etc/systemd/system/northnarrow-agent.service.d/readwritepaths.conf` adds `/etc/northnarrow` to `ReadWritePaths`. systemd's list-type setting appends, so the effective value becomes `/run/northnarrow /var/lib/northnarrow /etc/northnarrow`. This is a runtime artifact on the dev host; it is NOT in repo (operator-applied configuration). Verified via `systemctl show northnarrow-agent.service -p ReadWritePaths --value`.

**Architectural fix DEFERRED (BUG-009-arch).** The tactical fix widens trust on `/etc/`, which is conceptually wrong — config directories should be read-only. The correct architectural fix is to relocate runtime-state files out of `/etc/northnarrow/` into `/var/lib/northnarrow/` (already writable, already PROTECTED_INODES-registered). Concretely:

- `/etc/northnarrow/agent_id` → `/var/lib/northnarrow/agent_id`
- `/etc/northnarrow/agent.sig.key` → `/var/lib/northnarrow/agent.sig.key`
- `/etc/northnarrow/audit.log` → `/var/lib/northnarrow/audit.log`

Keep in `/etc/northnarrow/` (operator config, read-only at runtime):
- `admin.pub`, `combat-rules.v4`, `combat-allow.cidrs`
- `fim-paths.v1`, `netflow-blocklist.v1`, `netflow-ja3-blocklist.v1`, `process-comm-allowlist.v1`, `netflow-comm-allowlist.v1`
- `canary-templates/*.tmpl`
- `mass-write-carveout.local` (BUG-017 overlay)
- All operator `.local` overlays

This requires:
1. CLI flag default changes (`--agent-id-file`, `--signing-key-file`, `--audit-log`).
2. `install.sh` updated to bootstrap the placeholders in `/var/lib/northnarrow/` (already does so for FIM logs).
3. `PROTECTED_INODES` registration paths updated.
4. Migration shim: if old paths exist at agent start, move them to new paths (one-time, then warn on subsequent boots).
5. Once architectural fix lands, the P-1 drop-in becomes dead config — operator should remove it.

**References.**
- Conceptually independent of POSTURE_FSM_V2; this is a packaging issue.
- See entry 4 (BUG-010) and entry 11 (BUG-017) for other runtime-state/config-state pollution patterns.

---

## 4. BUG-010 — Anti-tamper blocks `systemctl restart`

- **Severity:** Beta-blocker architectural.
- **Status:** **Deferred.** Workaround for this session: VM reboot between fixes (BUG-013 prevents nn-admin graceful shutdown).

**Symptom.** Mid-session, `sudo systemctl restart northnarrow-agent` produced TWO agent processes in the cgroup — the old PID (still alive, refusing SIGTERM) and a new PID. Both PIDs registered in PROTECTED_PIDS. Manual `sudo kill -TERM <old_pid>` returned `Operation not permitted` even as root.

```
$ pgrep -af northnarrow-agent
14151 /usr/local/bin/northnarrow-agent --no-ade ...
17761 /usr/local/bin/northnarrow-agent --no-ade ...

$ sudo systemctl show northnarrow-agent.service -p MainPID
MainPID=17761

$ sudo bpftool map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_PIDS
key: 61 45 00 00  value: 01    # 0x4561 = 17761 (new)
key: 47 37 00 00  value: 01    # 0x3747 = 14151 (orphan)
Found 2 elements

$ sudo kill -TERM 14151
kill: (14151): Operation not permitted
```

Both agent processes running concurrently, attempting to attach to the same BPF programs, write to the same files, etc. — incoherent state.

**Root cause.** The agent registers its own PID in `PROTECTED_PIDS` at boot, and the LSM `task_kill` BPF hook (`/sys/fs/bpf/northnarrow/prog_task_kill`) denies signal delivery to any PID in that map — including from root, including from systemd. systemd's `Restart=no` does not auto-restart the agent, but `systemctl restart` issues SIGTERM → SIGKILL after `TimeoutStopSec`. Both are denied. systemd's view of the restart "succeeds" (new PID notified READY=1), but the old PID is not actually terminated.

There is no escape hatch in the V1 anti-tamper design for "trusted systemd-driven stop" — the protection is symmetric: it defends against malicious termination AND legitimate restart.

**Reproducer.**
1. Agent running, attached to BPF, PROTECTED_PIDS populated with its own PID.
2. `sudo systemctl restart northnarrow-agent`.
3. Wait `TimeoutStopSec` (default 90 s). New agent process appears in cgroup.
4. `pgrep -af northnarrow-agent` — TWO PIDs.
5. `sudo kill -TERM <old_pid>` — `Operation not permitted`.

**Recommended fix path.** Two complementary mechanisms:

**(a) `KILL_OVERRIDE` BPF map (mirrors the existing `FS_PROTECT_OVERRIDE` pattern):** a userland-writable map that explicitly lists "signals authorized to pass" with a short-lived TTL. The LSM `task_kill` hook checks this override before denying. The agent's own signal handler on SIGTERM writes a self-authorized override entry, then performs graceful shutdown. systemd-issued SIGTERM is honored; an unauthorized signal (from a different PID without the override) is still denied.

**(b) `nn-admin shutdown` is the canonical graceful-stop path:** today it requires 2-of-N quorum (BUG-013 chicken-and-egg). The architectural fix is tied to BUG-013 — once bootstrap-mode 1-of-N is allowed for `shutdown` until the second key is minted, `systemctl restart` can be wrapped to issue an nn-admin shutdown signal first, then start.

**References.**
- Cluster: **anti-tamper trust model gap** (§15.1) — co-clustered with BUG-011 and BUG-013.
- POSTURE_FSM_V2_REDESIGN.md does NOT subsume this (orthogonal to detection FSM; this is response-pipeline trust).

---

## 5. BUG-011 — Watchdog ptrace deadlock

- **Severity:** Beta-blocker architectural.
- **Status:** **Deferred.** Mitigation: `sudo systemctl disable northnarrow-watchdog.service` (applied this session).

**Symptom.** Watchdog enters a hot-restart loop within seconds of start. Each restart attempt logs:

```
WARN watchdog exited with error error=reading /proc/17761/exe for argv reconstruction
INFO systemd: northnarrow-watchdog.service: Main process exited, code=exited, status=1/FAILURE
INFO systemd: northnarrow-watchdog.service: Scheduled restart job, restart counter is at 11.
```

Watchdog logs counter reaching double digits within ~30 s. Each failure ~250 ms; the journal floods.

**Root cause.** The watchdog's startup procedure includes verifying the agent binary by reading `/proc/<agent-pid>/exe` (and parsing argv from `/proc/<agent-pid>/cmdline`). The agent has registered itself in `PROTECTED_PIDS`, and the LSM `ptrace_access_check` hook (`/sys/fs/bpf/northnarrow/prog_ptrace_access_check`) denies all ptrace-like access to protected PIDs. `/proc/<pid>/exe` and `/proc/<pid>/cmdline` reads go through `PTRACE_MODE_READ_FSCREDS` permission checks — which the LSM hook denies. The watchdog cannot complete its argv-reconstruction verification, exits with error, systemd auto-restarts, infinite loop.

**Deadlock.** The watchdog needs to *observe* the agent to perform its co-protection function. The agent's anti-tamper defends against observation. There is no trust hierarchy distinguishing "the watchdog (a trusted local observer)" from "an attacker process trying to inspect the agent's state."

**Reproducer.**
1. Fresh install (per `deploy/install.sh`). `northnarrow-agent` and `northnarrow-watchdog` both enabled.
2. `sudo systemctl start northnarrow-agent`. Wait until PROTECTED_PIDS contains agent PID (~3 s).
3. `sudo systemctl start northnarrow-watchdog.service` → fails.
4. `sudo journalctl -u northnarrow-watchdog -n 30` shows `error=reading /proc/<agent-pid>/exe for argv reconstruction`.
5. systemd's auto-restart triggers; counter climbs. Stop with `sudo systemctl stop northnarrow-watchdog`.

**Recommended fix path.** `PROTECTED_OBSERVERS` BPF map (parallel to `PROTECTED_PIDS`) listing PIDs that ARE allowed to observe (read `/proc/<protected_pid>/*`) but not write/kill. The `ptrace_access_check` LSM hook checks: if requester is in `PROTECTED_OBSERVERS` AND target is in `PROTECTED_PIDS`, allow read-only ptrace_access. Watchdog PID is added to `PROTECTED_OBSERVERS` after the same exe-path verification the agent currently performs for `ExemptPids` (the watchdog's `/proc/<pid>/exe` must match `DEFAULT_WATCHDOG_EXE = /usr/local/bin/northnarrow-watchdog`, kernel-resolved, not forgeable).

This requires bootstrap-order coordination: watchdog must be started AFTER agent has PROTECTED_OBSERVERS pinned, OR agent must accept a registration request from a verified watchdog post-attach. Either pattern works; the latter is symmetric with how `ExemptPids` already refreshes the watchdog PID slot on a timer (`spawn_watchdog_exempt_refresh` in `agent/src/main.rs`).

**References.**
- Cluster: **anti-tamper trust model gap** (§15.1).
- Symmetric design with `ExemptPids` / `agent/src/posture/exempt.rs`.

---

## 6. BUG-012 — FIM noise: `tmux`/`sshd` reading `/etc/passwd|shadow|login.defs`

- **Severity:** Cosmetic (no posture impact, no detection-correctness impact; just journal volume).
- **Status:** **Deferred.**

**Symptom.** Continuous WARN-level FIM DRIFT log lines, once per second per session:

```
WARN FIM DRIFT path=/etc/passwd op=Opened modifier_pid=1063 modifier_uid=1000 modifier_comm=tmux: server
WARN FIM DRIFT path=/etc/shadow op=Opened modifier_pid=956 modifier_uid=0 modifier_comm=sshd
WARN FIM DRIFT path=/etc/login.defs op=Opened modifier_pid=956 modifier_uid=0 modifier_comm=sshd
WARN FIM DRIFT path=/etc/passwd op=Opened modifier_pid=956 modifier_uid=0 modifier_comm=sshd
[…]
```

tmux re-reads `/etc/passwd` periodically to refresh user-info; sshd reads `/etc/passwd|shadow|login.defs|group` on every connection attempt. Both are legitimate. FIM emits a WARN per read.

**Root cause.** FIM watches every path in `fim-paths.v1` (125 default paths). The FIM observer fires on file_open events; `Event::Fim` rate-limiting at agent/src/fim/drain.rs reduces duplicate paths-per-PID but does not suppress *Opened* op-class on highly-read system files. The action is `Log` (NN-L-FIM-001 family, severity Low), so it does not feed posture; it is purely observability noise.

**Reproducer.**
1. Active SSH session into the host. `sudo tail -f /var/log/journal/...` or `journalctl -u northnarrow-agent -f`.
2. Any normal activity (a second SSH login, `getent passwd`, `id`) triggers reads on `/etc/passwd|shadow`.
3. FIM DRIFT lines accumulate at ~1 Hz steady-state.

**Recommended fix path.** Operator-tunable op-mask exclusion. Allow `fim-paths.local` to specify per-path which op classes are interesting:

```
+/etc/passwd op:Modified,Renamed,Deleted    # ignore Opened (read-only access)
+/etc/shadow op:Modified,Renamed,Deleted
+/etc/login.defs op:Modified,Renamed,Deleted
```

Defaults remain "all ops" for any path; operator narrows the mask per path. Schema extension to the existing `fim-paths.local` parser (`agent/src/config/overlay.rs`, `agent/src/fim/paths_config.rs`). NN-L-FIM-001 rule body unchanged; the op-mask filter happens at FIM drain.

**References.**
- POSTURE_FSM_V2_REDESIGN.md §5 — V2 multi-signal redesign would replace "fire on every Opened" with "fire on data-mutation pattern" anyway. This BUG-012 fix may be subsumed.

---

## 7. BUG-013 — Single-admin install cannot graceful-stop (2-of-N chicken-and-egg)

- **Severity:** Beta-blocker architectural.
- **Status:** **Deferred.** This session worked around it with VM reboots.

**Symptom.** On a fresh single-admin-key install (the default `deploy/install.sh` flow):

```
$ sudo /usr/local/bin/nn-admin shutdown --help
Usage: nn-admin shutdown [OPTIONS] --key <KEY> --cosign-key <COSIGN_KEY>
[…]
BOTH keys are required — the quorum requires two distinct admin keys, each with
the `shutdown` role (per admin.pub allowlist). Same key for both args fails
server-side as QuorumNotMet { required: 2, provided: 1 } because the server
tallies distinct fingerprints.
```

Only ONE admin key exists on disk (`/etc/northnarrow/admin.key`). The same key cannot satisfy both `--key` and `--cosign-key`. To MINT a second key, `nn-admin rotate-keys add` is the path — but `rotate-keys` ALSO requires 2-of-N quorum to add a key. Chicken-and-egg.

**Root cause.** Both `shutdown` and `rotate-keys add` enforce 2-of-N quorum (design §10 / §7.2). `install.sh` (Beta Step 4c) bootstraps exactly one admin keypair. There is no bootstrap mode that allows 1-of-N until the fleet is established.

The intent is sound (defend against single-key compromise post-deployment) but the bootstrap UX makes the deployment unreachable: a fresh install cannot reach a 2-key state without an existing 2-key state.

**Reproducer.**
1. Fresh install: `sudo deploy/install.sh`. Single keypair generated at `/etc/northnarrow/admin.{key,pub}`.
2. Try graceful shutdown: `sudo /usr/local/bin/nn-admin shutdown --key /etc/northnarrow/admin.key --cosign-key /etc/northnarrow/admin.key` → `QuorumNotMet { required: 2, provided: 1 }`.
3. Try to add a second key: `sudo /usr/local/bin/nn-admin rotate-keys add …` — same failure (2-of-N required).
4. Only path to a clean stop is `sudo reboot` (which works, but is not "graceful").

**Recommended fix path (b — agreed in session ACK of BUG-013):** **Bootstrap-mode 1-of-N until the first rotate-keys-add succeeds, then permanent 2-of-N.** Mechanically:

- `install.sh` marks the install as `bootstrap` mode (sentinel file at `/etc/northnarrow/.bootstrap`, root-owned 0600).
- While the sentinel is present, `nn-admin rotate-keys add` accepts 1-of-N quorum.
- The first successful `rotate-keys add` operation:
  - Verifies a SECOND distinct admin key has been added to `/etc/northnarrow/admin.pub`.
  - DELETES the sentinel file (via the same atomic rename-then-protect path the FIM logs use).
- Post-sentinel-removal, the agent enforces 2-of-N for ALL admin operations including `rotate-keys add` and `shutdown`.

Security stays strong post-bootstrap (full 2-of-N). The bootstrap window is narrow (operator runs `install.sh` then immediately runs `rotate-keys add` from a separate offline-backed key). Operator workflow:

```
sudo deploy/install.sh
# admin.key (key1) + admin.pub generated
sudo cp /path/to/offline/key2.pub >> /etc/northnarrow/admin.pub  # add second pubkey
nn-admin rotate-keys add --key /etc/northnarrow/admin.key \
                          --new-pub /path/to/key2.pub  # 1-of-N during bootstrap
# .bootstrap sentinel removed; permanent 2-of-N enforced
```

Alternative considered: `install.sh` generates TWO keypairs by default. Rejected because operators rarely have two offline-storage paths ready at install time; the bootstrap-mode approach decouples timing.

**References.**
- Cluster: **anti-tamper trust model gap** (§15.1).
- Interacts with BUG-010 (anti-tamper blocks restart) — once BUG-013 fix lands, `nn-admin shutdown` becomes the canonical pre-restart graceful-stop, partially mitigating BUG-010.

---

## 8. BUG-014 — Mass-write FP on sysfs/cgroup writes (PID 1 systemd at boot)

- **Severity:** Beta-blocker (every fresh boot escalated to COMBAT before fix).
- **Status:** **Fixed** in P-6, commit `1c15300`.

**Symptom.** Every fresh boot of the agent on this host escalated posture from OBSERVING → COMBAT within ~3 s of agent attach. Ground-truth attribution captured by BUG-015 observability:

```
07:42:40.918 WARN POSTURE TRANSITION state=COMBAT trigger=Some(ConfirmedIntrusion)
07:42:40.775 WARN mass-write threshold crossed — posture will escalate to COMBAT
              trigger="ConfirmedIntrusion_MassWrite"
              focal_pid=1  focal_comm=systemd
              focal_filename=/sys/fs/cgroup/system.slice/ssh.service/memory.zswap.max
              count_within_window=20  threshold=20
```

systemd (PID 1), during early boot, writes to ~30+ cgroupfs control files (`memory.max`, `memory.swap.max`, `pids.max`, `cpu.weight`, etc.) per service to configure resource limits. These writes are observed via the file_open LSM hook, count toward `confirmed_intrusion`'s mass-write arm, threshold trips at the 20th, posture goes Combat.

Also closed T7.13 Scenario B (`sudo apt-get` cascade) — apt's systemd service activations during `update`/`upgrade` trigger the same cgroupfs-write burst from PID 1 systemd.

**Root cause.** The mass-write rule counts *any* file_open with write flags. Pseudo-filesystems (`/sys`, `/proc`) are not data writes — they are kernel control RPCs that happen to use the `write(2)` syscall syntax. The rule conflates the two.

**Reproducer.**
1. Pre-fix: agent build without `MASS_WRITE_CARVEOUT_PREFIXES`. Reboot. Observe COMBAT within seconds via `sudo nn-admin status --json`.
2. Post-fix: same reboot. Observe `nn-admin status` reports `Observing` (or `Alerted` from BUG-018, not Combat).
3. Direct test (no reboot): `sudo systemd-run --unit=t714-trigger --collect bash -c 'for i in $(seq 1 30); do echo 100M > /sys/fs/cgroup/user.slice/memory.max; done'` — pre-fix Combats; post-fix stays Observing.

**Fix applied (P-6, commit `1c15300`).** Path-class carve-out in `agent/src/posture/triggers.rs:83-89`:

```rust
pub(super) const MASS_WRITE_CARVEOUT_PREFIXES: &[&str] = &[
    "/sys/", "/proc/", "/run/systemd/", "/run/log/journal/",
];

fn is_mass_write_carveout(filename: &str, extras: &[String]) -> bool {
    MASS_WRITE_CARVEOUT_PREFIXES.iter().any(|p| filename.starts_with(p))
        || extras.iter().any(|p| filename.starts_with(p.as_str()))
}
```

Applied at both the focal_filename check (triggers.rs:533) and the recent-loop count (triggers.rs:556) so a burst of recent writes that includes kernel-RPC paths doesn't inflate the count.

Deliberately NOT in the carve-out:
- `/dev/shm/` — canonical ransomware staging tmpfs.
- `/run/user/<uid>/` — per-user runtime where a compromised user session could mass-write.
- `/tmp/` — exec-from-tmp arm of `confirmed_intrusion` independently catches /tmp executions.

Regression tests at `agent/src/posture/triggers.rs::tests::mass_write_excludes_sysfs_writes` (+ 3 sibling `excludes_*` tests + 3 `still_fires_for_*` tests + 1 mixed-boundary test).

**References.**
- Cluster: **detection heuristic crudeness** (§15.2) — subsumed by POSTURE_FSM_V2_REDESIGN.md §5.1 (path-class becomes a continuous "is-data-path" score, not a binary list).
- See entry 10 (BUG-016) — mass-write log spam resolves once the threshold isn't crossed by sysfs.
- See entry 11 (BUG-017) — same root cause class on different path family.

---

## 9. BUG-015 — Silent posture transitions

- **Severity:** V1.0-blocker for observability/operability. Indirectly Beta-blocker — without it, diagnosing BUG-014/BUG-017/BUG-018 would have required code instrumentation per iteration.
- **Status:** **Fixed** in P-5, commit `1c15300`.

**Symptom.** Pre-fix, the `WARN POSTURE TRANSITION` log line carried only the new state, not the firing trigger:

```
WARN POSTURE TRANSITION state=COMBAT      ← which trigger fired? unknown from journal
```

The firing `TriggerType` was recorded in `PostureMachine.inner.transitions` (in-memory ring buffer, see `agent/src/posture/mod.rs::log_transition`) but not exposed to journald. Diagnosing posture transitions required either:
- Reading the in-memory ring buffer via internal API (no exposed CLI surface).
- Adding tracing instrumentation and rebuilding.

**Root cause.** `PostureMachine::observe` returned `Option<PostureState>` — the firing `TriggerType` was discarded at the API boundary. The WARN log at `agent/src/main.rs` had no way to retrieve it.

**Reproducer.**
1. Trigger any posture transition (e.g., scenario C from `tests/repro/t713/scenario_c_ransomware_shape.sh`).
2. `sudo journalctl -u northnarrow-agent | grep POSTURE TRANSITION` — pre-fix shows only the state, not the cause.

**Fix applied (P-5, commit `1c15300`).** Two changes:

(a) `PostureMachine::observe` return type changed from `Option<PostureState>` to `Option<(PostureState, Option<TriggerType>)>` — the firing trigger (computed internally at the rank-collapse point) is now exposed. `agent/src/posture/mod.rs:271-292`.

(b) `agent/src/main.rs:1773-1779` log line now includes `trigger = ?firing_trigger`:

```rust
warn!(
    state = %new_state.kind(),
    trigger = ?firing_trigger,
    "POSTURE TRANSITION"
);
```

(c) `confirmed_intrusion` mass-write arm now emits a one-shot attribution WARN when the threshold is crossed, with focal_pid + focal_comm + focal_filename + count_within_window. `agent/src/posture/triggers.rs:601-608`. This was what enabled the BUG-014 PID 1 systemd identification.

Regression tests at `agent/src/posture/tests.rs::observe_returns_firing_trigger_on_transition` and `observe_returns_none_when_no_transition`.

**Known limitation.** The mass-write attribution WARN currently fires per-FileOpen above threshold, not per-threshold-edge (entry 10 = BUG-016). Cosmetic.

**References.**
- POSTURE_FSM_V2_REDESIGN.md §8.4 — V2 will extend the return type further to surface per-signal confidence breakdown.

---

## 10. BUG-016 — Mass-write attribution log fires per-FileOpen, not per-edge

- **Severity:** Cosmetic.
- **Status:** **Deferred.** Resolves organically once BUG-014 prevents sysfs writes from hitting threshold.

**Symptom.** During the BUG-014 ground-truth capture, ~30 identical attribution WARNs fired per Combat-engage:

```
… mass-write threshold crossed … count_within_window=20 threshold=20
… mass-write threshold crossed … count_within_window=21 threshold=20
… mass-write threshold crossed … count_within_window=22 threshold=20
… (continues for every additional write above threshold) …
```

The WARN fires inside `confirmed_intrusion`'s mass-write arm, which runs on every focal FileOpen event. Once the count exceeds threshold, every subsequent FileOpen from the same PID re-triggers the WARN until the 60 s window decays.

**Root cause.** The attribution WARN was added in P-5 (BUG-015 fix) inline in the rule body. It has no "already-warned-this-edge" guard. Logically the rule is "fire if count ≥ MIN" and re-fires on every event.

**Reproducer.**
1. Mass-write burst from a non-exempt PID (pre-BUG-014: PID 1 systemd at boot; post-BUG-014: simulate via `sudo systemd-run … bash -c 'for i in $(seq 1 40); do echo > /home/test/f_$i; done'`).
2. `sudo journalctl -u northnarrow-agent --since "30 seconds ago" | grep "mass-write threshold"` — pre-fix: ~20+ identical lines.

**Recommended fix path.** Add a `HashSet<(focal_pid, window_start_ts)>` to `TriggerDetector` that records "already-warned" edges; emit the WARN only on the transition from `count == MIN - 1` → `count == MIN`. Window-roll clears the set entry. Minor code (~5-10 lines) but fix is deferred because post-BUG-014, the spam scenario no longer occurs naturally (sysfs writes don't count, so the most common high-volume burst is suppressed). Re-evaluate if other workloads still trip the spam.

**References.**
- POSTURE_FSM_V2_REDESIGN.md §5.1 — V2 replaces the count-based mass-write arm with confidence-scored multi-signal. The per-edge log decision belongs in the new confidence-calculation code.

---

## 11. BUG-017 — Claude Code Bun-pool I/O trips mass-write threshold

- **Severity:** Beta-blocker on this dev host (Claude Code is the load generator); NOT on operator hosts (no Claude Code in production deployments).
- **Status:** **Fixed** in P-8 via runtime-configurable overlay, commit `1c15300`.

**Symptom.** Post-BUG-014 fix, mass-write still tripped — but the focal PID was no longer PID 1 systemd. Ground-truth attribution:

```
WARN mass-write threshold crossed — posture will escalate to COMBAT
     trigger="ConfirmedIntrusion_MassWrite"
     focal_pid=1112  focal_comm="Bun Pool 1"
     focal_filename=/home/forty/.claude/projects/.../subagents/agent-…jsonl
     count_within_window=20  threshold=20
```

The Bun runtime (Claude Code's execution engine) maintains a worker pool; each worker writes subagent transcripts to `/home/<user>/.claude/projects/.../subagents/*.jsonl` and tool outputs to `/tmp/claude-1000/.../tasks/*.output`. Heavy multi-agent operation (e.g., the `/security-review` sub-task spawning + the parallel filter sub-tasks) exceeds 20 writes in 60 s.

**Root cause.** Same class as BUG-014: the mass-write rule's binary threshold cannot distinguish "legitimate high-IO dev tool" from "ransomware." The BUG-014 carve-out covers kernel-RPC pseudo-FS but deliberately does NOT carve out `/home/` or `/tmp/` (those are real ransomware targets).

**Reproducer.**
1. On a host running Claude Code (or any other Bun/Node.js application with bursty tool I/O).
2. Trigger heavy multi-agent activity (or simulate: `for i in $(seq 1 25); do echo "data_$i" > /home/$USER/.claude/test_$i; done`).
3. Within seconds: `sudo journalctl -u northnarrow-agent | grep "mass-write threshold"` shows attribution with `focal_filename` under `/home/<user>/.claude/`.

**Fix applied (P-8, commit `1c15300`).** Operator-tunable runtime overlay at `/etc/northnarrow/mass-write-carveout.local`. Schema mirrors other operator overlays (`fim-paths.local`, `process-comm-allowlist.local`):

```
# /etc/northnarrow/mass-write-carveout.local
# DEV-HOST ONLY — DO NOT deploy to operator hosts
+/home/forty/.claude/
+/tmp/claude-
```

Implementation:
- Loader: `agent/src/posture/mass_write_overlay.rs::load_mass_write_carveout_extras` (DEFAULT_MASS_WRITE_OVERLAY constant at line 31).
- TriggerDetector field: `mass_write_extras: Arc<Vec<String>>` (triggers.rs:174-178), builder method `with_mass_write_extras` (triggers.rs:223).
- Wired in `agent/src/main.rs` boot path: file loaded once at agent start, passed via `PostureMachine::new_with_hooks_and_exempt_and_auth_and_extras`.
- 4 parser tests + 3 detector integration tests (`mass_write_extras_overlay_exempts_listed_prefix`, etc.).

The overlay is **operator deployment artifact**, NOT in repo. The dev-host copy with `/home/forty/.claude/` is documented and clearly DEV-ONLY in its inline comments.

**References.**
- Cluster: **detection heuristic crudeness** (§15.2) — same class as BUG-014, BUG-018.
- POSTURE_FSM_V2_REDESIGN.md §5.1 — V2 multi-signal redesign eliminates the need for explicit per-path overlays by scoring writes on entropy/extension-rename/lineage-trust rather than count alone. Bun-pool transcript writes would score very low on the V2 ransomware-shape confidence (low entropy text JSON; no extension-rename; long-lived parent process).

---

## 12. BUG-018 — `systemd-user` lineage gap

- **Severity:** Beta-blocker architectural. Causes posture=Alerted at every boot on hosts with PAM-mediated user sessions (i.e., every Linux multi-user host).
- **Status:** **Deferred.** No tactical fix attempted because the naive AUTH_BINARY_EXES widening is unsafe.

**Symptom.** Within ~5 s of every fresh agent attach on a host with an active SSH user session, posture transitions OBSERVING → ALERTED:

```
07:42:45.383  WARN POSTURE TRANSITION state=ALERTED trigger=Some(SensitiveFileAccess)
```

No corresponding actor-driven `sudo cat /etc/shadow` or similar — the trigger fires on legitimate uid=1000 helpers spawned by `systemd --user` reading `/etc/passwd` during session setup.

Network is NOT isolated (Alerted ≠ Combat), but the host is permanently in a "low-grade alert" baseline that mucks with detection-test interpretation (every escalation now starts from Alerted, not Observing).

**Root cause.** The T7.13 auth-lineage exemption (commit `5a0d736`, `agent/src/posture/lineage.rs`) keys on `/proc/<pid>/exe` matching `AUTH_BINARY_EXES`. On modern systemd-PAM Linux, the SSH login does NOT make sshd the direct parent of the user's shell:

1. sshd accepts the connection (PID 967, uid=0).
2. PAM `pam_systemd.so` notifies systemd PID 1 to start `user@1000.service`.
3. `systemd --user` (PID 974, uid=1000) launches under PID 1, NOT under sshd.
4. PAM session helpers (xdg generators, env helpers, dbus, locale-check, etc.) spawn under `systemd --user`, all uid=1000.
5. One or more of these reads `/etc/passwd` legitimately.

The `is_auth_mediated` walk: helper → `systemd-user` (PID 974, `/usr/lib/systemd/systemd`) → `systemd` (PID 1, also `/usr/lib/systemd/systemd`) → end. Neither match an entry in `AUTH_BINARY_EXES`. `SensitiveFileAccess` fires.

**Naive fix is unsafe.** Adding `/usr/lib/systemd/systemd` to `AUTH_BINARY_EXES` auth-mediates ANY process whose lineage runs through PID 1 — which is every persistent service on the host. The argv differentiator (`--user`) is not currently plumbed into the lineage cache, and argv is itself untrusted (an attacker with execve setup tricks can supply arbitrary argv).

**Reproducer.**
1. Fresh boot of a host with an SSH login active for a uid=1000 user. Or: cold-start a new login session post-boot.
2. Within 5-10 s: `sudo /usr/local/bin/nn-admin status --json | jq -r .posture` → `Alerted`.
3. `sudo journalctl -u northnarrow-agent -b | grep "POSTURE TRANSITION"` shows `trigger=Some(SensitiveFileAccess)` near the time of session start.

**Recommended fix path.** **DO NOT** patch via AUTH_BINARY_EXES. Instead, **subsume into POSTURE_FSM_V2_REDESIGN.md §5.2** — replace the binary auth-mediated/not gate with a continuous `lineage_trust_score(pid) → f32 ∈ [0, 1]`:

- Interactive sshd→bash with controlling tty: 0.95
- **`systemd-user` (uid ≥ 1000) PAM-session ancestry: 0.7** ← BUG-018 case scores 0.7, not 0
- cron/systemd-timer user-job lineage: 0.5
- Daemon/service with no tty, lineage rooted at PID 1 system slice: 0.3
- Orphan PID, no parent, no tty: 0.1

A 0.7 lineage trust suppresses most uid=1000 sensitive-file-access FPs while preserving detection of a genuine `uid=1000` ransomware burst (0.7 alone insufficient; needs multi-signal confirmation per §5.1).

Detection of "PAM-attested user session" requires a signal that V1 does not currently track: presence of a session leader (TIOCGSID), session_id in `/proc/<pid>/status` Session field, or systemd's reported "user manager" classification (queryable via `sd_pid_get_user_unit`).

**References.**
- Cluster: **detection heuristic crudeness** (§15.2).
- POSTURE_FSM_V2_REDESIGN.md §2.3 (problem statement) and §5.2 (proposed fix).

---

## 13. P-7 RESIDUAL — R011 `/proc/<ppid>/exe` TOCTOU over-fire on transient kworkers

- **Severity:** Cosmetic. Security-neutral (over-fire only, no bypass).
- **Status:** **Deferred.** Subsumed by PF_KTHREAD-via-BPF (Phase C scope, POSTURE_FSM_V2_REDESIGN.md §9.6).

**Symptom.** Post-P-7 fix, R011 fires on legitimate kernel-driven modprobe events when the kworker parent has been reaped from the pool before the agent's userspace `/proc/<ppid>/exe` check:

```
07:42:40.918  WARN VERDICT (rule) rule=R011_KernelModuleTooling
              action=KillProcess severity=High target_pid=961
              target_filename=/sbin/modprobe parent_comm="kworker/u12:2"
07:42:40.919  INFO EXECUTED action=KillProcess primary=AlreadyGone { pid: 961 }
```

modprobe already exited before the agent's kill attempt → `AlreadyGone`. Hardware probe completes. R011's KillProcess action has no effect. **Functional impact: zero.** Just noisy WARN VERDICT log lines.

**Root cause.** The P-7 fix gates the kthread exemption on `/proc/<ppid>/exe` absence. For a live kworker, that returns `NotFound` → returns true → exempts. For a kworker that has been reaped (exited) between exec event delivery and the agent's userspace check, `/proc/<ppid>/` is *also* gone → my failsafe (`return false` to avoid silently exempting attacker scenarios) → returns false → R011 fires.

Kworkers in the pool can be short-lived. The kernel's `call_usermodehelper` queues to a worker, the worker spawns modprobe via execve, the worker can be released back to the pool quickly. The race window between `sched_process_exec` (delivered to agent ringbuf) and agent's `/proc` readlink is microseconds-to-milliseconds, which is enough.

**Security analysis.** The TOCTOU manifests only in the *over-fire* direction (legitimate kworker over-flagged). The bypass direction (forged kworker comm) is fully closed — the `forged_kworker_comm_is_not_exempt` regression test in P-7 verifies this. So this residual is acceptable from a security standpoint; it is purely a cosmetic noise issue.

**Reproducer.**
1. Fresh boot or any kernel-driven module-load event (network adapter hotplug, USB device, etc.).
2. `sudo journalctl -u northnarrow-agent -b | grep R011_KernelModuleTooling` — observe verdicts with `parent_comm="kworker/..."` and immediately followed by `EXECUTED action=KillProcess primary=AlreadyGone`.

**Recommended fix path.** Plumb the PF_KTHREAD flag (kernel `task_struct->flags & 0x00200000`) through the BPF probe into the wire-format `ProcessSpawnRaw` (additive field at the end, per the Tappa 10.6 §13 Q5 strict-append rule). Userland decodes a non-zero flag as "parent is a real kthread, agent-can-trust-this-bit" — no race, no /proc lookup needed. The userspace `/proc/<ppid>/exe` check from P-7 becomes a fallback for older agent-ebpf builds.

Implementation effort: ~30-50 LOC in agent-ebpf + 1 field in common/src/wire + 1 field in common/src/model + decode + rule update. Lock-in: requires discovering the `task_struct.flags` BTF offset for the production kernel (analogous to existing `TASK_STRUCT_COMM_OFFSET` in `agent-ebpf/src/btf_offsets.rs`).

**References.**
- Cluster: **kernel-thread identification** (§15.3).
- POSTURE_FSM_V2_REDESIGN.md §9.6 — explicitly called out as the upgrade path.
- Direct predecessor: BUG-008 (P-2 comm-based, withdrawn), BUG-008' (P-7 /proc-based, security-correct but TOCTOU-prone).

---

## 14. Session ship summary

### 14.1 Code on `benchmark/cc-t7-13-fix` after this session

| Commit | Type | Title |
|---|---|---|
| `5a0d736` | code | feat(t7.13): auth lineage exemption for sudo subprocess cascade (CC implementation) — predates this session |
| `1c15300` | code | fix: pre-beta bug sweep — R011 bypass, BUG-014 carve-out, BUG-017 overlay, observability **(pushed to origin)** |
| `592bf7f` | docs | docs(design): POSTURE_FSM_V2 redesign — gradient multi-signal posture + fleet-level architecture **(local only)** |
| *(this commit)* | docs | docs(backlog): session bug catalog — 13 findings with reproducers, fix paths, thematic clustering **(local only)** |

### 14.2 Runtime artifacts on the dev host (NOT in repo)

| Path | Purpose | Lifecycle |
|---|---|---|
| `/etc/systemd/system/northnarrow-agent.service.d/no-ade.conf` | `--no-ade` flag override | Operator-managed |
| `/etc/systemd/system/northnarrow-agent.service.d/readwritepaths.conf` | BUG-009 tactical fix (P-1) | Remove when BUG-009-arch lands |
| `/etc/northnarrow/mass-write-carveout.local` | BUG-017 dev-env carve-out | Dev-only; absent on operator hosts |
| `/etc/northnarrow/combat-allow.cidrs` (with `10.0.2.0/24`) | Anti-lockout SSH carve-out for COMBAT iptables | Operator-managed |
| watchdog disabled (`systemctl disable northnarrow-watchdog.service`) | BUG-011 mitigation | Until BUG-011 fix lands |

---

## 15. Thematic Clusters

Multiple findings share a common root cause. Fixing them piecemeal is correct
short-term; recognizing the cluster is what lets V1.0 / V2.0 ship a coherent
redesign rather than 13 separate patches.

### 15.1 Anti-tamper trust model gap *(BUG-010 + BUG-011 + BUG-013)*

These three are the same problem at different layers: **the V1 anti-tamper
model has no concept of "trusted local controllers / observers / authorities."**
Every "is this principal allowed to perform action X on the protected agent?"
question is answered "no, unless the requester is the agent itself."

- **BUG-010**: systemd (the host's process supervisor) cannot stop the agent
  because the agent's own PID is in PROTECTED_PIDS and `task_kill` LSM denies
  the SIGTERM. systemd is the legitimate controller; it has no
  protected-channel signal authority.
- **BUG-011**: the watchdog (an explicit local observer of the agent) cannot
  read `/proc/<agent>/exe` because ptrace_access_check LSM denies. The
  watchdog is the legitimate observer; it has no protected-channel
  observation authority.
- **BUG-013**: the operator (the legitimate admin authority) cannot issue
  graceful shutdown on a fresh single-key install because the 2-of-N quorum
  has a bootstrap chicken-and-egg. The operator is the legitimate authority;
  the system locks them out at install time.

**Unified fix direction.** Introduce a small explicit trust hierarchy at the
anti-tamper layer:

| Map | Role | Mechanism |
|---|---|---|
| `KILL_OVERRIDE` (BPF map, parallel to FS_PROTECT_OVERRIDE) | "this PID may signal this PID with a TTL'd, agent-self-issued override" | Agent's SIGTERM handler writes the override before graceful drain; systemd → agent SIGTERM authorized. |
| `PROTECTED_OBSERVERS` (BPF map, parallel to PROTECTED_PIDS) | "this PID is a verified local observer; ptrace-read-access to PROTECTED_PIDS allowed, write/kill still denied" | Watchdog PID registered after exe-path verification (analogous to `ExemptPids`). |
| `BOOTSTRAP_MODE` sentinel (filesystem, `/etc/northnarrow/.bootstrap`) | "1-of-N quorum permitted for `rotate-keys add` until the sentinel is cleared by a successful 2nd-key add" | install.sh creates; first rotate-keys-add success deletes. |

Single coherent design — these three become one design doc + one
implementation PR.

### 15.2 Detection heuristic crudeness *(BUG-014 + BUG-017 + BUG-018)*

These three are all manifestations of **binary single-signal heuristics being
too coarse for the real workload distribution**:

- **BUG-014**: count of file_opens, no path-class signal → systemd's
  cgroup writes mistaken for ransomware.
- **BUG-017**: count of file_opens, no entropy or extension-rename signal →
  Claude Code's transcript writes mistaken for ransomware.
- **BUG-018**: binary allowlist of auth binaries, no continuous trust score
  → systemd-user-mediated session helpers mistaken for unauthenticated
  uid=1000 attackers.

**Unified fix direction.** **`docs/design/POSTURE_FSM_V2_REDESIGN.md`** —
specifically §5.1 (multi-signal mass-write confidence) and §5.2 (continuous
lineage trust score). The redesign subsumes all three; the tactical fixes
(BUG-014 path carve-out, BUG-017 runtime overlay, BUG-018 deferred) become
obsolete once V2 lands.

### 15.3 Kernel-thread identification *(BUG-008 + BUG-008' + entry 13 TOCTOU)*

The same question — "is this process's parent a kernel thread?" — has been
answered three different ways across this session, each with a known
limitation:

- **BUG-008 (P-2)**: gate on `parent_comm.starts_with("kworker/")`.
  Limitation: `comm` is forgeable via `prctl(PR_SET_NAME, …)` — security bypass.
- **BUG-008' (P-7)**: gate on `/proc/<ppid>/exe` absence. Limitation:
  TOCTOU race when kworker is reaped before userland readlink — cosmetic
  over-fire on transient kworkers.
- **Entry 13 (Phase C)**: gate on `PF_KTHREAD` flag read in BPF at exec
  time. No known limitation; this is the clean answer.

**Unified fix direction.** Plumb PF_KTHREAD via BPF (entry 13's recommended
fix path). When that lands, both BUG-008'-style userland /proc checks and
the residual cosmetic over-fire disappear in one move. POSTURE_FSM_V2_REDESIGN.md
§9.6 notes this as the path.

### 15.4 State/config separation *(BUG-009 + BUG-009-arch)*

Single-bug cluster but worth naming for symmetry: the agent's runtime-state
files (`agent_id`, `agent.sig.key`, `audit.log`) are currently colocated with
operator-config files in `/etc/northnarrow/`. This forces `ReadWritePaths` to
include `/etc/northnarrow` (tactical P-1 fix), which conceptually widens
write authority across a directory that should be read-only at runtime.

**Unified fix direction.** Relocate runtime-state to `/var/lib/northnarrow/`
(already writable, already PROTECTED_INODES-tracked). See entry 3
(BUG-009-arch) for the migration steps. Eliminates the P-1 drop-in once
the relocation lands.

---

## 16. Verification gaps in this catalog

The following references could not be verified to exact file:line at the
time of writing this catalog and should be re-confirmed during V1.0
implementation:

- **Drop-in `/etc/systemd/system/northnarrow-agent.service.d/readwritepaths.conf`** — runtime artifact on the dev host, confirmed via `sudo ls` during the session; not in repo.
- **PROTECTED_INODES BPF map registration paths for `/etc/northnarrow/` files** — listed in agent boot logs (`anti-tamper FS: /etc/northnarrow file registered in PROTECTED_INODES path=… ino=…`) but the registration call site was not re-inspected for this catalog. The BUG-009-arch migration must update this set.
- **PF_KTHREAD bit value `0x00200000`** — kernel-stable constant per `include/linux/sched.h`, but the per-kernel BTF offset for `task_struct.flags` was not looked up. Required as a prerequisite for the entry 13 fix path.
- **All Phase C cross-references to POSTURE_FSM_V2_REDESIGN.md** — that doc is committed in this session (commit `592bf7f`), accessible at `docs/design/POSTURE_FSM_V2_REDESIGN.md`.

Everything else is anchored to specific file:line from session-verified `grep`
output (commit `1c15300` source).

---

**End of catalog.** Authoritative reference for Phase B implementation and
V1.0 backlog grooming.
