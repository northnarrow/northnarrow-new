# Session Bug Catalog — Pre-Beta Findings

**Status:** Catalog. NOT implementation. Read-only design document.
**Session date:** 2026-05-27 → 2026-05-28.
**Branch context:** `benchmark/cc-t7-13-fix` on commits `5a0d736` (T7.13 lineage) and `1c15300` (tactical fix sweep). Phase B design doc at `docs/design/POSTURE_FSM_V2_REDESIGN.md` (commit `592bf7f`).
**Total findings:** 13 + 9 post-session addenda (6 fixed this session, 5 architectural deferred, 2 cosmetic deferred; all added 2026-05-29 — **BUG-019** (credential FIM) fixed + VM-validated, **BUG-020** (install.sh anti-tamper pin) tactical-fixed/structural-pending, **BUG-021** (logging journal) fixed + VM-validated; and **BUG-022..027** (§20-25) from the audit sweep run `wf_2027282a-052` — discovered via static analysis + adversarial refutation, **VM-validation PENDING** (operator-owned)).

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
| 14 | BUG-019 | Credential FIM rules dead under `ProtectHome=yes` *(post-session, §17)* | Beta-blocker (security HIGH) | **Fixed + VM-validated** (2026-05-29) |
| 15 | BUG-020 | `install.sh` reinstall denied by pinned anti-tamper (honeypot-bait rewrite) *(post-session, §18)* | Beta-blocker (operational) | **Tactical fix applied** (reinstall unblocked); structural design-pending |
| 16 | BUG-021 | Disk saturation: NN journal amplified to an uncapped `/var/log/syslog` *(post-session, §19)* | Beta-blocker (availability) | **Fixed + VM-validated** (2026-05-29) |
| 17 | BUG-022 | FIM directory watches are bare-inode-only (no populate recursion) → a rule family is dead/blind *(audit sweep, §20)* | Beta-blocker (security) | **Discovered** (static + adversarial) — VM-validation pending |
| 18 | BUG-023 | No content-write/append FIM hook → in-place content tamper unobserved *(audit sweep, §21)* | Beta-blocker (security) | **Discovered** (static + adversarial) — VM-validation pending |
| 19 | BUG-024 | FS_PROTECT_EVENTS pinned-ringbuf reuse vs NON-transient producer (FS_FIM_EVENTS sibling) *(audit sweep, §22)* | Beta-blocker | **Runtime-CONFIRMED**; log-flood mitigated (`fd55797`); structural fix **(a2) implemented+deployed (`68d5ff3`) — zero-window VALIDATION PENDING (VM)** |
| 20 | BUG-025 | NN-L-NET-003 BadJa3 dead rule — `tls_fingerprint` has no live producer *(audit sweep, §23)* | Medium | **Discovered** (static + adversarial) — VM-validation pending |
| 21 | BUG-026 | Uncapped on-disk JSONL logs — second disk-fill vector, **REOPENS BUG-021** *(audit sweep, §24)* | Beta-blocker (availability) | **Discovered** (static + adversarial) — VM-validation pending |
| 22 | BUG-027 | `DnsCache.by_pid` unbounded per-PID-key growth (no cap/eviction) *(audit sweep, §25)* | Medium | **Discovered** (static + adversarial) — VM-validation pending |

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
| *(2026-05-29)* | code+docs | fix(deploy+fim): BUG-019 — `ProtectHome=read-only` restores credential FIM coverage + boot-time coverage guard + §17 catalog entry **(local only)** |

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

### 15.1 Anti-tamper trust model gap *(BUG-010 + BUG-011 + BUG-013 + BUG-020)*

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
- **BUG-020**: `install.sh` (the legitimate local installer) cannot rewrite
  the honeypot/control-surface baits because the pinned `inode_protect` deny
  hook exempts only the live agent PID. The installer is the legitimate
  maintainer; it has no protected-channel write authority, so a stopped-agent
  reinstall is denied.

**Unified fix direction.** Introduce a small explicit trust hierarchy at the
anti-tamper layer:

| Map | Role | Mechanism |
|---|---|---|
| `KILL_OVERRIDE` (BPF map, parallel to FS_PROTECT_OVERRIDE) | "this PID may signal this PID with a TTL'd, agent-self-issued override" | Agent's SIGTERM handler writes the override before graceful drain; systemd → agent SIGTERM authorized. |
| `PROTECTED_OBSERVERS` (BPF map, parallel to PROTECTED_PIDS) | "this PID is a verified local observer; ptrace-read-access to PROTECTED_PIDS allowed, write/kill still denied" | Watchdog PID registered after exe-path verification (analogous to `ExemptPids`). |
| `BOOTSTRAP_MODE` sentinel (filesystem, `/etc/northnarrow/.bootstrap`) | "1-of-N quorum permitted for `rotate-keys add` until the sentinel is cleared by a successful 2nd-key add" | install.sh creates; first rotate-keys-add success deletes. |
| `FS_PROTECT_OVERRIDE` (BPF map, parallel to `KILL_OVERRIDE`) gated by admin-key presentation | "a key-authorized local installer may suspend `inode_protect` bait/pin denial for the duration of an install" | `install.sh` (or a small `nn-admin install-mode` helper) presents the Ed25519 admin key; agent arms a TTL'd override covering protected-inode writes, then clears it. Closes BUG-020. |

Single coherent design — these four become one design doc + one
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

**Audit-sweep escalation (2026-05-29, run `wf_2027282a-052`) — fresh-install beta-blocker.**
The sweep's adversarial pass re-confirmed FOUR distinct `ProtectSystem=strict` EROFS
exposures on FIRST boot: the mint of `/etc/northnarrow/agent.sig.key` (audit.rs:193,247),
`agent_id` (agent_id.rs:127,184 → zero-UUID anti-replay degrade), `master.key`
(response/quarantine.rs:352 → quarantine response fails), and `audit.log` (admin ops run
UNAUDITED). On THIS dev host they are masked ONLY by the **runtime-only** `readwritepaths.conf`
drop-in (the BUG-009 P-1 fix, which is NOT in repo). A fresh customer install via
`deploy/install.sh` does NOT ship that drop-in, so a stock install hits all four on first
boot. This makes **BUG-009-arch a fresh-install beta-blocker**, not a cleanliness deferral:
until runtime-state relocates to `/var/lib/northnarrow/` (or the drop-in ships in-repo), a
stock install is exposed. (These four were filed *refuted* by the sweep only because they are
not NOVEL — they ARE BUG-009 — not because they are unreachable.)

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

## 17. BUG-019 — credential FIM rules silently dead under `ProtectHome=yes` *(post-session; finding #14)*

- **Severity:** Beta-blocker (security HIGH). The entire credential-theft FIM rule family — NN-L-FIM-011..017 (AWS / Azure / GCP / Docker / browser / KeePass / GnuPG) plus the `/root` SSH-key (NN-L-FIM-004) and shell-history (NN-L-FIM-020) watches — is **dead in production**: it never fires. Unit tests pass, so the gap is invisible to CI.
- **Status:** **Fix applied + VM-validated (2026-05-29).** Re-validation on the reference VM (Ubuntu 6.8, `lsm=…,bpf`) passed: with the committed unit reinstalled, `systemctl show -p ProtectHome` = `read-only` and populate reports `inserted=90 skipped=35 credentials_watched=2 credentials_total=17` (vs the pre-fix `inserted=88 skipped=37` with creds unwatched); reading `/root/.aws/credentials` fires `NN-L-FIM-011_AwsCredsRead action=KillProcess severity=High` (MITRE T1552.001) with the kill landing on a lingering reader (exit 137); no coverage-degraded WARN. **Guard self-test:** a temporary `ProtectHome=yes` drop-in reproduced `credentials_watched=0` and the boot WARN `FIM credential coverage degraded: 17/17 credential paths unwatched (17 with hidden-parent signature) … masked_by_namespace=17 example=/root/.aws/config`, then was removed and read-only restored.

**Symptom.** Every credential path under a home directory is skipped at FIM populate time; the credential-read rules get no input and never fire. Boot log (pre-fix binary, `ProtectHome=yes`):

```
INFO fim: WATCHED_PATHS populated inserted=88 skipped=37 configured=125
```

`/root/.aws/credentials` (and every other `/root/…` / `/home/…` credential path) is among the 37 skipped — even though the file exists `root:root` on the host. Reading it produces NO event and NO verdict:

```
# cat /root/.aws/credentials      →  completes normally; no NN-L-FIM-011 verdict in the journal
```

`/etc`-based FIM works (e.g. `op=Modified` on `/etc/hosts` fires) — that asymmetry is the diagnostic tell.

**Root cause.** The shipped unit `deploy/systemd/northnarrow-agent.service:93` set `ProtectHome=true` (≡ `yes`). `ProtectHome=yes` mounts an **empty tmpfs over `/home`, `/root` and `/run/user`** inside the service's mount namespace. `populate_watched_paths()` (`agent/src/fim/attach.rs`) runs in that namespace, so `symlink_metadata("/root/.aws/credentials")` returns `ENOENT`; the path is debug-logged "absent on this host — skip" and never inserted into the kernel `WATCHED_PATHS` map. The BPF `file_open` observe hook is kernel-side (outside the namespace) and DOES see the real open — but with no matching inode in `WATCHED_PATHS` it emits no FIM event, so the rule engine receives nothing. `/etc` is exempt because `ProtectSystem=strict` keeps `/etc` read-only but **visible**, so its inodes populate normally. Classic `ProtectHome` signature: only `/home` + `/root` FIM is dead.

**Why unit tests missed it.** The NN-L-FIM-011.. rule tests and the FIM privileged e2e (`agent/tests/fim_privileged_e2e.rs`) exercise the rule engine + BPF path against files visible to the test process; they never run inside the production unit's mount namespace, so the masking is invisible to them. A green test suite + a dead production subsystem is exactly the failure mode the regression guard (below) exists to convert into a loud runtime signal.

**Reproducer.**
1. Agent installed with the pre-fix unit. `sudo systemctl show northnarrow-agent -p ProtectHome --value` → `yes`.
2. `sudo journalctl -u northnarrow-agent -b | grep 'WATCHED_PATHS populated'` → high `skipped`; at debug level, `path absent … /root/.aws/credentials`.
3. `sudo cat /root/.aws/credentials` → completes; `journalctl -u northnarrow-agent -b | grep NN-L-FIM-011` → nothing.
4. Inverse confirmation: temporary drop-in `ProtectHome=read-only` + restart → populate stops skipping the `/root` creds; the same `cat` fires `NN-L-FIM-011_AwsCredsRead action=KillProcess severity=High (T1552.001)`.

**Fix applied (this commit).** Two parts, both in repo so `install.sh` ships them. The fix must NOT be a runtime-only VM drop-in like BUG-009's P-1 — `install.sh` copies `deploy/systemd/northnarrow-agent.service` verbatim, so a hand-patched VM unit would be silently reverted on the next reinstall.

1. **`deploy/systemd/northnarrow-agent.service`:** `ProtectHome=true` → `ProtectHome=read-only`, with an inline rationale comment. `read-only` restores `/home` + `/root` + `/run/user` *visibility* (the agent only `stat(2)`s/reads credential paths to record their `(dev,ino)`; it never writes under a home dir — all writes go to `ReadWritePaths`) while keeping the write-hardening of `ProtectHome` intact. **Rejected alternative** `ProtectHome=yes` + `BindReadOnlyPaths=/root /home`: more surgical (keeps `/run/user` hidden) but merely *relocates* the silent hole — a future `/run/user/<uid>/keyring` rule would die exactly as NN-L-FIM-011 did. `read-only` closes the class uniformly with one verifiable directive (`systemd-analyze security`), and for a root EDR with full kernel BPF visibility, hiding `/run/user` from its userland is not a real security boundary. The **watchdog unit is left at `ProtectHome=true`** — it performs no FIM and never needs home visibility (minimal blast radius).

2. **`agent/src/fim/attach.rs` (`populate_watched_paths`):** boot-time regression guard. A FIM that watches nothing must scream, not whisper at debug. Home-rooted credential paths (`/root`, `/home`, `/run/user`) are counted; if any is unwatched *specifically* because its home root is present-but-empty/inaccessible (the namespace-masking signature — kept distinct from a genuinely-absent file, which stays `debug`), the agent emits one WARN: `FIM credential coverage degraded: N/M credential paths unwatched … — check ProtectHome/mount namespace`. The healthy `info!` line gains `credentials_watched` / `credentials_total` for at-a-glance coverage. Classifier locked by `protecthome_mask_root_classifies_home_paths` + `mask_root_looks_hidden_distinguishes_empty_from_populated`.

**References.**
- Sibling of **BUG-009** (§3 / §15.4): both are systemd unit-hardening directives that silently disabled a subsystem — `ProtectSystem=strict` blocked `/etc` *writes* (BUG-009); `ProtectHome=yes` blocked `/home`+`/root` FIM *reads* (BUG-019). **Cluster pattern: a hardening directive that trades away a capability the agent depends on, failing silent.** Any future `Protect*` / `*Paths` unit change MUST be checked against (a) the FIM watch set and (b) the runtime-state write set.
- Unlike BUG-009's tactical fix, this one IS committed to repo (not a runtime drop-in), so reinstall cannot revert it.
- Guard: `agent/src/fim/attach.rs::populate_watched_paths`. Unit: `deploy/systemd/northnarrow-agent.service`.

---

## 18. BUG-020 — `install.sh` reinstall aborts on honeypot-bait rewrite while anti-tamper pins are active *(post-session; finding #15)*

- **Severity:** Beta-blocker (operational — breaks the documented reinstall path). NOT a security hole: this is anti-tamper *failing closed* exactly as designed. The harm is that `install.sh` aborts partway under `set -euo pipefail`, leaving the operator unsure whether the install succeeded and skipping the script's own `daemon-reload` + completion banner.
- **Status:** **Tactical fix applied + VM-validated (2026-05-29) — reinstall unblocked; structural deferred (design-pending).** The idempotent skip-if-identical (below) lets a reinstall complete with the agent running, no fresh boot. The structural trusted-installer is still required for the residual case (see **Residual limit** below) and remains a design call (anti-tamper trust model, §15.1).

**Symptom.** Re-running `deploy/install.sh` on a host where the agent has booted at least once (so the anti-tamper LSM programs are pinned) aborts at the honeypot control-surface rewrite:

```
install.sh: writing control-surface file /var/lib/northnarrow/override.config
install: cannot remove '/var/lib/northnarrow/override.config': Operation not permitted
```

The binary + unit copies (which run earlier in the script) DID land, so the install is functionally partial-but-usable — but the script never reaches its own `systemctl daemon-reload` or the "install complete" + next-steps banner, so the operator must notice and run `daemon-reload` manually. Observed 2026-05-29 during BUG-019 (§17) validation via the `stop agent → install.sh` flow; worked around with a manual `daemon-reload`.

**Root cause.** The 10 honeypot / control-surface bait files (`override.config`, `shutdown.signal`, `disable.token`, the `/etc/northnarrow/*` control files, the `/run/northnarrow/*` pair) are PROTECTED_INODES. The `inode_protect` deny LSM program (with `inode_unlink` / `inode_setattr` / `inode_rename`) is **pinned** — by Tappa 7 design, the pins survive an agent-restart window so protection never drops. Its only write-exemption is the caller-side `PROTECTED_PIDS.get(caller_tgid)` check — i.e. *the live agent process*. `install.sh` runs as a plain root `install`/`cp`, never the agent PID:

- Agent **stopped** → pins still active, agent PID gone from the exemption → every bait rewrite (replace = unlink + create) is denied (`EPERM`).
- Agent **running** → `install` still isn't the agent PID → denied, and an anti-tamper verdict may additionally fire against the installer.

The rewrite only succeeds on a **fresh boot before the agent attaches** (no pins yet) — which is why the session's `install.sh → reboot` flow worked but `stop → install.sh` does not.

**Reproducer.**
1. Boot the agent at least once (pins the anti-tamper programs).
2. `sudo systemctl stop northnarrow-agent`.
3. `sudo ./deploy/install.sh` → aborts at the first honeypot bait with `Operation not permitted`; no `daemon-reload`, no completion banner.

**Fix paths (record both; pick during design).**
- **Tactical — APPLIED (this commit, VM-validated 2026-05-29).** The honeypot loop is now idempotent: `cmp -s` the on-disk bait against the shipped source and SKIP the rewrite when they match, instead of letting `install` attempt the (denied) replace. A reinstall now completes with the agent running — no fresh boot, no manual `daemon-reload`. A missing/divergent bait is still (re)written, and the agent's boot `HoneypotIntegrityCheck` recreates any tampered one from the same embedded bytes, so coverage is not weakened.
- **Structural — close the cluster.** Introduce a **trusted-local-installer** principal that presents the Ed25519 admin key to authorize a scoped, TTL'd bait/pin teardown for the duration of an install (analogous to the BUG-010 PID-1 kill-override, but key-gated and covering `inode_protect` writes — the `FS_PROTECT_OVERRIDE` row in §15.1). This is the same "no concept of a trusted local controller / observer / authority / **installer**" gap as BUG-010 (controller) and BUG-011 (observer); solving it once with an explicit trust hierarchy closes BUG-010 / BUG-011 / BUG-020 together.

**Residual limit (the tactical fix is NOT a full close).** Skip-if-identical unblocks exactly two cases: (a) **same-version reinstall** — baits already match the shipped bytes → skipped; and (b) **fresh install** — baits absent → written. It does NOT cover the third case: a reinstall that **changes an existing bait's content** (a release ships different `configs/honeypot-baits/*` bytes). There the `cmp` mismatches, the loop falls through to `install`, and the replace EPERMs against the pinned hook exactly as before — so that update still requires a **fresh boot** (no pins at install time) or the **structural trusted-installer**. The structural fix is therefore not optional forever: it is the ONLY mechanism that can apply a bait-content update on a running host. **Trigger that re-opens BUG-020:** shipping changed honeypot-bait content and reinstalling on a running (pinned) host.

**References.**
- Cluster: **anti-tamper trust model gap** (§15.1) — BUG-020 is the fourth instance (installer) alongside BUG-010 (controller), BUG-011 (observer), BUG-013 (authority).
- Discovered while validating **BUG-019** (§17); the manual `daemon-reload` workaround kept that validation unblocked.
- **Independently re-confirmed by the audit sweep** (run `wf_2027282a-052`) as a CASCADE inconsistent-deploy finding: when a release ships changed bait content to a running (pinned) host, the abort leaves new binaries live + a stale systemd catalogue (the residual above). This is the 4th of the sweep's four cascade findings (the other three are disk-fill — see [[BUG-026]] §24).
- Code: honeypot rewrite loop in `deploy/install.sh` (`HONEYPOT_BAIT_DIRS`); caller-side exemption in `agent-ebpf/src/inode_protect.rs` (`PROTECTED_PIDS` check); pin lifecycle in `agent/src/anti_tamper/`.

---

## 19. BUG-021 — disk saturation: NN's journal amplified into an uncapped `/var/log/syslog` *(post-session; finding #16)*

- **Severity:** Beta-blocker (availability). NN filled the host's 76G disk twice in one day — risking a full-disk cascade that takes down the agent, the watchdog, and every other service on the box.
- **Status:** **Fixed + VM-validated (2026-05-29).** Flood-tested on the reference VM (below) under the exact condition that filled the disk.

**Symptom.** `/` hit 100% twice in a day. `/var/log/syslog` reached 44G while the systemd journal sat at 223M — a 200× split.

**Root cause — amplification + no ceiling, NOT agent verbosity.** Measured idle logging is ~3 lines/min; the agent itself is not noisy. The fill is two compounding *host-default* vectors:
1. **rsyslog amplification.** Stock Ubuntu journald runs `ForwardToSyslog=yes`; every NN message (agent stdout → journal) is forwarded to rsyslog (`imuxsock`) and written by `50-default.conf`'s `*.*;auth,authpriv.none -/var/log/syslog` rule into `/var/log/syslog` — a full second copy. (Confirmed: 101,929 NN lines in a 36M syslog snapshot.)
2. **No size ceiling on that copy.** `/etc/logrotate.d/rsyslog` rotates syslog `weekly`, `rotate 4`, with **no `size`/`maxsize`** — a one-day flood grows unbounded until the weekly tick. journald itself self-caps (no explicit `SystemMaxUse` → default `min(10% fs, 4G)` ≈ 4G), which is why the journal stayed at 223M while syslog hit 44G.

So the SizeMismatch flood (since fixed) didn't fill the disk by being in the journal — it filled it via the uncapped rsyslog *copy*. The next noisy bug had no guardrail.

**Fix — de-amplify by construction + a hard cap, zero customer config.**
- **`LogNamespace=northnarrow` on BOTH the agent and watchdog units.** NN logs into its own `systemd-journald@northnarrow` instance. By systemd design a non-default namespace does NOT forward to syslog/kmsg/console (only the default namespace does) — so NN messages never reach rsyslog / `/var/log/syslog`. De-amplification is structural, not a filter.
- **`deploy/systemd/journald@northnarrow.conf`:** `SystemMaxUse=1G` hard ceiling (+ `SystemMaxFileSize=128M`, `RuntimeMaxUse=128M`, `Storage=persistent`, `ForwardToSyslog=no`). journald vacuums oldest files to stay under the cap — a future noisy bug can churn the 1G window but can never fill the disk.
- **`install.sh`** ships the conf to `/etc/systemd/`, restarts the namespace journald on reinstall, and the banner + all 11 operator/test `journalctl` invocations gain `--namespace=northnarrow`.

**Watchdog-respawn cascade — why BOTH units need the namespace.** On agent CRASH the watchdog does not `systemctl start` the agent; it `fork-exec`s it as its own child, which **inherits the watchdog's stdio**. So if only the agent unit had `LogNamespace`, a watchdog-respawned agent would log through the *watchdog's* stdio → the default journal → rsyslog — re-opening the amplification vector for exactly the crash-loop case (the worst case: a crashing agent is also the noisiest). Namespacing the watchdog routes both the watchdog and the agent it respawns into the capped namespace.

**Why not the tactical fix.** A global journald `SystemMaxUse` + an rsyslog `:programname … stop` filter was rejected: it edits system-wide journald + rsyslog policy NN must not own, is ordering-fragile (the filter must precede `50-default.conf`), and breaks under syslog-ng / no-rsyslog. The namespace is self-contained and de-amplifies by construction.

**No code change / nothing reads the journal back.** Both binaries log via `tracing_subscriber::fmt()` → stdout (systemd routes it to the namespaced journald). `nn-admin audit` reads the on-disk chained `audit.log` (JSONL), not journald; the watchdog observes via pidfd, not the journal. Composes cleanly with `ProtectSystem=strict` / `ProtectHome=read-only` (the namespaced journald runs as `systemd-journal`, outside the agent's sandbox).

**Validation (reference VM, Ubuntu 6.8, `lsm=…,bpf`).** Reinstalled; both units carry `LogNamespace=northnarrow`; `systemd-journald@northnarrow` socket-activates; the namespace journal is persistent at `/var/log/journal/<machine-id>.northnarrow`. Isolation by PID: agent logs only in the namespace, **0** lines in the default journal, **0** in `/var/log/syslog`. **Flood test** (temporary 64M cap; 94,277 incompressible ~1KB lines ≈ 95MB pushed via `systemd-run -p LogNamespace=northnarrow`):

| Metric | Result |
|---|---|
| namespace disk-usage | **56.2M ≤ 64M** (capped, not ~95M) |
| FLOODTEST lines surviving | **11,160 / 94,277** (oldest vacuumed at the limit) |
| `/var/log/syslog` delta | **+546 B** (background only — not forwarded) |
| FLOODTEST in `/var/log/syslog` | **0** |
| `df /` used delta | **−1,624 KB** (95M flood → zero net disk) |

The journal caps + rotates at the ceiling instead of growing unbounded, and syslog does not grow — both vectors closed under the exact condition that filled the disk.

**Restart-determinism re-verification (2026-05-30) — LogNamespace was NOT the gap.** A follow-up reported agent logs in the DEFAULT journal and suspected `LogNamespace` wasn't applying on `systemctl restart`. Investigated and DISPROVEN: `LogNamespace=northnarrow` is deterministic on restart-started instances — 3× `systemctl restart` each produced an instance logging to `--namespace=northnarrow` with **ZERO** lines in the default journal (verified by `_PID`), and the newest default-journal agent boot stayed **PID 10120 @ 2026-05-29 17:52** (the last *pre*-LogNamespace start) — i.e. no post-LogNamespace boot ever fell back to default. The apparent "split" was (a) stale pre-LogNamespace agent history retained in the default journal, plus (b) the namespace's ~72-min retention window collapsing under a restart-triggered reject flood — root-caused to **[[BUG-024]]**, not a LogNamespace defect. BUG-021's LogNamespace fix is therefore confirmed complete for restart-started instances; the 2026-05-30 observability failure belongs to BUG-024.

**Separate follow-ups (NOT bundled).** tty-aware ANSI in logs (`.with_ansi(std::io::stdout().is_terminal())` — the agent currently emits ANSI escapes into the journal) and ProcessSpawn `INFO`→`debug` tiering (audit-useful but the dominant volume; the cap bounds it regardless of source).

**References.**
- Cluster sibling of **BUG-009** (§3) and **BUG-019** (§17): all three are a systemd/journald **default or hardening directive interacting badly with NN's needs and failing silent** — `ProtectSystem=strict` blocked `/etc` writes (009), `ProtectHome=yes` blocked `/home`+`/root` FIM reads (019), `ForwardToSyslog=yes` + no cap amplified into an unbounded syslog (021). Standing lesson: every `Protect*` / `*Paths` / journald / rsyslog default must be checked against NN's actual runtime footprint.
- **BUG-020** (§18) was discovered during this fix's reinstall (install.sh honeypot rewrite denied by the pinned anti-tamper hook).
- Commit `e799d76`. Files: `deploy/systemd/{northnarrow-agent,northnarrow-watchdog}.service`, `deploy/systemd/journald@northnarrow.conf`, `deploy/install.sh`, + 11 `journalctl --namespace=northnarrow` doc/script updates.

---

> **§20–§25 provenance.** All six entries below were surfaced by the discovery-only audit
> sweep (Dynamic Workflow run `wf_2027282a-052`, 2026-05-29: 38 read-only agents, 31 candidates
> → 20 confirmed / 11 refuted, each confirmed candidate survived an adversarial refutation pass).
> Status on every entry: **discovered via static analysis + adversarial refutation — VM-validation
> PENDING** (the operator runtime-confirms before any fix). NO fixes applied. §20/§21 are CLUSTER
> headers (one root cause, many symptom rules); §22–§25 are independent findings.

---

## 20. BUG-022 — FIM directory watches are bare-inode-only (no populate recursion): a rule family is dead/blind *(audit sweep; CLUSTER A)*

- **Severity:** Beta-blocker (security — multiple Critical/High persistence + rootkit detectors silently non-functional on the shipped config).
- **Status:** **Discovered (static + adversarial refutation) — VM-validation PENDING.**

**Symptom.** A whole family of FIM rules for directory-rooted persistence surfaces never fires on a real host, even though the directories are watched. Unit tests pass because they inject synthetic full child paths the live pipeline never produces.

**Root cause (the cluster).** `populate_watched_paths` (agent/src/fim/attach.rs:214-278) stats each configured path and inserts ONLY that path's own (dev,ino) into WATCHED_PATHS — there is NO recursion / `read_dir` expansion, and `compute_baseline` rejects directories (baseline.rs:227-238). So a fim-paths.v1 DIRECTORY entry watches only the directory inode; no child-file inode is ever enrolled. This produces TWO failure facets:
- **(i) dead create-detection:** a new-file drop fires `inode_create` on the watched PARENT dir inode, which the drain resolves to the BARE directory path (drain.rs:583-594, no child reconstruction) — e.g. `/etc/systemd/system` — but the rules match a trailing-slash CHILD-path prefix (`/etc/systemd/system/`), so `starts_with` is FALSE and the rule returns None for every real event. A structural producer/matcher mismatch.
- **(ii) blind in-place-modify:** an in-place edit of an existing child (whose inode was never enrolled) fires hooks only on the unwatched child inode → ZERO events.

**Symptom rules (each confirmed; adversarially survived):**

| Rule | Surface (MITRE) | Why dead/blind | file:line | Sev |
|---|---|---|---|---|
| NN-L-FIM-008 | kernel module `.ko` (T1014 rootkit, Critical) | `/lib/modules` dir-inode only; path fails `/lib/modules/`; 6474 `.ko` unwatched; in-place `.ko` modify blind | rules.rs:452-459 | HIGH |
| NN-L-FIM-009 + 023 | systemd unit / `.timer` (T1543.002 / T1053.006) | 4 unit dirs bare-inode; dir path fails `…/system/`; in-place unit edit blind (runtime-proven: today's reinstall fired 0 verdicts) | rules.rs:488-495 | HIGH |
| NN-L-FIM-021 | PAM module `.so` (T1556, Critical) | `/security` dirs only; fails `/security/`+`.so`; in-place `.so` swap blind (47 `pam_*.so` unwatched) | rules.rs:1203-1210 | HIGH |
| NN-L-FIM-007 | cron drop-in (T1053.003) | `/etc/cron.d` etc. bare-inode; fails `/etc/cron.d/`; only `/etc/crontab` literal can fire; in-place cron edit blind | rules.rs:413-423 | HIGH |
| NN-L-FIM-016 / 017 | password-store / GPG keyring (T1555) | `/root/.password-store`, `/root/.gnupg` dirs; fail `/.password-store/`,`/.gnupg/`,`.kdbx`; default config only | rules.rs:1083-1092 | MEDIUM |

**Evidence / what survived refutation.** Watch granularity (bare dir inode → parent-dir path) is fundamentally incompatible with the rules' slash-terminated child-path prefixes; the dirs are live-populated (pam_unix.so, cron files present) and watched but structurally incapable of matching. FIM-008/009/021 are KillProcess-action detectors blind on 100% of real hosts.

**Reproducer (static; VM-validation PENDING).** Read attach.rs:214-278 (no recursion), drain.rs:583-594 (bare-path resolve), rule prefixes (rules.rs:98,102-106,1208). Runtime (operator): drop a new `.ko`/`.service`/cron file or swap a `pam_x.so` in a watched dir → grep the `northnarrow` namespace journal for the rule verdict → expect none.

**Fix direction (NOT applied — discovery).** Either (a) recursively expand watched directories into WATCHED_PATHS (bounds-check growth), which also closes facet (ii); or (b) have create/setattr hooks resolve+emit the CHILD path so child-prefix matching works. Design call.

**Fix (implemented locally 2026-05-30 — option A + on-the-fly enroll; NOT built, NOT VM-validated).** Chose direction (b) plus a bounded slice of (a). Kernel `inode_create` / `inode_rename` read the new child dentry's leaf (`d_name`→`qstr`) and carry it in a strict-appended `FimDriftRaw.child_name` (72→144 B, process-local ring so kernel+user rebuild together). Userland reconstructs `dir + "/" + leaf`, normalizes a rename-INTO-watched-dir to `Created` (single userland point — dir-rule op-sets unchanged), enrolls the dropped child into WATCHED_PATHS + InodePathMap on the fly (so its later in-place edits are caught by the [[BUG-023]] write-then-close hook), and sets a `child_truncated` flag that fires FIM-021/023 even when a >63-byte leaf loses its suffix. FIM-008 widened `Modified`→`Created|Modified`. New BTF offsets (`dentry.d_name`@32 / `qstr.name`@8 / `qstr.len`@4) validated on WSL2 BTF, **VM (Ubuntu 6.8.x) revalidation pending**. **RESIDUAL (deliberate — option A scope; facet (ii) declined):** in-place modify of a PRE-EXISTING, non-explicitly-enrolled child of a watched dir is NOT covered by this pass (no boot-time recursive enrollment). To protect a specific critical pre-existing child (e.g. a shipped `pam_unix.so`), add that path EXPLICITLY to `fim-paths.v1`/`.local` — [[BUG-023]] then covers its content edits. **VM fire-test pending:** drop a `.ko`/`.service`/cron/`.so` (and `mv` one in) → grep the `northnarrow` namespace journal for the FIM-007/008/009/021/023 verdict; control = a legit create now carries the child path, not the bare dir.

**References.** Source: audit sweep `wf_2027282a-052`. Sibling of [[BUG-023]] (content-write gap). The FIM-009 facet is runtime-anchored (BUG-019 validation reinstall fired zero NN-L-FIM-009 despite rewriting the unit in place).

---

## 21. BUG-023 — no content-write/append FIM hook: in-place content tamper is unobserved *(audit sweep; CLUSTER B)*

- **Severity:** Beta-blocker (security — the actual attack form of several rules is silently uncovered).
- **Status:** **Discovered (static + adversarial refutation) — VM-validation PENDING.**

**Symptom.** Rules that should catch content changes to a watched FILE do not fire when the change is an in-place write/append (vs a metadata change).

**Root cause (the cluster).** There is no content-write/append LSM hook anywhere in agent-ebpf/src/fim_watch.rs, and no write variant in the `FimOp` enum (common/src/wire/mod.rs:615-624). `FimOp::Modified` is produced ONLY by the `inode_setattr` hook (fim_watch.rs:285) — chmod/chown/truncate, via `notify_change`. A pure `O_APPEND` or same-size in-place overwrite updates mtime via `file_update_time()` WITHOUT `notify_change` → no Modified. The only other signal, `file_open`→`Opened`, is dropped by the drain for non-credential paths (drain.rs:618-627). No periodic re-hash compensates (recompute is event-driven).

**Symptom rules (each confirmed; adversarially survived):**

| Rule | Bypass technique (the real attack form) | file:line | Sev |
|---|---|---|---|
| NN-L-FIM-004 | `O_APPEND` a key to `/root/.ssh/authorized_keys` (T1098.004 SSH backdoor) — **fully dead** vs append | drain.rs:618-627; rules.rs:284-305 | HIGH |
| NN-L-FIM-003 | same-size / `O_WRONLY`-no-`O_TRUNC` rewrite of `/etc/sudoers`, `sshd_config`, `passwd`, `shadow`, `pam.d/*` | drain.rs:705-714; rules.rs:251 | HIGH |
| NN-L-FIM-005 / 018 / 019 | in-place record `pwrite` to `wtmp`/`btmp`/`lastlog` (T1070 utmp-zeroing) — partial gap | drain.rs:618-627; rules.rs:341,989 | MEDIUM |
| NN-L-FIM-007 | in-place edit of `/etc/crontab` content (also see [[BUG-022]] for the drop-in dir facet) | rules.rs:418 | (overlap) |

**Evidence / what survived refutation.** `TAPPA9_FIM_DESIGN.md` explicitly PROMISED FIM-004 catches authorized_keys appends (:78,:885) and that `Modified` covers write-then-close (:246) — but the write/close hook was never implemented. Truncate-to-zero / rm / mv ARE still caught (setattr/unlink/rename), so FIM-003/005/018/019 are PARTIAL gaps; FIM-004-against-append is fully dead.

**Reproducer (static; VM-validation PENDING).** Read fim_watch.rs:265-289 (setattr is the only Modified source), drain.rs:618-627 (Opened dropped for non-cred). Runtime (operator): `echo key >> /root/.ssh/authorized_keys` (or `>> /etc/passwd`) → grep namespace journal for NN-L-FIM-004/003 → expect none.

**Fix direction (NOT applied — discovery).** Add a write/close BPF hook emitting `Modified` on content change, OR forward `Opened` on integrity-critical paths and re-hash in userland (reuse the existing baseline-diff machinery). Design call.

**Fix (implemented locally 2026-05-30 — write-then-close; NOT built, NOT VM-validated).** Chose the write/close hook. A `file_permission` LSM program gated on `MAY_WRITE` sets a per-inode dirty mark carrying the WRITER's pid/uid/comm (so the FIM-003/004 KillProcess attribution is the writer, not whoever closes the fd); a `file_free_security` LSM program emits ONE `FimOp::Modified` on close and clears the mark; userland re-hashes via the existing `compute_baseline` + no-op suppression (so an identical-bytes rewrite still yields no drift). Catches `O_APPEND` AND same-size in-place rewrite — the two forms `inode_setattr` misses. **VM-VALIDATION GATE:** the close hook is `file_free_security` (confirmed BPF-attachable in this kernel's BTF: `bpf_lsm_file_free_security`) — but which of `file_free_security` / `__fput`-fexit / `filp_close`-fexit reliably fires with a readable `f_inode` on the TARGET kernel must be fire-tested; the emit body ([`emit_drift_close`]) is reused, so swapping the attach point is a ~2-line change. **Fallback if fragile:** emit-per-write (`file_permission` emits directly) + rate-limit, accepting noise. **Residual:** `MAP_SHARED` mmap writes (no `vfs_write`/`file_permission` call) remain uncovered — an `mmap_file` hook is the follow-up. **VM fire-test pending:** `echo k >> /root/.ssh/authorized_keys` → FIM-004; same-size rewrite of `/etc/sudoers` → FIM-003; control = identical-bytes rewrite must NOT fire. **Ring-capacity fire-test:** the 144-byte `FimDriftRaw` (BUG-022 child-name tail) halves `FS_FIM_EVENTS` capacity (256 KiB ⇒ ~1820 records, was ~3640), so for frequently-written watched files (`utmp`/`wtmp`/`lastlog`, `/var/log/*`) verify (a) the write-then-close coalescing actually holds volume down — one event per close, not per `write()` — and (b) no `Modified` is dropped under a sustained write burst (a dropped close-event = a missed in-place tamper). Multi-writer attribution is last-write-wins (the writer that last touched the inode before close); documented on `DirtyMeta`.

**References.** Source: audit sweep `wf_2027282a-052`. Sibling of [[BUG-022]]. Related (deny-side analogue of this observe-side gap): `inode_protect` denies removal of a PROTECTED_INODE but NOT in-place `inode_setattr` content-modify — see the incidental finding in [[BUG-024]] §22 (intended-vs-gap open).

---

## 22. BUG-024 — FS_PROTECT_EVENTS pinned ringbuf reused across restart while its producer is NON-transient (PINNED-REUSE sibling of FS_FIM_EVENTS) *(audit sweep)*

- **Severity:** Beta-blocker (runtime-confirmed 2026-05-30). TWO harms: (1) **silent** loss of fs-protect denial telemetry after a restart; (2) a restart-triggered reject **flood** that self-DoSes ALL agent observability — the root cause of the 2026-05-30 validation-blocking incident.
- **Status:** **Runtime-CONFIRMED (2026-05-30).** Log-flood facet **MITIGATED** (per-entry reject WARN rate-limited via `RejectThrottle`, commit `fd55797`). Structural fs-protect fix **(a2) IMPLEMENTED + DEPLOYED** (commit `68d5ff3`: per-boot fresh `with_byte_size` ring + `reattach_fresh` on the 5 inode_protect deny hooks, attach→purge→pin) — but **zero-window-across-restart is NOT YET runtime-validated (VM-only)**. Until validated, the structural fix is unproven; the silent blackout is only *theoretically* closed. See **Structural fix (a2) — validation status + NEXT ACTION** below.

**Symptom.** After a `systemctl restart` / watchdog respawn (same boot — bpffs persists), the fresh userland consumer of FS_PROTECT_EVENTS desyncs from the reused pinned kernel ring — the FS_FIM_EVENTS failure shape (commit 9e1c229), but SILENT (no SizeMismatch flood) for fs-protect denials.

**Root cause.** FS_PROTECT_EVENTS (agent-ebpf/src/inode_protect.rs:130) is the ONE remaining `RingBuf::pinned` event ring (every other `*_EVENTS` ring is `with_byte_size`/process-local). It is reused across restart via the EbpfLoader `map_pin_path` (multiplexer.rs:143-147). Its five `inode_*`/`file_ioctl` LSM producers are **NON-TRANSIENT**: `attach_lsm` reuses the prior boot's pinned LSM link and returns WITHOUT re-loading (antitamper-bpf/src/lib.rs:351-364, wired filesystem.rs:331-332) — the OLD program keeps firing into the OLD ring across the death→respawn gap. The fresh consumer (multiplexer.rs:213,225 — the identical pump that produced the FIM `expected=72 got=0` flood) drains the reused ring with a stale position view → desync.

**Runtime CONFIRMED + observability self-DoS (2026-05-30).** Hit live: after 3× `systemctl restart`, the current restart-started agent (PID 27256) held **49,990 lines in its LogNamespace journal, ~100% `WARN ringbuf entry rejected label="fs_protect"`** at ~400/sec. The desynced fs_protect consumer rejects every entry, and the pump logged one WARN **per rejected entry, unbounded** (`agent/src/sensors/multiplexer.rs:388`) — filling the 1G `LogNamespace` `SystemMaxUse` cap and collapsing the namespace retention window to **~72 min**, vacuuming out populate lines, FIM verdicts, and ProcessSpawn telemetry. **This — not any LogNamespace bug — was the root cause of the 2026-05-30 "observability broken" incident** that blocked FIM validation (see [[BUG-021]]). So BUG-024 has TWO harms: the *silent* fs-protect blackout (original finding) AND a *loud* restart-triggered self-DoS of all agent observability.

**Mitigation shipped (log-flood ONLY) + CRITICAL caveat.** The per-entry reject WARN in the generic `pump<T>` and the `pump_tcp_connect` / `pump_dns_query` pumps is now coalesced to ≤1/sec with a dropped-count (`RejectThrottle`, `agent/src/sensors/multiplexer.rs`), so a desynced ring can no longer flood/vacuum the namespace — observability is restored and deterministic. **This does NOT restore fs-protect.** The rate-limit stops only the *log flood*; the FS_PROTECT_EVENTS consumer is still desynced on every restart-without-reboot, so **fs-protect denial events remain LOST** until the structural ring-pin + `inode_*` link-pin coordinated teardown lands. The now-quiet logs MUST NOT be mistaken for a working sensor — the silent blackout persists.

**Structural fix (a2) — IMPLEMENTED + DEPLOYED 2026-05-30 (commit `68d5ff3`); zero-window NOT YET VALIDATED.** (a2) makes `FS_PROTECT_EVENTS` a per-boot `with_byte_size` (process-local) ring and re-attaches the 5 inode_protect deny hooks fresh every boot via `reattach_fresh` (load+attach NEW → purge OLD pins → pin NEW), so the new consumer never reuses a stale pinned ring. Ordering reviewed correct — attach strictly precedes purge, and it is fail-safe (an attach error returns BEFORE any purge, leaving the prior boot's pinned hook intact). **Confirmed:** deny-of-removal works on a stable agent (root `rename`/`unlink` of a PROTECTED_INODE → EPERM). **NOT confirmed:** the zero-window-across-restart claim. The prior burst was INVALID — it used `echo > file` = `inode_setattr` (truncate), which is NOT a denied operation here (see the incidental finding below), so its "slips" proved nothing; it also bursted a self-healing bait (recreation race) as root (DAC-bypassing). Zero-window is therefore **neither confirmed nor refuted**.

**NEXT ACTION (next VM session) — do this before trusting (a2):** reboot for a clean baseline (fresh bpffs, freshly-registered baits, single boot-started agent), then re-validate (a2) with the CORRECT method:
1. confirm a target's rename/unlink is denied via a **single** op (must EPERM);
2. **CONTROL burst** of rename/unlink on a **stable** agent, no restart — must be **0 slips** (this validates the method itself; the prior bug was a control burst would also have "slipped");
3. rename/unlink **burst ACROSS an agent restart** — must be **0 slips** (the zero-window proof);
4. BUG-024 closure checks: no `ringbuf entry rejected` flood, no stale-PID `ANTI-TAMPER DENIAL` replay, namespace retention recovers, `/etc/hosts` thermometer clean.
**Commit-promote (mark validated) only if (2)+(3) both pass; if (3) shows real slips, the attach→purge ordering has a defect → fix before promoting.**

**Incidental finding (surfaced 2026-05-30 during a2 validation; intended-vs-gap OPEN).** On a real host `inode_protect` denies **removal** of a PROTECTED_INODE — `inode_unlink` / `inode_rename` / `inode_rmdir` (root `mv`/`rm` → EPERM; this is the BUG-020 install-time denial) — but does **NOT** deny in-place **`inode_setattr`** modify (root `truncate` / `chmod` / content-rewrite succeed; only FIM-*observed* as drift, rate-limited). So a root attacker can content-rewrite a protected control-surface file in place — *observed, not blocked*. Adjacent to **[[BUG-023]]** (in-place content-modify coverage), but on the DENY side rather than the OBSERVE side. **OPEN question:** is "deny removal, observe modification" the intended PROTECTED_INODES contract, or is the absent setattr-content deny a gap? Likely pre-existing (under a2 `inode_rename` re-attaches and denies correctly, so a2's attach path works; the `inode_setattr` program's own predicate is what permits the modify) — needs a deliberate design decision, NOT a2's concern.

**⚠️ CRITICAL CAVEAT — the FIM one-liner fix is UNSAFE here.** Because the producer is non-transient, the `pinned → with_byte_size` fix used for FS_FIM_EVENTS (9e1c229) would split the OLD producer (old ring) from the NEW consumer (new ring) = a SILENT fs-protect blackout. The correct fix must drop the ring-pin AND the `inode_*` link-pins **together** so producer+ring+consumer reattach fresh — but the link-pins exist precisely to keep deny-protection alive across the restart gap, so the teardown must preserve that anti-tamper guarantee. There is an in-tree `TODO(fs-protect-ringbuf-reuse)` at inode_protect.rs:115-128 + multiplexer.rs:131-142 acknowledging exactly this deferred hazard.

**Why reachable.** Restart-without-reboot is routine (watchdog W4 respawn, watchdog/src/lib.rs:424+; operator `systemctl restart`); bpffs survives both (deploy prerequisite, install.sh), wiped only on full reboot. FsProtectDenial telemetry is live downstream (ADE escalate.rs:54, dual_verify.rs:153, correlation/RAG/XAI).

**Reproducer (static; VM-validation PENDING).** Static evidence above. Runtime (operator): trigger an inode_protect denial, `systemctl restart northnarrow-agent`, trigger another denial → confirm the post-restart denial is missing/garbled in the fs_protect pump (the `ringbuf entry rejected expected=56 got=…` path).

**Fix direction (NOT applied — discovery).** Coordinated unpin of the FS_PROTECT_EVENTS ring + the `inode_*` link-pins on (re)attach, preserving the cross-restart deny guarantee. Structural; design call.

**References.** Source: audit sweep `wf_2027282a-052`. Direct sibling of the confirmed FS_FIM_EVENTS PINNED-REUSE (commit 9e1c229). PINNED-REUSE signature.

---

## 23. BUG-025 — NN-L-NET-003 (BadJa3) is a dead rule: `tls_fingerprint` has no live producer *(audit sweep)*

- **Severity:** Medium (false coverage — a Critical/KillProcessTree rule that can never fire; operators get zero JA3 detection).
- **Status:** **Discovered (static + adversarial refutation) — VM-validation PENDING.**

**Symptom.** Operators populate `/etc/northnarrow/netflow-ja3-blocklist.{v1,local}` and get ZERO detection.

**Root cause.** `NetFlowEvent.tls_fingerprint` is hardcoded `None` by both production producers (flow_tracker.rs:270,309); the only setter `attach_tls` (flow_tracker.rs:328) is uncalled dead code; the live drain enriches only `resolved_hostname` and never parses a ClientHello (drain.rs:339-425); no TLS/packet-capture eBPF sensor exists or is attached (multiplexer.rs:161-206). NN-L-NET-003 (net.rs:407-412) gates on `tls_fingerprint` → can never fire. DEAD-RULE / MISSING-INPUT (the pre-ProtectHome cred-rule pattern: logic fine, input never produced).

**Reproducer (static; VM-validation PENDING).** Read flow_tracker.rs:270,309,328 + drain.rs:339-425. Runtime (operator): add a known JA3 to the blocklist, make a matching TLS connection → grep namespace journal for NN-L-NET-003 → expect none.

**Fix direction (NOT applied — discovery).** Implement a TLS ClientHello-capture sensor + wire `attach_tls`, OR remove the rule + JA3 blocklist config to avoid false coverage. Design call.

**References.** Source: audit sweep `wf_2027282a-052`. DEAD-RULE signature.

---

## 24. BUG-026 — uncapped on-disk JSONL logs: a second disk-fill vector NOT covered by the BUG-021 journal cap *(audit sweep — REOPENS BUG-021)*

- **Severity:** Beta-blocker (availability — the BUG-021 disk-fill class, via a path BUG-021 did not cap).
- **Status:** **Discovered (static + adversarial refutation) — VM-validation PENDING.**

**⚠️ REOPENS [[BUG-021]] (§19).** BUG-021 capped the systemd JOURNAL (LogNamespace + `SystemMaxUse=1G`) but NOT the agent's on-disk JSONL logs — they live under `/var/lib/northnarrow` + `/etc/northnarrow` (separate `ReadWritePaths`, no quota, no LogNamespace coverage). The disk-fill beta-blocker is therefore only PARTIALLY closed.

**Symptom.** Agent-written append-only JSONL hash-chains grow without bound until `/` fills — impairing the agent, the watchdog, and every other service (the Family-A cascade BUG-009/BUG-021 already showed corrupts deploy + truncates files).

**Root cause / vectors (each confirmed; adversarially survived):**
1. **Seven chained logs, no rotation/cap (audit.rs:54-56).** netflow.jsonl, netflow_listeners.jsonl, the FIM baseline + drift chains, canary access + registry, and `/etc/northnarrow/audit.log` — no eviction/rotation/backoff. The highest-volume, **netflow.jsonl, fsyncs ONE row PER TCP-close and PER UDP-send** (net/drain.rs:149-196, called :416), no sampling/dedup, net drain on by default (main.rs:1454-1476). Fill timeline weeks-to-months (each row ~hundreds of bytes) — slower than BUG-021's 76G rsyslog loop but unbounded. Rotation is an acknowledged deferred item (audit.rs:54-56, RFC §14 Q9 / "audit-rotate").
2. **fim_drift.jsonl flood-on-churn (drain.rs:734).** The on-disk append is UNCONDITIONAL (before the rate-limit branch); `DriftRateLimiter` gates only the engine emit, Critical tier never throttled (drain.rs:315); Deleted/Renamed bypass SHA no-op suppression (drain.rs:705). Attacker-driven file churn in any watched dir writes unbounded fsync'd rows. The BPF comments (fim_watch.rs:328-330,356-359) claim a userland `(dev,ino,ts)` dedup that does NOT exist in drain.rs → each multi-fire syscall (up to 4 appends/rename) is written in full.
3. **canary_access.jsonl flood-on-repeat-access (detector.rs:362, LOW).** For a Credential-type canary at a credential path watched at boot, every open appends unconditionally + fsyncs (access_log.rs:154-176) with no throttle/cap; a tight-loop reader (AV/backup) or exfil loop drives unbounded growth. Requires the Credential-type + credential-path + watched-at-boot conjunction.

**Reproducer (static; VM-validation PENDING).** Read net/drain.rs:149-196 + main.rs:1454-1476 (netflow per-connection fsync), drain.rs:734,315,705 (fim_drift unconditional append). Runtime (operator): generate sustained connection or watched-dir churn, watch `du -sh /var/lib/northnarrow/*.jsonl` grow unbounded with no rotation.

**Fix direction (NOT applied — discovery).** Extend the BUG-021 cap discipline to on-disk logs: size-cap + rotation/eviction on the `/var/lib/northnarrow` chains (esp. netflow.jsonl), sampling/dedup on the per-connection netflow append, and gate the fim_drift/canary on-disk append behind the same rate limit as the emit. These are tamper-evident hash-chains — rotation must preserve chain verifiability. Design call.

**References.** Source: audit sweep `wf_2027282a-052`. REOPENS [[BUG-021]] as the second disk-fill vector. (The sweep's 4th cascade finding — install.sh abort = inconsistent deploy — is the already-recorded residual of [[BUG-020]] §18, independently re-confirmed.)

---

## 25. BUG-027 — `DnsCache.by_pid` grows one entry per PID with no global cap or eviction *(audit sweep)*

- **Severity:** Medium (slow unbounded memory growth over agent lifetime).
- **Status:** **Discovered (static + adversarial refutation) — VM-validation PENDING.**

**Symptom.** The DNS-attribution cache grows monotonically with PID churn for the agent's whole lifetime (the `Arc` is built once at main.rs:564).

**Root cause.** `DnsCache.by_pid` (agent/src/net/dns_cache.rs:63) has no cap on the NUMBER of pid keys and no path removes an emptied key. `on_dns_query` inserts a key per distinct PID on the hot path (dns_cache.rs:99-110, every `Event::DnsQuery` via multiplexer.rs:541), bounding ONLY the inner per-pid `VecDeque`. The sole prune (`lookup_for_connect`, dns_cache.rs:127-141) TTL-prunes only the looked-up pid's deque, never removes the key, and runs only on TCP-close (drain.rs:407). No `sched_process_exit` sensor exists (ancestry.rs:22) → dead PIDs never reaped; no periodic sweep. UNIQUE exception: every sibling per-process structure HAS a key-count cap + eviction (store.rs `MAX_TRACKED_PROCS=4096` + prune; ancestry.rs `MAX_TRACKED_EDGES=10000` FIFO; lineage.rs `TRACKER_CAP=2048`; flow_tracker.rs capacity + evict).

**Reproducer (static; VM-validation PENDING).** Read dns_cache.rs:63,99-110,127-141. Runtime (operator): sustained PID churn (fork loop) emitting DNS queries; watch the agent RSS climb without plateau over hours.

**Fix direction (NOT applied — discovery).** Add a global key-count cap + eviction to `by_pid` (mirror the sibling structures), and/or drop emptied keys in `lookup_for_connect`. UNCAPPED-RESOURCE signature.

**References.** Source: audit sweep `wf_2027282a-052`.

---

**End of catalog.** Authoritative reference for Phase B implementation and
V1.0 backlog grooming.
