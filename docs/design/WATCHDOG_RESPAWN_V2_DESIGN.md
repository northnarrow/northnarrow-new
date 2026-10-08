# Watchdog respawn v2 — respawn through the agent's own systemd unit

- **Status:** proposal (2026-10-08). Supersedes §5.3 "CLI for the respawn" and amends §2.3 / §10.2 of `TAPPA7_TASK6_WATCHDOG_DESIGN.md`. No ROADMAP change: this is a bug-fix of Tappa 7 task 6.
- **Closes:** `watchdog-respawn-1` (`docs/audit/NN_REVIEW_2026-10-08.md` #4) and `combat-avail-1` (`NN_BUG_AUDIT_2026-06-09.md` #6).
- **Code touched (when approved):** `watchdog/src/{main,lib}.rs`, `deploy/systemd/northnarrow-watchdog.service`, `deploy/systemd/northnarrow-agent.service` (comments only), `watchdog/tests/`.

---

## 1. Problem

The Tappa 7 design chose **option (b)** — a systemd unit pair, the agent in its own unit, the watchdog in its own — and explicitly rejected **option (a)** "watchdog forks/execs the agent" because it *"forces a process-tree shape that conflicts with the systemd-native deployment"*. The shipped W4 respawn is option (a) anyway: `respawn_cycle` → `spawn_agent(argv)` → `Command::new(bin).args(..).spawn()`. Three consequences, all observable on the 6.8 VM today:

| # | Effect | Where |
|---|--------|-------|
| 1 | **Argv is not the first launch's argv.** With `--agent-bin` (required in production, see the unit) the respawn argv is `[bin, --pid-file, <pidfile>]`: `--combat-rules`, `--combat-rules-v6`, `--admin-pub`, `--admin-socket` and any `--detect-only` are dropped. A detect-only host silently becomes full-enforcement (`combat-avail-1`); a respawned agent has no admin key / socket / COMBAT rules. §5.3's "read `ExecStart=` via `systemctl show`" was never implemented. | `watchdog/src/main.rs:104-110` |
| 2 | **The respawned agent inherits the watchdog unit's sandbox**, because it is the watchdog's child and systemd scopes it to the watchdog's cgroup: `MemoryMax=64M` (ADE OOMs at model load), `TasksMax=8`, `CPUQuota=10%`, `CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN` (no `CAP_NET_ADMIN` → COMBAT isolation cannot engage; no `CAP_SYS_PTRACE`/`CAP_DAC_OVERRIDE` → quarantine + lineage blind; no `CAP_LINUX_IMMUTABLE`; no `CAP_KILL` → kill verdicts EPERM), `ProtectHome=true` (credential FIM rules see ENOENT at boot → zero coverage). `systemctl status northnarrow-agent` shows the unit **inactive** while an agent process runs under the watchdog. | `deploy/systemd/northnarrow-watchdog.service` `[Service]` |
| 3 | **`BindsTo=northnarrow-agent.service`** on the watchdog unit: when the agent crashes its unit goes `inactive/failed` (`Restart=no`), and systemd stops any unit bound to it — the watchdog is stopped **by design of BindsTo** during or right after the respawn it is supposed to perform. (The unit comment claims BindsTo "does NOT trigger on agent CRASH"; it does — BindsTo reacts to the bound unit becoming inactive for any reason.) | `deploy/systemd/northnarrow-watchdog.service` `[Unit]` |

The watchdog's *detection* (pidfd POLLIN, STATUS ping, layer-2 PROTECTED_PIDS evict, backoff, shutdown-marker check) is sound and stays. Only the *respawn action* and the unit coupling change.

## 2. Options

**(A) Keep fork-exec, fix argv and sandbox.** Read `ExecStart=` via `systemctl show`, and widen the watchdog unit's `MemoryMax`/`TasksMax`/caps/`ProtectHome` to the agent's. Rejected: the watchdog would need the agent's full capability set and 11 GiB ceiling just in case — its whole point (§7, §9) is to be a tiny, low-privilege supervisor. `systemctl status` would still show the agent unit inactive.

**(B) Respawn = `systemctl start northnarrow-agent.service`.** The watchdog keeps *deciding when* (backoff, ceiling, tamper heuristics, shutdown marker) and delegates *how* to systemd: the agent comes back under its own unit, its own `ExecStart=` argv, its own cgroup/caps/`ProtectHome=read-only`, journald namespace, `Type=notify` readiness. **Chosen.** This is what §2.3 option (b) actually implies.

**(C) `Restart=on-failure` on the agent unit, watchdog demoted to evict + telemetry.** Rejected for v2: it moves the backoff policy into systemd (`StartLimitBurst`), which cannot express the tamper heuristics (§5.1 "5 in 60 s = tamper suspected") nor the shutdown-marker distinction, and reintroduces the restart split-brain the original design avoided. Can be revisited for non-systemd hosts.

## 3. Design

### 3.1 Respawn backend

```rust
pub enum RespawnBackend {
    /// `systemctl start <unit>` (default when /run/systemd/system exists).
    SystemdUnit { unit: String },
    /// Fork-exec with a persisted argv (non-systemd hosts, dev VMs).
    ForkExec { argv: Vec<String> },
}
```

- CLI: `--respawn-backend {systemd,exec}` (default: auto — `systemd` if `/run/systemd/system` is a directory, else `exec`), `--agent-unit northnarrow-agent.service`.
- `SystemdUnit` runs `/usr/bin/systemctl start --no-block <unit>` via `Command` (exit status + stderr logged). No D-Bus crate: `systemctl` is present on every systemd host, the call is one line, and `CAP_*` are not involved — unit control is authorised by uid 0 (the watchdog runs as root). `--no-block` returns as soon as the job is queued; readiness is still observed by the existing `wait_for_new_agent_pid` (pidfile written after every LSM hook is attached) — unchanged.
- `ForkExec` keeps today's `spawn_agent`, but **argv is the full first-launch argv**: on startup the watchdog reads `/proc/<agent_pid>/cmdline` (the agent is in PROTECTED_OBSERVERS, the watchdog is an observer — no EACCES) and persists it; `--agent-bin` becomes an override for `argv[0]` only. This also closes `combat-avail-1` for non-systemd hosts.
- `respawn_cycle` is unchanged after the spawn step: wait pidfile → `pidfd_open` → defensive PROTECTED_PIDS reinsert.

### 3.2 Unit changes (`northnarrow-watchdog.service`)

- Remove `BindsTo=northnarrow-agent.service`. Operator-intended stops are already distinguished by the A8 shutdown marker (`/run/northnarrow/agent.shutdown_authorised`, written by the agent on a signed stop): marker present → watchdog logs and **does not** respawn (existing behaviour). Keep `After=`.
- Add `Wants=northnarrow-agent.service` so `systemctl start northnarrow-watchdog` on a cold host also pulls the agent in.
- `ExecStart` gains `--agent-unit northnarrow-agent.service`; `--agent-bin` stays for the `exec` backend.
- Sandbox unchanged (`MemoryMax=64M`, `TasksMax=8`, `CPUQuota=10%`, `CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN`, `ProtectSystem=strict`). `systemctl` is an exec of a system binary (allowed read-only) and a `connect()` to `/run/dbus/system_bus_socket`: read-only `/run` does not block socket connects (`sb_permission` applies EROFS to regular files/dirs/symlinks only). **To verify on the VM** (§5.1); fallback is `ReadWritePaths=/run/dbus` (no security impact).
- `TasksMax=8` covers the transient `systemctl` child (1 extra task).

### 3.3 Agent unit (`northnarrow-agent.service`)

- Unchanged semantics: `Restart=no` stays (the watchdog is still the only restart policy). Update the comment block to describe the v2 flow: "crash → watchdog backoff → `systemctl start` → fresh unit instance".
- `StartLimitIntervalSec=0` in `[Unit]` so systemd's own start-rate limiter never blocks the watchdog's 5-in-60 s retry pattern (the ceiling is the watchdog's, not systemd's).

### 3.4 Failure modes

| Case | v2 behaviour |
|------|--------------|
| `systemctl` missing / non-zero exit | logged at ERROR, counted as a failed attempt, backoff continues; after the ceiling: "tamper suspected" line as today. |
| Agent unit masked / disabled by an attacker | `systemctl start` fails → same as above, plus a dedicated `watchdog.respawn unit_masked=true` line. Unit files are in PROTECTED_INODES (Tappa 9 C7) so masking requires defeating the FS deny first. |
| Agent crashes during its own argv parse | identical to §5.3: ceiling trips, `failed` state visible, journal explains. |
| Operator `systemctl stop northnarrow-agent` | agent writes the shutdown marker on a signed stop (A8) → watchdog stands down. An **unsigned** stop (plain `systemctl stop` without the admin token) is, by Tappa 8 design, indistinguishable from a kill: the watchdog respawns. This is unchanged from today and is the intended anti-tamper posture. |
| Watchdog crashes mid-respawn | systemd restarts the watchdog (`Restart=on-failure`); the queued `systemctl start` job completes independently; new watchdog adopts the new agent via pidfile (§7.3). Better than today, where a watchdog crash killed the child agent with it. |
| Non-systemd host | `--respawn-backend exec` with full argv (§3.1). |

## 4. Tests

- **Unit (`watchdog/src/lib.rs`):** backend auto-detection; `ForkExec` argv reconstruction from a synthetic `/proc/<pid>/cmdline` (NUL-separated, with the `--agent-bin` override); `SystemdUnit` command line assembly (`systemctl start --no-block <unit>`), exit-status mapping.
- **Integration (`#[ignore]`, root, VM):** `kill -9 <agent>` → within the backoff delay `systemctl is-active northnarrow-agent` = `active`, the new PID's `/proc/<pid>/status` `CapEff` contains the agent set (incl. `CAP_KILL`), `/proc/<pid>/cgroup` is the agent unit's cgroup, `nn-admin status` answers, `--detect-only` is preserved when configured. Second scenario: signed stop → no respawn within 60 s.
- **Regression guard:** a test asserting the watchdog unit file has no `BindsTo=` and the agent unit has `Restart=no` + `StartLimitIntervalSec=0` (parse the files in `deploy/systemd/`).

## 5. Rollout

1. **5.1 VM pre-check (no code):** from a root shell inside a transient unit with the watchdog's sandbox (`systemd-run -p ProtectSystem=strict -p CapabilityBoundingSet="CAP_BPF CAP_SYS_ADMIN" -p NoNewPrivileges=yes --wait systemctl start --no-block northnarrow-agent.service`) confirm the D-Bus connect works under the read-only `/run`. If not: `ReadWritePaths=/run/dbus`.
2. Implement §3.1 + §3.2 + §3.3 in one PR with the unit tests; keep the old `spawn_agent` path as the `exec` backend.
3. VM validation per §4; update `docs/integration-test-runbook.md`.
4. Mark `watchdog-respawn-1` / `combat-avail-1` fixed in the audit fix logs; amend `TAPPA7_TASK6_WATCHDOG_DESIGN.md` §5.3 with a pointer to this document.

## 6. Out of scope

- Watchdog ↔ agent mutual monitoring (§7.2), `task_kill` signal allowlist (`task-kill-signals-1`), and making the watchdog's own `CapabilityBoundingSet` drop `CAP_SYS_ADMIN` (it only needs `CAP_BPF` on 5.8+; separate hardening PR).
