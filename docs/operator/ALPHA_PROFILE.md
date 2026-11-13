# The `alpha` profile: observe-only (lot 341)

A tester installs NorthNarrow on a VM or a spare machine, and it must never
break anything there. The `alpha` profile is how: the agent detects, judges
and records exactly as it does in production, and **no response touches a
user program** — every verdict is recorded with what it *would have* done.
The agent's protection of itself stays on.

`alpha` is the profile of every fresh install made with `install.sh` (and of
a fresh package install). The other profile is `enforcing`.

## 1. What `alpha` changes, and what it does not

`alpha` is one more input of the agent's single no-enforcement gate (the one
`--detect-only` and `NN_DETECT_ONLY` set). The start resolves that gate once
and hands the same value to every response path and deny switch it arms:

| Path | `enforcing` | `alpha` |
|---|---|---|
| Response executor: kill, tree kill, quarantine, per-process egress block, throttle, file-capability strip | carried out | `WouldExecute`; the record reads `would have: <action>` |
| COMBAT network isolation (and its egress release) | applied | not applied, recorded |
| Exec quarantine (`--exec-quarantine enforce`): holds before the first instruction, kills, vaults | enforced | observe mode: nothing held, "would refuse" recorded |
| Exec quarantine: a kill an earlier enforcing run owed (a process left stopped) | killed | resumed; the boot's record lists it as `would_have_killed` |
| Exec policy (`--exec-policy enforce`): exec / preload / mmap denies | denied | audit mode: recorded, not denied |
| Kernel connect deny (`--net-connect-deny`) | armed | not armed, said at the start |
| Exploit guard (`--exploit-guard-response enforce`) | SIGKILL / EPERM | detect mode |
| Module-load judge (R018: untrusted `.ko` loads, `init_module`) | refused (the default deny mode) | record mode: let through, recorded |
| Copy-on-first-write guard's automatic restore | restored | copies kept, nothing restored |

Unchanged in `alpha`:

- **Detection, posture and evidence.** Every rule runs, the posture ladder
  moves (a COMBAT is entered and recorded, without isolation), every record
  is signed in its chain.
- **The agent's self-protection.** The deny hooks on its own files, units,
  directories, pins, maps, programs and links, on signals, `ptrace`,
  `prlimit`/`renice`, cgroup moves and `oom_score_adj` aimed at the agent and
  its watchdog, the units' refusal of a manual stop
  ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §3.7). An
  operator still needs a trusted-installer window to stop, upgrade or remove
  it.
- **The host-wide guards that keep the agent able to see.** They are
  self-protection too, and stay on: the refusal of foreign tracing and LSM
  BPF programs (`bpftrace`, BCC tools, another EDR: a signed
  `bpf-loader-allow` line in the per-rule policy lets a loader through,
  [`RULE_POLICY.md`](RULE_POLICY.md)), `kexec_load` (a `kdumpctl restart`
  needs a window), the sysctl guard (`kernel.ftrace_enabled`,
  `kprobes-optimization` and the values that starve the agent), the kprobes
  and lockdown switches, cgroup v1 writes where the unified hierarchy runs,
  and debugging PID 1. A tester who runs such a tool sees it refused and the
  refusal recorded.

## 2. Where the profile comes from

Strongest first:

1. **A signed `profile.local`** in `/etc/northnarrow` (overlay kind
   `profile`, `--profile-local` moves it): one line, `profile = alpha` or
   `profile = enforcing`, signed by a key with `config-manage` for this
   agent ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md)
   §3.6). An unsigned or edited file is refused (a signed `integrity_drift`)
   and changes nothing — an unsigned `alpha` does not disarm an enforcing
   install (only the escape hatch `NN_OVERLAY_ALLOW_UNSIGNED=1`, itself a
   reported weakening, loads it).
2. **The install manifest's `profile`**, which `install.sh` writes: `alpha`
   on a fresh install, `enforcing` with `--profile enforcing`; every later
   run of `install.sh` keeps the one it finds. It applies to the installed
   binary only (a copy run by hand, a test's, takes none).
3. Neither: `enforcing` — an install older than the field, a developer run.

`--detect-only` and `NN_DETECT_ONLY` keep their meaning: they switch an
`enforcing` agent to observe-only too, and a signed `enforcing` does not
switch them off.

The start logs `response profile profile=alpha (install manifest)`; the
signed `agent_boot` row names the source of detect-only
(`detect_only_source: "profile alpha (install manifest)"`); the trust level
is at most L2 while no response runs.

## 3. What you see

```sh
sudo nn-admin status --key /root/northnarrow-admin.key
```

starts with a summary:

```
── summary ──────────────────────────────────────────────
posture           : Observing, OBSERVE-ONLY — profile alpha (install manifest): nothing is killed, blocked or quarantined; every verdict is recorded with what it would have done
sensors           : OK — no degradation, no event lost
records today     : 9 (2 High, 7 Low) — UTC day 2026-11-13, counted since 2026-11-13T09:30:00Z; `nn-admin detections` lists them
would have        : KillProcessTree x2
─────────────────────────────────────────────────────────
```

- `sensors` is `DEGRADED` with the number of degradations of this run
  (listed below the summary, each signed) and the events lost, if any.
- `records today` counts the records this agent appended to its detection
  chain in the current UTC day (since its start, if it started that day).
- `would have` counts the responses the gate suppressed, by action.

Without `--key` the agent shows the posture only (external audit ASK-009).

The records themselves: `sudo nn-admin detections --key <key>` (JSONL; the
bootstrap key `install.sh` writes carries `telemetry-read` for it). A
suppressed response reads `"response": "would have: KillProcessTree"`; a
decision that would have run nothing (a `Log` verdict) reads `"none"`.

What a switch to `alpha` does not undo: processes an enforcing run moved
into the blocked or throttled scopes stay there (`nn-admin response status`
lists them, `nn-admin response release` releases them), and files it
quarantined stay in the vault (`nn-admin response restore`). A stale COMBAT
chain is torn down at every start, whatever the profile.

## 4. Switching to `enforcing` (and back)

A signed operator action, applied at the agent's next start:

```sh
echo 'profile = enforcing' > /root/profile.local
sudo nn-admin config overlay set profile --file /root/profile.local --key <config-manage key>
# restart the agent inside a window (§3.7 of INSTALL_UPGRADE_UNINSTALL.md)
sudo nn-admin trusted-installer-grant --key <trusted-installer key> --window-secs 120
sudo systemctl kill -s SIGTERM northnarrow-agent       # the watchdog starts it again
sudo nn-admin status --key <key>                        # posture … ENFORCING — profile enforcing (signed profile.local)
```

`profile = alpha` the same way switches back. `install.sh --profile` does not
switch an installed agent: it refuses and names these commands.

## 5. Installing and removing, as a tester

```sh
sudo ./deploy/install.sh            # alpha, started now and at every boot
sudo ./deploy/install.sh --no-enable            # installed, not started
sudo ./deploy/install.sh --profile enforcing    # a fresh enforcing install
```

Before it changes anything, `install.sh` refuses a host it cannot run on,
each reason with what to do: not x86_64, systemd not the init system, no
kernel BTF, a kernel the agent's own `--btf-check` does not support, and —
when it is to start the units — the BPF LSM off or bpffs not mounted
([`KERNEL_COMPATIBILITY.md`](KERNEL_COMPATIBILITY.md)). A distribution
outside the verified matrix is named, not refused. The start must pass the
upgrade's health check (both units active, every deny hook attached, the
admin socket answering, the watchdog registered). The run ends with a short
summary: the profile, whether it runs, the status and records commands, the
uninstall command and the admin key to move off the host.

```sh
sudo ./deploy/uninstall.sh --purge --grant-key /root/northnarrow-admin.key
```

removes everything ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md)
§3). If the agent is **wedged** — its unit active but its admin socket not
answering within 10 s, or an agent that does not come up for the window —
no window can open and its hooks refuse the stop until the next boot. The
script then disables both units, schedules the rest of the removal for the
next boot (`northnarrow-uninstall.service`, a one-shot that runs a copy of
the script with the same options and then removes itself) and exits 3:

```
uninstall.sh: REBOOT NOW to finish: sudo systemctl reboot
```

No key is needed on that path. After the reboot, `journalctl -b -u
northnarrow-uninstall` shows what was removed.
