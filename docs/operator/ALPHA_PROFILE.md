# The `alpha` profile: observe-only (lot 341)

A tester installs NorthNarrow on a VM or a spare machine, and it must never
break anything there. The `alpha` profile is how: the agent detects, judges
and records exactly as it does in production, and **no response touches a
user program** — every verdict is recorded with what it *would have* done,
and a host-wide deny (a tester's `bpftrace`, a kexec, a sysctl) is recorded
as what it *would have* refused (§1.1). The agent's protection of itself
stays on.

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

Unchanged in `alpha`: **detection, posture and evidence.** Every rule runs,
the posture ladder moves (a COMBAT is entered and recorded, without
isolation), every record is signed in its chain.

### 1.1 The kernel's denies: what stays enforced, what is only observed

The alpha promises a tester it never breaks anything on the machine. The
deny hooks therefore split in two (the coordinator's decision of
13/11/2026, lot 341's second round):

- the denies that refuse a **third-party tool something on the host** are
  only **observed** under the gate: the action goes through, and the
  attempt is recorded as a **"would deny"** — what the enforcing profile
  would have refused;
- the denies that **protect the agent itself** stay **enforced** under
  every profile: without them anyone could switch the agent off, and the
  record of what it observed would mean nothing.

**Observed in `alpha`** (recorded "would deny"; refused under `enforcing`
outside a trusted-installer window):

| Deny | What a tester meets | Why it is only observed |
|---|---|---|
| A foreign tracing, LSM, extension or `struct_ops` BPF program's load (`bpftrace`, BCC and libbpf tools, another EDR, Netdata- or Cilium-like agents) | the tool loads and runs | it attaches elsewhere on the host; refusing it breaks the tester's own tooling |
| A `cgroup/sysctl` program attached to the root cgroup | attached | it guards the sysctl guard, which is itself only observed |
| The kprobes switch (`/sys/kernel/debug/kprobes/enabled`) and the lockdown file (`/sys/kernel/security/lockdown`) | written | a host setting the tester owns |
| A kexec image (`kexec -l`, `kdumpctl restart`) | loaded | kdump and live-patch tooling must keep working |
| The sysctl guard (`kernel.ftrace_enabled`, `kernel.sched_rt_*`, overcommit, `pid_max`, `threads-max`, `max_map_count`) — its write deny and its `cgroup/sysctl` judge; the integrity round's and a window's close's put-back of a harmful value (and of `kprobes/enabled`) | written, and left as written (the round records `sysctl_would_restore`) | the tester's tuning |
| A write to a cgroup v1 hierarchy where the unified one runs | written | an older container runtime's |
| A ptrace attach of PID 1 (a debugger, `/proc/1/mem`) | allowed | a debugging session on the tester's machine |

**Enforced under every profile** (the agent's self-protection):

| Deny | Why it stays enforced |
|---|---|
| A signal (`kill`, `pkill`, `systemctl stop` outside a window), a signal through a file's owner (`F_SETOWN`/`O_ASYNC`), a ptrace or `/proc/<pid>/mem` access, a `prlimit`/`renice`/scheduling/I/O-priority change, `oom_score_adj`, a move out of its cgroup — aimed at the agent, its watchdog or a worker | they stop, blind or starve the agent |
| A write, rename, unlink, `chattr`, extended attribute or new entry on the agent's files, units, drop-ins, state and pins; a read of its signing key | they change or remove what it runs and what it signs |
| A write to its units' cgroup files (`cgroup.kill`, `cgroup.freeze`, limits) | they kill or freeze it |
| A BPF operation on the agent's **own** programs, maps and links: a handle on one by id or through its pin (`bpftool map/prog/link … id`, `BPF_OBJ_GET`), a map update or delete, a link detach or replacement | they detach its hooks or rewrite its configuration |

A foreign BPF program that would **target** the agent's programs or maps
(an `freplace` of one of its functions, a program loaded against one of its
maps) still needs a descriptor of that object, which the last row refuses:
it stays denied. A foreign tracing program that merely attaches elsewhere
is only observed.

The deny self-test (every round) still sees its own probe's tracing program
refused: the hook judges, whatever the profile; only a third party's
attempt is let through.

An operator still needs a trusted-installer window to stop, upgrade or
remove the agent ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md)
§3.7).

How it holds: the start writes its resolved gate into the kernel's
`HOST_DENY_MODE` right after the eBPF object loads, before any program
attaches, and freezes it (no descriptor writes it again, the agent's
included; a write that fails leaves every deny enforcing, a signed
`host_deny` degradation). The start's log says which: `host-wide denies
OBSERVED (the observe-only gate) …` or `host-wide denies ENFORCED …`. A
ratchet (`xtask/tests/host_deny.rs`) keeps every deny site of the eBPF
object either routed through that switch or listed as the agent's
self-protection with its reason. `--detect-only` and `NN_DETECT_ONLY`, the
gate's other inputs, observe these denies too.

### 1.2 A "would deny" record

`nn-admin detections` shows it as the refusal it would have been
(`NN-L-AT-001_AntiTamperDenial`, the same operation and severity), with

```
"response": "would have: deny:bpf_prog_type (would deny: not refused — the observe-only gate leaves the host-wide guards in observe)"
"reasoning": "`bpftrace` attempted to load a `tracepoint` BPF program … Would deny: NOT refused — …"
```

and the status summary counts it with the suppressed responses
(`would have : deny:bpf_prog_type x3`). A loader is recorded once a second
per program type; a switch, kexec, sysctl or cgroup write once a second per
process and operation; the agent's journal reads `WOULD DENY: a host-wide
guard let it through`.

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
- `would have` counts the responses the gate suppressed, by action, and the
  host-wide denies it let through, by operation (`deny:bpf_prog_type`,
  §1.2).

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
