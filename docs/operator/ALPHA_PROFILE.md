# The `alpha` profile: observe-only (lot 341)

A tester installs NorthNarrow on a VM or a spare machine, and it must never
break anything there. The `alpha` profile is how: the agent detects, judges
and records exactly as it does in production, and **no response touches a
user program** — every verdict is recorded with what it *would have* done.
The host's integrity and the agent's protection of itself stay **enforced**
(§1.1): among them, a foreign tracing BPF program's load is refused — a
tester who runs `bpftrace` or BCC names them at install time
(`install.sh --allow-bpf-tools`, §1.2).

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
| Copy-on-first-write guard's automatic restore | restored | copies kept, nothing restored |

Unchanged in `alpha`: **detection, posture and evidence.** Every rule runs,
the posture ladder moves (a COMBAT is entered and recorded, without
isolation), every record is signed in its chain. And every deny of §1.1.

### 1.1 The kernel's denies: enforced under every profile

`alpha` means no response against **the users' programs**. The host's
integrity and the agent's self-protection are not responses: every deny
hook below holds under `alpha` as under `enforcing` (outside a
trusted-installer window), because without it anyone could blind, freeze or
kill the agent, and the record of what it observed would mean nothing. (Lot
341's first rounds left the host-wide ones in observe under `alpha`; the
review of #550 showed each of them is self-protection in disguise, and the
coordinator's corrected decision of 13/11/2026 puts them back.)

| Deny | What it would allow under `alpha` if it only observed |
|---|---|
| A signal (`kill`, `pkill`, `systemctl stop` outside a window), a signal through a file's owner (`F_SETOWN`/`O_ASYNC`), a ptrace or `/proc/<pid>/mem` access, a `prlimit`/`renice`/scheduling/I/O-priority change, `oom_score_adj`, a move out of its cgroup — aimed at the agent, its watchdog or a worker | they stop, blind or starve the agent |
| A write, rename, unlink, `chattr`, extended attribute or new entry on the agent's files, units, drop-ins, state and pins; a read of its signing key | they change or remove what it runs and what it signs |
| A write to its units' cgroup files (`cgroup.kill`, `cgroup.freeze`, limits) | they kill or freeze it |
| A BPF operation on the agent's **own** programs, maps and links: a handle on one by id or through its pin (`bpftool map/prog/link … id`, `BPF_OBJ_GET`), a map update or delete, a link detach or replacement | they detach its hooks or rewrite its configuration |
| A foreign BPF load of the nine refused types — tracing (`kprobe`, `tracepoint`, `perf_event`, `raw_tracepoint`, `tracing`: `bpftrace`, BCC and libbpf tools, another EDR), `raw_tracepoint_writable`, `struct_ops`, `ext`, `lsm` — outside the signed per-loader opt-out (§1.2) | `bpf_send_signal` kills the agent and its watchdog with a signal the `task_kill` hook never sees (the kernel checks no permission for it), at every restart; `bpf_probe_write_user` rewrites its memory; a foreign LSM program refuses its operations |
| An untrusted kernel module (the module-load judge, R018: `init_module`, `finit_module`) — outside the signed policy's `module-allow` lines or a mode other than `enforce` for R018 | a module can do anything to the agent |
| A kexec image (`kexec -l`) | a kernel booted without the agent's hooks |
| The sysctl guard (`kernel.ftrace_enabled`, `kernel.sched_rt_*`, overcommit, `pid_max`, `threads-max`, `max_map_count`) — its write deny, its `cgroup/sysctl` judge, and the integrity round's and a window's close's put-back of a harmful value; a `cgroup/sysctl` program attached to the root cgroup | `kernel.ftrace_enabled=0` silences the BPF trampolines — every deny hook of the agent among them, on 6.0 to 7.2 — and then a plain `kill -9` reaches it; the other values abort or starve it; a root `cgroup/sysctl` program runs after the guard and rewrites what it judged |
| The kprobes switch (`/sys/kernel/debug/kprobes/enabled`) and the lockdown file (`/sys/kernel/security/lockdown`) | `0` disarms every kprobe of the agent; lockdown takes the kernel-memory helpers from its programs |
| A write to a cgroup v1 hierarchy that binds a controller (`cgroup.procs`, `tasks`, `freezer.state`) where the unified one runs | a v1 `freezer` moves the agent past the v2 move guard and freezes it |
| A ptrace attach of PID 1 (a debugger, `/proc/1/mem`) | PID 1's memory rewritten between a deny hook's read of a write PID 1 may make (a unit's limit, a thaw) and the kernel's |

Each refusal is recorded as it is under `enforcing` (`NN-L-AT-001`, the
operation, signed). A refused foreign load raises the posture to ENGAGED
(never the decisive tamper on its own); under `alpha` nothing follows from
it but the record.

How it holds: none of these hooks reads the profile — the start writes no
switch for them. A ratchet (`xtask/tests/deny_routes.rs`) lists every deny
site of the eBPF object as self-protection or host integrity with its
reason, or as a response path whose own mode the gate sets (the exec
quarantine, the exec policy, the connect deny, the exploit guard), and
fails when a self-protection site — or any function of the object it
calls, at any depth — names one of the gate's switches. The module-load
judge takes no gate either (`module_trust::kernel_mode`).

The deny self-test (every round) sees its own probe's tracing program
refused, as before.

An operator still needs a trusted-installer window to stop, upgrade or
remove the agent ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md)
§3.7).

### 1.2 bpftrace, BCC and other tracing tools

They are refused under `alpha` too (the table above). A tester who uses
them names their loaders at install time:

```sh
sudo ./deploy/install.sh --allow-bpf-tools                       # this host's bpftrace and BCC
sudo ./deploy/install.sh --allow-bpf-loader /usr/local/bin/mytool  # any executable (repeatable)
```

- After the agent starts and passes its health check, `install.sh` signs
  one `bpf-loader-allow <path> kprobe,tracepoint,perf_event,raw_tracepoint,tracing`
  line per loader with the install's key (the bootstrap key it wrote, or
  `--grant-key`) and applies it through the agent (`nn-admin policy set`):
  the signed per-loader opt-out of [`RULE_POLICY.md`](RULE_POLICY.md) §2.5.
  The lines join the policy in force; a loader it already names keeps its
  line, widened to those five types when it lacks some (lot 345; the
  summary says `(widened: +…)`). The lines are signed over the policy on
  disk only when it is the verified policy in force (`nn-admin config
  overlay status` does not say NOT LOADED): an unsigned edit of a kept
  configuration is never signed with the install's key — the install warns
  and signs nothing.
- `--allow-bpf-tools` names `bpftrace` (as found on the system path) and the
  interpreter BCC's tools run under (`/usr/sbin/*-bpfcc` on Debian and
  Ubuntu, `/usr/share/bcc/tools/*` on Fedora: their shebang, `python3`).
  Install the tools **before** `install.sh`; one installed later needs a
  signed line by hand (RULE_POLICY.md §2.5).
- **What it opens.** The kernel matches a loader by the executable it runs:
  while a line is in force, **any root process running that executable**
  may load the tracing types — bpftrace runs the script it is given, and
  BCC's line names the Python interpreter, so **any root Python script**
  may. A tracing program reads the memory of every process, the agent's
  included. `install.sh --help` and its summary say so. The other refused
  types (`raw_tracepoint_writable`, `struct_ops`, `ext`, `lsm`) take a
  hook's place and are never named by these flags.
- **What it does not open (lot 345).** Whoever loads it, opted out or not,
  the agent refuses a program that would kill or blind it:
  - an **fmod_ret** (`BPF_MODIFY_RETURN`) program — it overrides the return
    of any `security_*` function (`security_file_open` failing for the
    agent blinds it the way an LSM program would). The `bpf` hook reads the
    attach type from the kernel's copy of the load's arguments;
  - a program that **calls `bpf_send_signal`, `bpf_send_signal_thread`,
    `bpf_probe_write_user` or `bpf_override_return`** (and, on 6.13 and
    later, the `bpf_send_signal_task` kfunc): the signal kills the agent
    past its `task_kill` hook, the write rewrites its memory, the override
    fakes a kernel function's return. bpftrace's `signal()` (behind
    `--unsafe`) is refused this way; BCC's tools call none of them.
    - **6.9 and later**: judged at the `bpf_prog_load` hook, on the kernel's
      copy of the instructions, before the verifier — a refused program
      never gets an id (`EPERM`).
    - **5.15 to 6.8** (no `bpf_prog_load` hook): judged at the `bpf_prog`
      hook once the verifier fixed the calls up, on every handle a foreign
      caller takes (the load's, and one by id: the program has an id a
      moment before its descriptor). The verified call names the helper by
      its address, which the agent cannot read from `kallsyms` (its unit has
      no `CAP_SYSLOG`): it **calibrates** the targets at its start from its
      own programs (the hook reads the calls of two small programs the
      agent loads, never attaches and unloads). `bpf_probe_write_user`,
      which the agent cannot calibrate (a program calling it needs
      `CAP_SYS_ADMIN`), is refused at the verifier's lockdown question
      (`locked_down`, `LOCKDOWN_BPF_WRITE_USER`): the load fails with
      `EINVAL` (the verifier: "unknown func"). A kernel built without
      `CONFIG_BPF_KPROBE_OVERRIDE` has no `bpf_override_return` to refuse.
    - A program longer than 1,048,576 instructions, or one the judge cannot
      read, is refused as if it called one.
  - Each refusal is a signed `bpf_prog_type` record (High) that names the
    helper or the fmod_ret. What stays open: a tracing program that reads
    (the agent's keys in its memory are not protected from it), and a
    kernel without the judge's targets (a start that could not calibrate
    reports a degradation, `bpf content judge`).
- The flags go with a fresh install that `install.sh` starts (not
  `--upgrade`, `--no-enable` or a package step: refused before anything
  changes). Every load they let through is recorded (`bpf_prog_opt_out`,
  Low). `install.sh`'s summary says which loaders it named (`bpf tools :
  allowed for …`) or that the tools are refused.

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

**An unsigned downgrade is an alarm.** A start whose profile is `alpha`
from the install manifest (or no overlay) right after a run of the
`enforcing` profile (the chain's last `agent_boot` signed `profile:
"enforcing"`; lot 345 — a row written before the field: one that ran its
responses) signs an `integrity_drift` of kind `profile_downgraded` and logs
`PROFILE DOWNGRADED WITHOUT A SIGNATURE`: a signed `profile.local` that was
deleted, or a manifest edited while the agent was stopped. Lot 345: the
comparison is profile to profile — one observing boot of the enforcing
profile in between (a detect-only drop-in) no longer launders it — and the
alarm is in `nn-admin status --key` too: a degradation of source `profile`
(listed below the summary, `sensors : DEGRADED`, and counted against the
trust level). A signed `profile = alpha` is the operator's switch and
raises nothing.

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
