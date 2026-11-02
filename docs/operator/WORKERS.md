# The agent's workers

Since Wave 4's R14a the agent is a **core** — the root process that loads
the eBPF programs, holds the keys, decides and acts — and its **workers**:
the same binary started by the core as an unprivileged account, in a
sandbox, for the work that reads bytes an attacker writes. The design is
[the process model](https://github.com/northnarrow/northnarrow-new/blob/main/docs/architecture/PROCESS_MODEL.md).

| Worker | What it does | Since |
|---|---|---|
| `parse` | nn-parse's parsers: the DNS query names, DNS answers, the TLS ClientHello | R14a (started), R14b (the parsing moves in) |

## 1. The `northnarrow-worker` account

`install.sh` creates it, as the packages' configure step does (both run
the same script), before the units start: a system account with its own
group, no home (`/nonexistent`), no shell (`nologin`), never root:

```
useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "NorthNarrow agent workers" northnarrow-worker
```

It owns no file. `uninstall.sh` (and the packages' removal) deletes it with
its group, as it deletes `northnarrow-scan`.

An account of that name that **already exists** is used as it is, so the
install checks it first, before it changes anything on the host: a system
account (uid and gid neither 0 nor in the login range of
`/etc/login.defs`), a `nologin` or `false` shell, a locked password (or
none in the shadow file), no group but its own, a uid no other account
shares, no process running as it but the running agent's own children
(its workers, during an upgrade). Anything else — an
account someone made by hand, or one made to take the name — and the
install stops:

```
install.sh: the existing account northnarrow-worker is not the unprivileged system
account NorthNarrow creates — its shell is '/bin/bash', not nologin. Refused: remove the
account (or make it a locked system account with its own group only and no shell),
then install again (docs/operator/WORKERS.md).
```

`northnarrow-scan` is checked the same way.

Without the account no worker starts: the agent runs, without what the
worker gives, and signs the degradation (`worker_parse: cannot start: no
worker account …`). Reinstall the agent to create it.

## 2. What you see

```
$ ps -o pid,ppid,user,comm,args -C nn-worker-parse
    PID    PPID USER       COMMAND         COMMAND
   2214    2190 northna+   nn-worker-parse northnarrow-agent --worker parse --ipc-fd 3
```

- Its parent is the agent's pid; its binary (`/proc/<pid>/exe`) is the
  agent's — the one the agent runs, even when an upgrade replaced the file
  (`(deleted)`): the core starts its workers from the descriptor it opened
  at boot.
- `/proc/<pid>/status`: `NoNewPrivs: 1`, `Seccomp: 2`, `CapEff`, `CapPrm`,
  `CapInh`, `CapAmb` all zero; its descriptors are stdio and its channel.
  The agent reads this itself when a worker says hello, and refuses a
  worker whose `/proc` disagrees with what it declared.
- `/proc/<pid>/oom_score_adj` is `1000` and its `nice` `10`: under memory
  pressure the kernel kills a worker before anything else, the agent
  starts another; under CPU pressure it yields first.
- Its stderr is a pipe the agent reads: what a worker writes reaches the
  agent's journal as `worker parse: …` lines — escaped (a control
  character, a line break or a backslash as `\xHH`), at most 200 bytes each
  and 20 a minute (the rest counted: `worker parse: N line(s) of its stderr
  not logged`). A worker cannot write the journal's lines itself.
- `kill -9 <worker>` from a root shell is refused (`Operation not
  permitted`): the worker is a protected pid, as the agent is. Only the
  agent stops it. It dies with the agent.

**Scripts that look for the agent by name will find its workers too**:
`pgrep -f northnarrow-agent`, `pidof northnarrow-agent` and
`/proc/*/exe` scans match them (same binary, `argv[0]` `northnarrow-agent`).
Use the unit's main pid (`systemctl show -p MainPID --value
northnarrow-agent`) or `/run/northnarrow/agent.pid` for the agent, and
`comm` (`nn-worker-parse`) or the account for a worker.

## 3. The sandbox, and how much of it your kernel gives

Every worker, on every kernel: its own account, no supplementary group, no
capability, `no_new_privs`, not dumpable, no process (`RLIMIT_NPROC` 0),
no core, 8 descriptors, 512 MiB of address space, and a **seccomp
allowlist** that kills it on any system call outside its own few (its
channel, stderr, memory without execute, the clock, random bytes, signal
returns, an abort, exit). It opens nothing, connects nowhere, executes
nothing, signals and traces no one.

Beneath the filter, **Landlock** — when the kernel has it and `landlock` is
in its active LSM list (`/sys/kernel/security/lsm`) — denies, by the
kernel's ABI:

| Kernel (lab) | Landlock ABI | Denied by Landlock |
|---|---|---|
| Ubuntu 22.04, 5.15 | 1 | every path (open, create, remove, execute) |
| Debian 12, 6.1 | 2 | every path |
| Ubuntu 24.04, 6.8 | 4 | every path; TCP bind and connect |
| Debian 13, 6.12 | 6 | every path; TCP; signals and abstract UNIX sockets outside the worker |

The level is **measured by the worker and declared, never assumed**: after
it enters Landlock the worker tries to open `/`, to connect over TCP to
`127.0.0.1` and to connect to an abstract socket of its own, and declares
only what was refused. The agent checks the declaration against the
kernel's ABI as it reads it — a worker on a kernel with Landlock that is
not under every right that ABI gives is refused. The capability
manifest's `workers` entry carries it, with the kernel's ABI as the core
read it:

```
nn-admin capabilities --key <admin key> --json | jq '.manifest.workers'
[{"kind":"parse","state":"ready","kernel_landlock_abi":4,
  "sandbox":{"landlock_abi":4,"landlock":"Partial","fs_denied":true,"net_denied":true,
             "scoped":false,"seccomp":true,"no_new_privs":true,"dumpable":false,
             "uid":998,"gid":998,"groups":0,"cap_eff":0,…}}]
```

`landlock` is `Partial` on every kernel of the lab: the worker asks for
the rights of the newest ABI its build knows (9), and the kernel enforces
those its own ABI has — `fs_denied`, `net_denied` and `scoped` say which
(measured, lot 272: `Partial` with `fs_denied` on Ubuntu 22.04's ABI 1
and Debian 12's ABI 2; with `fs_denied` and `net_denied` on Ubuntu 24.04's
ABI 4; with `fs_denied`, `net_denied` and `scoped` on Debian 13's ABI 6).
`Full` takes a kernel with ABI 9.

A kernel without Landlock is no error: the filter is the worker's
confinement there, and the manifest says `landlock_abi 0`.

Some calls **only the filter** refuses, on every kernel of the lab: a UNIX
socket by path (the D-Bus system bus), UDP, a user namespace, `io_uring`,
`keyctl`, `perf_event_open`, `userfaultfd`, `pkey_mprotect`, signals by
`tkill`, `rt_sigqueueinfo` or a pidfd. Landlock has no right for them on
these ABIs, or the distribution's settings decide (`kernel.io_uring_disabled`,
`kernel.perf_event_paranoid`, `vm.unprivileged_userfaultfd`, the
unprivileged user namespace policy). The worker's filter kills it on each.

The agent's keys are denied to a worker three times over: its account
(the key is root's, 0400), Landlock, and the BPF LSM hooks — a worker's pid
is protected but **not exempt** (`PROTECTED_PIDS` value `0x02`; the agent
and the watchdog are `0x03`), and the hooks let only exempt pids open the
keys and the protected paths.

## 4. When a worker fails

The agent kills a worker that breaks its protocol (a malformed or
oversized packet, an answer nobody asked for, a result out of its bounds,
a request left unread), that hangs (no answer in time; an idle worker is
pinged every 10 s; one that burns half a CPU over 10 s while it is asked
nothing is a hang too) or that dies (a crash, the seccomp filter's
`SIGSYS` — a descriptor sent along is one: the worker has no call that
sends one),
and starts another after a backoff (at once, then 1, 2, 4… s, at most
60 s). Each failure is a signed degradation (`worker_parse: …`; at once
for a protocol violation, a seccomp kill or a sandbox not entered,
otherwise at most one a minute, the others counted into it).

After **five failures in a row** the worker's kind is **disabled**: the
agent does without what it gives — and **never does that parsing in its own
process instead**. It keeps starting workers at its backoff; one that stays
up 60 s enables the kind again. The manifest's state (`ready`,
`restarting`, `disabled`, `unavailable`) changes with a signed
`capability_manifest_change` row, a worse state at once; `nn-admin status
--key` lists the degradations.

| You see | It means | Do |
|---|---|---|
| `worker_parse: cannot start: no worker account` | `northnarrow-worker` is missing | reinstall the agent |
| `… (SIGSYS: a system call outside its seccomp allowlist)` | the worker tried a call it may not make: a parser taken over by its input, or a bug | keep the journal and the input's time; report it |
| `… protocol violation: …` | the worker sent what an honest worker never sends | as above |
| `… protocol violation: N bytes of earlier requests left unread` | the worker stopped reading its channel: the agent never waits on it | as above |
| `… hello refused: landlock below what ABI N gives …` or `… hello refused: its process is not what it declared …` | the worker's sandbox is not what the kernel gives, or its process (`/proc`) is not what it declared | report it with the kernel and `lsm=` |
| `… spinning: N% of a CPU …` | the worker burnt the CPU with nothing to do | as above |
| `… pid N could not be taken out of PROTECTED_PIDS …` | the agent keeps the dead worker unreaped (its pid cannot be reused) and tries again | look at the pinned maps (`nn-admin status`) |
| `… exit status 78 (the sandbox could not be entered)` | the worker refused to run unconfined (the journal line before it says which step) | report it with the kernel and `lsm=` |
| `worker_parse: disabled: 5 failures in a row …` | the kind is off until a worker stays up 60 s | look at the failures above it |

## 5. Lab

- `agent/tests/privileged_worker_harness.rs` (`nn-lab.sh test-ignored`):
  the compromised worker — every forbidden call killed by the filter, each
  layer beneath it refusing what the kernel lets it (what a distribution
  decides printed), every protocol attack refused, a worker spinning
  between its pings killed, the core alive.
- `deploy/lab/workers/worker-lab.sh <out> roles faults`: the installed
  agent's worker, its roles in the kernel, a root `kill -9` refused, the
  hooks' answer to each role, crash / hang / kill / crash-loop faults (lab
  builds: `/run/northnarrow/debug-worker-{crash,hang,kill,crashloop}`).
