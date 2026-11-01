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

The level is **measured by the worker and declared, never assumed**: the
capability manifest's `workers` entry carries it, with the kernel's ABI as
the core read it:

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
(measured: `Partial`, `fs_denied` only on Ubuntu 22.04's ABI 1; `Partial`,
`fs_denied` and `net_denied` on Ubuntu 24.04's ABI 4). `Full` takes a kernel
with ABI 9.

A kernel without Landlock is no error: the filter is the worker's
confinement there, and the manifest says `landlock_abi 0`.

The agent's keys are denied to a worker three times over: its account
(the key is root's, 0400), Landlock, and the BPF LSM hooks — a worker's pid
is protected but **not exempt** (`PROTECTED_PIDS` value `0x02`; the agent
and the watchdog are `0x03`), and the hooks let only exempt pids open the
keys and the protected paths.

## 4. When a worker fails

The agent kills a worker that breaks its protocol (a malformed or
oversized packet, a descriptor sent along, an answer nobody asked for, a
result out of its bounds), that hangs (no answer in time; an idle worker is
pinged every 10 s) or that dies (a crash, the seccomp filter's `SIGSYS`),
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
| `… exit status 78 (the sandbox could not be entered)` | the worker refused to run unconfined (the journal line before it says which step) | report it with the kernel and `lsm=` |
| `worker_parse: disabled: 5 failures in a row …` | the kind is off until a worker stays up 60 s | look at the failures above it |

## 5. Lab

- `agent/tests/privileged_worker_harness.rs` (`nn-lab.sh test-ignored`):
  the compromised worker — every forbidden call killed by the filter, each
  layer beneath it refusing what the kernel lets it, every protocol attack
  refused, the core alive.
- `deploy/lab/workers/worker-lab.sh <out> roles faults`: the installed
  agent's worker, its roles in the kernel, a root `kill -9` refused, the
  hooks' answer to each role, crash / hang / kill / crash-loop faults (lab
  builds: `/run/northnarrow/debug-worker-{crash,hang,kill,crashloop}`).
