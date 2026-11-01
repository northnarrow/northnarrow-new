# The process model: a core and its unprivileged workers

Wave 4 restructure, R14 (plan §3.1, §3.2, §3.3, §3.5; report 06 INI-19).
R14a: the sandbox, the worker model, the IPC, the kernel's roles, the
`northnarrow-worker` account. R14b: the parsers in the worker. R14c: the
keys in one place, the capabilities per thread, the unit's hardening.

Operator side: [`docs/operator/WORKERS.md`](../operator/WORKERS.md).

## 1. Domains and processes

| Process | Identity | Capabilities | Confinement | Holds |
|---|---|---|---|---|
| `northnarrow-agent`, the **core** | root; its pid in `PROTECTED_PIDS` as **protected and exempt** (`0x03`) | the unit's bounding set | the unit (`ProtectSystem=strict`, `NoNewPrivileges=true`, `LimitCORE=0`…); no Landlock: it acts on any path through `/proc/1/root` | the eBPF loader and links, the keys, the decision, the posture, the COMBAT ladder, the actuators, the signer and the chains, the admin server, the workers' supervisor |
| the **`parse` worker** | `northnarrow-worker`; its pid **protected, not exempt** (`0x02`) | none: effective, permitted, inheritable and ambient sets empty; `no_new_privs` | seccomp allowlist; Landlock: every filesystem right handled with no rule, TCP bind/connect (ABI ≥ 4), signals and abstract sockets scoped (ABI ≥ 6); not dumpable; `RLIMIT_NPROC` 0, `RLIMIT_CORE` 0, 8 descriptors, 512 MiB of address space | nn-parse's parsers (R14b) |
| the watchdog | unchanged (root, `CAP_BPF`, `CAP_SYS_PTRACE`); `0x03` | | | |
| `nn-admin` | the operator | | | public keys only |

The exec quarantine's scanner (lab PR 223) is a confined process of the
same kind with its own binary and account (`northnarrow-scan`); it is not
moved by R14.

## 2. Starting a worker (`nn_linux::worker::spawn`)

1. At boot, before the runtime is built, the core opens its own binary
   (`/proc/self/exe`, read-only, close-on-exec, kept on a descriptor ≥ 64):
   `SelfImage`. A worker is started from that descriptor
   (`/proc/self/fd/N`), never from a path: after an upgrade replaced the
   file on disk the core starts workers of its own version, whose protocol
   it speaks.
2. `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)`; then `fork`.
3. In the child, between `fork` and `exec`, async-signal-safe system
   calls only: the worker's end of the channel on descriptor 3,
   `setgroups(0)`, `setresgid`, `setresuid` (raw system calls: the child
   has one thread), `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG(SIGKILL)` (after
   the uid change, which clears it) and a check that the core still lives,
   then every descriptor above 3 marked close-on-exec
   (`close_range(4, ~0, CLOSE_RANGE_CLOEXEC)`: the image's descriptor is
   resolved by `execve` before the close happens). The environment is
   empty, the directory `/`, stdin and stdout `/dev/null`, stderr the
   agent's (its journal).
4. `execve("/proc/self/fd/N", ["northnarrow-agent", "--worker", "parse",
   "--ipc-fd", "3"])`.
5. The worker's `main` sees `--worker` before anything else of the
   agent's — no command line parsed, no log, no runtime — and calls
   `sandbox::enter` first (§3). It exits `78` when it cannot.
6. The supervisor registers the child's pid in `PROTECTED_PIDS` with the
   worker's role (§4) and waits for its hello (§5).

The bounding set is not emptied: dropping it takes `CAP_SETPCAP`, which
the core does not have and is not given for this — with `no_new_privs`
set and no file capability honoured, a worker can gain no capability from
any `execve`, which is what the bounding set would bound.

The agent's own detection sees the launch as any exec: a
`ProcessSpawn` of `/proc/self/fd/N`. R004 (fileless execution) knows the
core's own launch (`OwnWorkerLaunch`): the parent is the core's pid, the
path exactly the core's descriptor, the account the workers', the command
line exactly a worker's, and — with the exec sensor's identity — the
executed file the core's own image (`dev`, `ino`), unlinked or not (an
upgrade unlinks it). Any one fact off and R004 judges the exec as before.

## 3. The sandbox (`nn_linux::sandbox`)

`enter(profile)`, in this order:

1. refuse to run as root, with a group 0, or with a supplementary group;
2. `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE 0`, close every descriptor
   above the channel, `RLIMIT_CORE 0`, `RLIMIT_NPROC 0`, `RLIMIT_NOFILE 8`,
   `RLIMIT_AS`;
3. measure: ids, groups, the five capability sets (capget, then the
   ambient and bounding sets one capability at a time), the flags, the
   limits — while `/proc` and the system calls that tell are still there;
4. Landlock (the `landlock` crate, best effort, the newest ABI it knows
   asked for): what the running kernel's ABI enforced is declared —
   `SandboxLevel { landlock_abi, landlock: full|partial|none, fs_denied,
   net_denied, scoped }`. Ubuntu 22.04's 5.15: ABI 1; Debian 12's 6.1: 2;
   Ubuntu 24.04's 6.8: 4; Debian 13's 6.12: 6 — when Landlock is in the
   kernel's `lsm=` (0 otherwise);
5. last, the seccomp allowlist (the `seccompiler` crate; kill the process
   on any other call). The parse worker keeps: `recvmsg` and `sendmsg` on
   descriptor 3, `write` to descriptor 2, `brk`, `mmap`/`mprotect` without
   `PROT_EXEC`, `munmap`, `mremap`, `madvise`, `futex`, `close`,
   `clock_gettime`, `getrandom`, `rt_sigreturn`, `rt_sigprocmask`,
   `sigaltstack`, `restart_syscall`, `sched_yield`, `getpid`, `gettid`,
   `tgkill` of itself (an abort), `exit`, `exit_group`. Another
   architecture's numbers and x86_64's x32 numbers match no rule.

The core takes no Landlock ruleset (it acts on any path), and seccomp only
per thread in R14c.

## 4. The kernel's roles (`common::wire::pid_role`)

`PROTECTED_PIDS` (`HashMap<u32, u8>`, pinned, 16 entries) holds a pid's
roles:

- `PROTECTED` (`0x02`): defended as a target — `task_kill` refuses every
  signal but 0, `ptrace_access_check` every trace, from a caller that is
  not exempt;
- `EXEMPT` (`0x01`): trusted as a caller — `inode_protect` lets it open
  the keys and the protected paths, `task_kill` and `ptrace_access_check`
  let it signal and trace a protected pid, `bpf_defense` lets it use the
  agent's BPF objects, `fim_watch` does not report its writes, the exec
  quarantine never stops it. An exempt pid is protected too.

The core and the watchdog are `0x03`; a worker `0x02`: the hooks defend it
as the agent's family and deny it the keys and the protected paths as they
deny anyone. Every lookup in the eBPF sources goes through
`task_kill::is_protected_pid` or `is_exempt_pid` (`xtask/tests/pid_roles.rs`).

**ABI.** The map's type, name, pin and size are unchanged. Before R14a
every entry held `1` and meant both roles; `1` is `EXEMPT`'s bit and an
exempt pid is protected, so an entry an earlier agent or watchdog wrote
means what it meant. An earlier object's hooks test only presence, so they
would read a worker's `0x02` as both roles; a worker starts only after this
boot's own hooks are attached and pinned (the attach phase), and while an
earlier link is still attached beside them the LSM chain denies when any
program denies. A downgrade leaves no worker behind: a worker dies with its
core (`PR_SET_PDEATHSIG`).

## 5. The channel (`nn_proto::ipc`, `nn_linux::worker::transport`)

- One message per packet (`SOCK_SEQPACKET`), postcard, at most 64 KiB; a
  larger packet is refused (`MSG_TRUNC`), as is any ancillary data
  (`MSG_CTRUNC`: a descriptor sent along is closed by the kernel). No
  descriptor crosses: a QNAME is a few hundred bytes, a ClientHello a TLS
  record, a DNS answer at most a frame. (The scanner's protocol is where
  one must: the file to hash, a sealed memfd for its configuration.)
- The worker speaks first: `WorkerHello { version, kind, pid, sandbox }`.
  The core refuses a version, a kind or a pid it did not start, another
  account, a group, no seccomp filter, no `no_new_privs`, a dumpable
  process, any capability, a core or process limit above 0, a Landlock
  level the declared ABI cannot give. Landlock itself is declared, not
  required.
- Requests carry ids the core chose, strictly increasing; a worker answers
  the request it was sent, once. An answer to another id, a second hello, a
  packet between requests (a flood), an answer of another kind, an answer
  out of its bounds (a count, a length, a character outside the result's
  alphabet) is a violation: the worker is killed. The core never parses the
  input itself, so it cannot compare a result with its own; it bounds what
  a lying worker hands it.

## 6. The supervisor (`nn_linux::worker::supervisor`)

One thread (`nn-workers`) starts what is due, reads a starting worker's
hello (5 s), notices a death, a packet nobody asked for, and pings an idle
worker every 10 s (2 s deadline). Requests run on the caller's thread, one
at a time per worker, with the caller's deadline.

A failure — a death, a violation, a hang, a hello late or refused — kills
the worker, takes its pid out of `PROTECTED_PIDS` (before the reap, so the
pid cannot be reused meanwhile), reaps it and starts the next one after a
backoff (at once, then 1, 2, 4… s, at most 60 s). Five failures in a row
disable the kind: its requests are refused at once, its signed degradation
written (`worker_parse: disabled: …`); a worker that then stays up 60 s
enables it again. A failure is a signed degradation too, at once for a
violation, a seccomp kill or a refused sandbox, otherwise at most one a
minute (the others counted into it).

**When a worker is down, the core does without what it gives. It never
parses in its own process instead** (plan §5).

The capability manifest carries each kind (`workers`): its state (`ready`,
`restarting`, `disabled`, `unavailable`, `stopped`), why, the kernel's
Landlock ABI as the core read it, and the sandbox level the worker declared.
A worse state is signed at once as a `capability_manifest_change`.

## 7. The compromised worker

`agent/tests/privileged_worker_harness.rs` (lab builds; every lab kernel)
starts workers through the core's own spawn path with `--hostile
<attack>` (`nn_linux::worker::hostile`):

- every forbidden call — the agent's key, a protected or a world-readable
  file, a new file, a TCP connect, an abstract socket, a signal or a trace
  of the core, an exec, a fork, `bpf`, `setuid`, executable memory — is
  killed by the filter (`SIGSYS`);
- beneath the filter (`noseccomp+`, the harness only), each layer refuses
  what the kernel lets it: DAC, `RLIMIT_NPROC`, the empty capability sets,
  Landlock by ABI; what no layer below the filter refuses on that kernel is
  asserted as such and printed;
- every protocol attack after a genuine hello is refused and the worker
  killed; the core survives and a new worker serves.

`deploy/lab/workers/worker-lab.sh` checks the installed agent's worker on
a guest: its identity and limits, the roles in `PROTECTED_PIDS`, a root
`kill -9` refused, the roles' meaning in the hooks (a root shell registered
with no role, the worker's or the agent's), crash, hang, kill and crash-loop
faults.
