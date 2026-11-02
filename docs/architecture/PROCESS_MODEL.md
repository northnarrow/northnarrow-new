# The process model: a core and its unprivileged workers

Wave 4 restructure, R14 (plan §3.1, §3.2, §3.3, §3.5; report 06 INI-19).
R14a: the sandbox, the worker model, the IPC, the kernel's roles, the
`northnarrow-worker` account. R14b: the parsers in the worker. R14c: the
keys in one place, the capabilities per thread, the unit's hardening.

Operator side: [`docs/operator/WORKERS.md`](../operator/WORKERS.md).

## 1. Domains and processes

| Process | Identity | Capabilities | Confinement | Holds |
|---|---|---|---|---|
| `northnarrow-agent`, the **core** | root; its pid in `PROTECTED_PIDS` as **protected and exempt** (`0x03`) | the unit's bounding set; per thread, each role's effective set (R14c, §8) | the unit (`ProtectSystem=strict`, `NoNewPrivileges=true`, `LimitCORE=0`, a system-call denylist, native calls only, the personality locked: §10); the decision thread's own seccomp filter (§8); no Landlock: it acts on any path through `/proc/1/root` | the eBPF loader and links, the keys (§9), the decision, the posture, the COMBAT ladder, the actuators, the signer and the chains, the admin server, the workers' supervisor |
| the **`parse` worker** | `northnarrow-worker`; its pid **protected, not exempt** (`0x02`) | none: effective, permitted, inheritable and ambient sets empty; `no_new_privs` | seccomp allowlist; Landlock: every filesystem right handled with no rule, TCP bind/connect (ABI ≥ 4), signals and abstract sockets scoped (ABI ≥ 6); not dumpable; `RLIMIT_NPROC` 0, `RLIMIT_CORE` 0, 8 descriptors, 512 MiB of address space | nn-parse's parsers: the DNS pump's names (R14b, §6a) |
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
   `oom_score_adj` 1000 and `nice` 10 (the first the OOM killer takes,
   the last the scheduler serves — while the child may still lower its
   own score; review of #480, F12), `setgroups(0)`, `setresgid`,
   `setresuid` (raw system calls: the child has one thread),
   `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG(SIGKILL)` (after the uid
   change, which clears it) and a check that the core still lives, then
   every descriptor above 3 marked close-on-exec
   (`close_range(4, ~0, CLOSE_RANGE_CLOEXEC)`: the image's descriptor is
   resolved by `execve` before the close happens). The environment is
   empty, the directory `/`, stdin and stdout `/dev/null`, stderr a pipe
   the supervisor reads (§6; F4: never the agent's journal directly).
   `PR_SET_PDEATHSIG` belongs to the thread that forked: a worker is
   started from the supervisor's own thread only (`nn-workers`, which
   lives as long as the agent); `ImageLauncher` refuses any other.
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
   asked for), then **measured** (review of #480, F7): an abstract UNIX
   listener is made before the ruleset; after `restrict_self` the worker
   tries `open("/")` (`EACCES`: the files are denied), a TCP connect to
   `127.0.0.1:1` (`EACCES`: TCP is denied) and a connect to its own
   listener (`EPERM`: the scope holds). What it declares —
   `SandboxLevel { landlock_abi, landlock: full|partial|none, fs_denied,
   net_denied, scoped }` — is what was both asked of the kernel and seen
   to hold. Ubuntu 22.04's 5.15: ABI 1; Debian 12's 6.1: 2; Ubuntu 24.04's
   6.8: 4; Debian 13's 6.12: 6 — when Landlock is in the kernel's `lsm=`
   (0 otherwise);
5. last, the seccomp allowlist (the `seccompiler` crate; kill the process
   on any other call). The parse worker keeps: `recvfrom` on descriptor 3
   with the flags `MSG_TRUNC` and no address, `sendto` on descriptor 3
   with `MSG_NOSIGNAL` and no address (F8: no `msghdr`, so no
   `SCM_RIGHTS` can leave the worker), `write` to descriptor 2, `brk`,
   `mmap`/`mprotect` without `PROT_EXEC`, `munmap`, `mremap`, `madvise`,
   `futex`, `close`, `clock_gettime`, `getrandom`, `rt_sigreturn`,
   `rt_sigprocmask`, `sigaltstack`, `restart_syscall`, `sched_yield`,
   `getpid`, `gettid`, `tgkill` of itself (an abort), `exit`,
   `exit_group`. Another architecture's numbers and x86_64's x32 numbers
   match no rule. Some calls only the filter refuses on every lab kernel
   — a UNIX socket by path (the D-Bus bus), UDP, a user namespace,
   `io_uring_setup`, `keyctl`, `perf_event_open`, `userfaultfd`,
   `pkey_mprotect`, `tkill`, `rt_sigqueueinfo`, `pidfd_send_signal`
   (Landlock has no right for them on these ABIs, or the distribution's
   settings decide): the harness asserts each one killed (§7).

The core takes no Landlock ruleset (it acts on any path); its seccomp is
the unit's (§10) and, on the decision thread, a filter of its own (§8).

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
  level the declared ABI cannot give. Review of #480 (F7): the declared
  ABI must be the kernel's as the core reads it (capped at the newest the
  worker's build knows, 9), and every right that ABI gives must be
  measured — files from 1, TCP from 4, the scope from 6: a worker on a
  kernel with Landlock that is not under it is refused. The core then
  reads the worker's `/proc/<pid>/status` itself: the four uids and gids
  the account's, no supplementary group, `NoNewPrivs 1`, `Seccomp 2`, the
  inheritable, permitted, effective and ambient sets empty — the kernel's
  view, not only the worker's word.
- Requests carry ids the core chose, strictly increasing; a worker answers
  the request it was sent, once. An answer to another id, a second hello, a
  packet between requests (a flood), an answer of another kind, an answer
  out of its bounds (a count, a length, a character outside the result's
  alphabet) is a violation: the worker is killed. The core never parses the
  input itself, so it cannot compare a result with its own; it bounds what
  a lying worker hands it. An ALPN name is printable ASCII (the worker
  writes any other byte `\xHH`, F9); a refusal is one of a closed set
  (`Refusal`), never free text. The checks read bytes, never slice a
  `&str` at an offset a worker chose (F1: a JA4 with a two-byte character
  across byte 23 panicked the core): `clippy::string_slice` and
  `clippy::indexing_slicing` are denied in the module, and the `ipc_check`
  fuzz target holds every check to "no panic" and to its promises.
- The core never blocks on a worker (F2): before each request the core's
  send queue must be empty (`SIOCOUTQ`: a worker that does not read what
  it was sent is a violation, `Unread`), and the send does not wait
  (`MSG_DONTWAIT`: a full queue is the same violation).

## 6. The supervisor (`nn_linux::worker::supervisor`)

One thread (`nn-workers`) starts what is due, reads a starting worker's
hello (5 s), notices a death, a packet nobody asked for, and pings an idle
worker every 10 s (2 s deadline). Requests run on the caller's thread, one
at a time per worker, with the caller's deadline. The status the
heartbeat, the admin socket and the manifest read is a snapshot each pass
publishes: it never waits on a request in flight (F2).

A failure — a death, a violation, a hang, a hello late or refused — kills
the worker, takes its pid out of `PROTECTED_PIDS` and only then reaps it
(F3): a death is seen with `waitid(WNOWAIT)`, which leaves the zombie
holding the pid, so no new process can take a pid the hooks still defend.
A pid that cannot be taken out stays unreaped (its zombie keeps the pid)
and is a signed degradation; the supervisor tries again on each pass. The
next worker starts after a backoff (at once, then 1, 2, 4… s, at most
60 s).

What a worker writes to stderr reaches the journal through the
supervisor (F4): each line prefixed `worker parse:`, escaped (a byte
outside printable ASCII, and the backslash, as `\xHH`), cut at 200 bytes,
at most 20 lines a minute (the rest counted in one line when the minute is
over). A worker that burns half a CPU over 10 s while it is asked nothing
but pings is a hang (F12: what the ping does not find — it answers in
time and spins between them): killed, and signed like a hang. Five failures in a row
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

## 6a. What the parse worker parses (R14b)

The core runs no parser of hostile bytes: nn-parse's parsers run in the
parse worker only (`xtask/tests/no_parsing_in_the_core.rs`: the core's
production sources name `nn_parse` nowhere but the worker's side, nor the
worker's own answer, `worker::serve::answer` — `pub(crate)`, the parsers
in its caller's process — nor anything of `worker::serve::` but the
worker's entry; review of #481, R14b-3).

- **DNS query names.** The DNS pump copies a pass's records off the ring,
  asks the worker for their names (`Request::DnsNames`, a name's `form`:
  the `udp_sendmsg` sensor's wire name, the socket-buffer sensor's wire
  bytes with the end of the name asked for, an NSS record's text), in
  batches whose worst answer fits a frame, 50 ms each at most
  (`NAMES_TIMEOUT`: review of #481, R14b-2 — a quarter of the connects'
  wait for the pass, `INGEST_WAIT`, at most, pinned by a test; a worker
  slower than that is a hang, killed and signed, never a pass slowed to the
  connects' wait in silence), then builds the events from the answers the
  core checked. Every record gives its event: one decode or none per name,
  never a shorter list paired off (R14b-5). The socket-buffer sensor's
  query type is the two bytes after the end the worker found (bounded by
  the core to the record's bytes). Without an answer — the worker starting,
  restarting, disabled, out of time — an event carries no name
  (`qname_partial`), the DNS cache is not fed, and the names are counted
  and said in the journal; the telemetry probe's DNS round finds a gap and
  the capability manifest says so.
- **The TLS ClientHello and DNS answers** have no producer in this build
  (no sensor captures them); `nn_linux::worker::parse::ParseClient`'s
  `client_hello` and `dns_answers` are the one way a producer reaches
  them. The agent's `net::tls_parser` and nn-linux's DNS answer
  re-exports are gone (the fuzz targets name nn-parse).

**What the core checks of a decode** (`check_response`, review of #481,
R14b-1): one answer per name, its length and alphabet, an end only where
asked and just past a zero byte (the root label), no pointer in an NSS
name, and an empty name only where the bytes allow one (a wire name that
is empty, starts with its root label or is one byte; an NSS text empty to
its first NUL) — read from the input's first bytes, never its labels. A
refusal (`Answer::Refused`) of a request the core checked — it checks
each before it sends it, with the worker's own check — is a violation: the
worker is killed and the refusal signed, so a worker cannot blind the DNS
by refusing. A false but well-formed name (another real name for the
bytes) is within every bound: the round-trip check — the core re-encoding
the worker's presentation form and comparing it with the bytes' prefix,
a memory compare, no parse — is Open.

**The boot.** The workers start at the head of the attach phase, before the
sensors, so the DNS pump's first records find the worker ready; a worker's
pid is registered in `PROTECTED_PIDS` once this boot's deny hooks are
attached (`Workers::arm_roles`) — never in an earlier boot's map, whose
hooks would read any entry as both roles. Until then the worker is not
protected (root could kill it; the core would start another) and never
exempt.

**The cost**, measured in the lab (`docs/roadmap/CAPABILITY_PROGRAM.md`,
lot 272): one round trip per pass of the DNS ring over a `SOCK_SEQPACKET`
pair, and the worker's CPU; the overhead and soak scripts count the
worker's CPU and memory with the agent's.

## 7. The compromised worker

`agent/tests/privileged_worker_harness.rs` (lab builds; every lab kernel)
starts workers through the core's own spawn path with `--hostile
<attack>` (`nn_linux::worker::hostile`):

- every forbidden call — the agent's key, a protected or a world-readable
  file, a new file, a TCP connect, a UDP datagram, a UNIX socket by path
  (the D-Bus bus where there is one), an abstract socket, a signal to the
  core or to init by `kill`, `tgkill`, `tkill`, `rt_sigqueueinfo` or a
  pidfd, a trace of the core, an exec, a fork, `bpf`, `setuid`,
  executable memory (`mmap`, `mprotect` of a writable mapping,
  `pkey_mprotect`), a user namespace, `io_uring_setup`, `keyctl`,
  `perf_event_open`, `userfaultfd` — is killed by the filter (`SIGSYS`);
- beneath the filter (`noseccomp+`, the harness only), each layer refuses
  what the kernel lets it: DAC, `RLIMIT_NPROC`, the empty capability sets,
  Landlock by ABI; what no layer below the filter refuses on that kernel is
  asserted as such and printed; what the distribution's settings decide
  (user namespaces, `io_uring`, `perf_event_paranoid`, `userfaultfd`, a
  UNIX socket by path, UDP) is printed, not asserted;
- every protocol attack after a genuine hello is refused and the worker
  killed (a descriptor sent along now dies by `SIGSYS`: `sendmsg` is not
  the worker's); a worker that answers its pings and spins between them is
  killed as a hang; the core survives and a new worker serves;
- an honest worker's process, read from outside: the declared level, the
  kernel's ABI, `oom_score_adj` 1000, `nice` 10.

`deploy/lab/workers/worker-lab.sh` checks the installed agent's worker on
a guest: its identity and limits, the roles in `PROTECTED_PIDS`, a root
`kill -9` refused, the roles' meaning in the hooks (a root shell registered
with no role, the worker's or the agent's), crash, hang, kill and crash-loop
faults.

## 8. The core's threads and their capabilities (R14c, `nn_linux::caps`)

The unit's `CapabilityBoundingSet=` is the process's ceiling. Linux keeps
the effective, permitted and inheritable sets per thread: `capset(2)`
changes the calling thread only, and a thread starts with its creator's.
Each thread with a role keeps effective only what the role needs, from
its first line (`caps::enter`, said in the journal: `thread capabilities:
role …`):

| Role | Threads | Effective | Permitted | Why |
|---|---|---|---|---|
| decision | `nn-decision` | `CAP_SYS_PTRACE` | the same, for good | it reads `/proc/<pid>/exe` of the process it judges (the rules' trusted actor, the COMBAT guard, the lineage), which `ptrace_may_access` refuses for another user's or a more privileged process without it |
| actuator | `nn-response-*`, `nn-response-watch` | `CAP_KILL CAP_NET_ADMIN CAP_SETFCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE` | the bounding set | kill, `pidfd_send_signal`, `cgroup.kill`; nft and iptables; the strip; quarantine; `/proc/1/root` and the target's `/proc/<pid>/exe` (plan §3.2's own entry for `CAP_SYS_PTRACE`) |
| writer | `nn-canary-log` | `CAP_LINUX_IMMUTABLE` | the bounding set | the state directory's `chattr +i` lifted for a new chain file |
| supervisor | `nn-workers` | `CAP_SETUID CAP_SETGID CAP_KILL CAP_BPF` | the bounding set | the worker's account, set in the child before `exec`; the worker's signals (another user); its pid's role in `PROTECTED_PIDS` |
| loader | the start's thread while the eBPF object loads, its programs attach and its maps are pinned (`caps::lower`) | `CAP_BPF CAP_PERFMON` (and `CAP_SYS_ADMIN` where the Debian drop-in grants it) | the bounding set | load, attach, pin; tracepoint attach under `perf_event_paranoid` 3 |
| errands | `nn-errands` | `CAP_BPF` | the bounding set | what the decision's filter refuses it, done for it (below) |

Every other thread — tokio's runtime, the sensors' pumps, the admin
server's tasks, the chain writers that run on the runtime, the exec
guards, the copy-on-first-write guard — keeps the bounding set effective.
A runtime thread starts with the sets of the thread that made it start (a
role's thread's `spawn_blocking`); the runtime's start hook
(`caps::restore_core`) gives it the core's back, and so do the pumps,
which start inside the loader's window, and every other thread the core
starts — the copy-on-first-write guard's and its restore (review of #482,
R14c-4: `nn-cow-restore` is started by a response worker, and kept that
role's set: no `CAP_CHOWN`, no `CAP_FOWNER` for the files it puts back),
the exec guards, the slow-work and lineage-sweep threads.
`xtask/tests/thread_roles.rs` holds every production thread of the core to
a role or `restore_core` in its first lines, or to a listed reason. A
thread that cannot take the core's set back — its sets unreadable or
refused, or its permitted set less than the process's (one started by the
decision thread) — is a signed degradation (`thread_caps`). Only the
decision gives up its permitted set, and it starts no thread (Open: a
filter rule refusing it `clone` of a thread, so that this is enforced and
not only true).

**The decision's filter** (`caps::filter`, on that thread only, no
`TSYNC`): `capset`, `execve`, `execveat`, `bpf`, and — because it keeps
`CAP_SYS_PTRACE` to read `/proc` — `ptrace`, `process_vm_readv`,
`process_vm_writev`, `pidfd_getfd` fail with `EPERM` (on x86_64 under
their x32 numbers too). Review of #482 (R14c-1): and so do a file opened
for writing (`open`/`openat` with `O_WRONLY`, `O_RDWR`, `O_CREAT` or
`O_TRUNC`; `creat`; `openat2` whatever it asks, its flags being in user
memory a filter cannot read) and a signal to another process (`kill`,
`tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo` to a thread group not the
agent's, a group included; `tkill` and `pidfd_send_signal` always). The
decision writes no file and signals no process: the canary is the
writer's, the detections and the responses go by channels, and the lab's
trace of its calls saw none (below). Two side paths used to fall back to
the caller when their thread was missing — the canary's access writer
(`nn-canary-log`: its trips' rows and registry marks) and the COMBAT
ladder's worker (`nn-combat-ladder`: kills, nft, the signed stage rows) —
and, run on the decision thread, would now meet `EPERM`. Since the
re-check of #482 neither ever runs on its caller
(`nn_core::supervised::Supervised`): its queue's receiver is held apart
from the thread; a thread that did not start, or ended, is a signed
degradation (`canary_writer`, `combat_ladder`) and is started again — the
canary's writer every 30 s by a runtime task, the ladder's worker by its
5 s tick, both on runtime threads, never the decision's — with its work
waiting in its queue meanwhile (beyond the queue: counted and said); a job
that panics is lost and said, the thread goes on (in builds that unwind:
the release profile aborts on a panic, and the watchdog starts the agent
again). `EPERM`, not a kill: a crafted event that steers
the decision into one of them must not become a way to stop the agent.
Two things the decision did itself need two of them: the module
provenance rule's and the impact trust's `rpm -qf` on an RPM host, and
the security tools' detector registering a tool's new process in
`DEFENDER_PIDS`. They are its **errands** (`caps::errands`): done on
`nn-errands`, a thread the start makes before the decision runs, the
decision waiting for the answer as it waited for the call.

**What this is not.** The threads share one address space: a thread's set
is no wall against code that runs in the process — the worker's process
is that wall (§1–§7). A thread's set bounds what that thread's own calls
can do, and only where the kernel asks for a capability. The core runs as
uid 0: for another root process, or a root-owned file, the owner's rights
need none. So (review of #482, R14c-1, corrected here) a flaw that steers
the decision:

- into an `execve`, a `bpf`, a `capset`, a `ptrace` or a process's memory
  by `process_vm_*`, an nft rule (`CAP_NET_ADMIN`), a `chattr`
  (`CAP_LINUX_IMMUTABLE`), a file capability (`CAP_SETFCAP`), or a signal
  or a file of another user (`CAP_KILL`, `CAP_DAC_OVERRIDE`) — meets
  `EPERM`, from the filter or the missing capability;
- into opening a file for writing — a root-owned file by ownership, or
  another root process's `/proc/<pid>/mem` through its `CAP_SYS_PTRACE` —
  or a signal to a root process (`kill(2)` by equal uid, no `CAP_KILL`) —
  meets `EPERM` from the filter (above), not from the capability sets;
- into the other calls that change a root-owned file by its path —
  `unlink`, `rename`, `chmod`, `truncate`, `link`, `mkdir`… — is
  **not** refused: uid 0 owns those files. Nor is reading another
  process's open files through `/proc/<pid>/fd/N` (`CAP_SYS_PTRACE`'s
  read). Open: a read-only Landlock domain for the decision thread
  (`landlock_restrict_self` binds the calling thread; ABI ≥ 1 on the
  lab's four kernels), and the `/proc` broker that would leave it no
  capability at all;
- other threads' sets are not its own: the actuator, the writer, the
  errands and every thread that holds the core's set run programs with
  root's full sets at their `execve` (nft, iptables, rpm), as before R14c —
  for those threads the per-thread set is least privilege by default, not
  a wall (R14c-8).

**Measured** (`deploy/lab/caps/thread-caps.sh`: a kprobe and a kretprobe on
`cap_capable()` for the agent's threads, by name, through the workers' lab,
tamper-check and EXP-13r's burst and hang (and its crash on Ubuntu 24.04);
Ubuntu 22.04 5.15, Ubuntu 24.04 6.8, Debian 12 6.1, Debian 13 6.12; lot
272): no capability check a role's thread made for its work was refused.
The decision thread's granted checks were all `CAP_SYS_PTRACE`; the response
workers' `CAP_SYS_PTRACE` (their targets' `/proc`) and `CAP_KILL`; the
supervisor's `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL` and, on 5.15 and 6.1,
`CAP_BPF` (6.8 and 6.12 check no capability for a map update through a
descriptor); the errands' `CAP_BPF` (`DEFENDER_PIDS`, on 5.15).
Refused, and why it does not matter:

- capabilities the unit does not grant, refused before R14c as well: the
  decision's `CAP_SYS_NICE` (its renice to −5 keeps the agent's priority,
  as before), `CAP_SYS_ADMIN` probes, `CAP_SYS_RESOURCE`,
  `CAP_DAC_READ_SEARCH`;
- a worker's child after its `setresuid`, before its `exec`: the
  `DAC_OVERRIDE`/`DAC_READ_SEARCH` pair on its own `/proc/self/fd`, which
  the kernel then allows as the process's own;
- inside the loader's window, `CAP_NET_ADMIN` for aya's `DEVMAP` feature
  probe (the agent creates no devmap; with the Debian drop-in the probe's
  `CAP_SYS_ADMIN` fallback is granted);
- at an agent's exit, `CAP_KILL` on a role's thread without it (the
  decision, the errands, the writer): the kernel re-sends a worker's
  `PR_SET_PDEATHSIG` from each sibling thread the worker is reparented to;
  the thread that started it (the supervisor, `CAP_KILL`) delivered it
  first. A worker also exits when its channel closes.

The census (`CapEff`, `CapPrm`, `Seccomp` per thread) shows each role's set
and every other thread with the bounding set. No agent thread entered a call
the decision's filter refuses but the decision's own `capset` at its role's
entry, before its filter.

A thread left with more than its role (its sets not changed, its filter
refused) is a signed degradation (`thread_caps`): the agent runs.

## 9. The keys (R14c, `nn_linux::keys`)

The evidence signing key and the quarantine's master key are loaded once,
at the start, into the **key store** (`KeyStore`): not `Clone`, it hands
out an `Arc<dyn Signer>` and the `Vault` (seal, open) — never the bytes.
Each key lives in a mapping of its own (`keys::locked::Locked`):
`mlock`ed (never swapped), `MADV_DONTDUMP` (out of any core dump, beside
the process's `PR_SET_DUMPABLE 0` and the unit's `LimitCORE=0`), and on
drop zeroed byte by byte before it is unlocked and unmapped; the decoded
key file is zeroized after its move. The master key is read the first
time the vault is used (the quarantine), into the same kind of mapping.
Only `nn_linux::keys` names `SigningKey` and the vault's AES key
(`xtask/tests/keys_in_one_place.rs`).

After the review of #482:

- a key's mapping that the kernel did not lock (`RLIMIT_MEMLOCK`) or did
  not leave out of the dumps is a signed degradation (`key_memory`), the
  signing key's and the master key's alike (R14c-3);
- the crypto crates are built with their `zeroize` features (`aes-gcm`
  with `aes`, `ghash`, `polyval`; `hmac`, `sha2`, `digest`,
  `block-buffer`): the AES key schedule, the GHASH key and the HMAC state
  the vault's derivation leaves are zeroed when dropped (R14c-2). Not
  closed: `ed25519-dalek`'s signature computes `SHA-512(secret)` on the
  stack of the thread that signs, and nothing zeroes that copy upstream
  (Open: a signing thread with a locked, wiped stack);
- a key file is read once into a buffer of its maximum size (no growth,
  no freed copy) zeroed when dropped; the master key is read as the
  signing key is — a regular file, never a wait on a FIFO, at most 4 KiB
  (R14c-7);
- the signing key's public half is read from the half published beside it
  (`agent.sig.pub`); the private key is read for it only on a host without
  one (`keys::public_half`; the store's `verifying_half` for a holder of
  the store);
- no production path reads the master key but the store: an executor's
  configuration without the store's vault fails its quarantine, said
  (`vault_of`; the tests' builds make one), and the source test now also
  refuses `Vault::at`, `public_half`, `DEFAULT_SIGNING_KEY_PATH` and the
  crypto's types under any alias outside `keys` but where it lists them
  (R14c-5).

## 10. The unit's hardening (R14c)

`deploy/systemd/northnarrow-agent.service`, beside what it had
(`NoNewPrivileges=true`, `ProtectSystem=strict`, `LimitCORE=0`, the
bounding set):

- `SystemCallFilter=~ptrace process_vm_writev kexec_load kexec_file_load
  init_module finit_module delete_module swapon swapoff reboot mount
  umount2 pivot_root userfaultfd open_by_handle_at` with
  `SystemCallErrorNumber=EPERM` — for the agent and every program it
  starts (nft, iptables-restore, rpm, the scanner, the workers; a
  worker's own filter still kills on its first forbidden call);
- `SystemCallArchitectures=native` (no x32 or i386 entry);
- `LockPersonality=yes`.

Validated in the lab: through the workers' lab, tamper-check and EXP-13r,
under the unit, on Ubuntu 22.04, Ubuntu 24.04, Debian 12 and Debian 13, no
thread of the agent entered one of these calls (`thread-caps.sh`'s
`calls.tsv`), nor — traced from the Ubuntu 24.04 round on — any program it
starts (nft, iptables, rpm, the scanner); the one `finit_module` traced was
tamper-check C58's own module tool. Those runs passed as on `main`
(tamper-check's outcomes `main`'s). The
self-integrity round expects the process's `no_new_privs` 1, its seccomp
mode 2 and its core limit 0 from the unit (`limit_unexpected` otherwise;
`docs/operator/INSTALL_UPGRADE_UNINSTALL.md`).

