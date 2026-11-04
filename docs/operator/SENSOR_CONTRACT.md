# The sensor contract and the capability manifest

*Wave 4 restructure, R13 (lab PR 271; plan §3.6, report 06 INI-09 and
R4-01, EXP-37). Code: `crates/nn-core/src/contract/` (the types, the class
contracts, the manifest's portable half), `crates/nn-linux/src/sensors/contract.rs`
(the Linux values: `SOURCES`), `agent/src/boot/manifest.rs` (the signed
manifest and its revisions). Related: `BOOT_INTEGRITY.md` (the boot's
phases, the trust level, the manifest's older fields), `HEARTBEAT.md` (the
verifier off the host), [the event bus](https://github.com/northnarrow/northnarrow-new/blob/main/docs/architecture/EVENT_BUS.md)
(the classes, the queues, the loss stages).*

## 1. What the contract is

Every event the agent judges comes from a **source** of its event bus — a
ring's pump or a drain. For each source the contract declares:

- **where its events come from** — its attach point, and each fallback it
  can take, with when and what the fallback costs;
- **the synchronous verdict** — what decides on an event *before* the
  operation it reports completes: nothing (the event reports what
  happened), a **kernel deny** on a hook, or a **user-space deadline** (the
  operation held until it is judged); and the verdict an operator's opt-in
  adds;
- **the failure semantics** — what a failure of the source means:
  **fail-open** (the operations go on unchecked), **fail-closed** (they are
  refused, or the agent does not run without it), **blind** (nothing of it
  is seen until it is back) — and what the agent does then;
- **the kernel's budgets** that hold its records back before its ring, and
  the counter that counts what they hold (stage 2);
- **the truncations** — each field its records cut, with the bytes kept and
  how a reader knows (a flag, or nothing);
- **its loss counters** — the `RING_DROPS` slots of its rings (stage 1),
  its budgets (stage 2), the decoder (stage 3) and, for each class of its
  events, the bus's queue (stage 4) and the decision's delay (stage 5).

Each **class** of events (tamper, process, file, network, health) has the
contract its sources make, with the bus's own terms: its queue, the
queue's capacity, what a full queue does, the decision's budget.

The contract is code, not this page: a test fails when a kind of event or a
class has no source in it, when the code starts a pump or a drain, or notes
an attach point, that the contract does not name, when a truncation is not
the wire's bound or a budget not the eBPF program's constant. This page is
held to it too (a test reads it for every source and class).

## 2. The classes

| Class | Queue | When the queue is full | Decision's budget | Sources | Strongest verdict | Worst failure | Loss stages |
|---|---|---|---|---|---|---|---|
| tamper | P0, 1,024 events | the source waits 50 ms, then the event is dropped (counted and signed); the rare tamper events wait for room | 100 ms | `fs_protect`, `module_load`, `io_uring` (its `SensorFlood`), `bpf_syscall`, `exploit_guard`, `open_sensor` (its `DefenderSignal`), `net_drain`, `net_inbound`, `dns_answer`, `tls_hello` (their `SensorFlood`) | kernel deny (the deny hooks) | blind | 1, 2, 3, 4, 5 |
| process | P1, 4,096 events | waits 10 ms, then dropped and counted | 250 ms | `process_spawn`, `exec_check`, `io_uring` | none (opt-in: the exec quarantine's deadline, the exec policy's deny) | blind | 1, 2, 3, 4, 5 |
| file | P2, 8,192 events | a new `FileOpen` dropped and counted; every other file event waits | 1 s | `file_open`, `open_sensor`, `fim_drain` | none | blind | 1, 2, 3, 4, 5 |
| network | P3, 8,192 events | the new event dropped and counted | 500 ms | `tcp_connect`, `dns_query`, `net_drain`, `net_inbound`, `dns_answer`, `tls_hello` (lot 275) | none (opt-in: the connect deny) | blind | 1, 2, 3, 4, 5 |
| health | P0's | — | — | none yet | — | — | — |

The health class has no event yet: the sensors' health is the capability
manifest's (below), the telemetry probe's (an exec, a file open and a DNS
datagram a minute, each signed `telemetry_gap` when it does not arrive) and
the heartbeat's.

## 3. The sources

| Source | Events | Attach point; fallbacks | Synchronous verdict | Failure | Kernel budget (counter) | Truncations | Rings |
|---|---|---|---|---|---|---|---|
| `process_spawn` | ProcessSpawn | `tracepoint:sched/sched_process_exec`; without its standard-stream probes when the verifier refuses them (R020 off) | none; opt-in: the exec quarantine holds the process up to 2,000 ms (100 to 10,000) until its exec is judged | blind: its attach failing refuses the start; its pump ending stops the agent within 5 s | — | argv 511 B (`ARGV`), filename 255 B (`FILENAME`), exe path 31 B per component (`DEEP`), comm 15 B | `exec` |
| `file_open` | FileOpen | `tracepoint:syscalls/sys_enter_openat` — attached at every start, inert while `open_sensor` runs: its fallback | none | blind | — | filename 255 B (read from the caller's memory, not marked), comm 15 B | `file_open` |
| `exec_check` | ExecCheck | `lsm:bprm_check_security`; `tracepoint:syscalls/sys_enter_execve` with `--exec-sensor tracepoint`, a `linux_binprm` offset missing, the LSM program refused, or `bpf` not in the active LSM list (the path read from the caller's memory, no executable identity, no exec guards) | none; opt-in: the exec policy refuses with `EACCES` | blind | — | filename 255 B, exe path 31 B per component, comm 15 B | `exec_check` |
| `tcp_connect` | TcpConnect, NetFlow | `kprobe:tcp_v4_connect+tcp_v6_connect` | none; opt-in (`--net-connect-deny`): `socket_connect` refuses a blocklisted destination | blind; the opt-in deny lets a connect through when it cannot read the destination, uncounted | — | comm 15 B | `tcp_connect` |
| `dns_query` | DnsQuery, DnsFlood | `kprobe:udp_send_skb+udp_v6_send_skb` (and `dns_nss`, a uprobe on `libnss_resolve`); `kprobe:udp_sendmsg` with `--dns-sensor sendmsg` or without what the socket-buffer programs need (the name read from the sender's memory, IPv4 only) | none | blind | 64 queries at once then 128 a second per process, 2,048 then 1,024 per user (`dns_rate`) | query 288 B wire form (`qname_partial`, `NONLINEAR`), 252 B on the fallback, comm 15 B | `dns` |
| `fs_protect` | FsProtectDenial | `lsm:` the 21 deny hooks (lot 273b: `file_permission`, the write deny, the seventeenth; lot 273c: `task_setrlimit`, `task_setscheduler`, `task_setnice`, `task_setioprio`, another process's limits and priorities of a protected one; and `inode_set_acl`, `inode_remove_acl`, `file_ioctl_compat` where the kernel has them; lot 273: the cgroup move guard, `inode_permission`, `fexit:cgroup_procs_write_start` and (lot 273b) `fentry:cgroup_procs_write_finish`, where the kernel's BTF has the functions in the shape they read); lot 277: the start-in-cgroup tracker — `tp_btf:cgroup_attach_task`, `sched_process_fork`, `sched_process_exit`, `fentry:cgroup_post_fork`, `fexit:cgroup_procs_write_start`, their links and maps pinned beside the pin root so the marks go on while no agent runs and through an upgrade (`docs/operator/RULE_POLICY.md` §2.1) | **kernel deny** (the tracker refuses nothing: it marks a process not started in its cgroup, and the agent applies no exemption by cgroup or unit to it) | **fail-open**: a hook that cannot read what it needs lets the operation through, counted per hook and signed (`deny_fail_open`); a missing hook, `bpf` not in the LSM list or a delivered self-test signal refuses the start unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`; the move guard absent from the kernel is signed degraded; (lot 277) the tracker not attached is signed degraded and no exemption by cgroup or unit applies, a process whose mark could not be kept is *not known* (no such exemption for it and its forks until its thread group ends) | refused signals, ptraces (lot 273c: PID 1 in attach mode), kexecs, cgroup moves, `oom_score_adj` writes, (lot 273b) writes through a descriptor and (lot 273c) `prlimit` / `sched_set*` / `setpriority` / `ioprio_set` of a protected process, (lot 273d) a harmful write of a critical sysctl, and (lot 277) a move into a cgroup an exemption names (`cgroup_join`, recorded, not refused): one record per caller and operation a second, 50 a second per CPU (`task_denial_rate`); cost (lot 273c, signed in the manifest's `overhead`; Ubuntu 24.04, the BPF stats off, medians of three A/B rounds): the move guard about 62 ns a call — `git status` ×10 +13 %, `find /usr` +2 % — and the write deny about 96 ns a write to a regular file — a 2,000-file package installed and removed +4 %; a socket, a pipe, a tty leave at its `i_mode`; the tracker (lot 277) runs at every fork (a new group's state cleared, a map lookup, a byte of the "not known" map, the reset's epoch) and at the exit of a marked group, and walks at most 255 bytes of path at a migration while an exemption by cgroup or unit is in force — about 0.93 µs a fork and its exit on Ubuntu 24.04 (6.8: `cgroup_post_fork` 469 ns, `sched_process_fork` 192 ns, `sched_process_exit` 272 ns a call) and 0.6 µs on 22.04 (5.15: 269, 139, 187 ns), `run_time_ns / run_cnt` over 100,024 calls with the BPF stats' own clock reads; a fork + exit + wait (about 140 µs on the 24.04 guest, 55 µs on the 22.04 one) the same with its links detached within the rounds' spread (lot 277, the third review of #494's lab) | comm 15 B | `fs_protect` |
| `module_load` | ModuleLoad | `lsm:kernel_read_file+kernel_load_data` | none | blind | — | module path 31 B per component (`path_truncated`), comm 15 B | `module_load` |
| `io_uring` | IoUring, SensorFlood | `tracepoint:io_uring/io_uring_create+io_uring_submit_req` (or `_sqe`); without a submit tracepoint `partial` | none | blind | ring creations 64 then 128 a second per process, 512 then 256 per user; submissions one record a second per process (`io_uring_rate`) | comm 15 B | `io_uring` |
| `bpf_syscall` | BpfSyscall | `lsm:bpf` | none (the same hook's refusals of the agent's links are `fs_protect`'s) | blind | one record per process and command a second (not counted) | comm 15 B | `bpf` |
| `exploit_guard` | ExploitPostcondition | lite: `lsm:capable+bprm_check_security+file_open` with `fentry` and `tp_btf` hooks; strict (`--exploit-guard strict`, an equivalent fallback): `fentry` and raw tracepoints | none; enforce: SIGKILL before the call returns | blind | 4 reports per task (the rest counted by the kernel) | comm 15 B | `exploit_guard` |
| `open_sensor` | FileOpen, Fim, MassWrite, FileBurst, DefenderSignal | `lsm:file_open` (the FIM observer); its fallback is the `file_open` source's tracepoint (`--file-open-sensor tracepoint`, a failure to arm, or `bpf` not in the active LSM list): every open reaches userland, no mass writes, bursts, security-tool signals or FIM `Opened` records | none | blind | a read-only open repeated within 1 s is not recorded (by design) | path 31 B per component, 16 components (`path_truncated`), a renamed name's first 31 B, comm 15 B | `open_sensor` |
| `fim_drain` | Fim | `lsm:` the FIM observe programs | none | blind | 8,192 inodes with a write pending (`fim_dirty_full`) | child name 63 B (`FIM_CHILD_TRUNCATED`), comm 15 B | `fim` |
| `net_drain` | NetFlow, NetListener, SensorFlood | `kprobe:inet_csk_listen_start, fexit:tcp_close, kprobe:udp_sendmsg(+udpv6_sendmsg)` | none | blind | `listen()` 64 then 128 a second per process, 512 then 256 per user; UDP one row a second per destination (`listen_rate`) | comm 15 B | `tcp_close`, `listen`, `udp` |
| `net_inbound` | NetInbound, SensorFlood | `fexit:inet_csk_accept` (the program built for this kernel's parameter count: 4 up to 6.9, 2 from 6.10, read from its BTF), `fexit:tcp_close` (an accepted socket the accept recorded) — lot 275 | none | blind: its attach failing is signed (`net_inbound`) and the agent runs without it; its drain ending stops the agent within 5 s | accepts 256 at once then 512 a second per accepting process, 2,048 then 1,024 per user; a held accept's close is not recorded either (`inbound_rate`); cost (lot 275, signed in the manifest's `overhead`; Ubuntu 24.04, `run_time_ns / run_cnt`): about 666 ns an accept — a connect/accept/close loop +5.9 % with the agent on | comm 15 B | `inbound` |
| `dns_answer` | DnsAnswer, SensorFlood | `fexit:udp_recvmsg+udpv6_recvmsg` (6 parameters up to 5.18, 5 from 5.19), the response read from the receiver's buffer; `udp_recvmsg` alone: partial — lot 275 | none | blind: its attach failing is signed (`dns_answer`), NN-L-NET-028 then judges every connect unknown; its pump ending stops the agent within 5 s | 64 responses at once then 128 a second per process, 2,048 then 1,024 per user, the resolvers' users exempt (`dns_answer_rate`); cost (lot 275, signed in the manifest's `overhead`): about 128 ns a UDP receive from another port than 53 (the family and port read first, the address only for 53) — a receive loop +20.6 % | response 512 B (`truncated`: the records past the cut are not read), comm 15 B | `dns_answer` |
| `tls_hello` | TlsClientHello, SensorFlood | `fentry:tcp_sendmsg` on an outbound flow's first send (marked by the connect kprobes), a ClientHello copied from the sender's buffer — lot 275 | none | blind: its attach failing is signed (`tls_hello`), NN-L-NET-003 cannot match; its pump ending stops the agent within 5 s | 64 hellos at once then 32 a second per process, 512 then 256 per user (`tls_rate`); cost (lot 275, signed in the manifest's `overhead`): about 121 ns a TCP send (a lookup that misses past a flow's first send) — a send loop +9.9 % | ClientHello 4096 B (`truncated`: a longer hello is `incomplete`, no fingerprint), comm 15 B | `tls` |

`CanaryTripped` is no source's: the canary detector makes it inside the
decision from the event it replaces, which has that event's source and
class.

Lot 275: a `dns_answer` record is decoded, and a `tls_hello` record
fingerprinted, by the same parse worker; while it is down a response binds
nothing and NN-L-NET-028 judges unknown (no detection) every connect no
earlier binding covers, for five minutes after the last record it could not
decode; a hello's event says `undecoded`. The sender's
buffer a ClientHello is read from is user memory, read when the send
begins: a sender can rewrite it meanwhile, as it can shape its hello like
another client's. A ClientHello sent with the connect (TCP Fast Open) is not
seen.

R14b: a `dns_query` event's name is decoded by the agent's parse worker
(`WORKERS.md`), not by the agent's core. While the worker is down or
disabled the events still come, with no name (`qname_partial`), and the
core does not decode them itself: the DNS rules that match on a name are
silent, the connects that follow are not attributed to a name, and the
telemetry probe's DNS round finds a gap (`dns_query`'s `probe: gap`), which
the manifest signs as any other.

## 4. The capability manifest

At every boot, before `READY=1`, the agent signs what it runs with against
this contract: the audit row `capability_manifest` (revision 0; its fields
of lab PR 218 are in `BOOT_INTEGRITY.md` §6). While the agent runs it builds
the manifest again every 5 s, and from the status and each heartbeat; when
anything in it changed it signs a **`capability_manifest_change`** row —
the next revision, whole, with what changed. Read the newest one with
`sudo nn-admin capabilities --key <key>` (`--json` for all of it); `sudo
nn-admin status --key <key>` prints its summary. The key needs
`audit-read` or `telemetry-read`.

What R13 adds to the row (`manifest_version` 2):

| Field | Content |
|---|---|
| `sensors[].took` | how the attach code took each attach point: `whole`, `partial` (with what did not attach), `fallback`, `off`, `absent` |
| `contract_version`, `contract_hash` | the contract's version (1), and the hash of its terms, the agent's version and the kernel's release |
| `sources` | one entry per source: `source`, `classes`, `attach` (as the boot noted it, `not attached` without), `on` (`primary`, `fallback`, `none`), `state`, `why` (the boot's reasons and the degradations recorded about it), `probe` (the telemetry probe's word: `pending`, `seen`, `gap`, `stale`; absent for a source it does not exercise), `evidence` (what its `ok` rests on: `probe`, `self_test`, `attach_only`; `fs_protect`'s `self_test` is the deny self-test's one hook, `task_kill`, of the sixteen: the other fifteen rest on their attach), `terms` (its contract, as in §3: in the boot's row; a change's row names them by `contract_hash`) |
| `classes` | one entry per class: its queue, capacity, full-queue policy, decision budget, sources, strongest verdict, worst failure, loss stages, and `state`, the worst of its sources' |
| `fallbacks` | each source on a fallback, with its attach point |
| `missing` | each deny or observe hook not attached, and each source not `ok` (with its first reason) |
| `content` | the shipped lists not in force from their file: the copy built into the agent took over, or the file was edited by hand (the overlay gate's `default_list_*` rows say when) |
| `telemetry_probe`, `settled` | the probe's period (`off`), and whether its first round has ended (before it, every probed source is `pending`) |
| `degradations`, `trust_level`, `trust_reasons` | as before, now of this revision — the status shows these |
| `revision`, `hash`, `previous_hash`, `change`, `changes` | the revision (0 at the boot), its capabilities hash, the hash of the revision before it, what changed (one line each) and how many changes the row folds; the running view (`status`, `capabilities`) adds `unsigned_changes`, the changes not signed yet |
| `workers` | R14a (`WORKERS.md`): each worker kind, its `state` (`ready`, `restarting`, `disabled`, `unavailable`, `stopped`), `why`, `kernel_landlock_abi`, and the `sandbox` its worker declared (the Landlock ABI and what it enforced, the seccomp filter, `no_new_privs`, the account, the capability sets). A worse state — a kind disabled, unavailable, gone, or a worker sandboxed less than before — is signed at once like a source's; a worker's restart that ends within the 5 s between two builds changes nothing |

The **states** of a source:

| State | Meaning |
|---|---|
| `ok` | its attach code took the contract's attach point whole — that note exactly, never a prefix of it — or an equivalent fallback; its pump runs; its BPF LSM programs run when it has some; the probe saw it or does not exercise it |
| `standby` | attached and inert by design: the fallback of a source that runs on its own (the `file_open` tracepoint while `open_sensor` runs) |
| `disabled_by_admin` | switched off by the operator (`--exploit-guard off`) |
| `partial` | part of it runs: a hook of it not attached (12 of 16 deny hooks; the DNS sensor without `udp_v6_send_skb`), a fallback that covers less (`open_sensor` on the tracepoint: no `MassWrite`, `FileBurst`, `DefenderSignal`, no FIM `Opened` records, the path read from the caller's memory; `exec_check` on `sys_enter_execve`: no executable identity, no exec guards), part of it an LSM program that does not run (the lite exploit guard without `bpf`), an opt-in configured that cannot run (`--exec-policy enforce`, `--exec-quarantine enforce`, `--net-connect-deny` without `bpf`) — what is missing in `why` |
| `unknown` | not known: an attach note the contract does not know, or one that does not say how it attached; the telemetry probe's word `stale` (no round ended for two of its longest intervals and its deadline: 149 s at 60 s) |
| `attached_not_invoked` | attached, and not running: its BPF LSM programs do not run (`bpf` not in the active LSM list, or the deny self-test's signal was delivered), or the telemetry probe's event did not reach the pipeline |
| `unavailable` | nothing attached on this host (with why), or attached with no pump or drain started to read it |
| `adapter_terminated` | its pump or drain ended: the agent stops for the watchdog's restart, and signs this revision first |

A source's **losses** are not a state of the manifest: they are counted by
stage, signed in `telemetry_loss` rows and carried by every beat
([the event bus, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/architecture/EVENT_BUS.md)). A manifest that changed at every lost record would say
nothing about what is attached.

**Two hashes.** `hash` is the SHA-256 of the capabilities: the manifest
without its revision fields, without the contract's terms, without what an
upgrade or a new kernel changes by itself (the agent's version, the
kernel's release, the offsets counted, the host checks' values), its
unordered lists sorted. Two starts that attach the same way have the same
hash; the telemetry probe's first round changes it once (`pending` to
`seen`); a change of a capability changes it, an upgrade alone does not.
`contract_hash` covers the terms, the contract's and the agent's versions
and the kernel's release: what an upgrade changes.

**What signs a revision**: a degradation recorded after the boot (a drain
that ended, a fallback, a stream not persisted — every `subsystem_degraded`,
its own row kept), the telemetry probe's first round, a gap, its end, its
word going stale, an adapter that ended, a shipped list given way to its
built-in copy. The running agent builds the manifest every 5 s (and for
each status and each beat): a change shows at once in the status and the
beats. Its `capability_manifest_change` row is signed **at once** when the
state is worse — a source in a worse state or gone, a probe's word turned
`gap` or `stale`, a line new in `missing`, `fallbacks`, the degradations,
the content or the deny hooks' missing ones, fewer deny hooks, a lower
trust level — unless the same state was signed within the minute (an
oscillation): a real loss's row does not wait, nor die with a crash in the
minute. A better state's row, and an oscillation's, is signed at most once
a minute — the changes in between folded into it, counted (`changes`) and
named, even those undone before the row —; an adapter that ended and the
stop sign at once.

## 5. Off the host

Every heartbeat carries the newest view as `capabilities`: its `hash`, the
last `revision` signed, `settled`, `contract`, `contract_version` and
`kernel` (`HEARTBEAT.md`). `nn-admin heartbeat watch` remembers the last
settled hash it saw and says
**`DEGRADED`** when a settled hash differs from it — "the capability
manifest changed" (within a run) or "… changed across a restart" (a new run
that attaches otherwise: an LSM list without `bpf`, a sensor on its
fallback, a probe gone silent or stale) — naming both hashes and the
revision. A change of `contract` alone — an upgrade, a new kernel — is a
**`NOTICE`** line, no alert: a fleet's upgrade does not page anyone. The
beat carries the contract's version and the kernel's release beside it, and
the verifier checks that they and the agent's version each advanced or
stayed: one going backwards (a downgrade to an older agent, whose terms may
be weaker; a boot on an older kernel) or one not known to be newer (a
kernel's other flavour, a pre-release tag) is **`DEGRADED`** "the sensor
contract changed backwards", naming it. Two builds that carry the same
versions are told apart by the hash alone: a `NOTICE`. A run
whose manifest has not settled 120 s after its start, and a beat without
the field after beats that had it, are `DEGRADED` too. The first check
anchors what it sees. On the host, `nn-admin capabilities --key` names the
change; the audit log holds each revision.

## 5a. What the probe proves, and what it does not

The telemetry probe makes one exec, one file open and one DNS datagram a
minute and checks that each reaches the pipeline. It finds a sensor blinded
**naively or by accident** — a hook detached, a ring no longer read, a
kprobe disarmed for all, a layout broken by a kernel update, its own rounds
stopped (`stale`). It does not hold against **an adaptive root**: the probe
child is the agent's own binary run with `--telemetry-probe`, which a root
watching the execs can recognise and serve, re-arming what it disarmed for
the probe's few milliseconds; kprobes can be switched off as a whole through
debugfs (`/sys/kernel/debug/kprobes/enabled`); and the ten sources the probe
does not exercise (`evidence: attach_only`; `fs_protect`'s `self_test` is
one deny hook of sixteen, at the boot) are never verified again after their
attach. Against a
root on the host the deny hooks (the agent's own files, maps and processes)
and the heartbeat's verifier off the host are the defence: the manifest
says what the agent can see, not what it cannot.

**`kernel.ftrace_enabled`, the switch under the deny hooks** (lot 273d, R1
of the external review of 04/11). On 6.0 to 7.2 a write of `0` turns every
call site ftrace manages back into a NOP, with no error, and the BPF
trampolines on them stop firing: the fentry/fexit sensors (`cgroup_guard`,
`epg`, `epg_lite`, `tcp_close`, `sensor_probe`; since the merge with lots
277 and 275 also the start-in-cgroup tracker's `fexit:cgroup_procs_write_start`
and `fentry:cgroup_post_fork`, and the network telemetry's
`fexit:udp_recvmsg` / `udpv6_recvmsg` and `inet_csk_accept`), the kprobes
ftrace carries (`tcp_connect`'s among them) and, by the kernel's code, the
BPF-LSM programs — every deny hook. With the switch at `0` (possible only
inside a window) the tracker misses a birth by `CLONE_INTO_CGROUP` into an
exempt cgroup (`cgroup_post_fork` silenced), and NN-L-NET-028 loses half
its evidence; treating the tracker's marks as lost while the `ftrace_enabled`
degradation holds is lot 280's (the short re-check of #497, NB1).
The lab measured it on our own guests (lot 273d, C106c: the run counts of
the agent's programs under the same load, the switch written `0` inside a
window, then `1`): on 6.1, 6.8, 6.12 and 7.0 the BPF-LSM programs ran
10,535 to 13,333 times with the switch on and **0 times at 0**, the kprobe
programs 5 and 0, the fentry programs (`epg_lite`'s `commit_creds` and
`switch_task_namespaces`, `tcp_close`) 5 to 57 and 0; the programs on
tracepoints (`tp_btf`: fork, exit) kept running, and everything ran again
at `1`. On 5.15 the write was `EBUSY` and nothing stopped. On 5.15 to 5.19 the write is `EBUSY` while a trampoline is
attached; from 7.3 it is refused. So the deny hooks defend against a root
only while the switch is on, and the agent holds it there three ways:

- every write of it outside a trusted-installer window is refused by the
  write deny itself, whatever it carries (`sysctl`, signed, ENGAGED): no
  legitimate use is known, and with no value to judge the hook reads no
  byte a second thread of the writer could change before the kernel
  copies it. The agent's own restore passes by its identity, as every
  guarded write of its does;
- the switch is read at every build of the capability manifest (5 s): `0`,
  or a value that cannot be read, is a signed `ftrace_enabled`
  degradation while it holds — a worse state, so its revision is signed at
  once and the beat's hash changes: `DEGRADED` off the host within the
  bound below;
- a `0` set inside a window, or before the agent's start, is put back to
  `1` at the window's close and by the integrity round (`sysctl_restored`,
  signed).

What `0` silenced in between stays silenced: the verifier is told that it
happened, not that the hooks held. On 5.15 a `0` set before the agent's
start makes the trampolines' attach fail (`EBUSY`, by the kernel's code;
not measured here): the start's own degradations name the hooks.

**Worst-case delays** for a probed source blinded at random: its next
round within 72 s (60 s, +20 % jitter), its deadline 5 s, the next build
5 s — about **82 s to the signed row** (a worse state is signed at that
build, whatever row came before it; an oscillation already signed in the
minute waits for the next row); then the
next beat (30 s) and the verifier's next check (its timer, 30 s in the
example of `HEARTBEAT.md`) — about **2.4 minutes to `DEGRADED`** off the
host. A probe whose rounds stop is `stale` after 149 s. For the sources the
probe does not exercise there is no such bound: their blinding by a root
that leaves the attach in place is not seen.

## 6. A kernel without `bpf` in `lsm=` (EXP-37)

On a kernel built with `CONFIG_BPF_LSM=y` whose active LSM list does not
name `bpf`, the BPF LSM programs attach and the kernel never runs them. The
start is refused (exit 78, signed `refused_by: bpf_lsm`) unless
`NN_ANTI_TAMPER_ALLOW_DEGRADED=1`: then the agent runs in its **degraded
mode**, trust level L0, and

- takes the tracepoints its sensors have instead (R13): the exec sensor on
  `sys_enter_execve` (`exec_check` on a fallback) and the file opens on
  `sys_enter_openat` (`open_sensor` on its fallback, `file_open` running),
  each signed (`exec_sensor`, `file_open_sensor`: "bpf is not in the active
  LSM list");
- states in the manifest every source whose programs are LSM programs and
  have no fallback as `attached_not_invoked` with why: `fs_protect` (no
  deny runs: no self-defence), `module_load`, `bpf_syscall`, `fim_drain`;
  the lite exploit guard as `partial` (its `fentry` and `tp_btf` hooks run,
  its LSM use points do not); `exec_check` and `open_sensor` as `partial` on
  their fallbacks (what each loses named); an opt-in configured that needs
  an LSM program (`--exec-policy enforce`, `--exec-quarantine enforce`,
  `--net-connect-deny`) as inert, its source `partial`;
- signs the boot's `subsystem_degraded` (`source: bpf_lsm`) and its manifest,
  and every beat carries a manifest hash that is not the one a verifier saw
  while the host ran `bpf`: `DEGRADED` off the host.

Enable `bpf` as `KERNEL_COMPATIBILITY.md` describes ("Enabling the bpf
LSM").
