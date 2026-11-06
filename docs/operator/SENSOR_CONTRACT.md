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
manifest's (below), the sensor self-test's (lot 280c, §5a: every round, each
source's own event or, for three, a check of its attach; a miss signed at
once, two in a row an alert) and the heartbeat's.

## 3. The sources

| Source | Events | Attach point; fallbacks | Synchronous verdict | Failure | Kernel budget (counter) | Truncations | Rings |
|---|---|---|---|---|---|---|---|
| `process_spawn` | ProcessSpawn | `tracepoint:sched/sched_process_exec`; without its standard-stream probes when the verifier refuses them (R020 off) | none; opt-in: the exec quarantine holds the process up to 2,000 ms (100 to 10,000) until its exec is judged | blind: its attach failing refuses the start; its pump ending stops the agent within 5 s | — | argv 511 B (`ARGV`), filename 255 B (`FILENAME`), exe path 31 B per component (`DEEP`), comm 15 B | `exec` |
| `file_open` | FileOpen | `tracepoint:syscalls/sys_enter_openat` — attached at every start, inert while `open_sensor` runs: its fallback | none | blind | — | filename 255 B (read from the caller's memory, not marked), comm 15 B | `file_open` |
| `exec_check` | ExecCheck | `lsm:bprm_check_security`; `tracepoint:syscalls/sys_enter_execve` with `--exec-sensor tracepoint`, a `linux_binprm` offset missing, the LSM program refused, or `bpf` not in the active LSM list (the path read from the caller's memory, no executable identity, no exec guards) | none; opt-in: the exec policy refuses with `EACCES` | blind | — | filename 255 B, exe path 31 B per component, comm 15 B | `exec_check` |
| `tcp_connect` | TcpConnect, NetFlow | `kprobe:tcp_v4_connect+tcp_v6_connect` | none; opt-in (`--net-connect-deny`): `socket_connect` refuses a blocklisted destination | blind; the opt-in deny lets a connect through when it cannot read the destination, uncounted | — | comm 15 B | `tcp_connect` |
| `dns_query` | DnsQuery, DnsFlood | `kprobe:udp_send_skb+udp_v6_send_skb` (and `dns_nss`, a uprobe on `libnss_resolve`); `kprobe:udp_sendmsg` with `--dns-sensor sendmsg` or without what the socket-buffer programs need (the name read from the sender's memory, IPv4 only) | none | blind | 64 queries at once then 128 a second per process, 2,048 then 1,024 per user (`dns_rate`) | query 288 B wire form (`qname_partial`, `NONLINEAR`), 252 B on the fallback, comm 15 B | `dns` |
| `fs_protect` | FsProtectDenial | `lsm:` the 21 deny hooks (lot 273b: `file_permission`, the write deny, the seventeenth; lot 273c: `task_setrlimit`, `task_setscheduler`, `task_setnice`, `task_setioprio`, another process's limits and priorities of a protected one; and `inode_set_acl`, `inode_remove_acl`, `file_ioctl_compat` where the kernel has them; lot 273: the cgroup move guard, `inode_permission`, `fexit:cgroup_procs_write_start` and (lot 273b) `fentry:cgroup_procs_write_finish`, where the kernel's BTF has the functions in the shape they read); lot 277: the start-in-cgroup tracker — `tp_btf:cgroup_attach_task`, `sched_process_fork`, `sched_process_exit`, `fentry:cgroup_post_fork`, `fexit:cgroup_procs_write_start`, their links and maps pinned beside the pin root so the marks go on while no agent runs and through an upgrade (`docs/operator/RULE_POLICY.md` §2.1); lot 280a: the sysctl judge — `cgroup/sysctl` linked to the root cgroup (the kernel's multi mode), its program and link pinned beside the pin root, which judges a guarded sysctl's write on the kernel's copy (attach point `sysctl_judge`; where it cannot be linked the write deny judges alone: `lsm:file_permission`, the fallback, signed) | **kernel deny** (the tracker refuses nothing: it marks a process not started in its cgroup, and the agent applies no exemption by cgroup or unit to it) | **fail-open**: a hook that cannot read what it needs lets the operation through, counted per hook and signed (`deny_fail_open`); a missing hook, `bpf` not in the LSM list or a delivered self-test signal refuses the start unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`; the move guard absent from the kernel is signed degraded; (lot 277) the tracker not attached is signed degraded and no exemption by cgroup or unit applies, a process whose mark could not be kept is *not known* (no such exemption for it and its forks until its thread group ends) | refused signals, ptraces (lot 273c: PID 1 in attach mode), kexecs, cgroup moves, `oom_score_adj` writes, (lot 273b) writes through a descriptor and (lot 273c) `prlimit` / `sched_set*` / `setpriority` / `ioprio_set` of a protected process, (lot 273d) a harmful write of a critical sysctl (lot 280a: or one refused on the kernel's copy, `sysctl_value`), and (lot 277) a move into a cgroup an exemption names (`cgroup_join`, recorded, not refused), (lot 281) the first code-injection access to a process (`exempt_injection`, the tracker's `lsm:ptrace_access_check` and `lsm:ptrace_traceme`, never refusing; signed when an exemption covered the process): one record per caller and operation a second, 50 a second per CPU (`task_denial_rate`); (lot 280a) a write the signed per-sysctl opt-out lets through (`sysctl_opt_out`, recorded, not refused): every one, within the 50 a second per CPU; cost (lot 273c, signed in the manifest's `overhead`; Ubuntu 24.04, the BPF stats off, medians of three A/B rounds): the move guard about 62 ns a call — `git status` ×10 +13 %, `find /usr` +2 % — and the write deny about 96 ns a write to a regular file — a 2,000-file package installed and removed +4 %; a socket, a pipe, a tty leave at its `i_mode`; the tracker (lot 277) runs at every fork (a new group's state cleared, a map lookup, a byte of the "not known" map, the reset's epoch) and at the exit of a marked group, and walks at most 255 bytes of path at a migration while an exemption by cgroup or unit is in force — about 0.93 µs a fork and its exit on Ubuntu 24.04 (6.8: `cgroup_post_fork` 469 ns, `sched_process_fork` 192 ns, `sched_process_exit` 272 ns a call) and 0.6 µs on 22.04 (5.15: 269, 139, 187 ns), `run_time_ns / run_cnt` over 100,024 calls with the BPF stats' own clock reads; a fork + exit + wait (about 140 µs on the 24.04 guest, 55 µs on the 22.04 one) the same with its links detached within the rounds' spread (lot 277, the third review of #494's lab); the sysctl judge (lot 280a) runs at every access to a `/proc/sys` file — about 56 ns a read, 455 ns a judged write of a guarded sysctl on Ubuntu 24.04 (6.8, `run_time_ns / run_cnt` over 20,009 calls each) | comm 15 B | `fs_protect` |
| `module_load` | ModuleLoad | `lsm:kernel_read_file+kernel_load_data` (lot 285: and `lsm:file_open`, the module files' write history; the exec tracepoint notes a package manager's `#!` script, dnf or yum, for its lineage) | kernel deny (lot 285): a module file the agent does not vouch for and an `init_module` buffer, outside a signed window, in the deny mode; a registered DKMS or akmods build written since boot outside a package transaction let through and recorded unless `enforce R018` (`RULE_POLICY.md` §2.4) | blind | — | module path 31 B per component (`path_truncated`), comm 15 B | `module_load` |
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
sensor self-test's DNS step finds a miss (`dns_query`'s word `missed`, then
`gap`), which the manifest signs as any other.

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
| `sources` | one entry per source: `source`, `classes`, `attach` (as the boot noted it, `not attached` without), `on` (`primary`, `fallback`, `none`), `state`, `why` (the boot's reasons and the degradations recorded about it), `probe` (the sensor self-test's word, lot 280c — every source has one: `pending` before its first round, `seen`, `missed` (the last round missed it), `gap` (two rounds or more in a row), `stale` (no round ended for 149 s), `not_exercised` (its step cannot run here: io_uring switched off, a trusted-installer window, its source not running); §5a), `evidence` (what its `ok` rests on: `probe` (its own event in the last round), `attach_check` (its programs found linked in the last round: the three sources no live event exercises), `self_test` (`fs_protect` before its first round: the boot's deny self-test, one hook), `attach_only`), `terms` (its contract, as in §3: in the boot's row; a change's row names them by `contract_hash`) |
| `classes` | one entry per class: its queue, capacity, full-queue policy, decision budget, sources, strongest verdict, worst failure, loss stages, and `state`, the worst of its sources' |
| `fallbacks` | each source on a fallback, with its attach point |
| `missing` | each deny or observe hook not attached, and each source not `ok` (with its first reason) |
| `content` | the shipped lists not in force from their file: the copy built into the agent took over, or the file was edited by hand (the overlay gate's `default_list_*` rows say when) |
| `telemetry_probe`, `settled` | the self-test's period (`off`), and whether its first round has ended (before it, every source is `pending`) |
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
| `unknown` | not known: an attach note the contract does not know, or one that does not say how it attached; the self-test's word `stale` (no round ended for two of its longest intervals and its deadline: 149 s at 60 s); lot 280c: its word `missed` (the last round's event did not come, or its attach check failed: not known whether it sees) |
| `attached_not_invoked` | attached, and not running: its BPF LSM programs do not run (`bpf` not in the active LSM list, or the deny self-test's signal was delivered), or (lot 280c) the self-test's event did not reach the pipeline in two rounds in a row (`gap`) |
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
hash; the self-test's first round changes it once (`pending` to
`seen`); a change of a capability changes it, an upgrade alone does not.
`contract_hash` covers the terms, the contract's and the agent's versions
and the kernel's release: what an upgrade changes.

**What signs a revision**: a degradation recorded after the boot (a drain
that ended, a fallback, a stream not persisted — every `subsystem_degraded`,
its own row kept), the self-test's first round, a miss (lot 280c), a gap,
its end, its word going stale, an adapter that ended, a shipped list given way to its
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

## 5a. What the self-test proves, and what it does not

Lot 280c (Wave 1): the telemetry probe became the **sensor self-test**.
Every round (60 s, ±20 %; `NN_TELEMETRY_PROBE_SECS`) a child of the
agent's own binary (`--telemetry-probe <nonce>`) makes one known, harmless
event for each source, and each must reach its pipeline within 5 s. Three
sources have no such event and get a check of their attach instead —
stated as such (`evidence: attach_check`):

| Source | The round's step | Word |
|---|---|---|
| `process_spawn` | the child's exec (`sched_process_exec`) | live |
| `exec_check` | the same exec (`bprm_check_security`; `sys_enter_execve` on the fallback) | live |
| `open_sensor`, `file_open` | a read of `/run/northnarrow/probe/<nonce>` | live |
| `dns_query` | a datagram naming `<nonce>.probe.northnarrow.invalid` sent to `127.0.0.1:53` (a response: no resolver answers or forwards it, external audit EVD-015) | live |
| `tcp_connect` | a connect to the child's own listener on a loopback port | live |
| `net_drain` | that listener's `listen()` (the listen kprobe) | live |
| `net_inbound` | the connection's accept | live |
| `tls_hello` | a ClientHello for the nonce's name as the connection's first send | live |
| `io_uring` | a ring of one entry made and closed | live (not exercised where io_uring is switched off) |
| `bpf_syscall` | a one-entry array map made and closed (`BPF_MAP_CREATE`) | live |
| `fim_drain` | a file created in the probe directory, which the FIM watches | live |
| `fs_protect` | `SIGURG` to the agent and a file created in `/etc/northnarrow`: both must be refused and their denials must arrive — two of the deny hooks (`task_kill`, `inode_create`); a step let through is a miss by itself; not exercised in a trusted-installer window, where nothing is refused by design | live |
| `module_load` | each of its programs still linked, and a load reported for each module new in `/proc/modules` since the last round | attach check |
| `exploit_guard` | each of its loaded programs still linked | attach check |
| `dns_answer` | each of its programs still linked | attach check |

The three attach checks, and why: loading a module is neither cheap nor
harmless; the exploit guard's event is an exploit's post-condition; a DNS
response comes from port 53, which the unit cannot bind (no
`CAP_NET_BIND_SERVICE`), and a query to the host's resolver is what
EVD-015 removed. The state directory is `chattr +i`: a create there is
refused by the kernel before any LSM hook runs, so the deny step creates in
`/etc/northnarrow` (registered `NOCREATE`, not immutable).

**A source missed** — its event did not come, its attach check failed, a
deny step was let through: at the round's end a signed degradation
(`subsystem_degraded`, source `sensor_selftest`, its detail naming the
sensor, its source and the step), the manifest's word `missed` and the
source `unknown` (a worse state: the revision signed at the next build),
the trust level counting it; **missed in two rounds in a row**, an alert
(`sensor_selftest_alert`, ERROR in the journal), the word `gap` and the
source `attached_not_invoked`; later rounds the journal only; **seen
again**, `sensor_selftest_restored` and the degradation withdrawn. A step
that cannot run is `not_exercised` (a WARN once): its round says nothing
of the source.

**The self-test's events are never judged.** The decision thread offers
every event to the self-test's tap first: an event of the child — its pid
within its lifetime (the agent reaps the child itself, so its pid is not
reused before) —, of its steps' shape (the round's nonce, a loopback
address, the expected target) and within the number its steps make, is
taken there and never reaches the rules, the posture, the detection store
or a response; anything else the child did is judged as any process's. The
network and FIM drains do not write the child's rows to the signed
netflow, listener and FIM drift logs, which the export reads (counted:
the journal's `rows_skipped`); before this lot the probe's DNS datagram left
one netflow row a minute.

**Its cost** is measured every round — the child's CPU time (its
`rusage`) and the agent's own checks — against a budget of 50 ms of CPU a
round; a round over it is a signed degradation until a round is back
under. The journal's summary every ten rounds gives the maxima
(`sensor self-test: the rounds' cost`). The lab measured, over ten rounds,
at most 3.9 ms of the child's CPU and 6.5 ms of the agent's checks a round
on Ubuntu 24.04 (6.8), 2.6 and 3.1 ms on 22.04 (5.15), every event within
5 ms of the round's start
([the capability programme, lot 280c](https://github.com/northnarrow/northnarrow-new/blob/main/docs/roadmap/CAPABILITY_PROGRAM.md)).

It finds a sensor blinded **naively or by accident** — a hook detached, a
ring no longer read, a kprobe disarmed for all, a layout broken by a kernel
update, its own rounds stopped (`stale`). It does not hold against **an
adaptive root**: the child is the agent's own binary run with
`--telemetry-probe`, which a root watching the execs can recognise and
serve, re-arming what it disarmed for the child's few milliseconds; kprobes
can be switched off as a whole through debugfs
(`/sys/kernel/debug/kprobes/enabled`: refused outside a window since lot
280b, below); an attach check proves a program linked, not that the kernel
runs it (a BPF LSM program without `bpf` in the active LSM list is the
manifest's other word, §6); and the deny step exercises two deny hooks of
the twenty-one each round. Against a root on the host the deny hooks (the
agent's own files, maps and processes) and the heartbeat's verifier off the
host are the defence: the manifest says what the agent can see, not what
it cannot.

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
its evidence. Since lot 280b (the short re-check of #497, NB1) the tracker
treats that period as marks lost: its fork tracepoint (`tp_btf`, which goes
on) checks every new thread group against what its fentry saw — a birth
the fentry missed is "not known" at once (that process tree, fail closed)
and counted, the check channel that tells "silent because ftrace is off"
from "silent because nothing happened"; at every build of the manifest the
switch at `0` (or unknown) or a birth missed opens a signed
`cgroup_join_marks` degradation naming when the loss began, and once the
switch is back at `1` with no birth missed since the last read the marks'
epoch is reset (every process started before is not known until it exits)
and the period is signed, the reset's line kept.
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

**The kprobes' switches** (lot 280b). `/sys/kernel/debug/kprobes/enabled`
at `0` disarms every kprobe on the host, the agent's among them (they stay
registered, silent); `debug.kprobes-optimization` at `0` turns every
optimised kprobe back into a breakpoint trap (a cost on each probed call,
not a blindness). Every write of either is refused outside a window,
whatever it carries — the debugfs file by the write deny's debugfs branch
(found by its filesystem and its names, `kprobes`), the sysctl by the write
deny and the `cgroup/sysctl` judge (`sysctl`), never opted out — and a `0`
set before the start or inside a window is put back to `1` at the window's
close and by the integrity round, signed as blinding. The lockdown file
(`/sys/kernel/security/lockdown`, `lockdown`) is refused the same way: a
raise to `confidentiality` takes the helpers that read kernel memory from
every BPF program loaded after it (`KERNEL_COMPATIBILITY.md`, "Lockdown").

The sysctl judge of lot 280a is a `cgroup/sysctl` program, which the
sysctl handler calls directly, not a trampoline: by the kernel's code
`ftrace_enabled=0` does not stop it (not measured in the lab).

What `0` silenced in between stays silenced: the verifier is told that it
happened, not that the hooks held. On 5.15 a `0` set before the agent's
start makes the trampolines' attach fail (`EBUSY`, by the kernel's code;
not measured here): the start's own degradations name the hooks.

**Worst-case delays** for a source blinded at random: its next round
within 72 s (60 s, +20 % jitter), its deadline 5 s — about **77 s to the
signed degradation**, the next build 5 s later the manifest's revision (a
worse state is signed at that build, whatever row came before it; an
oscillation already signed in the minute waits for the next row); the
alert one round later (at most 72 s more); then the next beat (30 s) and
the verifier's next check (its timer, 30 s in the example of
`HEARTBEAT.md`) — about **2.4 minutes to `DEGRADED`** off the host. A
self-test whose rounds stop is `stale` after 149 s. For the three sources
with an attach check the bound holds for a detach; their blinding by a root
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
