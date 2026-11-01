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
| tamper | P0, 1,024 events | the source waits 50 ms, then the event is dropped (counted and signed); the rare tamper events wait for room | 100 ms | `fs_protect`, `module_load`, `io_uring` (its `SensorFlood`), `bpf_syscall`, `exploit_guard`, `open_sensor` (its `DefenderSignal`), `net_drain` (its `SensorFlood`) | kernel deny (the deny hooks) | blind | 1, 2, 3, 4, 5 |
| process | P1, 4,096 events | waits 10 ms, then dropped and counted | 250 ms | `process_spawn`, `exec_check`, `io_uring` | none (opt-in: the exec quarantine's deadline, the exec policy's deny) | blind | 1, 2, 3, 4, 5 |
| file | P2, 8,192 events | a new `FileOpen` dropped and counted; every other file event waits | 1 s | `file_open`, `open_sensor`, `fim_drain` | none | blind | 1, 2, 3, 4, 5 |
| network | P3, 8,192 events | the new event dropped and counted | 500 ms | `tcp_connect`, `dns_query`, `net_drain` | none (opt-in: the connect deny) | blind | 1, 2, 3, 4, 5 |
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
| `fs_protect` | FsProtectDenial | `lsm:` the 16 deny hooks (and `inode_set_acl`, `inode_remove_acl`, `file_ioctl_compat` where the kernel has them) | **kernel deny** | **fail-open**: a hook that cannot read what it needs lets the operation through, counted per hook and signed (`deny_fail_open`); a missing hook, `bpf` not in the LSM list or a delivered self-test signal refuses the start unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` | refused signals, ptraces, kexecs: one record per caller and operation a second, 50 a second per CPU (`task_denial_rate`) | comm 15 B | `fs_protect` |
| `module_load` | ModuleLoad | `lsm:kernel_read_file+kernel_load_data` | none | blind | — | module path 31 B per component (`path_truncated`), comm 15 B | `module_load` |
| `io_uring` | IoUring, SensorFlood | `tracepoint:io_uring/io_uring_create+io_uring_submit_req` (or `_sqe`); `create only` without a submit tracepoint | none | blind | ring creations 64 then 128 a second per process, 512 then 256 per user; submissions one record a second per process (`io_uring_rate`) | comm 15 B | `io_uring` |
| `bpf_syscall` | BpfSyscall | `lsm:bpf` | none (the same hook's refusals of the agent's links are `fs_protect`'s) | blind | one record per process and command a second (not counted) | comm 15 B | `bpf` |
| `exploit_guard` | ExploitPostcondition | lite: `lsm:capable+bprm_check_security+file_open` with `fentry` and `tp_btf` hooks; strict (`--exploit-guard strict`): `fentry` and raw tracepoints | none; enforce: SIGKILL before the call returns | blind | 4 reports per task (the rest counted by the kernel) | comm 15 B | `exploit_guard` |
| `open_sensor` | FileOpen, Fim, MassWrite, FileBurst, DefenderSignal | `lsm:file_open` (the FIM observer); its fallback is the `file_open` source's tracepoint (`--file-open-sensor tracepoint`, a failure to arm, or `bpf` not in the active LSM list): every open reaches userland, no mass writes, bursts, security-tool signals or FIM `Opened` records | none | blind | a read-only open repeated within 1 s is not recorded (by design) | path 31 B per component, 16 components (`path_truncated`), a renamed name's first 31 B, comm 15 B | `open_sensor` |
| `fim_drain` | Fim | `lsm:` the FIM observe programs | none | blind | 8,192 inodes with a write pending (`fim_dirty_full`) | child name 63 B (`FIM_CHILD_TRUNCATED`), comm 15 B | `fim` |
| `net_drain` | NetFlow, NetListener, SensorFlood | `kprobe:inet_csk_listen_start, fexit:tcp_close, kprobe:udp_sendmsg(+udpv6_sendmsg)` | none | blind | `listen()` 64 then 128 a second per process, 512 then 256 per user; UDP one row a second per destination (`listen_rate`) | comm 15 B | `tcp_close`, `listen`, `udp` |

`CanaryTripped` is no source's: the canary detector makes it inside the
decision from the event it replaces, which has that event's source and
class.

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
| `contract_version` | the contract's version (1) |
| `sources` | one entry per source: `source`, `classes`, `attach` (as the boot noted it, `not attached` without), `on` (`primary`, `fallback`, `none`), `state`, `why` (the boot's reasons and the degradations recorded about it), `probe` (the telemetry probe's word: `pending`, `seen`, `gap`; absent for a source it does not exercise), `terms` (its contract, as in §3) |
| `classes` | one entry per class: its queue, capacity, full-queue policy, decision budget, sources, strongest verdict, worst failure, loss stages, and `state`, the worst of its sources' |
| `fallbacks` | each source on a fallback, with its attach point |
| `missing` | each deny or observe hook not attached, and each source not `ok` (with its first reason) |
| `content` | the shipped lists not in force from their file: the copy built into the agent took over, or the file was edited by hand (the overlay gate's `default_list_*` rows say when) |
| `telemetry_probe`, `settled` | the probe's period (`off`), and whether its first round has ended (before it, every probed source is `pending`) |
| `degradations`, `trust_level`, `trust_reasons` | as before, now of this revision — the status shows these |
| `revision`, `hash`, `previous_hash`, `change` | the revision (0 at the boot), its hash, the hash of the revision before it, and what changed, one line each |

The **states** of a source:

| State | Meaning |
|---|---|
| `ok` | attached and running (on its attach point or a fallback), and the probe saw it or does not exercise it |
| `standby` | attached and inert by design: the fallback of a source that runs on its own (the `file_open` tracepoint while `open_sensor` runs) |
| `disabled_by_admin` | switched off by the operator (`--exploit-guard off`) |
| `attached_not_invoked` | attached, and not running: its BPF LSM programs do not run (`bpf` not in the active LSM list, or the deny self-test's signal was delivered), or the telemetry probe's event did not reach the pipeline |
| `unavailable` | nothing attached on this host (with why) |
| `adapter_terminated` | its pump or drain ended: the agent stops for the watchdog's restart, and signs this revision first |

A source's **losses** are not a state of the manifest: they are counted by
stage, signed in `telemetry_loss` rows and carried by every beat
([the event bus, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/architecture/EVENT_BUS.md)). A manifest that changed at every lost record would say
nothing about what is attached.

The **hash** is the SHA-256 of the manifest's JSON without its revision
fields, its unordered lists sorted: two starts that attach the same way on
the same host have the same hash, and the telemetry probe's first round
changes it once (`pending` to `seen`). A change of any capability changes
it.

What signs a revision: a degradation recorded after the boot (a drain that
ended, a fallback, a stream not persisted — every `subsystem_degraded`, its
own row kept), the telemetry probe's first round, a gap and its end, an
adapter that ended, a shipped list given way to its built-in copy.

## 5. Off the host

Every heartbeat carries the newest revision as `capabilities`: its `hash`,
its `revision` and `settled` (`HEARTBEAT.md`). `nn-admin heartbeat watch`
remembers the last settled hash it saw and says **`DEGRADED`** when a
settled hash differs from it — "the capability manifest changed" (within a
run) or "… changed across a restart" (a new run that attaches otherwise:
another kernel, an LSM list without `bpf`, a sensor on its fallback) —
naming both hashes and the revision. A run whose manifest has not settled
120 s after its start, and a beat without the field after beats that had
it, are `DEGRADED` too. The first check anchors the hash it sees. On the
host, `nn-admin capabilities --key` names the change; the audit log holds
each revision.

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
  deny runs: no self-defence), `module_load`, `bpf_syscall`,
  `exploit_guard` (lite), `fim_drain`;
- signs the boot's `subsystem_degraded` (`source: bpf_lsm`) and its manifest,
  and every beat carries a manifest hash that is not the one a verifier saw
  while the host ran `bpf`: `DEGRADED` off the host.

Enable `bpf` as `KERNEL_COMPATIBILITY.md` describes ("Enabling the bpf
LSM").
