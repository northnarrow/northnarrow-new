# Tappa 10.9 — Sensor attach points (file open, exec, DNS) Design

**Status:** Accepted — merged on 2026-10-11 at the owner's request. The
options §8 proposes are taken as decided unless the owner says otherwise;
Q5 is restated after step 0 (§9), which refused `fexit` below 6.5, and
revised in step 3 (§12). Done: step 0 (§9), step 1 — file opens (§10),
step 2 — exec (§11). Step 3 — DNS is §12.
**Author:** Claude Code (architecture), 2026-10-11.
**Scope:** the first item of Tappa 10.9 ("Punto di aggancio dei sensori").
The other 10.9 items (workload identity, runtime injection, persistence
chains, new LSM hooks, …) are out of scope here, except where this change
prepares them (§6).

---

## 1. Purpose

Three sensors read what a process *asks* the kernel to do, at syscall
entry, from user memory:

| Sensor | Attach point today | What it reads |
|---|---|---|
| file open | tracepoint `syscalls/sys_enter_openat` | the path string in user memory, flags |
| exec pre-check | tracepoint `syscalls/sys_enter_execve` | the filename string in user memory |
| DNS QNAME | kprobe `udp_sendmsg` | the payload through the user `iov` |

That placement has three measured or published costs:

1. **Overhead and loss.** Every `openat` of the host reserves a ring-buffer
   record and is shipped to userland, which drops almost all of them
   (`fim::drain` keeps only the paths a rule reads). The overhead
   benchmark (lab PR 37, one round on a busy host) measured **37 % of
   open and 47 % of open+write throughput lost** with the agent running,
   about 7 µs of agent CPU per open; review 45 recorded **1 261 and 4 597
   lost events** on a `daemon-reload` and an install burst (5.15, 4 vCPU).
2. **Time of check vs time of use.** A string read at `sys_enter` can be
   changed by another thread before the kernel copies it ("Phantom",
   Guo/Zeng): the sensor sees a benign path while the kernel opens or
   executes another one. The same holds for the DNS payload read through
   the user `iov` before `udp_sendmsg` copies it.
3. **Channels that skip the syscall.** `io_uring` opens files without
   entering `sys_enter_openat` (`IORING_OP_OPENAT` calls the VFS
   directly), so the file sensor never sees them; the lab's C22 case is
   caught only by the io_uring sensor's own ring events. (DNS is not
   affected: the kprobe is on the `udp_sendmsg` function, which an
   io_uring send reaches too — its problem is only item 2.)

The proposal moves each sensor to the point where the kernel acts on
**kernel-owned data**: LSM `file_open` for opens, LSM
`bprm_check_security` for the exec pre-check, and the socket buffer after
the copy for DNS. Each is reached by every path into the kernel
operation, `io_uring` included.

## 2. Constraints that shape the design

- **Kernel floor:** BPF LSM (5.7+, `bpf` in `lsm=`) and kernel BTF are
  already hard prerequisites (review 53). The lab matrix is 5.14 (RHEL 9,
  vendor tracepoint header), 5.15 (Ubuntu 22.04, old verifier), 6.1
  (Debian 12) and 6.8 (Ubuntu 24.04). Every program must load on all
  four.
- **The 5.15 verifier rules** (KERNEL_COMPATIBILITY.md) apply unchanged:
  no memset subprogram, no uninitialised stack reads, no `Option` spill,
  no large stack arrays (per-CPU scratch instead), no
  subtraction-derived map index, stay within the state budget.
- **No CO-RE.** Kernel struct offsets come from the `BTF_OFFSETS` map,
  resolved at boot from the live BTF (multi-kernel level 1), with
  alternatives for fields that moved and fail-closed on a missing one.
  Every new `struct file` / `dentry` / `linux_binprm` / `sk_buff` read
  needs a slot.
- **Event shape is a contract.** Rules, the posture machine, the canary
  detector and the telemetry probe consume `Event::FileOpen`,
  `Event::ProcessSpawn` and `Event::DnsQuery`; the change should keep
  those types (new fields appended with `#[serde(default)]`) so no rule
  changes in the same commit.
- **Fail-closed stays fail-closed.** A sensor that cannot attach is a
  `telemetry_gap`, never a silent downgrade to the old tracepoint.

## 3. What the sensors feed today (code survey, 2026-10-11)

### 3.1 File opens

`sys_enter_openat` (`agent-ebpf/src/file_open.rs`) reads the path from the
user pointer, resolves nothing (`dfd` is ignored, so relative paths stay
relative) and emits a 296-byte `FileOpenRaw` for **every** open of the
host into a 256 KiB ring (~860 records). There is no `openat2`, `open` or
`creat` hook.

**No decision rule reads `Event::FileOpen`.** The credential-read rules
(NN-L-FIM-011..017) and the chain precursors already come from an LSM
`file_open` program — FIM's `fim_file_open_observe` on inodes in
`WATCHED_PATHS` — and the canary detector consumes FIM events too. The
tracepoint stream feeds only:

| Consumer | Fields | What it needs from the stream |
|---|---|---|
| telemetry probe | filename | the agent's own probe file, `/run/northnarrow/probe/<nonce>` |
| posture `sensitive_file_access` | pid, uid, filename, flags | 5 exact files (`/etc/shadow`, …), all already in `WATCHED_PATHS` |
| posture `critical_file_modification`, `persistence_mechanism` | pid, filename, write flags | write-opens under a few prefixes (`/etc/...`, cron, systemd units) |
| posture `confirmed_intrusion`, mass-write arm | pid, comm, filename, flags, ts | **≥ 20 write-opens by one pid on any path in 60 s**, minus carve-outs (`/sys/`, `/proc/`, `/run/systemd/`, journal, `/run/user/<loginuid>/`, operator extras) |
| correlation buffer, ADE context, detection store | pid, uid, comm, filename, flags | context only |

So the full stream is needed for exactly one thing — counting write-opens
per process — and everything else is a small, known set of files.

Two more facts from the survey:

- `file_open` already runs two of our LSM programs (`fim_file_open_observe`
  and `protected_open_deny`): the hook itself is already paid for.
- **Credential stores are watched only under `/root` by default.**
  `configs/fim-paths.v1` lists `/root/.aws/credentials`, the gcloud,
  Docker, browser, password-store and GnuPG paths under `/root`, and
  asks operators to add `/home/<user>/…` through `fim-paths.local`. A
  default install does not see a user's `~/.aws/credentials` being read
  (review 54).

### 3.2 Exec

Two programs:

- `sched_process_exec` → `ProcessSpawnRaw` (840 B): filename from the
  tracepoint's kernel copy, parent data from `task_struct`, argv from
  the new `mm`. Every process rule (R001–R017), the chains, the canary
  detector, posture and the auth-lineage tracker read it. **Kernel data,
  post-exec: it stays as it is.**
- `sys_enter_execve` → `ExecCheckRaw` (296 B): filename from the **user
  pointer**, `ppid` left 0. No rule consumes it; posture's
  `confirmed_intrusion` uses it for `/tmp`/`/dev/shm` execs, and it is an
  ADE focal event. `execveat` is not hooked, so `fexecve` and
  `execveat(AT_EMPTY_PATH)` never produce it.

The "toolchain limit" its header cites (no BTF from bpf-linker 0.10, so no
LSM) no longer holds: 20 LSM programs load today with the same toolchain
through `Lsm::load(hook, &Btf::from_sys_fs())` and the `BTF_OFFSETS` map.

### 3.3 DNS

kprobe at `udp_sendmsg` entry: the QNAME is read from user memory through
the `iov_iter` (only `ITER_UBUF`, or `ITER_IOVEC` with one segment; enum
values resolved by name per kernel). There is **no `udpv6_sendmsg`
attach**: queries sent to an IPv6 resolver are not seen. Consumers: the
DNS attribution cache, NET-004/005/014, posture `suspicious_dns`, the
telemetry probe.

## 4. Proposal

### 4.1 File opens: one LSM `file_open` observer, filtered in the kernel

Extend the FIM observer on `file_open` (or add a sibling program on the
same hook) with three cheap, string-free checks, and retire
`sys_enter_openat`:

1. **Known files** — the opened inode, *or its parent directory's inode*,
   is in `WATCHED_PATHS` → emit as today's FIM `Opened`. The parent match
   gives one directory level without enumerating children: the posture
   prefixes (`/etc/cron.d`, `/etc/systemd/system`, …) and the telemetry
   probe directory become map entries.
2. **Credential stores anywhere** (answers review 54) — the dentry name,
   optionally with its parent's name, is in a small kernel table:
   `credentials` under `.aws`, `config.json` under `.docker`,
   `Login Data`, `key4.db`, `logins.json`, `*.kdbx`, any file under
   `.gnupg` or `.password-store` (ancestor walk ≤ 8 levels, constant
   bound). Every home is covered without listing it; userland keeps the
   final fragment check it already does (`is_credential_path`).
3. **Write-opens are counted, not shipped** — when `f_mode` has
   `FMODE_WRITE`, an LRU map keyed by tgid holds `{window_start, count}`.
   The program emits one `MassWrite` record when a process crosses the
   threshold in the window (same 20 in 60 s), not one record per open.
   Carve-outs are directory inodes in a `MASS_WRITE_CARVEOUT` map,
   tested by the same bounded ancestor walk; `/sys` and `/proc` are
   excluded by superblock magic.

Records carry pid, uid, comm, flags, `(dev, ino)` and a mount-relative path
from a bounded `d_parent` walk (16 × 32 B, the technique `module_load.rs`
already uses; no `bpf_d_path`, whose LSM allowlist is uncertain across our
kernels). Userland turns `dev` into the mount point through
`/proc/self/mountinfo` for display.

Effect: the ring sees only opens a consumer reads, plus one record per
mass-write burst. `io_uring` and `openat2` opens are covered because the
hook sits below every open path, and the path comes from the kernel's
dentry, not from user memory.

New `BTF_OFFSETS` slots: `super_block.s_magic`, `inode.i_mode`,
`inode.i_nlink` (the last two are also needed by §4.2).

### 4.2 Exec pre-check: LSM `bprm_check_security`, observe first

Replace `sys_enter_execve` with `lsm/bprm_check_security`. It runs for
`execve`, `execveat` and `fexecve` alike, after the kernel resolved and
opened the file. From `linux_binprm` it reads the kernel copy of the
filename and, from `bprm->file`, the inode properties the 10.9
"exec by inode property" item needs: tmpfs or memfd (superblock magic,
`memfd:` dentry), `i_nlink == 0` (deleted or `O_TMPFILE`), the
`(dev, ino)` identity. `ExecCheck` keeps its shape and gains those fields
(appended, `#[serde(default)]`); `ppid` comes from the task, as in
`sched_process_exec`.

The program returns 0. A `deny` mode (a map written by userland, off by
default) for the deterministic cases — memfd/fd exec (R004's class) and
exec from operator-listed tmpfs mounts (R001–R003's class) — belongs to
the 10.9 "inline enforcement" item; this step only leaves the hook ready
for it (§8 Q4).

New slots: `linux_binprm.file`, `linux_binprm.filename`, plus §4.1's.

### 4.3 DNS: read the query after the kernel copied it

Read the UDP payload from the socket buffer the send path built, instead of
the user `iov`: a `kretprobe` on `ip_make_skb` and `ip6_make_skb` (global
functions; the returned skb holds the copied payload, in the sending task's
context), or `kprobe` on `udp_send_skb` / `udp_v6_send_skb` where those
static functions are not inlined. (`fexit` would read the same return
value, but the two functions take 10 and 9 arguments and x86-64 BPF
trampolines take more than 6 only from 6.5: step 0 saw it refused on the
older kernels, §9.) The QNAME walk then runs on kernel memory
(`bpf_probe_read_kernel`), and the `iov_iter` enum handling disappears.
IPv6 resolvers are covered by the same change.

New slots: `sk_buff.head`, `sk_buff.transport_header` (an offset from
`head` on 64-bit kernels; the payload starts 8 bytes after it) and
`sk_buff.len`.

## 5. Facts noted while writing this

- Comments in `posture/triggers.rs` (around line 536) and
  `posture/lineage.rs` say the open events come from "the LSM file_open
  hook"; they come from the tracepoint.
- The exec ring's comment promises "~880 events"; at 840-byte records the
  256 KiB ring holds about 309.
- DNS over IPv6 is not captured (§3.3) — a coverage gap independent of
  this design, fixed by §4.3 (step 3: review 67). The N2 UDP flow sensor
  has the same gap (review 68).
- DNS over TCP (port 53) gives a flow but no query name, with either
  sensor.
- Default credential coverage stops at `/root` (§3.1, review 54).

## 6. What this prepares

- "Exec by inode property" (10.9) gets its data source in §4.2.
- "Inline enforcement" (10.9) gets a hook that can return `-EPERM`.
- "Workload identity" (10.9): cgroup id and namespaces are cheap to add to
  the same records while their layouts change.

## 7. Plan and gates

**Step 0 — feasibility on the four lab kernels (5.14 RHEL, 5.15, 6.1,
6.8).** Load throw-away programs: the §4.1 observer with the parent lookup,
the 8-level ancestor walk and the LRU counter inside the 5.15 verifier
budget; `bprm_check_security` reading `linux_binprm`; the DNS attach
candidates; resolve every new `BTF_OFFSETS` slot (RHEL alternatives
included). Nothing changes in the agent until this passes. Results: §9.

Then one PR per sensor, in this order: file opens (largest gain), exec,
DNS. Each keeps the old program behind a configuration switch for one
soak cycle, then deletes it. Gates for every PR, on all four guests:
`tamper-check`, `pkgmgr-check`, `pkg-check`, `release-check`, the e2e
suites, the telemetry probe, plus:

| Gate | Target |
|---|---|
| `nn-lab.sh overhead` (3 rounds, idle host) | open and write-open throughput loss < 5 % (unreachable on the lab, §9.1: restated in Q7) |
| ring drops on `daemon-reload` and an install burst (5.15) | 0 |
| a "Phantom" reproducer: a second thread rewrites the path after `openat` entry | the record names the file actually opened |
| `io_uring` openat of a credential file | credential-read detection, not only the ring events |
| a `~/.aws/credentials` read by a non-owner process for a user in `/home` | detected on a default install |
| a DNS query to an IPv6 resolver, and one whose payload changes after `sendmsg` entry | the QNAME the server receives |
| 24 h soak | no RSS slope above the current baseline |

## 8. Decisions for the owner

- **Q1 — Credential stores in user homes.** Kernel name/ancestor table
  (§4.1.2, covers every home by default) vs per-user expansion of
  `WATCHED_PATHS` at boot and on login. The table is proposed; it closes
  review 54 without configuration.
- **Q2 — Mass-write counting in the kernel** (one record per burst,
  carve-outs as directory inodes) vs shipping every write-open to
  userland. Kernel counting is proposed; it is what removes the load.
- **Q3 — Paths in records** are mount-relative from a bounded `d_parent`
  walk, with `(dev, ino)` and the mount point resolved in userland — no
  `bpf_d_path`. Acceptable?
- **Q4 — Exec deny now or later.** Observe-only in this step (proposed),
  with the deny mode left to the 10.9 inline-enforcement item, or the
  deny plumbing (mode map, default off) in the same PR.
- **Q5 — DNS attach point.** `fexit` on `ip_make_skb` / `ip6_make_skb`
  (proposed if step 0 confirms it on all four kernels) vs `kprobe` on
  `udp_send_skb` / `udp_v6_send_skb`. *Step 0 did not confirm it:* the
  trampoline refuses functions of more than 6 arguments before 6.5 (§9).
  Restated proposal, for the owner to confirm before the DNS PR: a
  `kretprobe` on the same two functions, which reads the same returned
  socket buffer on all four kernels; the `udp_send_skb` kprobe stays the
  fallback (static functions: attached by name on the lab kernels, but a
  compiler is free to inline or rename them).
  *Revised in step 3 (§12.1):* the return probe cannot tell a DNS query
  from another datagram, because the UDP header, port included, is written
  after `ip_make_skb` returns. It would also miss corked sends, and its
  instance pool can drop calls. Step 3 therefore attaches the kprobe on
  `udp_send_skb` / `udp_v6_send_skb`, and falls back to the old
  `udp_sendmsg` program if that function cannot be attached. The owner can
  reverse this.
- **Q6 — Transition.** Old programs kept behind a switch for one soak
  cycle and then deleted (proposed), or a direct switch.
- **Q7 — Overhead gate (added after step 0).** On the lab, an empty BPF
  LSM program on `file_open` already costs 4.6 % of open throughput
  (§9.1), so §7's "< 5 % loss" cannot be met by any design on this hook.
  Proposed instead: step 1 at least halves today's loss in
  `nn-lab.sh overhead` (3 rounds, idle host, same guest) and reports the
  nanoseconds added per open. The agent's own CPU per open must also fall,
  since no per-open record reaches userland any more. **Measured in step 1
  (§10.6):** the open loss falls from 31.9 % to 28.2 % and the agent's
  CPU per open from 6.4 µs to almost zero; the sensor's own kernel time on a
  read-only open is lower than the tracepoint's it replaces. Halving the
  total loss needs FIM's close and write-intent hooks reworked too
  (review 59). Two gates are therefore on the table: (a) the sensor costs
  no more kernel time per open than the tracepoint it replaces and no
  userland time (met for read-only opens, +154 ns for write-opens), or
  (b) the halving, which then waits for review 59.
- **Q8 — Credential-store opens in every home (added in step 1).** The
  kernel name table (Q1) now finds them in every home. NN-L-FIM-011..017
  kill any opener that is not the store's own CLI. But an owner's editor,
  or an SDK such as boto3 or terraform, opens these files too, so killing
  across every home would turn routine work into kills. Step 1 therefore
  reports these opens at the rule's severity without acting on them
  (`FimEvent::wide_coverage`). Files in the operator's watch list
  (`/root` by default) keep the kill, and the chain rules that use a
  credential read as a precursor are unchanged. Proposed: keep it this
  way, or kill only when the opener's uid differs from the file's owner.

## 9. Step 0 results (2026-10-11)

The runner is `northnarrow-agent --sensor-feasibility`, built only into lab
binaries (feature `test-privileged`) and driven by
`deploy/lab/nn-lab.sh sensor-feasibility [BASE]`; the probes are
`agent-ebpf/src/sensor_probe.rs`. The installed agent is stopped for the
run. The probes look only at the runner and its children, and the runner
exercises every property itself. Each run prints a Markdown report;
`BASE` moves the file fixtures to another filesystem.

| | Ubuntu 24.04, 6.8 | Debian 12, 6.1 | Ubuntu 22.04, 5.15 (lockdown) | AlmaLinux 9, 5.14 |
|---|---|---|---|---|
| required properties | 18/18 | 18/18 | 18/18 | after the soak |
| `file_open` observer, verified insns | 11 220 | 66 802 | not reported (< 5.16), accepted | |
| `bprm_check_security`, verified insns | 7 443 | 7 470 | not reported, accepted | |
| kretprobe `ip_make_skb` / `ip6_make_skb` | QNAME read (IPv4, IPv6) | QNAME read (IPv4, IPv6) | QNAME read (IPv4, IPv6) | |
| kprobe `udp_send_skb` / `udp_v6_send_skb` | attached by name, QNAME read | attached by name, QNAME read | attached by name, QNAME read | |
| fexit `ip_make_skb` / `ip6_make_skb` | loads and attaches | loads; attach refused (errno 524, `ENOTSUPP`) | loads; attach refused (`ENOTSUPP`) | |

The same runner with the fixtures on a btrfs loop filesystem (Ubuntu
24.04, `BASE` on the top level and in a subvolume) holds 14/18: the four
properties that compare a record's `(dev, ino)` with `stat()` fail (see
the notes).

What each run checks, all from the runner's own process:

- the eight new offsets resolve from the live BTF;
- a file in a watched directory (parent inode in the table) gives exactly
  one record, with the `(dev, ino)` of the file opened and its
  mount-relative path; a file outside the tables gives none;
- the record's `(dev, ino)` is the identity userland computes with
  `stat()` (checked on a record produced by the name table, which does
  not depend on any key userland computed);
- the name table (`credentials` under `.aws`, `key4.db` under any parent)
  and the ancestor table (`.gnupg`, up to 8 levels) match, and the same
  names under other directories do not;
- time of check vs time of use: 200 opens of one name while a second
  thread swaps it with another file (`renameat2(RENAME_EXCHANGE)`); every
  record carries the inode the open returned, and both inodes were opened;
- the in-kernel write counter emits one record at the 20th write-open of
  the window, none before or after;
- exec of `/usr/bin/true`, of a copy in `/dev/shm`, of a deleted file and
  of a memfd, the memfd both through `/proc/<pid>/fd` and through
  `execveat(fd, "", AT_EMPTY_PATH)` (what glibc's `fexecve` does; today's
  `sys_enter_execve` sensor does not see that call). The record carries
  the kernel's filename (`/dev/fd/<n>` for `execveat`), the `(dev, ino)`,
  `i_nlink` (0 for the deleted file and the memfd), `i_mode`, and the
  superblock magic (tmpfs for `/dev/shm` and the memfd);
- a DNS query over IPv4 and over IPv6: the bytes read from the socket
  buffer are the query sent, byte for byte.

Notes for the next steps:

- The verifier budget is not a constraint: the whole `file_open` observer
  (parent lookup, name table, 8-level ancestor walk, LRU counter, 16-slot
  path walk) is about 11 000 verified instructions on 6.8, against the
  1 000 000 limit (about 67 000 on 6.1, whose verifier walks more states
  for the same program), and it loads on 5.15.
- `fexit` on the two `*_make_skb` functions loads everywhere but attaches
  only from 6.5, as x86-64 trampolines took at most 6 arguments before
  that; the `kretprobe` reads the same return value on every kernel (Q5).
- `udp_send_skb` and `udp_v6_send_skb` attached by their plain names on
  every lab kernel; the runner also tries the compiler's renamed copies
  (`.isra.0`, `.constprop.0`) from `/proc/kallsyms`, and did not need them.
- Paths are mount-relative, as Q3 accepted: the `/dev/shm` copy is recorded
  as `/nn-feasibility-true` and the memfd as `/memfd:nn-feasibility`.
- On btrfs the kernel side reads the superblock's device number, while
  `stat()` gives each subvolume its own (lab: `0x2c` in the record, `0x2e`
  from `stat()` on the top level, `0x2f` in a subvolume). No inode-keyed
  table can match there: not these probes' `PROBE_DIRS`, and not the
  production `WATCHED_PATHS`, `PROTECTED_INODES` and `OWN_EXE_INODES`
  either (review 55). Fixed right after step 0 (lab PR 48): the kernel
  side now reports the device `stat()` reports, and step 1 builds on it.

### 9.1 Cost per open (sizing for step 1)

`NN_FEASIBILITY_BENCH=500000 nn-lab.sh sensor-feasibility` measures open +
close of an unwatched file five levels below the root. The run was on
Ubuntu 24.04 (6.8, 4 vCPU, nested virtualisation), agent stopped, median of
five rounds. Times are added per open, against no program:

| what runs on `file_open` | read-only | write |
|---|---|---|
| nothing | 327 k/s | 310 k/s |
| an LSM program that returns at once | +147 ns (−4.6 %) | +139 ns (−4.1 %) |
| the open's inode key + one lookup (what today's FIM observer does) | +427 ns (−12.3 %) | +451 ns (−12.3 %) |
| the same + the parent directory's key + a cache lookup | +875 ns (−22.2 %) | +847 ns (−20.8 %) |
| the full step 0 observer (name reads, 5-level ancestor walk) | +1 587 ns (−34.2 %) | +1 596 ns (−33.1 %) |

What this means for step 1:

- **The full observer cannot run on every open.** Name reads plus the
  ancestor walk cost about as much as today's sensor (open −37 %,
  write-open −47 % in the one-round benchmark of lab PR 37). Directory
  classification must therefore be cached: computed once per directory,
  with the parent's key mapped to class bits in an LRU map, and
  invalidated by a generation counter that directory renames bump. A
  regular open then pays two inode keys and two lookups.
- **Kernel reads dominate the cost.** One `bpf_probe_read_kernel` costs
  about 70 ns here. Step 1 therefore puts the new checks into the FIM
  `file_open` observer, so there is one program and the open's key is
  computed once. Where the layout allows, it reads adjacent fields in a
  single call.
- **The < 5 % gate cannot be met here.** An empty program already costs
  4.6 %, so Q7 asks for a restated gate.

## 10. Step 1 — file opens: implementation design

§9.1 fixes the shape: one program, and per-directory work cached, because
every kernel read costs about 70 ns on the lab.

### 10.1 One program, two modes

The FIM `file_open` observer (`fim_file_open_observe`) already computes the
open's inode key and looks it up in `WATCHED_PATHS`. The sensor runs in
the same program, after that lookup: `fim_file_open_sensor` is that
observer plus the sensor, and userland attaches it in its place. If a
kernel's verifier refuses it, the plain observer is attached and
`sys_enter_openat` stays, so FIM never depends on the sensor. When
userland arms `OPEN_SENSOR` (LSM mode, the default), `sys_enter_openat`
is detached. With `--file-open-sensor tracepoint` (or
`NN_FILE_OPEN_SENSOR=tracepoint` in the unit's environment), the old
tracepoint is attached as before and the new checks stay off. This is
Q6's switch, kept for one soak cycle.

### 10.2 What makes an open interesting

| class | rule source | which opens |
|---|---|---|
| sensitive file | `SENSITIVE_FILES` (`/etc/shadow`, …), by inode | any |
| critical / persistence file | the file entries of `CRITICAL_FILES_PREFIXES` / `PERSISTENCE_PREFIXES` (`/etc/crontab`, `/root/.bashrc`, …), by inode | write |
| critical / persistence tree | their directory entries (`/etc/pam.d/`, `/etc/systemd/system/`, `/root/.ssh/`, …), subtree | write |
| telemetry probe | `/run/northnarrow/probe` (direct children) | any |
| credential store (Q1, review 54) | names: `.aws/{credentials,config}`, `.docker/config.json`, `gcloud/{credentials.db,access_tokens.db,application_default_credentials.json}`, trees under `.azure`, `.gnupg`, `.password-store`, `gcloud/legacy_credentials`; in home trees also `Login Data`, `logins.json`, `key4.db`, `key3.db`, `signons.sqlite`, `*.kdbx` | any |
| mass write (Q2) | per-tgid counter, 20 write-opens in 60 s | write |

Rules come in three kinds, all keyed the way §4.1 and review 55 require
(`(dev, ino)` as `stat()` reports it):

- `OPEN_RULES[inode]`: a file's own class, or a directory's class bits
  for its children or its whole subtree.
- `CHILD_RULES[(parent inode, name)]`: the same, for a path that does not
  exist yet when userland registers the rules (`/root/.ssh`, `/root/.bashrc`
  on a fresh host). A directory created later is classified by name under
  its registered parent.
- `NAME_RULES[name]` (and `(name, parent name)`): the credential names,
  which need no registration per home.

Home trees are the registered home roots: `/root` and the home of every
`/etc/passwd` account with a uid of 1000 or more.

The posture's lists are path prefixes (`filename.starts_with(entry)`),
while the kernel classifies by inode and directory. An entry that ends
in `/` or names an existing directory is therefore a tree. Any other
entry is that one file, so the lists spell out the directories a name
prefix used to cover: `/etc/ssh/sshd_config` also matched sshd's
drop-ins, and `/etc/ssh/sshd_config.d/` is now listed. The mass-write
carve-outs have no file entries, so each one is a tree, with or without
the final `/`. An entry the kernel cannot express (a carve-out naming a
file, a file two missing levels down) is logged at start as skipped.

### 10.3 Directory classification, cached

`DIR_CLASS` is an LRU map, keyed by the parent directory's inode key, that
holds `{class bits, owner uid, generation}`. An open does the following:

1. reads its parent key and looks it up;
2. on a hit with the current generation, uses the cached bits;
3. otherwise walks at most 8 ancestors, combining `OPEN_RULES` subtree
   bits, `CHILD_RULES` and the credential tree names, and caches the
   result.

The leaf name is read only when the bits say leaves matter: a
credential-name parent, or a home tree for the browser and KeePass names.
The generation (`DIR_CLASS_GEN[0]`) is bumped on every directory rename
(the FIM rename observer already runs there) and by userland when the
rules change. `rmdir` removes only the entry of the directory it deletes,
whose inode number a new directory may reuse: a directory being removed
is empty, so no other entry depends on it, and an `rm -rf` of a large
tree does not empty the cache once per directory. A stale entry is
therefore never used, at the price of re-walks after a rename. One case
is left to the LRU: a filesystem mounted after another was unmounted can
reuse its device number (anonymous devices are reused lowest first), and
its directories then hit the old entries until they age out. The bits
such an entry can carry come from name rules only, since every inode
rule is a host path registered by userland; bumping the generation on
every mount change would re-walk the whole cache at each container
start.

Mass-write carve-outs are part of the class:

- filesystems by superblock magic: sysfs, procfs, cgroup and cgroup2,
  bpffs, debugfs, tracefs, securityfs, configfs, pstore and efivarfs (the
  old `/sys/` and `/proc/` prefixes);
- the `/run/systemd` and `/run/log/journal` subtrees, and the operator's
  `mass-write-carveout.local` entries;
- the writer's own runtime directory. Each `/run/user/<uid>` mount root is
  registered with its uid (re-read with the rules every 60 s) and
  compared with the writer's `loginuid`.

### 10.4 Records and events

An interesting open emits one record. It carries:

- pid, uid and comm;
- `f_flags` and `f_mode`;
- the `(dev, ino)` key and the class bits;
- the mount root's key (the top of the walk);
- the 16 × 32-byte mount-relative path.

Userland maps the mount root key to a mount point: it stats every mount
point listed in `/proc/self/mountinfo`, again on a miss and when the
mount table changes. From that it rebuilds the absolute path, so every
consumer keeps `Event::FileOpen { filename, flags, … }` as it is today.

Credential-class opens are also given to the FIM rules as
`FimEvent { op: Opened, path, wide_coverage: true }`, so NN-L-FIM-011..017
now fire for every home. They report without acting (Q8).

A mass-write crossing becomes `Event::MassWrite { pid, uid, comm, count,
path }`. The posture's mass-write arm reads that event (lineage gates
unchanged) instead of counting `FileOpen` events.

### 10.5 Verification

The gates of §7 apply, with Q7 for the overhead. On every guest, the lab
adds:

- the rename race of §9 against the production program;
- an `io_uring` open of a credential file;
- a non-owner reading `/home/<user>/.aws/credentials`;
- `daemon-reload` and an install burst with zero ring drops;
- the telemetry probe and `tamper-check` unchanged.

### 10.6 Implementation status

Implemented in lab PR 52:

- **Kernel** (`agent-ebpf/src/open_sensor.rs`). `observe()` runs inside
  `fim_file_open_sensor` and is armed by userland. Directory renames
  invalidate the cache; `open_sensor_rmdir` drops the removed directory's
  entry. The ancestor walk of a cache miss is a global BPF function
  (`nn_open_walk`), which the verifier checks once on its own. Inlined,
  it took the program past the 5.15 verifier's million-instruction
  budget (KERNEL_COMPATIBILITY, 5.15 rule 6). `struct file` and the
  inode are read in two bulk windows. If a window cannot be read, the
  open still reaches FIM through the plain observer's field reads, and
  only the sensor skips it.
- **Userland** (`agent/src/sensors/open_sensor.rs`): the rule builder, the
  mount table, record decoding and a rule refresh every 60 s.
- **Events.** `Event::MassWrite` is new. In LSM mode the posture's
  mass-write arm reads it, and the userland count is off.
- **New offset slots.** `inode.i_mode`, and `task_struct.loginuid`
  (optional).
- **Switch.** `--file-open-sensor lsm|tracepoint` or
  `NN_FILE_OPEN_SENSOR`. The agent stays on `sys_enter_openat` whenever the
  FIM observer, the maps or the ring are unavailable. When it arms, it
  retires the tracepoint's link in the BPF self-check before unloading it.

`deploy/lab/nn-lab.sh open-sensor-check` covers end to end:

- the sensor is armed and the tracepoint retired without a missing-link
  report;
- `~/.aws/credentials` of a user in `/home` gets NN-L-FIM-011 (Log), also
  when opened through `io_uring`;
- 25 write-opens give exactly one `MassWrite`;
- a write under `/etc/cron.d` raises `PersistenceMechanism`;
- a write under `/etc/ssh/sshd_config.d` raises
  `CriticalFileModification`;
- a write-open of `/etc/crontab` through a symlink with an innocuous
  name raises `CriticalFileModification`. This is §7's "Phantom" gate in
  deterministic form: the record names the file the kernel opened, while
  `sys_enter_openat` read only the caller's string, and in tracepoint
  mode the same case fails;
- the telemetry probe never goes silent.

The §7 gates, on Ubuntu 24.04 (6.8), Ubuntu 22.04 (5.15,
`lockdown=integrity`) and Debian 12 (6.1):

- all nine checks pass, and `tamper-check` is OK;
- `pkgmgr-check` and the e2e suites (agent, FIM, watchdog) pass;
- `ringbuf_drops_total` stays 0 across five `daemon-reload`s and a
  package reinstall burst;
- on 6.8, `pkg-check` and `release-check` (the CI tarball of this
  change) also pass.

AlmaLinux 9 (5.14) follows its soak. With the sensor refused (as on 5.15 before
`nn_open_walk`), the same check shows the fallback: the plain observer
and `sys_enter_openat`, with the cron and sshd cases still passing, and
`tamper-check` still OK.

#### Measured

`nn-lab.sh overhead 3` in each mode, on Ubuntu 24.04 (6.8, 4 vCPU, nested
virtualisation) and the same guest. The AlmaLinux 9 soak ran on the same
host, so the table compares the two modes. It does not replace the
official figures of §7.

| workload | tracepoint mode (before) | LSM mode (step 1) |
|---|---|---|
| open | −31.9 %, agent CPU 1,290 ms | −28.2 %, agent CPU 0 ms |
| write-open | −31.0 %, 400 ms | −30.3 %, 0 ms |
| exec | −11.0 % | −8.7 % |
| connect | −34.3 % | −35.4 % |

Per operation, from the kernel's BPF statistics (`bpftool prog show`
with `kernel.bpf_stats_enabled=1`, which itself adds a few ns per
program):

| program (hook) | open, LSM | open, tracepoint | write-open, LSM | write-open, tracepoint |
|---|---|---|---|---|
| FIM observer, with the sensor in LSM mode (`file_open`) | 517 ns | 294 ns | 661 ns | 308 ns |
| `sys_enter_openat` | — | 342 ns | — | 199 ns |
| FIM close emit (`file_free_security`) | 288 ns | 291 ns | 302 ns | 298 ns |
| anti-tamper open deny (`file_open`) | 100 ns | 102 ns | 319 ns | 318 ns |
| FIM write intent (`file_permission`) | 66 ns | 92 ns | 291 ns | 331 ns |

What the numbers say:

- **Read-only open.** The sensor adds 223 ns to the FIM observer. It
  removes the tracepoint (342 ns) and the agent's work per open: 1.29 s
  of CPU per 200,000 opens, about 6.4 µs each on another core.
- **Write-open.** The sensor adds 353 ns, most of it the per-process
  count, and removes 199 ns plus about 8 µs of agent CPU. The lookup of
  the agent's own pids runs only when an open would emit.
- **The rest of the loss** comes from hooks that step 1 does not touch,
  plus about 100 ns of dispatch per attached LSM program (§9.1). These
  are FIM's close and write-intent hooks (review 59) and the anti-tamper
  open hook.

Q7's proposed gate, halving the open loss, is therefore not met by step 1
alone. The open loss falls by 3.7 points, and the agent's CPU per open
goes to almost zero.

## 11. Step 2 — exec: implementation design

Step 0 loaded `bprm_check_security` and read `linux_binprm` on all four
kernels (§9, 7.4k instructions). This section is the implementation plan.

### 11.1 What the code survey found (review 61)

- **The exec rules match the caller's string.** `ProcessSpawn.filename`
  is `bprm->filename`: the kernel's copy of the string the caller passed.
  It is free of races, but not resolved. The kill rules match prefixes on
  it: R001 `/tmp/`, R002 `/dev/shm/`, R003 `/var/tmp/`, R009, R010; also
  R008, CHAIN-002's precursor, posture's `/tmp` and `/dev/shm` arm, and
  R013's and R017's exemptions. Process canaries and the auth-lineage
  tracker compare the exact string. So `cd /tmp && ./payload`, a symlink,
  `..`, `//` or `execveat` with a directory fd escape all of them. In the
  lab (Debian 12), `/tmp/x` is killed by R001; `cd /tmp && ./x` runs with
  no detection at all.
- **`ExecCheck` is weak and little used.** `sys_enter_execve` reads the
  filename from user memory, fires on failed attempts (`execvp` walking
  `PATH`) and never for `execveat`/`fexecve`, and leaves `ppid` 0. No rule
  reads it; posture's `/tmp`/`/dev/shm` arm reads it as well as
  `ProcessSpawn` (it fires twice), and ADE takes it as a focal event.
- **Out of reach of this step:** the `comm` rules (R005–R007, R011,
  R012, R014–R016, posture's recon and lolbas). `comm` is the basename of
  the name invoked, and a renamed copy evades them; that is the 10.9
  "exec by inode property" item.

### 11.2 One LSM program, the file the kernel opened

`exec_check_lsm` on `bprm_check_security`, observe only (it returns 0;
Q4 leaves the deny to the inline-enforcement item). The hook runs once
per binfmt pass, before the point of no return: for a `#!` script once
for the script, then for the interpreter (`bprm->file` and `bprm->interp`
change, `bprm->filename` does not). Pass 0 is the one where
`bprm->interp == bprm->filename`. For each pass it reads `bprm->file`:

- `(dev, ino)` as `stat()` reports it (review 55);
- the superblock magic (tmpfs and hugetlbfs: `TMPFS`), a `memfd:` dentry
  name (`MEMFD`) and `i_nlink == 0` (`DELETED`: an unlinked file or an
  `O_TMPFILE`);
- the mount-relative path from the dentry, with the mount root's key
  (§10.4). The walk is a global BPF function (`nn_exe_walk`, verified on
  its own: KERNEL_COMPATIBILITY rule 6) that goes up to 64 levels. It
  keeps the 12 names nearest the file and the last 4 below the root, so
  a deep path still shows its top (`/tmp/a/b/…/x`). Past 64 levels the
  root is not reached and the record says so (`UNRESOLVED`).

It emits one `ExecCheck` per pass (kernel data now: the canonical path,
the inode facts, the pass number, `ppid` from the task). At pass 0 it
also leaves the same facts in `EXEC_HANDOFF[task]`. `sched_process_exec`
runs in the same task once the exec has succeeded. It appends them to
`ProcessSpawnRaw` and deletes the entry. A failed exec leaves an entry
that the task's next exec overwrites at its own pass 0.

### 11.3 Rules read the canonical path

`Event::ProcessSpawn` and `Event::ExecCheck` gain `exe`: the absolute
path (the mount table maps the root key to a mount point, as for file
opens), `(dev, ino)` and the flags. `exe.path_or(filename)` gives the
canonical path, or the caller's string when there is none (tracepoint
mode, `UNRESOLVED`). The prefix and exact-path consumers use it: R001,
R002, R003, R008, R009, R010, R013's and R017's exemptions, CHAIN-002's
precursor, posture's arm (now on `ProcessSpawn` only), the auth-lineage
tracker, process canaries (either string), and the verdict's
`event_filename`.

R004 keeps its string patterns (an exec through `/proc/self/fd/N` or
`/dev/fd/N`) and also fires on `MEMFD`, so a symlink to the fd no longer
hides a memfd. `DELETED` alone does not kill: a binary replaced by an
upgrade and re-executed through `/proc/self/exe` is deleted too. It is
recorded for the inode-property item.

### 11.4 Switch, attach, sizes

- `--exec-sensor lsm|tracepoint` (`NN_EXEC_SENSOR`), default `lsm`, for
  one soak cycle (Q6). In LSM mode `sys_enter_execve` is not attached;
  in tracepoint mode the LSM program is not attached and `exe` stays
  empty. The program is attached inside the multiplexer, so the BPF link
  self-check covers it.
- New offsets (optional slots; if one is missing the agent stays on the
  tracepoint): `linux_binprm.file`, `.filename`, `.interp`,
  `inode.i_nlink`.
- `ExeIdentityRaw` is 552 bytes. It goes into `ExecCheckRaw` (296 → 848
  bytes) and is appended to `ProcessSpawnRaw` (840 → 1,392). The exec
  ring grows from 256 KiB to 1 MiB, so it holds about 750 records instead
  of 309.
- The cost is one walk per pass, about 3 µs on the lab for an ordinary
  depth, against roughly 800 µs for an exec.

### 11.5 Verification

`nn-lab.sh exec-sensor-check` runs these cases:

- the program is armed, and `sys_enter_execve` is retired without a
  missing-link report;
- `cd /tmp && ./x` is killed by R001; on main it is not;
- `x` run through a symlink in a root-owned directory is killed by R001;
- `/usr/bin/../../tmp/x` is killed by R001;
- a script in `/tmp` run as `./x.sh` is killed by R001 on the script;
- a memfd run through `execveat(AT_EMPTY_PATH)` is killed by R004;
- `/usr/bin/sleep` is not killed;
- the telemetry probe never goes silent.

The gates of §7 apply on the three lab kernels, plus the exec workload of
`nn-lab.sh overhead` in both modes.

### 11.6 Implementation status

Implemented in lab PR 53:

- **Kernel**, `agent-ebpf/src/exec_lsm.rs`:
  - `exec_check_lsm` on `bprm_check_security`;
  - `nn_exe_walk`, a global function, for the dentry walk;
  - `EXEC_HANDOFF`, an LRU of 1,024 entries keyed by task, for the
    post-exec record.
- **`sched_process_exec`** appends the handed-over identity to
  `ProcessSpawnRaw`. Its ring grows to 1 MiB.
- **Wire**, `common/src/wire/exe.rs`: `ExeIdentityRaw` and the path
  rebuild. `ExeIdentity` (`model.rs`) carries `path_or`.
- **Userland**, `agent/src/sensors/exe_identity.rs`:
  - the switch and the attach, with a fallback to `sys_enter_execve`;
  - mount-table resolution before any consumer reads the event.
- **Consumers.** The exec rules, CHAIN-002, posture, the lineage tracker,
  process canaries, ADE (prompt and sanitising) and the detection store's
  `exe` all use the file the kernel executed.
- **New offset slots** (optional): `linux_binprm.file`, `.filename` and
  `.interp`, `inode.i_nlink`, `task_struct.fs`, `fs_struct.root`.

Found on the way: review 61 (above) and, from the gate runs, reviews 62
and 63 (a restarted agent lost the kill/ptrace evidence and filled
`PROTECTED_INODES`; fixed separately in lab PR 54).

## 12. Step 3 — DNS: implementation design

Step 0 read the query from the socket buffer on the three lab kernels it
ran on, at both candidate attach points (§9). This section is the
implementation plan. It revises Q5: the return probe Q5 proposed cannot
tell a DNS query from any other datagram (§12.1).

### 12.1 What the code survey found (reviews 66, 67)

- **The name is read from user memory before the kernel copies it**
  (`agent-ebpf/src/dns_query.rs`, kprobe at `udp_sendmsg` entry). Besides
  the race of §1, this has three effects:
  - a payload in a page the process has not touched yet (a file it has
    just mapped) cannot be read from BPF, which may not fault. The record
    has an empty name and NET-004/-005/-014 see nothing. The kernel's own
    copy faults the page in, and the query leaves intact;
  - the read stops at the first zero byte (`bpf_probe_read_user_str`). A
    label may contain one, and the name is cut there;
  - a query sent in two pieces (`MSG_MORE` or `UDP_CORK`) is read once per
    `sendmsg`: a header with no name, then a name read 12 bytes too far.
- **No IPv6.** `udpv6_sendmsg` is not attached, so a query to an IPv6
  resolver gives no record at all (§3.3). An IPv4-mapped destination is not
  affected: `udpv6_sendmsg` hands it to `udp_sendmsg`.
- **Q5's return probe has no port to filter on.** When `ip_make_skb`
  returns, the UDP header is still blank: `udp_send_skb` writes it
  afterwards, from the flow (`fl4->fl4_dport`). The return probe no longer
  has the flow argument, so it would need a second program at the
  function's entry to keep it per task. Two more limits:
  - corked sends never call `ip_make_skb`; `udp_push_pending_frames`
    builds the buffer with `ip_finish_skb`;
  - a return probe has a fixed pool of instances (`maxactive`: 10 on a
    4-CPU host when created through perf), and a call that finds the pool
    empty is not seen.
- **The N2 UDP flow sensor has the same IPv6 gap** (`udp_sendmsg_outbound`
  is attached to `udp_sendmsg` only). It is outside this step: review 68,
  fixed separately in lab PR 58.

### 12.2 One kprobe per family, where the buffer is sent

`udp_send_skb(skb, fl4, cork)` and `udp_v6_send_skb(skb, fl6, cork)` are
where both send paths meet: the uncorked one right after
`ip_make_skb` / `ip6_make_skb`, the corked one after `ip_finish_skb` /
`ip6_finish_skb`. At their entry:

- the flow argument holds the destination the datagram will use, after any
  `cgroup/sendmsg` BPF rewrite: `fl4->daddr` and `fl4->uli.ports.dport`,
  or the same fields of `fl6`. A port other than 53 returns at once, after
  one read per datagram;
- the buffer holds the kernel's copy of the payload, which starts 8 bytes
  after `skb->head + skb->transport_header`. The UDP header in between is
  still blank, since this function fills it. The linear data ends at
  `skb->head + skb->tail`.

`dns_udp_send_skb` and `dns_udp_v6_send_skb` share one body. It copies
up to 288 bytes from the start of the name (12 bytes into the payload, after
the DNS header), in 32-byte reads that stop at the end of the linear data.
That is enough for the longest legal name (255 bytes) and the type and
class after it. Userland then walks the labels with the `QnameLabels`
iterator that Kani checks, and reads the type after the root label. A zero
byte inside a label no longer cuts the name.

A name that does not end within the linear data is marked partial. Either
the rest is in page fragments (a corked send, UDP GSO, zero copy), or the
datagram is not a DNS query. Resolvers send a query in one piece. NET-004
records a partial name (Log, High) for one soak cycle, without killing.
Reading the fragments would need a page's address from BPF; it is left out.

Both functions are `static`, so a compiler may inline or rename them. On
the lab kernels both attach by their plain name (§9). Only the plain name
is attached, because a renamed copy (`.isra.0`, `.constprop.0`) may take
different arguments. If the IPv4 function cannot be attached, the agent
falls back to the `udp_sendmsg` program. If only the IPv6 one cannot,
IPv4 stays on the socket buffer and the log says IPv6 queries are not seen.

### 12.3 Records and events

- `DnsQueryRaw` keeps its fields. `query_name` grows from 253 to 288 bytes,
  so the record grows from 312 to 344 bytes and the 256 KiB ring holds
  about 760 records instead of 840.
- The pad byte after `family` becomes `flags`:
  - `SKB`: read from the socket buffer; `query_name` holds wire bytes;
  - `NONLINEAR`: `skb->data_len != 0`.
- `Event::DnsQuery` gains `qname_partial` (`#[serde(default)]`).
- In `sendmsg` mode the record is the one of today: a string read, IPv4
  only.

### 12.4 Switch, attach, sizes

- `--dns-sensor skb|sendmsg` (`NN_DNS_SENSOR`), default `skb`, for one
  soak cycle (Q6). The programs are attached inside the multiplexer, so
  the BPF link self-check covers them.
- New offsets (optional slots): `sk_buff.head`, `.tail`,
  `.transport_header`, `.data_len`; `flowi4.daddr`, `.uli`; `flowi6.daddr`,
  `.uli`. If one is missing, the agent stays on `udp_sendmsg`.
- `udp_sendmsg_outbound` (N2 flows) is unchanged.
- The cost is one kprobe hit and one read per UDP datagram. A DNS query
  adds about ten reads. Measured on 6.8 (§12.6): 176 ns per UDP datagram
  against 256 ns for the `udp_sendmsg` program, and 919 ns per DNS query
  against 904 ns.

### 12.5 Verification

`nn-lab.sh dns-sensor-check` sends queries for a name NET-004 kills on: a
first label of 40 base64 characters. It runs these cases:

- the programs are armed, and `udp_sendmsg` is retired without a
  missing-link report;
- connected `send()` to `127.0.0.1:53`: killed by NET-004;
- unconnected `sendto()`: killed;
- the same query to `[::1]:53`: killed; on main there is no record;
- the payload in a page not faulted in yet: killed; on main the name is
  empty;
- a zero byte inside the first label: killed with the whole name; on main
  the name is cut;
- the query sent in two pieces (`MSG_MORE`): a NET-004 record for a
  partial name;
- `getent hosts` through the system resolver: no NET record;
- the telemetry probe never goes silent.

The §7 gate "a query whose payload changes after `sendmsg` entry" is
covered by the page that is not faulted in. Both are a read of user memory
at a different time from the kernel's copy, but the page case gives the
same result on every run, while a second thread rewriting the buffer is a
race the reproducer may lose. With `--dns-sensor sendmsg` the IPv6,
page and zero-byte cases are expected to fail. The gates of §7 apply on the
three lab kernels.

### 12.6 Implementation status

Implemented in lab PR 57:

- **Kernel**, `agent-ebpf/src/dns_skb.rs`: `dns_udp_send_skb` and
  `dns_udp_v6_send_skb`, one body; the record goes to the existing DNS
  ring.
- **Wire**: `DnsQueryRaw.flags` (`SKB`, `NONLINEAR`) and a 288-byte
  `query_name`.
- **Model**: `qname_wire_end` (with a Kani proof) and `qname_partial`.
- **Userland**, `agent/src/sensors/dns_sensor.rs`: the switch and the
  attach, with the fallbacks of §12.2.
- **NET-004**: the partial-name verdict.
- **New offset slots** (optional): `sk_buff.head`, `.tail`,
  `.transport_header` and `.data_len`; `flowi4.daddr` and `.uli`;
  `flowi6.daddr` and `.uli`.
- **Lab**: `nn-lab.sh dns-sensor-check`, and the `udp` and `dns`
  workloads of `nn-bench`.

#### Measured

The programs load and attach on 5.15, 6.1 and 6.8. `dns-sensor-check`
gives 10/10 on all three. With `--dns-sensor sendmsg`, the four cases the
old sensor misses (IPv6, the unfaulted page, the zero byte, the query in
two pieces) go undetected on all three. Per case, on Ubuntu 24.04 (6.8):

| | `skb` (default) | `sendmsg` (the old sensor) |
|---|---|---|
| armed, no missing-link report | yes | — |
| connected `send()`, unconnected `sendto()` to `127.0.0.1:53` | killed | killed |
| `[::1]:53` | killed | **no record** |
| payload in a page not faulted in yet | killed | **no record** (empty name) |
| a zero byte inside the first label | killed | **no record** (name cut) |
| a query in two pieces (`MSG_MORE`) | NET-004 Log, partial name | no record |
| `getent hosts` | no NET record | no NET record |

BPF cost (`kernel.bpf_stats_enabled`, ns per run, 6.8):

| | `skb` | `sendmsg` |
|---|---|---|
| a UDP datagram to another port (`nn-bench udp`) | 176 | 256 |
| a DNS query (`nn-bench dns`) | 919 | 904 |

The N2 flow program on `udp_sendmsg` costs 350–525 ns per datagram in
both modes; it is unchanged.

