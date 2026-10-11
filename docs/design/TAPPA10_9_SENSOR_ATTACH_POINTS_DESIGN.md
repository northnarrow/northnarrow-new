# Tappa 10.9 — Sensor attach points (file open, exec, DNS) Design

**Status:** RFC — proposal for owner review. Nothing implemented. §8 lists
the decisions the owner is asked to take before the first commit.
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
the user `iov`: `fexit` on `ip_make_skb` and `ip6_make_skb` (global
functions; the returned skb holds the copied payload, in the sending task's
context), or `kprobe` on `udp_send_skb` / `udp_v6_send_skb` where those
static functions are not inlined. The QNAME walk then runs on kernel memory
(`bpf_probe_read_kernel`), and the `iov_iter` enum handling disappears.
IPv6 resolvers are covered by the same change.

New slots: `sk_buff.data`, `sk_buff.len`, and the transport-header offset.

## 5. Facts noted while writing this

- Comments in `posture/triggers.rs` (around line 536) and
  `posture/lineage.rs` say the open events come from "the LSM file_open
  hook"; they come from the tracepoint.
- The exec ring's comment promises "~880 events"; at 840-byte records the
  256 KiB ring holds about 309.
- DNS over IPv6 is not captured (§3.3) — a coverage gap independent of
  this design, fixed by §4.3.
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
included). Nothing changes in the agent until this passes.

Then one PR per sensor, in this order: file opens (largest gain), exec,
DNS. Each keeps the old program behind a configuration switch for one
soak cycle, then deletes it. Gates for every PR, on all four guests:
`tamper-check`, `pkgmgr-check`, `pkg-check`, `release-check`, the e2e
suites, the telemetry probe, plus:

| Gate | Target |
|---|---|
| `nn-lab.sh overhead` (3 rounds, idle host) | open and write-open throughput loss < 5 % |
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
  `udp_send_skb` / `udp_v6_send_skb`.
- **Q6 — Transition.** Old programs kept behind a switch for one soak
  cycle and then deleted (proposed), or a direct switch.
