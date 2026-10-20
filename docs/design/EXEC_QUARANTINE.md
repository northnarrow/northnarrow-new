# Exec quarantine at first sight (EXPERIMENTAL, lab PR 223)

Capabilities C13 (malware prevention) and C12 (synchronous inline blocking),
Wave 4. Off by default (`--exec-quarantine off`). Code: `agent-ebpf/src/execq.rs`
(kernel), `agent/src/execq/` (controller), `scan/` (the `northnarrow-scan`
scanner), wire `common/src/wire/execq.rs`, protocol `common/src/execq.rs`.

## 1. What it does

An executable never judged on this host, run from a guarded location, is
neither denied blindly nor let run: the kernel holds the new image before its
first instruction, the agent has it scanned by a confined process and waits
for the rule engine's verdict on the same exec, then resumes it or kills it
and quarantines the file. Without a decision within a bounded budget (2 s by
default) the configured default policy applies — resume and alert in this
lot — and the decision is signed like every other.

| mode | `--exec-quarantine` | the kernel | the agent |
|---|---|---|---|
| off (default) | `off` | writes no candidate, stops nothing | — |
| observe | `observe` (and every detect-only agent) | reports candidates, stops nothing | scans them while they run; the record says what it would have done |
| enforce | `enforce` | stops candidates before their first instruction | decides, resumes or kills, records |

## 2. The kernel half

**Classification** (`note_pass`, called by `exec_check_lsm` on LSM
`bprm_check_security` for each binfmt pass, after the dentry walk the exec
sensor already does). The file of the pass is a candidate when it is in a
guarded class (`wire::execq::class`) and its identity is not cached:

| class | test |
|---|---|
| `memfd` | the dentry name starts with `memfd:` |
| `deleted` | `i_nlink == 0` (unlinked, `O_TMPFILE`) |
| `tmpfs` | tmpfs, hugetlbfs or ramfs superblock (`/dev/shm`, `/run`, a tmpfs `/tmp`) |
| `world_writable_dir` | the parent directory's mode has `S_IWOTH` |
| `tmp` | the task's own view starts with `/tmp/` or `/var/tmp/` |
| `home` | the task's own view starts with `/home/` or `/root/` |
| `guarded_mount` | the walk ended on the root of a filesystem mounted at a guarded point (a separate `/home`, `/tmp`, `/var/tmp`, `/root`, `/dev/shm`, `/run/user/*`): `EXECQ_ROOTS`, refreshed by the agent every 10 s from `mountinfo` |

The path classes read the walk's top components, so a container's or a
chroot's `/tmp` is guarded in its own view. Package-managed binaries live
outside every class (`/usr`, `/opt`, `/snap`…): they are never stopped.

**Identity cache** (`EXECQ_KNOWN`, LRU, 16 384 entries, per agent run, not
pinned): `(dev, ino)` → `(ctime, size, verdict)`. A candidate whose inode is
cached under the same ctime and size skips the stop (counter `KNOWN_SKIP`),
whatever the verdict cached. The controller caches an identity only when
its ctime was read and stamped, the file is neither a memfd nor deleted,
and the decision was a resume (in observe mode, any decision); a kill is
never cached.
Any `write(2)`, truncation, `chmod`, `fallocate` or first write fault through
a shared mapping moves ctime. Offsets: `INODE_I_CTIME_SEC_OFFSET` /
`INODE_I_CTIME_NSEC_OFFSET` in the BTF table (`i_ctime` up to 6.5,
`__i_ctime` 6.6–6.10, `i_ctime_sec`/`i_ctime_nsec` from 6.11), optional:
without them nothing is cached and every exec of a guarded file is held.

**The stop** (`maybe_stop`, from the `sched_process_exec` tracepoint). That
tracepoint fires in the exec'ing task once the exec is past its point of no
return: the new `mm` is installed, `de_thread` has left one thread, nothing
can fail any more, and the task has not returned to user mode. There:

1. `bpf_send_signal(SIGSTOP)` targets the current task's thread group. A
   tracepoint program runs with interrupts enabled, so the helper calls
   `group_send_sig_info` at once (the irq_work path is for programs that run
   with interrupts off); the signal is pending when the program returns. It
   comes with `SEND_SIG_PRIV`: no permission check. The helper refuses
   kernel threads, exiting tasks and the global init (`-EPERM`): those are
   counted (`SIGNAL_FAILED`), not held.
2. On the way back to user mode the kernel delivers pending signals before
   any user instruction: the task stops (group stop) before the first
   instruction of the new image — the dynamic loader's entry for a dynamic
   binary, the entry point of a static one. No constructor, no loader code
   runs.
3. A `SIGCONT` that arrives before the task has processed the pending
   `SIGSTOP` removes it from the queue (`prepare_signal`): a fast resume is
   still a resume. A `SIGKILL` kills a stopped task.

Why not stop at `bprm_check_security`: the exec can still fail after that
hook (a later LSM, `ENOEXEC`, memory), and the stop would then hold the
caller's old image. The LSM hook only classifies; the candidate travels in
`EXECQ_CAND` (keyed by `task_struct`, cleared at every pass 0) to the
tracepoint.

**Fail-open by construction.** A stop needs the agent's heartbeat
(`EXECQ_ALIVE`, written every 250 ms) younger than 1.5 s, a free entry on
`EXECQ_EVENTS` (256 KiB), and the helper's success; otherwise the process
runs and the kernel counts why (`EXECQ_COUNTERS`; a full ring also in
`RING_DROPS[execq]`, a security ring). The agent's and the watchdog's own
processes (`PROTECTED_PIDS`) are never stopped. `EXECQ_CONF` (mode, classes,
heartbeat bound) is written once, `OFF` included, and frozen
(`BPF_MAP_FREEZE`): no process, root included, can switch the guard on or
change its classes behind the agent. The sensor programs belong to the
agent's process: when it dies they detach and nothing more is stopped. What
it had stopped is in `EXECQ_STOPPED`, pinned: the next agent resumes those
processes at boot (signed `exec_quarantine` entry, `recovered_at_boot`) —
when it runs the guard: the resume is the controller's, so an agent started
with `--exec-quarantine off`, or whose guard cannot start, leaves them
stopped (`kill -CONT` by hand).

## 3. The agent half (`agent/src/execq/`)

One dedicated thread (`nn-execq`), not a tokio task: a held process's budget
must run out even when the runtime is busy. It polls the ring, the scanner's
channel and an eventfd, with the nearest deadline as timeout.

For each candidate:

1. **The file.** `/proc/<pid>/exe` when its `(dev, ino)` is the candidate's
   (the image), else the candidate by its path (a `#!` script, or the image
   of a process already gone), opened `O_NOFOLLOW`, and kept only if it is
   the inode the kernel reported. A memfd or unlinked script has no path:
   default policy, recorded as not scannable.
2. **Package trust** (`pkgtrust.rs`): a file a package lists with this
   content is trusted — dpkg's `*.md5sums` (MD5 is the only digest dpkg
   keeps; trusting a file needs a second preimage of a package's file),
   rpm's recorded `FILEDIGESTS` through the system `rpm`. Paths no package
   uses (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`, `/run/user`) skip
   the lookup.
3. **The scan** (§4), with the file's descriptor.
4. **The rule engine.** Within the budget, the process is resumed only
   after the rule engine has judged the exec's `ProcessSpawn` (`SpawnLedger`,
   marked when `process_event` returns, after a kill the rules decided was
   carried out); a budget that expires first gets the default policy
   ("exec not yet judged by the rules").
   A rule kill — R001 on a `/tmp` binary, R005 on a netcat copy — lands on
   a held process: it never ran an instruction. This is the C12 property:
   the exec rules' kills become synchronous for held execs.
5. **The decision** (`policy.rs`):

| basis | action | identity cached | record |
|---|---|---|---|
| scanned clean | resume | yes | Low |
| allow list, package database | resume | yes | Low |
| content judged clean earlier (another path) | resume | yes | none (its first sight was recorded) |
| suspicious (heuristics) | `--exec-quarantine-on-suspicious` (resume) | if resumed | Medium resumed, High killed (and quarantined) |
| block list | kill + quarantine | no | Critical |
| budget expired, not scannable, scanner unavailable | `--exec-quarantine-on-expiry` (resume) | no | Medium |
| left stopped by an agent that died | resume | no | signed audit entry |

A held process whose scanner cannot be back before its budget runs out is
decided at once on the default policy, not after the budget. A verdict that
arrives after the default policy decided (up to 30 s) still acts: a late
block-list hit kills the running process and quarantines the file; a late
clean verdict is cached. A request unanswered past its budget means a hung
scanner: it is killed and restarted.

Stopping the agent resumes every held process and clears the heartbeat
(signed `exec_quarantine` entry, `stopping`).

## 4. The scanner (`northnarrow-scan`)

A separate binary the agent spawns and supervises (`scan/src/supervisor.rs`):

- **Account.** `northnarrow-scan`, a system user `install.sh` and the
  packages create (no home, no shell, its own group); refused if it is root
  or in group 0. The agent drops to it with `setgroups(0)`/`setgid`/`setuid`
  (`CAP_SETUID`, `CAP_SETGID` in the agent unit's bounding set) and sets
  `PR_SET_PDEATHSIG` after the drop. Empty environment, `/` as cwd, stdin
  and stdout `/dev/null`, stderr to the agent's journal.
- **Confinement** (`harden.rs`, `seccomp.rs`). Refuses to run as root;
  `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE` 0 (no core, no ptrace by its own
  user), every descriptor above its socket closed (`close_range`),
  `RLIMIT_NPROC` 0, `RLIMIT_NOFILE` 16, `RLIMIT_CORE` 0, `RLIMIT_AS` capped.
  Then, once its configuration is read, a seccomp filter that kills the
  process (`SECCOMP_RET_KILL_PROCESS`) on any system call outside: `read`,
  `pread64`, `lseek`, `fstat`, `close`, `recvmsg`, `sendmsg`, `brk`,
  `munmap`, `mremap`, `madvise`, `futex`, `sched_yield`, `clock_gettime`,
  `getrandom`, `rt_sigreturn`, `rt_sigprocmask`, `sigaltstack`,
  `restart_syscall`, `getpid`, `gettid`, `exit`, `exit_group`; `mmap` and
  `mprotect` without `PROT_EXEC`; `write` to fd 2 only; `fcntl(F_GETFD)`
  only; `tgkill` to itself only; another architecture's numbers (x32) never.
  No `open*`, no `exec*`, no `socket`/`connect`, no `clone`, no `ptrace`, no
  `bpf`: no filesystem access but the descriptors it is handed, no network.
  Hand-written classic BPF (no libseccomp: no C in production). Tested by
  forking children under the filter (`scan/src/seccomp.rs` tests).
- **Channel** (`ipc.rs`). A `SOCK_SEQPACKET` socket pair on descriptor 3,
  one postcard message per packet (≤ 64 KiB), at most one descriptor per
  packet (`SCM_RIGHTS`, received `MSG_CMSG_CLOEXEC`, extras closed,
  truncation refused). The configuration (`ScanConfig`: the hash lists, the
  threshold, the read limits) comes in a memfd sealed against any change.
  The scanner answers `Ready` only with its filter in place and its uid
  reported; the supervisor checks both.
- **Supervision.** A scanner that exits, is killed, breaks the protocol or
  does not say ready within 5 s is restarted: at once, then after 1, 2, 4…
  30 s. A loss is a signed `subsystem_degraded` naming the exit status and
  what waits for it; the same cause again within 10 minutes is held back and
  counted into the next record of it (another cause is recorded at once).

**The engine** (`engine.rs`): SHA-256 of the whole file (up to 1 GiB, else
`unscanned`), the signed block list (→ malicious) and allow list (→
trusted), then explainable heuristics on the first 64 MiB (`heuristics.rs`,
a bounded hand-written ELF reader in `elf.rs`). Each finding is a stable code
with a weight; the file is suspicious when the weights reach 3:

| code | weight | what |
|---|---|---|
| `elf.upx_marker` | 3 | UPX's `UPX!` header or banner |
| `elf.unusual_interpreter` | 3 | `PT_INTERP` outside the system library directories |
| `script.unusual_interpreter` | 3 | a `#!` interpreter outside the system directories (or relative) |
| `elf.packed_no_sections` | 2 | no section table, an executable segment of entropy ≥ 7.2 |
| `elf.high_entropy_code` | 2 | an executable section of entropy ≥ 7.2 |
| `elf.rwx_segment` | 2 | a `PT_LOAD` segment readable, writable and executable |
| `elf.entry_outside_code` | 2 | the entry point in no executable segment |
| `elf.needed_without_interpreter` | 2 | `DT_NEEDED` libraries and no `PT_INTERP` |
| `elf.malformed` | 2 | header tables past the end of the file |
| `elf.suspicious_imports` | 2 (≤ 256 KiB), 1 | `ptrace`, `memfd_create`, `process_vm_writev`, `fexecve`, `execveat`, `init_module`, `setns`, `unshare`, `bpf`… |
| `elf.static_stripped` | 2 (staging class), 1 | no interpreter, no dynamic section, no symbol table |

No single weak sign makes a verdict (a static stripped Go binary in `/tmp`
scores 2); a UPX-packed copy of a harmless binary scores 9. Measured on the
development host (WSL 6.18) over the 941 executables of `/usr/bin`,
`/usr/sbin` and `~/.cargo/bin` (666 ELF, 275 scripts): none suspicious, 21
with one finding of weight 2 at most (`elf.suspicious_imports` in `nsenter`,
`peekfd`, `ip`, `kmod`…).

## 5. The signed hash list

`/etc/northnarrow/execq-hashes.local`, overlay kind `execq-hashes`
(`OverlayKind::ExecqHashes = 13`), verified by the overlay gate like every
`.local` overlay (`config-manage` signature over its SHA-256 and length, this
agent's id, the rollback floor), MUTATE-protected with its `.sig`:

```text
# comment
block <sha256> [label]
allow <sha256> [label]
```

A malformed line or a digest listed twice refuses the whole file (a
signature never covers content the loader would skip). Stored with `nn-admin
config overlay set execq-hashes --file F --key K`; applied at the next agent
start, handed to the scanner in its sealed memfd. Nothing ships in it.

## 6. YARA

Asked: YARA rules in signed packs, with yara-x or the yara C library.

- **yara (libyara via bindings)**: C — against the charter's "no C in
  production" (VISION_TECHNICAL rule 1, checked by CI for `onig_sys` and
  `zstd-sys`); its parsers are the attack surface the scanner exists to
  confine, with a memory-safety CVE history. Refused.
- **yara-x 1.22** (pure Rust, BSD-3-Clause): measured with
  `default-features = false`, 137 crates, among them wasmtime 48 and
  cranelift 0.135 (Apache-2.0 WITH LLVM-exception). Two blockers in this
  lot: it declares `rust-version = 1.95` (the workspace supports 1.89, and
  `xtask/tests/supply_chain.rs` holds the MSRV to the locked dependencies,
  so even an optional dependency raises it workspace-wide); and its rules
  run as cranelift-compiled code — executable memory the scanner's filter
  refuses (`mmap`/`mprotect` with `PROT_EXEC` kill it), which is the line
  that keeps a parser of hostile files from becoming a code-execution
  primitive. Its Pulley interpreter (`pulley` feature) would avoid the JIT;
  its footprint and speed are unmeasured.

Shipped: the hash and heuristic engine. The `yara` cargo feature of
`northnarrow-scan` is reserved and fails the build with the reason;
`ScanConfig::yara_rules` is in the protocol and the scanner reports a pack it
cannot apply. Follow-up: yara-x with `pulley` in the scanner only, the MSRV
raise as its own PR, a signed overlay kind for rule packs (content never
compiled into the binary), its footprint and per-file cost measured in the
lab.

## 7. Records and status

A decision is a record in the signed detection chain, rule
`NN-L-EXECQ-001_FirstSightQuarantine`, category `malware_prevention`, through
the per-rule budget — except a resume on content already judged clean (its
first sight was recorded), a clean verdict that arrives after the default
policy resumed the process, and the records the per-rule budget holds back
(counted in the next record's `suppressed_before`); a process resumed at
boot is a signed audit entry, not a record. ATT&CK (Enterprise 20.0, lab PR 221's typed mapping,
`execq::ATTACK`; `mitre_version` "20.0"): tactic TA0002, technique T1204.002
(User Execution: Malicious File), plus T1059.004 / T1059.006 / T1059.007 /
T1059 for a script by its interpreter. The record's `execq` field: the verdict,
SHA-256, format, the reasons (`code (+weight): detail`), the decision
(`would …` in observe mode), its basis, the classes, whether the process was
held and for how long. `response` says what was done (`resumed`, `killed
while held; quarantined (vault …)`, `ended while held` when the rules killed
it).

Signed audit entries: `subsystem_degraded` for a guard that cannot start
(no scanner account, the exec sensor not on LSM, a kernel configuration that
failed), for a scanner loss (one per cause per 10 minutes, the repeats
counted), and for the fail-open execs — run without being held because the
events ring was full or the stop signal was refused (at most one per 10
minutes, with the counts since the previous one; the ring's drops are also
counted in its ring-drop slot `execq`, signed `ringbuf_drop`); a stale
heartbeat (a dead controller) leaves nothing to report it but the counter;
`exec_quarantine` for `recovered_at_boot` and `stopping`.

`nn-admin status --key` (signed telemetry; appended fields of
`StatusResponse`): `execq_state` (`off`, `enforce`, `observe`, `degraded:
…`) and the counts held, resumed, killed, quarantined, default policy, known
identity (kernel skips), known content, not held, scanner deaths.

`NN-L-EXECQ-001` is outside the frozen V2 validation denominator
(`docs/validation/v2-rules.tsv`): the guard is experimental and off by
default; it enters a new registry version when it leaves that status.

## 8. Threat model

Considered: an unprivileged user or a compromised service dropping a binary
where it can write (a staging directory, its home, a world-writable
directory, memory) and running it — the most common first stage on Linux.
The guard sees the image before it runs and has it judged by content, not
only by location.

What it does **not** stop:

- **Interpreted code.** A `#!` script executed directly from a guarded
  location is a candidate: its interpreter is held, the script is opened by
  path (its inode checked), hashed against the lists, and its `#!` line
  judged; the ELF heuristics do not apply. A script handed to an interpreter
  (`bash /tmp/x.sh`, `python3 x.py`, `curl … | sh`, `perl -e`) is no exec of
  the script: the exec is the interpreter's, package-managed, never held. The
  exec rules and the FIM see what they see.
- **Known binaries reused** (living off the land): a package-managed
  binary, or a copy of content judged clean, runs as it always did.
- **Execution without `execve`**: `ld.so /tmp/x` maps the file instead of
  executing it (the image is the loader); `LD_PRELOAD`; code injected into a
  running process (`ptrace`, `process_vm_writev`, `/proc/<pid>/mem`); an
  interpreter's in-memory code.
- **Kernel-mode code** (a module, an eBPF program, an exploit): out of
  scope; R018 and the BPF guard are other lines.
- **Root.** Root can kill the scanner (the default policy then applies and
  each loss is signed), run the agent detect-only, or change the system
  clock. The scanner is deliberately not a protected pid: that membership
  exempts from the inode and BPF-map guards, which a process parsing
  hostile files must not have.
- **Content changed under a cached identity.** The cache trusts ctime and
  size. On kernels that refuse to execute a file open for writing (`ETXTBSY`,
  Ubuntu 24.04's 6.8), content cannot change between two runs without moving
  ctime; a page already mapped shared and writable before the first run is
  the residual case (writes through it fault again only after writeback).
- **Fail-open paths**, by design: a stale heartbeat, a full ring, a refused
  signal, observe mode — each counted.

Side effects to know:

- **Job control.** A held process is in group stop: an interactive shell
  with job control sees `Stopped` and gives the prompt back; the resume
  continues the job in the background (`fg` brings it back). Scripts,
  services and non-interactive shells are unaffected. A debugger sees the
  `SIGSTOP`.
- **Latency of first sight** (§9), and of every exec of a guarded file on a
  kernel without the ctime offsets.

## 9. Expected overhead (to be measured, lab check 5)

- Guard off: one array lookup per binfmt pass and per exec.
- Guard on, exec outside the guarded classes: the classification (a few
  probe reads, one hash-map lookup when the walk ends on a filesystem root);
  no stop.
- Known identity: one LRU lookup and two probe reads; no stop.
- First sight: the stop, the ring's wake-up, two opens, the package lookup
  (skipped in the usual locations), the scan, and the rule engine's verdict
  on the same exec. The engine alone, measured in process on the
  development host (best of 5, file in memory): `true` (27 KB) 47 µs, `ls`
  (142 KB) 166 µs, a 21 MB Rust binary 19 ms, 64 MiB of data 69 ms (SHA-256
  about 1 GB/s). Expected end to end: about 1–5 ms for a binary under
  1 MB, up to 100 ms for 64 MB; a copy of known content costs the same scan
  but writes no record. A build that runs thousands of new binaries from a
  home directory pays this once per binary.

## 10. Configuration

| flag | env | default |
|---|---|---|
| `--exec-quarantine off\|observe\|enforce` | `NN_EXEC_QUARANTINE` | `off` |
| `--exec-quarantine-budget-ms MS` (100–10000) | `NN_EXEC_QUARANTINE_BUDGET_MS` | 2000 |
| `--exec-quarantine-on-expiry resume\|kill` | `NN_EXEC_QUARANTINE_ON_EXPIRY` | `resume` |
| `--exec-quarantine-on-suspicious resume\|kill` | `NN_EXEC_QUARANTINE_ON_SUSPICIOUS` | `resume` |
| `--exec-quarantine-scanner PATH` | | `northnarrow-scan` next to the agent |
| `--exec-quarantine-scan-user USER` | | `northnarrow-scan` |
| `--execq-hashes-local PATH` | | `/etc/northnarrow/execq-hashes.local` |

The guard needs the LSM exec sensor (`--exec-sensor lsm`, the default, on a
kernel booted with `bpf` in its LSM list); otherwise it is degraded and
signed as such.

## 11. Lab checks and open items

The guest checks (`deploy/lab/execq/execq-check.sh`, `nn-lab.sh
execq-check`): a new binary held, scanned, resumed and recorded, its second
run not held; a block-listed test binary killed before its first instruction
and quarantined; a UPX-packed binary flagged; a package-managed binary never
held; the latency with and without the guard; the scanner killed during a
scan. The kernel half loads on 5.15, 6.1, 6.8 and 6.12
(`deploy/lab/nn-lab.sh verifier-check`, 2026-10-21). Owed: RHEL 9; the
latency numbers; the job-control effect measured; YARA (§6); a
`fanotify` `FAN_OPEN_EXEC_PERM` variant, which blocks inside `execve`
invisibly to the parent but needs `CAP_SYS_ADMIN`, has no kernel timeout and
does not see a memfd.
