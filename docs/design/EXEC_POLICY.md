# Exec policies and the exec environment (EXPERIMENTAL, lab PR 226)

Capabilities C12 (synchronous inline blocking) and C13 (malware prevention),
Wave 4; countermeasures CM-01 and CM-25 of the malware matrix. Off by
default (`--exec-policy off`). Code: `agent-ebpf/src/execpol.rs` (kernel),
`agent/src/execpol/` (table, kernel objects, controller, records), wire
`common/src/wire/execpol.rs`. Builds on the exec quarantine of lab PR 223
(`docs/design/EXEC_QUARANTINE.md`): its classification, its guarded mount
roots, its stop-and-scan.

## 1. What it does

Before lab PR 226 `bprm_check_security` returned 0 for every exec: an exec
from `/dev/shm`, a memfd or a deleted file ran, and the exec rules (R001–R004)
killed it after the fact. Now the LSM exec sensor's program returns the
policy's verdict for each binfmt pass:

| verdict | effect | record |
|---|---|---|
| `deny` | `-EACCES` from `bprm_check_security`, before the exec's point of no return: the caller keeps its image, no byte of the file runs | `NN-L-EXECPOL-001` High, `deny` |
| `audit` | the exec runs | `NN-L-EXECPOL-001` Medium, `would deny` |
| `quarantine` | handed to the exec quarantine (held before its first instruction, scanned, judged: lab PR 223) | the quarantine's `NN-L-EXECQ-001` |
| `allow` | nothing | none |

The verdict is a cell of a table: the file's **class** × the caller's
**lineage tier**. A file in several classes gets the strictest of their
cells (a deny wins; quarantine and audit can both apply). The global mode:

| `--exec-policy` | the kernel |
|---|---|
| `off` (default) | classifies nothing for the policy; the exec quarantine, if on, holds every candidate of its classes as in lab PR 223 |
| `audit` (every detect-only agent) | every deny is a "would deny" record; quarantine cells hand off |
| `enforce` | deny cells refuse |

Per class, `audit <class>` in the policy keeps that class's deny cells as
"would deny" while the others enforce: the learning period of a class.

## 2. Classes

Lab PR 223's classification of the pass's file (the dentry walk to the task's
root, the superblock, the link count, the memfd name), with three classes
split out or added in this lot:

| class | test |
|---|---|
| `memfd` | the dentry name starts with `memfd:` |
| `deleted` | `i_nlink == 0` (unlinked, `O_TMPFILE`) |
| `dev_shm` | the task's view starts with `/dev/shm/`, or the file is on the filesystem mounted at `/dev/shm` (new) |
| `tmp` | the task's view starts with `/tmp/`, or the filesystem mounted at `/tmp` (a tmpfs `/tmp`) |
| `var_tmp` | the task's view starts with `/var/tmp/`, or the filesystem mounted there (new; `tmp` before) |
| `world_writable_dir` | the parent directory has `S_IWOTH` |
| `tmpfs` | tmpfs, hugetlbfs, ramfs (also `/run`, a container's `/dev/shm`) |
| `home` | the task's view starts with `/home/` or `/root/`, or a filesystem mounted there |
| `other_home` | `home`, and the file's owner is neither the caller's real uid nor root (new): code another account controls |
| `guarded_mount` | a filesystem mounted at a guarded point (`/home`, `/tmp`, `/var/tmp`, `/root`, `/dev/shm`, `/run/user/*`) |

The guarded mount roots (`EXECQ_ROOTS`, from `mountinfo` every 10 s) now say
which point they are at (`root_kind`), so a file on a tmpfs `/tmp` is `tmp`
and one on a separate `/home` is `home`. The exec quarantine refreshes them
when it runs, the policy's controller otherwise.

## 3. Lineage tiers

Computed in the kernel at the exec, from signals a process cannot set for
itself without root:

| tier | test |
|---|---|
| `service` | the caller's cgroup v2 ancestor at level 1 is `system.slice` (units, cron jobs, `systemd-run`, containers under the systemd cgroup driver) |
| `admin` | in `user.slice`, real uid 0, a controlling terminal (`task->signal->tty`), a login uid, and either a root login (login uid 0) or an elevation binary (sudo, su, doas, pkexec, run0, sudo-rs; by image `(dev, ino)`) within 8 hops of the lineage, the caller included |
| `session` | in `user.slice` with a login uid, not `admin`: a user's shell or desktop, `ssh host cmd`, root without a terminal |
| `unknown` | anything else: no slice ids published (cgroup v1, no systemd), `machine.slice`, `kubepods`, a user slice without a login uid |

The slice ids are the inode numbers of `/sys/fs/cgroup/{system,user}.slice`
(a cgroup v2 id), published by the agent and refreshed every 10 s
(`user.slice` may appear after the agent starts); the kernel reads the
caller's ancestor with `bpf_get_current_ancestor_cgroup_id(1)`.

Why these signals: moving between `system.slice` and `user.slice` needs
write access to the root cgroup's `cgroup.procs` (root); a login uid can be
set only once, from unset, by the process itself (so a service could give
itself one — it still cannot leave `system.slice`); a terminal is easy to
obtain, which is why it is one signal among four. A process that is already
root can forge the admin tier (set its login uid with `CAP_AUDIT_CONTROL`,
move its cgroup, open a pty, run sudo): the admin tier is a concession to
humans at a terminal, not a boundary against root, and the default keeps
memfd and deleted-file execs of the admin tier on record.

**Exemptions.** init (`tgid 1`) is never refused: systemd 255 executes its
executor from a descriptor pinned at start, unlinked after an upgrade until
`daemon-reexec`. The caller's own image (`mm->exe_file`) is looked up in
`EXECPOL_IMAGES`: init's image (`/proc/1/exe`, so the child init forks
before its exec is covered), container runtimes that re-execute a sealed copy
of themselves (runc, crun, lxc-start/attach/execute: CVE-2019-5736) and the
policy's `exempt` lines lift memfd and deleted. Re-executing one's own image
(`/proc/self/exe` of a program whose file an upgrade replaced: Docker's
reexec, Go programs) lifts them too. An exempt image counts only when it is
root-owned and not writable by group or others. Exemptions are counted
(`EXEMPTED`) and marked in a record's tier signals.

## 4. The default tables

`--exec-policy-profile server` (default). Cells: admin / session / service /
unknown.

| class | admin | session | service | unknown |
|---|---|---|---|---|
| memfd | audit | deny | deny | deny |
| deleted | audit | deny | deny | deny |
| dev_shm | allow | deny | deny | deny |
| tmp | allow | quarantine | quarantine | quarantine |
| var_tmp | allow | quarantine | quarantine | quarantine |
| world_writable_dir | allow | quarantine | quarantine | quarantine |
| tmpfs | allow | quarantine | quarantine | quarantine |
| guarded_mount | allow | allow | quarantine | quarantine |
| home | allow | allow | quarantine | quarantine |
| other_home | allow | quarantine | audit | audit |

`--exec-policy-profile desktop`:

| class | admin | session | service | unknown |
|---|---|---|---|---|
| memfd | allow | audit | deny | audit |
| deleted | allow | audit | deny | audit |
| dev_shm | allow | quarantine | deny | quarantine |
| tmp, var_tmp, world_writable_dir, tmpfs | allow | allow | quarantine | quarantine |
| guarded_mount, home | allow | allow | quarantine | allow |
| other_home | allow | quarantine | audit | quarantine |

Why:

- **memfd and deleted files** are how fileless loaders run (Mirai and
  Kinsing stagers, `memfd_create` + `fexecve` droppers, a binary that
  deletes itself): nothing a package installs runs that way, and the
  legitimate cases are the exemptions above. Denied for services and every
  non-admin session on a server — the brief's "non-interactive sessions"
  included (`ssh host cmd`, Ansible) — recorded as "would deny" for an admin.
- **`/dev/shm`** is a POSIX shared-memory directory: BPFDoor
  (`/dev/shm/kdmtmpflush`) and miners stage there, no package executes from
  it. Denied, not quarantined: the brief said quarantine for `/tmp`,
  `/dev/shm`, `/var/tmp`; with the quarantine's defaults (resume on expiry,
  resume a suspicious verdict) a quarantined `/dev/shm` binary would still
  run, and MS-01 expects the refusal.
- **`/tmp`, `/var/tmp`, world-writable directories, tmpfs** carry
  legitimate execs — installers (makeself), `go test`, pip and npm builds,
  DKMS, CI runners as services: scanned before their first instruction, not
  refused. A quarantine cell needs `--exec-quarantine`: without it the exec
  runs and is counted `quarantine inactive` (a signed degradation at start
  says so).
- **A session's own home** is allowed (a user's `./script.sh`); a service
  running from a home is held for a scan; **another user's home** is
  "would deny" for services (a root cron job running a user-writable script
  is an escalation path — and also a common misconfiguration: audit first).
- **Desktop**: a login session runs AppImages (mounted under
  `/tmp/.mount_*`), Flatpak and toolchain outputs from staging locations;
  services stay as strict as on a server.

## 5. The exec environment (CM-25)

`sys_enter_execve` / `sys_enter_execveat` read the new environment from the
caller's `envp` (its old image, before the kernel's copy): at most 64
variables, the first 24 bytes of each compared against a fixed set of names,
the values of the loader variables captured (128 bytes of `LD_PRELOAD`, 64 of
`LD_AUDIT`, 64 of `LD_LIBRARY_PATH`, 128 of `GLIBC_TUNABLES`, 16 of
`HISTFILE`). Nothing else of the environment is read or reported. The
findings wait in `EXECPOL_ENV` (keyed by `task_struct`) for the exec's pass 0.

| finding | kernel | record |
|---|---|---|
| `LD_PRELOAD` / `LD_AUDIT` entry under `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/proc/` (`/proc/self/fd/N`: a memfd preload), `/dev/fd/` | denied for `service` and `unknown` on a server, for a root caller in `session` (on a desktop: `service`, and a root caller in `session` or `unknown`); recorded for `admin` | `NN-L-EXECENV-001` High (deny) / Medium / Low, T1574.006 |
| the same at a **set-id target** | never denied | Medium, "the kernel sets AT_SECURE and the loader ignores the entry" |
| `GLIBC_TUNABLES` at a set-id target | recorded | `NN-L-EXECENV-002` Medium; Critical for the shape of CVE-2023-4911 (a tunable whose value holds another assignment, or a value filling the buffer), T1068 |
| `LD_LIBRARY_PATH` under a staging prefix | recorded for services, unknown callers, root | `NN-L-EXECENV-002` Medium, T1574.006 |
| `HISTFILE` empty or `/dev/null`, `HISTSIZE=0`, `HISTFILESIZE=0`, `HISTCONTROL=ignore*` exported, at the exec of a shell | recorded | `NN-L-EXECENV-002` Low, T1070.003 |

**What the kernel already enforces, not duplicated.** For a set-id or
file-capability target the kernel sets `AT_SECURE`; the loader then ignores
`LD_PRELOAD` entries with a slash (names without one only from the system
directories, and only set-id libraries), `LD_LIBRARY_PATH`, and unsafe
`LD_AUDIT` values. The policy does not deny those (a record says the attempt
was made). What `AT_SECURE` does not cover is a caller that is **already
privileged**: a root service, a root cron job, root in a session without a
terminal — no credential changes, no `AT_SECURE`, the loader honours the
preload with root's credentials. That is what `deny-root` and the service
deny are for. File capabilities are not visible to the program (the target
is judged by its set-id bits): a preload into a capability binary from a
service is refused, which the loader would have ignored anyway.

Limits, by design: the string check reads prefixes of the value, not
resolved paths (`//tmp/x.so`, `/./tmp/x.so`, a symlink, `..`); the first 128
bytes of `LD_PRELOAD`; the first 64 variables (`TRUNCATED` is counted); a
caller racing its own memory between the syscall's entry and the kernel's
copy (TOCTOU); 32-bit compat `execve` (no syscall tracepoint). The mapping
check (§6) does not depend on the string.

## 6. Executable mappings (`mmap_file`)

The LSM hook `mmap_file(file, reqprot, prot, flags)`: a mapping with
`PROT_EXEC` in `reqprot` of a file in a class, by the caller's tier, is
refused or reported (`NN-L-EXECENV-003`, T1574.006, T1129, T1620 for memfd
and deleted). This is where a preload or a `dlopen` from a staging path, and
`ld.so /tmp/x` (IA-13), are seen whatever string named them. The image an
exec is loading (`mm->exe_file`) is skipped: its exec was judged. Classes are
cached per inode and ctime (`EXECMAP_SEEN`, a rename or a write moves ctime);
a file is reported once a minute at most, the counters keep the total.

Defaults (server): services — `/dev/shm` denied; `/tmp`, `/var/tmp`,
world-writable directories, deleted files and other users' homes recorded;
unknown callers — the same recorded; sessions — `/dev/shm` and deleted
recorded; admins — nothing. Desktop: services recorded, sessions `/dev/shm`
recorded. **memfd mappings are never reported by default**: .NET's W^X
double mapping (`doublemapper`), libffi closures and JIT engines map memfds
executable by design. `/tmp` is recorded, not refused: Java services extract
JNI libraries there (snappy-java, netty-tcnative, sqlite-jdbc, JNA in
Elasticsearch) and PyInstaller one-file programs unpack into `/tmp/_MEI*`.
`mprotect(PROT_EXEC)` of an existing mapping (`file_mprotect`) is not judged
in this lot.

## 7. Scripts and the exec quarantine (design review, lab PR 226)

A `#!` script held by lab PR 223's quarantine was scanned while its
interpreter was stopped; once resumed the interpreter opens the script **by
its path** and reads it — incrementally, for a shell — so what it executes
need not be what was scanned (the file rewritten, or another file renamed
onto the path, between the scan and the read). Handing the interpreter a
sealed memfd copy of the scanned content would mean rewriting a stopped
process's argv in place and installing a descriptor in it from outside; the
simplest safe option is taken instead: **in enforce mode the exec
quarantine refuses a script it would hold** (`-EACCES` at the interpreter's
pass, before the exec's point of no return; `SCRIPT_REFUSED`, a Medium
`NN-L-EXECQ-001` record, decision `refuse`; the same for a binfmt_misc
input). Observe mode scans it and records "would refuse". With the exec
policy on, only quarantine cells reach the quarantine, so a script the
policy allows (an admin's or a user's script in their home) is neither held
nor refused. A script handed to an interpreter (`sh x.sh`) is no exec of the
script and is not seen (lab PR 223's documented gap).

## 8. Records, status, degradations

Records (signed detection chain, through the per-rule budget; field
`execpol`: kind, decision, tier and its signals, classes, environment
findings, the captured values escaped, whether `AT_SECURE` applies, where the
policy came from; response says what was done; record-only findings are not
repeated for 10 minutes; denies always):

| rule | what | ATT&CK v20 |
|---|---|---|
| `NN-L-EXECPOL-001_StagingExecDenied` | an exec a deny or audit cell named | T1620 (memfd, deleted), T1070.004 (deleted), T1204.002 (staging locations), T1564.001 (a hidden component); tactics TA0005, TA0002 |
| `NN-L-EXECENV-001_PreloadFromStaging` | `LD_PRELOAD` / `LD_AUDIT` into a staging path | T1574.006 |
| `NN-L-EXECENV-002_ExecEnvironmentTrick` | `GLIBC_TUNABLES` at a set-id target, a staging library path, history disabled | T1068, T1574.006, T1070.003 |
| `NN-L-EXECENV-003_ExecMappingFromStaging` | an executable mapping from a class | T1574.006, T1129, T1620 |

ATT&CK identifiers: T1620, T1070.004, T1574.006, T1068, T1070.003,
T1564.001, T1204.002 and T1129 are in the pinned v20 table
(`docs/detection/attack-enterprise-20.0.tsv`, lab PR 221; T1204.002 pinned
with lab PR 223's mapping, T1129 with this lot's, both checked active in
the v20 bundle), as the typed references of `execpol::record::ATTACK_*`
(the record carries those its finding names, `mitre_version` "20.0"). T1036
(Masquerading) was considered and not used: no class says anything about a
name.

`nn-admin status --key`: `execpol_state` (`off`, `audit`, `enforce`, with
`; N partial` when a part could not start, or `degraded: …`) and the kernel's
counts: denied, would deny, quarantine, quarantine inactive, environment
denied / reported, mappings denied / reported; `execq_script_refused_total`
for §7.

Signed `subsystem_degraded`, one per cause at start: the exec sensor not on
LSM (nothing can be refused); the environment programs or the mapping
program refused or not attachable; no slice ids (every caller `unknown`);
`task_struct.signal` / `signal_struct.tty` absent (no admin tier);
`task_struct.loginuid` absent (no session tier); `inode.i_uid` absent (no
`other_home`); quarantine cells without the quarantine; a signed policy
file that does not parse at boot (a bad line `overlay set` would have
refused: the built-in profile applies, source `exec_policy`).

The rules are outside the frozen V2 validation denominator, like
`NN-L-EXECQ-001`: experimental and off by default.

## 9. Kernel objects and the verifier

- `EXECPOL_CONF` (`Array<u64>`, 32 slots): mode, per-tier deny / quarantine /
  audit / map-deny / map-record class masks, class audit mask, environment
  tier masks, flags — written once, **frozen** (`BPF_MAP_FREEZE`), `OFF`
  included. `EXECPOL_SLICES`, `EXECPOL_IMAGES` refreshed by the controller
  every 10 s; the BPF guard keeps other processes away from the agent's maps.
- New optional BTF offsets `TASK_STRUCT_SIGNAL_OFFSET`,
  `SIGNAL_STRUCT_TTY_OFFSET` (slots 98 and 99) and lab PR 219's
  `INODE_I_UID_OFFSET` (slot 94), read here too; tracepoint fields
  `sys_enter_execve.envp`, `sys_enter_execveat.envp` (slots 111 and 112);
  the fixed-position check `bpf_lsm_mmap_file` argument 0 is a `struct
  file`. The enum, tracepoint and hook-argument slots move up (116 slots in
  all with lab PRs 219 to 224).
- 5.15: every loop is in a global function verified on its own (`nn_env_scan`
  64 iterations, `nn_list_staging` 128 bytes, `nn_execpol_tier` 8 hops,
  `nn_map_classify` the 64-level walk); findings are kept in map memory, not
  registers, so the loop states do not multiply; helper reads only
  (`bpf_probe_read_user{,_str}`, `bpf_get_current_ancestor_cgroup_id`, 5.10+
  for tracing programs); no `bpf_loop`. Every program loads on 5.15, 6.1,
  6.8 and 6.12 (`deploy/lab/nn-lab.sh verifier-check`, 2026-10-21); the
  first build's growth of `exec_check_lsm` did not on 5.15 and 6.1
  (KERNEL_COMPATIBILITY "Older verifiers", rule 9), and the agent fell back
  to `sys_enter_execve`, with no exec refused. Owed: RHEL 9; the per-exec
  cost (expected: two helper reads per variable at the syscall's entry, a
  hash lookup and two map reads per classed exec, a cache lookup per
  executable mapping).
- Fail-open: the programs are not pinned; they detach with the agent and
  nothing more is refused.

## 10. Configuration

| flag | env | default |
|---|---|---|
| `--exec-policy off\|audit\|enforce` | `NN_EXEC_POLICY` | `off` |
| `--exec-policy-profile server\|desktop` | `NN_EXEC_POLICY_PROFILE` | `server` |
| `--exec-policy-local PATH` | | `/etc/northnarrow/exec-policy.local` |
| `--exec-policy-no-env` | `NN_EXEC_POLICY_NO_ENV` | off |
| `--exec-policy-no-map` | `NN_EXEC_POLICY_NO_MAP` | off |

The signed overlay (`OverlayKind::ExecPolicy = 14`, keyword `exec-policy`,
MUTATE-protected with its `.sig`), applied at the next agent start over the
profile, in order; a line that does not parse refuses the whole file —
at `overlay set`, and at boot, where the built-in profile applies and the
refusal is a signed degradation (§8):

```text
profile server|desktop
exec <class|*> <tier|*> allow|audit|quarantine|deny
audit <class|*>
preload <tier|*> allow|record|deny|deny-root
map <class|*> <tier|*> allow|record|deny
exempt <absolute path> [class,class…]      # default: memfd,deleted
```

## 11. Expected false positives

- A root cron job or a unit running a script or binary from `/root` or a
  home (`service` × `home` → quarantine; with `--exec-quarantine enforce` a
  script there is refused, §7) — move it to `/usr/local/sbin`, or `exec home
  service allow`.
- Services that execute from `/tmp` (CI runners, installers run by
  unattended-upgrades, DKMS helpers): quarantine cells — held and scanned
  with the quarantine on, counted `quarantine inactive` without it.
- Programs that execute an unlinked file of another image (not their own):
  rare; `exempt <image>`.
- An admin in a detached `tmux`/`screen` as root: the lineage no longer
  reaches sudo, the session rules apply (memfd and `/dev/shm` refused).
- Root over `ssh host 'cmd'` and Ansible `become`: `session` with uid 0 — an
  `LD_PRELOAD` into `/tmp` there is refused (`deny-root`).
- Mapping records: Java services extracting JNI libraries into `/tmp`,
  PyInstaller programs, libffi on SELinux hosts with old libffi (`/tmp`,
  `/dev/shm` trampolines) — recorded once a minute per file, not refused
  except `/dev/shm` for services.
- `HISTCONTROL=ignoreboth` exported by a user's profile: a Low record per
  shell per 10 minutes.
- Kubernetes pods, `machine.slice` containers, hosts without cgroup v2:
  `unknown`, the strictest column.
