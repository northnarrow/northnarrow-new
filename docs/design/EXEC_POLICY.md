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
| `guarded_mount` | a mount at a guarded point (`/home`, `/tmp`, `/var/tmp`, `/root`, `/dev/shm`, `/run/user/*`) is among the file's ancestors, by identity (lot 318: a btrfs subvolume, a bound directory; `docs/design/EXEC_QUARANTINE.md` §2) |

The guarded mount roots (`EXECQ_ROOTS`, from `mountinfo` every 10 s) now say
which point they are at (`root_kind`), so a file on a tmpfs `/tmp` is `tmp`
and one on a separate `/home` is `home`. Lot 318 (external bug hunt BUG108):
a file on a btrfs subvolume mounted at `/home`, or in a directory bound
there, is `home` too, and a file the dentry walk cannot place (more than 64
levels deep) is `tmp`, `var_tmp` and `home`. The guarded points themselves
are published by identity as well (the review of #545, F2): `/var/tmp` in
openSUSE's `@/var` subvolume, `/home` and `/var/tmp` under an ostree
deployment's `/var` bind are no mount, and their files had no class; a
point gives its class only (`var_tmp`, `home`), `guarded_mount` stays a
mount's. A FUSE file outside the task's
root is `guarded_mount` whatever its daemon says its root is (and `tmp`,
`var_tmp`, `home` where no published root places it). A filesystem a user
mounts in their own user namespace (an overlay at `/tmp/m` after `unshare
-rm`), or a chroot into a FUSE directory, gives no class (not only in a
container; follow-up lot 323, `docs/design/EXEC_QUARANTINE.md` §2). The
identity search stops at the task's root (the re-check of #545, R3): a
container whose root is a directory in a home (LXC's dir backend, rootless
podman's vfs or btrfs storage) is classed in its own view, as before lot
318, not `home` and `other_home` by the host's `/home` above it; the
container policy is lot 323's. The exec quarantine refreshes them
when it runs, the policy's controller otherwise.

Lot 311 (bug hunt 1.4, BUG-98 and its sibling here, BUG-108, N8): the table
is read as bytes (`nn_linux::mountinfo`). Read as text, one mount whose point
or source is not UTF-8 — an unprivileged user's FUSE mount (`fusermount3`)
at `~/\xff` — emptied it: the roots removed, and here the slices unpublished
(every caller `UNKNOWN`, `NO_SLICES`: a service's deny became an audit). A
table that cannot be read at all leaves the slices and roots last published
in force, never zeros or an empty set, with a degradation
(`execpol_mounts`, `execq_roots`) while it fails, withdrawn at the next good
read. A btrfs subvolume mounted at a guarded point (`/home` on Fedora and
openSUSE: `subvol=/home`) is published although its root field is not `/`,
when no mount of that filesystem is its root (a bind mount of a directory of
a filesystem mounted elsewhere stays out); the kernel's walk to it is lot 9's
(the userland half only here).

The independent review of #538 (lot 311b): a FUSE mount — any, wherever it
is mounted (a user's, through `fusermount3`, in `~/mnt` or in a world-writable
directory) — is classed by its type (`fuse`, `fuseblk`, `fuse.*`) and keyed
in `EXECQ_ROOTS` by its device alone, `(dev, 0)`: its daemon (the user) names
its root's inode and changes it at will (`fuse_change_attributes_common`
takes the inode number from every answer), and root may not `stat` it (no
`allow_other`) or be stalled by it. The kernel's half — telling a FUSE file
by its superblock's magic in the exec hooks and looking `(s_dev, 0)` up — is
lot 318's. Any other root is read without following a link
(`O_PATH | O_NOFOLLOW | O_DIRECTORY`) and only while its mount point shows the
line's device (a btrfs subvolume excepted): a mount point a user swapped for
a link to another filesystem's root no longer gets that root published. A
line of the table that is not in the kernel's shape is a degradation
(`execq_roots_rows`, `execpol_mounts_rows`) while it lasts — a source `-`
(`fsname=-`) or an empty one is a mount, read as such. The roots are
ranked, the FUSE ones last (a user mounts up to `mount_max`, 1000): when
the kernel's map (1024 entries since lot 318, 64 before) is full, a FUSE root it holds gives way to a
system root mounted after it (another user's `/run/user/<uid>`, an
automounted `/home`). A root other than a FUSE one that the map still
refuses is a degradation (`execq_roots_full`, `execpol_roots_full`), its
text the same whatever the count and standing 5 minutes at least once
reported (one signed record per hold, however often the count comes and
goes); a FUSE root left out is no loss — the exec hooks class a FUSE file
by its magic (lot 318) — and only logged. A degradation that ends within
the 15 s before its flush is signed at its withdrawal: every one leaves its
record in the chain.

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

The exec's first pass (`bprm_check_security`, pass 0) reads the new
environment from the caller's `envp`, in the caller's own memory (the new
image is mapped later, by the binfmt's `load_binary`). `envp` is the exec's
own syscall argument, as its registers hold it (`task_pt_regs`: `dx` for
`execve`, `r10` for `execveat`; the review of #546, F1: a 32-bit
`int $0x80` exec's `edx` / `esi` and an x32 exec's `dx` / `r10` too, an
array of 32-bit pointers, the register's low half as the kernel reads it).
The kernel copied the strings earlier in the exec, into the new image's
stack, which the program cannot read: this is a second read of the
caller's memory, after the kernel's copy (see the limits below). Lot 325
(the re-check of #546, R2): **every variable is read**. Each costs its
pointer and the first eight bytes of its name; the names the scan judges
(`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `GLIBC_TUNABLES`, the history
ones) are then read whole, 24 bytes compared against a fixed set of names.
The scan is three loops of global functions, 128 rounds of 128 steps of 64
variables: 1,048,576, above any environment the kernel accepts (its strings
and pointers share at most 6 MiB, and each variable costs 9 bytes at least:
699,050). It read the first 64: 64 padding variables, then a staging
`LD_PRELOAD`, passed — no privilege, no race — and for a root session left
no record. An array longer than the cap can only have grown after the
kernel counted it: `TRUNCATED`, counted (`nn-admin status`: "environments
not finished"), recorded (`NN-L-EXECENV-002`, High), and **refused at a
protected target** (the tier's rule refuses a staging preload: `deny`, or
`deny-root` with a root caller) **or a set-id one**. The choice rests on
what legitimate programs carry, measured: see the lot note in
`docs/roadmap/CAPABILITY_PROGRAM.md` (tens to a few hundred variables on our
hosts, a CI runner and a build script; a Kubernetes pod carries about seven
per service of its namespace, thousands at most — every one far below the
cap, which no exec the kernel accepts can reach). Each occurrence of a
loader variable is judged when it is read (the mini-hunt): glibc's loader
takes the last `LD_PRELOAD`, musl's (and any `getenv`) the first, and the
scan judged the last only, so a staging preload first and a clean one last
passed into a musl target.

The review of #547 (F1, F7): **each loader value is judged whole, entry by
entry, as the loader reads it.** The value is read 255 bytes at a time, up
to 16 reads (about 4 KiB, `ENV_VALUE_READS`), and every byte goes through
one parser (`value_parse` in `common/src/wire/execpol.rs`, the same code
the host tests run): `LD_PRELOAD` splits on colons, spaces and the other
`isspace` bytes (glibc and musl), `LD_AUDIT` on colons, `LD_LIBRARY_PATH`
on colons and semicolons; each entry's path is normalised (`//`, `/./`,
`..`) and judged against the staging directories (`/tmp`, `/var/tmp`,
`/dev/shm`, `/proc`, `/dev/fd`). A relative entry (a `/` not at its start:
`./x.so`, `lib/x.so`), or a bare name searched through a relative
`LD_LIBRARY_PATH` directory, says nothing of where it resolves:
`relative_loader_path` (`PRELOAD_RELATIVE`), refused at a protected or
set-id target and recorded elsewhere; a bare name searched through a
staging `LD_LIBRARY_PATH` directory is a staging preload. The re-check of
#547 (G1–G4): a loader value holding a control byte (glibc keeps a tab
inside an `LD_PRELOAD` entry, which the musl split read as two entries;
musl splits its library path on a newline) or a `$` (glibc expands `$LIB`,
`$ORIGIN`, `$PLATFORM` — `$LIB` is two components on Ubuntu, so
`/tmp/$LIB/../../x.so` is `/tmp/x.so`) is `irregular_loader_value`
(`LOADER_IRREGULAR`), whichever variable: refused at a protected or set-id
target, recorded elsewhere — legitimate set-id execs carry none of them.
An empty `LD_LIBRARY_PATH` element (`:`, `a::b`, a trailing `:`: glibc
searches the caller's directory there) is a relative directory (the
re-check 2 of #547): alone it is recorded (`library_path_staging`), never
refused — `LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/lib` with the variable
unset is its commonest shape, and it was refused in containers, root shells
and `sudo`; a bare `LD_PRELOAD` / `LD_AUDIT` name searched in it, the
combination that loads from the caller's directory, is `relative_loader_path`,
refused where a staging preload is. It compared the
first nine bytes of each entry of a 128-byte capture: 120 spaces then
`/tmp/x.so`, `//tmp/`, `/./tmp/`, a tab (musl) passed, and a clean value
longer than 128 bytes was refused as not finished. A value longer than the
reads (`LOADER_CUT`, and a bare name with an `LD_LIBRARY_PATH` that long) is
not refused at the first pass when what it read is clean: the post-commit
check judges the kernel's copy of it (below). At most 64 judged names are
read whole per exec (`ENV_JUDGED_MAX`; past them, `TRUNCATED`): no
legitimate environment carries that many. The values of the loader
variables are captured for the record: 128 bytes of `LD_PRELOAD`, 64 of
`LD_AUDIT`, 64 of `LD_LIBRARY_PATH`, 128 of `GLIBC_TUNABLES` and 16 of
`HISTFILE` (a longer one is quoted cut, `VALUE_CUT`: the judgment rests on
the whole value). Nothing else of the environment is read or reported. The findings go into the
task's own `EXECPOL_ENV` entry, keyed by its thread id and start time. They
are judged in the same run, and the entry is removed.

Lot 322: the environment was read by two programs on the
`sys_enter_execve{,at}` tracepoints and handed to pass 0 through that map.
On Ubuntu 26.04's 7.0 those programs ran only for the execs entered on
CPU 0, so the check refused almost nothing: 0 of 11 staging preloads, and
none pinned to CPU 1, 2 or 3. Their read also could not fault a page in: an
`LD_PRELOAD` string in a file mapping that had never been touched read as
nothing, while the kernel's copy faulted it in.

| finding | kernel | record |
|---|---|---|
| `LD_PRELOAD` / `LD_AUDIT` entry under `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/proc/` (`/proc/self/fd/N`: a memfd preload), `/dev/fd/` | denied for `service` and `unknown` on a server, for a root caller in `session` (on a desktop: `service`, and a root caller in `session` or `unknown`); recorded for `admin` | `NN-L-EXECENV-001` High (deny) / Medium / Low, T1574.006 |
| the same at a **set-id target** | lot 318: denied as any other, for the same tiers (it was never denied) | denied: as above; recorded (a tier whose rule does not deny): Medium, "the kernel sets AT_SECURE and the loader ignores the entry" when the exec changes the credentials, else "the exec ran; the target is set-id, but the exec changes no credential, so the loader honours the entry" (lot 315) |
| `GLIBC_TUNABLES` at a set-id target | recorded | `NN-L-EXECENV-002` Medium; Critical for the shape of CVE-2023-4911 (a tunable whose value holds another assignment, or a value filling the buffer), T1068 |
| `LD_LIBRARY_PATH` under a staging prefix | recorded for services, unknown callers, root | `NN-L-EXECENV-002` Medium, T1574.006 |
| `HISTFILE` empty or `/dev/null`, `HISTSIZE=0`, `HISTFILESIZE=0`, `HISTCONTROL=ignore*` exported, at the exec of a shell | recorded | `NN-L-EXECENV-002` Low, T1070.003 |

**What the kernel enforces, and why the policy does not count on it.** For
a set-id or file-capability target whose credentials change the kernel sets
`AT_SECURE`; the loader then ignores `LD_PRELOAD` entries with a slash (names
without one only from the system directories, and only set-id libraries),
`LD_LIBRARY_PATH`, and unsafe `LD_AUDIT` values. What `AT_SECURE` does not
cover is a caller that is **already privileged**: a root service, a root cron
job, root in a session without a terminal — no credential changes, no
`AT_SECURE`, the loader honours the preload with root's credentials. That is
what `deny-root` and the service deny are for. Lot 318 (external bug hunt
BUG101): a set-id target is denied as any other. The program read the
target's set-id bits as "the kernel sets `AT_SECURE`" and let the preload
through, which the bits do not promise: root running a set-uid-root file
(`su`, `passwd`, `mount`) changes no credential, and no set-id bit applies
under `no_new_privs`, on a `nosuid` mount, to a `#!` script (its
interpreter's bits decide) or for an owner the caller's user namespace does
not map. `deny-root` was side-stepped with `su`, or with a set-gid copy of
anything run under `setpriv --no-new-privs`. Telling those cases apart in the
kernel would take four more facts of it and could still miss one; refusing a
preload from a staging path at a set-id target whose loader would have
ignored it costs nothing legitimate. File capabilities were already judged
the same way: a preload into a capability binary from a service is refused,
which the loader would have ignored anyway. The set-id bits still decide
where `GLIBC_TUNABLES` is reported.

Lot 322 moved the read from the `sys_enter_execve{,at}` tracepoints (on
Ubuntu 26.04's 7.0 they ran for CPU 0's execs only) into the exec's own
`bprm_check_security` run. The re-check of #547 (G6): that run is a second
LSM program on the hook, `exec_env_lsm`, beside the exec sensor's
`exec_check_lsm` — the scan, the judgment, the record of the first pass and
the note for the post-commit check, at the exec's first pass. The verifier
gives each program its own million instructions: with the scan inside it,
`exec_check_lsm` counted 930,372 on 5.15 (measured by a kprobe on the
verifier's `check_max_stack_depth` while `verifier-check` loaded it: 5.15
has no `verified_insns`, and the loader keeps the verifier's log only for a
refusal). BPF-LSM runs a hook's programs in turn and the first refusal
refuses the exec; the policy attaches `exec_env_lsm` after the exec sensor's
program, so an exec refused on its classes is recorded on them, not also on
its environment. Without the program (refused by the verifier, not
attached), the start signs an `exec_policy` degradation and the environment
is not judged at exec.

Lot 325 (the re-check of #546, R1): an **x32** exec's `envp` is the
register whole, as the kernel's x32 stub passes it (`SC_X86_64_REGS_TO_ARGS`,
`__SC_DELOUSE`); only an **ia32** exec's is the register's low half (the
ia32 stub's `(unsigned int)` cast). Lot 322 truncated both: a 64-bit caller
of the x32 `execve` put the real array above 4 GiB and a clean decoy at its
low half, and the scan read the decoy (where the kernel has x32 at run
time; Ubuntu's 7.0 has not).

Lot 315 (external bug hunt 1.4, BUG-101, the record's half): a set-id
target is no `AT_SECURE` by its bits alone. The kernel sets it when the
exec changes the credentials — a set-user-ID file owned by another user
than the caller's real uid, or a set-group-ID file (the record does not
carry the file's group: a set-group-ID target counts as changing it, as it
does for every caller outside that group). Root running a set-user-ID-root
file (`su`, `passwd`, `mount`) changes nothing: the loader honours the
preload, as root, and the record said it ignored it. The record now says
the exec ran (`at_secure: false`, Medium). The kernel's half is lot 318's:
it drops the set-id skip entirely (a set-id target is denied as any other,
whatever `AT_SECURE`); this record's `at_secure` stays as it is, the
evidence of whether the loader would have ignored the entry. Residuals of
the record's wording (no privilege at stake): a set-id bit the kernel does
not apply (`nosuid` mount, `no_new_privs`, a set-id `#!` script) still reads
`AT_SECURE`; a file capability sets it and the record says nothing.
`GLIBC_TUNABLES` at a set-id target stays reported by the bits (an exploit
attempt is one whatever the caller).

Limits, by design: the string check normalises the path's text (`//`,
`/./`, `..`; the review of #547) but resolves no link (a symlink to a
staging file); a relative path (a bare name in an empty library-path
element included), a control byte or a `$` token is refused at a protected
or set-id target whatever it names; about 4 KiB of each loader value at the first pass (a
longer value is judged on the kernel's copy after the commit: killed at a
protected or set-id target, recorded elsewhere); an array longer than any
the kernel accepts (`TRUNCATED`, refused at a protected or set-id target,
above);
another architecture than x86-64 (the `pt_regs` offsets do not resolve: a
signed degradation). The mapping check (§6) does not depend on the string.

**The TOCTOU window (the review of #546, F2).** The scan re-reads the
caller's memory after the kernel's copy: from `copy_strings(envp)` to
`security_bprm_check` the kernel copies `argv` (up to about 6 MB), prepares
the credentials, may migrate the task (`sched_exec`), opens the file (5.15)
and reads its first page. Another thread of the caller, a process sharing
the page (`MAP_SHARED`, `process_vm_writev`) can rewrite `LD_PRELOAD=` or
unmap the page in that window, and make it deterministic with a
FUSE-backed `argv` page whose read the daemon holds. The kernel keeps its
copy; the scan judges what the memory holds when it reads. A string or an
entry it cannot read is `UNREADABLE`: counted (`ENV_UNREAD`, `nn-admin
status`: "environments not read") and recorded (`NN-L-EXECENV-002`, High).

**The kernel's own copy, past the point of no return (lot 325).** A second
program, `execpol_env_commit` on `sched_process_exec` (a tracepoint that is
no syscall's: it runs on every CPU), reads the new image's environment —
`[mm->env_start, mm->env_end)`, the strings the kernel copied and
`create_elf_tables` placed, which the loader will read — after the exec's
point of no return and before the image's first instruction. No other task
shares that memory (the exec ended every other thread of the caller; the
new `mm` is no one else's), so this read cannot be raced. It reads the
strings one after another, compares each one's first eight bytes, and reads
the judged names whole and judges their values with the first pass's
parser (above) — in a per-CPU buffer (`COMMIT_ENV`: the tracepoint runs
with preemption off), which no flood of execs in flight can take, and
bounded (the review of #547, F8): at most 8 rounds of 192 steps of 64 reads
(98,304 reads of the strings) and 64 judged names; past them, not finished
(`TRUNCATED`). A staging loader entry there that the first pass did not
see — or saw and refused, which leaves no image — is the environment
**changed after the kernel's copy** (`CHANGED`): counted (`nn-admin
status`: "changed after the kernel's copy", `env_changed`), recorded
(`NN-L-EXECENV-001`, Critical when killed), and, where the tier's rule
refuses it in enforce mode, the image is **killed** (`SIGKILL`, delivered
before it returns to user mode: the loader never runs). The review of #547
(F2): what this read cannot clear is never silent either — a loader value
longer than the reads, an environment past the bound, a relative loader
path, a string it cannot read (`relative_loader_path`, `loader_value_cut`,
`truncated`, `unreadable`): a protected target (the tier's rule refuses a
staging preload) or a set-id one is killed, any other exec recorded and
counted. It acted on new staging entries only. The record says `killed`
only when the signal went (`bpf_send_signal` refuses for the global init,
or a task already exiting): else "would deny" (F9). The first pass notes
what it judged and let through (a tier that records, or an environment it
could not read), so an entry it judged is no news. Audit mode records
"would deny". The exec cannot fail with `EACCES` at that point; that is why
the first pass stays.
Two new optional BTF offsets, `mm_struct.env_start` and `env_end` (slots 130
and 131); without them the program is not attached (a signed `exec_policy`
degradation).

Reading the kernel's copy at `bprm_check_security` itself, where the exec
can still fail with `EACCES`, is not possible: the new image's memory
(`bprm->mm`) belongs to no task yet, and no BPF helper reads an `mm` no task
runs (`bpf_probe_read_user` reads the current one, the caller's;
`bpf_copy_from_user_task` reads a task's, and is sleepable only). Walking its
page tables by hand from the program would take the direct map's base
(`page_offset_base`, randomised by KASLR, not in the BTF), the paging depth
(4 or 5 levels), the memory-encryption mask, and up to 1,536 pages per exec.

Limits of the post-commit check: a tracer the caller attached
(`PTRACE_EVENT_EXEC` stops after it) can still write the new image's memory —
it needs `ptrace` rights over it, which a set-id exec drops and which already
give it the image; the tier is computed again from the new image (the one
difference: an elevation binary that execs in place, `doas`, is no longer in
the lineage — only when the first pass did not see the entry).

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
for §7. Shown when not zero: environments not read (lot 322), runs without
their buffer (lot 322; lot 325: the protected targets refused past the
capacity), environments not finished, environments changed after the
kernel's copy, execs let through without their walk (lot 325; `--json`:
`env_unread`, `lost`, `env_truncated`, `env_changed`, `lost_open`).

Lot 325: while the exec guards are past their capacity (§9), the runtime
degradation `execpol_capacity`; `mm_struct.env_start` / `env_end` not
resolved, or the post-commit program refused, a start degradation.

Signed `subsystem_degraded`, one per cause at start: the exec sensor not on
LSM (nothing can be refused); the exec's registers not readable (the
`pt_regs` offsets unresolved: the environment is not judged) or the mapping
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
  `INODE_I_UID_OFFSET` (slot 94), read here too; the fixed-position check
  `bpf_lsm_mmap_file` argument 0 is a `struct file`. Lot 322: the
  environment's `envp` from `pt_regs` (`PT_REGS_ORIG_AX_OFFSET`,
  `PT_REGS_DX_OFFSET` of lot 273b, `PT_REGS_R10_OFFSET`, slot 129, all
  optional and x86-64), through `bpf_task_pt_regs(bpf_get_current_task_btf())`
  (5.15+); the tracepoint fields `sys_enter_execve.envp` and
  `sys_enter_execveat.envp` of lab PR 226 are gone with their programs.
- Lot 322: per-task buffers. `EXECPOL_ENV` (the environment), the exec
  sensor's `EXEC_SCRATCH` (the walk the classes are read from), the
  mapping check's `EXECMAP_SCRATCH` and the quarantine's candidate buffer
  are hashes keyed by the running task (`TaskKey`: thread id, start time),
  made zeroed at the start of the run, read by the global functions
  through the key, removed before it returns (the candidate is then copied
  into `EXECQ_CAND`, which `sched_process_exec` reads). They were per-CPU
  buffers, and an LSM program runs with preemption enabled (migration
  disabled only): on a `full` or `lazy` preemption kernel another task's
  exec on the same CPU could rewrite the walk between its write and the
  classes judged from it. A report of the mapping check from its cache
  walks the file again (it copied the CPU's last walk, another file's
  path). The review of #546 (F4): plain hashes, never LRU (an LRU insert
  can evict an entry in flight and give its memory to another task), 2048
  entries each; past them a mapping is classed `tmp`, `var_tmp`, `home`
  (not cached), counted (`LOST`, `nn-admin status`).
- Lot 325 (the re-check of #546, R5): **the exec guards past their
  capacity.** Past 2048 execs in flight (each a task preempted in the
  middle of `exec_check_lsm`: a fork bomb's flood) lot 322 refused every
  exec in enforce mode — the administrator's shell's too. An exec whose walk
  cannot be made is now judged on what needs none (`nn_exec_unwalked`): the
  caller's tier, memfd, deleted, tmpfs, a world-writable directory. It is
  refused (counted in `LOST`) when those classes meet a deny cell. The
  environment is judged by its own program (`exec_env_lsm`, the re-check of
  #547), into its own entry whether or not the walk could be made: a staging
  loader entry where the tier's rule refuses it, an environment past the cap,
  a relative or irregular loader value at a **protected target** (the
  tier's rule refuses a staging preload, or the file is set-id) are refused
  there. The review of #547 (F5): an environment the flood left unread (its
  own map full too) is no longer refused — that refused every root and service exec of a server
  once both maps were full: it is noted for the post-commit check, which
  reads the kernel's copy in its per-CPU buffer and kills a protected or
  set-id target on a staging entry or on what it cannot clear (§5); the e2e
  fills both maps and checks root's plain exec, `su`, and root's staging
  preload (killed). Every other exec runs, counted in
  `LOST_OPEN` ("execs let through without their walk", `lost_open`) and
  recorded (`NN-L-EXECPOL-001`, Low, "judged without its walk"); the
  quarantine holds nothing then (it needs the walk's path). While either
  count moves, the agent signs the degradation `execpol_capacity` (held five
  minutes at least: one record per episode), so that refusals the capacity
  caused are told apart from the policy's. The e2e fills the maps itself
  (`debug-execpol-fill`, `debug-trigger` builds): bounded, deterministic.
- Lot 325 (the re-check of #546, R6): `EXECQ_CAND`, the candidate from the
  exec's pass to its `sched_process_exec`, is a plain hash (4096 entries)
  — an LRU insert could evict an entry a preemptible program holds and give
  its memory to another task's candidate. Its entries go at
  `sched_process_exec`, at the task's next exec, at a refused pass, and when
  the kernel frees the task: the LSM `task_free` program `nn_task_free`
  (also the FIM sensor's buffers, kept for the task's life since lot 325,
  and `EXECPOL_ENV_SEEN`, the first pass's note for the post-commit check).
  The review of #547 (F4): a failed exec's candidate stayed until the
  task's next exec or its end, and one user's idle threads (each failing an
  exec) filled the map for everyone: it goes when the kernel frees the
  exec's file (the LSM `file_free_security` program `execq_exec_failed`,
  which removes the task's candidate naming that inode); each share holds
  at most 1024 candidates (`EXECQ_CAND_UIDS`) — the re-check of #547 (G5):
  it was the uid's, and four subuids of one login filled the map. Lot 332
  (the re-check 2, G5): an account's share
  (`task_scratch::nn_share_key`, `wire::execq::share_key`) — its uid in
  the initial user namespace; in a user namespace, the account that made
  the outermost one (nested namespaces included), or that namespace's
  inode number when root made it (one share per system container). The
  login uid it was keyed by is set to any value, without a privilege, by a
  task that has none (a service, a container under a root daemon): one
  share per child. The review of #551 (F1): a user with an `/etc/subuid`
  range takes any uid of it as its real uid in the initial namespace (a
  binary owned by that subuid made setuid inside a namespace the user
  made, run outside it, then `setresuid`) or as the creator of a new
  namespace — 65,536 keys, about 67 of which filled the map. The uid or
  the creator is first looked up in the host's ranges, which the agent
  publishes (`SHARE_SUBUID`, an LPM trie of 16,384 entries,
  `nn_linux::sensors::share_subuid`, read again within 2 s of a change to
  `/etc/subuid` or `/etc/passwd`): a uid of a range is its owner's share;
  one of the ranges' span no single owner is known for (an owner
  `/etc/passwd` does not resolve, two users' ranges overlapping, a gap, a
  range past the trie's room) is the overflow row's, never a share of its
  own; an unreadable `/etc/subuid` puts every uid from 65,536 up there.
  What a task can still choose: a namespace root made is one share each,
  so a setuid-root helper that makes one per run gives its caller one
  share per run, and ranges served by NSS (`subid:`) are not published.
  The shares the rows' map has no room for share one overflow row under
  the same cap, and every share's entries are counted together (lot 332,
  the global cap): past the map's room less one share's (3072), a share
  holding 16 candidates or more takes no more, so the shares at their cap
  leave room for 64 others — a bound on greedy shares, not on their
  number: the map's room is that. The map full, the oldest candidate still in it
  — made at least a second ago (its exec is stuck: no program of its task
  holds it) — goes for the new one (`CAND_EVICTED`); lot 332: found by
  walking the map (`bpf_for_each_map_elem`, every entry, on the full map's
  path only), where it was the first 8 slots of a ring of the candidates
  in the order they were made, which failed execs (a candidate made, then
  removed with its file) filled with gone ones. None old enough, the new
  one is dropped (`CAND_DROPPED`). Either is an exec that ran unheld — counted in
  `not_held` and in the signed `exec quarantine fail-open` degradation (one
  per ten minutes while they move). `task_free` is attached
  once per object and the agent tracks "attached", not "loaded" (F9: a load
  whose attach failed made the next caller skip it, silently).
- The review of #547 (F6): the FIM sensor's buffers (`OPEN_TASK`, 65,536
  tasks) — each share (the account's, the re-check's G5 and lot 332, as
  above) holds at most 16,384 (`OPEN_TASK_UIDS`), and past 49,152 entries
  in all no more than 256 (the global cap); past it, or the
  map full, the open is judged in a buffer made and removed in the run
  (`OPEN_TASK_RUN`, the cost before lot 325: an insert and a delete), and
  counted (`nn-admin status`: `open_sensor_per_call_total`); only with no
  room in either is it the plain observer (counted as a ring drop). The
  uids' shares are plain read-modify-writes (the eBPF crate has no atomics:
  the re-review of #494, R1), so two runs that update one uid's share at the
  same instant can lose an update: the agent recounts the shares from the
  entries — the candidates' every 30 s, the FIM buffers' when opens went to
  a run's own buffer (at most every five minutes) — and removes the rows of
  uids that hold nothing.
- Lot 325: the post-commit check `execpol_env_commit` (§5) and its maps:
  `COMMIT_ENV` (the review of #547: one entry per CPU, sound there — the
  tracepoint runs with preemption off — and out of a flood's reach; it was
  the task's `EXECPOL_ENV` entry), `EXECPOL_ENV_SEEN` (keyed by
  `task_struct`, written for what the first pass judged and let through).
- 5.15: every loop is in a global function verified on its own (lot 325:
  `nn_env_scan` 128 rounds of `nn_env_round`'s 128 steps of `nn_env_step`'s
  64 variables (and 64 stops at judged names), the judged names in
  `nn_env_var`; the post-commit check's
  `nn_env_region` / `_round` / `_step`; the review of #547: a judged
  name read whole by the scan itself (`nn_env_pending`), its value by
  `nn_env_judge` in 255-byte reads (`nn_env_chunk`, each separator and `/`
  in `nn_value_end` / `nn_value_slash`), the rounds and steps calling
  nothing below them — inline, the judgment multiplied the loops' states
  past the verifier's million instructions (7.0 and 5.15 refused
  `exec_check_lsm`); the re-check of #547 (G6): the environment in its own
  program, `exec_env_lsm` (processed on 5.15: 292,123, `exec_check_lsm`
  141,595; 6.8: 268,903 and 87,890; 6.12: 269,131 and 96,410; 7.0: 330,221
  and 87,234); the deepest
  call chains 384 (`exec_check_lsm`) and 352 (`exec_env_lsm`) of 512 bytes
  of stack,
  `nn_execpol_tier` 8 hops,
  `nn_map_classify` the 64-level walk); findings are kept in map memory, not
  registers, so the loop states do not multiply; helper reads only
  (`bpf_probe_read_user{,_str}`, `bpf_get_current_ancestor_cgroup_id`, 5.10+
  for tracing programs); no `bpf_loop`. Every program loads on 5.15, 6.1,
  6.8 and 6.12 (`deploy/lab/nn-lab.sh verifier-check`, 2026-10-21); the
  first build's growth of `exec_check_lsm` did not on 5.15 and 6.1
  (KERNEL_COMPATIBILITY "Older verifiers", rule 9), and the agent fell back
  to `sys_enter_execve`, with no exec refused. Owed: RHEL 9; the per-exec
  cost (expected: two helper reads per variable at the exec's first pass,
  a hash insert and remove for the walk (and one for an environment with a
  finding), a hash lookup and two map reads per classed exec, a cache
  lookup per executable mapping).
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

The environment variables are set in a drop-in of the agent's unit
(`/etc/systemd/system/northnarrow-agent.service.d/<name>.conf`,
`Environment=NN_EXEC_POLICY=audit`), written inside a trusted-installer
window (`nn-admin trusted-installer-grant`; outside one the directory
refuses it), then `systemctl daemon-reload` and a restart of the agent
inside the window. Lot 273d: the window's close keeps the drop-in and
write-protects it, and the agent signs each `NN_` setting it gives
(`own_dropin_setting`; `NN_EXEC_POLICY=off` and the other switches that
weaken the agent are a High `own_dropin_weakening`); a loader variable
(`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`) in it gets the drop-in
quarantined.

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
