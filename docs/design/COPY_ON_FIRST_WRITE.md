# Copy on first write — ransomware rollback for Linux

**Status:** EXPERIMENTAL (lab PR 222). Implemented in `agent/src/cow/`, off
by default: it runs only on a host with the `20-cow-guard.conf` drop-in and a
signed `/etc/northnarrow/cow-guard.local` that says `enabled = true`.
**Capabilities:** C19 (rollback and remediation), C17 (response on processes
and files). **Levels unchanged** until the lab has run
(`deploy/lab/cow/cow-check.sh`): C19 1, C17 2.

## 1. What it does

Before a process whose trust is not established opens an **existing file
for writing** inside a **protected scope**, the agent takes a cheap copy of
the file's current content. When the ransomware response kills the process
tree, everything that tree rewrote can be put back from those copies — by a
signed admin verb, or on its own when the policy says so — and every file
put back is a signed audit row.

```text
 writer: open("doc.odt", O_RDWR)                   agent (nn-cow-* threads)
   │                                                 │
   │ kernel: LSM file_open, then FAN_OPEN_PERM ─────▶ reader: own thread? regular,
   │ (the open waits; O_TRUNC not applied yet)       │ non-empty? /proc/<tid>/syscall:
   │                                                 │ a write? trusted writer? in scope?
   │                                                 │ already copied for this writer?
   │                                                 ├─ no copy needed ──────▶ FAN_ALLOW
   │                                                 └─ copier: FICLONE (reflink) or
   │                                                    bounded copy ≤ 16 MiB, ≤ 50 + 25 ms ─▶ FAN_ALLOW
   │◀──────────────────────── open returns ──────────┘    │
   │ writes (encrypts)                                    └─▶ index worker: SHA-256,
   │                                                         index.jsonl, budget, LRU
   ▼
 response kills the tree (COMBAT NEUTRALIZE, or NN-L-FIM-010's KillProcessTree)
   └─▶ auto_restore = true: restore its files ── or ── `nn-admin remediate ransomware --pid N`
```

The guard **never denies** an open in this lot and **never blocks
indefinitely**: every permission event is answered `FAN_ALLOW` by exactly one
party — the reader, the copier, or a backstop. Counted from when the reader
reads the event (time in the kernel's queue is not counted): an open the
guard copies for is answered at the latest `event_budget_ms` + 25 ms (the
backstop's 20 ms grace and 5 ms poll: 75 ms by default), and a copy the
backstop had to answer is discarded; any other open is answered once the
reader has decided, with no deadline of its own but the 3 s stall (§3).

## 2. Mechanism

### 2.1 fanotify permission events

- One group: `fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_REPORT_TID,
  O_RDONLY | O_LARGEFILE | O_CLOEXEC)`. Permission events need
  `CAP_SYS_ADMIN`, which the agent's unit drops on purpose: the drop-in
  `deploy/systemd/20-cow-guard.conf` (installed by `install.sh --cow-guard`,
  checked by self-integrity like the Debian one) adds it, with `CAP_CHOWN` and
  `CAP_FOWNER` for the restore. The blast radius of a compromised agent grows
  with it; that is the price of the experiment and why it is opt-in.
- `FAN_OPEN_PERM` is raised in the opening task after the LSM `file_open`
  hook and before the open returns — before `O_TRUNC` is applied (the
  truncation runs after `vfs_open`). The copy taken while the task waits is
  the content before the first write.
- **Marks** (per scope, `mark=`):
  - `dirs` (default): an inode mark with `FAN_EVENT_ON_CHILD` on every
    directory of the tree (same filesystem, no link followed, the journal
    skipped), at most `max_dir_marks` (8192), walked again every 60 s for
    new directories. Only opens in the tree reach the agent.
  - `mount` / `filesystem`: `FAN_MARK_MOUNT` / `FAN_MARK_FILESYSTEM`,
    refused unless the scope is a mount point (so `/` is never marked by
    accident: every open on the host would go through the agent). The
    `filesystem` mark sees every mount of the filesystem (containers'
    bind mounts too); `mount` only that one.
  - Marks are placed through `/proc/1/root/<scope>`: the agent runs in a
    mount namespace of its own (`ProtectSystem=strict`), and a mount mark on
    its own copy of a mount would see none of the host's opens.
  - With `mount` or `filesystem`, the journal (by default under the scope)
    lies under the mark too: the guard's own opens of its copies and of
    its index are permission events its reader answers (an event of its own
    process, allowed first thing). The reader takes the journal's and the
    index's locks, so no thread of the guard opens a journal file while
    holding one of them — a copy is opened and hashed, and a compaction's
    new index created, with no lock held — or the guard would wait on itself
    until the 3 s stall closed its group (lab PR 222's first version did).
    `agent/tests/cow_privileged_e2e.rs` runs the guard on a `mark=mount`
    scope.
- **The writer's flags.** The event metadata carries no open flags, and
  the event's descriptor is the agent's own open (its `fdinfo` shows
  `O_RDONLY`), so neither `f_flags` nor `/proc/self/fdinfo` says how the
  writer opens the file. The guard reads `/proc/<tid>/syscall` of the
  blocked thread (`FAN_REPORT_TID`): the syscall number and arguments from
  the registers saved at entry — not from the task's memory, so another
  thread of the writer cannot rewrite them. `open`, `openat`,
  `open_by_handle_at`: the flags register (`O_RDONLY` without `O_TRUNC` is a
  read; anything else a write). `creat`: a write. `openat2` (flags in user
  memory, a race away from a lie) and anything the table does not know (an
  `io_uring` open, a 32-bit task, a task the kernel reports `running`):
  counted as a write. Reading it needs `CAP_SYS_PTRACE` over the task (the
  unit has it); with Yama's `ptrace_scope=3` it fails and every open of an
  untrusted writer is copied — slower, not a hole. `status --key` says
  which (`open flags from`).

### 2.2 Who is copied for (the trust filter, `cow/trust.rs`)

Trust is decided by what the kernel executed — `/proc/<pid>/exe` and, for an
interpreter, the script it runs — on the posture's ordered lineage walk
(`AuthSessionTracker::lineage_identities`, POS-003), never by `comm`. A
writer is **trusted** (not copied) when:

- it belongs to a package transaction run by root
  (`AuthSessionTracker::in_package_transaction`), or
- it is a **trusted writer** — `vim`, `vim.basic`, `vim.tiny`, `vim.gtk3`,
  `nvim`, `nano`, `emacs`, `gedit`, `gnome-text-editor`, `kate`, `mousepad`,
  `soffice.bin`, `git`, plus the overlay's `trusted_writer` lines — matched by
  `ExecIdentity::is_client` (the executable in a root-owned system tree), and
  no ancestor is **foreign**: every hop up to PID 1 is a program root
  installed (`ExecIdentity::is_installed_program`) or an installed
  interpreter running no named script (an interactive shell, `sh -c`).

Everything else is copied for: generic tools (`cp`, `dd`, `tar`, `rsync`,
`openssl`, `gpg`, `sed`) are what an intruder rewrites files with, a script
from a home directory or a binary from `/tmp` is foreign, and an unreadable
lineage fails toward copying. Interpreters are refused as trusted writers
(`python3` with no script would trust every `python3 -c`). Verdicts are
cached 10 s per (pid, start, exe).

### 2.3 Copy on *first* write

One copy per file and writer process. A second writer of a file unchanged
since the last copy (same size, mtime, ctime, birth time) shares that copy
instead of taking another (`linked`). A copy:

1. `FICLONE` into a new object of the scope's journal (`reflink`): shared
   extents, constant time, the filesystem copies a block only when the
   writer changes it. Needs the same filesystem and mount — hence a journal
   per scope on the scope's filesystem, both reached through the host's
   mount namespace.
2. Else, up to `copy_cap` (16 MiB): `copy_file_range` in 1 MiB steps
   (`pread`/`write` when it is refused), the deadline checked between steps.
   A copy that misses its deadline, or whose source changed while it ran (a
   writer that opened the file earlier), is deleted.
3. Else not protected (`over_cap`, signed).

The SHA-256 of the object is computed by the index worker **after** the open
was answered.

### 2.4 The journal (`cow/journal.rs`, `cow/index.rs`, `cow/protect.rs`)

```text
<scope>/.northnarrow-cow/            0700 root   MUTATE | NOCREATE
<scope>/.northnarrow-cow/objects/    0700 root   the copies (0600)
<scope>/.northnarrow-cow/evidence/   0700 root   encrypted files a restore moved aside
<scope>/.northnarrow-cow/index.jsonl 0600 root   MUTATE | WRITE
```

- **Index** (`index.jsonl`, one record per line, replayed at start):
  objects (id, bytes, method, time) and entries — path, device, inode, size,
  mtime, ctime, birth time, mode, owner, SHA-256, the writer (pid, start in
  ticks, program) and its lineage, the time, the method. Orphan objects are
  deleted at start; the file is compacted when it grows past four times its
  live records.
- **Budget** per scope (`budget=`, default 1 GiB), each copy counted at its
  logical size — a reflink too, since an attacker who rewrites the whole file
  unshares every block. A copy that does not fit evicts the least recently
  used objects of the scope, **never one used less than the eviction floor
  ago** (`eviction_floor_minutes`, 15; an object's use is its copy or a
  later writer sharing it): during an attack the earliest copies are the
  ones that matter, and an attacker who churns files first must not push
  them out. When the room cannot be made the copy is refused (`budget_full`,
  signed). No copy either under `min_free_percent` (5 %) free.
- **Retention** 24 h (`retention_hours`) from an object's last use (its copy
  or a later share); the evidence files by their own mtime.
- **Anti-tamper**: the three directories take the flags of the agent's own
  directories in `PROTECTED_INODES` (MUTATE | NOCREATE — no unlink, rename,
  chmod, chattr or xattr of them and no new entry in them from outside the
  agent's family, outside a trusted-installer window), `index.jsonl` MUTATE |
  WRITE. The objects are not registered one by one (the map has 1024 slots
  for the whole agent): root can still open one for writing — its SHA-256
  then no longer matches the index and the restore refuses it
  (`journal_corrupt`) instead of writing it back. Without the anti-tamper
  hooks (no BPF LSM, `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`) the guard runs with
  a signed `journal_unprotected`.

### 2.5 Restore (`cow/restore.rs`, `cow/store.rs`)

Selected entries: those of a process tree (`--pid`: the writer is the
process, or the process was an ancestor when the copy was taken; a pid that
names several processes in the journal is refused — narrow it with
`--since`), and/or copies taken since a time; with both, an entry must meet
both. `--since` alone selects every writer's copies taken since then — for
each file the earliest copy at or after that time, which is the content
before the attack only if the attack began after it. One entry per file: the
earliest selected, the content before the tree's first write. A file whose
writer still runs is skipped. Then, per file:

1. copy missing or SHA-256 mismatch → **refused** (`journal_corrupt`);
2. nothing at the path (renamed `.locked`, deleted) → **recreated** (mode,
   owner, mtime of the original); the attack's renamed copy of that inode, in
   the same directory, is moved to `evidence/` unless someone else wrote it;
3. not a regular file now → **kept both**;
4. content already the original (whatever the inode) → **unchanged**;
5. another file at the path (other inode, or the inode number reused — the
   birth time differs) → **kept both**;
6. a write-open of the inode after the copy by a process outside the attack
   (a trusted editor or anyone else; the guard records them) → **kept both**;
7. the copy predates this run of the guard (the agent restarted: write-opens
   in between were not seen) and the file was modified since → **kept both**;
8. otherwise → **restored in place** (same inode, links, xattrs; content and
   mtime of the original).

"Kept both" writes the original beside the file (`<name>.nn-restored-<entry>`,
new, never over anything) and reports both: a restore does not overwrite a
file someone else changed after the attack **as far as the guard saw it**.
The write-opens of rule 6 are kept in memory (the last 8 per inode, one per
writer) and lost at a restart, after which only the mtime is compared (rule
7); a file of 0 bytes is never copied, so its write-opens are not recorded.
Paths are reached with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
RESOLVE_NO_XDEV)` from the scope's root: a directory swapped for a link to
`/etc` is refused, nothing is written through it.

- **Admin**: `nn-admin remediate ransomware --pid <pid> | --since <ts>
  [--dry-run] --key <key>` (`--pid` and `--since` together narrow each
  other) — `OperationCode::RemediateRansomware` (26),
  `AdminMessage::RemediateRansomwareRequest/Response` (appended: indices 56
  and 57, after lab PR 217's signed unlock pair), role
  `response-manage`, 1-of-N. One signed `cow_restore` row per file, then the
  verb's own `remediate_ransomware` row. The reply lists up to 120 files.
- **Automatic** (`auto_restore = true`, default **false**; never in
  detect-only): when the COMBAT ladder's NEUTRALIZE contains a tree
  (`CombatLadder::with_neutralize_hook`), or NN-L-FIM-010's
  `KillProcessTree` kills its writer, and a ransomware signal named one of
  those processes — a mass rewrite of existing files (`Event::MassWrite`
  with `overwrites`) or NN-L-FIM-010 — the guard restores that tree's files
  on a thread of its own, once the processes are gone. With the policy off it
  signs `cow_guard` `restore_available` and logs the command.

Note the posture's design: ransomware alone (one evidence class) raises
ENGAGED, not COMBAT (BUG-032, POS-001), so it is not killed by the ladder —
the copies are there, the restore is the operator's signed verb. A
corroborated episode (a second evidence class) or a decisive one reaches
NEUTRALIZE and, with the policy on, the automatic restore. With
`auto_restore = true` NN-L-FIM-010's kill restores without any COMBAT;
`auto_restore` is off by default.

## 3. Threat model

**Protects against**: a process the agent does not trust — a user's
ransomware, a script from a home directory, a dropper from `/tmp`, a root
process run outside a package transaction — rewriting existing files in a
protected scope through an open made while the guard watches, up to the
journal's budget, within the retention. Root cannot delete the copies or
rewrite the index while the anti-tamper hooks run; a corrupted copy is
refused at restore, never written back.

**Cannot protect** (each one stated, none silent):

- **Files over the copy cap on a filesystem that cannot reflink** (ext4,
  tmpfs): over 16 MiB they are not copied (`over_cap`). On XFS
  (`reflink=1`), btrfs, bcachefs the cap does not apply — only the budget.
- **Writers already trusted**: a trusted editor, `git`, a package
  transaction are never copied for. A compromised trusted writer, or an
  attacker driving one from a neutral hop (`curl … | sh` starting
  `vim -es`, a shell with no script), rewrites files without copies.
- **A root attacker with the anti-tamper hooks off** (no BPF LSM, the
  degraded opt-in, or inside a signed trusted-installer window) can delete
  the journal. With them on, root can still corrupt an object's content
  (refused at restore) or fill the budget with its own copies first (the
  eviction floor keeps the earliest).
- **mmap writes**: `FAN_OPEN_PERM` sees the **open**, not the writes. A
  shared writable mapping needs a descriptor opened for writing, so a file
  encrypted in place through `mmap` is copied at that open like any other —
  as long as the open happened while the guard watched. A descriptor opened
  **before** (before the agent started, before a directory was marked,
  inherited from or passed by a process opened earlier) is not seen: its
  writes and mappings are not protected.
- **Encrypting into new files**: ransomware that writes `x.enc` and then
  unlinks `x` or renames over it never opens `x` for writing — no copy. An
  `unlink`/`rename` permission event does not exist in fanotify; that needs
  a pre-delete hook (BPF LSM `inode_unlink`/`inode_rename` keeping a link),
  a follow-up. So does `truncate(2)` by path (no open).
- **What the guard does not see**: a directory created after the last
  rescan (60 s), past the mark cap, on another filesystem below the scope
  (`mark=dirs` stays on the scope's filesystem), opens through another mount
  of a `mark=mount` scope (use `filesystem`).
- **Degradations, signed** (audit op `integrity_drift`, kind
  `subsystem_degraded`, `subsystem: cow_guard`; per reason the first one at
  once, then a summary at most every 10 min, checked each minute). They go
  through the guard's work queue (4096): on a full queue, without an audit
  log, or at a stop before the next summary, they can be lost. Some skips
  are counted but not signed (a path that cannot be resolved, a file larger
  than the budget, a source that changed during its copy, a copy the
  backstop answered). Reasons: `event_budget` (a copy past its budget: slow
  disk, large file), `budget_full`,
  `low_space`, `queue_full` (more than 256 copies waiting), `queue_overflow`
  (the kernel's fanotify queue, 16384 events: the opens beyond pass
  unchecked), `over_cap`, `copy_failed`, `mark_cap`, `scope_unmarked`,
  `journal_open`, `journal_unprotected`, `start_failed`, `reader_stalled`,
  `reader_ended`.

**Safety of the host.** An open the guard copies for waits at most the
event budget + 25 ms after the reader read it (the backstop's grace and
poll); any other open, until the reader has decided. The reader thread
touches `/proc` and the event's
descriptor only — never a file on a marked filesystem, whose open would wait
on the reader itself; the agent's other threads' opens reach it as events of
its own process and are allowed first thing. If the reader makes no
progress for 3 s the backstop closes the group: the kernel allows every
pending and queued open and generates no more events (`reader_stalled`, the
guard off). An agent that exits or dies releases the group the same way.
`mark=dirs` keeps the host's other opens out of the agent entirely.

## 4. Configuration (`cow-guard.local`, signed)

```text
enabled = true
scope = /srv                                  # mark=dirs, budget=1GiB
scope = /home mark=dirs budget=4GiB
scope = /mnt/data mark=filesystem budget=8GiB journal=/mnt/data/.nn-cow
copy_cap = 16MiB
event_budget_ms = 50                          # 5..=500
retention_hours = 24                          # 1..=168
eviction_floor_minutes = 15
min_free_percent = 5
auto_restore = false
trusted_writer = rsync                        # added to the built-in list
max_dir_marks = 8192
copiers = 2
```

Stored with `nn-admin config overlay set cow-guard --file F --key K`
(`config-manage`), read at the next agent start through the overlay gate
(`OverlayKind::CowGuard`, 12; the file and its `.sig` protected like the
other overlays). The parser is strict: an unknown key, a scope that is
relative, `/`, overlapping another or under the agent's own directories
(`/etc/northnarrow`, `/var/lib/northnarrow`, `/run`, `/proc`, `/sys`,
`/dev`, `/boot`) refuses the whole file — the guard then reports `failed`.

Enable: `sudo deploy/install.sh --upgrade … --cow-guard` (the drop-in), then
the signed overlay, then restart the agent. `nn-admin status --key` shows
the guard (`copy on write : running`), its scopes, copies, skips by reason
and the answer latencies. Disable: `enabled = false` (or remove the
overlay in a trusted-installer window) and `--no-cow-guard`. The journals
stay on disk after an uninstall: remove `<scope>/.northnarrow-cow` by hand
once the agent is gone (its directories are protected only while it runs).

## 5. Overhead

`agent/examples/cow_bench.rs` opens, rewrites and closes N files and times
the `open(2)` alone and the whole sequence; `deploy/lab/cow/cow-check.sh
bench` runs it outside and inside a scope on the guest (guard off / on).
`--simulate-copy` does in-process what the guard does on the copy path (the
`/proc` reads of the checks, the copy into a journal, the SHA-256) without
fanotify or root.

Measured on the development host (WSL2 6.18, ext4, `--simulate-copy`,
release build; the fanotify round trip is not in these numbers):

| file size | `open(2)` baseline p50 | copy path p50 (mean, p99) | SHA-256 afterwards (index worker) |
|---|---|---|---|
| 4 KiB | 2.7 µs | 86 µs (99, 275) | 20 µs |
| 64 KiB | 3.1 µs | 116 µs (134, 376) | 53 µs |
| 1 MiB | 4.5 µs | 585 µs (678, 1501) | 593 µs |

Expected on the guest, to be measured with `cow-check.sh bench` (the
check plan records it): every open in a marked directory (reads included)
pays one fanotify round trip — the reader's wake-up, `fstat`, the
`/proc/<tid>/syscall` read, the answer — of the order of 10–40 µs; a write by
an untrusted process adds the trust walk (cached 10 s) and the path lookup;
its first write of each file adds the copy (above, or a few tens of µs for a
reflink on XFS). Later writes of the same file by the same process pay the
round trip only. Opens outside the marked trees pay nothing with
`mark=dirs`. `status --key` reports the measured averages and maxima of both
paths (`open latency`).

## 6. Records

| Row (`op`) | When |
|---|---|
| `cow_guard` `started` | the guard runs: scopes, marks, copy method, budgets, flags source |
| `cow_guard` `restore_available` | ransomware neutralized, copies held, no restore on its own |
| `cow_guard` `auto_restore` | an automatic restore ran (totals) |
| `cow_restore` | one per file a restore attempted: path, action, entry, SHA-256 before and after, the writer, by whom |
| `remediate_ransomware` | the admin verb (pid, since, dry run, totals), after its files' rows |
| `integrity_drift` `subsystem_degraded` (`subsystem: cow_guard`) | a degradation (§3): the first per reason, then a summary at most every 10 min |

## 7. Follow-ups

- Deny mode (refuse a write-open whose copy could not be taken) — after the
  lab has measured the false-positive cost.
- Pre-delete protection (`inode_unlink` / `inode_rename` keeping a link) for
  the encrypt-into-new-file shape and rename-over.
- The writers' flags from the BPF LSM `file_open` hook (a per-task record
  read at the permission event) instead of `/proc/<tid>/syscall`.
- NN-L-FIM-010 matches the ransomware extension on a rename's destination
  path, which the drain resolves to the destination *directory*: a watched
  `x` renamed `x.locked` in place may not match. To be checked in the lab
  (the check plan says how); the automatic restore does not depend on it.
