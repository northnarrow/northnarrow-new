# Ransomware recorded on its own evidence, security tools watched (lab PR 225)

Countermeasures CM-16 (part) and CM-18 of the Wave 4 malware matrix;
capabilities C14 (behavioural detection), C17 (response on processes and
files), C19 (rollback: a kill gives the copy on first write of lab PR 222
something to restore).

**Held by the decision of 21/10/2026.** No new destructive automation is on
by default until the signed per-rule response policy (Phase 2) can turn it
on rule by rule. The kills this lot adds — NN-L-IMP-001's of the actor's
tree, NN-L-EVA-001..004's of a staged program that asked, NN-L-FIM-010's
for a rename seen only as a watched directory's new entry — and the
posture's COMBAT on `RansomwareEncryption` without corroboration are in the
code, each behind a switch that is off by default
(`agent/src/decision/response_policy.rs`,
`common::posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`). Until it
is on, a verdict keeps its severity and its signed record with action
`Log`, its reasoning saying what was held back, and `RansomwareEncryption`
needs corroboration like every other heuristic (ENGAGED alone). The text
below describes the responses the switches hold.

Before this lot a ransomware run — mass rewrites of existing files — only
raised the posture's mass-write arm (`ConfirmedIntrusion`, a
`NeedsCorroboration` signal): ENGAGED, no verdict, the encrypting process
left running. NN-L-FIM-010 named the destination *directory* of a rename,
so `x → x.locked` of a watched file never matched. No rule saw a burst of
renames to a new extension, and nothing saw auditd, the firewall or an EDR
agent being switched off.

## 1. The decisive ransomware signal (NN-L-IMP-001)

### Four shapes, each measured where it is cheap

| Shape | Sensor | Threshold (per process unless said) |
|---|---|---|
| (a) rewrites of existing files | `file_open` LSM, mass-write counter (`MASS_OVERWRITE`, existing) | 20 write-opens of existing regular files of ≥ 4 KiB in 60 s; or 40 by one cgroup's processes (each ≥ 3) |
| (b) ciphertext-like content | userland sampling when (a), (c) or (c′) is read | ≥ 2 of up to 4 files (the one named, siblings changed in the window; for (c′) the copies only) with Shannon entropy ≥ 7.5 bits/byte in the first 4 KiB block or a middle one, and no known container signature |
| (c) renames to a new extension | `inode_rename` LSM, new counter (`MASS_RENAME`) | 20 renames of regular files to **one** new extension in 60 s, the extension appended to the whole old name or replacing the old one; then, in userland, the encryptor's shape: half or more appended, or ≥ 3 changes of the original extension, or an extension of NN-L-FIM-010's list |
| (c′) copies under a new extension | userland, when (d) is read | a copy named the deleted original's name with an extension appended exists (the new files' extension, else any: the crossing write may be a ransom note), and (b) holds on the copies of that shape — files `<original>.<suffix>` whose original is gone, changed in the window, in its directory, then below and beside it (≤ 4096 entries looked at; never below a world-writable sticky directory such as `/tmp` nor beside a directory in one) — never on the originals still waiting beside them |
| (d) deletion of originals after writing new files | `inode_unlink` LSM, new counter (`MASS_UNLINK`) | 20 unlinks of regular files of ≥ 4 KiB in 60 s, by an actor that crossed the new-file mass-write threshold in the window |

**Any two distinct shapes within 120 s (two kernel windows) for one actor →
Critical, `KillProcessTree` of the actor (held: a record until the per-rule
policy turns it on), and the posture's `RansomwareEncryption` (COMBAT; held:
it needs corroboration until then).** One shape keeps the level it had: (a)
raises the mass-write arm (ENGAGED) and no verdict; (c) alone is
NN-L-IMP-002 (Log, High); (d) alone is nothing (`rm -rf`, a cache sweep).
A burst re-crosses its threshold once per kernel window while it lasts, so
a long encryption keeps its shapes fresh.

Sampling at write-close is not possible host-wide: the only close hook
(`file_free_security`) watches the FIM inodes, and a BPF program cannot read
file content. The agent samples in userland when it reads a burst record,
without following links or blocking (`O_NOFOLLOW | O_NONBLOCK`), through
`/proc/1/root`, keeping nothing of the content. "Over low-entropy
originals" cannot be measured after the fact (they are overwritten or
renamed): the absence of a format header (gzip, zstd, zip and the office
formats, media, SQLite and its WAL, qcow2, LUKS, ELF, OpenPGP, age,
git-crypt, borg, browser caches, …) stands in for it.

The rename counter never counts the renames of an atomic write — a
temporary file renamed to its final name (`x.py.dpkg-new → x.py`, rsync's
`.x.c.AbC123 → x.c`, `sed -i`'s `sedAbc12 → x.conf`, `x.pyc.140234 →
x.pyc`) — nor a rotation's digits (`syslog → syslog.1`), a move under the
same name, or a random new name.

### Who is judged: trust by identity, package ownership and lineage

The trust model of copy on first write (lab PR 222), with the package
database in place of its list of editors. A writer's bursts never count when
it belongs to a **package transaction run by root**, or when it is a
**packaged program** — its executable (for an interpreter, the script it
runs) is listed by dpkg or rpm (snap and Nix store images are owned by
construction; a host with neither database falls back to a root-owned system
tree) — **and no hop of its lineage is foreign** (every ancestor up to PID 1
an installed program or an installed interpreter running no named script).
Never by `comm`, never by a name list.

That is why `rsync`, `tar`, `git`, `cp`, compilers, `apt`/`dpkg`, a packaged
backup agent or database, started by a person or by a unit, never trip it.
What is judged: a binary no package installed (`/root/x`, `/opt/x`,
`/usr/local/bin/x`, `/tmp/x`), an interpreter running an inline program or
an unpackaged script, a packaged tool started by such a program, an unknown
lineage.

Shapes add up under one process: the writer, or the payload whose forked
workers it is. A packaged tool under a foreign script counts for itself —
two tools a user's script runs one after the other are two bursts — and the
kill targets the nearest foreign program (the script, the payload).

### Decision against BUG-032 and POS-001

- **BUG-032** made every heuristic COMBAT signal need a second, distinct
  signal: a single blunt count caps at ENGAGED. The ransomware combination
  is not one blunt count: it is two independent observables of the same
  actor — content, names, deletions, rewrites — from a writer no package and
  no installed lineage vouches for. It is its own corroboration, so
  `RansomwareEncryption` is meant to be `Confidence::Decisive` and reach
  COMBAT alone — held, off by default, until the signed per-rule policy
  (`RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`): until then it is
  `NeedsCorroboration`. The single shapes keep `NeedsCorroboration`.
- **POS-001** locks COMBAT (no decay, signed release, isolation allowed)
  only on evidence an unprivileged user cannot produce. Any user can
  encrypt their own files, so the combination **does not lock**:
  `TriggerType::locks_combat()` (kernel denial, control-surface tamper) now
  decides the lock, not `Confidence::Decisive`. COMBAT on ransomware is
  unlocked: the ladder contains at the process level (NEUTRALIZE kills and
  quarantines the offender's binary; ISOLATE is refused) and the posture
  decays to ENGAGED after 30 min without a new signal. It locks only as
  POS-001 says for every signal (root's change outside an administrator's
  session, corroborated in its scope).
- The rule's kill does not wait for the ladder: NN-L-IMP-001 kills the
  actor's tree when the second shape is read — once the per-rule policy
  turns its switch (`IMP_001_KILL`) on.

### Expected false positives, and residuals

- An unpackaged program that rewrites twenty documents a minute with
  compressed data that carries no header — an IDE installed from a tarball
  rewriting its caches, a self-built backup tool — meets (a)+(b). Not seen
  in the lab; the lab's baseline hour on the desktop profile is the check.
- A user's own script that renames twenty files by appending one extension
  and rewrites twenty more within two minutes: (a)+(c).
- A user's own script that encrypts twenty files a minute into copies with
  no known format header and deletes the originals (`openssl enc`,
  `ccrypt`): (c′)+(b)+(d).
  The legitimate copy-then-delete shapes are one shape, (d), whoever runs
  them (`agent/src/impact/tests.rs`,
  `benign_copy_delete_shapes_are_not_decisive`): `mv` across filesystems
  and `rsync --remove-source-files` leave no copy beside the original; a
  package unpack (`x.dpkg-new`), compiler temporaries, an editor's safe
  write (`x.tmp`), `git gc` and log rotation with compression
  (`x.log.1.gz`, `.zst`) leave none, or copies that are plain, compressed or
  of another known format.
- Copy-delete's (b) was first sampled like (a)'s, on the files beside the
  copy changed in the window. In the lab (MS-23 copy-delete, debian12) the
  unlink crossing came at the 20th original with 280 originals written a
  minute before still beside the 20 copies: they filled the pick, one file
  of four sampled as ciphertext and NN-L-IMP-001 never fired. The copies
  are now what is sampled. (a)'s sampling keeps the siblings — a rewrite
  in place leaves no name that tells the rewritten files from the others —
  so an in-place run with no rename among originals changed in the last
  two minutes can miss (b) the same way: a residual (documents are rarely
  that fresh; (a)+(c) does not need (b)).
- The copy walk went below and beside the burst's directory whatever
  shared it (lab PR 232): a user's script with one plain copy in
  `/tmp/job` was decisive on another tree's fresh copies of ciphertext
  under the same suffix in `/tmp` — another user's or program's, or
  planted by anyone to have a benign job judged an encryptor. It no
  longer crosses a world-writable sticky directory (`/tmp`, `/var/tmp`,
  `/dev/shm`): not below one, not beside a directory in one, not into one
  found beside or below. A world-writable directory without the sticky
  bit (a `0777` share) is walked: that is where an encryptor goes.
  When the burst's own directory is a shared one (the copy in `/tmp`
  itself), only the copies owned by the uid the burst ran as count there
  (lab PR 238), the copy the record names included, checked again on the
  file opened: an encryptor's copies are new files, its own. Residual: an
  encryptor that runs set-uid (its files owned by another uid than the one
  the kernel records for the burst) has its copies in a shared directory
  left out.
- Residuals: an intruder in an interactive session who encrypts with
  packaged tools only (`openssl`, `gpg` from that session) is a trusted
  writer here; an encryptor that forks a new process every few files stays
  under the per-process rename and unlink counts (the cgroup window covers
  rewrites only); a random new name per file (no extension streak); a
  program loaded into a trusted process (`LD_PRELOAD`, CM-25).

## 2. NN-L-FIM-010: the destination is the file

The kernel now carries the renamed watched file's new leaf
(`FIM_RENAME_DEST_LEAF`) next to the destination directory's key; the drain
names `dir/leaf`, the directory being the watched one or the source's own,
and falls back to the entry of that directory that holds the renamed inode
(an older eBPF object, a leaf cut at 63 bytes). A rename inside a watched
data directory reaches the rules as the directory's `Created` of the new
name (`moved_in`), which NN-L-FIM-010 now reads too; when both records of
one rename reach it, one verdict. That moved-in match is new: its kill is
held (`FIM_010_MOVED_IN_KILL`, a Critical record), and a held moved-in
record does not hide the watched file's own `Renamed`, which kills as the
rule always meant to.

## 3. Security tools switched off (NN-L-EVA-001..004)

The list is content: `configs/security-tools.v1`, shipped like the other
`.v1` lists, but **not signed and with no operator overlay**: it is pinned
to the copy the agent was built with, compared byte for byte. A file that
differs is an ERROR and a signed `default_list_modified` and is never
applied — not even under `NN_OVERLAY_ALLOW_UNSIGNED=1`, which applies an
edited `.v1` of the lists that have an overlay; install.sh installs it;
PROTECTED_INODES write-denies it. An operator overlay of the list is a
follow-up. It names each
tool's class, units, processes and configuration paths, and the tools' own
switch-off commands. No tool name is in the code.

| Rule | Evidence |
|---|---|
| NN-L-EVA-001 | exec of `systemctl stop/disable/mask/kill/freeze`, `service … stop`, `invoke-rc.d`, `update-rc.d … disable/remove`, `chkconfig … off`, `rc-service … stop`, `rc-update del`, `/etc/init.d/<name> stop` naming a listed unit (`--user` excluded) |
| NN-L-EVA-002 | exec of a listed switch-off command, arguments in order and next to each other (`auditctl -e 0`, `-D`, `ufw disable`, `setenforce 0`, `nft flush ruleset`, `iptables -F`, `aa-teardown`, cloud-agent uninstallers); the program by its executable or its `argv[0]` (`iptables` is `xtables-nft-multi`); one record per command and process tree (the children of one parent) within 10 s — the first at once, the repeats counted (below) |
| NN-L-EVA-003 | a stop or end signal (INT, QUIT, ABRT, KILL, TERM, STOP, TSTP) to a listed tool's process, seen on `task_kill` and never refused — a shell's builtin `kill` included (`DEFENDER_PIDS`, filled from `/proc` at boot and from the tools' execs, each exec followed by `/proc` scans 0.3, 2 and 6 s later for the processes it forks — a `Type=forking` daemon such as Debian's auditd runs as a child of the exec'd process, which exits; PID 1, the tool itself and the agent excluded; one report a second per sender and target) — or an exec of `kill`, `pkill`, `killall` naming one |
| NN-L-EVA-004 | a change of a listed configuration file: FIM watches the files and, for a listed directory, the files it holds at boot (FIM does not enumerate a directory's children) |

High and recorded (`Log`); Low in a package transaction run by root, an
administrator's interactive sudo/su session or under a configuration-
management actor of `process-comm-allowlist`, and — the agent's own units
only (`northnarrow-agent`, `northnarrow-watchdog`: `stop`, `force-stop`,
`kill`, the restart a window grants) — inside a valid signed
trusted-installer window (decision of 21/10/2026): the record is written,
Low, its `sanction` field names the window (the signing key's id and the
deadline), and the posture does not move. Our window sanctions no other
tool (auditd stopped inside it is High), nor a disable or mask of our own
units; outside a window or once it has expired nothing changes (High, the
posture moves, the kill of a staged asker held behind `EVA_KILL`); `KillProcessTree` of the
program that asked when the lineage holds a program from `/tmp`, `/var/tmp`,
`/dev/shm` or a deleted or memory-only executable (a cryptojacking script) —
held (`EVA_KILL`, off by default): a High record until the per-rule policy
turns it on.
NN-L-EVA-002 coalesces: `ufw disable` runs `ufw-init`, which flushes and
resets each chain with an `iptables` or `ip6tables` exec of its own —
dozens of the same listed command in a second or two, one High record each
until then. The first is recorded at once (its reasoning says the repeats
are counted); a repeat by a child of the same parent within 10 s, at the
same level (sanctioned or not), is counted in the detection budget — the
next NN-L-EVA-002 record of that uid carries the count in
`suppressed_before`, the reporter's signed `detections_held` row names it
within 60 s — and is not recorded. Another tree, or the same one after the
window, draws its record. A finding whose lineage holds a staged program
(the kill path) is never coalesced.
The posture raises `DefenseImpairment` (ENGAGED, execution evidence that
corroborates a later heuristic of another kind) when the finding is not
sanctioned (coalesced repeats included). ATT&CK v20 (the ids of lab PR 221): T1685 Disable or Modify
Tools, T1685.004 for the audit system, T1686 for the firewall; tactic
Defense Impairment (TA0112).

Residuals: a unit stopped over D-Bus (`busctl`, `gdbus`) rather than by
`systemctl`; a signal to a tool's helper process that is not its listed
executable; a signal to a forking daemon in the first 0.3 s after its exec,
before the `/proc` scan registers its pid (a builtin `kill`; an exec of
`kill` naming it is still read); an edit of a configuration file created
after boot in a directory that was empty at boot is seen as its creation
only.

## 4. Records and status

Every verdict is a signed detection record. `nn-admin status --key`
(signed telemetry) shows the decisive assessments, the shapes counted, the
trusted bursts not counted, the entropy samplings, the security-tool
findings and the sanctioned ones, and the tools' processes watched
(`StatusResponse` fields appended at the end).

## 5. Lab

`deploy/lab/nn-lab.sh ransom-check` runs `deploy/lab/malsim/ransom-check.sh`
(MS-23 with the benign simulator `ransom-sim.py`, which refuses any path
outside `/srv/nn-malsim`; MS-25 with auditd installed in the guest). MS-23
expects the Critical record with the kill held and the posture at ENGAGED,
in place and copy-delete; its negatives — tar, rsync, git checkout, apt,
and the simulator's own unpackaged script compressing its files into
`.gz` (`gzip-delete`) or moving them to another directory (`move-away`)
before deleting them — draw none.
The eBPF changes (`inode_rename`, `inode_unlink`, `task_kill`) count only
regular files, and only while the LSM file-open sensor is armed; the lab
runs them on 5.14 (RHEL 9), 5.15, 6.1, 6.8 and 6.12 (Debian 13).
