# NorthNarrow FIM trust model (Tappa 9 C7)

This is the operator-facing companion to the FIM design note, which is
in the source repository and not in the release
(<https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/TAPPA9_FIM_DESIGN.md>;
the `§13` references below are to it). Read it before deploying or
customising the File Integrity Monitoring (FIM) module — two of the
design's RFC resolutions (§13 Q5 trust-on-first-use baselines and
§13 Q7 operator overlay) bake-in trust assumptions that operators
must understand to operate the agent honestly.

## TL;DR

- The agent baselines watched paths on first boot. The baseline is
  trusted **as-is** — if the host was already compromised when the
  agent was first installed, the compromise is in the baseline and
  drift detection will NOT flag the originally-bad file. Treat
  first-boot baselines as TOFU.
- Operators may extend OR narrow the curated path list via
  `/etc/northnarrow/fim-paths.local` (`+/path` add, `-/path`
  disable). Every disabled-default emits a `WARN` at every agent
  boot so the overlay can't silently hide a regression.

## First-boot baselines (§13 Q5)

When the agent starts and the file `/var/lib/northnarrow/fim_baseline.jsonl`
is empty (the `install.sh` bootstrap creates the file as a zero-byte
placeholder for `PROTECTED_INODES`; the chain stays empty until the
first recompute), the agent fires a one-shot
`RecomputeReason::FirstBootTofu` request on the in-process recompute
channel. The boot-time recompute task walks every effective watched
path, computes SHA-256 + lstat metadata, and appends one
`BaselineEntry` per path to the chained log.

**Trust assumption:** the host filesystem state at first boot is
what FIM will subsequently compare against. If the attacker is on
the box before the agent installs, the attacker's modifications
become the trusted baseline. NorthNarrow cannot detect what it
didn't observe.

**Mitigations operators have today:**

1. Install the agent as part of host provisioning (kickstart /
   cloud-init / Ansible role), before any operator workload runs.
   The provisioning timeline is the smallest TOFU window.
2. Run `nn-admin fim baseline` manually after a known-good moment
   (e.g., post-`apt upgrade && reboot` on a clean image). The
   chain APPENDS — old entries stay as audit history; the latest
   entry per path is the active baseline. An agent that found no
   baseline database at its start records nothing, and says so
   (lab PR 263): `fim baseline: nothing was recorded: …`, exit 5,
   a signed `fim_baseline` row `failure: action_failed`; the
   agent's journal says why the database did not open.
3. Cross-check the baseline against an external known-good
   manifest (a future V1.1 `seed-from-file` op will accept a
   signed SHA-256 manifest at install time; until then, operators
   can `diff` the baseline JSONL against any out-of-band source
   manually).

**What V1.0 does NOT support:** install-time baseline computation
that ships a SHA helper alongside the agent binary. Decision per
§13 Q5: the install-time path forces shipping a SHA-256 helper
without the agent + adds a 200 ms install block + STILL doesn't
solve "host might already be compromised" honestly. First-boot
TOFU + this disclosure is the deliberate tradeoff.

## Operator overlay (§13 Q7)

`/etc/northnarrow/fim-paths.local` is the **optional** operator
overlay. Since Tappa 10.8 the agent reads it (at boot and on every signed
`fim baseline`) only when `fim-paths.local.sig` proves that a key with the
`config-manage` role signed this exact content: store it with
`nn-admin config overlay set fim-paths --file <file> --key <key>`; an
unsigned or edited file is ignored (shipped watch set) and recorded as an
`unauthorized_overlay` integrity finding. Format:

```text
# Comments and blanks are ignored. Lines are absolute paths
# with a single-character directive prefix:
#   +/abs/path   → add (also the default if no prefix)
#   -/abs/path   → disable a default-list entry
+/opt/myapp/bin/myapp
+/etc/myapp/config.toml
/etc/myapp/secrets.toml     # bare path is also `add`
-/var/log/wtmp              # we rotate aggressively; skip the truncation check
-/var/log/btmp
```

The agent merges the overlay onto the default list at every boot:

1. Read `/etc/northnarrow/fim-paths.v1` (curated default, ~100
   paths shipped by `install.sh`). It is applied only when it is the
   list built into the agent; an earlier release's copy or one edited
   by hand gives way to that list (a WARN, or an ERROR and a signed
   `default_list_modified`; external audit LLMR-015), and `install.sh`
   replaces it.
2. Apply every `-` line: if the path is in the default list, drop
   it from the effective set AND emit
   `WARN fim paths-config: default path <P> disabled by operator
    config (§13 Q7)`.
3. Apply every `+` line (or bare-path line): insert into the
   effective set.

**Disabled defaults are deliberately loud.** The boot-time WARN
fires on EVERY agent restart so the operator can't silently hide a
regression: a `disable: /etc/passwd` line stays visible in the
journal forever. The `nn-admin fim status` subcommand also reports
the disabled-default count so operators can audit the current
overlay without parsing `/etc/northnarrow/fim-paths.local`
manually.

**`-` lines targeting paths not in the default list** are no-ops
+ surface a separate WARN
(`fim paths-config: operator `disable:` targets a path not in
the v1 default list — no-op (check spelling)`). Common cause: the
operator typo'd the path or is trying to disable an `+`-added
path — the disable directive is for *defaults only*.

## Writers that are recorded, not killed (reviews 49, 52 and 83)

A write that a FIM rule answers with a kill is still written: the file
changes before the writer is killed. For the writers below, the kill only
broke legitimate work, so the rule records the write instead.

| Writer | Rules | Recorded as |
|---|---|---|
| The package manager: `dpkg`, `rpm`, `apt`, `dnf`, `yum`, `snapd`, `packagekitd` and their children (kernel-resolved lineage) | system binaries, setuid binaries, kernel and PAM modules, sensitive configs, cron drop-ins, units, timers, file capabilities | Log, Low |
| An interactive administrator session: `sudo` or `su` in the lineage, a login uid and a terminal | sensitive configs (NN-L-FIM-003), cron drop-ins (-007), units (-009), timers (-023), file capabilities (-025) | Log, at the rule's severity |
| An account tool (`passwd`, `useradd`, `usermod`, `chpasswd`, `systemd-sysusers`, libuser's `l*` tools…), told by its exe | `/etc/passwd` and `/etc/shadow` (NN-L-FIM-003), `/var/log/lastlog` (-018) | Log: Low when a user other than root ran it, else the rule's severity |
| Lot 340: the packaged `logrotate` (its path, and the device and inode of the file there), as root, run exactly as `logrotate /etc/logrotate.conf`, forked by PID 1 (its timer's `logrotate.service`) or run by cron's daily run (`/etc/cron.daily/logrotate` under `run-parts`, a short root chain up to a cron daemon PID 1 forked) | logs (NN-L-FIM-005), wtmp and btmp (-019) | Log, Low |

Everything else keeps the rule's response. That includes:

- a service;
- a cron job;
- a command run without a terminal (`ssh host 'sudo …'`, most automation);
- a root process with no `sudo`/`su` above it;
- `doas` and `pkexec`, which replace themselves with the command and so leave no trace in the lineage;
- `logrotate` run by hand, with any other argument (`-f`, `-s`, another configuration), by a non-root user, under anacron or cron run by hand or below a cron `@reboot` entry, a copy of it, and any other writer of wtmp or btmp (lot 340; the review of #552).

Lot 340: a log's size is compared with the size the agent last read in that
same file (else the size it had when it was watched), not with the path's
baseline at the start. rsyslogd's own appends (its exe, the `syslog` user,
the file grown) are not recorded (FP-1); after a rotation they read as
truncations against the rotated file's size, every day, and the first one
after the agent's start raced the baseline. A truncation in place still
shrinks the file and is recorded High.

Lot 340: a directory of a credential store opened (a listing: `find /`,
plocate's `updatedb`) is no verdict of NN-L-FIM-015/016/017; a file of the
store opened is judged as before.

The `ld.so.preload`, `authorized_keys`, bait and credential rules are never relaxed.

An administrator session's configuration changes still raise the posture to ENGAGED and stay in the signed detection chain. They do not corroborate each other into COMBAT: editing `sshd_config` and then adding a unit is routine work. A signal of another kind in the same login session (an offensive tool, exfiltration, an exec from `/tmp`) still takes the next one to COMBAT.

Whoever holds an administrator's session and sudo password is that administrator to these rules.

## A store's own client (review 85)

The credential rules (cloud CLIs, browsers, password managers, GnuPG) and
the login-record rules (`wtmp`, `btmp`, `lastlog`) do not act on a
store's own client, or on the login machinery. The agent tells them by
what the kernel executed, never by the name a process gives itself:

- a binary client: its exe, inside a root-owned system tree (`/usr`,
  `/opt`, `/snap`, …), named like the client (`aws`, `firefox`, `gpg`,
  `sshd-session`);
- a client written in a scripting language: the interpreter's exe and
  the script it runs, both in such a tree (`/usr/bin/python3` running
  `/usr/lib/google-cloud-sdk/lib/gcloud.py`);
- a client that bundles its runtime: its exe under that tree
  (`/opt/az/`).

An inline program (`python3 -c …`), a module run from the caller's path,
or a copy outside a system tree is not a client. A client reading another
user's credentials is acted on like any other reader.

Lot 347: `systemd-update-utmp` (the boot, shutdown and runlevel records of
`/var/log/wtmp`) is also told by facts the FIM drain reads at the write,
while the writer runs — the device and inode of the image the kernel runs
for it (`/proc/<pid>/exe` opened as a file) are those of the host's packaged
`/usr/lib/systemd/systemd-update-utmp`, and the process is placed in its
unit's own cgroup (`system.slice/systemd-update-utmp.service` or
`…-runlevel.service`). At the host's shutdown its exec was not always in the
lineage when the write was judged (Ubuntu 24.04: NN-L-FIM-019 High, `would
have: KillProcess`, at about one shutdown in two); such a write now has no
verdict. A copy of the binary, the binary run from a session or another
unit, and any other writer (`dd` appending a record) keep the High kill.
What this trusts: root's units — only root places a process in a unit's
cgroup, and the binary writes only its three records.

The review of #556 tightened both facts. The kernel keeps one dirty mark
per file and the drain credits its LAST writer with every write since its
last read, so a root shell's truncation or rewrite of wtmp followed by
`systemctl restart systemd-update-utmp` was the unit's write: the unit's
fact now exempts only an append of whole login records (the file grew by a
multiple of glibc's `struct utmp`, 384 bytes, 400 on aarch64, s390x and
loongarch64, since the drain's last read); a shrink, a rewrite of the same
size, a part of a record or unknown sizes keep the High kill. And the
process the drain reads at the writer's pid must have started no later than
the record (`/proc/<pid>/stat`'s start): a pid handed out again since names
another process. Residuals (root's): a rewrite of earlier records in place
followed by the unit's append within one mark still grows the file by whole
records (the drain compares no prefix), and the record's time is its last
close's, so a descriptor held open past the writer's exit lets a pid reused
before that close pass (the writer's start in the record itself, #554's
`modifier_start`, closes it).

The script is read from the interpreter's argv with that interpreter's own
option table (lot 292, BUG-44): `python3 -O /tmp/steal.py /usr/bin/aws` runs
`/tmp/steal.py` and is no `aws` client (NN-L-FIM-011 kills it, as any other
reader); `perl -X`, `node -r <module>`, `ruby -r <lib>`, `sh -e <script>`
are read the same way. An option the table does not hold, or one whose
argument is missing, leaves what the interpreter runs not known: never a
client, and the record says the kernel ran the interpreter with "options not
understood". The tables cover python, perl, ruby, node, bash/dash/sh, and
for zsh, ksh and mono the options every one of them reads the same way;
`crates/nn-core/src/posture/script_args.rs` lists them. Residual, as a
binary's `LD_PRELOAD`: an option that loads the caller's code before the
named script (`node -r`, `perl -M`, `ruby -r`) and the interpreter's
environment (`PYTHONPATH`, `NODE_OPTIONS`, `PERL5OPT`) are not judged: the
identity is the script named.

## File capabilities (review 86)

A file capability (`security.capability`) gives whoever runs the file the
capabilities it names: `cap_setuid` on a copy of an interpreter is a root
shell for every user. The agent sees every capability set, by any route
(`setcap`, a direct `setxattr`, `cp --preserve=xattr`, `tar --xattrs`),
and NN-L-FIM-025 strips it again. It is Critical when the set holds a
root-equivalent capability, else High. A namespaced capability (one that
applies only inside a user namespace, e.g. a rootless container build) is
only recorded.

Capabilities installed by the package manager, and those an administrator
grants from an interactive sudo session, are recorded and kept. To grant
one any other way (from a script, or a configuration-management run), open
the trusted-installer window first, or expect the capability to be removed.

## What FIM does not protect against

- **Host already compromised at install time** (TOFU window —
  documented above).
- **The agent binary itself** — Tappa 7 task 5 + 7 LSM hooks
  protect `/usr/local/bin/northnarrow-agent` against in-place
  tamper. FIM observes paths that are NOT the agent binary.
- **Paths the operator removed from the overlay** — disabled
  defaults stay loud in the journal but ARE in fact unwatched.
- **Recursive directory drift** — V1.0 watches the curated ~100
  paths (no recursive subtree). V1.1 adds opt-in `recurse: true`
  per-entry. Adding `/etc/passwd` to the watch list catches
  modifications to that exact path; it does NOT catch new files
  appearing under `/etc/` more generally.
- **`modprobe.d`'s `install` and `remove` commands (lot 279).** kmod
  runs the command an `install <module> <cmd>` or `remove <module> <cmd>`
  line names, through `/bin/sh -c`, as root, whenever `modprobe` (or
  `modprobe -r`) reaches that module — a name R011 records since lot 279
  (it judges the command line, not the configuration). The command's
  execs are judged by the exec rules like any other (`modprobe` is no
  trusted actor: its children inherit no exemption), but no rule says
  "modprobe started a shell". Writing the configuration takes root, who
  can run the command directly; for a kernel-driven load
  (`request_module`, a kernel thread's child) this was so before lot 279
  too, while a `modprobe` run from user space was killed by R011 on `main`
  (racing it, so its command usually did not run). Coverage (lot 285):
  every `modprobe.d` directory — `/etc`, `/run`, `/usr/local/lib`, `/lib`
  and `/usr/lib` — is in the watch list, and NN-L-FIM-026 records a write
  there (High outside a package transaction, Low inside one; a directory
  absent at the agent's start is not watched); R011 records each child of
  the module tool (Medium: the command a directive runs, `/bin/sh -c …`),
  but not the `install <module> /bin/true` (or `/bin/false`) idiom of the
  hardening guides; an `install` line in
  `/lib/modules/$(uname -r)/modules.softdep`, which kmod reads with the
  same parser, is a file under `/lib/modules/` (NN-L-FIM-008, Critical).
  The module a directive loads is the kernel's to judge (lot 285: by the
  file).

## Audit + integrity guarantees

- Every `BaselineEntry` is signed with the agent's Ed25519
  identity key (Tappa 8 B1) and chained via `prev_hash` /
  `entry_hash`. The off-host `audit verify` tooling extended in
  Tappa 9 C8 will reject a tampered baseline chain.
- The `fim_baseline.jsonl` + `fim_drift.jsonl` files are
  registered in `PROTECTED_INODES` (Tappa 9 C7 — see
  `crates/nn-linux/src/anti_tamper/filesystem.rs::STATE_PROTECTED_FILES`).
  An attacker with root cannot truncate, unlink, rename, or chmod
  the files; the LSM hook denies the syscall before it reaches the
  filesystem.
- The `fim-paths.v1` + `fim-paths.local` files are likewise in
  `PROTECTED_INODES` (`ETC_PROTECTED_FILES`) so an attacker can't
  silently widen or narrow the watch set between agent restarts; an
  edit made while the agent is down is reported at its next start and
  not applied.
  Operator changes go through `nn-admin config overlay set fim-paths`
  (signed, stored by the running agent, applied at its next start).

## See also

- Design doc (source repository):
  <https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/TAPPA9_FIM_DESIGN.md>
  (§5 LSM hooks, §6 userland, §13 RFC resolutions).
- Rule catalogue: `crates/nn-core/src/fim/rules.rs` (NN-L-FIM-001..014).
- Install script: `deploy/install.sh` (Tappa 9 C7 additions —
  drops `fim-paths.v1` + bootstraps the two chained logs).
- Operator commands: `nn-admin fim baseline`, `nn-admin fim
  report`, `nn-admin fim status` (Tappa 9 C6 + C7).
