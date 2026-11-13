# The per-rule response policy (lab PR 236)

Every detection rule has a built-in response: a record (`Log`), a kill of the
process or of its tree, a capability stripped from a file. Some kills added by
lab PRs 219–226 and lot 275 (NN-L-NET-028's — `NETWORK_TELEMETRY.md`) are
**held** by default (recorded as an alert, the process left running) until an operator
turns them on. The per-rule response policy is
where you do that, rule by rule, and where you tone a noisy rule down or
exempt one known program from it. Design:
https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/MULTI_MATCH_AND_RULE_POLICY.md

Without a policy nothing changes in what the agent *does*: every held kill
stays held, and no event gets a stronger response than the agent gave it
before lab PR 236 (the legacy ceiling, §1). What changes is what it
*records*: every rule that matches an event is named.

## 1. What a decision is

Since lab PR 236 every rule judges every event. When several rules match, the
agent writes **one** record that names all of them (`matches`, each with its
ATT&CK ids), with a primary rule (the highest severity, then the strongest
action, then the most specific rule), and runs, for each process concerned,
the strongest response the matched rules' modes allow. A rule set to `audit`
or exempt for the actor never raises that response.

**The legacy ceiling.** Before lab PR 236 only the first matching rule
answered an event, so some responses never ran: a new `authorized_keys`
under `/home` was NN-L-FIM-002's record, never NN-L-FIM-004's kill. To keep
an administrator's `ssh-copy-id` from being killed the day the agent is
upgraded, a rule without `enforce` never runs more than the first-match
engine would have run on that event (on the same process). Such a match is
recorded with `held: "legacy_ceiling"`, the action it asked for in
`held_action`, and its reasoning names the directive that lifts it:
`enforce <rule>`. To turn FIM-004's kill on:

```
enforce NN-L-FIM-004
```

**Kills that wait for COMBAT (lot 278).** R009 (a file in `/home`, `/tmp` or
`/var/tmp` executed by root) kills its tree only while the posture is
COMBAT. Below COMBAT the match keeps its High severity, its signed record and
its ATT&CK ids; its action is `Log`, `held` names what was held ("the kill of
the root exec's process tree (R009, lot 278)"), `held_action` the kill, and
the reasoning the posture the event was judged in. R001 and R003 wait the
same way for an exec by root (a root exec from `/tmp` or `/var/tmp` is
R009's to decide); a non-root exec from those directories is killed as
before, in every posture. Why: R009's legitimate matches are root automation
run from a checkout or an unpacked tree — `install.sh --upgrade`,
`uninstall.sh`, Ansible `become` without a terminal, cloud-init, a CI job —
and the script's own exec comes before any window it can open
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §2.1). Holding
the kill in OBSERVING only would not be enough: any exec from `/tmp` raises
ENGAGED for 24 hours, so the second run of the same installer would be killed;
COMBAT is reached on corroborated or decisive evidence only. To kill R009's
matches in every posture, as before:

```
enforce R009
```

**Decision record (03/11/2026, lot 278).** By the coordinator, with the
authority the founder delegated; after the independent review of #493.
- *What:* R009's kill, and R001's and R003's of an exec by root from `/tmp` or
  `/var/tmp`, run in COMBAT only. That is a default, and it changes, for
  these three cases only, the decision of 21/10/2026 ("a kill that existed
  before … is not held") and external audit POS-015 ("R001..R003 still kill
  the exec, whatever the posture").
- *Why:* their legitimate matches are frequent and destructive when killed:
  installers and upgrades from a checkout or `/tmp`, Packer, Terraform
  remote-exec, Vagrant, Ansible `script:`/`become`, self-extracting
  installers, CI runners in a home. Against a process that is already root
  the kill is worth little: it moves the file to `/root`, `/opt` or `/run`,
  which R009 does not cover.
- *The way back:* `enforce R009` (and `enforce R001`, `enforce R003`) in
  the signed per-rule policy kills in every posture.
- *What is left:* a root dropper run from `/tmp` (or a home) in OBSERVING,
  ALERTED or ENGAGED is a High record and is not killed. It is killed at its
  first egress (NN-L-CHAIN-002/005/007, NN-L-NET-008), or in COMBAT. A
  process recorded in ENGAGED is not killed after the fact when COMBAT comes
  later, unless it is the ladder's offender. On the priority bus an exec may
  be judged before an earlier event that brings COMBAT: it is judged in the
  posture it found.

The hold never stands in for another rule's kill of the same exec. A shell
copied to `/tmp` or a home (R017), and the module, capability and namespace
tools (R011, R012, R013), run by root from there, are killed in every
posture, as before.

**Kills that broke benign workloads (lot 283b, 06/11/2026).** Lot 283a's
benign corpus ([the benign corpus](https://github.com/northnarrow/northnarrow-new/blob/main/docs/validation/BENIGN_CORPUS.md): a
developer's workstation, a CI runner, a container host, a database server on
Ubuntu 22.04 and 24.04) saw every kill of a default install land on benign
work. Four changes, each a default the signed per-rule policy can undo with
`enforce <rule>`:

- **R001 and R003, a person's exec.** An exec from `/tmp` or `/var/tmp` by an
  account a person logs in as — `UID_MIN` (`/etc/login.defs`, 1000 by
  default) and up, with a login shell — is a High record below COMBAT, killed
  in COMBAT: `go test`'s binaries and `go run`'s program
  (`/tmp/go-build…`), an AppImage's `AppRun` (`/tmp/.mount_*`,
  `/tmp/appimage_extracted_*`), a CI runner's user. An exec by a system
  account — below `UID_MIN`, or a `nologin`/`false` shell (`www-data`,
  `postgres`, `nobody`, systemd's dynamic users) — is killed in every
  posture, as before: the web shell that runs its payload from `/tmp`. The
  account decides, not a profile; root's exec waits for COMBAT (lot 278). An
  account of another NSS source (LDAP, SSSD) has no `/etc/passwd` entry: from
  `UID_MIN` up it counts as a person's, and so does a rootless container's
  sub-uid (it carries its owner's standing).
- **R013, a runc.** A `runc` executed from outside the system directories is
  a High record, its kill held (`enforce R013` gives it back): k3s runs its
  own from `/var/lib/rancher/k3s/data/<hash>/bin/runc`, and the corpus saw
  645 kills and no pod start. A copied `nsenter` or `unshare` is killed as
  before.
- **NN-L-FIM-007 and NN-L-FIM-009.** A cron entry or a systemd unit written
  outside a package transaction and an administrator's session is a High
  record, the kill of its writer held (`enforce NN-L-FIM-007`,
  `enforce NN-L-FIM-009`). The kill came after the write — the entry or the
  unit stays — and the corpus saw it only on benign writers (`crontab -u
  postgres`, `install` into `/etc/cron.d`, the k3s installer's `tee` of
  `k3s.service`), each already gone. Preventing the write is not a kill's
  job: the kernel's deny of a persistence write and the persistence that
  repairs itself are Wave 3's. `enforce` gives back the kill only of what the
  carve-outs left a kill: a package transaction's write stays a Low record
  under `enforce`.
- **R011 in a package transaction.** A root exec of a program in a system
  tree whose lineage holds a package manager run by root, as the agent read
  it at the exec, is recorded, not killed: a dpkg trigger's
  `update-initramfs` runs `/usr/share/initramfs-tools/hooks/kmod` (comm
  `kmod`) from forks of `mkinitramfs` that never execute, gone by the time the
  decision walked the lineage — the hook was killed in an `apt upgrade`, and
  a kill that lands aborts the initramfs build. By lineage, never by name.
- **R011 in an initramfs build (lot 287).** The same hook in an
  administrator's own `sudo update-initramfs -u` has no package manager in
  its lineage (lot 283b's lab: killed, rc 137). The agent remembers each
  process whose exec ran an initramfs builder — `/usr/sbin/update-initramfs`,
  `/usr/sbin/mkinitramfs`, `/usr/bin/dracut`: the packaged file by the
  device and inode the kernel gave for the script, run by root; a copy, a
  file under `/tmp`, a user's run is none — and reads, at an exec of a
  module tool, the nearest one from the exec's parent up, while the build's
  forks are alive. In such a build a root exec is recorded (High), not
  killed, when it is what the build runs: a `#!` script of a system tree
  outside the tools' own places (the hook; the interpreter is the process's
  image, or its `#!` line once it has exited), or the system's `modprobe`
  asked to load nothing (`--show-depends`, `--dry-run`: `manual_add_modules`
  on Debian 12 and Ubuntu 22.04). Still killed in a build: `MODPROBE_OPTIONS`
  or `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` in the environment; a tool
  that is not the system's; anything outside a system tree; `insmod` and a
  `modprobe` that may load, so a hook root plants (`mkinitramfs -d`,
  `/etc/initramfs-tools/hooks`) does not launder them. Best effort: a
  build's fork that exited before the agent read the exec breaks the
  lineage, and R011 judges the exec as before. Tracepoint mode (no LSM exec
  hook) sees no build: killed as before.

**Decision record (06/11/2026, lot 287).** By the coordinator, with the
authority the founder delegated.
- *A narrow record, not the whole tree.* Inside a build R011 records only
  what the build itself runs: the hook (a `#!` script of a system tree) and
  `modprobe`'s dry runs. It does not record every exec under a builder.
  `mkinitramfs -d <dir>` and `/etc/initramfs-tools/hooks` run hooks that
  root chooses, so a record of the whole tree would let `sudo mkinitramfs -d
  /tmp/x` launder an `insmod /tmp/rk.ko`. The narrow record keeps that
  `insmod` killed.
- *No "not modified since boot" check on the builder.* The builder is
  trusted by its packaged file's device and inode in a root-owned tree, run
  by root. Its modification time is not compared with the boot: an `apt
  upgrade` of initramfs-tools changes the builder's ctime, and the
  administrator's `update-initramfs -u` run right after it, before a
  reboot, would be killed again. No helper of the agent compares a file
  with the boot either.

**Decision record (06/11/2026, lot 283b).** By the coordinator, with the
authority the founder delegated, after lot 283a's inventory.
- *What:* the four changes above. NN-L-FIM-004, NN-L-FIM-023 and
  NN-L-NET-008 keep their kill: the corpus did not exercise them, there is no
  measured false positive to correct; they are candidates to look at again
  (the catalogue names their benign writers: `ssh-copy-id`, a timer outside a
  package, an installer from `/tmp` that calls out).
- *What is left:* a person's own account running a payload from `/tmp` below
  COMBAT is a High record, not a kill — killed at its first egress
  (NN-L-CHAIN-002/005/007, NN-L-NET-008) or in COMBAT. A cron entry or a unit
  dropped by a foreign writer is recorded, not undone. A `runc` renamed copy
  of `nsenter` is recorded, not killed. The in-session small-file threshold of
  lot 282's backlog is not turned on: at 50, `cargo fmt` and `prettier` cross
  it (the corpus's data, in the repository's `docs/validation/`).
- *Not changed:* the `ConfirmedIntrusion` raises of ordinary servers
  (PostgreSQL, containerd, the Go build cache: ENGAGED, never COMBAT) are lot
  283c's.

**R011 judges a module tool's command line (lot 279, 04/11/2026).**
R011's kill existed before Wave 4 and stays in `OBSERVING_KILLS` below; lot
279 narrows it and adds no kill. An exec of the system's module tool by
module name — plain names, before the first name only options that move and
force nothing, no `MODPROBE_OPTIONS`, `LD_PRELOAD`, `LD_AUDIT` or
`LD_LIBRARY_PATH` in its environment — is a High record (T1547.006), not
killed, in every posture. Killed as before, in every posture: `insmod`;
`modprobe` of a path or a `.ko*` name; `-C`, `-d`, `-S`, `--force*`, `-o`,
`--remove-holders`, `--remove-dependencies`; any argument starting with `-`
after the first name (`modprobe <name> -q` included); a copy of the tool or
a program that is not the system's (its device and inode against the file
`/usr/bin/kmod` resolves to; every tool when `/usr/bin/kmod` and `/bin/kmod`
are two different files, not one file under both names as a merged `/usr`
shows it); one of those variables (read, it is evidence: killed even if the
process has since exited), a running process
whose environment the agent could not read at the exec, an environment over
1 MiB, an unknown start; an argv not read whole. A tool that had exited
before the agent could read its environment is recorded, its environment
not verified — a kill would reach no one; a tool whose first thread (its
leader) exited while another thread runs on has not exited: the agent reads
the environment through the running thread, and kills when it cannot read
it whole — or sees no thread running while the kernel counts more than one. For a short-lived `modprobe` the environment's check is best
effort. R011 resolves nothing: whether a name
loads a module, and which, is the kernel's to judge — its module signature
enforcement and lockdown (the host check reports both) and lot 285's deny of
an untrusted file are what prevent a load. Lot 285: the kernel judges every
load by the file it reads (§2.4), whoever loads it, and R018 records what it
refused or let through; R018's loader allowlist by `comm` is gone. What R011
never covered: a root parent tracing the tool and
rewriting its argv or environment after the agent read them, code injected
into the tool (an `LD_PRELOAD` read too late, `/etc/ld.so.preload`) that
forks and lets the tool exit: the agent reads an exited tool (recorded),
and a kill of the tool would not reach that child, which runs on out of its
tree. The
`install`/`remove` commands of root's `modprobe.d` run as programs the exec
rules judge; lot 285 records each child of the module tool (R011, Medium:
the command a directive runs) and each write of kmod's configuration
directories (NN-L-FIM-026, High outside a package transaction) — the
residual is in `TAPPA9_FIM_TRUST_MODEL.md`. Why: the container runtimes, kube-proxy and k3s
run `modprobe` of the distribution's netfilter, bridge and overlay modules
(lot 275's lab: rootful podman's network killed on Ubuntu 22.04). No
directive restores the kill of a recorded exec: `enforce R011` runs R011's
own response, which for it is the record.

Inside an administrator's `sudo` session at a terminal, a package
transaction or an installer's window (R009's Low record), those rules'
kills of the same exec are held by the legacy ceiling (R009's record is the
first match), in COMBAT too. That was so for the session and the package
transaction before lot 278.

**What brings COMBAT, and what the ladder kills (lot 282).** COMBAT is
where the kills above wait, and where the ladder's NEUTRALIZE kills the
offender's process tree; on `main` before lot 282 a host's first `podman
pull` and an `apt purge` reached it. Since lot 282
([the posture design, §10](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/POSTURE_FSM_V2_REDESIGN.md)):
- the posture's mass-write signal counts distinct existing files rewritten
  in place, or destroyed (unlinked, emptied by a truncate then unlinked, or
  replaced by a rename) by a process — or a cgroup — that also wrote files
  new — never files written new alone (an image pulled, a clone, an archive
  extracted, a build), one file rewritten again and again (a database) or
  files deleted alone (`rm -rf`, a purge). Files of any size that hold data
  count; rewrites of files under 4 KiB only outside an authenticated session
  (a build's own small outputs inside one: lab PR 127);
- since lot 283c, a server doing its normal job does not sit in ENGAGED: a
  crossing whose every file was the writer's own data does not raise the
  mass-write signal — a service account's files under `/var/lib` or its home,
  in a directory it owns, and its own shared memory in `/dev/shm`, written
  from its system service (PostgreSQL's
  backends, not `initdb` run by hand in a session); a listed root daemon's
  directory (`daemon-data.v1`: containerd, Docker, the kubelet, etcd, k3s;
  more in the mass-write overlay) written from that unit's cgroup; a person's
  `~/.cache` written by that person. One file of anyone else in the window
  and the crossing counts whole; tree replacements in a session (`npm ci`,
  `rsync --inplace`, `git checkout`) count as before. NN-L-IMP-001 judges
  every crossing, these included. Residuals: a compromised service account
  encrypting its own data directory only reaches NN-L-IMP-001; a root daemon
  named like a listed unit gets that unit's directory exempt, and nothing
  else; a file moved into such a directory before it is rewritten is judged
  there (the posture design, §10.5 and §10.7);
- an anti-tamper refusal of a package transaction's process (a package
  manager root executed, whose run covers it, as R009 judges it) of a file
  operation a maintainer script does — removing, renaming, changing the
  attributes of, or making an entry beside, a file or directory the agent
  protects — raises ALERTED (`PackageTamperRefusal`) and never vouches for
  COMBAT; any other refused operation of that process (a signal, a ptrace, a
  BPF handle, a kexec, a cgroup write, a limit, a read of the key) keeps its
  weight, since any root command can run as an apt hook; a refusal of any
  other process still brings COMBAT on its own;
- the ladder never kills on one heuristic signal: a COMBAT whose cause is a
  heuristic with no signal of another kind vouching for it holds its
  NEUTRALIZE (a signed `combat_stage` row, "NEUTRALIZE held"), and does not
  isolate for it;
- NN-L-EVA-002 no longer reads a container runtime flushing its own chain
  (`CNI-…`, `DOCKER…`, `KUBE-…`, `cali-…`, `cilium_…`, `NETAVARK…`,
  flushed by the runtime's packaged program: podman's CNI plugin, dockerd)
  as the firewall switched off; the same chain flushed by another process,
  the filter chains a runtime creates (`DOCKER-USER`, `CNI-ADMIN`,
  `KUBE-FIREWALL`) and the host firewall's chains (ufw, fail2ban,
  firewalld, the built-in ones), still are;
- the replacement shape (copy then delete) counts outside an authenticated
  session only: ransomware run from an SSH shell that way is judged by the
  ransomware tracker (NN-L-IMP-001), not by the mass-write signal. What
  neither sees — originals deleted more than a minute after the copies, a
  deleter in another cgroup or forked once per file, tracepoint mode — is
  listed in the design's §10.5.

None of this is a policy directive: the per-rule policy does not change it,
and no `enforce` brings the old behaviour back.

Every other rule whose response can be a kill, and why it may kill in
OBSERVING, is listed in `crates/nn-core/src/decision/posture_floor.rs`
(`OBSERVING_KILLS`): the kills that existed before Wave 4, kept as they were
by the decision of 21/10/2026; the exploit guard's kernel kill in enforce
mode and the exec quarantine's, both opt-ins. A test holds the list to the
rule catalogue: a new rule that can kill must say where it kills. The kills
Wave 4 added are held in every posture until `enforce` (above).

## 2. Writing a policy

`/etc/northnarrow/rule-policy.local`, one directive per line, `#` comments.
Name a rule by its full id or its short id (`NN-L-IMP-001`, `R020`; see the rule catalogue,
https://github.com/northnarrow/northnarrow-new/blob/main/docs/detection/RULE_CATALOGUE.md).

| directive | effect |
|---|---|
| `enforce <rule>` | the rule's own response, **its held kill included** (held by a switch or by the posture, §1), above the legacy ceiling |
| `alert <rule>` | recorded as an alert (counted for severity), no response |
| `audit <rule>` | recorded only (no alert line, not counted) |
| `off <rule>` | not recorded, no response (the rule still runs, so chains and windows keep their state) |
| `exempt <rule> uid <uid>` | that uid's matches of the rule are recorded only (not uid 0) |
| `exempt <rule> exe <path> sha256 <hex>` | that executable — root-owned, in `/usr`, `/opt`, `/bin`, `/sbin`, `/lib*`, `/snap` or `/nix/store`, every directory up to `/` root-owned, no one else may write it, and its content exactly that digest — while **no code was injected** into the process (§2.3). The path is the one the kernel gives as the process's executable (`/proc/<pid>/exe`), symbolic links resolved: on Ubuntu 26.04 `/usr/bin/sleep` is a link to uutils' `/usr/lib/cargo/bin/coreutils/sleep` (one file for every utility, hard-linked), and an exemption of `/usr/bin/sleep` covers nothing (lot 303) |
| `exempt <rule> cgroup <path>` | processes of that cgroup v2 path (it must end in a `.service` or `.scope`) **started there** (§2.1) and **not injected into** (§2.3) |
| `exempt <rule> unit <name>` | processes of that systemd unit (`backup.service`) **started there** (§2.1) and **not injected into** (§2.3) |
| `combat-without-corroboration NN-L-IMP-001` | the ransomware trigger reaches COMBAT without a second signal (it never locks COMBAT) |
| `sysctl-allow <sysctl> <value>` or `sysctl-allow <sysctl> <min>..<max>` | (lot 280a) a guarded sysctl may take that value or range outside a trusted-installer window too, each such write recorded; honoured **only signed** (§2.2) |

`enforce` is **refused** for a rule whose kill would not be fail-safe:
- NN-L-NET-003, a TLS fingerprint (JA3 or JA4) in the operator's list — one
  attribute many benign programs share, until the rule has a second
  predicate (a destination, an executable) to act on (lot 275, R6 of the
  external review of 04/11; a fingerprint names a TLS stack, not a program
  — `NETWORK_TELEMETRY.md` §3);
- NN-L-NET-028, "no DNS, no connect" — it judges the absence of a DNS
  answer the agent saw, which benign software can produce out of its sight
  (a container's resolvers of its own, DNS over TCP, DoT or DoH, an address
  configured by hand): refused until it is measured on a wider corpus
  (review of #495; `NETWORK_TELEMETRY.md` §4). Its kill stays held. The
  agent's own export worker (lot 276) connects to its syslog receiver by
  address, never by a name: a receiver at a public address is recorded
  (Medium) unless it is in `nodns-allow.local`; were this `enforce` ever
  accepted, its kill would be aimed at that worker — the allowlist first
  (`EXPORT.md` §8).
In a policy you sign, the line refuses the file like any bad line
(`nn-admin config overlay set` and `policy-test` say so). In a policy
signed before the upgrade, the agent's start takes only that line as
`alert` and keeps the rest of the policy in force — its exemptions, its
other modes, its switches — and signs a `rule_policy` degradation naming
the line ("enforce refused, applied as alert"); `policy show` names it in
the policy's source. `alert`, `audit`, `off` and `exempt` of the rule are
accepted.

An exemption is **never** by process name: `comm`, `name`, `process` and
`argv` refuse the file (any user can name a process `sshd`). When the agent
cannot read a fact (the process is gone), the match is not exempt.

Any bad line refuses the whole file: an unknown rule or keyword, two modes
for one rule, a rule decided outside the engine (NN-L-AT-001, NN-L-EPG-*,
NN-L-EXECPOL/EXECENV-*, NN-L-EXECQ-001), a refused exemption, more than 64
exemptions for one rule.

Example — enforce the ransomware kill, keep the backup service out of it:

```
# rule-policy.local — signed by config-manage
enforce NN-L-IMP-001
exempt  NN-L-IMP-001 unit backup.service
exempt  NN-L-IMP-001 exe /usr/bin/restic sha256 3f1c…(64 hex digits)
```

### 2.1 Exemptions by cgroup or unit: started there, not moved there (lot 277)

A cgroup's members are not all what the unit started: root can write its
own pid into `/sys/fs/cgroup/system.slice/backup.service/cgroup.procs`, or
start a child there with `clone3(CLONE_INTO_CGROUP)`, and is then "in"
`backup.service`. Since lot 277 an exemption by `cgroup` or `unit` holds
only for a process **started in that cgroup**: spawned into it by systemd
(PID 1), or forked from a process that was.

The kernel tells them apart (`agent-ebpf/src/cgroup_join.rs`, the
start-in-cgroup tracker). It marks a process that was moved into a cgroup
by anyone but systemd's placement, or started by `CLONE_INTO_CGROUP` by
anyone but PID 1. A process it forks after that is marked too, before it
runs, and the mark goes when its last thread exits. A new process starts
with nothing at its pid, whatever a dead process left there (a move of a
process already exiting marks after its exit: the review of #494, N5).
The rule's match of a marked process is not exempt by `cgroup` or `unit`. An exemption by `uid` or
`exe` still covers it: those name the actor, not where it runs. systemd's
placement is a move PID 1 makes (a unit's process at its start, a scope's
process, a process systemd was asked to attach), or the move a child of
PID 1 makes of itself before it ran any program (systemd up to 254 forks,
the child moves itself, then executes the unit's command). A move that
changes nothing is no move — only a thread that moves **itself** into the
cgroup it is already in: systemd 255's executor (`posix_spawn`ed by PID 1,
moved by PID 1, then moving itself) and 256's and later (started by
`CLONE_INTO_CGROUP`, then moving itself). A thread that writes another
thread of its own process into `cgroup.threads` moves it, and the process is
marked (the review of #494, B1).

A move into a cgroup an exemption names, by anyone but systemd's placement,
is a **signed detection**: NN-L-AT-001 with `operation` `cgroup_join`
(Log, High). It is not refused, and it raises no posture trigger. The record
names the mover (`principal`, `exe`) and, in `response`, the exemption the
moved tree lost. The move goes through; what the moved process does is
judged by the rules without the exemption. The kernel matches the
destination's whole path against the `cgroup` exemptions and each of its
components against the `unit` names: a move into a cgroup below an exempt
unit (`backup.service/sub`) is signed too. A destination path of 255 bytes
or more (the kernel's read fills its 256-byte buffer: the path may go on) is
signed without a name while any such exemption is in force.

The tracker's programs and maps are pinned like the other anti-tamper
programs (the review of #494, D6), in a directory of their own beside the
pin root: `/sys/fs/bpf/northnarrow-cgroup-join-v<schema>_<generation>`
(the re-review of #494, R2), recorded in
`/run/northnarrow/cgroup-join-pins`. Stopping the agent leaves them
attached, and the marks go on being made and passed on; `install.sh
--upgrade` purges the pin root and leaves this directory, so the marks
outlive an upgrade too; a new start attaches its programs before it
removes the old links. A start adopts only the directory its predecessor
of this boot recorded, each map the one recorded (the third review of
#494, R2-b). Anything else — the directory gone between two agents, maps
that are not the recorded ones, a directory nobody recorded, an older
schema's — is a **reset**: new maps, a signed degradation "cgroup
exemptions: marks reset …" (or "marks lost between agents"), and every
process started before that start, with what it forks, is not known —
refused an exemption by cgroup or unit until it exits. **Restart the
exempt services** after one. `kernel.pid_max` or `kernel.threads-max`
raised later is no reset (R2-a): the marks keep their capacity, signed
as below the host's. `uninstall.sh` removes the directory with the pin
root.

Where the exemption is refused:

- on a kernel without the tracker (its targets not in the shape its
  programs read: `northnarrow-agent --btf-check` prints `tracker
  cgroup_join`; a signed `subsystem_degraded` "cgroup exemptions" at
  every start) — every exemption by cgroup or unit;
- for a process whose mark the kernel could not keep — the insert into the
  marks failed, or the leader's start time could not be read: that process
  and what it forks after, until its thread group ends (its byte in the
  pinned `CGROUP_JOIN_LOST`, 4 MiB, written with plain stores: the
  re-review of #494, R1); every other process's exemption stands. The
  marks are sized when they are made (the first start of the boot) to
  hold every thread group the host can run at once (`kernel.pid_max`,
  capped by `kernel.threads-max`; 32,768 to 4,194,304; allocated as they
  are taken), so a failed insert is a kernel out of memory or a limit
  raised since, not a full map of live processes;
- after a reset of the marks (above): every process started before it, and
  what it forks, until it exits; It is never silent: counted in the start's
  journal line (`marks lost`). Why per process (the review of #494, D2):
  a state for the whole host, which any user's fork storm might reach,
  would switch off every exemption by cgroup or unit until a reboot;
- under the agent's containment slice (`/northnarrow.slice`, where it moves
  the processes it blocks or throttles, unmarked): no exemption by cgroup or
  unit applies there, and a policy that names `cgroup /northnarrow.slice…`,
  `unit blocked.scope` or `unit throttled.scope` is refused (the review of
  #494, N1).

Refusals that are not an attack (fail-closed, as designed):

- **`Delegate=yes` and container runtimes.** A service that moves its own
  processes into its sub-cgroups is not systemd: those processes are
  marked and lose the service's `unit` exemption. The same for a container
  runtime — runc writes the pid itself, with the systemd cgroup driver too.
  Exempt such a workload by `exe <path> sha256 <hex>` or `uid`.
- **A cgroup v1 hierarchy** (a hybrid host): a move in it by anyone but
  systemd's placement marks the process; the policy reads only the v2
  (`0::`) cgroup.
- **systemd 255's order inverted.** If the executor moved itself before PID
  1 moved it (PID 1 kept off the CPU for milliseconds in that window), the
  move is the executor's own and the unit's process is marked.
- **A thread that is not the leader writing its own process into its
  cgroup** (`cgroup.procs`, its tgid or `0`): the leader moves, not the
  writer — marked (the re-review of #494, N-d).

What it does not cover, as measured:

- **A root that changes the unit itself** — a drop-in that rewrites
  `ExecStart=`, a transient unit given the exempt unit's name where none is
  loaded, systemd asked over D-Bus to attach a process
  (`AttachProcessesToUnit`). Those are systemd's placements: the unit
  exemption trusts the unit's definition. To bind an exemption to a
  program, use `exe <path> sha256 <hex>` (a rewritten unit runs another
  digest).
- **A root that writes PID 1's memory**, or its pre-exec child's (systemd up
  to 254): `ptrace`, `/proc/1/mem`. What PID 1 does is systemd's placement.
- Code injected into an exempt process that is already running: since
  lot 281 its exemption is revoked (§2.3).
- A move made before the agent's first start since the host booted (no
  program ran). Inside the trusted-installer window (a signed, audited
  grant; an upgrade's), root can replace both the tracker's pins and
  their record: the window trusts its holder. On a 6.18+ kernel with cgroup2 mounted `favordynmods`
  (not systemd's default), a move of a dead group can mark its pid after
  a new process took it: a false refusal. While no agent runs, the last agent's and watchdog's pids
  stay the agent's family until the next start evicts them (pinned
  `PROTECTED_PIDS`): a process given one of those pids moves unmarked; and
  the `cgroup_join` record of a move made then reaches no journal (the mark
  is made).
- A start by `CLONE_INTO_CGROUP` is marked, not signed: the kernel's fork
  path gives no destination path to match cheaply.
- The same principle holds for any future exemption by container or
  workload: a process counts as the workload's when the workload's runtime
  started it there, never because its cgroup says so.

### 2.2 The signed per-sysctl opt-out (lot 280a)

The agent refuses, outside a trusted-installer window, a write of a guarded
sysctl whose value aborts, starves or blinds it (`kernel.pid_max` below
32768, `kernel.threads-max` below 8192, `vm.max_map_count` below 65530,
`vm.overcommit_memory` 2, `vm.overcommit_ratio` below 50, a
`vm.overcommit_kbytes` cap below 1 GiB, `kernel.sched_rt_runtime_us` -1 or
at least 990000), and any write of `kernel.sched_rt_period_us` and
`kernel.ftrace_enabled`; the integrity round puts such a value set at boot
or inside a window back to a safe one (lots 273d and 280a in the trust
model,
https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/ANTITAMPER_TRUST_MODEL.md). Some hosts need one of them: tuned's `realtime` profile
writes `kernel.sched_rt_runtime_us = -1`. Say so in the policy:

```
# rule-policy.local — signed by config-manage
sysctl-allow kernel.sched_rt_runtime_us -1
sysctl-allow kernel.pid_max 4096..32767
```

- The name is the `sysctl(8)` one of a guarded sysctl; `kernel.ftrace_enabled`
  is refused (0 stops the BPF trampolines, the agent's deny hooks among
  them: a window lets a write of it through), and so is
  `debug.kprobes-optimization` (lot 280b: 0 makes every kprobe a breakpoint
  trap). Any other name refuses the
  file; the refusal lists the names the line takes (lot 299, BUG78: it
  listed `debug.kprobes-optimization` too). One line per sysctl; the value
  a decimal integer, the range's ends included and in order.
- **Honoured only with a valid signature.** The agent writes the range to
  the kernel only from a policy whose signature it verified for the very
  text it applies, at its start or through `nn-admin policy set`. A policy
  loaded unsigned through `NN_OVERLAY_ALLOW_UNSIGNED=1` keeps its other
  lines and loses its `sysctl-allow` (a signed `rule_policy` degradation
  says so); an edited file is refused whole, as every overlay.
- **Every write it lets through is recorded**: NN-L-AT-001 with
  `operation` `sysctl_opt_out`, the sysctl and the value, Low, no posture
  change (the operator's tuning). A value in the range that is harmless
  anyway is no record. The integrity round leaves a value in the range
  (`sysctl_opted_out`, signed once while it holds).
- It names a sysctl and its values, not a program: while it is in force any
  root process may write a value in the range. Keep the range to what the
  host needs.
- `nn-admin policy show` lists the lines in force; the policy's summary
  counts them (`…, 1 sysctl opt-out`).

### 2.5 The signed per-loader opt-out of the refused BPF program types (lot 290)

Outside a trusted-installer window the agent refuses (`EPERM`) a
`BPF_PROG_LOAD` of the program types that can rewrite a process's memory
(`bpf_probe_write_user`), override a kernel function's return
(`bpf_override_return`, `fmod_ret`), signal a process (`bpf_send_signal`)
or take one of the agent's hooks' place — nine types: `kprobe`,
`tracepoint`, `perf_event`, `raw_tracepoint`, `raw_tracepoint_writable`,
`tracing` (fentry, fexit, fmod_ret, iterators), `struct_ops`, `ext`
(freplace) and `lsm`. Every other type — the cgroup device, skb, sock and
sysctl programs of systemd and the container runtimes, tc and XDP
networking, socket filters — is let through and recorded; inside a window
everything is let through and recorded (the trust model's lot 290,
https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/ANTITAMPER_TRUST_MODEL.md).
A host that runs bpftrace, Falco, Tetragon, Cilium or another BPF tool of
those types outside a window says so in the policy:

```
# rule-policy.local — signed by config-manage
bpf-loader-allow /usr/bin/bpftrace kprobe,tracepoint,perf_event,raw_tracepoint,tracing
bpf-loader-allow /usr/bin/falco raw_tracepoint,tracing
```

- The executable is an absolute path (no `.` or `..` component); the types
  are among the nine above, each once (the file reads them back in that
  order). Any other type refuses the file: there is nothing to opt out of.
  One line per executable, 32 at most. bpftrace loads a `kprobe` for
  `kprobe:`, a `tracepoint` for `tracepoint:`, a `perf_event` for
  `interval:`/`profile:`/`software:`/`hardware:`, a `raw_tracepoint` for
  `rawtracepoint:` and a `tracing` program for `fentry:`/`kfunc:` and its
  `iter:` probes: name the ones the host's scripts use.
- **By device and inode.** When the policy is applied (the agent's start,
  `nn-admin policy set`) the path is resolved — a symlink followed to the
  file the kernel runs — and the kernel matches the loader's executable by
  that device and inode, not by its name. A package upgrade that replaces
  the file leaves the line without effect (its loads refused again) until
  the policy is applied again: `nn-admin policy set` with the same file, or
  the agent's next start. A path that is not there is named in a signed
  `rule_policy` degradation.
- **Honoured only with a valid signature**, like `sysctl-allow`: an unsigned
  policy loaded through `NN_OVERLAY_ALLOW_UNSIGNED=1` keeps its other lines
  and loses its `bpf-loader-allow` (a signed `rule_policy` degradation says
  so).
- **Every load it lets through is recorded**: NN-L-AT-001 with `operation`
  `bpf_prog_opt_out`, the loader and the type, Low, no posture change (one
  record a second per loader and type). A refused load is NN-L-AT-001
  `bpf_prog_type`, High, and raises the posture to ENGAGED (an
  administrator's bpftrace meets it too: never the decisive tamper). Lot
  341: under the observe-only `alpha` profile the
  load is not refused — the same record, marked "would deny"
  ([`ALPHA_PROFILE.md`](ALPHA_PROFILE.md) §1.1); the opt-out matters only
  under `enforcing`.
- It names an executable, not a user: while it is in force any root process
  that runs that executable may load those types. bpftrace runs what it is
  given — opt out a tool only where its use outside a window is routine.
- `nn-admin policy show` lists the lines in force; the policy's summary
  counts them (`…, 1 BPF loader opt-out`).
- **bpftool needs a window, not an opt-out.** Its `pids` column comes from
  an iterator it loads (a `tracing` program: refused outside a window, the
  column left empty), and in enforce mode — a production build's default —
  `bpftool prog|map|link show` stops at the first object of the agent's
  (bpftool gives up a listing at a refused handle; the handles are not a
  load and no opt-out reaches them). Inspect the host's BPF inside a
  trusted-installer window, or read `/run/northnarrow/bpf-own-ids` and
  `/run/northnarrow/bpf-foreign` outside one.

### 2.4 Kernel module loads judged in the kernel (lot 285)

A root user loads a module without any tool — `finit_module(2)` on a file of
their choice, `init_module(2)` on a buffer — so the prevention is the
kernel's. The agent's two module-load hooks (`kernel_read_file` for
`READING_MODULE` and, from 7.0, `READING_MODULE_COMPRESSED` — the file a
`finit_module` with `MODULE_INIT_COMPRESSED_FILE` reads, kmod's load of a
`.ko.zst` or `.ko.xz` the kernel decompresses, every module of Ubuntu 26.04
(lot 303: before it, those loads were neither judged nor recorded on 7.0);
`kernel_load_data` for `LOADING_MODULE`) judge the FILE, never who loads it.
The boot checks the ids the hooks compare against with the running kernel's
BTF; where one differs, both hooks are left out and that is signed (module
loads neither judged nor recorded, a kexec image not refused) rather than
judge the wrong reads:

- **Trusted** (loads, no record): a regular file owned by root that neither
  its group nor others may write, whose inode the agent found walking the
  running kernel's tree (`/lib/modules/$(uname -r)`: the inode the kernel
  reads, not a path's text — a copy elsewhere is another inode, a hard link
  the same file), unchanged since the agent vouched for it (its change time
  and size), and:
  - unchanged since boot and a **verified package's** (dpkg's `md5sums`,
    rpm's file digests, compared with the file's content) or **DKMS's
    build** (in a DKMS or akmods output directory — `updates/dkms/`,
    `extra/` — the same content, byte for byte, as DKMS's own copy of a
    module it registered for this kernel,
    `/var/lib/dkms/<package>/<version>/<release>/<arch>/module/`); or
  - written since boot **inside a package transaction**: the kernel keeps
    the write history of every module file of the tree — created by a
    process with a package manager in its lineage, run as root, and opened
    for writing by nothing else since. A package manager is a process whose
    image is one (`dpkg`, `apt`, `rpm`, `dnf5`, `microdnf`, …) or whose
    last exec named the package manager's `#!` script by its own file
    (`/usr/bin/dnf`, `dnf-3`, `yum`: Python programs, their image the
    interpreter's; `python3 /usr/bin/dnf` is not one) — the inode the
    agent stat'ed, root-owned and written by no one else. A DKMS build
    under `apt install …-dkms` or `dnf install …-dkms` is one;
  - or named by a signed **`module-allow <module>`** line.
- **Let through, recorded High** (the coordinator's matrix, for GPU and DKMS
  hosts): a file of `updates/dkms/` or `extra/` that DKMS's registry (the
  same content) or a verified package (an akmods-built `kmod-*` package)
  vouches for, but written since boot **outside** a recognised package
  transaction — a root shell's `dkms install`, `akmods` at boot before the
  agent started. Under `enforce R018` it is refused.
- **Untrusted**: anything else — a file outside the tree, a copy, a file of
  the tree outside those two directories changed since boot outside a
  package transaction (a module built by hand, `make modules_install`), a
  file of those directories nothing vouches for (no registered build of
  its module, or one with other content), one whose owner or mode no
  longer protects it — and every `init_module` buffer.

The matrix, by file:

| The file | Default policy | `enforce R018` |
|---|---|---|
| outside `/lib/modules/$(uname -r)` (a copy, `/tmp`, another kernel's tree) | **refused** | refused |
| an `init_module` buffer | **refused** | refused |
| in the tree, a verified package's, unchanged since boot or written in a package transaction | trusted | trusted |
| in the tree outside `updates/dkms/` and `extra/`, failing the package check, or changed since boot outside a transaction | **refused** | refused |
| in `updates/dkms/` or `extra/`, the registered build (DKMS's copy, or the package's digest), before boot or written in a package transaction | trusted | trusted |
| in `updates/dkms/` or `extra/`, the registered build, written since boot outside a recognised transaction | **let through, R018 High** | refused |
| in `updates/dkms/` or `extra/`, not registered (or other content than the registered build) | **refused** | refused |
| named by a signed `module-allow` | let through, R018 Medium | let through, R018 Medium |

**The write history survives an agent restart and an upgrade within the
boot.** Its maps (`MODULE_WRITES`, and `MODULE_PKG_SCRIPTS` for dnf's and
yum's scripts) and the observer's program and link are pinned in a
directory of their own beside the pin root,
`/sys/fs/bpf/northnarrow-module-writes` (an upgrade's purge of the pin root
leaves it; `uninstall.sh` removes it). The observer goes on while no agent
runs, and the next start adopts the history registered this boot
(`/run/northnarrow/module-writes-pins`): each map the one registered (its
id), in this version's layout, the observer's link pinned beside them. The
maps are frozen (no handle writes them; the observer does), the directory
and the state protected like the agent's other pins. Anything else is a
signed reset (degraded "the module files' write history was reset"): a file
changed since boot before the new history begins is let through and
recorded High if a package or DKMS vouches for it, until the next boot —
never refused in silence. Measured: `linux-modules-extra` installed, the
agent restarted inside a window, the history adopted (the same maps), 12 of
its modules probed, 0 refused.

What happens to an untrusted load is the policy's mode of
`R018_KernelModuleLoad`:

| Policy line | Kernel | Record |
|---|---|---|
| none (default) | **refused** (`EPERM`) outside a signed trusted-installer window; an unattested DKMS or akmods build let through | R018 High; Critical and the loader's tree killed for a file outside `/lib/modules` |
| `enforce R018` | refused, an unattested DKMS or akmods build too | as the default |
| `alert R018` / `audit R018` / `off R018` | let through | as the default (the rule's own mode applies to its record) |

Inside a signed trusted-installer window an untrusted load goes through and
is recorded (Medium). A load a `module-allow` line lets through is recorded
(Medium) too. Until the agent has filled its trust map — the first seconds
of its start, measured in the lab — nothing is judged (R018 then judges by
the path, as before lot 285); the agent signs a degradation when the judge
cannot be armed (its maps not taken, or this kernel's inode offsets
unresolved: the record mode then, never the deny mode).

```
# rule-policy.local — signed by config-manage
module-allow nvidia
module-allow vboxdrv
```

- The name is the module's (`modinfo -F name`; `-` and `_` are the same
  module): letters, digits, `_`, `-` only — never a path, a `.ko`, a glob.
  At most 256 lines.
- **Honoured only with a valid signature**, as `sysctl-allow`.
- It names a module, not a file's content: while it is in force any root
  process may replace that module's file in the tree and load it (each load
  recorded). Prefer a package (the module built under the package manager)
  where one exists.
- The agent names in its journal, at its start and when the tree changes,
  every module file of the tree it does not vouch for and why
  (`module-load judge: a module file NOT trusted`): read it before you sign
  an opt-out, and before you install the agent on a host whose DKMS modules
  were built outside a package transaction.

What it does not cover: a module the boot loads before the agent starts
(the initramfs, `systemd-modules-load`, udev's first pass) — the kernel's
module signature enforcement and lockdown are what judge those (`nn-admin
host-check` reports both); a module file changed after boot but before the
write history covers it (the agent's first start of the boot; a reset of
the history, below) has no history to read: a package's or DKMS's file is
let through and recorded High (refused under `enforce R018`), one nothing
vouches for is refused, until the next boot (`akmods` at boot is one);
dnf's and yum's scripts are
recognised only where the exec sensor runs on the LSM hook (its default
where BPF-LSM is active; `--exec-sensor tracepoint` loses it: a DKMS build
under dnf is then let through and recorded, not trusted); a module file
written once outside a package transaction keeps that history until it is
created anew — a later transaction that overwrites it in place (DKMS 2.8
does) leaves it let through and recorded until the next boot. **By design**,
root who writes a module file into `updates/dkms/` or `extra/` AND puts
the same content in DKMS's registry
(`/var/lib/dkms/<package>/<version>/<release>/<arch>/module/`) gets a High
record, not a refusal, unless the policy enforces R018 — as root who runs
the package manager on a package of its own making gets a trusted file
(the package database is root's). And the residuals of
the judge itself: the trust map is the agent's (not pinned), so a restarted
agent judges nothing until it has filled it again; the change time and
size are what tie a file to its verification, so root who sets the clock
back to the very nanosecond of a verified change time and rewrites the file
in place keeps its entry (the package digests are checked again only when
the change stamp moves); a module file written under a name that is no
module's and renamed into the tree has no write history (untrusted, fail
closed), but a file a package transaction created and root rewrote through
a hard link of another name, outside the tree, before the agent first
vouched for it (a race with the transaction) keeps its package history; the
package
database itself is root's to edit before a boot; the hooks judge
`READING_MODULE` and `LOADING_MODULE` (2 in both enums on every kernel the
agent supports) — a kernel that reads compressed modules under an id of its
own would need it added.

### 2.3 Code injected into an exempt process: the exemption revoked (lot 281)

An exemption names a program (`exe`, by its file's digest) or where it was
started (`cgroup`, `unit`); neither says what the process's memory holds
once another process could write it. Since lot 281, when a process gains
**code-injection access** to another, the start-in-cgroup tracker taints
the target's mark (`agent-ebpf/src/cgroup_join.rs`, two BPF LSM programs
that never refuse anything):

- a debugger's attach (`PTRACE_ATTACH`, `PTRACE_SEIZE`: `gdb -p`,
  `strace -p`), `process_vm_writev`, `/proc/<pid>/mem` opened for writing,
  `pidfd_getfd` (whatever the descriptor), and any other access the kernel
  checks in attach mode whose system call the agent cannot read (an io_uring
  worker's: fail closed);
- a program that asks its parent to trace it (`PTRACE_TRACEME`: a program
  started under `gdb` or `strace`), tainted by the parent;
- **not** a read: `/proc/<pid>/mem` opened read-only, `process_vm_readv`,
  `ps`, `/proc/<pid>/environ`, `perf`, `kcmp` (read mode).

The taint lasts for the rest of the process's life — an exec, a move into
another cgroup, the agent's restart or upgrade do not clean it — and every
process it forks after is tainted too (inherited). The match of a tainted
process is **not exempt** by `exe`, `cgroup` or `unit`: it is judged like
any other process's, by its rule, the policy's mode and the posture, a held
kill included; the record's reasoning names the exemption and why it does
not hold ("… does not hold: code-injection access to it was given to pid
N"). An exemption by `uid` still holds: it is the uid's, whatever code runs
as it (root can become that uid without injecting anything).

Not tainted: an access by the agent or its watchdog; PID 1 and the agent's
protected processes (the anti-tamper hook refuses the access; a tainted
PID 1 would taint every service it starts); an access another LSM refused
before ours (Yama's `ptrace_scope`, AppArmor).

**The detection.** The first injection into a process is recorded by the
kernel; the agent signs it when an exemption of the policy covered the
process (whatever the taint says now): NN-L-AT-001 with `operation`
`exempt_injection`, Log, not refused, no posture trigger. Its severity:

| injector | severity |
|---|---|
| root, from an administrator's interactive `sudo`/`su` session (login uid and terminal) | **High** |
| root, any other lineage (a service, a cron job, `ssh host sudo …` without a terminal, a setuid exploit) or a lineage that cannot be told | **Critical** |
| not root | **Critical** |

The record names the injector (`principal`, `exe`), the process and its
exemption, the access (`ptrace` attach, `process_vm_writev`, …). An
injection into a process no exemption covers is a debug line only (its
mark is tainted all the same).

Where an exemption by `exe`, `cgroup` or `unit` is refused because the
taint is **not known** (fail closed): no tracker on this kernel; a process
whose mark the kernel could not keep; one started before a reset of the
marks (an upgrade from a release before lot 281 is one: its marks knew no
injection — **restart the exempt services** after it); until the tracker
is armed at the agent's start (below); a process gone before its match was
judged.

**Kept from tampering (#494's notes N1, N2).** The tracker's pinned maps
are frozen (`BPF_MAP_FREEZE`) as soon as they exist: no handle writes them,
the agent's own included — one a root took in a window, in an upgrade's
gap or while a new generation was being made writes nothing; only the
tracker's programs do. A start that makes a new generation makes its maps
with the load and pins them after it, in a directory it made: a file
planted at a pin's path or anything else in that directory is never
adopted — the maps go to the next generation, signed ("the new tracker
directory … was not the tracker's alone"). No exemption by `exe`, `cgroup`
or `unit` holds until the tracker is armed: its pins and their record
protected (the journal's "the tracker is armed" line gives the time since
the start planned them).

Refusals that are not an attack (fail closed): a tool that takes a
descriptor of a process with `pidfd_getfd` (a container runtime, a
supervisor) taints it, whatever the descriptor; an io_uring worker's
access in attach mode (its registers are not its own call) is an
injection; debugging an exempt service ends its exemption until it is
restarted.

What it does not cover:

- an injection before the agent's first start since the host booted, or
  while `kernel.ftrace_enabled` is 0 (possible inside a window only): the
  BPF programs do not run; the agent resets the marks' epoch once ftrace
  runs again (every process started before is not known);
- inside the trusted-installer window, root can plant a registered tracker
  directory with maps of its making (the window trusts its holder: it can
  replace the binaries); those maps are frozen when the next start adopts
  them, and the record says they were not;
- a BPF program of root's own that names a tracker map (any handle, a
  read-only one included, lets a program write a map): the agent's
  `bpf()` observer records the load, it does not refuse it;
- a shared library planted in the exempt program's path, an
  `LD_PRELOAD` in its unit, a writable memory mapping shared with another
  process: not an access the kernel checks as `ptrace`.

### 2.6 Modes on an open flow (lot 294)

Bug hunt 1.3, BUG45. A TCP flow is judged at its connect, in snapshots while
it stays open and at its close, and a rule that answered it is not asked
again. An `off` match and an exempt one are no answer: they leave the flow
to the other rules (an `off` NN-L-CHAIN-002 at the connect used to take the
flow's chain verdict, so the CHAIN-001/CHAIN-007 kill of a credential read
on the open session never came). A chain answer that ran no response —
`alert`, `audit`, an aged precursor's record, NN-L-CHAIN-008's `Log` — does
not keep a chain's kill from a later phase of the flow; another record of a
chain on that flow is not written. An exempt rule is judged again in the
later phases, so its recorded-only match may be written again (bounded by
the detection budget), and it acts there if the exemption no longer holds
(§2.3).

## 3. Testing it before it is signed

`nn-admin policy test` replays sample events through an offline engine (the
shipped lists of `--config-dir`, an empty `/proc`) under the candidate and
prints each decision, judged as a fresh agent judges, in OBSERVING (R009's
kill held, §1). Nothing is signed, stored, applied or executed.

```sh
nn-admin policy test --policy ./rule-policy.local --events ./sample.jsonl
nn-admin policy test --events ./case.json                  # a golden case of the repository, built-in defaults
nn-admin policy test --policy ./rule-policy.local --events ./sample.jsonl --json
```

The events are one `nn_model::Event` JSON per line (as the agent serialises
them), `{"event": …}` per line, or a golden case. Exemptions by exe, cgroup
or unit never match offline (there is no `/proc` to read); a uid exemption
does.

## 4. Signing and applying it

The policy is an overlay, signed like every other (`config-manage` role in
`admin.pub`, this agent's id, newer than the last accepted signature):

```sh
sudo nn-admin policy set --file ./rule-policy.local --key <config-manage key>
# prints the summary, then: … written; applied now (1 enforce, …; replaces built-in defaults)
sudo nn-admin policy show
```

The agent verifies the signed request, validates the content, stores the file
and its `.sig`, and applies the policy at once (between two events). The
signed `config_overlay_set` audit row records it (`applied now` in its
detail). At each boot a signed policy in force writes a signed
`rule_policy_loaded` row. Offline (agent stopped):
`nn-admin config overlay sign rule-policy --file … --key …`.

Refusals:

- a bad line: `policy set` refuses before sending (exit 2), and the agent
  refuses it too; the policy in force stays;
- an edited or unsigned file at boot: not loaded, the built-in defaults
  apply, a signed `integrity_drift` (`unauthorized_overlay`);
- a signed file that does not parse at boot (an older agent's format): the
  built-in defaults apply, a signed degradation `rule_policy`.

`--detect-only` overrides every mode: no response runs, the kernel denies
nothing; the records say `suppressed (detect-only)`.

## 5. Rolling back

- To the previous policy: `nn-admin policy set --file <the previous file>`
  (a new signature over the older content; the rollback floor refuses an
  older *signature*, not older content).
- To the built-in defaults: `nn-admin policy set` with a file that has only
  comments — applied at once: every held kill held again, the legacy
  ceiling on every rule.
- `nn-admin policy show` exits 1 when a present file would not be loaded.

## 6. Reading the records

`nn-admin detections` / the signed `detections.jsonl`: `rule_id` is the
primary rule; `matches` (absent on a record of one rule under the built-in
defaults) lists every rule with its `action`, `severity`, `mode`
(`builtin`, `enforce`, `alert`, `audit`, `exempt`), `pid`, ATT&CK ids, the
switch or the legacy ceiling still holding it (`held`: the switch's text or
`legacy_ceiling`, with `held_action`) and the exemption that covered the
actor (`exempt`). A held kill reads `Log` with its reasoning ending in
`[held back: …]`; an enforced one names the policy.

**A kill's outcome (lot 311).** Each response's outcome is signed after it
ran: `Killed`, `AlreadyGone`, `Refused` (a guard spared it) or `Failed` with
an errno. A process is captured by a pidfd and its start before it is
signalled, so a PID reused by another process is never hit. Its name does
not matter: `/proc/<pid>/stat` is read as bytes, so a process that named
itself with bytes that are not UTF-8 (which any process may do) is killed
like any other — before lot 311 its kill was signed `Failed` (errno 5) and
it ran on. A running process whose `/proc` entry cannot be read at all (the
agent out of memory or descriptors) is still signalled through its pidfd,
its start unread, and the agent logs `the process's start could not be read
— captured by its pidfd alone`. A `Failed` outcome now means the process
could not be reached: no pidfd could be opened on it, or the signal failed.
