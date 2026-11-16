# Upgrade notes: Wave 4

What changes for an operator who upgrades to a build of Wave 4 (the
capability program, tracker in the source repository:
<https://github.com/northnarrow/northnarrow-new/blob/main/docs/roadmap/CAPABILITY_PROGRAM.md>).
The changes of the external audit of `16f7563` that came before are in
`UPGRADE_NOTES_AUDIT_16f7563.md`; `CHANGELOG.md` `[Unreleased]` (at the
root of the release tree, in `/usr/share/doc/northnarrow/` from a package)
has the details of each change below.

## Before you upgrade

1. Nothing in the unit or your wrappers has to change for the agent to
   start: the settings of the removed LLM advisor are accepted and
   ignored, each named in a WARN (§1). Drop them when convenient. A
   drop-in in the agent's own unit directories that this release's agent
   judges harmful does have to change (lot 273d, §9): `install.sh
   --upgrade` lists each one and refuses, nothing changed, until you
   remove it or pass `--accept-dropin-quarantine`.
2. A host that had the advisor's model installed keeps it on disk until
   you delete it (§2).
3. A dashboard, report or SIEM rule that counted `VERDICT (ADE)` lines,
   `EXECUTED (from ADE)` lines or advisor detections gets no new ones
   (§3).
4. The quarantine vault keeps every entry and restores it as before; a
   file quarantined after the upgrade is written in a new record format
   that an agent from before it cannot restore (§5): restore such an
   entry with this release, also after a rollback.
5. A canary whose trip an earlier agent lost when it stopped at the wrong
   moment — its access row is in `canary_access.jsonl`, the registry has
   no `trip` row for it, and the agent re-armed it — is tripped at the
   first start of this release (§3): look for its signed
   `canary_trip_recovered`, and re-arm it with `nn-admin canary refresh`
   if you want it armed.
6. A start the agent refuses exits 78 whatever refused it (the capability
   gate, the audit log, the demo rules, the eBPF object and the state
   directory exited 1), and every refusal is a signed `agent_boot` row: a
   monitor that matched exit status 1 sees 78 (§6). A broken audit chain
   now refuses the start before anything is loaded.
7. R009 (a file in a home, `/tmp` or `/var/tmp` executed by root) no
   longer kills below COMBAT (lot 278, §3): a root exec it used to kill in
   OBSERVING, ALERTED or ENGAGED is a High record with the kill held, and
   R001 and R003 no longer kill an exec by root below COMBAT either. A dashboard or a
   test that expected the kill sees the record; `enforce R009` in the
   signed per-rule policy restores it in every posture
   (`RULE_POLICY.md` §1).
8. R011 no longer kills an exec of the system's `modprobe` by module name
   (lot 279, §3): the container runtimes', kube-proxy's, k3s's and an
   administrator's `modprobe <name>` is a High record. A dashboard or a test
   that expected the kill of `sudo modprobe dummy` sees the record;
   `insmod`, `modprobe` of a path, `-C`/`-d`/`-S`/`--force*`, an option
   after the name and `MODPROBE_OPTIONS` are killed as before.
9. **The first upgrade to this release** runs the scripts' windows through
   the installed nn-admin, the older one, which has no `--for-installer`:
   that upgrade's window names no installer. Below COMBAT nothing changes
   (the tree's `--version` is a High record, not killed); in COMBAT the
   script's own exec is killed anyway (§3). From the next upgrade on, the
   installed nn-admin is this one and the window covers the script's tree.
   To upgrade a host in COMBAT, release COMBAT first or install from a
   tree root owns (`/opt`, `/usr/local/src`), whose execs R009 does not
   match.
9. A signed `rule-policy.local` with `enforce NN-L-NET-003` or `enforce
   NN-L-NET-028`: from lot 275 that line is taken as `alert` at the start,
   the rest of your policy in force, and the start signs a `rule_policy`
   degradation naming it (§7). Re-sign the policy without it (`alert …`)
   when convenient: `nn-admin config overlay set` refuses a file that
   keeps it.
10. An exemption by `cgroup` or `unit` of the per-rule policy holds only
    for a process started in its cgroup since lot 277 (§8): a process
    moved into an exempt service, and a `Delegate=yes` service's or a
    container runtime's own processes, lose it. After a **"cgroup
    exemptions: marks reset"** degradation — the tracker's pins gone
    between two agents, not the registered ones, or of another schema —
    every process started before that start is "not known": **restart the
    exempt services** (`systemctl restart <unit>`) so that their processes
    are exempt again.
11. **Guarded sysctls (lot 273d).** Outside a trusted-installer window
    the agent refuses a write that would abort, starve or blind it (§9):
   `vm.overcommit_*`, `vm.max_map_count`, `kernel.pid_max`,
   `kernel.threads-max` and `kernel.sched_rt_runtime_us` by their value;
   `kernel.ftrace_enabled` and `kernel.sched_rt_period_us` whatever the
   write carries. A configuration management run or a `sysctl --system`
   that sets one of them to a harmful value sees the write refused (a
   signed `sysctl` record); inside a window it goes through and is put
   back at the window's close or the next integrity round.
12. **Upgrades refuse units the next boot would not start** (lot 273d,
   §9): enable them first — `systemctl enable northnarrow-agent
   northnarrow-watchdog` — then run `install.sh --upgrade` again.
13. **Drop-ins of the agent's own units** (lot 273d, §9): the ones this
   release's agent would quarantine are listed by `install.sh --upgrade`,
   which refuses until they are gone or you accept their move
   (`--accept-dropin-quarantine`); the ones kept are write-protected
   outside a window from then on.
14. **`nn-admin` without root** (lot 365, §54): a command that talks to
   the agent and is refused its socket, key or agent id exits 17 (was 5,
   which also means "the agent is not running") and says to use `sudo`.
   A script that ran it without root and read 5 as "agent down" gets 17.

## 1. The on-host LLM advisor is removed (lab PR 214)

The agent no longer runs a language model. The ADE (Active Defense
Engine: a Foundation-Sec-8B GGUF model run inside the agent on the execs no
rule matched), its RAG knowledge base (ATT&CK and Sigma, `cargo xtask
rag-kb`) and its XAI explanations are gone, with the vendored `candle-core`
and every model and tokenizer dependency. Why:

- a multi-gigabyte model inside the root agent process, fed with strings an
  attacker writes (process names, arguments, paths), was the largest
  attack surface of the agent;
- its accuracy was never measured (the follow-ups of the external audit
  left every model measurement open);
- it cost gigabytes of RAM on a server (about 7 GB of peak RSS with the
  model loaded);
- mature EDRs keep on-host detection deterministic; an AI assistant, if
  any, belongs off the enforcement path (for instance a future analyst
  assistant on the backend).

Detection stays deterministic: the rules, their correlation, the posture
and the COMBAT ladder. On almost every host nothing changes in what the
agent does: the model was never shipped, and without it the agent already
ran on its rules alone; and since lab PR 134 a model verdict that named a
response was only recorded as a recommendation, unless `NN_ADE_ENFORCE=1`
let it act (`UPGRADE_NOTES_AUDIT_16f7563.md` §7, which no longer applies).

**Removed settings.** The agent still accepts them, so that a unit or a
drop-in written for an older agent starts, ignores them, and writes one
WARN per setting it finds at start:

| Setting | Was |
|---|---|
| `--no-ade` | run without the advisor |
| `--ade-model PATH` | the GGUF model |
| `--ade-timeout SECS` | the inference timeout |
| `--ade-prompt PATH` | the system prompt |
| `--ade-threads N` | the CPU threads of the inference |
| `NN_ADE_ENFORCE` | let a model verdict kill, quarantine or block |
| `NN_ADE_ALLOW_MOCK` | the mock backend after a failed model load |
| `NN_ADE_RAG_ENABLED`, `NN_ADE_RAG_INDEX_DIR`, `NN_ADE_RAG_JSONL_DIR` | the knowledge base |
| `NN_ADE_TOKENIZER` | the tokenizer of the golden test |

The WARN reads, for `--no-ade`:

```text
command-line flag --no-ade removed in Wave 4 (lab PR 214) with the on-host LLM advisor: ignored, detection is deterministic (rules, correlation, posture, COMBAT); drop it from the unit, its drop-ins and wrappers flag=--no-ade
```

and `environment variable NN_ADE_ENFORCE removed in Wave 4 …
variable=NN_ADE_ENFORCE` for a variable. A removed flag's value is not
read: `--ade-timeout abc` starts too. The flags are no longer in
`northnarrow-agent --help`. `NN_ADE_ENFORCE=1` and `NN_ADE_ALLOW_MOCK=1` are
no longer reported as weakening variables by the self-integrity check
(`integrity_drift`, `weakening_env`): nothing reads them.

Other journal lines that are gone: `ADE engine ready`, `ADE engine
unavailable, fallback to rule-only mode`, `insufficient free memory to load
the ADE model`, `ADE inference started` / `completed`, `VERDICT (ADE)`,
`EXECUTED (from ADE)`, `ADE advisory: …`, `ADE shutdown stats` and the
`ADE rayon worker count pinned` line. The signed `subsystem_degraded` of a
refused RAG corpus is gone too.

## 2. Files left on the host

The agent no longer reads `/var/lib/northnarrow/models/` (the model and
its tokenizer, which an operator installed there; the release never
shipped them). `install.sh` names the directory when it finds it and
leaves it in place: they are your files, possibly several GB. Delete the
files to free the space:

```sh
sudo rm -f /var/lib/northnarrow/models/*
```

The empty directory can stay: while the agent runs it keeps
`/var/lib/northnarrow` immutable, so the directory entry itself goes with
`uninstall.sh --purge`. Nothing else of the advisor was installed: no
unit setting, no configuration file, no knowledge-base file
(`target/kb` was a build-host directory).

The unit's memory limits are unchanged (`MemoryHigh=9G`, `MemoryMax=11G`,
`OOMScoreAdjust=-500`): they were sized for the model, and stay until the
lab has measured the agent's memory without it. On a host whose memory is
not above 11G the agent still raises its own `oom_score_adj` to 0 at start
(`UPGRADE_NOTES_AUDIT_16f7563.md` §1).

## 3. Detections and evidence

- **R011 judges a module tool's command line (lot 279).** An exec of
  `modprobe` (or `kmod`) by the system's tool, of plain module names with
  only options that move and force nothing before the first name, and none
  of `MODPROBE_OPTIONS`, `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` in its
  environment, is recorded (High, T1547.006, `response: none`), its
  reasoning naming the names ("modprobe of 'overlay'"); `kmod list`,
  `static-nodes` and kmod run as `lsmod`, `rmmod`, `modinfo`, `depmod` too.
  Killed as before, the reasoning saying why ("killed: …"): `insmod`; a
  path or a `.ko*` name; `-C`, `-d`, `-S`, `--force*`, `-o`,
  `--remove-holders`, `--remove-dependencies`; an argument starting with
  `-` after the first name (`modprobe <name> -q`); a copy of the tool or a
  program whose device and inode are not those of the file `/usr/bin/kmod`
  resolves to, or every tool when `/usr/bin/kmod` and `/bin/kmod` are two
  different files (not one file under both names, as a merged `/usr`
  shows it); one of those variables (a root shell with `LD_LIBRARY_PATH`
  set kills its `modprobe`; read, it is evidence: killed even if the
  process has since exited, not a false positive); a running process whose environment the agent
  could not read at the exec, an environment over 1 MiB; a cut argv. A
  module tool that had exited before the agent could read its environment
  is recorded, the reasoning saying so ("exited before its environment
  could be read — a load it made is the kernel's to judge (R018); its
  environment not verified"): its kill would reach no one. A tool whose
  first thread exited while another runs on has not exited: its
  environment is read through the running thread (killed when none is read
  whole). R011 resolves no
  name and reads no `modprobe.d`: the load is the kernel's signature
  policy's to refuse, and R018's to judge after it (with no verdict for a
  packaged file loaded by a comm of its loader allowlist). The
  `install`/`remove` commands of `modprobe.d` are a residual
  (`TAPPA9_FIM_TRUST_MODEL.md`).

- **No more advisor detections.** An exec that no rule matches gets no
  detection (it was offered to the model when one was loaded). Rule
  detections, posture transitions, the COMBAT ladder, the canaries, FIM
  and the anti-tamper denials are unchanged.
- **Older records still read and verify.** A detection the advisor wrote
  before the upgrade (`"path":"Ade"`, `"verdict":{"Ade":"…"}`, a response
  `advisory: <action> recommended by the model, not executed`) is still
  decoded by `nn-admin` and the chain verifiers, byte for byte, and its
  chain verifies; no new one is written. The `explanation` field of the
  detection schema (XAI, never written) is gone.
- **Signed audit log.** No `subsystem_degraded` for a refused knowledge
  base any more; nothing else in the audit rows changes with the
  advisor's removal.
- **COMBAT rows name the trigger and the offender (lab PR 245).** The
  `combat_stage` rows of a COMBAT the posture reached carried `"trigger":
  null`, and the INVESTIGATE row named no offender. They now carry the
  trigger (in `trigger`, and in the `combat_outcome` rows), and two new
  fields, `cause` (the evidence the trigger cites, or the forced COMBAT's
  signers) and `offender_details` (each offender's pid, start, executable
  and cgroup as captured); a later COMBAT entry naming another process
  during an episode writes a row with `added`. `COMBAT_RECOVERY.md` §3.4
  has the fields. A query of `trigger` sees names where it saw `null`; the
  rows written before the upgrade keep their bytes and verify as before,
  and the INVESTIGATE row of an episode that opened with a failed soft
  block now carries the failure (it was a row of its own).

- **A canary trip survives an agent that stops in the middle of it (lab
  PR 260).** A trip is two signed rows, the access row in
  `canary_access.jsonl` (`first_trip: true`) and then the `trip` row in
  `canaries.jsonl`. An agent stopped between the two (a crash, a kill, a
  power loss, or a `trip` row it could not write) re-armed the canary at
  its next start: the next access was a first trip again, and the
  registry never showed the first one. Each start now reads the access
  log's first-trip rows of the canaries the registry holds armed, and
  records one the registry does not: an ERROR (`canary: a trip the
  registry did not record`), a signed `canary_trip_recovered` in the
  audit log (`extra`: the canary's id and name, the access row's
  position, hash and time, the accessor's pid, uid, comm and executable,
  how many such rows) and a `trip` row naming the access row, which
  `nn-admin canary list` shows; the canary stays tripped until `canary
  refresh`. If the agent stopped before it answered the access, the
  response (NN-L-CANARY-00x, the kill) did not run: check the accessor.
  Only rows the agent's key signed count, at the place they were signed
  with. A `refresh` row now names the trip it clears
  (`first_trip_access_hash`, `tripped: false`; `null` when the canary was
  armed): an agent from before reads it as before, the trip cleared.
  A trip an agent before this release recorded only in memory (before lab
  PR 143) or lost as above, and an operator refreshed afterwards, stays
  refreshed: a refresh row that names nothing counts after the first-trip
  rows older than it.

- **R009 kills in COMBAT only; an installer's window covers its own tree
  (lot 278).** R009 killed root automation run from a checkout or an
  unpacked tree — `install.sh --upgrade`, `uninstall.sh`, Ansible `become`
  without a terminal, cloud-init, CI — in OBSERVING too; at a terminal under
  `sudo` the record was sometimes the kill, depending on the milliseconds
  between sudo's exec and the fork of its monitor (the lineage lost the
  session: fixed). Now: below COMBAT the match is a High record, `held`
  naming the kill and the posture (R001 and R003 likewise on an exec by
  root); in COMBAT, or under `enforce R009`, the tree is killed as before. A
  trusted-installer grant asked for an installer (`nn-admin
  trusted-installer-grant --for-installer`, which the scripts pass when the
  installed nn-admin knows it; a new admin request, which an older agent
  cannot read — nn-admin then asks for the plain grant) is made to that installer
  (the process that ran `nn-admin`, by its pid and its start; the agent's
  journal line `trusted-installer override ARMED` names `granted_to_pid`,
  the audit row `for_installer` and `installer_pid`), and R009 records at
  Low what that process's tree executes after the grant while the window is
  open, naming the installer (`INSTALL_UPGRADE_UNINSTALL.md` §2.1). The
  tool rules' kills of a root exec from `/tmp` or a home (R011–R013,
  R017) are unchanged. The decision is recorded in `RULE_POLICY.md` §1. `install.sh --upgrade` opens its
  window before it executes anything from its tree; a refused run executes
  nothing from it.

- **The mass-write signal counts files destroyed, not writes; a package
  transaction's refusal no longer brings COMBAT; no kill on one heuristic
  (lot 282).** What you see change
  ([the posture design, §10](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/POSTURE_FSM_V2_REDESIGN.md)):
  - fewer `ConfirmedIntrusion` transitions: image pulls, package and build
    tools, clones and databases no longer raise it (an image pull on a
    fresh host reached COMBAT, and the ladder killed podman);
  - the kernel's mass-write events count differently. `MassWrite` with
    `overwrites: true` carries in `count` the distinct existing files
    rewritten (it carried every write-open); with `overwrites: false` it is
    the files written new — created by the open, or empty when opened
    (`mknod`, `O_TMPFILE`), each once (it was every write-open, the same
    file's included); a new field `small_files: true` marks an overwrite
    crossing that needed files under 4 KiB (counted by the posture outside
    an authenticated session only, never by NN-L-IMP-001's shape (a)); a
    `FileBurst` of kind `unlink` counts each original once per name and
    window — any regular file that holds data (it was 4 KiB or more), or
    held it within the window (a truncate then an unlink), a rename onto
    one included, a file the process itself created in the window and a
    file in a directory whose writes do not count (`/run/systemd`, the
    journal, a pseudo-filesystem, `/run/udev` — a carve-out since this lot:
    udevd's device database —, the operator's carve-outs, the process's
    own runtime directory) excluded;
    both events carry a new `cgroup_id` (the writer's cgroup v2 id, the
    posture's pairing of a copy and a deletion). The
    agent's journal lines say so: `mass write: distinct existing files
    rewritten crossed the threshold` (with `small_files=` and `cgroup=`),
    `mass write: files created crossed the threshold (files written new …)`,
    `file burst: rename or destroyed-originals threshold crossed` (with
    `cgroup=`) (were `mass write: write-open threshold crossed` and `file
    burst: rename or unlink threshold crossed`); an exempt writer's crossing
    is an INFO line naming the exemption;
  - a new posture trigger, `PackageTamperRefusal` (ALERTED), in the
    journal's `POSTURE TRANSITION` lines, for an anti-tamper refusal of a
    file operation (unlink, rmdir, rename, setattr, create, link, symlink,
    mkdir, mknod, an extended attribute) of a package transaction's process
    (it was `AntiTamperDenial`, COMBAT); its other refused operations — a
    signal, a ptrace, a BPF handle, a kexec, a cgroup write, a limit — keep
    their weight; the refusal's NN-L-AT-001 record is unchanged;
  - a COMBAT whose cause is one heuristic signal with nothing of another
    kind vouching for it signs a `combat_stage` row "NEUTRALIZE held" and
    kills nothing; the journal line of a COMBAT entry now names the signals
    that corroborated it;
  - NN-L-EVA-002 is no longer recorded when a container runtime flushes
    its own chain (`CNI-…`, `DOCKER…`, `KUBE-…`, `cali-…`, `cilium_…`,
    `NETAVARK…` — not the filter chains `DOCKER-USER`, `CNI-ADMIN`,
    `KUBE-FIREWALL`, which stay a switch-off — the `iptables`'s parent the
    runtime's packaged program); it still is for the same chain flushed by
    another process and for the host firewall's chains (an INFO line,
    `NN-L-EVA-002: a container runtime's chain flushed by a process its
    runtime does not vouch for`, names the parent).
  The signed rows written before the upgrade keep their bytes and verify.

## 4. Build and development (source builds only)

- `cargo xtask ade-demo` and `cargo xtask rag-kb` are gone, so are the
  examples `ade_attacks`, `ade_demo`, `ade_smoke`, `ade_with_rag`,
  `bench_threads`, `rag_demo` and `diag_hw`, and the fuzz targets
  `ade_verdict` and `ade_preparse`. The posture demo stays, without its
  verdict-modulation phase.
- The release profile is unchanged (`lto = "fat"`, `panic = "abort"`); a
  build is shorter and the dependency graph smaller (about 150 crates fewer
  in `Cargo.lock`).

## 5. The quarantine vault's record format (lab PR 238)

A file the agent quarantines is kept encrypted in
`/var/lib/northnarrow/quarantine/vault/<id>.bin`, described by
`<id>.meta`. The `.bin` had no header: its format was implied by the key
derivation alone. A new entry is now written as format 2: the `.bin`
starts with `NNQV` and the byte `02`, which the encryption authenticates
with the content, and the `.meta` says `"format": 2`.

- **Nothing to migrate.** Entries written before the upgrade are not
  rewritten: their `.meta` names no format, and they are read and restored
  as before (`nn-admin response restore`, the same SHA-256 check).
- **Rollback.** An agent from before this release does not read format 2:
  its restore of a new entry fails (a decryption error) and writes
  nothing; the entry stays in the vault for this release to restore.
- **Refusals.** A `.meta` that names a format this agent does not read,
  or a `.bin` whose header disagrees with its `.meta`, is refused with
  that reason (`response restore` exits non-zero, nothing is written):
  the entry was changed or damaged after it was written.

## 6. Refused starts (lab PR 262)

The agent checks its integrity before it loads anything into the kernel
and refuses the start when a check fails (`BOOT_INTEGRITY.md` §1 and §7).
What an operator sees change:

- **Exit status 78 for every refusal** (`EX_CONFIG`; systemd shows
  `status=78/CONFIG`). The capability gate (CAP_KILL missing in
  enforcement), the audit log (not writable, or its chain cannot be
  opened), the demo rules' gate, the embedded eBPF object, the state
  directory as a link, the sensors' load and the deny hooks' shortfall
  exited 1; the install manifest, the BPF LSM, the deny self-test and the
  BTF offsets already exited 78. The watchdog restarts a refused agent as
  before, within its ceiling.
- **Every refusal is signed.** An `agent_boot` row with `result: refused`
  names the gate in `refused_by`: `ebpf_object`, `state_dir`,
  `btf_offsets`, `demo_rules`, `capabilities`, `install_manifest`,
  `audit_log`, `bpf_lsm`, `sensors`, `deny_hooks`, `deny_self_test`. A
  refusal before the install manifest's check carries `binary_integrity:
  unchecked`. A query of refused boots finds rows it did not find before.
- **When the audit log is what refuses** (not writable, its chain broken),
  the refusal is signed in a file of its own,
  `/run/northnarrow/boot-refusals/refusal-<random>.jsonl` (the audit log's
  format and key: `sudo nn-admin audit verify --from <file>`), whose first
  row (`boot_refusal_fallback`) names the audit log and its head. The
  agent creates that directory and checks it before it writes; a link, a
  FIFO or any other name put there is never followed, written or waited
  on — such a start's refusal is then in the journal alone. The next start
  that opens the audit log records each file there — a
  `boot_refusals_recovered` row, before its own `agent_boot`, `recorded`
  for a chain bound to that log, `refused` with why for anything else —
  and removes it. The files are on tmpfs: a reboot before that start
  loses them, and root can delete them (the journal keeps the refusal's
  lines).
- **A signing key that is there but cannot be loaded refuses the start**
  (corrupted, empty, a bind mount of `/dev/null` over it, not a regular
  file): exit 78, `refused_by` cannot be signed — the journal's `start
  refused gate=audit_log` and `agent signing key cannot be loaded` are the
  record. Such a start ran unaudited before, with one WARN. An absent key
  is minted as at a first boot; `NN_AUDIT_ALLOW_UNWRITABLE=1` starts it
  unaudited, as for an unwritable audit log.
- **The deny hooks' pin root and the kernel's BTF are checked before the
  load.** A pin root that is a symbolic link, and a kernel without
  `/sys/kernel/btf/vmlinux` (or a tmpfs over `/sys/kernel/btf`), refused
  the start after the load (the maps pinned, on a host without them); now
  before it (`refused_by: deny_hooks`), unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` as before. The preflight's
  `boot phase done` line lists `pin_root` and `vmlinux_btf` among its
  steps.
- **A refusal before the load creates no state file but what it needs to
  be signed**: the eBPF object's, the state directory's and the BTF
  offsets' refusals no longer bootstrap the FIM, detection, canary and
  network logs or the head anchor.
- **A broken audit chain refuses before the load.** A line before the end
  that is not a row used to refuse the start after the eBPF object was
  loaded, its maps pinned and the hooks attached; now nothing is loaded and
  the previous agent's hooks, when pinned, stay as they were.
- **A refused start leaves no protected pid.** Its registration in the
  pinned `PROTECTED_PIDS` (made before it bootstrapped its files) is
  withdrawn before it exits.
- **The journal of a start**: `reusing existing agent signing key`, which
  the audit log's open logs, comes before the attach now (it came after
  the deny self-test); every other line is where it was.
- **Rollback to a release before this one.** Nothing to migrate: the rows
  are the audit log's format. An older agent does not read
  `/run/northnarrow/boot-refusals/`; it stays until a reboot or until this
  release starts again and records it. An older agent starts unaudited on
  a key that cannot be loaded, as it did.

## 7. NN-L-NET-003: a TLS fingerprint is not an identity (lot 275)

- **What changes.** The TLS ClientHello sensor of lot 275 produces the
  first real fingerprints, so NN-L-NET-003 matches for the first time. A
  JA3 — or, new, a JA4 — in `netflow-ja3-blocklist.{v1,local}` is a
  **Medium** record with no response (`Log`), no longer a Critical
  `KillProcessTree` with COMBAT: a fingerprint names a TLS library and its
  settings, which every program on it shares (R6 of the external review
  of 04/11; `NETWORK_TELEMETRY.md` §3). The list file keeps its name and
  accepts JA4 entries next to JA3.
- **A policy that enforced it.** `enforce NN-L-NET-003` is refused until the
  rule has a second predicate (a destination or an executable). A signed
  `rule-policy.local` that holds the line is **not** dropped at the start:
  only that line is taken as `alert`, every other line stays in force, and
  the start signs a `rule_policy` degradation — "line N: enforce
  NN-L-NET-003_BadJa3 refused, applied as alert … — the rest of the policy
  is in force" — which `nn-admin status --key` lists and `policy show`
  names in the policy's source. `nn-admin config overlay set` refuses a
  file with the line: replace it with `alert NN-L-NET-003` (or `audit`)
  and re-sign.
- **NN-L-NET-028 too** (the review of #495): its `enforce` is refused the
  same way — refused by `config overlay set`, applied as `alert` at the
  start, a signed degradation — until the rule is measured on a wider
  corpus: its kill judges the absence of a DNS answer, which benign
  software can produce out of the agent's sight (a container's resolvers
  of its own, DNS over TCP, DoT or DoH). Its records stay Medium or Low,
  `Log`.
- **Monitoring.** A rule that matched NN-L-NET-003 as Critical, or its
  `net_critical` category, sees `Medium` and `net_medium`; it is out of the
  V2 Critical sub-gate.
- **Rollback.** An agent from before this release reads the same policy
  file as before (the line was valid there) and the list's JA3 entries; it
  skips the JA4 entries at its start (a line it cannot parse, a WARN each)
  and its `config overlay set` refuses an overlay that has one.

## 8. Exemptions by cgroup or unit and the start-in-cgroup tracker (lot 277)

An exemption by `cgroup` or `unit` (`RULE_POLICY.md` §2.1) holds only
for a process started in that cgroup — spawned there by systemd, or
forked from one that was; the kernel's start-in-cgroup tracker marks the
others. What an operator sees change:

- **The tracker's pins are beside the pin root**:
  `/sys/fs/bpf/northnarrow-cgroup-join-v<schema>_<generation>`, recorded
  in `/run/northnarrow/cgroup-join-pins` (both protected like the agent's
  other files). `install.sh --upgrade` leaves them — the marks outlive
  the upgrade — and `uninstall.sh` removes them.
- **A reset is signed and fails closed.** A start adopts only the
  directory its predecessor of this boot registered, each map the one
  registered, in this schema's layout. Anything else — the directory gone
  between two agents ("marks lost between agents"), maps that are not the
  registered ones, a directory nobody registered, an older schema's —
  builds new maps and signs "cgroup exemptions: marks reset …"; from that
  start every process started before it, and what it forks, is "not
  known" (refused an exemption by cgroup or unit) until it exits. **Restart
  the exempt services** after such a degradation. A schema change of a
  future release says in its notes whether it migrates the marks; this
  release's schema is the first.
- **`kernel.pid_max` or `kernel.threads-max` raised** after the marks were
  made is no reset: the marks keep the capacity they were made with, a
  signed note says it is below the host's, and a process past it is "not
  known" (refused), never exempt. A reboot makes them at the new size.

## 9. Guarded sysctls and the boot enablement (lot 273d)

- **Known limit: tuned's `realtime` profile.** It sets
  `kernel.sched_rt_runtime_us = -1` (real-time throttling off), which the
  agent treats as harmful: outside a window the write is refused, and a
  value set at boot or inside a window is put back (to 95 % of the period)
  at the window's close and at every integrity round. With lot 273d alone
  that profile cannot hold, not even inside a window. Since lot 280a a
  signed opt-out per sysctl lets it: `sysctl-allow
  kernel.sched_rt_runtime_us -1` in the signed per-rule policy
  (`RULE_POLICY.md` §2.2), honoured only with a valid signature, every
  write it lets through recorded.
- **`kernel.ftrace_enabled` and `kernel.sched_rt_period_us`** are refused
  outside a window whatever the write carries: a tool that writes them,
  even the value they hold, needs a window.
- **A value written in another base than 10** (`040000`, `0x10000`) is
  refused outside a window: write the decimal value. (Lot 280a: the
  kernel's copy is judged in base 0, as the kernel reads it; the write
  deny before it still refuses such a spelling unread.)
- **The hook and the round judge the RT runtime differently.** Outside a
  window the write deny refuses a runtime of -1 or of at least 990000 µs —
  99 % of the default 1 s period: it cannot read the period, whose every
  write it refuses. The integrity round judges the runtime against the
  period the host has (one set inside a window): with a period of 500000,
  a runtime of 495000 passes the hook and is put back by the next round,
  to 95 % of the period (never 0; for a 1 µs period, to the kernel's
  defaults, 1 s and 950 ms).
- **`install.sh --upgrade`** refuses, before it changes anything, to
  upgrade running units that are not enabled or not pulled in by the
  default target ("the next boot would start no agent"); its health check
  reads the same after the switch, and a failed upgrade's rollback enables
  again the units that were enabled before it.
- **Drop-ins of the agent's own units.** The directories
  `northnarrow-agent.service.d`, `northnarrow-watchdog.service.d`,
  `northnarrow-.service.d` and `northnarrow.slice.d` (under
  `/etc/systemd/system`, `/run/systemd/system` and both `system.control`)
  are the agent's: a drop-in there that this release's agent judges
  harmful to its units — a value below a floor, a setting that breaks the
  agent, an `NN_` or loader variable, an `EnvironmentFile=` outside
  `/etc/northnarrow/` (such as `EnvironmentFile=-/etc/default/…`), a
  `CPUAffinity=` that leaves out online CPUs, a symlink, a hard link —
  is moved to `/var/lib/northnarrow/quarantine/dropins/`.
  - **At the upgrade, nothing of yours moves silently.** `install.sh`
    (full mode, `--upgrade` or a new install) asks the new agent
    (`northnarrow-agent --own-dropins check`, read-only) which existing
    drop-ins it would quarantine, lists them, and refuses — nothing
    changed — until you remove them or re-run with
    `--accept-dropin-quarantine`, which moves them first (each move
    printed). A refused `--upgrade` has already opened its
    trusted-installer window: it ends at its deadline.
  - **After the install,** the integrity round moves only a drop-in
    changed outside a window since the agent was installed (its binary's
    ctime): one made inside a window is judged at the window's close, one
    from before the install is never moved by the round.
  - **A drop-in kept** at a close or by a round — and the file an
    `EnvironmentFile=` of it names under `/etc/northnarrow/` — is
    write-protected outside a window: edit it inside one. Such an
    environment file must be a regular file with one name, there when the
    drop-in is judged; otherwise the drop-in is quarantined.
  - **To put one back,** open a window (`nn-admin trusted-installer-grant`),
    copy the file from the quarantine into place, `systemctl
    daemon-reload`; it is judged again at the window's close. Writing a
    drop-in of the agent's units inside a window (a copy, `systemctl
    edit`) is a Low record of NN-L-FIM-009; before this release the rule
    killed the writer even inside a window.
  - **Settings of the agent (`NN_` variables) in its units' drop-ins are
    configuration, kept.** Write such a drop-in inside a trusted-installer
    window (outside one the directories refuse it), `systemctl
    daemon-reload`, restart the agent inside the window. The window's
    close keeps it and write-protects it; the agent signs each `NN_`
    setting it finds (`own_dropin_setting`, with the name, the value and
    the drop-in), and a switch that weakens it — `NN_ANTI_TAMPER_ALLOW_DEGRADED`,
    `NN_AUDIT_ALLOW_UNWRITABLE`, `NN_DETECT_ONLY`, a sensor back to its
    fallback (`NN_FILE_OPEN_SENSOR=tracepoint`, `NN_EXEC_SENSOR=tracepoint`,
    `NN_DNS_SENSOR=sendmsg`), `NN_EXEC_POLICY=off`, `NN_EXEC_POLICY_NO_ENV`,
    `NN_EXEC_POLICY_NO_MAP`, `NN_EXEC_POLICY_PROFILE=desktop`,
    `NN_EXEC_QUARANTINE=off`, `NN_EXPLOIT_GUARD=off`, an
    `NN_EXPLOIT_GUARD_TASKS` below the host's `pid_max`,
    `NN_EXPLOIT_GUARD_RESPONSE=detect`, `NN_NET_CONNECT_DENY=0`,
    `NORTHNARROW_DRY_RUN`, the others the agent's own start flags — is a
    High `own_dropin_weakening`. `install.sh` lists them as kept
    configuration and never refuses for them. A loader variable
    (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`), or one that points a
    tool the agent runs elsewhere (`XTABLES_LIBDIR`, `IPTABLES_LIB_DIR`,
    `RPM_CONFIGDIR`) or redirects systemd's notifications (`NOTIFY_SOCKET`),
    stays harmful:
    the drop-in is quarantined, and so is one that sets an `NN_` variable
    beside something harmful.
  - A package install or upgrade (`.deb`, `.rpm`) runs the check as a
    warning only: its configure step names each drop-in the agent judges
    harmful and moves nothing (a package hook never fails on it). The
    agent's integrity round leaves such a drop-in from before the install
    in place and reports it, signed (`own_dropin_preinstall_harmful`):
    remove it, or move it out inside a trusted-installer window.

## 10. The sysctl judge on the root cgroup (lot 280a)

- The agent links a `cgroup/sysctl` program to the root cgroup: a write of a
  guarded sysctl is judged on the kernel's copy of the write, after the
  write deny judged its bytes (a second thread can no longer change them in
  between). Its program and link are pinned in
  `/sys/fs/bpf/northnarrow-sysctl`, beside the pin root and protected like
  it: they outlive an agent stop and `install.sh --upgrade` (marked `kept`
  in `/run/northnarrow/bpf-own-ids`, not waited for), and the new agent
  swaps them for its own. `uninstall.sh` removes them.
- `bpftool cgroup show /sys/fs/cgroup` lists it (`sysctl`, `multi`,
  `nn_sysctl_guard`). Another `cgroup/sysctl` program on the root cgroup
  is named at the start, in a signed degradation (attached after ours it
  runs after it).
- A host without a cgroup v2 mount of the hierarchy's root (cgroup v1 only)
  keeps lot 273d's write deny alone: a signed `anti_tamper` degradation,
  and the manifest's `sysctl_judge` attach point names the fallback.
- **A downgrade below lot 280a** with `install.sh --upgrade` of the older
  release leaves the judge linked (that release does not know its
  directory) until the next boot: run `uninstall.sh` first, or remove
  `/sys/fs/bpf/northnarrow-sysctl` inside a trusted-installer window.

## 11. The switches that blind the sensors (lot 280b)

- **Refused outside a trusted-installer window, whatever they carry**:
  writes of `/sys/kernel/debug/kprobes/enabled`, of
  `debug.kprobes-optimization` and of `/sys/kernel/security/lockdown`
  (NN-L-AT-001 `kprobes`, `sysctl`, `lockdown`, ENGAGED). A tool that
  writes one of them, even the value it holds, needs a window; raise the
  lockdown mode at boot (`lockdown=integrity`). A `0` found in either
  kprobes switch is put back to `1` at a window's close and by the
  integrity round.
- **`lockdown=confidentiality`**: the agent does not start under it (the
  helpers its programs read kernel memory with are taken from every BPF
  program loaded after the raise: `KERNEL_COMPATIBILITY.md`, "Lockdown").
  The host check now warns on it; boot with `lockdown=integrity`.
- **An attach of a `cgroup/sysctl` program to the root cgroup** outside a
  window is refused (`sysctl_root_attach`); one already there, or attached
  inside a window, is signed High once (`sysctl_root_prog`, not refused).
  A tool that attaches such a program to the root needs a window; one that
  attaches it to its own child cgroup is not concerned.
- **New detections, not refusals**: a taint flag of code entering the
  kernel that appears while the agent runs (`kernel_taint`: Critical for
  an unsigned or forced module, High for an out-of-tree or proprietary
  module or a livepatch). A DKMS module built and loaded after the start
  is one: the detection says so, the posture does not move. The flags set
  before the start are only in the manifest's new `kernel_code` (and in
  `nn-admin capabilities`).
- **`kernel.ftrace_enabled=0` inside a window**: the start-in-cgroup
  tracker's marks are lost while it holds (signed `cgroup_join_marks`) and
  reset once ftrace runs again — as after a start that could not adopt
  them, **restart the exempt services** after it.

## 12. Code injected into an exempt process (lot 281)

- **An exemption by `exe`, `cgroup` or `unit` no longer holds for a
  process code was injected into** — a debugger's attach (`gdb -p`,
  `strace -p`), `process_vm_writev`, a write handle on its
  `/proc/<pid>/mem`, `pidfd_getfd`, or a program started under a debugger
  (`PTRACE_TRACEME`) — nor for what it forks after, for the rest of their
  lives (`RULE_POLICY.md` §2.3). Its matches are judged like any other's;
  the record's reasoning says which exemption did not hold and why. A
  read (`/proc/<pid>/mem` read-only, `process_vm_readv`, `ps`) changes
  nothing; an exemption by `uid` still holds. Debugging an exempt service
  ends its exemption until it is restarted: restart it after a debugging
  session.
- **A new detection, not a refusal**: NN-L-AT-001 `exempt_injection` for
  the first injection into a process an exemption covered — High from an
  administrator's interactive `sudo`/`su` session, Critical otherwise
  (another lineage, not root). No posture trigger.
- **The upgrade resets the marks once**: the tracker's schema is now 2
  (its marks carry the injection taint); a schema-1 directory is not
  adopted. The start signs "cgroup exemptions: marks reset … schema v1 …"
  and every process started before it is refused an exemption by `exe`,
  `cgroup` or `unit` until it exits. **Restart the exempt services after
  the upgrade.**
- **Until the tracker is armed** at each start (its pins and their record
  protected; the journal's "the tracker is armed" line), and on a kernel
  without the tracker, an exemption by `exe` is refused too (before, only
  `cgroup` and `unit` were): whether code was injected into the process is
  not known.
- **The tracker's maps are frozen**: `bpftool map update` or `delete` on a
  pinned `northnarrow-cgroup-join-v2_*` map fails with `EPERM` for every
  caller, root and the agent included. The start no longer sweeps dead
  processes' marks (a dead group's mark goes at its pid's next fork).

## 13. Kernel module loads judged in the kernel (lot 285)

- **A module load of a file the agent does not vouch for is refused**
  (`EPERM`), outside a signed trusted-installer window, by default — and
  every `init_module` from memory (`RULE_POLICY.md` §2.4). The agent vouches
  for the module files of the running kernel's tree that a verified
  package installed or DKMS built (unchanged since boot), that a package
  transaction wrote since boot, or that a signed `module-allow <module>`
  names. Who loads does not matter: `modprobe`, `udev`, a service, a
  process of its own.
- **GPU and DKMS hosts keep loading their modules** (the coordinator's
  matrix, `RULE_POLICY.md` §2.4). A DKMS build in `updates/dkms/`, or an
  akmods `kmod-*` package's file in `extra/`, whose content is the build
  DKMS registered for the running kernel (compared byte for byte with
  `/var/lib/dkms/…/module/`) or the digest the package database recorded,
  is trusted when it was written before this boot or inside a package
  transaction (`apt`, `dpkg`, `rpm`, `dnf`, `dnf5`, `yum`: dnf's and yum's
  Python script recognised by the file their exec named). Written since
  boot outside one — a root shell's `dkms install`, `akmods` at boot
  before the agent started — it is **let through and recorded High**
  (`R018`, "let through by the default policy"); with a signed
  `enforce R018_KernelModuleLoad` it is refused. **A file in those
  directories that DKMS's registry and the packages do not vouch for is
  refused**, like a file outside the tree, a copy, a buffer, and a
  packaged file elsewhere in the tree changed since boot outside a
  transaction.
- **Before the upgrade, list what would be refused.** A module copied into
  `/lib/modules` by hand (`make modules_install`), a vendor's `.run`
  installer's module (not DKMS-registered), a file of `updates/dkms/` or
  `extra/` that is not the registered build: untrusted, refused. After the
  upgrade the agent names each such file in its journal at its start
  (`module-load judge: a module file NOT trusted`, with why); the summary
  line counts the DKMS or akmods builds let through and recorded. Sign a
  `module-allow <module>` for each module the host needs, or put the deny
  off for the time being with a signed `alert R018_KernelModuleLoad` (the
  record mode: every untrusted load let through and recorded High).
- **The module files' write history goes through the upgrade**: its maps
  and observer are pinned beside the pin root
  (`/sys/fs/bpf/northnarrow-module-writes`, protected, kept by the
  upgrade's purge, removed by `uninstall.sh`), and the new agent adopts the
  history of this boot's package transactions — a package of modules for
  the running kernel installed earlier in the boot stays trusted. A history
  the new agent cannot adopt (another version's layout) is reset, signed:
  until the next boot the files changed since boot before the new agent
  started are let through and recorded High when a package or DKMS vouches
  for them. The first upgrade to this release finds no history: the same,
  for the files written this boot before it.
- **Residual, by design**: root who writes a module file into a DKMS
  output directory AND registers the same content in DKMS's state
  (`/var/lib/dkms/<package>/<version>/<release>/<arch>/module/`) gets a
  High record, not a refusal, unless the policy enforces R018. Hosts with
  no DKMS or akmods modules lose nothing by `enforce R018_KernelModuleLoad`.
- **What the boot loads before the agent starts is not judged** (the
  initramfs, `systemd-modules-load`, udev's first pass). From the agent's
  start until its trust map is filled (the first seconds) nothing is judged
  either; R018 judges those loads by the path, as before.
- **R018 has no loader allowlist any more**: a trusted file is silent
  whoever loads it (no more Medium for a standard module by an unexpected
  loader); an untrusted one is recorded High whoever loads it (no more
  silence for `kmod`, `systemd-udevd`, `systemd-modules-load`); a file
  outside `/lib/modules` still has its loader's tree killed.
- **New records**: NN-L-FIM-026 for a write in a `modprobe.d` directory
  (High outside a package transaction), R011 Medium for a command a
  `modprobe.d` `install`/`remove` directive runs. The FIM watch list gains
  `/run`, `/usr/local/lib`, `/lib` and `/usr/lib` `modprobe.d`; an
  unmodified `fim-paths.v1` of an earlier release is replaced by the
  install, as for every shipped list.

## 14. Foreign BPF (lot 290)

- **A load of a `kprobe`, `tracepoint`, `perf_event`, `raw_tracepoint`,
  `raw_tracepoint_writable`, `tracing`, `struct_ops`, `ext` or `lsm` BPF
  program is refused outside a signed trusted-installer window** (`EPERM`)
  to every process outside the agent's family, in every mode of the BPF
  guard (`NN_BPF_DEFENSE_OBSERVE=1` included). bpftrace, Falco, Tetragon,
  Cilium's agent and the like stop loading outside a window: before the
  upgrade, sign a `bpf-loader-allow <executable> <types>` line for each
  tool the host runs outside one (`RULE_POLICY.md` §2.5: bpftrace's
  `tracepoint:` and `interval:` probes are `tracepoint` and `perf_event`
  programs — name them too). Every other program type (systemd's and the
  container runtimes' cgroup programs, tc, XDP, socket filters) loads as
  before, recorded.
  A refusal is NN-L-AT-001 `bpf_prog_type` (High, ENGAGED), a load the
  opt-out lets through `bpf_prog_opt_out` (Low).
- **The agent's maps and programs are off limits outside a window** (the
  guard enforcing, a production build): `BPF_MAP_GET_FD_BY_ID` (a read-only
  handle too), `BPF_PROG_GET_FD_BY_ID`, and `BPF_OBJ_GET` of anything under
  `/sys/fs/bpf/northnarrow*` fail with `EPERM` (NN-L-AT-001 `bpf_handle`,
  ENGAGED). **`bpftool prog|map|link show` stops at the first NorthNarrow
  object** outside a window (bpftool gives up a listing at a refused
  handle), and its `pids` column is gone (its iterator is a `tracing`
  program); inside a window both work. The agent lists its own programs in
  `/run/northnarrow/bpf-own-ids` and the host's foreign ones in
  `/run/northnarrow/bpf-foreign`.
- **New records of the kernel-state round** (5 s, not refusals, no posture
  trigger): at each start every BPF program not the agent's that its `bpf`
  hook did not see loading is signed once, NN-L-AT-001 `bpf_baseline` — Low,
  High for one of the nine types above (one loaded while no agent ran); a
  program or link that appears later and the hook never saw is
  `bpf_unseen`, High. A host with many container or systemd programs has
  as many Low baseline records at each agent start; the kernel's own
  programs (loaded before user space: HID-BPF's `hid_tail_call`) are Low.
- **R011's record of a plain `modprobe <name>` by root is Low** (it was
  High): the system's tool asked for modules by name, its environment read
  clean. The suspicious cases keep their severity (a process gone before
  its environment was read High, every kill High).
- **Frozen maps**: `BPF_DEFENSE_MODE`, `OWN_EXE_INODES`, `OWN_PIN_NAMES`,
  `SYSCTL_KERNEL_JUDGE`, `DNS_EXEMPT_UIDS` and `NET_CONNECT_DENY_MODE` take no
  write from any process after the start (the agent's included).

## 15. DNS tunnels, the parse worker and the open flows (lot 291)

Ten bugs of the external bug hunt (editions 1.2 and 1.3), as our triage
verified them; `CHANGELOG.md` has each one.

- **NN-L-NET-014 kills more tunnels.** Its eight distinct high-entropy
  labels within a minute now add up under the name's **registrable
  domain** (`evil.example`, `evil.co.uk`), whatever lies between the
  payload's first label and it: a payload over several labels (iodine,
  dnscat2), a random label more, letters in another case. Before, the
  parent was everything after the first label, and such a tunnel was only
  recorded. The registrable domain comes from a built-in list of public
  suffixes (the country codes' second-level registries, the large cloud
  platforms' zones: `s3.amazonaws.com`, `blob.core.windows.net`,
  `azurewebsites.net`, `github.io` …); the key is never finer than
  before. **What to check after the upgrade:** a process that resolves,
  within a minute, eight or more distinct names of 25 characters or more
  of high entropy under one registrable domain the list does not split —
  a security product's reputation lookups by hash in DNS, a client of
  many hashed sub-domains of one company's domain — is now killed where
  before only names of the very same parent were counted. The records of
  the old agent show it: NN-L-NET-014 Medium records of one process under
  one domain, many a minute.
- **The parse worker stays up** for a DNS response whose records name the
  root (`.`): the agent counted it as a protocol violation, and five
  disabled the worker — every DNS name of the host without a decode until
  a worker stayed up 60 s. On an older agent `worker_parse: … protocol
  violation: bounds: dns_answers: more answers than bytes` followed by
  `worker_parse: disabled` was the sign (`WORKERS.md` §4).
- **Open flows**: a flow open longer than 300 s keeps its DNS name on its
  snapshots and in its closed row of the netflow log (it lost it when its
  process resolved nothing since its connect), and a flow deferred by the
  snapshots' per-tick bound comes first at the next tick.
- **`net_window_evictions_total`** also counts a host NN-L-NET-026/027's
  per-process bound dropped while still in its window, and a live window
  of NN-L-NET-020/021 evicted when 4,096 are held (they were all cleared
  before).

## 16. What an interpreter runs, and who vouches for a writer (lot 292)

The external bug hunt (editions 1.2/1.3) found an interpreter's script read
with one option rule for every interpreter (BUG-44, BUG-42) and a writer's
ancestors trusted by the tree they lie in (BUG-49). After the upgrade:

- **An interpreter is the script its own option table reads**
  (`crates/nn-core/src/posture/script_args.rs`; python, perl, ruby, node,
  bash/dash/sh, and for zsh, ksh and mono the options every one of them
  reads alike). `python3 -O /tmp/x.py /usr/bin/aws` is `/tmp/x.py`: a
  reader of `~/.aws/credentials` run that way is killed by NN-L-FIM-011 like
  any reader that is not the client; `sh -e /usr/lib/dpkg/info/x.postinst`
  is that script (an installed program), not an inline one. An option the
  table does not hold leaves what the interpreter runs **not known**: it is
  no client of any rule's list (a credential client reading its store with
  an unusual interpreter option is killed — report the option, it joins the
  table), no installed service on a common port (NN-L-NET-006/-019), no
  trusted writer, and it vouches for nothing below it. The record says
  "(options not understood)".
- **A shell's `-s` reads its commands from standard input**: `bash -s
  /usr/bin/x` runs no script, and is treated as `sh -c` (it vouches as an
  installed shell does).
- **Every ancestor of a ransomware writer, and of a copy guard's trusted
  editor, is asked of the package database** (dpkg or rpm; with neither, a
  root-owned tree as before). A packaged tool (`tar`, `openssl`, `gcc`)
  started by a program a person installed in `/opt` or `/usr/local` from a
  tarball (a toolchain, a vendor's agent, a container's entrypoint) is
  judged now: its bursts count, NN-L-IMP-001/-002 may record them. No kill
  by default (NN-L-IMP-001's kill is held by the signed per-rule policy).
  An interactive shell or `sh -c` a package installed still vouches.
- A not-judged kernel module load (the agent's first seconds) from a path
  whose component the sensor read only in part (31 bytes) is recorded High
  as unverifiable; before, it was looked up as the 31-byte name.

## 17. Self-defence findings of the external bug hunt (lot 293)

- **A signal through a file's owner is refused to the agent, the watchdog
  and the workers** (BUG14). A new deny hook, `file_send_sigiotask` (22 deny
  hooks in all; a kernel whose BPF LSM cannot attach it refuses the start,
  as for any deny hook, unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`): the
  SIGIO, the `F_SETSIG` signal or SIGURG of a file whose owner
  (`F_SETOWN`, `F_SETOWN_EX`, `FIOSETOWN`, `SIOCSPGRP`) is a protected pid
  never reaches it — a root shell killed the agent that way. Inside a
  signed trusted-installer window the window's signal grant (SIGTERM,
  SIGCONT, SIGKILL) applies; the plain SIGIO stays refused. A refusal is
  NN-L-AT-001 `sigio` (High), the posture ENGAGED. The pid the record names
  is the process whose I/O raised the signal — not necessarily the one
  that armed the file: look for a descriptor whose owner is the agent
  (`/proc/<pid>/fdinfo/<fd>`, `flags` with `O_ASYNC` 020000). Nothing to
  configure; no NorthNarrow process arms a file's owner.
- **`denial_rate` in the ring drops** (BUG37): the refusals signed at each
  attempt (a protected file's unlink, rename, write-open…) are recorded
  50 a second per CPU at most, in a budget of their own; past it they are
  counted in `nn-admin status`'s ring drops as `denial_rate` (a security
  ring: past 64 in a sample, telemetry loss). The refusal itself is never
  dropped.
- **NN-L-BPF-001 judges `BPF_RAW_TRACEPOINT_OPEN`** (BUG05): an attach that
  way by an unlisted process is a record like `PROG_ATTACH`'s
  (`raw_tracepoint_open` in the `bpf` records).
- **`admin.pub` with a byte that is not UTF-8** (BUG03): an ISO-8859-1
  comment no longer disables the admin socket; a key line with such a byte
  is skipped and signed (AUT-004's record) like any malformed line.
- **The exploit guard and `setgroups`** (BUG71): a uid or gid gain inside
  `setgroups` is an anomaly (NN-L-EPG-001); a `setgroups` that changes only
  the groups, as logins and privilege drops do, is not.

## 18. Posture triggers and the flows' chain verdicts (lot 294)

The external bug hunt (editions 1.2/1.3) found the posture's exfiltration
pattern counting connects that never leave the host (BUG41), the correlation
store's ring shared by all precursor kinds (BUG62) and a record-only answer
holding a flow against a later kill (BUG45). After the upgrade:

- **ExfiltrationPattern counts only destinations off the host and its
  link.** Twenty connects of one process to `127.0.0.1`, `::1`, an
  IPv4-mapped loopback, the unspecified address, a multicast group or
  `169.254.0.0/16` (a cloud instance's metadata service) on 80/443 no
  longer raise it: a local proxy or health check no longer moves the
  posture to ENGAGED, nor, with another class's signal in the same unit or
  session, to COMBAT. CGNAT (`100.64.0.0/10`, Tailscale and carriers) still
  counts. Reconnaissance (3 ports) and HeavyReconnaissance (10) count the
  connect being judged once; Lolbas reads the shell's parent's latest exec.
- **A process's chain precursors no longer push each other out**: 16 of
  each kind are kept (64 at most), so sixteen re-execs of an image named
  `su` or `sudo` no longer hide a credential read from NN-L-CHAIN-001.
- **A rule the signed policy turns `off`, or whose exemption covers the
  actor, no longer answers an open flow**, and a chain answer that ran no
  response (an aged precursor's High record, `alert`, `audit`,
  NN-L-CHAIN-008) no longer keeps a chain's kill from the flow's later
  phases (`RULE_POLICY.md`, "Modes on an open flow"). Two visible effects:
  a credential read made while a flow is open can now draw NN-L-CHAIN-001's
  kill at the next snapshot (every 60 s) under a policy with a chain `off`
  or in `alert`, or after an aged record at the connect; and an **exempt
  rule's recorded-only match may be written again** at a flow's snapshots
  and its close (the detection budget bounds the repeats), where it was
  written once at the connect.
- NN-L-CHAIN-007 completed by a credential read processed after the egress
  needs the staging exec within 300 s of the egress (BUG75): a flow whose
  exec was older gets NN-L-CHAIN-001 alone, as in the kernel's order.

## 19. The chains' head anchor and the heartbeat's verifier (lot 295)

- **A chain cut while the agent runs is a finding of the running agent**
  (BUG25). Every 5 minutes and at the stop, the head anchor checks the heads
  it anchored last: one cut, emptied, rewritten or deleted since is a signed
  `integrity_drift` with `at_boot: false` (`chain_truncated`,
  `chain_rewritten`, `chain_missing`, `chain_archives_missing`), written
  before the anchor takes the head as it is now — it used to take it
  silently, and the next start found nothing. When the audit log cannot
  take the row, the old head stays anchored (the ERROR every 5 minutes) and
  the next start reports the loss. Nothing to configure;
  `EVIDENCE_CHAINS.md` says what to do with one.
- **A head the agent cannot read again stays anchored** (BUG26): more than
  64 lines shaped like the chain's that do not verify after it (or 16 MiB
  of lines that are not the chain's) no longer take the chain out of the
  anchor — WARN `chain head: not known — the anchored head is kept while it
  is still in its file`, once.
- **An archive is evicted only when its manifest says so** (BUG08): at the
  start, an archive that held an anchored head or checkpoint and is gone is
  `chain_missing` unless the manifest's signed `Evicted` row for it is in
  its last 256 KiB; a foreign `<log>.<higher number>` no longer hides a
  deleted generation.
- **The heartbeat's verifier** (`nn-admin heartbeat watch`, BUG18, BUG30,
  BUG01, BUG12, BUG32): use the `nn-admin` of this release on the
  verifier's host. It reads every new beat, not only the newest: a cut the
  agent declared (`kept: false`) or a head that went back in any beat of a
  fetch is `REPLAY`; a head gone from the beats is `REPLAY` once (not at
  every check while it stays gone; its state file keeps it as
  `heads_gone`) and compared when it comes back; the loss and health of a
  run that ended between two checks are `LOSS`/`DEGRADED`, and a stop with
  a reason that is not a clean stop's followed by the next start is
  `DEGRADED`. A beat's `interval_secs` is taken within 5 to 300 s. A state
  file of an earlier verifier is read as it is.
## 20. The chain writers after a failed write (lot 296)

- **A full disk, or a failed fsync, no longer breaks a chain** (external
  bug hunt BUG15, BUG17, BUG27). Before its next row the writer reads the
  file's tail again: the start of a row a write left at the end is cut and
  the cut attested — `chain_tail_repaired` in the audit chain,
  `torn_tail_repaired` in a rotating log's manifest (role `active` or
  `manifest`), each with the length and SHA-256 of what was cut —; a row
  written whole stays. Expect these rows after a disk was full: they are
  the repair, not tampering (`EVIDENCE_CHAINS.md`, "What the agent did
  about it"). An audit log an earlier version left with a row glued to a
  fragment (a disk full then) is still refused at the start: a line before
  the end that is not a row is corruption (`BOOT_INTEGRITY.md`, gate
  `audit_log`); keep it as evidence (`EVIDENCE_CHAINS.md`, "When a check
  fails").
- **Each rotating log's manifest** (`<log>.manifest.jsonl`) now exists from
  the agent's first start after the upgrade, empty until its first row:
  created by the start inside the protected directory's `+i` lift, so the
  actions chain's response threads, which may not lift it, can attest a
  repair there (lot 296's lab: without it, every action row after a full
  disk was lost until the next start).
- **The actions chain rotates** (lot 295's finding, added to this lot):
  its rows are written by the response threads, which may not lift the
  state directory; past its cap (16 MiB, `NN_ACTIONS_CAP_BYTES`) every row
  was lost until the next start. A response thread now keeps its row past
  the cap and the chain's rotation thread (`nn-actions-rotate`, role
  writer) rotates it. Nothing to configure. An install that lost rows that
  way has the ERRORs `an action's row is NOT in the signed actions chain`
  with `lifting immutability` in the journal, and an active file ending in
  a terminator that the next start's open archived.
- **Retention** (BUG10): an entry at an archive's name that is not a
  regular file is left in place and passed (ERROR in the journal; `chain
  verify` names it); a pass that fails keeps the `Evicted` rows of what it
  removed.
- **The JSONL export** (BUG31): a write stopped part-way leaves one line
  that is not a record, then the batch whole. A fragment left by a worker
  that ended in the middle of a write is not closed (`EXPORT.md` §8).
- Nothing to configure; the files' formats are unchanged (an `nn-admin` of
  an earlier version reads the new rows).

## 21. The agent's stores and the watchdog's respawn argv (lot 297)

- **The copy-on-first-write journal (EXPERIMENTAL) keeps its copies across
  a crash** (external bug hunt BUG64). A start after a crash during an
  append to `index.jsonl` reads every line it can: expect one signed
  `subsystem_degraded` `journal_open` "1 unreadable line(s) of index.jsonl
  skipped" — the cut line, nothing lost; the line is ended at that start.
  An index the agent cannot read at all (a disk error) leaves its scope
  unprotected for that run (`journal_open: false` in the guard's start row,
  the same signed `journal_open` naming the error): its copies stay on
  disk for the next start — check the disk. Before, either case deleted
  every copy of the scope. A restore keeps both (`<name>.nn-restored-<id>`)
  when a writer seen before the copy restored wrote again after it (BUG48).
- **The `response` of a tree kill whose root was not killed** (BUG61) now
  also names what was left running, after a `;`: `KillProcessTree (already
  gone; partial: 2 not killed, 1 spared, walk truncated)`. A reader matching
  the whole string `KillProcessTree (already gone)` misses these; the action
  stays the first word. Records written before keep their text.
- **`nn-admin detections` returns** with a directory at a chain path or a
  failing disk (BUG69, BUG74), and serves the rows it verified when a
  thousand forged rows came first (BUG59). Nothing to configure.
- **The watchdog's exec backend** (non-systemd hosts, `--respawn-backend
  exec`; BUG58, BUG67): the respawned agent gets the first launch's argv
  byte for byte, an empty argument (`--flag ''`) and one that is not UTF-8
  included; `/run/northnarrow/agent.argv` keeps them the same way (its
  format is unchanged). The systemd backend (the default with systemd) was
  never affected. The agent itself no longer aborts at its start on such an
  argument, or on an environment variable that is not UTF-8. The `admin_socket_vanished` record says "on N STATUS
  pings since it last answered" (BUG81: a timeout between two of those
  pings does not start the count over — that was always so; the text said
  "in a row").

## 22. FIM, the admin tools and minor findings of the external bug hunt (lot 299)

- **Our own vendor units inside a window** (BUG73). A write in place of
  the agent's own unit, or of a drop-in of it, under
  `/usr/lib/systemd/system/` inside an open trusted-installer window is
  NN-L-FIM-009's Log/Low record only: NN-L-FIM-001 (`/usr/lib/` prefix)
  killed the writer's tree beside it. Nothing to configure; outside a
  window, and for any other unit or file under `/usr/lib/`, NN-L-FIM-001
  kills as before.
- **The heartbeat's verifier** (`nn-admin heartbeat watch --from-cmd`,
  BUG22, BUG34, BUG38): use the `nn-admin` of this release on the
  verifier's host. The fetch is over when the source command exits — a
  process it left holding its output (an ssh `ControlPersist` master) no
  longer holds `watch` — and a long stderr no longer stops the command. A
  failed fetch says the last line of the command's stderr.
- **The syslog/TLS export** (BUG20): after a quiet time the first row is no
  longer dropped and written again on a receiver whose acknowledgement
  takes more than 100 ms; the receiver sees fewer duplicates.
- **The admin protocol's envelope** (BUG36): not on the live wire (the
  bare frame); its v0 fallback `decode_versioned_or_legacy_frame` is
  removed from `nn-proto`. Nothing to do on a host.

## 23. The evidence readers, verifiers and the export's check (lot 298)

External bug hunt (editions 1.2/1.3), the triage's lot 8. Nothing to
configure; use the `nn-admin` of this release where the export is checked.

- **`nn-admin chain verify`** refuses a line after a file's terminator
  (`a line after the file's terminator`, BUG29): genuine lines replayed
  after an archive's seal were counted twice. A chain this agent wrote has
  none; one that says it was edited. The canary chains' rows ending in
  `\r` are refused where they are numbered (BUG09).
- **The read verbs** (`fim report`, `net flows`, `net listeners`, `canary
  list`): the answer is always the newest rows, contiguous (BUG04); an
  unreadable archive (BUG07) or, with `--since`, a row out of time order
  (the clock stepped back, BUG06) sets `truncated`, and such a row no longer
  hides the archives' rows.
- **The audit chain's `previous_run`**: a start refused by a gate is not a
  run (BUG16): the next boot no longer signs `abrupt` (and the SIGKILL/OOM
  warning) after a clean stop and a refused start; after a killed run, it
  names the killed run's boot and last row.
- **The actions chain's `interrupted` rows** carry the intent they answer
  (BUG19): a new value of an existing optional field, the line's form
  pinned (`an_interrupted_row_with_its_intent_is_pinned`); the rows an
  older agent wrote still read and verify. The export maps them to their
  intent's class from the row; an older one with the intent the worker
  kept, attached as an outcome's.
- **`nn-admin export verify`** (BUG23, BUG24): a line that is not UTF-8 is
  `MALFORMED`, the other records verified (it ended the check, exit 1); an
  exec detection's companion record without its Detection Finding is
  `BROKEN` (exit 11), the finding without its companion a `NOTICE`. The
  export's JSONL files keep a row's records in one file; check a
  receiver's files together, in order. `--json`: the report's fields are
  unchanged (the findings are `breaks` and `notices`).
- **The head read-back** of the heartbeat's `kept` and of the export's
  cursor reads a line up to 16 MiB back (BUG11; it read 64 KiB), and a
  foreign entry skipped at an archive slot before a rotation's seal is
  attested (`ForeignArchive`, BUG28) as one met at the rename was.

## 24. Every deny hook proves it denies; the bpf() guard pinned (lot 302)

- **The deny self-test** (`docs/operator/SENSOR_CONTRACT.md` §5b). Each
  sensor self-test round now makes one harmless attempt per deny hook on
  targets of its own — a target process it starts and registers as a
  worker, `/run/northnarrow/selftest` and its files (protected), a
  throwaway cgroup `/sys/fs/cgroup/northnarrow-deny-selftest` (removed
  after each round; `uninstall.sh` removes a leftover) — never the agent:
  the `SIGURG` the agent itself received each round is gone. A hook that
  lets its attempt through, or whose refusal does not arrive, is a signed
  `subsystem_degraded` (source `deny_selftest`, the hook named), two rounds
  in a row `deny_selftest_alert`; refused again, `deny_selftest_restored`.
  An alerting rule on the audit log that watches `sensor_selftest_alert`
  should watch `deny_selftest_alert` too. `fs_protect`'s own word in the
  manifest is now the round's refusals arriving (a hook let through is the
  hook's miss, not the source's). `bpf_map` and `bpf_prog` are attempted
  where the BPF guard enforces (production builds); a hook the kernel does
  not have, or a trusted-installer window, is "not exercised".
- **The bpf() guard pinned.** The pin root holds four new entries:
  `prog_bpf`, `link_bpf`, `prog_bpf_prog`, `link_bpf_prog` (the `bpf` and
  `bpf_prog` hooks, like `bpf_map`'s), where the guard enforces (every
  production build; an observing guard — `NN_BPF_DEFENSE_OBSERVE=1`, a
  `debug-trigger` build — is attached for the agent's life, as before). Through a restart or an upgrade's
  gap the previous start's guard keeps refusing a handle on the agent's
  objects (the start-in-cgroup tracker's links among them) and a load of a
  program type it refuses outside the family; outside a trusted-installer
  window, a `bpftool prog load` of such a type while no agent runs is
  refused too (inside one it is let through, as with an agent running).
  Nothing to configure: the upgrade's window (`install.sh --upgrade
  --grant-key`) and `uninstall.sh` handle the new pins like the others.
- **The agent registers itself earlier.** The agent enters
  `PROTECTED_PIDS` right after its eBPF object loads, before its first
  program loads (the previous start's pinned guard judges those loads).

## 25. The known system programs (lot 304)

- **systemd's own BPF programs are no longer foreign** ([the anti-tamper
  trust model, "Lot
  304"](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/ANTITAMPER_TRUST_MODEL.md)).
  On a host with systemd 257 or later (Debian 13, Ubuntu 26.04) every start signed systemd-networkd's
  `sysctl_monitor` (`sysctl_root_prog`, High), PID 1's
  `restrict_filesystems` (`bpf_baseline`, High) and a sysctl judge
  degradation (`nn-admin status`: the trust level "degraded"). Each is now
  signed once a start as Low, its loader the record's principal
  (`systemd-network` or `systemd`) and the proof in the reasoning, and the
  degradation names only a program not proven one. A SIEM rule keyed on
  `sysctl_root_prog` or `bpf_baseline` at High keeps firing for any other
  program, the same name from another loader included.
- **Restarting systemd-networkd** outside a trusted-installer window has
  its sysctl monitor's attach to the root cgroup refused, as before
  (`sysctl_root_attach`, High): networkd logs it and runs without the
  monitor. Restart it inside a window (`nn-admin trusted-installer-grant`)
  to keep it; that load, seen by the agent, is signed Low.

## 26. The evidence chains' residues of the third bug hunt (lot 319)

- **The flat chains after a failed write**: the canary registry
  (`canaries.jsonl`), the canary access log, the FIM baseline and the
  listener log (`netflow_listeners.jsonl`) read their tail again before
  the next row after a write the disk stopped part-way or a failed fsync.
  The fragment is cut and the cut signed in the audit chain
  (`chain_tail_repaired`, the file, the length and SHA-256 of what was cut;
  at once, or within the next flush of 15 s when the audit log is busy). An
  install that already holds a glued line keeps it (`nn-admin chain verify`
  names it); nothing to do.
- **A stalled retention is a degradation**: `nn-admin status` lists
  `chain_retention: <log>: the retention stopped at archive N: it cannot be
  removed (…)` while an archive past the budget cannot be removed, and the
  trust level counts it; a `subsystem_degraded` row (source
  `chain_retention`) is signed once. Make the archive removable again
  (`chattr -i`, or move it aside to keep it): the next rotation's pass runs
  and the line leaves the status. A SIEM keyed on the trust level sees the
  degradation where it saw an ERROR alone.
- **Foreign entries at archive names**: one `ForeignArchive` row each in
  the log's manifest — new for those a rotation jumped over, those below a
  rotation a crash interrupted, and those planted while the agent was
  stopped above the last rotation the manifest records (at the next
  start). Each is still refused by `nn-admin chain verify`; the row says
  the agent saw it.
- **The JSONL export**: each start of the export on a non-empty
  `export.jsonl` writes a newline before its first record — one empty line
  when the file had ended whole. `nn-admin export verify` skips empty
  lines; configure your shipper to skip them (Fluent Bit's `tail` input:
  `Skip_Empty_Lines On`; its default is off, and with a JSON parser the
  empty line is an event that is no record). A reader that counts lines
  counts one more per start.
- **`--since` and `--until`**: a value past any row's time (beyond year
  9999, or 2^63 seconds and more) keeps no row for `fim report` and `net
  flows`, and is the farthest time for `detections`; `nn-admin heartbeat
  verify --max-skew-secs` holds at any value. They all kept every row, or
  reported a skew, before.
- Nothing to configure; the files' formats are unchanged.

## 27. The exec quarantine's stop and a process it cannot capture (lot 317)

Only for hosts that run the exec quarantine (`--exec-quarantine enforce`,
EXPERIMENTAL, off by default; [the design, §3](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EXEC_QUARANTINE.md)).

- **A stop leaves nothing stopped.** The agent's stop now also resumes the
  processes the kernel stopped after the agent last read its reports; they
  stayed in state T until the next start of an agent with the guard on (or
  a `kill -CONT` by hand). The signed `exec_quarantine` entry `stopping`
  gains `unreported` (those, among `resumed`), `recaptured`, `killed`
  (kills owed, see below) and `left` (not captured: still stopped; the next
  start resumes them, or kills those whose kill is owed).
- **A process the kernel's map cannot name is not stopped** (the review of
  #541): `EXECQ_STOPPED` holds 4096 processes; past it an exec runs
  unheld (record: `not held (the map of stopped processes was full …)`,
  counted in `not_held`, and in the signed fail-open degradation with the
  full ring and the refused signal) — it used to be stopped with no entry
  anything would resume.
- **New responses in the records**: `resume deferred: …` and `kill
  deferred: …` — the agent could not capture the held process
  (`pidfd_open` out of descriptors or memory). The process stays held and
  the decision is carried out once it is captured, with a new signed
  `exec_quarantine` entry, `deferred` (`pid`, `action`, `result`,
  `waited_ms`). A kill owed (a block-list hit, also one that arrives late
  while a resume is owed) is marked in the pinned map: if the agent stops
  or dies first, the process stays stopped and the next start kills it
  (`recovered_at_boot`'s `killed`). The binary does not run — unless the
  next agent runs without the guard (`--exec-quarantine off`, or a guard
  that cannot start), which leaves it stopped, neither run nor killed. These records used to say `ended while
  held` or `already ended`, and the process stayed stopped for good. A SIEM
  rule that reads `already ended` as "the rules' kill landed first" keeps
  its meaning; one counting `ended while held` sees fewer of them only
  where they were false.
- `recovered_at_boot` gains `deferred`: processes a previous agent left
  stopped that could not be captured at the boot (no longer counted in
  `gone`), given their decision once they are; and `killed`: the kills a
  previous agent owed.

## 28. The kernel halves of the third bug hunt (lot 318)

- **A set-id target no longer escapes the exec policy's environment deny**
  (BUG101; [the exec policy's design, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EXEC_POLICY.md)). With `--exec-policy enforce`,
  an `LD_PRELOAD` or `LD_AUDIT` entry under a staging path (`/tmp/`,
  `/var/tmp/`, `/dev/shm/`, `/proc/`, `/dev/fd/`) at the exec of a set-uid
  or set-gid file is refused like at any other file, for the tiers whose
  rule denies (`service`, `unknown`, a root caller under `deny-root`): the
  record is `NN-L-EXECENV-001` "denied at exec (EACCES)", where it was
  "recorded: the target is set-id, the kernel sets AT_SECURE". The bits
  did not promise it (root running `su`, `no_new_privs`, a `nosuid`
  mount, a set-id `#!` script). A service whose environment carries such a
  preload has every other exec refused already; nothing to configure.
  **On 7.0** (Ubuntu 26.04's 7.0.0-43) the environment check is unreliable,
  before this release too: the scan's syscall tracepoint program sees the
  execs of one CPU only there, and a preload on another CPU is not refused
  (lab: 6 of 20 unpinned). Do not count on this deny on 7.0 until lot 322
  ([the exec policy's design, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EXEC_POLICY.md)).
- **More files are in the guarded classes** (BUG108). A file on a btrfs
  subvolume mounted at `/home` (Fedora, openSUSE), or in a directory of
  another filesystem bound at a guarded point or at `/home/<user>`, is
  `home` and `guarded_mount` now, whichever path runs it — the exec
  quarantine holds it and the policy's cells judge it, as for any home. A
  file more than 64 levels deep, which the walk cannot place, is `tmp`,
  `var_tmp` and `home`. A directory bound deeper in a user's tree (a
  chroot's `/usr`) stays out. The guarded points are published by their
  own identity too: on openSUSE (`/var/tmp` in the `@/var` subvolume) and
  on ostree systems (Silverblue, CoreOS: `/home` and `/var/tmp` under the
  `/var` bind) their files are `var_tmp` and `home` now (not
  `guarded_mount`), and a file under `/home` or `/tmp` reached through a
  bind elsewhere (a container's bind of a home directory) has the point's
  class, as it had with a separate `/home` partition. Containers and
  chroots keep their own view: a container whose root is a plain directory
  in a home (LXC's dir backend, rootless podman on vfs or btrfs) is not
  `home` or `other_home` by the host's `/home` above its root (the search
  stops at the task's root). Not covered yet (lot 323, with the container
  policy): a filesystem a user mounts in their own user namespace (an
  overlay after `unshare -rm`, no container needed), a chroot into a FUSE
  directory, and a chroot or container whose root is below a guarded mount
  or point give no class. Every FUSE filesystem (`fuse`,
  `fuseblk`; not `virtiofs`, a VM's or a Kata container's shared
  directory, told apart by the superblock's type name) outside the task's
  root is `guarded_mount`, with the class of the point it is mounted at, or
  `tmp`, `var_tmp`, `home` where the agent's table does not place it: a
  service that runs programs from a FUSE mount (sshfs, rclone, s3fs) now has
  those execs held for a scan (`quarantine` cells) and recorded by the
  `audit` cells; a session's own home on the desktop profile is still
  allowed. Two optional BTF offsets are new (`super_block.s_type`,
  `file_system_type.name`, slots 127–128; the enum, tracepoint and
  hook-argument slots move up by two): without them a FUSE-magic file is
  guarded whatever its type. Check `nn-admin status` (`execpol`
  counters) after the upgrade on such a layout. A user's FUSE mount
  without `allow_other` cannot be read by the agent: the scan's basis is
  unreachable and `--exec-quarantine-on-expiry` applies — with `kill`, an
  AppImage or an sshfs tool run by a service from such a mount is killed;
  keep the default (`resume`) where those run.
- **The BPF guard's refusals have a budget** (BUG37), and the records
  that decide nothing have their own (the review of #545 and its
  re-check). A refused read of the agent's key, a handle on its BPF
  objects, a refused program type or root `cgroup/sysctl` attach, a refused
  write of the kprobes or lockdown switch, a refused renice (nice,
  scheduling, I/O priority) or sysctl write, a signal through a file's
  owner, a loader or sysctl opt-out's record, a move into an exempt cgroup
  and a code-injection record: 50 a second per CPU, the rest counted in the
  signed `ringbuf_drop` entry (`minor_denial_rate`, a new slot) and never a
  telemetry loss — a `bpftool prog list` or `map list` outside a
  trusted-installer window, a monitoring agent listing the BPF objects
  every second, a tuning daemon or a burst of opted-out sysctl writes
  records its first 50 in the second and raises no `TelemetryLoss`. The
  decisive refusals (an unlink, rename or write-open of a protected file, a
  write handle on or a detach of the agent's BPF objects; the refused
  signals, ptraces, kexecs, cgroup moves and limit changes) keep their 50 a
  second to themselves, and one of them held back (`denial_rate`,
  `task_denial_rate`) is a telemetry loss at once, where more than 64 in a
  10 s sample were. Every refusal holds.
  A reader of the `ringbuf_drop` counters by index sees 30 slots
  (`minor_denial_rate` is the 30th).
- **The io_uring sensor** attaches one more program, `io_uring_exit` on
  `sched/sched_process_exit` (N9): a process's aggregation state goes with
  its last thread. Where it does not attach, the start signs the
  `io_uring_sensor` degradation.

## 29. What a response reports, read back (lot 312)

- **A new failure text in the signed rows**: `not in effect: <reason>`
  (the action ran, its effect read back did not take); the detection
  record's `response` reads `BlockOutbound (not in effect: …)`. A SIEM rule
  keyed on the bare action name as success is unaffected: these rows are
  `failure` (`COMBAT_RECOVERY.md` §3.5).
- **The quarantine does to a file only what the offender could have done
  itself.** Never the system's own files, by identity (the dynamic
  loaders, the shells, init, sshd, the agent's binaries), whatever name
  leads to them (an `/etc/shells` that cannot be read — a FIFO, a device,
  over 1 MiB — refuses every quarantine at once); a non-root offender only
  a file it owns; a root offender
  any file under a verified name; never a root-owned file reached through
  a name that cannot be verified. Otherwise `refused`, the owner named. A
  name is removed only when it is the file's only name; a non-root
  offender's own file is emptied under every name whatever its links (a
  second hard link no longer keeps it runnable); a shared file root or
  another user owns (a package store's hard links) is made mode 000 where
  the agent may, its
  content kept (`partial`), or, where its mode cannot change, only vaulted
  (`failure`); the offender's own file under an unverified name is emptied
  in place. `nn-admin response restore` of those puts content and mode
  back into the same file — every name of it — and creates no name
  (without a verified name: `--to` any current name of the file).
  NEUTRALIZE's text for an offender gone before its binary was opened is
  now "binary not quarantined: the process exited before NEUTRALIZE could
  open it".
- **A soft block of a process holding sockets is partial**: "new
  connections blocked; N inet socket(s) opened before the move are not",
  and the INVESTIGATE window is the short one.
- **The SSH service is spared only in the system manager's own SSH unit**
  (`/system.slice/[<sub>.slice/]ssh.service`, one unit). A root sshd in a
  container's nested `ssh.service`, or — on a systemd host — in a cgroup
  with no unit, is no longer spared.
- **A tree kill keeps a protected process's whole tree** (the agent, its
  watchdog, init) and spares a host-critical descendant (an sshd) alone;
  below a spared host-critical root only the offending lineage (the chain
  to the offender and its subtree) can be killed, never the root's other
  sessions. Each spared pid is in the outcome.
- **A release says `released` only once the process is back** in the
  cgroup it came from (`response release`: exit 9 with the reason
  otherwise).

## 30. The exec environment's check on every CPU (lot 322)

- **On Ubuntu 26.04 (kernel 7.0) the check now refuses.** This is the
  check of [the exec policy's design, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EXEC_POLICY.md):
  an `LD_PRELOAD` or `LD_AUDIT` entry under a staging path, with
  `--exec-policy enforce`. On that kernel it refused almost nothing. Its two
  programs on the `sys_enter_execve{,at}` tracepoints ran only for the execs
  made on CPU 0 (0 of 11 refused in the lab). The exec sensor's own
  `bprm_check_security` program now reads the environment from the exec's
  registers. Expect `NN-L-EXECENV-001` "denied at exec (EACCES)" records,
  and refused execs, where there were none: a service, a cron job or a root
  session that runs programs with a preload from `/tmp/`, `/var/tmp/`,
  `/dev/shm/`, `/proc/` or `/dev/fd/`. On the other kernels nothing changes
  but the way the environment is read. Nothing to configure.
- **Programs and offsets.** The programs `execpol_env_execve` and
  `execpol_env_execveat` are gone, and so are their two tracefs fields. One
  optional BTF offset is new, `pt_regs.r10` (slot 129). The enum,
  tracepoint and hook-argument slots move by one: 144 slots in all. Where
  the `pt_regs` offsets do not resolve (another architecture than x86-64),
  the environment is not judged: the start signs the `exec_policy`
  degradation "the exec's registers cannot be read on this kernel".
- **32-bit and x32 execs are judged too** (the review of #546, F1). An exec
  through the 32-bit entry (`int $0x80`, any process can make one) or the
  x32 one carries an array of 32-bit pointers: it is read like a native
  one, and a staging preload in it is refused like any other. It was not
  read at all. A 32-bit runtime (Steam, Wine) running with a preload from a
  staging path now meets the same rule as a 64-bit one.
- **An environment the check cannot read whole is recorded** (F2): a
  string or an entry unreadable when the scan reads it (the caller's memory
  changed after the kernel's copy), an unknown call. `NN-L-EXECENV-002`,
  High, "the new environment could not be read whole at exec"; the exec is
  not refused. `nn-admin status` reports the count on the exec policy's
  line ("environments not read"), and in `--json` as `env_unread`.
- **The per-task buffers.** The following moved from per-CPU buffers to
  plain hashes of 2048 entries keyed by the running task (never LRU: an
  LRU insert can evict an entry in flight; the review of #546, F4):
  - the exec sensor's walk;
  - the mapping check's walk;
  - the environment;
  - the exec quarantine's candidate (then copied into its own map);
  - the BPF guard's `OBJ_GET` path;
  - the FIM sensor's windows and names, a rename's names (F3: they feed
    `NN-L-FIM-011`/`014`'s kills and the FIM-010..017 posture floors).

  Each entry lives for one run of its program. Past 2048 runs in flight at
  once (each one a task preempted in the middle of the program), the path
  fails closed and counts it: an exec is refused in enforce mode, a mapping
  is classed `tmp`, `var_tmp`, `home`, the FIM sensor falls back to the
  plain observer (a ring drop). `nn-admin status` reports the exec guards'
  count ("runs without their buffer", `lost` in `--json`). A mapping
  report from the check's cache now carries the file's own path; it had the
  path of whatever that CPU had walked last.

## 31. What an interpreter runs, and a fileless exec, read in one place (lot 310)

- **One reader of an interpreter's options**
  (`crates/nn-core/src/posture/script_args.rs`, the external bug hunt's
  edition 1.4: BUG-97, BUG-99, BUG-100, N3; the independent review of #539).
  bash's long options written with one hyphen before its first cluster
  (`bash -noprofile x.sh`, `-norc`, `-rcfile F`, `-login`) are read as bash
  reads them, and dash and busybox's `sh` with their own options (`-posix`
  is `-p -o six` to dash, an error to busybox); node's `--eval=…`,
  `--print=…` and `--run <task>` as inline code; zsh's and ksh's `-ovi` as
  `-o vi`, and the name `-o` and `-O` take is checked (a name the shell does
  not know makes it refuse the argv); perl reads on after a space inside one
  argument (`'-i -e'`: an in-place edit, then the program). Each of them
  used to move the identity onto an argument the caller chose: `bash
  -noprofile /tmp/x.sh x /usr/bin/aws` was taken for the `aws` client and
  its read of `~/.aws/credentials` drew no NN-L-FIM-011. An option the
  reader's table does not hold, `--name=value` included, leaves what the
  interpreter runs not known ("(options not understood)"): no client, no
  installed program, no trusted writer — report the option, it joins the
  table. So does an option that runs nothing (`--help`, `--version`, `-c`
  syntax checks).
- **Code loaded before the program named is the caller's.** node's `-r`,
  `--require`, `--import`, `--loader`, `--env-file`, perl's `-M`, `-m`,
  `-I`, `-d`, ruby's `-r`, `-I` leave a named script not known, an inline
  program inline; so do python's `-i` (its standard input runs after the
  script) and `-X pycache_prefix=`, node's `--test-reporter`, and an
  environment that loads code — `PYTHONPATH`, `PYTHONHOME`,
  `PYTHONUSERBASE`, `PYTHONINSPECT`, `PYTHONPYCACHEPREFIX`, `NODE_PATH`,
  `PERL5OPT`, `PERL5LIB`, `PERLLIB`, `RUBYOPT`, `RUBYLIB`, `GEM_HOME`,
  `GEM_PATH`, `BASH_ENV`, `SHELLOPTS`, `ZDOTDIR`, bash's exported functions
  (`BASH_FUNC_*`), set and not empty; `NODE_OPTIONS` only when it names a
  loading option (`--require`, `--import`, `--loader`…, read with node's
  table: `--max-old-space-size` loads nothing); `PYTHONSTARTUP`, `ENV`,
  `NODE_REPL_EXTERNAL_MODULE` only for an interpreter naming no program
  (they load nothing into a script: a user's `PYTHONSTARTUP` leaves `aws`
  its identity) — for an interpreter (or busybox's shell) naming an
  installed script or nothing, as the exec pump reads it at the exec. An
  environment larger than the pump reads (1 MiB) is taken to load. A
  developer's `PERL5LIB` or `PYTHONPATH` therefore takes the client
  identity from an installed perl or python program it runs (its reads of
  a client's store are judged as any other process's).
- **The kernel-resolved names of an interpreter are interpreters**
  (BUG-104): `mono-sgen` and `mono-boehm` (what `/usr/bin/mono` resolves
  to: KeePass 2's store read by its own process is its client again,
  NN-L-FIM-016 no longer kills it), `mksh`, `lksh`, `pdksh`, `oksh`, and
  busybox, which runs the program `argv[0]` names (`busybox sh`, `busybox
  busybox sh`, an `argv[0]` starting `busybox`): as `/bin/sh` (Alpine, its
  containers) a script it runs is that script; another applet is the
  installed `/bin/busybox`, as before.
- **An inline program vouches for nothing** (BUG-49, the decision of
  11/11/2026). A shell or interpreter running a program its arguments carry
  (`sh -c`, `bash -c`, `python3 -c`, `perl -e`, `node --eval`) or its
  standard input (`sh -s`, `bash < file`, `curl … | sh`: a shell naming
  nothing whose standard input is a file, a pipe or a socket) no longer
  vouches for the packaged tools it starts: the ransomware signal judges
  them (NN-L-IMP-001/-002; the kill held by default) and the copy guard
  copies an editor it starts. Nor does a user's service manager
  (`systemd --user`: `systemd-run --user /usr/bin/openssl enc …` was a
  lineage of installed programs end to end), for any unit — a user moves
  its own processes between the cgroups of its delegated subtree, so a unit
  read from a cgroup proves nothing (lot 326 will record the unit's cgroup
  in the kernel at its main exec). On a desktop the user's manager starts
  the terminal emulator: the commands typed in it are judged (records, the
  kills held by default; the copy guard copies their editors) — a cost
  accepted for now. The record names the process the manager started,
  never the manager. A package transaction and PID 1's units are trusted
  as before, a unit's `ExecStart=/bin/sh -c …` included: an installed shell
  PID 1 FORKED inherits PID 1's vouching. "Forked" is the kernel's record
  at `sched_process_fork` (the exec record's `fork_ppid`; processes only,
  not threads), for the first exec after the fork — carried in the kernel
  through systemd's executor, by its verified identity (the packaged
  file's, PID 1's copies: the eBPF map `EXECUTOR_IDS` the agent writes at
  each 10 s read), to the unit's program — never the parent at exec time:
  a webshell's double-forked orphan, which PID 1 reaps before its `sh -c`,
  was forked by the webshell. A process forked before the agent started
  has no record (judged); a record the map evicted under a flood of forks
  is counted (`fork_record_lost` in the ring-drop counters; a record goes
  at its process's exit, and a later exec of a process is no loss). One
  more program attaches: `fork_parent_forget` on
  `sched/sched_process_exit` (not attached: a warning; exited processes'
  records then wait for the map to evict them). Expect more ransomware assessments of the tools a
  cron job (a user's crontab or the system's: a job carries no owner in
  this judgement) or a non-interactive `ssh host 'cmd'` runs; the lab
  measured one on Ubuntu 24.04 — a user's crontab `sh -c 'rsync -a
  --inplace …'` of random data drew NN-L-IMP-001 (Critical, its kill
  held). A record names the shell ("which runs an inline program") or the
  manager ("a user's service manager").
- **A lineage the walk does not follow to PID 1 is not known, and vouches
  for nothing** (the re-check 4 of #539). The walk reads a writer and at
  most 32 ancestors; 33 nested `timeout`s (each a packaged program that
  forks the next) put a webshell's `sh -c`, or a user's manager, above the
  cut, and every hop read vouched. Now a walk that stops before PID 1 — the
  cap, a parent that started after its child (a later process at an exited
  parent's pid), a process its own parent — is a lineage not known: the
  ransomware judge and the copy guard judge the writer ("its lineage could
  not be read"), as for a hop that cannot be read. A deeper legitimate tree
  is judged too (the kill held by default). The searches for a hop that
  grants something (a package manager, an authentication binary, a client)
  find nothing above the cut, as before; the defense-impairment rules
  (NN-L-EVA-*) still look for a staged or deleted program among the hops
  below it. As before this lot, a writer that is a fork which never
  executes (`rsync`'s receiver) is read from `/proc` only: once it has
  exited, its bursts judged after that have a lineage not known — a
  unit's `rsync` may be judged where a unit's `cp` is vouched.
- **R004 decides on the executed file** (BUG-88). A memfd or an unlinked
  file is a fileless exec whatever path reached it:
  `/proc/thread-self/fd/N`, `/proc/self/task/<tid>/fd/N`, `/dev/stdin`, a
  relative `fd/N`, a symlink to a descriptor, `/proc/<pid>/exe` and
  `map_files/` ran an unlinked file without the kill before. In LSM mode
  (the default) the exec sensor's identity says so; in tracepoint mode the
  exec pump reads `/proc/<pid>/exe` (the same identity) while the process
  lives, and the path, read by the posture's one reader of a `/proc` link
  (`crates/nn-core/src/posture/proc_link.rs`: `..` folded outside a link,
  `/proc/<pid>/root/…` chains followed), when it is gone. Not fileless:
  - the agent's own worker;
  - systemd's executor left unlinked by an upgrade, by its identity
    (`(dev, ino)`), re-read every 10 s and replaced ("R004: systemd-
    executor's identities changed" in the journal): a copy the host's PID 1
    holds by that identity alone — no user can reach it, and a flood of
    forks evicting the kernel's records must not stop a unit's launch after
    an upgrade —; the packaged file at its install path (root's, listed by
    the package database) or a copy a genuine user manager holds (its image
    the packaged manager's, in PID 1's mount namespace) for the first exec
    of a process PID 1 or such a manager FORKED (the kernel's record); no
    longer by a
    file *named* `systemd-executor` (BUG-103), by `argv[0]` and a parent
    PID 1 in tracepoint mode, nor by a "manager" a user's namespace runs;
  - a process re-executing the very image its parent runs
    (`/proc/self/exe` after a package upgrade unlinked it: Chromium's and
    Electron's children, Docker's `reexec`), when that image was executed
    from a directory only root can write, by a process in PID 1's mount
    namespace (a container's process gets no such exemption); the parents
    running at the agent's start are read at its start. A user's dropped binary that
    unlinks and re-executes itself is killed, as before.

  Residual: a program re-executing itself in place (no fork) through
  `/proc/self/exe` after an upgrade is killed; so is an exec that opens a
  binary at the instant an upgrade renames its replacement over it
  (microseconds). An identity a manager released stays exempt until the
  next re-read (10 s); the kernel's identity carries no inode generation.
  Without the fork-parent record (`sched_process_fork`'s BTF tracepoint
  refused: a signed degradation) no unit's shell vouches and only PID 1's
  executor copies are exempt.

## 32. The system tools' options, read by their tables (lot 316)

- **systemctl, kill, pkill, killall, iptables, nft and firewall-cmd are read
  by the interpreters' reader, through a table each**
  (`crates/nn-core/src/impair/tool_options.rs`, the external bug hunt's
  edition 1.4: BUG-106, BUG-89, N4). NN-L-EVA-001..003 used to compare their
  argv with hand-written lists: an unlisted valued option before the verb
  (`systemctl -P Id stop auditd`, `--check-inhibitors no`, `--kill-who
  main`), a getopt_long prefix (`--si KILL`), a cluster (`-qs KILL`), a
  long or separate form (`iptables --policy INPUT ACCEPT`, `firewall-cmd
  --set-default-zone trusted`) switched a tool off unrecorded, and `pkill
  -n auditd` or `killall -g auditd` lost the name. The tables come from the
  tools' sources (systemd 249–262, procps-ng 4.0.4, psmisc 23.7, iptables
  1.8.11, nftables 1.0.6/1.1.3, firewalld 2.3.1).
- **An option after the verb is read both ways.** GNU getopt reads it as an
  option, and with `POSIXLY_CORRECT` in the tool's environment (which the
  exec event does not carry) as an operand: `systemctl stop auditd --user`
  stops the system's auditd then, and is NN-L-EVA-001. The manager is the
  last of `--system`, `--user`, `--global`, `--capsule`.
- **An option a table does not hold errs toward a detection.** The record
  says "(options not understood)": any operand may be systemctl's verb and
  every later one a unit, any spelling of iptables' `-F` or `-P` counts,
  pkill's name is matched every way. Expect it for an iptables extension's
  option the table does not list, or a newer systemctl's — report it, it
  joins the table.
- **Every listed unit of a command is judged** (BUG-96). `systemctl stop
  northnarrow-agent auditd` is auditd's High record (`unit auditd stop
  (with northnarrow-agent)`), inside a trusted-installer window too: the
  window sanctions a command only when every listed unit it stops is the
  agent's own. A glob is matched as systemd matches it — `fnmatch` with
  `FNM_NOESCAPE` (`\` is itself) on the unit's full name, a listed unit
  with no type suffix a `.service` (`snap.amazon-ssm-agent.amazon-ssm-agent`):
  `*uditd*`, `audit?.service`, `[[:alpha:]]uditd.service`,
  `snap.*.service` — in time linear in the pattern and the name (the
  review of #548: the first matcher backtracked, and a 21-byte glob of
  stars held the decision thread for hours). A bracket class ends as glibc
  ends it (the re-check, N2): a `[:` whose name meets a byte outside
  `a`–`y` before `:]` is no class, and a `[=` holds exactly one character,
  so `[a[:]uditd.servic[:e:]` names auditd. Checked on 60,560 cases against
  glibc: every name glibc matches is matched. The manager matches the
  patterns itself, in the C locale. systemctl matches them on its own side
  only when the manager refuses the listing (an old manager). There, its
  locale's ranges and `POSIXLY_CORRECT`'s literal `^` are not modelled
  (residual).
- **systemd's verbs that reach a unit** (the review of #548). `stop`,
  `condstop`, `kill`, `freeze`, `clean`, `disable`, `mask`, `preset`,
  `revert`, `edit`, `link` (the unit file's name), `set-property`,
  `service-log-level`, `service-log-target`, `bind`, `mount-image` (their
  first operand), `isolate` of a target other than `default`, `multi-user`
  or `graphical`, `rescue`, `emergency` and `preset-all` (every listed
  unit). Not judged: the restart and reload family (`restart`,
  `try-restart`, `condrestart`, …: the unit runs again), `start`,
  `enable`, `unmask`. A unit's aliases are listed with it (rsyslog's
  `syslog.service`, firewalld's `dbus-org.fedoraproject.FirewallD1`).
- **A reload signal the processes catch is Low** (the review of #548, the
  coordinator's decision, as its re-check left it). A SIGHUP sent by
  `systemctl kill` or `kill` is a Low record ("a reload, no stop") when:
  - the tool documents SIGHUP as its reload: auditd (reconfigure), rsyslog
    (reopen its files), firewalld (reload), falco (hot reload). No other
    signal is a reload: auditd's SIGUSR1 rotates its logs, and five in a
    row delete the older ones (`num_logs`), so it is High;
  - every process it reaches catches it (`SigCgt` in `/proc/<pid>/status`).
    For `kill`, each tool's process it names, still the one registered.
    For `systemctl kill` (`--kill-whom=all`), every process of the unit's
    cgroup (`cgroup.procs` of the cgroup a registered process runs in). A
    cgroup with cgroups below it, a unit no registered process runs in (an
    alias's name) or a list that cannot be read: High;
  - the reading of the argv the process makes sends SIGHUP. Under
    `POSIXLY_CORRECT` an option after systemctl's verb, or after a pid for
    procps' `kill`, is an operand and the signal SIGTERM: logrotate's own
    `systemctl kill -s HUP rsyslog.service` then kills `-s.service`,
    `HUP.service` and rsyslog.service with SIGTERM (measured with systemd
    255). The exec pump reads the environment of an exec of systemctl or
    `kill` while it runs (its start the exec's, its memory still there
    after the read): without `POSIXLY_CORRECT` GNU's reading alone names
    the signal (logrotate's rotation is Low), with it the
    `POSIXLY_CORRECT` reading alone (High). When it could not be read (the
    process gone, its memory gone, its pid another's, a read that failed),
    every reading must send SIGHUP: `systemctl kill rsyslog -s HUP` and
    `kill <pid> -s HUP` are then High, `systemctl -s HUP kill
    rsyslog.service` (the option before the verb), `kill -HUP <pid>` and
    `kill -s HUP <pid>` Low. Residual: a process that rewrites its own
    environment before the pump reads it (code injected into systemctl,
    which could send any signal itself).
- **Names.** iptables by any of its names (`iptables-nft`,
  `iptables-legacy`, `xtables-nft-multi main4`); nft's operands as one
  command line (`nft 'add table x; flush ruleset'`); pkill's pattern a part
  of the process name at least half of it, unless `-x` (`pkill audit` ends
  auditd; `pkill -f agent` names no listed agent), `-f` the full
  command line, `-i` (killall `-I`) any case; killall's name with a `/` the
  executable, its path folded as stat() walks it (`killall
  //usr/sbin/auditd`, `/usr/bin/../sbin/auditd`); procps' pgrep binary run
  as `pkill` or `lt-pkill` is pkill. procps' `kill`: the last `-s` over the
  first `-SIGNAL` (`kill -s KILL -0 <pid>` kills), a pid with leading blanks
  or a `+`.
- **A cloud agent's uninstaller is the switch-off it is** (BUG-86): `sh
  /usr/local/qcloud/YunJing/uninst.sh` is NN-L-EVA-002, no longer registered
  as the agent's own process starting.
- Residual, declared: some ways to stop a listed tool are not recognised
  by these tables, and only some of the signals that end a registered tool
  are recorded (lot 330 is to report every default-fatal signal).

## 33. The exec environment's check complete (lot 325)

- **A staging preload behind other variables is refused now.** The check of
  [the exec policy's design, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EXEC_POLICY.md)
  read the first 64 variables of an exec's environment. It reads all of
  them. Expect `NN-L-EXECENV-001` records and refused execs where a staging
  `LD_PRELOAD` / `LD_AUDIT` sat past the 64th variable: CI jobs, IDE
  terminals and Kubernetes pods carry far more than 64. Nothing to
  configure.
- **An environment longer than any the kernel accepts** (more than
  1,048,576 variables: its array grew after the kernel counted it) is
  refused at a protected target — a tier whose rule refuses a staging
  preload — or a set-id one, and recorded High (`NN-L-EXECENV-002`, "could
  not be read whole"). No legitimate program comes near it (the lab's
  measurements are in the lot's note in the [capability program](https://github.com/northnarrow/northnarrow-new/blob/main/docs/roadmap/CAPABILITY_PROGRAM.md)).
- **Each `LD_PRELOAD` is judged, each entry as the loader reads it.** An
  environment with two (a staging one and a clean one) is refused whichever
  comes last. Each value is read whole (about 4 KiB at the exec's check),
  split as the loader splits it (colons and white space for `LD_PRELOAD`)
  and each path normalised: `//tmp/x.so`, `/./tmp/x.so`, 120 spaces then
  `/tmp/x.so` are refused like `/tmp/x.so`. **A relative loader path**
  (`LD_PRELOAD=./x.so`, `lib/x.so`, or a bare name with a relative
  `LD_LIBRARY_PATH`) **is refused where a staging preload is** (a tier whose
  rule refuses one, a set-id target) and recorded elsewhere
  (`relative_loader_path`). **A clean value longer than 128 bytes is no
  longer refused** (it was, as "not finished"). **A loader value with a
  control byte or a `$` token is refused where a staging preload is**
  (`irregular_loader_value`), and so is a bare `LD_PRELOAD` / `LD_AUDIT`
  name with an empty `LD_LIBRARY_PATH` element (the caller's directory). An
  empty element alone — `LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/lib` with the
  variable unset — is only recorded.
- **New status counts** on the exec policy's line of `nn-admin status`, when
  not zero: "environments not finished", "changed after the kernel's copy",
  "execs let through without their walk" (`--json`: `env_truncated`,
  `env_changed`, `lost_open`).
- **A new program, `execpol_env_commit`, on `sched_process_exec`.** It reads
  the new image's environment — the kernel's own copy — after the exec's
  point of no return and kills the image (`SIGKILL`, before its first
  instruction) when it holds a staging loader entry the exec's first check
  did not see. A legitimate program never shows one there: the first check
  would have refused it. Two optional BTF offsets (`mm_struct.env_start`,
  `env_end`, slots 130–131; the enum, tracepoint and hook-argument slots
  move by two: 146 slots). Without them, or with the program refused by the
  verifier, the start signs an `exec_policy` degradation and the first check
  works alone. It also kills a protected or set-id target on what it cannot
  clear (a loader value longer than about 4 KiB, a relative path, an
  unreadable string), and records it elsewhere.
- **A new LSM program, `nn_task_free`** (`task_free`), attached with the
  file-open sensor or the exec guards. It removes, when the kernel frees a
  task, the entries that live as long as the task: the file-open sensor's
  buffer (kept between opens now: one lookup per open), the exec
  quarantine's candidate (`EXECQ_CAND`, a plain hash now), the exec
  policy's note for the post-commit check. **A new LSM program,
  `execq_exec_failed`** (`file_free_security`), attached with the exec
  quarantine, removes a failed exec's candidate when its file is freed;
  each login holds at most 1,024 candidates (a session's container
  subuids count as the login), and a dropped one is counted in `not_held`
  and signed (`exec quarantine fail-open`); the map full, the oldest
  stuck candidate goes for the new one, counted and signed the same way.
- **A new LSM program, `exec_env_lsm`** (`bprm_check_security`), attached by
  the exec policy when it judges the environment: the environment's check,
  moved out of the exec sensor's `exec_check_lsm` (each program has its own
  verifier budget). A tool that lists the agent's programs sees one more on
  the hook; without it the start signs an `exec_policy` degradation.
- **The file-open sensor's per-task buffers** are capped per login (16,384);
  past it the open is judged in a buffer of its own run (correct, at the
  cost before lot 325), counted in `nn-admin status --json`
  (`open_sensor_per_call_total`, appended last: a reader that requires the
  key set must accept it).
- **Past the exec guards' capacity** (2048 execs preempted in the middle
  of the exec sensor at once: a fork bomb), enforce mode refused every exec,
  an administrator's shell's included. A protected target (a deny that the
  tier, memfd, deleted, tmpfs, a world-writable directory or the
  environment support) is still refused; an environment that could not be
  read is judged on the kernel's copy after the commit (a staging preload
  killed there); every other exec runs and is recorded
  (`NN-L-EXECPOL-001`, Low, "judged without its walk"). The agent signs
  the degradation `execpol_capacity` while it lasts.


## 34. A benign host's daily records (lot 340)

What a benign host produced every day — and what an operator who reads the
records after the upgrade will see instead. The attack variants beside each
are judged as before; `CHANGELOG.md` has the detail.

- **logrotate's daily run**: NN-L-FIM-005 and NN-L-FIM-019 records of a
  write by the packaged `/usr/sbin/logrotate`, as root, run exactly as
  `logrotate /etc/logrotate.conf`, that PID 1 forked (the timer's
  `logrotate.service`) or cron's daily run started
  (`/etc/cron.daily/logrotate` under `run-parts`, up to a cron daemon PID 1
  forked) are **Low** and never acted on (NN-L-FIM-019 killed). Run by hand
  from a session, with any other argument (`-f`, `-s`, another
  configuration), by a non-root user, under anacron or cron run by hand or
  a cron `@reboot` entry, a copy of logrotate, any other writer of wtmp or
  btmp: as before. A root that runs the packaged rotation under
  `systemd-run` leaves the Low record the timer would have.
  **What to check after the upgrade**: a host whose logrotate runs with
  other arguments (a unit or crontab of its own) keeps its records at the
  rules' verdicts.
- **rsyslogd after a rotation, and at the start**: its appends no longer
  read as truncations (NN-L-FIM-005 High until the file outgrew the rotated
  one; the first append after the agent's start, before the baseline was
  read). **What changed in the record**: a FIM event's `baseline_size` is
  the size of that file when the agent last read it, else when it was
  watched (else the path's baseline, as before).
- **A key store's directory listed** (`find /`, plocate's daily
  `updatedb`): no NN-L-FIM-015/016/017 verdict any more; opening a file of
  the store is judged as before.
- **Backups**: the writer that never executes (rsync's receiver) is judged
  on its forker's lineage from the kernel's fork record, after it exited
  too (and its forker's, when that one never executed either: rsync's
  generator): a unit's `sh -c 'rsync …'` is vouched for by the unit. The
  open sensor's ring record grew to 632 bytes (an agent and its eBPF object are
  one build; nothing to do).
- **`npm ci` / `go test`** do not raise ENGAGED any more: npm's CLI run
  through `/usr/bin/npm` (the package's link) or npm's CLI under a system
  path prefix, with no `NODE_OPTIONS`/`NODE_PATH` loading code (known limit:
  the prefix is not a proof of root ownership, and npm loads
  `~/.npm-init.js` itself; a follow-up narrows the exemption to npm's own
  write paths), and the packaged `go`
  command writing in its work directory (`$TMPDIR/go-build<digits>/`), its
  build cache or its module cache. A `go` in a home (`GOTOOLCHAIN`), what
  `go` runs, and node running any other script still count.
- **R011**: root's `modprobe <name>` of the system's tool that exited
  before its environment was read is **Medium** (was High).
- **Ubuntu 26.04**: systemd's own BPF loads the hook refuses (the user
  manager's and networkd's feature probes; PID 1's `RestrictFileSystems=`
  program at a `daemon-reexec`) are still refused, now recorded **Low**
  (NN-L-AT-001, "A known system program's BPF load, refused"); the posture
  no longer goes ENGAGED for them, and they never corroborate another
  signal into COMBAT. The proof is the loader's image as its exec recorded
  it when it loaded: the packaged `/usr/lib/systemd/systemd` or
  `/usr/lib/systemd/systemd-networkd`, device and inode, loading a
  `tracepoint` or `kprobe` program, or PID 1 itself an `lsm` one. A loader
  whose exec the agent has not received when the refusal arrives stays
  High.
- **DNS resolvers**: NN-L-NET-004/-005/-014 treat a sender as a resolver
  only when the agent proves it — the host's packaged resolver at its path
  (device and inode) running as the system's service (its own unit under
  `system.slice`, forked by PID 1 or, for dnsmasq, NetworkManager, system
  users, no `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`), or Kubernetes'
  CoreDNS as containerd, k3s' containerd or CRI-O record it (`kube-system`,
  a `coredns` image, `/coredns`; the container's id the leaf of a
  `kubepods` cgroup, the sender in its init's namespaces). **What to check
  after the upgrade**: a resolver installed outside the system trees
  (`/usr/local/sbin/unbound`, `/opt/…`), or run in a unit of another name
  (the units known: `systemd-resolved`, `named`/`bind9`, `unbound`,
  `dnsmasq` or the network manager's that starts it, `dnscrypt-proxy`,
  `pdns-recursor`, `kresd@`, `stubby`, `connman`), is now judged as any
  process — its forwarded legs count against it, and a tunnel's worth of
  hash-shaped names under one zone kills it. A known
  resolver's legs that cannot be traced to the process that asked stay one
  Medium record each and are no longer a High "tunnel" of the resolver. The
  `DnsQuery` event gained `known_resolver` (absent when false).
## 35. The verifier's headroom, and shares an account's (lot 332)

- **`deploy/lab/nn-lab.sh verifier-check` fails above 900,000** processed
  instructions for any program the agent needs, or when it cannot measure
  one (lab builds only; the agent itself is unchanged by it). It measures
  5.15 too, with a kprobe event on `check_max_stack_depth` created for the
  run in a tracing instance of its own (`instances/nn_verifier_check`),
  filtered on its own pid (a filter that cannot be set is no probe), each
  load's line found by its program's tag; `nn-lab.sh` removes the instance
  and the event before and after every run, a killed one included. A lab
  that runs it on a kernel without kprobe events or tracefs and without
  `verified_insns` (before 5.16) gets a failure, "unmeasured". `NN_VERIFIER_CHECK_BUDGET` lowers the budget, never raises
  it. The nightly `lab-vm.yml` runs it on every guest
  ([kernel compatibility, "Verifier headroom"](https://github.com/northnarrow/northnarrow-new/blob/main/docs/operator/KERNEL_COMPATIBILITY.md)).
- **The file-open sensor runs as global functions** (`nn_open_class`,
  `nn_open_count_write`, `nn_open_observe`): the same reads, judgments and
  records in the same order; a tool that dumps the program sees them as
  its subprograms. `fim_file_open_sensor` processes 144,600 instructions
  on 5.15 where it processed 821,228.
- **The FIM buffers' and the exec quarantine's shares are an account's**:
  the uid in the initial user namespace; in a user namespace, the account
  that made the outermost one, or that namespace when root made it (one
  share per system container). They were the login uid's, which a
  service's children set to any value. A root session (`sudo -i`) now
  counts in root's share, not the login's. Three optional BTF offsets
  (`user_namespace.parent`, `.level`, `.owner`; the slots after them move
  by three, an agent and its object are one build): without them a task's
  share is its uid's.
- **A user's subordinate uids count as the user's** (the review of #551,
  F1): the agent publishes `/etc/subuid` into an LPM trie (`SHARE_SUBUID`,
  16,384 entries, 16,383 used — one kept free for an in-place rewrite on
  kernels before the upstream fix for full LPM tries —, about 1,300 users'
  ranges; read again within 2 s of a
  change to `/etc/subuid` or `/etc/passwd`, a thread `nn-subuid`), and a
  uid of a range, taken as a real uid in the initial namespace or the
  creator of a namespace, is its owner's share. A uid of the ranges' span
  no single owner is known for — an owner name `/etc/passwd` does not
  resolve (an LDAP account's range is not resolved through NSS), two
  users' ranges overlapping, a gap between ranges, a range past the trie's
  room — counts in the overflow row (one share, the same cap), never in a
  share of its own; an `/etc/subuid` that cannot be read puts every uid
  from 65,536 up there (logged). An account whose uid lies inside another
  account's range counts as that account's — except in a range root owns
  (LXD, Incus: `root:1000000:1000000000`), which is a reserved row of its
  own (`ROOT_SUBID_SHARE`, the per-share cap), never root's: a domain
  account (sssd, FreeIPA) with a uid there cannot fill root's row (the
  re-check of #551, G1). An account whose uid lies in a gap between
  ranges, or in a range whose owner is not known, counts in the overflow
  row. A range's start and count are read in decimal, as `useradd` writes
  them: a line `newuidmap` would read in hex is skipped, one with a
  leading `0` is read as decimal. `/etc/subgid` is not read (the key is a
  uid). What a task still chooses: a namespace root made is one
  share per namespace, so a setuid-root helper that makes one per run
  (firejail, a setuid bwrap) gives its caller one share per run; ranges
  served by NSS (`subid:` in `nsswitch.conf`) are not published.
- **A global cap on each shares' map**: past the map's room less one
  share's (3,072 of the quarantine's 4,096 candidates, 49,152 of the FIM
  sensor's 65,536 buffers), a share holding a 64th of a share or more takes
  no more — the FIM open is then judged in its run's own buffer, as past a
  share's cap; a candidate is dropped (`CAND_DROPPED`, signed with the
  quarantine's fail-opens). The cap holds back greedy shares; 64 more
  shares still take their floor, so the map's room stays the bound on how
  many shares fit.
- **A full candidates' map evicts its oldest held candidate**, found by
  walking the map (a candidate made at least a second ago), where the
  first 8 slots of a ring could all be gone ones. Kernel 5.13 or later
  (`bpf_for_each_map_elem`), as every kernel the agent supports.

## 36. Shells and tools by what the kernel executed (lot 313)

- **R020 knows a shell by its file** (the external bug hunt's edition 1.4:
  BUG-85, N1). A copy of an installed shell or interpreter under any name
  (`cp /bin/bash ~/x`), an installed one under another name (a hard link, a
  bind mount), busybox running a shell (`busybox sh`, `/bin/busybox sh`, the
  login shells `-sh`, `-ash`, a link named `sh`) and a shell the dynamic
  loader runs (`/lib64/ld-linux-x86-64.so.2 /bin/bash -i`, `ld.so ~/x`) with
  its stdin or stdout on a socket is a reverse shell: Critical, the
  posture's `ConfirmedIntrusion` (the kill stays held by the per-rule
  policy). The agent records the host's shells, interpreters and busybox by
  device and inode at its start and every minute ("R020: the installed
  shells and interpreters known by their identity" in the journal):
  `/etc/shells`, and the files of `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`,
  `/usr/local/bin`, each resolved, whose resolved file is named as one.
  Only an exec with its stdio on an inet socket has its running image (or
  the loader's operand) compared, on the exec pump's thread and bounded:
  an answer is remembered by the file's device, inode, size and change
  time; a file is compared whole up to 4 MiB, by samples above (its first
  and last MiB and eight blocks between); each user's compares share 64
  MiB a second (one user's flood spends only that user's) and all users'
  128 MiB (a user with many host uids, the subuids rootless podman maps,
  reads no more; the least recently used of 256 uids kept makes room),
  past either of which an exec is not compared — judged by its name,
  and, for an image a user can
  write with its stdin or stdout on a socket or a parent whose stdio is
  one connected out (the pty-wrapped shape), recorded High, "identity
  unverified"; an image the pump cannot open (a user's FUSE mount without
  `allow_other`) is recorded so too: a flood followed by a renamed shell is
  never silence — `nn-admin status` shows "shell copies: N running images
  compared, M execs not compared". The dynamic loader is recorded with the
  shells: a renamed copy of `ld-linux-x86-64.so.2` running bash is the
  loader, its operand the program. Residuals: a shell that is not byte-identical to an
  installed one, and a container's own shells, are judged by name only. A
  behaviour-based check, independent of identity, is the next lot's.
  A behaviour-based check, independent of identity, is the next lot's.
- **R006 reads socat's addresses as socat does** (BUG-112). The
  distribution's socat whose address runs a shell is killed in more
  spellings: each address read by socat's lexer (`\` and quotes dropped
  anywhere: `EXEC:/bin/s\h`, `EX"EC":/bin/sh`), each half of a dual
  address (`a!!b`) and each link of a chain (`a|b`); `SYSTEM:` and
  `SHELL:` always (socat runs `/bin/sh -c`: a `SYSTEM:` relay that runs a
  plain command is now killed too — allowlist socat in
  `process-comm-allowlist` if a harness needs one); `EXEC:` past `env`
  (`-S` too), `setsid`, `nohup`, `stdbuf`, `timeout`, `nice`, `ionice`,
  `chrt`, `taskset`, `sudo` (`-i`, `-s`: a shell), `doas`, `su`,
  `runuser`, `chroot`/`nsenter`/`unshare` with no command, the dynamic
  loader, busybox; a shell, `script`, or an interpreter running inline
  code, its standard input or a REPL. And whatever the address's spelling,
  **a shell or an interpreter socat starts** (by identity, directly or
  through a launcher that forks, `sudo -i`, `su -`) **is killed**:
  `EXEC:python3 /srv/app.py` is killed now too. A link to `/usr/bin/socat`
  under another name is socat, and so is socat 1.8's own file,
  `/usr/bin/socat1` (a tool's name takes a version suffix). The record
  names the address that runs the shell, as socat read it.
- **System-tree exemptions read the kernel's executed file** (BUG-119):
  the trusted actor's record (R011, R012, R013, R017), R011's package
  transaction and initramfs build, and R006's distribution socat. An exec
  whose kernel path is not known (a mount root the agent cannot place, an
  argv string cut at 255 bytes with `/proc/<pid>/exe` unreadable) is in no
  system tree: killed, as a copy would be. A path with an empty, `.` or
  `..` segment is in none either (the lineage's fallback to a caller's
  string costs trust, never grants it).
- **A module file's name, and a DKMS build, have one reader** (BUG-87,
  BUG-111). `common::module_judge::module_stem` takes the last `.ko`,
  `.ko.xz`, `.ko.zst` or `.ko.gz` that ends the name and refuses `.`, `..`
  and empty: `acme.kontrol.ko` is `acme.kontrol` (the kernel judge vouched
  for no such DKMS module), `..ko` nothing. R018 takes a file of
  `updates/dkms/` or `extra/` for DKMS's build when DKMS's registry holds a
  file of that module, for that kernel, with the same content — as the
  kernel judge does — not when `/var/lib/dkms/<name>` is a directory.
- **An encryption tool asked to encrypt is never trusted for (b) and (c)**
  (BUG-49's residue, the decision of 11/11/2026). `openssl enc` (or a
  cipher command) without `-d`, `openssl smime|cms|pkeyutl|rsautl
  -encrypt`, `gpg`/`gpgtar` `-c`/`-e`/`--symmetric`/`--encrypt`/
  `--encrypt-files` (abbreviations, clusters), `age`/`rage` without `-d`,
  `7z a|u -p`, `rar a -p`/`-hp`, `zip -e`/`-P`, `zipcloak`, `ccrypt`,
  `ccencrypt`, `mcrypt`, `aescrypt -e`, `scrypt enc` — each argv read with
  the tool's own option table (a value is never an option; the last mode
  wins where the tool's does) — whoever started them:
  - their outputs count as ciphertext (b) whatever their header: OpenPGP,
    age, 7-Zip, zip and rar wrap their ciphertext in a container that the
    entropy sampler otherwise sets aside;
  - their renames to a new extension (`ccrypt -r`), and the encrypted
    copies beside originals deleted (c), count — the originals deleted by
    another process of the session that started the tool (`gpg
    --encrypt-files *; rm *`, whether that session is trusted or not) count
    for that tool;
  - two make the assessment decisive (NN-L-IMP-001; the kill held by
    default, aimed at the process that started the tool); their rewrites
    (a) and deletions (d) keep the trust their lineage gives.

  Expect an assessment of a backup job that encrypts with a packaged tool
  in bulk and deletes the originals. **Open (lot 331)**: the shape of an encryption tool followed by
  deletions is decisive in the unit tests but not yet confirmed live on
  every tested system. Encryption that does not show these shapes may be
  seen only by weaker signals (KNOWN_LIMITATIONS).

## 37. The `alpha` profile, the install's start, a wedged uninstall (lot 341)

- **A fresh install is observe-only and starts.** `install.sh` on a host
  without `/etc/northnarrow/install-manifest.json` records the `alpha`
  profile (no response touches a user program; every verdict recorded with
  what it would have done — [`ALPHA_PROFILE.md`](ALPHA_PROFILE.md)), starts
  the agent then the watchdog and enables both at boot. Automation that
  wants the old behaviour passes `--profile enforcing --no-enable` and
  starts the units itself.
- **An existing install keeps enforcing.** An upgrade, or a reinstall over a
  kept `/etc/northnarrow`, keeps the profile its manifest has; a manifest
  from before this lot has none, and its agent enforces as before.
  `install.sh --profile` never switches an installed agent: switching is a
  signed `nn-admin config overlay set profile` (kind 18), applied at the
  agent's next start.
- **Records say what would have run.** A response the no-enforcement gate
  suppressed (`--detect-only`, `NN_DETECT_ONLY`, `alpha`) reads `"response":
  "would have: KillProcessTree"`; it read `"suppressed (detect-only)"`. A
  `Log` decision under the gate reads `"none"`. Records already written keep
  their text; a reader keyed on the old string matches neither.
- **Detect-only also stops an earlier enforcing run's owed exec-quarantine
  kills** (the process is resumed). The module-load judge keeps refusing
  untrusted modules under the gate, as before: the host's integrity.
- **Under `alpha`, the host's integrity and the agent's self-protection
  are enforced as under `enforcing`**: a foreign tracing, LSM, extension
  or `struct_ops` BPF program's load (`bpftrace`, BCC, another EDR), an
  untrusted module, a kexec image, the sysctl guard and its put-back, a
  `cgroup/sysctl` program on the root cgroup, the kprobes and lockdown
  switches, a cgroup v1 move or freeze and a ptrace of PID 1 are refused
  outside a window, besides the agent's own files, processes, cgroup and
  BPF objects ([`ALPHA_PROFILE.md`](ALPHA_PROFILE.md) §1.1). A tester who
  runs bpftrace or BCC installs with `--allow-bpf-tools` (or
  `--allow-bpf-loader <path>`): signed `bpf-loader-allow` lines, applied
  through the started agent (§1.2). Nothing changes on an `enforcing`
  install.
- **An `alpha` start after an enforcing run, with no signed
  `profile.local`**, writes a signed `integrity_drift` of kind
  `profile_downgraded`. A reader of the audit chain that alerts on
  `integrity_drift` sees it; a signed switch to `alpha` raises nothing.
- **`install.sh` refuses a host it cannot run on** before any change:
  not x86_64, systemd not the init system, no kernel BTF, a kernel the new
  agent's `--btf-check` refuses; on a fresh install that starts the units,
  also the BPF LSM off or bpffs not mounted (`--no-enable` installs anyway).
- **The bootstrap key** a fresh install writes also has `telemetry-read`
  (`nn-admin detections`). Keys bootstrapped before keep their line.
- **`uninstall.sh` exits 3** when the agent is wedged: both units disabled,
  the removal finished at the next boot by `northnarrow-uninstall.service`.
  Automation that treated any non-zero exit as a failure should reboot on 3.
- **`nn-admin status`** prints a summary block first; `--json` gains
  `profile` and `records_today`. An `nn-admin` of this release needs an
  agent of this release (the status reply grew two fields, as every
  appended field before).

## 38. The host's and the agent's own records, round 2 (lot 344)

What a tester saw on a plain Ubuntu or Debian host that came from the host
itself or from the agent — and what an operator reads instead after the
upgrade. Each benign case is told by what the kernel proves; the attack
beside it is judged as before. `CHANGELOG.md` has the detail.

- **The watchdog's start**: no NN-L-BPF-002 High any more for our own
  watchdog opening `PROTECTED_PIDS`' pin before it is a protected pid (its
  binary by device and inode, its role vacant, its main thread, its first
  minute — the exemption the refusal already applied): one NN-L-BPF-002
  **Low** record at each start of the agent or the watchdog instead
  (`fresh_instance_get_fd`). A Low one with no such start beside it is a
  program that made itself the watchdog's binary while the role was vacant
  — worth a look. A second watchdog binary started beside the live one, one
  past its first minute, and any handle on a link of the agent's are
  recorded High (and refused) as before.
- **A reboot**: systemd's SIGTERM to the watchdog and the agent during a
  shutdown is still refused until `systemd-shutdown`, and no longer
  recorded as an attempt (NN-L-AT-001 High after every reboot). The agent
  judged it on systemd's last answer, asked up to a second before the
  poweroff (`running`); an answer asked before the signal no longer judges
  it. A `systemctl stop` / `kill` / `restart` outside a trusted-installer
  window while the host runs: High, as before.
- **rsyslogd around a truncation**: with `copytruncate` (a stanza of its
  own, or any `truncate` of a log), rsyslogd's appends were read after the
  truncation and recorded as a truncation by rsyslogd (NN-L-FIM-005 High).
  The kernel now says whether every write since the file's last record was
  an `O_APPEND` write by one process, and whether another process
  truncated the file meanwhile; rsyslogd's appends are not recorded (on
  Debian too, where rsyslogd runs as root and every one was) when the file
  grew, or when that other process's truncation explains the smaller size
  — the truncation is recorded, with its own writer (logrotate's scheduled
  run Low, anyone else High). A shrink nothing else explains (a
  `fallocate` collapse through an `O_APPEND` file) is High as before.
  **What changed in the record**: a FIM event may carry
  `appends_only: true` and `truncated_by_another: true`.
- **A writer that never executes**: a FIM drift's writer forked without an
  exec (a backup's receiver, a daemon's worker) and gone before its record
  was judged is read from the kernel's fork record (its forker's exec), and
  any writer gone from its exec record — the record's `exe` was empty. The
  FIM ring record grew to 176 bytes (the writer's fork records, and the
  writer's start for a write seen at close; an agent and its eBPF object
  are one build; nothing to do).
- **Not changed, measured**: the packaged rotation under `systemd-run`
  (`logrotate /etc/logrotate.conf`, root, PID 1's fork) was already Low —
  its High was rsyslogd's, above; `-f`, `-s` or another configuration keep
  the rules' verdicts (the review of #552). plocate's daily `updatedb`
  makes no record (lot 340). The BPF cross-view's records on a clean host's
  boot are Low (systemd's device, firewall and `restrict_filesystems`
  programs; HID-BPF); a program of a refused type present when the agent
  starts (a tracing tool left running) is High by design. docker's
  install, restart, `docker run` and `docker build` made no NN-L-EVA-002
  record on Ubuntu 24.04 or Debian 13, before or after.

## 39. Developer tools and services, round 2 (lot 346)

What a developer's or a self-hoster's normal work produced, and what an
operator who reads the records after the upgrade will see instead. The
attack variants beside each are judged as before; `CHANGELOG.md` has the
detail.

- **`go test` and `go run`** no longer raise ENGAGED (`StagingExec`): a
  program the packaged `go` built in its work directory
  (`<tmp>/go-build<digits>/b<digits>/…`) and runs itself, with no second
  factor. R001's record of that exec stays High (a person's exec from
  `/tmp`, lot 283b). `go test`'s rewrite of its own archives is no longer
  NN-L-IMP-001 Critical: the ransomware tracker trusts the packaged `go`
  in its work, build-cache and module-cache directories. The packaged `go`
  is its path executed from a root-only directory in PID 1's mount
  namespace (its image): a container's `go` or one a user namespace binds
  over it is judged as any program — for the staging exec, the mass-write
  arm (lot 340's exemption too) and the tracker. The same file run by a
  shell, by a test binary, by a `go` in a home, and anything else run from
  `/tmp` raise as before. **Residual**: a file in the work directory's
  layout is not proof that `go` built it — `go run -exec`, `go test -exec`,
  `-toolexec`, `go vet -vettool`, `//go:generate` or `GOFLAGS` have `go`
  fork a program the user names; one dropped at `/tmp/go-build<n>/b<n>/`
  that way raises no `StagingExec` (R001's High stays).
- **npm** is exempt from the mass-write arm only in its own directories:
  a `node_modules` tree, `~/.npm`, a manifest or lockfile; it was exempt
  wherever it wrote. npm must be the packaged one: node (`/usr/bin/node`,
  `/usr/local/bin/node`) running npm's CLI from `/usr` or a link a package
  installed (`/usr/bin/npm`, `/usr/local/bin/npm`), executed from a
  root-only directory in PID 1's mount namespace, with no
  `NODE_OPTIONS`/`NODE_PATH` loading code. **What to check after the
  upgrade**: npm from a user prefix (nvm, volta) is judged as any process;
  `npm ci` from such a node in a CI runner raises ENGAGED as before. A
  cache moved out of its default place (`npm_config_cache`) is no longer
  npm's own. **Residual**: the arm judges the one file that crossed its
  threshold (the kernel reports a window's crossing once per process), so
  code running inside npm (`npm init`'s `~/.npm-init.js`) that puts each
  window's crossing in `node_modules` pads the window — the documents it
  rewrites beside it are not counted by the arm.
- **yarn, pnpm and bun** are judged as any writer, as before: an install
  that crosses a threshold still raises ENGAGED. They load a project's
  code in their own process on every install (`.pnpmfile.cjs`, yarn
  berry's `plugins:`, corepack's downloaded yarn or pnpm), which could pad
  the window as above; no exemption by directory is safe for them. The
  lab's dev corpus installs a project with each and crosses no
  threshold.
- **`initdb`** making a cluster (`pg_createcluster` by hand, `sudo -u
  postgres initdb`) no longer raises ENGAGED: the packaged `initdb`
  (`/usr/lib/postgresql/<N>/bin`, `/usr/pgsql-<N>/bin`, `/usr/bin`) and
  the bootstrap `postgres` it starts, as a service account, writing only
  that account's own data. Any other program of the account in a session
  still counts. **Residual**: `initdb -L <dir>` has the exempt bootstrap
  run the SQL files of a directory the caller names, as superuser, which
  can rewrite the account's live cluster unjudged — as `psql` to the
  running server can, whose writes are exempt by design.
- **Kubernetes' NodeLocal DNSCache and kube-dns** are known resolvers, as
  CoreDNS: their legs are recorded, never their own tunnel, never killed.
- **A resolver daemon that forked itself** (`Type=forking`) is its unit's
  service when its lineage records the fork.
- **The exec record's argv** keeps empty arguments (`""`): an exec's
  `argv` in a record may now hold `""` where it read as missing. A command
  line of exactly 512 bytes is now marked cut (`argv_truncated`), as a
  longer one: the sensor reads 511.

## 40. Allowed BPF loaders, the profile alarm, install's policy edges (lot 345)

- **A loader `bpf-loader-allow` names is still refused what would kill or
  blind the agent.** In a load of a type refused by default (`kprobe`,
  `tracepoint`, `perf_event`, `raw_tracepoint`, `raw_tracepoint_writable`,
  `tracing`, `struct_ops`, `ext`, `lsm` — the types only such a line opens),
  an fmod_ret (`BPF_MODIFY_RETURN`) program, and a program that calls
  `bpf_send_signal`, `bpf_send_signal_thread`, `bpf_probe_write_user`,
  `bpf_override_return` or one of the kfuncs below, are refused to every
  loader outside the agent's family and a trusted-installer window — the
  ones `install.sh --allow-bpf-tools` / `--allow-bpf-loader` named
  included.
  bpftrace's `signal()` (`--unsafe`) is refused this way; its other probes,
  BCC's tools and plain tracing programs load as before. Each refusal is a
  signed `bpf_prog_type` record (High) naming the helper or the fmod_ret
  (`ALPHA_PROFILE.md` §1.2). Where the kernel judges it: from 6.9 at the
  `bpf_prog_load` hook (`EPERM`, before the verifier); before 6.9 at the
  `bpf_prog` hook once verified (`EPERM`), the targets calibrated at the
  agent's start from its own programs (two programs loaded, read and
  unloaded: `nn_calib_signals`, `nn_calib_override`), and
  `bpf_probe_write_user` at the verifier's `locked_down` question (the
  verifier reports `EINVAL`). The agent's unit gains no capability. Two
  more pins under the pin root on such kernels (`prog_bpf_prog_load` /
  `link_bpf_prog_load` from 6.9; `prog_locked_down` / `link_locked_down`
  before) — `uninstall.sh` removes them with the rest.
- **The signalling kfuncs are refused in a load of EVERY type (the review
  of #553).** `bpf_send_signal_task` (6.13 and later) and the
  `bpf_task_work_schedule_signal` / `bpf_task_work_schedule_resume` kfuncs
  (6.18 and later; their `_impl` spellings on 6.18) are refused in a
  foreign load of any program type — `syscall` (run with `BPF_PROG_RUN`),
  XDP, tc, `cgroup_skb` and every other type a root process loads with no
  opt-out — at the `bpf_prog_load` hook (`EPERM`, before the verifier), a
  signed `bpf_prog_type` record (High) naming the kfunc. The kfuncs the
  kernel's BTF has are read; a program the judge cannot read whole is
  refused. Before this release, on 6.13 and later, **any root process**
  could kill the agent and its watchdog this way: a `syscall` program doing
  `bpf_task_from_pid(agent)` then `bpf_send_signal_task(…, SIGKILL, …)`
  signals as `SI_KERNEL`, which no `task_kill` hook sees, and the judge
  read only the types refused by default. Per kernel: before 6.13 none of
  these kfuncs exists (nothing to refuse); on 6.9 to 6.12 a type let
  through by default is not read at all (no cost); from 6.13 each foreign
  load of such a type is read once, at the load (no cost per packet).
  Cilium and systemd call none of them. Measured on Ubuntu 26.04 (`7.0.0-43`, our lab guest): with no agent, a
  root `syscall` program run this way killed a `sleep`; with the agent
  (installed `--allow-bpf-tools`), the same program against the agent —
  `syscall`, XDP and tc, from a root process no line names and from
  python3 — was refused `EPERM` at the load, each with a signed record
  naming `bpf_send_signal_task`, and the agent kept its pid; the same
  programs without the signal loaded (and ran), bpftrace and BCC's
  `opensnoop-bpfcc` ran. `bpf_prog_load_guard`: 5,613 instructions
  processed; `verifier-check` 0 failing, the highest program 360,991.
- **A failed calibration suspends the opt-outs (before 6.9).** The
  `locked_down` guard for `bpf_probe_write_user` is attached whatever the
  calibration does (a failed one used to drop it). While the content judge
  is not armed — a calibration that failed, or that read other calls than
  its programs make (it now takes exactly the two signal calls and the one
  override call, each a different helper), a configuration not written —
  the `bpf` hook honours **no** `bpf-loader-allow` line: their types are
  refused again, as without the line, until a start arms the judge. The
  observe failure `bpf content judge` says so in `nn-admin status`.
- **The profile alarm compares profiles.** The signed `agent_boot` row
  carries `profile` and `profile_source`; an `alpha` start without a signed
  `profile.local` alarms after a boot of the `enforcing` profile, observing
  or not (a row written before this release: after one that ran its
  responses). The alarm is also a degradation of source `profile` in
  `nn-admin status --key` (and counts against the trust level). A reader of
  the audit chain keyed on `detect_only` keeps working; one that wants the
  profile reads `profile`.
- **The profile alarm stays until something signed answers it (the review
  of #553).** It no longer lives one boot only: while the chain holds a
  `profile_downgraded` row that nothing signed answered, every later start
  keeps the degradation of source `profile` (`PROFILE DOWNGRADE NOT
  ACKNOWLEDGED` in the journal; `nn-admin status --key`, the trust level),
  however many times the host reboots. It ends when a start runs a profile
  from a signed `profile.local` (alpha or enforcing), or after a signed
  `nn-admin config overlay set profile` succeeds (its `config_overlay_set`
  row is the acknowledgement; the next start no longer alarms). An unsigned
  return to `enforcing` (the manifest edited back) does not end it. No new
  row is written per start: the chain already holds the event. An
  observing `agent_boot` row of an agent before the profile field no longer
  resets the known profile to "unknown".
- **`install.sh --allow-bpf-tools` / `--allow-bpf-loader`**: an existing
  line of a named loader that lacks some of the five tracing types is
  widened (its own types kept); a policy file without a final newline no
  longer makes the agent refuse the whole policy; nothing is signed over a
  `rule-policy.local` whose signature does not verify (the install warns,
  the lines are not applied — sign them by hand after a review); a script
  named by `--allow-bpf-loader` is warned about (the kernel sees its
  interpreter). `--help` and the summary say what the flag opens.
- **`install.sh` signs no policy with a line opening `lsm`, `struct_ops`
  or `ext` (the review of #553).** Such a line is hand-made (the flags
  write the five tracing types only), and a program of those types blinds
  or starves the agent — the content judge reads no return value. The
  install warns, names the line and signs nothing; review the policy and
  sign it yourself (`RULE_POLICY.md` §2.5).
- **Feature probes (measured).** `bpftool feature probe kernel` loads a small
  program of each type: the nine types refused by default are refused to
  it (bpftool is no opt-out's loader) — nine signed `bpf_prog_type`
  records, High, on Ubuntu 26.04 (7.0); no content-judge record. Run it
  inside a trusted-installer window, or expect them. `bpftrace --info`
  under the opt-out: six records, none High (its loads are the opt-out's,
  Low).

## 41. A container runtime's start, the shutdown record (lot 347)

- **runc's copy of itself is no longer Critical.** At every container
  start, `docker exec`, build and Podman run, runc (1.1 on Debian 13, under
  containerd's shim, dockerd or conmon) executes itself again from a sealed
  memfd copy of its own image; R004 recorded each as fileless (Critical,
  `would have: KillProcessTree` under `alpha`, the kill under `enforcing`).
  Such an exec now has no verdict when the exec pump finds the memfd sealed
  and byte for byte an installed runtime (`runc`, `crun` in the binary
  directories), the process that made it runs that image (the kernel's exec
  records) and an installed manager started the runtime
  ([`CONTAINER_HOST_DEPLOY.md`](CONTAINER_HOST_DEPLOY.md)). Any other memfd
  exec is Critical as before. A runtime the agent does not record (k3s's
  bundled runc, a snap's) keeps the Critical.
- **containerd's and dockerd's module probes are Low.** containerd 1.7's
  `modprobe aufs`, run with the `LD_LIBRARY_PATH` its `opt` plugin sets, was
  R011's kill at every containerd start on Debian 13 (High). The packaged
  containerd's or dockerd's `modprobe` of a container runtime's modules
  (`overlay`, `aufs`, `erofs`, `bridge`, `br_netfilter`, `veth`, the
  netfilter, nftables, xtables and iptables families), the system's tool by
  name, is a Low record; R018 still judges the module file at its load. Any
  other module, a caller's library path, `MODPROBE_OPTIONS`, `LD_PRELOAD`
  or another parent keeps R011's verdict.
- **The shutdown record of wtmp.** `systemd-update-utmp` writing the
  shutdown record while the agent was still stopping was NN-L-FIM-019 High
  (`would have: KillProcess`) on Ubuntu 24.04 at about one shutdown in two.
  The FIM drain now reads the writer's image and cgroup at the write; the
  host's packaged binary in its own unit's cgroup has no verdict. Any other
  writer of wtmp or btmp keeps the High kill.
- **The review of #556 narrowed each exemption.** A memfd is exempt only
  when the kernel executed it already sealed against writing (the exec
  sensor reads its seals at the exec; an agent in tracepoint mode, or on a
  kernel whose BTF lacks `shmem_inode_info`, keeps the Critical). The
  compares' budget is per user (64 MiB a second each) with a reserve for
  root (256 MiB of 512): a memfd past the budget is "not compared
  (budget)" — root's recorded High, never killed; any other uid's (a user
  can spend its own share) killed, Critical, as before. A runtime or
  manager is recorded only when its file and its directories are root's and
  writable by no one else. containerd's library
  path is accepted only as exactly `/var/lib/containerd/opt/lib` or
  `/opt/containerd/lib`, a root-only directory of root-only files. The utmp
  unit's write is exempt only as an append of whole login records, by a
  process that started before the record.
- **Nothing to configure.** No overlay, allowlist entry or signed policy
  changes; the container-runtime overlay of `process-comm-allowlist` (R013)
  is unchanged. Detection records of these three shapes stop appearing.

## 42. A controller change, an account tool, an initramfs build (lot 348)

- **A cgroup controller enabled above the agent is no attempt on it
  (kernels before 6.5).** systemd, runc and containerd-shim enable the
  cgroup v2 controllers of a new container's ancestors at its start. Before
  6.5 the kernel's cpuset controller then asks the scheduling hook of every
  task it re-homes — the agent's threads among them, whose CPUs nothing
  changes — and the agent refused it: on Ubuntu 22.04 each container start
  left three or four NN-L-AT-001 High records ("denied in kernel",
  operation `sched`) and the cpuset controller was never enabled
  (`docker run --cpuset-cpus` could not apply). The thread writing a
  `cgroup.subtree_control` is now let through for that write
  ([`CONTAINER_HOST_DEPLOY.md`](CONTAINER_HOST_DEPLOY.md)); any other
  change of the agent's scheduling (`taskset -p`, `chrt`, `sched_setattr`,
  `timerslack_ns`) is refused and signed as before. A new eBPF program,
  `cgroup_subtree_mark` (pins `prog_cgroup_subtree_control_write`,
  `link_cgroup_subtree_control_write`), is attached with the cgroup move
  guard; an older agent's pins have no such entry, and an upgrade adds them.
- **A package's system account is a Low record.** A maintainer script that
  creates its package's account (`adduser` → `useradd`, `usermod`, `chage`,
  `chfn`; `systemd-sysusers`) wrote `/etc/passwd` and `/etc/shadow` with
  NN-L-FIM-003 High at Docker's install on Ubuntu 22.04 and 26.04 and
  Debian 13. An account tool run in a package transaction is now recorded
  Low, as every other write of the transaction; root's account tool run by
  hand stays High, and any other writer keeps its verdict.
- **A dpkg trigger's initramfs build is Low.** A package whose postinst
  asks for `update-initramfs` (Podman's `fuse3` on Debian 13, any kernel
  update) had R011 record the hook `kmod` and, on Ubuntu 22.04, about a
  hundred `modprobe --show-depends` High. They are Low now when the exec
  pump read the packaged builder and a root package manager in the lineage
  and the exec is the system's modprobe asked to load nothing, or a script
  of a system tree that is the host's file at its path. Your own `sudo
  update-initramfs -u` stays High (lot 287).
- **containerd's first start right after its install.** On Debian 13 the
  first `modprobe aufs` of the just-installed containerd was R011 High
  (`would have: KillProcess`) at `apt install docker.io`; later starts were
  Low (lot 347). The agent now records a runtime installed since its last
  minute's census before it judges a module tool's exec: Low at the install
  too.
- **Two log and login-record judgements narrowed (after #554).** A size
  change of a log by another process explains a later shrink only when it
  made the file smaller; a login record's writer must be the process that
  started at the writer's start the kernel recorded. Neither changes what
  a benign host records.
- **`--watchdog-exe` naming the agent's own binary is refused.** The agent
  does not start (the journal names the option); point it at the watchdog,
  or drop it (the `northnarrow-watchdog` next to the agent is the default).
- **Residuals named by the review of #557.**
  - With `+cpuset` now enabled at the root on 5.15 (and, as before, on 6.8
    and later), root can confine the agent to one CPU through a sibling
    cgroup in `cpuset.cpus.partition=root`: no hook sees it and no record
    is written. The agent does not yet watch its own effective CPUs.
  - The write's mark lives up to 5 s if the clean-up fexit is skipped
    (full preemption), and stale entries are not reclaimed. A user with a
    delegated cgroup can fill the 64 entries, and root's containers then
    get the old record back (High, no change of state).
  - Inside a package transaction faked by root, `useradd -o -u <uid>`
    resets that user's lastlog with a Low NN-L-FIM-018, where it was High.
    The transaction is proven by lineage (a root package manager on the
    host, still running), so a user or a setuid path cannot fake it.
  - The initramfs hook directories (`/etc/initramfs-tools/hooks`, …) are
    not watched by FIM. A hook planted there stays R011 High when it runs,
    because it is not in a system tree.
- **Nothing to configure.** No overlay, allowlist or signed policy changes.

## 43. The agent's own CPUs, a window's BPF load, the release's features (lot 349)

- **A confinement of the agent's CPUs is a signed record.** A sibling
  cgroup in `cpuset.cpus.partition=root` (or `isolated`) takes its CPUs
  from every other cgroup of the parent — the agent's among them — with no
  hook asked: root could confine the agent to one CPU and nothing was
  recorded. Every 5 s the kernel-state round now compares each thread's
  CPU affinity and the agent's cgroup's `cpuset.cpus.effective` with the
  CPUs it should run on: the online CPUs, less those `isolcpus=` isolates,
  narrowed by systemd's `[Manager] CPUAffinity=` (read at the agent's
  start) and by the `cpuset.cpus` of a slice above it (`AllowedCPUs=` on
  `northnarrow.slice`). A shrink is a signed NN-L-AT-001 `cpu_confined`
  High that names the cause (a partition and its cgroup, the agent's own
  cgroup's `cpuset.cpus`, a thread's affinity, a move to another cgroup),
  and the degradation `own_cpus` in `nn-admin status --key` ("the agent may
  run on CPUs 0 of the 0-3 it should …") while it holds; when it ends the
  degradation leaves the status.
  - **What records nothing:** a CPU taken offline or brought back (each
    round is judged against the CPUs online at its two reads and at the
    last round's: the kernel narrows the masks to the active CPUs), a container runtime enabling
    the cpuset controller above the agent, and `AllowedCPUs=` on
    `northnarrow.slice` set by systemd (a reservation: set it inside a
    trusted-installer window, as any change of the slice). A host whose
    real-time workload uses an `isolated` partition gets the record: the
    agent does run on fewer CPUs there.
  - **Removing that `AllowedCPUs=` is recorded (measured, true).** When
    systemd then drops the cpuset controller from the slice, the kernel
    leaves the agent's threads on the CPUs they had (Ubuntu 22.04 and
    24.04: three of four after `AllowedCPUs=0-2` was reset): the agent
    does run on fewer CPUs than it should, and says so (`cpu_confined`,
    cause `affinity`). Restart the agent (inside a window) to give it every
    CPU back; it does not widen its own threads' masks.
  - **Nothing blinds it silently (the review of #558, F2, F3, F6, F7).**
    - A round it cannot judge — the online CPUs moving at every round (root
      toggling a CPU), a cgroup file it reads reached through a mount — no
      longer passes silently: three in a row are a signed `cpu_confined`
      High, cause "the watch could not judge".
    - The online CPUs, `/proc/stat`, `/proc/self/cgroup` and the thread
      list are files opened once at the agent's start (a sysfs or procfs
      file, by its filesystem's magic: a FUSE file there at the start is
      refused) and read afresh each round: a file bound over
      `/sys/devices/system/cpu/online` later changes nothing. The expected
      CPUs are the union of the online list and `/proc/stat`'s: one faked
      source cannot narrow them.
    - The cgroup files are opened beneath the cgroup root opened at the
      start (`openat2`, `RESOLVE_NO_XDEV`, no symlinks): a bind mount over
      the slice's `cpuset.cpus` (or over the slice's directory) makes the
      round unjudged, never a narrower expectation; the partition walk
      skips mounted directories.
    - systemd's repeated `[Manager] CPUAffinity=` are merged, as systemd
      does (an empty one resets): the expectation was the last one alone,
      narrower. The agent unit's own `CPUAffinity=` (an operator pinning
      the EDR to housekeeping CPUs) is what it should run on when every
      file that sets it is in the agent's unit directories and older than
      the install; set later, or in a host-wide drop-in, it stays a
      confinement (the drop-in judge's assumption on ctime).
    - Every state read (`read_state`, the watch's sources) opens
      non-blocking, takes a regular file only and reads at most a bound
      (16 MiB; the watch's sources 4 MiB): a FIFO or `/dev/zero` bound over
      one no longer stalls the round or exhausts the agent.
    - **A read that does not answer no longer stalls the round (its
      re-check, F7).** `O_NONBLOCK` does not reach a FUSE file: a regular
      FUSE file bound over `/proc/sys/kernel/tainted`, `/proc/1/stat`, a
      loader's `/proc` files or a file the CPU watch reads at its start
      stalled the whole kernel-state round (the cross-view, the taint
      read, the CPU watch, the held set's prune). Those reads now wait at
      most 2 s for their answer (a helper thread; at most four left
      blocked, then each such read fails at once): the round goes on, and
      a round with such a read is one the CPU watch cannot judge — three
      in a row are the signed `cpu_confined` "could not judge" record,
      naming the read.
    - Still open: another sysfs or procfs file bound over the online file
      BEFORE the agent starts passes the magic check (the union keeps it
      from narrowing unless both sources are faked); a FUSE regular file
      bound over a file the round reads costs each round its 2 s deadline
      (reads outside that round are not timed); a slice's `cpuset.cpus`
      written inside a window narrows the expectation; `CPUAffinity=numa` is not read;
      three rounds of real hotplug in a row give the "could not judge"
      record (true: the watch could not judge).
  - Not watched: the watchdog's CPUs (the agent's own threads only).
- **A program loaded in a window cannot be taken after it (6.9 and
  later).** A program the BPF content judge refuses outside a window (a
  tracing program calling `bpf_send_signal`, `bpf_probe_write_user`,
  `bpf_override_return`; from 6.13 any program calling
  `bpf_send_signal_task`) loaded INSIDE a trusted-installer window was, on
  6.9 and later, free for any root process to take by id or through its pin
  once the window closed — and to attach or run (a `syscall` program
  signalled the agent past its `task_kill` hook). Its handles after the
  window are refused now (`EPERM`, signed `bpf_prog_type`, the call named),
  as before 6.9.
  - **Nor run or attached after it, through any descriptor (every
    kernel; the review of #558).** The loader's own descriptor, kept from
    inside the window (or passed over a socket, or taken by another root
    process with `pidfd_getfd`), ran or attached the program after the
    window with no refusal and no record: `BPF_PROG_RUN` of a `syscall`
    program calling `bpf_send_signal_task` (6.13+), a kprobe calling
    `bpf_send_signal` attached by a perf event's `PERF_EVENT_IOC_SET_BPF`
    (silent) or by `BPF_LINK_CREATE` (Medium only), on every kernel. The
    program, not the descriptor, is judged now: every `BPF_PROG_RUN`,
    `BPF_PROG_ATTACH`, `BPF_LINK_CREATE`, `BPF_LINK_UPDATE`,
    `BPF_RAW_TRACEPOINT_OPEN`, `PERF_EVENT_IOC_SET_BPF` and prog-array
    update (a tail call's slot) of a held program outside a window, by a
    process outside the agent's family, is refused (`EPERM`) and signed
    (`bpf_held_use`, High, naming the use and the program id).
  - **The window's load itself is signed** (`bpf_held_load`, High, not
    refused, naming the call and the program id), on every kernel, so it
    is never silent — even where it is used in a way no hook sees.
  - **A tail call's slot fails closed (its re-check, N1).** A prog array's
    update was judged on its value read the way a user pointer is read,
    and let through when that read failed: a value in a page not yet in
    memory (the kernel's own copy, after the check, brings it in) or the
    kernel pointer a `syscall` program's own update passes
    (`bpf_sys_bpf`). A held program then went into a slot, and a clean
    program's run jumped into it with no record. The kernel's read is
    tried next now, and a value neither read gives is refused (`EPERM`,
    `bpf_held_use` High, "a value not read", the prog array's map id). A
    tool that updates a prog array from a value neither read can see is
    refused and signed. The refusal comes before the kernel's copy, so
    nothing faults the page in: the same retry is refused again until
    the tool touches that page itself.
  - **Still loaded after the window: signed (its re-check, item 2).**
    Once no window is open, the kernel-state round signs each held
    program still loaded — attached by a link or an attach made inside
    the window, pinned, or kept by a descriptor — as `bpf_held_load`
    High, "still loaded after the window closed", naming the program,
    its call and where it is attached; once per program and per agent
    start (an agent restart signs it again).
  - **What stays open:** what was attached INSIDE the window keeps running
    after it (a link, pinned or not; a perf event; a prog array filled
    then; an iterator link read later with `cat`), and an XDP or tc program
    attached over netlink (`ip link`, `tc`: no `bpf(2)` command; 6.13+
    only, where such a program can call `bpf_send_signal_task`). A
    descriptor swapped by another thread (`dup2`) between the hook's read
    and the kernel's, or a prog array's value rewritten in that gap, can
    win a race. Each attempt that loses the race is refused and signed,
    but a stall (userfaultfd or FUSE on the prog array's key copy, or on
    perf's context lock for `SET_BPF`) can make the race deterministic,
    and the winning attempt leaves no record at its use (re-check 2 of
    #558, N4): the load's High and the "still loaded after the window"
    High are then the only records. Check
    `bpftool link` and `bpftool prog` for the ids a `bpf_held_load` names.
  - **Held across an agent restart, emptied as programs go.** The held set
    (`PROG_CONTENT_HELD`, 1024 ids) is pinned now: a restart keeps it. Each
    kernel-state round removes the ids no longer loaded. When it is full,
    a window's forbidden load is refused (`bpf_held_use`, "held set full":
    fail closed) instead of being kept nowhere.
  - **A program loaded before the agent started** is signed High at the
    agent's start when its type is one the agent refuses outside a window
    (the cross-view's baseline, `bpf_baseline`, naming its id, name, tag and
    attach point); before 6.9 its handles are judged and refused like any,
    from 6.9 they are not, nor (on any kernel) the runs and attaches of the
    descriptor its loader kept: its content cannot be read without the
    calibration the older kernels need, and a dump of it
    (`BPF_OBJ_GET_INFO_BY_FD`) has its calls blanked for a reader without
    `CAP_SYSLOG`, which the agent's unit does not grant. Remove such a
    program, or reboot, before you trust the host.
- **A copy of `/etc` over `/etc` is signed, as before.** Mounted after the
  agent loaded its key, it is `integrity_drift` `mount_over_protected` in
  the audit chain within one integrity round (30 s), naming the mount and
  each protected path it hides (measured on Ubuntu 24.04 and 26.04). No
  hook refuses the mount.
- **`--build-features` names the linked crates' test features.** A binary
  whose nn-core or nn-linux was built with `test-util` (a `cargo test`
  build: their test doors) prints `nn-core/test-util,nn-linux/test-util`
  beside the agent's own lab features; a release build prints `none` as
  before, and release.yml refuses any artefact that does not.
  - **Its limits (the review of #558, F8, named).** The ratchet's `--cfg`
    scan reads release.yml and `.cargo/config.toml` only — not a legacy
    `.cargo/config`, a `RUSTFLAGS` set by xtask, a script writing
    `$GITHUB_ENV`, nor a `build.rs` printing `cargo::rustc-cfg`. The
    backstop is `--build-features` on the artefact, which sees any of them
    for nn-core's and nn-linux's `test-util` in the agent binary only: the
    watchdog and nn-admin are not asked, and no symbol check is made (Phase
    1 checks the shipped binaries). Its name filter for third-party test
    features (`test`, `debug`, `demo`, `mock`, `fake`) fails closed on a
    harmless name (`debugger_visualizer`): such a feature is classified by
    hand.
- **Nothing to configure.** No overlay, allowlist or signed policy changes;
  the eBPF object adds two maps: `PROG_CONTENT_HELD`, pinned under the pin
  root (an uninstall removes it with the rest), and
  `PROG_CONTENT_HELD_INFLIGHT`, unpinned. Two new NN-L-AT-001 operations:
  `bpf_held_load` (not refused) and `bpf_held_use` (refused).
- **Residuals, named (the re-check of #558).**
  - **P1, after the alpha: the trusted-installer window is the host's.**
    While it lasts, EVERY root process gets what it lifts — an untrusted
    module, kexec, the protected files, `systemctl stop` of the agent, a
    forbidden BPF load and what it attaches — not only the process tree
    of the `nn-admin trusted-installer-grant` that opened it. Scoping the
    window to the requester's tree is one fix for all of them; until then
    open a window only on a host you trust for its length, and keep it
    short (`--window-secs`).
  - **P2: the `dup2` race.** Another thread's `dup2` of a descriptor
    between the agent's check and the kernel's own read (a few
    microseconds), or a prog array's value rewritten in that gap, can
    win. A lost attempt is refused and signed (`bpf_held_use`); but a
    stall on the copy (userfaultfd or FUSE on the prog array's key, or
    on perf's context lock for `SET_BPF`) makes the race deterministic,
    and the winning use then leaves no record of its own (N4). The load
    and the "still loaded after the window" record are signed High. No
    hook exists that sees the resolved program for every run and attach.
  - **P3: a `struct_ops` map read as a program.** `BPF_LINK_CREATE` with
    attach type `BPF_STRUCT_OPS` and `BPF_LINK_UPDATE` of such a link
    carry a map's descriptor where the agent reads a program's: on 6.8 a
    counted fail-open (with a rate-limited `deny_fail_open` record), on
    7.0 a random id that is never held in practice — noise on hosts with
    sched_ext or a BPF TCP congestion control, never a false refusal.
  - **P3: the CPU watch's sources trusted by filesystem type.** A file of
    the same filesystem bound over the online list and `/proc/stat` (or a
    cgroup2 subtree over `/sys/fs/cgroup`) BEFORE the agent's first round
    passes the check and can narrow what it expects; it needs a boot unit
    or an upgrade, since the agent does not restart outside a window.

## 44. Our own install, boot and uninstall: no High; a purge leaves nothing undeclared (lot 350)

- **rsyslog's log after a fresh install is no truncation.** The agent's
  first baseline read of `/var/log/syslog` (and its own re-hash of each
  record) closes the log, which emits rsyslogd's pending appends — appends
  that read had already measured, so the record read "no growth" and
  NN-L-FIM-005 was High at 4 of 10 fresh installs on Ubuntu. A record whose
  bytes are the very bytes the drain read for the file's previous record,
  with the kernel's record of `O_APPEND` writes by rsyslogd alone, is
  rsyslogd's append now. A truncation by another writer, by rsyslogd itself,
  or a rewrite in place stays High. The drift log is unchanged.
- **`sudo ./deploy/uninstall.sh` at a terminal is Low** (the race is
  closed: 0 High in 15 runs; lot 351's wording: an exec record lost to a
  full ring or the lineage cache's eviction can still leave one High). It
  was High 3 runs in 7: a shell that runs `sudo` as its last command executes
  sudo in place of itself, and sudo's monitor, forked in the same 10 ms
  clock tick, was not known as sudo's. sudo-rs (`/usr/lib/cargo/bin/sudo`,
  Ubuntu 26.04's `sudo`; `/usr/bin/sudo-rs`, `/usr/bin/su-rs`) counts as
  sudo for an administrator's session (R009, the FIM rules' session checks,
  the credential readers). A High R009 now names, in the agent's journal,
  which part of the session check failed.
- **cloud-init's own netcat at boot is Low.** On cloud images with
  cloud-init 24 or later (Debian 13, Ubuntu 26.04), every boot ran `nc -U
  /run/cloud-init/share/<phase>.sock` (cloud-init 25: `nc -Uu -W1 <socket> -s
  <return socket>`) as root: R005 High and the posture
  ENGAGED. That exec — the packaged `nc.openbsd`, on that socket, in the
  cgroup of the cloud-init unit of that phase, forked by the unit's own
  `ExecStart=` shell — is recorded Low and raises no ExploitAttempt. Any
  other netcat is High as before.
- **`uninstall.sh` stops `northnarrow.slice`** (it stayed loaded and active
  until the next boot) and removes the empty `system.control` directories,
  the journal namespace's runtime directory and varlink socket, and, with
  `--purge`, `/var/log/northnarrow`. A `--purge` after an uninstall that
  kept the state no longer fails on hosts with other products' BPF-LSM
  programs (systemd's `RestrictFileSystems=`). What remains after a purge
  (kernel modules loaded on demand, the host's own logs) is listed in
  [`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §3.

## 45. A log shrunk back to its baseline, sudo's askpass helper, the uninstall's leftovers (lot 351)

- **A log truncated back to its baseline's exact content is recorded.**
  The drain dropped a record whose content matched the start's signed
  baseline as a no-op; a `truncate -s <baseline size>` of a log after
  rsyslogd's appends matched it, and the lines written since were erased
  with no drift row and no NN-L-FIM-005. A file read smaller than the drain
  last read it is a change now, whatever the baseline says: a drift row and
  NN-L-FIM-005 (High; a scheduled `copytruncate` of a log whose baseline is
  empty is Low on logrotate's own record). A watched configuration file
  edited in place and then shrunk back to its baseline is recorded too (it
  was dropped). Not seen (P3, below): a growth the drain never read, then a
  truncation back to the baseline's content — after the agent's start, and,
  for a log whose signed baseline is empty, after every rotation.
- **`sudo -A`'s askpass helper is no administrator's session.** The session
  checks (R009, the FIM rules' kill hold, the impair rules' sanction, the
  posture's admin changes) took any descendant of a sudo or su. sudo forks
  the user's `SUDO_ASKPASS` program, as the user, before authenticating: a
  root payload below it (a local privilege escalation) was Low, no kill.
  Only the process sudo or su ran as root after authenticating vouches now
  (its child's first exec since the fork, by the kernel's fork record, as
  root, no PAM helper); what sudo runs as the user, `sudo -u bob` and `su
  bob` vouch for nothing themselves (a sudo further up still covers what
  runs below them: P3, below). `sudo env … ./x` and `sudo bash -c …` keep
  the session (up to three execs in place). A High R009 says in the
  journal "the sudo or su in its lineage (pid N) ran nothing as root after
  authenticating above it".
- **A sudo or su that root ran vouches for nothing** (the review of #560).
  Root runs sudo and su with no credential check: after a local privilege
  escalation, `sudo ~/payload` (sudo executed in place or from a fork, with
  or without an askpass helper) was R009 Low, no kill, and the same pass
  held the FIM rules' kill and the impair sanction. The real uid sudo's or
  su's own exec ran as decides (sudo's monitor: the exec of the sudo it is
  a fork of); the walk goes on to an elevation further up: an
  administrator's `sudo -i` then root's own `sudo -A`, `sudo su -`, `su -`
  then `sudo ./x` stay the administrator's. Root logged in directly (no
  sudo or su above) who runs `sudo ./x` from a home is R009 High now — as
  root's direct session already was. The journal says "the sudo or su in
  its lineage (pid N) was run by a process already root". A sudo session
  older than the agent's start is not held against (its caller cannot be
  read).
- **A sudo or su not executed as the host's binary vouches for nothing**
  (the re-check 1 of #560). The elevation binaries were recognised by
  their path only: after a local privilege escalation, a fake
  `/usr/bin/sudo` in a chroot or a private mount namespace, executed with
  the user's own real uid, forked its payload as root exactly as the host's
  sudo does, and it was R009 Low. The sudo or su that vouches must have its
  image now — executed from a root-only directory, in PID 1's mount
  namespace and with PID 1's root directory (`ROOT_DIR`, as the packaged
  `go` of #555); otherwise it is passed over and the walk goes on. The
  journal says "was not executed from the host's root-only directory in
  PID 1's mount namespace". `ROOT_DIR` itself now also needs PID 1's root:
  a chrooted process gets none (a plain chroot had none in practice
  already; one root built to match did). In tracepoint mode the exec pump's
  read gives sudo its image as before. The operator's `sudo
  ./deploy/uninstall.sh` and `sudo -i` stay Low.
- **This does not close every LPE (P2, residual below).** An escalation
  that keeps real uid 0 and runs sudo is High; one that first sets its real
  uid to a sudoer's whose sudo asks for nothing — a `NOPASSWD` sudoer (the
  default user of cloud images), or any sudoer once root forges sudo's
  timestamp in `/run/sudo/ts` (FIM does not watch it) — and then runs the
  host's sudo still gets the session's cover (R009 Low, the FIM kill hold,
  the impair sanction): sudo authorizes by the real uid, and the agent sees
  an administrator's `sudo payload`.
- **`uninstall.sh` and the agent's containment cgroups.** `blocked.scope`
  and `throttled.scope` under `northnarrow.slice` are removed when empty.
  One holding a process the agent contained is left with it — not killed,
  not released — the processes (pid and command) and the agent's
  containment record printed, and the slice is then not stopped (it goes
  at the next boot). The review of #560: a kill cgroup an agent stopped in
  the middle of a kill left (`blocked.scope/neutralize-*`) is removed when
  empty, and thawed when it holds processes (nothing else would ever thaw
  them; its processes are named, with their real pids, and run again,
  unwatched). An uninstall that leaves such processes names them again at
  the end and **exits 4** (`--package`: 0) — not 0: they are outside any
  unit and no longer confined. Scripts that run `uninstall.sh` and test for
  0 see 4 there.
- **`/etc/systemd/system.control` is removed only when the install made
  it.** A first install records the directories its units are about to
  make in `/etc/northnarrow/made-dirs`; the uninstall removes /etc's empty
  `system.control` only when it is listed (or when no record exists: an
  install older than this one). No action on upgrade: the record is made by
  a first install only.
- **The uninstall removes no mount point in systemd's trees.** The
  directories it removes there (drop-in directories, the journal
  namespace's runtime directory and journals) are left when they are a
  mount point, and their removal does not cross into another file system.

Known residuals of lot 351 (P3 unless marked, named for later lots):

| Residual | Where | What would close it |
|---|---|---|
| **P2 (the re-check 1 of #560, H(a)).** A local privilege escalation that sets its real uid to a sudoer's whose sudo asks for nothing (`NOPASSWD`: a cloud image's default user; or a timestamp root forges in `/run/sudo/ts`, which FIM does not watch), then executes the host's sudo: sudo authorizes by the real uid, forks the payload as root, and the agent sees an administrator's `sudo payload` — R009 Low, the FIM kill hold, the impair sanction | the session check (`is_interactive_admin`) | the real uid stays the same along the walk, from the sudo or su up to the login or authentication hop (a uid change with no elevation hop between is no session) |
| **F (the re-check 1 of #560).** Without the kernel's fork record (`FORK_PARENT_DEGRADED`: an eBPF object or kernel that cannot attach it) no sudo session is an administrator's — fail-closed: an administrator's `sudo ./deploy.sh` from a home is R009 High and killed outside `alpha`, and the FIM kill hold is lost — and the degradation's text does not say so; the fork record is not re-checked on 5.15 or Debian since lot 351 | `FORK_PARENT_DEGRADED` (`nn-linux` multiplexer), the lab | the degradation's text names both effects; a lab round on a 5.15 kernel and on Debian |
| **G (the re-check 1 of #560, hardening).** The start's scan enters a process whose `/proc` shows no uid as real uid 0 (`uid.unwrap_or(0)` in the seed); `ELEVATION_EXES` is `pub`, outside the ratchet that keeps the elevation walk its only reader. No user can cause either, and nothing outside tests reads the constant | `posture::lineage` | a process with no uid read is not entered (or entered as unknown); the constant private to the crate, or named in the ratchet |
| A growth the drain never read, then a truncation back to the baseline's content: after the agent's start (until the first close of the log), and, **for a log whose signed baseline is empty, after every rotation** (`copytruncate`, `create`: the last read is 0 again, a wipe to 0 matches both) | the FIM drain (`TAPPA9_FIM_TRUST_MODEL.md`) | the kernel's size before the setattr in the record (eBPF + wire) |
| A sudo or su further up covers what runs below `su bob` / `sudo -u bob` (an administrator's `sudo -i`, `su bob`, then a root payload of bob's: the administrator's session) | the session check | a hop below that ran as another user as a barrier (a decision of its own) |
| `is_credential_reader` trusts any direct child of an authentication binary — sudo's askpass helper in `/home` or `/tmp` included — for SensitiveFileAccess and the service-uid credential read (reads its DAC already allows, or under an LPE that root's own exclusion already silences) | the posture triggers | only a child whose image is in a root-owned system tree (`in_system_tree`): sshd's login shell keeps it, an askpass helper in a home loses it |
| A sudo session older than the agent's start: its caller is not read (`/proc` shows sudo as root once it has authenticated); an askpass helper root through an LPE at an agent restart, inside sudo's timeout | the session check | needs an agent restart, which a user cannot cause |

## 46. A link's new path, the whole module tree, chains across forks (lot 352)

- **A hard link made to a watched file is judged where it went.** A
  `Linked` detection now names the watched file in `path` and the new link
  in `dest_path`; NN-L-FIM-002 (Critical) fires for a link into /tmp,
  /var/tmp, /dev/shm or /home (and for one deeper than 16 directories,
  whose place is not known). A link elsewhere (a backup tree) is a drift row
  only, as before. Links were dropped as no-op touches: expect `Linked`
  drift rows of watched files you did not see before (`cp -al`, backup
  tools that hard-link a system tree).
- **NN-L-FIM-008 covers every kernel version's module tree, up to 10
  directories below the version directory** (merged `/usr`; 11 with a
  separate `/lib`). A write below `/lib/modules/<version>/` (or
  `/usr/lib/modules/`) is Critical outside a package transaction. A kernel or DKMS package
  install is one Low record per package-manager process (dpkg, its postinst's
  depmod) per 15 minutes; the other writes are counted in the record budget
  as coalesced (`detections_held` audit entries, at most 8 paths kept). An
  administrator's `depmod -a` is Low; a module installed outside a package
  transaction (`make modules_install`, the NVIDIA installer, `vboxconfig`, a
  DKMS build by the dkms service at boot) is one Critical per file: the alpha
  profile records them, it kills nothing. A file moved, hard-linked or
  symlinked into a version directory is not seen (no open).
- **The cross-PID chains follow processes that never executed.** A fork-only
  descendant of a process holding a precursor (a credential-store read, a
  /tmp exec, a canary trip) now completes NN-L-CHAIN-004/005/006/008 as an
  exec'd one did: a Python `os.fork()` worker, a subshell's command, a
  double-forked daemon. Expect these chains where a parent reads a watched
  credential store and its forked workers connect out. A read or a canary
  trip counts for the process that made it (the re-check of #561): a later
  holder of an exited process's pid lends that process's descendants
  nothing. FIM events and canary trips in the agent's event records carry
  the process's start when the kernel said it (`modifier_start`,
  `accessor_start_ns`, nanoseconds of `CLOCK_MONOTONIC`; absent when 0).
- **Wire.** The fork record map grew to 32 bytes an entry (65,536 entries,
  about 1 MiB more kernel memory); the exec record grew 16 bytes, the TCP
  connect record 24. The eBPF object and the agent are rebuilt together.

## 47. A FUSE over `/proc`, `/sys` or the cgroup root does not stall the agent's critical loops; stuck restarts are named and a loop is signed (lot 353)

What this lot covers, and what it does not (mounts over the agent's own
directories: lot 357, §51, which closes them), is stated exactly at the
end of §47.1.

The pre-alpha's Phase 3 (case X6): root mounted a FUSE file system over
`/sys/fs/cgroup` that never answered the agent's threads. The integrity
round's read of the agent's own `memory.max` and the kernel-state round's
open of the cgroup root waited in the kernel — on the runtime's worker
threads, with every thread that looked up the same names behind them — and
the admin socket stopped answering the watchdog. Its stuck recovery
(SIGINT, SIGKILL after 5 s) restarted an agent that had recorded nothing,
and the signed log showed a clean `agent_stop` `sigint`.

- **The kernel's views are read beneath the roots the agent's start
  anchored.** `/proc`, `/sys` and the cgroup2 root are opened once, at the
  start, and checked to be the kernel's own file systems
  (`antitamper_bpf::kernel_roots`); every read of them — the shared state
  readers, the mount table, the process table, the integrity and kernel-
  state rounds, the cgroup floors and guards, the responses' cgroups — is
  opened beneath those roots, crossing no mount (`openat2`,
  `RESOLVE_NO_XDEV`). A mount laid over a view since is not walked: the
  agent keeps reading the real files. A path that crosses a mount below a
  view is read only when that mount is one of the kernel's file systems
  (securityfs, tracefs, binfmt_misc, a cgroup v1 controller…), within a
  2-second deadline; **a FUSE, a tmpfs or a disk's file system mounted below
  `/proc` or `/sys` is refused** (the read fails: "not the kernel's").
  Nothing is crossed below the cgroup2 root.
- **A view already covered when the agent starts is not read** (a restart
  under the mount): its reads fail at once, naming why, and the start signs
  a `kernel_views` degradation.
- **The integrity and kernel-state rounds run off the runtime's worker
  threads**: a read that blocks never holds the admin socket's tasks.
- **A mount over the kernel's views is signed High.** `mount_over_protected`
  now also covers a mount at `/proc`, `/sys` or `/sys/fs/cgroup` of another
  file system than theirs, and a mount below `/proc` or `/sys` of a file
  system not the kernel's; the detail names the mount, its file system and
  its source. **Every `mount_over_protected` row carries `"severity":
  "high"`** (the R003 bind over `/etc` included). A host that mounts its own
  non-kernel file system below `/proc` or `/sys` in PID 1's namespace (none
  of the supported distributions does; containers' masks are in their own
  namespaces) now has this row.
- **The watchdog's stuck recovery names its cause.** Before its SIGINT it
  records which ping failed, how many in a row and for how long
  (`stuck_unresponsive`, signed by the agent at its next round) and leaves a
  marker (`/run/northnarrow/watchdog.stuck`) the agent reads at that SIGINT:
  the stop is `stuck_unresponsive` — its `agent_stop` row, its heartbeat
  stop beat, a non-zero exit — and `heartbeat watch` says `DEGRADED`,
  naming the stuck recovery. An operator's SIGINT is still a clean `sigint`.
- **A restart loop is signed High.** Three stuck recoveries within 10
  minutes are `agent_restart_loop` (High), a degradation in `nn-admin
  status`, and `DEGRADED: … (a restart loop)` in the watchdog unit's status.
- **A stuck recovery that fails is signed High** (`stuck_recovery_failed`,
  once per stuck signal — at most one a minute — and the unit's status says
  `DEGRADED` meanwhile; the watchdog holds no key, the next agent signs it).
- **The watchdog aborts a FUSE holding the agent.** When the stuck
  recovery's SIGKILL cannot end the agent (a thread of it waiting,
  uninterruptibly, on a FUSE request its daemon never answers — 6.12), the
  watchdog aborts that FUSE connection (`/sys/fs/fuse/connections/<id>/abort`)
  and records `fuse_aborted` (High: the mount, its source, the connection,
  the outcome): only a FUSE mounted over `/proc`, `/sys` (the cgroup tree)
  or the agent's own directories (at or above them, never `/`), in the
  agent's or PID 1's mount table, whose connection has requests waiting —
  never a user's FUSE elsewhere. Self-protection: enforced under every
  profile, `alpha` included.
- **The agent counts its CPUs without walking the cgroup tree**
  (`kernel_roots::available_parallelism`: the runtime's workers, the audit
  log's parallel check): std's count reads the cgroup's `cpu.max` by path.
  A mount's root (the open sensor's and the exec quarantine's mount rounds)
  is read beneath the views and from the kernel's cache, never asking a FUSE
  mounted over its point.

### 47.1 The review of #563: no `/proc` on the signing path, every view read routed

- **A signed record never walks `/proc`.** The signed logs (the audit log,
  the rotating chains — heartbeat, detections, actions, netflow… — the flat
  chains, the COMBAT compatibility log, a refused start's fallback chain)
  were opened at every append through `/proc/self/fd/<dir>/<name>`: a FUSE
  over `/proc` held every signed append and the audit log's lock with it
  (the High record of that very mount was never written; detections, admin
  handlers and decisions then waited on the lock), and a tmpfs over `/proc`
  made every signed record fail with `ENOENT`, silently. The directory
  descriptors are kept as before (review entry 44) and every file
  operation of a writer — the append, the fsync's open, the tail read
  again, a rotation's create, rename (`renameat2`), listing and eviction
  (`unlinkat`), the manifest's, the heads store's — resolves its name
  beneath them (`openat2`, `RESOLVE_BENEATH | RESOLVE_NO_XDEV |
  RESOLVE_NO_MAGICLINKS`): no `/proc`, no path walked from `/`, no mount
  crossed (a mount over the log file itself fails `EXDEV` at once, never
  asked anything). No lock is held across an operation a mount can stall.
  The paths in the logs' errors are the logs' own names again.
- **A signing failure is never silent.** A signed log whose appends fail is
  a degradation (`signed_log: <file>: appends fail: <error>`, in `nn-admin
  status` and the trust level; signed when a chain takes rows again, never
  dropped), an ERROR in the journal, and the watchdog's: the `LoopProgress`
  reply carries how long the oldest failure has lasted (`unsigned_ms`, an
  appended field; an older agent's reply reads as 0), and the watchdog
  records `signed_records_failed` (High) in its hold once per episode
  lasting 30 s at a ping, with an ERROR of its own.
- **Every read of `/proc` and `/sys` the ratchet sees is routed** (the
  ratchet no longer missed them; re-check 1 found two walks it did not see,
  below): the known-program judgement's process walk and link
  descriptors, the admin socket's re-bind chmod (WDG-007), the quarantine's
  restore and its listed-shells read and its emptying, the kill response's
  descendant walk (the `procfs` crate is gone from the product code), the
  copy-on-write guard's writer judgement, the ring-drop and package checks,
  the systemd executor scans (the user managers' and PID 1's descriptors),
  the module tool's thread scan and environment, the exec checks' images
  (`/proc/<pid>/exe`) and environments (`/proc/<pid>/environ`), the mount
  table's watch and the open sensor's check that a mount point still shows
  its root (`metadata` of `/proc` asked the FUSE over it), the agent's own
  image (`std::env::current_exe`, which the telemetry probe's round asked on
  a runtime worker), the debug `/proc/<pid>/mem` probe — all beneath the
  anchored roots. The ratchet
  (`xtask/tests/kernel_views.rs`) follows a path under a view through a
  function's locals and through the parameters a call in the same file
  hands it, whatever they are named, and refuses std's `current_exe`, the
  `procfs` crate, aya's CPU counts and BTF read, and a per-CPU map's
  `get`/`set`/`iter`. aya's per-thread
  CPU count (`/sys/devices/system/cpu/possible`, read by path on every fresh
  thread a per-CPU map was read from — the samplers on the runtime, a
  `block_in_place` hands the core to a fresh thread) is not used: the
  per-CPU maps are read and written by `antitamper_bpf::per_cpu`, the CPU
  count read once at the start beneath the `/sys` root. The kernel's BTF
  (`/sys/kernel/btf/vmlinux`, 13 loaders) is read beneath the `/sys` root
  too: a start under a FUSE over `/sys` fails its BTF at once instead of
  waiting with no deadline.
- **A mount stacked or bound over a view's own point is recorded and
  refused.** At `/proc`, `/sys` and `/sys/fs/cgroup`, a file system stacked
  over the one mounted there (a tmpfs over the cgroup2 root, another proc
  over `/proc`) and a directory of a file system bound over the point (a
  cgroup2 subtree over the hierarchy's root, `/proc/sys` over `/proc`) are
  `mount_over_protected` (High) at every round; a bind of the view onto
  itself is the view. At the start the same mounts are not anchored, and
  **a tmpfs at `/sys/fs/cgroup` with no cgroup2 below it on a host whose
  processes are in the cgroup2 hierarchy alone** (`/proc/self/cgroup` names
  no v1 hierarchy: the kernel's word, whatever is mounted) is refused —
  never taken for a cgroup v1 host: the cgroup tree is not read, the start
  signs a `kernel_views` degradation, and every round signs the refusal as
  a `mount_over_protected` (High). A hybrid host's tmpfs (with `unified`
  below it, or v1 controllers in `/proc/self/cgroup`) is still the host's.
- **WSL2's `binfmt_misc/status` tmpfs is not a mount over a view.** WSL's
  init lays a tmpfs (source root `/wsl/…`) over
  `/proc/sys/fs/binfmt_misc/status`, below the binfmt_misc mounted there, at
  every boot: in PID 1's table that one mount is the platform's — by its
  type, its point, its parent and its source, never a path allowed whatever
  is mounted there. A tmpfs or a FUSE over `/proc` or `/sys` themselves, or
  another mount at that point, still fires.
- **The watchdog's records are never dropped** (point 5). The watchdog
  holds no key (DEP-004): `stuck_unresponsive`, `stuck_recovery_failed`,
  `agent_restart_loop`, `fuse_aborted`, `signed_records_failed` are written
  unsigned to `/run/northnarrow/watchdog.hold` and **signed by the next
  agent's integrity round** — once the hold file is taken (renamed to
  `watchdog.hold.taken`: a record the watchdog writes meanwhile goes to a
  fresh file), it is removed only when every one of its records is signed;
  a round whose appends fail keeps it, and the next signs it (a finding
  whose record failed is not remembered as reported). With the signed path
  free of `/proc`, the agent that follows a FUSE or a tmpfs over `/proc`
  signs them. `stuck_unresponsive` is named, not High (its stop is
  `DEGRADED` for the verifier); the other four are High. Hiding them takes
  writing to `/run/northnarrow`.
- **The FUSE abort reads the mount again just before it** (F6): the
  connection's id is the mount's anonymous minor, which the kernel gives the
  next FUSE once this one is gone; a FUSE no longer at its point on that
  connection in the mount tables read again is not aborted. Left: the
  moments between that read and the abort's write.

- **The open sensor's rule refresh never walks the `/proc` or `/sys`
  mounted now, and never runs on the runtime** (re-check 1 of #563). The
  mass-write carve-outs `/proc/` and `/sys/` — and any carve-out or daemon
  directory under a view — are placed beneath the roots the start anchored
  (`kernel_roots::walk_root`: the walk starts at the view's root and
  crosses no mount below it): they key the kernel's own `/proc` and `/sys`,
  never a file system mounted over them since (a write there is counted).
  The refresh, every minute, runs on a thread of its own, and its build of
  the rules from the host runs on a helper thread waited for at most 10 s.
  A build that does not answer (a mount on a home, `/run/user` or a
  daemon's directory that does not answer) is a refresh not judged: the
  rules last written stay in force, and a degradation `open_sensor_rules`
  stands (in `nn-admin status`, signed) until a build answers again; while
  one build is held, the next is not judged at once. The start's build is
  bounded the same way: one that does not answer keeps `sys_enter_openat`
  for the run (every open reaches userland). This was the one `FUSE_STATX`
  of the `/proc` root the lab measured about 30 s after the mount, whose
  caller round 1 did not find: on a host with one runtime worker (the
  workers follow the CPUs: a 1-vCPU host) it stopped the whole runtime —
  the status, the admin socket — and the watchdog's stuck recovery
  restarted the agent under the mount.
- **The other periodic tasks that walk a path by path run off the
  runtime's workers:** the BPF link self-check (every 10 s, the pins under
  `/sys/fs/bpf`), the telemetry probe's round (its probe file, its view of
  the links, the deny self-test's targets), the trusted-installer window's
  close, the `systemd-shutdown` identity refresh, the program images'
  refresh (the system's bin directories) and the watchdog exemption's
  refresh (its pidfile, its binary, the pins): a mount there that does not
  answer holds that task's thread, never a worker the status answers on.
  The admin socket's watch looks at its path on a helper thread with a 2 s
  deadline (the look runs in the socket's own serve loop): a look that does
  not answer is logged, and nothing is bound again.
- **The canary's writer** opens PID 1's root (`/proc/1/root`) beneath the
  anchored `/proc` root, the magic link followed as the kernel resolves it:
  a canary's deploy no longer walks the `/proc` mounted now. The tracepoint
  offsets' tracefs reads (the `format` files, the roots' file system type)
  open beneath the anchored `/sys` root, tracefs crossed within the
  deadline.
- **WSL2's exemption holds on WSL's kernel only** (its release, `uname`,
  names Microsoft). On any other kernel a tmpfs whose source root is named
  `/wsl/…` over `binfmt_misc`'s `status` is a `mount_over_protected`
  (High), as any other mount there.
- **The ratchet** (`xtask/tests/kernel_views.rs`) also refuses: a walk
  that starts at `/` by path outside `kernel_roots` (an open of `/` to walk
  from: the refresh's shape); an `*at` call (`openat`, `fstatat`, `statx`…)
  whose path names a view, whatever its directory, and any call whose
  directory is `AT_FDCWD` (a closure or a helper around `openat`); a
  constant or static that holds a view path, over several lines (a slice of
  prefixes), and the items a `for` loop or a closure binds from one; a
  function that builds and returns a view path, by its module path in the
  other files; a parameter another file's call hands a view literal or
  constant (`module::function(…)`). It fails on the four shapes the re-check
  planted. Re-check 2 of #563: it also follows a struct field a function
  sets to a view path (`Self { root: "/proc".into() }`, or a constructor's
  parameter), an exec of a view path (`Command::new`, `execv*`), a helper
  imported and called bare, the closure a function calls with a view path
  (`on_host_path`'s op, and through a trait's impl that hands it on), a
  callable returning one handed by name (`&host_view`), and a function
  returning what a view-returning one returns; and it scans the functions
  whose signature holds an array type (`[u8; 32]`), which it skipped. It is
  lexical: a path that reaches a by-path call through a `Vec` filled by
  `push` is not followed.

Measured (the lab, debian13, 6.12, one vCPU: the agent's runtime with one
worker): round r2b (this round's tree): `nproc` 1; a FUSE over `/proc` that
never answers the agent (`EIO` to others), 180 s, laid in PID 1's namespace.
No agent thread sent it a request (`stalled=0`, 0 threads); `nn-admin
status` answered at 15/45/75/105/135/165/178 s, no ping failed, the same
pid, no restart; the rule refresh ran under the mount (one `rules
refreshed`, none unjudged); the signed chains took rows (audit +11,
heartbeat +7), no signing error; `mount_over_protected` (High) signed during
the mount and cleared after it. The deny self-test's step that opens a
target's `/proc/<pid>/mem` (the probe's child, by path) failed under the
FUSE and was signed as a `deny_selftest` degradation, as a step that cannot
judge is.

Not done here (recorded): the flat chains' tail read after a failed write (`heal`) reads the
file by its path (a mount over the directory meanwhile makes the next row's
link a visible break, never a lost row); aya's loader reads the CPU count
by path for a perf-event array at load (none in our object); a bind of a
kernel file system below a view (`/proc/1` over `/proc/<pid>`, F5) passes
the record and the read (pre-existing); `waiting` counts every process's
requests, not only the agent's; an `nn-kview-open` thread stuck in a FUSE
`STATFS` at a start under the mount keeps the agent from exiting at a later
stop; a rotation's lift of the state directory's `+i` opens the directory
by its path (a FUSE over the agent's own directories: refused since lot
357, §51; the watchdog's abort comes only after a failed SIGKILL).

Re-check 2 of #563 (fix round 3) — what re-check 1 recorded, and what the
second re-check found, systematically: a census of every `/proc`, `/sys`
and own-directory path of the agent, the watchdog, nn-linux, nn-core and
the start, by thread, and every by-path use on a thread whose stall stops
the detection, the status or the signing that the census found moved off
it or beneath the anchored roots (re-check 3 found three by-path steps in
our own directories it missed, and two stay on the decision thread: the
end of this section):
- **The decision thread never opens `/proc/<pid>/exe` by path**: a rule's
  `exe … sha256` exemption opens the image beneath the anchored `/proc`
  root (the magic link followed). The account database (`passwd`,
  `login.defs`, the host's view) is read beneath it too, its stamps looked
  at once a second on a helper with a 200 ms deadline: unanswered, the
  table read last answers.
- **No ransomware burst is judged with its I/O on the decision thread.**
  The entropy sampler and the copy check read the host's view (`/proc/1/root`)
  beneath the anchored `/proc` root; a burst the dispatcher of slow work
  cannot take — its queue full, its thread held on one preparation past
  10 s, or not running — and the bursts queued behind a held preparation
  are judged on the decision thread **without** their I/O: no file sampled,
  no package asked (the writer is not trusted by a package), counted
  (`unprepared`). Until then, past 256 bursts the decision thread sampled
  the files itself, and a mount that did not answer held it. While the
  thread is held, the degradation `ransomware_slow_work` stands (in
  `nn-admin status`, signed at the next flush), withdrawn when its
  preparation answers.
- **The admin socket's whole check runs off the serve loop**: the look at
  its path and, for a socket taken away, the clear, the parent, the bind and
  the mode run on a helper thread (one at a time); the serve loop starts a
  check every 10 s and takes its answer when it comes, serving the listener
  it has meanwhile. Only the look was bounded: a FUSE over
  `/run/northnarrow` that answered it ("removed") and held the next lookup
  of the same name held the serve loop and its worker — on one worker the
  whole runtime. The start's bind is bounded the same way (5 s; past it the
  serve loop does not start, an ERROR and a signed record).
- **The watchdog reaches the agent and writes its records off its loop**:
  the admin socket's connect on a helper thread within the ping's timeout,
  its hold and shutdown-marker records on a helper within 2 s, one
  unanswered step at most per path (the next fails at once, a ping
  failure): a mount over `/run/northnarrow` that does not answer no longer
  holds the ping or those records. It still holds the watchdog's other
  by-path steps there (the stuck marker's removal, the respawn's reads:
  below). Its FUSE abort runs only when the stuck recovery's SIGKILL failed.
- **No exec walks a view**: a worker is executed by its image's descriptor
  (`execveat(fd, "", …, AT_EMPTY_PATH)` in the child, argv and environment
  made before the fork; the exec sensor names it `/dev/fd/<n>`, which R004
  knows as the core's own launch); the start's deny self-test and the move
  guard's test execute the path `/proc/self/exe` names (read beneath the
  anchored root). The telemetry probe's child is spawned off the runtime's
  worker (its exec resolves the image by path).
- **The responses that change a host file reach it beneath the anchored
  `/proc` root** (the quarantine's opens and checks, a file capability's
  removal through the opened file, the share's subuid read), and **the
  copy-on-write journal** (its directories, index, objects and evidence:
  the guard's fanotify thread, whose stall left the guarded scopes' opens
  waiting) through `kernel_roots` or its own descriptors.
- **The systemd watch asks one question at a time**: while one is held
  (a mount over `/run/systemd` that does not answer the connect), the next
  is `None` at once and starts no thread — it leaked one blocking thread per
  question, and a full pool left every `off_the_runtime` waiting.
- Measured by a test (`fuse_stall_tests`): in a user and mount namespace,
  a FUSE over `/proc` and one over the admin socket's directory, each
  answering the first lookup and holding the rest, the runtime on one
  worker: the serve loop (STATUS through a second name of the socket, past
  its check), the decision's process facts, the signed appends, the rule
  refresh and the entropy sampler each keep going for 14 s. In CI too since
  re-check 3: the CI test job enables unprivileged user namespaces, and
  under CI a namespace test that cannot run fails instead of skipping
  (`nn_linux::fuse_testing::ran`; `xtask/tests/namespace_tests_in_ci.rs`
  holds every such test to it). At 5da316c1 this test and the watchdog's
  `by_path_bounds` were skipped there and "passed" in 0.00 s.
- Measured (the lab): debian13, 6.12 (our own guest under a lease, clean
  before, purged and powered off after), a cold boot with ONE vCPU (the
  agent's runtime on one worker), round r3b: a FUSE over `/proc` laid in PID
  1's namespace for 180 s that answers the agent's first lookup (`ENOENT`)
  and holds every later request of the agent (`EIO` to others). The agent
  sent it no request at all (answered 0, held 0, 0 threads); `nn-admin
  status` answered at each of 12 samples (15 s to 178 s), no watchdog ping
  failed, the same pid (695), no restart; decisions flowed during the mount
  — an encryptor's copy-then-delete of 60 documents (`NN-L-IMP-001`
  Critical: the entropy sampler read the burst's files beneath the anchored
  root) and a program dropped in `/dev/shm` and run (`R002` High); the
  signed chains took rows (audit +14, heartbeat +7), no signing error;
  `mount_over_protected` (High) signed during the mount and cleared after
  it. As in r2b, the deny self-test's step that opens a target's
  `/proc/<pid>/mem` from the probe's child (another process, by path) failed
  under the FUSE and was signed as a `deny_selftest` degradation.

Re-check 3 of #563 (fix round 4): **what this lot covers, exactly.**

**Covered** (each by a test that runs in CI): a FUSE over `/proc`, `/sys` or
the cgroup2 root — the case X6 — does not stall the agent's critical loops:
the runtime's workers and the admin socket's serve loop, the decision's
process facts, the signed appends, the open sensor's rule refresh, the
entropy sampler (`agent/tests/fuse_stall.rs`); nor the watchdog's ping and
its record appends under a FUSE over `/run/northnarrow`
(`watchdog/tests/by_path_bounds.rs`).

**Not covered by this lot — closed by lot 357 (§51).** A mount over the
agent's own directories (or, for the decision thread, over a system
directory) held these. Lot 357 refuses the mount itself (the mount guard:
a BPF-LSM refusal, in the host's mount namespace, of a mount on, over or
below `/proc`, `/sys`, the cgroup root, the bpffs and the agent's own
directories, binaries and units), and bounds each site below as defence in
depth.
- **The integrity round reads our directories by path before it signs.**
  `/etc/northnarrow` (the overlays, `read_dir`) and
  `/run/northnarrow/watchdog.pid` (the limits) are read by path before the
  round's findings are signed; the watchdog's holds and the rejected
  shutdowns there are taken and removed by path (`rename`, `remove_file`)
  after. A FUSE over either directory (root) holds the round for as long as
  it stays — off the runtime, with no stall watch, silently: nothing is
  signed meanwhile, that mount's own `mount_over_protected` included.
  Closed by lot 357: the mount is refused, and the round's reads, renames
  and removals resolve beneath the directories' anchors (`crate::anchored`:
  `openat2` `RESOLVE_BENEATH | RESOLVE_NO_XDEV`, `renameat2`, `unlinkat`,
  bounded reads).
- **The watchdog's stuck marker and the shutdown marker, by path.** After a
  stuck signal the watchdog removes its marker
  (`/run/northnarrow/watchdog.stuck`) by path, unbounded, on its one
  thread; its respawn checks the shutdown marker (with `admin.pub` and
  `agent_id`) and reads the dead agent's pidfile and argv by path. A FUSE
  over `/run/northnarrow` holds the whole watchdog: no stuck recovery, no
  respawn, no `sd_notify`. The FUSE abort does not come before these: it
  runs only after a **failed** SIGKILL (`recovery_failed`); an agent the
  stuck recovery's SIGKILL ended is respawned through these reads with no
  abort before them. Closed by lot 357: the mount is refused; the stuck
  marker's removal and write, and the shutdown check (marker, `admin.pub`,
  `agent_id`, the honoured list), run on a helper thread waited for at most
  2 s (no answer: a refusal, and a respawn), beneath the run directory
  opened at the watchdog's start. The respawn's pidfile reads stay by path
  (the mount guard covers them).
- **`bpf-foreign` is written by path every round.** The kernel-state round
  writes `/run/northnarrow/bpf-foreign` (`atomic_file::replace`: remove,
  create, rename by path) at the end of every round (5 s), off the runtime:
  a FUSE over `/run/northnarrow` holds the round that signs the taint,
  livepatch, root-cgroup program and foreign BPF findings. Closed by lot
  357: the mount is refused, and the file is replaced beneath the run
  directory's anchor (`anchored::replace_file`).
- **`trusted_exe` and `ran_host_file`, on the decision thread.** A rule's
  `exe … sha256` exemption checks the image's path and its parents by path
  in the agent's mount namespace; the lineage's `ran_host_file`
  (FIM-005/-019 with `logrotate` only) reads a packaged program's file at
  its path. A FUSE over a system directory (root) holds the decision there.
  Closed by lot 357 on a bounded reader, as the account database's (not by
  the mount refusal: covering `/usr/sbin`, `/usr/lib` and every directory a
  packaged program lives in would refuse too much): the image's checks and
  digest wait at most 500 ms (unanswered: not trusted, the exemption does
  not hold for that event), a host file's identity at most 200 ms
  (unanswered: not the host's file).
- **The ratchet's bypasses.** `xtask/tests/kernel_views.rs` is lexical and
  does not see: a helper returning a view path as `&'static str` (or
  `CStr`, `OsStr`); `std::fs` or one of its functions imported under
  another name (`use std::fs as disk`, `use std::fs::read as slurp`);
  libc's `*64` calls (`open64`); a `String` built from `"/proc/"` and read
  in another file. `decision_path_io` does not scan nn-linux's decision
  hosts (`decision_host_linux.rs`, `accounts.rs`, `canary_host_linux.rs`). A
  by-path read of a view written in one of these shapes passes both.
  Closed by lot 357's mount refusal: no mount over or below a view is left
  to hold such a read (the ratchet's shapes stay a named residual).

### 47.2 Fix round 5 of #563: the decision thread's reads, the bpffs's view

- **The decision thread reads the kernel's views under its own filter.**
  Its seccomp filter refuses `openat2` whatever it asks (R14c-1: a filter
  cannot read the call's flags), and every read beneath the anchored roots
  failed there with `EPERM`: the process facts of a rule's exemptions (a
  process's uid, its cgroup, its executable and that image's digest) were
  never read — no exemption by executable matched, and a debugger's attach
  or a `process_vm_writev` into an exempt process tainted its mark but was
  never signed (`EXEMPTION REVOKED`). Where `openat2` is refused (`EPERM`)
  or missing (`ENOSYS`), `kernel_roots` now walks one name at a time:
  `openat` with `O_PATH | O_NOFOLLOW`, each step's mount read from the
  kernel's cache (`statx`, `AT_STATX_DONT_SYNC`, nothing asked: a FUSE root
  reached is never asked anything) and refused (`EXDEV`) when it is not the
  root's — before any name is looked up in it; a link of names alone
  (procfs's `self`, `thread-self`) followed from its directory, a magic link
  `ELOOP` (resolved from the root, as before), a `..` refused; the file then
  opened through its checked descriptor (`/proc/self/fd/N` beneath the
  anchored `/proc` root). The filter's own rules still judge every open:
  nothing is opened for writing that way (`/proc/<pid>/mem` read-write is
  still `EPERM`). The FUSE harness runs the decision's loop in its role,
  under its filter, with a FUSE below `/proc` over the directory of the
  process it reads.
- **`/sys/fs/bpf` is a view of its own.** The bpffs is a mount below
  `/sys`, which a path beneath the `/sys` root does not cross (`EXDEV`): the
  start-in-cgroup tracker's pin directories beside the pin root
  (`/sys/fs/bpf/northnarrow-cgroup-join-v2_<n>`) are made and removed by
  their parent, the bpffs root, and every one was refused — a planted
  directory there was left (`an old tracker pin directory NOT removed`)
  and never signed as removed, a new generation's plant (the debug build's)
  never made. The start anchors the bpffs on top at `/sys/fs/bpf` (the one
  the pins made by path reach; a second bpffs stacked there is the
  integrity round's `bpffs_mount`); a host with no bpffs there has no such
  view (the agent pins nothing), and another file system over it at the
  start is refused and named with the other views (`kernel_views`).

### 47.3 Re-check 4 of #563: the walk's last open, a link's `..`, an exemption not judged

- **The decision thread's walk opens its file again through its own
  descriptor directory.** Where `openat2` is refused (the decision thread's
  filter), the walk one name at a time checks every name's mount, but the
  file it reached was then opened again by name through `self/fd/N` beneath
  the `/proc` root — a lookup of `<pid>`, then `fd`, with no mount check: a
  tmpfs over `/proc/<agent pid>/fd` gave the decision thread its files for
  every fact (a uid, a cgroup, the `Tgid` the marks are read for), a FUSE
  there held its loop. The reopen goes through the thread's own
  `thread-self/fd` now, every name of the way checked as the walk checks
  them (the directory kept for the thread, opened again in a forked
  child); the entry itself is looked at first (procfs's, nothing mounted
  on it), and the file opened is compared with the one the walk reached —
  the same mount and inode, or the open fails (`EXDEV`). A directory is
  opened again through its own descriptor (`.`), no name looked up. The
  kernel has no reopen of a descriptor without a name. `kernel_roots`'s
  `chmod_fd` and `reopen_fd` (the quarantine, the admin socket, the copy-
  on-write journal) go through the same directory and checks. A cover laid
  over a thread's own `fd` directory fails its reads closed (or sends them
  to the bounded crossing, which reads the kernel's file systems only).
- **A link whose target climbs with `..` is walked beneath the root.**
  sysfs's links (`/sys/class/net/<if> -> ../../devices/…`) were `ELOOP` to
  the walk, then opened with a plain `openat` that crossed whatever was
  mounted on the way: the walk follows a target of names and `..` from the
  link's directory, a `..` going back to the directory it came from, never
  above the root (`EXDEV`), each step's mount checked. A name with a `:` is
  a name off procfs (`pci0000:00`); on procfs it is still a magic link's.
  Beside it: `openat2` beneath a root answers `EAGAIN` for a `..` while any
  rename or mount on the host races the walk — that error was the read's;
  it is tried again, then walked one name at a time.
- **An exemption that could not be judged is signed.** When code is first
  injected into a process (a debugger's attach, a write handle on its
  memory, `process_vm_writev`, `pidfd_getfd`), the agent asks whether an
  exemption of the per-rule policy covered it. A fact it is judged by that
  could not be read while the process is there (a mount laid below
  `/proc/<pid>`, a read that did not answer) made it "none covers it", and
  the injection was a debug line. It is now `Covering::Unjudged`: signed
  as for an exempt process (NN-L-AT-001, Log, High — Critical from a
  non-root injector or one outside an administrator's interactive session),
  the journal's `EXEMPTION UNJUDGED` and the record naming the exemption
  and the file that could not be read. A process gone (no file) is still
  "none".

## 48. The admin protocol's version, the help, the checksums' signature (lot 354)

- **`PROTOCOL_VERSION` is 2.** The admin envelope (`VersionedAdminMessage`)
  carries version 2, and a decoder refuses a version 1 envelope as
  `ProtocolVersionUnsupported` (`OLDEST_PROTOCOL_VERSION`): the formats
  changed since version 1 was set (the status reply grew by appended
  fields), and an old envelope would be misread. From now on a change to a
  frame the tests pin raises the version
  (`a_pinned_frame_changes_only_with_a_new_protocol_version`, and
  `xtask/tests/protocol_history.rs` for a row edited in place).
  - **No effect at run time today.** The live admin socket speaks bare
    frames, as before: no running peer sends or reads the envelope, so the
    agent, the watchdog and `nn-admin` exchange exactly what they did.
  - **An older `nn-admin` against a newer agent** gets no version message.
    A reply that grew by appended fields is read without them (the extra
    bytes are ignored); a request or reply one side does not know is a
    protocol error, exit 5 ([`NN_ADMIN.md`](NN_ADMIN.md)). Use the
    `nn-admin` of the agent's release.
  - **The upgrade from rc1 works.** `install.sh --upgrade` opens its window
    with the installed `nn-admin`, against the installed agent (one
    release), and then replaces both binaries together; the packages
    replace `nn-admin` with the agent too. An `nn-admin` kept elsewhere (a
    copy on an administrator's machine) must be updated with them.
- **The help.** `nn-admin`'s commands and options are described for an
  operator (no lot, review or design references), the shared options have
  one help text, and `install.sh --help` lists its package-hook options and
  its exit codes. A script that parsed the help text sees new wording; the
  options, the output of the commands and the exit codes are unchanged.
  `nn-admin` writes no colour when `NO_COLOR` is set (non-empty).
- **`install.sh --upgrade`** names each side's build on its UPGRADE line:
  `installed: northnarrow-agent 0.0.1 (sha256 …) → new: northnarrow-agent
  0.0.1 (build v0.0.1-…, sha256 …)`, and says when the two binaries are the
  same build. The "UPGRADE complete" line carries the new build too.
- **A release's `SHA256SUMS` is signed** (`SHA256SUMS.asc`, the `.rpm`'s
  release key) from the first tag after this change: the check without
  `gh` of [`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §5.
  A tag release without it is not published.
- **`install.sh` checks that signature itself.** With `SHA256SUMS.asc` next
  to `SHA256SUMS`, it verifies it with `gpgv` against the tree's copy of the
  release key and the fingerprint it pins
  (`BBBB EB6F 5566 A1CE 99AE  8379 C66A E018 C172 7C8D`), then reads the
  tarball's checksum from that signed copy. On a host with no attestation
  verifier (Ubuntu 24.04's gh 2.45) the release installs with no flag,
  recorded as `signed-checksums`, a new level in `install-manifest.json`
  (`nn-admin host-check`: OK; with the flag that accepted it: WARN). A bad
  signature, a signature by another key, or a release key missing from the
  tree is refused whatever the flags (`--no-verify` aside). A verifier that
  ran and refused (gh not logged in, no network) is not overruled by the
  signature. *Action:* keep `SHA256SUMS` and `SHA256SUMS.asc` next to the
  tarball; a tester who used `--allow-unverified` after the manual check no
  longer needs it. A tool that reads `provenance` sees the new value.
- **The journal** names an absent optional kernel field's own effect (it
  named the DNS decoder for every field that was not btrfs's, a hook's
  argument or the move guard's).

## 49. An AppImage's program is its image's, not a staging exec in /tmp (lot 355)

- **What changes.** An AppImage (type 2) serves its own image read-only at
  `$TMPDIR/.mount_*` (`/tmp` by default) and runs its programs from there.
  Each was an exec from `/tmp`: R001 High at every launch, then
  NN-L-CHAIN-002 or NN-L-CHAIN-005 Critical ("would have: KillProcessTree")
  as soon as the program, or its zygote's child, connected, and
  NN-L-NET-008 High; the same program run from the home drew none of them.
  The exec pumps now mark such an exec a user's image (`USER_IMAGE`) when
  the kernel's state ties the mount to the image file the user ran:
  - a FUSE filesystem (not `fuseblk`) whose superblock is read-only, mounted
    by the exec's user (`user_id=`), on a mount that is no FUSE mount;
  - entered by the process that had just executed the image file — the
    user's own regular file, outside the staging directories and the system
    trees, still that file at its path — by a path the caller named under
    that mount point;
  - with a daemon of that same image file (device and inode) started since
    the image's exec, neither stopped nor traced (`TracerPid:`), holding
    `/dev/fuse` and the image file itself open (device and inode: a
    runtime's daemon keeps open the file it serves), and no other regular
    file a staged image could be served from (one under a staging
    directory, unlinked, on a memory or FUSE filesystem, or a `memfd`).

  Later execs of the mount's files (`AppRun`'s program, a zygote's
  `/proc/self/exe`, a helper) are the image's while that mount and its
  daemon are there. R001..R003, the chains' staging precursor (CHAIN-002,
  -005, -007), the posture's exec arm, NN-L-NET-008 and the staged-ancestor
  test of the transfer-tool and impair rules judge such a program as the
  image, as from the home (`nn_linux::sensors::app_image`).
- **What stays judged.** An AppImage itself in `/tmp`, `/var/tmp` or
  `/dev/shm`, or the user's legit AppImage made to serve a file staged
  there through the runtime's documented `TARGET_APPIMAGE` variable (its
  daemon holds that file, not its image); another user's; one extracted (`--appimage-extract-and-run`,
  or a host without FUSE: a writable copy in `/tmp`); a writable FUSE
  mount; a squashfs served by another program (`squashfuse` over a
  downloaded file), whatever AppImage runs meanwhile; a mount over another
  FUSE mount; an AppImage installed in a system tree (`/opt`, `/usr`), not
  the user's own file; tracepoint mode. And
  whatever the program then does: a credential read followed by an egress
  is NN-L-CHAIN-001, a file it stages and runs is R001, persistence and a
  shell with a socket are judged as for any user program. A script of the
  image that a system interpreter runs is judged by its path, as before.
- **Residual.** A malicious AppImage the user runs is a user program,
  judged by its behaviour. `/proc` shows no tie of a FUSE mount to the
  process that serves it, so the pump ties the mount through the exec that
  entered it and a daemon of the image started since. No mount namespace
  is needed to swap what is served: a user who stops its own AppImage's
  runtime after the mount, unmounts it, mounts its own read-only squashfs
  there and starts the image again with `--appimage-mount` (a daemon of
  the image, started since), then lets the runtime go on, gets its
  squashfs's programs judged as the image's. So does a runtime made to
  serve a file of the user's home (`TARGET_APPIMAGE` there, with the image
  held as well). Those are programs it could run from its home, which it
  can write: the impact stays the user's own. Every fact is checked on the
  uid (the mount's `user_id`, the image's owner, the daemon's real uid, the
  exec's), no other user inherits the mark, and root's exec from
  `/tmp/.mount_*` is still R009. A kernel record of the process the
  connection's `/dev/fuse` file is handed to would close the swap.
- **Operator action.** None: no setting, no overlay. The records name the
  program's path as before.

## 50. A window's held BPF load is always signed (lot 356)

- **A held load's record spends no budget.** A program the content judge
  refuses outside a trusted-installer window (a kprobe calling
  `bpf_send_signal`, a `syscall` program calling `bpf_send_signal_task`),
  loaded inside one, is held by id and signed `bpf_held_load` (High, lot
  349). Its record went through the kernel's per-CPU budget of the
  non-decisive refusals (`minor_denial_rate`, 50 a second per CPU): a flood
  of refused uses of an earlier held program, of refused handles on the
  agent's maps or of refused reads of its key on that CPU spent it, and the
  load in the same second was held with no record naming it — only the
  anonymous `minor_denial_rate` count (no `TelemetryLoss`). The lab lost it
  1 time in 3 on 6.8; it held on every kernel. Now the record is written
  through no budget, one per held program.
- **No room for the record, no load.** When the agent's denial ring has no
  room for a held load's record, the load is refused (`EPERM`), counted in
  the new ring-drop counter `held_load_unsigned` (signed, not a security
  ring: the load's descriptor was never handed out; the lost reservation is
  counted in `fs_protect`, which is one; the journal's line says
  "REFUSED", not "lost"). Its id stays held: the kernel gives the program
  its id before the hook runs, and a process that took a handle on it by id
  in between keeps it alive — its runs and attaches outside a window are
  refused and signed (`bpf_held_use`), and once the window closes the
  kernel-state round signs it once (`bpf_held_load`, "still loaded after
  the window"); the round releases the id when it is no longer loaded. An
  installer that sees a window load refused with `EPERM` and
  `held_load_unsigned` > 0 in `nn-admin status` met a full ring: retry the
  load. Residual (lot 349's, unchanged): with the held set full (1,024
  ids) there is no room to hold the id, and a handle taken by id in the
  same race keeps the refused program un-held — the load's `bpf_held_use`
  record (held set full) names it, and the cross-view signs it
  `bpf_unseen` once it is in two enumerations (its load was refused before
  the hook recorded it).
- **A sole trace in the agent too.** The held load, its "still loaded after
  the window" record and the kernel-state round's findings (`kernel_taint`,
  `sysctl_root_prog`, `bpf_unseen`, `bpf_baseline`, `cpu_confined`) are the
  only trace of something the agent let through. They are logged and stored
  past NN-L-AT-001's record budget for the uid (a root flood of refusals
  spent it, and the held load's record was a held count naming a process,
  not the program), never coalesced or capped by the event bus, and they
  wait for room in its tamper queue instead of being dropped after 50 ms.
  They take no token of that budget either: a flood of them no longer
  turns root's next decisive refusals into held counts. None changes the
  posture: they stay non-decisive. A held program's refused uses
  (`bpf_held_use`) keep the non-decisive budget — a caller repeats them at
  will, and each is refused whatever its record.
- **The kernel-state round's quota.** Root makes BPF objects at will: tens
  of thousands of tiny programs loaded faster than the agent's seen map
  keeps them come back as one `bpf_unseen` record each. A round (every
  5 s) now signs at most 32 findings of each kind by name and the rest in
  ONE `sole_trace_summary` record (NN-L-AT-001, High; Medium when all are
  the start's baseline) with each kind's count.
  - **The most dangerous first**, by what the object can do: a held
    program (its load called a signal or write helper or kfunc), an
    fmod_ret and a link whose program is hidden; then the types run in the
    kernel or on the host's traffic (kprobe, tracepoint, perf_event,
    fentry/fexit, LSM, struct_ops, ext, syscall, XDP, tc); then every other
    type; socket filters and cgroup_skb last; a proven known system
    program after all. An XDP program loaded among a thousand socket
    filters is named the round it is found.
  - **A held program's records are never under the quota**: its outliving
    (`bpf_held_load` with the use "outlived"), and the program found
    unseen or in the baseline, are each signed by name — the held set
    bounds them (1,024 ids, each once), and the outliving is the only
    record of a held load refused for want of room in the ring.
  - **The summary names objects**: its `comm` gives, per kind held back,
    the count and three objects (id and type) — the highest-ranked held
    back, the first and the last: `bpf_unseen 968
    top=prog:1040:cgroup_sock first=prog:33:socket_filter
    last=prog:1000:socket_filter` (kinds apart by `; `). Its `target_ino`
    bits 0–15 count those carried from an earlier round.
  - **Nothing held back is left unnamed**: what a round holds back is
    carried into the next, first in its rank, until a round names it once
    (at most 1,024 carried, the highest-ranked kept; past that an object is
    counted and listed only). A thousand socket filters are named 32 a
    round, all within 3 minutes.
  - Nothing is dropped silently: the counts are in the signed records and
    in `nn-admin status --key` (`kernel-state quota`, JSON
    `kernel_state_held_back`, each finding counted once), and each BPF
    object held back is listed in `/run/northnarrow/bpf-foreign` with the
    state `suppressed` until a round names it. A host with thousands of BPF
    programs (Cilium, Calico) gets, at the agent's start, 32 `bpf_baseline`
    records a round and one Medium summary a round until each is named,
    instead of thousands of records at once.
- **`PROTOCOL_VERSION` is 3** (§48): the status reply grew by
  `kernel_state_held_back`; a version 2 envelope is refused as unsupported
  (`OLDEST_PROTOCOL_VERSION` 3). No effect at run time today — the live
  admin socket speaks bare frames — and an older `nn-admin` reads the
  newer reply without the field: use the `nn-admin` of the agent's release.
- **No action on upgrade.** The ring-drop counters gain one slot
  (`held_load_unsigned`, slot 31) at the end: readers by name are unchanged.

Audit of the records that were "minor" (lot 356). Each kind left in the
budget is refused whatever its record, or let through by the operator's
signed per-rule policy, or keeps its defence in the kernel's mark:

| Record | Refused? | Can losing it hide an attack on the agent? | Now |
|---|---|---|---|
| `read` (the agent's key), `bpf_handle`, `bpf_prog_type`, `sysctl_root_attach`, `kprobes`, `lockdown`, `sched`, `nice`, `ioprio`, `sysctl`, `sysctl_value`, `sigio` | yes | no: the refusal holds without its record | minor |
| `bpf_held_use` (incl. the held set full, a prog array's slot not read) | yes | no: refused; repeatable at will | minor |
| `bpf_prog_opt_out`, `sysctl_opt_out` | no: the signed per-rule policy lets it through | no: the operator's signed choice; the content judge still refuses a signalling or overriding program; recorded once a second per caller | minor |
| `cgroup_join`, `exempt_injection` | no | no: the kernel's mark already strips the exemption | minor |
| `bpf_held_load` (and its outliving; a held program found unseen or in the baseline) | no | **yes**: the only record of a program that can signal the agent | sole trace, never under the round's quota |
| `kernel_taint`, `sysctl_root_prog`, `bpf_unseen`, `bpf_baseline`, `cpu_confined` | no (found by the kernel-state round) | **yes**: the only record of foreign kernel code, a program the agent never saw, the agent confined | sole trace, 32 a kind a round by name, the most dangerous first; the rest carried to the next rounds |
| `sole_trace_summary` | no (the round's findings past its quota) | **yes**: the only signed count of those findings, naming each kind's highest-ranked, first and last | sole trace, one a round |

## 51. A mount on, over or below the agent's paths is refused (lot 357)

- **What changes.** In PID 1's mount namespace — and in the agent's and the
  watchdog's own (§51.1) — for root (`CAP_SYS_ADMIN` in PID 1's user
  namespace), the agent's kernel hooks now refuse
  (`EPERM`, signed High: NN-L-AT-001, operation `mount`):
  - a mount on or over `/proc`, `/sys`, `/sys/fs/cgroup`, `/sys/fs/bpf`,
    `/etc/northnarrow`, `/var/lib/northnarrow`, `/run/northnarrow`, the
    agent's pin directory, its binaries, its units and their drop-in
    directories, and every directory above them (`/`, `/etc`, `/var`,
    `/var/lib`, `/run`, `/usr`, `/usr/local/bin`…);
  - a mount anywhere below the agent's own directories;
  - a mount below `/proc`, `/sys`, the cgroup root or the bpffs that is not
    one of the kernel's own pseudo-filesystems at its usual point
    (binfmt_misc and systemd's automount for it, nfsd, xenfs, debugfs,
    tracefs, securityfs, configfs, fusectl, pstore, efivarfs, bpffs,
    selinuxfs, smackfs, resctrl, a hybrid host's cgroup hierarchies), and
    any mount inside the tracefs, the debugfs or the securityfs —
    `/proc/<pid>/…` (a tmpfs over `/proc/<agent>/fd` fed the agent false
    facts) and a cgroup directory are never one;
  - an unmount (lazy too) or a move of one of those mounts — the mounts
    themselves, by their id, not a copy of one (§51.1) — and an unmount
    that takes one with it (§51.3: what a lazy unmount takes below the
    mount it names), a move through `mount(2)`'s `MS_MOVE`, `pivot_root`;
  - a remount of the super block of a view or of a file system the agent's
    paths are on, and a bind remount making one of those mounts read-only
    or `noexec` (§51.1).
- **Also from another mount namespace whose change reaches the host's**
  (a raw `unshare(CLONE_NEWNS)` keeps the shared peer groups: a mount there
  is copied into the host's view): judged as in the host's. A container,
  `unshare -m` and a unit's sandbox are private or slaves: untouched.
- **`mount_setattr(2)`** (read-only, propagation) has no kernel hook: not
  refused, signed High (`integrity_drift` `mount_attrs_changed`) within one
  integrity round when it changes a mount that holds the agent's paths. A
  write the agent can no longer make there is already a signed degradation
  (lot 353).
- **What does not change.** Containers, `unshare -m`, systemd's sandboxes
  of its units, snapd's and the container runtimes' mounts elsewhere
  (`/var/lib/docker`, `/snap`, `/run/netns`, `/run/user`…) are not judged;
  nor are propagation changes, PID 1's unmounts, systemd-shutdown's last
  pass (§51.1) or an unprivileged caller's mount (the kernel refuses it).
  The mount watch (`integrity_drift` `mount_over_protected`) stays: it
  signs a mount the guard does not see (one propagated from another
  namespace, one on a kernel without the guard).
- **For you.**
  - To mount, unmount or move one of these on purpose (a maintenance step,
    `systemd-sysext refresh` or `systemd-confext refresh` at run time),
    open a trusted-installer window: inside it the guard lets everything
    through and records what it let through (operation `mount_window`,
    Low).
  - On Ubuntu 22.04 (util-linux 2.37), `mount --move` in the host's
    namespace is refused: `mount(2)` names the moved mount by a string the
    hook cannot resolve. From util-linux 2.39 (Ubuntu 24.04, Debian 13)
    `mount --move` uses `move_mount(2)` and only a protected mount is
    refused.
  - A separate `/var` (or `/usr`) partition: its mount unit cannot unmount
    it at shutdown (refused, the unit is marked failed); systemd-shutdown's
    own pass (PID 1 and the helpers it forks) unmounts or remounts it
    read-only as before.
  - A kernel without the hooks (`sb_mount`, `move_mount`, `sb_umount`,
    `sb_pivotroot`, `sb_remount`) or the offsets they read: the start signs
    `mount guard not attached` (a degradation, not a refused start) and the
    mount watch alone records such mounts.

### 51.1 The review of #567: the mounts themselves, the units' namespaces, remounts

- **The mounts held are mounts (F1).** The guard used to recognise a
  protected mount by its root's dentry, so the unmount of any copy of `/`,
  `/run` or `/sys` was refused. It now holds the mounts the protected paths
  resolve through, by their id, in each namespace it guards. A backup's
  `mount --bind / /mnt/snap`, a chroot's `mount -t proc`, `mount -t sysfs`
  (the host's super block), `mount -t cgroup2` below it, its `--bind /run`
  and `--bind /sys`, and their teardown (debootstrap, pbuilder, schroot,
  arch-chroot, live-build, diskimage-builder) are let through, with no
  record. What is still refused is an unmount the kernel would propagate
  onto a held mount: an `rbind` of `/sys` that was not made `rslave`
  first, unmounted with `umount -R`, takes the host's childless
  `/sys/fs/cgroup` and `/sys/fs/bpf` with it. Make the copy `rslave` (or
  `private`) before unmounting it, as the distributions' guides do.
- **The agent's and the watchdog's own namespaces (F2).** Their units'
  `ProtectSystem=strict` gives each a mount namespace of its own: the one
  they read their paths through. Once the agent holds its role (the BPF
  self-defence's liveness watch), its namespace is judged as PID 1's;
  the watchdog's is, from the agent's watchdog refresh (at most 30 s after
  the watchdog starts). Each is dropped at the process's exit, before the
  kernel can give its number to another namespace. Records name it
  (`made in the agent's own mount namespace`). The integrity round also
  reads both namespaces' mount tables, besides PID 1's.
- **Remounts (F3).** A reconfigure of the super block of `/proc`, `/sys`,
  the cgroup root or the bpffs is refused whatever its options (proc's
  `subset=pid`, `hidepid=`); one of a file system the agent's state, run,
  configuration or binaries are on is refused when it makes it read-only —
  `mount -o remount` and `fsconfig(FSCONFIG_CMD_RECONFIGURE)` (util-linux
  2.39 and later) alike, both through the kernel's `sb_remount` hook, the
  new flags read at `reconfigure_super()` by an `fentry` (without it,
  every such reconfigure is refused, signed). A writable one passes:
  Ubuntu's finalrd remounts `/run` `exec` at every shutdown; `size=` of
  `/run` and `commit=` of `/` pass. A bind remount
  (`mount -o remount,bind`) that makes one of the held mounts read-only or
  `noexec` is refused too. util-linux 2.39 and later make a bind remount
  with `mount_setattr(2)`, which has no hook: the integrity round signs it
  (`mount_attrs_changed`, High), and now compares the super block's
  options as well. A state, run or configuration directory found on a
  read-only file system is signed High (`state_fs_read_only`). Exempt: a
  kernel thread (`SysRq-u`'s emergency remount) and systemd-shutdown at the
  end of a shutdown. The emergency path is named, not closed: root can
  trigger it (`echo u > /proc/sysrq-trigger`, the SysRq key with
  `kernel.sysrq` allowing it) and every block-backed file system goes
  read-only, unrefused — `state_fs_read_only` (High) records it; a
  `kernel.sysrq` value that forbids `u` closes it on a host that needs no
  emergency remount.
- **systemd-shutdown (F4).** PID 1 running systemd-shutdown (the kill
  guard's identity: its comm and the file the agent recorded) and the
  helpers it forks (`(sd-umount)`, `(sd-remount)`) unmount, remount
  read-only, move the API mounts and pivot to `/run/initramfs` (dracut)
  unjudged. PID 1 at any other time is judged for a pivot or a move:
  `systemctl soft-reboot` needs a window.
- **Mounts made before the guard attached.** At arming, every mount of
  PID 1's and the agent's namespaces (the watchdog's at its refresh) that
  covers a protected path or a directory above one, or lies below the
  agent's directories or a view, is judged against the canonical layout by
  its type, point and root: a view holds its own type whole, `/` anything
  but a FUSE, a directory above the agent's paths no memory, FUSE or
  stacking file system and no bind of another directory (a subvolume and a
  unit's bind of a directory onto itself are canonical). Each other one is
  a signed degradation of the start and a High of the integrity round's
  first read (`mount_not_canonical`). An ostree host's binds of `/var` and
  a NixOS impermanence host's `/` on tmpfs are named so: known false
  positives. The overlays a host's image tooling merges at boot are the
  canonical layout (§51.2): `systemd-sysext` over `/usr` or `/opt`,
  `systemd-confext` over `/etc`, composefs over `/usr` (an overlay whose
  source is `sysext`, `confext`, `composefs`).
- **The tracefs, debugfs and securityfs the agent reads.** Their unmount is
  let through and recorded Low (`mount_noted`). A clone of a subdirectory
  of the kernel's own type moved onto its canonical point (securityfs'
  `apparmor/` onto `/sys/kernel/security`) is refused.
- **`/usr/local`.** Only the agent's binaries and units that exist are
  points. With the package (`/usr/bin`), an NFS or automounted
  `/usr/local` (an HPC host) is the host's business; with `install.sh`
  (`/usr/local/bin`), a mount over `/usr/local` hides the agent and is
  refused: install the package on such a host.
- **The agent's libraries.** The directories of the shared libraries the
  agent has mapped (`libc`, `libgcc_s`, the loader: `/usr/lib/<triplet>`,
  `/usr/lib64`) are points too: a mount over one would swap what the
  agent's or the watchdog's restart loads.
- **Overlay root.** On an overlay of layers on more than one file system
  (without `xino`), `stat(2)` gives a file the layer's device and the hook
  reads the overlay's: the agent's binaries and units are registered under
  both.
- **Which namespace is judged (the cross-model check).** The namespace
  that owns the target mount, never the caller's: a path through
  `/proc/<pid>/root`, or an `O_PATH` descriptor of one passed to
  `move_mount(2)`, names a mount of another namespace, and is judged there.
  A change made elsewhere is judged when it propagates into a guarded
  namespace: its target mount's peer group is the own group or the
  master's group of a mount there that holds a protected point or is a
  view (`MOUNT_GROUPS`, one look-up), or — a group the map does not hold
  yet (§51.2: a guarded mount regrouped since the last refresh) — its
  peers and each one's slaves, read in the hook up to 16 mounts, include a
  mount of a guarded namespace, or cannot be read whole (more mounts, a
  slave that is itself shared or a master: counted as reaching, and then
  refused only on, over or below a protected point, so a host with many
  containers is not judged wholesale). The groups, the held mounts and
  their super blocks are read again every 30 s (an automounted tracefs, a
  mount a window left) and within a second of a propagation change the
  hooks let through (§51.2).
- **PID 1 (the cross-model check).** Its exemption is an unmount of a mount
  of its own namespace that is not one of the agent's directories. In the
  agent's and the watchdog's namespaces PID 1 and its helpers are judged:
  `systemctl bind northnarrow-agent.service … /run/northnarrow` (and
  `mount-image`) fail at entering the agent's namespace — the ptrace guard
  refuses the open of its `/proc/<pid>/ns/mnt` (a read-mode access), a
  signed Low record (`ptrace_read`) since §51.2 (once an hour per caller
  program and target since §51.3); before it, that refusal left no record —
  and would be refused there.
- **The units' drop-in directories.** `install.sh` and the agent's
  `ExecStartPre=+` lines make `/etc/systemd/system/<unit>.service.d`,
  `/run/systemd/system/<unit>.service.d` and their `system.control`
  twins for the agent and the watchdog; they are the agent's own
  directories (no new file, no mount on or below them, outside a window;
  lots 273d and 330), and every drop-in found there at a start or a round
  is judged (`own_dropin_*`). A drop-in with `InaccessiblePaths=`,
  `TemporaryFileSystem=`, `BindPaths=` or `ExecStartPre=` is refused at its
  write.
- **A self-test of the guard at the start is not possible**: the agent's
  unit filters `mount(2)` (`SystemCallFilter=`), and every other mount
  call checks `CAP_SYS_ADMIN` before the hook. The lab proves the hooks;
  the start signs what was not attached.
- **The persistence vector of a mount made before the guard.** `/etc/fstab`
  is in the FIM watch set (`fim-paths.v1`; a change is a Medium drift, no
  rule of its own), and a `.mount` or `.automount` unit in
  `/etc/systemd/system`, `/lib/systemd/system` or `/usr/lib/systemd/system`
  is NN-L-FIM-009 (High). Not watched: `/run/systemd/system` and
  `/run/systemd/transient` (runtime units), the generator directories
  (`/etc/systemd/system-generators`, `/usr/lib/systemd/system-generators`,
  `/usr/local/lib/systemd/system-generators`) and the automounter's maps
  (`/etc/auto.master`, `/etc/auto.master.d`) — the next items below.
- **What the kernel source says (verified on 5.15, 6.1, 6.5, 6.8, 6.12,
  7.3, 7.4-rc2; systemd v247–v262):**
  - a mount through `/proc/<pid>/root` into another namespace is the
    kernel's `EINVAL` (`check_mnt`, `may_use_mount` from 6.15); the guard
    judges the target's own namespace anyway (the hook runs first). The
    real ways in are `setns(2)` (no LSM hook before 7.4: what is mounted
    after it in the agent's or the watchdog's namespace is judged, and
    opening their namespace is the ptrace guard's refusal),
    `MOVE_MOUNT_SET_GROUP` and shared propagation (the peer groups);
  - `move_mount`'s hook does not see its flags: `MOVE_MOUNT_SET_GROUP` and
    `MOVE_MOUNT_BENEATH` onto a protected mount are refused by their
    target (the protected mount's root), recorded as `move_mount(2)`
    without the flag; `SET_GROUP` onto another mount of a guarded
    namespace gives it a group: the hook wakes the refresh (§51.2), and
    walks that group until the refresh holds it;
  - `MS_REMOUNT | MS_BIND` reaches `sb_mount` only, `fsconfig`'s
    reconfigure `sb_remount` (and `fs_context_parse_param`) only, and
    `sb_remount` does not see the new options: every reconfigure of a held
    super block is refused there, whatever the options;
  - `mount_setattr(2)`, `open_tree_attr(2)` and `fsmount(2)`'s attributes
    have no LSM hook up to 7.4-rc2: observed by the integrity round (High
    within one round); a control at the system call would decide on the
    caller's string, not done;
  - btrfs: the hooks key a dentry by its subvolume's `anon_dev` and inode,
    as `stat(2)` does — unique across subvolumes; the super block keys are
    `s_dev` on both sides (not measured on a btrfs guest);
  - systemd's live mounts (`systemctl bind`, `mount-image`, v248+) are made
    by a grandchild of PID 1 (or of the `(sd-mount-in-ns)` worker, v257+)
    after `setns(2)`: no exemption is tied to PID 1 there; the shutdown one
    is PID 1 running systemd-shutdown;
  - procfs: since 5.8 each mount is its own super block; the host's
    `/proc` remount is refused. A private procfs instance for the agent
    (`ProtectProc=`/`ProcSubset=` in its unit) would change what it sees:
    not done, named.
- **Public techniques, checked:** an overmount of `/proc/<pid>` (MITRE
  T1564.013): refused; a `/proc` remount with `hidepid=`: refused; the
  bpffs or a tracefs overmounted: refused; `mount_setattr(2)`: signed
  High (not refused); `kernel.ftrace_enabled=0` and
  `/sys/kernel/debug/kprobes/enabled=0`: refused by the sysctl guard
  (lot 280b); the agent's BPF maps written: the BPF guard; runc's
  redirected procfs writes (CVE-2025-52881): the agent does not write
  `/proc/sys`; io_uring: no mount operation.
- **Later (named for the backlog):** a device-mapper table swap and raw
  block-device writes below a mounted file system; an overlay's upper
  directory written directly; `systemctl soft-reboot` (systemd 254 and
  later) and the guard's keys across it; the time sources (`machine-id`,
  the RTC, PTP).
- **The next items** (the adversarial review's persistence knobs, outside
  the mount guard; what the FIM watch set covers today):
  - `binfmt_misc`'s `register` (an interpreter for the ELF magic runs at
    every exec, the agent's restart included): not watched — neither the
    write to `/proc/sys/fs/binfmt_misc/register` nor `/etc/binfmt.d`,
    `/usr/lib/binfmt.d`, `/run/binfmt.d`.
  - `kernel.core_pattern` and `kernel.modprobe`: not in the sysctl guard's
    list, and `/etc/sysctl.conf` and `/etc/sysctl.d` are not watched.
  - `/etc/ld.so.preload`: watched, NN-L-FIM-022 (Critical); `/etc/ld.so.conf`
    and `/etc/ld.so.conf.d`: not watched.
  - The CA store (`/etc/ssl/certs`, `/usr/local/share/ca-certificates`,
    `/etc/pki/ca-trust`) that the uplink trusts: not watched.
  - `/etc/resolv.conf`: watched (`fim-paths.v1`, a Medium drift), no rule
    of its own; `/etc/hosts` and `/etc/nsswitch.conf` likewise.
  - An overlay's upper and work directories (an overlay root or `/usr`):
    a change there changes what a protected path shows with no mount;
    not watched.

### 51.2 The re-check of #567: a regrouped mount, the read-mode refusals

- **A regrouped guarded mount (N1).** The peer groups through which a
  change made in another namespace reaches a guarded one were read every
  30 s only. Root in the host could regroup a guarded mount — `mount
  --make-private /`, a decoy `mount --make-shared` taking the freed
  number, `mount --make-shared /` — and a raw `unshare(CLONE_NEWNS)` copy
  of it, a peer in the new group, then mounted a tmpfs over
  `/etc/northnarrow` that the kernel propagated into PID 1's namespace with
  no refusal (recorded only at the next round). Now:
  - a group the map does not hold is walked in the hook — the target
    mount's peers and each one's slaves, up to 16 mounts: a mount of a
    guarded namespace among them, or a walk that cannot be finished (more
    mounts, a slave that is itself shared or a master, a peer ring
    unreadable), counts as reaching, and the mount is refused there on,
    over or below a protected point (anything else is let through);
  - an unmount whose parent is in such a group is refused when it would
    take a held mount: each held mount's place is also registered under
    its parent mount itself (by its id), and the hook walks the parent's
    peers and their slaves for that mount; a walk it cannot finish is
    refused only when the mount unmounted has a held mount's root and its
    parent is a copy of a held mount (its namespace's root, or sitting at
    a held mount's place: a raw namespace's `/sys`). A chroot's own sysfs
    (the host's dentries, another mount, a copy of it in each sandboxed
    unit's namespace) unmounting its `sys/fs/cgroup` is let through: two
    first versions refused it on every lab guest (keyed by the place
    alone; then failing closed on any undecided walk);
  - `mount(2)`'s `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE` and
    `MS_UNBINDABLE` on a mount of a guarded namespace (or of a group the
    map holds), and a `move_mount(2)` into one of a mount in a peer group
    (`MOVE_MOUNT_SET_GROUP` among them), are counted by the hooks (they
    run before the change: the new group has no number yet); the agent
    reads the count each second and reads the guarded namespaces' groups
    again when it moved. `mount_setattr(2)` has no hook: until the 30 s
    refresh, the walk;
  - a propagation chain two masters deep is no longer a residual: the
    slave that carries the change on makes the walk undecided, so it
    counts as reaching.
  Named: a peer of a regrouped held parent made at another place (a
  bind of `/sys` elsewhere, in a group the map does not hold yet), behind
  more than 16 mounts of propagation, can unmount a childless held mount
  (`/sys/fs/bpf`) through it within the window before the refresh (a
  second after `mount(2)`, up to 30 s after `mount_setattr(2)`): signed by
  the integrity round, not refused.
  The false-positive side: a mount in a group the map does not hold and
  the walk cannot finish (a container running systemd, whose mounts have
  more than 16 peers and slaves) is judged as reaching — refused only on a
  protected point, which a container's own file systems never are, or on
  the host's own view super block (`systemd-nspawn` sharing the host's
  network namespace, a mount below its `/sys` that is not the kernel's
  own).
- **The read-mode refusals of the ptrace guard (b).** Opening an agent's
  process's `/proc/<pid>/ns/*` (`nsenter -t <agent> -m`, `systemctl bind`
  or `mount-image` into its namespace), `exe`, `root`, `cwd`, `fd/`,
  `environ`, `maps` or `io` is refused (as before) and now recorded: a
  signed Low `NN-L-AT-001` (`ptrace_read`), once a minute per caller and
  target, through the non-decisive budget, raising no posture trigger.
  journald reading the agent's executable for its log lines, `lsof` and a
  monitoring agent's process collector meet it too: a few Low records a
  minute on a host that runs them (§51.3: once an hour per caller program,
  none from journald). A `PTRACE_MODE_NOAUDIT` check (`ps`
  reading `/proc/<pid>/stat`) stays silent.
- **btrfs (d).** The guard's key of an inode is now one function
  (`common::mount_guard::inode_key`), the hooks' and the unit tests': two
  subvolumes of one file system, whose roots are both inode 256, are two
  keys (each the subvolume's device, as `stat(2)` gives it), and a point on
  one never matches the other. Without the btrfs offsets the key is the
  super block's, which matches no point on a subvolume: not measured on a
  btrfs guest yet.
- **The image tooling's overlays.** The start's audit of the mounts made
  before the guard took a `systemd-sysext` overlay over `/usr` (Flatcar),
  a `confext` over `/etc` or a composefs over `/usr` (Silverblue-like
  hosts) for a stacking file system over the agent's paths: a High at each
  start. These are the canonical layout now, by type and source (an
  overlay whose source is the tool's); root names a mount's source as it
  likes, so this is a layout, not a proof, and a merge at runtime
  (`systemd-sysext refresh`) is still refused outside a window.
- **The allow list out of line.** The object itself is checked now: the
  embedded eBPF object has `allowed_kernel_mount` as a function of its own,
  and the `sb_mount` and `move_mount` programs make a function call (the
  source's `#[inline(never)]` stays pinned too).
- **Named, not changed:** `MOVE_MOUNT_SET_GROUP` from a held mount (not
  `/`) to another one is refused as a move away (CRIU or podman restoring
  external slave mounts of `/sys` or `/run`: niche); SysRq-u (§51.1,
  remounts).

### 51.3 The re-check 2 of #567: what an unmount takes below, journald's reads

- **A lazy unmount is judged by the subtree it takes (N3).** `umount -l`
  (`MNT_DETACH`) calls the kernel's hook once, for the mount it names; the
  kernel then takes that mount's whole subtree and propagates the unmount
  of each mount in it to the peers and slaves of that mount's parent, with
  no other check. `mount --rbind /sys /mnt/s; umount -l /mnt/s` — the copy
  at a place nothing is held at — took the host's childless `/sys/fs/bpf`
  and `/sys/fs/cgroup` through the copies below it, and the copies in every
  slave namespace (the agent's own included): the bpffs lost its last
  mount, with no refusal. The same held for a raw namespace's `umount -l
  /`. Now the guard reads the subtree in the kernel's order (32 mounts: a
  child, else the next sibling of the mount or of one of its parents up to
  8 levels), and refuses
  the unmount when a mount in it is held (by its id in a guarded
  namespace), or its unmount propagates onto a held mount (its place under
  its parent's peer group; a group not followed yet, regrouped since:
  under a copy of a held mount), or — the subtree wider than the walk — it
  is in PID 1's, the agent's or the watchdog's namespace, or a mount read
  in it sits under a parent in a peer group. A refusal is the usual signed
  High (`NN-L-AT-001`, operation `mount`, an unmount).
- **What goes through.** An rbind made `rslave` before its lazy unmount
  (its copies propagate nothing), a chroot's own mounts (`mount -t sysfs`,
  its cgroup2, a proc at `$T`: new mounts, at no held mount's place), a
  container runtime's old root after `pivot_root` (every mount a slave or
  private, in a namespace of its own), `umount -R` (one mount at a time,
  each judged as before).
- **For you.** In PID 1's namespace, a lazy unmount of more than the walk
  reads at once (an rbind of `/` and its submounts) is refused even when
  `rslave`: unmount it with `umount -R`, or inside a trusted-installer
  window. Two new optional offsets (`struct mount`'s `mnt_mounts` and
  `mnt_child`): a kernel without them does not attach the guard (a signed
  degradation, as for the others).
- **The refused reads of the agent's processes (point 2).** The read-mode
  ptrace record (§51.2) was once a minute per caller process and target:
  about 2,880 Low records a day from journald alone, and as many from each
  periodic reader. Now:
  - the packaged `systemd-journald` is not recorded — its image at its
    install path (root's file, in a directory only root may write, not
    disowned by the package database, read again every 10 s) running in
    the cgroup of `systemd-journald.service` or of the namespace instance
    the agent's units log to (`systemd-journald@northnarrow.service`),
    written to the kernel before the ptrace guard attaches. Its reads are
    still refused (its lines from the agent carry no `_EXE`, as before);
  - every other caller is recorded once an hour per caller program (its
    executable's identity, not its process) and target: htop or a
    monitoring agent is one record an hour per process of the agent's, a
    tool run each minute (`pidof`, `lsof`, `ss -p`) the same, and a program
    never seen before (`nsenter -t <agent> -m`) at its first use.
- **The agent holds what it pins (fix round 3).** A link stays attached
  while one reference to it is left: its pin, or a descriptor. The deny
  links were held by their pins alone once the agent's start was over: one
  pin removed detached its hook at once while the agent ran, and the bpffs
  losing its last mount left them to whatever descriptor in it the agent
  held (its anchor of `/sys/fs/bpf`). Now the agent keeps a descriptor of every
  link and program it pins, for its life (`antitamper_bpf::held`: the deny
  hooks, the BPF guard's, the mount guard's, the start-in-cgroup
  tracker's, the sysctl judge's, the module files' write history's, the
  liveness watch). The watchdog pins nothing of its own and loads no
  program: its handles on the agent's pinned maps are opened per use, as
  before (a map the agent re-creates at each start must not be held from
  an earlier one). The agent's own purge of a pin drops the descriptor
  first (what it retires still detaches). One more open descriptor per
  pinned link and program (about ninety; the lab's 5.15 agent held 446 in
  all, its soft `RLIMIT_NOFILE` 65,536, raised to the hard limit at its
  start; `MAX_HELD` = 1,024 objects at most). The eBPF object is
  unchanged.
- **What happens if the bpffs loses its last mount** (what N3 did, and
  what the residual below can still do): no path reaches the pins any
  more, while the super block keeps them as long as a descriptor in it is
  open — the agent's anchor of `/sys/fs/bpf` (lot 353's views) is one, and
  the kernel frees the pins with the super block once the agent's
  descriptors close. The deny hooks (the kill, ptrace, file, cgroup, BPF
  and mount guards) stay attached while the agent runs — it holds them —
  and so do its sensors and maps (the lab: `umount -l /sys/fs/bpf` in a
  window, no bpffs left in any namespace, then SIGKILL of the agent, a
  read of its `environ` and a create in `/etc/northnarrow` refused, on
  5.15 and 6.8). The integrity round signs `protected_mount_gone`; the
  pins it reads beneath its anchor are in place, so no `bpf_pin_vanished`.
  The watchdog's handles on the pinned maps fail. If the agent stops
  before a reboot, its hooks go with it: the next start finds no bpffs at
  `/sys/fs/bpf` (its hooks attach for that run only, a signed
  degradation) or, if root mounted a fresh one, an empty pin root it
  takes for a first start: the previous run's pins are out of its reach,
  as after a reboot (BOOT_INTEGRITY.md).
- **A pin removed or hidden** (a pin root writable only inside a
  trusted-installer window, a mount over it refused by the guard): the
  integrity round (outside a window) compares every pin of an object the
  agent holds with the inode it was pinned at, in the directory it was
  pinned in. A pin gone, replaced or unreadable is a signed High
  (`bpf_pin_vanished`) naming the pin, the object and its id; a pin
  removed is pinned again from the descriptor, in that directory only
  (never into a new bpffs, nor a mount laid over the directory), so the
  next start finds it — the record says so, and a later round clears it.
  The pin directory itself removed is one High with the number of links
  and programs it held, nothing pinned again. The lab: three pins removed
  in a window (`link_task_kill`, `prog_task_kill`,
  `link_ptrace_access_check`), then outside it SIGKILL, the `environ` read
  and the create still refused; three Highs, the three pins back, three
  clears a round later.
- **Named, not changed:** a lazy unmount in a namespace that is not PID
  1's, the agent's or the watchdog's, of a subtree whose first 32 mounts
  (or a chain of 9 levels) are all private, behind which lies a copy in one of the host's
  peer groups (root building it on purpose in a raw `unshare(CLONE_NEWNS)`
  namespace) is not refused: the walk is bounded. A lazy unmount that races the
  walk (a copy grafted by a concurrent rbind after the guard read the
  subtree, in any namespace) is not refused either: the hook runs before
  the kernel's mount lock (re-check 3 of #567, N4); the deny links stay,
  the loss is signed, the pins do not. To close it: the pin directory as
  its own private, unbindable mount. And the regroup window
  of §51.2 (a peer of a regrouped held parent unmounting through it before
  the refresh) needs only one shared slave of that parent, not 16 mounts —
  every sandboxed unit's namespace is one — hiding the host's bpffs mount
  (not the agent's copy, nor the pins). KNOWN_LIMITATIONS.md names both:
  the pins can still be lost or hidden, the hooks no longer detach while
  the agent runs.

## 52. The pin directory is locked; three record fixes (lot 359)

The re-check 3 of #567 named an unmount the guard could not stop: the
kernel calls the unmount hook before it takes its namespace lock, so the
subtree the guard reads can still grow (a copy grafted by a concurrent
rbind), and the walk reads a bounded subtree only. A lazy unmount could then
take the host's bpffs, and the pins with it, in any namespace (N4, and the
residual of §51.3). This lot closes the rbind variants of both for the
pins; what stays open for the alpha, each signed at the next integrity
round, is listed in 52.1 ("What it does not cover"), 52.3 and 52.4.

### 52.1 The lock

- **What it is.** The agent's pin directory, `/sys/fs/bpf/northnarrow`, is
  bound onto itself, then made unbindable (which makes it private too), as
  the child of the host's bpffs in PID 1's mount namespace. The kernel
  never takes, in an unmount's propagation, a mount that keeps a child
  that is not itself unmounted, and an rbind never copies an unbindable
  mount: whatever an rbind copy's unmount takes (a racing graft, a copy
  beyond the walk's bound), the host's bpffs keeps its child, and the pins
  stay. A unit's own namespace (the agent's and the watchdog's among them)
  is not covered, for the unit's whole run: systemd builds its view with a
  recursive bind, which skips an unbindable mount (the lab: no copy of the
  lock there), so a racing unmount can still take that namespace's view
  of the bpffs — not the pins, which the host's bpffs keeps; the agent and
  the watchdog keep their anchors, and a restart builds the view again.
- **Who makes it, and when.** A new step of the agent's unit, before the
  agent's process exists and before any pin is written:
  `ExecStartPre=-+/usr/local/bin/northnarrow-agent --pin-lock` (install.sh
  rewrites the path with `BIN_DIR`). `+` runs it with full privileges,
  outside the unit's sandbox — the agent itself has no `CAP_SYS_ADMIN` and
  no `mount(2)` (its system call filter), on purpose, for its whole life,
  so it could not make a mount in the host's namespace, nor `setns(2)` into
  it. The unit's `LogNamespace=` still gives the step the unit's own mount
  namespace, so the step enters PID 1's itself (`setns(2)`), then checks it
  is there. `-`: a lock that cannot be made does not fail the start. The
  step uses the new mount API (`open_tree(OPEN_TREE_CLONE)`, then
  `move_mount(2)`), then `MS_UNBINDABLE` (52.3: no `MS_PRIVATE` step), and
  reads PID 1's table again; one line in the unit's journal:
  `pin lock: made`, `reused`, `repaired`, or `NOT made: <why>`.
- **Kept across restarts.** A lock already in place, private and
  unbindable, is reused; a reboot's new bpffs has none, and the next start
  makes it. A lock whose propagation changed is made unbindable (and so
  private) again.
- **The guard.** The lock passes the mount guard only as its maker's own
  two steps, in PID 1's namespace: the agent's binary run as a unit's
  process (PID 1's child, the main thread, in its first seconds, its
  start-in-cgroup and injection marks clean), and exactly the self-bind of
  the pin directory onto itself (judged by the kernel's objects: a
  detached, childless clone whose root is the target's own dentry, on the
  bpffs, not stacked), then `MS_UNBINDABLE` on the host's lock itself.
  Anything else is refused and signed High (`NN-L-AT-001`, operation
  `mount`): an unmount or a move of it (a held mount), a mount on or below
  it, any other change of its propagation — on the lock, or on a copy of it
  in a namespace whose changes reach the host's — and, in the host's
  namespace, a recursive `MS_SHARED` on `/`, `/sys` or `/sys/fs/bpf` that
  would make it shared and (52.3) a recursive `MS_PRIVATE` there (52.4:
  in another namespace neither is judged). A caller who
  forged the maker's identity gains nothing: each of the two steps only
  makes the lock (52.3: lot 359's third step, `MS_PRIVATE`, did not).
- **The integrity round.** The start reads the lock in PID 1's table: in
  place, or a signed degradation (the walk of §51.3 then remains the
  defence). Each round after a start that found it in place checks it is
  still there, private, unbindable and the child of the host's bpffs:
  missing (`pin_lock_missing`) or changed (`pin_lock_changed`), a signed
  High, and the lock made again by the same step, run in a transient unit
  (`systemd-run`, at most 20 s, all attempts waited for at most 30 s), its
  result in the record; the guard's held mounts are read again for its new
  id within a second. 52.3: the attempts, the back-off, and a start that
  found none.
- **Uninstall, upgrade, the window.** A mount point cannot be removed:
  `uninstall.sh` and `install.sh` unmount the lock before they remove the
  pin root (`rm_pin_root`), which the guard lets through only inside the
  signed trusted-installer window (recorded, `FS_OP_MOUNT_WINDOW`). No lock
  is left behind.
- **What it does not cover.** Each of these is signed at the next
  integrity round (about 30 s), not refused; the coordinator kept them for
  the alpha as signed and documented limits, and the first lot after it
  refuses the move of a copy that is a peer of a held mount and signals a
  `mount_setattr(2)` at once (KNOWN_LIMITATIONS.md):
  - `mount_setattr(2)` has no LSM hook: root can clear the lock's flags
    through it; until the round makes the lock again (`pin_lock_changed`,
    High), a racing unmount can take the host's bpffs and the pins;
  - a raw mount namespace holds its own copy of the lock: its own
    recursive change of propagation above it is not judged (52.4), and a
    move of its copy of `/sys` is judged by its target only: that copy is then
    defended by the walk alone, and its unmount can still race the walk,
    or lie beyond its bound, and take the host's bpffs and the pins
    (`protected_mount_gone`, `pin_lock_missing`, High);
  - the units' own views of the bpffs never have the lock (above;
    `protected_mount_gone`, High);
  - `/sys/fs/cgroup` has no such child: its unmount by a racing or
    out-of-bound lazy unmount stays behind the walk.
- **For you.** `mount --make-rshared /` (or of `/sys`, `/sys/fs/bpf`) in
  the host's namespace is refused: it would make the lock shared. 52.3:
  `mount --make-rprivate` of the same there is refused too. 52.4: in
  another namespace a recursive change of propagation — shared, private or
  slave — is not judged: container runtimes (Kubernetes' `Bidirectional`
  mounts included), `unshare -m` (with `--propagation shared` too),
  `systemd-nspawn` and systemd's own unit namespaces work. A tool
  that removes `/sys/fs/bpf/northnarrow` by hand must unmount it first, in
  a window. `findmnt /sys/fs/bpf/northnarrow` shows the lock
  (`unbindable`).

- **The root's own point (a fix found by the lab).** The host's `/` was
  read through `/proc/1/root/` without following its link (a path's
  trailing `/` is no component): the key registered was the link's, so
  `/` was no point of the guard (`mount --make-rshared /` was let through
  in the lab, and the lock repaired a round later), and no mount's place
  directly under `/` (`/sys`, `/proc`, `/run`, `/etc`…) was held in PID 1's
  or the watchdog's namespace. Both are read through the link now: a mount
  on `/`, a read-only bind remount of `/`, an unmount propagating onto a
  root-level held mount from a namespace that reaches the host's are
  judged as the other points always were.

### 52.2 The re-check 3's records (P3)

- **journald's quiet reads.** The packaged journald's refused reads of the
  agent's processes are left unrecorded only while its start-in-cgroup and
  injection marks are clean: a process written into journald's cgroup, or
  journald with code-injection access given to another, is recorded as any
  caller.
- **The dedup of a refused read carries the caller's cgroup.** An
  interpreter is one image for every program it runs: a collector's record
  no longer silences another program's probe of the same target, by the
  same interpreter, for the hour.
- **A record the budget drops is not "seen".** The once-an-hour key was
  written before the records' budget was asked: a flood of minor refusals
  on one CPU dropped the first record and still silenced that program and
  target for an hour. It is written once the record is let through.
- **The executor's identities before the fork record attaches.** A unit
  started in the window between the fork record's attach and the identities'
  write (at each start of the agent) carried `fork_ppid` 0 ("not known").
  The identities are written first.
- **The watchdog's handles on the pinned maps.** A failure of
  `register_self_pid`, `claim_role`, `reinsert_new_agent_pid` or
  `evict_dead_agent` (the pins out of reach) is a record the agent signs, a
  degradation of its status (`watchdog_pin_handle_failed`), once per handle
  and watchdog — no longer only a log line.
- **eBPF.** The ptrace guard's record (`emit_task_read_denial`: its quiet
  check, its dedup key, its order) and the mount guard (`sb_mount`'s change
  of propagation, `move_mount`'s self-bind) changed; the fork record's
  program did not.

### 52.3 The review of #569: the lock kept unbindable, retried, its limits

The review of #569 found the lock's `MNT_UNBINDABLE` could be cleared
without a refusal, which reopens the race for the pins (an rbind copies a
bindable lock); and the lock missing at a start was never made again.

- **A recursive `MS_PRIVATE` above the lock, in the host's namespace,
  is refused.** The kernel clears `MNT_UNBINDABLE` at any `MS_PRIVATE`, the
  recursive one included: `mount --make-rprivate` of `/sys/fs/bpf`,
  `/sys` or `/` left the lock private but bindable, and a later plain
  `--make-shared` restored the propagation. It is now refused and signed
  High (`NN-L-AT-001`, operation `mount`, the lock's reason), in PID 1's
  namespace only (in another namespace it changes that namespace's own
  copies: `unshare -m`, container runtimes and systemd's unit namespaces
  still make it there). `systemd-shutdown`'s switch to its shutdown image
  (`switch_root()`, at the very end of a shutdown, by its identity) is let
  through, as its pivot was. A plain `--make-shared` of the lock itself
  stays refused, its maker's included; a recursive `MS_SLAVE` or
  `MS_UNBINDABLE` above it keeps the flag and is not judged.
- **The maker's steps: the self-bind, then `MS_UNBINDABLE`, in the host's
  namespace only.** Lot 359 let its maker's `MS_PRIVATE` through at any
  time and in any namespace: on a lock in place it cleared the flag, and a
  raw namespace's copy of the lock could be made bindable the same way.
  `MS_UNBINDABLE` alone makes the fresh self-bind private and unbindable
  (the kernel leaves its peer group), so the step no longer asks for
  `MS_PRIVATE` — the step's journal line and its result are unchanged —
  and the guard refuses it. The maker's exemption holds only on the
  host's lock, in PID 1's namespace.
- **A lock that could not be made is asked for again.** Each integrity
  round that finds it missing or changed asks for it up to three times
  (a pause of 1 s, then 2 s), all within 30 s, so one failure (the
  transient unit's name taken, a slow manager) no longer leaves it missing
  until the next round; the record says at which attempt it was made, or
  that every attempt failed and when the next one is due. A round whose
  attempts all failed leaves the next rounds out — 1, 3, then 7 rounds
  (an attempt about every four minutes) — and the same High stays signed
  meanwhile (it is not "cleared" while the lock is not in place). A start
  of the agent's unit that found no lock (signed as a degradation) no
  longer leaves it unwatched for the whole run: the round makes it, then
  keeps it. An agent run by hand (no `--pin-lock` step ran) is left as its
  start signed it.
- **What the lock closes, and what it does not.** It closes the rbind
  variants for the pins: a racing rbind graft, an rbind copy beyond the
  walk's bound. It does not close, each signed at the next integrity round
  (about 30 s) — 52.1, "What it does not cover": a change of the lock's
  flags through `mount_setattr(2)`, which has no LSM hook; a raw
  namespace's own copy of the lock, whose move is judged by its target
  only and is then defended by the walk alone (52.4: its own recursive
  change of propagation is not judged either); the units' namespaces,
  which never have the lock. The first lot after the alpha refuses the move of peer copies
  and signals `mount_setattr(2)` at once.
- **Found by the lab (5.15).** With these changes the BPF back end loaded
  the payload of an `Option` that the peer-group walk (`spread`) carried
  across its loop before it tested the tag; the payload of its first
  `None` was never written, and 5.15's verifier refused `sb_mount`
  ("invalid read from stack" — 6.5 and later allow that read to a
  privileged loader). The walk carries a value always written and a flag
  now, the same walk, and a test forbids a mutable `Option` in the walks
  the eBPF inlines.
- **eBPF.** `sb_mount`'s judge of a change of propagation that reaches the
  lock changed (a recursive `MS_PRIVATE` above it judged by the target's
  namespace, the maker's step on the host's lock only,
  `systemd-shutdown`'s exemption); the peer-group walk's code changed in
  `sb_mount`, `move_mount`, `sb_umount` and the lock's judge (the same
  walk).

### 52.4 The re-check of #569: container runtimes and Kubernetes' `Bidirectional` mounts

52.1 refused a recursive `MS_SHARED` above the lock in any namespace whose
changes reach the host's. A container's fresh mount namespace is one: its
`/` is still a peer of the host's `/` when the runtime makes its first
change. So every container whose runtime makes `/` recursively shared was
refused at its start — containerd and CRI-O do it (`rootfsPropagation:
rshared`) for any Kubernetes `mountPropagation: Bidirectional` mount:
Cilium's bpffs mount (its chart's default), the CSI node plugins
(Longhorn, Rook-Ceph and others), so a node had no CNI and its pods stayed
in `Init`; `unshare -m --propagation shared` the same.

- **A recursive `MS_SHARED` above the lock is judged in the host's
  namespace only**, as the recursive `MS_PRIVATE` of 52.3 already was. In
  another namespace either changes that namespace's own copies only: let
  through, without a record. Container runtimes and Kubernetes'
  `Bidirectional` mounts work: the container's `rootfsPropagation:
  rshared`, a bind of `/sys/fs/bpf` with `rbind,rshared`, `docker run -v
  /sys/fs/bpf:/sys/fs/bpf:rshared`, `unshare -m --propagation shared`.
- **Unchanged in the host's namespace.** `mount --make-rshared` and
  `--make-rprivate` of `/`, `/sys` or `/sys/fs/bpf` stay refused and
  signed High (`NN-L-AT-001`, operation `mount`). Every change of
  propagation of the lock itself, or of a raw namespace's copy of it whose
  changes reach the host's, stays refused in every namespace.
- **What it costs.** It is inside the raw-namespace residual of 52.1: a
  raw namespace may now also make its own copy of the lock shared through
  a recursive change above it. That copy, like its move, is defended by
  the walk alone, and a loss is signed at the next integrity round
  (`protected_mount_gone`, `pin_lock_missing`, High). The units' views
  never have the lock, so nothing is lost in the agent's or the
  watchdog's namespace.
- **eBPF.** `sb_mount`'s judge of a change of propagation that reaches the
  lock changed: a recursive `MS_SHARED` above it is judged by the target's
  namespace, as a recursive `MS_PRIVATE` was.

## 53. An AppImage's fork-only child is judged like its AppImage (lot 360)

- **What changes.** §49 made an AppImage's programs its image's. Its
  zygote's child — forked without an exec, as Chromium's and Electron's
  zygotes do — was the image's only while `/proc` still showed it: it has
  no exec record, so the connect pump named it from `/proc/<pid>/exe` and
  the judgement found its image's mark through `/proc` again. A child that
  closes its connection and exits at once was gone by then, its mark "not
  known", and its flow was judged as a staged image's: NN-L-NET-008 High,
  "would have: KillProcess" (the pre-alpha's rc3 round, five kernels).
  The connect already carried the kernel's fork record of such a process
  (lot 352: its forker, the forker's start and its own start, read by the
  eBPF connect program); the connect pump now teaches it to the lineage
  before it names the flow's image, as the open sensor does for a write
  (lot 340). In a judgement, a process that executed nothing since its fork
  is its forker's exec at that fork — its image and its mark — whether it
  still runs or not; a connect made before a later exec of it stays its
  forker's. No eBPF program changed.
- **The forker's exec must be the forker's at the fork.** The record names
  the forker by its pid and its start. The forker's cached exec answers
  only when its process has that start: a forker's pid an earlier process
  held, whose exec the lineage keeps once that process is gone, lends that
  exec to no fork (no image, no mark; the lookup goes on as without a
  record). A write's record carries the forker's start only for a forker
  that never executed either; otherwise it is not checked, as before. A
  cached exec of an earlier process of the fork's own pid (the record shows
  the fork came after that process started) is not the fork's image
  either: the record names it. Of two records of one pid read out of order
  (the pumps are separate threads), the later process's is kept.
- **At the pump, only what `/proc` confirms.** The lineage learns execs when
  the event loop takes them, so when the connect pump names a fork's
  connect, its forker's last exec may not be read yet (a shell that
  executes a staged binary in place, which forks at once). There the record
  names the fork only when `/proc` shows the fork itself (its start the
  record's) running that image. When `/proc` shows the fork or its forker
  running another file, the fork is named from `/proc`, as before. When it
  shows neither, the record names the flow only by a staging path (the flow
  is judged; the image's mark is decided in the judgement), never by an
  image that would leave it unjudged; otherwise the row names no image and
  the judgement reads the record against the lineage the event loop has
  brought up to date (every exec that reached it before the connect). An
  exemption is never taken from an unconfirmed record.
- **An image file named with 31 bytes or more is tied (§49).** The LSM exe
  walk keeps 31 bytes of each name, marked as possibly cut, so the path of
  an image named `Bitwarden-2025.1.1-x86_64.AppImage` (or any image
  AppImageLauncher integrates, `<name>_<md5>.AppImage`) named no file and
  §49's tie never held: R001 High on each exec, CHAIN-002/005 Critical. The
  image's whole path is now its daemon's `exe` link (the kernel's own view
  of the file), taken only when it is the walk's path name by name (a cut
  name its start, every other name equal, as many names) and lies under no
  FUSE mount; the image file's checks (owner, linked, its device and inode
  the LSM program's) run at that whole path, and the tie keeps it. The cut
  text only selects candidates: the device and inode decide. A name cut
  inside a multibyte character is not tied (as before). A program inside
  the mount whose name is cut is compared the same way.
- **An image nothing names.** NN-L-NET-008 judges a flow by its process's
  image path. A flow whose image is empty or unreadable, and that the
  lineage cannot name (no exec, no fork record, no `/proc` link at the
  connect), is not judged by a path: it is counted and said in the agent's
  journal at debug level. A process the lineage names by its `/proc` link
  alone (no exec or fork record: the record lost, a process older than the
  agent) is judged by that path, as before: the user image's exemption
  needs the mark.
- **What stays judged, and is now judged more.** A binary staged in `/tmp`,
  `/var/tmp` or `/dev/shm`, its fork+exec child and its fork-only children
  keep NN-L-NET-008's kill (and R001, CHAIN-002/005 as before), within the
  residuals below. A fork-only child of a staged binary that exited before
  the pump read it was not named, and drew nothing: it is now its forker's
  image, judged; so is one on a pid whose earlier holder's exec was still
  cached (that exec named it before). The programs of a FUSE mount the exec
  pump does not tie (§49: `squashfuse`, a writable mount, a daemon that
  does not hold its image) and their forks stay judged.
- **Residuals, accepted.**
  - The forker's exec in place, just before the fork, that reaches the
    event loop only after the connect: the connect is judged on the
    forker's earlier image. At the pump this fails closed (no image and no
    mark from a record `/proc` does not confirm, but a staging path); it
    remains open only in the judgement, for an exec read after the connect
    itself. NN-L-CHAIN-002/005 judge a connect that soon after a staged
    exec. The full closure is the connect carrying the identity of the
    file its process runs (`mm->exe_file`), an eBPF change for a later
    release.
  - A UDP datagram carries no fork record: a fork-only sender is named as
    before (`/proc` at the drain).
  - A fork of a fork-only process whose forker has already exited without
    a record of its own (a helper double-forked without an exec) is named
    by its `/proc` link and judged by its path: this fails closed (at worst
    an NN-L-NET-008 on that rare shape). The nearest process that executed
    (its anchor) is not used: it may have executed since that fork.
- **Operator action.** None.

## 54. Release binaries for glibc 2.34, a clear permission error, no false bpffs warning (lot 365)

An external tester followed the alpha tester's guide on Debian 12 with a
release built by CI; two of the findings are fixed here (the third, the
masking of the diagnostics the guide collects, is the guide's own: no
product code builds that bundle), with a false `host-check` warning.

- **The release is built on Ubuntu 22.04 and holds glibc 2.34.** The release
  workflow's `package` job ran on Ubuntu 24.04 (glibc 2.39). Rust's
  standard library refers weakly to two glibc 2.39 functions
  (`pidfd_spawnp`, `pidfd_getpid`), so the agent, the watchdog and
  `nn-admin` recorded a weak need of `GLIBC_2.39`, and on Ubuntu 22.04
  (2.35) and Debian 12 (2.36) every start printed
  `weak version 'GLIBC_2.39' not found (required by nn-admin)` — in every
  command's output and in the agent's journal. Harmless then; but a build
  on a newer image (GitHub's `ubuntu-latest` is moving to 26.04) could
  need a newer symbol strongly, and then the binaries would not start
  there at all. The job now runs on `ubuntu-22.04`, the oldest image
  GitHub offers (glibc 2.35), and the check below holds every need at or
  below 2.34: AlmaLinux/RHEL 9, the oldest supported distribution, whose
  glibc is the floor the `.deb` and the `.rpm` declare (a 22.04 build
  tops out at `GLIBC_2.34` today). It stays a GitHub-hosted image, so the
  build provenance is unchanged: the `sign` job (which builds nothing)
  attests the same artefacts, and `gh attestation verify
  --deny-self-hosted-runners` with the tag-bound identity still applies.
- **The baseline is checked on what is shipped.** A new step of the
  `package` job, `deploy/release/glibc-baseline.sh check`, reads every ELF
  file of the tarball's tree, of the `.deb` and of the `.rpm` (the four
  binaries, the eBPF object; any shared library a later release ships)
  and fails when one needs a glibc symbol version above 2.34 — weak needs
  included (`readelf -V`, the `.gnu.version_r` section) — or a shared
  library other than glibc's own and `libgcc_s` (a dependency the packages
  would not declare). Its `selftest` runs first, in the same step: it
  builds, with the release's linker, binaries with a strong and a weak need
  of `GLIBC_2.35` (one above the baseline) and of `GLIBC_2.39`, and one of
  `GLIBC_2.34`, and proves the check refuses the first four and accepts the
  last. The CI
  artefact the tester installed fails this check (the agent, the watchdog
  and `nn-admin`: `GLIBC_2.39`, flags `WEAK`). Ratchets in
  `xtask/tests/supply_chain.rs`
  (`the_release_is_built_and_checked_on_the_glibc_baseline`: the job runs on
  the oldest image, the glibc step carries no `if` nor `continue-on-error`,
  and the `.deb`'s and `.rpm`'s glibc floors equal the baseline) and the
  selftest passes (`glibc_baseline_check_refuses_a_binary_that_needs_above_2_34`).
  An operator of an earlier release: nothing to do; the warning goes away
  with the next upgrade.
- **`nn-admin` exits 17 when this user may not reach the agent.** Without
  root, `nn-admin status` (any command that talks to the agent) failed to
  open `/run/northnarrow/admin.sock` (root's) and exited 5 with
  `connecting to /run/northnarrow/admin.sock: Permission denied` — the
  code and the words of an agent that is not running. A permission the
  host refused (`EACCES`, `EPERM`) on the admin socket, on the key or on
  the agent id file now exits **17**, with the step that met it and, in
  plain words, what to do: run it with `sudo`; and that this does not
  mean the agent is stopped. As root (a security module refused it) the
  message says so instead. Exit 5 keeps its meaning: no socket, nobody
  listening on it, or a protocol failure. One helper decides it for every
  command (`exit_from_request_error`); nn-admin's output matrix covers
  each of its 41 socket cases with a socket this user may not open
  (`sock.<verb>.permission-denied`, run only without root). A script that
  runs `nn-admin` without root and read 5 as "the agent is down" now gets
  17. NN_ADMIN.md §4 lists it; 11 to 16 stay the alerts of `heartbeat
  watch` and `export verify`.
- **`nn-admin chain verify` without root.** Its readers met the state
  directory (root's, mode 0700) and printed each chain they could not open
  as `BROKEN`, exit 8 — "evidence missing or altered", a false alarm.
  Without root, a chain this user may not open is now exit 17 with the
  same advice; as root a refused read stays `BROKEN` (no mode refuses
  root, so it is evidence). `audit read` and `audit verify` keep exit 1, "a
  file that cannot be read".
- **`nn-admin host-check` no longer counts the agent's pin lock as a
  second bpffs.** Lot 359 (§52) binds `/sys/fs/bpf/northnarrow` onto
  itself, private and unbindable, to lock the pins; the check counted
  every bpffs mount and warned "mounted 2× — a second bpffs can hide
  pinned objects" on every host with the agent. The lock is recognised by
  what it is, never by its path: the mount lot 359's start and integrity
  round take for it (`pin_lock::state_in`: the self-bind of the pin
  directory, the child of the whole bpffs at `/sys/fs/bpf`) with private
  and unbindable propagation, and a lock stacked on it with the same
  propagation. The check's line names it ("and the agent's pin lock at
  /sys/fs/bpf/northnarrow, not counted"). A bpffs at that path that is not
  the lock (another bpffs, another directory of the host's), the lock made
  shared or bindable, a mount laid over it, and any other bpffs anywhere
  still warn. Named test `the_agent_s_pin_lock_is_not_a_second_bpffs`
  (`host_hardening`). `nn-admin status`'s "host hardening" line counts one
  warning less.
- **Not changed:** the agent's eBPF programs, its units, `install.sh`,
  every protection. The release's contents are the same programs, linked
  on another image.

## 55. A user's FUSE file system cannot hold the exec pumps (lot 366)

- **What changed.** For each exec, the exec pump and the exec-check pump
  read the file the process runs and a few facts about it: the directory
  it was run from, an AppImage's image and daemon, a module tool's script
  and library path, the image of a program whose stdio is a socket. These
  reads no longer ask a FUSE or network file system anything:
  - a process's file, root and descriptors are identified by the kernel's
    cached identity of the file;
  - a path is walked one name at a time. Before any name is looked up in a
    directory, its file system is judged by the device the kernel reports,
    against PID 1's mount table. FUSE (`fuse`, `fuse.*`, `fuseblk`,
    `virtiofs`), network file systems (NFS, CIFS/SMB, 9p, Ceph, AFS, …) and
    a file system the table does not show are not walked;
  - where the fact is about a path (the directory an image was run from,
    an AppImage's image, a module tool's script), no symbolic link on the
    way is followed;
  - a file is opened for reading only once its file system is judged.
- **A deadline.** An exec's reads run on the agent's bounded reader:
  500 ms at most, and at most four unanswered at once (past that, a read
  is refused at once). The pump goes on either way. An exec the pumps read
  nothing of (no module tool, no socket program, no AppImage tie to check)
  is not handed over.
- **What is judged when a fact is not read.** Not verified, never trusted:
  - no `ROOT_DIR` and no AppImage tie (`USER_IMAGE`);
  - an interpreter naming a system script or nothing is taken to load the
    caller's code, as for an environment larger than the pump reads;
  - a module tool's program and environment are not checked: R011
    refuses it, as for an environment it could not read;
  - the image of a program whose stdio is a socket is unverified:
    R020 records it.
- **Signed.**
  - `exec_reads_unanswered`: a degradation of the exec pumps while an
    exec's reads do not answer within the deadline (it stands at least
    60 s once reported).
  - `exec_pump_mounts`: PID 1's mount table could not be read. The table
    last read stays in force; a file system mounted since is not trusted.
- **Before this change.** On a host whose `/etc/fuse.conf` sets
  `user_allow_other`, a program a user ran from their own FUSE mount
  (mounted with `allow_other`) whose daemon then stopped answering held the
  exec pump until the daemon answered; the sensor self-test signed the
  exec source degraded. Without `user_allow_other` (the default on Debian
  and Ubuntu) the kernel refuses root's access to a user's FUSE mount at
  once, and nothing was held.
- **Residuals, accepted.**
  - A file system the administrator mounted, served from outside the
    kernel, of a type outside the list above, is walked as a local one.
    If its server stops answering, it holds one of the four readers; the
    pump goes on after 500 ms.
  - On a slow local disk, an exec whose reads take longer than 500 ms is
    judged as not verified (signed).
- **Operator action.** None.
