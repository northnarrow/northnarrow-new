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
  class, as it had with a separate `/home` partition. Not covered yet
  (lot 323): a filesystem a user mounts in their own user namespace (an
  overlay after `unshare -rm`, no container needed), a chroot into a FUSE
  directory, and a chroot 62 levels or more below a guarded mount give no
  class. Every FUSE filesystem (`fuse`,
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
- **The BPF guard's refusals have a budget** (BUG37), and the refusals
  that decide nothing have their own (the review of #545). A refused read
  of the agent's key, a handle on its BPF objects, a refused program type
  or root `cgroup/sysctl` attach and a loader opt-out's record: 50 a second
  per CPU, the rest counted in the signed `ringbuf_drop` entry
  (`minor_denial_rate`, a new slot) and never a telemetry loss — a
  `bpftool prog list` or `map list` outside a trusted-installer window, or
  a monitoring agent listing the BPF objects every second, records its
  first 50 refusals in the second and raises no `TelemetryLoss`. The
  decisive refusals (an unlink, rename or write-open of a protected file, a
  write handle on or a detach of the agent's BPF objects; and the refused
  signals and ptraces) keep their 50 a second to themselves, and one of
  them held back (`denial_rate`, `task_denial_rate`) is a telemetry loss
  at once, where more than 64 in a 10 s sample were. Every refusal holds.
  A reader of the `ringbuf_drop` counters by index sees 30 slots
  (`minor_denial_rate` is the 30th).
- **The io_uring sensor** attaches one more program, `io_uring_exit` on
  `sched/sched_process_exit` (N9): a process's aggregation state goes with
  its last thread. Where it does not attach, the start signs the
  `io_uring_sensor` degradation.
