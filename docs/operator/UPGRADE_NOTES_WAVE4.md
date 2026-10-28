# Upgrade notes: Wave 4

What changes for an operator who upgrades to a build of Wave 4 (the
capability program, tracker in the source repository:
<https://github.com/northnarrow/northnarrow-new/blob/main/docs/roadmap/CAPABILITY_PROGRAM.md>).
The changes of the external audit of `16f7563` that came before are in
`UPGRADE_NOTES_AUDIT_16f7563.md`; `CHANGELOG.md` `[Unreleased]` (at the
root of the release tree, in `/usr/share/doc/northnarrow/` from a package)
has the details of each change below.

## Before you upgrade

1. Nothing in the unit, its drop-ins or your wrappers has to change for
   the agent to start: the settings of the removed LLM advisor are
   accepted and ignored, each named in a WARN (§1). Drop them when
   convenient.
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
