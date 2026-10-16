# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow the ROADMAP "Tappe"; `0.0.1` covers everything up to Tappa 9.0.

## [Unreleased]

### Changed
- The ADE is a consultant: a model verdict that names a response (Kill,
  KillTree, Quarantine, BlockNetwork, Isolate) is recorded as a
  recommendation — a detection with the model's reasoning, response
  "advisory: … recommended by the model, not executed" — and nothing runs.
  The model reads strings an attacker writes; responses stay with the
  deterministic rules and the COMBAT ladder. `NN_ADE_ENFORCE=1` lets the
  verdicts act again and is reported as a weakening in the signed chain.

### Fixed
- External audit, Wave 2, response and detection assertions (Medium
  TST-018, TST-005, TST-008, TST-006): a detection record named the
  response's action even when it did not happen — a kill that found the
  process already gone, was refused (a protected process), denied or
  failed read `"response":"KillProcess"`, like one that landed. The bare
  action name now means it was carried out; otherwise the outcome follows
  it: `KillProcess (already gone)`, `KillProcessTree (refused: <reason>)`,
  `KillProcess (permission denied)`, `Quarantine (failed: <error>)`, and
  `KillProcessTree (partial: 1 not killed, 1 spared)` for a tree killed in
  part. The action stays the first word, so readers that key on it still
  find it; `suppressed (detect-only)` and `none` are unchanged, and records
  already written keep their text. The privileged e2e now check who the
  response hits: a new suite runs an enforcing agent and asserts that a
  `/tmp` offender is named by its record and dies by SIGKILL while a
  same-named sibling runs on; the honeypot tests assert one signed record
  (Critical, KillProcessTree carried out, the tamperer as principal) and
  the death of the tamperer and its child, where three unrelated
  substrings of the log passed before (`COMBAT` matched the boot banner);
  the uncommon-port listener test asserts its NN-L-NET-006 record; and
  absence checks wait for a barrier through the same pipeline (an exec, a
  FIM write, a settled row count) instead of a fixed sleep.
- External audit, Wave 2, the anti-tamper proved in enforce mode (Medium
  TST-001, TST-002, TST-010, LAB-001): every privileged fixture stops its
  agent by evicting it from `PROTECTED_PIDS` with bpftool, which only a
  test build's observing BPF guard allows, and no test showed the
  production guard refusing it. A new e2e runs the guard in enforce mode
  and asserts that root's eviction and `kill -9` are refused and recorded,
  that the fixtures' teardown then fails and says why, and that the signed
  shutdown stops the agent. That teardown used to ignore a failed eviction
  and a refused signal and leave the agent running: it now fails the test,
  sends no signal it knows will be refused, and no agent is started when
  `bpftool` does not run (on an Ubuntu 22.04 lab guest without
  `linux-tools-$(uname -r)` the refused signal sent the agent into COMBAT;
  it killed the test runner, then the next test binaries). The runbook's
  respawn test no longer publishes the eviction recipe (`systemctl kill`
  inside a trusted-installer window instead), `nn-lab.sh respawn-check`
  fails where it warned when a root `kill -9` or an out-of-window
  `systemctl kill` succeeds, the lab installs and checks the guest's
  bpftool before the test suites, and `docs/verify-2b.sh`, whose normal
  stop was the eviction, is retired.
- External audit, Wave 2, agent start and watchdog respawn; RAG and ADE
  tooling (Medium DEP-004, WDG-009, WDG-011, WDG-R01): the agent unit's
  bpffs pre-flight was a `ConditionPathIsMountPoint`. Without bpffs at
  `/sys/fs/bpf` systemd skipped the agent and reported its start job done
  — "inactive (dead)", nothing in `systemctl --failed` — and the
  watchdog's `systemctl start --no-block` succeeded the same way. It is now
  `ExecStartPre=/usr/bin/mountpoint -q /sys/fs/bpf`: the unit fails
  (`Result: exit-code`), is listed by `systemctl --failed` and the system
  reads degraded (an `AssertPathIsMountPoint`, the audit's proposal, fails
  the start job but leaves the unit inactive). Every watchdog hold — a start that brought no agent back within 30 s, a failed
  `systemctl start`, the restart ceiling — is recorded with the unit's
  systemd state at `/run/northnarrow/watchdog.hold`, and the agent signs
  it as an `integrity_drift` (`watchdog_hold`) at its next start; it was a
  journal line only. **Regression:** a host without bpffs shows a failed
  agent unit instead of a skipped one, and a host without
  `/usr/bin/mountpoint` (util-linux) cannot start the agent. The watchdog ran `systemctl start`
  on its runtime's only thread, so a busy PID 1 stopped the STATUS ping and
  every timer for up to the D-Bus timeout, and after any stall the ping
  interval fired its missed ticks back to back: "two timeouts 60 s apart"
  could be two pings 2 s apart. The respawn now runs on the blocking pool,
  a stop request is honoured while it runs, missed ping ticks are delayed,
  and the fallback argv no longer re-reads `/proc/<pid>/exe` in a 60 s
  blocking sleep. `cargo xtask rag-kb` parsed what it downloaded or found
  in `--mirror` unchecked, fetched the ATT&CK bundle and licence by tag and
  the DRL licence from `master`, and labelled the commit-pinned Sigma
  tarball `master`. Every input is now fetched by commit and must match a
  pinned SHA-256 before it is parsed, in both modes; `provenance.json`
  records `input_sha256`; a rebuild whose dumps differ from the committed
  anchors writes nothing unless `--update-anchors`. The anchors were
  rebuilt from the verified inputs: the dumps are byte-identical; the Sigma
  `pin` is now its commit, so `kb_index_hash` changed (`4d335aed…` →
  `b6cd7d32…`). `ade_attacks` with `NN_ADE_ALLOW_MOCK=1` and a model that
  did not load scored the mock backend, which never reads the prompt
  (100 %): it now exits non-zero naming the mock, and the report names the
  backend next to the rate.
- External audit, Wave 2, install integrity fails closed (Medium DEP-007,
  DEP-009, DEP-006): `install.sh` stepped its release checks down on its
  own — a tree without `MANIFEST.sha256` installed as a "source tree", so
  removing that one file from an altered release switched every check off.
  A tree without it is now refused unless `--source-tree` is given, and a
  tree vouched for only by its own `MANIFEST.sha256` (no tarball +
  `SHA256SUMS`, no attestation) unless `--allow-manifest-only`; the flag is
  recorded in `install-manifest.json` (`verify_override`), and a new
  `nn-admin host-check` line warns below `checksums` (`package` included).
  At boot a deleted install manifest switched the binary integrity check
  off where an edited one refused the boot: once the signed audit chain
  holds a verified boot of this install, a missing manifest refuses the
  boot too (exit 78, `agent_boot` refused, `NN_ALLOW_UNVERIFIED_BINARY=1`
  for a development host). The upgrade and uninstall drain waited for no
  LSM program at all on the host, so a second BPF-LSM product made them
  give up with the agent already stopped; the agent now lists its own
  program ids in `/run/northnarrow/bpf-own-ids` and the scripts wait for
  exactly those (an agent older than the list: the old count, naming what
  is left). **Regression:** a scripted install from a source tree needs
  `--source-tree` (the lab and the range bootstrap pass it); an extracted
  release without its tarball and `SHA256SUMS` needs `--tarball`/`--sums`
  or `--allow-manifest-only`; a host restored without its install manifest
  does not start until `install.sh` runs again.
- External audit, Wave 2, release trust chain and CI supply chain (Medium
  SUP-001, SUP-002, SUP-005, SUP-017, DEP-008): an attestation check
  accepted any ref, so the artefacts of a `workflow_dispatch` run on a
  branch verified like a release. install.sh (gh and cosign), README, the
  operator guide and the tarball's README-RELEASE now require the release
  workflow at a `v*` tag (`--cert-identity-regex '…release\.yml@refs/tags/v'`,
  `--deny-self-hosted-runners`). Every GitHub action is pinned by commit
  SHA with its version as a comment, and cargo-cyclonedx (which writes the
  attested SBOM) and cargo-fuzz by version; a test fails on a tag-pinned
  action or an unpinned `cargo install`. `.cargo/config.toml` defaults to
  `target-cpu=x86-64-v2`: `native` tied any build copied to another host to
  the build CPU (SIGILL elsewhere) and is now an explicit opt-in. The
  `.rpm` is signed on a tag by its own job with a key from a tag-restricted
  environment, checked against the public key committed at the tag, and
  verified (`rpm -K`) before it is attested; `rpm --import` + `rpm -K` or
  dnf with `localpkg_gpgcheck=1` check it on the host. The `.deb`, which
  dpkg and apt do not verify per file, is checked with the tag-bound
  attestation before `dpkg -i` (operator guide §6.1); `dpkg --verify` and
  `rpm -V` are no longer presented as an integrity check of the package's
  origin. **Regression:** the artefacts of a dispatch run on a branch no
  longer pass install.sh's attestation step (`--require-attestation`
  refuses them); dev, lab and range builds decode with candle at the
  x86-64-v2 ISA unless they opt into native; a tag release fails at
  `rpm-sign` until the maintainer has created the rpm signing key.
- External audit, Wave 2, C code in the agent (Medium MAIN-006): the ADE
  tokenizer split every prompt — strings the observed processes chose —
  with Oniguruma, a C regex library (`onig_sys`), inside the root agent,
  against the no-C rule the same manifest applied to zstd. Asking
  `tokenizers` for `fancy-regex` was not enough: candle-core 0.10 requires
  its `onig` feature, and with both on, tokenizers uses Oniguruma.
  candle-core 0.10.2 is now patched (`vendor/candle-core`: the crates.io
  package, its tokenizers dependency asking for `fancy-regex`) and the
  backend is `fancy-regex` (Rust). A golden test recorded with Oniguruma
  first (Unicode, every whitespace class, long argv, DNS names, an
  ADE-shaped prompt, hostile runs) gives the same pieces and token ids; a
  full prompt tokenizes in about 7.5 ms instead of 6. A CI step fails when
  `onig_sys` or `zstd-sys` enters the agent's dependency graph. AUT-009:
  the rollback-floor residual (a log cut inside a UTF-8 character emptying
  the floor for a boot) was already gone with LLMR-014; two tests pin it.
- External audit, Wave 2, lab and build tooling (Medium SNS-003, EBPF-014):
  the sensor-feasibility runner of lab builds (`--sensor-feasibility`,
  feature `test-privileged`) ran as root on fixed names in world-writable
  directories: it removed and re-created `/var/tmp/nn-feasibility`, wrote
  its fixtures there and copied `/usr/bin/true` to
  `/dev/shm/nn-feasibility-true`, then executed that copy, so a local user
  who prepared those names could have root run their file. Each run now
  works in fresh `mkdtemp` directories (0700, `<base>/nn-feasibility.XXXXXX`
  and `/dev/shm/nn-feasibility.XXXXXX`; `NN_FEASIBILITY_BASE` kept),
  creates every file with `O_CREAT|O_EXCL|O_NOFOLLOW`, checks each file it
  is about to execute (regular, owned by root, the expected link count, a
  named copy writable by root only), and never touches the old names. The
  eBPF build stamp recorded only the source hash, so an object rebuilt
  outside `cargo xtask` from the same sources (other flags, another
  toolchain, an IDE) or replaced after the stamp was embedded as fresh.
  The stamp (`nn-ebpf-buildhash-v2`) now also holds the SHA-256 of the
  object xtask built, and `agent/build.rs` refuses an object whose bytes
  differ. **One forced rebuild:** a stamp written before this change reads
  as absent and the agent build stops on "UNSTAMPED eBPF OBJECT" until
  `cargo xtask build-ebpf` (or `cargo xtask build --release`) runs once.
- External audit, Wave 2, RAG corpus integrity and provenance (Medium
  XAI-001, XAI-009, XAI-002, XAI-010, XAI-018; dormant while
  `NN_ADE_RAG_ENABLED` is off): the RAG canary indexed every `*.jsonl` in
  its directory, unchecked, into the trusted part of the ADE prompt; an
  empty or missing directory gave RAG on the ~36 built-in seed notes,
  logged as "RAG enabled"; and an index on disk was opened whenever its
  marker file, forgeable by whoever could write there, matched. The
  agent now embeds
  `docs/kb-sources/kb_index.json`, which names each canonical dump with its
  SHA-256 (`cargo xtask rag-kb` writes the names), and starts RAG only when
  the directory holds exactly those dumps, byte for byte; otherwise it
  runs without RAG, with a WARN and a signed `subsystem_degraded` naming
  the cause. The index is built in memory at every start (about 0.4 s);
  `NN_ADE_RAG_INDEX_DIR` is ignored with a WARN. The XAI `environment_hash`
  now includes the loaded corpus fingerprint (an empty field with RAG
  off). The Article 13 dossier §8 no longer claims that the signed chain
  commits every retrieved snippet: the prompt carries only the titles and
  Sigma severities, and which documents were retrieved is covered only in
  part until the Tappa 13 log; a new §9 records that the ADE is advisory.
  **Regression:** a knowledge-base update needs an agent release.
- External audit, Wave 2, correlation context and XAI readiness (Medium
  XAI-004, XAI-013, XAI-005, XAI-011): the focal event sat in its own
  correlated context — the agent pushed a copy into the buffer and excluded
  it by address, which never matched — so the model read it twice, once as
  untrusted correlated data. The copy is now excluded (same variant, pid
  and timestamp; the ExecCheck of the same exec stays). About 20 unrelated
  events in the 30 s window (DNS queries) pushed a precursor of the same
  process, parent or file out of what the model saw: up to half of the 20
  correlated slots now go to events sharing a key with the focal one,
  within 5 minutes, before nearby events; an event left out for its
  injection score takes no slot; the 4 KiB block cap and the model-window
  fit drop nearby events before keyed ones. The selection runs on the ADE
  evaluation's task, not on the event loop. XAI (not wired yet): the
  preflight refused every ProcessSpawn with 4 or more correlated events;
  the bounded-K cap now adapts to the budget (20 correlated events: K = 4,
  a Degraded chain) and is recorded in `method.max_units`, and only the
  correlated events the prompt renders are units. An event ADE keeps from
  the model (injection score, a prompt over the window) no longer yields a
  signed "Complete" chain of zero deltas over the hash of an empty prompt:
  it is refused before any probe. **Regression:** the model sees a
  different correlated context (at most 20 events, keyed first).
- External audit, Wave 2, deception content and state (Medium DEC-007,
  DEC-008, DEC-010, DEC-011): what the decoys held told an attacker what
  they were — the credential templates said "Canary credential — DO NOT
  USE. NorthNarrow XDR", used `northnarrow.io` names and
  `NORTHNARROW_API_TOKEN`, a File canary was three comment lines naming the
  product, the operator key and the rule — so one `grep -ri northnarrow`
  found every decoy on every host. The templates are now neutral (no
  comment, Docker Hub and ghcr.io entries, `API_TOKEN`, `azure-cli-<date>`,
  a generated GCP project id) and a File canary holds 512 to 4095 bytes
  derived from its seed. `install.sh` replaces an installed template that
  is byte-identical to the one an earlier release shipped, keeps an edited
  one (with a WARNING if it still names the product) and installs them
  0640 in a 0750 directory; the agent does not use a shipped template of an
  earlier release it still finds. The content was rendered from the
  operator key fingerprint and the path: the fingerprint was printed into
  the azure, gcp and docker decoys and every host got the same credential
  for the same path. Each deploy now draws a random 32-byte seed, recorded
  in the registry with the SHA-256 of the bytes written, and `nn-admin
  canary refresh` writes the decoy again from a new seed (in place, the
  same inode), recorded too; a refresh whose decoy cannot be written or
  watched is refused. At boot each decoy is compared with its record: one
  modified, removed or replaced (a link, a FIFO) while the agent was down
  used to be re-armed in silence; it is now an ERROR and, when its state
  changed, a signed `integrity_drift` (`canary_decoy_tampered` or
  `canary_decoy_missing`) and a `decoy_check` row that `nn-admin canary
  list` shows; only a regular file is watched. A trip lived in memory only:
  every restart re-armed the response for a canary already tripped. It is
  now a signed `trip` row naming the access row (that hash was always
  empty), read back at boot. **Regression:** a tripped canary stays tripped
  (recorded, not responded to) across restarts until `nn-admin canary
  refresh`, as the design's manual refresh intends. Decoys deployed before
  keep their content, which names the product, and cannot be checked
  beyond their presence (a WARN at boot): refresh them, or burn and
  deploy again. Reading a decoy trips it: `nn-admin canary list` is the
  inventory. An older agent (downgrade) skips `trip` and `decoy_check`
  rows as unreadable, re-arms tripped canaries, and chains its next row
  to the last row it could read, which an off-host check of the registry
  then reports as broken.
- External audit, Wave 2, DNS attribution identity (Medium NET-016,
  NET-006): a connect took the last name its PID had asked for in the
  past 300 s, whoever held the PID then. A process that inherited the PID
  of one that resolved a `.onion` name — and that resolves through
  Varlink, or connects to a bare address — was recorded in the signed
  netflow row with that name and killed by NN-L-NET-002. The connect pump
  now reads the connecting process's start (the exec's from the spawn
  cache, else `/proc` less the host's suspended time), the row carries it
  (`proc_start_ns`), and only the queries made since count. A forwarded
  DNS leg went to the newest PID that had sent the same name, compared
  case-sensitively and wherever it was sent: a process could choose whom
  NN-L-NET-014's kill named. The originator must now have asked a loopback
  stub resolver, the name matches ignoring case, and two such processes
  are an ambiguous attribution — logged, not acted on.
- External audit, Wave 2, netflow drain throughput and honest coverage
  (Medium NET-019, NET-012, NET-009): every TCP close was written to
  `netflow.jsonl` with its own fsync and handed to the rules before the
  next record was read, so one user's loop of short connections made the
  kernel drop closes, other users' among them. Rows are now committed
  together, one fsync at most every 100 ms (a crash of the host can lose
  the last 100 ms, or tear the last row, which the next open cuts and
  attests); the listener log too. The rows handed to the rules are paced
  per uid (1,000, then 200 a second); a row held back is still written,
  with `"decision_engine_skipped": true`, and is never one a killing rule
  could match (NN-L-NET-001, -002, -003, -008, -010, -018) or one of a
  process with a chain precursor, which keeps NN-L-CHAIN-* complete. The
  flow tracker scanned up to 65,536 pending connects on every close and,
  when full, evicted the oldest — the long session; a close is now O(1)
  and the eviction takes the oldest connect of the process holding the
  most, and a row built at close names its executable. No sensor
  produces TLS fingerprints yet (BUG-025): a JA3 list with entries is now
  an ERROR and a signed `subsystem_degraded` at boot instead of silent
  coverage, the shipped `netflow-ja3-blocklist.v1` says NN-L-NET-003 is
  inactive, and the new `nn-admin net status` shows the rows held back,
  the evictions, the network rings' drops and the inactive rules.
- External audit, Wave 2, posture scope and exemptions (Medium POS-005,
  POS-015, POS-009): every process without a login uid — each service,
  each container, a process already gone — shared one corroboration
  scope, and with it the lock: puppet or salt rewriting a unit file locked
  a COMBAT that any other service or container then corroborated. Such a
  process is now scoped by the systemd unit or container its cgroup names
  (read, for an event that raised a trigger, from the process or its
  nearest running ancestor); a signal that cannot be placed is recorded
  but corroborates nothing and locks nothing, and root's change locks
  COMBAT only when its own actor's evidence pairs with it. One exec from
  `/tmp`, `/var/tmp` or `/dev/shm` was a COMBAT-tier signal: a build's
  `conftest`, then an upload from the same session, reached COMBAT. It now
  raises `StagingExec` (ENGAGED, never corroboration), and
  `ConfirmedIntrusion` only when the file was unlinked or a memfd as it
  ran, or the same process crossed the mass-write threshold within a
  minute — never under a package manager. The watchdog's exemption from
  posture triggers was a PID compare refreshed every 30 s: it now ends
  with the process verified (its start time), and a kernel denial from the
  watchdog's PID is raised; the agent's own PID stays exempt.
  **Detection change:** a plain staged binary followed by another signal
  from the same session stays at ENGAGED (R001..R003 still kill the
  exec). Scoping login sessions by workload too waits for the
  workload-context design (steps 1–2).
- External audit, Wave 2, open-sensor path and classification fidelity
  (Medium SNS-005, SNS-006, SNS-007, EBPF-011): a writer that forked a
  fresh worker every few files never reached the mass-write threshold,
  which was counted per process. A second window per cgroup
  counts overwrites (existing files of 4 KiB or more) of processes that
  rewrote at least three, with a threshold of 40 a minute; its crossing is
  file-system evidence that needs corroboration, and a build (one process
  per output) never enters it. The classification walk goes 16 directories
  up (was 8) and says when it stopped short. A path under a filesystem
  root the agent cannot place reads `mnt[<dev>:<ino>]/…` instead of a host
  path, a path component cut at 31 bytes ends in `…` and an unreadable one
  is `?`; for such paths the posture uses the kernel's class of the file,
  so a kernel-classed write there no longer goes unnoticed. The open
  sensor's rules are written past a full map — stale rules removed first,
  the posture's own paths before homes and runtime directories, the cache
  generation always bumped — with an ERROR and one signed
  `subsystem_degraded` when some do not fit; the maps hold 4096 inode
  rules (was 1024). The sensor's program now verifies on 5.15 in about
  460,000 instructions (was 834,000): the record writer and the counts are
  global BPF functions.
- External audit, Wave 2, process and canary rule coverage (Medium
  PROC-009, PROC-010, PROC-008, NETR-006): the first rule to match wins,
  and records ran ahead of kills — a shell in a hidden home directory was
  recorded, not killed; a staging-dir process reaching port 21 or an
  internal host was recorded; a DNS tunnel with names over 60 characters
  never reached its kill. Every rule that kills now comes first, and the
  specific tool rules come before the staging ones: `/tmp/insmod` is R011
  (High, T1547.006), not R001 (Medium). R007 killed the tree of any
  process whose name contained a miner's (`xmrig-cleanup`), and R006
  every `socat`, the distribution's included: both take the process
  allowlist; R007 kills an exact miner name (in the process name or the
  executed file's) and records a name that only contains one; R006
  records the distribution's `socat` unless it runs a shell. The shipped
  process allowlist names package managers and configuration management,
  but the rules judged only the program run, so it never applied: a root
  exec of a system-tree tool under one of them (DKMS running `modprobe`
  under apt) is now recorded, not killed. A canary accessed in a way its
  type does not expect — a File decoy's path executed — got no verdict
  and was burned; any access now answers. **Regression:** rule ids and
  severities change for these cases, a miner renamed `xmrig-something`
  and the distribution's `socat` relaying to anything but a shell are only
  recorded, and the engine holds R007 twice (73 rules, 72 ids).
- External audit, Wave 2, admin read verbs (Medium ASK-006, ASK-007,
  ASK-008): `fim report`, `net flows` and `canary list` read the active
  file from its start and stopped at half a frame, so past about fifty rows
  they answered with the OLDEST rows, and no verb opened a rotated archive:
  a flood of connections from any user hid the newest flows from
  `net flows`. They now answer the newest rows first, from the active file
  then the archives, within the same budget; `truncated` means older rows
  were left out. The read is bounded per file and per request and opens
  only regular files, without following a symlink. `fim report` and
  `net flows` read the built-in paths whatever `--fim-drift-file` and
  `--netflow-file` said; they read the configured files now.
  `net listeners`, `net fingerprint` and `net resolve` answered Success with
  nothing, without reading anything: `net listeners` lists the listener log
  (listen events, not a snapshot of open sockets), `net fingerprint` the
  netflow rows of that flow (`ja3`/`ja4`/`sni` null: the TLS capture is not
  wired yet), `net resolve` the hostname of the newest retained flow to
  that address; a malformed address or flow id is refused. **Regression:**
  `fim report`, `canary list`, `net flows` and `net listeners` print the
  newest row first — a script that read the first line as the oldest must
  read the last.
- External audit, Wave 2, inputs trusted but forgeable (Medium ATP-010,
  ATP-005, SNS-002): the tracepoint field offsets came from whatever was
  mounted at `/sys/kernel/tracing` — a tmpfs over it, or a file bound over
  one `format`, chose where the exec, open and io_uring tracepoint sensors
  read, silently. A root and each file are now used only on tracefs; a
  field must have the width the sensor reads, lie past the common header
  and end within 512 bytes; a field missing from the io_uring submit event
  now tries its other name. A field left on its compiled offset is a
  signed `subsystem_degraded`, and a mount over or under the tracefs roots
  a signed `integrity_drift` (`tracefs_mount`). The COMBAT carve-out took
  any prefix: `10.0.0.0/0`, a typo for `/8`, spared every address and
  COMBAT isolated nothing. A line wider than /8 (IPv4) or /48 (IPv6), or
  naming the unspecified or a multicast address, is now skipped with a
  WARN and refused by `config overlay set|sign`; with the overlay gate, a
  carve-out file missing at a check is no longer read unsigned a moment
  later. **Regression:** a signed carve-out with such a line loses that
  line at the next COMBAT engage; `nn-admin config overlay status` names
  it. A `.` inside a DNS label read as a separator, so one label passed for
  several or spelled a well-known host: query names now use RFC 4343
  escapes (`\046`, `\092`, `\DDD` for unprintable bytes, which were all
  `?`); ordinary names are unchanged.
- External audit, Wave 2, FIM watch set (Medium FIMP-007, FIMP-008,
  FIMP-010, FIMP-009): the FIM drain's retry queues had no cap and no
  de-duplication, and their pass (one `stat` per entry, under a lock, on a
  runtime worker) ran after every emitted event, so a burst of short-lived
  files in a watched directory slowed the only reader of the FIM ring
  quadratically. Each queue now holds one entry per path or inode, at most
  1024 (the rest counted), and the pass runs at most every 5 ms, off the
  runtime's threads. Files enrolled at runtime were never let go, and a
  full `WATCHED_PATHS` refused every new watch with a WARN: a canary
  deploy still answered Success and its decoy never tripped. Runtime
  children are now capped at 4096, oldest out, swept every minute once
  their file is gone; a full map makes room by evicting them, never a
  configured path, a symlink hop or a decoy; an eviction or a refusal is an
  ERROR and a signed `subsystem_degraded` (`fim_watch_map_full`, at most
  once an hour), and a canary whose decoy cannot be watched is refused. A
  watched symlink was watched by the link's inode only: an in-place change
  of the file behind it (`/usr/bin/python3` to `python3.12`) or a
  re-pointed `/etc/alternatives/nc` touched no watched inode. Each link (at
  most 8, a loop refused) and the final target are now watched under the
  configured path, a change there is checked against that path's baseline
  once it has landed, and the baseline row records the canonical target.
  A write on a path a Critical rule guards whose re-hash found the
  baseline content (a change undone before the drain looked) left no
  trace; it is now a drift row flagged `content_restored`, without a
  verdict.
- External audit, Wave 2, ADE window, prefill, failure evidence, prompt
  (Medium LLMR-008, LLMR-017, LLMR-003, LLMP-013): an over-long prompt
  lost its head, which is the system prompt; the engine now drops the
  oldest correlated events to fit the model window, never the system
  prompt, and escalates an event whose prompt cannot fit. The prefill
  runs in 256-token chunks and stops at the time budget. A timeout or a
  backend error is recorded as an Escalate (`ade_unavailable`) instead of
  a journal line. The system prompt (v1.1) says that observed strings are
  evidence, never instructions, and its few-shot examples, three instead
  of five, decide on behaviour in the format the agent sends.
- External audit, Wave 2, ADE sanitizer score and coherence matrix
  (Medium LLMP-003, LLMP-011, LLMR-010, LLMP-004, LLMP-006): every event
  string was scored twice and before deduplication, and the keyword
  matchers were too broad, so one DNS lookup of `admin.<domain>`, a
  systemd `override.conf`, `react-assets` or a path in Russian forced an
  Escalate (or skipped the model). Each string is now scored once on the
  deduplicated flags, and one strong signal (a chat-template token, an
  explicit "ignore previous instructions" or role switch) still forces an
  Escalate on its own; `system`, `admin` and `override` are no longer
  separator variants (their hostile forms stay keywords), the product's
  own names raise nothing, and `act as` matches whole words only. A high
  injection score now overrides any verdict but Escalate (a hostile
  correlated string could sit behind a Kill), and a severe indicator with
  an Allow is escalated; a correlated event too hostile for the prompt
  still weighs. The prompt no longer echoes decoded ROT13 text,
  and a confidence or novelty outside [0, 1] is a parse error (a Kill at
  confidence 5.00 ran).
- External audit, Wave 2, signed evidence logs (Medium EVD-004,
  EVD-018): one forged line at the end of a signed log (detections,
  status, FIM drift, NetFlow) could force a spurious rotation and then
  make every later append fail, at every boot; a forged line in its
  manifest kept the log from opening. A file planted at the next archive
  name made the next rotation erase the sealed file. Tail lines are now
  checked (format, hash, signature) before the chain continues from them;
  a bad one is cut and recorded in the signed manifest. A rotation never
  replaces or truncates an existing file: it moves to the next free name
  and records the foreign entry.
- External audit, Wave 2, self-integrity and detection-store evidence
  (Medium EVD-013, EVD-012, EVD-006): a drop-in reported once, removed and
  put back identically was never reported again. The self-integrity check
  now records a finding that goes away (`integrity_drift_cleared`, signed)
  and reports it again when it comes back (at most once per 10 minutes,
  with the count), capped at 64 findings per kind per round. Limits that
  appear or vanish are drift, the agent's cgroup is checked, and when the
  agent runs as its unit the first round compares the limits with the
  unit's values (`limit_unexpected`), so a limit changed in the first 15 s
  is no longer taken as normal. A full detection queue drops the lowest
  severity logged-only record first, and drops are recorded in a signed
  `detections_dropped` audit entry per minute.
- External audit, Wave 2, kernel telemetry loss (Medium EBPF-009,
  EBPF-013): holding 4096 watched files open for write filled the FIM
  write-marker map, and the next in-place rewrite of a watched file left
  no `Modified` event and no counter. The map now matches the watch set
  and a refused marker is counted (`fim_dirty_full`). An unprivileged loop
  of `listen()` or `io_uring_setup()` could push other processes' listener
  and ring-creation records out of their ring: both now have DNS's
  per-process and per-user record budgets (64, then 128/s per process),
  the excess is counted (`listen_rate`, `io_uring_rate`) and carried by
  the process's next record, and the new NN-L-NET-021 names the process
  that floods.
- External audit, Wave 2, telemetry loss (Medium SNS-001, SNS-008,
  SNS-009): a ring-buffer pump that died went unnoticed — the agent kept
  running blind on that sensor. Every telemetry task is now watched: one
  that ends is recorded in the signed audit log, the agent stops
  (`sensor_pump_exited`, non-zero exit) and the watchdog restarts it.
  Malformed records of the open sensor are counted and shown by `nn-admin
  status` (`ringbuf rejected`), like every other ring's. A security ring
  losing more than 64 events in 10 s raises the posture to ALERTED
  (`TelemetryLoss`, never corroboration for COMBAT; not during a package
  transaction or a trusted-installer window), and an unreadable drop
  counter keeps its last value instead of reading as zero.
- A build rewriting its own outputs (`cargo build`: fingerprints,
  timestamps, `.d` files) was counted as encryption in place: with another
  alert in the session it reached COMBAT, which killed cargo and
  quarantined `cargo` and `rustc`. An overwrite counts only for an existing
  file of at least 4 KiB (its size read at open).
- External audit, Wave 2, network rule state and addressing (Medium
  NETR-005, NETR-007, NETR-008): NN-L-NET-008 (outbound from a staged
  binary) never fired — no flow row carried the process's executable. The
  image is now named at connect time (lineage cache, `/proc` as fallback,
  a deleted image included), so a dropper's forked child that never execs
  is killed when it calls out; NET-008, CHAIN-002/005/007 and the posture's
  exec arm share one staging set (`/tmp`, `/var/tmp`, `/dev/shm`), with a
  package transaction's processes recorded, not killed. NN-L-NET-007/018
  treat IPv6 unique-local and link-local peers as internal: SMB, RDP, WinRM
  or VNC over them now draws the same verdict as over RFC 1918. The DNS
  burst, beacon and DNS-tunnel windows have hard caps in O(1) per event —
  before, a connection or DNS spray by any user grew them for up to an hour
  with a full scan per event, and a spray of 4096 parent domains switched
  off NN-L-NET-014's tunnel kill for every other process. At a cap the
  least recently updated key goes (a beacon's or a tunnel's keys last),
  counted and warned about; a process reaching more than 256 destinations
  in an hour is held to its own quota.
- External audit, Wave 2, bounded correlation state (Medium NETR-004,
  NETR-009, NETR-010): the chain rules' correlation store now holds a hard
  cap of 4096 processes in O(1) per insert — before, every new process above
  it cost a full scan under the engine's lock, so any user could stall the
  rule engine with a loop of execs. Processes holding only a `sudo`/`su`
  precursor are evicted first; losing a blocking chain's precursor is
  counted and warned about. Precursors and lineage now follow the process
  incarnation (its start time), so a process that inherits a recycled PID no
  longer inherits the old holder's precursors or ancestors (a wrong
  `KillProcessTree`). The ancestry tree keeps live processes under a flood
  of short-lived ones (second-chance eviction against `/proc`, 65,536
  edges), and counts and warns when it must drop a live one.
- A TCP flow closed abortively (RST, `SO_LINGER` 0) was recorded with
  source port 0: the close probe read the port after the kernel had
  released it. It now falls back to the socket's `inet_sport` (a new
  BTF-revalidated offset).
- External audit, Wave 2, undoing a response (Medium CMB-016, Low CMB-026):
  three signed admin verbs, run by the agent and recorded in the signed
  audit log. `nn-admin response status` (`audit-read`) lists the contained
  processes, the quarantine vault and the COMBAT stage; `response release
  --pid` and `response restore --vault-id [--to]` need the new
  `response-manage` role, never granted by default. A release goes back to
  the cgroup the process came from, by the containment record; a restore
  checks the vault id (32 hex digits) and the SHA-256 recorded at capture,
  creates a new file (mode 0600, never over an existing file or through a
  link, never under a protected prefix, the directory must exist) and keeps
  the vault entry — before, restore took any id as a path fragment and
  overwrote whatever the destination named. `nn-admin status` shows the
  COMBAT stage and whether COMBAT is locked.
- External audit, Wave 2, containment state and recovery (Medium CMB-010,
  CMB-017, CMB-013, CMB-015): a released process goes back to its systemd
  unit (recorded when it was contained), never to the root cgroup — before,
  it left its unit's accounting and limits for good; an agent restart
  reconciles the record. A corrupt quarantine index is rebuilt from the vault instead of
  being replaced by an empty one, and every quarantine, containment and
  release is in the signed audit log. The throttle reports the limits it
  actually set and does not move a process when it could set none. The
  carve-out docs describe IPv6 isolation as it is.
- External audit, Wave 2, process identity in kills (Medium CMB-004,
  CMB-019): a kill could reach a process that had taken the PID of an
  offender since it was attributed; the COMBAT ladder and the rule and ADE
  verdicts now capture the process (a pidfd and its start time, checked
  against what the event says about it) and signal it through the pidfd. A tree that keeps forking is no longer killed from a
  one-time snapshot that misses its new children: it is moved into a
  cgroup of its own, frozen and killed as a whole. The agent raises its
  open-files limit at start (a large episode holds one pidfd per offender).
- External audit, Wave 2, the COMBAT ladder's execution model (Medium
  CMB-007, CMB-011, CMB-012, CMB-014; CMB-010 stop-gap): the ladder's side
  effects — `nft`, cgroup writes, kills, quarantine, iptables — ran on the
  event loop, so no sensor event was read while a large tree was
  neutralized; they now run in order on a worker thread. A stand-down waits
  for a step already under way, so an isolation decided just before an
  admin unlock no longer lands after the release. A forking offender costs
  one `nft` run per episode, and a tree past 1 024 processes escalates. A
  soft egress block that did not take effect (no `nft`) is recorded and
  shortens INVESTIGATE to 10 s; `nn-admin host-check` reports a host
  without `nft`. The stand-down releases only processes it blocked and
  that are still the same process in the blocked scope.
- External audit, Wave 2, the variables that weaken the agent (Medium
  MAIN-008, MAIN-004, MAIN-007): `NN_DETECT_ONLY=yes` (or `true`) switched
  the response off without the integrity finding `=1` gets, and detect-only
  also let the agent run without a writable audit log — the audit gate now
  needs its own override (`NN_AUDIT_ALLOW_UNWRITABLE=1`), and `agent_boot`
  records where detect-only came from. The evidence logs' rotation caps
  read from the environment have a 1 MiB floor and every override is
  logged and reported; the mock ADE backend and a telemetry probe switched
  off or thinned out are reported too. A drain loop that ends is an ERROR
  and a signed `subsystem_degraded` record.
- External audit, Wave 2, the overlays' rollback floor (Medium LLMR-014):
  the newest accepted signature of each overlay was read from `audit.log`
  as plain JSON, and a missing log gave no floor — removing the log
  offline brought a retired, once legitimately signed exemption back. The
  floor now comes from the chain the agent verifies, anchored so that a
  boot checks only the new entries; a log that is gone or does not verify
  resets it, recorded in the signed chain: no overlay signed before the
  reset is loaded until it is signed again.
- External audit, Wave 2, the signed overlays (Medium LLMR-013, LLMR-016):
  what the agent applies is the overlay it verified — the loaders, and
  COMBAT at every engage, read the file a second time, so a root process
  able to pause the agent's reads could get unsigned content applied. An
  overlay is no longer read through a link, and a FIFO in its place no
  longer stops the agent's boot. A shipped default list that cannot be
  read gives way to the copy built into the agent, recorded in the signed
  audit log.
- External audit, Wave 2, the admin key files (Medium AUT-003, AUT-004,
  MAIN-005, AUT-002): a link planted in `/etc/northnarrow` no longer makes
  the agent write through it when it replaces `admin.pub` or a signed
  overlay — a key rotation could truncate the audit log. A malformed line
  in `admin.pub` costs its own key, recorded, instead of the admin socket.
  `nn-admin verify-keys` accepts the `admin.pub` install.sh writes and
  shows each key's roles; the CLI refuses an admin private key others can
  read.
- External audit, Wave 2, the trusted-installer window (Medium ATP-003,
  ATP-012): the window ends at its deadline in the kernel itself — before,
  a host whose events had stopped kept every protected file, the kexec
  refusal and the pin root's protection open until something reached the
  agent. The agent closes and records it on time, and a close that failed
  is recorded as failed.
- External audit, Wave 2, the filesystem deny (Medium EBPF-008, ATP-008):
  root could clear the immutable flag of the state directory, or make
  `audit.log` append-only to the agent, through the fsxattr interface
  (`xfs_io -c 'chattr -i'`): the deny let it through, and the number it
  held for that ioctl was none. The shipped `.v1` lists (the netflow and
  JA3 blocklists, the comm allowlists) can no longer be appended to; they
  are tuned through their signed `.local` overlays.
- External audit, Wave 2, the BPF guard (Medium ATP-013, ATP-009,
  EBPF-004): the agent's ring buffers and drop counters are guarded like
  its other maps — a root process could take a writable handle on each,
  enough to silence a sensor, the anti-tamper denials included. The
  kernel-offset table is frozen once armed. A production agent whose
  guard only observes counts it as a missing deny hook, and the signed
  boot entry records the build's test features and the guard's mode.
- External audit, Wave 2, file integrity (Medium TST-004, FIMR-007, FIMR-008,
  FIMR-009, FIMP-011): a change of a watched file's permissions, owner or
  group is drift of its own — a set-uid bit, or write for others, on a
  system binary is treated as a rewrite of it; `chmod o+r /etc/shadow` as
  a change of it. sshd's `.ssh/authorized_keys2` and
  `/etc/ssh/authorized_keys` are judged like `.ssh/authorized_keys`. The
  control-surface files the agent re-creates at boot are watched at once
  (after a reboot the runtime ones were not), restored without following
  a link, and a removal within one boot is recorded in the signed audit
  log. File monitoring that attached nothing is recorded there too.
- External audit, Wave 1, kernel module loads (High PROC-005): a module file
  under /lib/modules that no package installed and DKMS did not build is no
  longer "standard": loaded by an unexpected loader it is killed like one
  from /tmp. A module on another mount is placed on its mount point (it
  could pass for /lib/modules), and a path component that is not UTF-8 no
  longer disappears.
- External audit, Wave 1, the tracepoint fallback (High POS-004): when the
  file-open sensor runs on the `openat` tracepoint, an open's path is the
  caller's own string, read before any permission check. A refused open of
  a persistence or critical path no longer counts as a COMBAT-tier signal
  (it alerts), and a path through `/proc/self/cwd` or `..` no longer
  escapes the mass-write count.
- External audit, Wave 2, the advisory gate (Medium SUP-006): `cargo audit`
  checks every lockfile — the fuzz harness and the eBPF crate were never
  audited — and runs as a plain step with a read-only token; the action it
  replaces failed pull requests that had found nothing.
- External audit, Wave 1, the evidence signing key (High EVD-001): the
  agent's private signing key can no longer be read by root (or anyone
  outside the agent); its public half is published at
  `/etc/northnarrow/agent.sig.pub`, which `nn-admin audit verify` reads.
  **Note:** a backup of `/etc` gets `EPERM` on `agent.sig.key` (recorded,
  ALERTED); the key is not meant to leave the host.
- External audit, Wave 1, the release pipeline (High SUP-003): building and
  signing are separate jobs. The job that compiles the dependency tree has
  a read-only token, not persisted, and cannot request the signing token;
  the job that attests and publishes compiles nothing.
- External audit, Wave 1, the ADE model (High LLMR-004): the model and its
  tokenizer are loaded only when root owns them and every directory above
  them, closed to others; the default location moved from a user's home to
  `/var/lib/northnarrow/models/`. **Upgrade note:** move a model kept
  elsewhere there (or pass `--ade-model` to a root-owned location), or the
  agent runs on its rules alone. The ADE's system prompt is built into the
  agent (an installed agent never found the relative path it read). A model
  that fails to load leaves the ADE off instead of falling back to the mock
  backend, which judged by process names (LLMR-005); `NN_ADE_ALLOW_MOCK=1`
  brings the mock back for demos.
  agent (an installed agent never found the relative path it read).
  agent runs on its rules alone.
- External audit, Wave 1, DNS (High NET-004, EBPF-006): the cache of recent
  DNS queries is bounded in total (about 20 MiB at worst; it could grow
  past a gigabyte); a flood evicts the flooder's queries first. The DNS
  sensor's degraded mode (query names read from the sender's memory, on
  kernels where the socket-buffer programs cannot attach) is recorded in
  the signed audit log.
- External audit, Wave 1, a second network isolation (High CMB-006): an ADE
  `Isolate` verdict no longer cuts the host off the network through an
  nftables blackout of its own (no management carve-out, no release, not
  in `status`). Host-wide isolation is the COMBAT ladder's alone; the
  verdict kills the process tree it names. An older agent's leftover
  chains are removed at start.
- External audit, Wave 1, file integrity (High FIMR-004, FIMR-005,
  FIMP-003, FIMP-004):
  - A watched file replaced by renaming another over it (how installers
    and rootkits swap a binary, a PAM module, a unit) is now judged like a
    modification: the new file checked against the baseline, attributed to
    the process that renamed it. Before, only the rename was recorded.
  - A change to a path a Critical rule guards (system binaries, kernel
    and PAM modules, `ld.so.preload`, the baits) is never throttled.
  - One large watched file can no longer stall the FIM pipeline: a burst
    of changes to a 256 MiB file used to block the agent until the
    watchdog killed and restarted it, losing other files' changes.
  - A path added to the signed `fim-paths` overlay and re-baselined with
    `nn-admin fim baseline` is watched at once, without a restart.
- External audit, Wave 1, posture lineage (High POS-002, POS-003):
  - Ransomware run from an SSH, desktop or cron session no longer goes
    unseen: every process of a session was exempt from the mass-write
    trigger. A session's new files (a build, a clone, an archive, a
    browser's cache) still do not count; its rewrites of existing files —
    encryption in place, told apart by the kernel — do. A credential-file
    read is exempt only for the authentication program itself (sudo, su,
    unix_chkpwd, …) or its direct child, not for the whole session.
  - A process can no longer borrow sudo's (or a package manager's)
    exemption by forking its payload and then executing sudo, which needs
    no password to be seen, nor through the pid of an exited parent: an
    ancestor counts only if it ran the program before the process below
    it was forked.
- External audit, Wave 1, the quarantine (High CMB-001):
  - The agent vaults and removes the file a process ran — held open from
    `/proc/<pid>/exe`, removed only after the name is checked to still be
    that inode — never whatever its path leads to by the time the
    quarantine runs. A user could swap a directory of their own binary's
    path for a symlink and have the agent (root) delete any file.
  - Found in the lab: on a fresh install no quarantine completed — the
    vault directory was created on first use, inside the immutable state
    directory (EPERM). The agent now creates it at start.
- External audit, Wave 1, canaries (High DEC-004, DEC-005):
  - A canary kills on its first access only; later accesses are recorded
    (every access stays in the signed canary access chain). Before, every
    read of a tripped canary killed again.
  - A File or Credential canary read by a backup, anti-malware, indexing or
    sync program (restic, borg, clamd, tracker, syncthing, …: told by the
    executable the kernel ran) is recorded, not killed. A backup that runs
    a generic tool (`tar`, `rsync`) is added by the operator in the new
    signed overlay `canary-readers.local`.
- External audit, Wave 1, the agent's BPF links (High EBPF-010):
  - Detaching or replacing one of the agent's links is refused to any
    process but the agent and the watchdog, by the link the fd names —
    however the handle was obtained. The supported kernels refused both on
    the agent's link types already (EOPNOTSUPP / EINVAL in the lab); the
    agent no longer depends on it.
  - A link handle through a pin path padded past the hook's buffer is
    denied like the plain path (it went through in enforce mode).
  - Pin names are matched by a hash of the path's final component: the
    previous byte-by-byte key made the `bpf()` observer fail the kernel's
    verifier once the deny was added (it would have run without it).
- External audit, Wave 1, kills on everyday shapes (High FIMR-006, NETR-002):
  - A file created in a watched directory under `/home` (or `/tmp`,
    `/var/tmp`, `/dev/shm`) no longer kills the process tree and moves the
    host to COMBAT (NN-L-FIM-002): it is recorded. A watched binary
    hardlinked there is still killed.
  - Resolving a long DNS name no longer kills the resolving process
    (NN-L-NET-004 and NN-L-NET-014 — S3 buckets, CDN, load balancers,
    Kubernetes names): a name over 60 characters, or one high-entropy
    label, is recorded. The kill is for a tunnel's shape: 8 distinct
    high-entropy labels under one parent domain from one process within a
    minute.
    (NN-L-NET-004 — S3 buckets, CDN, load balancers, Kubernetes names): a
    name over 60 characters is recorded; encoded labels stay NN-L-NET-014's.
- External audit, Wave 1, the bootstrap admin key as a standing bypass (High
  DEP-001):
  - The package hooks no longer pick up the admin key left on the host on
    their own: an upgrade or removal opens the trusted-installer window only
    with the key in `NN_GRANT_KEY` (or one the operator opened first).
    Before, every `apt upgrade` suspended the anti-tamper with
    `/etc/northnarrow/admin.key` if it was still there.
  - A fresh install writes the bootstrap private key to
    `/root/northnarrow-admin.key` (`--admin-key-out` to choose; never under
    `/etc/northnarrow` or `/var/lib/northnarrow`, where backups, etckeeper
    and tooling would pick it up). `uninstall.sh --purge` removes it.
  - While an admin private key sits at either location, `nn-admin
    host-check` reports `WARN admin_key` and the agent records
    `admin_key_on_host` in the signed audit chain (`integrity_drift`).
- External audit, Wave 1, the agent's own binaries as a way around the BPF
  self-defence (High EBPF-002):
  - The guard on the agent's maps and links exempted any process running
    one of the agent's executables (agent, watchdog, `nn-admin`). Root could
    preload its own library into one of them: in the lab, `nn-admin`, a
    second agent and a second watchdog each got a write handle on
    `PROTECTED_PIDS` and a handle on the task_kill hook's link (enough to
    detach it). Now only the successor of an agent or a watchdog that
    exited may open the maps before it is a protected pid — while no live
    process holds that role (tracked in the kernel: the slot empties when
    the process exits), from its main thread, in its first minute. No
    process gets a link handle, `nn-admin` is not exempt at all, and a
    process running the agent's or the watchdog's binary cannot be ptraced
    before it registers.
  - The agent no longer protects a second watchdog that the pidfile names
    while the registered one still runs.
- External audit, Wave 1, systemd as a way around the anti-tamper (High
  EBPF-001):
  - The task_kill hook let PID 1 deliver any signal to the agent and the
    watchdog for the agent's whole life (BUG-010's `KILL_OVERRIDE`, armed
    at boot). systemd only relays root's request: `systemctl stop` of both
    units ended them in 0.6 s and nothing respawned them, `systemctl kill
    -s SIGKILL` killed the agent. PID 1 now passes only under a grant the
    agent writes when a signed trusted-installer window opens — the stop
    signals, until the window ends, under this boot's session nonce — or
    as `systemd-shutdown`, the last stage of a shutdown, recognised by its
    comm and its executable.
  - The units refuse a manual stop (`RefuseManualStop=yes`; without it
    systemd ignored the EPERM and reported the units dead while they ran)
    and never start a second instance beside a running one
    (`SendSIGKILL=no`). Maintenance takes the window and `systemctl kill
    -s SIGTERM`; `install.sh`, `uninstall.sh` and the lab do so.
  - A refused signal relayed by systemd is a signed detection (NN-L-AT-001,
    "on behalf of a `systemctl stop` / `kill` / `restart`") and raises the
    posture to ENGAGED (`RelayedTamperAttempt`), not COMBAT: init is never
    an offender (in the lab, the first refused `systemctl kill` made init
    the offender, which the ladder could only contain by isolating the
    host). While systemd reports the host as stopping — asked over its
    private socket, served by PID 1 — the refusal is expected, the ladder
    stands down and the posture stops escalating; the agent runs, and
    detects, until `systemd-shutdown`, and records `agent_stop` with reason
    `system_shutdown`.
- Found while verifying it in the lab:
  - Stopping `systemd-journald@northnarrow` aborted both the agent and the
    watchdog (the log writer reported the broken pipe with an `eprintln!`
    that panicked, and `panic = "abort"`), so every reboot ended the agent
    with SIGABRT and five stops in a minute would have tripped the
    watchdog's ceiling. A lost log line no longer costs the process.
  - The mass-write counter (the ransomware shape) counted write-opens of
    device nodes: `> /dev/null` in a script loop, systemd writing
    `/dev/console` at shutdown. It counts regular files only (files in
    `/dev/shm` still count).
- External audit, Wave 1, bootstrap gate and unit drop-in (High ATP-004,
  DEP-002):
  - The one-time relaxation that lets a one-key install add its second
    key with one signature (`rotate-keys add`, BUG-013) was decided on
    files root can write: `admin.pub` as it read at the request, a
    sentinel, and the install nonce the sentinel is computed from. After
    a second key was added, a root process could show the agent a
    one-key `admin.pub` again — rewritten before a restart, or
    bind-mounted over the file while it ran — with a sentinel recomputed
    from the readable nonce, and add a key of its own with one
    signature. The gate now counts the keys the agent has loaded, not the
    file, and is closed for good once the signed audit chain records a
    successful `rotate-keys add`.
  - `install.sh`'s Debian drop-in
    (`northnarrow-agent.service.d/10-debian-perf-paranoid.conf`) was
    neither protected nor checked: the integrity check skipped it by
    path. A root process could add `ExecStart=`, `Condition…=` or
    `Environment=` lines to it and stop or weaken the agent at its next
    start, unreported. The drop-in directory and file join the protected
    binary/unit set (writes, unlink and rename denied); the content ships
    as `deploy/systemd/10-debian-perf-paranoid.conf`, and the integrity
    check passes the drop-in only while it matches that file byte for
    byte.
- External audit, Wave 1, COMBAT rulesets (High ATP-001, DEP-003): the
  files that decide what COMBAT isolates — `combat-rules.v4`,
  `combat-rules.v6` and the management carve-out `combat-allow.cidrs` —
  were protected by file permissions only, re-read at every isolation and
  never signed. A root process could rewrite the rulesets so COMBAT dropped
  nothing, delete them so isolation failed, or add its own network to the
  carve-out, while the agent still logged "network isolated".
  - They are now applied only as shipped (the content the agent was built
    with) or with an admin signature (`config-manage`) for their exact
    content — the signed-overlay mechanism, with three new kinds
    (`combat-rules-v4`, `combat-rules-v6`, `combat-allow`). Anything else,
    or a missing file, makes COMBAT apply the built-in content; the
    refusal is an ERROR and a signed `integrity_drift` entry.
  - A signed ruleset must still isolate (filter table, the COMBAT chain and
    its DROP, the INPUT and OUTPUT jumps, COMMIT); a signed carve-out must
    parse whole.
  - The files and their signatures join the protected `/etc/northnarrow`
    set (unlink, rename and attribute changes denied), and the periodic
    integrity check reports one that differs from the shipped content
    without a signature, before COMBAT ever needs it.
  - Operators store a carve-out with `nn-admin config overlay set
    combat-allow --file <cidrs> --key <key>`; `install.sh --upgrade` adopts
    one edited by hand under an earlier release with the grant key.
- External audit, Wave 1, FIM availability (High MAIN-003, FIMR-001,
  FIMP-001):
  - The FIM sensors, the file-open sensor, the drain and every FIM rule
    were started only if the baseline database opened: one malformed line
    in `fim_baseline.jsonl` switched FIM off for the boot. They now start
    regardless; without the database only a new baseline cannot be
    recorded, and that is written to the signed audit chain
    (`subsystem_degraded`). A torn last write of the baseline is repaired
    and a malformed line skipped, as for the other chain logs.
  - The drain dropped "no-op" changes against baseline rows it never
    verified: a forged row giving a watched file the hash of its
    backdoored content hid every later change. Only the verified suffix of
    the chain (signature, recomputed hash, link to the previous row) may
    now silence an event; rows before a break report every change until a
    new signed baseline, and the break is recorded.
  - One invalid line in `fim-paths.v1` (or any shipped list) emptied the
    whole list — FIM watched nothing. The line is skipped and reported;
    an empty watch list is an ERROR and a signed record. `fim-paths.v1`
    is now write-denied like `install-manifest.json` (install.sh writes it
    with the pins purged); `fim-paths.local` stays MUTATE-only and
    signature-gated.
- External audit, Wave 1, chain logs cut short (High EVD-005, NET-003,
  DEC-006): one write interrupted by a crash or a power loss no longer
  switches a subsystem off.
  - A torn last line of `audit.log` kept the agent from starting again in
    enforce mode ("Refusing to run unaudited", lab: Ubuntu 22.04). The
    fragment is cut off — or given its missing newline when it is a whole
    entry — and the repair is recorded in the signed chain
    (`chain_tail_repaired`, with the dropped bytes' SHA-256). A bad line
    before the end still refuses the log, untouched; no repair ever
    empties a chain.
  - A torn `netflow_listeners.jsonl` kept the network drain from starting
    at every later boot, so no network rule saw a flow. The listener log
    is repaired the same way, and if it still cannot be opened, flows and
    listener events reach the rules anyway — only that log is not
    written.
  - One unreadable line in the canary registry or access log switched
    deception off ("rule engine sees no CanaryTripped events"). The line
    is skipped and reported (`integrity_drift`, `chain_lines_unreadable`);
    the readable canaries stay deployed and watched.
- External audit, Wave 1, identity of the protected processes (High
  MAIN-001, ATP-002, WDG-002, WDG-003):
  - The agent put whatever pid `/run/northnarrow/watchdog.pid` named into
    PROTECTED_PIDS: in the lab a root `sleep` copied as
    `northnarrow-watchdog` became unkillable (`kill -9` from root: EPERM).
    It now protects only a pid verified to run the installed watchdog
    binary, re-checked every 30 s.
  - Entries a previous agent left in the pinned map were kept while their
    process merely called itself `northnarrow-wat`; they are now kept only
    while they run the agent's or the watchdog's executable.
  - The watchdog took the agent pidfile at its word: in the lab it watched
    a `sleep` as the agent. It now verifies the process runs the agent
    binary (pidfd first, then the executable's device and inode) before
    it protects it, signals it or copies its command line, and signals
    through the pidfd. The unit gains CAP_SYS_PTRACE for that check.
  - A "stuck" signal buffered while the agent was dying could SIGINT,
    evict and SIGKILL the healthy agent that replaced it. Signals now name
    the agent they were raised against and are dropped for any other.
- External audit, Wave 1, authorised shutdown (High EVD-021, WDG-001,
  TST-003):
  - Any root process could switch NorthNarrow off for good: the watchdog
    stood down — no respawn, exit 0 — for any file at
    `/run/northnarrow/agent.shutdown_authorised` with a 64-hex hash and
    a future deadline. In the lab, such a file and a `systemctl stop` of
    the agent left both agent and watchdog off.
  - The marker now carries the shutdown the admin quorum signed and the
    exiting agent's pid, and the watchdog verifies it against
    `admin.pub` as the agent did: quorum and role, this install, signed
    while that agent ran and recently, not honoured before. Anything
    else is refused: the agent is respawned, and the agent records the
    refusal in its signed audit chain (`shutdown_marker_rejected`).
  - The agent wrote the marker through a temporary file that followed a
    symlink; it is now created exclusively, never through a link.
  - New privileged tests cover both halves: a forged marker brings the
    agent back, a quorum-signed one stands the watchdog down.
- External audit, Wave 1, allowlists on exec identity (High LLMR-012;
  the NETR-003 class swept across the remaining rules):
  - A process could silence the io_uring and BPF rules by naming itself
    like a known program: in the lab, the io_uring probe built as
    `nginx` read a file and connected through a ring, and python renamed
    `systemd` with `prctl(PR_SET_NAME)` loaded a BPF program, with no
    verdict. The rules' known programs and the operator allowlist are
    now judged on the executable the kernel ran, inside a root-owned
    system tree. The same now holds for R011–R017.
  - The allowlists keep working as written: an entry of 15 characters,
    the length the kernel cuts a process name to, also matches the
    longer program it was cut from (`unattended-upgr`,
    `systemd-network`). `systemd-udevd` is recognised as `udevadm`, the
    file it links to.
  - When the executable cannot be read (the process exited first), a
    verdict for a process named like an allowlisted program is recorded,
    not acted on.
- External audit, Wave 1, process rules (High PROC-002, PROC-003,
  PROC-004, PROC-007):
  - Without the kernel-resolved path (tracepoint mode), a relative
    `./payload` from /tmp or `/usr/bin/../../tmp/x` slipped past the exec
    rules; the fallback path is now normalised or read from the process.
  - A kernel module loaded from a directory nested deeper than 16 levels
    got an alert instead of the kill; it is now killed, and an unreadable
    path raises a High alert.
  - R009 no longer kills root scripts run from a home or /tmp in an
    administrator's sudo session at a terminal, nor package scriptlets;
    it records them. Other root execs from those paths are still killed.
- External audit, Wave 0, anti-tamper (High EBPF-003, WDG-004):
  - A single write to the pinned ptrace override map lifted the agent's
    ptrace protection until the next reboot. The override now needs the
    current session's nonce and is cleared at every start.
  - When the agent kept dying (tamper suspected) the watchdog exited
    quietly, leaving neither agent nor watchdog. It now stays up, reports
    the degraded state to systemd, and resumes once the agent is started
    again.
- External audit, Wave 0, detection (High FIMP-002, FIMP-005, FIMP-006,
  NETR-001, DEC-003):
  - A watched symlink pointing at a FIFO froze file integrity
    monitoring for good; one pointing at a device read forever.
  - After `mv` of a watched file, edits to the moved copy were reported
    under the watched name, and could get the editor killed.
  - When the drift log could not be written, the FIM rules never saw
    the change. They now always do, and the lost evidence is reported.
  - A credential file opened by its own application (a keyring, a
    browser profile) and a network flow by the same process drew a
    KillProcessTree; such opens are reported only, as designed.
  - File canaries never worked once deployed by the installed agent:
    writing the decoy failed on its read-only sandbox, the decoy was never
    watched by the kernel, and after a restart its reads were dropped.
    Decoys are now written through the host's view without following a
    symlink anywhere on the way, watched from deploy to burn, and watched
    again at every boot (High DEC-001, DEC-002 from Wave 1).
- External audit, Wave 0, COMBAT response (High CMB-002, CMB-005, and
  CMB-003 from Wave 1):
  - NEUTRALIZE reported a threat contained when the root of its tree
    died but descendants lived on, or when the tree walk stopped at its
    limit. Every descendant now counts.
  - The guard that spares sshd and the agent's watchdog applied only to
    the tree walk; a rule's KillProcess, or a Quarantine, BlockOutbound
    or Throttle verdict, ignored it. It now covers every action on a
    process.
  - The guard spared any process running the sshd binary, which any
    user can run. It now spares the SSH service: sshd as root in an SSH
    unit.
- External audit, Wave 0, LLMR-002 (Critical): any user could blind the
  agent by running unknown binaries in a loop. Each one sent to ADE held
  the event loop for up to the inference timeout, and the kernel dropped
  events meanwhile; a timed-out generation also kept running for up to
  two minutes. ADE now evaluates on its own task, one exec at a time
  (the others are judged by the rules only and counted), and a timeout
  stops the generation.
- External audit, Wave 0, POS-001 (Critical): any local user could put
  the host in a locked COMBAT — network isolation, with no way out but a
  signed release — with two cheap heuristics, such as twenty HTTPS
  connections and then three internal SSH connections. Signals now
  corroborate only across kinds of evidence (network, execution, file
  system, kernel). A COMBAT reached on heuristics alone contains threats
  at the process level, never isolates, and decays after 30 quiet
  minutes. Isolation needs a locked COMBAT: a kernel-adjudicated denial,
  root changing a system file outside an administrator's session, or an
  administrator's order.
- External audit, Wave 0, LLM (Critical LLMP-002, High LLMP-001,
  LLMR-001, LLMR-006):
  - The correlated events reached the model raw, inside the prompt's
    trusted block, and a line break in a file name could forge a prompt
    section. They are now sanitized and untrusted, and every untrusted
    string is printed as a JSON string.
  - Model output with a multi-byte character at byte 4096 crashed the
    agent when an escalation kept it.
  - A low-confidence `KillTree` ran because the verifier answered
    "inconclusive". Below its floor every destructive action is refused,
    and an inconclusive check escalates.
- External audit, Wave 0, PROC-001 (Critical): a fileless (memfd)
  exec escaped R004 when its parent named itself `systemd` and its
  `argv[0]` ended in `/systemd-executor`. With the exec sensor's
  identity R004 now judges what the kernel executed: a memfd, or an
  unlinked file reached through an fd. systemd's launch of every unit (a
  real file) is no longer something to exempt. Without the identity,
  the exemption needs `argv[0]` exactly and a systemd parent by
  identity, never by name.
- External audit, Wave 0, network (Critical NET-001 and NET-010, High
  EBPF-007, NET-002, NET-005, NET-011):
  - A dual-stack IPv6 socket reaching an IPv4 address (`::ffff:a.b.c.d`)
    slipped past the IP blocklist and the posture's internal and loopback
    checks. Addresses are now canonical wherever they are decoded.
  - A process could silence the network rules by naming itself like an
    allowlisted program (`prctl(PR_SET_NAME)`). The allowlist is now
    judged on what the kernel executed; when that cannot be read, the
    verdict is recorded instead of acted on.
  - UDP sent from port 53 to anything but a local client was dropped by
    the kernel sensor. It is now reported, aggregated per client address
    for a DNS server.
  - One malformed line emptied a whole blocklist at load; now only that
    line is dropped.
  - A DNS query issued after a connect hid the hostname the connect was
    attributed to.
  - The shipped blocklist held CGNAT (`100.64.0.0/10`) and benchmarking
    (`198.18.0.0/15`) space, which Tailscale, EKS and VPN clients use,
    on a rule that kills the process tree.
- A file capability granted by any route other than the `setcap` program
  (a direct `setxattr`, `cp --preserve=xattr`, `tar --xattrs`) drew no
  verdict (review 86, High). In the lab a user read `/etc/shadow`
  through a copy of `cat` given `cap_dac_read_search`. The agent now
  watches `security.capability` on every file (LSM
  `inode_post_setxattr`). The new rule NN-L-FIM-025 strips the capability
  again, Critical for a root-equivalent one. Package-manager installs and
  interactive admin sessions keep theirs. The unit's capability bounding
  set gains `CAP_SETFCAP` for the strip.
- The COMBAT ladder's NEUTRALIZE never quarantined the offender's binary
  (review 87, High). It looked the binary up after the kill, when it was
  already gone, and under the unit's read-only sandbox the unlink failed
  while the outcome still claimed success. NEUTRALIZE now reads the
  binary before the kill. File-changing responses reach the host's view
  of the file through `/proc/1/root`, and a quarantine that leaves the
  binary in place is reported as failed.
- An account tool was killed after it wrote `/etc/passwd`, `/etc/shadow`
  or `/var/log/lastlog` (review 83). On AlmaLinux 9 `useradd` was killed
  for resetting the new uid's `lastlog` entry and created no account. On
  Ubuntu `useradd` run without a terminal left an account with no group
  and no home. A user changing their own password with `passwd` was
  killed the same way. Writes by the account tools (shadow-utils,
  libuser, `systemd-sysusers`), told by what the kernel executed, are now
  recorded: at Low for a user's own change, else at the rule's severity.
- A process could read cloud, browser, password-manager and GPG
  credentials, or write `wtmp`, `btmp` and `lastlog`, with no detection
  by giving itself a legitimate client's name (review 85, High):
  `prctl(PR_SET_NAME, "aws")` was enough. The rules now recognise a
  client by what the kernel executed: its exe, or the script an
  interpreter runs, inside a root-owned system tree. They also recognise
  gcloud, the Azure CLI and AWS CLI v1, which run as `python3`. A client
  reading another user's credentials is no longer exempted.
- An administrator's `sudo` edit of a watched configuration, cron, unit or
  timer file killed the command or the editor (review 52). `sudo useradd`
  was killed after writing `/etc/passwd` and left an account with no group
  or home. Two such edits in one session also put the host in COMBAT,
  whose ladder then killed the writer. Writes from an interactive sudo/su
  session (login uid and terminal) to these files are now recorded at the
  rule's severity. They raise the posture without corroborating each
  other. Services, jobs, commands run without a terminal and root
  processes with no sudo/su above them keep the kill.
- Root could boot a kernel without the agent through kexec (review 82,
  High): on AlmaLinux 9, `kexec -l` succeeded with the agent running. The
  agent now refuses every kexec image load outside the trusted-installer
  window and records it as an anti-tamper denial; its unit starts after
  `kdump.service`, so kdump keeps loading its crash kernel at boot.
- Sealed chain-log archives and their manifests could be altered by root
  after an agent restart (review 81, High): only the active files were
  protected again at start, and the manifest never was. The agent now
  protects every retained archive and manifest at start and the manifest
  at each rotation.
- An evicted log archive left its inode protected until the next agent
  start (review 80): when the filesystem reused the number for an
  unrelated file, that file could not be written or removed and each try
  was an anti-tamper detection. The agent now releases an archive's inode
  before evicting it.
- The TCP close sensor sent a record for every passive socket (listeners,
  accepted peers) that the agent then dropped, so inbound connections
  could fill the ring the outbound flow closes need; and a close lost to a
  full ring left a stale entry that misattributed a later socket's close
  (review 79, part). Only sockets the connect sensor recorded are reported
  now. Still open: a loop of outbound connects can still overflow the flow
  rings (design pending).
- Detections held back by the per-rule budget (review 75) were reported
  only as a count, so a flood of one rule could hide which file another
  detection of that rule was about. The held report (journal and signed
  audit entry) now names up to eight distinct subjects per rule and uid.
- An unprivileged loop of DNS queries could hide a DNS tunnel (review 78,
  High). The DNS sensor recorded every datagram into one ring: a loop of
  benign queries lost half of the records and took more than a CPU of the
  agent, and a tunnelling-shaped query in the middle evaded NN-L-NET-004
  one time in three. The kernel now gives each process and each user a DNS
  budget; queries over it are not recorded but counted on the process's
  next record, and the new NN-L-NET-020 reports the process that floods.
  The local resolvers are exempt.
- A file detection did not say which file it was about (review 77). The
  record of a cron drop-in named the writer but not the drop-in; records
  carried a path only for exec detections. Detection records now have a
  `file` field for the file sensors (FIM drift, file open, mass write,
  module load).
- Root could switch off the FIM kill rules for a minute at a time (review
  76, High). The drift events handed to the rules were paced by host-wide
  buckets (50 created and 100 modified files per minute, whoever wrote
  them). After 60 throwaway files in `/etc/cron.d`, a real cron drop-in
  was only logged: NN-L-FIM-007 never ran and its writer was not killed.
  The buckets now pace only package-manager writes, the upgrade noise they
  were meant for; every other write reaches the rules.
- An unprivileged loop of reads disabled the FIM kill rules and erased
  detection records (review 75, High). Every open of the user's own
  credential file, or of a world-readable sensitive file such as
  `/etc/passwd`, sent a record to a kernel ring and a verdict to the journal
  and the detection store. Two `open()` loops lost 94 % of the open-sensor
  ring and kept the agent's event channel full; the FIM drain then dropped
  the drift events it could not queue, so a root process writing a cron
  drop-in was not killed. journald suppressed 400k agent lines, and the
  store's queue evicted the records of real kills. Now the kernel drops a
  task's repeated reads of a file within one second, the FIM drain waits
  for room instead of dropping, detections are logged and stored within a
  per-rule, per-uid budget (every verdict is still acted on; the rest are
  counted and reported), and a full queue evicts logged-only records first.
- NN-L-NET-009 (more than 100 MiB sent) never fired for UDP (review 74,
  High). The flow tracker emits one UDP row per kernel record, at most
  about 1 MiB, so no row reached the threshold: 150 MB sent over UDP in
  0.6 s went unflagged. NET-009 now sums the UDP rows of a (process,
  destination) over 10 minutes.
- An unprivileged UDP burst could erase every network flow record (review
  73, High). A connected UDP socket emitted one record per `send()` into the
  ring the TCP closes share. One process sending 146k datagrams/s lost 1.45
  million records in 10 s, TCP flows included. UDP sends are now aggregated
  in the kernel per destination: one record per second, or per MiB, carrying
  the bytes sent. UDP records also have their own ring.
- An unprivileged shell loop could blind the exec rules (review 72, High).
  For every event, the agent cloned its ring of up to 1,000 recent events to
  hand the posture triggers a slice. Under an exec burst (four `cat` loops,
  about 2,000 execs/s) that was a full CPU on Ubuntu 24.04. On Ubuntu 22.04
  and Debian 12 the exec rings overflowed, so the execs in the burst,
  including a hidden payload, reached no rule. The triggers now read the
  ring in place: the agent's CPU per exec drops from about 520 µs to 80 µs.
- A credential theft could be reported only as a `/tmp` C2 connection
  (review 70). CHAIN-007 (`/tmp` exec → credential read → egress) and
  CHAIN-001 checked their precursors only when the egress arrived. A
  credential read processed after the connect it preceded (it comes
  through another ring) left both silent: CHAIN-002 killed the tree but
  did not name the theft (lab, Ubuntu 22.04). A late read now completes
  the chain with the egress it preceded.
- The agent wrote every exec and every network flow to the journal at INFO
  (review 71). On a busy host journald then rate-limited the agent, which
  lost other lines too, and every command line on the host (with any
  secret in its arguments) was copied into the journal. Both lines are now
  DEBUG; the records stay in the detection store and the signed netflow
  log.
- An agent start could lose events in its first seconds (review 69). Until
  the LSM file-open sensor took over, the `sys_enter_openat` tracepoint sent
  every open of the host to the agent's event channel, which nothing reads
  before the boot sequence ends. The channel filled, every sensor waited
  behind it, and the file-open ring overflowed: up to 1,018 records lost on
  the lab. The tracepoint now stays inert in the default mode until it is
  needed (`--file-open-sensor tracepoint`, or as the fallback).
- UDP datagrams to IPv6 destinations left no flow row (review 68, High).
  The N2 UDP program was attached to `udp_sendmsg` only, so a QUIC-like
  beacon or raw-UDP exfiltration over IPv6 was invisible to the flow
  rules. It is now attached to `udpv6_sendmsg` too. An IPv4-mapped
  destination still gives one row, not two.
- DNS tunnelling could escape NET-004/-005/-014 (reviews 66, 67, High).
  The DNS sensor read the query name from user memory before the kernel
  copied it, and saw IPv4 only. On the lab, a tunnelling-shaped name ran
  untouched when it was sent in any of these ways:
  - to an IPv6 resolver (`[::1]:53`);
  - from a page the process had not touched yet (the name read as empty);
  - with a zero byte inside its first label (the name was cut there).
  The sensor now reads the kernel's copy, IPv4 and IPv6, and all three are
  killed. A query whose name does not end in the copy's linear data (sent
  in pieces, with UDP GSO or zero copy) is recorded by NET-004 (Log).
- The exec kill rules could be evaded with a relative path (review 61,
  High). They matched the string the caller passed to `execve`, so
  `cd /tmp && ./payload` ran with no detection while `/tmp/payload` was
  killed (lab, Debian 12). A symlink, `..` or `execveat` with a directory
  fd did the same, and a memfd behind a symlink escaped R004. R001, R002,
  R003, R008, R009, R010, R013's and R017's exemptions, CHAIN-002, the
  posture's `/tmp` arm, process canaries and the auth-lineage tracker now
  read the file the kernel executed, and R004 also fires on the kernel's
  memfd flag.
- Review 64's fix had no effect (review 65, High). `cargo xtask build`
  dropped every `CARGO_*` variable before building, including the release
  job's `x86-64-v2` override. A release built on a runner with AVX-512 still
  died with SIGILL on CPUs without it (seen on PR #223's tarball). xtask now
  passes per-target settings on to the nested build. The release job also
  starts the binaries on an emulated `x86-64-v2` CPU
  (`qemu-x86_64 -cpu Nehalem`).
- Release binaries could die with SIGILL at start (review 64, High). The
  workspace builds with `target-cpu=native`, and the release workflow did
  not override it, so a release built on a GitHub runner with AVX-512 used
  AVX-512 and did not run on CPUs without it (the lab's guests, many
  servers). Releases now target `x86-64-v2`.
- The agent stopped starting after about 41 restarts in one uptime
  (review 63, High). Every boot added the inodes it protects to the
  pinned `PROTECTED_INODES` map (23 per restart on the lab, mostly the
  re-created bpffs pins) and never removed the earlier boots' keys; at
  1024 entries an insert failed and the agent refused to start with a
  missing protection. The boot now removes every key it did not register
  itself, after registering its own, and `tamper-check` checks that one
  more restart does not grow the map.
- After an agent restart, kill -9 and ptrace attempts on the agent were
  still refused but left no evidence (review 62). The two hooks emit on the
  anti-tamper ring, yet reused the previous boot's pinned program, bound to
  a ring no one read any more. They are now reattached fresh every boot,
  like the file-protection hooks, and `tamper-check` repeats the kill and
  ptrace cases after its restarts.
- `nn-lab.sh tamper-check` left its overlays in `/etc/northnarrow`, and
  C24's was signed, so its `+backupd` exemption stayed in force on the
  lab guest. The e2e fixtures' agents then logged it as an unauthorised
  overlay, and `audit_verify_e2e` failed on its entry count (Ubuntu
  22.04). The check now purges the pins, removes the overlays and
  restarts the units.
- `nn-lab.sh sync` could leave the lab guest building stale code. rsync
  kept the host's file times, so sources synced from another checkout or
  worktree could be older than the guest's last build. cargo then kept
  the old crate: the build failed, or linked the previous code. Files are
  now compared by content, and a changed file takes the guest's clock.
- Every file operation on the host went through a global kernel lock
  (review 56). 45 `bpf_printk` diagnostic markers from a 2026-05
  investigation were still in the anti-tamper LSM programs: one per
  `file_open`, up to five per write-open, and more on every unlink,
  rename, setattr and ioctl. `bpf_trace_printk` serialises on one spinlock
  and writes the trace buffer, and its "trace_printk() … unsafe for
  production" banner appeared on every agent host. All are removed.
  Overhead benchmark on Ubuntu 24.04, 3 rounds: open throughput loss
  falls from 38.5 % to 31.9 %, write-open from 48.8 % to 25.6 %.
- FIM killed unrelated processes after a watched file was deleted
  (review 57). A file dropped in a watched directory is watched by its
  inode, and deleting the file left the inode number watched, even across
  agent restarts. ext4 hands that number to the next new file, so a
  compiler's temporary file in `/tmp` was killed as a "cron drop-in". A
  deleted file's inode is now forgotten, and stale keys are cleared at
  boot. The enrollment of dropped files itself often failed (review 58):
  it ran before the file existed at its final path. It is now retried
  for two seconds. `nn-lab.sh fim-reuse-check` covers both.
- On btrfs, FIM and the anti-tamper file protection saw nothing (review
  55). Userland keys watched and protected files by `(dev, ino)` from
  `stat()`, which on btrfs reports the subvolume's device. The eBPF hooks
  looked them up with the superblock's device, so no key ever matched.
  FIM missed every file on btrfs, the deny hooks protected none of them,
  the BPF guard's exemption for the agent's own executables never applied,
  and nothing warned. The eBPF side now reports the device as `stat()` does
  (`BTRFS_I(inode)->root->anon_dev` for btrfs inodes). The offsets come
  from the btrfs module's BTF, which the resolver now reads as split BTF
  on top of vmlinux. `nn-lab.sh btrfs-check` reads a watched credential
  file on the root filesystem and on a btrfs subvolume; NN-L-FIM-011 must
  fire both times. Before the fix it fired only for the root filesystem.
- Without the kernel BTF (`/sys/kernel/btf/vmlinux`) the anti-tamper
  attach only logged a WARN and skipped every LSM hook, outside the
  fail-closed check that refuses to start on a missing deny hook. Only the
  network sensor's own BTF load kept such an agent from running. The
  no-BTF case now takes the same fail-closed path
  (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` is the only way to start degraded),
  and a mount that hides `/sys/kernel/btf` while the agent runs is
  reported as `integrity_drift` (review 53).
- A copy of the agent's unit in an earlier directory of systemd's load
  path replaced the installed unit at the next `daemon-reload` without any
  evidence. The tmpfs `/run/systemd/transient` and `system.control`
  outrank even `/etc/systemd/system`, and both are outside the FIM watch.
  The integrity check now reports every second copy of the units as an
  `integrity_drift` entry of kind `unit_shadowed`, `systemctl mask`
  included.
- The FIM rules killed the package manager. dpkg was killed while it
  installed or removed any package that ships a systemd unit or timer, a
  cron drop-in, a PAM module or a setuid binary, which left packages
  half-installed (`apt-get install --reinstall rsync` failed). Writes made
  by dpkg, rpm, dnf/yum, microdnf or PackageKit, or by the maintainer
  scripts they run, are now recorded as Low log-only detections instead of
  killed. The package manager is recognised by the kernel-resolved
  executable of the writer's lineage, never by process name.
- NN-L-CHAIN-008 (sudo/su, then network) killed legitimate admin work: any
  network flow of a descendant of `sudo` or `su` within 5 minutes drew a
  Critical `KillProcessTree`, `sudo apt-get update` and loopback traffic
  included. The rule is now informational (Medium, log only), ignores
  loopback destinations and is evaluated after every other rule, so it
  never hides a blocking verdict on the same flow.
- NN-L-FIM-019 killed systemd's getty start-up child, which writes the
  login record under the name `(agetty)`: after a reboot both console
  gettys hit their start limit and the host had no console login. The
  login-record rules (FIM-018/019) now accept systemd's pre-exec name and
  the `systemd-update-utmp` and `sshd-session` writers.
- The mass-write posture trigger logged its WARN on every event while a
  steady writer kept the threshold crossed (one line per second for 24 h
  on the first soak); the line is now emitted once per pid per window.
  Detection and posture behaviour are unchanged.
- Memory leak in the DNS attribution cache: the per-pid map was never
  pruned of dead pids, so every short-lived process that resolved a name
  grew the agent by a few hundred bytes for the life of the process
  (~1 MB/h on the first 24 h soak). Stale pids are pruned by TTL and the
  map is capped at 4096 distinct pids.
- Lab soak sampler counts WARN/ERROR lines by text in the `northnarrow`
  journal namespace (tracing output has journald priority 6, so the
  priority filter counted nothing); `soak start` passes `SOAK_*_PER_S`
  rates through to the generator.
- RHEL 9 family (AlmaLinux 9 / 5.14 el9): the vendor tracepoint header
  shifts `sched_process_exec.filename` by 4 bytes; the exec sensor read an
  empty filename on every exec and R017 killed every shell. Tracepoint
  field offsets are now resolved from tracefs at boot (4 new `BTF_OFFSETS`
  slots), and the "non-standard path" rules (R017, R013) never fire on an
  empty filename.
- Short-lived TCP flows (connect and close within the pipeline latency:
  loopback probes, scanners, reverse-shell attempts) produced no netflow
  row and could silence CHAIN-007; the close now synthesises the row when
  it overtakes its connect.
- Debian-family hosts: the hardened agent unit could not attach its
  tracepoint/kprobe sensors (`perf_event_open` EACCES: Debian's
  `perf_event_paranoid=3` patch demands `CAP_SYS_ADMIN`); `install.sh`
  adds a drop-in with that capability on those hosts only, and the attach
  error explains the condition.
- Kernel 5.15 (Ubuntu 22.04): the eBPF object was rejected by the older
  verifier (`memset` subprogram call on ring-buffer entries; variable-length
  read into uninitialised stack; `Option` payload read before its
  discriminant in the FIM rename hook). Entries are zeroed inline, such
  reads land in the ring-buffer entry, the rename destination is a plain
  key; the agent now loads on 5.15 with every program and all 8 FIM hooks
  attached (DNS QNAME via `ITER_IOVEC` only — degraded, not refused).
- e2e fixtures (agent and watchdog): teardown signalled only the `sudo`
  pid and relied on the relay; sudo 1.9.9 does not relay from its own
  process group, so suites hung on 22.04. The whole subtree is now
  signalled, with a bounded wait. The map-pin test accepts the 15-byte
  kernel program name printed by older bpftool.

- FIM e2e suite: the credential-read test asserted a drift row that
  BUG-012 v2 deliberately never writes; it now asserts the
  `NN-L-FIM-011_AwsCredsRead` detection record and the empty drift log.
  The lab's `test-e2e` step runs the FIM suite (it ran nowhere before).

### Added
- Lab without `/dev/kvm` (`deploy/lab/nn-lab.sh`, `NN_LAB_ACCEL=whpx|tcg`):
  WSL exposes no nested virtualization on AMD hosts since Windows
  KB5127648 (microsoft/WSL#41918). `whpx` runs the guests in QEMU for
  Windows on the Windows hypervisor, next to WSL, at full speed — disks in
  `C:\nn-lab\<distro>`, ssh forwarded on the WSL-facing address only and
  mapped to `127.0.0.1:<port>` by a socat user unit, so every sub-command and
  probe works unchanged; a guest reboot (WHPX hangs on a reset) ends QEMU
  and `up` starts it again. `tcg` is software emulation in WSL.
- DNS sensor on the socket buffer (Tappa 10.9 step 3). Kprobes on
  `udp_send_skb` and `udp_v6_send_skb` read the query from the buffer the
  kernel sends: the destination from the flow, and the name from the
  kernel's copy of the payload. Userland walks the labels, so a zero byte
  inside a label no longer cuts the name. `udp_sendmsg` is no longer
  attached for DNS; `--dns-sensor sendmsg` (or `NN_DNS_SENSOR`) keeps it
  for one soak cycle. `DnsQuery` gains `qname_partial`. Eight optional BTF
  slots (`sk_buff.{head,tail,transport_header,data_len}`,
  `flowi4.{daddr,uli}`, `flowi6.{daddr,uli}`). `nn-lab.sh
  dns-sensor-check` verifies it end to end.
- Exec sensor on LSM `bprm_check_security` (Tappa 10.9 step 2). For each
  binfmt pass (a `#!` script: the script, then its interpreter) it reads
  the file the kernel opened. It records `(dev, ino)`, whether the file is
  on a memory-backed filesystem, is a memfd or is unlinked, and its path
  rebuilt from the dentry up to the exec'ing task's root (containers and
  chroots keep their own view). The path walk is a global BPF function,
  verified on its own. The first pass's identity is handed to the
  post-exec `ProcessSpawn`, and `ExecCheck` now carries kernel data (and
  a real `ppid`). `sys_enter_execve` is no longer attached;
  `--exec-sensor tracepoint` (or `NN_EXEC_SENSOR`) keeps it for one soak
  cycle. The exec ring grows to 1 MiB for the larger records.
  `nn-lab.sh exec-sensor-check` verifies it end to end.
- File-open sensor on LSM `file_open` (Tappa 10.9 step 1). The FIM
  `file_open` observer now also classifies every open in the kernel, and
  only the opens a rule reads reach userland:
  - sensitive files, and writes to critical or persistence files and trees;
  - the telemetry probe directory;
  - credential stores found by name in every home (review 54);
  - one `Event::MassWrite` per process crossing 20 write-opens in 60 s,
    instead of every open.

  `sys_enter_openat` is detached once the sensor is armed, so the path is
  the one the kernel opened (no time-of-check gap) and opens through
  `io_uring` are seen. A relative path, a directory fd or a symlink no
  longer slips past the posture's file triggers (review 60, High). Directory classes are cached; a directory rename
  invalidates the cache and `rmdir` drops the removed directory's entry.
  Paths are rebuilt from the mount table.
  `--file-open-sensor tracepoint` (or `NN_FILE_OPEN_SENSOR`) keeps the old
  sensor for one soak cycle. Credential-store opens in homes outside the
  watch list are reported; the reader is killed only when it is a non-root
  user other than the file's owner and holds no DAC capability on the host
  (design Q8): the owner's own tools and root's backups are not.
  The posture's path lists are prefixes and the kernel classifies by
  directory, so `/etc/ssh/sshd_config.d/` is now listed: the
  `/etc/ssh/sshd_config` prefix used to cover sshd's drop-ins.
  Mass-write carve-outs are directory trees, with or without the final
  `/`. If the verifier refuses the sensor, FIM keeps its plain observer
  and the agent stays on `sys_enter_openat`.
  `nn-lab.sh open-sensor-check` verifies it end to end on Ubuntu 24.04
  (6.8), Ubuntu 22.04 (5.15) and Debian 12 (6.1). On the 6.8 lab guest
  the open benchmark loses 28.2 % instead of 31.9 %, and the agent's own
  CPU per open drops from 6.4 µs to almost nothing (design §10.6, Q7).
- `nn-lab.sh sensor-feasibility [BASE]`, step 0 of the Tappa 10.9 sensor
  attach points. A lab build of the agent (`--sensor-feasibility`, feature
  `test-privileged`) loads throw-away probes on the attach points the
  design proposes and exercises them from its own process. The probes are
  LSM `file_open` with the parent-directory, name and ancestor tables and
  the in-kernel write counter; LSM `bprm_check_security`; and the DNS
  payload read from the socket buffer by a `kretprobe` on
  `ip_make_skb`/`ip6_make_skb` and a `kprobe` on `udp_send_skb`. All 18
  properties hold on 6.8, 6.1 and 5.15. Among them: every record names the
  inode the open returned while another thread swaps the name, and an
  `execveat` of a memfd is seen. The run on btrfs found review 55. The
  probes ship in the shared eBPF object but the agent never loads them;
  their maps take about 70 KiB until step 1 replaces them. With
  `NN_FEASIBILITY_BENCH=<opens>` it also measures the cost per open. On
  6.8, an empty LSM program adds 147 ns, today's FIM observer 427 ns, and
  the full observer 1 587 ns (−34 %). The full checks cannot therefore run
  on every open: step 1 caches the classification per directory.
- Kani proof of the admin multi-signature rule. `verify_quorum` and
  `verify_signed_payload_quorum` now share `quorum_decision`, the tally of
  distinct keys, threshold and role check separated from the signature
  checks, and Kani proves it accepts only when enough distinct keys matched
  and every required role is carried by one of them (weekly job). A
  threshold of 0 was refused only by a `debug_assert`; the rule now uses
  `max(threshold, 1)` in every build.
- `nn-lab.sh release-check DIR`: the release tarball CI built and attested
  (`gh run download`), installed and verified on a guest. It checks
  SHA256SUMS, that the binaries run on the guest's glibc, `install.sh`'s
  tree and tarball verification (provenance `checksums`), the boot-time
  binary integrity check, every deny hook, the telemetry probe and one
  detection. It passes on Ubuntu 24.04, Ubuntu 22.04 and Debian 12.
- Fuzz targets `combat_allow` and `canary_template`: the COMBAT management
  carve-out (allow-file text, generated ACCEPT lines, splice into the
  operator ruleset) and the operator canary templates. Besides "never
  panics", `combat_allow` asserts that no allow-file content can inject an
  `iptables-restore` line other than an ACCEPT for one validated address.
- `tamper-check` with kernel lockdown: kexec (C17) is a required refusal
  when lockdown is active instead of a known gap, and C27 loads a module
  whose signature was stripped through a bare `finit_module`. Verified on
  Ubuntu 22.04 with `lockdown=integrity`: the agent runs unchanged, both
  are refused by the kernel, and R018 still records the module attempt.
  `nn-admin host-check` reports module signing as enforced when lockdown
  is in integrity or confidentiality mode, which refuses unsigned modules
  whatever `module.sig_enforce` says.
- Distribution packages: `northnarrow_<ver>-<rel>_amd64.deb` and
  `northnarrow-<ver>-<rel>.x86_64.rpm`, built by
  `deploy/release/mk-packages.sh` with dpkg-deb and rpmbuild only, and
  published, checksummed and attested with the tarball. Their scripts run
  `install.sh` / `uninstall.sh` in new package modes (`--package-stop`,
  `--package-configure`, `--package`). Installing over an `install.sh`
  install migrates it; upgrade and removal go through the
  trusted-installer window (`NN_GRANT_KEY`) and stop cleanly without it;
  the first install starts nothing. Lab: `nn-lab.sh pkg-check`.
- Package install layout: `install.sh` and `uninstall.sh` accept
  `BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system` and rewrite the units
  for `BIN_DIR`. The agent protects the binaries and units of both layouts
  and finds the watchdog next to its own executable, so `--watchdog-exe`
  is now optional. Prerequisite for `.deb`/`.rpm` packages (review 26).
- Overhead benchmark (`nn-lab.sh overhead [ROUNDS]`): the agent off and on,
  alternated, over four worst-case micro-workloads (open, open + write,
  exec, loopback connect); the report gives the median throughput lost and
  the agent's own CPU per workload. Runbook section "Overhead (agent off
  vs on)".
- Host hardening checks (`nn-admin host-check [--json]`, summary in
  `nn-admin status`, one WARN per gap at agent boot, table at the end of
  `install.sh`): BPF LSM, kernel lockdown, unprivileged BPF, module
  signature enforcement, Secure Boot, IMA, kexec, single bpffs mount —
  the host settings that keep root from rewriting the kernel at runtime,
  which is the only way around the anti-tamper.
- Kani model checking (`.github/workflows/kani.yml`, weekly): the TLS
  ClientHello `Cursor` and the DNS name walk (`QnameLabels`, split out of
  `decode_dns_qname` without behaviour change) are proved in bounds for
  every input of a bounded size. The first proof found the cursor's bound
  check `pos + n > len` wrapping for a huge `n` in release builds; it is
  now saturating.
- Signed operator overlays: the agent loads a `*.local` overlay
  (allowlists, blocklists, FIM paths, posture carve-outs) only if
  `<overlay>.sig` proves that a key with the new `config-manage` role signed
  its exact content, for this `agent_id`, and not earlier than the last
  accepted signature (rollback guard from the audit chain); otherwise it
  boots on the shipped defaults for that list and records an
  `unauthorized_overlay` integrity finding. `nn-admin config overlay
  set|sign|status`; `install.sh` bootstraps the key with `config-manage`
  and `--upgrade` adopts existing overlays with `--grant-key`; the posture
  overlays and the `.sig` files join the protected set; escape hatch
  `NN_OVERLAY_ALLOW_UNSIGNED=1` (reported). Closes the gap found by
  tamper-check C19.
- Adversarial anti-tamper check, second part: `cgroup.kill` on the agent's
  unit (C20), an exec flood hiding an exec from `/tmp` (C21) and an
  io_uring probe that opens, reads and connects through a ring with no
  openat/connect syscall (C22, `deploy/lab/adversarial/iouring-probe.c`, raw
  syscalls) — 23 cases, all with signed evidence on 6.8 and 5.15. Kills that
  nothing can refuse are now evidence: every run writes `agent_stop` with the
  reason it left its event loop, and every `agent_boot` says how the previous
  run ended (`previous_run`: none / clean / abrupt; review 46). The four
  remaining append-by-path logs (FIM baseline, canary registry and access
  log, listener log) also write through a directory fd (review 44).
- Adversarial anti-tamper check (`nn-lab.sh tamper-check`,
  `deploy/lab/adversarial/anti-tamper.sh`): 20 cases (signals, ptrace,
  protected files and pins, BPF maps/links/programs, unit drop-ins,
  `set-property`, bpffs and bind mounts, cgroup freeze, module load,
  `oom_score_adj`, config overlays), each with expected outcome and the
  evidence it must leave in the signed chain logs. Found and fixed:
  `OWN_BPF_IDS` collisions between map/program/link ids (review 40),
  silent signal/ptrace denials — now `op=signal`/`op=ptrace` records and
  detection NN-L-AT-001 for every anti-tamper denial (41), silent
  systemd/kernel tampering — now a self-integrity check every 30 s ±20 %
  with `integrity_drift` audit entries, `OOMScoreAdjust` in both units
  (42), the telemetry probe tripping NN-L-NET-004 (43), and the signed
  logs being divertible by a bind mount over their directory — every log now
  writes through a directory fd taken when it is opened (44). Ring-buffer
  losses are signed audit entries (`ringbuf_drop`); the telemetry probe
  and the link self-check run with ±20 % jitter.
- Telemetry probe: every 60 s the agent runs a child of its own binary
  (`--telemetry-probe <nonce>`, hidden) that produces one known event per
  probed sensor — exec, file open of `/run/northnarrow/probe/<nonce>`, DNS
  query for `<nonce>.probe.northnarrow.invalid` to 127.0.0.1:53 — and
  checks each reaches the pipeline within 5 s; a silent sensor is an
  `ERROR TELEMETRY GAP` and a signed audit entry (`telemetry_gap`, then
  `telemetry_restored`), coverage as a product function.
  `NN_TELEMETRY_PROBE_SECS=0` disables it.
- BPF self-defence, second half: the `bpf` LSM hook now DENIES (enforce
  mode) a handle to one of the agent's own links to a foreign process, by id
  (`LINK_GET_FD_BY_ID`) and through the pin (`OBJ_GET` whose final path
  component is one of our `link_*` pins) — the two routes to `bpftool link
  detach`; denial `operation=bpf_link` in the audit chain and the posture
  ladder. Own ids are kept with their kind (map / program / link live in
  separate kernel id spaces; before, a foreign map with the id of one of our
  programs would have been write-denied). Link self-check every 10 s: a
  registered link missing — checked through the agent's own fds and pins,
  no `CAP_SYS_ADMIN` — is an ERROR and a signed audit entry
  (`bpf_link_missing`), in every mode. Review entry 39 (High): the pin root
  `/sys/fs/bpf/northnarrow` and every pin are now in the protected-inode
  set, so `systemctl stop` + `rm -rf` of the pins no longer drops the
  hooks; the trusted-installer window is the authorised purge —
  `install.sh --upgrade --grant-key <key>` / `uninstall.sh --grant-key
  <key>` open it, the bootstrapped admin key carries the role
  (`unlock,audit-read,trusted-installer`), and the lab migrates guests
  installed with an older key once (units disabled across a VM restart).
- BPF self-defence, first half: LSM hook `bpf_map` denies any write handle
  on the agent's own maps (ids registered after load) to processes that
  are not the agent or the watchdog — `bpftool map update/delete` against
  `PROTECTED_PIDS` now fails with EPERM and lands in the audit chain as an
  anti-tamper denial (`bpf_map`); read-only handles stay allowed, but
  `bpftool` always asks for RDWR, so in enforce mode `map show/dump` on the
  agent's maps fail too (read the state with `nn-admin status`). LSM hook
  `bpf`
  observes program loads, attaches, link create/update/detach, BTF loads
  and handles-by-id on the agent's maps/links by foreign processes
  (`Event::BpfSyscall`, one record per pid per command per second); rules
  `NN-L-BPF-001_BpfProgramLoaded` (Medium, Log; known tooling exempt) and
  `NN-L-BPF-002_BpfForeignHandleOrDetach` (High, Log). Observe mode (no
  deny) in `debug-trigger` builds and with `NN_BPF_DEFENSE_OBSERVE=1`; the
  guard counts as a ninth deny hook in the fail-closed LSM health. Seven new
  BTF offset slots (`bpf_map`, `bpf_prog`, `bpf_prog_aux`, `mm_struct.exe_file`
  for the exe-inode exemption that lets a restarting watchdog register itself).
- io_uring sensor — the asynchronous I/O channel syscall-centric sensors
  miss: tracepoints `io_uring_create` and `io_uring_submit_{req,sqe}`
  (name resolved per kernel), submissions aggregated per pid in kernel by
  opcode class (file open, file read/write, network connect, network
  send/recv, filesystem mutation) and emitted on a new class or once per
  second; `Event::IoUring`; rules `NN-L-IOU-001_IoUringRingCreated` (Low,
  Log: baseline of ring creators outside the allowlist) and
  `NN-L-IOU-002_IoUringFileAndNetwork` (High, Log: file and network I/O
  through rings from the same unlisted process — the RingReaper shape).
  Known io_uring servers (qemu, nginx, postgres, mariadb, mysql, redis,
  node, fio, systemd-journal) and the process comm allowlist are exempt.
  Five new `BTF_OFFSETS` tracepoint slots; a kernel without
  `CONFIG_IO_URING` degrades with a WARN.
- Ring-buffer drop accounting: every eBPF producer bumps a per-ring
  counter (`RING_DROPS` per-CPU map, 11 rings) when its reservation
  fails; the agent samples it every 10 s, logs each increase at WARN with
  the ring's name, and `nn-admin status` shows the total and the per-ring
  breakdown (`ringbuf_drops_total`, `ringbuf_drops` in `--json`). Before,
  only the exec ring counted and nothing read it.
- Fuzzing (`fuzz/`, cargo-fuzz): eight libFuzzer targets over every
  parser that consumes attacker-shaped bytes — admin socket frames, TLS
  ClientHello and DNS payloads from the kernel rings, the BTF blob,
  tracefs `format` files, role lists, chain-log lines, the install
  manifest. The `fuzz` CI job builds every target and runs each for a
  short smoke on every PR; a crash artefact fails the job.
- Supply chain, install-time and runtime halves: `install.sh` verifies the
  extracted tree (`MANIFEST.sha256`, now shipped in the tarball), the
  tarball against `SHA256SUMS` and the SLSA provenance attestation (gh or
  cosign, bound to this repository's release workflow;
  `--require-attestation`, `--no-verify`), and records the level reached
  plus the hashes of every installed binary and of the eBPF object in
  `/etc/northnarrow/install-manifest.json`. The agent re-verifies those
  hashes at every boot and refuses to start on a mismatch
  (`NN_ALLOW_UNVERIFIED_BINARY=1` to override); the `agent_boot` audit
  entry carries `binary_integrity` and `install_provenance`.
- Lab: fourth guest AlmaLinux 9 (`NN_LAB_DISTRO=alma9`, kernel 5.14 el9,
  SELinux enforcing, port 2622) — verified end to end; the compatibility
  matrix records it.
- `BTF matrix` workflow + `deploy/btf-matrix/run.sh`: computed
  kernel-compatibility matrix over the BTFHub archive (newest non-cloud
  kernel per distro/version, `--btf-check` verdicts, BPF LSM floor),
  compared with a baseline (`expected.tsv`); on PRs touching the offset
  tables, weekly, and on demand. Verdicts recorded in
  `KERNEL_COMPATIBILITY.md`.
- `northnarrow-agent --btf-check <btf>`: offline compatibility verdict
  (SUPPORTED / SUPPORTED (degraded) / NOT SUPPORTED) for any kernel BTF;
  optional offsets (the `iov_iter` family behind DNS QNAME decoding)
  degrade the sensor instead of refusing the boot. Lab: third guest
  `ubuntu2204` (kernel 5.15), verified end to end.
- Multi-kernel, level 1: kernel struct offsets are resolved from the
  running kernel's BTF at boot and published to the eBPF programs through
  the `BTF_OFFSETS` map before any hook attaches (compiled-in values are
  only the fallback); `iov_iter` alternative paths (≤ 6.3) and the
  `ITER_UBUF` enumerator resolved by name. Debian 12 / kernel 6.1 now
  runs the full e2e suites (agent 6/6, watchdog 4/4); a field absent on
  the running kernel still refuses the boot (BUG-036, exit 78).
- Lab: second guest Debian 12 (`NN_LAB_DISTRO=debian12`, kernel 6.1) with
  its own disk, port and reports; `docs/operator/KERNEL_COMPATIBILITY.md`
  records the verified matrix. Finding: the agent refuses to start on 6.1
  (20 of 41 compiled-in BTF offsets differ — fail-closed as designed);
  runtime offsets tracked as review entry 27.
- Release workflow on tags `v*`: locked build, release tarball consumed by
  `install.sh` unchanged, CycloneDX SBOM, `SHA256SUMS`, SLSA build
  provenance attestation (`gh attestation verify`); dry run on packaging
  PRs. `deploy/release/mk-tarball.sh` builds the same tree locally.
- `install.sh --upgrade`: in-place upgrade of a running install (stops
  watchdog → agent, drains the LSM programs, replaces, restarts; keys,
  agent_id, audit chain and chain logs preserved). Without the flag the
  script now refuses when the units are active instead of failing halfway
  with `Operation not permitted`.
- `deploy/uninstall.sh` (`--purge`, `--yes`): ordered removal that the
  anti-tamper layer allows; keeps `/etc/northnarrow` and
  `/var/lib/northnarrow` unless purged.
- Lab: `nn-lab.sh upgrade-check` / `uninstall-check`, both in the nightly.
- `docs/operator/INSTALL_UPGRADE_UNINSTALL.md`.

### Fixed
- Lab/test only: `privileged_map_pin` and the watchdog 3-cycle respawn
  e2e evict the agent from PROTECTED_PIDS before signalling it (the
  `task_kill` deny-by-default policy refuses a bare SIGQUIT/SIGKILL);
  two illustrative doctests re-fenced as text.

## [0.0.1] - 2026-10-09

Tag `v0.0.1-tappa9.0`: everything up to Tappa 9.0 plus the 2026-10-08/09
hardening round (PR #145, #155–#170). All High/Medium findings of
`docs/audit/NN_BUG_AUDIT_2026-06-09.md` and
`docs/audit/NN_REVIEW_2026-10-08.md` closed and verified on the QEMU lab
guest (kernel 6.8, BPF-LSM).

### Security / safety
- RAG release gates (golden ≥ 90 %, latency, e2e format) fail fast when
  `target/kb` is missing instead of silently benchmarking the built-in
  seed; the lab ships the corpus and reports 28/30 = 93.3 % on the real
  ATT&CK + Sigma dumps (the earlier 36.7 % was the seed-only artefact).
- `nn-admin rotate-keys add --new-roles` accepts every role keyword the
  agent understands (`canary-manage`, `fim-manage`, `net-read`,
  `triage`, …), not only the legacy five: least-privilege keys for
  canary/FIM operators can now be granted from the CLI instead of
  hand-editing `admin.pub` or granting `all`. The install-bootstrapped
  key's roles (`unlock,audit-read` only) are documented in
  `docs/operator/COMBAT_RECOVERY.md` §1.1.
- An orphan TCP close (no pending flow) is logged at WARN with the
  5-tuple instead of silently dropped at debug.
- The outbound UDP sensor now observes unconnected `sendto()` traffic
  (destination read from `msghdr->msg_name`), rate-limited kernel-side
  to one netflow row per `(pid, destination)` per second. Before, only
  connected UDP sockets produced a row: QUIC-like beacons and raw-UDP
  exfil through an unconnected socket were invisible.
- Boot-time audit self-check: a signed `agent_boot` entry is appended at
  startup; an unwritable audit log is fatal in enforcement mode
  (`NN_AUDIT_ALLOW_UNWRITABLE=1` to override, detect-only warns).
- Posture corroboration ledger is scoped per login session (`loginuid`
  of the owning pid; host-level activity is its own scope): a weak
  ENGAGED-tier signal from one user/container no longer corroborates a
  blunt COMBAT-tier signal from an unrelated one into a host-wide COMBAT.
- Audit Medium round: TCP netflow rows and `flow_id` carry the real
  source address/port (close-time), not `0.0.0.0:0`; the COMBAT
  kill-tree spares host-critical descendants (sshd, watchdog) via the
  ladder guard; the `detections/` chain logs are in PROTECTED_INODES;
  mass-write ignores a session's own `/run/user/<uid>/` writes only;
  `nn-admin detection-set-status` reports a persistence failure (exit
  10) distinctly from "not found" (exit 9).
- `/etc/northnarrow` directory inode is now in PROTECTED_INODES
  (mutation-denied): the config tree can no longer be renamed or removed
  from under the agent by a root process outside PROTECTED_PIDS.
- Canary deploy enforces a path policy (no system trees, no `/run`, no
  NorthNarrow state/config, no `..`, no symlink escape, `O_NOFOLLOW`
  write): a leaked admin key can no longer write root-owned files at
  arbitrary paths through `nn-admin canary deploy`.
- Anti-tamper `task_kill` hook is deny-by-default: every userspace signal
  towards a protected pid is refused (previously only SIGKILL/SIGTERM, so
  `kill -INT/-HUP/-QUIT/-STOP` from root stopped or froze the agent).
  Allowed: signal 0, self-signals, signals between protected pids
  (watchdog ↔ agent) and PID 1 with the armed nonce. The watchdog now
  registers its own pid in PROTECTED_PIDS at boot (design §7.1; before,
  it was protected only if its pidfile pre-dated the agent's start).
- R004 (fileless exec) also matches `/dev/fd/N` (what glibc's `fexecve`
  really passes) and `/memfd:` pseudo-paths; previously a memfd exec on
  Ubuntu 24.04 was undetected.
- File canaries deployed at arbitrary paths trip again on READ: the FIM
  drain's BUG-012 v2 gate now forwards `Opened` events for canary inodes
  (published by the K3 index rebuild) to the rule engine.
- Watchdog respawn v2 (`docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md`): a
  crashed agent is restarted with `systemctl start` under its own unit
  (full ExecStart argv, own cgroup/caps/ProtectHome) instead of as a
  fork-exec child of the watchdog's 64 MiB / 2-cap sandbox. `BindsTo=`
  removed from the watchdog unit; `StartLimitIntervalSec=0` on the agent
  unit. New flags `--respawn-backend {auto,systemd,exec}` and
  `--agent-unit`. Closes `watchdog-respawn-1` and `combat-avail-1`.
- Audit Beta-blockers closed: `abi-modpath-1` (module path sensor now
  keeps 16 components and flags truncation; R018 never auto-kills on an
  unverifiable prefix), `posture-1` (two blunt COMBAT-tier signals in one
  round cap at ENGAGED), `ebpf-lsm-1` (LSM deny-hook attach shortfall is
  fail-closed: the agent refuses to start unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`). `at-authz-2` was already closed by #142.
  **Wire change:** `ModuleLoadRaw` grows from 312 to 568 bytes (eBPF and
  userland from the same `common` crate — rebuild both).
- `CAP_KILL` added to the agent's `CapabilityBoundingSet`; without it
  KillProcess could only signal root-owned targets. New boot preflight
  (`response/caps_preflight.rs`) refuses to start in enforcement mode when
  `CAP_KILL` is missing and logs any other missing capability.
- `kill_process_tree` refuses PID 0/1 as a root before walking `/proc`
  (PID 0's children are init + kthreadd, i.e. the whole host) and never
  yields PID 1/2 as descendants.
- Quarantine refuses to vault + unlink binaries under system prefixes
  (`/usr/bin`, `/usr/lib`, `/etc`, `/boot`, …) and NorthNarrow's own paths.
- Posture: the corroboration ledger is cleared on every COMBAT release
  path (audit `posture-2`).
- NN-L-NET-005 / NN-L-NET-013 stateful windows evict idle keys (audit
  `catchall-1`, unbounded memory growth on a long-lived agent).

### Fixed
- Agent unit: `/etc/northnarrow` added to `ReadWritePaths` — under
  `ProtectSystem=strict` the installed agent could not append its own
  signed audit log (EROFS) nor bootstrap `agent_id`/`agent.sig.key`.
- Agent unit: `RuntimeDirectoryPreserve=yes` — a respawn-v2 restart no
  longer wipes `/run/northnarrow` (watchdog pidfile, shutdown marker,
  honeypot baits).
- `install.sh` now ships `combat-rules.v4/.v6` from `configs/` (missing
  ruleset = no NetworkIsolator = admin socket silently absent = watchdog
  stuck-recovery restart loop) and lifts `chattr +i` on the state dir
  for upgrades. The agent logs an ERROR when the ruleset is missing.
- CI: `cargo fmt`, `cargo clippy -D warnings` and the `test` job are green
  again; `ade-build` no longer runs out of disk on the hosted runner;
  `ebpf-build` pins `bpf-linker 0.10.3` (0.11 needs a system LLVM 21+).
- Test flake `anti_tamper::network_isolate::release_is_idempotent`
  (ETXTBSY race on the mock `iptables-restore` script).
- Dependencies: `rustls` 0.23.45 (RUSTSEC-2026-0285), `crossbeam-epoch`
  0.9.21 (RUSTSEC-2026-0204).

### Added
- `deploy/lab/nn-lab.sh`: QEMU/KVM Ubuntu 24.04 lab guest (kernel 6.8,
  `lsm=…,bpf`) with sync/build/test-e2e/test-ignored/install/respawn-check
  sub-commands; runs from WSL2 with nested virtualization.
- `cargo audit` CI job, Dependabot (cargo + GitHub Actions), `SECURITY.md`.

## [0.0.1] — 2026-06-10

Tappe 0–9.0 as described in `ROADMAP.md`: eBPF sensors, rule engine,
response executors, local ADE (candle), posture machine, anti-tamper
(BPF-LSM + watchdog), signed admin channel, detection store.
