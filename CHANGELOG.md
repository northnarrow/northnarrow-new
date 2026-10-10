# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow the ROADMAP "Tappe"; `0.0.1` covers everything up to Tappa 9.0.

## [Unreleased]

### Fixed
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
