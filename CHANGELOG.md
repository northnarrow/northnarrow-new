# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow the ROADMAP "Tappe"; `0.0.1` covers everything up to Tappa 9.0.

## [Unreleased]

### Security / safety
- Anti-tamper `task_kill` hook is deny-by-default: every userspace signal
  towards a protected pid is refused (previously only SIGKILL/SIGTERM, so
  `kill -INT/-HUP/-QUIT/-STOP` from root stopped or froze the agent).
  Allowed: signal 0, self-signals, signals between protected pids
  (watchdog ↔ agent) and PID 1 with the armed nonce.
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
