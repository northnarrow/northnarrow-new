# Capability program (Wave 4)

From 2026-10-20 NorthNarrow grows capability by capability towards level 3
("extended or mature") on the thirty capabilities below. This file is the
program's tracker: each lab PR adds one note at the end, with the capability
it moves, what was verified in the lab and what is still open.

Levels, as self-assessed from the code and the lab, never from marketing:

- **0** absent;
- **1** limited or partial;
- **2** present, tested in the lab;
- **3** extended or mature: complete, documented, with negative tests, verified
  in the lab on every supported kernel. Where a capability's level 3 needs
  something only a third party can give (independent validation, a platform
  vendor's entitlement or driver signature), the note says so and the level
  stays below 3 until it exists.

No note claims an effect that was not measured. A capability's level changes
only in the table below, in the same PR as the evidence.

## Capabilities

Levels as of 2026-11-03: a re-assessment of `main` at `5f8046f3` against
the code, the notes below and the public CI runs, made apart from the lab
PRs (not a third party's: C29 is unchanged). Lot 274's note says what
changed and why. The evidence column names what each level stands on; a
number in parentheses is a lab PR.

| ID | Capability | Level (2026-11-03) | Evidence | Target |
|---|---|---|---|---|
| C01 | Linux sensor | 2 | verified on Ubuntu 22.04, 24.04, 26.04, Debian 12, 13 and AlmaLinux 9 (last verified on 10/10, before Wave 4) (`docs/operator/KERNEL_COMPATIBILITY.md`); the 13-source sensor contract, the signed capability manifest (218, 271); verifier 77 of 77 programs on 6.8 and 6.12 (238); privileged suites in KVM guests, 2 on a pull request, 5 every night (227): green 6 nights of 12 from 22/10 to 02/11, the red ones a lab harness race and a test fixture (lot 274), not the sensor | 3 |
| C02 | Windows sensor | 0 | no sensor code; `ci.yml` checks the portable crates for Windows targets, which is preparation, not support | 3 (user-mode first; a kernel driver needs WHCP signing) |
| C03 | macOS sensor | 0 | no sensor code (as C02) | 3 (needs Apple's Endpoint Security entitlement) |
| C04 | ARM64 support | 0 | aarch64: the portable crates' check only (`ci.yml`); the agent and the eBPF object are built for x86_64 only | 3 |
| C05 | Process telemetry | 1 | exec only, with argv, parent and `start_ns` (`crates/nn-model/src/event.rs`; the parent's key, 238); no fork, exit or credential-change event (`crates/nn-core/src/contract/mod.rs`): those hooks serve the exploit guard only (219) | 3 |
| C06 | File telemetry and FIM | 2 | the LSM `file_open` observer and the FIM drain (`docs/operator/SENSOR_CONTRACT.md`); 25 FIM rules (`docs/detection/RULE_CATALOGUE.md`); rename and unlink bursts (225); setattr from 6.9; multi-match (236) | 3 |
| C07 | Endpoint network telemetry | 1 | outbound TCP connect v4/v6, flows at close, listen, outbound UDP and DNS queries (`SENSOR_CONTRACT.md`; 229); no inbound connection (`agent-ebpf/src/tcp_close.rs` drops passive sockets), no DNS answer, no TLS fingerprint in a flow (the parsers in `crates/nn-linux/src/worker/parse.rs` have no sensor); 224 added verdicts (C12, C14), not telemetry | 3 |
| C08 | Identity and ITDR | 0 | no authentication event source (the FIM on `authorized_keys`, PAM and sudoers is C06) | 3 |
| C09 | Cloud telemetry and posture | 0 | no IMDS code, no cloud context | 3 |
| C10 | Network detection (NDR) | 0 | the beacon and fan-out rules judge the endpoint's own flows (C07, C14); no protocol log | 3 |
| C11 | Containers and Kubernetes | 1 | the agent on a container host (`docs/operator/CONTAINER_HOST_DEPLOY.md`); R013 and EPG-002 detect an escape to the host; no container or pod id in the records | 3 |
| C12 | Synchronous inline blocking | 2 | the exec policy at `bprm_check_security`: `-EACCES` per file class and lineage, LD_PRELOAD and LD_AUDIT, `mmap_file`; armed on 4 kernels, MS-01/02/03/32 refused (226); the `socket_connect` deny of the blocklist (224); EPG enforce, SIGKILL in the kernel (219); exec quarantine (223). All EXPERIMENTAL and off by default (`docs/design/EXEC_POLICY.md`); the behaviour proofs on one kernel | 3 |
| C13 | Malware prevention | 1 | exec quarantine with a confined scanner (223), its signed hash list shipped empty (`docs/design/EXEC_QUARANTINE.md`), the default ELF heuristics resume the process; the exec policy refuses execs from memfd, deleted files and `/dev/shm` (226); EXPERIMENTAL, off by default | 3 |
| C14 | Behavioural detection and correlation | 2 | 93 rules; the multi-match engine (236); chains with late execs (235, 244); the posture and the COMBAT ladder; golden replay of 29 cases (228, 243); the priority bus: tamper rows lost 3,699 → 0 (267) | 3 |
| C15 | Custom rules, declarative format | 1 | the rules are compiled Rust; the operator has signed overlays only: per-rule off/audit/alert/enforce with exemptions (`docs/operator/RULE_POLICY.md`, 236), the lists, the exec policy's cells | 3 |
| C16 | Structured ATT&CK mapping | 2 | `Rule::attack()` is mandatory: 93 of 93 rules on 66 techniques and 12 tactics of ATT&CK 20.0, pinned by the STIX bundle's commit and sha256 (`docs/detection/ATTACK_COVERAGE.md`); `mitre` and `mitre_version` in every record, a revoked or unlisted id fails the tests; the records of 44 rules carried their typed ids on 4 guests (221). The coverage is not measured: 0 `campaign` rows, the V2 campaign not run | 3 |
| C17 | Response on processes and files | 2 | NEUTRALIZE on every offender, a signed outcome and unlock (217); intent and outcome signed per action, the actions in parallel: 400 kills' longest wait 19 s → 1.6 s (270); the quarantine vault v2 with restore (238) | 3 |
| C18 | Host network isolation | 1 | ISOLATE per family, IPv4 and IPv6, with read-back, retry and a signed outcome, in the lab on 24.04 only (217); the signed management carve-out (`configs/combat-allow.cidrs`) and unlock; only inside an engaged COMBAT (`docs/operator/COMBAT_RECOVERY.md`) | 3 |
| C19 | Rollback and remediation | 1 | copy on first write (222; EXPERIMENTAL, off by default): a signed restore of 51 of 51 files on XFS, 50 of 51 on ext4 (over the 16 MiB cap); in-place rewrites only: `x.enc` then an unlink or rename over `x`, and `truncate` by path, are not covered (`docs/design/COPY_ON_FIRST_WRITE.md`); no remediation of persistences | 3 |
| C20 | Automation, playbooks, SOAR | 1 | the automatic COMBAT ladder and the per-rule policy; no playbook, webhook or OpenC2 | 3 |
| C21 | SIEM integration and export | 0 | no export of the detections ("until R15 exports the chains off the host", `docs/operator/HEARTBEAT.md`); local JSON reads and the heartbeat pull (270) only; no OCSF, syslog or OTLP | 3 |
| C22 | Backend and multi-host correlation | 0 | the heartbeat's external verifier (270) is not a backend | 3 |
| C23 | Anti-tamper and self-defence | 2 (provisional) | 21 LSM deny hooks and 6 optional (lot 273: the cgroup move guard; lot 273b: the write deny `file_permission`, the guard's third program; lot 273c: `task_setrlimit`, `task_setscheduler`, `task_setnice`, `task_setioprio`), the fail-opens counted and signed (215); start refused without BPF LSM, a hook's self-test (218); a fail-visible watchdog (216); the signing key decided once at boot (265, 268); unprivileged workers under Landlock and seccomp (272); the signed heartbeat's external verifier sees a stop in 6.5 s (270). Provisional: on systemd 257 and later `systemctl kill -s SIGKILL` stopped the agent through `cgroup.kill` outside a maintenance window, and any root shell could kill, freeze or move the units' cgroups on every kernel (tamper case C31; C33's `systemctl stop` was refused all along — it read C31's kill); closed by lot 273 (#489: the units' cgroups protected, the move guard; C15, C20, C31, C65–C75 refused and signed and C76 allowed inside a window on the five guests); lot 273b (the review of #489): the units' and their slices' resource limits (an OOM kill inside the write, a starvation), a cgroup v1 hierarchy where systemd runs the unified one, a write through a descriptor opened earlier and the protected pids' `oom_score_adj` refused outside a window, the move guard self-tested at every boot (C12, C18, C77–C86); lot 273c (the review of #490): another process's `prlimit`, `renice`, `chrt`, `taskset`, `ionice` of a protected process refused (four deny hooks, 21 in all), PID 1 closed to attach-mode access, no resource value below a floor registered (the agent's start, the watchdog's check of a respawn, a window's close), systemd's copy of a refused `set-property` taken back by a reload, the host's drop-ins judged by their value for our units (never moved), cgroup v1 refused only where it moves or freezes (C89–C102), provisional until its review | 3 |
| C24 | Offline and air-gapped operation | 2 | the agent's only traffic of its own is the DNS probe to 127.0.0.1:53 (`crates/nn-linux/src/telemetry_probe.rs`); updates are an operator's action; the attestation is verified offline with a bundle (`docs/operator/INSTALL_UPGRADE_UNINSTALL.md`) | 3 |
| C25 | Data sovereignty | 2 | the telemetry stays on the host; no model in the root process (214); the README's compliance table states design properties, not certifications (its NIS2, GDPR, DORA and CRA badges were removed on 2026-11-03) | 3 |
| C26 | Open code, licence, inspectability | 2 | Apache-2.0 (`Cargo.toml`), the eBPF object Dual MIT/GPL, a public repository, the module map | 3 |
| C27 | Product supply-chain security | 1 | SLSA provenance, a CycloneDX SBOM and a signed RPM in `release.yml`; install takes attested trees only (220); dependency audit, Dependabot. No release with assets since 09/10, `release-check` not run in Wave 4, SHA256SUMS and the RPM key not attested | 3 |
| C28 | Safe content release | 1 | a transactional upgrade with a byte-for-byte rollback (220); signed overlays with an anti-rollback floor; the content is in the binary: no channel, canary or ring | 3 |
| C29 | Independent public validation | 0 | the public CI runs are "a step towards, not, an independent validation" (227); the V2 matrix is empty (`docs/validation/matrix.md`) | 3 (needs third parties) |
| C30 | Generative AI and data governance | 0: absent by design, no AI on the host | the on-host LLM advisor and its RAG removed (214); the README's EU AI Act row: "no AI system on the host"; the governance of data is C25's | 3 (off the host only: 214) |

## Order

1. Correct before extending: the defects a static review of `baf4c25` found
   that are still on `main` (BPF command constants, watchdog exit status,
   COMBAT outcomes, upgrade rollback, boot phases and signed degradations,
   ATT&CK identifiers).
2. Linux telemetry (C05, C06, C07, C11), then prevention (C12, C13, C17, C18),
   detection (C14, C15, C16), integration and backend (C19–C22, C24, C28),
   platforms (C01, C04, then C02), product trust (C25–C27, C29, C30).

## Notes on the lab PRs

- **Wave 4 — the on-host LLM advisor removed, lab PR 214 (C30, C14).**
  Removed: the ADE (`agent/src/ade`, a Foundation-Sec-8B GGUF model run
  inside the agent on the execs no rule matched), its RAG knowledge base
  (`agent/src/rag`, `cargo xtask rag-kb`, `docs/kb-sources`, the ATT&CK and
  Sigma licence texts), the XAI explanations (`agent/src/xai`,
  `common::xai_types`), the vendored `candle-core`, every model and tokenizer
  dependency (candle, tokenizers, tantivy, num_cpus; about 150 crates out of
  `Cargo.lock` and `fuzz/Cargo.lock`, no version changed), the ADE examples
  and `diag_hw`, the `ade_verdict` and `ade_preparse` fuzz targets, the
  `ade-build` and `ade-unit-test` CI jobs, the posture's modulation of
  model verdicts and the operator documents of the model. Why: a multi-GB
  model inside the root agent process, fed with strings an attacker writes,
  was the largest attack surface of the agent; its accuracy was never
  measured; it cost gigabytes of RAM on a server; mature EDRs keep on-host
  detection deterministic, and an AI assistant, if any, belongs off the
  enforcement path (a future analyst assistant on the backend). What
  replaces it: nothing on the enforcement path — detection is the rules,
  their correlation, the posture and the COMBAT ladder, as on every host
  without the model (which no release shipped); an exec no rule matches gets
  no detection. The removed flags (`--no-ade`, `--ade-model`,
  `--ade-timeout`, `--ade-prompt`, `--ade-threads`) and variables
  (`NN_ADE_*`) are accepted and ignored with one WARN each
  (`agent/src/removed_settings.rs`, `docs/operator/UPGRADE_NOTES_WAVE4.md`);
  detection records the advisor wrote before still decode and chain-verify
  (`DetectionPath::Ade`, `AdvisorAction`, byte-exact tests). Capability
  effect: **C30 changes meaning** — it no longer covers an on-host
  generative model: there is no generative AI on the host, by design, and
  C30 now tracks the governance of data and of any future AI assistant off
  the host. Its level is not changed by this note (nothing was measured
  under the new meaning); C14 is unchanged (its detection was deterministic
  already). Verified on the host: `cargo fmt`, the three clippy runs
  (workspace, the agent with `test-privileged,debug-trigger`, the posture
  demo) clean; `cargo test --workspace` 2,388 passed, 0 failed, 11 ignored
  (about 420 tests left with the removed code); the fuzz build, 11 targets,
  every committed seed and regression replayed. On a guest,
  still open: the start with an old unit and drop-in (WARN, no crash), the
  agent's RSS before and after, the rules and COMBAT acting, the package
  contents. The unit's memory limits (9G/11G, sized for the model) are not
  re-sized until that RSS is measured.
  - Lab: On Ubuntu 24.04 the upgrade from the tree without this lot kept an old unit drop-in with the five advisor flags and four variables: after it the agent started with one WARN per removed setting (9), no "unexpected argument", no `weakening_env` for them, `--help` without the flags, and a respawn by the watchdog behaved the same; RSS 30.6 MB after against 33.2 MB before (no growth), the agent binary 18.9 MB → 11.1 MB; the tarball (66 entries) and the .deb (73) hold no model path and NOTICES no advisor section (the agent unit's comment, embedded for the self-integrity check, still names the old model: wording only). Gate: the integration tree of lab PRs 214–218 on `main` with lab PRs 176–213: Ubuntu 22.04 (5.15) 47 suites, 79 passed, 0 failed; Ubuntu 24.04 and Debian 12, 47 suites, 78 passed, 1 failed — `audit_verify_e2e`, whose expected row list did not have lab PR 218's new boot-time `capability_manifest` row (the expectation is updated in lab PR 218 and passes on 22.04 with it); Debian 13 (6.12) 47 suites, 78 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); anti-tamper suite on 24.04 and 22.04: every case OK but C64 (lab PR 215's enumeration case, which found a stale own link id, a recorded follow-up); deny fail-opens 0 over the whole run; `upgrade-check` from the tree without these lots OK on 24.04 (with the old advisor drop-in in place); host 2,480 passed, 0 failed.
- **C23 — BPF command numbers and the deny hooks' fail-opens, lab PR 215.**
  Order item 1, correct before extending: P0 C-02 / G-01 / TD-03 and
  Q9-06 of the static review of `baf4c25`, still on `main` and not in the
  audit tracker. The level stays 2: a correction, not an extension.
  - What was wrong: the `bpf` LSM hook had its own copy of the uapi
    `bpf_cmd` numbers with `BPF_LINK_GET_FD_BY_ID = 31`. The uapi value is
    30; 31 is `BPF_LINK_GET_NEXT_ID` (a hand count goes wrong at the alias
    `BPF_PROG_RUN = BPF_PROG_TEST_RUN`). `bpf_cmd_name` had the same 31. A
    handle by id on one of the agent's links was granted in enforce mode and
    left no record in either mode. The enumeration `bpftool link list`
    steps through was refused when it started from one of the agent's link
    ids, and recorded as an anti-tamper denial (a false NN-L-AT-001, COMBAT).
    Detaching or updating a hook stayed refused (EBPF-010 reads the link
    from the fd). The operator guide said every handle by id was refused.
    Separately, a deny hook whose kernel read failed let the operation
    through and left no trace (`Err(_) => return 0`).
  - What changed: one copy of the numbers, `common/src/bpf_cmd.rs`
    (`no_std`), for the eBPF programs and userland; the hook's command set
    is `bpf_cmd::observed`. Tests compare every number with
    `/usr/include/linux/bpf.h` and with `enum bpf_cmd` in the running
    kernel's BTF, and both fail with 31. A scan fails on any other constant
    copy; it lists 22 on the starting tree. A per-CPU `DENY_FAIL_OPEN` map
    (20 hook slots) is bumped on every path where a hook cannot decide. The
    agent samples it every 10 s: a WARN, a signed `deny_fail_open` entry
    (paced, none lost), and `deny_fail_open_total` / `deny_fail_open` in
    the signed status. The posture is not raised. `anti-tamper.sh` has C63
    and C64, C43 also asks for a write handle on `DENY_FAIL_OPEN`, and the
    enforce-mode privileged e2e checks the link deny and the enumeration.
  - What the lab must verify: every LSM program still loads and attaches
    on the five gate kernels (the `bpf` hook grew from 502 to 641
    instructions, the other deny hooks by 10 to 70) and the boot logs
    `deny fail-open counters armed hooks=20`. In observe mode C63 is
    granted and recorded as NN-L-BPF-002; in enforce mode it is refused and
    recorded (`deny=bpf_link`). C64 is allowed with neither `deny=bpf_link`
    nor NN-L-BPF-002 in both modes, and both rows deviate on the base agent.
    `bpf_guard_enforce_refuses_protected_pids_write` passes.
    `nn-admin status --key` shows `deny fail-open : 0` after the whole run
    on every kernel. A counter written by hand in observe mode gives the
    WARN, one signed entry and the status line. In enforce mode
    `bpftool link list` stops at the first NorthNarrow link with one
    recorded denial (the documented trade-off, as `bpftool map show`).
  - Host: `cargo xtask build-ebpf --release`; `cargo fmt --all -- --check`
    and the three clippy runs (workspace, the agent with
    `test-privileged,debug-trigger`, `posture_demo`) are clean.
    `cargo test -q --workspace`: 2,810 passed, 0 failed, 21 ignored, with
    18 new tests. `anti-tamper.sh --selftest`: 77 checks, 0 failed (64 on
    the starting tree). On the starting tree the new tests do not compile
    (new modules). Run against it, the source scan lists the 22 copies and
    the names test fails (`link_get_fd_by_id` named "other"). The new
    selftest fails 8 of its checks on the starting tree's probe. With 31
    put back, the header, BTF, names and observed-set tests fail.
  - Lab: On Ubuntu 24.04 before this lot, a handle by id on one of the agent's links was neither denied nor recorded (C63) and the enumeration from its link ids was recorded as an attack (C64); after it, on 24.04, Debian 12, 22.04 (5.15 verifier) and Debian 13 the deny hooks attach (deny_attached = expected), C63 is recorded as NN-L-BPF-002 (observe mode), a walk of 46 links from 0 enumerates them all with no record, the deny fail-open counter stays 0 over the whole run and an injected fail-open gives the WARN, the signed `deny_fail_open` row and the status line. C64's case still deviates: the agent's own-id map held one link id (49) that no live link has on a clean boot — a stale entry, a recorded follow-up. Gate: the integration tree of lab PRs 214–218 on `main` with lab PRs 176–213: Ubuntu 22.04 (5.15) 47 suites, 79 passed, 0 failed; Ubuntu 24.04 and Debian 12, 47 suites, 78 passed, 1 failed — `audit_verify_e2e`, whose expected row list did not have lab PR 218's new boot-time `capability_manifest` row (the expectation is updated in lab PR 218 and passes on 22.04 with it); Debian 13 (6.12) 47 suites, 78 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); anti-tamper suite on 24.04 and 22.04: every case OK but C64 (lab PR 215's enumeration case, which found a stale own link id, a recorded follow-up); deny fail-opens 0 over the whole run; `upgrade-check` from the tree without these lots OK on 24.04 (with the old advisor drop-in in place); host 2,480 passed, 0 failed.
- **C23 — fail-visible supervision and process hardening** (static review
  of `baf4c25`: C-43, C-44, G-05, G-06, TD-08, TD-10; Order item 1, the
  watchdog exit status).
  - Watchdog: every failure exits non-zero with a status of its own
    (`ExitReason`, 10–20; the failed pidfd wait was a clean 0 that
    `Restart=on-failure` never restarted) and leaves a `watchdog_exit`
    record. Unit: `Restart=always`, `RestartPreventExitStatus=0`, backoff
    2 s → 60 s, no start limit (never stays down; each failed run
    recorded), `OnFailure=` for a unit-level failure: the new
    `northnarrow-watchdog-failed.service` (`watchdog_failed`, with
    systemd's result). The agent signs `watchdog_gone`.
  - Stuck recovery evicts from `PROTECTED_PIDS` only after the pidfd
    confirms the exit; a live agent stays protected and supervised
    (`stuck_recovery_failed`). The SIGKILL wait is bounded (10 s).
  - Liveness: the ping reads the event loop's round count (unsigned
    `LoopProgress`); a count that stands still over three pings in a row
    (90 s or more) is a stuck agent (`event_loop_stalled`), even with the
    admin socket answering.
  - Hold: bounded retries (10, 20, 40 min, then hourly; they supersede
    WDG-004's operator-only restart), a `STATUS=` line with its length, an
    ERROR every 10 min, `hold_retry` / `hold_ended`.
  - Hardening: the agent is not dumpable (`PR_SET_DUMPABLE` 0,
    `RLIMIT_CORE` 0), `LimitCORE=0` and `TimeoutStartSec=` in both units,
    `/run/northnarrow` 0700 from install.sh, the watchdog and every unit.
  - Evidence so far: unit tests (exit statuses, a real failed pidfd wait,
    the recovery verdict on live processes, the stall tracker, the
    two-frame ping, the hold schedule), the unit contract with an offline
    `systemd-analyze verify`, install.sh's 0700. The guest checks (the
    pidfd wait made to fail, the watchdog failing repeatedly, a
    stalled loop, a refused recovery) are owed; the level stays 2 until
    they pass on the supported kernels.
  - Lab: On Ubuntu 24.04 (and the unit checks on Debian 12, 22.04, Debian 13): a forced pidfd-wait failure exits the watchdog with status 20 after a signed `watchdog_exit`, systemd restarts it (NRestarts 0 → 1) and the agent keeps its pid; twelve failures in a row never leave it `failed` (`StartLimitIntervalUSec=0`), the OnFailure handler signs `watchdog_failed`; a stalled event loop (debug trigger) is caught after 3 pings and signed `event_loop_stalled`; a refused recovery keeps the agent's pid and pidfile and signs `stuck_recovery_failed`; the bounded hold retries and signs `hold_retry`; SIGKILL restarts with a new pid, SIGTERM stops cleanly, SIGHUP is ignored. No core of either daemon: `Max core file size 0` and no "could not forbid core dumps" line (the SIGSEGV the probe sends through systemd is refused by the agent's own signal protection, so no crash happened to test). Gate: the integration tree of lab PRs 214–218 on `main` with lab PRs 176–213: Ubuntu 22.04 (5.15) 47 suites, 79 passed, 0 failed; Ubuntu 24.04 and Debian 12, 47 suites, 78 passed, 1 failed — `audit_verify_e2e`, whose expected row list did not have lab PR 218's new boot-time `capability_manifest` row (the expectation is updated in lab PR 218 and passes on 22.04 with it); Debian 13 (6.12) 47 suites, 78 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); anti-tamper suite on 24.04 and 22.04: every case OK but C64 (lab PR 215's enumeration case, which found a stale own link id, a recorded follow-up); deny fail-opens 0 over the whole run; `upgrade-check` from the tree without these lots OK on 24.04 (with the old advisor drop-in in place); host 2,480 passed, 0 failed.
- **Lab PR 217 — truthful response outcomes: the COMBAT ladder, the
  isolation, the unlock.** C17 (response on processes and files), C18 (host
  network isolation); static review of `baf4c25` P0 C-30, C-32, C-35, G-02,
  G-03, TD-07, TD-11; the NN-AUD-243 residue
  (`docs/operator/COMBAT_RECOVERY.md` §3).
  - C17: NEUTRALIZE handles every offender — it returned at the first one it
    could not contain, the others left running with their binaries in
    place — and signs one `combat_outcome` row with each offender's kill
    and quarantine outcome and the host-critical ones spared (`success`
    only when all are contained).
  - C18: the isolation state is per IP family, set and cleared only from
    the tables read back (`iptables -S` / `ip6tables -S`) after an engage
    or a release, public in `nn-admin status`; every iptables, ip6tables
    and nft invocation is bounded (10 s, then killed). ISOLATE is no longer
    marked done before it runs: the stage reads ISOLATE once IPv4 is
    isolated, each attempt's per-family outcome is signed, and an attempt
    that left a family not isolated is retried (5 s, 10 s; three attempts).
  - C17 / C18: the release hook returns the read-back and runs before the
    posture changes: an unlock (or a force-posture out of COMBAT) whose
    teardown did not leave the tables clear is answered `ActionFailed`
    (`nn-admin` exit 9), recorded `failure: release_failed`, and COMBAT
    stays. The unlock is a signed `OperationCode::Unlock` payload whose row
    names the signer; the legacy nonce signature is refused (no
    compatibility flag: a downgrade switch on the release of the isolation,
    and `nn-admin` ships with the agent).
  - Evidence so far: unit tests with fake actuators and fake filter tables
    — an offender uncontainable first and the others still killed (real
    processes), an `ip6tables-restore` that fails, a teardown whose `-X` is
    refused, a hung `iptables`, an ISOLATE failing then partial then done,
    retries exhausted, a release hook that fails (posture, reply and audit
    row), the legacy unlock refused — six of them ported to the base tree
    fail there; the three clippy runs and `cargo fmt` clean, `cargo test
    --workspace` 2,811 passed, 0 failed, 21 ignored. Levels unchanged (C17
    2, C18 1): the guest checks are owed — COMBAT forced to ISOLATE on
    Ubuntu 24.04 and Debian 12, `ip6tables` made to fail, the chain held
    during an unlock, the signed unlock and the older `nn-admin` refused.
    Open: an IPv6 hole that a retry cannot close (no `ip6tables`, no IPv6
    filter table) is recorded, not closed; offenders attributed after the
    NEUTRALIZE are soft-blocked, not killed; an admin operation still
    proceeds when its audit row cannot be written (G-02, by design — only
    the COMBAT records are queued and counted).
  - Lab: On Ubuntu 24.04, a COMBAT driven to ISOLATE: status per family (IPv4 and IPv6 isolated), both tables with the chain, its DROP and one jump per base chain, the signed rows in order (INVESTIGATE, NEUTRALIZE outcome, ISOLATE outcome attempt 1 of 3 v4 done v6 done); with ip6tables made to fail (an unparsable nft rule), IPv4 isolated and IPv6 FAILED were reported and signed, three attempts at 0, 10 and 25 s ending in "ISOLATE did not take after every attempt" (journal and row; the probe read before the third); the signed unlock released both families (read back), recorded `key_fp` and `protocol: signed`, a second unlock said "not in COMBAT"; the legacy unlock is refused; this nn-admin against the previous agent exits 5 and says which nn-admin to use. Gate: the integration tree of lab PRs 214–218 on `main` with lab PRs 176–213: Ubuntu 22.04 (5.15) 47 suites, 79 passed, 0 failed; Ubuntu 24.04 and Debian 12, 47 suites, 78 passed, 1 failed — `audit_verify_e2e`, whose expected row list did not have lab PR 218's new boot-time `capability_manifest` row (the expectation is updated in lab PR 218 and passes on 22.04 with it); Debian 13 (6.12) 47 suites, 78 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); anti-tamper suite on 24.04 and 22.04: every case OK but C64 (lab PR 215's enumeration case, which found a stale own link id, a recorded follow-up); deny fail-opens 0 over the whole run; `upgrade-check` from the tree without these lots OK on 24.04 (with the old advisor drop-in in place); host 2,480 passed, 0 failed.
- **Lab PR 218 — boot integrity: checks before the attach, the deny
  self-test, signed degradations, a trust level and a capability
  manifest.** C01 (Linux sensor), C23 (anti-tamper and self-defence);
  external review G-09, G-11, G-12, AR-09, P0 C-13, P0 C-14
  (`docs/operator/BOOT_INTEGRITY.md`).
  - C23: without `bpf` in the active LSM list the deny hooks attached and
    never ran, behind one WARN. The start is now refused before anything
    attaches (exit 78) unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, signed
    either way; after the attach a child of the agent signals it and must be
    refused (`task_kill`), so hooks attached but not run refuse the start
    too. The self-test's own denial never reaches the posture.
  - C01 / C23: the capability, install-manifest and audit checks run before
    any attach, in typed phases (`BootSequence`, an `AttachPermit` the
    attach takes, a test on `main.rs`'s order); every sensor fallback and
    degradation is signed within 60 s and listed by `nn-admin status --key`;
    the network drain runs without its log instead of staying off.
  - Trust level L0–L3 and a capability manifest (kernel, BTF, LSMs, deny
    hooks and self-test, each sensor's attach point, host hardening,
    degradations) signed at every boot, read with `nn-admin capabilities
    --key`.
  - Levels unchanged (C01 2, C23 2): the evidence is the lab's, owed on
    Ubuntu 24.04 and Debian 12 — a guest booted without `bpf` in `lsm=`
    (refusal, then L0 under the opt-in), the self-test's refusal with the
    LSM list hidden, a netflow log made unopenable, the forced fallbacks.
    Open: the self-test exercises one deny hook, not each of the 16; the
    host's hardening is listed, not scored; `main()` is still one body (one
    function per phase is the follow-up).
  - Lab: On Ubuntu 24.04, Debian 12, 22.04 and Debian 13: the five boot phases in order (preflight steps through bpf_lsm, attach, self-test, attest, subsystems), the deny self-test refused and its signal consumed (no NN-L-AT-001 for it), trust level L3, the signed capability manifest equal to `nn-admin capabilities`, the unsigned status withholding the trust level; NetFlowDb made unopenable: the drain ran without persistence and signed `net_drain`; three sensor fallbacks signed within 60 s; a read-only audit log and a dropped CAP_KILL refused before any attach. On 22.04 booted without `bpf` in `lsm=`: the start refused with exit 78 and signed rows, the opt-in start at L0, a hidden LSM list caught by the self-test (`refused_by deny_self_test`), the guest restored (39 of 39 checks). Gate: the integration tree of lab PRs 214–218 on `main` with lab PRs 176–213: Ubuntu 22.04 (5.15) 47 suites, 79 passed, 0 failed; Ubuntu 24.04 and Debian 12, 47 suites, 78 passed, 1 failed — `audit_verify_e2e`, whose expected row list did not have lab PR 218's new boot-time `capability_manifest` row (the expectation is updated in lab PR 218 and passes on 22.04 with it); Debian 13 (6.12) 47 suites, 78 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); anti-tamper suite on 24.04 and 22.04: every case OK but C64 (lab PR 215's enumeration case, which found a stale own link id, a recorded follow-up); deny fail-opens 0 over the whole run; `upgrade-check` from the tree without these lots OK on 24.04 (with the old advisor drop-in in place); host 2,480 passed, 0 failed.
- **Lab PR 227 — the privileged suites in KVM guests on GitHub-hosted
  runners.** C01 (Linux sensor), C29 (independent public validation); Wave 4
  Phase 2.1.
  - What was wrong: the privileged tests and the `#[ignore]` integration
    tests ran only in the self-hosted lab (`nn-lab.sh test-ignored` on four
    guests). CI compiled them (`--no-run`): a pull request could merge with
    a suite red on a kernel until the next lab gate, and no run of them was
    visible to anyone outside the lab.
  - What changed: `.github/workflows/lab-vm.yml` runs the same
    `test-ignored` in one KVM guest per job on a GitHub-hosted
    `ubuntu-24.04` runner — on the pull requests that touch the trees the
    suites are built or run from, Ubuntu 24.04 (6.8) and 22.04 (5.15); every
    night and on dispatch, the lab's four guests (and Debian 12, 6.1; Debian
    13, 6.12). On a pull request the job is informational (its own
    workflow, not a required check, `continue-on-error`); the nightly and a
    dispatch are the gate; a runner without KVM reports "skipped: no KVM"
    and fails only the nightly and a dispatch; no `pull_request_target`, a
    read-only token, no secret. nn-lab.sh gains a CI mode (`NN_LAB_CI=1`:
    KVM only, every cargo build `--locked`, batch ssh with keepalives, the
    serial console on a failed boot; the lab unchanged without it) and
    `image-info` / `fetch-image`: the image cache is keyed by the digest the
    vendor's signed list gives now and a restored image is checked against
    that list again. `cargo xtask gate-summary` judges a run (a crash, a build error
    or a run that never ended fails it, not only a failed test) and writes
    `gate-summary.json` and the job summary; the expected failures of
    `deploy/lab/expected-failures.tsv` (Debian 13's DNS attribution under
    `nss-resolve`, a recorded follow-up) are counted and shown, and fail the
    run once they pass. `cargo xtask gate-report` makes a run's artefacts a
    Markdown table the maintainer commits.
  - Evidence so far, offline only: `xtask/tests/lab_ci.rs` (the path
    filters derived from the repository, the matrix, the pins and the
    read-only token, the pull-request policy and the no-KVM skip, the time
    bounds, the KVM step, the image cache, the order of the steps and the
    evidence; the CI switches of nn-lab.sh run under bash, its ssh options
    under `ssh -G`; gate-summary and
    gate-report on synthetic logs: an expected failure on its guest and not
    on another, a stale one, a crash, a build error, a cut log, a job that
    stopped before the gate), each mutation of the workflow tried failing
    them; the download self-test with the CI glue (82 cases); actionlint
    1.7.12 with shellcheck 0.10.0 clean on the workflow, no new shellcheck
    finding in the lab scripts; `cargo fmt`, `cargo test -p xtask`. No guest
    was booted and no workflow ran: the dev host has no usable `/dev/kvm`.
  - Levels unchanged (C01 2, C29 0): owed, the first runs — KVM on a hosted
    runner, the boot and builds within the bounds, the measured run time
    (estimated 1.5–3 h a job), the four kernels green with Debian 13's one
    expected failure. For C29 the runs are public and reproducible on
    infrastructure the project does not own; that is a step towards, not,
    an independent validation, which still needs a third party.
    Open: AlmaLinux 9, the lockdown guests, `test-e2e`'s counts, the
    security checks and the rest of the nightly stay in the self-hosted
    lab; the image cache shares the repository's 10 GB with the cargo
    caches.
  - Lab: the VM job's first run on its pull request
    (https://github.com/northnarrow/northnarrow-new/actions/runs/39551564149):
    Ubuntu 22.04 (5.15) and 24.04 (6.8) guests, 48 suites, 79 passed and
    0 failed each, about 26–28 minutes per guest.
- **Lab PR 219 — exploit post-condition guard (C12, C14; experimental).**
  The kernel exploit's end state checked against the kernel's own
  mechanisms (`commit_creds`, `switch_task_namespaces`, `set_fs_root`) and
  the system call each ran for; NN-L-EPG-001 (T1068) and NN-L-EPG-002
  (T1611). Default **lite**: no system-call hooks; the mechanisms judged on
  the call in progress, a credential changed without one caught at its
  first use (`capable`, exec, a root-private open) against a per-task
  record in an LRU task map (aya 0.13 cannot load task storage: the first
  build stopped the agent on every kernel; a test now holds every map to
  the types aya loads); an evicted record is re-taken, counted, attested
  (at most once per 600 s), and recorded as degraded evidence (High) when
  it holds privilege. Opt-in **strict**: the comparison around every call
  (the agent refuses it below Linux 6.1, a version check). Detect by
  default; enforce sends SIGKILL in the kernel before the return to user
  mode, and lite refuses the use (C12: inline responses that do not depend
  on a userland round trip). Verified so far: the decision model's unit
  tests, the embedded object's maps and programs (aya-obj; every map type
  against aya 0.13.1's loader), the rules, the posture, the status and both
  builds. Open: the lab run of `deploy/lab/epg/epg-check.sh` on 5.15, 6.1,
  6.8 and 6.12 — the agent's start, the negative suite's zero records in each
  variant, the injected records and kills, the lite map under a task flood
  (evictions counted and attested), the measured cost per call; a real
  kernel credential
  write is not exercised in the lab (only the debug-build injection);
  supplementary groups, the bounding set and the fork-inherited baseline
  are follow-ups. Levels unchanged until then.
  - Lab: Every program of the eBPF object passed `nn-lab.sh verifier-check` (exit 0) on the four guests — 76 of 76 OK on Ubuntu 24.04 (6.8) and Debian 13 (6.12); 74 OK on Debian 12 (6.1) and Ubuntu 22.04 (5.15), where the two optional ACL deny hooks are absent from the kernel (not counted) — and the agent then started with both units active, no "refused", "attach FAILED" or "NOT running" in its journal (the deny self-test's own refused signal aside) and 0 degradations in the signed status. The exploit post-condition guard attached lite by default on all four (detect; the signed status `lite detect (experimental)`, withheld from the unsigned one; no exploit_guard degradation; no verifier rejection); `--btf-check` SUPPORTED with no w4b slot absent (the slots that drift from the compiled values — not all one kernel's — resolved at boot). Strict attached on 6.1, 6.8 and 6.12 (`strict detect … calls judged`) and was refused on 5.15 by the agent's 6.1 check ("strict needs Linux 6.1 or later … this kernel is 5.15.216"), a signed subsystem_degraded exploit_guard and the status `unavailable: …`. The negative suite (sudo, su, passwd, sg / newgrp, setpriv, capsh, unshare -U / -r / -rm / -rpf, chroot in a user namespace, systemd-run --uid; on 24.04 the `unshare -r` cases are refused by AppArmor before they run) left zero guard journal lines and zero NN-L-EPG records in lite and strict, detect and enforce (Debian 12: lite detect). On 24.04 the lab build's injection (the probe named nn-epg-probe): lite exec and strict getppid in detect — the probe continued, one Critical NN-L-EPG-001 recorded only (caught at exec / at sys_exit), {TA0004 / T1068}, 20.0; in enforce — killed (137) before it could print, the record "refused (-EPERM) and killed in kernel" (lite) / "killed in kernel" (strict), the anomaly, kill and refusal counters +1; the lite capable() case was skipped by the harness (its user-namespace probe refused before the hook by AppArmor on 24.04). Cost per call (best of 3, 2,000,000 calls): getppid as root 235.4 ns off, 235.5 lite, 469.1 strict; as the lab user 235.6 off, 237.3 lite, 883.8 strict; rdzero as root 511.3 / 511.3 / 785.0, as the lab user 476.7 / 511.1 / 1110.1 ns. Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 220 — transactional upgrade with rollback, blocking provenance
  verification.** C27 (product supply-chain security), C28 (safe content
  release); static review of `baf4c25` P0 C-45, G-07, TD-09, App.D C-46,
  G-36.
  - C28: `install.sh --upgrade` is a transaction. Every file it may create
    or replace is copied before anything stops; binaries, units and the
    install manifest are staged beside the installed ones and switched by
    rename; the restarted units must pass a health check (active, the
    agent's own every-deny-hook-attached event from its main pid, its pid
    file and admin socket, the watchdog's own PROTECTED_PIDS registration);
    any failure after the stop restores the previous files byte for byte
    through the new agent's own window, starts the previous units, checks
    them (exit 3), and the previous agent signs `upgrade_rolled_back`. A
    rollback the new hooks block (after install.sh started the new agent
    once more for its window) ends with exit 4 and a `rollback.sh` for after
    a reboot; a restored file that is not the one backed up, or a restored
    version that fails its own health check, is exit 4 too (the latter
    without `rollback.sh`). `--upgrade` over running units needs
    `--grant-key`.
    The `.deb` configure step and a new `.rpm` `%posttrans` fail an upgrade
    whose units do not pass the same check; neither package manager
    restores the previous version then (documented per manager).
  - C27: a release tree installs only at `attested` (the tag-bound SLSA
    attestation of its tarball: gh, or cosign with an offline bundle,
    `--attestation`; the cosign path has no automated test) and only when it is the
    tarball's tree (the `MANIFEST.sha256` inside the tarball); an unsigned
    `SHA256SUMS` is no longer enough. `--allow-unverified` (lab,
    development) accepts less and is logged at `auth.warning`, recorded in
    the install manifest and reported by `nn-admin host-check`, which now
    warns on `checksums`.
  - Evidence so far: `xtask/tests/install_scripts.rs` runs install.sh
    whole against stub `systemctl`, journal and fake agents that keep the
    anti-tamper's rules — rollback byte for byte (mode, mtime) after a
    failed health check, a failure at each stage (a unit that does not
    start is caught, and reported, at `health_check`), a forged health line, a
    deny-hook shortfall, the pinned-and-dead new agent finished by
    `rollback.sh`, a healthy upgrade committed, an agent older than the
    marker, an unattested release refused and the flag logged, a tree not
    from its tarball, the package configure and verify steps; agent unit
    tests of the marker against install.sh's writer; the three clippy runs,
    `cargo fmt`, `cargo test --workspace`. Levels unchanged (C27 1, C28 1):
    the guest checks are owed — an upgrade over a running install with a
    deliberately broken new build rolled back, a good upgrade, `nn-lab.sh
    upgrade-check` and `release-check`.
    Open: the evidence a new agent wrote at its boot (audit rows, chain
    heads, any state migration) is kept, not rolled back; a new agent that
    pins its hooks, dies and cannot be started again for its window leaves
    the rollback to a reboot; SHA256SUMS and
    the RPM key file are still not attested (C-50 / G-08); a package
    upgrade that fails its health check is reported, not restored.
  - Lab: On Ubuntu 24.04, the upgrade from `main` (origin/main c29527a) to this tree through `nn-lab.sh upgrade-check` (install.sh --source-tree --upgrade over the running units): the health check of both units passed, "UPGRADE complete", the transaction directory empty, no upgrade_rolled_back row, the install manifest naming northnarrow-scan and the running version, northnarrow-watchdog-failed.service staged with the other two, the --source-tree override in the system log, the audit chain verified. A broken new agent (a copy of the tree whose agent exits 1) rolled back by itself on Debian 12 and 24.04: exit 3 after 104–110 s, "UPGRADE FAILED — health_check: northnarrow-watchdog.service is activating; northnarrow-agent.service is failed", the previous files back byte for byte (55–56 snapshot lines: bytes, mode, owner, mtime), both units active with every deny hook (17/17 on 6.1, 19/19 on 6.8), one upgrade_rolled_back row signed by the restored agent (stage health_check, failed_version northnarrow-agent 0.0.0-broken). A broken new watchdog beside a healthy new agent first ended in exit 4 on 24.04 — the new agent had set chattr +i on /var/lib/northnarrow again, and three control-surface files could not be put back ("Operation not permitted"); fixed in this lot (the restore lifts the flag as the install does, rollback.sh receives STATE_DIR) and run again: exit 3, "lifting it for the restore", 31 files restored, the previous units healthy (19/19), the row signed. Before the fix the failure line named only the first unit not active (the watchdog the broken agent left activating); it now names every one. install.sh with no flag in a source tree was refused ("REFUSED — no MANIFEST.sha256") with nothing changed and the agent untouched. Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 221 — structured ATT&CK mapping, a coverage manifest and the
  rule catalogue.** C16 (structured ATT&CK mapping); groundwork for C15
  (a declarative rule will carry the same typed references) and C29 (the
  coverage a third party would check is generated, not written).
  - What was wrong: ATT&CK lived only in prose (doc comments, reasoning
    text; many of the 76 engine rule ids named no technique), the rule-path
    detection record's `mitre` was always empty, and several of the ids in
    prose are revoked in ATT&CK 20.0, the version pinned here (the T1562
    Impair Defenses family, replaced by T1685 and its siblings under the
    Defense Impairment tactic, TA0112; TA0005 is now Stealth), or did not
    describe what the rule sees (R016's T1622).
  - What changed: `Rule::attack()` (required, no default) returns typed
    references — a `Tactic` enum and technique ids whose shape is checked
    when the constant compiles — of ATT&CK Enterprise 20.0 (2026-10-13).
    All 93 rules (lab PR 219's two, 223's NN-L-EXECQ-001, 224's three,
    225's six and 226's four included) are mapped: 66 techniques and sub-techniques under 12
    tactics. A rule detection record carries the ids in `mitre` and
    `mitre_version` `"20.0"` (an additive field: older lines keep their
    bytes and verify). The ids in use are pinned with their v20 names,
    tactics and status in `docs/detection/attack-enterprise-20.0.tsv`,
    extracted from MITRE's STIX bundle by commit and sha256 (`cargo xtask
    attack-coverage --pin-ids --mirror`), with the Terms of Use and the
    designation (`NOTICES.md`). Tests fail on a rule without a mapping, an
    id outside the list, a revoked or deprecated id, a technique filed
    under a tactic it does not have, a catalogue entry missing or citing a
    test that does not exist, Critical severities that disagree with the V2
    sub-gate, and committed documents that differ from the generated ones.
    `cargo xtask attack-coverage` renders `docs/detection/ATTACK_COVERAGE.md`
    (technique → rules → sensor and ATT&CK data components → validation
    status, with the V2 rows and their v20 ids), an ATT&CK Navigator 4.5
    layer and `docs/detection/RULE_CATALOGUE.md`.
  - Level unchanged (1): the evidence so far is in-process (the mapping and
    catalogue tests, the record and chain tests, the engine's attribution
    test). Owed on a guest: a few rules fired, their records' `mitre` and
    `mitre_version` read back through `nn-admin detections`. Open: the
    partial fits the catalogue's ATT&CK notes name (CANARY-002 the weakest:
    no technique names running a decoy), the reasoning ids kept as they
    were (FIM-024's is pinned by a test), and the frozen
    `v2-techniques.tsv`, which keeps its pre-v19 ids (the coverage document
    reads them in v20).
  - Lab: On Ubuntu 24.04: a record written by `main` before this lot (R001_ExecFromTmp, `"mitre":{"tactic":[],"technique":[]}`, no mitre_version) was byte-identical after the upgrade, and `nn-admin chain verify` found nothing broken since the run began (its one break, a manifest entry written on 20/10 with another key, predates the run and the agent had signed it then as tail_unverified). R001, R014 (an `at` job), NN-L-FIM-007 (a file in /etc/cron.d from a unit) and NN-L-NET-004 (a long name under example.com) were recorded with the typed ids RULE_CATALOGUE.md gives them, in order, mitre_version 20.0 — R001 {TA0002 / T1059}, R014 {TA0003, TA0002 / T1053.002}, NN-L-FIM-007 {TA0003 / T1053.003}, NN-L-NET-004 {TA0011 / T1071.004} — and no rule record written by the upgraded agent had an empty mitre (the 105 written between the mark and its first start were the base agent's); tamper-check's 94 NN-L-AT-001 records carried {TA0112, TA0005, TA0006 / T1685, T1055.008, T1055.009, T1552.004}. Across every step of the lab, on the four guests, the records of 44 rules passed the typed check and none failed (exec quarantine, exec policy and security-tool records within their catalogue entry). The operator read-back (`nn-admin detections --key`) was not run: the lab key holds no telemetry-read role. Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 222 — copy on first write: ransomware rollback for Linux
  (EXPERIMENTAL, off by default).** C19 (rollback and remediation), C17
  (response on processes and files); `docs/design/COPY_ON_FIRST_WRITE.md`.
  - C19: before a writer whose trust is not established opens an existing
    file for writing in a protected scope, the agent copies it while the open
    waits in a fanotify permission event (`FAN_OPEN_PERM`, answered
    `FAN_ALLOW` by the reader, the copier or a backstop — a copy within
    50 + 25 ms of the reader reading the event, any other open once the
    reader has decided; never denied). Reflink (`FICLONE`) where the
    filesystem shares extents, else a bounded copy (16 MiB), into a
    root-only journal per scope (by default on the scope's filesystem)
    under the anti-tamper inode protections, with a content index, a byte
    budget, LRU eviction past a 15 min floor and 24 h retention, both from
    a copy's last use. The guard's own threads open no journal file while
    holding a lock its reader takes (a scope marked by mount or filesystem
    has its journal under the mark). Trust by exec identity
    and ordered lineage (a root package transaction, or a trusted writer
    with no foreign ancestor), never by `comm`; the writer's open flags from
    `/proc/<tid>/syscall`.
  - C17 / C19: `nn-admin remediate ransomware [--pid] [--since]
    [--dry-run]` (signed, `response-manage`; together they narrow each
    other, `--since` alone takes every writer's copies since then) restores
    a tree's files; with `auto_restore = true` (off by default) the COMBAT
    ladder's NEUTRALIZE or NN-L-FIM-010's kill (no COMBAT needed) of a tree
    a ransomware signal named restores them on its own. One signed
    `cow_restore` row per file; a file someone else changed after the
    attack, as far as the guard saw (its write-open records are in memory,
    8 per inode, and only the mtime counts after a restart), is not
    overwritten (the original is written beside it).
  - Not protected, stated: files over the cap without reflink, writers
    already trusted, the journal against root with the anti-tamper hooks
    off, descriptors opened before the guard watched (an `mmap` write is
    seen at its open), encryption into new files with unlink or rename-over.
    Pure ransomware raises ENGAGED, not COMBAT (BUG-032, POS-001): there the
    restore is the operator's signed verb.
  - Levels unchanged (C19 1, C17 2): the evidence is the lab's, owed on
    Ubuntu 24.04 — ext4 (copy path), an XFS loop filesystem with
    `reflink=1` (reflink path), the automatic restore after a NEUTRALIZE,
    the trusted-writer negative run and the open-for-write overhead
    (`deploy/lab/cow/cow-check.sh`). Open: no deny mode, no pre-delete
    protection, flags from `/proc` rather than the LSM hook.
  - Lab: On Ubuntu 24.04, with the guard on (the lot's cow-check.sh: its drop-in, a signed cow-guard.local, response-manage on the lab key, all put back by its cleanup): on ext4 (mark=dirs) the signed cow_guard row "started" with copy_method copy, on an XFS loop filesystem (mark=mount, reflink=1) copy_method reflink, no integrity drift for its drop-in. The benign simulator, run as the lab user, rewrote and renamed 51 files: on XFS `nn-admin remediate ransomware --pid` recreated all 51 (sha256 51 of 51); on ext4 50 (the 20 MiB file is over the 16 MiB copy cap, unprotected as designed), each a signed cow_restore row; the run drew NN-L-IMP-001 (lab PR 225) with its kill held. With auto_restore = true and the simulator as root tripping the anti-tamper tripwire, COMBAT NEUTRALIZEd it and the guard restored the 50 files itself ("restore done source=COMBAT NEUTRALIZE", 50 cow_restore rows "by auto (COMBAT NEUTRALIZE)", a cow_guard auto_restore row). vim started by a unit as the lab user rewrote 10 files with no copy (trusted opens 0 → 10), `cp` over three took three copies. Cost on ext4 (cow_bench, 2,000 files of 4 KiB): open 4.0 µs mean outside the scope, 302.5 µs on the copy path inside it; 200 files of 1 MiB 6.7 ms; the guard's own counters: fast path avg 79 µs, copy path avg 820 µs, max 8.1 ms (2,203 copies). The first ext4 run copied nothing: the harness re-made the tree's directories after the guard had marked them (with mark=dirs a new directory is marked at the next 60 s rescan), its chown of the tree touched the guard's write-denied journal (four NN-L-AT-001 denials, a locked COMBAT), and it started vim from its own script, an ancestor the guard's trust rule refuses; the harness was fixed in this lot and the ext4 cases run again. After the fix of the guard's fanotify reader (it reads the group only through its own descriptor, under its lock, and ends an orderly stop with an INFO line), a restart of the agent with the guard running on ext4 left the stopping agent's "the fanotify reader ends (the guard stops)" and no "reading the fanotify group failed" ERROR, and the new agent's guard ran. Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 223 — exec quarantine at first sight (EXPERIMENTAL) and a
  confined scanner.** C13 (malware prevention), C12 (synchronous inline
  blocking); `docs/design/EXEC_QUARANTINE.md`. Off by default.
  - C13: a new executable run from a guarded location (`/tmp`, `/var/tmp`,
    `/dev/shm`, a home directory, a world-writable directory, tmpfs, a
    memfd, an unlinked file) is held by the kernel before its first
    instruction (`SIGSTOP` from `sched_process_exec`, past the exec's point
    of no return), scanned by `northnarrow-scan` — an unprivileged process
    of its own account under a seccomp filter (no file but the descriptors
    it is handed, no network, no exec, no executable memory) — against a
    signed hash list and explainable ELF heuristics, then resumed, or
    killed and quarantined. Package files are trusted by their recorded
    digest; an identity judged once is not held again. YARA is left out
    (libyara is C; yara-x needs rustc 1.95 and a JIT the filter refuses):
    the `yara` feature is reserved, the packs are a follow-up.
  - C12: within its budget the controller resumes a held process only
    after the rule engine has judged its exec, so the exec rules' kills
    (R001 on a `/tmp` binary…) land on a process that never ran an
    instruction. A decision has a budget (2 s), then the default policy
    (resume and alert); a decision is a signed `NN-L-EXECQ-001` record
    (not a resume on a digest already judged clean, a late clean verdict,
    or what the per-rule budget holds back), a scanner loss a signed
    degradation (one per cause per 10 min); fail-open on a stale
    heartbeat, a full ring or a refused signal, each counted, the last two
    a signed degradation at most every 10 min.
  - Evidence so far: unit tests — the decision table and the budget gate,
    trust by a fixture dpkg database, the heuristics on ELF images built
    byte by byte, the seccomp filter on forked children (an `open`, a
    `socket`, an executable `mmap`, a write to stdout kill them), the
    scanner process configured through a memfd and the supervisor
    restarting it after a `SIGKILL`, and the controller on real stopped
    processes (resumed after the rules' verdict, killed and quarantined on
    a block-list hit, the default policy without a scanner and after a
    budget, a late block-list verdict, a scanner death, recovery at boot);
    the three clippy runs, `cargo fmt`, `cargo test --workspace`. Levels
    unchanged (C13 0, C12 1): the guest checks are owed — the six cases of
    `deploy/lab/execq/execq-check.sh` on 5.15, 6.1, 6.8 and 6.12 (and RHEL
    9), the latency numbers.
    Open: interpreted code handed to an interpreter, a known binary
    reused, `ld.so <file>`, injection into a running process and
    kernel-mode code are not seen; a root attacker can kill the scanner
    (the default policy applies, signed); an interactive shell sees a held
    job as stopped; the identity cache trusts ctime and size;
    `NN-L-EXECQ-001` is outside the frozen V2 denominator.
  - Lab: On Debian 12 and Ubuntu 24.04 the install created the system account northnarrow-scan (home /nonexistent, nologin) and /usr/local/bin/northnarrow-scan (0755 root) in the install manifest, with the guard off in the signed status (withheld from the unsigned one), EXECQ_CONF frozen and EXECQ_STOPPED pinned; on 6.1, 6.8, 6.12 and 5.15, with NN_EXEC_QUARANTINE=enforce, the exec sensor on LSM bprm_check_security, the quarantine armed in the kernel, its programs past the verifier with no rejection, the signed state enforce, no degradation, and the scanner running as northnarrow-scan under a seccomp filter with no_new_privs, no capability and file descriptors 0–3 only. On 24.04 the lot's execq-check.sh passed 11 of 11: a never-seen copy of true in /tmp held before its first instruction and scanned clean, ended while held by R001's kill (a rule that predates the lot), a second run not held (known identity, no new record); a binary in the home held, scanned clean and resumed; a block-listed test binary killed while held (no instruction ran) and quarantined; a UPX-packed ls judged suspicious; package-managed binaries never held; a stopped scanner → after the 2 s budget the default policy resumed the process (signed) and the hung scanner was killed and restarted (signed degradation); a scanner killed mid-scan signed a degradation and the scan finished clean; first sight decided in 3.1 ms. Observe mode let the block-listed marker run with its record "would kill", held false; a process held across an agent killed by SIGKILL was resumed by the next agent with a signed recovered_at_boot row naming it, and one held across a graceful stop by a signed "stopping" row (the first run of this case crashed the agent after the decision budget and launched the held process through runuser, which kept its resumed child a zombie: a probe defect, fixed and run again, 14 of 14). Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 224 — network verdicts at connect, reverse shells, outbound
  fan-out (C07, C14; with C12).** C07: a TCP flow is judged at its connect
  and re-judged every 60 s while open (snapshots with the current image,
  bounded per tick), no longer only at its close; the port-53 exemption of
  NN-L-NET-008 and NN-L-CHAIN-002/005 holds only for a configured resolver;
  the network allowlist's transfer tools lose their exemption under a
  precursor in their lineage; the signed detection record names the flow
  and its phase. C14: R020 (a shell or interpreter with stdin/stdout on an
  inet socket — outbound, accepted outside an inetd-style launcher, or the
  pty-wrapped form through the parent's stdio, read in
  `sched_process_exec`), NN-L-NET-026 (scan fan-out) and NN-L-NET-027
  (outbound brute force), per process and per parent's children, monitoring
  exempt by lineage. The kills these add — R020's, the fan-out kill tier,
  port 53 to a server that is no configured resolver, a transfer tool under
  a precursor — are held behind the per-rule response policy, off by
  default until it is signed (Phase 2): Critical or High records, posture
  escalation kept. C12: an optional `socket_connect` deny of the operator
  blocklist (`--net-connect-deny`, off by default, never armed in
  detect-only). Verified so far: the
  unit tests (phases, ledger, snapshots, resolvers, R020 shapes, fan-out
  windows and thresholds, the allowlist's revocation), the eBPF build, both
  clippy builds and the workspace tests; the connect-time evaluation cost
  bounded by a unit test (under 500 µs; no figure recorded). Open: the
  lab suite `deploy/lab/malsim/net-check.sh` on the guests; no
  byte counters in snapshots (NET-009 still at the close); an interpreter
  that keeps a `dup2`'d socket without running a new image is not seen.
  Levels unchanged until then.
  - Lab: On Debian 12 (6.1), Ubuntu 24.04 (6.8), Ubuntu 22.04 (5.15) and Debian 13 (6.12): the stdio probe in sched_process_exec and the network programs past each verifier with no rejection, SOCKET_SK_OFFSET resolved, the connect deny off by default (counter null); with NN_NET_CONNECT_DENY=1 it armed on LSM socket_connect (ipv4=4 ipv6=1 skipped=0, counter 0, socket_connect_deny loaded, no degradation); with NN_DETECT_ONLY=1 as well it did not arm ("ignored in detect-only", counter null, trust L2 "detect-only: no response action runs"). The first run of that case found a defect of this lot: `NN_NET_CONNECT_DENY=1`, the value the help and the CHANGELOG give, stopped the agent at its start (exit 2, "invalid value '1' for '--net-connect-deny'") and the watchdog held; the environment switches now read 1/0, true/false, yes/no, on/off (a unit test), and the case passed 14 of 14 on all four kernels. On 24.04 the lot's net-check.sh passed 13 of 13 (against `main`: 4 PASS, 9 KNOWN GAP): NN-L-NET-010 at the connect of a long-lived C2-port connection (client killed after 29 ms), open-flow snapshots of a benign flow, NN-L-NET-013 on a beacon at its close, CHAIN-002/NET-008 on TCP/53 to a server that is no configured resolver (the stub 127.0.0.53 exempt), R020 Critical on bash over /dev/tcp and on a pty-wrapped reverse shell, no R020 for an Accept=yes service, NN-L-NET-026 on a 199- and a 600-host sweep and a 400-port scan, NN-L-NET-027 on 25 SSH connects, no Critical and no fan-out record for apt, git, ssh and a 40-connection burst; the kills this lot adds are held (alert only by default): R020 2, NN-L-NET-026 5, NN-L-NET-027 2 records, none a kill. A connect to 192.0.2.10:443 (TEST-NET-1, on the shipped blocklist) was judged at the connect and its client killed by NN-L-NET-001 (a kill that predates the lot); with the deny armed the same connect got EPERM at once (0 ms), a record "tcp 192.0.2.10:443 denied", operation connect, the kernel counter 0 → 1. NN_NET_SCAN_HOSTS=128 and NN_NET_SCAN_KILL_HOSTS=0 each drew a signed weakening_env, a stricter NN_NET_SCAN_HOSTS=32 none. Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 225 — malware countermeasures M9 (part): ransomware recorded on
  its own evidence, security tools watched.** C14 (behavioural detection and correlation),
  C17 (response on processes and files), C19 (rollback);
  `docs/design/RANSOMWARE_DECISIVE.md`.
  - C14 / C17: NN-L-IMP-001 records, Critical, an actor whose file
    activity shows two of four shapes within 120 s — rewrites of existing
    files, ciphertext-like content left behind, renames (or copies) to one
    new extension, deletion of originals after new files. For copies the
    copies themselves are sampled (`<original>.<suffix>`, the original
    gone), never the originals still waiting beside them: the lab's MS-23
    copy-delete run on 6.1 drew no record until then (280 fresh originals
    filled the sample). The legitimate copy-then-delete shapes — `mv`
    across filesystems, `rsync --remove-source-files`, package unpacks,
    compiler temporaries, editors' safe writes, `git gc`, log rotation with
    compression — stay one shape. Its kill of the actor's tree and the
    posture's COMBAT on it alone (unlocked: POS-001) are in the code but
    held behind the per-rule response policy, off by default until it is
    signed (decision of 21/10/2026): the posture's
    RansomwareEncryption needs corroboration (ENGAGED alone). The rename and
    unlink bursts are counted in the kernel on regular files (unlinks of
    4 KiB or more), while the LSM file-open sensor is armed
    (`inode_rename`, `inode_unlink`); the entropy is sampled in userland when
    a burst is read (no host-wide close hook reads content). Trusted writers
    — root package transactions, packaged programs with an installed
    lineage — never count. A rename burst of an encryptor's shape (an
    extension appended or put in place of the old one), alone, is a record
    (NN-L-IMP-002). NN-L-FIM-010 names the renamed file, not its directory,
    and reads a rename seen as a watched directory's new entry (that new
    match's kill is held likewise).
  - C14: NN-L-EVA-001..004 record a security tool stopped, disabled,
    masked, killed (on `task_kill`, a builtin `kill` included — a forking
    daemon restarted, Debian's auditd, is registered by `/proc` scans after
    its exec), switched off by its own command or reconfigured, from the
    shipped list `security-tools.v1` (not signed: pinned to the agent's
    built-in copy, a modified file never applied, no operator overlay yet);
    Low when sanctioned (package transaction, administrator's session,
    configuration management; a stop or restart of the agent's own units
    inside a valid signed trusted-installer window, the window named in
    the record, no posture move); High with the kill of a staged script that
    asks held behind the per-rule policy. Posture `DefenseImpairment`
    (ENGAGED). NN-L-EVA-002 records a command once per process tree
    within 10 s (`ufw disable`'s dozens of `iptables` calls: one record
    per command, the repeats counted in `detections_held`).
  - C19: once the per-rule policy turns IMP-001's kill and COMBAT on, the
    ladder's NEUTRALIZE runs on pure ransomware, where copy on first write
    (lab PR 222) can restore; until then a corroborated COMBAT does.
  - Levels unchanged (C14 2, C17 2, C19 1): in-process tests only so far
    (58 new; two of the three NN-L-FIM-010 drain tests fail with the
    starting tree's resolution, the third needs the new kernel leaf). Owed
    in the lab (`nn-lab.sh ransom-check`): the counters on 5.14, 5.15, 6.1,
    6.8 and 6.12; MS-23 in place and copy-delete recorded Critical with the
    posture at ENGAGED (the kill held); the tar, rsync, git checkout and
    apt negatives with no
    NN-L-IMP-001; MS-25 records. Open: fork-per-file encryptors (per-process
    counts), packaged tools used from an interactive session, D-Bus unit
    stops, no operator overlay of the tool list yet.
  - Lab: On Debian 12 (6.1), Ubuntu 24.04 (6.8), Ubuntu 22.04 (5.15) and Debian 13 (6.12): fim_rename_observe, fim_unlink_observe and task_kill loaded with no verifier rejection, DEFENDER_PIDS in use with the listed tools that run registered (auditd and rsyslogd on 24.04, rsyslogd on 22.04, none on the Debian cloud images, which run neither), security-tools.v1 installed (33 tools), the ransomware and security-tool lines in the signed status. On 24.04 the lot's ransom-check.sh passed 19 of 19 (against `main`: MS-23 and MS-25 drew no record, 8 KNOWN GAP, its 11 negatives clean): MS-23 in place and copy-delete each drew a Critical NN-L-IMP-001 whose kill is held (response none: alert only by default), the simulator ran to its end (300 of 300 files), the posture reached ENGAGED and never COMBAT on RansomwareEncryption; the simulator's own gzip-delete and move-away scripts, tar (twice), rsync (twice), a git checkout and an apt install / reinstall of 400 random files drew none; MS-25 `systemctl stop auditd`, `auditctl -e 0`, a builtin `kill -STOP` of a restarted auditd, a rule file in /etc/audit/rules.d and `ufw disable` each drew its High NN-L-EVA record, none a kill. NN-L-EVA-002, which drew dozens of High records for one `ufw disable` (one per iptables call of ufw-init), was fixed in this lot before the lab: 5 records for `auditctl -e 0` and `ufw disable`, the repeats counted in a signed detections_held row. Run on their own, tar, rsync and rm bursts (new files, the same tree again, unlinks) were judged trusted writers (the status counter 0 → 6, no shape counted, no record); in the harness's run its tar / rsync negatives left no burst line at all (an open observation). A watched file renamed x → x.locked drew one Critical NN-L-FIM-010 naming the file, the verdict's reasoning naming x.locked (the watched file's own rename keeps its kill, which predates the lot). After the decision that a stop or restart of the agent's own units inside a valid signed trusted-installer window is sanctioned, the build with it ran on 24.04: two restarts inside a window each drew one Low NN-L-EVA-001 whose sanction names the window ("key c2e8f3da (until 2026-10-21T12:41:37Z)"), and the posture stayed at OBSERVING; with no window, and after a 2 s window had expired, `systemctl kill` of the agent's unit was refused (the agent kept its pid) and drew a High record with a DefenseImpairment transition; auditd stopped inside a valid window was High too; MS-25 passed 5 of 5 (none a kill, NN-L-EVA-002 coalesced), trust225 judged six bursts trusted; the upgrade-check from `main` passed, and a second one over the installed build drew two Low NN-L-EVA-001 (install.sh's stops, an administrator's sudo session at a terminal) with no posture change. Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).

- **Lab PR 226 — synchronous exec policies and the exec environment
  (EXPERIMENTAL).** C12 (synchronous inline blocking), C13 (malware
  prevention); countermeasures CM-01, CM-25; `docs/design/EXEC_POLICY.md`.
  Off by default.
  - C12: `bprm_check_security` returns the policy's verdict — `-EACCES`
    before the exec's point of no return — for a file class (memfd, deleted,
    `/dev/shm`, `/tmp`, `/var/tmp`, world-writable, tmpfs, home, another
    user's home, guarded mount) × a lineage tier computed in the kernel
    (interactive admin, session, service, unknown: the systemd slice, the
    login uid, the terminal, an elevation binary's image up the lineage);
    quarantine cells hand the exec to lab PR 223's stop-and-scan, audit
    cells and classes record "would deny". `LD_PRELOAD`/`LD_AUDIT` into a
    staging path are refused at exec (server profile) for services,
    unknown callers and root in a session — an admin-tier root caller is
    recorded only (`AT_SECURE` targets left to the kernel) — and
    `mmap_file` judges
    executable mappings from the same classes. The quarantine refuses a
    script it would hold (the interpreter re-reads it by path after the
    scan).
  - C13: memfd, deleted-file and `/dev/shm` execs refused outside an
    interactive admin session in the server profile (MS-01, MS-02, MS-03);
    `GLIBC_TUNABLES` of the CVE-2023-4911 shape at a set-id exec recorded
    Critical.
  - Evidence so far: unit tests — the server profile and its encoding
    into the kernel configuration (the desktop profile on a few cells), the
    overlay grammar (a bad line refuses the file at `overlay set`; at boot
    it is a signed degradation), the records and their ATT&CK mapping for
    the exec, preload and environment findings (not EXECENV-003's mapping
    record), the repeat window, the controller publishing the slices and
    roots (the images' encoding is tested on its own), the quarantine's
    "would refuse" script on a real process (the refusal on a pid nothing
    runs under), the wire layouts, the BTF and tracepoint slots; the eBPF
    object built; the three clippy runs, `cargo fmt`, `cargo test
    --workspace`. Not tested: the configuration freeze (`BPF_MAP_FREEZE`).
    Levels unchanged (C12 1, C13 0): the guest checks are owed — the four
    phases of `deploy/lab/malsim/exec-check.sh` (MS-01, MS-02, MS-03, MS-32
    before and after, the environment and mapping records, the negatives,
    audit, the desktop profile) on 5.15, 6.1, 6.8, 6.12 and RHEL 9, the
    per-exec cost.
    Open: the environment check reads string prefixes at the syscall's
    entry (a racing caller, `//tmp`, symlinks: the mapping check is the
    line that does not depend on them); `file_mprotect` is not judged; a
    root attacker can forge the admin tier; quarantine cells need
    `--exec-quarantine`; the rules are outside the frozen V2 denominator.
    (Integration w4b: T1204.002 — EXECPOL-001 — and T1129 — EXECENV-003 —
    checked active in the ATT&CK 20.0 bundle and pinned; the mapping is lab
    PR 221's typed one.)
  - Lab: On Debian 12 (6.1), Ubuntu 24.04 (6.8), Ubuntu 22.04 (5.15) and Debian 13 (6.12), with NN_EXEC_POLICY=enforce: the exec policy armed in the kernel with the environment and mapping checks on, exec_check_lsm, execpol_env_execve / execveat and execmap_check loaded with no verifier rejection, the signed status `enforce; 1 partial` whose one note is the server profile's quarantine cells while the exec quarantine is off (no other degradation), off again once the drop-in was removed. On 24.04 the lot's exec-check.sh passed 20 of 20: with the policy off MS-01/02/03/32 ran (MS-01 then killed by R002, MS-02/03 recorded by R004, rules that predate the policy); in enforce a service's /dev/shm copy of id (MS-01), memfd exec (MS-02), exec of a deleted file (MS-03) and LD_PRELOAD from /tmp (MS-32) were refused at exec (EACCES / exit 203), each a signed NN-L-EXECPOL-001 or NN-L-EXECENV-001 deny at the service tier, counted 0 → 3 in the signed status; the `//tmp` preload side-step was recorded through the loader's mapping (NN-L-EXECENV-003), HISTFILE=/dev/null and a CVE-2023-4911-shaped GLIBC_TUNABLES at su recorded; the lab user's script in its home (session tier) and through sudo at a terminal (admin tier), a package install and removal and systemd services ran with no deny; audit mode recorded MS-01 as "would deny"; the desktop profile let an AppImage-shaped run from /tmp/.mount_* and a Flatpak-shaped one through and kept services strict. The 9 exec policy records each carried their execpol evidence (decision, tier) and ATT&CK 20.0 ids within the catalogue's. With the exec quarantine on as well, a /tmp script started by a service was refused at exec (NN-L-EXECQ-001 decision refuse, script_refused 0 → 1). NN_EXEC_POLICY_NO_ENV / _NO_MAP now read 1/0, true/false, yes/no, on/off, like lab PR 224's switch whose `=1` stopped the agent in the lab (a unit test; not run on a guest). Gate: the integration tree of lab PRs 219–226 on `main` (the guest gates ran integ/w4b f69fae9; the final f1284c7 adds the fix of the lab harness deploy/lab/cow/cow-check.sh and two fixups — lab PR 225's sanction of the agent's own units inside the trusted-installer window, lab PR 222's fanotify reader — whose build passed on 24.04 the smoke, the window's cases, MS-25, trust225, the guard's restart and two upgrade-checks): Ubuntu 24.04 (6.8), Debian 12 (6.1) and Ubuntu 22.04 (5.15) 54 suites, 80 passed, 0 failed; Debian 13 (6.12) 54 suites, 79 passed, 1 failed — `net_outbound_connect_records_flow_with_dns_attribution`, the same on `main` there (nss-resolve, a recorded follow-up); on each guest first the smoke step: `nn-lab.sh verifier-check` exit 0 (76 of 76 programs OK on 6.8 and 6.12, 74 on 6.1 and 5.15 with the two optional ACL hooks absent, 0 failing), both units active, no refused / attach FAILED / NOT running in the agent's journal, 0 degradations; anti-tamper suite on 24.04 and 22.04: 72 of 75 cases OK, C27 (no lockdown) and C57c (journal vacuum) known gaps, C64 the stale own link id of lab PR 215 (a recorded follow-up, as in the lab of lots 214–218); deny fail-opens 0 on every guest over the whole run; `upgrade-check` from `main` OK on 24.04; host 2,828 passed, 0 failed (f1284c7).
- **Lab PR 228 — performance baseline, regression gate and golden replay
  (every capability; no level changes).** Methods, not capabilities, that
  every later lot is held to. The baseline (`nn-lab.sh perf`): what the
  agent costs the operations it hooks (agent stopped through the
  trusted-installer window and running, 10 passes after a warm-up,
  pinned), the latency from a probe read to its signed record, the loss
  counters and the event rate under a 60 s burst, the agent's CPU and RSS,
  the cold start to READY — every raw sample in one JSON with the host,
  the tree, its branch point and which build inputs differ from it. The
  gate (`cargo xtask perf-compare`) with committed thresholds
  (`deploy/lab/perf/thresholds.tsv`) set above an A/A check's spread with
  a margin. The golden replay (`agent/src/decision/golden.rs`, in `cargo
  test`): twelve recorded streams through the decision path, compared
  byte for byte, deterministic across runs and threads, covering the rules
  of lots 219–226 and every held kill as an alert; `cargo xtask golden
  --update` for reviewed changes, refused under CI. `docs/PERFORMANCE.md`
  takes figures only from committed result files (the advisor's tuning,
  removed with lab PR 214, and the figures without raw data are gone);
  `docs/validation/PERF_BASELINE.md` and `GOLDEN_REPLAY.md` say how to read
  them. Open: a baseline on the other guests (Debian 12 and 13, Ubuntu
  22.04, Alma 9) and on bare metal; a latency probe for the exec and
  network rules; TCP connect's threshold (35 %) is wide because its median
  moved 15 % between two runs on the shared lab host — a quieter host or
  more passes would tighten it; golden streams captured from a kernel (the
  cases are written in the agent's event format, shaped on the lab
  scenarios).
  - Lab: On Ubuntu 24.04 (kernel 6.8.0-147, 4 vCPU of a Ryzen 9 3900XT, 7.8 GiB, QEMU for Windows with WHPX), the agent of `main` 8180540 (the run's tree 40fd666, no build input changed, lab build test-privileged+debug-trigger, thin LTO, agent sha256 93308a27… in every run): `nn-lab.sh perf --fresh --quick` complete in ~3 min; three full runs A (21:11 UTC), B (21:19, the committed baseline) and C (21:27), each complete with no note, ~7.5 min. Baseline B, agent off → on, ns per operation: getppid 176 → 176 (−0.3 %, the control), read of /dev/zero 327 → 449 (+37.3 %), open unwatched 3,706 → 5,149 (+38.9 %), open FIM-watched 3,794 → 5,717 (+50.7 %), write open 4,527 → 6,538 (+44.4 %), fork + exec 795,868 → 879,135 (+10.5 %), TCP connect 42,076 → 59,113 (+40.5 %), UDP send 3,730 → 4,753 (+27.4 %), DNS sent 4,967 → 6,063 (+22.1 %), DNS to the resolver 92,464 → 98,136 (+6.1 %); a credential read signed in 0.23 ms (on disk 2.50 ms); agent CPU 0.20 % idle, 7.40 % under the burst at 455 processes/s; RSS 34,352 KiB idle, 44,008 KiB under load; 0 ring drops, rejections, evicted connects, forgotten sockets; READY 4,506 ms after the start. A/A spread over the three runs (largest move of the median between two runs): workloads agent on 0.1–2.9 % except TCP connect 15.3 %, agent off 0.3–8.6 % (another job's test suite ran on the host during A's and C's agent-off phases); latency 7.5 % / 2.7 %; CPU 25 % / 19.6 % (0.05 / 1.45 points, inside the 0.5 / 2-point floors); RSS 2.5 % / 10.6 %; boot 0.1 %; no loss in any run; the overhead of a workload moved by at most 6.5 points between runs, TCP connect's by 26.5. Thresholds by the rule (≥ 10 %, ≥ twice the move, ≥ move + 5): 10 % for every workload but fork + exec and the resolver query (20 %) and TCP connect (35 %); latency 20 / 10 %; CPU 50 / 40 %; RSS 10 / 25 %; boot 10 %; loss counters floor 0. `cargo xtask perf-compare` B against A and against C with them: PASS (0 regressions); B against itself with fork + exec 25 % slower and 3 ring drops: exit 1, both REGRESSION. Golden replay: 12 cases, 4 tests, the same bytes on 5 separate test processes and 4 threads at once; a golden line edited by hand fails with the line that differs; `cargo xtask golden --update` under CI=1 is refused. Gates on the host: `cargo xtask build-ebpf --release`, the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` (52 suites, 2,886 passed, 0 failed), `cargo xtask attack-coverage --check`, `cargo xtask golden`: all pass.
- **Lab PR 230 — cryptographic test vectors before the RustCrypto bump.**
  C27 (product supply-chain security), C17 (the quarantine vault), C23
  (signed admin payloads and overlays); Wave 4 Phase 2, D0 of the
  dependency plan.
  - What was wrong: D2 moves aes-gcm, hkdf/hmac, sha2, md-5, ed25519-dalek
    and rand to their next generation in one step. Outside the reference
    vectors of JA3/JA4 and the fuzz seeds (which a bless run rewrites), no
    test fixed the bytes those crates produce through our formats: a vault
    sealed, a manifest recorded or an overlay signed before the bump could
    stop restoring, verifying or loading after it with every test green.
  - What changed: tests only, each in a `crypto_vectors` module next to the
    code it pins (`cargo test crypto_vectors`). The vault: the HKDF-SHA256
    file key, the record `nonce ‖ ciphertext ‖ tag` (no header: the format
    is the salt's `-v1`), the refusal of a changed nonce, ciphertext, tag or
    vault id, what `quarantine_file` writes (`.bin`, the `.meta` SHA-256),
    and a vault written by `main` at 8180540 — master key, `.bin` as hex,
    `.meta`, `index.json` in `agent/tests/fixtures/vault-v1/` — listed and
    restored. SHA-256: `install_manifest::sha256_file` (empty, `abc`, 30
    bytes, a million `a` across the 64 KiB reads), a manifest in the shape
    `install.sh` writes with the hashes as literals, the self-integrity
    report's short overlay hash. MD5: JA3, and a dpkg `.md5sums` line. Ed25519:
    the seed `[0x42; 32]` (key, signature, `verify_strict`), an admin
    payload's CBOR, SHA-512 signing digest and signature, and an overlay
    signed and stored as `nn-admin config overlay set` stores it
    (`agent/tests/fixtures/overlay-v1/`) accepted by the gate with its
    content hash and key fingerprint. The vault's encryption and decryption
    became `seal` and `open` (bytes, errors and their order unchanged).
    HMAC has no call site of its own: it is HKDF's, covered by the file key.
  - Evidence: the plan's eight vectors (`w4-deps-plan.md` §2.4) are what the
    code produces; all twenty recomputed outside the repository (Python
    `cryptography` 41 on OpenSSL, coreutils `sha256sum`), the vault fixture
    decrypted there too; the four clippy runs, `cargo fmt`, `cargo test
    --workspace`. Levels unchanged: D2 must pass these tests with no value
    changed.
  - Lab: none — host tests only (plain `cargo test`, no root, no network): 20 vectors pinned in 14 tests.
- **Lab PR 232 — the copy walk stays out of shared directories (C14;
  follow-up of lab PR 225; no level changes).** NN-L-IMP-001's
  copy-delete evidence (`sample_copies_dir`) looked for the copies below
  and beside the burst's directory whoever shared it: a user's script
  with one plain copy in `/tmp/job` was decisive on another tree's fresh
  copies of ciphertext under the same suffix in `/tmp` — another user's,
  or planted. The walk no longer crosses a world-writable sticky
  directory (`/tmp`, `/var/tmp`, `/dev/shm`): not below one, not beside a
  directory in one, not into one met beside or below; that directory's
  own copies, and the trees of ordinary directories (a `0777` share
  included), still count. The impact tests each work in a directory of
  their own inside their `TempDir` (CI of PR 427: one test's walk read
  another's `.locked` copies beside it in `/tmp`, `(4, 4)` for
  `(3, 3)`). Open: in a shared directory the burst's own directory's
  copies count whoever owns them (an owner match is a follow-up).
  - Lab: host tests only. Before: the unchanged `sample_copies_reads_the_copies_not_the_originals` failed `(4, 4)` on every run with one decoy `.locked` copy planted beside its `TempDir` (TMPDIR set to a private directory) and passed without it; the impact tests alone in that directory failed 36 of 200 runs; the two new tests failed on the old walk (the script's job decisive, three shapes, "3 of 4 copies under .part"). After: `cargo test -p northnarrow-agent --lib impact` 20 times in a row, 20 green (27 tests); 200 runs in the private non-sticky directory (the sandbox alone) and 200 in `/tmp`, 0 failures; golden replay byte-identical, no golden file changed (its sampler answers by path, the walk is not on its path); fmt and the four clippy runs clean; host 2,898 passed, 0 failed (on `main` 381fac6).
- **Lab PR 231 — aya 0.14 in userland (D1a of the Wave 4 phase 2
  dependency plan; every capability, no level changes).** aya 0.13.1 →
  0.14.0 and aya-obj 0.2.1 → 0.3.0 (the agent's dev pin `=0.3.0`, xtask
  `0.3`), one copy of each in `Cargo.lock` and `fuzz/Cargo.lock`
  (supersedes Dependabot #363, which left aya-log at 0.2, so two aya in
  the graph, and did not update `fuzz/Cargo.lock`). aya-log removed: the
  object exports no `AYA_LOGS` map and its init only ever failed. The
  loader keeps its meaning under 0.14's names: `map_max_entries` (the
  exploit guard's task maps) and `default_map_pin_directory` (by-name pins
  under `/sys/fs/bpf/northnarrow`, an existing pin reused); `map_data` in
  the BPF guard covers the nine new `Map` variants (`Map` is not
  `#[non_exhaustive]`: the next new variant fails the build there); the map
  types the object is held to (`ebpf_object::tests`) are re-read from
  0.14's `parse_map`, 29 instead of 20, task storage still not one of them
  (that stays the separate EPG task-storage lot). The kernel side, aya-ebpf
  0.1.1, is lot D1b: the object is the same bytes as on `main`, so a
  verifier or load difference could only come from the loader — aya-obj
  0.3 now hands the kernel the full `line_info` of programs with
  subprograms (0.2.1 truncated it to the `func_info` count), the risk this
  lot's lab run was for. One fix rides along: `boot::release_boot_heap()`,
  a `malloc_trim(0)` once after READY (glibc only), because with aya-obj
  0.3 glibc kept the freed pages of the boot's vmlinux BTF parses and the
  perf gate failed on the agent's RSS (Lab, below).
  - Lab: QEMU for Windows guests with WHPX, the tree 3326d4f (on `main` 381fac6). The eBPF object is the same bytes as `main`'s: sha256 243a806b… from clean builds at the same path on the host (`main` 1f6bc4f and this tree), and the same object embedded on every guest. `verifier-check` of `main` (1f6bc4f; 381fac6 on 24.04) and of this tree, every row equal (result, instructions, instructions verified, stack): Ubuntu 22.04 (5.15.0-198) 74 OK and 2 ABSENT (`inode_set_acl`, `inode_remove_acl`: optional hooks this kernel lacks), no verified count in 5.15's log; Debian 12 (6.1.0-54) 74 OK and the same 2 ABSENT, 1,344,125 instructions verified in both; Ubuntu 24.04 (6.8.0-147) 76 OK, 898,196; Debian 13 (6.12.113) 76 OK, 914,070. The full `line_info` aya-obj 0.3 hands the kernel changed no load and no count. The agent of this tree installed on the four: L3, no degradation, deny hooks 17 of 17 (5.15, 6.1) and 19 of 19 (6.8, 6.12), 8 sensors. On 24.04: `upgrade-check` from `main` installed and running OK (deny 19 of 19, 36 own LSM programs before and after, identity kept, no rollback; `install.sh --upgrade` drops the pin root, so the 12 pinned maps are created again rather than taken over from the 0.13 agent); `test-ignored` 56 suites, 80 passed, 0 failed (the map-pin restart test included). Perf (`nn-lab.sh perf --fresh`): the bump alone regressed the agent's RSS — against `main` measured on the same guest the same night, idle 35,328 → 52,104 KiB (+47.5 %) and under load 46,000 → 63,320 KiB (+37.7 %), both REGRESSION, every other metric ok; a build that logged a `malloc_trim(0)` after READY saw the anonymous memory go from 28,340 to 3,720 KiB: pages glibc kept after the boot's vmlinux BTF parses (about 8 per boot, a 15 MB transient each with aya-obj 0.3, whose `BtfType` grew from 48 to 72 bytes), not a leak — in isolation aya 0.14's loader and its `Ebpf` hold what 0.13's do (10.8 MB after `load()`, 7 MB after a trim, both versions). With `boot::release_boot_heap()` against the committed baseline `perf-2026-10-21-ubuntu2404-40fd666`: 0 regressions (RSS idle 33,876 KiB −1.4 %, load 46,976 KiB +6.7 %, READY 4,508 ms, no ring drop or tracker loss); `perf-compare` needs `--allow-host-mismatch`: the guest's MemTotal reads 8,131,768 KiB, 8,131,764 at the baseline. Host: `cargo xtask build-ebpf --release`, the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` (51 suites, 2,898 passed on 3326d4f, 2,900 after the rebase onto lab PR 232, 0 failed; the golden replay unchanged), `cargo xtask attack-coverage --check`, `cargo +1.89.0 check --workspace --all-targets --locked`, the fuzz job's build (nightly-2025-12-01, cargo-fuzz 0.13.2) and the replay of the 12 targets' seeds and regressions: all pass.
- **Lab PR 233 — aya-ebpf 0.2 in the eBPF programs (D1b of the Wave 4
  phase 2 dependency plan; every capability, no level changes).**
  aya-ebpf 0.1.1 → 0.2.1 in `agent-ebpf/` (aya-ebpf-bindings 0.2.0,
  aya-ebpf-cty 0.3.0, aya-ebpf-macros 0.2.0). This supersedes Dependabot
  #361, whose `ebpf-build` failed because aya-build 0.2.1 needs rustc
  1.98. aya-build is held at 0.2.0 in `agent-ebpf/Cargo.lock`, and
  Dependabot now ignores it there. The nightly (1.93) and bpf-linker
  0.10.3 stay. The source changes are mechanical:
  `helpers::gen` → `helpers::generated` (edition 2024 reserves `gen`; 56
  calls, 10 `use` lines and 3 full paths in 11 files; the file-open
  sensor's `DirClass::gen` field is not the helper and keeps its name),
  and `RetProbeContext::ret` returns the value (one site, a sensor
  feasibility probe). The generated code is not mechanical: 48 of the 96
  BPF functions differ, including every `epg_*`, `exec_check_lsm`,
  `fim_file_open_sensor` and the network kprobes, which now read their
  arguments from the context instead of through `bpf_probe_read`. The
  lab run is the check of that code against the verifiers. The comments
  that said aya-ebpf 0.1 has no CO-RE now say the same of 0.2 (the
  object has no CO-RE record).
  - Lab: QEMU for Windows guests with WHPX; the tree 6112f3c on `main` a9d65ab. Objects: `main` e5a83897…, this tree 8333a443… (the same bytes embedded on every guest, and from a rebuild after the comment changes). Static check of both objects (`llvm-objdump -dr`, their ELF symbols, relocations and BTF): 48 of 96 functions differ (36 change size), 60,997 → 60,615 instructions; the call targets are the same function for function (71 `memset`, 1 `memcmp`, no `memmove` or `memcpy`; the same 42 programs reach `memset`, none of them an `epg_*`, `exec_check_lsm`, `fim_file_open_sensor` or `fim_rename_observe`); the 16 global functions take `u64` arguments only; there is no static subprogram but the `mem*` ones and no CO-RE record; the `maps`, `license` and `.rodata` sections are byte-identical. `nn-lab.sh verifier-check` of both objects with this tree's lab build on each guest (the embedded object, then `main`'s copied over the synced one; per program: `docs/validation/results/verifier-2026-10-22-aya-ebpf-0.2.md`): Ubuntu 22.04 (5.15.0-198) 74 OK and 2 ABSENT (the optional ACL deny hooks) with both objects, processed instructions counted with `bpftrace` on `do_check_common` (the verifier-check process's own loads) 1,670,537 → 1,650,981 in total, the five largest fim_file_open_sensor 483,599 → 483,485, exec_check_lsm 288,804 → 288,811, execmap_check 240,363 → 240,363, probe_file_open 115,372 → 108,358, execpol_env_execve(at) 100,005 → 100,005; Debian 12 (6.1.0-54) 74 OK and 2 ABSENT, 1,344,125 → 1,326,525 (fim_file_open_sensor 300,702 → 300,387, exec_check_lsm 284,239 → 284,246); Ubuntu 24.04 (6.8.0-147) 76 OK, 898,196 → 897,597; Debian 13 (6.12.113) 76 OK, 914,070 → 911,541. No program that loads with `main`'s object fails with this one, none processes more than 20 % more instructions (the largest rises: udpv6_sendmsg_outbound +15.8 % and udp_sendmsg_outbound +15.0 % on 6.8 only, 5,702 → 6,604 and 3,983 → 4,581; module_read_file_observe +9.3 % on 5.15 and 6.1, 12,099 → 13,220), none comes within 25 % of the 1M limit (the largest, fim_file_open_sensor on 5.15, at 48 %); the TCP connect kprobes process 47 % fewer; the deepest call chain stays 448 of 512 bytes (tcp_close). The agent of this tree installed on the four: L3, 0 degradations, deny hooks 17 of 17 (5.15, 6.1) and 19 of 19 (6.8, 6.12) with the self-test denied, no refused / attach FAILED / NOT running in its journal, no verifier rejection. On 24.04: `upgrade-check` from `main` (installed and running) OK — deny 19 of 19, 36 own LSM programs before and after, identity kept; the exploit guard's harness (`deploy/lab/epg/epg-check.sh`, the sequence of lab PR 219) 14 PASS, 0 FAIL, 1 SKIP — the negative suite zero records in lite and strict, the lite exec and strict getppid injections recorded only in detect and killed (137) in kernel in enforce, the capable() case skipped as in lab PR 219 (AppArmor refuses its user namespace before the hook); `test-ignored` 56 suites, 80 passed, 0 failed; `nn-lab.sh perf` (this guest the only one up, the host idle) against the committed baseline `perf-2026-10-21-ubuntu2404-40fd666` with `cargo xtask perf-compare --allow-host-mismatch` (the guest's MemTotal reads 8,131,760 KiB, 8,131,764 at the baseline): 0 regressions, 0 missing — exec 921,666 ns (+4.8 %), TCP connect +1.5 %, open watched +0.8 %, the DNS resolver query +8.2 %, RSS idle 35,580 KiB (+3.6 %), READY 4,524 ms, no ring drop or tracker loss. Host: `cargo xtask build-ebpf --release`, the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` (51 suites, 2,898 passed, 0 failed, the golden replay included), `cargo xtask attack-coverage --check`, the fuzz job's build (nightly-2025-12-01, cargo-fuzz 0.13.2) and the replay of the 12 targets: all pass.
- **Lab PR 234 — the RustCrypto generation moves together (C27; C17
  vault, C23 signed payloads and overlays; Wave 4 Phase 2, D2 of the
  dependency plan; no level changes).**
  - What was wrong: the crypto crates were a generation behind (aes-gcm
    0.10, hkdf/hmac 0.12, sha2 0.10, md-5 0.10, ed25519-dalek 2, rand 0.8),
    and they cannot move one at a time: ed25519-dalek 2 holds digest 0.10,
    so bumping sha2, hkdf or aes-gcm alone carries two copies of digest and
    crypto-common (the E0277 of Dependabot #287; #289 failed on the
    deprecated `Nonce::from_slice`), and ed25519-dalek 3 needs rand_core
    0.10, hence rand 0.10, which has no `OsRng`.
  - What changed: sha2 0.11 (agent, common, ebpf-guard, scan), hkdf and
    hmac 0.13, aes-gcm 0.11, md-5 0.11, ed25519-dalek 3 (`std` → `alloc`),
    rand 0.10, in `Cargo.lock` and `fuzz/Cargo.lock` alike, one copy of
    each (getrandom 0.4.3 in both). `agent/src/os_rng.rs`: `OsRng`, an
    infallible `CryptoRng` over rand's `SysRng` — getrandom, the
    `getrandom(2)` syscall on Linux as before, no buffer and no userland
    generator between it and a key, a panic if it fails as rand 0.8's did;
    the 102 `SigningKey::generate(&mut OsRng)` and every nonce, challenge
    and seed use it; the agent id, the audit signing key and the probe
    nonce read `SysRng` and keep their error paths; the anti-tamper session
    nonce moved from `thread_rng` (a ChaCha seeded by the OS) to the OS
    generator itself. The vault's nonce is `Nonce::from` its array (the
    read side checks the 12 bytes first) and the `.meta` SHA-256 is
    `hex::encode` (same lowercase hex). The fuzzer lock check
    (`security_crates_are_locked_alike_for_the_fuzzer`) also covers rand,
    rand_core, getrandom and md-5. Supersedes Dependabot #289 and #287.
  - Evidence: the 20 vectors of lab PR 230 (14 tests, `cargo test
    crypto_vectors`) pass with no value or fixture changed; `cargo tree -d`
    shows no copy of a RustCrypto, rand or getrandom crate (only syn,
    hashbrown and thiserror, as on `main`); the eBPF object's program, map
    and data sections are byte-identical to `main`'s (only the debug and
    BTF path strings differ); `cargo +1.89.0 check --workspace
    --all-targets --locked` passes at the `rust-version` (aes 0.9.3 needs
    exactly 1.89), and the fuzz job's nightly-2025-12-01 builds and
    replays all 12 targets; `cargo audit` clean.
  - Lab: On Ubuntu 22.04 (5.15, QEMU for Windows with WHPX): `main` a9d65ab synced, built and installed; its agent at L3, deny hooks 17 of 17, self-test denied, 0 degradations. A signed overlay (process-comm-allowlist) stored with `main`'s nn-admin. `nn-lab.sh execq-check` on `main`'s tree: PASS; case 2's harmless block-listed test binary killed while held and quarantined by the agent: vault 1fe5d76348f44eec9b12fad4acdd76dc, 16,136 bytes, `.meta` sha256 c02f2e6a0c0d11dfa1af84c8069e88c2fa9aea1e5730c41f288f3193d4be1e4f (the harness had hashed the test binary as c02f2e6a0c0d11df… before running it). Then the branch synced and built, and `nn-lab.sh upgrade-check` (`install.sh --upgrade`): OK — UPGRADE complete, health check passed, identity kept, deny_attached=17 deny_expected=17, 34 own LSM programs before and after, no anti-tamper degradation signed. The entry's `.bin` (df2bfce1…), `.meta` (d1d0cda2…) and `master.key` (939d66ff…) byte-identical across the upgrade. `nn-admin response restore` with the branch's nn-admin: first refused `role denied` (the lab's bootstrap key has no `response-manage`, as `cow-check.sh` notes); the role granted the way `cow-check.sh` grants it (trusted-installer window, agent restart), the restore wrote 16,136 bytes, mode 0600, sha256 c02f2e6a0c0d11dfa1af84c8069e88c2fa9aea1e5730c41f288f3193d4be1e4f — the `.meta` `main` wrote — signed `response_restore`; the vault kept the entry; the role taken back. `main`'s signatures on the branch: the overlay `main`'s nn-admin stored was accepted by the upgraded agent at boot (`signed overlay accepted`, sha256 940b124a…) and `config overlay status` says it loads; `main`'s nn-admin binary (kept aside) got `response status` and `capabilities` through the branch agent's challenge, and its `config overlay set` (a signed CBOR payload) was verified, stored and signed `config_overlay_set` by the branch agent. The branch agent at each of its three boots (upgrade, the two restarts): L3, deny hooks 17 of 17, deny self-test `denied` (a signal from an unprotected child refused), 0 degradations. Guest put back (overlay, kept binary, role). Host: `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` 2,900 passed, 0 failed; `crypto_vectors` 14 of 14; golden replay unchanged; the four clippy runs, `cargo fmt`, `attack-coverage --check`, MSRV 1.89, the 12 fuzz targets built and replayed on nightly-2025-12-01, `cargo audit`: all pass.
- **Lab PR 229 — two flaky privileged tests fixed in the product: a
  `chmod u+s` always recorded, the DNS attribution behind its ring and
  through `nss-resolve`.** C06 (file telemetry and FIM), C07 (endpoint
  network telemetry); Wave 4 Phase 2.
  - What was wrong: `fim_chmod_setuid_records_attribute_drift` failed on
    PR 421 (CI run 39622005407, Ubuntu 24.04) with one `Modified` row and
    no baseline: the recompute task filled the drain's cache only after
    the baseline row's fsync, and a chmod in that window was compared with
    nothing. Two more ways a set-uid bit went unrecorded: the
    `inode_setattr` hook fires before the change lands, and a drain that
    re-read the file first dropped the event as a no-op touch; a mode
    change read with a content change left no attributes on its row.
    `net_outbound_connect_records_flow_with_dns_attribution` left
    `resolved_hostname` null on 24.04 (CI run 39602279581): the query, the
    connect and the close come on three rings read by three tasks, and a
    close read before the DNS pump had read the query found no name. On
    Debian 13 (`resolve` before `dns` in nsswitch.conf) it always failed:
    the lookup goes to systemd-resolved over varlink, no datagram of the
    process's own (lab PR 227's one expected failure).
  - What changed: `BaselineDb::append_cached` (the cache holds the entry
    before its row is written); a setattr re-read as unchanged waits for
    the change like a rename or an enrollment (2 s, looks from 5 ms
    doubling to 250 ms) and is then checked as its writer's modification;
    a `Modified` row names a mode or owner change that came with it.
    `DnsIngest`: the net drain and the connect pump wait, bounded (250 ms
    from the record), for a pass of the DNS pump begun after their newest
    record; the pump feeds the cache a whole pass at a time and holds the
    bus's events in order (up to 8192). A uprobe on `libnss_resolve.so.2`
    (`_nss_resolve_gethostbyname4_r`, `…3_r`; optional) feeds the names
    asked through systemd-resolved into the attribution only (no
    `DnsQuery` event, no server); the expected failure is gone and
    `verifier-check` loads uprobes. Lab gates: `malsim/exec-check.sh`
    copies `true` as `dir/<case>/true` (uutils on 26.04); nn-lab.sh knows
    `ubuntu2604`, which joins the nightly CI matrix (not the pull
    requests'); its first gate run found two uutils differences, fixed:
    `fs_deny_privileged_e2e` read EPERM from coreutils' message (uutils
    prints "Permission denied" for EPERM; the attempts now go through
    python3, which prints the errno's own), and `install.sh --upgrade` ran
    `install -d` on the immutable state directory before lifting the flag
    (uutils sets owner and mode again where GNU skips them). The local
    gate script replays the fuzz inputs as the CI job does.
  - Lab: On Debian 13 (6.12), 30 runs of each test before (main 8180540) and after: the FIM test with its fixtures on tmpfs 30/30 → 30/30, on ext4 30/30 → 30/30, on ext4 with a 1 ms baseline poll 30/30 → 30/30, on a dm-delay ext4 (an fsync of ~100 ms) 6/30 → 30/30, the 24 failures each one `Modified` row with a null baseline, the chmod's own (the CI's shape); the DNS test through nss-resolve 0/30 → 30/30 (probes on `/usr/lib/x86_64-linux-gnu/libnss_resolve.so.2`, 4_r and 3_r), with `hosts: files dns` (24.04's path) 30/30 → 30/30, the same with 600 DNS records queued ahead of the helper's query 28/30 → 30/30, the 2 failures a null `resolved_hostname`. On the final tree there: `verifier-check` 77 of 77 OK (`dns_nss_resolve` 537 instructions processed, stack 64 bytes, 96 down its deepest call chain, of 512), `dns-sensor-check` OK (10 of 10), `net-check` 13 of 13, the net and FIM privileged suites 5 of 5 and 6 of 6; `fim-reuse-check` NOT RUN (no inode reused within 5000 files). Ubuntu 26.04 (`ubuntu2604`, the lab's WHPX guest) booted from the catalogue: its image list checked against the pinned UEC key, kernel 7.0.0-38-generic with `bpf` in the LSM list, uutils coreutils (rust-coreutils 0.10), systemd 259, no libnss_resolve (the NSS probe not attached, said so); `verifier-check` 77 of 77 OK; the gate's test-ignored on the tree before the two fixes: 55 suites, 79 passed, 1 failed (`new_entries_and_xattrs_are_denied_outside_the_window`, the refusal read from uutils' message); after them `fs_deny_privileged_e2e` 2 of 2, an `install.sh` upgrade over the running install (immutable state directory) through where it had failed and rolled back, and the two tests of this lot 10 of 10 each. On the final tree the gate's test-ignored there: 56 suites, 80 passed, 0 failed (gate-summary: pass); `malsim-exec-check` there: MS-01/02/03/32 before and after, audit and the desktop cases passed with the copies of `true` (MS-02 and MS-03 ran, rc 0, as on 24.04), the two NN-L-EXECENV-002 cases (`HISTFILE=/dev/null bash`, `GLIBC_TUNABLES` at su) drew no record — open, outside the CI gate.
- **Lab PR 235 — NN-L-CHAIN-007 completed by a `/tmp` exec processed
  after the read and the egress.** C14 (behavioural detection and
  correlation); Wave 4 Phase 2.
  - What was wrong: on PR #428's first CI attempt (run 39729153594,
    Ubuntu 22.04, 5.15) `chain_tmp_then_cred_then_egress_trips_chain_007`
    found no CHAIN-007 verdict. The agent log: the exec check raised
    StagingExec, then FIM-015 fired on the credential read, CHAIN-001 on
    the connect, and R009 on the `ProcessSpawn` last — the exec record
    (its own ring and pump) reached the engine after the read and the
    connect it preceded, and the `TmpExec` was not in the store when the
    egress was judged. Review 70 had covered a late read, not a late
    exec. Not a regression of lab PR 229 (its `DnsIngest` wait delays
    the connect, not the exec; the loop below is the same before and
    after it), and no earlier CHAIN-007 failure in the 47 lab-vm runs.
  - What changed: CHAIN-007 also judges a staging exec: when the same
    process has a credential read at or after the exec and a noted
    egress after the read, within the window (kernel timestamps), it
    fires the Critical KillProcessTree verdict naming the egress, and
    observes the exec and records its `TmpExec` as CHAIN-002 would. On a
    miss nothing changes. CHAIN-001's in-order and late completions now
    claim the noted egress instead of removing it, so no second two-step
    chain uses it but the late exec still upgrades it to the three-step
    one; the flow ledger keeps one more chain verdict off its close.
  - Lab: On Ubuntu 22.04 (5.15, KVM guest ubuntu2204), the test alone, 30 runs per tree: `main` before #428 (4423267) 30/30 pass; `main` 8f52f5c 30/30, and 30/30, 30/30, 10/10 with 3, 8 and 16 `/bin/true` exec loops in the guest (the CI reorder not reproduced in the lab); this branch 30/30, and 30/30 with 8 exec loops; the whole `detection_rules_at_scale_privileged_e2e` suite 16 of 16. Host: `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` 2,913 passed, 0 failed (3 new unit tests of the late exec); the four clippy runs, `cargo fmt`, `attack-coverage --check`: pass.
- **Lab PR 237 — the remaining dependencies refreshed (C27; Wave 4
  Phase 2, D3a of the dependency plan; no level changes).**
  - What was wrong: after D1 and D2 the lockfiles still trailed by 49
    patch/minor entries at the root, 10 in the fuzzer and 9 in
    agent-ebpf; nix was at 0.29 with 0.31 out (Dependabot #433); and
    Dependabot's grouped cargo entry moved only the root `Cargo.lock`, so
    its PR left `fuzz/Cargo.lock` behind on tokio or nix and
    `security_crates_are_locked_alike_for_the_fuzzer` red (#413, redone
    by hand in cc6ac72).
  - What changed: nix 0.31.3 (the agent; `signal` and `process`, no
    source change); `cargo update` of the three lockfiles (tokio 1.54.1,
    cc 1.9, syn 2.0.119 / 3.0.9, zerocopy 0.8.63, …), aya-build held at
    0.2.0, aya / aya-obj and the RustCrypto crates not moved (Dependabot
    #435's aya-obj 0.5 does not fit aya 0.14's pin); the CLI stub's
    unused `northnarrow-common` and `anyhow` removed; the grouped cargo
    entry of `.github/dependabot.yml` covers `directories: ["/",
    "/fuzz"]`, checked by `dependabot_moves_the_fuzz_lockfile_with_the_root_one`.
    MSRV 1.89 unchanged; parking_lot 0.13 (MSRV 1.95) is left to D3b.
    Supersedes Dependabot #433.
  - Lab: QEMU guests (ubuntu2204 KVM, debian12); the tree c73d0a3 on `main` 60a65cb. Objects: the same tree path built with `main`'s and with this branch's `agent-ebpf/Cargo.lock` differ only in `.debug_str` (the crate hashes of the mangled names, same length): `.text`, every program and map section, `.BTF`, `.BTF.ext`, `.rodata`, `license` and the ELF symbols byte-identical; this branch's object cfa68c2b…. `nn-lab.sh verifier-check` with the branch's lab build (the object embedded, cfa68c2b…, and the synced copy): Ubuntu 22.04 (5.15.0-198) 77 programs, 75 OK, 2 ABSENT (the optional ACL deny hooks), 0 failing; Debian 12 (6.1.0-54) 77 programs, 75 OK, 2 ABSENT, 0 failing (fim_file_open_sensor 300,387 and exec_check_lsm 284,246 instructions processed, as in lab PR 233). `test-ignored` on Ubuntu 22.04: 56 suites, 80 passed, 0 failed (24.04 was in use by another lot). Host: `cargo +1.89.0 check --workspace --all-targets --locked`, `cargo xtask build-ebpf --release`, the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` (2,914 passed, 0 failed, the golden replay included), `cargo xtask attack-coverage --check`, the fuzz job's build (nightly-2025-12-01, cargo-fuzz 0.13.2, `fuzz/Cargo.lock` `--locked`) and the replay of the 12 targets, `cargo audit` on the three lockfiles (0 vulnerabilities; the registered unsafe-libyaml exception): all pass.
- **Lab PR 236 — multi-match decisions and the signed per-rule response
  policy.** C14 (behavioural detection: multi-match) and C12 (a response
  policy per rule); Wave 4 Phase 2, the core of the phase.
  `docs/design/MULTI_MATCH_AND_RULE_POLICY.md`, `docs/operator/RULE_POLICY.md`.
  - What was wrong: the engine stopped at the first rule that matched an
    event, so later rules never saw it: NN-L-FIM-023 was never reached
    (NN-L-FIM-009 first on the same paths), NN-L-FIM-002's record beat
    NN-L-FIM-004's kill on a new `authorized_keys` under `/home`,
    NN-L-NET-007 (Medium) shadowed NN-L-NET-009 (High) and its UDP sum,
    and a late exec that completed NN-L-CHAIN-007 (lab PR 235) left R001 and
    R009 silent. The kills held by the decision of 21/10/2026 had no way to
    be turned on.
  - What changed: every rule judges every event and the decision is
    computed from all the matches — the strongest action the matches'
    modes allow, run once per target; the highest severity; a primary rule
    by severity, action, then registration order — and the record names
    every match (`matches`) with the union of their ATT&CK ids. The legacy
    ceiling (the review of 22/10/2026): without a signed `enforce` for the
    rule supplying it, no event gets a stronger response than the
    first-match engine gave it — so FIM-004's kill on a new
    `authorized_keys` under `/home` is recorded and held until `enforce
    NN-L-FIM-004`. A signed
    overlay `rule-policy.local` (`OverlayKind::RulePolicy = 15`) maps a rule
    to off, audit, alert or enforce (a held kill given back), exempts an
    actor by uid, executable with its digest, cgroup or unit (never by
    name), and carries the ransomware COMBAT flag; the `PolicySwitch`
    constants are its built-in defaults, so without a policy nothing that
    was held runs. Boot through the overlay gate (signed row
    `rule_policy_loaded`, refusal `unauthorized_overlay`, a signed file
    that does not parse a degradation `rule_policy`), live swap on
    `nn-admin policy set`, `nn-admin policy show|test`, fuzz target
    `rule_policy`, golden format 2 with seven new cases, lab harness
    `nn-lab.sh policy-check`.
  - Lab: On Ubuntu 24.04 (6.8, QEMU for Windows with WHPX), `main` 60a65cb synced and installed, then this branch (4c89614, the tree of e1c23c3 but for two operator-doc lines) synced and built: `upgrade-check` from `main` OK (deny 19 of 19, 36 own LSM programs before and after, identity kept); `test-ignored` 56 suites, 80 passed, 0 failed. Harnesses without a policy, every held kill held: `ransom-check` 15 PASS, 1 SKIP (auditd not installed), MS-23 in place and copy-delete each a Critical NN-L-IMP-001 with its kill held (the simulator ran to 300 of 300 files, posture ENGAGED, never COMBAT), the 9 negatives clean; with auditd installed `ransom-check --only MS25` 5 of 5 (NN-L-EVA-001..004 High, the 27 EVA records of the run all response none); `net-check` 13 of 13 (R020 on both reverse shells recorded, the shells not killed; NN-L-NET-026's kill tier held, kills=0; NN-L-NET-010 killed the C2-port client at the connect after 34 ms, a kill that predates the holds; the TCP/53 flow of a /var/tmp program one record naming NN-L-CHAIN-002 and NN-L-NET-008, both held); `malsim-exec-check` 20 of 20; `epg-check` 14 PASS, 0 FAIL, 1 SKIP (the capable() case, AppArmor refuses its user namespace, as in lab PRs 219 and 233). Multi-match on the guest: 9 records carried `matches` — NN-L-FIM-009 with NN-L-FIM-023 on dpkg's `nn-pkgprobe.timer` (Low, the package carve-out; FIM-023 had never recorded), NN-L-FIM-001 with NN-L-FIM-009 on `auditd.service.dpkg-new` (Low, 3), NN-L-CHAIN-002 with NN-L-NET-008 (held), NN-L-IMP-001 enforced (4). Signed policy (`nn-lab.sh policy-check`, `deploy/lab/malsim/policy-check.sh`, run before its last step — removing the policy files — was added; the lab key, role config-manage): built-in, MS-23 recorded and held (300 of 300 files); `nn-admin policy set` of `enforce NN-L-IMP-001` stored, applied at once, a signed `config_overlay_set` row "applied now"; a policy exempting by `comm` refused by nn-admin (exit 2), nothing sent, no row, the policy in force unchanged; MS-23 then killed — the simulator's tree stopped after 21 of 300 files, the record KillProcessTree, mode enforce; the agent restarted in a trusted-installer window booted on the signed file (a signed `rule_policy_loaded` row, the journal's "per-rule response policy in force") and killed MS-23 again at 21 files; a policy of comments only put the built-in defaults back, MS-23 held (300 of 300). Guest put back (the policy files removed, auditd purged). Perf (`nn-lab.sh perf --fresh`, e1c23c3, the guest the only one up) against the committed baseline `perf-2026-10-21-ubuntu2404-40fd666` with `cargo xtask perf-compare --allow-host-mismatch` (MemTotal 8,131,760 KiB, 8,131,764 at the baseline): PASS, 0 regressions, 0 missing — exec −1.3 %, open watched −2.0 %, TCP connect +15.2 % (threshold 35 %), DNS sent +9.6 % (its agent-off reference +14.5 %: the host), agent CPU 0.15 % idle and 7.45 % under the burst, RSS 34,276 KiB idle (−0.2 %) and 39,408 KiB under load (−10.5 %), a credential read signed in 0.22 ms, READY 4,517 ms, no ring drop or tracker loss. On Ubuntu 22.04 (5.15): the branch synced and installed, `test-ignored` 56 suites, 80 passed, 0 failed. Host: `cargo xtask build-ebpf --release`, the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` (51 suites, 2,954 passed, 0 failed; the golden replay included), `cargo xtask attack-coverage --check`, `cargo +1.89.0 check --workspace --all-targets --locked`, the fuzz job's build (nightly-2025-12-01, cargo-fuzz 0.13.2) and the replay of the 13 targets' seeds and regressions (FUZZ-OK): all pass. Rebased onto `main` 1609034 (lab PR 237, dependencies only; the guest runs above are of the tree before it): the host gates again — build-ebpf, the four clippy runs, fmt, 51 suites 2,955 passed 0 failed, attack-coverage, the 13 fuzz targets replayed: all pass. The legacy ceiling (review of 22/10/2026), on Ubuntu 24.04 with no policy on the guest: the tree synced and installed, `nn-lab.sh policy-check` PASS (MS-23 held built in, 300 of 300 files; killed at 21 of 300 under the signed `enforce NN-L-IMP-001`, live and after a restart with a signed `rule_policy_loaded`; the policy exempting by comm refused; comments only put the defaults back, 300 of 300 held; the policy files removed after), `net-check` 13 of 13, `ransom-check` 15 PASS and 1 SKIP (auditd not installed): over the 48 records of the run no match held by the ceiling, and the only kills were R003's and NN-L-NET-010's (both predate the lot) and NN-L-IMP-001's under the test policy — nothing new kills by default. Host on that tree: the four clippy runs, fmt, 51 suites 2,962 passed 0 failed (the golden replay with `main`'s executed action on every one of its 63 lines), attack-coverage, the 13 fuzz targets replayed: all pass.
- **Lab PR 238 — three small correctness bugs (C05, C14, C17; Wave 4
  Phase 2; no level changes).**
  - What was wrong: (1) lot 122, never merged: `parent_start_ns`, the
    PID-reuse key of an exec's parent, was `real_parent->start_time`,
    and `real_parent` is the thread that forked: a child of a thread
    other than its parent's main one carried that thread's start, which
    no record of the parent names (its exec reports the leader's), so
    once an offender had exited the COMBAT ladder no longer took such a
    child for its child (the residual of lab PR 120). (2) The quarantine
    vault's `.bin` had no header: its format was only implied by the
    HKDF salt `-v1`, so a format change could not be told from damage.
    (3) In a world-writable sticky directory that was the burst's own
    (`/tmp`), NN-L-IMP-001's copy-delete evidence counted the copies of
    whoever owned them (the residual of lab PR 232).
  - What changed: (1) the exec sensor reads
    `real_parent->group_leader->start_time` (new required BTF offset
    `TASK_STRUCT_GROUP_LEADER_OFFSET`, slot 100, appended so no earlier
    slot moves; the enum, tracepoint and hook-argument slots move up by
    one, 117 slots); unread, 0, never a thread's start. Two plain reads
    into the ring record, no stack copy and no call (KERNEL_COMPATIBILITY
    "Older verifiers"). (2) New entries are written as v2: `"NNQV" ‖ 02 ‖
    nonce ‖ ciphertext ‖ tag`, the key salted `-v2`, the header and the
    vault id authenticated, `"format": 2` in the `.meta`; entries without
    a `format` are read as v1; an unknown format, in the `.meta` or the
    header, or a `.bin` that disagrees with its `.meta`, is refused with
    that reason before anything is decrypted. Lab PR 230's v1 vectors and
    v1 vault fixture unchanged (the test of what the quarantine writes
    now pins v2); a v2 record pinned, recomputed outside the repository
    (Python `cryptography` 41 on OpenSSL). (3) In a shared directory a
    copy counts only when the uid the burst ran as owns it — the copy the
    record names included, checked on the file opened; elsewhere
    unchanged. A new `Sampler::sample_copies_by` (default: the uid-less
    `sample_copies`) carries the uid, so the decision engine's test and
    golden samplers are untouched.
  - Lab: QEMU for Windows guests with WHPX, the branch's lab build (eBPF object 82172165…). (1) `nn-lab.sh verifier-check`: Ubuntu 22.04 (5.15.0-198) 77 programs, 75 OK, 2 ABSENT (the optional ACL deny hooks), 0 failing; Debian 12 (6.1.0-54) 75 OK, 2 ABSENT, 0 failing — `sched_process_exec` 1,952 instructions and 4,926 processed (`main`'s object 1,909 / 4,869), `sched_process_exec_nostdio` 1,030 / 2,377 (987 / 2,320); Debian 13 (6.12.113) 77 of 77 OK; Ubuntu 24.04 (6.8.0-147) 77 of 77 OK, `sched_process_exec` 1,952 / 3,649; on each, 105 slots resolved from the live BTF (2 optional ones absent on 5.15). The e2e with the installed units stopped the operator way (trusted-installer window, watchdog then agent, pin root removed): on Ubuntu 22.04 `main` 1609034's eBPF with the new test FAILED as expected — the child's `parent_start_ns` 1190978440890, the forking thread's start, 1.2 ms after its parent's exec `start_ns` 1190977234699 — and the branch's passed (`exec_sensor_live` 4 of 4); on Debian 12 the branch's passed, 4 of 4; units put back on both (L3, deny hooks 17 of 17, self-test denied, 0 degradations). (2) On Ubuntu 22.04: `main` 1609034 synced and installed, `nn-lab.sh execq-check` (`main`'s tree) quarantined its block-listed test binary as v1 entry 72b62a03…, beside two v1 entries of earlier `main`s (1fe5d763…, 6b286cc1…); the branch built, `upgrade-check` from `main` OK (UPGRADE complete, identity kept, deny hooks 17 of 17, 34 own LSM programs before and after); the vault's `.bin`, `.meta` and `master.key` byte-identical across the upgrade; response-manage granted as `cow-check.sh` does; the three v1 entries restored by the branch's nn-admin, each sha256 c02f2e6a… as its `.meta` recorded, mode 0600; `execq-check` on the branch: entry e55bec99…, its `.bin` starting `4e 4e 51 56 02` (16,169 bytes: 5 + 12 + 16,136 + 16), its `.meta` `"format":2`, restored with the sha256 the harness took before the quarantine; a copy of it with the version byte set to 3 refused (exit 9, "the entry's .meta declares vault record format 2, its .bin is format 3 — refused"), nothing written, a signed `response_restore` row; copy removed, role taken back, the agent at L3, deny hooks 17 of 17, 0 degradations. (3) Before: `main`'s impact code with the new tracker test — another uid's copy-delete burst in a sticky directory decisive on this test's copies (`!b.decisive` failed); after: the impact tests pass (29, one root test ignored on the host), and the root test with two owners side by side passed as root on Ubuntu 22.04 and Debian 12; golden replay byte-identical, no golden file changed. Host: `cargo xtask build-ebpf --release`, the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` 2,922 passed, 0 failed (the golden replay and `crypto_vectors`, 19 tests, included), `cargo xtask attack-coverage --check`, `cargo +1.89.0 check --workspace --all-targets --locked`, the fuzz build and replay of the 12 targets (nightly-2025-12-01, `--locked`): all pass.
- **Lab PR 239 — the restructure's guardrails and scaffolding (Wave 4
  Phase 2, R00 + R01 of the restructure plan; no level changes).**
  - What was wrong: the restructure (R02–R17) moves the agent's modules
    into layered crates, and several checks would have switched off in
    silence under a move: embeds and reads relative to the including file
    (`include_str!("../../../configs/…")`, `CARGO_MANIFEST_DIR/..`), member
    lists parsed from one line of `Cargo.toml` (the licence check, the
    lab-vm filter scan) or written by hand (the Kani proof scan: six
    crates), the journal-field scan of two fixed directories, the line
    guard pinned to two `main.rs`, workflow path filters nobody checked
    but lab-vm.yml's; no crate rule said where a module may go; the
    x86-64-v2 rustflags applied to every target.
  - What changed: R00 — `NN_REPO_ROOT` (`.cargo/config.toml` `[env]`) for
    every repository path of the agent and the watchdog (37 files);
    `cargo metadata` for the member lists; `xtask/tests/path_liveness.rs`
    (workflow path filters, `cargo kani` steps, `-p` and features of CI and
    the lab scripts, the files the xtask tests name, no depth-relative path
    in a member); `docs/architecture/module-map.toml` (the crates, what each
    may depend on, the target crate of every module of `agent/src` and
    `common/src`, the post-plan ones marked) and its ratchet
    `xtask/tests/module_map.rs` (77 violations: nn-core 53, nn-evidence 12,
    nn-admin 6, nn-linux 3, nn-proto 3); `[workspace.lints]`; SBOM cleanup
    to depth 3; `fuzz/**` in lab-vm.yml's filters (the agent's seed test
    reads it, which the new scan sees). R01 — the empty crates
    `crates/nn-{parse,model,proto,evidence,core,linux,admin}` (workspace
    fields and lints, `#![forbid(unsafe_code)]` but nn-linux), members and
    `[workspace.dependencies]`, the gate `xtask/tests/workspace_layers.rs`
    (the members' dependencies against the map, no cycle, the pure crates'
    rules, the lints, `portable-core`'s list), the CI job `portable-core`
    (`cargo check` of the pure crates for aarch64 Linux, Windows and macOS
    on x86_64 and aarch64), the x86-64-v2 rustflags under
    `[target.x86_64-unknown-linux-gnu]` as a string (the per-target
    variable still replaces it), `crates/**` in lab-vm.yml. Deviations
    from the plan: the golden replay of lab PR 228 is the replay harness
    (the posture and the ladder are not replayed yet: before R08); common's
    one `CARGO_MANIFEST_DIR/..` (a test) and `agent/build.rs` keep theirs
    (the eBPF source closure; R09b); the modules of lab PRs 214–238 are
    mapped on the plan's principles; the scanner crate (lab PR 223) has a
    rule of its own. Open, for the next lots: the ratchet shows
    nn-evidence → nn-proto (`verify_lines` and `canary::chain_lines` read
    `admin_protocol`), which §2.1 draws as siblings — R05 cuts it or the
    map allows it; nn-admin's host checks are nn-linux's (`agent_id`,
    `host_hardening`), a decision for R10; nn-model will depend on
    `common`, whose `atomic_file` is Unix-only until R03 takes it out, so
    R02 either follows R03 or leaves nn-model out of `portable-core` until
    then.
  - Lab: no guest (the shipped code does not change: see the identity below). Host: `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test --workspace --exclude northnarrow-agent-ebpf --locked` 2979 passed, 0 failed (2972 at R00); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` with the golden files unchanged; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets, seeds and regressions, the three lockfiles unchanged); `portable-core`'s `cargo check` for the five targets, installed with rustup. Identity against `main` 0abf596, same path, same commands: the eBPF object (sha256 9345ac10…) and its stamp are byte-identical to `main`'s; built as the release job builds (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`), the watchdog (b538235d…) and the scanner (33be3ab2…) are byte-identical, the agent (23f51b19… → 130f3707…) and nn-admin (1390b7b8… → 3db04031…) have the same size and the same `.text`, and differ in 127 and 22 bytes, all in `.rodata`, `.data.rel.ro` (line numbers moved by 1, 2, 3, 4, 12 and 15: the lines the reformatted embeds of seven files added) and the build id; R01's four binaries and object are byte-identical to R00's. `mk-tarball.sh`: the same 72 entries; `mk-packages.sh` (.deb): the same 79 paths, modes and sizes but `CHANGELOG.md`.
- **Lab PR 240 — nn-proto and nn-model: the admin protocol and the event
  model leave `common` (Wave 4 Phase 2, R03 + R02 of the restructure
  plan; no level changes).**
  - What was wrong: `common`, the crate the eBPF object compiles, also
    held the userland's event model, the admin protocol, the signed
    payloads, the quorum, the shutdown marker, the watchdog hold and two
    Unix-only helpers (`atomic_file`, `sd_notify`): an edit to any of them
    made the eBPF object's stamp stale, the watchdog and nn-admin took the
    whole event model to read a frame, and no crate above `common` could
    build for another OS — R02's nn-model would have inherited
    `atomic_file` (lab PR 239's finding), hence R03 first.
  - What changed: R03 — `common`'s `wire::admin_protocol`,
    `wire::admin_signed_payload`, `admin_quorum` (and its Kani proof),
    `shutdown_marker` and `watchdog_hold` moved unchanged (`git mv`,
    100 %; `admin_protocol` 97 % with the new test) to `crates/nn-proto`,
    with their dependencies and the `debug-trigger` feature (the agent
    forwards it; CI's wire-discriminant step and `kani.yml` on `-p
    nn-proto`); `atomic_file` and `sd_notify` to
    `northnarrow-antitamper-bpf`. A test pins five admin frames and a v1
    envelope byte for byte (computed on `main` before the move, the same
    after). R02 — `common`'s `model.rs` to `crates/nn-model/src/event.rs`
    (its items at nn-model's root), `posture_types`, `netaddr`,
    `log_escape` to nn-model, the std types of `wire/mod.rs` and their
    tests to `nn_model::telemetry` (the `std` gates dropped), `dns_qname`
    and its Kani proofs to `crates/nn-parse`; nn-proto then depends on
    nn-model only, the watchdog and the fuzz crate no longer on `common`.
    The moved files compile through `pub(crate)` shims at the new crates'
    roots (`crate::wire`, `crate::epg`, `crate::dns_qname`,
    `crate::posture_types`; removed in R17). The ratchet scan names the
    crates of `crates/` (a moved module's reference still counts): 77,
    unchanged. nn-model and nn-proto now hold code; `portable-core`
    checks them on the five targets. Deviations from the plan: no shim at
    the old paths — `common` cannot re-export crates that depend on it
    (cargo refuses the cycle), so the importers' paths were rewritten (the
    plan's "riscrittura meccanica" of R02, done for R03 too), in the
    step's one commit: no separate move and rewrite commits, no
    `.git-blame-ignore-revs`, and `wire/mod.rs`'s std half cut rather than
    split with appendix A's merge recipe (`git blame -C -C` finds the
    lines); `execq` (post-plan, mapped to nn-proto), the name tables of the
    raw layouts and `wire::cstr_lossy` stay in `common`, which is the ABI
    plus the scanner protocol, not the ABI alone; the ratchet does not go
    down — no counted reference was from a moved module, and the two
    nn-evidence → `admin_protocol` ones (`verify_lines`,
    `canary::chain_lines`) remain; the binaries are not byte-identical
    (below); no guest run (the KVM jobs of the PR run the privileged
    suites). Open: `execq` to nn-proto with the scanner; the nn-evidence →
    nn-proto arc (R05); nn-admin's `--events` help still names
    `common::Event` (kept: no output changes in a move).
  - Lab: no guest (moves only; the identity below). Host, on each commit (R03 09c65fd and the tip): `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked` 68 suites, 2,988 passed, 0 failed (`main` 2e1438f: 2,987; the test list is `main`'s plus `encoded_frames_are_pinned`, every moved test found by name); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo test -p nn-proto --features debug-trigger --lib admin_protocol` (60 passed); `cargo xtask attack-coverage --check`; `cargo xtask golden` with the golden files unchanged; `cargo +1.89.0 check --workspace --all-targets --locked`; `portable-core` locally, the five targets, nn-parse, nn-model, nn-proto, nn-evidence, nn-core; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets built against nn-proto, nn-model and nn-parse, seeds and regressions; the three lockfiles unchanged by the build): all pass. Identity against `main` 2e1438f, same path, same commands: the eBPF object is byte-identical (sha256 d5474fc4…) at R03 and at the tip, its stamp's source hash f4fb7f9d… → d93b49ed… (R03) → c3651dc3… (`common/src` and its manifest are the object's source closure), embedded in the agent as before. Built as the release job builds (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`), the binaries are not byte-identical: scanner 401,368 → 401,400 bytes, watchdog 2,337,264 → 2,336,904, nn-admin 3,901,064 → 3,912,344, agent 14,631,184 → 14,642,952. A move between crates cannot keep them so: a crate's identity seeds symbol names and `TypeId`s, and the fat-LTO module is composed anew. Control: `main` built in another directory is byte-identical to `main` here (no path in the binaries); `main` rebuilt with one unused optional dependency in `common` (anyhow, enabled by `std`; no source changed) moves the scanner by 16 bytes and changes 2 functions of the watchdog (a `TypeId`), 16 of nn-admin and 17 of the agent. Unstripped builds (same flags, strip off), function by function, names mapped to the new crates and addresses dropped: scanner 503 of 504 functions the same code (one postcard decoder of `execq`, a crate this lot does not touch, allocates its registers otherwise), watchdog 2,429 of 2,468 (+1 kept out of line), nn-admin 3,210 of 3,330, agent 7,217 of 7,408; the others differ in inlining (postcard and serde helpers), interprocedural constant propagation (`RawVec` growth), which of identical bodies keeps its name, register allocation and `TypeId` constants. The text of `.rodata` differs only in the moved files' paths (panic locations: `common/src/{admin_quorum,shutdown_marker,model,dns_qname}.rs` → `crates/…`), log-callsite line numbers and the stamp hash; no module path, type name or help text changed (a first build changed nn-admin's `--events` help, a clap doc comment the path rewrite had touched; restored). Sources, by a token check: of the 157 `.rs` files changed or moved (the new `telemetry.rs` aside), 148 have the same tokens outside `use` once the moved paths are mapped and their `use` declarations import the same items; the 9 others are the crate roots and declarations, the new test, the ratchet's scanner and `journal_fields`' scan patterns (`nn_model::log_escape::Escaped`); `telemetry.rs` and `wire/mod.rs` are the split rerun on R03's `wire/mod.rs`, byte for byte. `mk-tarball.sh`: the same 72 entries; `mk-packages.sh` (.deb): the same 79 paths and modes, the four binaries' sizes and `CHANGELOG.md` aside.
- **Lab PR 242 — nn-parse: the TLS and DNS parsers leave the agent (Wave
  4 Phase 2, R06 of the restructure plan; no level changes).**
  - What was wrong: the parsers of attacker-written bytes the plan puts
    in nn-parse, the leaf the confined worker will run (R14b), were the
    agent's: the ClientHello parser (`net/tls_parser.rs`, JA3, JA4, SNI,
    ALPN, its cursor Kani-proved) and the DNS reply parser inside
    `net/dns_cache.rs`. nn-parse held the QNAME walk only (R02, lab PR
    240), and the TLS proof ran on the whole agent package with
    `--ignore-global-asm`, a flag kept for a dependency long gone.
  - What changed: `net/tls_parser.rs` → `crates/nn-parse/src/tls.rs`
    (`git mv`, 99 %: its tests, the `crypto_vectors` pin and the Kani
    proof with it; two `x % 2 != 0` became `!x.is_multiple_of(2)`, the
    workspace's clippy, which the agent's SUP-015 exception kept off);
    `dns_cache`'s reply parser (`parse_a_records`, `parse_aaaa_records`,
    `try_parse_answers`, `DnsPacket`, `answer_capacity`), its tests and
    wire helpers cut verbatim into `crates/nn-parse/src/dns_records.rs`
    (checked block by block); nn-parse depends on md-5, sha2 and hex as
    the agent did. Shims in the agent (plan §4.1 rule 2, out in R17): `pub
    use nn_parse::tls as tls_parser` in `net` and the two parsers
    re-exported by `dns_cache`, so `fuzz_api`, the fuzz targets
    `tls_client_hello` and `dns_records` and their seeds are unchanged.
    `kani.yml`: the cursor proof on `-p nn-parse`, path filter
    `crates/nn-parse/src/tls.rs`, no `--ignore-global-asm`;
    `fuzz/README.md` likewise. `module-map.toml`: `net::tls_parser` is
    gone from the agent's modules. Pins first (their own commit, on `main`
    c7bb346): the two `tls_client_hello` seeds → outcome, every field, the
    SNI both ways, ALPN, JA3's input, JA3 (MD5) and JA4, exactly; the
    `dns_records` seeds and regression → the answers and both public
    parsers' results; a hostile corpus of each (every prefix and xorshift
    mutants of the seeds, the reference vectors and the test responses:
    6,559 ClientHello inputs, 1,840 complete, 3,842 incomplete, 877
    invalid; 4,354 DNS inputs, 3,186 refused, 8 empty, 1,160 with
    answers) → those counts and a SHA-256 over every input's rendering in
    order. They live in the test modules that moved, and pass there
    unchanged. Deviations from the plan: the DNS parser is cut, not split
    with appendix A's merge recipe, and moved in the step's one commit
    with its shims (as lab PR 240); the ratchet does not go down — 77
    before and after (nn-core 53, nn-evidence 12, nn-admin 6, nn-linux 3,
    nn-proto 3): the moved code named no module of the agent, so no
    counted reference was its. Open: the shims (R17); nothing calls the
    parsers in production yet (`TLS_FINGERPRINT_PRODUCER` false, no DNS
    response observer), so the agent binary does not contain them.
  - Lab: no guest (moves only; the identity below). Host, on the move commit (the pins' commit: fmt, the agent's clippy with all targets, its `net::` tests): `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked` 68 suites, 2,992 passed, 0 failed (`main` c7bb346 plus the 4 pins; the list, 3,006 tests, is the pins' commit's, the 40 TLS and 8 DNS tests found by name in nn-parse); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo test -p nn-proto --features debug-trigger --lib admin_protocol`; the 19 `crypto_vectors` tests (1 now nn-parse's); `cargo xtask attack-coverage --check`; `cargo xtask golden` with the golden files unchanged; `cargo +1.89.0 check --workspace --all-targets --locked`; `portable-core` locally, the five targets, nn-parse with its new code; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets, seeds and regressions; `Cargo.lock` and `fuzz/Cargo.lock` give nn-parse its three dependencies, unchanged by the build); the xtask guards (ratchet 77, layer gate, path liveness, the Kani scan of `supply_chain`); Kani 0.68.0 locally, `cargo kani -p nn-parse` on the three harnesses without `--ignore-global-asm`: all verified (the cursor in 0.5 s). Identity against `main` c7bb346, same path, the release job's commands: the eBPF object (sha256 60d6bccc…) and its stamp (source c3651dc3…) byte-identical, as `common` is untouched; the scanner byte-identical (401,400 bytes); `mk-tarball.sh` the same 72 entries, `mk-packages.sh` (.deb) the same 79 paths and modes (the sizes of the agent, nn-admin, the watchdog and `CHANGELOG.md` aside). No shipped binary contains the moved parsers (no symbol of them in the unstripped builds). The others: watchdog 2,336,904 → 2,336,872 bytes, nn-admin 3,912,344 → 3,912,712, agent 14,641,912 → 14,642,376; function by function (unstripped, names mapped, addresses dropped) the watchdog differs in 2 of 2,469 (a `TypeId` constant in its async `main`, the `TypeId` comparisons of the log subscriber's `downcast_raw`, reordered by their values), nn-admin in 13 of 3,334 (3 names only in `main`'s build, 4 only in this one), the agent in 27 of 7,413 (4 and 5). Control: `main` archived to another directory and built with the same object is byte-identical to `main` here (all four binaries); the same tree with md-5, sha2 and hex added to nn-parse's manifest, no source changed, gives a watchdog and a scanner byte-identical to this lot's, and 11 functions of nn-admin and 24 of the agent changed as here (`TypeId` constants, which of identical bodies keeps its name, clap's `try_remove_one`). The move itself, from that control to this tree: 2 functions of nn-admin (`RawVecInner::finish_grow`, `RollbackFloor::scan`), 3 of the agent (the same and `do_reserve_and_handle`), and `RawVec<&[u8]>::grow_one` kept out of line in both — the agent crate's `Vec<&[u8]>` growth, which the parser's `alpn_values` shared with `RollbackFloor::scan` (via `chain_lines`) before the move. `.rodata` holds the same text (a few printable bytes of hash constants aside).
- **Lab PR 241 — nn-evidence: the evidence chain leaves the agent (Wave 4
  Phase 2, R04 + R05 of the restructure plan; no level changes).**
  - What was wrong: the signed chains (`chainlog`, `audit`, `chain_anchor`,
    `chain_tail`, `verify_lines`, the canary line reader) named the agent
    all over — its key and key files, its identity, the op of
    `self_integrity`, the BPF guard's mode, its feature set through
    `cfg!`, the payloads of its detection store and drains, the admin
    socket's netflow path, tokio tasks — 12 ratchet references, two of them
    to nn-proto (`MAX_FRAME_BODY`); and they made Linux calls of their own
    (`O_NOFOLLOW | O_NONBLOCK`, file modes, `renameat2` in an `unsafe`
    block, `access(2)`, `pwrite`, `/proc/self/fd` anchoring), while the map
    holds nn-evidence pure (no libc, no `std::os`, five other targets).
  - What changed: R04a, before any change a format pin
    (`agent/tests/chain_format_pin.rs`, fixtures written by `main`
    c7bb346's code: they verify after the move, and this code writes
    their bytes for the same inputs); then, each its commit: identity
    types and the `integrity_drift` op in `audit`, the boot rows' build
    facts by value (`build_info`); the key and its files to `keys`, the
    writers signing through `chain_host::ChainSigner`; the agent's chain
    list and tasks to `chains`; the two `MAX_FRAME_BODY` assertions to
    `admin_socket` (the agent sees both crates: no constant moved, nothing
    parameterised); the Linux calls behind `chain_host::ChainHost`
    (static functions; `chain_host_linux::LinuxHost` holds the same calls;
    the writers reach it through their key type, the readers name it),
    the audit preflight to `audit_preflight`; the chain tests on a
    portable host, the Linux semantics tested on the agent's
    (`chain_host_linux` tests); `pub` across the boundary. R05: `git mv`
    of the seven modules to `crates/nn-evidence` (99-100 %), the agent's
    paths kept as shims in `lib.rs` and `canary/mod.rs` (the writers
    aliased with the agent's key as default; callers, tests, fuzz targets
    and examples unchanged), the ratchet taught `[shims.agent]`. After it:
    `common::execq` to `nn_proto::execq` (lab PR 240's open item; importers
    rewritten, the scanner depends on nn-proto, `common` drops postcard
    and hex); nn-admin's `--events` help names `nn_model::Event`; R04a's
    detection records to `detection_payload` (mapped to nn-evidence, still
    in the agent: `DetectionRecord::from_rule`, `with_attack` and
    `RuleMatchRecord::of` name the engine and stay in `detection_store`);
    the core modules name the integrity op through `audit`; R04b's path
    text of the open sensor to `path_text`. Ratchet 77 → 54: nn-evidence
    12 → 0, nn-core 53 → 40, nn-admin 6 → 8 (`chain verify` builds the
    agent's chain list, which names nn-linux payloads), nn-linux 3,
    nn-proto 3; nn-core passed through 54 when `anchored` was mapped to
    nn-linux (`combat::reconcile` anchors its file through it). Deviations
    from the plan: nn-evidence stays pure, so `anchored` (the Linux
    anchor) stays in the agent and the chains reach the OS through
    `ChainHost`, a seam the plan did not list; the R04a commits that cut
    nothing the move needed (the detection payloads, the integrity op of
    the core modules) come after R05; `audit_ops.rs` and `paths.rs` were
    not made (the op is `audit::INTEGRITY_DRIFT_OP`; `ChainPaths` and its
    built-in paths went to `chains`); not done here, for the next lots:
    R04b's `ProcSource`, `Clock`, `PackageOwnership`, the installer
    window/kernel-sync split and `UnlockToken` (each needs a host handle
    through the rule engine's and the posture's constructors — some sixty
    call sites — or the composition root of R11a, and the posture's and
    ladder's clock a reviewed golden regeneration, which this lot's
    identity rules exclude), `ExecutionOutcome`/`ExecutionReport` to
    `response/outcome.rs`, and R04c's splits (fim/drain, overlay_auth,
    canary/registry, combat/protected+reconcile, net, response); the
    payload types into nn-evidence once their constructors leave the
    types.
  - Lab: no guest (moves and seams that keep every call; the identity below). Host, on R05 (452add6), on the lot's last commit before main's lab PR 242 was merged in (80486b7) and on the merge (f951e2f, 3,003 passed with lab PR 242's tests): `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked` 69 suites, 2,999 passed, 0 failed (the test list is `main`'s — 3,002 names, every one found at the tip — plus 12: the chain format pin's 5 and its ignored generator, the build facts' 2, the Linux host's exclusive create and `rename_noreplace`, the portable foreign-slot case, the payload kinds' pin); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `crypto_vectors` (19) and `encoded_frames_are_pinned`; `cargo xtask attack-coverage --check`; `cargo xtask golden` with the golden files unchanged; `cargo +1.89.0 check --workspace --all-targets --locked`; `portable-core`'s `cargo check` of nn-parse, nn-model, nn-proto, nn-evidence (now code) and nn-core for the five targets; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, 13 targets, seeds and regressions; `fuzz/Cargo.lock` carries nn-evidence, no lockfile changed by the build): all pass. Identity against `main` c7bb346, same path, same commands: the eBPF object is byte-identical (sha256 2cfdde83…) at R05 and the tip, its stamp's source hash c3651dc3… → c0365736… (the execq step: `common`'s sources and manifest). Built as the release job builds (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`): scanner 401,400 → 401,368 bytes, watchdog 2,336,904 → 2,336,920, nn-admin 3,912,344 → 4,006,152, agent 14,642,952 → 14,842,344. Unstripped (same flags, `CARGO_PROFILE_RELEASE_STRIP=none`), function by function — names mapped to their new crates and modules, the key and host type parameters dropped, addresses dropped (instruction addresses, rip displacements, branch targets, the layout-dependent symbol of a data reference), trailing padding dropped: scanner 478 of 479 the same (the postcard decoder of `Vec<execq::HashEntry>`), watchdog 2,242 of 2,244 (tracing-subscriber's `downcast_raw` and `main`'s closure: `TypeId` constants), nn-admin 2,980 of 3,131 (5 and 24 unpaired), agent 6,639 of 6,893 (16 and 40 unpaired; of the 254, 135 in dependencies, 65 nn-evidence's, 47 the agent's — stack frames, registers, inlining at the new boundary, clap's `TypeId`s of the agent's enums —, 4 in the new modules, 3 nn-proto/nn-model). `.text` grows by 2.5 % in the agent and nn-admin: rustc instantiates a generic function in each crate that uses it in a release build, and the copies of the same instantiation went from 509 to 669 in the agent (serde_json's deserializers of the audit row, chrono's formatting, base64's decode, one copy per crate). `.rodata`'s source paths and callsite lines differ only for the moved files (`agent/src/{audit,chain_anchor,chain_tail,chainlog}.rs` → `crates/nn-evidence/src/…`; `keys.rs`, `chains.rs`, `path_text.rs` new) and the lines of the edited ones (main.rs, admin_socket.rs, self_integrity.rs, detection_store.rs, agent_id.rs, open_sensor.rs, the exec policy's and quarantine's records); nn-admin's help text says `nn_model::Event`; the moved modules' tracing target is `nn_evidence::…` (not printed: `with_target(false)`). `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes, the four binaries' sizes, `RULE_POLICY.md` (the help's doc) and `CHANGELOG.md` aside.
- **Lab PR 243 — the golden replay of the posture and the COMBAT ladder
  (Wave 4 Phase 2, before R08; C14, C17, C18; no level changes).**
  - What was wrong: the golden replay (lab PR 228) pinned what the rules
    answer to a stream, not what acts on the answers. The posture state
    machine and the COMBAT ladder had unit tests and no replay of a stream,
    and R08 moves posture, lineage, correlation and decision into nn-core
    (the lot-239 agent: "posture e scala COMBAT non sono ancora
    rigiocate"). They could not be replayed the same way twice: the
    posture read `Instant::now` and `SystemTime::now` where it needed them,
    the trusted-installer window `Instant::now` and `Utc::now` (its end is
    named in the sanction of an own-unit stop), and the ladder's actuator
    is the kernel.
  - What changed: seams, no behaviour change — `posture::clock::Clock`
    (the monotonic now and the wall clock; the host's, `SystemClock`, by
    default) read by `PostureMachine` (`with_clock`) and the window
    (`with_clock`, `current_grant`, which the security-tool detector's
    own-unit sanction now asks); `SystemActuator`'s outcome words in
    functions of their own (`kill_outcome`, `quarantine_text`,
    `soft_block_of`). The replay, `agent/src/posture/golden.rs`
    (`GOLDEN_REPLAY.md` §6): the path `process_event` takes for the
    posture and the ladder, wired as `main.rs` wires them (hooks through a
    slot, the isolation gate, the decay stand-down), on a host of the
    case's own — the replay's clock on the events' clock with `main.rs`'s
    heartbeats (1 s window, 5 s ladder, 60 s decay); a process table
    written as a `/proc` of its own, read by the lineage, the scopes, the
    security-tool detector and the ladder's `SystemProtectedProcs`; a
    `CombatActuator` that carries out the ladder's calls on that table
    (soft block, the tree frozen, moved and killed in a cgroup of its own
    with each member checked by its identity, the quarantine with the
    production denylist, the isolation per family read back; a capture is
    a pid and a start, so a stale one reaches nothing); the real
    `AuditEvidence` over a real `AuditLog` (the writer's timestamp, the
    hashes and the signature over it and the test's pid named after the
    chain verifies); a fixed administrator key whose signed unlock and
    trusted-installer grant `ConnAuth` verifies. Eight cases
    (`agent/tests/golden/posture/`): ransomware corroborated to COMBAT
    (unlocked; jump-ahead NEUTRALIZE; decay to ENGAGED) and alone held at
    ENGAGED, security tools switched off around a signed trusted-installer
    window (the own-unit stop sanctioned, no transition; auditd's
    DefenseImpairment; the window's signed close; a unit drop it
    corroborates to a locked COMBAT), a forking tree killed in its cgroup
    with an attributed child gone and the signed unlock then decay to
    OBSERVING, a stale capture after a failed soft block (INVESTIGATE
    shortened), a member that does not die and ISOLATE retried (IPv6
    unavailable signed as a hole), detect-only, decay ALERTED and ENGAGED
    to OBSERVING. Each case's `path`, `stages` and `signed` are checked,
    and a coverage test requires each of these stories. `cargo xtask golden
    [--update]` runs both replays. Deviations from the plan: `Clock`
    returns the `Instant` the posture holds, not `mono_ns` (§2.3), so no
    timer changes type before R08; no `ProcSource` trait — the process
    source is a `/proc` directory (the existing `proc_root` seam) and the
    `CombatActuator`; the harness is a test module of the agent library,
    as the decision replay, not `agent/tests/replay_golden.rs` (it uses
    crate-private seams); R04b's `PackageOwnership`, the installer
    window/kernel-sync split and the `UnlockToken` verification are not
    done. Found, not changed (a behaviour change is another lot's): the
    signed `combat_stage` rows of a COMBAT the posture reached carry
    `trigger: null` and its INVESTIGATE row names no offender — `main.rs`'s
    entry hook opens the episode (`engage(None, None)`) inside `observe`,
    before `process_event`'s `engage_with`, which then only merges the
    offender and drops the trigger; two process-wide switches
    (`RANSOMWARE_DECISIVE` of the per-rule policy, `KERNEL_MASS_WRITE`)
    keep a case under `combat-without-corroboration` or the LSM mass-write
    mode out of a parallel replay; the audit writer's clock is
    nn-evidence's own (`build_signed_entry`: `Utc::now`), so byte-stable
    signed rows would need a clock there; the lineage's live check
    (`for_host`) reads the host's suspended time, so the replay runs
    `AuthSessionTracker::new`, as the decision replay. Open: the Linux half
    of the kill (pidfds, cgroupfs, nft, iptables) stays with its
    privileged tests; the ladder's worker thread runs inline in the replay
    (what an event sees while a step is queued is not replayed).
  - Lab: no guest (a replay of the agent library and seams that keep every call; no behaviour change: the decision replay's golden files unchanged). Host, on 00f9e15 (the final tree but for this line; the lot's four commits on `main` 70715b2, lab PR 241 merged): `cargo xtask build-ebpf --release` (`common` and the eBPF crates untouched: the stamp's source c0365736…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 69 suites, 3,011 passed, 0 failed, 15 ignored (the lot's 8 tests: the posture replay's 5, the two clock seams', xtask's directory check; no `#[ignore]` test added); `cargo xtask attack-coverage --check`; `cargo xtask golden` (both replays, 9 tests); `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, 13 targets, seeds and regressions; no lockfile changed by the build): all pass. Determinism: 25 separate test processes (20 with the default threads, 5 with `--test-threads=1`) each found the 8 posture golden files byte-identical to the committed ones, each process also replaying every case 3 times on one thread and once on each of 4 threads at once; `cargo xtask golden --update` changed no file; with `CI` set, `--update` and `NN_GOLDEN_UPDATE=1` are refused. No temporary directory is left behind: the first version of the harness kept each replay's host, and its `/proc`, alive through an `Arc` cycle between the posture's hooks and the ladder's gate (416 directories in `/tmp`, removed); the hooks now hold the ladder weakly and `a_replay_leaves_no_directory_behind` holds it. The same gates on 2af276e, before that fix: all pass, 3,010 passed.
- **Lab PR 244 — NN-L-CHAIN-002 completed by a `/tmp` exec processed
  after the egress.** C14 (behavioural detection and correlation); Wave 4
  Phase 2.
  - What was wrong: the exec record of a staged program comes through its
    own ring and pump, so it can reach the engine after the connect it
    preceded in kernel time; the connect was then judged without the
    `TmpExec` precursor, and the exec completed nothing: NN-L-CHAIN-002
    was missed (R001's kill on the exec, no Critical chain verdict). Lab PR
    235 fixed the same race for NN-L-CHAIN-007 and left CHAIN-002 out on
    purpose: the noted egress had no destination port, which CHAIN-002
    needs to leave a lookup at a configured resolver alone (lab PR 224)
    and to hold its port-53 kill (`PORT_53_KILL`).
  - What changed: the egress note keeps the destination address and port
    (`EgressNote::of`: two fixed-size fields; still at most four notes per
    process and 4,096 processes). A staging exec judges the unclaimed
    notes of its process on the kernel timestamps
    (`CorrelationStore::exec_egresses`): the earliest egress at or after
    the exec and within 300 s of it that is neither a lookup at a
    configured resolver nor a package transaction's completes CHAIN-002,
    the verdict naming the egress, its port-53 kill held as in order; the
    exec's start must be known. The claim on a noted egress names the
    two-step chain that made it (`CredRead` for CHAIN-001, `TmpExec` for
    CHAIN-002), and CHAIN-002 now claims in order too: a late two-step
    completion needs an unclaimed egress; CHAIN-007 takes one claimed by
    CHAIN-002 on a late read (the read is the step it lacked) and any on a
    late exec, as lab PR 235 left it. The flow-ledger rule is unchanged: at
    most two chain verdicts per flow, the two-step one first, then
    CHAIN-007. The comments of `chain.rs` and `ancestry.rs` no longer call
    `parent_start_ns` the forking thread's start (the parent's thread-group
    leader's since lab PR 238). Tests: 3 of the store (the note's
    destination, the late exec's candidates, the claim), 7 of the chains
    (the CI ordering with and without the read, the in-order claim, the
    resolver exemption and the port-53 hold, the window, the ordering, the
    package carve-out), 1 of the engine (the late exec's decision with
    R001 and one kill; two chain verdicts for the flow); golden cases
    `chain002-late-exec` and `chain002-late-exec-resolver`, every other
    golden file byte-identical.
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, QEMU for Windows with WHPX), this PR's code (local commit db39770, on `main` 70715b2, before the rebase below) synced, built and installed (`nn-lab.sh sync`, `build`, `install`: the agent and the watchdog active), the installed units then stopped the operator way (`lab_purge_pins`, no LSM program left), and `detection_rules_at_scale_privileged_e2e` (16 tests, NN-L-CHAIN-002 positive and negative and NN-L-CHAIN-004..008 among them) run 10 times as root, single-threaded, with `--include-ignored`: 10 of 10 runs passed, 16 of 16 tests each (47 to 50 s a run); the units put back, the guest powered off. Host, on db39770 and again after the rebase onto `main` 1f70068 (#444: uuid 1.29 in `Cargo.lock` and `fuzz/Cargo.lock`): `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings`; `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 69 suites, 3,014 passed, 0 failed; `cargo xtask attack-coverage --check`; `cargo xtask golden` (the two new golden files, every other one unchanged); `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed): all pass, both times.
- **Lab PR 246 — a network canary trip owns its connection, in any order
  the rings deliver it: no NN-L-CHAIN-003 on the trip's own connection.**
  C14 (behavioural detection and correlation), C07 (endpoint network
  telemetry); Wave 4 Phase 2; no level changes.
  - What was wrong: PR #448's KVM job on Ubuntu 22.04 (job 122036206565)
    failed `network_canary_connect_trips_canary_003_and_kills_the_connector`
    — the second connect to the canary drew NN-L-CANARY-003 and then
    NN-L-CHAIN-003 on its own connection, `tcp 127.0.0.1:0 closed`: two
    Critical verdicts for one connect. The connect and the close come on
    two rings, read by two tasks. The refused loopback connect closed
    within microseconds; the net drain read the close first and the flow
    tracker, with no pending connect, synthesised the row starting at the
    close, with the destination the kernel had left (port 0); the connect
    pump then put the connect on the bus before the drain sent that row.
    The detector made the connect the trip and remembered (pid, connect
    time), the row carried (pid, close time), `Detector::owns_trip_flow`
    did not own it, and CHAIN-003 — its precursor just recorded — judged
    it as an egress after the trip. Neither multi-match (lab PR 236) nor
    the late chains (lab PRs 235, 244) were involved. Forced in a unit
    test on `main`, the order gives exactly the CI verdict; a credential
    read processed late also completed NN-L-CHAIN-001 with the trip's
    connection, and on `main` with lab PR 244 a staging exec processed
    late completed NN-L-CHAIN-002 with it.
  - Decision (founder-delegated): the trip owns its connection. A network
    trip is the connect, NN-L-CANARY-003 answers it, and NN-L-CHAIN-003
    ("a canary trip, then an egress of the same process") on that
    connection counts one access twice; the test's expectation stands
    (design §5.4, lab PR 163). Any other flow of the process is still
    CHAIN-003.
  - What changed: a synthesised close starts at its connect, the time the
    kernel correlator carries (`FlowTracker::corr_start_ns`), so every
    row of a flow carries (pid, connect time); the connect pump announces
    a connect once its events are on the bus and the net drain holds a TCP
    close until then (`close_may_proceed`), at most `CONNECT_WAIT` (500
    ms) from the connect's time — a close of an older connect waits for
    nothing, nothing waits without a connect pump — so the trip is decided
    first and a refused connect's row keeps its real port, image and DNS
    name; the engine's flow ledger owns the connection from the trip on
    (`FlowLedger::claim_for_trip`, `RuleEngine::owned_by_trip`, used by
    `decide` and by `main.rs` before the posture), past the close (a
    connect-time row following it under a full bus drew the chain too),
    4,096 trips at most — the detector's 256-entry queue, which forgot a
    trip at its first close row, is removed; and CHAIN-003's trip drops
    the egress note its connection left when the close was judged first
    (`CorrelationStore::drop_trip_egress`), so no late read or exec
    completes NN-L-CHAIN-001, -002 or -007 with it. Tests: the agent's
    path over the tracker (close or connect first) and five bus orders,
    each followed by a late read, a late staging exec and a later egress
    (four mutations of the fix each fail it), plus the tracker, drain,
    pump, ledger and store units; golden cases
    `canary003-trip-owns-its-connection`, `canary003-close-before-the-trip`,
    `canary003-close-before-the-trip-late-exec` (on `main` they show
    CHAIN-003 on the close and the connect-time row, CHAIN-001 and
    CHAIN-002 completed late with the trip's connection), every other
    golden file byte-identical. Not done: a close still judged before its
    trip (its connect lost, or later than the wait) is judged as any flow,
    as lab PR 163 left it; an in-order chain whose precursor the process
    already held answers it.
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, QEMU for Windows with WHPX, 4 vCPU), each tree synced, built and installed (`nn-lab.sh sync`, `build`, `install`), the installed units then stopped the operator way (`lab_purge_pins`, no LSM program left), and `canary_privileged_e2e` (7 tests, the network canary test among them) run as root, single-threaded, with `--include-ignored`: `main` 1f70068 30 of 30 runs passed (the CI reorder not reproduced in the lab: no run drew NN-L-CHAIN-003 on a trip's connection); this fix on 1f70068 (local commit 8f8d48c) 40 of 40; rebased on `main` 2a44301 (lab PR 244; local commit 2e45dac, this commit's code) 30 of 30; 24 to 27 s a run before and after; the units put back, the guest powered off. The CI order forced in a unit test on `main` 1f70068 (temporary, not committed): the synthesised close (`127.0.0.1:0`, starting 40 µs after the connect) drew NN-L-CHAIN-003 after NN-L-CANARY-003, and a credential read processed late completed NN-L-CHAIN-001 with the trip's connection. Host, on 8f8d48c and again on 2e45dac: `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings`; `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 69 suites, 3,009 and 3,020 passed, 0 failed; `cargo xtask attack-coverage --check`; `cargo xtask golden` (the three new golden files, every other one unchanged); `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed): all pass, both times.
- **Lab PR 245 — the signed COMBAT rows say why the ladder engaged and
  against whom.** C17 (response on processes and files); Wave 4 Phase 2;
  no level changes.
  - What was wrong (found by the golden replay of lab PR 243): the signed
    `combat_stage` rows of every COMBAT the posture reached carried
    `"trigger": null`, and the INVESTIGATE row named no offender
    (`"offenders": []`); the `combat_outcome` rows too said `"trigger":
    null`. The posture's entry hook took no argument: `main.rs` opened the
    ladder's episode from it (`engage(None, None)`) inside
    `PostureMachine::observe`, before `process_event` passed the offender
    and the firing trigger to `engage_with`, which, the episode open, only
    merged the offender (a soft block) and dropped the trigger.
  - What changed (structural, no hook order or timing): the entry hook
    receives a `CombatEntry` (`posture/entry.rs`), built in `observe` where
    the posture decides — the cause, `CombatCause::Trigger`: the firing
    trigger, every trigger the event raised, its kind of evidence, decisive
    or a heuristic with the earlier signals of the actor's scope that
    corroborated it (`CorroborationLedger::corroborating`, read before this
    round's signals are recorded), locked or not, the scope, the event's
    kind, process and time; or a forced COMBAT, `AdminForce` with the
    signing keys' fingerprints (`admin_force_state_signed_by`, used by the
    admin socket) or `DebugForce` — and the process the event names
    (external audit EBPF-001's "never init" moved there from `main.rs`).
    The ladder has one entry point, `CombatLadder::engage(&CombatEntry,
    now)`: `engage_with` and `process_event`'s second call are gone. The
    episode holds its cause, never replaced, and each offender with what
    identified it when it was attributed (`combat::offender::OffenderId`:
    pid, `start_ticks`, `start_ns`, `seen_ns`, `exe` and `cgroup` read from
    `/proc` by the actuator while the capture still names the process —
    `CombatActuator::describe`, `actuator::read_proc_facts`, detect-only
    included — a path at most 512 bytes, its end kept; `via`: `entry`,
    `spread` with its parent, `later_entry`). Every `combat_stage` row
    names the trigger and carries `cause` and `offender_details` (in the
    order of `offenders`); the `combat_outcome` rows name the trigger; a
    later COMBAT entry naming another process during an episode adds it
    with a signed row of its own (from and to the current stage, `added`:
    that process and the later entry's cause, its soft block in the
    reason), the episode's trigger and cause unchanged; the ERROR line of a
    transition the audit log refused carries the cause and the identities
    too. Readers checked: `nn-admin audit read` (the human view unchanged;
    `--json`, the export, is the log's bytes for both shapes), `audit
    verify` and `chain verify` (the rows' own bytes), `nn-admin status`
    (the stage only, unchanged), the posture golden, the operator docs
    (`COMBAT_RECOVERY.md` §3.4, `UPGRADE_NOTES_WAVE4.md` §3), the chain
    pins of lab PR 241 (the v1 fixtures untouched and verified; they hold
    no COMBAT row, the posture golden pins those bytes). Rows written
    before keep their bytes and their `null`s. Tests: the posture's entry
    (trigger, offender, never init; a heuristic's corroborating signal; a
    forced COMBAT's signers), the ledger's corroborating signals, the
    identity's rendering and the `/proc` reader, and through the ladder: a
    COMBAT reached through the posture names its trigger and offender from
    INVESTIGATE on, the same entry again adds nothing; two offenders in one
    episode keep the first trigger in every row, outcomes included, the
    addition signed; `--detect-only` with the production actuator and a
    real process: the rows name the trigger and the offender (its real
    executable and cgroup), nothing is blocked, killed or quarantined; both
    row shapes read, exported and verified in one chain; every ladder row
    of every posture golden case names its trigger and offender
    (`every_ladder_row_names_its_trigger_and_offender`). Golden: the six
    cases that reach COMBAT moved, and only with this (the decision golden
    unchanged) — the capture of the offender before `begin episode`; the
    trigger, `cause` and `offender_details` in the rows (a spread child with
    its parent); `detect-only`'s INVESTIGATE reason with the offender's
    soft egress note; in `combat-stale-capture` the failed soft block,
    which had a row of its own, is in the INVESTIGATE row with the
    shortened window, the two rows after it one place earlier in the chain.
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, QEMU for Windows with WHPX, 4 vCPU, 7 GiB), this PR's code (local commit 7c6c981, on `main` 9de1923) synced, built and installed (`nn-lab.sh sync`, `build`, `install`: the agent and the watchdog active). `nn-lab.sh test-ignored`: the five runs exit 0, 74 suites, 84 passed, 0 failed (the privileged suites' COMBATs forced by `debug force-posture` wrote 6 rows to the installed agent's audit log: `cause` `debug_force_posture`, no offender, `trigger` null, as a forced COMBAT's is). Then, the units put back (`install`), a real COMBAT driven with the benign lab simulator (`deploy/lab/cow/ransom-sim.py --tripwire --hold 60`, root, in a unit of its own, `nn-lab245-sim`, on a 12-file tree under `/srv/nn-cow-lab245`): its append-open of `/etc/northnarrow/admin.pub` refused by the anti-tamper hook (EPERM) — AntiTamperDenial, decisive, COMBAT locked — and its child the jump-ahead to NEUTRALIZE. The agent's signed rows (seq 3929–3931): INVESTIGATE `trigger` AntiTamperDenial, `offenders` [18385], `offender_details` [pid 18385, `exe` `/usr/bin/python3.12`, `cgroup` `/system.slice/nn-lab245-sim.service`, `start_ticks`, `seen_ns`, `via` `entry`], `cause` `posture_trigger` (Kernel, Decisive, locked, `workload /system.slice/nn-lab245-sim.service`, FsProtectDenial of 18385 at its kernel time); NEUTRALIZE the same trigger and cause, `offenders` [18385, 18391], the child `/usr/bin/true` `spread` from 18385 in `/northnarrow.slice/blocked.scope` (born after the soft block took) with its exec's `start_ns`; the `combat_outcome` row `trigger` AntiTamperDenial (both contained, the system binary not quarantined). `nn-admin audit verify`: 3,933 entries, chain intact; `audit read --json` byte-identical to the log, and verified; the signed unlock released COMBAT (ALERTED, both families read back clear). The same audit log holds 110 `combat_stage` rows written by earlier builds (2026-10-20 to 10-22 lab runs): every one `"trigger": null`, and 47 of 47 INVESTIGATE rows `"offenders": []`. The guest powered off. Host, on 7c6c981: `cargo xtask build-ebpf --release` (the eBPF crates untouched); the four clippy runs with `-D warnings`; `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 69 suites, 3,044 passed, 0 failed, 15 ignored (no `#[ignore]` test added); `cargo xtask attack-coverage --check`; `cargo xtask golden`; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed): all pass. The same gates on the first tree of the lot (2687147) found the module ratchet one above its ceiling (nn-core 41 > 40: the new `combat/offender.rs` named `response`); the `/proc` reader moved to the actuator and the module holds data only. Mutation checks (temporary): the hook handed an entry without cause or offender fails 8 tests (the ladder's posture COMBAT and detect-only, the posture's entry and heuristic, four golden checks); a later entry overwriting the cause, an addition not signed, the identity not read from `/proc` each fail the test written for it.
- **Lab PR 247 — nn-core, part 1: the content lists leave the agent (Wave
  4 Phase 2, R07 of the restructure plan; no level changes).**
  - What was wrong: nn-core, the pure core of the layout (no OS call, built
    for five other targets by `portable-core`), was empty; R07 moves the
    content into it — the lists, their loaders and overlays, the canary
    templates, the COMBAT carve-out (plan §2.4). That content made Linux
    calls of its own: `read_overlay` (an operator overlay, a shipped `.v1`
    list) and the canary renderer's `read_template` opened their file with
    `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and turned an `ELOOP` into "a
    symbolic link (not read through one)"; the renderer drew the deploy's
    seed from the OS RNG (`os_rng`, nn-linux); `overlay_auth` held the
    loaders' types, the boot gate and the install (atomic replace, inode
    protection) together; the blocklist's `net status` report read the
    resolver's configuration (`net::blind_spots`). Ratchet: 54, nn-core
    40, five of them references of R07's modules.
  - What changed, one commit each: the seam —
    `nn_core::content_host::ContentHost` (the open that follows no final
    symlink and blocks on no FIFO, and how it refuses a symlink; static
    functions, as `ChainHost`), implemented for the agent's `LinuxHost` by
    `content_host_linux` with the same flags, `read_overlay` and the
    renderer's read generic over it; the tests that need Linux or the
    agent's other lists leave the files that move, verbatim (the Linux
    refusals to `content_host_linux`, every family's shipped list against
    `install.sh` to `config`, the OS seeds to `canary`); `overlay_auth`'s
    install half (`store`, `inode_key`) to `config::overlay_install`
    (nn-linux, R04c); the overlay check names the exec profile in
    `execpol::policy`, where it is defined; the inactive-rules report to
    `net::blind_spots`. Then the moves to crates/nn-core, the agent's
    module paths kept (`nn_core::config::overlay`, …):
    `anti_tamper/combat_allow.rs` (`git mv`, 99 %), the part of
    `overlay_auth` the loaders take (`Verified`, `content_sha256`,
    `read_overlay`, `ALLOW_UNSIGNED_ENV`, `MAX_OVERLAY_BYTES`, cut
    verbatim), `config/overlay.rs` (96 %: its three reading loaders and
    `load_defaults_with` take the host), `fim/paths_config.rs` (94 %),
    `canary/templates.rs` (98 %: `render` takes the host,
    `new_content_seed` stays in the agent). The agent keeps every path as
    a shim (plan §4.1 rule 2, removed in R17) in the parent's `mod.rs`: a
    `pub use` of nn-core's module and, for a loader that reads a file, the
    function under its name and signature bound to `LinuxHost`
    (`config::overlay::{load_defaults, load_pinned_defaults,
    load_flat_list}`, `fim::paths_config::load_watched_paths`,
    `canary::templates::render`); `overlay_auth` re-exports its moved
    part. Callers, tests, `fuzz_api` and the fuzz targets `canary_template`
    and `combat_allow` are unchanged; the moved tests run in nn-core on a
    portable test host. nn-core depends on sha2, anyhow, tracing, hex,
    base64, serde_json (`float_roundtrip`) and thiserror at the agent's
    versions; the lockfiles gain nn-core's edges, nothing else. Ratchet
    54 → 52, nn-core 40 → 43 (the seam: the content code names the Linux
    host where it called libc, which the scan does not see) → 42 (install)
    → 41 (exec profile) → 40 (inactive rules) → 40 (the moved loader no
    longer names the host; `config/mod.rs`, which binds it, does) → 38
    (the renderer and its RNG); nn-admin 8, nn-linux 3, nn-proto 3,
    nn-evidence 0. Deviations from the plan: not moved —
    `config::comm_allowlist` and `canary::readers` judge on
    `posture::lineage` (`AuthSessionTracker`, `ExecIdentity`,
    `in_system_tree`), and the allowlist holds a kill through
    `decision::response_policy`: R08's, as posture and the engine, which
    this lot leaves untouched (lab PR 245 changed them meanwhile; `main`
    with it is merged into this branch);
    `posture::{escalation_allow, mass_write_overlay}` sit in `posture/`
    (R08a); `net::blocklist`'s loaders are associated functions of the
    list types that the decision replay (`decision/replay.rs`, R08b) calls
    without a host — in nn-core the `.v1` read needs it as a type
    parameter, so they move with that caller; the gate (`OverlayGate`)
    verifies through `anti_tamper::admin_auth`, which the map sends to
    nn-proto once R04b cuts its UnlockToken and key loading, and writes
    the agent's audit log, and `overlay_floor` reads the agent's signing
    key (`keys`, nn-linux) and is the gate's: by §4.1 rule 3 they move
    when those are below nn-core. `new_content_seed` stays in the agent:
    the OS RNG is nn-linux's. `combat_allow` still reads its file with
    `std::fs` at each engage: a portable read, no seam (nn-evidence's
    rule). No separate move and rewrite commits and no
    `.git-blame-ignore-revs`: no importer was rewritten; the moved files'
    own lines changed for the host parameter, their tests' host and doc
    links to the agent (94–99 % similar); `overlay_auth`'s part is cut, not
    split with appendix A's recipe. Found: the eBPF object carries the
    build directory in its debug information (`/home/…/agent-ebpf/src/…`),
    so its bytes are a function of the checkout's path; the identity below
    builds `main` and this lot in the same directory. Open: the five
    modules above (R08, R04b/R09a); the shims (R17).
  - Lab: no guest (moves and seams that keep every call; the identity below). Host, on 0e7802b (the lot's code; the commit after it changes documentation only), on 0df3394 (the lot's last commit before `main`'s lab PR 245 was merged in) and on the merge (b4f2467, 3,044 passed with lab PR 245's tests, the posture golden files as lab PR 245 left them): `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 69 suites, 3,028 passed, 0 failed, 15 ignored (the test list is `main`'s: 3,043 names, every one found at the tip — 44 now nn-core's, 9 moved within the agent — and no test added); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` (both replays, golden files unchanged); `cargo +1.89.0 check --workspace --all-targets --locked`; `portable-core`'s `cargo check` of nn-parse, nn-model, nn-proto, nn-evidence and nn-core (now code) for the five targets; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, 13 targets, seeds and regressions; no lockfile changed by the build): all pass. The pins pass unchanged: `encoded_frames_are_pinned`, `chain_format_pin`, `crypto_vectors`, the TLS and DNS parser pins, and the overlay-v1 fixture of lab PR 230 (`an_overlay_signed_before_the_bump_is_accepted`, `the_stored_overlay_signature_is_pinned`). Identity against `main` 9de1923, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 42afd5b6… there; a clean rebuild of `main`'s, `agent-ebpf/target` removed, gives the same bytes), its stamp too (source c0365736…, `main`'s: `common` and the eBPF crates are untouched); the scanner (401,368 bytes) and the watchdog (2,336,920) are byte-identical, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes, the agent's and nn-admin's sizes, `CHANGELOG.md` and the two documents whose path mentions changed (`COMBAT_RECOVERY.md`, `install.sh`'s comment) aside. The agent (14,863,200 → 14,876,736 bytes) and nn-admin (4,022,024 → 4,029,320) are not byte-identical. Function by function (unstripped, names mapped to the new crates and modules, the host type parameter dropped, addresses and rip-relative targets dropped, trailing padding dropped): the agent 7,555 of 7,614 the same code (53 differ, 6 and 26 unpaired), nn-admin 3,441 of 3,463 (19; 3 and 20). Control — `main` with the agent depending on nn-core and nn-core on its new dependencies, no source moved: 14 of the agent's and 6 of nn-admin's change already (clap's `TypeId`s of the agent's enums: the agent crate's identity moves with its dependency list; which of identical bodies keeps its name). From the control to this lot: 41 of the agent's (19 only call a body LLVM folded under another name, the shared `RawVec::grow_one` among them; 22 differ in inlining at the new crate boundary, register allocation and stack frames, and an argument constant propagated into a callee: the moved loaders and parsers, their callers — the gate, the network isolator, the canary deploy, the COW and rule-policy boots —, nn-evidence's writers over the agent's key) and 13 of nn-admin's; the unpaired are generic code made a second time in nn-core (anyhow's message errors, `RawVec` growth, hex and base64 encoding, line iteration: `.text` +10,000 bytes in the agent, +0.14 %, +4,368 in nn-admin) and helpers kept out of line. `.rodata`: every text constant of one build is in the other's but the moved files' paths (panic locations, callsite files) and the callsite line numbers of the moved and edited files; the moved modules' tracing target is `nn_core::…` (not printed: `with_target(false)`).
- **Lab PR 248 — lab and validation tooling: `nn-lab.sh ssh`'s stdin,
  the whpx stop, the perf gate's MemTotal.** Tooling only (no capability,
  no level changes, no product change); Wave 4 Phase 2.
  - What was wrong: under whpx `vm_running` is an ssh probe (`ssh … true`)
    and ssh hands its stdin to the remote command, so `nn-lab.sh ssh …
    bash -s` with the script on stdin (a here-doc, a pipe, `< file`) had
    it eaten by the probe and ran an empty one, exit 0 (lab PR 245 sent its
    COMBAT drive as a base64 argument instead); a Windows program run
    through WSL interop reads the caller's stdin the same way. A whpx guest
    powered off from inside (the lab host's stop helper: a KVM procedure,
    its wait on a QEMU pid file and its unit stop do nothing under whpx)
    took QEMU for Windows down a few seconds later, but its ssh forwarder,
    a user unit of its own (`nn-fwd-<guest>`) that only `down` stops, kept
    listening on 127.0.0.1, while `status` said "stopped"; `down` itself
    said "stopped" without checking (a failed taskkill or `systemctl
    --user stop`, or no answer from tasklist.exe, went unseen). `cargo
    xtask perf-compare` compared the host fields for equality, MemTotal
    included, which moves by a few KiB between boots of one guest
    (8,131,760 and 8,131,764 KiB): exit 2, "host mismatch", every time.
  - What changed: the probes (`guest_probe`, the wait for ssh's
    provisioning check, `trust-host-key`'s strict connection) and every
    Windows program (`win`) read `/dev/null`; the real session keeps the
    caller's stdin. Under whpx (the block `whpx-stop`) the QEMU check tells
    "not running" from "no answer from tasklist.exe"; `down` still powers
    the guest off from inside, waits for QEMU (forced after two minutes)
    and stops the forwarder, then checks both and, if either is left, names
    it and exits 1; `status` says "stopped, but its forwarder … is still
    active on 127.0.0.1:<port>: `nn-lab.sh down` stops it". The perf gate
    takes a MemTotal within ±0.1 % of the base's, or ±1 MiB when that is
    more, for the same host and notes the drift; any other host field, or
    a larger MemTotal change, is still another host (exit 2 without
    `--allow-host-mismatch`). Tests: `xtask/tests/lab_host_safety.rs`
    `nn_lab_ssh_hands_the_callers_stdin_to_the_guest` (the real script
    under whpx and kvm, an ssh stub with OpenSSH's stdin semantics: a
    here-doc, a pipe and a file run, the probe reads 0 bytes) and
    `whpx_down_stops_qemu_and_the_forwarder_and_says_what_is_left` (the
    block with Windows, systemd and sshd stubs: the helper's leftover
    state, a running guest, a QEMU that hangs at power-down, and a QEMU,
    a forwarder, a user session or tasklist.exe that does not answer;
    nothing reads the caller's stdin); `perf_compare`'s
    `a_memtotal_drift_between_boots_is_the_same_host` and
    `a_real_host_change_is_still_another_host` (the bounds either way, the
    1 MiB floor, CPU model and count, kernel, a 6 GiB guest, a MemTotal
    not recorded, virtualisation, clocksource); `perf_baseline.rs`
    `a_memtotal_drift_between_boots_is_the_same_host` (exit 0 with the
    note, exit 2 for a smaller guest). Each test fails with its fix taken
    back (the probe's or `win`'s `/dev/null`, `down`'s check, `status`'s
    forwarder, the MemTotal drift and its bounds). Outside the repository,
    the lab host's stop helper now ends with `nn-lab.sh down`.
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, QEMU for Windows with WHPX, 4 vCPU; no other guest up). Before (`main` 60d9965, the branch's first base, and 8180540 on a second boot): `nn-lab.sh ssh bash -s` with the script in a here-doc, a pipe and `< file` printed nothing, exit 0, each time. The lab host's stop helper as it was (a poweroff from inside, its wait on a QEMU pid file and its unit stop): the guest reached `reboot: Power down`, QEMU for Windows was gone a few seconds later, the forwarder `nn-fwd-ubuntu2204` still active and listening on 127.0.0.1:2522 three and a half minutes later, and `status` said "stopped". After (this branch): in that state `status` names the forwarder ("stopped, but its forwarder nn-fwd-ubuntu2204 is still active on 127.0.0.1:2522 …") and `down` stops it (exit 0, 5 s; then `status` "stopped", no `nn-*` user unit, nothing listening on 2522). On a new boot the three scripts ran (here-doc, pipe and file, each printing the guest's hostname and kernel, exit 0), and a command as an argument as before; the helper, now ending with `nn-lab.sh down`, with this branch's script: exit 0 in 5 s, `status` "stopped", no `nn-*` unit, `tasklist.exe` listing no QEMU, nothing on 2522; on a third boot the same with the helper's default tree (the lab's main checkout, `main` 8180540's `down`): exit 0 in 5 s, nothing left. This branch's `up` (QEMU launched, the forwarder started, the probes with `/dev/null`) booted the guest in 24 s and passed `check`; a piped script ran; `down` on the running guest: exit 0 in 5 s, nothing left. Host, on the lot's commit over `main` 60d9965 and again after its rebase over lab PR 247 (`main` cedf7e1): `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 69 suites, 3,049 passed, 0 failed, 15 ignored, both times; `bash -n` on `nn-lab.sh` and the helper; shellcheck 0.9.0 (`-x`, warnings): the same two SC2054 on QEMU's comma-separated arguments as on `main`, nothing new (every finding of any severity the same set as on `main`), the helper clean.
- **Lab PR 249 — determinism seams: the signed chains' clock and the
  posture's switches per machine (Wave 4 Phase 2, before R08; C14, C17,
  C23; no level changes).**
  - What was wrong (found by lab PR 243): the chain writers of nn-evidence
    read `Utc::now` where they stamped a row (an audit row's `ts` in
    `build_signed_entry`, a rotating log's terminators and manifest rows,
    the head anchor's snapshots), and the hash covers the time, the
    signature the hash: the posture golden could not print its signed rows
    and named their time, hashes, signature and the test's pid (`@TS@`,
    `#n`, `@SIG@`, `@AGENT_PID@`); the chain pin of lab PR 241 could only
    verify those rows, not make them again. Two posture switches were
    process-wide — the runtime value of
    `RANSOMWARE_COMBAT_WITHOUT_CORROBORATION` (`RANSOMWARE_DECISIVE`, set
    by `rule_policy::install_global`) and `KERNEL_MASS_WRITE` (set by
    `main.rs` when the LSM file-open sensor is armed) — so a case or test
    that needed another value raced every other one.
  - What changed (seams, no behaviour change): `nn_evidence::clock`
    (`Clock`, `SystemClock` = `Utc::now`, `stamp`); every row stamp of the
    crate reads it — `AuditLog::open_with` and `AuditStamps` (the clock and
    the pid of the rows the writer signs about itself, `AuditLog::self_pid`,
    which the ladder's rows and the trusted-installer window's close row now
    read), `RotatingChainLog::open_with_clock`, `Anchor::with_clock`;
    `open` and `new` keep the host's clock and `std::process::id()`. The
    agent's `AuditEvidence::with_clock` stamps `occurred_at` of a late row.
    The posture reads the ransomware directive from the policy handle it is
    given (`PostureMachine::with_rule_policy`; `main.rs` passes
    `rule_policy::global()`, the handle the engine reads and `nn-admin
    policy set` swaps — read once per round; `TriggerType::confidence`
    takes the value), and the mass-write mode is the trigger detector's
    own (`PostureMachine::set_kernel_mass_write`, called by
    `start_open_sensor` where the global was set); the global setters and
    readers are gone. The posture golden opens its audit log with a fixed
    key, its clock and the replayed agent's pid (4,200,000) and prints the
    rows whole; a case's `rule_policy` lines are its machine's policy. New
    case `ransomware-alone-combat-policy`: under `combat-without-corroboration
    NN-L-IMP-001`, ransomware alone — decisive, nothing in its scope before
    — reaches COMBAT, unlocked; INVESTIGATE, NEUTRALIZE of the tree,
    contained; decay to ENGAGED. Golden diff: the six files that hold signed
    rows, and in their 25 rows only the named fields became values (checked
    by a script: each `ts` the line's time on the replay's wall clock,
    `prev_hash` chaining from 64 zeros, `client_pid` 4,200,000, every other
    byte of every line the same); the decision golden and the two other
    posture files unchanged. Proof that the format did not change: the v1
    fixtures of lab PR 241 made again, every file, byte for byte, by this
    code given `main`'s times through a scripted clock
    (`agent/tests/chain_format_clock.rs`: `audit.log`, and the whole
    rotating set with its three terminators, `Rotated` rows and checkpoint;
    `chain_format_pin.rs` and the fixtures untouched); the crypto vectors of
    lab PR 230 unchanged and passing. Other process-wide state read by the
    posture, impact or the engine, listed: NN-L-FIM-010's
    one-verdict-per-rename list (`FIM010_RECENT`, the engine's) — converted,
    the rule's own (one engine in the agent, so the same list; two replays
    or tests in one process shared it); kept, not switches or not trivial:
    `rule_policy::global()` (the agent's one policy handle, which the
    engine and now the posture are given), the per-process random keys of
    the DNS qname hash (`QNAME_HASH_KEYS`, NETR-012), the agent's own pid
    read by the control-surface trigger (`std::process::id()`; the dev
    build's machine has no agent pid to read instead) and as the default of
    the fan-out rules' and NN-L-FIM-024's per-instance `agent_pid`, the
    quarantine's boot-time `RUNTIME_DENY`, the impact sampler's
    `/proc/1/root` probe (`response::host_path`), the status counters
    (`impact`/`impair` `PUBLISHED`, `detection_budget::BUDGET`, eviction and
    verdict counters), the clock-tick constants; `response_policy`'s held
    switches are constants and its `HELD` per thread.
  - Lab: no guest (seams that keep every production call: `AuditLog::open`, `RotatingChainLog::open`, `Anchor::new` and `AuditEvidence::new` take the host's clock and pid as before; the switches are filled from the same places with the same defaults). Host, on afcf8ed (the final tree but for this line and a rewrapped paragraph; on `main` 60d9965, lab PR 245 merged), `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (`common` and the eBPF crates untouched: the stamp's source c0365736…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,058 passed, 0 failed, 15 ignored (the lot's 14 tests: the clock's 2, the audit log's 2, the rotating log's 2, the head anchor's, `chain_format_clock`'s 2, the posture machine's directive, the detector's mass-write mode, NN-L-FIM-010's list, the late ladder row's clock and pid, the golden's parallel policy replay; no `#[ignore]` test added); `cargo xtask attack-coverage --check`; `cargo xtask golden` ten times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed); `portable-core`'s check of the pure crates for its five targets: all pass. The crypto vectors (19 tests, `cargo test crypto_vectors`) and `chain_format_pin.rs` pass with their fixtures untouched. The first commit's tree alone (the clock seam): clippy on the workspace, nn-evidence's tests, both chain pins, the posture, COMBAT and window tests pass. Golden review: a script put the named fields of the 25 new rows back to their placeholders and found every line of the six files equal to the committed one (JSON equality), each `ts` its line's time on the replay's wall clock, `prev_hash` chaining from 64 zeros, `client_pid` 4,200,000. Mutation checks (temporary): the audit row's time not read from the log's clock fails 6 tests (the fixed chain written twice, the v1 audit log made again, the late ladder row, three golden checks); the manifest rows' 2 (the rotating set written twice, the v1 set made again), the terminators' and the head snapshot's 1 each; the posture ignoring its policy handle 5 (the directive per machine, four golden checks); the detector ignoring its switch 1; the ladder rows stamped with the test's pid 8 (the late row, seven golden checks); `occurred_at` on the host's clock 1; NN-L-FIM-010's list shared again 1. The first gate run of the final tree compiled a stale nn-model and failed: the two commits were split by restoring files with `cp -a`, which kept mtimes older than the first commit's build, so cargo saw nothing to rebuild; the files touched, the gates above ran on a fresh build. Rebased on `main` cedf7e1 (lab PR 247 merged; only the lot notes conflicted, both kept), the same gates on 321fb3c: all pass, 70 suites, 3,058 passed, 0 failed, 15 ignored, the ten golden runs identical; on GitHub (c34cdd9, pull request #453) the 13 checks pass, both KVM suites included. Merged with `main` a99aff9 (lab PR 248; again only the lot notes conflicted, both kept), the same gates on c093eeb: all pass, 70 suites, 3,063 passed (lab PR 248's tests with them), 0 failed, 15 ignored, the ten golden runs identical.
- **Lab PR 250 — nn-core, part 2a: the posture, its lineage, the
  correlation buffer and the detection budget leave the agent (Wave 4
  Phase 2, R08a of the restructure plan; no level changes).**
  - What was wrong: nn-core, the pure core (no OS call, no tokio,
    `forbid(unsafe_code)`, built for five other targets), held the content
    lists only (R07, lab PR 247). R08a moves the posture's logic into it,
    and that logic read its host itself: the process table
    (`/proc/<pid>/{stat,status,exe,cgroup,loginuid,cmdline,mountinfo,
    ns/mnt}` — the lineage's hops, the sessions' login uid and terminal,
    the cgroups) and the host's `/etc/subuid`, `/etc/passwd` and the
    owners of container storage through `std::fs` and `MetadataExt::uid`,
    and three clocks through libc in `unsafe` blocks (the time suspended,
    `CLOCK_BOOTTIME` − `CLOCK_MONOTONIC`, which `for_host`'s live checks
    read; `CLOCK_MONOTONIC`; `sysconf(_SC_CLK_TCK)`). It also named the
    agent's other modules: the rule engine's shapes the triggers share
    with the rules (NN-L-FIM-024's bait tamper, NN-L-EPG-001/002's event,
    R020's reverse-shell shape, the staging directories), the engine's
    per-rule policy handle, the trusted-installer window and the unlock
    token (`anti_tamper`), the ransomware and security-tool judges
    (`impact`, `impair`). The detection budget held a tokio reporter task
    over the agent's audit log and detection sink. Ratchet 52, nn-core 38,
    three of them R08a's (`posture/mod.rs` and `posture/triggers.rs` →
    `anti_tamper`, `detection_budget` → `detection_store`).
  - What changed, one commit each: the open sensor's path text
    (`path_text`, nn-model's by the map since lab PR 241) to nn-model
    first, as the lineage and the triggers read it (§4.1 rule 3); the
    correlation buffer to nn-core (98 %); the budget's reporter task cut
    verbatim into the agent's `detection_report` (it takes the counts
    through `detection_budget::take_held`, new), then the budget (100 %:
    the rule catalogue cites one of its tests for NN-L-EVA-002, so the
    citation and `RULE_CATALOGUE.md` follow, one line); the ledger, the
    state and the transitions (99–100 %); the two operator overlays
    `escalation_allow` and `mass_write_overlay` (99 %, R07's leftovers).
    Then the first seam, `nn_core::posture::host::PostureHost`: the
    process table's root and the host's, the file reads (generic over the
    path as `std::fs` is, so each call passes what it passed), a
    directory's owner, the three clocks — static functions, as `ChainHost`
    and `ContentHost` —, implemented for the agent's `LinuxHost` by
    `posture_host_linux` with the same calls (three tests of what is Linux
    about it: `lstat`'s owner, `/proc`, the kernel's clocks); the lineage
    and the exemption reading through it; then their move (99 %, 90 %) as
    generics over the host, and the canary readers after them (92 %: they
    judge on the lineage and name nothing of the engine). Then the second
    seam, `PostureAgent` on top of it: the four shapes and the three
    judges as static functions, the rule policy, the window, the two
    judges and the unlock token as associated types (the machine stores
    them, hands the token to its release hook and never makes one),
    implemented for `LinuxHost` with the calls the triggers and the
    machine made; then the move of the machine (93 %), the triggers (98
    %), the COMBAT entry (100 %) and the clock (84 %), generic over the
    host. The agent keeps every path as a shim (plan §4.1 rule 2, removed
    in R17): `lib.rs` for `path_text`, `correlation` and
    `detection_budget`, `canary/mod.rs` for the readers, a new
    `posture.rs` for the posture — `pub use nn_core::posture::*`, the
    machine, the detector, the tracker and the exemption as aliases on
    `LinuxHost` (an alias without a parameter: one with a default does not
    apply where a value is built), the release hook on the agent's unlock
    token, the two watchdog lookups under their names and signatures.
    Callers, `main.rs` (one import: the reporter's path), the admin
    socket, the ladder, the rules, the tests, the replays, the examples
    and the fuzz targets are unchanged. Tests: 252 moved with their code
    and run in nn-core on a portable test host (`posture::host::testing`:
    `std::fs`, every directory owned by one test user, never suspended,
    100 ticks a second, a monotonic clock an hour into its uptime; the
    staging directories and the exploit guard's event as the rules read
    them, no bait file, no reverse-shell shape, a policy and a window of
    `bool`, judges that never fire) — their fixture links made with
    `std::fs::soft_link`, their user that test user instead of `getuid()`,
    each test module binding the host in a few lines, every assertion the
    same; the cross-module tests that wire the agent's rules, ladder,
    judges and audit log, and the golden replay, stay in the agent and
    read nn-core's test helpers through a feature its dev-dependency
    enables, `test-util` (the triggers' event builders, the `TestClock`,
    the ledger's and the machine's readers the replay took from private
    fields, the lineage's two test builders); the legacy boolean release
    stays `cfg(test)` (WDG-R02), so its seven tests and the clock's are
    cut verbatim into nn-core's `posture/tests.rs`, and R020's trigger
    test, which needs the rules' real shape, into the agent's. nn-core
    gains nn-model, parking_lot and `common` (the agent's versions) and a
    `debug-trigger` feature the agent forwards; the lockfiles gain the
    edges, nothing else. Ratchet 52 → 50: nn-core 38 → 37 (the reporter
    left the budget) → 39 (the first seam: the lineage and the exemption
    name the Linux host where they called `std::fs` and libc) → 38 (they
    moved; the machine's `posture/mod.rs`, which bound them, named it) →
    39 (the second seam: the triggers) → 36 (the machine and the triggers
    moved; the agent's `posture.rs`, which binds the posture to the Linux
    host, names it, as `config/mod.rs` does for the loaders); nn-admin 8,
    nn-linux 3, nn-proto 3.
  - Deviations from the plan: the plan's `ProcSource` and `Clock` (§2.3,
    R04b) are one host trait of static functions with the calls the
    posture made (lab PR 247's way), not typed records of a process; the
    posture's own clock stays lab PR 243's `posture::clock::Clock` (an
    `Instant`). `PostureAgent` is a seam the plan did not foresee: the
    triggers share four shapes with the rules R08b moves, and the machine
    holds the agent's policy handle, window, judges and token; R08b drops
    its engine's half. `config::comm_allowlist` is not moved: its
    `Judgement::apply`, which 23 sites of the rules call, holds the
    revoked transfer tool's kill through the engine's per-rule response
    policy (`REVOKED_TRANSFER_TOOL_KILL`, a per-thread hold); a seam there
    changes every caller's arguments or imports, in R08b's code, and in
    R08b the policy and the rules move with it, so no seam is needed.
    `path_text` (to nn-model) and the canary readers were not in R08a's
    list: the posture needs the first, the second needs the lineage. The
    posture's shim is a file (`posture.rs`), not `lib.rs` as R05's: the
    ratchet's scan finds the test-only `mod` a file declares, not one
    inside an inline module, and would have read the golden replay and the
    cross-module tests as the posture's code. The moves carry their
    generics (no separate rewrite commits, no `.git-blame-ignore-revs`);
    `exempt` (90 %), the readers (92 %) and `clock` (84 %) are below
    §4.1's 95 %: short files. The test host's staging list is a copy of
    the rules' three prefixes until R08b.
  - Open: `comm_allowlist`, `net::blocklist` and the decision replay
    (R08b); `PostureAgent`'s engine half (R08b), its judges (`impact`,
    `impair`), the window and the token (R04b's split and the
    `UnlockToken` verification); the overlay gate and the rollback floor
    (after R04b and R09a); in R09, `LinuxHost` goes to nn-linux and its
    `PostureAgent` implementation with it (the orphan rule); the shims
    (R17).
  - Lab: no guest (moves and seams that keep every call; the identity below). Host, on 1356811 (the lot's code; the commit after it changes documentation only) and again on the final tree, `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (`common` and the eBPF crates untouched: the stamp's source c0365736…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo, whose output is `main`'s line for line); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,066 passed, 0 failed, 15 ignored (the test list is `main`'s — 3,078 names, every one found at the tip, 252 now nn-core's (44 → 296 there), R020's trigger test now the agent's `posture::tests::reverse_shell` — plus the Linux host's 3 tests; no `#[ignore]` test added); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets (nn-core's test code builds for Windows too): all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19), the TLS and DNS parser pins (5), the overlay-v1 fixture (2). Identity against `main` 9e33fad, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 a4f7006f… there), its stamp too (source c0365736…); the scanner (401,368 bytes) is byte-identical (unstripped: its 504 functions the same code, and 24 bytes differ, the numbers LLVM appends to the names of four local symbols); the watchdog (2,336,920 → 2,337,080 bytes) has every one of `main`'s 2,469 functions the same code and one more copy of a `RawVec` growth body `main` has twice — `path_text`'s commit alone builds this watchdog byte for byte, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes, the sizes of the agent, nn-admin, the watchdog and `CHANGELOG.md` aside. The agent (14,901,048 → 14,940,328 bytes) and nn-admin (4,029,280 → 4,029,840) are not byte-identical. Function by function (unstripped, names mapped to the new crates and modules, the host type parameter dropped, addresses and rip-relative targets dropped, trailing padding dropped): the agent 7,536 of 7,653 the same code (89 differ, 28 and 59 unpaired), nn-admin 3,440 of 3,478 (31; 7 and 12). Control — `main` with nn-core's three new dependencies, no source moved: the watchdog and the scanner byte-identical, 21 of the agent's functions and 6 of nn-admin's change already (clap's `TypeId`s of the binaries' enums: a crate's identity moves with its dependency list; which of identical bodies keeps its name). From the control to this lot: 69 of the agent's — 34 call other callees (inlining at the new crate boundary), 23 schedule or allocate registers otherwise, 12 have the same instructions with other operands — and 25 of nn-admin's (9, 14 and 2); the unpaired are generic code made in both the agent's library and its binary now that the lineage's and the exemption's methods are generic (`loginuid_of`, `image_path`, `is_running`, `proc_start_ticks_of`, …), the machine's `observe` kept out of line (28,039 bytes, which `process_event` loses: −24,512), and helpers kept out of line or folded: `.text` +35,376 bytes in the agent (+0.49 %), +32 in nn-admin. `.rodata`, cut at every address the code or a dynamic relocation names, callsite line numbers aside: the watchdog's and the scanner's text the same; the agent's the same but the reporter's source path and tracing target (`detection_report`, a move within the agent) and adjacent literals grouped otherwise; nn-admin's the same but a search for `/../` compiled with vector constants; the moved modules' paths and tracing target are nn-core's and nn-model's (not printed: `with_target(false)`).
- **Lab PR 251 — nn-core, part 2b: the decision engine leaves the agent
  (Wave 4 Phase 2, R08b of the restructure plan; no level changes).**
  - What was wrong: nn-core held the content lists (R07, lab PR 247) and
    the posture (R08a, lab PR 250). The decision engine — the rules, the
    multi-match combination and its legacy ceiling, the signed per-rule
    policy and the response switches (lab PR 236), the offline replay the
    golden replay and `nn-admin policy test` share, the rule catalogue's
    table, the ATT&CK mapping, the flow ledger, the chain rules'
    correlation store and ancestry tree — and the state its rules read
    (the comm allowlists, the FIM rules, the operator's blocklists, the
    DNS cache, the flow tracker, the netflow limiter, the host's
    resolvers, the ransomware tracker, the security-tool detector, the
    drift's classification, the canary detector) were the agent's, and
    did on their host themselves: `/proc` (the ancestry tree's `stat`, the
    per-rule policy's exemption facts — a process's uid and cgroup, its
    executable checked root-owned in a root-owned tree and hashed), `rpm
    -qf` through `trusted_bin` and the dpkg lists inside tokio's
    `block_in_place` (R018, the tracker's trust of packaged programs), the
    host's view of a path (`/proc/1/root`), the files' samples
    (`O_NOFOLLOW | O_NONBLOCK`, owners and modes), tokio's `Notify` (the
    DNS pump's ingest, the flow tracker's announcements of lab PR 246), the
    kernel's `DEFENDER_PIDS` (an aya map), the trusted-installer window,
    the canary registry and access log (signed chains), `getifaddrs`,
    `stat(2)`; they named the agent's detection records, bait table and
    window. R08a left `PostureAgent`'s engine half (the triggers' four
    shapes, the policy) for this lot. Ratchet 50, nn-core 36.
  - What changed, one commit each, bottom-up (§4.1 rule 3): the parts of a
    detection record the engine names (`Sensor` and its filter parse,
    `MitreAttack`, `Principal`) cut to nn-evidence's `detection_payload`;
    the anti-tamper bait table (`fim::baits`) and the trusted-installer
    window's vocabulary (`WindowGrant`, `OWN_SYSTEMD_UNITS`) cut to
    nn-core; the host's resolvers moved (95 %: `resolv.conf` read with
    `std::fs`, portable, as `combat_allow`). Then the seam,
    `nn_core::decision::host::DecisionHost`, on `PostureAgent` and R07's
    `ContentHost`: the work kept off the async runtime, `rpm -qf`, the
    host's view of a path, the window's grant and an inert window, the
    kernel map of the security tools as an associated type with its insert
    and remove — static functions, as the posture's seams, implemented for
    `LinuxHost` by `decision_host_linux` with the calls the code made, the
    call sites reading `H::…`; `PostureHost` gains `read_dir`. The
    engine's Linux halves stay with that host: the exemption facts read
    from a `/proc` (`ProcFacts`, cut verbatim to `decision_host_linux`,
    behind the engine's `ActorFacts`) and the files' sampler (`FsSampler`,
    behind `Sampler`, whose vocabulary — the signal's thresholds,
    `entropy_bits`, the format signatures — is cut to nn-core's
    `impact::entropy`). Then the moves: the blocklists (93 %, their loaders
    take the host that reads a `.v1`); the DNS cache's state (80 %, generic
    over the pump's ingest, which keeps tokio's `Notify` and the pump's
    mark in the agent's `net::dns_ingest`); the engine's foundations (the
    ATT&CK mapping, the bounded structures, the flow ledger: 100 %; the
    correlation store 99 %, the ancestry tree 90 %, generic over the host);
    the engine itself in one commit, its parts depending on each other —
    `decision/` but the golden replay, the validation registry and the
    catalogue's renderer and tests, `fim/rules.rs`,
    `config/comm_allowlist.rs` (its `Judgement::apply`, which 23 rule sites
    call, holds the revoked transfer tool's kill through the response
    policy: it moves with them, no seam), `net/limiter.rs`, `impact/` but
    the sampler, `impair/` (65–100 %, see below) — generic over the host
    where they hold what reads it; the drift's classification
    (`DriftClassifier`, `DriftRateLimiter`, the tiers and their defaults,
    cut from `fim::drain` to `fim::drift`); the posture reading the
    engine's shapes and policy itself (the triggers call
    `fim::rules::is_bait_tamper`, `rules::epg::is_exploit_postcondition`,
    R020's `shape` and `rules::is_staging_path`, the machine holds the
    engine's `PolicyHandle`; `PostureAgent` drops them and its policy
    type); the flow tracker (98 %; the notifier the net drain awaits is
    the host's, `DecisionHost::FlowNotify`); the canary detector's tests
    cut to `canary/detector_tests.rs` (they wire the agent's signed
    registry and access log), then the detector (82 %) behind a second
    seam, `nn_core::canary::host::CanaryHost` — the registry, the access log
    and the addresses' cache as associated types; the live set
    (`LiveCanary`), whether a canary is armed, the first trip, the access
    row, this host's addresses, the read-forward set, `stat(2)` and the
    accessor's executable as static functions — implemented by
    `canary_host_linux` (with `stat_inode_key`, cut there), and the network
    canaries' addresses (`CanaryAddr`, `connect_destination`,
    `PortCanaries`) cut from `canary::network` with it; the access row's
    draft is nn-core's. The agent keeps every path as a shim (plan §4.1
    rule 2, removed in R17): `decision.rs`, `impact.rs`, `impair.rs` (files:
    their test modules, and the two process-wide slots `status` reads,
    which hold the agent's types), inline modules for the comm allowlist,
    the limiter, the DNS cache, the flow tracker and the canary detector,
    `pub use` for the rest; the engine, the stores, the trackers and the
    detectors are aliases on `LinuxHost`, the default rule set and the
    replay keep their names and signatures. Callers are unchanged but for
    the three list loaders of `main.rs` and the posture's golden replay,
    which name the host (`NetBlocklist::load::<LinuxHost>`,
    `Ja3Blocklist::load`, `SecurityTools::load`). The agent forwards
    `demo-tappa5` to nn-core; nn-core's `test-util` gives the agent's tests
    the rules' and the exploit guard's event builders and the detector's
    indexes. Tests: 699 moved with their code and run on the portable test
    host, which implements `DecisionHost` (work where it is called, no
    `rpm`, a path its own view, a window a `bool`, the defenders' map a
    set, no exemption fact, a sampler that finds nothing, no DNS pump, no
    drain to wake) — their fixtures' links made with the portable
    `symlink`, each test module binding the host in a few lines, every
    assertion the same; the tests that wire the agent's other modules or
    test its Linux semantics stay in the agent, cut verbatim with copies of
    their fixtures (`decision/host_tests.rs` 4, `impact/host_tests.rs` 6,
    `impair/host_tests.rs` 3, `canary/detector_tests.rs` 19; with them the
    exemption facts' 2, the ingest's 2 and the sampler's 7). The rule
    catalogue and the validation matrix cite the moved tests at their
    paths; the renderer counts a crate's unit test as a unit test, so
    `ATTACK_COVERAGE.md` and the Navigator layer are unchanged and
    `RULE_CATALOGUE.md` differs in 88 lines of cited paths. clippy's
    `manual_is_multiple_of` applies in nn-core: five `% N == 0` read
    `is_multiple_of` (non-zero divisors). nn-core gains nn-evidence, serde
    and nn-proto (the agent's versions); the lockfiles gain the edges,
    nothing else. Ratchet 50 → 33: nn-core 36 → 32 (the resolvers moved:
    the response policy, the chain and network rules and the replay named
    them) → 35 (the seam: the ancestry tree, the transfer tools' clock,
    R018's and the tracker's package database, the tracker's host path,
    the detector, the FIM rules' window and the rule sets' inert one name
    the Linux host) → 36 (`rule_policy.rs` re-exported the Linux facts) →
    36 (the blocklists) → 37 (`net/mod.rs` gives the cache the ingest) →
    38 (the foundations; `decision/mod.rs` bound the store and the tree) →
    21 (the engine took its references with it, the catalogue's three to
    the rules decided outside the engine staying with its renderer; the
    shims `decision.rs`, `impact.rs`, `impair.rs`, `net/mod.rs` name the
    host) → 19 (the detector took its two; `canary/mod.rs`, which binds it,
    is nn-linux's); nn-admin 8, nn-linux 3, nn-proto 3.
  - Deviations from the plan: R08b's list is done — the rules, the FIM
    rules, the drift's classification, the network state (`flow_tracker`,
    `dns_cache`'s state, `limiter`), the canary detector — and more moved
    with it: R08a's leftovers (the comm allowlists, the blocklists, the
    replay), the host's resolvers (mapped to nn-linux by lab PR 239: they
    read with `std::fs`), the ransomware tracker and the security-tool
    detector (post-plan, lab PR 225: the rules' judges), and the bottom-up
    cuts the moves needed (the detection record's parts, the bait table,
    the window's vocabulary, the entropy vocabulary, the canaries'
    addresses). R08c keeps what the plan gives it: the COMBAT ladder's
    policy and traits, the response types and policy
    (`response::ExecutorConfig`, the executor's policy), the contract and
    bus skeletons. The seams are not the plan's: R04b's `ProcSource`,
    `PackageOwnership` and `InstallerKernelSync` are one host trait of
    static functions with the calls the engine made (lab PR 247's and 250's
    way), and the canary detector moved before R04c split the registry's
    format from its store, so it reaches the registry and the access log
    through `CanaryHost`; both stay the agent's. `PostureAgent` keeps the
    window, the token and the two judges as associated types: the tracker
    and the detector are nn-core's but generic over `DecisionHost`, which
    the posture's bound is not; binding the posture to `DecisionHost` would
    change every posture type's bound — with R09, when `LinuxHost` moves.
    The golden replay, the validation registry and the catalogue's
    renderer stay in the agent: they name the agent's records (the exec
    policy's and the quarantine's) and the docs it writes, and the frozen
    sweep files (`v2-*.tsv`, their hashes pinned in `matrix.md`) name the
    registry by its path. `decision::rule_policy::ProcFacts` is now
    `decision_host_linux::ProcFacts` (nothing named it); `stat_inode_key`
    keeps its path. The moves carry their generics (no separate rewrite
    commits, no `.git-blame-ignore-revs`), so many files are under §4.1's
    95 % (most over 85 %): the engine's root 65 %, `impair/tests.rs` 77 %,
    `dns_cache.rs` 80 %, the detector 82 %; `impact/tests.rs` kept 437 of
    its 870 lines in nn-core and git pairs it with the agent's
    `impact/host_tests.rs` (63 %), which took the copy-delete tests on real
    files and the fixtures' copies.
  - Open: R08c; the overlay gate and the rollback floor (after R04b and
    R09a); R04b's window and kernel-sync split and the `UnlockToken`
    verification (`PostureAgent`'s window and token); R04c's splits (the
    canary registry's format and store, `fim/drain`'s ring half, the rest);
    in R09, `LinuxHost` goes to nn-linux and its `DecisionHost` and
    `CanaryHost` implementations with it (the orphan rule), with
    `decision_host_linux`, `canary_host_linux`, `net::dns_ingest` and the
    sampler; the shims (R17).
  - Lab: no guest (moves and seams that keep every call; the identity below). Host, on f6dc5fe (the lot's code; the commit after it changes documentation and doc comments only) and again on the final tree, `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (`common` and the eBPF crates untouched: the stamp's source c0365736…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo, whose output is `main`'s line for line); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,066 passed, 0 failed, 15 ignored (the test list is `main`'s — 3,081 names, every one found at the tip, 699 now nn-core's: 296 → 995 there, the agent's library 2,005 → 1,306; no test added or removed, no `#[ignore]` added); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions, `rule_policy` among them; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets (nn-core's test code builds for Windows and macOS too): all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's now; the exemption facts' 2 on the Linux host; the signed overlay's and the fuzz seeds' tests). `nn-admin policy test`, `main`'s binary and the tip's on the same samples — the 24 golden cases under the built-in defaults and three candidate policies (one refused: it exempts root), with the shipped lists and with none, as a table and as JSON, and every case's events as one stream, plain and wrapped: the 402 outputs are the same bytes. Identity against `main` 55f0e97, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 7b9fa6d2… there), its stamp too (source c0365736…); the scanner (401,368 bytes) and the watchdog (2,337,080) are byte-identical, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes, the sizes of the agent, nn-admin, `CHANGELOG.md` and the two operator guides that name a moved file aside. The agent (14,939,576 → 15,035,960 bytes) and nn-admin (4,029,840 → 4,086,576) are not byte-identical. Function by function (unstripped, names mapped to the new crates and modules, the host's and the DNS ingest's type parameters dropped, addresses and rip-relative targets dropped, trailing padding dropped): the agent 7,500 of 7,684 the same code (139 differ, 45 and 105 unpaired), nn-admin 3,364 of 3,483 (90; 29 and 73). Control — `main` with nn-core's three new dependencies and the `demo-tappa5` feature it takes, no source moved: the watchdog and the scanner byte-identical, 12 of the agent's functions and 7 of nn-admin's change already (clap's `TypeId`s of the binaries' enums, which of identical bodies keeps its name). From the control to this lot: 127 of the agent's — 87 call other callees (inlining at the new crate boundary), 33 schedule or allocate registers otherwise, 2 have the same instructions with other operands, 4 call a body of the same code under another name, 1 name has two bodies — and 84 of nn-admin's (60, 20 and 2; 2 names with two bodies); the unpaired are the seams' functions kept out of line (`<LinuxHost as DecisionHost>::rpm_owns`, `<LinuxHost as CanaryHost>::append_access`, …), helpers inlined on one side and kept out of line on the other, and generic code made in both the agent's library and its binary: the engine is generic over the host now and is instantiated, and inlined, in the agent's crates — `.text` +83,104 bytes in the agent (+1.14 %: the security-tool detector's assessment inlined into NN-L-EVA's `evaluate`, +15,172; the ransomware judge into the posture's `observe`, +12,901; the canary indexes' rebuild into the admin socket's, +7,374 and −7,257), +44,224 in nn-admin (+1.36 %). `.rodata`, cut at every address the code or a dynamic relocation names: the same text but the moved and new files' paths, the callsite names (`event <file>:<line>`) of the moved and edited files, the rule catalogue's cited test paths (compiled in, never printed) and adjacent literals grouped otherwise (every run of either side is found in the other's text but runs under four bytes: word boundaries and constant bytes); the moved modules' tracing target is `nn_core::…` (not printed: `with_target(false)`). `cargo doc`: the moved modules' warnings are the ones they had in the agent, but for two that no longer occur (the credential renderer's link to nn-proto, a dependency of nn-core now; a link of the sampler's to a private item); ten links of the moved docs to the agent's items are code spans now.
- **Lab PR 252 — nn-core, part 2c: the COMBAT ladder and the executor's
  policy leave the agent; the skeletons of the bus and the sensor contract
  (Wave 4 Phase 2, R08c of the restructure plan; no level changes).**
  - What was wrong: nn-core held the content lists (R07, lab PR 247), the
    posture (R08a, lab PR 250) and the decision engine (R08b, lab PR 251).
    The policy of the graduated response — the COMBAT ladder: its stages
    and state machine, the jump-ahead, the attribution and its cap, the
    isolation gate, the worker, the stand-down, the signed rows — and the
    executor's configuration (the detect-only gate) were still the agent's,
    and the ladder named the agent's Linux parts: its capture of a process
    (`response::proc_ref::ProcRef`, a pidfd and the start `/proc` gives it,
    external audit CMB-004), the isolator's read-back vocabulary
    (`anti_tamper::network_isolate`), the production actuator and guard in
    the files that held the traits, the audit log on the agent's key, and
    the stale chain's record beside the compatibility line's open through
    the anchored directory (`anchored`). The types R12's priority bus and
    R13's sensor contract are built on did not exist. `PostureAgent` still
    carried the engine's two judges (lab PR 251's leftover). Ratchet 33,
    nn-core 19, five of them the ladder's (`combat/mod.rs` and
    `combat/actuator.rs` → `anti_tamper`, `response`; `combat/reconcile.rs`
    → `anchored`).
  - What changed, one commit each, bottom-up (§4.1 rule 3): the isolation's
    read-back vocabulary (`Family`, `FamilyOutcome`, `IsolationReport`)
    cut verbatim to nn-core's `anti_tamper::network_isolate`, which the
    agent's isolator re-exports; the offenders' identity
    (`combat/offender.rs`, lab PR 245, 98 %: `cgroup_path` and `shown`
    `pub`); the stale chain's record (`StaleChain`, its signed entry,
    `attest` over an audit log of any key) cut to nn-core's
    `combat::reconcile`, the agent's file keeping the compatibility line's
    file I/O. Then the seam, `nn_core::combat::host::CombatHost` — the
    capture as an associated type and how one is made (`open_for_event`),
    a static function, as the posture's, the engine's and the canaries'
    seams — and `Capture`, what the ladder reads of and asks of a capture,
    with `ProcRef`'s method names so that the ladder's calls stay as they
    are; implemented for `LinuxHost` by `combat_host_linux` with `ProcRef`'s
    own calls, with a test of what is Linux about it (a pidfd and a start).
    Then the ladder's tests that wire the agent, cut verbatim into files of
    their own in the agent (the six of the evidence, which sign with the
    agent's key, to `combat/evidence_tests.rs`; five of the ladder's — the
    production identity on a real process, the audit log that refuses the
    transitions, the three signed-row tests of lab PR 245 — to
    `combat/host_tests.rs`, with copies of their fixtures), so that the move
    after them is one: `combat/mod.rs` (95 %), `combat/evidence.rs` (95 %)
    and `combat/tests.rs` (98 %) to nn-core, generic over the host
    (`CombatLadder<H>`, `NeutralizeHook<H>`; `Attributed`'s `Clone` written
    out, as the derive would ask the capture to be `Clone`; one
    `LadderStep<H>` annotated, as the capture's projection does not name
    the host), `AuditEvidence<K>` over an audit log of any key; cut with
    them, from `combat/actuator.rs`, the outcomes and `CombatActuator<H>`
    (its two defaults capture a process as the host does and compare it as
    the capture does), and from `combat/protected.rs` `ProtectedReason`,
    `ProtectedProcs`, `NoProtectedProcs` and why the guard exists. The
    executor's configuration and policy (`response/config.rs`, 90 %: the
    detect-only gate, its variables and the values they are honoured with,
    the quarantine's cap, the cgroup and nftables names; three doc links to
    the agent's executor are code spans). The skeletons, types only:
    `nn_model::{EventClass, ProcessKey}` (§2.3), `nn_core::bus`
    (`Priority`, `SourceId`, `Envelope`, `LossStage` — §3.4's eight stages
    —, `LossCounters`, `PerClass`) and `nn_core::contract`
    (`ClassContract`, `SyncVerdict`, `FailureMode`, `Truncation`,
    `SourceState`). Last, the posture names the engine's judges itself: its
    machine and triggers take `DecisionHost`, their hook slots hold
    `impact::RansomTracker<H>` and `impair::DefenseDetector<H>`, the two
    calls are the agent's bodies at the call; `PostureAgent` keeps the
    trusted-installer window and the unlock token. What is Linux stays in
    the agent for nn-linux (R09), the map says so: `SystemActuator` (the
    executor's kill, quarantine and per-PID egress block, the isolator,
    `/proc`) on the trait (`combat::actuator`), `SystemProtectedProcs` (the
    identities read from the live `/proc`: the watchdog's slot re-checked
    by its executable, the SSH service by its executable, uid and systemd
    unit; `combat::protected`), the compatibility line
    (`combat::reconcile`), the executor and its actions, and the capture's
    host (`combat_host_linux`). The agent keeps every path as a shim (plan
    §4.1 rule 2, removed in R17): a new `combat.rs` — `pub use
    nn_core::combat::*`, the ladder and its hook as aliases on `LinuxHost`,
    the evidence on the agent's key, `ProcRef` as the host's capture, the
    agent's `actuator`, `protected` and `reconcile` re-exporting what was
    cut from each — and `response/mod.rs`. Callers, `main.rs`, the admin
    socket, the copy-on-write guard's hook and `admin_cli`'s test are
    unchanged; the posture's golden replay and the host tests implement
    `CombatActuator<LinuxHost>` (one line each). Tests: 39 moved with their
    code (nn-core 995 → 1,034) and run on the posture's portable test host,
    whose capture is the identity alone (no descriptor, never running: the
    agent's `ProcRef::for_test`), every assertion the same; the agent's
    library 1,306 → 1,268 (11 at a new path, the capture's test). No
    manifest and no lockfile changed: nn-core needed no new dependency.
    Ratchet 33 → 29: nn-core 19 → 18 (the stale chain's record moved and
    the agent's `combat/reconcile.rs`, its file I/O, is nn-linux's) → 15
    (the ladder and the actuator's file took their four references to
    `anti_tamper` and `response`; `combat.rs`, which binds the ladder to the
    Linux host, names it); nn-admin 8, nn-linux 3, nn-proto 3.
  - Deviations from the plan: the seam is a host trait with the capture as
    an associated type and a trait of the capture's own, not §2.3's
    "existing" `CombatActuator` alone: the actuator stays a trait object,
    generic over the host; §2.3's `ActuatorBackend`, `ResponsePolicy`,
    `decide` and `ActionRequest` are R12's dispatcher and are not written —
    nothing would call them. "The policy of `protected`": the guard's
    trait, its reasons and the guard that protects nothing moved; the
    identities (systemd's SSH units, sshd's executables, the watchdog's
    unit, `/proc`) are the production guard's and stay with it. "The
    policy of `reconcile`": the record (the outcome, its signed entry, its
    append) moved. "`ExecutorConfig` and the policy": `response::config`
    moved whole; the dispatcher's own refusals (the PID floor, host-wide
    isolation left to the ladder, the host-critical guard on every action on
    a process) sit between the pidfd's checks of the target in
    `execute_on` and stay with the executor; `ExecutionOutcome` and
    `ExecutionReport` (nn-model's by §2.4) are not needed by the moved code
    and stay where they are. The skeletons: `EventClass` and `ProcessKey`
    are nn-model's, as §2.3 places them; the plan's
    `contract::CapabilityManifest` is not written — the boot signs one
    since lab PR 218 (`boot::manifest`, op `capability_manifest`), which
    R13 extends with the class contracts; §2.3 sketches no trait for these
    modules, none is written; `SourceId` is an index. `PostureAgent`'s two
    judges: done here, not with R09 as lab PR 251 foresaw — only the
    machine and the triggers hold them, so the bound changes there and
    nowhere else. The moves carry their generics (no separate rewrite
    commits, no `.git-blame-ignore-revs`), as lots 250 and 251; the files
    the moved tests left are 95 % and 98 % because those tests left them in
    the commit before.
  - Open: in R09, `LinuxHost` goes to nn-linux and its `CombatHost`
    implementation with it, with `SystemActuator`, `SystemProtectedProcs`,
    the compatibility line, the executor and `ProcRef`; R12 builds the bus
    and the response dispatcher on these types, R13 the contract on the
    boot's manifest; R04b's split of the window and the `UnlockToken`
    verification (`PostureAgent`'s window and token); the overlay gate and
    the rollback floor (after R04b and R09a); the records of the exec
    quarantine and the exec policy (`execq::record`, `execpol::record`:
    five of nn-core's 15); the shims (R17).
  - Lab: no guest (moves and seams that keep every call; the identity below). Host, on ed75fae (the lot's code; the commit after it changes documentation and doc comments only) and again on the final tree, `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (`common` and the eBPF crates untouched: the stamp's source c0365736…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo, whose output is `main`'s line for line); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,067 passed, 0 failed, 15 ignored (the test list is `main`'s — 3,081 names, every one found at the tip, 39 now nn-core's (995 → 1,034 there) and 11 at a new path in the agent's `combat` — plus the test of the Linux host's capture; no `#[ignore]` test added); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets: all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's; the exemption facts' 2 on the Linux host; the signed overlay's and the fuzz seeds' tests). `nn-admin policy test`, `main`'s binary and the tip's on lab PR 251's samples (the 24 golden cases under the built-in defaults and three candidate policies, with the shipped lists and with none, as a table and as JSON, and every case's events as one stream, plain and wrapped): the 402 outputs are the same bytes. Identity against `main` 3a1ee3e, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 5eab9218… there), its stamp too (source c0365736…); the scanner (401,368 bytes) and the watchdog (2,337,080) are byte-identical, stripped and unstripped — nn-model's two new types change nothing in the watchdog; `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes, the sizes of the agent and, on the final tree, `CHANGELOG.md` aside. nn-admin keeps its size (4,086,576 bytes; unstripped 6,971,488) and is not byte-identical: function by function (unstripped, names mapped to the new crates and modules, the host's and the key's type parameters dropped, addresses and rip-relative targets dropped, trailing padding dropped), 3,526 of its 3,527 functions are the same code — NN-L-EVA's `evaluate` no longer inlines the security-tool assessment — with `.text` of the same size and `.rodata` of the same text. The agent (15,036,712 → 14,998,040 bytes) has 7,673 of its 7,744 functions the same code (40 differ, 31 and 26 unpaired). No manifest changed, so no control: the differences are the code's — 26 call other callees, 10 schedule or allocate registers otherwise, 3 call a body of the same code under another name, 1 name has two bodies. The security-tool detector's assessment is kept out of line (+17,473 bytes, its `assess_once` −20,887 folded into it) and called by NN-L-EVA's `evaluate` (−15,172) and the posture's triggers; the ransomware judge is no longer inlined into the posture's `observe` (−12,468); the ladder's entry is inlined into `main.rs`'s entry hook; helpers of the lineage and of the security-tool detector are made once where `main` made them twice; std's channel code of the ladder's queue and of the copy-on-write guard is inlined otherwise: `.text` −37,920 bytes (−0.52 %). `.rodata`, cut at every address the code or a dynamic relocation names: the same 21,703 text pieces but the callsite names (`event <file>:<line>`) of the moved and edited files, the stale chain record's source path and tracing target (`nn_core::combat::reconcile`, not printed: `with_target(false)`) and adjacent literals grouped otherwise. `cargo doc`: the moved modules' warnings are the ones they had in the agent (the ladder's two links to its private items); the new modules add none. The final tree builds the same four binaries as the code tip, byte for byte, stripped and unstripped.
- **Lab PR 253 — nn-linux, part 1: the actuators, the self-defence, the
  agent's key and its Linux host leave the agent (Wave 4 Phase 2, R09a of
  the restructure plan; no level changes).**
  - What was wrong: nn-linux, the Linux adapters' crate (R01, lab PR 239),
    was empty. nn-core held the content lists, the posture, the decision
    engine and the COMBAT ladder (R07–R08c), with what they do on their
    host behind traits that the agent's `LinuxHost` implemented in the
    agent (`*_host_linux`). R08c (lab PR 252) left for R09 what is Linux:
    the executor and its actions, `SystemActuator`,
    `SystemProtectedProcs`, the stale chain's compatibility line,
    `ProcRef`; the plan's R09a adds the self-defence (`anti_tamper/*`),
    the agent's key (`keys`) and `trusted_bin`, `fs_type`, `agent_id`,
    `atomic_file`, `runtime`, `async_fd`. Ratchet 29: nn-proto 3
    (`anti_tamper::admin_auth`, mapped to nn-proto for its role parse and
    its UnlockToken verification, names `anti_tamper`, `atomic_file` and
    `os_rng`), nn-admin 8, nn-core 15, nn-linux 3.
  - What changed, one commit each, bottom-up (§4.1 rule 3): the role
    keywords (`role_keyword`, the inverse of nn-proto's
    `parse_role_keyword`) cut verbatim to nn-proto's `admin_quorum`,
    `admin_auth` re-exporting it and `admin_cli` naming nn-proto's, so
    the operator client names no nn-linux module for the role table once
    `anti_tamper` moves. The seam for the network isolator's gate:
    nn-core's `config::overlay_auth::Vouch` (`Send + Sync + Debug`, its
    `verified(kind, path)` the gate's), beside the `Verified` content it
    hands over, implemented by the agent's `OverlayGate` with its own
    `verified`; the isolator holds `Arc<dyn Vouch>` and
    `with_overlay_gate` takes the `Arc` of any `Vouch` type, so `main.rs`
    and the tests are unchanged. The tests that read the agent's own parts
    cut verbatim into it, so that the moves after them are moves:
    `agent_id`'s scan of `main.rs` (MAIN-009) to `agent_id_tests.rs`, the
    content host's three (LLMR-015, DEC-016: they read through the agent's
    loaders and its renderer bound to `LinuxHost`) to
    `content_host_tests.rs`, the isolator's two with the signed-overlay
    gate (ATP-001 / DEP-003, NN-AUD-095: they build the agent's
    `OverlayGate` and rollback floor) to
    `config/overlay_auth/isolator_tests.rs` with copies of their fixtures.
    Then the utilities to `crates/nn-linux` (`git mv`, 98–100 %):
    `agent_id`, `anchored`, `async_fd`, `atomic_file`, `bounded_cmd`,
    `fs_type`, `os_rng`, `runtime`, `trusted_bin`. Then the four items
    the moved code names of modules R09b and R09c move, cut verbatim to
    nn-linux's `self_integrity` (the op of the signed findings, the
    self-checks' jitter) and `fim::attach` (the kernel's device number, a
    path's `InodeKey`), the agent's modules re-exporting them. Then one
    move (`git mv`, 98–100 %), because the types tie it together: the
    key's `ChainSigner` names the host its chains are written on (`type
    Host = LinuxHost`), so `LinuxHost` (`chain_host_linux`) moves with
    `keys`; a trait of nn-core or nn-evidence on a type of nn-linux is
    implemented in nn-linux, so every host on `LinuxHost` moves with it —
    `content_host_linux`, `posture_host_linux`, `decision_host_linux`,
    `canary_host_linux`, `combat_host_linux`; what those implementations
    name moves with them — the trusted-installer window and the unlock
    token (`anti_tamper`), the host's view of a path and `ProcRef`
    (`response`), the sampler of the host's files (`impact::entropy`),
    the DNS pump's ingest (`net::dns_ingest`) with the agent's cache
    carrying it (`net`'s inline `dns_cache`, moved whole), the kernel map
    of the security tools (`impair::DefenderMap`, an alias, cut), and the
    canary host's associated types and calls: the registry, the access
    log, this host's addresses, the read-forward set
    (`canary::{registry, access_log, network, read_forward}`); and every
    writer of the audit log signs with the agent's key unless told
    otherwise (`AuditLog<K = AgentSigningKey>`). `anti_tamper` moves
    whole, `admin_auth` with it: the token's mint is
    `pub(in crate::anti_tamper)` in the isolator, which moves, and it
    stays that narrow. The moved files change only where the crate
    boundary needs it: `pub(crate)` → `pub` where the agent names an item
    (the deny hooks' and the FIM's helpers the sensors call, the pidfd
    helpers, the carve-out's splice, the actuator's report texts and
    `/proc` facts the posture's golden replay reads, the isolator's two
    calls its gate tests make); the agent's tests' doors behind nn-linux's
    `test-util` (`ProcRef::for_test`, `SystemProtectedProcs::with_parts`,
    `_test_mint_unlock_token`, `AdminAuth::key_fingerprints_snapshot`, the
    isolator's `new_with_bin` and its fixed mock binary: they were
    `cfg(test)`); `btf_revalidate`'s `total_bits % 8 != 0` reads
    `!total_bits.is_multiple_of(8)` (clippy's `manual_is_multiple_of`,
    which the agent's manifest allows and the workspace lints do not; lab
    PR 251 did the same in nn-core; the divisor is 8). Every `unsafe`
    block moved verbatim with its `SAFETY` comment. The paths the moved
    code names for nn-evidence's and nn-core's modules resolve through
    nn-linux's own shims of the same names (§4.1 rule 2): `audit` (the
    key's name, the writer's default key), `chainlog`, `chain_anchor`,
    `chain_host`, `chain_tail` (tests), `decision`, `posture` (with
    `ExemptPids` on `LinuxHost`), `combat::offender`,
    `canary::chain_lines`, `fim::paths_config` (tests). The BPF guard's
    `cfg!(feature = "debug-trigger")` (it observes in such a build) reads
    nn-linux's feature now: nn-linux declares `debug-trigger` and the
    agent forwards its own (§4.1 rule 4). `test-util` is enabled by the
    agent's dev-dependency only. The agent keeps every path as a shim
    (removed in R17): `pub use nn_linux::…` in `lib.rs`, `combat.rs`,
    `canary/mod.rs`, `impact.rs`, `impair.rs`, `net/mod.rs`. Callers,
    `main.rs`, the admin socket, the tests, the replays, the examples and
    the fuzz targets are unchanged. `btf-matrix.yml`'s path filter,
    xtask's `lab_scripts.rs` (the plan names it) and `path_liveness.rs`
    follow `anti_tamper`. Then `common::bpf_cmd`'s scan for a second copy
    of a BPF command number reads `crates/` too: it listed the directories
    of before the crates, and the BPF rules (R08b) and the self-defence's
    `OBJ_GET` and `MAP_FREEZE` wrappers (this lot) had left them (a probe
    copy under `crates/nn-linux/src` made it fail, removed). Last, the
    documentation: the moved docs' links that the new crate cannot
    resolve, or resolves to a private shim, read nn-evidence's and
    nn-core's items or code spans; the operator guides, `install.sh`'s
    comments, `nn-lab.sh`'s and the tests' comments name the new paths.
    Tests: 438 moved with their code and run in nn-linux, 9 of them
    `#[ignore]`d privileged tests (the real kills, the freeze, the cgroup
    release, the kernel's BTF; `nn-lab.sh test-ignored` runs the
    workspace's); the agent's library 1,268 → 830, 6 of them at a new
    path; none added or removed. nn-linux takes the dependencies the files
    had in the agent, the same versions and features; the lockfiles gain
    the edges, nothing else. Ratchet 29 → 26: nn-proto 3 → 0 —
    `admin_auth.rs` left the scanned tree with `anti_tamper`; its three
    references are nn-linux's own now, not cut (R04b's split of its
    verification remains); nn-admin 8, nn-core 15 (the shims that
    re-export a moved child name it by its crate, `LinuxHost` with it:
    one reference each, as before), nn-linux 3.
  - Deviations from the plan: R09a's list is done, and more moved with
    it, for the types: `LinuxHost` and its six trait implementations
    (post-plan, lab PRs 241–252; their lot notes put them "in R09"), and
    what those name — R09b's canary store (the registry, the access log,
    with this host's addresses and the read-forward set), the sampler,
    the DNS ingest with its cache; `bounded_cmd`, `os_rng` and `anchored`
    (nn-linux's by the map, named by the actuators and the chains' host);
    `btf_revalidate` with `anti_tamper/*` (the plan names its
    `btf-matrix.yml` in R09b: updated here). `admin_auth` is nn-linux's
    whole for now: the map sends its role parse and UnlockToken
    verification to nn-proto, which R04b cuts first (the token, the key
    file's rewrite, the challenge's RNG); the role keywords went to
    nn-proto here. The overlay gate and the rollback floor stay in the
    agent: the plan places them in nn-core with the content (§2.4, R07),
    not in R09a; they wait on R04b's verification in nn-proto, on the
    post-plan content they validate (`cow::config`, `execpol::policy`)
    reaching nn-core, and on a seam for the floor's key; `Vouch` lets the
    isolator move without them. §2.3's `LinuxActuators: ActuatorBackend +
    CombatActuator`, `ProcFs: ProcSource` and `keys::KeyStore` are not
    written: `ActuatorBackend` is R12's dispatcher (lab PR 252), the one
    KeyStore R14c's. §4.1 rule 4's `test-privileged = ["nn-linux/…"]` is
    not needed: no moved code reads it. No separate move and rewrite
    commits and no `.git-blame-ignore-revs`: no importer was rewritten
    (the agent's shims keep the paths), the moved files are 98–100 %.
  - Open: R09b (the sensors, the eBPF embed and `build.rs`, the decode
    of `Raw` into `Event`, the FIM and network drains, the decoys' path
    policy) and R09c (hardening, integrity, `systemd_state`, the
    telemetry probe, the feasibility probe, the install manifest), which
    the cut pieces of `self_integrity` and `fim::attach` wait for; R04b's
    split of `admin_auth` (its verification and the `UnlockToken` to
    nn-proto), then the overlay gate and the rollback floor to nn-core;
    the nn-core shims that bind nn-core's generics to `LinuxHost` (seven
    of nn-core's 15) and the test doors, until R17; the comments of
    `agent-ebpf/` (the eBPF object's sources), `configs/combat-rules.v4`
    and the systemd unit (embedded, their bytes the shipped ones) still
    name the old paths.
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU; no other guest up), the lot's code (d8b91cf) synced, built (release, test-privileged,debug-trigger) and installed (`nn-lab.sh sync`, `build`, `install`): both units active, every deny hook attached (19 of 19), the deny self-test passed, trust level L3. `tamper-check`: 72 of 75 cases OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (the stale own link id of lab PR 215) the recorded deviation —, and `main` 0e89772 on the same guest right after (synced, built and installed the same way) gave the same 75 outcomes and verdicts, case by case (C38's PIDs aside); the evidence of 7 cases differs by the host's events in a case's window — the self-integrity watcher's jittered rounds, a `modprobe` systemd ran (R011), rsyslog rewriting `/var/log/syslog` and `auth.log` (FIM-005) — which `main`'s run saw at other cases or not at all. `ransom-check`: 15 PASS, 1 SKIP (MS-25's auditd, not installed on the guest), `policy-check`: 8 PASS — the same lines as `main`'s on that guest. `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs): 75 suites, 84 passed, 0 failed — nn-linux's 9 privileged tests among them (the kills, the freeze, the cgroup release, the kernel's BTF) —, the totals of lab PR 252's KVM run of `main`'s tree on Ubuntu 24.04. Each boot's chain check flags the guest's detections log (an entry under another key: the e2e fixtures' agents write the same file), on `main`'s boots as on the tip's. The guest powered off after. Host, on d8b91cf (the lot's code) and again on the final tree, `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release`; the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo, whose output is `main`'s line for line); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,067 passed, 0 failed, 15 ignored (the test list is `main`'s — 3,082 names, every one found at the tip, 438 now nn-linux's (0 → 438 there, the agent's library 1,268 → 830) and 6 at a new path in the agent; no test added or removed, no `#[ignore]` added); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets: all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19: the vault's 10 nn-linux's now), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's; the exemption facts' 2, nn-linux's now; the signed overlay's and the fuzz seeds' tests). `nn-admin policy test`, `main`'s binary and the tip's on lab PR 251's samples (the 24 golden cases under the built-in defaults and three candidate policies, with the shipped lists and with none, as a table and as JSON, and every case's events as one stream, plain and wrapped): the 402 outputs are the same bytes. Identity against `main` 0e89772, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 a568d328… there), its stamp too at the code tip (source c0365736…, `main`'s) and on the final tree but its source hash, 235e2fed… (the guardrail commit's test and a comment of `common`); the scanner (401,368 bytes) and the watchdog (2,337,080) are byte-identical, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes — the agent, nn-admin, the eBPF stamp, `CHANGELOG.md`, `install.sh` and the two operator guides whose path mentions changed aside —; the agent's SBOM lists nn-linux. The agent (14,998,040 → 15,192,208 bytes) and nn-admin (4,086,576 → 4,129,480) are not byte-identical. Function by function (unstripped, names mapped to the new crates and modules, addresses and rip-relative targets dropped, trailing padding dropped): the agent 7,550 of 7,739 the same code (172 differ, 17 and 270 unpaired), nn-admin 3,476 of 3,527 (42; 9 and 86). Control — `main` with nn-linux's dependencies and features and the agent's on nn-linux, no source moved: the watchdog and the scanner byte-identical, 19 of the agent's functions and 6 of nn-admin's change already (clap's `TypeId`s of the binaries' enums; which of identical bodies keeps its name), the sizes within 32 bytes. From the control to the lot's code: 160 of the agent's — 110 call other callees (inlining at the new crate boundary), 41 schedule or allocate registers otherwise, 5 have the same instructions with other operands, 4 names have several bodies — and 36 of nn-admin's (24, 11, 1); `NetworkIsolator::trusted_source` differs by its one call, through `Vouch`'s vtable. The unpaired are generic code instantiated in nn-linux as in the agent (the extra copies of an instantiation 736 → 953 in the agent, 360 → 434 in nn-admin: serde_json's deserializers and float parsers, anyhow's errors, tracing's field values, aya's error formatting, the audit log's `append` on the agent's key: +86,383 bytes in the agent) and code inlined on one side and kept out of line on the other (the canary stores' chain readers `read_chain`, `read_tail_hash` and `flat_rows::<CanaryToken>` out of line, the row parsers inlined into them: +87,776 and −26,559): `.text` +157,632 bytes in the agent (+2.15 %), +31,808 in nn-admin (+0.97 %). `.rodata`, cut at every address the code or a dynamic relocation names: the same text but the moved files' paths and the callsite names (`event <file>:<line>`) of the moved and edited files, the gate's `Debug` strings (`OverlayGate`, `allow_unsigned`: its vtable keeps the impl), a panic of serde_json's map serializer (`serialize_value called before serialize_key`) no longer kept where the call is inlined, and literals grouped or cut otherwise; nn-admin's the same text, one piece cut at another address. The final tree builds nn-admin, the scanner and the watchdog byte for byte as the code tip, stripped and unstripped, and the agent with the stamp's hash (`NN_EBPF_BUILD_HASH`) and its build id the only bytes that differ. `cargo doc --workspace --no-deps`: no warning the tree did not have (338, `main` 353).
- **Lab PR 256 — the e2e fixtures' agents keep their state in the test's
  directory; the boot check says the class and the extent of what fails
  (Wave 4; lot 255's follow-ups A and B; no capability, no level
  changes).**
  - What was wrong: at every start of the installed agent, on the lab
    guests and in the KVM CI, the background check reported
    `chain_verify_failed` on the detection log (and `chain verify` on the
    netflow and FIM drift manifests): `entry N: signature invalid`. Lot
    255 traced it to the privileged suites, which `nn-lab.sh
    test-ignored` runs as root where an agent is installed: six agent
    spawns gave their agent a signing key in a tempdir but not all of its
    chains (`fs_deny_privileged_e2e`, `fim_privileged_e2e` twice,
    `privileged_e2e`'s B5 helper, its `GuardFixture` and its agent
    without `admin.pub`), so those agents appended rows under their key
    to the installed agent's chains; three gave neither key nor audit log
    (`privileged_e2e::spawn_agent`, `privileged_map_pin`, the watchdog's
    suite) and wrote the installed agent's chains with its key (84
    `nn-admin-e2etest-*` rows in a guest's audit log). The product did
    what it must — rows of another key in its chain are what the check
    reports — but the report did not say so: `entry N` counted from the
    start of the 4 MiB window once the file is longer, and "signature
    invalid" did not say that the line's hash recomputed and its link
    held.
  - What changed: `agent/tests/common/agent_state.rs` (std only; the
    agent's tests' `common::agent_state`, `include!`d by the watchdog's
    suite). `AgentState` gives each of the agent's 17 state flags — every
    path flag of `Cli` that names a file the agent writes or that makes
    it this agent: `--agent-id-file`, `--admin-pub` (rotate-keys rewrites
    it, a signed overlay is stored beside it), `--signing-key-file`,
    `--audit-log-file`, `--chain-heads-file`, the eight chains,
    `--admin-socket`, `--shutdown-marker-file`, `--pid-file`,
    `--watchdog-pidfile` — a file in the test's directory
    (`AgentState::named` for two agents of one directory, which share the
    id and the admin keys), with `client_args` for nn-admin's signed
    calls and `watchdog_args` for the watchdog; `InstalledAgent` installs
    the root-owned copy (`-e2etest-`) and is the one constructor of the
    agent's command. `INPUT_FLAGS` lists the 21 other path flags (read
    only), `HOST_PATHS` the paths the agent has no flag for, none of them
    a chain: the pin root; `/var/lib/northnarrow` (the protected state
    directory, the quarantine vault's directories, `last_boot_id`, the
    baits, `combat-audit.jsonl`); `/etc/northnarrow` (its protection, the
    baits, `master.key`, `.bootstrap`, which a rotate-keys dispatch
    removes when the test's `admin.pub` holds two keys);
    `/run/northnarrow` (the probe, the containment record, the baits, and
    the watchdog's and install.sh's records, which the agent reads,
    signs into its own audit log and removes). Every agent spawn of
    `agent/tests` and `watchdog/tests` goes through it (the response suite
    runs the installed copy now); the older `privileged_e2e` tests'
    signed nn-admin calls name the test's agent id; `fs_deny` creates the
    `detections/` directory it tests. `xtask/tests/test_state_isolation.rs`:
    (1) every `PathBuf` flag of `Cli` is in `STATE_FLAGS` or
    `INPUT_FLAGS`, once, and the helper passes every state flag; (2) no
    `Command::new` outside the helper whose program, or `sudo`'s and
    `env`'s command, names the agent (a builder bound to a variable is
    followed), and no way to the agent's binary but `build_features_cli.rs`
    (`--build-features` exits before it opens a path); (3) no test names
    the agent's own state flags (the names nn-admin and the watchdog share
    aside); (4) a test that names the agent's host paths is in
    `HOST_PATH_USERS` with its reason (12 files: the pin root's purges,
    `privileged_map_pin`'s subject, `fs_deny`'s directories, the
    honeypot's baits, two of data), and a listed file that names none
    fails; (5) one helper for both crates. Planted violations: lot 255's
    spawn (a tempdir key, the host's log), the build's binary run
    directly, the old `GuardFixture` builder bound to a variable, the
    helper's own accessor used to start the agent; a state flag; a new
    path flag of `Cli`, a helper that stopped passing its flags, a flag
    classified twice; a host path without a reason, a listed file that
    names none. On `main`'s test sources, rules 2, 3 and 5 fail and name
    exactly lot 255's spawns, with the other fixtures' own spawns and
    state flags. The boot check: `verify_recent` returns `RecentError` —
    `SignedByAnotherKey` (lines whose hash recomputes and whose link
    holds, their signature not this agent's key: counted over the whole
    window, `K of the M lines checked …, from <first> to <last>`, a line
    `line N (byte B, ts T)` or `the line at byte B (ts T)`, the first 8
    hex digits of `agent.sig.pub`) or `Broken` (`content_altered`,
    `link_broken`, `malformed`, `not_canonical`, `legacy_after_v3`: at
    the first, as before, with the count of another key's lines before
    it); a `ts` is quoted only when it is a plain timestamp. The signed
    `chain_verify` names each broken log's `class`; the finding is the
    same `chain_verify_failed`, at every start while the lines are there.
    `chain verify`'s "signature invalid" says the hash recomputed.
    `EVIDENCE_CHAINS.md`: the classes, what to do about lines of another
    key (`chain verify`, the key's prefix, the other key's
    `tail_unverified` rows in the manifest, the lines' `ts`), and which
    findings are not written once. Tests: `chainlog` (another key's lines
    in a whole file — the exact report, `chain verify`'s text, one line in
    the singular, the other key's view —, in a window inside the file; an
    altered line, a removed line, an altered line after another key's
    lines; the quoted `ts`; lab PR 204's two boot-check assertions on the
    new type), `chain_anchor` (another key's lines and a cut file reported
    apart: `chain_truncated` stays the start's finding), `chains` (the
    signed `chain_verify` and `chain_verify_failed`), the ratchet's 10.
  - Lab: On Debian 12 (6.1.0-54-cloud-amd64, the lab guest debian12, ssh 2422, QEMU for Windows with WHPX, 4 vCPU, 6 GiB; ubuntu2404 was lot 254's), the guest lot 255 left clean (`main` 482a956 installed on a fresh state, `nn-admin chain verify` exit 0, its audit chain 2,007 rows of which 84 `nn-admin-e2etest-*` rows from before lot 255): the lot's tree synced, built (release, test-privileged,debug-trigger) and installed (`nn-lab.sh sync`, `build`, `install`): both units active, the start's background check `chain verify … result="ok"`, `chain verify` exit 0. `test-ignored` (the five runs, 03:59–04:22Z): 76 suites, 84 passed, 0 failed (`cargo xtask gate-summary`: PASS; `main`'s totals, the 76th suite this lot's ratchet, which has no ignored test); the 46 starts of the tests' agents that print their check: `result="ok"` each, no `chain_verify_failed` (the runs of lots 253 and 254 on ubuntu2404: 30 `chain_verify_failed`, 17 of 32 checks `broken`). The installed agent started three times during the run (the lab's purge between the runs) and once after it: `chain verify … result="ok"` each time. After the run and after that start, `nn-admin chain verify` exit 0 (detections 24 records and 9 checkpoints, netflow 13, FIM drift 16 — the installed agent's own rows; the audit chain 2,036 then 2,040 rows), no `tail_unverified` row in any manifest, and still 84 `nn-admin-e2etest-*` rows in the audit chain: none added. Lot 255's backups (`/var/lib/northnarrow.bak-255-*`) left in place; the guest powered off after. Host, on d5644080 (the lot's code and documentation; this line is all that changed after it), `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (`common` and the eBPF crates untouched); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 71 suites, 3,083 passed, 0 failed, 15 ignored (`main`'s 70 suites and 3,067, the ratchet's suite of 10 and 6 new tests; a first run failed nn-linux's `response::quarantine::tests::a_corrupt_index_is_rebuilt_from_the_meta_files`, a race on the process-global `INDEX_NOTES` that the executor's tests drain — on `main` 482a956 the same test fails 6 of 18 runs of `cargo test -p nn-linux --lib` —, and the rerun passed); `cargo xtask golden`; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build): all pass. The first commit alone: the four clippy runs, `cargo fmt --check` and the ratchet.
- **Lab PR 254 — nn-linux, part 2: the sensors, the eBPF object's embed,
  file integrity monitoring and the network drain leave the agent (Wave
  4 Phase 2, R09b of the restructure plan; no level changes).**
  - What was wrong: after R09a (lab PR 253) the agent still held the
    Linux adapters the plan gives R09b: the sensors and the single eBPF
    loader (`sensors/*`), the build script that embeds the object and
    refuses a stale one (`agent/build.rs`, which found the repository
    as "one level under the root"), file integrity monitoring
    (`fim/{attach, drain, baseline, honeypot, recompute}`), the network
    drain and its blind spots, the decoys' path policy; and nn-model
    still decoded a DNS record, its one use of nn-parse (R02 left it
    "until R09b"). Ratchet 26: nn-admin 8, nn-core 15, nn-linux 3 —
    `sensors/{multiplexer, dns_sensor, exe_identity}` name the agent's
    `boot` (the attach permit, the degradations, the sensor list) —,
    and the loader wrote the exec guards' kernel configuration
    (`execq`, `execpol`: post-plan modules of lab PRs 223 and 226 that
    stay in the agent), which no count shows but no move survives.
  - What changed, one commit each, bottom-up (§4.1 rule 3): the
    exploit guard's test that reads the agent's weakening list
    (`self_integrity::WEAKENING_ENV`) cut verbatim into the agent
    (`epg_tests.rs`), so the sensors' move is a move. What the sensors
    name of the agent's `boot` and `telemetry_probe` to nn-linux's: the
    boot sequence's typed phases with the attach permit (its field is
    private to the module that defines it, so the sequence that alone
    gives it goes with it; `AttachPermit::for_tests` keeps its
    `cfg(any(test, feature = "test-privileged"))`, nn-linux declares
    the feature and the agent forwards its own, §4.1 rule 4), the
    degradations' registry (`boot/degradation.rs`, `git mv`, 100 %),
    the sensors' attach points the capability manifest lists, cut
    verbatim with their five tests, and `PROBE_DIR`; the registries are
    statics, moved and never copied (one per process); the agent's
    `boot` keeps the deny self-test, the BPF LSM gate, the trust level,
    the signed manifest, `release_boot_heap` and the tests that read
    `main.rs`, and re-exports the rest. The seam for the exec guards:
    `sensors::multiplexer::ExecGuards` (one associated function,
    `install(&mut Ebpf)`), the loader `SensorMultiplexer<G>` with
    `PhantomData<fn() -> G>` and `G: ExecGuards` on its impl, the
    agent's `exec_guards::AgentExecGuards` the block cut verbatim from
    the load (`install(ebpf)` for `install(&mut ebpf)`), called at the
    same point (after the exec sensor's attach, before io_uring's); the
    agent's `sensors::SensorMultiplexer` is the loader on it, an alias,
    so `main.rs` is unchanged. Then the moves to `crates/nn-linux`
    (`git mv`): the sensors (96–100 %; `sensors/mod.rs` is `main`'s
    byte for byte, 84 % against the seam's commit, whose alias line
    goes back to the re-export it was) with the build script (97 %:
    `NN_REPO_ROOT` for the root, ebpf-guard its build-dependency, the
    embed's `cargo:rustc-env` lines nn-linux's, aya-obj its
    dev-dependency, bytemuck its dependency); file integrity monitoring
    whole, `fim/mod.rs` with the watched paths' loader on `LinuxHost`
    (100 %; `attach.rs` lands on R09a's cut of it: its two functions
    back in place, a rename with `git diff -B`, 96 %); the network drain
    and the blind spots (100 %), with the flow tracker's and the rules'
    gate's binding to `LinuxHost`, which the drain names, now nn-linux's
    (`net::{flow_tracker, limiter}`; the agent's `net` re-exports
    them); the decoys' path policy (100 %). Then the DNS record's
    decode, from nn-model to the DNS sensor
    (`sensors::dns_sensor::{query_event, nss_query_name}`: the
    `From<&DnsQueryRaw> for Event` as a function — a `From` between two
    other crates' types cannot be written in nn-linux — and
    `nss_query_name`, verbatim, `alloc::` paths std's, their six tests):
    nn-model drops nn-parse, and the module map no longer allows that
    arc. The moved files change where the crate boundary needs it: the
    items the agent's exec guards name become `pub`
    (`exe_identity::verifier_tail`, `open_sensor::unescape_octal`,
    `RejectThrottle` with `new` and `record`, which derives `Default`:
    clippy's `new_without_default` on a public type), the admin socket's
    tests' stand-in for the kernel's watched inodes
    (`WatchedPathsHandle::fake`) is behind nn-linux's `test-util`, and
    nn-linux's shims give the moved code its paths (`path_text`,
    `config`, `net::blocklist`, the posture's `PostureMachine` and
    `lineage::AuthSessionTracker` on `LinuxHost`; its rotating writer
    signs with the agent's key unless told otherwise outside its tests
    too). Every `unsafe` block moved verbatim with its `SAFETY` comment.
    The agent keeps every path as a shim (`sensors.rs`, `pub use
    nn_linux::fim`, `net/mod.rs`, `canary/mod.rs`, `boot`, removed in
    R17); `main.rs`, the admin socket, the tests, the replays, the
    examples and the fuzz targets are unchanged. CI's ebpf-build runs
    the embed's map-type test where it lives (`-p nn-linux`: filtered on
    the agent it would have matched nothing and passed); path_liveness
    no longer exempts `agent/build.rs`; the module map's scan floor goes
    from 100 files to 50 (102 scanned on `main`, 82 now). Last, what
    names the embed's
    old place: the build script's comment on the root, its message when
    `NN_REPO_ROOT` is missing, `cargo:rerun-if-env-changed`, the root
    normalised (cargo gives `<repository>/.`; collected by components,
    the paths the refusals print read as before), and the script's path
    in its three refusals' banner line; the two loaders' error on a
    placeholder object; the doc comments of the moved files,
    ebpf-guard's, xtask's, install.sh's, the lab's; and the docs' links
    rustdoc no longer resolved in nn-linux. Ratchet 26 → 22: nn-linux
    3 → 0 (the sensors left with their references to `boot`), nn-core
    15 → 14 (`net/mod.rs` names `LinuxHost` no more; it keeps one
    reference, to nn-linux), nn-admin 8.
  - Deviations from the plan: the decode of `Raw` into `Event` moved
    where it removes an arc — the DNS record's, nn-model's one use of
    nn-parse; the arc nn-model → nn-wire stays (the other decodes need
    only nn-wire and the model, whose own vocabulary maps ABI bytes
    nn-core's rules read: the exploit guard's kinds and syscall tables,
    `FsProtectOperation::from_wire`, the io_uring classes, the module
    path's marks, `ExeIdentity::from_raw`; moving their `From`s would
    rewrite every pump and nn-core's R018 tests for no arc removed).
    Post-plan parts moved to let the sensors go: the boot's phases,
    permit, degradations and sensor list (lab PR 218's `boot`, mapped to
    the agent: the rest stays) and `telemetry_probe::PROBE_DIR` (R09c's
    module). The exec quarantine and the exec policy (post-plan,
    nn-linux's by the map) stay in the agent behind `ExecGuards`: their
    records need the detection sink and payloads, not moved yet.
    `verifier_check` and `sensor_feasibility` (lab-only, nn-linux's by
    the map) stay in the agent and read the embed through its shim.
    §4.1 rule 1's 95 %: `sensors/mod.rs` (84 %, `main`'s bytes) and
    `fim/attach.rs` (onto an existing path) as above. The canary store
    and `btf-matrix.yml` were R09a's (lab PR 253); the btf-matrix path
    filter needs no change (`--btf-check` runs `btf_offsets` and
    `btf_revalidate`, neither moved here). The staleness guard's three
    refusals name the build script where it is now
    (`crates/nn-linux/build.rs`), the rest of each message the same
    (accepted). The scanner and the watchdog are no longer
    byte-identical after the decode's move (nn-model's metadata, the
    `TypeId`s of its types; the same code function by function:
    accepted). No separate rewrite commit and no
    `.git-blame-ignore-revs`: no importer was rewritten.
  - Open: R09c (`host_hardening`, `self_integrity`, `systemd_state`,
    `telemetry_probe`, `sensor_feasibility`, `install_manifest`) and
    `verifier_check`; the exec guards to nn-linux once their records
    can follow (then `ExecGuards` goes); the `boot` the agent keeps
    (R11a's phases); the nn-core shims that bind nn-core's generics to
    `LinuxHost` and the test doors, until R17; the comments of
    `agent-ebpf/` and `common/` (the object's source closure), of the
    embedded systemd unit and of `main.rs` that name the old paths;
    `cow::fanotify::tests::own_threads_and_tgid`, which failed once in
    this lot's gates under load (it reads `/proc/<tid>/status` after
    `/proc/self/task/<tid>`, and a thread id another test's thread
    reused and released in between gives `None`; it passes alone and
    in the other runs; agent code this lot did not touch): a known
    flake, its own fix.
  - Lab: Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU), its disk freed first: 94 % used (27 of 29 GB, 1.8 GB free) → 21 % (5.8 GB used, 23 GB free), only the checkout's `target/` removed (21 GB the lots accumulated: 12,582 files in `release/deps`, 28,352 of them root's from the `sudo` test runs; lab PR 253's stray `target-unstripped/` was gone already), `/var/lib/northnarrow` untouched. The lot's code (2a45e96; the final tree differs in the build script's root normalisation and in doc comments only) synced, built (release, test-privileged,debug-trigger, from the empty `target/` in 1 m 46 s) and installed (`nn-lab.sh sync`, `build`, `install`): `verifier-check` 77 programs, 77 OK (the embedded object; 105 offsets from the live BTF, 5 differing from the build kernel, 0 absent); `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs): 75 suites, 84 passed, 0 failed — `main`'s totals —; `tamper-check` 72 of 75 OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (lab PR 215's stale own link id) the recorded deviation —; `net-check` 13 PASS, 0 FAIL; `fim-reuse-check` PASS. `main` 482a956 on the same guest right after, synced, built and installed the same way: `verifier-check` the same table, row for row, and the same offsets; `tamper-check` the same 75 outcomes and verdicts, case by case (C38's PIDs aside): 72 of 75 OK, the same two gaps and the same deviation; the evidence of 7 cases differs by the host's events in a case's window — the self-integrity watcher's jittered rounds (`integrity_drift`, `unit_shadowed` and their clearing), a `modprobe` systemd ran (R011 in the tip's C12), the journal's error count ±1 —, which the other run saw at other cases or not at all; `net-check` the same 13 PASS lines and the same negative run (2 NN-L-CHAIN-008 and 1 NN-L-NET-006 records), MS04B's open-flow snapshots 0 → 1 on `main`, 0 → 2 on the tip (how many of the snapshot interval the hold fits); `fim-reuse-check` PASS. `upgrade-check` from that `main` to the lot's final code: `install.sh` without `--upgrade` refused while the units were active; with `--upgrade` and the lab's admin key the trusted-installer window opened, both units stopped, the pins dropped and NorthNarrow's BPF programs unloaded, both units started, "UPGRADE complete — health check passed"; a new agent pid and a new `agent_boot` (audit log 4,518 → 4,525 lines), the identity files the same (`admin.pub`, `agent.sig.pub`, `agent_id`), 19 of 19 deny hooks, 36 own LSM programs before and after, no foreign one. Every boot's signed capability manifest on that guest — the lot's code 17 boots (the install, the e2e fixtures' and the tamper-check's restarts), `main`'s 7, the upgraded one — is the same document but its time and hashes: kernel and BTF (116 offsets resolved, 5 drifted, none absent), BPF LSM active, 19 of 19 deny hooks, the deny self-test denied, the BPF guard observing (a debug-trigger lab build), the same nine sensors on the same attach points (exec on LSM `bprm_check_security`, file open on LSM `file_open` through the FIM observer, the ten FIM observers, DNS on `udp_send_skb` + `udp_v6_send_skb` with no NSS module, io_uring create + `submit_req`, the network flows' kprobes and `tcp_close` fexit, process spawn, TCP connect), the host hardening table, no degradation, trust level L3. Ubuntu 22.04 (5.15.0-198, ssh 2522) and Debian 12 (6.1.0-54-cloud, ssh 2422; free once lot 255 had stopped it): the lot's tree and `main`, each synced, built and run through `verifier-check`: the same table on each kernel, row for row — 77 programs, 75 OK, the two ACL deny hooks absent from the kernel (`inode_set_acl`, `inode_remove_acl`, optional), 0 failing — and the same offsets (5.15: 105 resolved, 45 differing, 2 absent; 6.1: 105, 40, 0). The guests powered off after. The staleness guard, end to end on `main`'s tree and the lot's (scratch checkouts, `cargo check` of the embedding crate, every file restored with `cp -a` and touched): a fresh object embeds; a line appended to `common/src/lib.rs` or to `agent-ebpf/src/main.rs` refuses "STALE eBPF OBJECT"; a byte appended to the object refuses "DOES NOT MATCH ITS STAMP"; no stamp refuses "UNSTAMPED eBPF OBJECT"; no object builds the placeholder (`NN_EBPF_EMBEDDED=0`, the warning) the boot preflight refuses; fresh again embeds — the same verdicts and the same messages, line for line, but the panic's location and the script's path in the banner line. Host, on 12b5e7a (the lot's code; the commit after it changes documentation only), `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo, whose output is `main`'s line for line); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,067 passed, 0 failed, 15 ignored (an earlier run of the same gates on the same code under load had one failure, `cow::fanotify::tests::own_threads_and_tgid`, the flake noted above; it passes alone and in every other run); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets; every one of the lot's commits checked (`cargo check` of the workspace and of the agent with the privileged features, `fmt`, the module map, path liveness and layer tests): all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's; the exemption facts' 2, nn-linux's; the signed overlay's and the fuzz seeds' tests). Identity against `main` 482a956, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical, its stamp too (source 235e2fed…: the agent embeds `main`'s build hash); after the path policy's move (500e3cd) the scanner (401,368 bytes) and the watchdog (2,337,080) were byte-identical, stripped and unstripped; the decode's move makes them differ — nn-model dropped nn-parse, which changes its metadata hash and with it the `TypeId`s of its types and the order of the symbols: function by function (unstripped, names mapped to the new crates and modules, addresses and rip-relative targets dropped, trailing padding dropped) the scanner's 504 functions are the same code and the watchdog's 2,468 of 2,470 (`downcast_raw` of the log subscriber and `main`'s closure differ by the 128-bit `TypeId` constants of nn-model's types only); stripped they are 401,384 and 2,337,064 bytes (`.text` ±16 bytes of alignment) — accepted: their SBOMs drop nn-parse and md-5, which they never used. `mk-tarball.sh`: the same 72 entries, paths and modes; `mk-packages.sh` (.deb): the same 79 paths and modes; `posture_demo` the same lines; `nn-admin policy test`, `main`'s binary and the tip's on lab PR 251's samples (the 24 golden cases under the built-in defaults and three candidate policies, with the shipped lists and with none, as a table and as JSON, and every case's events as one stream, plain and wrapped): the 402 outputs are the same bytes; the test list is `main`'s — 3,082 names, every one found, 220 now nn-linux's (438 → 658 there; the agent's library 830 → 616, nn-model's 47 → 41), 7 at a new path (the weakening test in the agent, the DNS decode's six in the DNS sensor); no test added or removed, no `#[ignore]` added. The agent (15,192,112 → 15,276,256 bytes) and nn-admin (4,129,480 → 4,130,440) are not byte-identical. Function by function: the agent 7,705 of 7,992 the same code (147 differ, 140 and 106 unpaired), nn-admin 3,528 of 3,604 (30; 46 and 22). Of the agent's 147: 105 call other callees (inlining at the new crate boundary — the loader's pumps, the drains' and the FIM's record paths, the nn-core generics bound to `LinuxHost` they call), 22 schedule or allocate registers otherwise, 14 have the same instructions with other operands (10 of them clap's `try_remove_one` and `from_arg_matches_mut` and the log subscriber's `downcast_raw`: `TypeId` constants), 5 names have several bodies; nn-admin's 30: 16, 7 and 7. The unpaired are generic code instantiated in the other crate (anyhow's errors and context, serde_json's (de)serializers, tokio's task harness of the exploit guard's pump, drop glue) and code inlined on one side only (`execq::install`, `execq::fail`, `execpol::install`, `execpol::fail`, out of line on `main`, inlined into `AgentExecGuards::install`, which is out of line): `.text` +81,872 bytes in the agent (+1.09 %), +2,000 in nn-admin (+0.06 %); `.rodata` +1,792 and −64. `cargo doc --workspace --no-deps`: 336 warnings, `main` 337 (the one gone: the link to `RejectThrottle`, public now); none new.
- **Lab PR 257 — nn-linux, part 3: the hardening, the integrity checks
  and the systemd integration leave the agent (Wave 4 Phase 2, R09c of
  the restructure plan; no level changes).**
  - What was wrong: after R09b (lab PR 254) the agent still held the
    Linux adapters the plan gives R09c (§2.4): the host hardening checks
    (`host_hardening`, which xtask's `operator_docs.rs` reads), the
    self-integrity watcher (`self_integrity`), what systemd reports the
    host as (`systemd_state`), the telemetry probe (`telemetry_probe`),
    the lab's sensor feasibility runner (`sensor_feasibility`) and the
    install manifest's boot check (`install_manifest`); and, nn-linux's
    by the module map beside them, `sd_notify` (§2.4), the shutdown
    marker's file I/O (§2.4), and the post-plan `process_hardening` (lab
    PR 216), `audit_preflight` (lab PR 241), `upgrade_rollback` (lab PR
    220) and `verifier_check` (lab-only), which R09b left reading the
    eBPF embed through the agent's shim. R09a and R09b had cut ahead the
    pieces their moves named (the findings' op and the self-checks'
    jitter; the probe files' directory). Ratchet 22: nn-admin 8, nn-core
    14, nn-linux 0 — none of the 22 is an arc of these modules: what
    names them (nn-admin's `host-check` names `host_hardening`) counts
    for nn-linux wherever they are.
  - What changed, one commit each, bottom-up (§4.1 rule 3): the test of
    `install_manifest` that reads the agent's fuzz fixture (`fuzz_api`,
    WDG-R05) cut verbatim into the agent (`install_manifest_tests.rs`,
    with a copy of the manifest helper it uses), so the move is a move.
    The integrity watcher names two parts of the agent's overlay gate
    (`config::overlay_auth`), which stays (R09a: it waits on R04b): the
    lookup of the shipped COMBAT defaults (`shipped_default`, ATP-001 /
    DEP-003) cut verbatim to nn-linux's `anti_tamper::network_isolate`,
    beside the three rulesets it returns, the gate re-exporting it; and
    the gate itself, whose `is_signed` tells a signed `config overlay
    set` from an edit — the seam is R09a's, nn-core's
    `config::overlay_auth::Vouch`, which takes `is_signed` beside
    `verified` (the gate answering with its own), the watcher holding an
    `Arc<dyn Vouch>` and `spawn` taking the `Arc` of any `Vouch`, as the
    isolator's `with_overlay_gate` does: `main.rs` is unchanged. Then
    the moves to `crates/nn-linux` (`git mv`): the systemd integration
    (`systemd_state`, `sd_notify`; 99 %, 100 %), the install manifest's
    check (100 %), the hardening (`host_hardening`, `process_hardening`;
    100 %, with xtask's `operator_docs.rs` and `path_liveness.rs`
    reading the checks' new path), the telemetry probe onto R09b's cut
    of it and the watcher onto R09a's (99 %, a rename with `git diff
    -B`: the cut items back in place, so each file is `main`'s of before
    the cut but the seam), the files around the start and stop
    (`audit_preflight`, `shutdown_marker`, `upgrade_rollback`; 100 %),
    the lab builds' probes (`sensor_feasibility`, `verifier_check`; 100
    %) behind the features they had, nn-linux's now (`test-privileged`,
    `debug-trigger`), which the agent forwards from its own (§4.1 rule
    4): a release build compiles neither, a lab build both. The moved
    files change where the crate boundary needs it and nowhere else:
    `systemd_state`'s padding reads `!buf.len().is_multiple_of(align)`
    (clippy's `manual_is_multiple_of`, which the agent's manifest allows
    and the workspace lints do not; its callers pass 4 and 8), and two
    comments name the agent's parts as the agent's (the removed
    advisor's settings, the event loop). What they name of nn-core's and
    nn-evidence's resolves through nn-linux's shims, as in the agent —
    `config::overlay_auth` is a module now, nn-core's items with the
    shipped defaults' lookup. Their statics (the probe's round tracker
    and gap count) moved, never copied. `upgrade_rollback`'s row names
    `env!("CARGO_PKG_VERSION")`, nn-linux's now: the workspace's
    version, as the agent's. Every `unsafe` block moved verbatim with
    its `SAFETY` comment (32 blocks, each with the same four lines
    before it as on `main`; the lab-only probes' 17 carry 4 comments, as
    on `main`). The agent keeps every path as a shim (`pub use
    nn_linux::…` in `lib.rs`, the two lab probes under their `cfg`,
    removed in R17); `main.rs`, the admin socket, the tests, the
    replays, the examples and the fuzz targets are unchanged.
    `install.sh`'s comments and the module map name the new places.
    Last, the ratchet: R09c's moves leave it at 22, and one arc of
    nn-admin's is a constant of the admin protocol —
    `detection_store::DEFAULT_DETECTIONS_LIMIT` (50), what `limit = 0`
    means in the `detections` verb's `DetectionsExtra` — cut verbatim to
    nn-proto's `admin_signed_payload`, `detection_store` re-exporting it
    and nn-admin's clap default naming nn-proto's. Tests: 89 moved with
    their code and run in nn-linux (658 → 747; the agent's library 616 →
    527, 1 of them at a new path), the lab probes' 8 in its lab-feature
    build; none added or removed. nn-linux takes no new dependency; no
    lockfile changed. Ratchet 22 → 21: nn-admin 8 → 7, nn-core 14,
    nn-linux 0.
  - Deviations from the plan: R09c's list is done, and more moved with
    it: the modules the map gives nn-linux that sit beside the integrity
    checks — `sd_notify` and the shutdown marker's file I/O (§2.4, in no
    R09 list), `process_hardening`, `audit_preflight`,
    `upgrade_rollback` and `verifier_check` (post-plan). The boot's deny
    self-test, BPF LSM gate, trust level and signed capability manifest
    stay in the agent: the plan gives the boot to the agent (§2.4,
    `main` → `boot/*`, R11a's typed phases) and the manifest to the
    sensor contract (R13), not to R09c. `shipped_default` went to
    nn-linux, not with the rest of the overlay gate to nn-core (§2.4):
    what it returns is the network isolator's, nn-linux's. The ratchet's
    one decrease is an arc of R10's (nn-admin's), not an R09c module's:
    R09c's had none. No separate rewrite commit and no
    `.git-blame-ignore-revs`: no importer was rewritten.
  - Open: the exec guards (`execq`, `execpol`, behind R09b's
    `ExecGuards`), `cow`, `detection_store` — nn-linux's by the map —
    and the agent's boot (R11a); nn-admin's 7 arcs (R10: `host-check`
    names `host_hardening`, the identity file, the OS RNG, the chain
    list, `anti_tamper`'s role list parse and the trusted-installer
    window's ceiling); `epg_tests.rs` (lab PR 254's cut, which reads
    `self_integrity::WEAKENING_ENV`) could return to `sensors::epg` now
    that both are nn-linux's; the comments of `agent-ebpf/` and
    `common/` that name `agent/src/sensor_feasibility.rs` (the eBPF
    object's source closure, whose stamp must not change); R04b's split
    of `admin_auth`, then the overlay gate and the rollback floor to
    nn-core; the shims, until R17.
  - Lab: Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU; no other guest up), its disk at 29 % (8.0 of 29 GB used; the checkout's `target/` 2.2 GB: nothing to free). The lot's code (af7f643) synced, built (release, test-privileged,debug-trigger) and installed (`nn-lab.sh sync`, `build`, `install`): `verifier-check` 77 programs, 77 OK (the embedded object; 105 offsets from the live BTF, 5 differing from the build kernel, 0 absent); `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs): 75 suites, 84 passed, 0 failed — `main`'s totals —; `tamper-check` 72 of 75 OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (lab PR 215's stale own link id) the recorded deviation. `main` 8738784 on the same guest right after, synced, built and installed the same way: `verifier-check` the same table, row for row (instruction counts and stack included), and the same offsets; `tamper-check` the same 75 outcomes and verdicts, case by case (C38's PIDs aside): 72 of 75 OK, the same two gaps and the same deviation; the evidence of 6 cases differs by what landed in a case's window — the self-integrity watcher's jittered rounds (an `integrity_drift` or its clearing in C02, C19, C20, C34), the overlay rollback floor's anchor (written once 256 entries verified since the last, at the tip's C24 boot), rsyslog's rotation and a `modprobe` systemd ran (FIM-005 and R011 in the tip's C25) —; over each run the self-integrity findings are the same, kind by kind and count by count: two unit drop-ins, two shadowed units, two unexpected limits, two mounts over protected paths (the random temporary directory of C14's aside) and a second bpffs, each found and cleared, the watchdog gone and the agent stalled; at boot the lab's admin key on the host, and C23's unsigned overlay as `config_overlay` and `unauthorized_overlay` while C24's signed one is no drift — the gate's `is_signed` through `Vouch` and the shipped defaults' lookup, now nn-linux's, decide as on `main`. `upgrade-check` from that `main` to the lot's code: `install.sh` without `--upgrade` refused while the units were active; with `--upgrade` and the lab's admin key the trusted-installer window opened, both units stopped, the pins dropped and NorthNarrow's BPF programs unloaded, both units started, "UPGRADE complete — health check passed"; a new agent pid and a new `agent_boot` (audit log 4,804 → 4,811 lines), the identity the same, 19 of 19 deny hooks, 36 own LSM programs before and after, no foreign one. What the agent hashes and checks at boot gives `main`'s verdicts: every boot of the installed agent on that guest — the lot's 11 (the install, the e2e fixtures' and the tamper-check's restarts), `main`'s 7, the upgraded one — verified its own binary, the watchdog, nn-admin, the scanner and the embedded eBPF object against the install manifest ("binary integrity verified", `checked=5`, provenance `source-tree`) and signed the same capability manifest but its time and hashes: kernel and BTF (116 offsets resolved, 5 drifted, none absent), BPF LSM active, 19 of 19 deny hooks, the deny self-test denied, the BPF guard observing (a debug-trigger lab build), the same sensors on the same attach points, the same host hardening table (11 checks, each the same status and value), no degradation, trust level L3; the e2e fixtures' own agents, run from the build tree (`not-applicable`), are not the installed one. Each boot's chain check flags the guest's detections log (entries under another key: the e2e fixtures' agents write the same file, which lot 256 isolates), on `main`'s boots as on the tip's. The guest powered off after. Host, on af7f643 (the lot's code; the commit after it changes documentation only), `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo, whose output is `main`'s line for line); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 70 suites, 3,067 passed, 0 failed, 15 ignored; `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets; every one of the lot's commits checked (`cargo check` of the workspace and of the agent with the privileged features, `fmt`, the module map, path liveness and layer tests): all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19: 13 nn-linux's now, the install manifest's two and the watcher's overlay digest with the vault's ten), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's; the exemption facts' 2, nn-linux's; the signed overlay's and the fuzz seeds' tests). Identity against `main` 8738784, both built in one temporary checkout (same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 58daf6d9…), its stamp too (source 235e2fed…: the agent embeds `main`'s build hash, the one the install manifest records); the scanner (401,384 bytes) and the watchdog (2,337,064) are byte-identical, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes, the three SBOMs the same components and edges (agent 145, scanner 59, watchdog 112); `mk-packages.sh` (.deb): the same 79 paths and modes; `posture_demo` the same lines; `nn-admin policy test`, `main`'s binary and the tip's on lab PR 251's samples (the 24 golden cases under the built-in defaults and three candidate policies, with the shipped lists and with none, as a table and as JSON, and every case's events as one stream, plain and wrapped): the 402 outputs are the same bytes; the test list is `main`'s — 3,082 names, every one found, 89 now nn-linux's (658 → 747 there; the agent's library 616 → 527), 1 at a new path (the fuzz fixture's test in the agent); no test added or removed, no `#[ignore]` added. The agent (15,276,288 → 15,282,760 bytes) and nn-admin (4,130,440 → 4,149,576) are not byte-identical. Function by function (unstripped, names mapped to the new crate — the watcher's task is the third closure of the now generic `spawn`, the second on `main` —, addresses and rip-relative targets dropped, trailing padding dropped): the agent 7,856 of 7,958 the same code (89 differ, 13 and 18 unpaired), nn-admin 3,555 of 3,580 (21; 4 and 27). Of the agent's 89: 72 call other callees (inlining at the new crate boundary — the watcher's rounds and readers, the probe's audit, the systemd reader, the overlay gate's read with the shipped defaults' lookup in the other crate, `main`'s `run`, generic code on `LinuxHost` and serde_json's instantiated in nn-linux), 10 schedule or allocate registers otherwise and 5 have the same instructions with other operands — 13 of those 15 the watcher's task and its tokio harness, whose state holds the gate as an `Arc<dyn Vouch>`, a wider pointer —, one name has two bodies; nn-admin's 21: 14 call other callees (the gate's `check`, the host check's parse of the install manifest, the chains' readers, serde_json), 5 scheduling, one name with two bodies. The unpaired are generic code instantiated in the other crate (serde_json's value parser and its drop glue, the canary readers' `flat_rows`) and code inlined on one side only (`jittered` out of line on `main`; the watcher's `collect_round`, the overlay read on `LinuxHost`, `UnixStream::read_exact` out of line on the tip), and one new function, the gate's `Vouch::is_signed`: `.text` +5,872 bytes in the agent (+0.08 %), +16,848 in nn-admin (+0.51 %: serde_json's generic deserializer instantiated again in nn-linux for the host check's install manifest); `.rodata`: the same text but the callsite lines (`event <file>:<line>`) of the four edited files and literals grouped otherwise. The documentation commit builds the same four binaries as the code commit, byte for byte. `cargo doc --workspace --no-deps`: no warning the tree did not have.
- **Lab PR 258 — three flaky host tests made deterministic (Wave 4; the
  flakes lab PRs 254 and 256 recorded and lab PR 234's hotfix saw; no
  capability, no level changes).**
  - What was wrong: nn-linux's
    `response::quarantine::tests::a_corrupt_index_is_rebuilt_from_the_meta_files`
    (lab PR 256: 6 of 18 runs on `main` 482a956). The quarantine kept
    the repairs of a vault's index (external audit CMB-017) in
    `INDEX_NOTES`, one list for the process, and every executor's
    `record_quarantine` took all of it, even for a refused quarantine
    that touched no vault: the COMBAT actuator's NEUTRALIZE tests, with
    an executor and a vault of their own, took the test's note between
    its repair and its read (`[]`). On `main` 48228ad the crate's suite
    no longer runs the two modules side by side (0 of 50 runs fail at
    the default threads); run together, their tests fail 161 of 200.
    The agent's `cow::fanotify::tests::own_threads_and_tgid` (lab PR
    254): it asked `/proc/self/task/<tid>` about a thread `join` had
    returned for, then read `/proc/<tid>/status`. `join` returns once
    the kernel has cleared the thread's tid (`CLONE_CHILD_CLEARTID`, at
    `exit_mm`), before it releases the task (`release_task`): listed at
    the first read, released at the second, `None`. Not a reused tid, as
    lab PR 254 thought: thread ids are handed out cyclically up to
    `pid_max` (4,194,304 here). The watchdog's
    `sd_notify_reaches_an_abstract_notify_socket` (lab PR 234's hotfix
    saw it fail under load): it closed its listener and expected the
    next `READY=1` refused ("nobody listens any more"). The crate's
    other tests spawn children (`sleep`, `sh`); a fork or a
    `posix_spawn` copies every descriptor of the process into the child,
    which holds them until its exec closes them (`CLOEXEC`), so the
    listener's socket outlived the test's close and took the datagram.
    Two more tests have that race: the watchdog's
    `nothing_listening_at_the_path_is_absent_not_unresponsive` (a stale
    stream socket; it failed 7 times in this lot's runs, `NotTheAgent`:
    the socket served by the test's own process) and nn-linux's
    `sd_notify::tests::ready_reaches_an_abstract_notify_socket` (the
    agent's until lab PR 257; not seen failing).
  - What changed: `INDEX_NOTES` is keyed by the vault's directory;
    `take_index_notes(quarantine_dir)` takes that vault's notes, and the
    executor takes its own config's. Production is unchanged: the agent
    builds one `ExecutorConfig`, its executor's, and the exec quarantine
    holds a clone of it — one vault, its repairs recorded in the signed
    audit log at the same quarantine as before. A new test,
    `an_index_repair_is_taken_by_its_own_vaults_executor`: another
    vault's executor records a refused quarantine (PID 0) and leaves the
    repair to its own vault; the flaky test also asserts that its vault
    starts without a note and that the note is taken once. The fanotify
    test reads the exited thread's `status` first, then its listing (the
    same assertion): the release goes one way, so a thread still listed
    had its `status` when it was read; and it looks at a thread it holds
    first — listed, its thread group this process, its tid not the
    process's pid. The three socket tests shut the socket down before
    they close it (`shutdown(SHUT_RDWR)`): a shut-down Unix socket
    refuses a datagram (`EPIPE`) or a connection (`ECONNREFUSED`)
    whoever still holds a descriptor of it. No sleep, no assertion
    weakened; no other product code changed.
  - Open: `pidfd_wakeup_latency_stays_in_sub_millisecond_budget`, the
    watchdog's 5 ms budget for a pidfd wakeup, failed in 5 of these
    loops' runs (1 on `main`, 4 on the lot's tree; 5.2 to 8.3 ms) — a
    latency budget under load, not a race, in code this lot did not
    touch; the agent's canary deploy test (`admin_socket.rs`) takes a
    free port by binding and closing a listener, the race above if a
    spawning child holds the copy while the deploy reads
    `/proc/net/tcp` (not seen failing).
  - Lab: Host only (the tests are host unit tests; no guest), WSL2 Ubuntu 24.04 (6.18.33.2-microsoft-standard-WSL2, 24 logical CPUs, 23 GiB), `CARGO_BUILD_JOBS=4`. Every loop under the same load: the workspace suite (`cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast`) back to back beside it, all of it started under `nohup` (whose ignored SIGHUP fails xtask's `the_aws_fixture_puts_back_what_it_found` in each of those background runs — the harness's; it passes in a plain shell and in the gates below). Before on `main` 48228ad, after on the lot's tree, the same two batches: batch 1, side by side, `cargo test -q -p nn-linux --lib --locked` 50 times, `-p northnarrow-watchdog --lib` 300 times and `-p northnarrow-agent --lib` 50 times: the quarantine test 0/50 → 0/50 failed, the sd_notify test 7/300 → 0/300 (the stale-socket test 2/300 → 0/300), the fanotify test 1/50 → 0/50; batch 2, side by side, `cargo test -q -p nn-linux --lib --locked -- combat::actuator response::quarantine` 200 times, `-p northnarrow-agent --lib --locked -- cow::` 1,000 times and `-p northnarrow-watchdog --lib --locked` 1,000 times: the quarantine test 161/200 → 0/200 (each failure `[]`, the note taken), the fanotify test 47/1,000 → 0/1,000, the sd_notify test 19/1,000 → 0/1,000 (the stale-socket test 3/1,000 → 0/1,000). No other test failed in those loops but the pidfd budget (0 → 4 of batch 1's 300 watchdog runs, 0 → 0 in batch 2). On `main` c0aa0c3, before lot 257 merged: batch 1 3/300 (sd_notify) and 2/50 (fanotify), the quarantine test 0/50, and 0/50 at `--test-threads=128`; the fanotify test alone (`cargo test -p northnarrow-agent --lib cow::fanotify::tests::own_threads_and_tgid`) 0/1,000; the watchdog's lib 18/1,000 (the stale-socket test 2, the pidfd budget 1). Diagnostics, the tests' reads in a loop of their own: 1,000,000 spawns and joins of a thread, half in each order — the thread still listed right after `join` 496 times and the assertion false 355 times in the test's old order, 53 and 0 with the `status` read first (200,000 more, the same halves: 90 and 62, 15 and 0); 3,000 abstract datagram sockets closed while four threads spawn `/bin/true`: 13 datagrams taken after the close, none after `shutdown` (21 `EPIPE`, 2,979 `ECONNREFUSED`); 3,000 stream sockets the same: 228 connections taken, none after `shutdown` (3,000 `ECONNREFUSED`). The new quarantine test with every vault under one key, as `main`'s one list: fails 5 of 5 runs (the other vault's executor takes the note). Host, on cf5e4e2b (the lot's code and documentation; this line is all that changed after it), in a plain shell, `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s: `common` and the eBPF crates untouched); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --all -- --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` three times, each 71 suites, 3,084 passed, 0 failed, 15 ignored (`main` 48228ad: 3,083, the new quarantine test the one more); `cargo xtask golden` (11 passed); `cargo +1.89.0 check --workspace --all-targets --locked`: all pass.
- **Lab PR 259 — nn-admin: the operator client leaves the agent (Wave 4
  Phase 2, R10 of the restructure plan; no level changes).**
  - What was wrong: nn-admin, the operator client's crate (R01, lab PR
    239), was empty. The `nn-admin` binary's code was the agent's:
    `admin_cli` (the library half) and the logic of `bin/nn_admin.rs`
    (the dispatcher), which named the agent's library for the rest, so
    the operator client was built on the agent's whole crate graph
    (aya, tokio, procfs, the eBPF embed). Ratchet 21: nn-admin 7 —
    `admin_cli` → `agent_id`, `chains`, `os_rng`; `nn_admin.rs` →
    `agent_id`, `anti_tamper` (the trusted-installer window's ceiling,
    the role list's parse), `chains`, `host_hardening` — and nn-core
    14. Under the count, through paths the map gives allowed crates,
    nn-admin also named what is still nn-linux's or the agent's: the
    agent key's files (nn-linux's `keys`, under the agent's `audit`),
    the overlay gate and its rollback floor and the loaders' checks of
    an overlay (`config`, the agent's until R04b), the offline engine
    on the Linux host (`decision::replay`), the shipped COMBAT defaults.
    Lab PR 239 left "nn-admin → nn-linux for the host checks" to R10.
  - The decision: no nn-admin → nn-linux arc. The plan draws nn-admin
    beside nn-linux, both below the agent (§2.1), and says that after
    R10 nn-admin needs "nn-proto, nn-evidence, nn-core and the host
    checks" (§2.2); the module map's rule for it (lab PR 239) has no
    nn-linux, and no lot has loosened a rule. A seam was needed in any
    case: what nn-admin reads of the agent itself — the list of its
    chains (the payloads are the agent's and nn-linux's), the gate and
    its floor, the loaders' checks — cannot be reached through nn-linux
    either (nn-admin cannot depend on the agent: the agent package
    carries the binary, a package cycle). An arc to nn-linux would only
    have shrunk that seam, at the price of the layering and of a library
    that builds aya, tokio, procfs and the eBPF embed for an operator
    client (and a `chain verify` that cannot be built off Linux). So
    the host checks come through the composition: the agent binds
    nn-admin to its host as it binds nn-core's generics to `LinuxHost`.
    nn-admin is not a pure crate (a Unix socket, `std::os::unix`, libc's
    open flags), and stays out of `portable-core`.
  - What changed, one commit each, bottom-up (§4.1 rule 3): the
    trusted-installer window's ceiling (`MAX_TRUSTED_INSTALLER_WINDOW_SECS`,
    what the agent clamps a grant to and nn-admin clamps `--window-secs`
    to) cut verbatim to nn-core's `anti_tamper::trusted_installer`,
    beside the window's vocabulary R08b put there, nn-linux's module
    re-exporting it; nn-admin's `--new-roles` names nn-proto's
    `admin_quorum::parse_role_list`, which nn-linux's `admin_auth` wraps
    (the same text). nn-admin's read of the identity file
    (`agent_id::load_existing`, MAIN-010: nn-admin was its one caller)
    moved from nn-linux to nn-admin's own `agent_id`, the all-zero rule
    both reads take (MAIN-009) cut from nn-linux's `agent_id::parse` to
    nn-proto's `shutdown_marker::parse_minted_agent_id`, beside the
    format's parse the watchdog uses (a `String` error, the text the
    same); the two tests of nn-linux's `agent_id` that read both reads
    cut verbatim into the agent's `agent_id_tests.rs`. The OS CSPRNG
    (`os_rng`, lab PR 234) moved from nn-linux to nn-evidence (`git mv`,
    100 %), below nn-linux and nn-admin (`init`'s keys, the offline
    overlay signature's nonce): rand's portable `SysRng`, no OS crate
    named, the pure crates' rules and `portable-core`'s five targets
    hold; nn-linux re-exports it. The overlay signature file
    (`OverlaySignature`, its hex helpers, `SIG_SUFFIX`, `sig_path`) and
    the gate's `Decision` cut verbatim to nn-core's
    `config::overlay_auth`, beside the verified content R07 put there,
    the agent's module re-exporting them (unhex's `% 2 != 0` reads
    `is_multiple_of`, the workspace lints). Then the twelve tests of
    `admin_cli` that wire the agent's key, its audit log, its chains and
    its loaders cut verbatim into the agent's `admin_cli_tests.rs`, with
    a copy of the key-file helper they share (`read_overlay_for_signing`,
    which one calls, is public). Then the seam: `nn_admin::host::AdminHost`
    — the host's hardening checks (`HostChecks`), the agent key's files
    (the published public half, its path, the private key's parse), the
    agent's chains and where they lie under its state directory
    (`Chains`, implemented by the agent's `ChainPaths`; the layout
    `chain verify` built moved verbatim into the agent's implementation),
    the overlay gate and its floor (`OverlayGate`, `RollbackFloor`,
    implemented by the agent's types), the loaders' checks, the shipped
    defaults, the offline engine — each method the call the code made
    before, in the same place and order, implemented by the agent's
    `admin_host::AgentAdminHost`; `admin_cli`'s five functions that made
    them take the host or the chains, the dispatcher is generic over
    the host. Then the move (`git mv`): `admin_cli` 99 %, the
    dispatcher to nn-admin's `cli` 99 % (a rename with `git diff -B`:
    the binary's root stays, the shim `nn_admin::main(&AgentAdminHost)`).
    The moved files change only where the crate boundary needs it: the
    paths the binary named the agent's library by read `crate::`, the
    shadowed printing macros name `cli::emit`, `read_priv_key`'s owner
    check reads the effective uid through rustix's safe `geteuid`
    (nn-admin forbids unsafe code; the `process` feature the workspace
    already builds), the moved docs' links. The clap help texts, two of
    which name the agent's old paths, are unchanged. nn-admin takes the
    dependencies the code had, the same versions and features, and
    declares `debug-trigger`, which the agent forwards (§4.1 rule 4);
    the agent keeps `admin_cli`'s path (`pub use nn_admin::admin_cli`,
    removed in R17). xtask's `test_state_isolation.rs` reads nn-admin's
    flags from its `cli`. Tests: 44 moved with their code and run in
    nn-admin (`admin_cli`'s 26, the dispatcher's 18), 14 at a new path
    in the agent; none added or removed. Ratchet 21 → 14: nn-admin 7 →
    0 (the arcs to `anti_tamper` by the cut and nn-proto's parse, to
    `agent_id` and `os_rng` by the moves, to `chains` and
    `host_hardening` by the seam; the binary's root is the agent's
    composition now), nn-core 14.
  - Deviations from the plan: the shim takes the agent's host
    (`nn_admin::main(&AgentAdminHost)`, not `nn_admin::main()`): the
    host checks and the agent's parts come through the composition.
    More moved than R10's list: nn-admin's identity read (from
    nn-linux) and the OS CSPRNG (to nn-evidence); cut ahead: the
    window's ceiling, the all-zero rule, the overlay signature file and
    the gate's decision. The layout of the chains under the state
    directory is the agent's implementation's now (it names the agent's
    files). The tests of `admin_cli` that wire the agent stay in the
    agent. R10's follow-ups are not done here, as the plan has them:
    the private-key fallback's removal (§3.3; it is
    `AdminHost::verifying_key_of_signing_key` now) and the 18
    connect/challenge sequences' dedupe.
  - Open: those two PRs; the seam's methods that bind the agent's own
    parts go when those parts reach a crate below nn-admin (the gate,
    its floor and the loaders' checks with R04b and the post-plan
    content reaching nn-core; the chain list with the payloads, R04a/R05,
    and `detection_store`); two help texts name the agent's old paths
    (`northnarrow_agent::audit::verify_chain`, `…verify_chain_file`):
    output, kept in a move; the shims, until R17.
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; no other guest up), its disk at 29 % (8.0 of 29 GB used). The lot's code (fa4bc061) synced, built (release, test-privileged,debug-trigger) and installed (`nn-lab.sh sync`, `build`, `install`): `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs): 76 suites, 84 passed, 0 failed — lot 256's totals, `main`'s —, the 49 starts of the tests' agents that print their chain check `result="ok"`; `policy-check`: PASS (its 9 checks: MS-23 held built in, `policy set` of `enforce NN-L-IMP-001` stored and applied at once, a policy exempting by comm refused by nn-admin before signing, the kill, the signed policy at the next boot, back to the built-in defaults) — the signed `config overlay set` of the tip's nn-admin; `tamper-check` (its signed calls the tip's nn-admin's): 72 of 75 cases OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (lab PR 215's stale own link id) the recorded deviation. `main` 48228ad on the same guest right after, synced, built and installed the same way: `policy-check` the same 9 PASS; `tamper-check` the same 75 outcomes and verdicts, case by case (C38's PIDs aside): 72 of 75 OK, the same two gaps and the same deviation; the evidence of 6 cases differs by what landed in a case's window — the self-integrity watcher's jittered rounds (an `integrity_drift` or its clearing in C14, C19, C26, C39), the overlay rollback floor's anchor (written once 256 entries verified since the last, at `main`'s C20 boot), denials and an R011 of systemd's in `main`'s C25. `upgrade-check` from that `main` to the lot's code: `install.sh` without `--upgrade` refused; with `--upgrade` and the lab's admin key the trusted-installer window opened, the pins dropped and NorthNarrow's BPF programs unloaded, both units restarted, "UPGRADE complete — health check passed"; a new agent pid and a new `agent_boot` (audit log 5,061 → 5,068 lines), the identity the same, 36 own LSM programs before and after, no foreign one. The two nn-admin binaries, each built in the guest (main's and the tip's), against the upgraded agent, every command run main, tip, main again, as root from a root-owned directory (run from `/tmp`, where the lab's build leaves them, the agent killed them, as it must: R009_RootExecFromUserPath with R001 — a first attempt): 35 commands — `--version`, `--help`, `host-check` (and `--json`), `status` and `status --json` with and without `--key`, `capabilities` (and `--json`), `net status` (with and without `--key`, `--json`), `detections` (twice), `fim status|report`, `canary list`, `net listeners|flows|resolve`, `response status`, `verify-keys`, `audit verify`, `chain verify` (all and `--log audit`), `config overlay status`, `policy show`, `policy test` (table, JSON, without the shipped lists), and four error paths (a missing key, a missing socket, `debug force-posture`) — give the same stdout, stderr and exit status, byte for byte, but `--help`'s usage line, which names the binary (`nn-admin-main`, `nn-admin-tip`): the same bytes when both run under the same name. Every boot of the installed agent on that guest — the lot's, `main`'s, the upgraded one: 19 — verified its own binary, the watchdog, nn-admin, the scanner and the embedded eBPF object against the install manifest ("binary integrity verified", `checked=5`, provenance `source-tree`) and signed one capability manifest, the same but its time and hashes (BTF 116 offsets resolved, 5 drifted, none absent; BPF LSM active; 19 of 19 deny hooks; the deny self-test denied; the BPF guard observing; no degradation). Each boot's chain check flags the guest's detections log — lab PR 256's class, lines signed by another key (324 → 288 of the 5,212 → 5,140 lines checked, leaving the 4 MiB window: the e2e fixtures' agents of the lots before lab PR 256 wrote them; none added by this run) — on `main`'s boots as on the tip's. The guest powered off after. Host, on fa4bc061 (the lot's code) and again on the final tree (the documentation commit; this line is all that changed after that run), `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 71 suites, 3,083 passed, 0 failed, 15 ignored (`main`'s totals); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets (nn-evidence with `os_rng`'s rand); every one of the lot's commits checked (`cargo check` of the workspace and of the agent with the privileged features, `fmt`, clippy, the module map, path liveness, layer and state-isolation tests): all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19: nn-parse 1, nn-proto 2, the agent 3, nn-linux 13), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's; the exemption facts' 2, nn-linux's; the signed overlay's and the fuzz seeds' tests). The output matrix: 1,964 cases (every help text and nested one, clap's errors, `init`, `verify-keys`, `host-check`, `audit read|verify`, `chain verify` on chain-pin-v1's log and every class of lab PR 256, `config overlay status|sign|set`, `policy show|set|test` — the 24 golden cases and their 205 events as two streams, plain and wrapped, under the built-in defaults, the three golden candidates and one refused (it exempts uid 0), with the shipped lists and with none, as a table and as JSON: 520, and 16 error cases —, every socket verb against a mock agent with its success replies, the ten refusals and six transport faults and no socket: 647, the key and identity errors through every verb, closed pipes, the default paths), each with fixed fixtures (keys from constant seeds, chain-pin-v1's log and key, chains written by `main`'s chain code) in the same directory, under the same binary path and environment: `main`'s release binary and the tip's give the same stdout, stderr, exit status, files written and requests sent in 1,964 of 1,964 cases, `main`'s lab build and the tip's in 1,964 of 1,964 (`main`'s twice: 1,964 of 1,964); normalised alike on both sides, only after the value is checked: `init`'s fresh key, `config overlay sign`'s nonce and time, a floor reset now, `policy test`'s temporary `/proc`, the mock's view of nonces, times and signatures. Identity against `main` 48228ad, both built in one temporary checkout (the same path: the eBPF object carries its sources' absolute paths, and two checkouts gave two objects that differ in those strings only), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical (sha256 084ee12e… there), its stamp too (source 235e2fed…); the scanner (401,384 bytes) and the watchdog (2,337,064) are byte-identical, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes, the scanner's and the watchdog's SBOMs the same components and edges, the agent's lists nn-admin (146 components, was 145); `mk-packages.sh` (.deb): the same 79 paths and modes; `posture_demo` the same 29 lines; the test list is `main`'s — 3,098 names, every one found, 44 now nn-admin's (0 → 44: admin_cli's 26, the dispatcher's 18), 32 at a new path (admin_cli's 12 and agent_id's 2 in the agent, the dispatcher's 18 under nn-admin's `cli`), the agent's library 528 → 504, nn-linux 747 → 743, nn-evidence 119 → 121; no test added or removed, no `#[ignore]` added. The agent (15,297,832 → 15,298,288 bytes) and nn-admin (4,160,520 → 4,218,272) are not byte-identical. Function by function (unstripped, demangled names mapped to the new crates and modules, addresses and rip-relative targets dropped, trailing padding dropped): the agent 7,007 of 7,030 the same code (23 differ, 4 and 4 unpaired), nn-admin 2,991 of 3,170 (179; 15 and 21). Of the agent's 23: 9 by the `TypeId` constants of its types (clap's `try_remove_one::<T>` of its enums and its `Cli`'s parse: the agent crate's dependencies changed, so did its types' ids), 9 call a body of the same code under another name or lay out a frame otherwise (the overlay gate's read calls nn-core's `sig_path`, out of line now), 3 names with another count of bodies, 2 scheduled otherwise; the unpaired are which of identical bodies keeps the name, and `sig_path`: `.text` −48 bytes. Of nn-admin's 179: 127 names with another count of bodies — generic code instantiated both in nn-admin's library and in the binary's crate, where the dispatcher, generic over the host, is monomorphized (`Debug` of the admin messages, serde's deserializers) —, 33 call other callees (inlining at the new crate boundary; `read_priv_key` calls rustix's `geteuid` where it called libc's), 14 scheduled otherwise, 5 other operands; the unpaired are code inlined on one side only (`audit_read_into` into `run_audit_read` and the response verbs into the dispatcher on the tip; `run_init`, `print_capabilities`, `sig_path` out of line there), the seam's methods kept out of line (`chains`, `to_json_pretty`, `Chains::targets`) and the shim's `main`: `.text` +42,144 bytes (+1.26 %). `.rodata`, cut at every address the code, a relocation or a pointer of `.data.rel.ro` names: the same text but the moved files' paths (`agent/src/admin_cli.rs`, `agent/src/bin/nn_admin.rs`, `crates/nn-linux/src/os_rng.rs`), the callsite lines (`event <file>:<line>`) of the three edited files (the agent's `config/overlay_auth.rs`, nn-linux's `agent_id.rs` and `anti_tamper/trusted_installer.rs`), the all-zero id's message (a `String` from nn-proto's literal) and literals grouped otherwise. The documentation commit builds the same four binaries as the code commit, byte for byte (stripped and unstripped, the lab build of nn-admin too), and the same eBPF object and stamp: every edited source file kept its line count. `cargo doc --workspace --no-deps`: no warning the tree did not have; three fewer (the nn-admin binary's own: its dispatcher is a private module of nn-admin now).
- **Lab PR 260 — a canary trip survives an agent stopped between its two
  rows (found by lab PR 258).** C14 (behavioural detection and
  correlation: the deception layer); Wave 4; no level changes.
  - What was wrong: PR #462's KVM job on Ubuntu 24.04 failed
    `canary_privileged_e2e › file_canary_deployed_at_runtime_survives_an_agent_restart`
    once — after the fixture's restart the next read was a first trip
    again. Its log: the restart's SIGQUIT (not handled: the process ends
    there, as in a crash) landed between the access row (seq 0) and the
    registry's `trip` row, and the registry was still at its deploy row.
    The detector (nn-core's, on the registry's lock) decides the first
    trip, appends and syncs the signed access row, then appends and syncs
    the `trip` row naming it (`Registry::mark_tripped`), then returns the
    trip for the K5 rules. Stopped before the access row is on disk, or
    in it (a torn last line, cut at the next open): nothing records the
    access, and the canary is armed — consistent. Stopped after it and
    before or in the `trip` row (also a `trip` row that cannot be
    written): the access log holds the trip and the registry does not;
    the next start read the registry alone and re-armed the canary — the
    trip forgotten by the registry (`nn-admin canary list` never showed
    it), the next access answered as a first trip (a kill). Stopped after
    the `trip` row and before the verdict: both rows, the trip holds; the
    response that had not run does not run, as for any event the agent
    had read.
  - Decision: the access row is the trip's commit — it is the first
    write, the signed source the registry's row names. The tripped state
    is derived from it at open rather than written before it (a `trip`
    row first would name an access row that a stop could leave unwritten:
    the trip without its evidence) or with it in a journal (a new state
    file for the LSM protection, a second commit protocol). The signed
    access log keeps its format; the registry keeps its rows' format and
    gives one field a value on one action.
  - What changed: at each start, after the two chains open and before
    the detector runs, the registry reads the access log's first-trip
    rows of the canaries it holds armed (`access_log::first_trip_rows`:
    hash, signature and canonical bytes verified; a row placed by the
    `seq` it was signed with — a copy of a row, or a row without a number
    after numbered ones, counts for nothing) and finds those written in
    the canary's current arming that no registry row names
    (`Registry::unrecorded_trips`, from what each genuine row of a canary
    id says: `ArmHistory`). The arming starts after the latest first-trip
    row a registry row names: the agent marks a canary tripped in memory
    at its first access and writes no other first-trip row for it until a
    refresh, and a `refresh` row now names the trip it clears
    (`first_trip_access_hash`, with `tripped: false`; `null` for an armed
    canary, as on every `refresh` row before — an agent before this lot
    reads it as cleared). A refresh that names nothing (of an armed
    canary, or written before this lot; before lab PR 143 no `trip` row
    was written at all) is placed by its time. Each trip found is an
    ERROR, a signed `canary_trip_recovered` (the canary, the access row's
    position, hash and time, the accessor; attested before the row, so a
    stop in between attests it again) and a `trip` row naming the access
    row (`main.rs`, `record_unrecorded_trips`); a log that cannot be read
    is a signed `subsystem_degraded`. The detector's error for a `trip`
    row it could not write says whether the next start finds the trip.
    A `debug-trigger` failpoint (`debug-canary-stop-before-trip` next to
    the registry; `Registry::debug_stop_before_trip_mark`, called by the
    Linux host before the trip mark) aborts the agent between the access
    row and the trip mark. Tests: the detector on nn-linux's stores,
    stopped at each step (before the access row, in it torn, after it,
    in the `trip` row torn, after it, not stopped), then the next start
    and the one after: an access row on disk is one trip, recorded once,
    and the next access is not a first trip; none, and the canary is
    armed and its next access is the trip; the registry's cases (the
    finding, a refresh naming the trip it clears, a trip after a refresh,
    a refresh after a `trip` row that could not be written, a refresh
    that names nothing placed by its time, rows before a named one,
    forged, copied and burned rows) and the reader's (`first_trip_rows`);
    each of 8 mutations of the fix fails at least one; and the privileged
    e2e `a_trip_the_agent_stopped_before_recording_is_kept_across_the_restart`
    (the failpoint: no `trip` row after the stop; after the restart one,
    naming the access row, one signed `canary_trip_recovered`, the next
    read not a first trip; the start after records nothing more). Golden
    and posture golden files unchanged.
  - Open: a torn first row of `canary_access.jsonl` or `canaries.jsonl`
    (the file's only line, a power loss in the first write) is left as
    it is by the open's repair, which never empties a chain, and the open
    refuses the file: the canary subsystem is off until the file is
    repaired, as before.
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, QEMU for Windows with WHPX, 4 vCPU, 7 GiB), each tree synced, built and installed (`nn-lab.sh sync`, `build`, `install`), the installed units then stopped the operator way (`lab_purge_pins`, no LSM program left), `canary_privileged_e2e` run as root, single-threaded, with `--include-ignored` (8 tests with this lot's), the units put back, the guest powered off at the end. Before: this lot's tree with the boot's recovery switched off (`Registry::unrecorded_trips` returning nothing; a patch for the sync only, reverted right after it): the failpoint test failed 5 of 5 runs the same way on `main` 495296d and 5 of 5 rebased on `main` b8b55a95 — the agent stopped by the failpoint after the access row, and the next start recorded no trip (`the start recorded the trip: []`: the registry at its deploy row, the canary armed again). After, this lot's code on `main` 495296d (local commit 97c2d511): the suite 20 of 20 runs passed (31.2 to 31.6 s a run), then the failpoint test alone 10 of 10 (6.7 s); rebased on `main` b8b55a95 (lab PR 259; local commit 38478cfa, this commit's code): the suite 20 of 20 (31.3 to 34.5 s), the failpoint test alone 10 of 10 (6.7 to 6.9 s). In every suite run the failpoint stopped the agent once and the next start recorded one trip; the access row was written 1.7 ms before the stop (`access_ts` 11:39:54.138691, the failpoint's WARN at .140381), the next start's ERROR said `canary: a trip the registry did not record … access_row=0 … first_trip_rows=1`, and the next read was a recorded access, not a first trip. Host, on 38478cfa (this line is all that changed after it) and, before the rebase, on 97c2d511, `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s: `common` and the eBPF crates untouched); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --all -- --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 71 suites, 3,094 passed, 0 failed, 15 ignored, both times (`main`: 3,084; the 10 new unit tests); the `test_state_isolation` ratchet (10 passed: the new e2e starts its agent through the fixture, on lab PR 256's helper); `cargo xtask golden` (11 passed, every golden and posture golden file unchanged); `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed): all pass.
- **Lab PR 261 — nn-agent: `main.rs` cut into typed phases (Wave 4
  Phase 2, R11a of the restructure plan; no level changes).**
  - What was wrong: the agent's start was one function, `main.rs`'s
    `run` — 3,900 lines from the log stream to the stop, with
    `process_event` and ~40 helpers beside it (7,093 lines). The boot's
    phases (lab PR 218) were enforced by `BootSequence` and the
    `AttachPermit`, but their code was one scope: every value of the
    start was a local of `run`, any line could read any of them, and the
    order of the steps was the order of the lines. The tests that guard
    that order (`boot`'s, `agent_id_tests`) and the state-isolation
    ratchet read `main.rs` as text.
  - What changed: first, in place (`main.rs`, one commit), `run` cut into
    the phases its code already ran in, each a function that takes what
    the phases before it produced and returns a struct of what the ones
    after it read — `boot_preflight` → `Preflight`, `boot_state` →
    `StateReady`, `boot_identity` → `Identity`, `boot_integrity` →
    `Integrity` (with the attach permit), `boot_attach` → `Attached`,
    `boot_self_test` → `SelfTested`, `boot_attest` → `Attested`, then
    the subsystems (`Policy`, `Response`, `Posture`, the audit log's late
    binding, `Combat`, `FimPaths`, `Stores`, FIM, `Canary`, the network
    drain, the admin socket, `Tasks`), `boot_ready` → `Armed`, `run_loop`
    → `Stopped`, `shutdown`; `run` calls them in that order and holds
    what the agent keeps until it stops, as its locals did. Every line of
    `run` is kept, in its order, but 49 edits the new signatures need (a
    `&x` of a value the phase now borrows: `&cli`, `&overlay_gate`,
    `&identity`, `&posture`, `Arc::clone(&x)`, `&mut sensor`, the event
    loop's arguments; three `let mut` whose mutation is in a later phase)
    and the `use …::OverlayKind` line, which goes to the imports. Then
    the history (the plan's Appendix A): 21 commits, each on a branch of
    its own, `git mv agent/src/main.rs <part>` (R100), merged beside
    main.rs in one merge commit; then eight rounds that each delete one
    contiguous region from each copy (pure deletions: xdiff's prefix and
    suffix stripping leaves `git blame` nothing to guess — the copies'
    trim in one commit defeated its cost heuristic and plain `git blame`
    lost most of a file's lines); then the move: the copies become
    the library's modules (a module header, the visibility a crate
    boundary needs, the phases' names `boot_x` → `x::verb`), `main.rs`
    the binary's shim (`northnarrow_agent::boot::main()`), and `main`'s
    one-shot modes and runtime with `run` go to `boot/mod.rs` (cut, found
    by `-C -C`). The plan's layout (§2.4): `boot/{cli, logging, preflight,
    state, identity, integrity, attach, evidence, policy, response,
    posture, fim, canary, net, admin, tasks, ready}.rs`,
    `pipeline/{mod, process_event}.rs`, `run_loop.rs`, `shutdown.rs`. The
    library names itself as the binary did (`extern crate self as
    northnarrow_agent`, a shim until R17), so the moved lines'
    `northnarrow_agent::` paths are unchanged; the doc of
    `spawn_watchdog_exempt_refresh`, which sat on `HOST_STOPPING`, moved
    onto it. Last, the plan's "Identity si costruisce una volta sola":
    `Identity` gets a private field — only `identity::resolve` builds
    one, `run` calls it once (the order test asserts each phase call
    once), it is the start's one caller of `agent_id::resolve`
    (`agent_id_tests`) — and the phase's unit test (a first start mints
    and writes the id, every value the phase gives is that file's, the
    next reads it back). The type guarantees hold as they did and more
    visibly: `attach::load` takes the `AttachPermit` by value, which only
    `integrity::check` holds (`BootSequence::enter_attach`, once every
    preflight step is done: the order test asserts `enter_attach` once,
    in the integrity phase, before the attach); `run_loop::run` takes the
    `ready::Armed` only `ready::arm` makes. The tests that read `main.rs`
    read the start's sources: `main_runs_the_phases_in_order` rebuilds
    the start in the order it runs (`run`'s body, then each phase's in
    the order `run` calls it, each call once and after the one before)
    and asserts what it asserted; the heap and net drain tests too; the
    identity's read-once scan and the counts read every file of `boot/`
    and `pipeline/`, `run_loop.rs`, `shutdown.rs` and `main.rs` (their
    test modules left out; a new file there is read too). The three Cli
    tests run in the library's tests, under a lock with the new one (they
    read the process environment `env_switches_read_1_and_0` sets).
    xtask's `test_state_isolation.rs` reads the agent's flags from
    `boot/cli.rs` (its parse drops `pub(crate)`); `btf-matrix.yml`'s path
    filter names `boot/mod.rs` (the modes) and `boot/preflight.rs`
    (`--btf-check`) where it named `main.rs`; the module map maps
    `pipeline`, `run_loop` and `shutdown` to the agent, the ratchet stays
    14 (the moved code is the agent's, which may name every crate).
    The lot was rebuilt on lab PR 260 (`main` 45eaae3, merged while it
    was in the lab): that lot's step of the canary start (the trips the
    access log holds and the registry does not record, recorded before
    the detector runs, and its two helpers) is in the first commit's
    `main.rs` and moved with the canary phase into `boot/canary.rs`, its
    115 lines as lab PR 260 wrote them (plain `git blame` gives them to
    its commit); the comments of its tests that named `main.rs` name the
    agent's `record_unrecorded_trips`.
  - Deviations from the plan: the plan's module list predates lab PR 218
    and is adapted to the code: no `keys` (the ~10 key loads stay where
    they are: one KeyStore is R14c and would change behaviour), `sensors`
    is `attach` (the attach phase and the self-test), and `integrity`
    (the checks before the attach) and `ready` (the run phase's
    manifest and READY) are new; `evidence` holds the attest phase, the
    late binding and the stores, `posture` the machine and the ladder,
    `fim` the paths and the subsystem — a module may hold two phases that
    run apart. The plan's chain of types (`Preflight → StateReady →
    Identity → Keys → Attached → Policy → Response → Evidence →
    Subsystems → Armed → StopReason`) is the chain above (no `Keys`;
    `Evidence` is `Attested` and `Stores`); a phase takes the values it
    reads as parameters from `run`, which holds them, rather than each
    phase threading the whole start through (ten phases take more than
    seven, `#[allow(clippy::too_many_arguments)]` as `process_event`).
    Appendix A's recipe, adapted: main.rs stays beside the copies (no
    `tmp` rename on the main line), one merge of the 21 side commits, and
    the trim in eight rounds of single-region deletions instead of a
    commit per file, so that every first-parent commit builds and passes
    the per-commit checks and plain `git blame` stays exact. R11b–R11d
    are not done here (the integrity checks before the load, the global
    setters, the admin socket's split).
  - Open: R11b (HIGH, the checks before the load and the pin); R11c (the
    late-bound setters `evidence::wire` gathers become explicit handles);
    R11d; the shims (`extern crate self`), until R17; comments elsewhere
    that name `main.rs` as where the agent wires something (the start's
    modules now).
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; no other guest up — lab PR 260's ubuntu2204 was off), its disk at 31 % (8.6 of 29 GB used). The lot's code on `main` 45eaae3 (c4fc7c24) synced, built (release, test-privileged,debug-trigger) and installed three times (`nn-lab.sh sync`, `build`, `install` ×3: three boots): `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs): 76 suites, 85 passed, 0 failed — `main` 45eaae3's, run on the same guest after the lot's: the same 76 suites and 85 tests, each with the same outcome (lab PR 260's failpoint test the one more than lot 259's 84) —, the tests' agents' 52 chain checks `result="ok"`; `tamper-check`: 72 of 75 cases OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (lab PR 215's stale own link id) the recorded deviation. `main` 45eaae3 on the same guest right after, synced, built and installed three times the same way: `tamper-check` the same 75 outcomes and verdicts, case by case: 72 of 75 OK, the same two gaps and the same deviation; the evidence of 8 cases differs by what landed in a case's window — the self-integrity watcher's jittered rounds (an `integrity_drift` or its clearing in C14, C19, C26, C34, C35, C39), the overlay rollback floor's anchor (the tip's C24 boot), an R011 of systemd's (the tip's C12) —; over each run the self-integrity findings are the same, kind by kind and count by count (32 rows each: the lab's admin key on the host (5), two unit drop-ins, two shadowed units, two unexpected limits, two mounts over protected paths and a second bpffs, each found and cleared, the agent stalled (C15), the watchdog gone, C23's unsigned overlay as `config_overlay` and `unauthorized_overlay`, the detections log's check at each boot), but one more `chain_verify_failed` on the tip — the boot its run's start made, `test-ignored` having stopped the units — and one more `limit_unexpected` cleared on `main` (on the tip the case's restart came 29 s after the finding, before a round). `upgrade-check` from that `main` to the lot's code: `install.sh` without `--upgrade` refused; with `--upgrade` and the lab's admin key the trusted-installer window opened, both units stopped, the pins dropped and NorthNarrow's BPF programs unloaded, both units started, "UPGRADE complete — health check passed"; a new agent pid and a new `agent_boot` (audit log 5,607 → 5,614 lines), the identity the same, 19 of 19 deny hooks, 36 own LSM programs before and after, no foreign one. The boot log: the journal of each boot from "NorthNarrow agent starting..." to READY — the lot's three, `main`'s three, the upgraded one —, compared line by line after the values one boot changes are masked (pids, the inodes of the files the installs rewrite, chain hashes, the chains' row counts, durations, and the time of the first line the detections log's check flags in its 4 MiB window, which moves as the log grows): the same 204 lines in the same order, every boot of both builds and the upgrade's; unmasked, 188 of the 204 are byte for byte the same (the journal's time aside) and the other 16 differ in pids (3), inodes (7), entry hashes (2), the floor's verified count and time (2), the sequence seed (1) and that window (1). Their signed rows, from the previous run's `agent_stop` to the boot's capability manifest, op by op with time, sequence, hashes, signatures, pids and the rows' counts masked: the same on all seven (`agent_boot`, `chain_verify`, its `integrity_drift`, `capability_manifest`), and the capability manifest the same but its time and hashes: kernel and BTF (116 offsets resolved, 5 drifted, none absent), BPF LSM active, 19 of 19 deny hooks, the deny self-test denied, the BPF guard observing (a debug-trigger lab build), the same nine sensors on the same attach points, the same host hardening table (11 checks), no degradation, trust level L3. Every boot verified its own binary, the watchdog, nn-admin, the scanner and the embedded eBPF object against the install manifest ("binary integrity verified", `checked=5`, provenance `source-tree`). Each boot's chain check flags the guest's detections log — lab PR 256's class, lines signed by another key (288 → 258 of ~5,070 lines checked as the window moves; none added by these runs) — on `main`'s boots as on the tip's. A first round, before lab PR 260 merged, on `main` b8b55a9 with the lot's code then (2a84d2dc; the same steps, `upgrade-check` too) gave the same results — `test-ignored` 76 suites, 84 passed; the boots the same 205/204 lines in the same order but for one line of a task the start spawns ("fim recompute task: ready"), one place apart in one boot, as between two boots of one build; the same signed rows and manifest — but C15 in `main`'s `tamper-check`, a DEVIATION: its 45 s cgroup freeze began 1.1 s after a round of the self-integrity watcher (13:24:06.27; the thaw at 13:24:52.39, when the agent answered the watchdog's timed-out STATUS ping), and the next round, 24 to 36 s after the last (jittered), came 10 to 15 s late, under the watcher's 15 s stall threshold (`STALL_SLACK_SECS`): no `agent_stalled`, by design; C15 alone, three times on that `main` and three times on the lot's code, was OK every time, with the same evidence run by run (an `agent_stalled`, then twice the watchdog's stuck recovery after two timed-out STATUS pings: SIGINT, SIGKILL, a new agent). The guest powered off after. Host, on c4fc7c24 (the lot's code) and again on the final tree (the documentation commit; this line is all that changed after that run), `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 71 suites, 3,095 passed, 0 failed, 15 ignored (`main` 45eaae3: 3,094, the identity phase's test the one more); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets; every first-parent commit of the lot checked on its own (`cargo check` of the workspace and of the agent with the privileged features, `fmt`, clippy, the module map, path liveness, layer and state-isolation tests, the start's textual tests and the Cli's: lib 20 and bin 3 before the move, 23 and 0 after it, 24 with the identity test): all pass. The pins pass unchanged, by name: `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19: nn-parse 1, nn-proto 2, the agent 3, nn-linux 13), the TLS and DNS parser pins (5), the overlay-v1 fixture (2), the per-rule policy's format (its 12 tests, nn-core's; the exemption facts' 2, nn-linux's; the signed overlay's and the fuzz seeds' tests). The output matrix of lot 259 (1,964 cases: every nn-admin subcommand, its help texts, errors, socket verbs against the mock agent with every reply), `main` 45eaae3's binaries and the tip's: the same stdout, stderr, exit status, files written and requests sent in 1,964 of 1,964 cases, release and lab build alike (`main` 45eaae3's against b8b55a9's: 1,964 of 1,964). Identity against `main` 45eaae3, both built in one exported tree (the same path), the release job's commands (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C target-cpu=x86-64-v2 cargo xtask build --release --locked`; unstripped: the same flags, `CARGO_PROFILE_RELEASE_STRIP=none`): the eBPF object is byte-identical, its stamp too (source 235e2fed…); the scanner (401,384 bytes) and the watchdog (2,337,064) are byte-identical, stripped and unstripped; `mk-tarball.sh`: the same 72 entries, paths and modes, the three SBOMs the same components and edges (agent 146, scanner 59, watchdog 112); `mk-packages.sh` (.deb): the same 79 paths and modes; `posture_demo` the same 29 lines; the agent's `--help` (380 lines), `--version`, `--build-features` (release and lab build), `--btf-check` on the host's BTF and a bad flag: the same text and exit status; the test list is `main`'s — 3,109 names, every one found, 3 at a new path (the Cli's tests, `src/main.rs::tests` → `src/lib.rs::boot::cli::tests`) — and one new (`boot::identity::tests::the_phase_reads_the_identity_and_gives_its_id`: 3,110); no `#[ignore]` added. The agent (15,338,880 → 15,182,136 bytes, `.text` 7,615,176 → 7,499,640, −1.5 %) and nn-admin (4,218,272 → 4,228,928) are not byte-identical. Function by function (unstripped, demangled names mapped to the new modules, addresses and rip-relative targets dropped, trailing padding dropped; unpaired functions paired again by their code): the agent 6,408 of 6,784 paired names the same code; of the 376 that differ, 214 have another count of bodies (generic code the binary's crate instantiated beside the library's is the library's now: fewer copies for 159, more for 55), 128 call other callees (inlining at the new crate boundary), 17 are scheduled otherwise, 11 differ in several bodies, 6 in operands; 53 are the same code under another name (the tasks `run` spawned, its closures then, a phase's now, and their tokio harnesses); unpaired, old 205 — `run`, its closures and their task harnesses (141), library code instantiated or inlined otherwise (61), `start_open_sensor`, `attest_chain_findings` and lab PR 260's `record_unrecorded_trips` with its `attest_trip_recovered`, inlined into their phases now — and new 187 — the 23 phases, their closures and harnesses (155), library code out of line now (32: the engine's `decide`, nn-core's `load_comm_allowlist`, `CanaryIndexes::rebuild_live`, …); nn-admin, which links the library, 3,135 of 3,188 (53: 34 another count of bodies, 17 callees, 2 scheduling; unpaired 3 and 8: the replay's `decide` and the security-tool detector's `assess` out of line). Against `main` b8b55a9 (the first round, the lot's code then) the same 376 functions differed in the same classes, the same 53 were renamed, the same 187 new: the two more old ones are lab PR 260's. `.rodata`: the same text but the 257 log callsites of the moved code, which name their new files (`event <file>:<line>`; 957 callsites in all, the same count), the new modules' paths (tracing's module path, not printed: the agent's journal lines have no target) and the moved files' paths (panic locations); the rest is laid out otherwise — each side's printable text is found in the other's, in pieces of 8 characters or more, but 0.08 % of the characters (printable bytes of binary constants at the strings' edges). The documentation commit builds the same binaries as the code commit, byte for byte — the four, stripped and unstripped, the agent and nn-admin of the lab build, the eBPF object and its stamp: every edited source file kept its line count. `cargo doc --workspace --no-deps`: no warning the tree did not have (the agent library's 52, `main`'s). History, `git blame` at the move commit: the 21 new files, 7,941 lines — plain `git blame` gives this lot 1,138 (the phases' signatures, structs and docs, the module headers and visibility) and the other 6,803 to the commits that wrote them, lab PR 260's 115 in `boot/canary.rs` to its commit; `git blame -C -C -M` gives this lot 1,064; `boot/mod.rs` (718 lines, which received `main`'s modes by a cut) 572 plain, 513 with `-C -C -M`.

- **Lab PR 262 — nn-agent: every integrity check before the load and the
  pin, enforced by the types; every refused start signed (Wave 4 Phase 2,
  R11b of the restructure plan; C23, C01; no level changes).**
  - What was wrong (the lot's step-1 map, `docs/operator/BOOT_INTEGRITY.md`
    §1): lab PR 218 had moved the capability, install-manifest and audit
    writability checks before the attach, behind an `AttachPermit` from
    `BootSequence::enter_attach`. But the audit chain itself (the key and
    `AuditLog::open`: a torn last write repaired, a line before the end
    that is not a row refused) was opened by the attest phase, once the
    eBPF object was loaded, its maps pinned (by name, at the load), the
    sensors and the deny hooks attached and the self-test run; only the
    install manifest's, the BPF LSM's and the self-test's refusals were
    signed — the eBPF object, the state directory, the BTF offsets, the
    demo rules, the capability gate and the audit log left a journal line
    and exit 1 (78 for the BTF), so did the gates after the load; a
    refused start left its registration in the previous agent's pinned
    PROTECTED_PIDS; and the permit proved the order, not the checks —
    `done()` and `enter_attach()` were public, the loader and the
    anti-tamper attach ignored the permit, the pins and deny hooks
    (`anti_tamper::attach`) and the second loader (`ExecSensor::start`)
    took none, the object's bytes were public.
  - What changed: nn-linux's `boot::IntegrityVerified` (no public field,
    not `Clone`/`Copy`/`Default`; its one constructor outside tests is
    `BootSequence::verify_integrity`), required by the load, the pins and
    the attaches (`SensorMultiplexer::start`/`start_with_net`,
    `ExecSensor::start`, `attach_anti_tamper`, `anti_tamper::attach`,
    `attach_exploit_guard`; `EBPF_BYTES` nn-linux's own); the steps it
    requires recorded only by `boot::checks`, each after its check ran
    against the host and passed (`done()` refuses them; the state
    directory required now too; the BPF LSM gate moved to nn-linux, `git
    mv`, so that its check records); `attach::load(&IntegrityVerified,
    &StateReady)`, `StateReady` built by `state::bootstrap` alone. The
    audit chain opened by `checks::audit_log` before the load; the attest
    phase appends the same rows in the same order to it (deferred to the
    attest phase only while the previous agent's hooks close the key or
    the log to this process). `boot::refusal`: every gate's refusal signed
    (`agent_boot` `refused`, `refused_by` the gate) in the audit log, else,
    when the audit log is the gate, in a fallback chain of its own — a new
    file (`O_CREAT|O_EXCL`, a random name) in `boot-refusals/` beside
    `--pid-file`, a directory the agent creates and checks, its first row
    naming the audit log's head —, recorded in the audit log by the next
    start that opens it (`boot_refusals_recovered`, read once, verified
    and bound to that log) and removed; the registration withdrawn; exit
    78 for every gate. The preflight's three (eBPF object, state
    directory, BTF) are signed at the start of the integrity phase, still
    before the load, with no state file bootstrapped first. Privileged e2e
    of six refusal paths.
  - After the independent review (#466; second reviewer, verdict "merge
    after fixes"), as new commits: F1 the fallback chain's writer and the
    audit chain's opens (no link followed, no FIFO waited on, a regular
    file only, no line's content in an error: a link planted at the old
    single file's name put the agent's key in the journal, truncated or
    created files, a FIFO hung the refused start); F2 its reader (one
    bounded read, verified and listed from the same bytes, bound to the
    audit log: a prefix of `audit.log` or a copy put back verified as a
    fallback before); F3 one boot sequence per process
    (`BootSequence::begin`), the checks on the host's own roots and the
    environment's overrides, Clone/Copy/Default probed when the tests
    build; F4 a signing key there but not loadable refuses (it ran
    unaudited); F6 the deny hooks' pin root and BTF before the load (new
    checked steps `pin_root`, `vmlinux_btf`); F7 the refusal's tail
    unit-tested (the withdrawal, exit 78, no other exit); F8 no state file
    before a preflight refusal. F5 open (below).
  - Checks that stay after the load, by their nature: the arming of
    `BTF_OFFSETS` (the map is the loaded object's; before any attach),
    the load and the mandatory sensors' attach themselves, the deny hooks'
    shortfall (the attach's result; what attached stays pinned, as it did:
    it protects the agent's files), the deny self-test (it exercises an
    attached hook), the boot's own `agent_boot` write (a full disk is
    found by the write). Their refusals are signed too.
  - Deviations from the plan: the plan names three checks (capability,
    manifest, audit writability); the lot moves or proves every check that
    can refuse a start (the table of `BOOT_INTEGRITY.md` §1) and adds the
    signed refusal of the gates after the load and the fallback chain, the
    one place an audit log that cannot be written can be signed. The
    deferred open (the previous agent's hooks closing the log to an
    unregistered process) keeps the audit chain's open after the attach
    in that one case, which only this boot's attach can register.
  - Open: R11c (the late-bound setters), R11d; a refusal after the attach
    keeps what attached (by design: the pins protect); review #466 F5:
    the fallback chains are on tmpfs, unprotected — a reboot before the
    next start loses them and root can delete them (the journal keeps the
    refusal's lines and the chain's hash); a persistent protected place
    and a head anchor are the follow-up.
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; ubuntu2204 was lot 263's). The lot's code (ffcc95e2; the commits after it are a unit test and this documentation) synced, built (release, test-privileged,debug-trigger) and installed three times: `test-ignored`, its five runs exit 0: 77 suites, 89 passed, 0 failed — `main`'s 76 and 85 (lab PR 261) and the new suite's four, each on the real kernel (a tampered binary, an unwritable audit log, a broken audit chain, CAP_KILL dropped) —, the tests' agents' 52 chain checks `result="ok"`; `tamper-check` 72 of 75 OK, C27 and C57c the known gaps, C64 the recorded deviation. `main` 4444f20b on the same guest right after, the same way: `tamper-check` the same 75 outcomes and verdicts case by case (C38's status differs in its pids only); the evidence of 4 cases differs by what landed in a case's window (C23 the overlay rollback floor's anchor, C57c and C43 an `integrity_drift_cleared`, C39 a `chain_verify_failed` of the guest's detections log); the self-integrity findings the same kinds and counts, but the tip's one more boot (its `test-ignored` ran first). The refusal paths on the installed agent (a trusted-installer window, both units stopped, one check made to fail, `systemctl start`, bpftool's programs and links and the pin root's names and inodes before and after, the rows verified with `nn-admin audit verify`, the change undone, both units started): on the lot's code every case exits 78 with its signed row and loads nothing — one line appended to the binary (`install_manifest`, in the audit chain), `chattr +i` on the audit log (`audit_log`, in /run/northnarrow/boot-refusals.jsonl, the first round's single fallback file; the next start recorded it, `boot_refusals_recovered` verified, and removed the file), a drop-in `CapabilityBoundingSet=~CAP_KILL` (`capabilities`), a broken audit chain (the installed binary by hand on scratch state: `audit_log`, in its fallback chain), the tampered binary with the pin root purged first (`install_manifest`) —: none of the load's journal lines, no program or link left that no process holds, the pin root's names and inodes unchanged (absent before and after with no pins, and no NorthNarrow LSM program), the refused pid withdrawn from PROTECTED_PIDS. On `main` the tampered binary was refused signed but left its pid in PROTECTED_PIDS; the unwritable audit log and the capability gate exited 1 unsigned (the pid left); the broken chain was refused only after the load, the attach and the self-test (exit 1, unsigned), 22 LSM and raw-tracepoint programs and 22 links left pinned in place of the previous agent's, the maps re-pinned. `upgrade-check` from that `main` to the lot's code and back (the downgrade): both OK (refused without `--upgrade`, the window, both units restarted, a new `agent_boot`, the identity the same, 19 of 19 deny hooks, 36 own LSM programs before and after, no foreign one), and the refusal paths on the upgraded host as on the lot's own install. The boot log of 3 boots of each build, from "NorthNarrow agent starting..." to READY, masked as lab PR 261's (pids, inodes, hashes, counts, durations, the detections check's window): the same 204 lines in each boot of both builds; the one line placed otherwise is the key's `reusing existing agent signing key` of the audit log's open, before `boot phase done phase="preflight"` on the lot's code and after the self-test on `main` (and in one boot the trust level's line, a spawned task's, one place apart); the upgraded and the downgraded boot are their build's. Their signed rows (`agent_boot`, `chain_verify`, its `integrity_drift`, `capability_manifest`) and the capability manifest: the same. The guest powered off after. Host, on the code (0d48635f) and on the final tree, `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings`; `cargo fmt --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 72 suites, 3,120 passed, 0 failed, 15 ignored (`main` 71, 3,095, 0, 15); the privileged no-run; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times (11 passed each, the 33 golden files the same bytes, the tree clean); `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (13 targets); `portable-core` (5 targets); every commit of the lot checked on its own (check, privileged check, fmt, clippy, xtask's tests, the boot tests): all pass. Second round, after the independent review's fixes (#466: F1–F4, F6–F8; the code 1d8a26d1, the commit after it this documentation), on the same guest: synced, built and installed three times: `test-ignored` 5/5 exit 0, 77 suites, 91 passed, 0 failed — the round's 89 and the two new e2e (names planted where the fallback goes, a key that cannot be loaded) —, 51 chain checks `result="ok"` (one fewer in the watchdog's respawn test: a respawned agent stopped before its check); `tamper-check` 72 of 75 OK, the same 75 outcomes and verdicts as `main`'s case by case (C38's pids aside), the evidence of 3 cases differing by timing (C25 an R011 in its window, the watcher's `unit_shadowed` clearing in C35 instead of C43). The boots against `main`'s three: the same 204 lines (the first 205: `chain head anchored chain=audit`, as the previous run — `main`'s agent from the guest's boot — signed a row after its last anchor, also the window's one more signed row), differing in the preflight's step list (`pin_root`, `vmlinux_btf` added), the key's line placed as in the first round, the guest's `mem_total` (another boot of the VM) and the detections check's window; the signed rows and the capability manifest the same; the upgraded boot the tip's, the downgraded one `main`'s. The refusal paths on the installed agent: the first round's five as before, every one exit 78, signed, nothing loaded, nothing left, the pid withdrawn — the unwritable audit log's refusal in a file of its own, `/run/northnarrow/boot-refusals/refusal-<hex>.jsonl` (two rows, the first `boot_refusal_fallback` naming the audit log's head; verified), which the next start recorded bound to the log (`boot_refusals_recovered`, verified, its `fallback` id and `audit_head`) and removed —; the pin root a symbolic link to an empty bpffs directory: exit 78, `deny_hooks` signed before the load, nothing in the link's target, no program, link or pin left; a tmpfs over `/sys/kernel/btf`: exit 78, `deny_hooks` signed, nothing loaded; a runtime drop-in `BindReadOnlyPaths=/dev/null:/etc/northnarrow/agent.sig.key` (the review's F4): exit 78 unsigned, the journal's `not a regular file: a device`, nothing loaded, the pid withdrawn; the review's four probes at `/run/northnarrow/boot-refusals` with the audit log immutable — a link to the key, a link to a file without a final newline, a dangling link into `/etc/northnarrow`, a FIFO —: each exit 78 within 2 s, unsigned, nothing loaded, nothing created in `/etc/northnarrow`, the file unchanged; the same four by hand on scratch state (the installed binary registered in the pinned PROTECTED_PIDS as the unit's agent is, so exempt from the deny hooks; a key the probe made and could read): the key in no line of the log and unchanged, nothing followed, created or waited on; a link to the key and a FIFO planted inside the directory: the refusal wrote a file of its own beside them, and the next start recorded it (verified) and both as refused (`a symbolic link, not followed`, `a FIFO, not a regular file`), removing the three. `upgrade-check` from `main` to the tip and back: OK both ways (36 own LSM programs before and after, 19/19 deny hooks, no foreign one), and the refusal paths on the upgraded host as on the tip's install. The guest powered off after. CI on 1d8a26d1: every check green, the KVM privileged suites 77 suites, 91 passed, 0 failed on 5.15 and 6.8 (the six e2e of the refused starts on both). Host on d4af6e53 (1d8a26d1 changes a comment, a help text and a debug line), `set -o pipefail`, `CARGO_BUILD_JOBS=6`: the same gates as the first round, all pass — `cargo test` 72 suites, 3,140 passed, 0 failed, 15 ignored —; every new commit checked on its own (check, privileged check, fmt, clippy, xtask's tests 193, nn-evidence 122 to 125, nn-linux's library 762 to 767, the agent's 514 to 523): all pass.

- **Lab PR 263 — nn-agent: the admin socket cut into `admin/*`, one
  verification pipeline for the signed verbs (Wave 4 Phase 2, R11d of
  the restructure plan; two fixes; no level changes).**
  - What was wrong: the admin socket, the agent's privileged control
    plane, was one file, `admin_socket.rs` — 10,134 lines, 5,347 of
    them production: the accept loop and the peers, the framing, the
    signed audit rows, and 25 signed verbs, each carrying its own copy of
    the verification around the verify nn-linux's `admin_auth` gives
    (`ConnAuth::verify_signed_payload_quorum`, or its `_keys` twin): the
    signatures collected, the verify called with the verb's quorum, roles
    and operation, the error mapped to the wire (by `map_admin_auth_error`,
    or in shutdown and force-posture by an inline copy of it), the
    signers' fingerprints handed to the audit row by hand (`fps_out`),
    the extra matched again. 25 places where a check could drift, and an
    audit arm a new verb could forget. The plan counted 22 on `w4a-base`,
    which had 23 call sites; lab PR 217 added the signed unlock and lab PR
    222 `remediate ransomware`.
  - The copies, read side by side (the table is in the PR): all 25 called
    the same core in the same order — the connection's failure budget,
    its challenge (consumed whatever the outcome: replay), `check_op`
    (the payload's op and extra the verb's), at most eight signatures,
    the nonce, the agent id, ±60 s around the server's clock (expiry),
    each signature against every loaded key over the canonical digest,
    the distinct quorum, the roles; counted: the op, the cap, the nonce,
    the agent id, no matching key; the third answered `RateLimited`. No
    verb checked less in the verification proper. Around it: the quorum
    and roles per verb (each verb's design: deliberate); rotate-keys add
    1-of-N while the one-key bootstrap is armed, its gate read before the
    verify (BUG-013, ATP-004: deliberate); telemetry-status with no role
    in the quorum, either read role after it and the signer named in the
    refusal's row (lab PR 213's decision: deliberate); the two inline
    maps (the same mapping, their own journal line for the unreachable
    payload-digest error) and shutdown setting the signers after its extra
    check (unreachable): cosmetic; 24 defensive re-checks of the extra,
    unreachable after `check_op`; the refusal replies and set-status's id
    read before the verify, to echo it (the wire's: deliberate). After
    the verify, every verb refuses when its subsystem is missing
    (`UnknownOperation`) — but two, which were bugs, fixed in commits of
    their own: `fim baseline` answered and signed success without the
    FIM's state and when its request was dropped, and `detections`
    without its state read the built-in paths and served rows unverified.
    No verb needs the trusted-installer window open (it lets an upgrade
    past the kernel's deny hooks; the grant is the verb that opens it).
  - What changed: first the split, history kept (the plan's Appendix A,
    as lab PR 261): 19 side commits, each `git mv agent/src/admin_socket.rs
    <part>` (R100) with the module map's `admin` entry, merged beside
    admin_socket.rs in one merge commit; five rounds, each deleting one
    contiguous region of each copy; the test module's copy dedented into a
    file module (whitespace and rustfmt's reflow only, no string literal
    spanning a line without a `\` continuation; listed in the new
    `.git-blame-ignore-revs`); then the move — admin_socket.rs goes, its
    two submodules `git mv` to `admin/` (100 %), each copy gets a header
    (module doc, `use` lines), `pub(super)` / `pub(in crate::admin)` where
    another part or the tests reach, two signatures rustfmt wraps, and
    `own_euid`'s test hook path (`super::tests::own_euid_override`). The
    layout: `admin/mod.rs` (the module doc, the shutdown signal and the
    admin states), `transport.rs` (serve and its entry points, the
    connection table, the peer's credentials and identity, the framing,
    the loop of one connection), `verify.rs`, `audit.rs` (the client, the
    dispatch notes, the signed row), `handlers/` (`dispatch` and the
    verbs, one file per family: unlock, shutdown, posture, keys, config,
    fim, installer, response, status, canary, net, detections; `read.rs`
    the read verbs' tail), `tests.rs` (admin_socket.rs's tests, whole).
    `lib.rs` keeps the old path, `pub use admin as admin_socket` (an R11d
    shim until R17); the module map maps `admin` and lists the shim. Then
    the pipeline: `verify::signed` verifies a request by its verb's
    `Rule` — one table (`signed_verbs!`: request, operation and extra,
    quorum, roles, journal name) — writes the signers for the row, and
    hands the handler a `Verified` request, which only verify.rs makes
    (private fields): the request, its extra typed, the matched keys and
    fingerprints, the token, the server's clock, whether the bootstrap
    relaxed the quorum. The two exceptions are the table's own
    (`Quorum::Bootstrap(2)`, `Roles::AnyOf`). Each verb is its entry
    (`dispatch_x`, the signature callers and tests use: one call to
    `signed` with its refusal reply) and its verified body. Then one
    request's path in one function, `transport::serve_request` (dispatch,
    the audit row, the status poll's count), and what a request acts on
    one value, `handlers::Wired`, built once per connection. Then the two
    fixes (below); nn-admin's note on fim baseline's `ActionFailed`, a
    reply of the agent's now (the mapping unchanged: "server rejected
    operation", exit 5); then this documentation.
    Tests: the 108 of admin_socket.rs pass under `admin::`, their
    assertions unchanged (three call `dispatch` with its `Wired` now; the
    five role tests of the `detections` read get a store of their own:
    the second fix refuses a read without one);
    new: `verify`'s two (the table pinned against the designs; every
    operation but `audit-read`, nn-admin's own, has exactly one rule),
    `pipeline_tests`' four — every signed verb through every refusal of
    the verification (no challenge, a replay over another connection's
    challenge, the challenge already spent, a bad signature, an unknown
    key, a key without the role, no signature, one key twice for the
    2-of-N verbs, a time 120 s before or after the server's clock, another
    install's id, another verb's payload, another verb's extra, nine
    signatures: 353 requests), the exact reply and the signed row (op,
    extra, result, key_fp, cosigners, client); each verb accepted, its
    signers named; each verb's connection rate-limited at its third
    counted failure and after; the requests without a signature —, and
    the two fixes' regression tests. The same rejection table, run on
    `main` 4444f20 through its own `dispatch` and `emit_audit_for`, gives
    the same 478 replies and rows byte for byte (the clocks masked); with
    the fixes, 4 differ: fim baseline and detections without their
    subsystem, accepted and refused now.
  - Fixed (each its own commit, with its regression test: the first two
    fail on `main`, which answers `Success`; the third without the lock):
    - `fim baseline` nothing records: without the FIM's state it logged
      "recompute scheduled for next agent restart", which no restart
      does; on a boot without a baseline database the recompute task's
      receiver is dropped, and the request with it, while the reply and
      the row said success. nn-linux's `BaselineRecomputeSender::trigger`
      says what became of a request (`Triggered::{Queued, Coalesced,
      Dropped}`); the verb answers `UnknownOperation` without the state
      and `ActionFailed` when dropped (lab PR 217's variant: verified, not
      carried out); a coalesced request stays a success. nn-admin says
      "fim baseline: nothing was recorded: …" for it (the review's L-3).
    - the `detections` read on a degraded boot: without the store's state
      (no agent key, or a status-event log that did not open, which
      dropped the whole state) it read the built-in paths and served their
      rows unverified (NN-AUD-112's check skipped). `DetectionAdminState`
      carries the agent key's public half and the status log as an
      `Option`; the boot builds it whenever the key loads; the read
      verifies with `agent_key` and is refused without a state;
      set-status is refused without a status log, as before.
    - found by the review (L-4, on `main` as well): two `rotate-keys
      add` at once while the one-key bootstrap was armed both found the
      gate armed and passed with its one signature, and an add and a
      revoke could each lose the other's line of admin.pub.
      `AdminAuth::rotation_lock` (nn-linux): both rotate-keys verbs take
      it before the gate, the verify, the rewrite and the reload. Tests:
      two adds released together (one passes, the other waits and finds
      the bootstrap spent), and an add and a revoke that wait while the
      test holds the lock.
  - Deviations from the plan: 25 copies, not 22 (above). The tests stay
    one file for now (`admin/tests.rs`: a split by handler needs the
    shared fixtures in a module of their own; R17 or a follow-up), and
    their history reads with `git blame -w --ignore-revs-file
    .git-blame-ignore-revs`. Not in the plan: `serve_request` and `Wired`
    (one request's path for the table test and the connection alike), the
    two fixes. The pipeline stays in the agent: the plan puts the role
    parse and the `UnlockToken`'s verification in nn-proto with R04b's
    split of `admin_auth`, which the rule table can follow.
  - Review (independent, of 53ccada0): the production code sound — the
    table matches `main`'s 25 call sites, no verb reaches its handler but
    through `verify::signed`, `Verified` is made nowhere else, the removed
    re-checks were unreachable, the two fixes correct — and the 478 rows
    reproduced on `main` with an adapter of its own (474 the same, the
    fixes' 4). It asked for tests, four mutations of the security rules
    having passed every one, and each finding has a commit of its own:
    - M-1: the bootstrap's 1-of-N had no test through the pipeline (never
      relaxing the quorum, or ATP-004's consumption flag read as false,
      passed), and every rotate-keys add of the tests read the host's
      `/etc/northnarrow/.bootstrap`, and could remove it.
      `verify::bootstrap_paths` puts the gate's files beside a test's own
      admin.pub (a `#[cfg(test)]` branch, as `own_euid` has; the tests
      reach no pinned map either), and three tests send through
      `serve_request`: armed then spent (shutdown and revoke stay 2-of-N),
      re-armed neither by a one-key admin.pub with a valid sentinel nor
      after the signed chain spent it, and the gate's closed states.
    - M-2: a role swapped (remediate on `audit-read`, the role every key
      holds) or a 1-of-N shutdown, with their pins, passed. Every verb is
      refused to keys of every other role and to keys of the default roles
      (the roles and quorums written by hand from the design), and the
      shutdown's quorum is the watchdog's `SHUTDOWN_QUORUM`, in the table
      and in the test that one key less gets no marker.
    - L-1: a test of the core's nonce binding (`NonceMismatch`, counted,
      the challenge spent); only the table's `Replayed` caught the check
      off.
    - L-2: the three tables are golden files of `cargo xtask golden`
      (`agent/tests/golden/admin/expected`, `docs/validation/
      GOLDEN_REPLAY.md` §7; the telemetry status's process-wide counters
      masked): undoing either fix turns them red.
    - L-3, L-4: above.
    - The nits: four comments no longer true fixed, the server's clock read
      after the gate's files again (as the add did), `Verified::request`
      says its unsigned fields; N-3 and N-5 (an unreachable arm's journal
      text, which no alert reads) left as they are.
    Each mutation the review left standing, the core's nonce check off,
    either fix undone, the rotation lock or the tests' files removed now
    fails one test or more (the PR lists them).
  - Open: the tests by handler; the shim (`admin_socket`), until R17;
    R04b's split of `admin_auth`; R11b and R11c; `fps_out`, an out
    parameter of the handler entries that only `verify::signed` writes
    (the review's N-3: returned, a later handler could not overwrite it).
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, ssh 2522, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; ubuntu2404 up for lot 262, two guests). The lot's code (6ab9e0fc) synced, built (release, test-privileged,debug-trigger) and installed (`nn-lab.sh sync`, `build`, `install`): `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs): 76 suites, 85 passed, 0 failed — lab PR 261's totals —, the tests' agents' chain checks `result="ok"` (52, none other); `tamper-check` (its signed calls through the pipeline: the trusted-installer grants, the signed overlay): 72 of 75 cases OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (lab PR 215's stale own link id) the recorded deviation; `policy-check`: PASS (its 8 checks; the signed `policy set` stored and applied at once). The guest's disk then freed (83 % → 26 % used: the build directory's entries older than a day, earlier lots' artifacts; cargo rebuilt what it needed). `main` 4444f20 on the same guest right after, synced, built and installed the same way: `test-ignored` the same 76 suites and the same 85 tests, each passed (51 chain checks `result="ok"`, none other); `tamper-check` the same 75 outcomes and verdicts, case by case (C38's pids aside); the evidence of 8 cases differs by what landed in a case's window — the self-integrity watcher's jittered rounds (an `integrity_drift` or its clearing in C02, C14, C19, C26, C34, C36), the overlay rollback floor's anchor (the tip's C20 boot), a module load systemd ran (`main`'s C16) —, and the cases' signed rows, summed over each run, are the same op by op (3 `agent_boot`, 3 `chain_verify`, 3 `capability_manifest`, 2 `agent_stop`, 4 `trusted_installer_grant`, 1 `config_overlay_set`, 5 `combat_stage`, 2 `combat_outcome`) but the watcher's 29 findings, split 21/8 between drift and clearing on `main` and 22/7 on the tip, and the floor's one anchor (the tip's); `policy-check` the same 9 lines. The live A/B (lab PR 259's way, its commands and the verification's refusals on the real socket: an unknown key, another install's id, the roles the lab key lacks — fim, canary, net, telemetry-read, force-posture —, `shutdown` with one key, refused by nn-admin before sending, and the signed `unlock`): 41 commands, each run with `main`'s nn-admin, the tip's and `main`'s again, against `main`'s agent and, after `upgrade-check`, against the tip's, the signed audit rows each invocation appended kept (time, sequence, hashes, signature and client pid masked). The two nn-admin binaries give the same stdout, stderr, exit status and rows on each agent, the binary's name and path aside (`--help`'s usage line, the rows' `client_comm` / `client_exe`). The two agents give the same for 33 commands, the same but numbers for 6 (the telemetry's counters, the run's time in `--since`, the verifiers' row counts) and the same but the boot's signed manifest row (its hash, `capabilities` ×2), and the same rows command by command: `telemetry_status` (6), `response_status`, `unlock` and `status_polled` accepted; `role_denied` (10), `invalid_signature` for the unknown key (2), `agent_id_mismatch` for another install's id (2) refused. (The first run's script counted the audit log's lines outside sudo and kept, after each invocation, the whole masked log; each invocation's rows are the lines its dump has beyond the one before, every dump extending the one before; the script was fixed for the second run.) `upgrade-check` from that `main` to the lot's code (bf1e07ef: 6ab9e0fc's code, the module doc's links its one change): `install.sh` without `--upgrade` refused; with `--upgrade` and the lab's admin key the trusted-installer window opened, both units stopped and started, "UPGRADE complete — health check passed"; a new agent pid and a new `agent_boot` (audit log 4,923 → 4,932 lines), the identity the same, 17 of 17 deny hooks, 34 own LSM programs before and after, no foreign one. The lab builds of `main` and the lot: the watchdog and the scanner byte-identical, the agent and nn-admin not. The guest powered off after. Host, on 6ab9e0fc (the lot's code; the commits after it change comments and the documentation only) and again on the final tree (the documentation commit; this line is all that changed after that run), `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --all -- --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 71 suites, 3,104 passed, 0 failed, 15 ignored (`main`: 3,095; the 9 new tests); `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 11 tests passed each time, the 33 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (nightly-2025-12-01, cargo-fuzz 0.13.2, the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets; every first-parent commit of the lot checked on its own (`cargo check` of the workspace and of the agent with the privileged features, `fmt`, clippy, the module map, path liveness, layer and state-isolation tests, the agent library's tests that name `admin` — the admin socket's and the admin keys': 133 from the merge to the move, then 135, 139, 140 and 141): all pass. The pins pass unchanged, by name (nn-proto, `common`, the eBPF crates and `agent/tests` untouched): `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19: nn-parse 1, nn-proto 2, the agent 3, nn-linux 13). The output matrix of lot 259 (1,964 cases, its mock agent built on `main`'s nn-proto, run under a root of its own), `main` 4444f20's binaries and the tip's: the same stdout, stderr, exit status, files written and requests sent in 1,964 of 1,964 cases, release and lab build alike; the final tree's release nn-admin is byte-identical to the one the matrix ran (2e206234…: b9750cf2 changes a comment). The rejection table, on `main` through its `dispatch` and `emit_audit_for` and on the tip through `serve_request`: 478 of 478 replies and rows the same before the fixes, 474 after (the 4 the fixes change). The test list: `main`'s 3,110 names, the admin socket's 108 at a new path (`admin_socket::` → `admin::`), 9 new, none removed, no `#[ignore]` added. `cargo doc --workspace --no-deps`: the agent library's warnings 52 → 49 (the module doc's links), none new. History, `git blame` at the move commit: the 19 parts, 10,442 lines — plain `git blame` gives this lot 416 production lines (the headers and the visibility) and the tests' dedent; `git blame -w -C -C -M --ignore-revs-file .git-blame-ignore-revs` gives it 418 of the 10,442. After the independent review (the branch at cc84d95e: its tests, the rotation lock, nn-admin's message, the nits), on the same guest: synced, built and installed; `test-ignored` the same 76 suites, 85 passed, 0 failed (51 chain checks `result="ok"`, none other); the units started again after it (`test-ignored` leaves them stopped) and the A/B's 41 commands once more, with `main`'s nn-admin (its lab build, kept on the guest) and the tip's: the two binaries give the same in 41 of 41, the binary's name aside; the tip's agent against the lot's before the review the same in 35, the same but numbers in 4 (the `--since` times, the verifiers' row counts) and the same but the boot's manifest hash in 2 (`capabilities`), against `main`'s the same in 33, 6 and 2 as before, and the rows the same command by command. The watchdog and the scanner of the lab build are `main`'s bytes still. The guest powered off after. Host, after the review: each mutation the review left standing (the bootstrap's consumption flag read as false, the bootstrap never relaxing the quorum, remediate on `audit-read` with its pin, a 1-of-N shutdown with both pins), the core's nonce check off, either fix undone, the rotation lock removed and the tests' bootstrap files back in `/etc`, applied one by one to the committed tree with the agent's admin tests (nn-linux's for the nonce) run and the file restored: all 9 fail one test or more (3, 2, 2, 5, 1, 3, 3, 2, 3); lot 259's matrix on the tip's nn-admin: 1,963 of 1,964 cases the same, release and lab build, the one changed `sock.fim-baseline.action-failed` (its stderr, the L-3 message; exit 5, stdout and the request sent the same); the rejection table, golden files now, against `main`'s tables: 474 of 478 lines the same, the fixes' 4; the gates on the final tree (41bef692, cc84d95e's code; this line is all that changed after the run): `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s), the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test` 71 suites, 3,116 passed, 0 failed, 15 ignored (3,104 and the review's 12 tests), `cargo test --no-run` with the privileged features, `cargo xtask attack-coverage --check`, `cargo xtask golden` five times (24 tests each, the admin table's with the replays; the 36 golden files the same bytes after every run, the tree clean), `cargo +1.89.0 check`, the fuzz replay (13 targets, no lockfile changed), `portable-core` (5 targets), and every commit after 53ccada0 checked on its own as before, with nn-linux's `admin_auth` tests and nn-admin's (the agent's admin tests 142, 145, 149, 149, 151, then 151; `admin_auth` 58, then 59; nn-admin 44, then 45): all pass. The test list: the lot's 3,119 names and the review's 12 (3,131), none removed, no `#[ignore]` added. `cargo doc --workspace --no-deps`: the same warnings, crate by crate (the agent library's 49).
- **Lab PR 264 — nn-agent: the global setters replaced by explicit handles
  (Wave 4 Phase 2, R11c of the restructure plan; no level changes).**
  - What was wrong: R11a cut the start into typed phases and R11b made the
    integrity checks a proof the attach takes, but much of what the start
    made still reached the code that read it through process-wide statics:
    a setter the start called (`rule_policy::install_global`, five
    `set_audit_log`s and `ring_drops::set_posture` in `evidence::wire`,
    `impact::publish` / `impair::publish`, `trust::set_boot_inputs`,
    `quarantine::set_runtime_deny`, `execq::configure` /
    `execpol::configure`, `cow::boot`, the load's switches `want_lsm`,
    `want_tracepoint`, `want_skb` and `set_task_map_entries`,
    `blocklist::note_ja3_entries`, `bpf_defense::mark_stopping`), or a
    phase's result parked for a later phase (the anti-tamper attach's deny
    report and degraded states, the sensors' attach points, the exec
    guards' kernel objects, the BPF guard's own maps, links and foreign
    pins, the exploit guard's control, the deny self-test's expected
    denial, the telemetry probe's tracker, the signed manifest,
    `HOST_STOPPING`). And some instances kept their own state in statics
    every other instance of the process shared: the overlay gate's
    configured paths, the canaries' read-forward set ("a global, with no
    new wiring"), the FIM drain's retry queues (a thread-local under test
    so that tests did not settle each other's entries), the copy guard's
    ransomware signals; tests worked around them with locks, unique
    markers and filters.
  - The inventory (the table is in the pull request): every `static` of
    the agent's code — `agent/src`, `crates/*/src`, `common/src`,
    `antitamper-bpf/src`, test code aside — and the process-wide state
    that is not a static of ours (the logger and tracing's callsite
    interest cache, the tokio runtime, the signal handlers, the process's
    environment, rlimits and `prctl`, `std::process::id()` as the default
    of the fan-out rules' and NN-L-FIM-024's `agent_pid` and in the rows
    the agent signs about itself). Classed (a) a real per-process
    singleton, kept and documented; (b) a setter wiring boot state into
    deep code, or a phase's result handed to a later one through a static,
    replaced by an explicit handle threaded from the typed phases; (c)
    per-instance state tests shared, made per instance. 48 statics were (b)
    or (c), 64 are (a): the process (the event loop's heartbeat, the one
    boot, the qname hash's random keys, the directory descriptors it
    holds, the detection log's budget), the host's facts (`/proc/1/root`,
    the clock tick, the mount table, the running kernel's BTF offsets,
    systemd's state, stdout a terminal), the one eBPF object's state as
    the status reads it (the ring-drop, fail-open and exploit-guard
    counters, the exec guards' state, `FLOW_SOCK_MAP`, the connect deny,
    the inodes this boot protected, the nftables ruleset), the status
    totals (evictions, verdicts at a connect, snapshots, rows skipped),
    the signed degradations (logger-like: any part reports one, the start
    binds the audit log once as it installs the logger), state keyed by an
    instance's own path (a vault's index notes since lab PR 258, the admin
    socket's retirement, the FIM's per-path counts and hashes) and the
    engine's per-thread hold. `rule_policy::global()`, `HELD`, the status
    counters, `QNAME_HASH_KEYS`, `RUNTIME_DENY`, the `process::id()`
    defaults and the interest cache, which lab PR 249 had listed as kept,
    are each classed: the policy handle and the runtime deny were (b), the
    others (a).
  - What changed, one commit per family: the per-rule policy (one
    `PolicyHandle` the policy phase makes, the engine's, cloned into both
    posture machines and into the admin socket's new `AdminHandles`, which
    `config overlay set` of a rule-policy installs through); the late
    binding through handles (`RingDrops`, `FailOpen` from their install,
    held by the multiplexer; the running `ExploitGuard`; the path map's own
    audit slot; `UnverifiedRows` in the detections' admin state;
    `TelemetryProbe` from its spawn to the event loop; `BpfGuard` made at
    the load; `late_audit::LateAudit` the bound-once slot they share); the
    boot's results carried (`anti_tamper::attach` returns its
    `AttachReport`, the self-test phase its `TrustInputs`, the run phase
    signs into the `SignedManifest` slot, the tracker and the judge go to
    the admin socket and the detection sink); the load's `LoadPlan`, its
    `DnsMode`, `ExecGuards::install` told whether the exec sensor is the
    LSM one and the object's own `AttachPoints`; the exec guards an
    instance (`AgentExecGuards`, through the load to the tasks phase); the
    run's guards handed on (`CowGuard`, `ExecutorConfig::own_files`,
    `ExpectedDenial`, `HostStopping`); per instance (the gate's configured
    paths, `ReadForward` in the FIM drain's map through
    `CanaryHost::ReadForward`, the drain's queues in its map); the JA3
    list's size in `Policy`. Every value is the one the static held, read
    at the same point of the start: a slot bound later is bound where the
    setter ran (the ladder's NEUTRALIZE hook reads the copy guard through
    a slot filled once the guard booted, as the static was), and what was
    read only after its setter ran is now passed at construction.
  - The hot apply (lab PR 236) proved where it applies: a new test sends a
    signed `config overlay set` of a policy through `serve_request` with
    one handle shared as the start shares it — the engine's (`replay`'s
    production engine), the posture's clone, the admin socket's — and the
    next event of each takes it at once: R020's held kill given back in the
    engine's decision, the executor (enforcing, on the test's paths) kills
    the test's own child with it, the posture judges ransomware alone
    decisive (COMBAT, unlocked); before it, the built-in defaults on all
    three. A start test asserts the start makes that one handle and hands
    it to the three. On the guest, `policy-check` (set live, then at boot).
  - The ratchet: `xtask/tests/global_state.rs` lists the 64 statics that
    stay, each with its class and reason, and the 20 calls the start makes
    into a free function naming one (the heartbeat, the exec guards'
    controllers, the signed degradations, …); a new static, a new such
    call, an entry gone, or a removed setter back fails. Each rule fails on
    a planted violation, and did on the real tree.
  - Deviations from the plan: the plan names the setters only; the lot
    inventories every static and converts the per-instance ones too. Kept,
    with their reasons: the degradation registry (the run's signed log,
    reported into from anywhere, like the journal) and the BTF offsets (a
    fact of the running kernel the preflight resolves once and must refuse
    on).
  - Open: the scratchpad that held lot 259's nn-admin output matrix (its
    mock agent, fixtures and baselines) was lost when the previous session
    stopped; the nn-admin check here is the function comparison, lab PR
    263's live A/B on the guest and the lab's verbs (below). R11d is
    merged; R12 and R14 will move the sensors and the parsers, where more
    of the (a) kernel-object state may become a worker's.
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; ubuntu2204 up for lot 265, two guests). The lot's code (ffbd3a84) synced, built (release, test-privileged,debug-trigger) and installed three times (`nn-lab.sh sync`, `build`, `install`), the three boots collected (the agent's journal from "starting" to `READY=1`, the signed rows of each boot's window): 204 lines each, the same among themselves as multisets. `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs, each exit 0): 91 passed, 0 failed — `main`'s 91 on this guest (lab PR 262's last round) —, the tests' agents' chain checks `result="ok"` (52, none other); `policy-check`: PASS (its 8 checks: the built-in defaults hold IMP-001's kill; the signed `policy set` stored, "applied now", and the simulator's tree killed on the next event; a comm exemption refused by nn-admin, nothing sent, the policy unchanged; the policy at boot, its signed `rule_policy_loaded` row, still enforced; the built-in defaults back at once); `tamper-check`: 72 of 75 cases OK — C27 (no lockdown on the guest) and C57c (the journal's vacuum) known gaps, C64 (lab PR 215's stale own link id) the recorded deviation. `main` 118d5044 right after on the same guest, the same way (installed three times, the boots, `policy-check`, `tamper-check`): each of `main`'s three boots against the tip's the same 204 lines as multisets and the same signed rows op by op (6, 6, 4); in boots 1 and 3 two neighbouring lines in the other order ("fim recompute task: ready", which the spawned recompute task logs, and the signing key's "reusing existing"; the tip's boot 2 has `main`'s order). `policy-check` the same 22 lines (times aside). `tamper-check` the same 75 outcomes and verdicts, case by case (C38's pids aside); the evidence of 4 cases differs by what landed in their window: in C15 (the agent's cgroup frozen for 45 s) on `main` the watchdog's STATUS ping timed out twice and its stuck recovery stopped the agent with SIGINT and restarted it (the watchdog is the same bytes in both builds; on the tip the freeze ended before the second timeout) — hence `main`'s one more `agent_stop`, `agent_boot`, `capability_manifest`, `chain_verify`, `overlay_floor_anchor` and two `integrity_drift` there, and in C19 the restarted agent's `combat_stage` (its COMBAT entry on the case's denial; the tip's agent was in COMBAT, locked, since C01) —; in C35 and C36 the self-integrity watcher's round (an `integrity_drift_cleared` and a `unit_shadowed`) one case apart. Summed over each run the cases' signed rows are the same op by op but those (the tip 55, `main` 63). `upgrade-check` from that `main` to the tip: `install.sh` without `--upgrade` refused; with `--upgrade` and the lab's admin key the trusted-installer window opened, "UPGRADE complete — health check passed"; a new agent pid and a new `agent_boot` (audit log 6,608 → 6,616 lines), the identity the same, 19 of 19 deny hooks, 36 own LSM programs before and after, no foreign one; the upgraded boot is lot 262's upgraded boot of 1d8a26d1 line for line (205 lines, the same order, the same signed rows). The live A/B of lab PR 263 (lab PR 259's commands and the verification's refusals on the real socket — an unknown key, another install's id, the roles the lab key lacks, `shutdown` with one key, refused by nn-admin before sending, the signed `unlock` —, 41 commands, each run with `main`'s nn-admin, the tip's and `main`'s again, the signed rows each appended kept, masked), with the release builds of both nn-admin binaries, against the tip's agent and then, `main` 118d5044 installed again, against `main`'s: the two nn-admin binaries give the same stdout, stderr, exit status and rows in 41 of 41 on each agent (the binary's name aside); the two agents the same in 33, the same but numbers in 6 (the telemetry's counters, the `--since` times, the verifiers' row counts) and in 2 (`capabilities`, text and JSON) the same but the hash of the boot's signed manifest row — the manifest itself the same —, and the same rows command by command (`telemetry_status`, `status_polled`, `response_status` and `unlock` accepted; `role_denied` ×10, `invalid_signature` ×2, `agent_id_mismatch` ×2 refused). The guest powered off after. Host, on ffbd3a84 (the lot's code; the commit after it is this documentation), `set -o pipefail`, `CARGO_BUILD_JOBS=6`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s); the four clippy runs with `-D warnings` (workspace all targets; agent and watchdog with test-privileged,debug-trigger; posture_demo); `cargo fmt --all -- --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 73 suites, 3,168 passed, 0 failed, 15 ignored (`main`: 72 suites, 3,161; the 7 new tests); `cargo test --no-run` with the agent's test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times, each a process of its own: 25 tests passed each time (the hot-apply test is in `admin::pipeline_tests`, which the golden run includes), the 36 golden files the same bytes after every run and the tree clean; `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (the 13 targets' seeds and regressions; no lockfile changed by the build); `portable-core`'s `cargo check` of the pure crates for its five targets; every commit of the lot checked on its own (`cargo check` of the workspace and of the agent with the privileged features, `fmt`, clippy, the agent library's tests 543, nn-linux's 769 then 770, nn-core's 1,033, xtask's 193, then 197 with the ratchet): all pass. The pins pass unchanged, by name (nn-proto, `common`, the eBPF crates and the golden cases untouched): `encoded_frames_are_pinned`, `chain_format_pin` (5, its generator ignored), `chain_format_clock` (2), `crypto_vectors` (19), nn-core's rule-policy tests (12). The identity build (each commit exported with `git archive` into one path and built as the release job builds it: x86-64-v2, stripped and unstripped, the debug build, the tarball, the `.deb`, the SBOMs): the eBPF object and its stamp, the watchdog and the scanner byte-identical to `main`'s; the tarball's 72 entries and the `.deb`'s 79 the same paths and modes; the three SBOMs the same (146, 59 and 112 components); `posture_demo`'s output, the agent's `--help`, `--version`, `--build-features` (release and debug), `--btf-check` and a bad flag's error, nn-admin's `--help` the same. The agent and nn-admin differ; function by function (objdump of the unstripped builds, addresses and the linker's data symbols masked): nn-admin 3,707 of 3,709 the same, the 2 the overlay gate's (`AgentAdminHost::overlay_gate` and the gate's drop glue: its configured map); the agent 7,582 the same and 165 differing — 134 in the code the lot changed (its modules and types, and library code instantiated over them), 31 elsewhere, each read: 13 by `int3` padding only, 11 by the name the linker kept for a folded `drop_slow` (identical code; the new `Arc<Mutex<Option<Expected>>>`'s), 6 by register allocation with the same calls in the same order (`default_rules_with_net`, hashbrown's and `RawVec`'s growth), 1 (`impact::trust::topmost_same`) by an inlining choice —, 114 only in `main` (the removed setters, their statics' `OnceLock` initialisers, the tasks renamed) and 97 only in the tip (the handles). The test list: `main`'s 3,176 names and the 7 new (3,183), none removed, no `#[ignore]` added.

- **Lab PR 265 — nn-agent, nn-linux: a signing key made to look absent
  refuses the start where it re-keyed the install — every way the review
  of #468 found while the previous agent's pins are there; a reboot with a
  persistent view that hides both trees is still open (Wave 4, security
  follow-up of the independent re-review of #466, F4-bis; C23, C01; no
  level changes).**
  - What was wrong (pre-existing, found by the re-review): since review
    #466 F4 a key that is there but cannot be loaded refuses the start, but
    an absent key was minted as at a first boot, and root could make it
    look absent without the unlink the deny hooks refuse — a bind mount
    over `/etc/northnarrow` on the host (no deny hook covers `mount(2)`;
    the self-integrity watcher only reports it), or a runtime drop-in
    (`TemporaryFileSystem=`, `BindPaths=`) — then `cgroup.kill` (C20,
    allowed). The watchdog's respawn minted a new key, published its
    public half and went on signing every chain under it: the signing
    identity reset with one INFO line.
  - What changed: two checks first in the preflight, before the start
    registers, bootstraps a file or reads its identity, each a checked step
    the integrity proof requires (nn-linux `boot::checks::agent_mounts` and
    `signing_identity`, `boot::continuity`). Mounts: in the agent's own
    mount table every mount at or under `/etc/northnarrow`,
    `/var/lib/northnarrow` and the directories of the files that make the
    agent must be a bind of a directory onto itself (the same filesystem as
    the mount under it, the directory that is there — the unit's
    `ReadWritePaths=`; a separate `/var` or a btrfs subvolume are such
    layouts); anything else refuses, a mount above them is not judged.
    Identity: a key whose name holds nothing, where its public half, the
    install's id or a signed first row of a chain is found, refuses and
    nothing is minted; the key's loader never mints beside a public half.
    Both unsigned, exit 78, the registration withdrawn (one exit,
    `refusal::refuse_unsigned`); no override. The unit makes its runtime
    drop-in directory before every start (`ExecStartPre=+/bin/mkdir -p`)
    and the deny hooks register it NOCREATE (no eBPF change): a runtime
    drop-in there needs a signed trusted-installer window; the watchdog
    and the installers write none there (the lab's `epg-check` opens a
    window first).
  - After the independent review of the PR (#468, "merge after X"): one
    byte-level `mountinfo` reader (nn-linux `mountinfo`) for the start and
    the watcher — the ASCII space the only separator, `\ooo` escapes as
    bytes, `OsString` paths, the line's shape checked; a malformed line
    refuses only when it may concern the agent's directories (R1: a path
    holding U+00A0 shifted the fields, a bind went unseen; R3: a byte that
    is not UTF-8 in any mount refused every start); the watcher's sandbox
    rule the start's self-bind rule. The kernel's proof (R2, fix a, no eBPF
    change): with the previous agent's pins there, `/etc/northnarrow` and
    `/var/lib/northnarrow` must be the inodes its `PROTECTED_INODES` holds
    (`agent_mounts`: a copy over an ancestor, a rename above, another root
    refuse), a start of the binary it protected is its restart and keeps
    its key (`signing_identity`: an `ExecStart=` redefined with every
    identity path in an empty directory refuses), one bpffs alone at
    `/sys/fs/bpf`. Evidence (R8): any lookup that is not "not found", the
    manifests and archives, a written head anchor. Re-key (R5): the journal
    and the fallback chains archived first, a branch for the agent that
    refuses to start (disable, archive, reboot, `uninstall.sh --purge`,
    install). Test holes closed (the same basename, the same path on
    another filesystem, the NBSP and non-UTF-8 tables, `Cli::identity_paths`
    and `state_dirs`, both NOCREATE directories): the review's mutations
    M2, M2d, M4 and M5 each fail a test now.
  - Re-keying on purpose: retiring the install's identity — the chains
    archived with `agent.sig.pub`, `uninstall.sh --purge --grant-key`,
    install again (`INSTALL_UPGRADE_UNINSTALL.md` §3.10); no `nn-admin`
    verb re-keys (none existed).
  - Open (the review of #468, section C): after a reboot (no pins), a
    persistent mount, drop-in or generator that swaps both `/etc` and
    `/var/lib`, or moves every identity path, still looks like a first
    install; a copy of the binary started by a drop-in is not the protected
    binary; R4, the window between the check and the key's ~13 loads (one
    decision — `KeyPresent` or `FirstInstall` —, one load,
    `load_or_bootstrap` split into `load_existing` and `mint_first` with
    `O_CREAT|O_EXCL`); R6, the false refusals a dedicated volume on the
    agent's directories gets (a `findmnt` pre-check in install.sh before it
    stops the units, an exception pinned in the manifest: mount point,
    fstype, filesystem UUID); R7, a `tmpfiles.d` entry for the runtime
    drop-in directory, and `systemctl revert` (`EPERM` outside a window);
    R2 b–d, the identity's paths pinned in the manifest, a root rule for
    the ancestors, an `sb_mount` deny (CM-12), the public key pinned off
    the host (TOFU); R5's signed `identity_retired` row and the old public
    key's hash in the new install's first `agent_boot`; a key replaced by
    another valid one offline (no new capability).
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, ssh 2522, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; ubuntu2404 is lot 264's). `main` 118d5044 synced, built (release, test-privileged,debug-trigger) and installed; the reproduction on it, as root on the guest (the probe `k265-probe`, each case undone before the next): R1 an empty directory bound over `/etc/northnarrow` and a copy of `/var/lib/northnarrow` over it (so that no row lands in the real chains), on the host, then `cgroup.kill` of the agent's cgroup: the watchdog respawned the agent 1 s later, its journal `bootstrapped fresh agent signing key` and `agent signing key's public half published` (INFO), a new public half (e6a6912d… for the installed 051c267e…), an `agent_id`, an audit log and a head anchor made in the empty directory, READY; the copy's three chain manifests grew by rows of the new key; restored (both cgroups killed, the mounts off, both units started): the installed public half unchanged, the audit chain 5,117 rows "hash chain intact, all sigs valid". R2a: `/run/systemd/system/northnarrow-agent.service.d` made, a drop-in written in it and the directory renamed: all allowed. R2b: a runtime prefix drop-in (`/run/systemd/system/northnarrow-.service.d`, `ReadWritePaths=` reset — else systemd keeps the unit's bind of the same path over the tmpfs —, `TemporaryFileSystem=/etc/northnarrow /var/lib/northnarrow`), `daemon-reload`, `cgroup.kill`: re-keyed in the tmpfs, READY. `tamper-check` on `main` (a first run was cut at case 60 by the host's WSL restart; run again): 75 cases, 72 OK, C27 and C57c the known gaps, C64 the recorded deviation. The lot's code (f4e29bc5; the commit after it is this documentation) synced, built and `upgrade-check`ed from that `main`: refused without `--upgrade`, the window, both units restarted, the identity the same, 17 of 17 deny hooks, 34 own LSM programs before and after, no foreign one; the upgraded boot's preflight `steps=agent_mounts,signing_identity,ebpf_object,…` (the unit's `ReadWritePaths=` binds, `/etc/northnarrow` and `/var/lib/northnarrow` each onto itself in the agent's mount table, pass) and the runtime drop-in directory made by `ExecStartPre=` and registered. `test-ignored` (every `#[ignore]` test as root, single-threaded, its five runs exit 0): 77 suites, 94 passed, 0 failed — the two new e2e (`a_key_absent_where_an_identity_was_is_refused_and_none_minted`, `the_agents_directory_bound_over_is_refused_and_nothing_written`) and the lot 262 six on the real kernel —, the tests' agents' 50 chain checks `result="ok"`. Installed, the same probe: R1 refused (`start refused gate="agent_mounts" exit=78`, `could not record the refused boot in a signed chain`), the empty directory still empty, the copy not grown, nothing loaded by the respawn, restored with the public half unchanged; R2b refused the same way. A second pass (the first ran R2a inside R1's cleanup window, and R3 stopped on a helper's exit status, leaving R4 without a running agent; the probe fixed, the lot's code upgraded from `main` again): R2a outside any window (320 s after the last grant): the drop-in's write, the directory's rename and its removal each refused (`EPERM`); R4 another valid key bound over `agent.sig.key` (the public half bound onto itself, so that nothing could be renamed over it), `cgroup.kill`: refused `agent_mounts`, the journal naming `/etc/northnarrow/agent.sig.key (ext4 /dev/vda1, its directory /root/k265-other.key)`, the foreign key not loaded; R3 in a signed window, both units stopped, the key moved aside, `systemctl start`: exit 78, `start refused gate="signing_identity"`, the evidence listed (the public half, the id, the audit log's and five chains' signed rows), no key minted; the public half, the id and the audit log's head unchanged (its two new rows the window's grant and the `agent_stop` before the start), the key put back in the same window and the units started. `tamper-check` on the lot's code: the same 75 outcomes and verdicts as `main`, case by case — C38 differs in its pids, C30 counts 97 protected inodes where `main` has 96 (the runtime drop-in directory) —; the evidence of 5 cases differs by what landed in a case's window (the boot findings of the probe's last restart in C02 on the lot's code, C03 on `main`; the watcher's clearings between C15 and C26, C43 and C57c). Back to `main` (`upgrade-check` from its tree, the downgrade): OK both times (17/17, 34 own LSM programs before and after); the guest left on `main` with both units active, its audit chain 5,453 rows all verified, the original public half, nothing of the probe left, then powered off. Host, on f4e29bc5 with this documentation, `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (the stamp's source 235e2fed…, `main`'s: no eBPF change, so no `verifier-check`); the four clippy runs with `-D warnings`; `cargo fmt --all -- --check`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 72 suites, 3,175 passed, 0 failed, 16 ignored; `cargo test --no-run` with northnarrow-agent/test-privileged,debug-trigger; `cargo xtask attack-coverage --check`; `cargo xtask golden` five times (24 tests each, the 33 golden files the same bytes, the tree clean); `cargo +1.89.0 check --workspace --all-targets --locked`; the fuzz replay (13 targets; no lockfile changed); `portable-core` (5 targets). Mutations, each applied alone and the tests run: the mount rule finding nothing, the rule judging the filesystem only (not the directory), the sentinel never refusing, the loader minting beside a public half, the evidence read following a link, an unsigned first row counted as evidence, the unsigned refusal's own `process::exit`, its withdrawal skipped: each fails one test or more. After the independent review of the PR (#468): On the same guest, `main` 8788e0d0 (lot 264 merged) synced, built and installed, then the reviewer's variants as root, each undone after: V1b, copies of `/etc` and `/var/lib` (each with an empty `northnarrow`) bound over them on the host, `cgroup.kill`: the watchdog's respawn minted a key in the copy (`bootstrapped fresh agent signing key`) and reached READY; V3b, a drop-in in `/run/systemd/system.control/northnarrow-agent.service.d` (not protected) redefining `ExecStart=` with the key, the id, the audit log, the head anchor and every chain in an empty `/opt/k265-v3` (and `ReadWritePaths=` for it), `daemon-reload`, `cgroup.kill`: minted there (a new public half, 58e34c62…), READY; restored, the installed public half unchanged each time. `tamper-check` on that `main`: 75 cases, 72 OK, C27 and C57c the known gaps, C64 the recorded deviation. The lot's code (e19a5a46; the commits after it change a unit test's fixture path, a refusal's wording and this documentation) synced, built, `upgrade-check`ed from that `main` (OK: the identity the same, 17 of 17 deny hooks, 34 own LSM programs before and after, no foreign one), `test-ignored` 5/5 exit 0 — 78 suites, 94 passed, 0 failed, 52 chain checks `result="ok"`: the tests' agents, started with earlier tests' pins there, refused none —, installed, then: P0, both cgroups killed — the 51 pins still there —, a plain `systemctl start` with them (READY), the watchdog's respawn after a `cgroup.kill` (READY); V1a (the copies without `northnarrow`): the unit does not start at all, systemd's "Failed to set up mount namespacing: /run/systemd/unit-root/etc/northnarrow: No such file or directory" (`ReadWritePaths=`), nothing runs or is minted; V1b: refused `agent_mounts` — `/etc/northnarrow` and `/var/lib/northnarrow` "not the directory the previous agent protected" (a first V1 pair ran on copies left by `main`'s V1b, whose state directory kept `+i`; run again on fresh copies, the same verdicts); V3b: refused `signing_identity` — "this start runs the binary the previous agent protected …, a restart of it, but its signing key /opt/k265-v3/agent.sig.key is not in a directory that agent protected …; … is absent: a restart never mints a key" —, nothing in `/opt/k265-v3`; B1, a second bpffs stacked on `/sys/fs/bpf` (the pins hidden), `cgroup.kill`: refused `agent_mounts` ("2 mounts stacked on /sys/fs/bpf"); R1 again (an empty directory over `/etc/northnarrow`, a copy over the state directory): refused `agent_mounts`, the empty directory still empty; each restored with the public half unchanged. `tamper-check` on the lot's code: the same 75 outcomes and verdicts as `main` 8788e0d0, case by case (C38's pids; C30 97 protected inodes for `main`'s 96, the runtime drop-in directory); the evidence of 4 cases differs by timing (C15's freeze ended in the watchdog's stuck recovery and a new agent this time, which started with the pins there: no refusal). §3.10, as written: branch A on the running install — step 0 (the journal's export, 33.5 MB; the state, its audit log 5,717 rows verified with the archived public half off the live files), `uninstall.sh --purge --grant-key` (the window, the pins dropped, everything removed), install: the first start minted a key (new public half 46de5f92… for 051c267e…), the archive still verifies, the archived journal holds the earlier refusals; branch B — the key moved aside in a window, the start refused (`signing_identity`), and after the window closed the signed uninstall failed as the review said ("PROTECTED … no trusted-installer window", nothing removed); both units disabled, step 0, the reboot (under WHPX the guest's reboot ends QEMU: brought up again cold, the same for the bpffs), `uninstall.sh --purge` without `--grant-key` (no pins, the units inactive): complete; install: a new key (6721d97f…), the archive verifies with the old public half, its journal holds the refusal. Back to `main` 8788e0d0 (`upgrade-check` from its tree): OK; the guest left on `main`, both units active, its audit chain verified, the archives of both branches kept, nothing else of the probes left, then powered off. Host, on the final code (264ddf6f) with this documentation, `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo xtask build-ebpf --release` (no eBPF change), the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test` 73 suites, 3,194 passed, 0 failed, 16 ignored, the privileged no-run, `attack-coverage --check`, `cargo xtask golden` five times (33 files the same bytes, the tree clean), `cargo +1.89.0 check`, the fuzz replay (13 targets), `portable-core` (5 targets): all pass (a first run caught a fixture path under `/home/x`, xtask's hygiene test; fixed). Mutations, each alone: the review's M2 (the same basename accepted), M2d (no `dev` check), M4 (the runtime directory out of the NOCREATE list), M5 (`identity_paths` with the audit chain only) and new ones — the view check always passing, no restart rule, no bpffs rule, a split on U+00A0, malformed lines ignored, archives not looked at, the watcher's old suffix rule — each fail one test or more.

- **Lab PR 266 — nn-admin's output matrix, committed (Wave 4 Phase 2,
  test infrastructure before R12–R14; no capability, no level changes).**
  - What was wrong: lab PRs 259 and 263 proved "nn-admin's output identical
    to `main`" with a matrix of 1,964 cases — stdout, stderr, exit status,
    files written and requests sent to a mock agent — run from a
    scratchpad, which a stopped session deleted. The next refactors
    (R12–R14) had nothing to prove the same against, and no test of the
    tree held nn-admin's messages, exit codes or requests: a change of one
    of them passed CI unseen.
  - What changed: `agent/tests/nn_admin_matrix/`, an integration test of
    the agent package (the `nn-admin` binary is its shim, on the agent's
    host): 2,703 cases, each in a directory of its own, an emptied
    environment, umask 022, compared byte for byte with
    `agent/tests/golden/nn-admin/expected/<area>.txt` (13 files) on every
    `cargo test`. The mock agent is a thread of the test serving the case's
    socket with nn-proto's frames and a script of replies; the keys are
    constant seeds (the agent's RFC 8032 test 1's, chain-pin-v1's), the
    install's id chain-pin-v1's, the chains written by the agent's writers
    with a fixed clock (2025-06-15, one second a row), the overlays signed
    at that time. Normalised, each after it is checked: the clock (a time
    within ten minutes of the run), `init`'s fresh key, `config overlay
    sign`'s random nonce and its signatures (verified with the fixture
    keys), the mock's view of each request (its time within five minutes,
    the nonce it issued, each signature verified and named), the host's
    hardening checks (`host-check` first compared with the agent library's
    checks run in the test, then each status and value masked; `status`'s
    summary line the same way), the case's directory and the repository
    (no case prints them) and `policy test`'s temporary `/proc`. A stream
    or files longer than four lines that an earlier case of the area has
    byte for byte name that case (`policy test` gives one output for many
    inputs: about 2 MB in all). `cargo xtask golden [--update]` runs the matrix
    after the library's replays (`EXPECTED_DIRS` +1); `--update` and
    `NN_GOLDEN_UPDATE=1` are refused with `CI` set.
    `docs/validation/GOLDEN_REPLAY.md` §8. `xtask/tests/test_state_isolation.rs`:
    the harness names nn-admin's default directories (to run the
    default-path cases only where none exists), listed in
    `HOST_PATH_USERS` with that reason.
  - Coverage, against lab PR 259's: help texts and clap's errors 505
    (every subcommand found by walking `-h`: `--help`, `-h`, `help <path>`;
    per subcommand an unknown flag, a missing argument, a stray positional,
    each option without its value, each flag twice and with a value; values
    clap refuses), `init` 13, `verify-keys` 17, `host-check` 2, `audit read|verify` 58,
    `chain verify` 45 (chain-pin-v1's log and heads, every class of lab PR
    256 on the flat audit chain and on the rotating FIM drift log, a head
    anchor reached, cut and rewritten), `config overlay status|sign` 56,
    `policy show|test` 548 (lab PR 259's 520 — the 24 golden cases and
    their 205 events as two streams × the built-in defaults, the three
    golden candidates and one refused × shipped lists or none × table or
    JSON — 18 errors, `show`'s 10), the socket verbs 789 (37 verbs, each
    success reply, the ten refusals, 7 transport faults for a signed verb
    and 5 for an unsigned one where lab PR 259 had 6, no socket, a socket
    nobody listens on, and 57 argument variants; lab PR 259: 647), key and
    identity errors through every signed verb 544, closed pipes 48, default
    paths 78. Not reproduced: the A/B of two builds (the committed files
    are the reference: a pull request's diff of them is that A/B), the lab
    build's `debug force-posture` (the test is not compiled with
    `debug-trigger`; in this build it is clap's unknown subcommand, a
    case), a key owned by another uid (needs root; the mode check before
    it is covered), an agent that never answers (the 5 s timeout; closed,
    cut and garbled frames are covered), rows in the canary, detections,
    status-events and netflow chains (listed empty; the classes run on the
    audit chain and the FIM drift log).
  - Found, pinned as they are (not changed here): `unlock`'s error for a
    key or an identity file it cannot read says "the signed unlock got no
    reply — an agent older than this nn-admin …" (the context wraps the
    whole signed request); `chain verify` with no chain on disk at all
    reports every chain OK and exits 0; `init` that cannot append the
    public half leaves the private key written and exits 1; clap's own
    `--help` and `--version` into a closed stdout exit 0, not 141; an error
    into a closed stderr exits 141, not the error's code.
  - Open: the findings above, for a lot of their own; rows in the other
    chains; the lab build's matrix, if CI ever runs the `debug-trigger`
    tests.
  - Lab: host tests only (no guest, no root, no agent). Host, on the lot's tree, `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 74 suites, 3,171 passed, 0 failed, 15 ignored, in 176 s (`main` 8788e0d0: 73 suites, 3,168; the matrix's 2 tests and xtask's 1); `cargo xtask golden` three times, each a process of its own: 27 tests passed each time (the library's 25 replays and the matrix's 2), every golden file the same bytes before and after each run (sha256 of them all dbf57a09…). The matrix: 2,703 cases in 8.8 to 10.1 s a run (8 threads, the debug build), its cases built in 2.5 s; three runs in a row, and the three golden runs, the same bytes. The mutation check, each on the committed goldens and reverted after: `status`'s help text changed ("Print current posture" → "Print the current posture"): the test fails with 4 problems (`help.no-arguments`, `help.help-alone`, `help.status.long`, `pipe.stderr.help`; the cases that name them by "the same bytes as" follow), each with the golden line and the new one; `unlock`'s exit code for a refused role 7 → 8: it fails on `sock.unlock.refused.role-denied` (`exit: 7` / `exit: 8`); reverted, it passes. Only the comments of the harness and this line changed after the gates' run; the matrix, fmt, clippy of the agent's tests and the state-isolation ratchet run again on the final tree: all pass.
- **Lab PR 266b — nn-admin's output matrix: a refused connection is
  always refused (follow-up of lab PR 266; test infrastructure, no
  capability, no level changes).**
  - What was wrong: in one of five `cargo xtask golden` runs of lab PR
    265, `sock.net-status-json.refused-connection` read `net status:
    reading frame length header: Connection reset by peer` where its
    golden file says `connecting to admin.sock: Connection refused`; the
    matrix runs in every `cargo test`, so CI would have failed at random.
    The cause is in the harness, not nn-admin: the case binds a listener
    and closes it, leaving a socket file nobody listens on, while other
    threads of the test start nn-admin for their cases. A child holds a
    copy of every descriptor of the test from its fork to its exec
    (`O_CLOEXEC` closes them at the exec only); when one was between the
    two as the listener was closed, the listener lived on in it, the
    case's connect went into its backlog, and the copy's close at the exec
    reset the connection. Shown alone (a listener closed while a forked
    child that has not exec'd holds it: the connect succeeds and the read
    is reset; without the child: refused). The closed-pipe cases had the
    same window: the read end closed before nn-admin starts could live on
    in another thread's child, and nn-admin's write would have found a
    reader.
  - What changed: one lock in the harness (`harness::FORKS`): every child
    the test starts (each case's nn-admin, the `-h` walk of the help
    cases) is spawned holding it shared, from before its fork to after its
    exec (`Command::spawn` returns once the child has exec'd); the
    refused-connection listener is bound and closed, and a closed pipe made
    and its read end closed, holding it exclusive — no child of the test is
    between its fork and its exec while either exists. The error text is
    not normalised and no golden file changed. The other socket cases,
    checked for the same race: a copy of the live mock's listener or of an
    accepted connection only delays an end of file by the fork-to-exec
    window (the mock keeps its listener until nn-admin has exited, and
    closes a connection only after reading every byte nn-admin sent, so no
    close leaves unread data and resets the peer); no case connects and
    exits without a request, and no golden file holds a read error or a
    reset. `GOLDEN_REPLAY.md` §8 says how the cases are kept apart.
  - Lab: host tests only (no guest, no root, no agent). Before the fix: the mechanism shown alone (a Unix listener closed while a forked child that has not exec'd holds it — the connect succeeds and the read is reset, `Connection reset by peer`; with no such child, `Connection refused`); the matrix on `main` 8df17fbb, 20 runs beside a fork storm: 0 failed (the race is rare: lab PR 265 saw it once in five golden runs). After it, the matrix's test binary run in a row by `loop-matrix.sh <worktree> <runs> <load> <log>` (the binary under `target/debug/deps/nn_admin_matrix-*`, each run its own process): 50 runs beside a fork storm (24 `while :; do /bin/true; done` loops under `timeout`, load average 42 on 24 cores), 0 failed, 17.3 to 24.1 s a run; 30 runs beside a parallel release build of the workspace (24 jobs, its own target directory), 0 failed, 9.2 to 13.0 s. Host, `set -o pipefail`, `CARGO_BUILD_JOBS=4`: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test -q --workspace --exclude northnarrow-agent-ebpf --locked --no-fail-fast` 74 suites, 3,171 passed, 0 failed, 15 ignored, in 193 s (`main`'s totals: no test added or removed); `cargo xtask golden` five times, each a process of its own: 27 tests passed each time, every golden file the same bytes before and after each run (sha256 of them all dbf57a09…, `main`'s) and the tree clean. The matrix still 2,703 cases, 9 to 10.5 s a run unloaded. Only this line changed after the gates' run; fmt and xtask's tests (the documentation's among them) run again on the final tree: pass.

- **Lab PR 267 — the priority event bus (Wave 4 Phase 2, R12a of the
  restructure plan, HIGH risk; C01, C14, C23; no level changes).**
  - What was wrong (plan §1.5): every source — the nine ring pumps, the
    exploit guard's, the file-open sensor's, the FIM and network drains —
    sent into one `mpsc` channel of 4,096 events that one consumer read. A
    flood of one class held every other class back: while the channel was
    full every pump waited on its send and its ring dropped in the kernel.
    EXP-13 on `main` (below): a flood of file opens with bursts of tamper
    attempts lost 3,702 of 12,000 `fs_protect` denials in the kernel, and
    each burst's first denial reached the rules 537–611 ms late.
  - What changed (`docs/architecture/EVENT_BUS.md`): a queue per class —
    P0 tamper (`FsProtectDenial`, `BpfSyscall`, `ModuleLoad`,
    `SensorFlood`, `DefenderSignal`, `ExploitPostcondition`; 1,024; the
    sender waits 50 ms, then drop), P1 process (`ProcessSpawn`,
    `ExecCheck`, `IoUring`; 4,096; 10 ms), P2 file (`Fim`, `MassWrite`,
    `FileOpen`, `FileBurst`; 8,192; a new `FileOpen` dropped when full or
    past 2,048 opens, every other file event waits, review 75), P3 network
    (`TcpConnect`, `DnsQuery`, `DnsFlood`, `NetFlow`, `NetListener`; 8,192;
    drop the new event); in P0 only `FsProtectDenial` waits 50 ms then
    drops, every other tamper event waits for room; `CanaryTripped` has the
    class of the event the detector replaces. Every variant placed by an
    exhaustive match (`nn_core::bus::class_of`). Take: P0 first, then P1,
    P2, P3 by weighted shares 2 : 1 : 1 (smooth weighted round robin), FIFO
    inside a queue. An event of any queue but P1 taken ahead of queued
    execs hands them to the lineage and the rules first; the lineage keeps
    three execs per pid and answers as of the judged event's time. Per-queue
    counters (queued, dropped, depth, max depth, longest wait since boot and
    in the last sample, sends that waited and the longest wait, takes by
    share ahead of a higher queue, latency queue → decision p50/p99/max)
    and the eight loss stages in `nn-admin status --key` (1–3 the kernel
    ring, the kernel budget, the decoder; 4 the bus; 5–8 named, not
    counted: R12b, R12c, R15). A drop: a WARN, a signed `event_bus_drop`
    row (P0 within a second, at most one a second; the others at most every
    600 s; every drop in a row), `TelemetryLoss` at any P0 drop and past 64
    a sample for P1–P3; at the stop the bus closed and what it still held
    counted in a signed `event_bus_stop` row. The DNS pump's outbox for a
    full channel is gone.
  - Ordering (`agent/src/decision/golden.rs`): every order of a golden
    case's events that keeps each class's own order gives, for each rule
    and process, the same strongest verdict and the same responses — all
    such orders for 25 of the 28 cases, class-major orders, the bus's take
    order with the consumer behind and 256 random merges for the others
    (973). It found three stores that depended on the order between classes
    (the third, the lineage answering with a pid's latest exec, by the
    independent review — below),
    fixed: the lineage and the chains' ancestry tree learned an exec only
    when judged (NN-L-EVA-003, NN-L-NET-026/027, NN-L-IMP-001 lost their
    target, parent or actor when the exec came later; an exec ingested
    twice, or after a newer one of its pid, now changes nothing); the chain
    store let one chain keep another off a flow (a flow whose staging exec
    came last lost the CHAIN-002 it has in kernel order) — each chain now
    answers a flow once in any order, and a late exec's CHAIN-002 prefers
    the egress whose kill is not held at port 53. Golden:
    `shadow-chain007-late-exec` gains CHAIN-002 on its late exec's line
    (responses unchanged), as do the two nn-admin matrix files that replay
    it; the matrix's full status shows the bus. The unsigned status frame
    is one byte longer (the appended field's `None`).
  - Independent review (PR #471, "merge after X"), fixed in the lot: A1
    (HIGH) an event could be judged on the image of a later exec of its pid
    — a File canary's reader exempt as its later `restic`, a `/tmp`
    program's credential read and connect in the package carve-out once it
    exec'd `dpkg`, NET-006/019 on a later `nginx` — the lineage keeps three
    execs per pid and every lookup of a judgement is scoped to the event's
    time (`lineage::judged_at`, `*_at(pid, ts)`), four golden cases; A2 the
    network starved under a higher class's flood (aging gave it one take in
    65, ~110 events/s) — the shares, `TelemetryLoss` for P3, the
    reviewer's simulation as a test; M1 a root denial flood dropped a rare
    tamper event — those wait for room; M3 the stop and a crash — the
    `event_bus_stop` row, the P0 row within a second; B2 the windowed wait,
    B3 the opens' cap, B4 the loss sample off the workers, M2 the
    open-sensor pump's signals first; wiring tests for the six mutations
    that survived (all 16 of the review's and 19 of the fix's caught, the
    lot's table in the PR); the soak report's journal namespace. Behaviour
    change outside the corpus: a late exec whose process had a port-53 flow
    to a non-resolver and then another flow now kills for the later one.
    Lab after the review: on ubuntu2404 only (ubuntu2204 was lot 268's), `main` 769d5615 and the tip in turn in one tree path, each freshly installed. EXP-13: `main` lost 3,681 of 12,000 `fs_protect` denials in the kernel, first records 532–602 ms; the tip 0, 12,000 accounted, 0.45–2.8 ms, P2 held at its 2,048 opens (longest wait 0.51 s). EXP-13c (new: the same flood and bursts plus 500 connects/s and 20 DNS queries/s of uid 1000, and probes — a connect to TEST-NET-1, in the shipped blocklist, and one from a copy of the helper in /var/tmp): `main` judged its NET-001 and chain probes 456–532 ms after the connect (the process gone), lost 3,732 denials; the tip, four runs, P3 49,8xx queued and 0 dropped each, 18 NET-001 probes judged and killed while connecting (13–27 ms), 24 chain probes judged (1.7–214 ms), no bus drop; in two runs the agent's rings fell behind on the saturated guest (`fs_protect` 408 once, `fim` 1,575 and 439, `open_sensor` 6,819 once) while P0's sends waited at most 3.4 ms — the pumps short of CPU, not the bus (the run without probes dropped nothing; pumps on threads of their own are R12b's). EXP-13b (the loop stalled 4 s, a burst of 3,000): `main`'s channel held it (3,000 judged, the first 3.94 s late); the tip 1,971 judged, 76 denials dropped on P0 after 50 ms — five signed rows one second apart during the stall — and 953 in the ring, 3,000 accounted. Overhead within noise (open +30.5 / +29.4 %, exec +13.4 / +8.6 %, connect +43.5 / +44.9 %). Soak pair, each after a fresh install, the same 0.8 h: RSS 33.2 → 55.7 MB (`main`) and 33.3 → 55.5 MB (the tip), threads 9 → 11 and 9 → 10, no restart, no ring drop, the bus's queues empty at every sample with nothing dropped, WARN/ERROR lines 2,887 / 1 and 3,022 / 1 (the one ERROR the lab's admin key on the host) — the first pair's 23 threads against 16 were not comparable runs; the soak report's WARN/ERROR file now reads the units' namespace by tracing level (it was empty: journald gives every line priority 6). Gates on fc23d1d1: build-ebpf, clippy ×4, fmt, 74 suites 3,237 passed 0 failed, the privileged build, attack-coverage, `golden` ×5 (53 files the same bytes), MSRV, 13 fuzz targets, portable-core 5 targets, lockfiles unchanged; the same gates on the merge with `main` c209e353 (lot 268, 35811cd1): 74 suites, 3,252 passed, 0 failed, every other gate green (`tmp/fix471/`).
  - Second review (PR #471, "merge after X"), fixed in the lot: R-A — the
    fix's strict P0 left exec, file and network events no take while a
    flood kept P0 full, and any user can keep it full on 6.8 (the lab: a
    uid-1000 `fork` + `bpf(BPF_MAP_CREATE)` loop, refused with EPERM under
    `unprivileged_bpf_disabled=2`, reached the agent's hook 581,951 times
    in 40 s on `main`) — every queue in the shares, 8 : 2 : 1 : 1, and a
    denial repeated by its process on its inode within a second counted
    into the one queued and signed (`event_bus_coalesced`); R-D — denials
    and `bpf()` calls take all of P0 but 64 slots, the rare tamper events';
    R-E — the opens' cap counts the opens, a write-open of a CRITICAL or
    PERSIST file waits for room, the open-sensor pump checks the cap before
    it builds an open; tests for the three mutations that survived it (the
    history's depth, a FIM record and a flow judged as of their own time,
    the golden case `a1-netflow-no-exe-later-exec`); 46 of 46 mutations
    caught. Lab on ubuntu2404 (6.8), `main` c209e353 against the tip
    9d0deab2, each freshly installed: EXP-13d (that bpf loop, 8 processes,
    with 500 connects/s, 20 DNS queries/s and probes of every class — a
    connect to TEST-NET-1, and a /var/tmp program that reads a decoy GPG
    key and connects): the tip queued 623,646 `bpf()` events in P0 (at
    most 960, its share) and dropped none on the bus, P1–P3 dropped
    nothing, every probe judged — NET-001 6/6 in 18–23 ms, the staged
    probe's exec, file and network records 6/6 each — the `bpf` ring 672 in
    the kernel while its pump waited; `main` (one FIFO channel) judged them
    all too. EXP-13e (8 processes' `fork` + refused `chmod`, root): the tip
    578,189 denials queued, none dropped on the bus, every probe judged,
    `fs_protect` 888 in the ring (`main` 236), all accounted (records +
    held + coalesced + ring). EXP-13: the tip 0 `fs_protect` drops (`main`
    3,699), the bursts' 12,000 denials 8 records + 11,992 coalesced, first
    records 0.23–1.2 ms (`main` 529–597 ms). EXP-13c ×3 with the agent's
    threads' CPU and the CPU pressure: P3 49,836–49,838 queued and 0
    dropped (longest wait 29 ms), NET-001 18/18 in 13–29 ms; rings: none,
    `fs_protect` 23, `open_sensor` 5,543 — in runs where no send of the bus
    waited for room, the agent used 56 s of CPU in the flood's 45 s on both
    builds (`main` 55 s) and the guest's CPU pressure covered ~36 s of it:
    the pumps short of CPU, plausible, not proven. Overhead within noise
    (open +27.3 / +28.8 %, exec +8.8 / +7.6 %, connect +43.5 / +39.5 %).
    Open from it: R-B (a deeper history and the walk on from the parent),
    R-C (a FIM `Modified` carries its close's time: an eBPF and wire
    change), R-F (the `/proc` fallback inside a judgement's scope; an
    assertion for a lookup outside one), a kernel budget per uid for the
    `bpf` hook (`tmp/fix471/lab3/`).
  - Third review (PR #471, "merge after X"): C1 — a denial the bus
    dropped opened a coalescing window, so for a second that process's
    repeats were counted into an event never judged: the window opens once
    the denial is queued; C2 — the coalescer's eviction scanned its 512
    windows per new key (a fork loop): a FIFO of keys, O(1); C6 — a denial
    keeps its 50 ms on the queue's slot too; C4 — the window's length is
    tested. Mutations on the bus's runtime, 22 of 22 caught (the window at
    60 s among them). EXP-13e ×3 per build on ubuntu2404, clean installs:
    `fs_protect` ring drops `main` 0, 662, 132, the tip 472, 0, 2,783 of
    ~590,000 denials a run; on the tip no bus queue dropped and no send
    waited for room, every probe judged (NET-001 18/18, 13–27 ms), the
    agent's CPU 37.3 s against `main`'s 37.0 s in the flood's 40 s with the
    guest's CPU pressure ~34 s of it — the fs_protect pump's own pace on a
    saturated guest, its sends dearer than one `mpsc` send (the coalescer,
    two semaphores, the queue's lock): batching them is with the pumps'
    threads in R12b. C3 (a cap per uid on `bpf()` records) and C5 (the
    coalesced repeats in AT-001's record) are open (`tmp/fix471/lab4/`).
  - Open: R12b (the decision thread without `await`: `exe_identity::
    resolve` in every pump, the systemd state as a snapshot,
    `close_if_expired` on a tick, the canary append through the writer,
    module provenance's cache; stage 5, the decision delay per class; the
    `Envelope`; the posture corpus under the same property); R12c (the
    response dispatcher by severity, no action without a signed record,
    stages 6–7, signed `telemetry_loss` rows, the heartbeat).
  - Lab: On Ubuntu 24.04 (6.8.0-147, the lab guest ubuntu2404, ssh 2322, QEMU for Windows with WHPX, 4 vCPU, 7 GiB) for the before/after, `main` 8df17fbb and the lot's code d88dd0f9 exported in turn into one tree path (`~/nn-r12a-lab/lab-tree`: the eBPF object, built there by each, is byte-identical, `8261779781f5…`), each synced, built (release, test-privileged,debug-trigger) and installed. EXP-13 (`deploy/lab/bus/exp13.sh`, the same load on both: 4 processes × 32 threads opening `/etc/passwd` and `/etc/login.defs` once per thread as uid 1000 in a transient unit with CPUQuota 300 %, 40 s; from +5 s 8 bursts of 1,500 `chmod()`s of `/etc/northnarrow/admin.pub` to its own mode, 3 s apart, as root): `main` — 2,368,128 opens; 12,000 attempts refused, `fs_protect` RING_DROPS +3,702 (lost in the kernel), AT-001 accounted 121 records + 8,177 held by the detection budget = 8,298 (= 12,000 − 3,702), each burst's first record 537–611 ms after the burst began, `open_sensor` RING_DROPS +2,071,038; the lot — 2,273,088 opens; 12,000 refused, `fs_protect` and `open_sensor` RING_DROPS 0, AT-001 121 + 11,879 held = 12,000, first records 0.4–4.8 ms, P0 12,000 queued, 0 dropped (3,007 sends waited for room, under 50 ms; max depth 1,024; queue → decision p50 90 ms, p99 147 ms within the bursts), P2 1,989,071 `FileOpen`s dropped (WARN each sample, a signed `event_bus_drop` row of 491,744 at the first); both runs: a locked COMBAT (AT-001), NEUTRALIZE on an offender already gone, no isolation, released with the lab key (`tmp/r12a-lab/exp13-{main,tip}/`, `exp13-compare.md`). EXP-13's stall mode (the lot's lab build, `--stall-secs 4`: the event loop made to stand still 4 s by lab PR 216's `debug-stall-loop`, then one burst of 3,000 refused `chmod()`s, no flood): 1,971 judged (AT-001 100 records + 1,871 held), 76 dropped on P0 after their 50 ms wait — a WARN and a signed `event_bus_drop` row (`queue` P0, `dropped_since_last_row` 76, `total` 76) at the next 10 s sample — and 953 dropped in the `fs_protect` ring while the pump waited (a signed `ringbuf_drop` row): 3,000 accounted (`tmp/r12a-lab/exp13-stall/`). Overhead (`nn-lab.sh overhead 3`, the same guest, agent off/on, medians of 3 rounds; `main` / the lot): open +28.2 / +28.7 %, wopen +31.5 / +31.2 %, exec +9.9 / +8.9 %, connect +41.6 / +44.0 %, udp +9.5 / +13.4 %, dns +7.8 / +3.4 % — within the rounds' noise; the agent's CPU during the runs 20 / 20 ms (open), 220 / 210 ms (exec), 760 / 800 ms (connect). Latency queue → decision per class (the lot's status after the overhead's last round: P0 p50 143 µs, p99 2.3 ms; P1 43 µs, 255 µs; P2 63 µs, 2.3 ms; P3 59 µs, 9.2 ms; the longest wait, about 1 s in P0 and P1, is the boot's backlog before the event loop starts); `main` has one queue and no per-class timing (its EXP-13 first records above). Soak (`nn-lab.sh soak start 1.5 60`, the lab generator at its default rates, the signed status every 5 minutes; the lot's agent as the overhead left it): 1.49 h, 90 samples, 5,342 iterations; no restart, no journal ERROR, CPU 1.3 % on average, fds 211 throughout; every queue empty at every sample, the most each held stable after the first minutes (P0 106, P1 116, P2 8, P3 450), no event dropped by the bus (P1 576,650 queued, P3 100,301); RSS 32.0 → 62.0 MB, growing for about an hour and nearly flat after it (62.1 → 63.3 MB over the last 35 minutes; the file-backed part flat at 25.6 MB from the first half hour, the anonymous part grew); the report's FAIL is the 19,922 `dns_rate` records (stage 2, the kernel's per-process DNS budget) the overhead's `dns 20000` workload held back just before, counted 2 s after the soak began and constant through it (`tmp/r12a-lab/soak-tip/`). `main` on the same guest right after, freshly installed, the same 1.5 h: 1.49 h, 90 samples, 5,349 iterations, no restart, CPU 1.0 %, RSS 28.7 → 59.5 MB (17.4 MB/h; 17.8 for the lot), the same warm-up and the same plateau (59.4 → 60.7 MB over its last 30 minutes) — the growth is `main`'s, the bus adds none; its report's FAIL is one journal ERROR, the lab's admin key on the host signed at its boot inside the window (`tmp/r12a-lab/soak-main/`). The privileged suites on the lot's code: ubuntu2404 `test-ignored` 79 suites, 91 passed, 0 failed (the tests' agents' 52 chain checks `ok`), `tamper-check` 75 cases, 72 OK — C27 and C57c the known gaps, C64 the recorded deviation, as on `main`; ubuntu2204 (5.15.0-198, the second guest, ssh 2522) `test-ignored` 79 suites, 91 passed, 0 failed (50 chain checks `ok`). CI on the pull request: CI, BTF matrix, release, lab VM gate (KVM, 22.04 and 24.04) green. At most two guests up at a time. Gates on the lot's code (0d3dd175) and on its merge with `main` cc1aefd1 (98bd4096), host, `--locked`: `build-ebpf --release`; clippy ×4; fmt; workspace tests 74 suites, 3,193 passed, 0 failed (the merge: 3,219); the privileged build `--no-run`; `attack-coverage --check`; `cargo xtask golden` ×5, the 49 golden files the same bytes each run; MSRV 1.89; the fuzz replay, 13 targets; portable-core, 5 targets; lockfiles unchanged. `posture_demo`'s output identical to `main`'s.
- **Lab PR 268 — nn-agent, nn-linux: the signing key decided once at boot
  and loaded once; the restart rule for any binary in a release build
  (Wave 4, security follow-up of the independent review of #468, R4, and
  its re-review, S1–S3; C23, C01; no level changes).**
  - What was wrong (R4, a TOCTOU): `boot::checks::signing_identity` ran
    once, then about 13 loads by path — the state bootstrap, the audit
    check (`checks::open_audit_log`), the refusals (two), the attest
    phase's deferred open, the head anchor, the detection store and the
    status log, FIM (two), the canaries (two), the network logs (two) —
    each called `AgentSigningKey::load_or_bootstrap`, which minted an
    absent key. A mount laid during the boot, after the check (systemd
    makes the unit's namespace a shared one: a mount on the host reaches
    it), gave a new key at the next load, and a later load a second one:
    one boot's chains under two keys. S1 (the re-review): the restart rule
    of lab PR 265 held only for the binary the previous agent protected; a
    copy started by a drop-in was stopped by accident — the check opens the
    pinned inode map read-write and the BPF guard denies a write handle to
    a process neither protected nor running a protected binary, which does
    not hold with the guard in observe or a read-only open. S2: the restart
    rule covered the key only (the id and the audit log moved away opened
    new chains under the real key). S3: the single-bpffs rule counted
    mounts, so a bind of the same instance onto itself refused every start
    on a host that has one.
  - What changed: the decision is a token (nn-linux `boot::checks`:
    `KeyVerdict::Decided(KeyDecision::KeyPresent | FirstInstall)`; private
    fields, not `Clone`, the `compile_fail` examples show it; a second
    decision in one boot sequence is `BootOrderError::KeyDecided`).
    `KeyPresent` records the file the check saw (device, inode). The start
    builds one `keys::BootKey` from it in the preflight, loads it in the
    state bootstrap (after `preregister_self`), and every phase takes a
    copy (`BootKey::signer`); a load the previous agent's hooks close
    (`EACCES` before the registration) keeps the decision and is read after
    the attach, any other failure is final. `load_or_bootstrap` split:
    `load_existing(path, &KeyPresent)` never mints and refuses another file
    than the one seen; `mint_first(path, FirstInstall)` takes the token by
    value, writes `<key>.tmp` with `O_CREAT|O_EXCL`, links it at the name
    (`link(2)`: `EEXIST` on anything there, where `rename(2)` replaced it)
    and refuses beside a public half; `load_or_bootstrap` stays as the
    tests' door, `#[cfg(any(test, feature = "test-util"))]` (a production
    caller does not compile in a build without dev-dependencies). S1:
    `continuity::restart_findings` (was `restart_key_findings`) treats any
    start with the pins as a restart unless `COPIES_EXEMPT`
    (`cfg!(any(feature = "test-privileged", feature = "debug-trigger"))`).
    S2: the key, the id and the audit log each in a directory the previous
    agent protected, and there. S3: stacked mounts at `/sys/fs/bpf` pass
    when they are one instance (the same `major:minor`, root `/`, the same
    type). Nits: the watcher reports a malformed line over a protected path
    (`mount_over_protected`, W1); `uninstall.sh`'s pin-root message names
    §3.10 branch B (N1); the comments of `boot::BootStep::SigningIdentity`
    and `continuity`'s header name the pins' proof and what stays open
    (N2); a test of `mounts_over`'s `(any)` branch.
  - Tests: the TOCTOU (a key decided present then gone with every piece of
    evidence: an error, no file at the key's or the public half's name, the
    audit check refusing; a key swapped in at the name: not loaded; the one
    key handed to every chain unchanged by what happens to the file after),
    a first install minting once and never over a key planted since the
    check, the decision once per sequence, the restart's id and audit log,
    V3b′ refused under the release rule and accepted under the lab
    builds', the release build holding no exemption, the bpffs self-bind,
    the watcher's malformed line; two ratchets — no source of the
    workspace but the start's one load mints the key or builds a
    `FirstInstall`, and no phase of the start reads a key of its own (each
    signing phase takes `signing_key.signer()`).
  - After the independent review of the PR (#473, "merge after the lab";
    its B1–B5): the tokens carry the key's path they were decided for
    (`BootKey::decided(decision)`, `load_existing(&present)`,
    `mint_first(first)`); a key decided present whose name the check could
    not look at (`seen` `None`: a dangling link) is never loaded; a first
    install removes the leftover `<key>.tmp` of a mint that died before its
    link; `mk-tarball.sh` and `mk-packages.sh` refuse an agent whose
    `--build-features` is not `none` and an nn-admin with `debug` (the
    lab's pkg-check packs its lab build with `NN_PKG_LAB_FEATURES=1`, no
    workflow sets it; xtask `the_release_scripts_refuse_a_lab_build`);
    `IdentityPaths::audit_log` named; a key, id or audit log outside the
    installed layout refuses every restart with the pins there (documented
    as not supported, BOOT_INTEGRITY §1.1, INSTALL §3.10).
  - Open (BOOT_INTEGRITY §1.1): a reboot with a persistent view that hides
    both trees (an off-host record of the public key); the bpffs unmounted
    and mounted fresh (CM-12); the chains other than the audit log moved
    away on a restart (signed by the chain check against the head anchor);
    the copies' exemption in the lab builds; a mount laid after the start's
    one load (the lab below: no mint, but the start goes on in that view
    and registers it, and the real view's next start is refused until the
    pins go); the id is still minted by `agent_id::resolve` outside the
    decision (a restart without it is refused, S2).
  - Lab: On Ubuntu 22.04 (5.15.0-198, the lab guest ubuntu2204, ssh 2522, QEMU for Windows with WHPX, 4 vCPU, 7 GiB; ubuntu2404 was lot 267's, not touched). Two builds of each tree: the lab's (`nn-lab.sh build`, test-privileged,debug-trigger: copies exempt, the BPF guard in observe) and a release build without features made in the guest (`--build-features` `none`), installed with `upgrade-check`. `main` cc1aefd1, the release build, as root, each case undone before the next: the restart (a plain start with the pins there) and the watchdog's respawn after a `cgroup.kill` READY, the key loaded 11 times per boot ("reusing existing agent signing key"); V3b′ (a drop-in in `system.control` with `ExecStart=` naming a copy of the binary, every identity path in an empty `/opt/k268-v3`): refused `agent_mounts` (the pinned `PROTECTED_INODES` unreadable, `BPF_OBJ_GET` EPERM: the guard's denial); V3b″ (first `Environment=NN_BPF_DEFENSE_OBSERVE=1 NN_ANTI_TAMPER_ALLOW_DEGRADED=1` and a `cgroup.kill`: the installed binary READY with its guard "observed only"; then V3b′): **minted** — a key in `/opt/k268-v3` (a new public half, f15a2c77…), 8 rows signed under it, READY; S2 (the installed binary, its key in place, `--agent-id-file` and `--audit-log-file` in an empty `/opt/k268-s2`): READY with a new id (f8a71944… for the installed 24b958f6…) and a new audit chain of 7 rows there; S3 (`mount --bind /sys/fs/bpf /sys/fs/bpf`): refused `agent_mounts` ("2 mounts stacked"); B1 (a second bpffs stacked) refused; restored each time with the installed public half unchanged. `main`'s lab build: the restart and the respawn READY (11 loads); `tamper-check` 75 cases, 72 OK, C27 and C57c the known gaps, C64 the recorded deviation. The lot (f881cb4d), its lab build: `upgrade-check` from `main` (refused without `--upgrade`; the identity the same, 17 of 17 deny hooks, 34 own LSM programs before and after, no foreign one); `test-ignored` 5/5 exit 0 (94 passed, 0 failed, the tests' agents' 52 chain checks `result="ok"`); the restart and the respawn READY, the key loaded once per boot; `tamper-check`: the same 75 outcomes and verdicts as `main`, case by case; `uninstall-check` OK, and its first install: one "bootstrapped fresh agent signing key", no other load, no refusal, its chains verified; re-key A (§3.10: step 0's archive, `uninstall.sh --purge --grant-key`, install): a new identity, one mint and no load at its first start, the archive verified with the old public half. Its release build: the restart and the respawn READY (one load); V1b refused `agent_mounts`; V3b refused `signing_identity`; V3b′ refused `agent_mounts`; V3b″ refused `signing_identity` ("whatever it runs … not the binary that agent protected"), nothing in `/opt/k268-v3`; S2 refused `signing_identity`, no id there; S3 READY; B1 refused. The TOCTOU probe (a copy of `/etc` whose `northnarrow` is empty bound over `/etc` while the respawned agent boots; triggers: the "BTF offsets resolved" line, the early registration's, 0 to 500 ms after the new process; 21 cycles): no mint in any, the installed public half unchanged — but the window from the decision to the load is about 25 ms here, too short for those triggers and the watchdog's back-off: cycle 1's bind landed after the load, that start went on READY in the copy's view and registered its directory, and every later start in the real view (cycles 2–21 among them) was refused by the pins' view proof until a reboot removed the pins. The final tip (0daa4afc, the review's B1–B5), its lab build: `upgrade-check` OK (the identity the same, 17/17, 34 own LSM programs), the restart and the respawn READY (one load), `uninstall-check` OK and its first install one mint, no load, no refusal; its release build: the restart and the respawn READY, V3b″ refused `signing_identity`, S2 refused, S3 READY, B1 refused; the TOCTOU probe with the window widened — the unit held to `CPUQuota=5%` (`set-property --runtime`, undone after), both cgroups killed (a restart, the pins kept), the agent started by the probe, the bind at a fraction of the measured "starting" → load window (0.5 to 1.6 s) or at the BTF line, each start killed at its outcome, before its attach (two earlier runs that let a copy-view start go on were polluted after their first cycle, as above; no mint in them either): 14 cycles, 2 with the bind between the decision and the load — refused at the audit check, "agent signing key /etc/northnarrow/agent.sig.key is absent, but the start's check found it there … refusing to mint", unsigned, exit 78 —, 12 after the load (the key loaded, the start killed before its attach), 0 minted, the public half unchanged, the audit chain 157 rows verified. Back to `main` (`upgrade-check` from its tree, the downgrade): OK (17/17, 34 own LSM programs), the restart and the respawn READY with `main`'s 11 loads, its audit chain 172 rows verified; the guest powered off. Host, on 0daa4afc (`set -o pipefail`, `CARGO_BUILD_JOBS=6`): `cargo xtask build-ebpf --release` (no eBPF change), the four clippy runs with `-D warnings`, `cargo fmt --check`, `cargo test` 74 suites, 3,212 passed, 0 failed, 16 ignored, the privileged no-run, `attack-coverage --check`, `cargo xtask golden` five times (49 files the same bytes, the tree clean), `cargo +1.89.0 check`, the fuzz replay (13 targets), `portable-core` (5 targets): all pass; again on e11e23cf (main 769d5615 merged, this lab in the docs): the same results, 3,212 passed. Mutations, each alone: R4 (the load minting on NotFound, the seen inode ignored, `rename` for `link`, a second decision, the key reloaded each time), S1 (copies exempt in every build), S2, S3, W1, the two ratchets (a phase loading its own key, another mint caller), the skipped load, B2 (an unseen key loaded), B3 (the leftover kept), B4 (the tarball's check dropped): each fails one test or more.
- **Lab PR 269 — R12b-1: the ring pumps on threads of their own with
  batched sends, the envelope, stage 5, the per-uid cap of P0's floods
  (Wave 4 Phase 2, R12b of the restructure plan, HIGH risk; part 1 of 2,
  R12b-2 the decision thread; no level changes).**
  - Why two PRs: R12b-1 is the sensors' side and carries the lot's
    measurable goal (EXP-13e), so it is measured alone against `main`;
    R12b-2 (stacked on it) is the decision's side — the event loop's
    threading and the lineage's semantics, a different risk — with its own
    gates, lab and review.
  - What was wrong: on R12a each ring's pump was a task of the async
    runtime, woken by its reactor and run when a worker had time, sending
    one event at a time (a round of the bus's locks and semaphores per
    event); in EXP-13e (a root loop of new processes' refused `chmod`s)
    R12a's tip lost more `fs_protect` records in the kernel than `main`
    before it (472, 0, 2,783 against 0, 662, 132) with no send waiting. A
    flood that keeps P0 full — any user's `fork` + `bpf()` loop on 6.x,
    root's loop of refused operations — took two thirds of the consumer
    (third review of #471, C3); the coalesced repeats were missing from
    NN-L-AT-001's ledger (C5); the decision's latency was timed from the
    push, not from the kernel's record (review #471 B2).
  - What changed (`docs/architecture/EVENT_BUS.md` §2a–2c, §5): each ring's
    pump is an OS thread (`nn-<ring>`) blocked in `poll(2)` on its ring,
    reading at most 1,024 records a pass and sending them in batches of up
    to 256 under one round of the queue's lock (`send_batch`; from the
    first event without a slot the rest one by one, each class's wait or
    drop); a dead pump thread is a finished pump (SNS-001 as before); the
    FIM and network drains stay tasks. The queues hold envelopes
    (`nn_core::bus::Envelope`: source, sequence, class, the record's kernel
    time, the process key). Stage 5: each decision timed from its record's
    kernel time against its class's budget (P0 100 ms, P1 250 ms, P2 1 s,
    P3 500 ms), the late ones counted and WARNed, shown in `nn-admin
    status --key` (an appended status field, `event_bus_decision`; the
    unsigned status frame one byte longer). C3: P0's floods (denials,
    `bpf()` calls) queued at most 256 a second per uid and kind — the
    `bpf()` records about the agent's own objects (NN-L-BPF-002's) a kind of
    their own with 1,024 —, the rest counted, WARNed and signed
    (`event_bus_capped`, naming the uid's distinct programs). C5: the
    coalesced and capped denials counted as AT-001's held records, the
    capped own-object `bpf()` records as BPF-002's. nn-admin matrix: the
    three full-status files gain the stage-5 lines, the cap in P0's
    behaviour and the new JSON field (+25 −13); no decision, posture or
    admin golden file otherwise changed; the eBPF object byte-identical.
  - Found by the lab, fixed: EXP-13's bursts (1,500 refused operations
    from one process on a saturated CPU) lost more `fs_protect` records on
    the threaded pump than on `main` — a thread woken on a busy CPU may wait
    a scheduler slice, about the time such a loop fills the 64 KiB ring the
    object declares (1,024 records): the loader sizes that ring at 256 KiB
    (`FS_PROTECT_RING_BYTES`, the object unchanged); the first tip's soak capped NN-L-BPF-002's
    records (the sampler's `bpftool map dump`s of the agent's maps, ~450 in
    a second as root: 192 capped every 15 minutes, never judged) — the
    own-object kind and its allowance; a batch's events had one queue time,
    so the hand-over of overtaken execs saw a tie — each push now a later
    time.
  - Open: the FIM and network drains are tasks still (the FIM ring
    dropped 12,072 records in one EXP-13c run of the final tip, none in
    `main`'s three; stage 5 counted, in the soak, 106 of 43,497 P3
    decisions later than 500 ms, up to 2.9 s, none on R12b-2's); the DNS pump's thread
    runs its own loop on the runtime's reactor; the cap is per uid, so a
    flood keeps a second process of the same uid and kind at 256 a second
    with it (named in the signed row); R12b-2 (#475).
  - Lab: on our own guests, at most two up — ubuntu2404 (6.8.0-147, QEMU for Windows with WHPX, 4 vCPU, 7.9 GiB) for the EXP-13 family, the overhead and `tamper-check`; ubuntu2204 (5.15.0-198, the same) for the soak pair; `test-ignored` on both —, `main` 28ecf720, the first tip b82d5ae2 and the final tip 303ae02b, each exported into one tree path per guest, built in the guest (release, `test-privileged,debug-trigger`) and installed fresh; the eBPF object the same bytes for every build (d248970b… on 6.8, 82d64fa9… on 5.15). EXP-13e ×3 per build (8 root processes' `fork` + refused `chmod` of `admin.pub`, 40 s, with 500 connects/s, 20 DNS queries/s, 6 NET-001 and 6 staged probes and the 8 bursts of 1,500): `fs_protect` ring drops `main` 575, 865, 3,176 (mean 1,539, max 3,176), the first tip 0, 0, 0, the final tip 0, 0, 0 (R12a's own lab: `main` c209e353 mean 265, R12a's tip mean 1,085); on the tips the agent's CPU ~12.3 s in the flood's 40 s against 36.7 s (P0 queued 256 a second of uid 0, ~690,000 a run capped and signed in 5 rows), no queue drop, no send that waited, NET-001 6/6 in every run of every build, every refused attempt accounted (AT-001's records + held, + coalesced on `main`, + the ring's drops). EXP-13 and 13c ×3 per build (a uid-1000 open flood of 4 × 32 threads with the 8 bursts of 1,500, each from one root process; 13c with the network load and probes): `fs_protect` ring drops `main` 183, 0, 0 and 11, 0, 0, the first tip 313 and 159 (one run each: a pump thread woken on a saturated CPU, the finding fixed above), the final tip 0, 0, 0 and 0, 0, 0, every burst's 12,000 accounted; the FIM ring (a task's) dropped 12,072 records in one 13c run of the final tip, none in `main`'s three (R12a's lab: two of four on this code). EXP-13d (8 uid-1000 `fork` + `bpf(BPF_MAP_CREATE)` loops, refused): no drop of `fs_protect` on any build; `main` judged every one of 558,188 calls (20.3 s of CPU), the tips queued 256 a second and capped the rest (640,511 and 693,702 a run, ~12 s of CPU), NET-001 6/6 on each. EXP-13b (the loop stalled 4 s, a burst of 3,000): 1 record + 2,999 held on the tips (C5) against 1 + 2,999 coalesced on `main`, no drop. Overhead within noise (`main` / the first tip: open +27.8 / +28.5 %, wopen +31.1 / +29.9 %, exec +4.6 / +11.7 %, connect +40.4 / +29.7 %, udp +15.3 / +14.1 %, dns +13.0 / +12.6 %). Soak pair on ubuntu2204, each a fresh install, 0.78 h of the same load: RSS 27.9 → 54.0 MB (`main`) and 31.8 → 55.6 MB (the first tip), threads 9 → 22 and 20 → 28 (12 pump threads; the runtime's 7 → 20 and 7 → 15), no restart, no ring or bus drop, WARN/ERROR lines 2,345 and 2,180 (one ERROR each: the lab's admin key on the host); the tip's 4 capped rows were the own-object finding above (768 records), and stage 5 counted P3 decisions later than 500 ms after their record (106 of 43,497, up to 2.9 s; none in R12b-2's soak) while P1's 310,215 and P2's 16,921 stayed within a few ms but the boot's backlog. `test-ignored` (the first tip): 79 suites, 94 passed, 0 failed on both guests, the tests' agents' 52 chain checks `result="ok"`; `tamper-check`: the first tip's 75 outcomes and verdicts those of `main`, case by case (72 OK, C27 and C57c the known gaps, C64 the recorded deviation). The final tip's code is part of R12b-2's final tip, whose `test-ignored` (both guests) and `tamper-check` are in its note. Host gates on 303ae02b (`CARGO_BUILD_JOBS=4`, `--locked`): build-ebpf, clippy ×4 `-D warnings`, fmt, 74 suites 3,288 passed 0 failed 16 ignored, the privileged no-run, attack-coverage, `golden` ×5 (54 files the same bytes, the tree clean), MSRV 1.89, the fuzz replay (13 targets), portable-core (5 targets), lockfiles unchanged. Mutations on the new code, each alone: 33 of 33 caught (the cap, its allowance by kind and its refund; stage 5's timing, total and WARN; the envelope's flow time; the batch's coalescing, window, cap, drops, wake-up and stamp; C5's held counts; the pump's batch, pass bound, wait and stop; the open sensor's order and cap; the ring's size) — A14 (a batch not waking the receiver) survived the first run and has its test (`tmp/r12b-lab/`).
  - Independent review of #474 ("merge after X"), fixed in the lot: C3
    held back events the rules must see — a program load, the 257th
    `bpf()` call of its uid in a second of map creates, was never queued,
    so NN-L-BPF-001 never judged it: the cap's key is now (kind, uid,
    target) — each `bpf()` command, each refused operation on each target
    —, NN-L-BPF-001's commands (load, attach, link create) are never
    capped, every capped key is signed with its count (rows of at most 256
    keys), a full table of keys queues a new one uncapped and counts it
    (judged, or dropped and signed by the bus: never unjudged and
    uncounted), and root's floods capped raise the posture's
    `TelemetryLoss`; the refund when the batch's fast path hands an event
    to the slow one is tested (the reviewer's K3); a batch a pump read and
    the closed bus refused is counted in the stop row; the verifier check
    loads the ring at the agent's size; the FIM and network drains run on
    threads of their own, each with a one-thread runtime. Attribution, as
    measured: EXP-13e's zero is not the threads' — `main` with the same
    256 KiB ring (a lab-only build) lost 0, 0, 0 too, at the same CPU
    (36.6 s); C3 cuts the agent's CPU in that flood to ~12.5 s and its
    decisions of uid 0 from ~14,000 to 256 a second per key; the threaded
    pumps alone made EXP-13 and 13c worse (313 and 159 against 183 and 11)
    until the ring was sized.
  - Lab after the review (round f on ubuntu2404, clean installs; the host
    ran the mutation suites through it): the final code 07480c40 —
    EXP-13e 0, 0, 0 (`main` 575, 865, 3,176; a lab-only `main` with the
    256 KiB ring 0, 0, 0 at 36.6 s of CPU against the final code's
    12.2–12.7 s), EXP-13 0, 0, 0 (`main` 183, 0, 0; `main` with the ring
    0, 0, 0), EXP-13c ×5 0 `fs_protect` and 0 FIM drops in each, with
    every thread's CPU (`nn-fim_drain` ~11.5 s of the flood's, the
    decision ~32 s; `main` 8 runs: `fs_protect` 11, 0, 0, 0, 0, 140, 0, 0,
    FIM none — round h repeats `main`'s five under the same load:
    59, 0, 0, 0, 0 — no FIM drop in any of `main`'s 13 runs), EXP-13d no drop (706,892 capped, 12.1 s), EXP-13b
    1 + 2,999 held; the C3 check (8 root `fork` + `bpf(BPF_MAP_CREATE)`
    loops with 6 root program loads spread over them): 6 of 6 loads with
    an NN-L-BPF-001 record in each of two runs (`main` 6 of 6), the capped
    rows naming uid 0's `map_create` key with its count; the ring read
    back at 262,144 bytes. Gates on 5dab2c77: build-ebpf, clippy ×4 `-D warnings`, fmt, 74 suites 3,293 passed 0 failed 16 ignored, the privileged no-run, attack-coverage, `golden` ×5 (54 files the same bytes, the tree clean), MSRV 1.89, the fuzz replay (13 targets), portable-core (5 targets), lockfiles unchanged. Mutations on the
    final code: 44 of 44 caught (the reviewer's K2 and K3 among them; AN2,
    every `bpf()` command keyed as one, survived the run and has a
    stronger test). The overhead was run again after the second review
    (R12b-2's last lab line, below).
  - R12b-2 (part 2 of 2, #475, stacked on R12b-1) — what was wrong: the
    decision was an async function on the runtime: it awaited systemd's
    state for a signal PID 1 relayed and the executor, read `/proc` for
    every exec (`exe_identity::resolve`, also in the bus's hand-over,
    review #471 B4), swept the trusted-installer window, appended a canary
    trip's row inline, and R018 asked the package database; the lineage's
    judgement time was a thread-local (`judged_at`), and a pid its cache
    did not hold was read from `/proc` — its present image — in a
    judgement (R-F, second review of #471).
  - R12b-2 — what changed (`docs/architecture/EVENT_BUS.md` §2d, §3): the
    decision on an OS thread of its own (`nn-decision`: `recv_blocking`,
    the overtaken execs taught, a plain `process_event` without `await`,
    stage 5), the event loop's task left with the signals, the admin
    shutdown, SNS-001's check and the lab triggers; its blocking I/O moved
    to the pumps (an exec's absolute path), the systemd watch (a snapshot
    refreshed every 2 s; a relayed signal on an answer older than a second
    handed to the watch, which asks at once and hands it back answered),
    the existing 1-s tick (the installer window), a writer thread
    (`nn-canary-log`: a trip's rows in DEC-011's order) and the module-load
    pump (R018's package answers, `OWNERSHIP`); the guard,
    `xtask/tests/decision_path_io.rs` (CI's `cargo test`): no `.await`,
    file, `/proc`, process, sleep, socket or fsync in the decision thread's
    own code, and a ratchet of the I/O sites the code it calls into still
    has, each listed with why. R-F: the lineage's time an explicit
    parameter (`AsOf`: `Judged`, `Live`, `Now`); in a judgement a pid the
    cache does not hold is not known unless its process started before the
    agent (the strict rule left a COMBAT reached after a restart unlocked:
    the posture golden replay's `eva-installer-window`; kept narrowed, no
    golden change). A decision thread that does not start ends the agent
    with a failure. Found while building it: the first systemd watch sent a
    deferred signal back on the bus, where the coalescer counted it into
    the denial already queued — never judged; it is handed back now. The
    lab found two privileged e2e tests racing the response, which the
    decision on its own thread now wins on 5.15 (the process canary's decoy
    killed before it returned, the /tmp dropper's tree before its child
    wrote its pid): the decoy sleeps and its SIGKILL is asserted, the
    dropper's test checks that no process of its image survives.
  - R12b-2 — open (as of the third review): the responses still run on
    the decision thread (R12c's dispatcher); the other I/O sites
    `EVENT_BUS.md` §2d lists (the ransomware tracker's sampler on a burst,
    the policy's exemption facts, a canary trip's reader, the
    security-tool detector's registration, a process's start and a fork's
    `/proc` facts in a judgement); in a judgement a process whose exec the
    agent did not read (dropped by P1, or not yet read) and whose image is
    neither its parent's nor that of a gone process it was orphaned from
    is not known, and a daemon's orphan is not known until the sweep after
    its parent's exit (at most 5 s); RR3 (a fork that executes another
    image, then its parent's again, judged as its parent's for the events
    between when neither exec is held) and RR5 (a swept fork whose later
    exec is lost judged as its parent's image) — the structural fix is an
    exec identity the kernel keeps per task; past 32,768 cached entries
    live ones are dropped (the most numerous account's first, whatever its
    class; counted, WARNed, `TelemetryLoss`); the start's scan can enter
    the image of an exec it reads before that exec's event arrives
    (milliseconds at the start); the session and workload attribution
    (`lookup_cache`) still takes a cached exec unchecked against the pid's
    present process (a reused pid can take the dead one's parent there;
    older than R12b);
    R-B and the property test over the posture corpus not done; the
    self-integrity check's window for a freeze that starts right after a
    round (C15 on the first tip).
  - R12b-2 — lab: the same guests and method, `main` 28ecf720 (#474's runs), the first tip bc480855 and the final tip 8c3c253b (it holds R12b-1's final; the branch's later commits are documents and two privileged tests, below). EXP-13e ×3: `fs_protect` ring drops `main` 575, 865, 3,176 (mean 1,539), the first tip 0, 0, 21 (mean 7, max 21), the final tip 0, 0, 0, the agent's CPU ~12.5 s against 36.7 s, every refused attempt accounted, NET-001 6/6 in every run. EXP-13, 13c ×3 and 13d: the first tip lost 297, 249 and 189 in the bursts (R12b-1's ring finding), the final tip 0 in each of its 7 runs; the FIM ring dropped 2,249 and 6,311 records in two 13c runs of the tips (none in `main`'s three; R12a's lab saw 1,575 and 439 on this `main` code). EXP-13b (`debug-stall-loop` stalls the decision thread 4 s): the first record 4.00 s late, stage 5 counting it, 1 record + 2,999 held, nothing dropped. Overhead (the first tip): open +31.6 %, wopen +30.6 %, exec +6.1 %, connect +18.0 %, udp +15.8 %, dns +14.4 % (`main` +27.8, +31.1, +4.6, +40.4, +15.3, +13.0) — and 256 `tcp_close` records dropped by the network drain during the connect workload (not on `main` or R12b-1). Soak on ubuntu2204 (a fresh install, the same 0.78 h load as R12b-1's pair): RSS 31.8 → 57.4 MB, threads 23 → 23 (the runtime's 8 throughout; `main` 9 → 22), no restart, no ring or bus drop, P0 1,810 queued and none capped, stage 5 late only the boot's backlog (P3 none, max 238 ms), 2,917 WARN/ERROR lines (one ERROR: the lab's admin key). `test-ignored`: the first tip and the final code 95 passed, 0 failed on ubuntu2404 and one failure on ubuntu2204 — the process canary's decoy (a copy of `/bin/true`) killed by NN-L-CANARY-002's response before it returned 0, a race the decision on its own thread now wins on 5.15 (R12b-1's runs found it `AlreadyGone`); with that test made deterministic the next run failed the /tmp dropper's test the same way (R001's kill before its child wrote its pid); with both tests fixed (1277ec24) 95 passed, 0 failed on ubuntu2204 and 95 passed, 0 failed on ubuntu2404, the 52 chain checks `ok` in every run. `tamper-check` (the final code): its 75 outcomes and verdicts those of `main`, case by case; the first tip's run missed C15's stall report (a 45-s freeze that began right after a self-integrity round: the check's window, Open). The `fs_protect` ring read back 262,144 bytes on both guests. posture_demo identical to `main`'s (29 lines). Host gates on 8c3c253b: build-ebpf, clippy ×4, fmt, 75 suites 3,303 passed 0 failed 17 ignored, the privileged no-run, attack-coverage, `golden` ×5 (54 files the same bytes), MSRV, fuzz (13), portable-core (5), lockfiles unchanged; clippy (privileged tests) and fmt again on 1277ec24 (the two e2e tests). Mutations: 18 of 18 on the final code (the resolve in the pumps, the systemd snapshot and its watch, the decision loop's teaching, delay and answered signals, the canary writer, the provenance cache, R-F's rules, the ratchet) and R-F's own 11 of 11; survivors along the way (B5 on the first watch, B17) have their tests.
  - Independent review of #475 ("merge after X"), fixed in the lot: R-F's
    exception read `/proc` in a judgement for a process older than the
    agent, which shows the image it runs now (a canary read, then a backup
    tool's exec, the read judged as the tool's): the agent's start enters
    every running process into the lineage once the exec sensors are
    attached (`seed_from_proc`) and no judgement reads a process's image
    from `/proc` (the posture replay seeds its host the same way: no golden
    change); `predates_observer`'s same-tick boundary is tested (K5); the
    guard's list includes the responses' code (the reviewer's K9, an I/O
    planted in the executor, now fails it), and `EVENT_BUS.md` §2d lists
    exactly what is still I/O on the decision thread — the responses
    (R12c), the ransomware tracker's sampler on a burst, the per-rule
    policy's exemption facts, a canary trip's reader, the security-tool
    detector's registration, a process's start in a judgement; a full
    canary writer's queue holds a trip at most 100 ms, then its rows are
    counted; the dropper e2e test stands the decision thread still while
    the dropper starts, so its child always exists before the verdict, and
    finds a survivor whose image was deleted.
  - R12b-2 — lab after the review (round g, ubuntu2404 and ubuntu2204,
    clean installs; the host ran the mutation suites through it): the
    final code e75d6205 — EXP-13c ×5 0 `fs_protect` and 0 FIM drops in
    each (the decision thread ~33 s, `nn-fim_drain` ~11.5 s of the flood's
    CPU), EXP-13e 0, 0, 0 (12.2–12.7 s of CPU), EXP-13 0, 0, 0, EXP-13d no
    drop (707,931 capped, 11.5 s), EXP-13b (the decision thread stalled
    4 s) 1 + 2,999 held, the first record 4.00 s late; the C3 check 6 of 6
    program loads judged; `test-ignored` 80 suites, 95 passed, 0 failed on
    each guest (the dropper test with the decision thread stalled, the
    canary test with the kill asserted); `tamper-check` the 75 outcomes of
    `main`, case by case, C15 reporting the freeze; the ring read back at
    262,144 bytes on both. Gates on 8144429a (the code of 1ef530c0): build-ebpf, clippy ×4 `-D warnings`, fmt, 75 suites 3,310 passed 0 failed 17 ignored, the privileged no-run, attack-coverage, `golden` ×5 (54 files the same bytes), MSRV 1.89, the fuzz replay (13 targets), portable-core (5 targets), lockfiles unchanged. Mutations on the
    final code: 22 of 23 caught (the reviewer's K5 and K9 among them; BN2,
    the scan's first check of a pid already held, is an equivalent mutant:
    the same check is made again before the ingest).
  - Second review of #475 ("merge after X"), fixed in the lot: strict R-F
    with the lineage's cache of 2,048 kept first in, first out made
    long-lived processes not known in a judgement (2,048 execs of other
    processes pushed out a seeded `clamd`, CANARY-001's reader exemption
    was lost and the daemon killed at its first canary read), and a fork
    that never executes had no entry. The cache is bounded by process
    lifetime (a sweep thread, `nn-lineage-sweep`, every 5 s, marks the
    exited; past 2,048 only their entries go, after a 30-s grace; past
    32,768 a live one, counted); a fork runs its parent's image while
    `/proc/<pid>/exe` is that file (`fork_entry`, `/proc/<pid>/stat`'s
    parent and start); a pin that the start seeds and sweeps; a full cap
    table raises `TelemetryLoss` for any uid and releases an ended key; a
    stuck canary writer costs one wait; the dropper test cannot vanish
    without `debug-trigger` (`compile_error!`).
  - Third review of #475 ("merge after a small X"), fixed in the lot: a
    daemon that forks and exits after the start (`Type=forking`,
    `daemon()`) is the orphan of its gone parent's image once the sweep
    found the parent gone (`orphan_entry`: reparented to pid 1 or a
    subreaper ancestor, started after the exec, the same file, the same
    script among the candidates); a pid reused by a fork is not judged as
    the dead process's image (`cached_live`: a fork of its parent in a
    judgement; a session's subshell stays auth-mediated, a regression
    against `main` before); the reviewer's surviving mutations M5, M6,
    M9, M11 have their tests; the start is read again after the exe; the
    hard bound drops the most numerous account's entries first, whatever
    its class (the final check: a webshell's flood as `www-data` does not
    push out a person's session), the start's scan's last, and raises
    `TelemetryLoss`; the keys a full cap table releases are bounded, their
    counts summed per kind and uid. The final check of #475 (merge after a
    one-line fix): an adopted orphan runs its image from the sweep's
    instant, not from its start (RRd2: an attacker's read before its own
    queued exec of a reader any user may run, judged as that reader's). RR3
    and RR5 stay open (above).
  - R12b-2 — lab after the reviews (our own guests, fresh installs):
    round m (ubuntu2404, the final code e01cb609): `test-ignored` 80
    suites, 97 passed, 0 failed, the 54 chain checks `ok` — a `Type=forking`
    reader daemon started after the agent (its subshell reparented to
    pid 1, read a file canary after one sweep): NN-L-CANARY-001 `Log` High,
    not killed; round j (ubuntu2404, the second review's X 8977f0b3):
    `tamper-check` the 75 outcomes and verdicts of `main`, case by case,
    and `test-ignored` 80 suites, 96 passed, 0 failed (a reader daemon
    started before the agent, after 2,100 execs: NN-L-CANARY-001 `Log`
    High, not killed). Overhead ×3 on ubuntu2404 (rounds i and l): `main`
    open +29.5 %, wopen +32.4 %, exec +8.0 %, connect +42.2 %, udp
    +16.7 %, dns +16.0 %; R12b-1's final 49bc024e +29.0, +32.5, +6.9,
    +38.5, +18.0, +14.4; R12b-2 before the second X (065a9b8f) +29.0,
    +31.4, +9.6, +33.5, +14.0, +23.6; with it (919b7416) +28.6, +30.7,
    +8.2, +29.3, +11.2, +19.9 — `dns` above `main` in both R12b-2 runs,
    not attributed. The soak pair on ubuntu2204 (0.78 h each): `main`
    28ecf720 RSS 31.5 → 57.3 MB, threads 9 → 20, 2,525 WARN/ERROR lines;
    919b7416 RSS 32.4 → 56.5 MB, threads 24 → 24, 2,298 lines; both no
    restart, no ring or bus drop, P0 1,794 queued (none capped), one ERROR
    (the lab's admin key); stage 5 on the tip: P0 1 and P1 10 late (the
    boot's backlog), P3 72 late (max 2.18 s) in two windows when the host
    ran the gates and builds (1-min load 4–7); the sweep's thread 2.1 s of
    CPU. The 51 chain checks of round g's run on ubuntu2204 against 52:
    the watchdog test SIGKILLs a respawned agent once its pid file names
    it, one boot killed before its chain line, the next verified `ok`.
    Gates on e01cb609: build-ebpf, clippy ×4 `-D warnings`, fmt, 75
    suites 3,325 passed 0 failed 17 ignored, the privileged no-run,
    attack-coverage, `golden` ×5 (54 files the same bytes), MSRV 1.89,
    the fuzz replay (13 targets), portable-core (5 targets), lockfiles
    unchanged (on 919b7416: 3,317 passed). Mutations on e01cb609: 31 of 32
    caught (set C again, the reviewer's M5, M6, M9, M11, the third X's
    own; DF1, the start's re-read, a race no unit test can stage); on
    8977f0b3: set C 15 of 15 (CN1, the start's `seed_from_proc` call
    removed, among them), set B 21 of 21 applicable, R-F's own 9 of 9
    applicable.
  - R12b-2 — after the final check (217af285): gates — build-ebpf, clippy
    ×4 `-D warnings`, fmt, 75 suites 3,327 passed 0 failed 17 ignored, the
    privileged no-run, attack-coverage, `golden` ×5 (54 files the same
    bytes), MSRV 1.89, fuzz (13), portable-core (5), lockfiles unchanged;
    mutations 4 of 4 (the orphan counted from its start — the reviewer's
    RRd2 —, users before system accounts at the hard bound, and two of set
    D's again); round n (ubuntu2404): `test-ignored` 80 suites, 97 passed,
    0 failed, the 54 chain checks `ok`, the `Type=forking` reader daemon
    (the test waits one sweep's period, 7 s, by design) `Log` High, not
    killed.
- **Lab PR 270 — R12c-1: the response dispatcher off the decision
  thread; no action without a signed record (Wave 4 Phase 2, R12c of the
  restructure plan, §3.4, HIGH risk; part 1 of 2, R12c-2 the signed
  `telemetry_loss` rows and heartbeat; no level changes).**
  - Why two PRs: R12c-1 changes who acts and what every action leaves
    behind (the risk of the lot); R12c-2 (stacked on it) adds what a
    reader on another host can check — the loss rows and the heartbeat
    with its verifier — with its own gates, lab and review.
  - What was wrong: the decision thread ran each decision's responses
    itself before the next event (a kill's cgroup with its verify retries,
    the quarantine's copy and synced ledger, the block's and the throttle's
    cgroup files), and the ransomware tracker's sampler and trust ran
    there too; no record tied an action to what was being done when the
    agent crashed, and an acting decision's record could be held by the
    per-rule budget. EXP-13r on `main` b201bd20 (new, below): the decision
    of P1 events up to 13.9 s and 14.5 s late, 14,932 and 18,632 records
    lost in the kernel's rings while it acted.
  - What changed (`docs/architecture/EVENT_BUS.md` §2e, §5–§7;
    `docs/operator/EVIDENCE_CHAINS.md`, the actions chain): the response
    dispatcher (`pipeline::dispatch`, thread `nn-response`; the queue
    `nn_core::response::dispatch`, stage 6) — four severity lanes, 500 ms
    aging, per-process order by priority inheritance, repeats merged, a
    full queue (1,024) displacing a less severe job or refusing the new
    one, each answered `not run`, counted, signed in an `overflow` row and
    raising `TelemetryLoss`; a dead dispatcher thread stops the agent for
    the watchdog (signed). The `actions` chain (rotating, signed, KIND
    `actions`): an `intent` row synced before every action of the agent's
    own decision and an `outcome` row after it; the `Intent` ticket every
    acting entry point requires, made only by the journal
    (`xtask/tests/action_records.rs` keeps it so); an intent left without
    its outcome by a crash answered by an `interrupted` row and a signed
    `response_interrupted` audit row at the next start. An acting
    decision's record is never budget-held (`admit_acted`); stage 7 keeps
    the records of actions up to twice the writer queue's capacity. The
    ransomware sampler and trust on `nn-slow-work` (`pipeline::slow`), the
    decision woken when a burst is prepared. The I/O guard's rule 1b: no
    acting call in the decision thread's code.
  - Found by the lab and fixed in the lot: aging took every job older than
    500 ms first, so under EXP-13r's backlog the response queue was first
    in, first out (185 of 400 takes passed over a more severe job); one
    take in four goes by age now (7710d5be). A dispatcher thread that ends
    is seen and stops the agent (cd5b7868).
  - Lab (round a, our own guests): ubuntu2404 (6.8.0-147, QEMU/WHPX, 4
    vCPU) `main` b201bd20 and the first tip 594d0661, each built in the
    guest and installed fresh. EXP-13r (new, `deploy/lab/bus/responses.sh`:
    200 execs from `/tmp` killed by R001 and 200 connects to a blocklisted
    address killed by NET-001, with the EXP-13 load, 30 s) ×2: `main` P1
    decisions over budget 6,339 and 6,478 (up to 13.9 and 14.5 s), stage 1
    lost 14,932 and 18,632, stage 4 1,711 and 1,922; the tip 0 and 0 over
    budget (P1 p99 7.7 and 6.7 ms), stages 1–7 nothing lost, 400 intents
    and 400 `success` outcomes in each run, none unanswered; the actions
    themselves waited in the response queue (p50 9.4 s, max 14.2 s: one
    kill tree at a time, ~35 ms each — `main`'s same backlog, now off the
    decision). The crash (`debug-crash-mid-action`): the intent written,
    the agent aborted after the kill, restarted by the watchdog, and 3.5 s
    later an `interrupted` row and a signed `response_interrupted` audit
    row named the intent. EXP-13 ×3, 13c ×3, 13d, 13e ×3: no `fs_protect`
    or FIM drop on either build; 13b 3,000 accounted on both; NET-001
    probes' records median 19.7 ms (`main`) and 23.1 ms (the tip; three of
    42 at 138–219 ms in two flood runs, cause not isolated). Overhead within
    noise (open +29.1 / +18.8 %, wopen +33.1 / +22.6 %, exec +8.3 / +9.3 %,
    connect +15.1 / +10.1 %, udp +19.1 / +13.7 %, dns +15.2 / +14.5 %).
    Soak on ubuntu2204 (`main`, 0.8 h): RSS 32.4 → 56.8 MB, 24 threads, no
    restart, no ring or bus drop. Identity: the eBPF object and
    `posture_demo` (29 lines) the same bytes for `main`, 02b6077b and
    R12c-2's 08972539. Host gates on 7710d5be: build-ebpf, clippy ×4, fmt,
    77 suites 3,370 passed 0 failed 17 ignored, the privileged no-run,
    attack-coverage, `golden` ×5 (54 files the same bytes), MSRV, fuzz
    (13), portable-core (5), lockfiles unchanged. Mutations 42 of 42 (35 of
    39 first; the four survivors' tests, 4 of 4; aging's share and the
    thread's end, 3 of 3).
  - Independent review of #476 ("merge after X"), fixed in the lot
    (537cf086, e058d1e8): a kill of a process that reused a pid was merged
    into the queued kill of the pid's old owner and left the new process
    alive — a process is its pid and its start now (X1); a full queue of
    Critical jobs refused a new Critical kill — a Critical kill goes past
    the capacity now, counted, up to four times it (X2); the intent row is
    written before every action (it survives a crash of the agent) and
    synced before it only for a quarantine, a strip or a restore, every
    fsync of the journal outside its lock; a kill goes before its
    process's queued jobs and supersedes its throttles and blocks; the
    I/O guard excludes the dispatchers' thread functions, not their files
    (the guards' `production()` no longer hides code after a
    `#[cfg(test)]` field); §2e says "an attempt at a signed record" and
    names `reconcile_stale_chain`; the reviewer's surviving mutations K2,
    K5, K11 have their tests.
  - Lab after the review (round c, ubuntu2404, e058d1e8, a fresh
    install): EXP-13r ×2 — 400 intents and 400 `success` outcomes in each
    run, none unanswered, P1 0 over budget, stages 1–4, 6 and 7 nothing
    lost (P3 16 decisions over budget in the second run, stage 5); the
    queue's wait p50 7.3 and 9.4 s, max 13.4 and 18.8 s, 68 and 67 takes
    by age past a more severe job (185 before the fix) — the actions still
    one at a time (~35 ms a kill tree, up to 371 ms under the load): the
    pool of R12c-3. The crash: the kill's intent written, not synced, the
    agent aborted, restarted, the `interrupted` row and the audit row 4.2 s
    later. EXP-13c ×3 and 13e ×3: no `fs_protect` or FIM drop; NET-001's
    record median 22.3 ms over 36 probes (`main` 19.2 ms, the first tip
    23.8 ms), one at 426 ms and one at 95 ms in the first 13c run (the
    first tip had three at 138–219 ms with the fsync before the kill: the
    outliers are the one executor thread under the flood, not the fsync).
    `test-ignored`: 82 suites, 97 passed, 0 failed, the 54 chain checks
    `ok`.
    Host gates on e058d1e8: build-ebpf, clippy ×4, fmt, 77 suites 3,378
    passed 0 failed 17 ignored, the privileged no-run, attack-coverage,
    `golden` ×5, MSRV, fuzz (13), portable-core (5), lockfiles unchanged.
    Mutations of the fixes 16 of 16 (15 first; MX1 — only `same_action`'s
    start — caught once `same_action` was tested directly). Round a's last
    results (594d0661): `tamper-check` 72 OK, C27 and C57c the known gaps,
    C64 the recorded deviation, case by case those of R12b-2's final;
    `test-ignored` 81 suites, 97 passed, 0 failed, the 54 chain checks
    `ok`; the soak (ubuntu2204, a fresh install, the same 0.8 h load as `main`'s): RSS 33.0 → 57.3 MB (`main` 32.4 → 56.8), 26 threads throughout (`main` 24: the dispatcher's and the slow work's), no restart, no ring or bus drop, P1 10 decisions over budget of 312,014 (the boot's backlog), 1,871 WARN/ERROR lines (`main` 1,929; one ERROR each: the lab's admin key on the host).
  - The re-check of #476 ("merge after one fix", 7c390d51): a kill
    supersedes its process's throttles and blocks only once it killed —
    they stay queued behind it, and run when it did not kill (the
    host-critical guard, EPERM, a cgroup that would not die); a durable
    intent always fsyncs itself; an outcome whose intent the chain could
    not take says `intent_written: false`; failed fsyncs counted apart
    (`sync_failed`). Gates on 7c390d51: 77 suites 3,380 passed 0 failed,
    every other gate green; mutations of the fix 5 of 5 (63 of 63 for the
    lot's R12c-1).
  - Open (R12c-3, after this merges): a pool of response workers keyed by
    process (EXP-13r's wait under 2 s), a stall detector for an action
    that hangs, `run_started`/`run_ended` rows for the crash report's edge
    cases; the batch limited to the most severe lane; the ticket passed by
    value.
  - Open: the ladder's and the exec quarantine's threads not ordered
    against the dispatcher's responses for one process (as before R12c).
  - R12c-2 (part 2 of 2, stacked on R12c-1) — what was wrong: everything
    the agent signs proves something only to a reader off the host, and
    no such reader had anything to watch: an agent stopped, frozen, killed
    or blinded was seen only by looking at the host, and the loss of
    stages 1–7 was in `nn-admin status`, never in a signed row (report 06,
    INI-14).
  - R12c-2 — what changed (`docs/operator/HEARTBEAT.md`,
    `docs/architecture/EVENT_BUS.md` §5, §7; `EVIDENCE_CHAINS.md`, the
    heartbeat chain): a beat every 30 s (`NN_HEARTBEAT_SECS`, 5 to 300,
    never off; longer than 30 s a weakening for the self-integrity check)
    on a chain of its own (`/var/lib/northnarrow/heartbeat.jsonl`, KIND
    `heartbeat`, 4 MiB × 4), numbered across runs, carrying the loss of
    stages 1–7, the actions chain's counts, the probe's gaps, the decision
    thread's progress, the posture, stage, trust, degradations and the
    audit and actions chains' heads; a `start` beat per run, a `stop` beat
    at a clean stop. Signed `telemetry_loss` audit rows (each stage's total
    and its loss since the last row: at a change at most once a minute,
    hourly with none, at the stop). `nn-admin heartbeat export` (the newest
    lines as on disk, for an SSH forced command) and `nn-admin heartbeat
    watch` (on another host, with the agent's public key and a state file:
    signatures, links, numbers, freshness, a rollback of a chain's head;
    exit 10 silent, 11 broken, 12 replay, 13 tampered, 14 loss, 15
    stopped, 16 degraded). The transport is a pull over SSH through a
    forced command (no listener added to the agent's host, no egress, the
    channel not trusted for integrity — every beat signed end to end;
    `HEARTBEAT.md`, "Why this transport").
  - R12c-2 — after the review of #476: the beat carries the actions
    chain's head (its position — the active file's archive number and
    length — its hash, and whether the chain still holds the head the
    previous beat named, read back at each beat and at the start); the
    verifier alerts REPLAY when that head goes back, is gone from the beat
    or is no longer held, and DEGRADED for a new run with no stop beat
    before it (the agent killed, crashed, or frozen and restarted) and for
    a beat late after the one before it in one run.
  - R12c-2 — lab (our own guests, fresh installs): the verifier on the WSL host pulling the
    beats over SSH from ubuntu2204 (rounds h–j): a replayed export REPLAY
    in 5.0 s, a beat altered on the way TAMPERED in 4.2 s, the network cut
    SILENT in 66.7 s, the agent stopped STOPPED in 6.5 s, the actions
    chain's last row cut while it was stopped REPLAY in 4.9 s after the
    start ("no longer holds the head"), the agent frozen DEGRADED in 55.7 s
    — the watchdog restarted it after ~69 s, under the silence bound, so
    the alert is the new run without a stop beat. The rounds found the
    gaps those last three alerts close (round h: a cut tail with rows
    appended past it and a freeze under the bound went unalerted; round
    i: the freeze ended by a restart). No regression
    (round d, ubuntu2404, this branch before the review's additions): the
    EXP-13 family with no `fs_protect` or FIM drop, NET-001's record median
    17.8 ms over 36 probes, EXP-13r's 400 intents answered with P1 0 over
    budget, overhead within noise (open +27.9 %, wopen +32.0 %, exec
    +8.9 %, connect +12.0 %, udp +15.4 %, dns +14.1 %; `main` +29.1, +33.1,
    +8.3, +15.1, +19.1, +15.2), `tamper-check` 72 OK with the known gaps and
    deviation (C30: one more protected entry, the heartbeat chain). Soak
    (round c, ubuntu2204, 0.8 h): RSS 31.1 → 55.1 MB (`main` 32.4 → 56.8),
    26 threads, no restart, no drop. `test-ignored` found two races in the
    privileged tests (the heartbeat's `telemetry_loss` rows in the audit
    test's fixed sequence; the canary writer's Trip row read before it was
    appended), fixed: then 82 suites, 97 passed, 0 failed, 53 chain checks
    `ok` on ubuntu2204. Host gates on c3e853c3: 77 suites 3,402 passed 0
    failed, every other gate green; mutations 41 of 41 (the six survivors
    of set B, MW6/MC1, MC2 caught once their tests were written);
    identity as `main`'s.
  - R12c-2 — review of #478 ("merge after two small fixes"), ead52778:
    X1, the host's clock alone decided the gravest alerts (a restart with
    the RTC behind was REPLAY, a clock ahead of the verifier's TAMPERED):
    beats are ordered by their numbers and links only; a beat stamped
    before the one seen, or ahead of the verifier's clock past
    `--max-skew-secs`, is DEGRADED; freshness on the verifier's clock from
    when it first saw the newest beat (`seen_at` in its state), a late
    beat within a run on `uptime_ms`. X2, `kept` missed a removed archive
    (`holds` turned the missing file into "not known"): a file the chain
    keeps (the active one, an archive within the retention) that is
    missing is `kept: false`, REPLAY. An unreadable verifier state is exit
    3, never a silent re-anchor (`--reanchor` on purpose). Tests for the
    reviewer's V2 (the export across a rotation — no bug, untested) and V5
    (the audit head rewritten at its row). `HEARTBEAT.md`: the key forges
    everything (attestation is future work), `kept` covers the tail not
    the middle, maintenance, a key change, a reinstall, `export --count`
    on the host. Gates on ead52778: 77 suites 3,407 passed 0 failed, every
    other gate green; mutations B10 5 of 5, B11 (V2, V5) 2 of 2; identity
    as `main`'s. Lab (rounds l, ubuntu2204, the verifier on the WSL host):
    the guest's clock 40 s ahead DEGRADED ("ahead of the verifier's") in
    15.0 s, then back 40 s DEGRADED ("clock went back") in 20.1 s, a clean stop with the clock set 40 s behind and
    a start STOPPED in 3.8 s then DEGRADED in 8.8 s — no REPLAY or
    TAMPERED in any of the three (round l1: 15.8, 14.4, 8.7 s); the
    actions chain's newest archive removed 6.8 s after a beat (the chain
    at 1 MiB for the run, rotated right after the beat) REPLAY ("no longer
    holds the head") at the next beat, 23.4 s after the removal (round
    l1 left that case unrun: the archive glob expanded in the lab user's
    shell, which cannot read the directory; fixed in the script).
  - R12c-2 — open: `STOPPED` repeats at every check while stopped (the
    doc: stop the verifier's timer for a maintenance window); the chain
    readable by a dedicated group instead of `sudo`; `export --count`
    through the forced command; the stall counts of R12c-3 in the beat.
  - R12c-3 (the third PR, after #476) — what changed: a pool of response
    workers keyed by process (eight, `NN_RESPONSE_WORKERS` 1–32, each at a
    nice value five above the agent's): the queue marks a process running
    while one of its responses runs, so different processes' responses
    run at once and one process's one at a time, in order (#476's kill
    first and supersede kept); a kill tree whose root has no child skips
    the `/proc` walks; a stall watch signs a `stalled` row for an action
    still running after 10 s, raises `TelemetryLoss` and starts a spare
    worker; `run_started` and `run_ended` rows, the start reading back to
    the `run_started` of a run that did not end, the boot's audit row
    before the interrupted rows.
  - R12c-3 — lab (round g on bec13ac4, round g2 on fec704ed, ubuntu2404,
    fresh installs): the first pool (eight workers at the agent's
    priority, every kill tree walking `/proc`) cut EXP-13r's queue wait to
    5.1 and 5.6 s but made 1,247 P1 decisions late in its first run —
    fixed (the workers' nice, the childless kill tree); then EXP-13r ×2:
    400 intents and 400 `success` outcomes each, P1 0 over budget, the
    queue's wait p50 0.23 and 0.29 s, max 2.0 and 4.1 s (target under
    2 s: the first run), the second run's P3 decisions 90 over budget (up
    to 3.5 s); EXP-13c ×3 and 13e ×3: no `fs_protect` or FIM drop,
    NET-001's record median 13.1 ms, max 19.0 ms over 36 probes (`main`
    19.2 / 27.0 ms, R12c-1 22.3 / 426 ms); `--hang`: the stalled row 10.5 s
    after the hung kill's intent, the twenty kills beside it each answered
    within 19 ms, the hung one's outcome at 15.0 s, the spare gone after;
    `--crash`: the audit row, then the `interrupted` row 3.4 s after the
    restart, then the new run's `run_started`. `test-ignored`: 82 suites, 97 passed, 0 failed, the 54 chain checks `ok`. Host gates on
    273ad1a4: 77 suites 3,387 passed 0 failed, every other gate green;
    mutations 12 of 12 (MC8 first written as an equivalent mutant; MK2
    caught once the children check took a proc tree of its own);
    identity: the eBPF object and `posture_demo` as `main`'s.
  - R12c-3 — review of #477 ("merge after one fix"), fb471460: one
    process sat in the queue under two keys — (pid, 0) from a kernel
    alert, (pid, start) from an exec's event — so two workers could act on
    it at once; the queue's key is the pid alone now (a reused pid waits
    behind the old process's responses), and a repeat merges and a kill
    supersedes only when both starts are known (non-zero) and equal.
    Tests: one pid's responses never at once whatever their start, kills
    of a pid with an unknown start not merged, such a kill superseding
    nothing, a spare that panics stopping the dispatcher (R9), the spares
    bounded by the pool (R13). The CPU contention: the decision thread at
    nice −5 (`DECISION_NICE`, `renice_this_thread`), the workers at the
    agent's priority (no longer +5). Round k (ubuntu2404, fb471460, a
    fresh install): EXP-13r ×2 400/400 `success`, P1, P2 and P3 0 over
    budget in both runs (round g2: 90 P3 late), the queue's wait p50
    0.11 s, max 0.67 and 1.6 s (g2: 2.0 and 4.1 s — the target under 2 s
    met in both); `--hang`: the `stalled` row 10.0 s after the intent,
    the twenty kills beside it within 33 ms; `--crash`: `interrupted` 3.4 s
    after the restart, then `run_started`; `test-ignored` 82 suites 97
    passed 0 failed, the boot's chain checks `ok`. Gates on fb471460: 77
    suites 3,392 passed 0 failed, every other gate green; mutations of the
    fix 4 of 4 (16 of 16 for R12c-3).
  - R12c-3 — open: `CPUWeight=` in the unit (the decision thread's nice
    is per thread; a weight would hold against other services); a stall
    watch for the ladder's, the exec quarantine's and the CoW restore's
    threads; an explicit "pool exhausted" state (every worker and spare
    stalled); the stall counts not in the heartbeat yet (R12c-2's own PR);
    the ticket passed by value.
- **Lab PR 271 — R13: the sensor contract and the signed capability
  manifest's revisions (Wave 4 Phase 2, R13 of the restructure plan, §3.6;
  report 06 INI-09, R4-01, EXP-37; MEDIUM risk; no level changes).**
  - What was wrong: what each source of the event bus promised — where its
    events come from, what decides before the operation completes, what
    its failure means, what the kernel holds back, what its records cut,
    where its losses are counted — was in comments and in the code's
    constants, nowhere a test or an operator could read it whole. The
    boot's capability manifest (lab PR 218) listed the attach notes and the
    degradations once, at the boot; a sensor lost later, a fallback taken,
    the telemetry probe's gap changed nothing signed in it; the status's
    trust level and degradations were computed apart from it
    (`trust_inputs`, the registry), the shipped lists given way to their
    built-in copy (`report_builtin_defaults`) were rows of the overlay
    gate's only; and a kernel without `bpf` in `lsm=` under the
    degraded-mode opt-in left the exec and file-open sensors on LSM
    programs that never run.
  - What changed (`docs/operator/SENSOR_CONTRACT.md`, new;
    `docs/architecture/EVENT_BUS.md` §2, §7; `BOOT_INTEGRITY.md` §2, §5, §6;
    `HEARTBEAT.md`): the contract — nn-core's `contract` (`EventKind`, one
    macro for the enum and its list; `SourceContract`; the class contracts
    derived from the sources and the bus's queues and budgets; `check`:
    every kind and class has its source; `bus::class_of` reads
    `EventKind::class`), nn-linux's `sensors::contract::SOURCES` with the
    thirteen sources' Linux values (the truncations made of the wire's
    constants, the kernel budgets held to the eBPF programs' constants by
    a test that reads them, the page held to the table by another); a test
    of the agent's that reads the code's pumps, drains and attach notes:
    each must have its entry. The manifest (`MANIFEST_VERSION` 2, its type
    nn-core's `contract::manifest::CapabilityManifest`, the plan's §2.3):
    each source's attach (primary, fallback, none), state (`ok`,
    `standby`, `disabled_by_admin`, `attached_not_invoked`, `unavailable`,
    `adapter_terminated`) and why, the probe's word, its terms; each
    class; the fallbacks; what is missing or not invoked; the shipped
    lists not in force from their file; the revision, its content hash
    and the one before. `SignedManifest` builds it at the boot from the
    boot's measurements (revision 0, `capability_manifest`) and again every
    5 s, for each status and each beat: a change is signed as
    `capability_manifest_change` with what changed; an adapter that ended
    is a revision before the stop; a source on its attach point whose pump
    did not start is `unavailable`. One truth: `status --key`'s trust level
    and degradations and every beat's are the newest revision's (no
    `trust_inputs` handle), `attest_degraded*` and every degradation feed
    it through the registry (their `subsystem_degraded` rows as they were),
    `report_builtin_defaults` through the overlay gate (`default_list_*`
    rows as they were), the anti-tamper attach's report (the former
    `take_degraded_boot_details`) through its deny section and notes. The
    heartbeat carries `capabilities` (hash, revision, settled); `nn-admin
    heartbeat watch` says DEGRADED when a settled hash changes — within a
    run or across a restart —, when a run does not settle within 120 s, or
    when the field goes. Without `bpf` in the active LSM list under the
    opt-in, the exec and file-open sensors take their tracepoints, each
    signed. Lab: `deploy/lab/contract/manifest-lab.sh` (normal, nobpf).
  - Pins: the manifest's row (a change's, revision 1) and its content hash
    (`the_manifest_row_and_its_hash_are_pinned`, nn-core); the heartbeat's
    line with `capabilities` (`chain_kinds_pin`; the line without it
    unchanged); the existing rows' formats (`subsystem_degraded`,
    `default_list_*`, `agent_boot`) unchanged. nn-admin's matrix
    regenerated: `status --key` prints a `capabilities` line (and its
    fallbacks, what is missing, the last change), `status --json` a
    `capabilities` object, `capabilities` the revision, the contract, the
    sources, the classes, the fallbacks, what is missing and the content
    (`contract: (none …)` for an older agent's manifest); a case with an R13
    manifest added.
  - Lab (our own QEMU guests under QEMU for Windows; the manifest lab,
    `deploy/lab/contract/manifest-lab.sh`, with `nn-admin heartbeat watch`
    run on the WSL host against the guest's beats). ubuntu2404 (6.8, main
    973e3356 then the tip 574afb7b): the manifest 17.3 KiB, revision 0 at
    the boot, revision 1 when the probe's first round settled it (`pending →
    seen` on process_spawn, open_sensor, dns_query), 13 of 13 sources `ok`
    (file_open `standby`), L3; the same hash (78ae2c74…) after two clean
    restarts, no manifest alert; `debug-probe-blind dns`: revision 2
    (`dns_query` attached, not invoked; probe gap) and DEGRADED off the host
    25.7 s after the trigger, removed: revision 3, the hash before, DEGRADED
    89.9 s after (a probe round is 48–72 s); EXP-13 and EXP-13e ×1 main vs
    tip: 12,000 of 12,000 refused attempts accounted both, ring drops 0, P0
    over budget 0 (main 3), 13e's capped and coalesced as main's; overhead
    ×3 (medians), tip no worse than main on any workload (open +28.6 % vs
    +31.2 %, exec +8.9 % vs +16.6 %, connect +12.3 % vs +33.5 %; the host
    under gates and mutations for both); `tamper-check` as main's (72 OK,
    C27 and C57c the known gaps, C64 the recorded deviation);
    `test-ignored` 82 suites 97 passed 0 failed. ubuntu2204 (5.15, the
    tip): the manifest (0c629a1f…), the same after two restarts, the probe
    blinded and restored (DEGRADED 29.9 s and 58.7 s after); then `lsm=`
    without `bpf` (the guest's grub drop-in, a reboot): every start refused
    and signed (`agent_boot` refused, `refused_by: bpf_lsm`, four boots
    while the guest came up), then the opt-in (a unit drop-in): the start
    at L0 — `fs_protect`, `module_load`, `bpf_syscall`, `exploit_guard`
    and `fim_drain` attached, not invoked (why: bpf not in the active LSM
    list), `exec_check` and `open_sensor` on their tracepoints, `file_open`
    carrying the opens, the probe seeing exec, file open and DNS on them;
    signed `subsystem_degraded` (`bpf_lsm`, `exec_sensor`,
    `file_open_sensor`), `weakening_env`, `unit_dropin`; `status --key`
    showing it; the verifier DEGRADED "the capability manifest changed
    across a restart" (0c629a1f → 41ff88df) 35 s after the start; the guest
    restored (the drop-in gone, `lsm=` with `bpf`, a reboot): the hash back
    to 0c629a1f…, L3, DEGRADED "changed across a restart" (41ff88df →
    0c629a1f); `test-ignored` 82 suites 97 passed 0 failed. Found by the
    lab and fixed in the lot: a guest's reboot under QEMU for Windows ends
    QEMU (`-no-reboot`; the script reboots through `nn-lab.sh up`, one at
    a time), and the script read the audit log at the wrong path (the
    refusal check said FAIL: the refusals were read by hand,
    `r13-lab/b/manifest/nobpf-audit-rows.jsonl`); the resumed nobpf run had
    no hash before to compare (the agent refused at its start), the hash
    after is the normal phase's. The guests left with the tip installed and
    running, `lsm=` with `bpf`, no drop-in, powered off.
  - Gates on fd0f9e52 (the code): 77 suites 3,449 passed 0 failed 17
    ignored, `build-ebpf`, the four clippy runs, fmt, the privileged
    no-run, attack coverage, golden ×5 (54 files, the same bytes, tree
    clean), MSRV 1.89, fuzz replay (13 targets), portable (5 targets),
    lockfiles unchanged. Mutations: 49 of 49 caught (set A 44 of 47 — MB3,
    MB8 survived, MD4 did not compile —, A2 3 of 3 with their tests and MD4
    rewritten, B 2 of 2 for a source without its pump). Identity against
    `main` 973e3356 (one checkout path): the eBPF object 81c9df98… and
    `posture_demo` 909a38dc… (29 lines) the same.
  - Review of #479 ("merge after two small fixes"), fixed in the lot:
    X1 — a note was matched by its prefix and an unknown one read as a
    fallback `ok` (12 of 16 deny hooks, the DNS sensor without IPv6 and a
    worded failure of the exploit guard all read `ok`): the attach code
    says how it took each attach point (`Took`: whole, partial with what is
    missing, fallback, off, absent) and a source is `ok` only on its exact
    attach point taken whole (or a kernel's other name, `also`) or an
    equivalent fallback — `partial` and `unknown` otherwise; the deny hooks
    not attached tested in `missing` (K5), the unknown branch never masking
    an error (K8). X2 — a probe round that never started left `seen` in
    place: the word goes `stale` (149 s at 60 s), a change, DEGRADED off the
    host. The coordinator's: fallbacks that cover less `partial` with the
    event kinds lost (open_sensor on the tracepoint: MassWrite, FileBurst,
    DefenderSignal; exec_check: no exe identity, no guards); the lite
    exploit guard without `bpf` `partial`; LSM opt-ins configured without
    `bpf` said inert; `evidence` per source (probe, self_test,
    attach_only); the capabilities hash without the terms, the build or the
    kernel, `contract_hash` beside it (a NOTICE of the verifier's when it
    changes alone); change rows at most once a minute, every change
    counted, the terms by reference; the operator page says what the probe
    does not hold against (an adaptive root) and the worst-case delays.
    Found by the lab's round r2 and fixed: a healthy host's `fim_drain`
    read `partial` (with the file-open sensor, `fim_file_open_sensor` is
    the file_open observer: `fim::attach::observe_programs_missing`), and
    the lab script removed its partial drop-in before the trusted-installer
    window. Gates on 3914e4f8: 77 suites, 3,456 passed, 0 failed, 17
    ignored, every gate (golden ×5, MSRV, fuzz 13, portable 5). Mutations:
    set C 24 of 24 on 80977e1d (K5, K8, X1, X2, the fallbacks, the LSM's
    part, the inert opt-ins, the evidence, the two hashes, the rows, the
    stop's flush, the NOTICE), set D 3 of 3 (the FIM observers); 76 of 76
    in the lot. Lab round r3 on 3914e4f8: 6.8 — 12 sources `ok` and
    `file_open` `standby`, the same hash through two restarts, the probe
    blinded and back, `open_sensor` `partial` on the tracepoint with its
    lost kinds and back, the probe's rounds stopped (`stale`) and back,
    each a DEGRADED off the host; a lab-only build that changes only a
    term: the same capabilities hash, a NOTICE, no DEGRADED; 5.15 — the
    normal phase again, then `lsm=` without `bpf`: the start refused and
    signed, the degraded start at L0 (four sources not invoked;
    `exec_check`, `open_sensor` and `exploit_guard` `partial`), DEGRADED
    across the restart, restored to the hash before; test-ignored 82
    suites, 97 passed, 0 failed on each guest. Both guests left clean and
    off.
  - Re-check of #479 (X1 and X2 confirmed; "merge after two small
    fixes"): a worse state's change row is signed at once
    (`CapabilityManifest::worsens_from`: a source in a worse state, gone or
    new and not `ok`, a probe's word turned `gap` or `stale`, a line new
    in `missing`, `fallbacks`, the degradations, the content or the deny
    hooks' missing ones, fewer deny hooks, a lower trust level), unless
    the same state was signed within the minute (an oscillation); a better
    state's waits for the minute — a real loss's row no longer waits up to
    a minute, nor dies with a crash in it. A contract change is a NOTICE
    only when the agent's version, the contract's version and the kernel's
    release (the beat carries the last two now) each advanced or stayed:
    one going backwards, or not known to be newer, is DEGRADED "the sensor
    contract changed backwards". `fs_protect`'s `evidence: self_test` is
    said to be one deny hook of sixteen. Gates on 0267bd27: 77 suites,
    3,460 passed, 0 failed, 17 ignored, every gate (gates7 found a test of
    the manifest racing a module-mate's degradation, now worse and signed
    at once: the module's manifest tests hold one lock). Mutations: set E
    28 of 28 (ME10, a source back and not `ok`, survived the first run: a
    test added); 104 of 104 in the lot. No lab: unit-level changes.
  - Open: the health class has no event yet; the probe exercises three
    sources (process spawn, file open, DNS), the ten others are judged from
    their attach, the LSM's state and their pump only (`evidence:
    attach_only`), and the deny self-test exercises one deny hook
    (`task_kill`) of sixteen — R13's follow-ups: a loopback `connect()`, a
    harmless `bpf()`, an `io_uring_setup`, a FIM write and a second deny
    hook in the probe; a periodic check that the BPF links are still
    attached; `/sys/kernel/debug/kprobes/enabled` protected; a probe child
    harder to recognise; the opt-in
    connect deny's fail-open is not counted (no `DENY_FAIL_OPEN` slot: an
    eBPF change); a FIM or network drain that does not start is not a
    registry degradation (the manifest says `unavailable`); the boot's row
    carries the contract's terms (about 17 KiB), a change's row names them
    by `contract_hash`; the verifier's "across a restart" is named from the
    run of the last settled hash it kept.
- **Lot 272 — R14: privilege separation, the agent's unprivileged workers
  (Wave 4 Phase 2, the last step; R14a/b/c of the restructure plan, §3.1,
  §3.2, §3.3, §3.5; report 06 INI-19; HIGH risk; three stacked PRs).**
  - R14a — what changed: the agent's own binary, started from the
    descriptor of `/proc/self/exe` opened at boot (`/proc/self/fd/N`), as
    the new `northnarrow-worker` account (install, the packages' configure
    step, uninstall, the privileged tests' helper), runs as a `parse`
    worker: `no_new_privs`, no capability, not dumpable, no process, no
    core, 8 descriptors, 512 MiB; Landlock at the kernel's ABI (the
    `landlock` 0.4.7 crate, best effort, the level declared) and a seccomp
    allowlist that kills on anything else (`seccompiler` 0.5.0); a
    `SOCK_SEQPACKET` channel of postcard frames of at most 64 KiB with no
    descriptor, a checked hello, request ids, every answer bounded by the
    core; a supervisor with a backoff, a disable after five failures in a
    row and signed degradations, never parsing in the core;
    `PROTECTED_PIDS` entries as roles (`0x01` exempt, `0x02` protected:
    the agent and the watchdog `0x03`, a worker `0x02`, an entry an
    earlier version wrote, `1`, keeping both); the manifest's `workers`;
    R004's own launch; a compromised-worker harness; the lab scripts that
    counted or killed by name reviewed.
  - R14a — lab (as measured; our own guests): the workers' lab (identity,
    roles 0x03/0x03/0x02, a root `kill -9` of the worker refused, the
    roles' meaning in the hooks, the manifest; a crash, a hang, a kill, a
    crash loop disabled in about 6 s, signed, ready again; the agent's pid
    and the unit's restarts unchanged) 24 + 15 checks passed on Ubuntu
    22.04 (5.15, Landlock ABI 1 declared `Partial`, files only), Ubuntu
    24.04 (6.8, ABI 4, files and TCP), Debian 12 (6.1, ABI 2, files) and
    Debian 13 (6.12, ABI 6, files, TCP, signals and abstract sockets); the
    compromised-worker harness 4 of 4 on the four kernels (Ubuntu 22.04 on
    ca641d69, the others on the stack's tip; beneath the filter, files and
    exec refused by Landlock and DAC everywhere, TCP from ABI 4, signals
    and abstract sockets from ABI 6, executable memory refused by the
    filter alone — as declared); tamper-check: the same outcomes as
    `main`'s on Ubuntu 24.04 but C61, which counted the worker's entry as
    stale — the script fixed; EXP-13 the same checks as `main`; overhead
    ×3 within `main`'s noise (dns +21.5 % → +18.3 %); test-ignored 101
    passed, 0 failed on Ubuntu 22.04 (on Ubuntu 24.04, 4dc2e1f6: 100 and
    1, the harness's listener name reused — fixed in ca641d69); upgrade
    from `main` (by hand: the
    account created, roles 03/03/02) and uninstall (both accounts removed)
    clean. A lab flake, on `main` too: right after an agent restart under
    the lab's load, R009 killed the lab's own `uninstall.sh` (round a2)
    and `install.sh` (round a's upgrade-check, `main`'s agent); both
    passed on a settled agent.
  - R14a — gates on ca641d69: 79 suites, 3,510 passed, 0 failed, 17
    ignored, every gate (eBPF, clippy ×4, fmt, privileged no-run, attack
    coverage, golden ×5, MSRV, fuzz 13 targets, portable 5 targets).
    Mutations: set A 84 (75 caught; 5 survivors given tests; 2 site
    errors and 2 compile errors redone) and A2 9 (8 caught; `MP2`, the
    hello's kind, equivalent while there is one kind).
  - R14a — review of #480 (an independent review; its probes and
    mutations): F1 (a JA4 with a two-byte character across byte 23
    sliced a `&str` and panicked the core: byte checks, the two clippy
    lints denied on the module, the `ipc_check` fuzz target with the input
    as a regression), F2 (a worker that never read its channel filled the
    core's send queue and stalled the supervisor and `status()`: the queue
    checked empty by `SIOCOUTQ` before each request, `MSG_DONTWAIT`, a
    published status snapshot), F3 (a dead worker was reaped before its
    pid left `PROTECTED_PIDS`: `waitid(WNOWAIT)`, evict, then reap; a pid
    that cannot be evicted kept unreaped, signed), F4 (the worker's stderr
    through the core: escaped, cut, rate-limited), F5 (the harness never
    tried `mprotect` to executable nor `tgkill` to another pid — the
    review's mutations RM1 and RM2 survived it: both added), F6 (the
    60 s re-enable mutation RM16 survived: a tick between ready and the
    fault), F7 (the harness adds a UNIX socket by path, UDP, a user
    namespace, `io_uring_setup`, `keyctl`, `perf_event_open`,
    `userfaultfd`, each killed by the filter on every kernel; the worker
    measures Landlock after it enters it, the core checks the declaration
    against the kernel's ABI and the worker's `/proc/<pid>/status`), F8
    (`sendto`/`recvfrom` with fixed flags in place of `sendmsg`/`recvmsg`),
    F9 (ALPN printable ASCII, `Refused` a closed set), F11 (install.sh
    refuses an existing account it would not have created), F12
    (`oom_score_adj` 1000, `nice` 10, a spinning worker killed as a hang),
    and `PR_SET_PDEATHSIG` being the forking thread's (workers started from
    `nn-workers` only).
  - R14a — open: the `export` worker of §3.1 (no exporter yet); Landlock
    `Full` takes a kernel with ABI 9; from the review of #480: F10 (the
    degradation registry fills with a crash-looping worker's rows at the
    report rate — how a verifier weighs a row a worker caused), F13
    (`request()` can take up to twice its deadline when a ping is in
    flight on the same worker: one lock, two waits), and a `cargo-deny`
    licence check in CI (the licences of `landlock`, `seccompiler` and
    their dependencies were checked by hand for this lot).
  - R14b — what changed: the DNS pump's names decoded by the parse worker
    (batches of at most 512 names whose worst answer fits a frame, 250 ms
    a batch), every answer checked against its request; without an answer
    an event with no name (`qname_partial`), no cache feed, the names
    counted and said — never parsed in the core
    (`xtask/tests/no_parsing_in_the_core.rs`); the protocol's version 2 (a
    name's form: wire, wire with its end, an NSS record's text); the TLS
    ClientHello and DNS answers' parsers reachable only through the
    worker; the workers started before the sensors, a worker's pid
    registered once this boot's hooks are attached.
  - R14b — budget, stated in the lot's log before the measurement (Ubuntu
    24.04, `main` against the stack's tip, the same scripts): the `dns`
    overhead within 5 points of `main`'s, the other rows within their
    noise, the agent's CPU in the dns run at most `main`'s + 150 ms;
    EXP-13 every check `main` passes, each class's p99 within 1.5×
    `main`'s; a soak pair of 30 min: RSS growth within `main`'s + 16 MiB,
    no worker restart, the worker under 2 % CPU, no name left without a
    decode while it is up.
  - R14b — lab (as measured): overhead dns +21.5 % → +15.2 % (agent CPU
    10 → 30 ms, the worker's included), the other rows within 3 points or
    better; EXP-13 the same checks (12,000 refusals recorded or held, no
    ring drop, nothing over budget), p99 P0 1.8 → 0.7 ms, P1 0.35 → 1.0
    ms — 2.9× this run of `main`, outside the ratio stated, within
    `main`'s own spread on the guest that day (0.35 and 3.1 ms) —, P2 426
    → 487 ms, P3 7.7 → 0.9 ms; EXP-13c (DNS 200/s, connects 50/s, 12 + 12
    probes): the DNS events' p99 3.1 → 1.9 ms, NET-001 12 of 12 killed
    while connecting (median 13.3 → 11.0 ms), the staging probes 12 of
    12; EXP-13r 400 of 400 `success` on both; the soak pair: RSS +23.9 MB
    (`main`) and +22.1 MB (tip), CPU 1.9 % and 1.5 %, 0 restarts, the
    worker 5.2 MB, 0.0 % CPU, 0 restarts, in every sample, no name left
    without a decode. The worker's `parse` phase (decoded, disabled — a
    gap said, nothing parsed in the core —, decoded again) 7 of 7 on the
    four kernels.
  - R14b — gates on 70508844: 80 suites, 3,520 passed, 0 failed, 17
    ignored, every gate. Mutations: set B 18 (17 caught; `MB13`, the DNS
    cache fed without a decode, given a test and caught on the rerun).
  - R14b — review of #481 (an independent review; its mutations RB1–RB3
    and planting P1): R14b-1 (a worker answering `Refused` to every batch,
    or empty names, blinded the DNS with no signature: a refusal of a
    request the core checked is now a violation — killed, signed — and an
    empty name is refused where the bytes decode to one, an end where it
    is not just past a zero byte); R14b-2 (`NAMES_TIMEOUT` was 250 ms, the
    connects' whole wait for the DNS pass: now 50 ms, under a quarter of
    it, pinned by a test with a worker answering in 100 ms — RB1); RB3 (a
    request out of bounds is refused before it is sent: a test, now that
    the worker's refusal is a violation); R14b-3 (`serve::answer`
    `pub(crate)`, and `no_parsing_in_the_core` refuses a call of it, any
    `worker::serve::` but the worker's entry, and a re-export of nn-parse:
    P1 caught); R14b-4 (the refusal reason is a closed set since #480's
    F9, and the journal's line of names left undecoded is escaped);
    R14b-5 (every DNS record gives its event: `ParseClient::names` gives
    one entry per name whatever a batch's answer holds, `dns_pass` pairs
    by index and counts a mismatch — RB2's dropped events cannot happen);
    R14b-6 (the P1 p99 of 2.9×: the agent's delays are over its life, the
    start's slow decisions included; EXP-13 now reads them after a
    warm-up of process events — 100 times the class's decisions so far,
    4,000 to 100,000 — and says whether the start's are under 1 % of the
    population, and runs are compared by the median of their p99s over
    alternate runs; the method, not a new measurement). The hostile
    worker gains `refuse-all`, `empty-names`, `end-off-root`, `slow` (each
    killed) and `swap` (printed).
  - R14b — open: the round-trip check of a name against its bytes (the
    core re-encoding the worker's presentation form, a memory compare: a
    false but well-formed name passes every bound today — the harness's
    `swap` prints it); the names left undecoded as a signed
    `telemetry_loss` row and in `nn-admin status`; a latency histogram of
    the worker's answers (a high p99 as a degradation); EXP-13 per-run
    histograms (the status carries quantiles only, and its encoding takes
    no new field inside a queue's entry).
  - R14c — what changed: the key store (`KeyStore`, not `Clone`, handles
    only: an `Arc<dyn Signer>` and the `Vault`; each key in a locked,
    undumpable mapping of its own, zeroed on drop; the master key read once
    and held; `public_half` for the readers that verify; only
    `nn_linux::keys` names the key types — the vault's crypto moved there
    in a commit of its own); each thread's own capabilities
    (`nn_linux::caps`): the decision thread `CAP_SYS_PTRACE` alone, for
    good, with a seccomp filter of its own refusing `capset`, `execve`,
    `execveat`, `bpf`, `ptrace`, `process_vm_readv/writev` and
    `pidfd_getfd` with `EPERM`; the response workers `KILL NET_ADMIN
    SETFCAP DAC_OVERRIDE SYS_PTRACE`; the canary writer `LINUX_IMMUTABLE`;
    the supervisor `SETUID SETGID KILL BPF`; the eBPF load `BPF PERFMON`
    (and `SYS_ADMIN` under the Debian drop-in); `nn-errands` `BPF` for what
    the decision's filter refuses it (an RPM host's `rpm -qf`,
    `DEFENDER_PIDS`); every other thread the bounding set (the runtime's
    start hook, the pumps). The unit: `SystemCallFilter=~…` (the plan's
    list, `EPERM`), `SystemCallArchitectures=native`,
    `LockPersonality=yes`; the self-integrity round expects
    `no_new_privs` 1, seccomp mode 2, core limit 0. Departures from the
    plan's table, measured: the decision keeps `SYS_PTRACE` (at ∅ the
    rules' trusted actor, the COMBAT guard and the lineage could not read
    `/proc/<pid>/exe`), and so do the actuators (`/proc/1/root`, the
    target's exe).
  - R14c — lab (as measured; `deploy/lab/caps/thread-caps.sh`, a kprobe
    and a kretprobe on `cap_capable()` per thread, through the workers'
    lab, tamper-check and EXP-13r): on Ubuntu 22.04, Ubuntu 24.04, Debian
    12 and Debian 13 no check a role's thread made for its work was
    refused — the decision's granted checks all `SYS_PTRACE`, the
    actuators' `SYS_PTRACE` and `KILL`, the supervisor's `SETUID`,
    `SETGID`, `KILL` (and `BPF` on 5.15 and 6.1), the errands' `BPF`;
    refused only capabilities the unit does not grant (as before R14c),
    the workers' children after `setresuid` (their own `/proc/self/fd`,
    then allowed), aya's `DEVMAP` feature probe inside the loader's window
    (`NET_ADMIN`; no devmap in the agent) and, at an agent's exit, the
    kernel's re-sends of a worker's `PR_SET_PDEATHSIG` from the decision,
    the errands or the writer (the supervisor's own delivery first,
    granted). The census showed each role's set, every other thread the
    bounding set. No agent thread entered a call of the unit's denylist,
    nor (traced from the Ubuntu 24.04 round on) a program the agent
    starts; the decision entered only its own `capset` at its role's
    entry. tamper-check: the same outcomes as `main`'s on Ubuntu 24.04
    and Debian 12 (75 cases; on Ubuntu 22.04 too but C61, the old
    script's count, fixed in R14a); on Debian 13 too, with two deviations `main` has there as well (run on `main` on that guest): C31 and C33 — systemd 257 writes the unit's `cgroup.kill` after the agent's `kill(2)` is refused, a kill no task_kill hook sees (a lot of its own). EXP-13r:
    400 of 400 `success`, nothing left running, on the four; the hang's
    `stalled` row and 201 of 201 on the four; the crash's `interrupted`
    row signed by the next run (24.04). The workers' lab 24 + 15 + 7 of
    46 on the four. test-ignored: 101 passed, 0 failed on Ubuntu 22.04,
    Ubuntu 24.04, Debian 12 and Debian 13. upgrade-check from `main` OK on
    24.04 (UPGRADE complete, 19 of 19 deny hooks, the worker up);
    uninstall-check OK on the four (both
    accounts removed); its first run on Debian 12 ended as the lab's R009
    flake does (`uninstall.sh` gone a second after opening its window,
    after the 25-minute privileged run), the re-run on a fresh boot
    passed.
  - R14c — gates on 96412022: every gate but workspace clippy (a needless
    lifetime in a test) and four xtask tests (a static and a start call
    not listed, the vault's key type behind an alias, an unshipped
    document named) — fixed in the next commit, workspace clippy and the
    222 xtask tests then green; on 83f0c199 (rebased on R14b's final
    tip) every gate: 82 suites, 3,543 passed, 0 failed, 17 ignored. Mutations: set C 31
    (25 caught; 4 survivors given tests; `MC15` equivalent — seccompiler
    sets `no_new_privs` itself, the redundant call removed, the mutation
    redone; `MC25` a site error, redone): 7 of 7 caught on the rerun.
  - R14c — review of #482 (an independent review; its mutations RC1–RC5
    and plantings P3–P8): R14c-1 (the decision's filter did not stop what
    uid 0 needs no capability for — `/proc/<pid>/mem` opened for writing
    through `CAP_SYS_PTRACE`, a root file written as its owner, a root
    process signalled by equal uid: the filter now refuses every writing
    open and every signal to another process, the lab's trace of the
    refused calls in the notes below; §8 and the `caps` docs say what it
    still does not refuse), R14c-2 (the crypto crates' `zeroize` features
    on — the lockfiles gain dependency edges only; the public half read
    from `agent.sig.pub`; a key file read into a bounded, zeroed buffer),
    R14c-3 (a key's memory not locked or not out of the dumps is a signed
    `key_memory`, the master key's too; RC1 and RC4 given tests), R14c-4
    (`nn-cow-restore` and every thread the core starts take the core's set
    or a role, pinned by a source test — P5; a thread that cannot is a
    signed `thread_caps`; RC3 given a test), R14c-5 (`keys_in_one_place`
    refuses `Vault::at`, `public_half`, `DEFAULT_SIGNING_KEY_PATH` and the
    crypto's types outside the store but where it lists them — P3, P4, P7,
    P8; the quarantine's own master-key fallback is the tests' only;
    `thread_roles` pins the errands' three callers — P6), R14c-6 (the
    errands' wait bounded at 2 s, `rpm -qf` at 1.5 s, `--` before its
    path), R14c-7 (the master key read as the signing key is), RC5 (the
    x32 twins' numbers tested), MP2 (a second worker kind does not build
    until `check_hello`'s kind check gets its test). The three source
    tests cut a file's test code by its `#[cfg(test)]` items, no longer at
    the first test module's declaration (which left most of the agent's
    `lib.rs` unchecked).
  - R14c — open: the decision at ∅ behind a `/proc` broker thread; the
    chain writers on threads of their own with `LINUX_IMMUTABLE` only; the
    runtime's tasks narrowed; the lab's R009 flake (on `main` too): right
    after an agent start under the lab's load, R009 can kill the lab's own
    `install.sh`/`uninstall.sh`. From the review of #482: a read-only
    Landlock domain for the decision thread (the path-changing calls uid 0
    needs no capability for: `unlink`, `rename`, `chmod`…); a filter rule
    refusing the decision thread a new thread (`clone` of a thread,
    `clone3`); a signing thread with a locked, wiped stack (ed25519-dalek
    leaves `SHA-512(secret)` on the signer's stack); `MADV_WIPEONFORK` on
    the keys' mappings; typed errands (an enum, not a closure); nn-admin's
    sources in `keys_in_one_place`; a round of the copy-on-first-write
    guard under the capability trace.
- **Lot 274 — the nightly lab VM gate's red nights (C01; the lab harness
  and one privileged test, no product change).**
  - What was wrong: six of the twelve nightly runs of `lab-vm.yml` from
    22/10 to 02/11 were red. Each was classified from its job log, the
    guest's serial console and the gate log (the runs' artefacts):
    - Debian 12 failed at `sync` on 24/10, 28/10, 01/11 and 02/11, and
      Debian 13 at `build` on 23/10 and 26/10. The cause is in the lab
      harness. `wait_ssh` took "the lab marker exists and bpf is among the
      LSMs" for "past cloud-init's reboot". The Debian 12 and 13 kernels
      list bpf on their first boot already: the `lsm` line of `check` in
      those jobs is the kernel's default list, not the template's. So `up`
      said "guest is up and provisioned" in the seconds between the marker
      (the last runcmd) and the reboot of power_state. The serial console
      shows cloud-init finishing, then sshd stopping and the reboot, while
      the next step's ssh was open ("kex_exchange_identification: read:
      Connection reset by peer", "Connection to 127.0.0.1 closed by remote
      host"). The gate's Ubuntu guests were not exposed, because their
      first boot lists no bpf. AlmaLinux 9's default list includes bpf too,
      so the same window was open in the self-hosted lab.
    - Ubuntu 26.04 failed on 01/11 and 02/11 at
      `canary_privileged_e2e::process_canary_exec_triggers_canary_tripped_event_and_combat`
      (`ExitStatus(unix_wait_status(256))`, "left: None, right: Some(9)").
      This is a bug in the test, deterministic on that guest since lab PR
      269 (3daa3a2d, between the green 31/10 and the red 01/11). That PR
      made the decoy a copy of `/bin/sleep` named `decoy_helper` and
      asserted its SIGKILL. uutils' multi-call binary picks its utility
      from the name it is run by: it found none and exited 1 at once. The
      access row, the record and the KillProcessTree response were all
      there (the assertions before the kill passed).
  - What changed: the templates now write the provisioning boot's id
    (`/proc/sys/kernel/random/boot_id`) into the lab marker, as a new file
    renamed over it. `nn-lab.sh`'s `guest_boot_state` reads the boot id,
    the marker, the active LSMs and the lockdown line in one connection.
    `up` (under KVM and whpx) returns only for a guest on a later boot,
    with bpf among its LSMs and, on a lockdown guest, its lockdown mode.
    A marker without an id comes from a template before this lot; that
    guest rebooted long ago, since runcmd runs once per instance. A guest
    that does not get there ends the wait, after its console, with an
    error naming where it stopped: still on its provisioning boot,
    rebooted without bpf, not in lockdown, or unreachable. The canary
    test's decoy is now a copy of `/bin/sleep` that keeps the name
    `sleep`, in the test's own directory (as `response_privileged_e2e`
    and the execq controller tests already do). Before any agent runs,
    the test checks that the copy runs as sleep. Every assertion stays as
    it was.
  - Evidence: four tests in `xtask/tests/lab_host_safety.rs`. The first
    covers the block's twelve states, among them the nightly's Debian case
    (marker and bpf on the provisioning boot), Ubuntu's, an older
    template's empty marker, bpf as a substring only, and the lockdown
    cases. The second runs `wait_ssh` itself against a guest that answers
    twice on its provisioning boot and is ready at the first answer after
    it, plus its three errors. The third runs the command that gathers
    the guest's facts on the build host. The fourth checks that every template writes the boot id last,
    right before the reboot. `xtask/tests/lab_ci.rs` checks the error's
    shape. Two mutations fail the tests: dropping the boot comparison, and
    restoring the old readiness check.
  - Lab, on GitHub-hosted KVM guests (our own CI, nothing else): a
    manual dispatch of `lab-vm.yml` on this branch, run 41590801439 at
    0a9fc062, is the nightly's gate on all five guests. It was green on
    every guest: Ubuntu 22.04 (5.15), Ubuntu 24.04 (6.8), Ubuntu 26.04
    (7.0), Debian 12 (6.1) and Debian 13 (6.12), each 87 suites, 103
    passed, 0 failed, 0 expected failures. On Debian 12 the poll landed in
    the window: at 06:40:21 "guest provisioned, still on its provisioning
    boot: waiting for cloud-init's reboot", ready at 06:40:36, and `check`
    then listed the template's LSMs (`…,apparmor,bpf`), not the first
    boot's. On Ubuntu 26.04, `canary_privileged_e2e` passed 10 of 10.
    The race needs no local guest to reproduce: the failing nights' own
    serial consoles show it, and the xtask tests replay it.
  - Level unchanged (C01 2). Lot 274's docs PR makes C01's row say what
    the gate is: five guests nightly, green 6 nights of 12 from 22/10 to
    02/11, every red night caused by the lab or a test.
- **Lot 274, docs — the capability table realigned with a re-assessment
  of `main` (every capability; documentation only, no product change).**
  - What was wrong: the table above still gave the levels of 2026-10-20.
    Every note since says "Levels unchanged" or "no level changes", so the
    levels the evidence of the later notes supports were never recorded
    here, as the rule at the top of this file asks.
  - What changed: the table's levels are those of a re-assessment of 3/11
    of `main` at `5f8046f3` (Phase 2 closed) against the code, these notes
    and their lab numbers, the operator and design documents and the
    public CI runs. It was made read-only and apart from the lab PRs, but
    not by a third party (C29 stays 0). It uses this file's scale, and it
    refuses a 3 without independent validation. Each row now names its
    evidence, and each citation was checked on `5f8046f3`.
    - C12 1 → 2. The guest checks the notes of lab PRs 219, 223, 224 and
      226 owed are in their lab lines: the exec policy armed on four
      kernels with MS-01, MS-02, MS-03 and MS-32 refused (226), the connect
      deny armed on four kernels (224), and exec quarantine armed on 5.15,
      6.1, 6.8 and 6.12 (223). EPG's enforce kill is shown only with the
      debug build's injection (219). Reservations kept in the row: all of
      it is EXPERIMENTAL and off by default, and the behaviour proofs ran
      on one kernel (on 26.04 two EXECENV-002 cases draw no record). The
      policy has fixed cells, not per-rule inline denials, and
      `BPF_MAP_FREEZE` is untested. If "present" meant "on by default",
      C12 would be 1.
    - C13 0 → 1. Exec quarantine has a confined scanner (223), and the
      exec policy refuses execs from memfd, deleted files and `/dev/shm`
      (226). Both are off by default. The signed hash list ships empty,
      and the default heuristics resume the process. This is partial
      prevention: no prevention content is distributed, and no detection
      rate has been measured on a malware corpus.
    - C16 1 → 2. The mapping is typed for 93 of 93 rules, and the records
      of 44 rules carried their ids on four guests (221's lab line). It is
      not 3: the coverage is not measured. There are 0 `campaign` rows,
      and "lab" in `docs/detection/ATTACK_COVERAGE.md` means a script
      exists, not that it ran. The V2 campaign never started, and no third
      party has reviewed the mapping.
    - C30 2 → 0, absent by design. Lab PR 214 removed the on-host model,
      and the README says "no AI system on the host". That is this
      scale's "absent", documented as not supported. It is a decision,
      not a defect. An AI assistant, if any, would run off the host (the
      target). The governance of data is C25.
    - C23 stays 2, provisional. On Debian 13 with systemd 257,
      `systemctl stop` and `systemctl kill` stop the agent through
      `cgroup.kill` outside a maintenance window (anti-tamper cases C31
      and C33). The 2 holds because the watchdog restarts the agent and
      the heartbeat's external verifier sees the stop. It is to be
      reviewed when lot 273 closes, or if it finds the same gap on
      another systemd.
    - C07 and C19 re-checked, both stay 1. C07 lacks the three items its
      2 needs: inbound accepted connections, DNS answers, and TLS
      fingerprints in the flow record (lab PR 224 added verdicts, not
      telemetry). C19 covers in-place rewrites only: there is no
      protection before a delete or a rename over a file, and no
      remediation of persistences.
    - The other 23 levels are confirmed as they were: C01 2, C02 0,
      C03 0, C04 0, C05 1, C06 2, C08 0, C09 0, C10 0, C11 1, C14 2,
      C15 1, C17 2, C18 1, C20 1, C21 0, C22 0, C24 2, C25 2, C26 2,
      C27 1, C28 1, C29 0.
  - C01's row says what the nightly gate is: five guests (lab PR 227),
    green 6 nights of 12 from 22/10 to 02/11. Lot 274's fix PR
    #487 gives every red night a cause: a race in the lab harness on
    the Debian guests and a test fixture on Ubuntu 26.04, neither of them
    in the sensor.
  - Evidence: no new measurement. The levels follow the evidence already
    recorded in the notes above and in the files each row names.
  - Open, the cheapest next steps, each verifiable in the lab: C27 1 → 2
    (a release from a tag, verified end to end), C18 1 → 2 (a signed
    isolation verb outside the COMBAT ladder, with an expiry), C21 0 → 1
    (a signed export of the detections with a cursor), C05 1 → 2 (fork,
    exit and credential changes as telemetry), C07 1 → 2 (the three items
    above).
- **Lot 273 — C23: the units' cgroups, kill, freeze and moves refused
  outside a signed window (a security fix; found by lot 272's Debian 13
  lab).**
  - What was open: on systemd 257 and later `systemctl kill -s SIGKILL`
    of the agent or the watchdog ended in a write to the unit's
    `cgroup.kill` once `task_kill` had refused the signal to the main
    process — the kernel killed the cgroup, no signal hook saw it, the
    watchdog brought the agent back. Every kernel from 5.14 let any root
    shell do the same, freeze the unit (`cgroup.freeze`, `systemctl
    freeze`), or move the agent's pid to a cgroup of its own and kill or
    freeze that one. `RefuseManualStop=yes` held on every version (249 to
    259): the R14 lab's C33 "stop" was C31's kill read through a stale
    pid.
  - What changed: the units' cgroups in `PROTECTED_INODES`
    (`antitamper_bpf::cgroup_guard`, shared with the watchdog; the unit's
    directory `MUTATE|NOCREATE|INIT_RMDIR`, its and its slices'
    `cgroup.kill` / `cgroup.freeze` `MUTATE|WRITE` signed `cgroup_kill` /
    `cgroup_freeze`, `cgroup.procs`/`threads` `MUTATE`); PID 1 may remove
    an empty unit cgroup (`fs_protect_init_may`); the move guard (fexit
    `cgroup_procs_write_start` + LSM `inode_permission`, an optional deny
    pair selected from the BTF's prototype, `cgroup_move`); registered at
    the early start, the attach (with the live watchdog's), the watchdog
    refresh and by the watchdog itself; `NN-L-AT-001` names the three
    operations; every denial row names its caller's executable (the
    lineage's, then `/proc`); tamper-check C15/C20 expect a refusal, C33
    reads the agent it checks, C65–C76 new.
  - Lab (as measured; our own guests, two at a time): before, `main` 5f8046f3 on the five guests (Ubuntu 22.04 5.15 /
    systemd 249, Debian 12 6.1 / 252, Ubuntu 24.04 6.8 / 255, Debian 13
    6.12 / 257, Ubuntu 26.04 7.0 / 259), the lot's probe: `systemctl stop`
    and `restart` refused on all five; `systemctl kill -s SIGKILL` of the
    agent or the watchdog refused on 249/252/255 (`kill(2)` per process)
    and the unit killed on 257/259 ("Killed unit cgroup with SIGKILL on
    client request"); on all five `systemctl freeze`, `echo 1 >
    cgroup.freeze`, `echo 1 > cgroup.kill` of either unit, the slice's
    files opened for writing, a child cgroup, a `chown` of `cgroup.procs`
    and moving the agent's or the watchdog's pid to another cgroup went
    through. After, the lot's code on the five: every one of those refused
    (EPERM or "Access denied"), the agent and the watchdog alive, the
    stop and restart refused as before; `rmdir` of the unit cgroup EPERM
    (was EBUSY). The tamper check with the new cases: Debian 13, `main`
    installed then the lot's code by `upgrade-check` — 87 cases, `main` 70
    OK, the lot 84 OK (C27, C57c the known gaps, C64 the recorded
    deviation); the 71 cases the lot does not touch the same outcome and
    verdict (C30 102 → 118 entries, no growth across a restart); C15, C20,
    C31, C65–C75 DEVIATION on `main` (allowed, partial, ERANGE, EBUSY) and
    OK on the lot, C76 (inside a window) OK on both; Ubuntu 24.04 the same
    picture (`main` 71, the lot 83; 73 the same; C76 failed on both on
    255 by `systemctl kill`'s exit status, the kill done — the case takes
    it by its effect now, OK on the re-run); the cgroup cases on Ubuntu
    26.04 17 of 17, on Ubuntu 22.04 and Debian 12 16 of 17 — C66 found
    systemd's own freezer state still `freezing` from the probe's refused
    freeze (249 and 252 keep it: "Previously requested freezer operation
    … still in progress"), nothing frozen; C66 reports that state now, and
    on Ubuntu 22.04 fresh it is OK, then N/A after a refusal by hand. The
    signed rows: `deny=cgroup_kill|cgroup_freeze|cgroup_move|mkdir|rmdir|
    setattr`, PID 1's relayed requests as `RelayedTamperAttempt`, the
    caller's executable from the lineage for one-shot processes
    (`/usr/bin/python3.12`, `/usr/bin/rmdir`, `/usr/bin/bash`; the first
    build, reading `/proc` in the writer, found them gone). Verifier: 79 of
    79 programs on 6.8, 6.12 and 7.0, 77 + the two ACL hooks absent on
    5.15 and 6.1 (`cgroup_move_deny` 285–309 instructions,
    `cgroup_move_stash` 149–165). `upgrade-check` from `main`: Debian 13
    and Ubuntu 24.04 OK (deny_attached=21 deny_expected=21, own LSM
    programs 36 → 37); its first run on 24.04 hit the R009 flake R14
    recorded (an `install.sh` right after the agent's restart), OK on a
    settled agent. `uninstall-check` OK on both. test-ignored: Debian 13
    103 passed, 0 failed; Ubuntu 24.04 103 passed, 0 failed. EXP-13 on
    both: 12,000 refused attempts, 8 recorded and 11,992 held, ring drops
    0, P0 none dropped. Host reboot on the five and power-off on Debian 13
    and Ubuntu 24.04: the stop job's `kill(2)` refused as before ("Failed
    to kill control group … ignoring"), `systemd-shutdown`'s SIGTERM ended
    the agent, a signed `agent_stop` `system_shutdown`, the next boot's
    `agent_boot` "ended clean, reason system_shutdown" (power-off 5–7 s;
    Ubuntu 22.04's reboot with systemd's freezer state stuck as well).
    Cost: `overhead` on Ubuntu 24.04 (2 rounds), `main` → the lot: open
    +28.1 → +37.0 %, wopen +30.2 → +36.3 % (exec, connect, udp, dns within
    the noise); an A/B on the lot itself (3 rounds, the move guard's links
    detached and attached in turn): open about −10 %, wopen about −8 % —
    the `inode_permission` program on every permission check of a path
    walk. Every guest left off.
  - Gates: on the code (0723b596) and on the lexical-test and resolver commits
    (dc9e5a4e), then on the tip rebased on `main` 94c8a79e (e027e33e):
    `cargo xtask build-ebpf --release`, the four clippy runs `-D warnings`,
    `fmt --check`, `cargo test --workspace` 83 suites, 3,602 passed, 0
    failed, 17 ignored, the privileged tests built, `attack-coverage
    --check`, `cargo xtask golden` five times (54 files, the same bytes,
    the tree clean), MSRV 1.89, the fuzz replay (14 targets), portable-core
    (5 targets), lockfiles unchanged. The eBPF object rebuilt: two new
    programs (`lsm/inode_permission`, `fexit/cgroup_procs_write_start`),
    one new map (`CGROUP_MOVES`, LRU, not pinned), `DENY_FAIL_OPEN` 20 →
    22 slots (not pinned); no wire record changed (`FsProtectDenialRaw` 56
    bytes): three new operation codes (19–21) and three `PROTECTED_INODES`
    flag bits (4–6) read by the new and the existing deny hooks; new
    bpffs pins `prog_`/`link_inode_permission` and
    `prog_`/`link_cgroup_procs_write_start`, purged and re-made like the
    others at each start.
  - Mutations: set A 47 (46 caught; MA9 — the `..` component check —
    equivalent: `.`, `..` and the empty name never end in `.slice` or
    `.service`, the suffix checks refuse them too; kept as defence in
    depth), set B 5 of 5 (the executable resolver). The eBPF guard's checks
    and every registration site are read by `xtask/tests/cgroup_guard.rs`
    (12 of set A's and 1 of set B's caught there).
  - Open, lot 273b's scope: the units' and their slices' resource limits
    are not refused, and are not only reported — a low `memory.max` is an
    OOM kill inside the write itself (on `system.slice` a persistent OOM
    loop that also kills new watchdogs), `cpu.max`, `cpu.idle` and
    `pids.max` starve the agent like a freeze (`pids.max` also breaks the
    actuators' execs); a change the agent survives is an `integrity_drift`
    (C12). systemd writes them as PID 1 at every realisation, so lot 273b
    refuses the other writers and checks the value PID 1 writes. cgroup v1
    is not covered, on pure v2 hosts too: root can mount the v1 `freezer`
    (or `devices`, `net_cls`, `net_prio`, `perf_event`), move both pids
    there and write `FROZEN` to `freezer.state`, and the move guard does
    not see the v1 `cgroup.procs` path (to be confirmed in lab, lot 273b).
    A write descriptor of `system.slice/cgroup.kill` opened at any time
    before the agent's first start stays usable (the refusal is at open),
    as does one of a unit's opened inside a window. Also open: a thaw
    outside a window is refused like a freeze; systemd 249 and 252 keep a
    unit `freezing`/`thawing` in their own state after a refused freeze or
    thaw (nothing frozen; their next
    `systemctl freeze`/`thaw` says "still in progress" until a freezer
    event); the move guard's cost on path-heavy work (about −10 % on the
    open microbenchmark): no cheaper attach point exists in the
    migration's path today (no LSM hook names the moved task; the
    functions there are not `fmod_ret` targets).
- **Lot 273b — C23: what stopped the agent without a signal — the units'
  resource limits, a cgroup v1 freezer, a descriptor opened earlier, the
  OOM score — refused outside a signed window; the move guard made to hold
  (a security fix; the review of #489).**
  - What was open (measured on `main` 56ce3c3b, lot 273, on the five
    guests; tamper cases C12, C18, C79–C85): a root shell's `memory.max`
    of one page OOM-killed the agent inside the write (C79, on all five);
    `pids.max=1` on `system.slice` (C80), `cpu.max` 0.1 % on the watchdog's
    unit (C81) and `cpu.idle=1` on the agent's (C81b) went through;
    `systemctl set-property --runtime MemoryMax=4G` lowered the agent's cap
    and left its drop-in (C12), `set-property northnarrow-watchdog
    TasksMax=1` the same for good (C85); a v1 `freezer` mounted at
    `/run/nn-lab-v1` took the agent's pid and froze it (C83, C83b, on all
    five: none booted with `cgroup_no_v1=`), unseen by the move guard; a
    `cgroup.freeze` descriptor opened inside a window wrote after it
    (C82); the agent's `oom_score_adj` took 900 and a thread's 1000 (C18,
    C84). And a regression of lot 273: every version's PID 1 rewrites a
    slice's unit cgroups' xattrs when it realises a sibling (an `xattr`
    refusal signed on every `set-property`, five guests), and 254/255 thaw
    the slices at each start and stop of any unit (Ubuntu 24.04: "Failed
    to thaw slice system.slice of unit: Operation not permitted" at every
    `systemctl restart`, a relayed attempt signed each time).
  - What changed: a write deny at the write (`protected_write_deny`, LSM
    `file_permission`, the 17th deny hook: a descriptor opened earlier
    writes nothing); the resource files of the units' and their slices'
    directories (`FS_PROTECT_LIMIT_DIR`, by name) refused to all but PID 1,
    whose write — its bytes read from the syscall, systemd's newline
    cleared — must be the value the file held at the registration (pinned
    `LIMIT_VALUES`) or the kernel's default; the values registered again
    at a window's close; the units' four `system.control` directories made
    by the agent's unit and registered `NOCREATE`; any cgroup v1 write
    refused where systemd runs the unified hierarchy (pinned
    `CGROUP_POLICY`; the host check's `cgroup_v1`); the protected pids'
    `oom_score_adj` / `oom_adj` refused (four optional BTF offsets); PID
    1's thaw (`0`) and its xattrs on unit cgroups let through, its freeze
    refused at the write; the move guard's third program (fentry
    `cgroup_procs_write_finish`) drops a record at the end of every write,
    a record consumed only on a cgroup v2 `cgroup.procs`/`threads`, the
    stash a non-evicting 64-entry map (an insert refused is a counted
    fail-open), the guard self-tested at every boot
    (`move_guard_self_test`); both units `IgnoreOnIsolate=yes`; the cost
    in the manifest (`fs_protect`'s `overhead`). Tamper cases C12 and C18
    expect a refusal, C77a/b, C78a/b, C79–C86 new, C08 takes PID 1 back out
    of `PROTECTED_PIDS`; a privileged test of the move guard, an earlier
    descriptor and the OOM score.
  - Lab (as measured; our own guests, two at a time, all left off):
    before, `main` 56ce3c3b on the five guests (Ubuntu 22.04 5.15 / 249,
    Debian 12 6.1 / 252, Ubuntu 24.04 6.8 / 255, Debian 13 6.12 / 257,
    Ubuntu 26.04 7.0 / 259) with the lot's tamper cases: C12, C18,
    C79–C85 DEVIATION on all five (allowed; C79 "pid … is gone"), C78b
    recorded the unit dead on 249, 252 and 259, C86 refused PID 1's thaw on
    252, every `set-property` an `xattr` refusal. After, the lot's code
    2347c573 (the final commit differs in comments, tests and docs): the
    sixteen cases OK on all five — C12/C85 `cgroup_limit` + `create`, C18
    and C84 `oom_adj`, C79–C81b `cgroup_limit`, C82 `cgroup_freeze` at the
    write, C83/C83b `cgroup_v1`, C78b no stop job, C86 nothing signed; the
    full tamper check 102 cases, 98 OK on 249, 252, 255 and 257 (C27, C57c
    the known gaps, C64 the recorded deviation, C78c N/A), 96 on 259:
    C04b (a ptrace read of `/proc/<agent>/environ`) and C58 (a renamed
    module tool's load) deviate there with `main` too (its own tamper
    check on the same guest: the host's, not the lot's).
    `upgrade-check` from `main`: Debian 13 OK (`deny_attached=23
    deny_expected=23`, own LSM programs 37 → 38), Ubuntu 24.04 OK after a
    settle (its first run the lab's R009 flake). `uninstall-check` and a
    fresh install with a new key (round 1) OK on 24.04 and Debian 13.
    Verifier: 81 of 81 programs on 6.8, 6.12, 7.0, 79 + the two ACL hooks
    absent on 5.15 and 6.1 (`protected_write_deny` 3,753–3,925
    instructions, `cgroup_move_deny` 556–580, `cgroup_move_clear` 9). The
    move guard's boot self-test refused its move at every start. Flows on
    the five: `daemon-reload` / `daemon-reexec` sign nothing (249, 252,
    255, 259 write the units' attributes again, with a newline, cleared
    now; the lot's first version refused them, round 1); a `set-property`
    outside a window answers 0, silent, refused at the cgroup and the
    drop-in; inside one kept, "values=40 units=2" registered again at the
    close (44 on 249 and 255), the reload after it let through; a refused
    `MemoryHigh=2G` still in systemd's copy reached the agent's fresh
    cgroup at a restart inside a window (2 GiB, all five). Soft-reboot on
    255 and 257, with #482's merge, lot 273 and the lot: identical — both
    processes survive (pins and links kept), the new userspace's systemd
    will not start the units while they run (`failed`); 259 records them
    stopped and waits about 90 s; a reboot after it signs `agent_stop
    system_shutdown`. test-ignored on Ubuntu 24.04, the lot's code: 89
    suites, 107 passed, 0 failed (`cgroup_guard_privileged_e2e` 4 of 4;
    round 1 found its first version writing the tempdir's `--admin-pub`,
    which nothing protects: it writes the installed one now). Cost: see `ANTITAMPER_TRUST_MODEL.md`, "Lot
    273b" (the move guard about 59 ns a call, `git status` ×10 +24 %; the
    write deny about 96 ns a write, a 2,000-file package +9 %; open/wopen
    +41 % agent off/on). Reboots clean on the five; every guest left off.
  - Gates: on the code (3aa8439a) and on the three commits on `main`
    da164d10 (8a6e838a, the tree of the lab's 2347c573 with comments,
    tests and docs; the eBPF object byte-identical): `cargo xtask
    build-ebpf --release`, the four clippy runs `-D warnings`, `fmt
    --check`, `cargo test --workspace` 84 suites, 3,617 passed, 0 failed,
    17 ignored, the privileged tests built, `attack-coverage --check`,
    `cargo xtask golden` five times (54 files, the same bytes, the tree
    clean), MSRV 1.89, the fuzz replay (14 targets), portable-core (5
    targets), lockfiles unchanged; the fix's commit alone: the xtask tests
    23 suites, 234 passed. The eBPF object: two new programs
    (`lsm/file_permission`, `fentry/cgroup_procs_write_finish`), two new
    pinned maps (`LIMIT_VALUES`, `CGROUP_POLICY`), the stash
    `CGROUP_MOVES` a 64-entry hash map (was LRU, not pinned),
    `DENY_FAIL_OPEN` 22 → 24 slots, three op codes (22–24:
    `cgroup_limit`, `cgroup_v1`, `oom_adj`) and one `PROTECTED_INODES`
    flag bit (7, `LIMIT_DIR`); the wire record unchanged; new bpffs pins
    `prog_`/`link_file_permission` and
    `prog_`/`link_cgroup_procs_write_finish`.
  - Mutations: 70 in three sets on the lot's code: 67 caught, two the
    compiler rejects (ML10: the clear hook out of the optional list, MS4:
    the self-test's refusal arm guarded off — neither builds), one
    survivor, MD9: the lab script's C08 restore disabled, which its
    `--selftest` does not see and the lab does (C12 deviates without it,
    as round 1 showed). The guard's checks, every registration and the
    window's refresh are read by `xtask/tests/cgroup_guard.rs`; the unit
    files' `IgnoreOnIsolate=` and `system.control` directories by
    `watchdog/tests/systemd_units.rs`.
  - The review of #490 (merge after A and B; the rest to lot 273c): A —
    the watchdog's drop-in directories and the `northnarrow-.service.d`
    prefix ones, which apply to both units, were not NOCREATE: on the PR's
    head the lab made a drop-in in all four (C87), which the next start's
    fresh cgroup would have taken (a `MemoryMax=4K`: an OOM loop); now the
    agent's unit makes them, the agent registers them NOCREATE,
    `uninstall.sh` removes them: 4 of 4 refused (`create`). B — the
    resource files were recognised by their dentry's name and parent:
    confirmed on the PR's head, the agent's `memory.max` reopened through
    `open_by_handle_at` after `drop_caches` (a disconnected dentry, its path
    `/`) took a write (C88; its own value, harmless there, where 4096
    would have been the OOM kill); now by the file's kernfs node (its
    `name`, its parent node's `id`: two optional BTF offsets,
    `kernfs_node.parent` / `__parent` and `.id`, their absence signed) or by
    its registered value — refused at the `open_by_handle_at` itself
    (EPERM, `cgroup_limit`); the node alone, the file's registered value
    deleted from `LIMIT_VALUES` first (`bpftool`, the lab build's
    observe-mode guard): refused the same. Ubuntu 24.04, the fix by `upgrade-check`:
    the verifier 81 of 81 (`protected_write_deny` 4,834
    instructions), the full tamper check 104 cases, 100 OK (C87, C88
    with them; C27, C57c, C64, C78c as before), `uninstall-check` and a
    fresh install, a reboot with both units active. Mutations, set F: 10,
    9 caught; MF10 (C88's helper without the dropped dentries) is the lab's
    to see. Gates on the two commits (ff15dcaf): `build-ebpf`, clippy ×4,
    fmt, `cargo test --workspace` 84 suites, 3,619 passed, 0 failed, 17
    ignored, the privileged build, `attack-coverage`, golden ×5 (54 files,
    the same bytes), MSRV, fuzz (14), portable-core (5), lockfiles
    unchanged.
  - Open: a refused `set-property` still sets systemd's own copy of the
    property until the next `daemon-reload`, and the unit's next start
    applies it (the operator's reload before a restart; lot 273c: the
    agent's own reload); a soft-reboot leaves both units `failed` with
    their processes running and protecting (since EBPF-001; lot 273c: end
    at its stop job, or survive the systemd way); a stop propagated from a
    `Conflicts=` unit records the unit stopped (C78a); `cpuset`,
    `cpu.uclamp.max`, `memory.swap.max`, a sibling's `memory.low` are not
    refused; a hybrid v1 host, another architecture than x86-64 and a
    kernel without the proc offsets are signed degradations; a shared
    writable mapping opened before a registration and a write in a fresh
    cgroup's first milliseconds are not seen; the move guard's cost on
    path-heavy work.
- **Lot 273c — C23: another process's limits and priorities of the agent
  refused, PID 1 closed to attach-mode access, no resource value below a
  floor registered, systemd's copy of a refused `set-property` taken
  back, the host's drop-ins judged by their value for our units (a
  security fix; the reviews of #490 and #492).**
  - What was open (measured on #490's head 25cff4ca, tamper cases
    C89–C102, Ubuntu 24.04 and Debian 13): `prlimit --pid <agent> --cpu=1:1` ended the
    agent (the kernel's RLIMIT_CPU SIGKILL, no signal hook saw it: nothing
    signed but its successor's `prev_run_abrupt`; C89), `--nofile=0:0` too
    (C90); `renice +19`, `chrt --idle`, `taskset` to one CPU and
    `ionice -c 3` of the agent went through unsigned (C91–C94); a tracer on
    PID 1 and `/proc/1/mem` for writing went through (C95, C96); a
    `memory.high` of 100 MiB set inside a window stayed after it (C98); a
    move in a named v1 hierarchy was refused (`cgroup_v1`, C99); a refused
    `set-property MemoryHigh=2G` left systemd's copy at 2 GiB (C100);
    `memory.reclaim` of the agent's unit was written (C101); the agent
    killed inside a window with systemd's copy at 100 MiB came back with it
    in its fresh cgroup, throttled — not up within the case's minute (C102).
  - What changed: four deny hooks (21 in all; `task_setrlimit`,
    `task_setscheduler`, `task_setnice`, `task_setioprio`, signed `rlimit`
    COMBAT, `sched` / `nice` / `ioprio` ENGAGED) refuse another process's
    change of a protected one's limits, scheduling, nice value and I/O
    priority outside a window; the ptrace hook refuses attach-mode access
    to PID 1 outside a window (a tracer, `/proc/1/mem`,
    `process_vm_writev`: lot 273b trusts PID 1's write-backs on its
    `write(2)` bytes); a registration (the start, the watchdog's check of
    the agent's fresh cgroup at its start and after a respawn, a window's
    close) registers a value below its floor only as the floor —
    registered, written, read back — signed `limit_floor_restored` (the
    watchdog's through its hold record); the agent asks systemd for a
    reload — a SIGHUP to PID 1 once PID 1 is found serving the private
    socket — after a refused PID 1 write of the units (at most one every
    30 s, later ones kept, one per target per 10 minutes), at a window's
    opening (signed `systemd_reload`); the host's drop-ins of
    `service.d`, `slice.d`, `system.slice.d` are never moved or changed
    (the review of #492, C1: the first version moved every one naming a
    "dangerous" directive, whatever its value, from every service of the
    host): a directive whose value harms our units is signed
    `unit_dropin_harmful` while it is there, any other one is an alert
    (`unit_dropin`); while a harmful one is on disk the agent's reloads
    are withheld (round 7: the reload at a window's opening applied a 4K
    `system.slice` inside the window); cgroup v1
    is refused only in a hierarchy that binds a controller, at
    `cgroup.procs`, `tasks`, `freezer.state` (six optional BTF offsets
    read the hierarchy's `subsys_mask`); `cpuset.*`, `memory.reclaim`,
    `io.weight`, `io.bfq.weight` are protected; the write deny leaves at
    once on a file that is not a regular one. PID 1's verdict and the
    files' classification are the shared module's pure functions
    (`init_write_lets_through`, `special_fs`), which the host's tests judge.
    `DENY_FAIL_OPEN` 24 → 28 slots, op codes 25–28, BTF offsets slots
    112–117 (the later slots move by six), new pins
    `prog_`/`link_task_set{rlimit,scheduler,nice,ioprio}`.
  - Found in the lab and fixed in the lot: the first reload was
    `Manager.Reload()` on systemd's private socket; systemd lets a caller
    reload at once only with `CAP_SYS_ADMIN` (not in the agent's unit) and
    asks polkit for any other, and on 255 each call waited its whole 30 s
    timeout, systemd reloading only at the connection's close (30 times
    "Failed to send queued message"; round 4). Now a SIGHUP.
  - Lab: our own QEMU guests, at most two at a time, each off at
    the end (Ubuntu 22.04 / 5.15 / 249, Debian 12 / 6.1 / 252, Ubuntu
    24.04 / 6.8 / 255, Debian 13 / 6.12 / 257, Ubuntu 26.04 / 7.0 / 259).
    The verifier: 85 of 85 programs on 6.8, 6.12 and 7.0, 83 + the two
    ACL hooks absent on 5.15 and 6.1 (`task_set*_deny` 802–841
    instructions, `ptrace_access_check` 874–906, `protected_write_deny`
    5,341–5,529; round 5, the lot's final eBPF). The new cases and the cgroup cases (C12–C102, 31 rows):
    31 of 31 on 6.1 and 7.0, 30 of 31 on 5.15 (C101 not run: no
    `memory.reclaim` before 5.19); on 6.8 the eleven of round 5's list
    OK (C102's cleanup, then without a window of its own, left systemd's
    copy in `/run`: the case grants one now, clean on the others); Debian 13's full tamper check
    119 rows, 114 OK (C27 and C57c the known gaps, C64 the recorded
    deviation, C78c not run, C102 in its first version: redone, OK). The
    privileged tests on 24.04 (`test-ignored`, round 4's code): 107
    passed, 0 failed. A reboot on 24.04 and Debian 13: both units active.
    An upgrade from #490's head: OK on 24.04 (round 4); on Debian 13 the
    head's agent killed `install.sh --upgrade` both times
    (`R009_RootExecFromUserPath`, `KillProcessTree` in Observing: the
    lab's known flake, the code before the lot), and the lot was
    installed fresh. The cost: the trust model's "Lot 273c", Cost. C97,
    the host's drop-ins, after C1: on #492's head (Ubuntu 24.04, round 7) all
    three drop-ins of the case — `LimitNOFILE=1048576` and
    `SystemCallFilter=~@obsolete` in `service.d`, `MemoryMax=4K` in
    `system.slice.d` — were moved; now (round 8) the three stay, the 4K is
    refused at the slice (inside a window opened with it on disk too: the
    agent's reloads withheld) and signed harmful, the other two are alerts.
    Round 7 also found the window case: with C1's first version, the
    reload at a window's opening applied the 4K, the slice's services
    killed — hence the withholding. C85, C98, C100, C102 OK again.
  - Mutations: 30 in three sets on the lot's code, 30 caught. Set G (20): each term of
    the task hooks' check and the rlimit refusal, PID 1's attach mode (off,
    and widened to read mode), the `i_mode` exit inverted, a named v1
    hierarchy refused, the agent's memory floor 0, a restoration always ok,
    the reload's interval dropping instead of deferring and its per-target
    quiet removed, the first version's quarantine without its reload and
    `NN_` not dangerous (both on the code C1 replaced), a
    refused priority made decisive, the pipeline's reload for a limit
    write, two fail-open slots shared, the rlimit op code reused,
    `memory.reclaim` given a default, the respawned agent unchecked. MG9
    and MG10 first ran under a suite filter that missed `cgroup_floors`
    and survived; under the floors' own suite MG9 is caught, MG10 once a
    read-back test was added. The review's P2 and P3 with three variants
    (5), caught by the shared module's tests and the whole-arm pins. Set H
    (5): the reload's peer check and its signal, the watchdog's records
    swapped, unrecorded and signed under another kind (MH1 and MH5 first
    "caught" by a stale eBPF stamp in the mutation tree, then by their
    tests once rebuilt).
  - Gates on a4f3bb83 (the fix commit's code): `build-ebpf`,
    clippy ×4, fmt, `cargo test --workspace` 84 suites, 3,636 passed, 0
    failed, 17 ignored, the privileged build, `attack-coverage`, golden ×5
    (54 files, the same bytes), MSRV, fuzz (14), portable-core (5),
    lockfiles unchanged.
  - Not done (reasons in the trust model's "Lot 273c", Cost): one program
    for the write deny and the FIM's on `file_permission` (it would tie a
    deny hook to the FIM's configuration); the signed "workstation" policy
    that detaches the move guard (a new overlay kind, its verbs, the
    kernel recovery path, its own review).
  - Open: `daemon-reexec` into a modified systemd binary (PID 1's exec is
    not refused; the FIM watches the binary); PID 1's memory before the
    first attach; a harmful host drop-in stays on disk and reaches our
    units' next start (lot 273d: `northnarrow.slice`, the signed opt-in
    list for a quarantine); the reload is asked, not awaited, and a repeated
    refusal of one file within 10 minutes asks none (the floors still
    apply at a restart); `cpu.uclamp.max`, `memory.swap.max`, a sibling's
    `memory.low` / `memory.min`; a soft-reboot (lot 273b's residual,
    outside this lot); a hybrid v1 host, another architecture than x86-64
    and a kernel without the proc offsets are signed degradations; the
    move guard's cost on path-heavy work.
- **Lot 277 — C15/C23: an exemption by cgroup or unit holds for a process
  started in the cgroup; the host check names the kernel fixes the sandbox
  relies on; a worker enters its sandbox single-threaded (Wave 4 phase 3,
  wave 1).**
  - What was open: the per-rule policy's `exempt <rule> cgroup|unit`
    matched any member of the cgroup (`/proc/<pid>/cgroup`). A root shell
    that wrote its own pid into an exempt service's `cgroup.procs` was
    exempt from the rule. `nn-admin host-check` named no kernel fix. The
    worker never checked that it was its process's only thread before
    Landlock and `no_new_privs`, which bind the calling thread only.
  - What changed: five eBPF programs (the start-in-cgroup tracker,
    `agent-ebpf/src/cgroup_join.rs`) mark a process moved into a cgroup by
    anyone but systemd's placement. That placement is a move by PID 1, or
    a fresh child of PID 1 moving itself while it shares PID 1's
    `mm->exe_file`; a move that changes nothing is no move. They also mark
    a child started by `clone3(CLONE_INTO_CGROUP)` by anyone but PID 1,
    and every process either one forks after, before it runs. The mark goes
    with the group's last thread. A marked process is not exempt by cgroup
    or unit, and neither is one whose state is not known (no tracker on
    this kernel, a mark the pinned map could not take). A move into a
    cgroup an exemption names is a signed NN-L-AT-001 `cgroup_join` (not
    refused, no posture trigger). The host check gained `kernel_fixes` for
    CVE-2022-0847, CVE-2022-30594, CVE-2024-42318 and CVE-2025-68736, the
    versions from the kernel CNA's records and the stable changelogs. A
    distribution's kernel below a fix is `unknown`, never `ok`.
    `lockdown=integrity` is recommended on every host; kexec counts its
    6.6+ load limits; module signing counts `modules_disabled`. The worker
    counts `/proc/self/task` first and exits 78 with more than one thread.
  - The lab, as measured (our own QEMU guests, two at a time, left off):
    - **Ubuntu 22.04** (`5.15.0-202-generic`, systemd 249). The first
      build's `cgroup_join_mark` was refused by the 5.15 verifier: E2BIG,
      a component length counted per byte over 256 bytes. The start signed
      the tracker absent, and every exemption was refused, the control
      included: fail closed. With the walk keeping no counter,
      `verifier-check` passed: 84 of 86 programs, the two ACL hooks absent
      on 5.15, the tracker's five loaded (`cgroup_join_mark` 876
      instructions). `exempt-check`: MS-23 started by systemd as
      `nn-lab-exempt.service` was exempt (300 of 300 files, no
      `cgroup_join` record). A root shell that moved itself into the unit's
      cgroup (`/proc/self/cgroup` named it) was killed under `enforce
      NN-L-IMP-001` (20 of 300), and its move was a signed NN-L-AT-001
      `cgroup_join` naming `unit nn-lab-exempt.service`. Its orphan
      (reparented to PID 1, in the unit's cgroup) was killed too (20 of
      300). A move into a cgroup no exemption names was not signed.
      `host-check` `kernel_fixes`: `unknown`, 5.15.222 from Ubuntu's
      signature, CVE-2025-68736 not in the version. On the tip before the
      merge of #492: `test-ignored` 90 suites, 108 passed, 0 failed;
      tamper-check 103 cases, 100 OK, C27 (no lockdown) and C57c the known
      gaps, C64 the recorded deviation.
    - **Debian 13** (`6.12.113+deb13-cloud-amd64`, systemd 257 with
      `CLONE_INTO_CGROUP`), on the merged tip: `verifier-check` 90 OK
      (`cgroup_join_mark` 908 instructions); `exempt-check` 8 of 8: the
      control exempt (300 of 300), the spoof killed (23 of 300) and signed,
      the orphan killed. The executor's own move after its
      `CLONE_INTO_CGROUP` start marked nothing. `kernel_fixes`: `ok`, all
      four in 6.12.113. `test-ignored` 90 suites, 108 passed, 0 failed (the
      threaded worker refused its sandbox, exit 78, here and on 22.04).
      Tamper-check against `main` (ebc4916a) on the same guest, 119 rows
      each: 114 OK on both, the same outcome and verdict on 113 and on the
      other six but for pids, job ids and an entry count. Both have C27
      (not run, no lockdown) and C57c as the known gaps, and C64 as the
      recorded deviation. Both also have C97 (#492's host drop-ins case),
      DEVIATION with the same text on `main` and on the lot: the 4K
      drop-in signed harmful, the other two drop-ins' alerts 0 — a finding
      for #492's case on Debian 13, not this lot's.
  - Gates on the lot merged with `main` ebc4916a (f8d83e4e, before the
    commits were squashed: the same tree but the docs): eBPF build, the four clippy runs,
    fmt, `cargo test --workspace` 85 suites, 3,662 passed, 0 failed (17
    ignored), privileged tests built, attack-coverage, golden ×5 (54 files,
    same bytes), MSRV 1.89, fuzz replay (14 targets), portable-core (5
    targets), lockfiles unchanged.
  - Mutations, by hand on the new code: 69 distinct, 67 caught, 2 argued
    equivalent. The equivalent ones are the merge of one hash's kinds (a
    cgroup path starts with `/`, a unit name has none, so one hash never
    carries both) and the order of `warn` and `unknown` (a missing fix
    needs an upstream kernel, an unknown one a distribution's: never both
    on one kernel). Three survivors of the first set were caught once they
    had tests: the banner's own Debian version, a frozen number without a
    banner, and threads past one `getdents64` batch. Five mutations were on
    the first walk, since replaced; seven were on its successor. The eBPF
    programs' code is read by `xtask/tests/cgroup_join.rs`, and its twelve
    mutations were caught there.
  - Levels: unchanged. C23 stays 2 (provisional): the lot closes a way
    around the policy, not a new capability. C15 stays 1: the exemptions
    are the same kinds, bound to a start.
  - Open: a root that rewrites the exempt unit (a drop-in, a transient
    unit of that name, systemd's D-Bus attach) gets systemd's placement,
    and the unit exemption trusts it; `exe … sha256` binds a program. Also
    open: a move while no agent runs; a `CLONE_INTO_CGROUP` start is marked
    but not signed; a full map refuses every such exemption until the host
    reboots (changed by the review of #494, below); on systemd 255 — which
    does not use `CLONE_INTO_CGROUP` at all: that came in 256, and this
    note first said otherwise (the review of #494, D4) — the executor's own
    move could beat PID 1's and mark it (a false refusal, not measured
    here); `kernel_fixes` is `unknown` on a distribution's kernel below a
    fix, because the version cannot say.
  - The reviews of #494 (three, before the merge), what changed:
    - The first: B1, a move was a no-op when the *writer's* cgroup did not
      change, so a second thread writing its leader into `cgroup.threads`
      moved it unmarked — now only the writing thread moving itself to
      where it is; D1, a full 256-byte path read is a cut path; D2, a mark
      the kernel cannot keep makes that tree not known, never every
      exemption on the host until a reboot, the marks sized from
      `pid_max`/`threads-max` and allocated as they fill; D3, CVE-2022-30594
      on 5.4.189 and 4.19.238; D4, systemd 255 has no `CLONE_INTO_CGROUP`
      (256 does); D5, a privileged behaviour test of the tracker; D6, its
      links pinned; D7, the kexec text; a `unit` exemption of the agent's
      containment scopes refused. N5 found on the way: a move of a group
      already exiting left a mark for the pid's next owner — a new thread
      group's tgid is now cleared at its fork.
    - The second: R1, the "not known" bit was set with a test and an atomic
      add that a fork and a move on two CPUs could add twice (the child
      exempt, the carry into the next tgid) — a byte a tgid now, plain
      stores; R2, an upgrade's purge of the pin root dropped the marks —
      the tracker's maps and links now in a directory of their own beside
      it, kept by `install.sh --upgrade`, removed by `uninstall.sh`.
    - The third: R2-a, the directory named by the marks' size made a
      `sysctl` before a restart a reset, and a reset gave the marked their
      exemption back — the directory is named by schema and generation,
      the size a capacity, and a reset fails closed: every process started
      before it, with what it forks, is not known (`CGROUP_JOIN_EPOCH`);
      R2-b, an existing directory was adopted unchecked — a start adopts
      only the directory its predecessor of this boot registered in
      `/run/northnarrow/cgroup-join-pins` (protected), each map checked with
      `BPF_OBJ_GET_INFO_BY_FD`; the pins gone between two agents are a
      signed "marks lost between agents".
    - Found in the lab on the way: `before_epoch`'s `match` on an unread
      start became a compare of an unset register, which the 5.15 and 6.8
      verifiers refused (`R1 !read_ok`, the tracker absent); a dot in the
      directory's name, which bpffs refuses (`bpf_lookup`: EPERM, the
      tracker absent) — now `v1_<n>`; a debug build's capacity remake that
      set an epoch, which made the e2e harness's own children not known.
  - The lab of the reviews, as measured on the final code (a8d5dc1d;
    ubuntu2404 6.8.0-147 with systemd 255, ubuntu2204 5.15.0-202 with
    systemd 249; overlays checked at the start, `enable --now`, the agent
    uninstalled at the end):
    - `verifier-check`: 90 of 90 on 6.8, 88 and 2 not counted on 5.15; the
      tracker's five on both (`cgroup_join_mark` 973 instructions,
      `cgroup_join_fork` 546, `cgroup_join_born` 386, `cgroup_join_exit`
      149, `cgroup_join_src` 47). The marks 63,222 (24.04) and 63,170
      (22.04) entries, `BPF_F_NO_PREALLOC`; the "not known" map 65,536 × 64
      bytes.
    - `exempt-check` 14 of 14 on each: the control exempt, the spoof, its
      orphan and the threaded spoof killed and signed, a move into a
      cgroup no exemption names marked and not signed; 200 starts of the
      exempt unit by systemd under busy CPUs and 200 more with PID 1 and
      the busy loops on one CPU (`taskset -pc 0 1`): 0 marked, on systemd
      255 and on 249.
    - `tracker-persist-check` 24 of 24 on each: the marks kept through an
      agent stop (a move with no agent running marked), a restart and
      `install.sh --upgrade` (the same directory, no reset); the pins
      refuse an unlink and a new entry; `threads-max` doubled: no reset,
      the signed capacity note; an LRU map planted in place of the
      registered directory: not adopted, a new generation, the planted one
      removed, the reset signed (`CGROUP_JOINED: id … where … was
      registered`), the earlier marked process not known; the directory
      deleted between two agents: "marks lost between agents", not known.
      Then a cold boot: agent and watchdog active, the pin root populated,
      our LSM programs loaded, the tracker attached (24.04: 73 pins, 42 LSM
      programs, 66 own programs loaded; 22.04: 69, 40, 64), the same 30 s
      later.
    - The tracker's cost (`fork-cost`, `kernel.bpf_stats_enabled` for the
      per-call part): about 0.93 µs a fork and its exit on 24.04
      (`cgroup_post_fork` 469 ns, `sched_process_fork` 192 ns,
      `sched_process_exit` 272 ns a call, 100,024 calls each) and 0.6 µs on
      22.04 (269, 139, 187 ns); a fork + exit + wait took about 140 µs on
      the 24.04 guest and 55 µs on the 22.04 one, the same with the
      tracker's links detached within the rounds' spread.
    - `test-ignored` on 24.04: 91 suites, 118 passed, 0 failed — the
      tracker's nine privileged tests and the threaded worker's among
      them; on 22.04 the tracker's nine: 9 of 9.
    - `tamper-check` on 24.04, the tip against `main` 80c8da36 on the same
      guest: 116 cases each, 115 OK on both, C64 the recorded deviation on
      both, the verdict and the outcome of every case the same.
    - The tracker's eBPF mutations against its privileged test on 24.04,
      caught: N4' (`is_lost` always false), R1's store of 0 and next byte,
      M2b (no one marked), M3 (even tgids skipped), N5's clear at the fork
      removed, B1-old in full (both checks back to the rule before B1:
      `a_threaded_move_of_the_leader_is_marked`), the epoch's PID 1
      exclusion removed, its compare inverted, the epoch never applied
      (`a_reset_makes_what_started_before_it_not_known`). B1-old at one
      check only, either one, survives: each of the two checks closes B1
      alone (the review's N-c), as designed.
    - Host mutations on the reviews' code: 22 of 22 (the review's), 18 of
      18 (R1/R2) and 21 of 21 (the third review's) caught — two only after
      their tests were strengthened (the uninstall's tracker directories, a
      foreign file in the registered directory); the agent's own read of a
      "not known" byte and of a lookup error is held by the shape test (a
      real map's), its behaviour by the privileged tests.
  - Gates on the final tip (eBPF, the four clippy runs, fmt, the
    workspace's tests, the privileged tests built, attack-coverage, golden
    ×5, MSRV, fuzz replay, portable-core, lockfiles): as PR #494 records
    them for this commit.
- **Lot 278 — R009 kills in COMBAT only; the installer's window covers its
  own process tree; the lab's "R009 flake" fixed at its cause (C14, C17;
  the false positive of the review of #492, section f).**
  - What was open: R009 (a file in `/home`, `/tmp` or `/var/tmp` executed
    by root) killed the tree of every root exec outside an administrator's
    `sudo` at a terminal and a package transaction, in OBSERVING too:
    `install.sh --upgrade` and `uninstall.sh` run by automation without a
    terminal from a checkout or an unpacked tree. At a terminal it killed
    them now and then (the flake of R14, 273, 273b, 273c): `sudo`'s monitor
    (`use_pty`, a fork without exec) forked in the tick of sudo's exec shows
    a start before it in `/proc`, and the judged lineage walk (lab PR 269)
    lost the session.
  - What changed: a fork's parent read at the fork's earliest time, and at
    its tick only when that is "only later", the parent took one identity
    in the tick and it is an authentication binary's (sudo's monitor; the
    reviews of #493); the engine judges in the agent's
    posture (`decide_in`): R009's kill, and R001's and R003's of an exec by
    root, run in COMBAT only, the record kept, `enforce R009` restores them;
    the hold counts as a switch's for the legacy first match, so it never
    stands in for another rule's kill of the same exec (R011–R013, R017 kill
    a root exec from `/tmp` or a home in every posture: review of #493, A1);
    every other rule that can kill in OBSERVING listed with why
    (`posture_floor::OBSERVING_KILLS`, held to the catalogue: before Wave 4,
    or an opt-in); a grant asked for an installer (`--for-installer`, what
    `install.sh` and `uninstall.sh` pass) names the installer (the
    requester's parent, by pid and the exact start `/proc` shows) and R009
    records its tree at Low after the grant, by lineage; `install.sh`
    executes nothing from its tree before its window. No capability level
    moves.
  - Decision record (03/11/2026; the coordinator, with the authority the
    founder delegated, after the independent review of #493): R009's kill,
    and R001's and R003's of an exec by root from `/tmp` or `/var/tmp`, run
    in COMBAT only by default — for these three cases only, a change of the
    decision of 21/10/2026 ("a kill that existed before … is not held") and
    of external audit POS-015 ("R001..R003 still kill the exec, whatever the
    posture"). Why: their legitimate matches are frequent and the kill
    destructive (installers and upgrades from a checkout or `/tmp`, Packer,
    Terraform remote-exec, Vagrant, Ansible, self-extracting installers, CI
    runners in a home), and against a process already root the kill is worth
    little (it moves the file to `/root`, `/opt` or `/run`). The way back:
    `enforce R009` (`enforce R001`, `enforce R003`) in the signed per-rule
    policy, in every posture. What is left: a root dropper from `/tmp` or a
    home in OBSERVING, ALERTED or ENGAGED is a High record, not killed —
    killed at its first egress (NN-L-CHAIN-002/005/007, NN-L-NET-008) or in
    COMBAT, not after the fact when COMBAT comes later unless it is the
    ladder's offender. `docs/operator/RULE_POLICY.md` §1.
  - Lab (as measured; Ubuntu 24.04, 6.8 / systemd 255, our own guest, one
    guest, every case right after an agent restart): before, `main`
    dc83881b: 812 records, 31 kills, all R009 in OBSERVING (the `/tmp` ones
    in ENGAGED) — 24 of 60 administrator `sudo ~/prog` at a pty (the flake;
    36 Low), one `install.sh` (`upgrade-check` 2 of 3), 6 root execs with no
    terminal; `uninstall-check` 3 of 3; tamper-check 104 cases, 100 OK, C27,
    C57c, C64, C78c as recorded. After, the lot as of 9d65882d (before
    `tree_version`'s `exec` and the review of #493) by `upgrade-check` from
    `main`: 3,251
    records, 0 kills; `upgrade-check` 11 of 11 and `uninstall-check` 10 of
    10; the pty probe 60 of 60 Low; automation with no terminal (the
    refusal, `--upgrade`, `uninstall.sh`, a reinstall) from the home ×2 and
    from `/tmp` ×2: 4 of 4 OK, the scripts' own execs High and not killed
    (from `/tmp` judged in ENGAGED), the tree's agent Low by the window;
    root execs with no terminal (`systemd-run`) from the home and `/tmp`:
    High, not killed; tamper-check: the 104 rows with `main`'s outcomes on
    the same guest. The head with the fixes of the review of #493 was not
    run on a guest when this note was written.
  - Open: R009 kills the installer's own exec in COMBAT (open the window
    from the root shell that runs it, `--for-installer`,
    `INSTALL_UPGRADE_UNINSTALL.md` §2.1); an install from `/tmp` still
    raises ENGAGED for 24 hours (the script's `StagingExec`) and leaves
    R001's Medium record of the tree's agent, its kill held; inside an
    administrator's session, a package transaction or an installer's window
    R009's Low record holds R010–R017's kills of the same exec by the legacy
    ceiling, in COMBAT too (as for the session before the lot); one
    installer per window; on the priority bus an exec is judged in the
    posture it found, which an earlier event bringing COMBAT may not have
    reached yet; the privileged test of a root dropper asserts the held
    record and was not run on a guest in this lot; EPG and EXECQ kill in
    OBSERVING only on their opt-ins.
- **Lot codeql — CodeQL code scanning on every pull request, every push to
  `main` and weekly (C27; CI only, no product change; no level changes).**
  - What was open: no static analysis of the code ran on the repository.
    Code scanning had never been set up (the API's default setup
    `not-configured`, no analysis), so neither a pull request nor `main`
    was checked for the dataflow and API-misuse classes CodeQL finds, in
    the agent's Rust, the lab's C and Python, or the workflows themselves.
  - What changed: `.github/workflows/codeql.yml`, an advanced setup (the
    default setup stays off). The four languages GitHub detects in the tree
    (`actions`, `c-cpp`, `python`, `rust`), each with `build-mode: none`,
    with the `security-extended` suite. It runs on `pull_request` to `main`
    (no path filter), on `push` to `main` and weekly. The token is
    `contents: read`; the `analyze` job alone adds `security-events:
    write`. `github/codeql-action` is pinned at v4.39.2 (`1fc58d04…`, the
    commit of the annotated tag, head of `releases/v4`) and checkout at
    ci.yml's SHA. The Rust job installs the toolchains the tree pins and
    fetches the three cargo projects `--locked`, and fails if the
    extraction changed a lockfile. `SECURITY.md` §Code scanning: an alert
    is fixed or triaged in a pull request, never dismissed to make a run
    pass. Private vulnerability reporting is enabled (checked 04/11).
  - Evidence: `xtask/tests/supply_chain.rs`. The new
    `codeql_scans_every_language_of_the_tree` derives the languages from
    the tracked files and compares them with the matrix (a new language in
    the tree, or one dropped from the scan, fails). It also checks the
    triggers, the weekly cron, the suite, the inputs of init and analyze,
    one pin for both, the permissions, the toolchain installs, the locked
    fetches and the lockfile check of each tracked `rust-toolchain.toml`
    and `Cargo.lock`, and that the step that frees disk space (it deletes
    the CodeQL bundle) and any secret stay out. `the_codeql_language_of_a_file`
    covers the extension map. The permission test allows one write:
    `security-events` to `analyze`. 39 mutations of the workflow, each
    failing a named test (after one survivor, agent-ebpf's toolchain
    install dropped, got its assertion).
  - Lab: no guest (CI only); GitHub-hosted runners, as measured on PR
    #496. The PR run at 8b4f29f6 (run 41790833220) was green on all four
    languages: actions 40 s, c-cpp 60 s (13 source files), python 46 s
    (5 files), rust 9 min 18 s. The Rust job's toolchains and fetches took
    22 s; the extraction took 2 min 37 s, read 544 files and found the
    three cargo manifests. No disk-freeing step was needed. It reported 0
    alerts, but the run is diff-informed (codeql-action's default on a pull
    request: 14 diff ranges in 7 files), so it covered the lines the PR
    changes only. One full analysis of the tree followed: commit 2fd2db6f
    set `CODEQL_ACTION_DIFF_INFORMED_QUERIES=false` and the next commit
    reverted it (run 41792146816, rust 8 min 35 s). It reported 161
    alerts, none of them real:
    - rust 159. 152 are in test code, not applicable: 64
      `hard-coded-cryptographic-value` (fixed keys and nonces of
      deterministic tests) and 88 `cleartext-logging` (assertion and
      panic messages that print a uid, a verdict's reasoning or a run's
      output).
    - Of the 7 in production code, 6 are false positives: three 32-byte
      nonces zeroed and then filled at once by `OsRng.fill_bytes`, which
      is getrandom and panics on failure (`admin_cli.rs:3221`,
      `admin_auth.rs:928`, `quarantine.rs:633`); the vault's versioned
      HKDF salts over a random master key (`vault.rs:42`, `:44`); and a
      `getifaddrs` list walked only after its null check
      (`canary/network.rs:90`). The seventh, the fuzz fixture's seed nonce
      (`fuzz_api.rs:139`), is not applicable.
    - c-cpp 2, not applicable: `cpp/toctou-race-condition` in the lab's
      EXP-13 load generator, which is built in the guest and not shipped
      (`deploy/lab/bus/nn-exp13.c:135`, `:360`).
    - python 0, actions 0.
    No alert was dismissed. Each is listed with its triage in the PR.
  - After the review of #496:
    - What was wrong: the analyze step held `security-events: write`
      while rust-analyzer ran the build scripts and proc-macros of the
      locked dependency tree, so one of them could upload a SARIF or close
      alerts through the API. The scan also covered directories that no
      shipped build contains.
    - What changed:
      - `analyze` holds `contents: read` only. It runs init and analyze
        with `upload: never` and keeps the SARIF as an artifact, as its
        last step, so only an analysis whose every step passed is kept.
      - `upload` needs `analyze`, runs unless the run was cancelled, and
        holds `contents: read` and `security-events: write`. Its steps are
        a checkout (the alerts' locations are fingerprinted against the
        files; nothing is built or run), download-artifact and
        upload-sarif at init's commit, with the same category.
      - `.github/codeql/codeql-config.yml` ignores the members'
        integration tests (`agent`, `cli`, `scan`, `watchdog` and `xtask`
        `/tests`), `fuzz` and `deploy/lab`. That leaves no C/C++ or
        Python in the scan, so the matrix is `actions` and `rust`.
      - A pull request's analysis is complete
        (`CODEQL_ACTION_DIFF_INFORMED_QUERIES=false`). codeql-action
        filters a diff-informed SARIF to the pull request's lines when it
        uploads it, and only in the job that computed the diff. The first
        run of the split (41797976722) therefore uploaded 68
        `hard-coded-cryptographic-value` results outside the diff, while
        the queries the diff restricts reported none. The complete
        analysis took no longer: rust 8 min 35 s against 9 min 18 s.
      - The dependencies' build scripts can still alter the SARIF in
        `analyze` before it is kept: what they lose is the write to the
        API, which reaches other analyses and the alerts' state.
    - Evidence:
      - `every_workflow_token_is_read_only_unless_it_publishes` allows
        that write to codeql.yml's `upload` alone. A job holding it may
        have no `run:` step and no action other than checkout,
        download-artifact and upload-sarif.
      - `codeql_scans_every_language_of_the_tree` checks the two jobs and
        their permissions, the artifact's name, path and place, upload's
        steps and inputs, and the config. Its paths-ignore must equal the
        integration-test directories of the members that have them, plus
        `fuzz` and `deploy/lab`. The languages must equal those of the
        tracked files outside those directories.
      - 72 mutations of the workflow and the config: 39 carried over, 19
        of the split, 11 of the config and 3 of the env. Each one fails a
        named test.
    - Lab, as measured on PR #496 (GitHub-hosted runners, no guest):
      - Run 41800849727 at 7d76f6c9 was green in all four jobs: analyze
        actions 49 s and rust 5 min 47 s (466 Rust files extracted, 544
        before the config); upload 14 s and 17 s.
      - The analysis key is now `codeql.yml:upload`. The rust analysis
        has 132 results, exactly the 132 of the full analysis outside the
        ignored directories, rule and file:line for each. The actions
        analysis has 0. The PR's CodeQL check reads "No new alerts in code
        changed by this pull request".
      - `analyze` logs that codeql-action cannot reach its feature-flag
        endpoints without `security-events: read`: no experimental
        features, and the CLI its release ships (2.27.4, as before). That
        read is not granted to the job that runs dependency code.
  - Open: the first push run after the merge opens 132 alerts on `main`.
    126 are in test code or the fuzz fixture (64 of them `critical` by
    CodeQL's rating, fixed test keys and nonces), and 6 are the false
    positives above. Their list with each reason ("used in tests", "false
    positive") is for the founder, who decides each closure in the UI. No
    run is made green by dismissing.
  - Level unchanged (C27 1).
- **Lot 279 — R011 judges a module tool's command line, and what the exec
  pump reads at the exec; the NET-006 listener test waits for both of its
  records (C14, C11; lot 275's lab, the CI of #493, the review of #498).**
  - What was open: R011 killed every exec of `insmod`, `modprobe` or `kmod`
    that no package-manager actor ran and no kernel thread asked for, in
    every posture (a kill from before Wave 4): the `modprobe` rootful
    podman runs for its netfilter modules (lot 275's lab, Ubuntu 22.04: W5
    rc 137, rootless rc 0), an administrator's `sudo modprobe dummy`, and
    by the same rule the container runtimes', iptables' and kube-proxy's.
    The privileged NET-006 listener test raced its own second record (the
    CI of #493 on Ubuntu 22.04).
  - What changed: R011 judges the exec on its command line's SYNTAX
    (`crates/nn-core/src/decision/rules/kmod_invocation.rs`: the multi-call
    binary's mode from `argv[0]`, getopt's options and long abbreviations)
    and on what the exec pump read at the exec
    (`crates/nn-linux/src/sensors/kmod_exec.rs`, kept per exec in
    `kmod_exec_facts.rs`: the executed file's device and inode against the
    system's tools', `/proc/<pid>/environ` tied to the exec by a pidfd and
    the start time). Killed: `insmod`; a `modprobe` argument with a `/` or a
    `.ko*` suffix; `-C`, `-d`, `-S`, `--force*`, `-o`, `--remove-holders`,
    `--remove-dependencies` and their abbreviations; any argument starting
    with `-` after the first name; an option the tool refuses; a `kmod`
    command but `help`/`list`/`static-nodes`/the version; a program not the
    system's tool, of another mount namespace; `MODPROBE_OPTIONS` or an
    environment not read; an argv not read whole. Recorded (High,
    T1547.006) otherwise. `OBSERVING_KILLS` unchanged: R011's kill narrowed,
    no kill added. The NET-006 test waits for as many records as listeners
    it opened, then asserts exactly that many. No capability level moves.
  - Decisions (04/11/2026, the coordinator, after the independent review of
    #498): the first design — kmod's lookup emulated (configuration aliases,
    `modules.dep`, `.symbols`, `.alias`, built-ins, soft dependencies, each
    file's owner, `max(mtime, ctime)` and signature) — is RETIRED: the
    review found `--remove-holders`/`--remove-dependencies` read as a
    removal (kmod 29..34 insert), `modprobe.d`'s `install`/`remove` commands
    not modelled (a "vouched" or "nothing to load" name running a command
    as root), an option after the name that `POSIXLY_CORRECT` or
    `MODPROBE_OPTIONS='--'` turns into a parameter, the exec pump blockable
    by a FIFO in `/run/modprobe.d`, limits that fell back on the record, an
    owner's time that root dates forward, a DKMS provenance a `mkdir` fakes.
    R011 now reads no `modprobe.d`, index or module file. R018 OBSERVES: it
    records each load the kernel reports and kills the loader of a file
    outside the module directories or of an unowned module by a loader it
    does not expect — after the load (its hook denies nothing; `kmod` is in
    its loader allowlist); it is not a backstop that prevents. Prevention is
    module signing and lockdown (the host check) and lot 285 (the kernel's
    deny of an untrusted file). What R011 never saw, as on `main`: a root
    process that loads a module without any tool (its own
    `finit_module(2)`), and the commands of root's `modprobe.d`.
  - Lab of the EARLIER design (retired: the decisions above; as measured;
    our own guests, lease `k279`; Ubuntu 22.04 5.15.0-202 and 24.04
    6.8.0-147; on each, `main` 80c8da36 then the lot on the same
    guest after a power cycle; `deploy/lab/malsim/kmod-check.sh` with
    podman, docker.io, k3s with kube-proxy in ipvs mode, zfsutils-linux and
    wireguard-tools installed for the run and removed after; no
    `/etc/northnarrow/*.local` before or after). R011's kills over the
    benign corpus: 22.04 `main` 43 (k3s 38 — 28 run by k3s-server, 10 by
    systemd —, podman rootless, containerd's `ExecStartPre=-/sbin/modprobe
    overlay` at docker.io's start, zfs-load-module, `sudo modprobe dummy`,
    `modprobe -n`), the lot (f6650f8b) 0: iptables-legacy's `ip_tables`,
    podman rootless's and containerd's `overlay`, k3s's eight (`br_netfilter`,
    `ip_vs`, `iptable_filter`, `iptable_nat`, `nfnetlink-subsys-11` →
    `nft_compat`, `nft-chain-2-nat` → `nft_chain_nat`, `overlay`…),
    zfs-load-module's `zfs`, `modprobe dummy`/`-r dummy` and the queries
    recorded, each with its module, file and owner; 24.04 `main` 15, the lot
    (19050626) 1 — k3s-server's `modprobe nft-expr-counter`, a name no index
    of 6.8.0-147's tree resolves (the counter is part of `nf_tables` there):
    killed, the brief's fail-closed for an unresolved name. The malicious
    shapes (insmod of a `/tmp` `.ko`, modprobe of a path, of a name nothing
    resolves, `-d`, `-C`, a copy of modprobe in `/tmp`): killed, 6 of 6, on
    `main` and the lot, both guests. Tamper-check, 119 rows: (case, verdict)
    of the lot = `main`'s on each guest (22.04: 114 OK, C64 DEVIATION, C27
    C57c KNOWN GAP, C78c C101 N/A; 24.04: 115 OK, the same but C101 run).
    Test-ignored of the lot on each guest: 109 passed, 1 failed —
    `r011_records_a_packaged_modprobe_and_kills_an_insmod_from_tmp`, whose
    verdict was the expected Log but which asserted the response "none" (a
    detect-only agent renders a Log "suppressed (detect-only)"; the test
    fixed); `r011_kills_a_module_copied_into_the_tree_and_r018_catches_what_argv_hides`
    (copied + `depmod` → R011 kill and R018 KillProcessTree;
    `MODPROBE_OPTIONS="-d /tmp/…"` → R011 record, R018 Critical kill),
    `process_kernel_module_tooling_trips_r011` and the NET-006 listener test
    passed on both. The final tree (b79f16a8: the test fixed, built-ins'
    aliases read, origin/main 0131394c merged), on both guests again:
    test-ignored 89 suites, 110 passed, 0 failed on each, the four tests
    above ok, none skipped; 24.04's kmod-check: R011's benign kills 1, the
    same k3s-server `modprobe nft-expr-counter` — on 6.8.0-147 `nf_tables`
    is a module (in `modules.dep`, not in `modules.builtin`), no index holds
    the alias (`modules.alias` 0, `modules.builtin.modinfo` 0) and kmod
    itself answers "Module nft-expr-counter not found" (`modprobe -n -v`):
    an unresolved name, killed (then fail-closed); the built-ins' aliases
    changed nothing there. The malicious shapes 6 of 6 killed; every other
    benign module tool exec recorded. After the coordinator's decision of
    04/11 (a plain name of no module: recorded, "nothing to load"),
    4977f3ed on 24.04, a short round (k3s, the plain miss, the malicious
    shapes): k3s's 9 module tool execs recorded, 0 killed; `modprobe
    nn_k279_no_such_module` recorded, "nothing to load: the name resolves to
    no module of this kernel" (modprobe's own exit 1, "not found"); the
    malicious shapes 6 of 6 killed, among them `modprobe -S 9.9.9` of that
    same missing name.
  - Measured beside R011, for the Tappa Prove (the kills on a benign corpus;
    not this lot's to change). Every run, on both guests, `main` and the lot
    alike, went to a locked COMBAT and judged most of the corpus there. The
    escalations: the posture's mass-write count on the container runtimes'
    own storage (podman's `/run/libpod/alive.lck` and layer locks: ENGAGED;
    rootless podman's first image pull, 259 writes to
    `~/.local/share/containers/storage/libpod/bolt_state.db`: COMBAT),
    corroborated by NN-L-EVA-002's false positive on the runtime's
    `iptables -F` of its own chain (found, and corrected, by lot 282); on
    22.04 `main` also an anti-tamper denial (`deb-systemd-helper`'s `rmdir`
    at podman's purge). Then NEUTRALIZE killed, with intent and outcome
    signed in the actions chain and the stage transitions in the audit
    chain: rootless podman's tree (rc 137; no OOM, no systemd-oomd kill, not
    the script's timeout, the container itself exited 0 — 22.04 the lot 1
    of 1, `main` 1 of 1, the lot's agent again 1 of 3 rounds, the one with
    the first image pull, the two with the image cached rc 0 with the
    posture ENGAGED only; without an agent 3 of 3 rc 0); on 24.04 the
    daemon's tree at docker.io's start (13 trees killed or already gone, in
    `main`'s run and the lot's: `docker run` rc 125, the daemon's API
    closed: EOF). In those COMBAT windows NN-L-FIM-009 killed the k3s
    installer's `touch`, `chmod` and `tee` writing
    `/etc/systemd/system/k3s.service.env` and `/etc/systemd/system/k3s.service`
    (each "already gone"; 22.04 `main` 5, the lot 3; 24.04 `main` 3, the lot
    4) and R013 k3s's bundled `runc`
    (`/var/lib/rancher/k3s/data/<hash>/bin/runc`; 22.04 `main` 4, the lot 21;
    24.04 `main` 11, the lot 21). The guests left as found: k3s's
    `/var/lib/rancher` removed on both; on 24.04 podman and
    `/var/lib/containers` were there before these runs and stay.
  - Lab of this design: pending (round i, lease `k279`, both guests).
  - Open: a module tool exec whose process exits before the exec pump reads
    its environment is killed (a kill that reaches no one; how often is the
    lab's to say); `modprobe -S` outside a package transaction (an initramfs
    build by hand) and a quiet probe written `modprobe <name> -q` are killed,
    as on `main`; the load itself is prevented only by the kernel's
    signature policy and lot 285.
