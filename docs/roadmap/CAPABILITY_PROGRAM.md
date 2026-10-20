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

| ID | Capability | Level (2026-10-20) | Target |
|---|---|---|---|
| C01 | Linux sensor | 2 | 3 |
| C02 | Windows sensor | 0 | 3 (user-mode first; a kernel driver needs WHCP signing) |
| C03 | macOS sensor | 0 | 3 (needs Apple's Endpoint Security entitlement) |
| C04 | ARM64 support | 0 | 3 |
| C05 | Process telemetry | 1 | 3 |
| C06 | File telemetry and FIM | 2 | 3 |
| C07 | Endpoint network telemetry | 1 | 3 |
| C08 | Identity and ITDR | 0 | 3 |
| C09 | Cloud telemetry and posture | 0 | 3 |
| C10 | Network detection (NDR) | 0 | 3 |
| C11 | Containers and Kubernetes | 1 | 3 |
| C12 | Synchronous inline blocking | 1 | 3 |
| C13 | Malware prevention | 0 | 3 |
| C14 | Behavioural detection and correlation | 2 | 3 |
| C15 | Custom rules, declarative format | 1 | 3 |
| C16 | Structured ATT&CK mapping | 1 | 3 |
| C17 | Response on processes and files | 2 | 3 |
| C18 | Host network isolation | 1 | 3 |
| C19 | Rollback and remediation | 1 | 3 |
| C20 | Automation, playbooks, SOAR | 1 | 3 |
| C21 | SIEM integration and export | 0 | 3 |
| C22 | Backend and multi-host correlation | 0 | 3 |
| C23 | Anti-tamper and self-defence | 2 | 3 |
| C24 | Offline and air-gapped operation | 2 | 3 |
| C25 | Data sovereignty | 2 | 3 |
| C26 | Open code, licence, inspectability | 2 | 3 |
| C27 | Product supply-chain security | 1 | 3 |
| C28 | Safe content release | 1 | 3 |
| C29 | Independent public validation | 0 | 3 (needs third parties) |
| C30 | Generative AI and data governance | 2 | 3 |

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
