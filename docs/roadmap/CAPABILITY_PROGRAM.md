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
  - Lab: the verification is the VM job's first run on this pull request
    (`lab-vm.yml`, Ubuntu 24.04 and 22.04 guests); its link is added here
    once the run exists.
  - Lab: @LAB218@
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
    All 79 rules (lab PR 219's two included) are mapped: 58 techniques and sub-techniques under 12
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
