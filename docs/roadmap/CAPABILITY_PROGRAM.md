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
