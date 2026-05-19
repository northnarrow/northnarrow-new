# ISSUE_001 — Tappa 7 Task 7 ENI integration test self-kills via R009

**Status:** OPEN — blocks live verify of Task 7 (Emergency Network Isolation)
**Discovered:** 2026-05-19, Ubuntu Server VM kernel 6.8.0-117-generic
**HEAD at discovery:** `1bb1f1f` (post Tappa 6.9.7.1 P5.1)
**Severity:** test-infrastructure (production code is correct)
**Owner action:** deferred — remediation tracked here, no fix applied in
this commit. Task 7 is marked PARTIAL (code-complete, test-blocked).

---

## 1. Reproducer

```
cargo test --release \
  --features test-privileged,debug-trigger \
  --test privileged_e2e \
  -- e2e_force_combat_then_unlock_via_cli
```

(Requires root or `CAP_NET_ADMIN`, `iptables` binaries on PATH, BPF-LSM
enabled per `docs/TAPPA7_PREREQ.md`.)

### Observed failure

```
thread 'e2e_force_combat_then_unlock_via_cli' panicked at
agent/tests/privileged_e2e.rs:177:
  debug force-posture failed: stderr=""
```

`stderr` is empty. The `nn-admin debug force-posture combat` invocation
exits with non-zero status before clap can emit any usage/error output.

---

## 2. Root cause

### Mechanism

1. `spawn_agent` (privileged_e2e.rs:71–94) launches
   `northnarrow-agent` from the value of `CARGO_BIN_EXE_northnarrow-agent`,
   which cargo expands to
   `<repo-root>/target/release/northnarrow-agent`. In any developer
   environment, `<repo-root>` lives under `/home/<user>/...`.

2. Agent boots, loads the production decision-rule set (R001..R010).
   No flag exists today to exclude individual rules at runtime.
   `spawn_agent` passes only `--combat-rules`, `--admin-pub`,
   `--admin-socket`, `--no-ade`.

3. Test runs `nn-admin debug force-posture combat …`. `nn-admin`
   is spawned from `CARGO_BIN_EXE_nn-admin`, which also resolves
   under `/home/<user>/.../target/release/nn-admin`.

4. The ProcessSpawn event for `nn-admin` reaches the decision pipeline.
   `R009_RootExecFromUserPath`
   (`agent/src/decision/rules/r009_root_exec_from_user_path.rs:8–44`)
   matches:
   - `uid == 0` (test must run as root for iptables),
   - `filename` starts with `/home/`
     (one of `USER_WRITABLE_PREFIXES = ["/home/", "/tmp/", "/var/tmp/"]`).
   - Verdict: `ResponseAction::KillProcess`, severity High.

5. The kill action lands on `nn-admin` ~47μs after spawn (observed via
   strace ordering: SIGKILL arrives before the admin-socket `connect()`
   returns). `nn-admin` dies before transmitting the force-posture
   command frame to the agent. The empty `stderr` in the assertion
   is the signature of this race — clap never reaches the point of
   emitting parser feedback.

### Why R009 is not at fault

R009 is correct production code: a root binary executing from
`/home/...` is a textbook privilege-escalation indicator (e.g. a
non-privileged attacker drops a payload in their home dir, then
escalates via SUID/sudo misconfig and re-execs). The rule has no
allowlist, no test-mode exemption, and no parent-PID heritage check
by design. Adding any of these to satisfy a test would weaken the
production detection.

### Why the test is not (just) at fault

The test follows the standard cargo idiom of resolving binaries via
`CARGO_BIN_EXE_*`. Changing the test to copy binaries elsewhere
before spawning is a viable remediation (option A below) but is also
a non-trivial deviation from the convention.

---

## 3. Evidence summary

| Item | Location |
|---|---|
| Production rule | `agent/src/decision/rules/r009_root_exec_from_user_path.rs:8` (`USER_WRITABLE_PREFIXES`) |
| Test spawn site | `agent/tests/privileged_e2e.rs:71–94` (`spawn_agent`) |
| Failing assertion | `agent/tests/privileged_e2e.rs:177` |
| Agent flag surface | `agent/tests/privileged_e2e.rs:77–86` — only `--combat-rules`, `--admin-pub`, `--admin-socket`, `--no-ade` |
| Action enum | `ResponseAction::KillProcess` (`common`) consumed by responder |
| Env-var origin | cargo built-in `CARGO_BIN_EXE_<name>` → `target/<profile>/<name>` |

---

## 4. Remediation options considered

Three approaches were sketched. None is applied in this commit — owner
decision is deferred to a separate workstream.

### Option A — test fixture copies binaries to a system path

Before `spawn_agent`, copy `northnarrow-agent` and `nn-admin` into
`/usr/local/bin/` (or another non-user-writable prefix) and exec
from there. R009 stops matching because `/usr/local/bin/` is not in
`USER_WRITABLE_PREFIXES`.

- **Pros:** no production-code change; surface confined to the test
  module; mirrors how the install would deploy binaries.
- **Cons:** requires root write to `/usr/local/bin/` at test time
  (already required for iptables, so cost is incremental); needs a
  Drop/cleanup path so failed runs don't leak binaries; adds I/O
  cost per test invocation.
- **Effort estimate:** ~1 hour (helper fn + Drop guard + runbook
  doc update).

### Option B — agent `--decision-rules-allowlist` / `--decision-rules-deny` flag

Introduce a CLI flag on `northnarrow-agent` that takes a comma-
separated list of rule IDs to include or exclude, gated behind a
test-only feature flag so production builds cannot ship with rules
disabled.

- **Pros:** general-purpose; useful beyond this test (e.g. isolating
  one rule for benchmarking or for narrow regression tests).
- **Cons:** adds a footgun surface even behind a feature flag —
  rule disablement is exactly the kind of switch we expect future
  red-team work to attack. Requires careful auditing of how the flag
  parses and where in the pipeline rules are filtered.
- **Effort estimate:** ~3–4 hours (CLI plumbing + decision-pipeline
  filter point + tests + docs); but design review is the real cost,
  not LOC.

### Option C — R009 parent-PID / signature exemption

Modify R009 to allow root execs whose parent process is itself a
PROTECTED_PID (i.e. the agent's own helpers) and/or whose binary
is signed with the customer admin Ed25519 key. The test would then
have `nn-admin` exempt because its parent (the cargo test harness)
is not what matters — but the agent could verify a signature on
`nn-admin` at exec time.

- **Pros:** strengthens R009 for the long term (signed admin tooling
  becomes a first-class concept); aligns with Tappa 8 Ed25519
  challenge-response.
- **Cons:** parent-PID alone is too weak (cargo test harness PID is
  not protected). Signature check requires binary-signing
  infrastructure that does not yet exist; this is arguably a
  Tappa 8/Tappa 9 scope item, not a test-fix.
- **Effort estimate:** ~1 week (sign tooling, key chain, verifier,
  rule rewrite, audit).

### Recommendation (non-binding)

Option A is the cheapest and least architecturally invasive. Option B
is the most flexible but introduces a footgun. Option C is the most
correct long-term but is wildly out of scope for a test fix and
belongs in the Tappa 8/9 admin-trust roadmap.

---

## 5. Invariants preserved by deferring

- No change to `agent/src/decision/rules/r009_*.rs`
- No change to `agent/tests/privileged_e2e.rs`
- No change to `NetworkIsolator`, `configs/combat-rules.v4`, or any
  production code path for Task 7 ENI.
- Tappa 7 Task 7 status is downgraded from "TODO / pending verify"
  to **PARTIAL** (code-complete, test-blocked) in
  `docs/CLAUDE_BRIEFING.md` and `docs/TAPPA7_PREREQ.md`.

---

## 6. Cross-references

- `docs/CLAUDE_BRIEFING.md` § "FASE 3: Anti-Tamper" Task 7 line
- `docs/TAPPA7_PREREQ.md` § "Remaining Tappa 7 work" / known issues
- `docs/integration-test-runbook.md` — manual run path for
  `privileged_e2e`
- Tappa 8 (Ed25519 admin override) — natural home for Option C
