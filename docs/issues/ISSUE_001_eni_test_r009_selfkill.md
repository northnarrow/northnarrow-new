# ISSUE_001 — Tappa 7 Task 7 ENI integration test self-kills via R009

**Status:** ✅ **RESOLVED 2026-05-19** — Option A (test fixture
relocates binaries to `/usr/local/bin/`) implemented and verified
live; Tappa 7 Task 7 ENI status promoted **PARTIAL → SHIPPED**.

**Discovered:** 2026-05-19, Ubuntu Server VM (`northnarrowdev`),
kernel `6.8.0-117-generic`.
**HEAD at discovery:** `1bb1f1f` (post Tappa 6.9.7.1 P5.1).
**HEAD at resolution:** `1bb1f1f` + feature branch
`tappa7-task7-r009-fix-eni-shipped`.
**Severity at discovery:** test-infrastructure (production code was
always correct).

---

## 1. Reproducer (pre-resolution)

```
cargo test --release \
  --features test-privileged,debug-trigger \
  --test privileged_e2e \
  -- e2e_force_combat_then_unlock_via_cli
```

(Requires root or `CAP_NET_ADMIN`, `iptables` binaries on PATH,
BPF-LSM enabled per `docs/TAPPA7_PREREQ.md`.)

### Observed failure (pre-resolution)

```
thread 'e2e_force_combat_then_unlock_via_cli' panicked at
agent/tests/privileged_e2e.rs:177:
  debug force-posture failed: stderr=""
```

`stderr` was empty. The `nn-admin debug force-posture combat`
invocation exited with non-zero status before clap could emit any
usage/error output.

---

## 2. Root cause

### Mechanism

1. `spawn_agent` (pre-fix `privileged_e2e.rs:71-94`) launched
   `northnarrow-agent` from the value of
   `CARGO_BIN_EXE_northnarrow-agent`, which cargo expands to
   `<repo-root>/target/release/northnarrow-agent`. In any
   developer environment, `<repo-root>` lives under
   `/home/<user>/...`.
2. Agent booted, loaded the production decision-rule set
   (R001..R010). No flag existed to exclude individual rules at
   runtime.
3. Test ran `nn-admin debug force-posture combat …`. `nn-admin`
   was spawned from `CARGO_BIN_EXE_nn-admin`, also under
   `/home/<user>/.../target/release/nn-admin`.
4. The ProcessSpawn event for `nn-admin` reached the decision
   pipeline. `R009_RootExecFromUserPath`
   (`agent/src/decision/rules/r009_root_exec_from_user_path.rs:8-44`)
   matched on `uid == 0` plus a `/home/`, `/tmp/`, or `/var/tmp/`
   prefix; verdict was `ResponseAction::KillProcess`.
5. The kill landed on `nn-admin` ~47 µs after spawn, before
   `nn-admin` could transmit the force-posture command frame.
   Empty `stderr` is the signature of this race: clap never
   reached the point of emitting parser feedback.

### Why R009 is correct production code

A root binary executing from `/home/...` is a textbook
privilege-escalation indicator (e.g. a non-privileged attacker
drops a payload in their home dir, then escalates via SUID/sudo
misconfig and re-execs). The rule has no allowlist, no test-mode
exemption, and no parent-PID heritage check by design. Adding any
of these to satisfy a test would weaken the production detection.

---

## 3. Evidence summary (pre-resolution)

| Item | Location |
|---|---|
| Production rule | `agent/src/decision/rules/r009_root_exec_from_user_path.rs:8` (`USER_WRITABLE_PREFIXES`) |
| Pre-fix spawn site | `agent/tests/privileged_e2e.rs:71-94` (`spawn_agent`) |
| Failing assertion | `agent/tests/privileged_e2e.rs:177` |
| Pre-fix agent flag surface | only `--combat-rules`, `--admin-pub`, `--admin-socket`, `--no-ade` |
| Action enum | `ResponseAction::KillProcess` (`common`) consumed by responder |
| Env-var origin | cargo built-in `CARGO_BIN_EXE_<name>` → `target/<profile>/<name>` |

---

## 4. Remediation options that were considered

Three approaches were sketched at discovery; the one implemented in
the resolution is **Option A**.

### Option A — test fixture copies binaries to `/usr/local/bin/` (CHOSEN)

Before `spawn_agent`, sudo-copy `northnarrow-agent` and `nn-admin`
into `/usr/local/bin/<name>-e2etest-<ts_ns>-<pid>` (timestamp +
PID suffix avoids collisions across concurrent / repeated runs).
R009 stops matching because `/usr/local/bin/` is not in
`USER_WRITABLE_PREFIXES`.

- **Pros:** no production-code change; surface confined to the
  test module; mirrors how the install would deploy binaries;
  RAII cleanup via the existing `AgentGuard`.
- **Cons:** requires root write to `/usr/local/bin/` at test time
  (already required for iptables, so cost is incremental).
- **Effort actual:** ~1 hour (helper + Drop guard + module doc
  update + verification run).

### Option B — agent `--decision-rules-allowlist` / `--decision-rules-deny` flag

Add a CLI flag on `northnarrow-agent` taking a comma-separated
list of rule IDs to include or exclude, gated behind a test-only
feature flag so production builds cannot ship with rules disabled.

- **Pros:** general-purpose; useful beyond this test.
- **Cons:** adds a footgun surface; rule disablement is exactly
  the kind of switch future red-team work will attack. Significant
  design review cost.
- **Why not chosen:** disproportionate complexity for a
  test-infrastructure fix.

### Option C — R009 parent-PID / signature exemption

Modify R009 to allow root execs whose parent process is itself a
PROTECTED_PID, and/or whose binary is signed with the customer
admin Ed25519 key.

- **Pros:** strengthens R009 for the long term.
- **Cons:** parent-PID alone is too weak; signature checks
  require binary-signing infrastructure that does not yet exist
  (Tappa 8/9 scope).
- **Why not chosen:** correct long-term answer, wildly out of
  scope for a test fix.

---

## 5. RESOLUTION — Option A implemented (2026-05-19)

### Implementation summary

Modified `agent/tests/privileged_e2e.rs` only. No production code
touched.

- New `InstalledBin` RAII type — wraps a copy under
  `/usr/local/bin/`, `sudo install -m 755 -o root -g root` on
  construction, `sudo rm -f` on `Drop`.
- New `install_to_priv_bin(src)` — copies any binary to
  `/usr/local/bin/<basename>-e2etest-<ts_ns>-<pid>`.
- Thread-local cache `NN_ADMIN_INSTALL` for the per-test
  `nn-admin` install; lazily populated on first
  `init_admin_keypair` / `run_nn_admin` call, cleared on
  `AgentGuard::drop`.
- `AgentGuard` extended with `agent_install: Option<InstalledBin>`;
  `Drop` first reaps the child via SIGQUIT, then drops the agent
  install, then clears the `nn-admin` cache — both binaries
  removed before the test returns.
- `spawn_agent` installs the agent binary before spawn and
  invokes the relocated copy.
- Module doc extended with a "Why both binaries are installed to
  `/usr/local/bin/` at fixture setup" section pointing back at
  this issue.

### Live-verify evidence

- **Host:** `northnarrowdev` (Ubuntu Server VM)
- **Kernel:** `6.8.0-117-generic`
- **LSM chain:** `lockdown,capability,landlock,yama,apparmor,bpf`
- **Build:** `cargo test --release --features
  test-privileged,debug-trigger -p northnarrow-agent --test
  privileged_e2e --no-run`
- **Run dir:** `/tmp/eni_run/r009fix_1779177273/`
- **Target test:** `e2e_force_combat_then_unlock_via_cli`
  → exit code **0**, `test result: ok. 1 passed; 0 failed;
  0 ignored; 0 measured; 3 filtered out; finished in 1.11s`.
- **Full privileged suite** (all 3 active tests in
  `privileged_e2e`): exit code **0**, `test result: ok.
  3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;
  finished in 3.13s`.
- **Workspace default suite** (`cargo test --release --workspace`):
  `381 lib tests: 371 passed, 0 failed, 10 ignored` + 50
  integration tests, 0 failures.
- **iptables side-effect check:** pre vs post diff shows only
  packet/byte counter deltas on the `INPUT` and `OUTPUT` policy
  rows — no chain added, no rule added, `NORTHNARROW_COMBAT`
  absent post-run. Cycle is clean.
- **`/usr/local/bin` residue check:** zero leftovers
  (`ls /usr/local/bin/ | grep e2etest` empty post-run). RAII
  cleanup works.
- **Deadman:** not triggered (test completed in 1.11s, deadman
  was set for 10 min).
- **Agent log evidence of cycle** (excerpts from
  `/tmp/eni_run/r009fix_1779177273/test.log`):

  ```
  anti-tamper: PIDs registered with kernel pids=[7053] map="PROTECTED_PIDS"
  anti-tamper: reused pinned LSM link hook="task_kill" ...   (×7 hooks)
  decision engine ready rules=10 demo_tappa5=false
  admin socket listening (mode 0600) path=/tmp/.tmpl2PRhi/admin.sock
  process spawn detected event=ProcessSpawn {
    ..., comm: "nn-admin-e2etes",
    filename: "/usr/local/bin/nn-admin-e2etest-1779177292184699518-7046", ...
  }
  COMBAT: network isolated (loopback only) rules=/tmp/.tmpl2PRhi/combat-rules.v4
  admin challenge issued (32-byte nonce)
  admin signature verified, unlock token minted
  COMBAT: network isolation released
  ```

  `nn-admin` was observed by the agent, the spawn was NOT killed
  (R009 didn't match the `/usr/local/bin/` prefix), the
  challenge-sign-verify-unlock-release pipeline executed
  end-to-end.

### Invariants preserved

- ✅ No change to `agent/src/decision/rules/r009_*.rs`
- ✅ No change to `agent/src/anti_tamper/network_isolate.rs`
- ✅ No change to `configs/combat-rules.v4`
- ✅ No new agent CLI flags (production behaviour unchanged)
- ✅ `cargo clippy --workspace --all-targets -- -D warnings` clean
- ✅ Full workspace default test suite passes (`cargo test
  --release --workspace`)
- ✅ All other privileged_e2e tests still pass with the new
  fixture (sibling tests `e2e_unlock_with_wrong_key` +
  `e2e_status_no_admin_action_initially`)

---

## 6. Status promotion

| Doc | Was | Now |
|---|---|---|
| `docs/CLAUDE_BRIEFING.md` Task 7 line | `TODO` | `✅ SHIPPED 2026-05-19` (live-verify on kernel 6.8.0-117) |
| `docs/TAPPA7_PREREQ.md` Task 7 section | (Implementation noted as ready) | `✅ SHIPPED 2026-05-19` appendix added |
| This issue | (would be `OPEN`) | `RESOLVED 2026-05-19` |

The intermediate "PARTIAL: code-complete, test-blocked" state that
the open PR on branch `tappa7-task7-eni-status-recon` documented
is **superseded** by this resolution. That PR can be closed
without merging — its analysis content is preserved verbatim in
§§1-4 above plus the explicit RESOLUTION section here. This PR is
the canonical reference.

---

## 7. Cross-references

- `agent/tests/privileged_e2e.rs` — module doc + helper functions
  `install_to_priv_bin`, `nn_admin_priv`, `InstalledBin`,
  extended `AgentGuard`.
- `agent/src/decision/rules/r009_root_exec_from_user_path.rs:8` —
  the production rule, unchanged.
- `docs/CLAUDE_BRIEFING.md` § "FASE 3: Anti-Tamper" Task 7 line.
- `docs/TAPPA7_PREREQ.md` § "UPDATE 19 maggio 2026 — Task 7 ENI
  SHIPPED" appendix.
- `docs/integration-test-runbook.md` — manual run path for
  `privileged_e2e`.
- Tappa 8 (Ed25519 admin override) — natural home for the
  long-term Option C signature-based exemption, should it ever be
  needed.
