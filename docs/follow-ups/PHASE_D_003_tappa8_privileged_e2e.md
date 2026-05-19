# PHASE_D_003 — Tappa 8 privileged e2e (deferred from A15)

**Status:** OPEN — deferred from B5 (Tappa 8 closing commit).
**Filed:** 2026-05-19 alongside B5 (`feat(admin_socket): Tappa 8
sub-sprint B B5 (A15) — wire AuditLog::append into every signed
admin dispatch + SO_PEERCRED client capture`).
**Depends on:** ISSUE_001 (R009 self-kill remediation in the agent's
existing `agent/tests/privileged_e2e.rs` harness; the same fix the
Watchdog sprint applied to `watchdog/tests/privileged_e2e.rs` via
the `install_to_priv_bin` helper in PHASE_D_001's W8 commit).

## What design A15 calls for

> `test(privileged_e2e): shutdown round-trip, rotate-keys round-trip,
> audit-verify e2e` | New tests in `agent/tests/privileged_e2e.rs`.
> Depends on R009 self-kill remediation.

Three privileged-mode integration tests:

1. **Shutdown round-trip** — spawn the agent under sudo + a mock
   watchdog (or no watchdog), `nn-admin shutdown` with 2-of-N
   quorum, observe the shutdown_authorised marker on disk, observe
   the agent process exit cleanly.
2. **Rotate-keys round-trip** — spawn the agent, `nn-admin rotate-
   keys add` a fresh pubkey, observe admin.pub atomic rewrite,
   observe in-memory reload by issuing a follow-up admin op with
   the new key.
3. **Audit-verify e2e** — exercise both add + revoke + a few
   unlocks, then `nn-admin audit verify --from /etc/northnarrow/
   audit.log --agent-sig-key /etc/northnarrow/agent.sig.key`
   returns Success with the expected entry count and an intact
   chain.

## Why deferred from B5

B5 ships the audit dispatch wiring (the operationally-meaningful
piece — without it the audit log is empty even after admin ops),
covered by 4 dispatch-level unit tests. The privileged e2e
additionally requires:

- Reimplementing the R009 install-to-/usr/local/bin pattern in
  `agent/tests/privileged_e2e.rs` (the existing file pre-dates
  PHASE_D_001's W8 commit which shipped the pattern in
  `watchdog/tests/privileged_e2e.rs`).
- A mock watchdog or no-watchdog mode so the shutdown round-trip
  doesn't need full Watchdog deployment.
- COMBAT-side safety (the W8 bring-up surfaced that orphaned
  agent processes can transition POSTURE→COMBAT and start
  applying iptables rules — needs the `pkill -QUIT -f
  <basename>` orphan-cleanup pattern PHASE_D_001's W8 commit
  added to the watchdog fixture).

All three are well-scoped follow-ups; none block the production
audit functionality B5 ships.

## What B5 verified instead (unit-level)

`agent/src/admin_socket.rs::tests`:

- `audit_emits_on_unlock_success` — full B1 module integration:
  fresh signing key → AuditLog::open → emit_audit_for → file on
  disk has one row chained off GENESIS_PREV_HASH.
- `audit_emits_on_shutdown_success_with_grace_extra` — the
  `grace_secs` field flows from SignedPayload → audit `extra`.
- `audit_emits_on_force_posture_failure` — failures audit the
  same way as successes (chain captures attempts, not just wins).
- `audit_chains_rotate_keys_add_emissions_and_skips_non_auditable`
  — TWO sequential emissions chain (second.prev_hash ==
  first.entry_hash) AND non-auditable messages
  (ChallengeRequest, Status) produce no rows.

Combined with B1's 8 audit-module tests + B2's 5 CLI tests, the
audit chain integrity is verified end-to-end without needing the
privileged harness.

## Follow-up fix sketch

1. Port `install_to_priv_bin` + RAII `InstalledBin` + bpffs
   purge + orphan-pkill from
   `watchdog/tests/privileged_e2e.rs` into a shared
   `tests/common/mod.rs` (or duplicate into `agent/tests/`).
2. Add the three test cases.
3. Gate behind `--features test-privileged` consistent with
   the watchdog harness.
4. Run on Hetzner with the same sudo wrapper PHASE_D_001 used:
   `sudo -E env CARGO_TARGET_DIR=... cargo test --release
   -p northnarrow-agent --features test-privileged --test
   privileged_e2e -- --test-threads=1`.

Expected size: ~600–800 LOC test code + a small refactor to share
the install helpers. ~2 hours.
