# Tappa 8 — Ed25519 Admin Override Design

**Status:** RFC / design only — no production code in this branch.
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-19.
**Predecessor design:** `docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md`
(§13 Q4 is resolved here).

This doc is reviewable as a PR. Tappa 8 is **partly implemented
already**: the challenge / sign / verify / unlock-token capability
pipeline shipped through commits up to HEAD; §2 is the explicit
inventory of what's there vs what's missing. The remaining work is
**signed shutdown** (the watchdog interaction), **wire-protocol
versioning + replay defence**, **key lifecycle** (rotation /
revocation), and a **tamper-evident audit log**.

---

## 1. Purpose & scope

Tappa 8 establishes the **trusted-human-override** path for every
operation that a non-trusted root cannot be allowed to perform on
the protected host. The headline operation is **release from
COMBAT** (the COMBAT iptables ruleset has no management-port
carve-out by design — see `agent/src/anti_tamper/network_isolate.rs:6-10`),
which means without Ed25519-signed unlock the only recoveries are
physical console access or a host reboot. Tappa 8 is what makes
COMBAT operationally tolerable.

### 1.1 Operations Tappa 8 authorizes (full list in §4)

- **ENI unlock** (COMBAT → Alerted) — primary use case, implemented.
- **Signed shutdown** (clean stop, watchdog must not respawn) —
  **new**, resolves Watchdog §13 Q4.
- **Force-posture** (any state → any state) — currently
  `debug-trigger`-only; spec'd here for production after gating.
- **Key rotation** — new admin key install / old key revocation;
  needs protocol surface today's CLI lacks.
- **Audit log read** — export the tamper-evident admin-action log
  for off-host inspection.

### 1.2 Operations explicitly out of scope

- **Rule allowlist mutation** (adding/removing detection rules at
  runtime). Detection-rule changes flow through the rule-engine
  config + restart cycle; runtime rule tweaks are a Tappa 10 / SaaS
  concern, not an Ed25519 admin scope.
- **eBPF program load/unload from outside the agent.** The agent is
  the sole BPF authority; nothing in Tappa 8 lets nn-admin push
  fresh eBPF objects.
- **Customer-facing service management** (start/stop unrelated
  services). systemd is for that.
- **Agent configuration mutation** (other than the explicit
  operations listed in §4). Anything that touches detection logic
  goes via re-deploy, not signed CLI.

### 1.3 Threat model

| Adversary | What they can do | What Tappa 8 prevents |
|---|---|---|
| Root on the protected host (post-LSM-bypass) | Read the agent binary, attempt to kill it (blocked by Tappa 7), open `/run/northnarrow/admin.sock` | Cannot release COMBAT, cannot signal a clean shutdown (no private key). Can read pubkeys (no secret). |
| Off-host attacker with a captured nonce + old signature | Replay the same signed nonce | Nonces are 32-byte CSPRNG, single-use, consumed even on failure (`admin_auth.rs:188-198`). Replay always hits `NoPendingChallenge`. |
| Off-host attacker with passwordless physical access but no key | Reboot, edit pubkey file, restart agent | Defeated by Tappa 7 task 5 filesystem LSM (`/etc/northnarrow/*` immutable + protected; **note: the current `attach()` only protects `/var/lib/northnarrow`, NOT `/etc/northnarrow` — see §13 Q1**). |
| Insider with one valid key, attempting to disable detection | Issue valid unlock | Authorised — accepted by design; tamper-evident audit log (§9) records the action and key fingerprint. |
| Stolen admin key file | Sign anything | Defeated only by key revocation (§7.3) — manual install-time process today; HSM/YubiKey future. |
| Compromised CI worker | Read priv key from env | Out of scope — operator must not push keys to CI. nn-admin reads from disk only today; env-var path is a §8 Q. |
| Network MITM | Modify wire traffic | Admin socket is **local Unix only** (no TCP) — MITM requires already-root which is already a worse threat. |

The trust boundary is **the kernel + the agent process + the
filesystem under LSM protection + the operator's private key**.
Anything outside that boundary is hostile by assumption.

---

## 2. Current state inventory (IMPLEMENTED vs TODO)

### 2.1 IMPLEMENTED (HEAD `1bb1f1f` and below)

| Surface | Where | Notes |
|---|---|---|
| Pubkey loading (multi-key, hex, `#` comments) | `agent/src/anti_tamper/admin_auth.rs:87-130` | At least one key required; line-numbered parse errors. |
| `AdminAuth` server: challenge issuance, verify, rate-limit (3 fails / 5 min) | `admin_auth.rs:153-257` | OsRng nonces, constant-time multi-key verify, nonce consumed even on failed verify. |
| `UnlockToken` capability type | `network_isolate.rs:48-64` | Zero-size private-field token; `mint_unlock_token()` is `pub(in crate::anti_tamper)` — type-system prevents external minting. |
| `PostureMachine::admin_release_combat_with_token` | `posture/mod.rs:310-340` | Combat → Alerted (intentionally not Engaged, see docstring). Fires `combat_release_hook` so `NetworkIsolator::release` can tear down iptables. |
| Wire protocol enum `AdminMessage` | `common/src/wire/admin_protocol.rs:103-130` | Variants: `ChallengeRequest`, `Challenge`, `Unlock`, `UnlockResult`, `Status`, `StatusResponse`, `DebugForcePosture(Ack)`. Length-prefixed framing, 64 KiB max body. |
| Admin socket server (tokio UnixListener) | `agent/src/admin_socket.rs:45-86` | Stale-socket unlink on bind, forced `0600`, accept loop with per-connection tokio task. |
| Dispatcher | `admin_socket.rs:122-216` | Maps ChallengeRequest → AdminAuth, Unlock → verify + posture release, Status → posture+isolator snapshot. |
| `nn-admin` CLI binary | `agent/src/bin/nn_admin.rs` | Subcommands: `init`, `unlock`, `status` (with `--json`), `verify-keys`, `debug force-posture` (feature-gated). Stable exit codes 0..=5. |
| `admin_cli` library | `agent/src/admin_cli.rs` | `run_init`, `run_unlock`, `run_status`, `run_verify_keys` + thin `nn-admin` wraps these. 5 s read/write socket timeout. |
| Keypair generation | `admin_cli.rs:72-115` | Ed25519 via `ed25519-dalek`; priv 64-hex one-line + mode 0600 (create_new unless `--force`); pub appended to `admin.pub` with timestamped fingerprint comment. |
| Pubkey fingerprint (SHA-256[..4] → 8-hex) | `admin_cli.rs:218-223` | Used as the short identifier in `init` output and (per docstring) in agent logs. |
| Privileged e2e tests | `agent/tests/privileged_e2e.rs:74-150` | `init_admin_keypair` helper + the round-trip cycle (combat-entry → unlock → posture+iptables verify). |

### 2.2 TODO (gaps this design addresses)

| Gap | Why it matters | Resolved by |
|---|---|---|
| **No `nn-admin shutdown` subcommand** | Watchdog has no way to know an admin authorized the agent's exit → would respawn it. Watchdog §13 Q4. | §10 |
| **No wire-protocol version field** | Future protocol evolution breaks rollups silently. Today every frame is variant-discriminated only. | §6.2 |
| **No timestamp on signed payloads** | Replay defence relies solely on nonce single-use. A captured signature can't be replayed within the same agent boot, but a future protocol that signs a longer-lived payload (shutdown, force-posture) needs explicit time-binding. | §6.3 |
| **No per-key operation scoping** | Any key can do anything. An "unlock-only" key for ops-on-call vs a "shutdown-also" key for sysadmin is impossible. | §3.2 |
| **No multi-key quorum (k-of-n)** | Critical operations (signed shutdown, key rotation) accept a single signature. Insider-attack mitigation requires quorum. | §3.3 |
| **No key rotation protocol** | Today: operator hand-edits `/etc/northnarrow/admin.pub`. Tappa 7 task 5 makes that file immutable post-install, so rotation requires LSM bypass. | §7.2 |
| **No key revocation** | A leaked key is forever-valid until manual file edit + agent restart. | §7.3 |
| **No tamper-evident audit log** | Today: `tracing::info!`/`warn!` to journald. An attacker with journald write can rewrite history. | §9 |
| **No air-gapped split flow** | `nn-admin unlock` requires both private key and socket on the same host. Air-gap-friendly recovery deferred to V1.1 per existing docs. | §13 Q5 (deferred) |
| **No HSM / YubiKey / TPM path** | Private key sits on disk in plaintext hex. | §13 Q6 (deferred V1.0+) |
| **Force-posture is `cfg(feature = "debug-trigger")` only** | No production way for an admin to drop COMBAT to Observing for an exercise / drill. | §4 + §6.4 |
| **`NetworkIsolator::release` not visibly plumbed past the hook surface** | Need to verify the combat_release_hook is wired in `main.rs` and that release reverses the iptables-restore. Cross-check during implementation. | §13 Q2 |

### 2.3 Test surface that already exists

- 16 `admin_auth` unit tests (load + issue_challenge + verify + rate-limit).
- 5 `admin_socket` integration-style tokio tests (status round-trip,
  end-to-end unlock cycle, stale-socket unlink, mock-server unlock).
- 11 `admin_cli` unit tests (init, verify-keys, unlock outcomes via
  mock server).
- 1 privileged e2e test (`e2e_force_combat_then_unlock_via_cli`) —
  blocked by R009 self-kill issue (see
  `docs/issues/ISSUE_001_eni_test_r009_selfkill.md`), unrelated to
  the Tappa 8 surface itself.

This is the test base the Tappa 8 finish work builds on; the new
operations (§4) replicate the same shape — unit tests on the
authz layer + admin_cli mock-server tests + one privileged e2e per
operation.

---

## 3. Trust model

### 3.1 What an Ed25519 admin key proves

A valid Ed25519 signature on a server-issued payload proves: **the
holder of the corresponding private key authorised this specific
operation on this specific agent instance at approximately this
time, and no replay of an earlier authorisation is being attempted**.
It does **not** prove the holder's identity beyond key control — the
key fingerprint is the only identity. Audit-log entries are signed
by the **key**, not by a "user account."

### 3.2 Per-key authorisation scoping (NEW)

Today `admin.pub` is a flat list; every key authorises every
operation. The new format extends each line with an **operation
allowlist**:

```
# format: <hex-pubkey> <space> [<role>[,<role>...]]
# roles:  unlock | shutdown | force-posture | rotate-keys | audit-read | all
#
# Operator on-call key — production
<hex64>  unlock,audit-read
# Sysadmin key
<hex64>  unlock,shutdown,force-posture,audit-read
# Break-glass key (kept offline)
<hex64>  all
```

Default when no role list is present: `unlock,audit-read` (the
"on-call" minimum). Lines without an explicit role list match the
current behaviour of allowing unlock and status — backwards
compatible, since `status` doesn't require a signature today.

The wire protocol carries the operation name in the signed payload
(see §6.3); `AdminAuth::verify_unlock` extends to
`AdminAuth::verify(payload, &[allowed_roles])` so the role check is
inside the verify, not a separate post-check (closes a TOCTOU
window).

### 3.3 Multi-key quorum for critical operations

Operations are classified single-key vs k-of-n:

| Operation | Quorum | Rationale |
|---|---|---|
| `unlock` (COMBAT release) | 1 of N | Time-critical; on-call needs to act fast. Misuse is auditable. |
| `force-posture` (production) | 1 of N | Same as unlock — operational. |
| `shutdown` | **2 of N**, of which one MUST carry the `shutdown` role | Stopping the agent is destructive (defence goes offline); requires sysadmin co-sign. |
| `rotate-keys` (add new key) | 2 of N including one `rotate-keys` role | Cannot install a fresh admin key on a single signature. |
| `rotate-keys` (revoke existing key) | 2 of N including one `rotate-keys` role | Same. |
| `audit-read` | 1 of N | Read-only, safe. |

**2-of-N implementation note:** the wire protocol carries
`signatures: Vec<KeyedSignature>` for quorum operations; the agent
verifies *each* signature against the outstanding nonce and tallies
**distinct** key fingerprints. A quorum payload with two signatures
from the same key is rejected. Implementation cost is moderate —
~150 LOC for the quorum verify + protocol changes.

### 3.4 No central CA / no PKI

NorthNarrow is sovereign-first. There is **no certificate
authority, no chain of trust, no X.509**. Admin keys are bare
Ed25519 pubkeys distributed and authorised by the operator at
install time. Key rotation (§7.2) is the only "re-issuance" path.

---

## 4. Authorized operations

| Operation | Roles required | Quorum | Signed payload (§6.3) | Status |
|---|---|---|---|---|
| `unlock` (COMBAT → Alerted) | `unlock` | 1 | `{op:"unlock", nonce, ts, agent_id}` | implemented (without ts/agent_id) |
| `shutdown` (clean stop, no watchdog respawn) | `shutdown` + one other | 2 | `{op:"shutdown", nonce, ts, agent_id, target:"agent+watchdog"}` | new |
| `force-posture <target>` | `force-posture` | 1 | `{op:"force-posture", nonce, ts, agent_id, target:<state>}` | new (debug-only today) |
| `rotate-keys add <hex-pubkey> <roles>` | `rotate-keys` + one other | 2 | `{op:"rotate-add", nonce, ts, agent_id, new_pubkey, roles}` | new |
| `rotate-keys revoke <fingerprint>` | `rotate-keys` + one other | 2 | `{op:"rotate-revoke", nonce, ts, agent_id, fingerprint}` | new |
| `audit-read [--since <ts>]` | `audit-read` | 1 | `{op:"audit-read", nonce, ts, agent_id, since}` | new |
| `status` (already exists, unauthenticated) | — | — | (no signature) | implemented |
| `verify-keys` (local-only, parses admin.pub) | — | — | (no socket) | implemented |

**Out of scope** (explicitly): adding/removing detection rules at
runtime, mutating eBPF programs, changing agent CLI args. These
require redeploy.

**ENI unlock semantics** (already implemented, restated for
completeness): COMBAT → Alerted (NOT Engaged) — see
`posture/mod.rs:283-309` for the rationale ("threat acknowledged,
network restored" ≠ "incident over"). This design does not change
that.

---

## 5. CLI ergonomics

### 5.1 Subcommand surface (after Tappa 8 finish)

```
nn-admin <command> [options]

Commands:
  init                Generate keypair; install pubkey
  status              Print posture / network-isolation / last admin action
  verify-keys         Parse admin.pub locally; print fingerprints + roles
  unlock              Sign challenge, request COMBAT release
  shutdown            (NEW) Signal clean agent stop (watchdog won't respawn)
  force-posture       (NEW) Drive posture machine to a chosen state
  rotate-keys         (NEW) Subcommands: add | revoke
    add <hex-pubkey> <roles>
    revoke <fingerprint>
  audit               (NEW) Subcommands: read | verify
    read [--since <ts>] [--json]
    verify [--from <file>]
  debug force-posture (UNCHANGED, debug-trigger feature only)
```

### 5.2 Examples

```
# Unlock (already works today)
$ nn-admin unlock --key /etc/northnarrow/admin.key
unlock: success

# Signed shutdown (new — requires 2-of-N quorum)
$ nn-admin shutdown --key /home/sysadmin/admin.key \
                    --cosign-key /home/oncall/admin.key
shutdown: 2 signatures collected (fingerprints: 8a1c2f3e, 7b5d4ce0)
shutdown: accepted; agent + watchdog stopping
$ systemctl status northnarrow-agent
... Active: inactive (clean shutdown by admin: 8a1c2f3e+7b5d4ce0)

# Force-posture (new — production-gated, requires 'force-posture' role)
$ nn-admin force-posture --target observing --key /etc/northnarrow/admin.key
force-posture: target=Observing accepted
$ nn-admin status
posture           : Observing
network isolation : clear
last admin action : 2s ago

# Key rotation: install a new key (2-of-N)
$ nn-admin rotate-keys add \
    --new-pubkey c0ffee...  \
    --new-roles unlock,audit-read \
    --key /home/sysadmin/admin.key \
    --cosign-key /home/oncall/admin.key
rotate: new key c0ffee... installed (roles: unlock,audit-read)
       admin.pub regenerated atomically (rename(2))

# Audit log (new)
$ nn-admin audit read --since '2026-05-19T00:00:00Z' --json | jq .
[
  {"ts":"2026-05-19T08:14:02Z","op":"unlock","key_fp":"8a1c2f3e",
   "result":"success","prev_hash":"...","entry_hash":"...","sig":"..."},
  ...
]
$ nn-admin audit verify --from /tmp/audit_export.jsonl
audit: 142 entries, hash chain intact, all sigs valid
```

### 5.3 Output format conventions

- **Human output (default):** lowercase prefix `<command>: <message>`
  on the success line. Colour via ANSI when stdout is a TTY
  (existing `colorize` helper). Errors to stderr.
- **JSON output (`--json` flag where applicable):** one-line JSON,
  field names are stable wire-protocol field names where they
  exist. Hand-rolled (no `serde_json` dep at the binary surface,
  consistent with current `print_status`).
- **Exit codes (stable, extending the current 0..=5 contract):**
  - `0` success
  - `1` generic startup failure (bad args, file I/O, missing keys)
  - `2` server rejected signature
  - `3` server reports no pending challenge
  - `4` rate-limited (`retry_after_secs` printed)
  - `5` transport / protocol failure
  - `6` (NEW) quorum requirement not met (e.g. only 1 signature
    provided for `shutdown`)
  - `7` (NEW) role check failed (key valid but lacks required role)
  - `8` (NEW) audit verification failed (hash chain broken)

---

## 6. Wire protocol

### 6.1 Framing (UNCHANGED)

- 4-byte big-endian length prefix → `MAX_FRAME_BODY = 64 KiB`
  (`common/src/wire/admin_protocol.rs:130`).
- Body is the encoded `AdminMessage` variant (today: postcard or
  bincode — confirm during implementation; the encode/decode pair
  is opaque to this design).
- One-shot synchronous request/reply per frame. The `unlock` flow
  uses two frames on one connection (challenge → unlock). Quorum
  operations use **two-and-a-half frames**: ChallengeRequest →
  Challenge → quorum-bundled signed op → result.

### 6.2 Protocol version field (NEW)

Today's `AdminMessage` enum is the version surface — adding a
variant is a breaking change. To allow rollups (agent newer than
nn-admin, or vice versa, during a staged rollout):

```rust
// common/src/wire/admin_protocol.rs
pub const PROTOCOL_VERSION: u16 = 1;

pub struct VersionedAdminMessage {
    pub version: u16,
    pub message: AdminMessage,
}
```

- Server **rejects** any `version > server-known`.
- Server **tolerates** any `version <= server-known` as long as the
  contained `AdminMessage` variant is one it understands; variants
  added in newer versions of the protocol are gated on the
  `version` field carrying a value ≥ their introduction version.
- Client first frame is always a `VersionedAdminMessage`; server
  replies in the same envelope.
- **Migration path** (v0 → v1): the v1 server accepts an unframed
  v0 `AdminMessage` for `unlock`/`status`/`ChallengeRequest` for
  one release cycle (Tappa 8.x), then v0 is dropped.

### 6.3 Signed-payload structure (NEW)

Today: `signature: [u8; 64]` over a 32-byte nonce alone
(`admin_protocol.rs:43`). That's safe for unlock because the nonce
is fully server-controlled and consumed once — but for new
operations (especially `shutdown`, `force-posture <target>`,
`rotate-keys`) the **operation** must be inside the signed scope,
otherwise an admin who signs an unlock could have their signature
re-used as a shutdown if the wire variants ever overlapped (they
shouldn't but defence in depth).

New payload shape (CBOR-serialized, hashed with SHA-512 per Ed25519
domain-separation):

```
SignedPayload = {
    op:        u8,           // OperationCode (1 = unlock, 2 = shutdown, ...)
    nonce:     [u8; 32],     // server-issued, one-shot
    ts:        u64,          // client wall-clock, secs since epoch
    agent_id:  [u8; 16],     // agent install UUID, see §6.5
    extra:     OperationExtra // op-specific fields (target posture, new key, ...)
}
```

The bytes signed are `SHA-512(domain_sep || cbor(SignedPayload))`
where `domain_sep = b"northnarrow.admin.v1"`. Verification
re-serialises locally and compares; this avoids signature
malleability over alternative CBOR encodings.

### 6.4 Replay defence

Three layers:

1. **Nonce single-use** (already implemented):
   `admin_auth.rs:188-198` consumes the pending challenge inside
   `verify_unlock` regardless of outcome. A replay of an old
   signature always hits `NoPendingChallenge`.
2. **Timestamp skew check** (NEW): server rejects `ts` outside a
   ± **60 s** window relative to its own clock. Replay of an
   ancient capture is bounded. Required because nonce single-use
   is per-agent-boot — a captured nonce/sig that was never
   submitted would otherwise replay on the next boot. Today this
   can't happen because we never persist nonces, but the timestamp
   makes the property explicit and future-proofs against any
   nonce-cache addition.
3. **Agent install UUID binding** (NEW): every agent has a stable
   `agent_id` (16-byte UUID) written at first start to
   `/etc/northnarrow/agent_id` (mode 0644, immutable post-LSM).
   The signed payload includes it. A signature captured from
   agent-A cannot be replayed on agent-B even with full clock
   sync.

### 6.5 Agent install UUID

Generated by `nn-admin init --bootstrap-agent-id` (new flag, paired
with the existing keypair-gen flow at install time) OR by the agent
on first start if missing. Persisted at
`/etc/northnarrow/agent_id` (16 raw bytes hex-encoded one-line).
LSM-protected by the existing Tappa 7 task 5 filesystem hooks once
the protected-path set widens to include `/etc/northnarrow/` (see
§13 Q1).

### 6.6 Error variants

Existing `UnlockResult` enum (`admin_protocol.rs:53-60`) extends:

```rust
pub enum AdminResult {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    // NEW:
    RoleDenied,                                 // key valid, lacks role
    QuorumNotMet { required: u8, provided: u8 },
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
}
```

CLI `nn-admin` maps these to the §5.3 exit codes.

---

## 7. Key lifecycle

### 7.1 Generation

`nn-admin init` (already implemented at `admin_cli.rs:72-115`)
generates a fresh Ed25519 keypair from `OsRng`, writes the private
key (mode 0600, refuses to overwrite without `--force`), appends
the public key with a timestamped fingerprint comment to
`admin.pub`. **No change in V1.0** beyond accepting an optional
`--roles <list>` flag that gets recorded in the comment + the
appended line (per §3.2 format).

### 7.2 Rotation (NEW)

**Graceful rotation without downtime**:

1. Generate the new keypair on a trusted host:
   `nn-admin init --priv-out new.key --bootstrap-only` (writes only
   the priv key locally, does NOT install to the protected host).
2. Operator transfers the **public** key to the protected host (out
   of band: SCP from operator workstation, USB, paper QR code in
   air-gap scenarios — operator's choice).
3. On the protected host, an existing admin with `rotate-keys` role
   plus a co-signer install it:
   `nn-admin rotate-keys add --new-pubkey <hex> --new-roles unlock
   --key /home/sysadmin/admin.key --cosign-key /home/oncall/admin.key`
4. Agent verifies quorum, then **atomically rewrites**
   `/etc/northnarrow/admin.pub` (write to `admin.pub.tmp`, fsync,
   `rename(2)` over the immutable original — needs the LSM
   filesystem hook to allow rename-of-protected-path when the
   verified Ed25519 signature is present; this requires a small
   `agent-side` widening of `inode_rename` policy to honour an
   UnlockToken-equivalent capability; tracked in §13 Q3).
5. `AdminAuth` re-reads the file on next challenge; existing keys
   remain valid until explicitly revoked.

**Old-key revocation:** `nn-admin rotate-keys revoke
--fingerprint <8-hex> --key ... --cosign-key ...`. Same atomic
rewrite path; the revoked key is removed from `admin.pub`.

### 7.3 Revocation

There is **no CRL / no online revocation check** — sovereign
design, no network calls. Revocation = removing the line from
`admin.pub` via `rotate-keys revoke`. A revoked key continues to
work for any operation submitted before the agent re-reads
`admin.pub` (sub-second window after rotation); operators should
not treat revocation as instantaneous.

If a key is lost without warning, the operational answer is:

1. SSH/console into the host using whatever non-Tappa-8 mechanism
   exists (the host's normal admin path; Tappa 8 does not gate
   shell access).
2. Use a co-signed `rotate-keys revoke` if quorum is reachable.
3. If quorum is unreachable (lost too many keys), the **break-glass
   path** is: physical access to the host + manual edit of
   `/etc/northnarrow/admin.pub` after temporarily disabling the
   Tappa 7 task 5 LSM via `systemctl stop northnarrow-agent`
   (which itself requires either the watchdog allowing a signed
   shutdown, or physical reboot to a maintenance boot with the
   agent unit disabled). This is **destructive of audit-log
   continuity** by design — the new audit chain starts fresh after
   recovery, with a `RECOVERY_FROM_QUORUM_LOSS` entry as the new
   root.

### 7.4 Recovery if a key is lost (summary)

| Scenario | Path |
|---|---|
| One key lost, quorum still reachable | `rotate-keys revoke` + `rotate-keys add` (cheap, audited) |
| All keys lost | physical-access break-glass path (§7.3 step 3), audit-chain reset |
| Single-key-deployment & key lost | **don't deploy single-key in production** — pre-deploy policy. V1.0 install docs require ≥ 2 keys minimum at first install. |

---

## 8. Key storage

### 8.1 Recommended paths and permissions

| File | Purpose | Mode | Owner | Notes |
|---|---|---|---|---|
| `/etc/northnarrow/admin.pub` | Server-side pubkey allowlist | 0644 | root:root | LSM-protected via Tappa 7 task 5 widening (§13 Q1). Append-only via `rotate-keys` flow. |
| `/etc/northnarrow/agent_id` | 16-byte install UUID | 0644 | root:root | LSM-protected (immutable). Bootstrapped at install. |
| `/etc/northnarrow/audit.log` | Tamper-evident audit log | 0640 | root:root | Append-only via O_APPEND; LSM hook prevents truncate. See §9. |
| Operator's `admin.key` | Private key | 0600 | operator:operator | **Off the protected host** when feasible. On disk: hex one-line, no encryption today (HSM in §13 Q6). |

The protected host should hold **zero admin private keys**. The
threat model assumes a compromised host root attacker, and a
priv key on disk is undermines the whole Tappa 8 trust chain.
Operator workflow:

- Admin private keys live on the **operator's workstation** (laptop,
  YubiKey via §13 Q6 future).
- nn-admin runs **on the operator's workstation** and connects to
  the agent's admin socket via SSH-forwarded Unix socket
  (`ssh -L /tmp/admin.sock:/run/northnarrow/admin.sock host` —
  `nn-admin` already accepts an arbitrary `--socket` path).
- This satisfies the "compromised host root cannot unlock" property
  because no key material ever lives on the protected host.

### 8.2 CI / automation

For CI integration (e.g. emergency-unlock automation): `nn-admin`
extends to read priv key from `NN_ADMIN_KEY` env var with explicit
opt-in (`--key-from-env NN_ADMIN_KEY`), refuses by default. This is
a footgun and the docstring on `--key-from-env` says so loudly.
**Out of scope for V1.0** — flagged in §13 Q7.

### 8.3 HSM / YubiKey / TPM

**Out of scope V1.0.** Tracked as a V1.1 hardening item. The
ed25519-dalek surface is amenable to swapping the signer for a
`pkcs11`-based or `yubikey`-crate-based one; CLI change is minimal
(`--key` becomes `--key <PATH>` OR `--key-pkcs11 <pin>` OR
`--key-yubikey <slot>`). Design considered, deferred.

---

## 9. Audit trail

### 9.1 What's recorded

Every admin operation — success or failure — appends one record to
`/etc/northnarrow/audit.log` (JSONL). Fields:

```json
{
  "ts":             "2026-05-19T08:14:02.123456Z",
  "agent_id":       "1f8a...d0c1",
  "op":             "unlock",
  "extra":          { "target": null },
  "key_fp":         "8a1c2f3e",
  "cosigner_fps":   ["7b5d4ce0"],
  "result":         "success",
  "client_pid":     12345,
  "client_uid":     0,
  "client_comm":    "nn-admin",
  "prev_hash":      "abc...",
  "entry_hash":     "def...",
  "agent_sig":      "..."
}
```

`prev_hash` chains each record to the previous record's `entry_hash`
— the same primitive that backs sigstore's Rekor and certificate
transparency logs. `entry_hash = SHA-256(prev_hash || serialised
record minus entry_hash and agent_sig)`. `agent_sig` is an Ed25519
signature **by the agent's own keypair** (an internal key, separate
from admin keys, generated at agent install and rotated only via
agent re-install) over `entry_hash`. The agent's pubkey ships with
the install binary so any auditor with the binary can verify the
log without further key distribution.

### 9.2 Tamper evidence

An attacker with root who wants to hide an unauthorised operation
must either:

- (a) **Forge an entry** — requires the agent's signing key, which
  is only in the live agent process memory (loaded from a
  TPM-sealed file at boot in V1.1; from a file at boot in V1.0 —
  see §13 Q6).
- (b) **Truncate the log** — blocked by Tappa 7 task 5 LSM hooks
  on `/etc/northnarrow/` (no `O_TRUNC`, no `rename` of the log
  file, no `unlink`). Append-only is enforced by both `O_APPEND`
  in the agent + the LSM hooks rejecting alternate opens.
- (c) **Rewrite history** — breaks the hash chain. `nn-admin
  audit verify` recomputes the chain from genesis and flags any
  discontinuity.

`audit-read` is itself an admin operation logged in the same chain
(meta-auditing). The reading operator cannot make their own read
disappear from the chain.

### 9.3 Off-host export

`nn-admin audit read --since <ts> --json > evidence.jsonl` exports
the chain in JSONL. Off-host verification:
`nn-admin audit verify --from evidence.jsonl --agent-pubkey
<hex>` recomputes hashes and verifies the per-entry agent
signature. No live connection needed.

### 9.4 Article 13 (EU AI Act) cross-reference

The audit log dovetails with the existing Tappa 6.9
Article-13-evidence chain (`docs/TAPPA6_9_ARTICLE_13_COMPLIANCE.md`):
Tappa 8 admin overrides are the "human-in-the-loop intervention"
events that the AI Act expects to be recorded for high-risk AI
systems. The audit format here is compatible with the dossier
fields the Article-13 work already produces; alignment is
implementation-time work.

---

## 10. Signed-shutdown — Watchdog §13 Q4 resolution

This is the headline new operation and the design's main load-bearing
contribution beyond inventory.

### 10.1 The problem (from Watchdog design §13 Q4)

The watchdog restarts the agent on every death. An operator who
runs `systemctl stop northnarrow-agent` would see the agent killed
by SIGINT (or SIGTERM, hook-bypassed), then watchdog-respawned, and
the unit would flap. The operator wants a **single CLI** that says
"agent off, watchdog stand down."

### 10.2 Wire-protocol resolution

```
AdminMessage::ShutdownRequest(ShutdownRequest {
    signatures: Vec<KeyedSignature>,  // quorum, min 2
    payload: SignedPayload {
        op: 2 /* shutdown */,
        nonce: <server-issued>,
        ts: <client wall>,
        agent_id: <16 bytes>,
        extra: ShutdownExtra { grace_secs: u32 }
    }
})
```

`grace_secs` (operator-chosen, default 30, max 300) is how long the
agent gets to flush its work before the watchdog stops respawning.

### 10.3 Server-side flow (in the agent)

1. Verify quorum (`shutdown` requires 2-of-N including ≥1
   `shutdown` role) → otherwise `RoleDenied` /
   `QuorumNotMet`.
2. Write **shutdown authorisation marker** to
   `/run/northnarrow/agent.shutdown_authorised` containing the
   `entry_hash` of the audit-log record for this operation +
   `grace_deadline_unix_ts`. Mode 0600. tmpfile + rename atomic
   write.
3. Reply `AdminResult::Success` to the client.
4. Begin graceful shutdown internally (drain telemetry queues,
   release the admin socket cleanly, do **not** release COMBAT —
   shutdown of the agent is orthogonal to network state).
5. Process exits cleanly via `std::process::exit(0)`.

### 10.4 Watchdog-side flow

This is what the **Watchdog design §13 Q4** asked for. Concrete
protocol:

1. Watchdog observes pidfd POLLIN (agent dead).
2. **Before** entering the restart path, watchdog `stat`s
   `/run/northnarrow/agent.shutdown_authorised`.
3. If present, watchdog reads the file:
   - Validates that `grace_deadline_unix_ts >= now()` (rejects
     stale markers).
   - Validates the `entry_hash` against the audit log (opens
     `/etc/northnarrow/audit.log`, finds the latest
     `op == "shutdown"` record, checks `entry_hash` match). This
     is the **defence against a forged marker** — only the agent
     can produce a valid audit chain entry.
   - If all validations pass: watchdog **does not respawn**, logs
     `INFO: agent shutdown was admin-authorised
     (entry=<hex>, grace=<n>s); standing down`, deletes the marker,
     and itself exits cleanly (`std::process::exit(0)`).
     systemd `BindsTo=` brings the watchdog unit down with the
     agent unit.
4. If marker absent or stale or hash mismatch: watchdog proceeds to
   normal restart path (the agent died unexpectedly, or someone
   forged a marker — either way the right answer is "restart").
5. Restart-ceiling counter is **incremented** on restart-after-bad-marker
   so a tampering attempt that tries to forge the marker just to
   suppress restarts gets counted into the 5-in-60s tamper signal.

### 10.5 Operator UX

```
$ nn-admin shutdown --key sysadmin.key --cosign-key oncall.key
shutdown: 2 signatures collected; quorum met
shutdown: agent acknowledged (grace 30s); watchdog will stand down
$ systemctl status northnarrow-agent
... Active: inactive (reason: admin shutdown 8a1c2f3e+7b5d4ce0)
$ systemctl status northnarrow-watchdog
... Active: inactive (reason: agent shutdown authorised)
```

To bring everything back up: `sudo systemctl start
northnarrow-agent` (the BindsTo brings the watchdog up
automatically per `After=`).

### 10.6 What if watchdog rejects the signed shutdown?

Causes: marker file corrupted, audit chain broken, clock skew on
watchdog, hash mismatch. Watchdog restarts the agent — the operator
sees the unit come back up. They re-run `nn-admin status`, get a
posture report, can investigate the audit log. The system **does
not silently agree to stay down**. Conservative bias = always
restart on doubt.

### 10.7 What if agent shuts down without signed approval (crash, OOM)?

Marker file absent → watchdog restarts. Identical to today's
proposed Watchdog behaviour, no change. The point of the signed
path is **only** for graceful, authorised shutdown; everything else
is "crash" by definition.

---

## 11. Failure modes & edge cases

| # | Scenario | System response |
|---|---|---|
| A1 | Admin socket unreachable (`/run/northnarrow/admin.sock` missing) | nn-admin: exit 5 (transport failure), clear error message pointing at the socket path. |
| A2 | Socket present but agent not reading (busy / wedged) | nn-admin's 5 s read/write timeout fires (`admin_cli.rs:251-252`), exit 5. |
| A3 | Signature valid but operation not allowed for that key | server returns `RoleDenied`; nn-admin exit 7. Audit log records the attempt with `result: "role_denied"`. |
| A4 | Replay of an old signature on a new boot | nonce single-use defeats it on the same boot; timestamp check defeats it on a later boot (§6.4). |
| A5 | Time skew > 60s between client and server | server returns `TimestampSkew { server_ts, max_skew_secs }`; nn-admin prints the server's clock and a suggestion to NTP-sync. |
| A6 | Key file corrupted (not 64 hex chars) | nn-admin local error before any socket round-trip; exit 1 with line-number error from existing parser. |
| A7 | Multiple admins issuing conflicting commands simultaneously | Admin socket is single-tokio-accept-loop; each connection is one short transaction; serialised effectively at the dispatcher. Race resolution = first-to-verify wins. `PostureMachine` writes hold a write-lock, so posture mutations are strictly serialised. |
| A8 | nn-admin invoked from a compromised user shell on the operator's workstation | Out of scope by definition (the workstation is in the trust boundary). Defence-in-depth: HSM (§13 Q6) requires physical touch per signature. |
| A9 | Quorum requested but only 1 signature provided | server returns `QuorumNotMet { required: 2, provided: 1 }`; exit 6. |
| A10 | All quorum signatures from the same key (one operator double-signing) | server tallies distinct fingerprints; rejects with `QuorumNotMet { required: 2, provided: 1 }`. |
| A11 | Rate-limited (3 fails / 5 min already implemented) | server replies `RateLimited { retry_after_secs }`; exit 4. (Existing behaviour.) |
| A12 | nn-admin exits / crashes mid-handshake (between Challenge and Unlock frames) | server's per-connection task observes EOF, the pending challenge stays in `pending_challenge` and is overwritten by the next `issue_challenge` call (existing `admin_auth.rs:352-364` test confirms). |
| A13 | Watchdog's `entry_hash` validation against the audit log finds the chain broken | Watchdog logs `ERROR` and restarts the agent (defence: prefer restart over honouring a possibly-forged marker). Operator sees the failed shutdown, runs `nn-admin audit verify`, investigates. |
| A14 | `agent_id` file deleted / regenerated mid-flight | All in-flight signed payloads (including ones already sent over the wire) become `AgentIdMismatch`. nn-admin retries with the fresh agent_id (visible via `nn-admin status` which already returns it). |
| A15 | Two simultaneous quorum operations contend for the same nonce | Existing nonce-single-use semantics handle this: second op gets `NoPendingChallenge` and must re-request. nn-admin retries. |

---

## 12. Integration with posture state machine

```
                                       ┌─────────────────────────┐
                                       │       OBSERVING         │
                                       └────────────┬────────────┘
                                                    │ (telemetry)
            ┌──── force-posture(OBSERVING) ─────────┤
            │              (admin)                  ▼
            │                          ┌─────────────────────────┐
            │                          │        ALERTED          │
            │                          └────────────┬────────────┘
            │ ┌── force-posture(ALERTED) ───────────┤
            │ │            (admin)                  ▼ (escalation)
            │ │                        ┌─────────────────────────┐
            │ │     unlock             │        ENGAGED          │
            │ │   (1-of-N admin,       └────────────┬────────────┘
            │ │    requires Combat)                 │ (ConfirmedIntrusion)
            │ │                                     ▼
            │ │                        ┌─────────────────────────┐
            │ └────────────────────────┤        COMBAT           │
            │                          │ (iptables DROP active)  │
            └──────────────────────────┴─────────────────────────┘

   ----- ADMIN-INITIATED TRANSITIONS -----
   unlock          COMBAT → ALERTED   (NOT Engaged; see posture/mod.rs:283-309)
   force-posture   any → any          (requires force-posture role)
   shutdown        process exit; posture state preserved in iptables
                   (kernel state survives; new agent inherits COMBAT
                   ruleset and starts in COMBAT — see Watchdog §5.2 Q2)
```

### 12.1 No new "RECOVERY" state

The original brief asked about introducing a custom RECOVERY state.
**Recommendation: no.** Alerted already carries the right
semantics ("threat acknowledged, still vigilant") and the
`last_admin_action_secs_ago` field already exposed by `status`
already lets nn-admin / dashboards distinguish "Alerted because of
admin unlock 30s ago" from "Alerted because of detector trigger
5min ago." Adding a fifth state doubles the transition matrix for
marginal benefit.

### 12.2 force-posture transition rules

- Allowed: any state → any state, but the transition is recorded
  in the audit log with `op="force-posture"` and the source +
  target states.
- Side effects:
  - `→ COMBAT` from non-COMBAT fires `combat_entry_hook` (iptables
    engage) — identical to a detector-driven entry.
  - `COMBAT →` non-COMBAT fires `combat_release_hook` (iptables
    release) — identical to an unlock.
- The transition is **not** an emergency exit hatch; the existing
  unlock path remains the preferred way out of COMBAT because it
  carries clearer audit semantics ("admin acknowledged COMBAT
  release") than a force-posture from COMBAT to anything else.

---

## 13. Effort estimate — commit-by-commit plan

Numbered against the §2.1/§2.2 inventory. Re-uses the agent's
existing `admin_auth` / `admin_socket` / `admin_cli` modules.

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **A1** | `feat(common): VersionedAdminMessage envelope + PROTOCOL_VERSION` | §6.2. Wire-protocol versioning. v0 backward-compat tolerated for unlock/status. Tests: 4 (encode/decode round-trip, v0-tolerance, future-version reject, malformed envelope). | 2 |
| **A2** | `feat(common): SignedPayload {op, nonce, ts, agent_id, extra}` + domain-sep | §6.3. CBOR serialise, SHA-512 hash, ed25519-dalek verify path. Adds `OperationCode` enum, op-specific `*Extra` types. Tests: 6 (one per op + tamper-detection + cbor-stability). | 3 |
| **A3** | `feat(agent): agent_id bootstrap to /etc/northnarrow/agent_id` | §6.5. Generate on first start, persist, expose via `AdminAuth::agent_id()`. Tests: 3 (fresh-gen, reuse-existing, file-corrupted). | 2 |
| **A4** | `feat(admin_auth): timestamp skew check (±60s, monotonic-aware)` | §6.4 layer 2. Skew check inside `verify` before posture mutation. Server returns `TimestampSkew { server_ts, max_skew_secs }`. Tests: 4 (in-window, future-skew, past-skew, exact-boundary). | 2 |
| **A5** | `feat(admin_auth): per-key role allowlist parsed from admin.pub` | §3.2. Extend `AdminAuth::load` to read `<pubkey> <roles>` lines, default `unlock,audit-read` when no roles specified. `AdminAuth::verify` takes `required_role` and returns `RoleDenied` on mismatch. Tests: 8 (parse + each role + multi-role + default + malformed). | 4 |
| **A6** | `feat(admin_auth): k-of-n quorum verify` | §3.3. New `AdminAuth::verify_quorum(payload, &[sigs], min_distinct, role_requirements)`. Distinct-fingerprint tally. Tests: 6. | 3 |
| **A7** | `feat(admin_socket): shutdown op + /run/northnarrow/agent.shutdown_authorised marker` | §10.3. New `AdminMessage::ShutdownRequest`. Server-side: quorum verify, atomic marker write, graceful exit. Tests: 4 unit on marker format + 1 mock-server e2e. | 4 |
| **A8** | `feat(watchdog): honour shutdown_authorised marker on pidfd POLLIN` | §10.4. Watchdog-side change once Watchdog crate exists (depends on Watchdog W3). Marker validation includes audit-log entry-hash cross-check. Tests: 4 (present-valid, present-stale, present-bad-hash, absent). | 3 |
| **A9** | `feat(admin_cli): nn-admin shutdown subcommand with --cosign-key` | §5.1. Two-signature flow on a single connection (request 2 nonces? — or one nonce signed by both? Latter is simpler; verify both sigs against same nonce). Tests: 4 unit. | 3 |
| **A10** | `feat(admin_cli): nn-admin force-posture (production, role-gated)` | §4 + §12.2. Distinguish from `debug force-posture` (which stays). Tests: 4. | 2 |
| **A11** | `feat(audit): tamper-evident audit log + agent-side append + agent signing key` | §9. New module `agent/src/audit.rs`. Hash chain + per-entry agent signature. Generates agent signing keypair on first start (stored at `/etc/northnarrow/agent.sig.key` mode 0400, LSM-protected). Tests: 8 (chain integrity + tamper detection + concurrent append + signature verify). | 6 |
| **A12** | `feat(admin_cli): nn-admin audit read / audit verify` | §5.2. Read: streaming export. Verify: chain + signature recomputation. Tests: 5. | 3 |
| **A13** | `feat(admin_cli): nn-admin rotate-keys add / revoke` | §7.2. Atomic `/etc/northnarrow/admin.pub` rewrite via tmpfile+rename. Requires LSM rename-of-protected-path policy widening (§13 Q3). Tests: 6. | 5 |
| **A14** | `feat(anti_tamper): widen filesystem LSM protection to /etc/northnarrow/` | §13 Q1. Extend `PROTECTED_INODES` set to include `/etc/northnarrow/admin.pub`, `/etc/northnarrow/agent_id`, `/etc/northnarrow/audit.log`, `/etc/northnarrow/agent.sig.key`. Honour an UnlockToken-equivalent capability for rename/replace during `rotate-keys`. Tests: 6 + 2 privileged e2e. | 4 |
| **A15** | `test(privileged_e2e): shutdown round-trip, rotate-keys round-trip, audit-verify e2e` | New tests in `agent/tests/privileged_e2e.rs`. Depends on R009 self-kill remediation (`docs/issues/ISSUE_001_*.md`). | 4 |
| | **TOTAL** | | **~50 hours** ≈ 1.5 working weeks with CC pair-programming. |

Roughly 60 % of the value (lines A1–A4, A7–A10) ships in a focused
~17 h sprint and unblocks the Watchdog/Tappa-7 closure. The
remaining 40 % (key lifecycle + audit log + LSM widening) can land
as a separate sprint without blocking Tappa 7.

---

## 14. Open questions / RFC items

1. **Q1 — LSM filesystem widening to `/etc/northnarrow/`.** Today's
   `attach()` (`anti_tamper/filesystem.rs`) covers
   `/var/lib/northnarrow` only. `/etc/northnarrow/admin.pub` plus
   the new `agent_id` / `audit.log` / `agent.sig.key` MUST be
   protected for the trust model to hold. Confirm scope can include
   this widening in commit A14? Or is `/etc/` widening a separate
   review?
2. **Q2 — `NetworkIsolator::release` wiring.** Verify before
   implementation: is the `combat_release_hook` already wired to
   `NetworkIsolator::release` in `main.rs`, or is that itself part
   of the open Tappa 7 task 7 work? Confirm during implementation.
3. **Q3 — LSM rename-of-protected-path during rotate-keys.** The
   atomic `rename(2)` over `admin.pub` is blocked by the current
   `inode_rename` hook. Options: (a) extend the hook to honour an
   `UnlockToken` capability passed via a kernel-userland channel
   (complex but principled); (b) special-case the `admin.pub`
   inode for rename when `AdminAuth` set a "rotation in progress"
   in-memory flag (simpler but TOCTOU surface); (c) do not atomic-
   rewrite — `truncate + write + fsync` in place under a userland
   advisory lock (acceptable, audit log captures the gap). Owner
   preference?
4. **Q4 — Quorum nonce semantics.** Two options for the 2-of-N
   wire flow: (a) **one nonce, both signatures over it** (simpler,
   smaller wire surface, has implications for separation-of-duty —
   the second signer technically signs the same bytes as the
   first); (b) **two challenges, two nonces, two replies** (more
   round-trips, true co-signature). Recommendation: (a). Owner
   ruling?
5. **Q5 — Air-gapped split flow.** Recap of existing roadmap note
   in `admin_cli.rs:13-16`: "split request → offline sign →
   submit" is V1.1. Confirm we keep it deferred for Tappa 8?
6. **Q6 — HSM / YubiKey support.** V1.1 hardening? Or V1.0 with
   a feature-flag shim? Recommendation: V1.1.
7. **Q7 — `--key-from-env` for CI automation.** Yes / no / yes
   with required confirmation flag (`--i-know-this-is-dangerous`)?
8. **Q8 — Production force-posture (§4, §12.2).** Should we keep
   `debug-trigger`-gated only, or promote to production with the
   `force-posture` role? Recommendation: production with role. The
   debug flag stays for tests that don't want to run the auth
   pipeline.
9. **Q9 — Audit-log size management.** Append-only logs grow.
   Strategies: (a) yearly rotation with chain-of-chains
   continuation; (b) hard cap with oldest-eviction (breaks audit
   immutability, dispreferred); (c) export-and-truncate via signed
   `audit-rotate` op (operator commits to having exported the old
   log before truncation, signed by quorum). Recommendation: (c)
   for V1.0 with manual operator workflow; (a) as automated V1.1
   refinement.
10. **Q10 — Backend-SaaS audit-log mirror (Tappa 13).** Should the
    agent stream audit-log appends to the backend in addition to
    the local file? Tappa 13 design concern; deferred. Local file
    + manual export is V1.0.

---

## Appendix A — Cross-references

- `docs/CLAUDE_BRIEFING.md:109` (Tappa 8 status: TODO).
- `docs/TAPPA7_PREREQ.md:139` ("canale firmato Ed25519 — Tappa 8
  dependency" on the LSM task_kill exception).
- `docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md:§13 Q4` (signed-shutdown
  resolution — §10 here).
- `agent/src/anti_tamper/admin_auth.rs:1-258` (production AdminAuth).
- `agent/src/admin_socket.rs:1-250` (production admin server).
- `agent/src/admin_cli.rs:1-300` (production nn-admin client lib).
- `agent/src/bin/nn_admin.rs:1-305` (production nn-admin binary).
- `agent/src/anti_tamper/network_isolate.rs:38-64` (UnlockToken
  capability).
- `agent/src/posture/mod.rs:283-340` (admin-release transition).
- `common/src/wire/admin_protocol.rs:1-130` (wire enum + framing).
- `agent/tests/privileged_e2e.rs:74-150` (existing e2e test
  scaffolding).
- `docs/issues/ISSUE_001_eni_test_r009_selfkill.md` (test-blocker for
  the existing e2e, unrelated to Tappa 8 design).

---

## Appendix B — Threat-model recap

Tappa 8 defends against: **root on the protected host attempting
to release COMBAT** (defeated by Ed25519 + nonce single-use +
timestamp + agent-id binding), **root on the protected host
attempting to silently stop the agent** (defeated by watchdog +
signed-shutdown marker chain), **replay of captured signatures**
(defeated by nonce + timestamp + agent_id), **insider abuse of a
single key** (defeated by 2-of-N quorum on destructive operations
+ tamper-evident audit log), **history rewriting after the fact**
(defeated by hash-chained signed log).

It does **not** defend against: **compromised operator workstation
holding the private key in plaintext** (HSM is V1.1), **physical
attacker with hours of console access** (the break-glass recovery
path is for the operator, not against the attacker — physical
access is out of scope by definition for a software-only XDR),
**quantum adversary that can forge Ed25519 signatures** (PQC
migration is a V3.0+ concern, will require protocol-version bump
and key re-roll).
