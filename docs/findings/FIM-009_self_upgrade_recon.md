# FIM-009 self-upgrade — RECON findings (read-only)

**Date:** 2026-06-07 · **Branch:** main (sha at recon: `345727c`) · **Scope:** investigation only, no
code changes. Grounds the self-upgrade design in what already exists. **No design proposal here** —
facts only, with a short cross-cutting section on the most design-relevant prior art.

TL;DR — the FIM-009 self-upgrade problem is **two distinct collisions on the same root cause**:

- **(A) Detection.** Every (re)install rewrites `/etc/systemd/system/northnarrow-agent.service`
  (`deploy/install.sh:224`), which is exactly the `NN-L-FIM-009` watch prefix. A non-agent writer →
  `KillProcess` / High verdict. The unit file is **not** in any protected-inode set, so this is a
  *detection* collision, not an EPERM.
- **(B) Prevention.** Rewriting *protected* inodes (the control-surface baits, the `/etc/northnarrow`
  config files, the `/var/lib/northnarrow` chains) EPERMs against the pinned `inode_protect` hooks
  (BUG-020), unless the writer is the agent's own PID **or** `FS_PROTECT_OVERRIDE` is armed.

Both already converge on one designed-but-unbuilt primitive: an **admin-key-gated, TTL'd "trusted
upgrade window"** (`§15.1` of `docs/backlog/BUG_CATALOG_DESIGN.md`). Its **kernel half already
exists and is wired in** (`FS_PROTECT_OVERRIDE` + `override_active()`); only the userland arming path
is a stub.

---

## 1. `maintenance.mode` — bait/canary only, NOT a real mechanism

**Verdict: pure honeypot bait. There is no maintenance-mode behaviour anywhere in the agent — no code
reads a maintenance state, suppresses verdicts, or opens a write window.**

- It is one of 10 inert control-surface baits. `agent/src/fim/honeypot.rs:40` maps it to
  `bait!("maintenance.mode")` (content `include_str!`'d from `configs/honeypot-baits/maintenance.mode`).
  Module header `agent/src/fim/honeypot.rs:3-5`: *"The detection rule (NN-L-FIM-024) only **watches**
  the `HONEYPOT_PATHS`; this module owns their inert content and the boot-time integrity sweep."*
- `agent/src/fim/rules.rs:1542-1553` lists it in `HONEYPOT_PATHS` (`:1545`). The doc comment
  `:1537-1541` is explicit: *"Names suggest a way to disable the agent (kill switches, maintenance
  flags, override tokens); **NN never reads them and no operator workflow writes them**."*
- The bait file's own body (`configs/honeypot-baits/maintenance.mode`) contains decoy text including
  `maintenance_active=false`. **That string is never parsed** — it exists only to make the decoy look
  plausible to an attacker. (`honeypot.rs:14-16` "no deception leak" + the test at `:142-151`.)
- **Exhaustive negative check:** grep of `agent/src` for `maintenance_active | maintenance_mode |
  MaintenanceMode | disable_until | scheduled_window` → **0 hits.** No reader exists.
- It IS seeded + watched: `deploy/install.sh:213,373` write it; `NN-L-FIM-024` treats any
  create/modify/delete/rename of it as Critical → `KillProcessTree` → COMBAT (`rules.rs:1555-1558`);
  delete is covered by the e2e test `agent/tests/honeypot_tamper_e2e.rs:515`.

**Consequence for the design:** there is currently **no** "suppress verdicts / open a write window"
gate of *any* kind keyed on a file or flag. The only real gates that exist are the Ed25519 admin-op
path (§4) and the `FS_PROTECT_OVERRIDE` eBPF stub (§6). A self-upgrade window must be built; it cannot
piggyback on a maintenance flag because none exists.

---

## 2. `NN-L-FIM-009_SystemdUnitDropped` — exact predicate, zero exemptions

**Defined:** `agent/src/fim/rules.rs:704` (`struct NnLFim009SystemdUnitDropped`), `impl Rule` at
`:706-732`, registered in `fim_rules()` at `:1656`. id `"NN-L-FIM-009_SystemdUnitDropped"` (`:708`),
category `fim_persistence` (`:713`).

**Predicate (`evaluate`, `:716-731`), all three must hold:**

1. event is a FIM event (`as_fim`);
2. `fe.op ∈ {Created, Modified}` (`:718`) — delete/rename do **not** match;
3. `fe.path` starts with any `SYSTEMD_UNIT_PREFIXES` (`:721`).

`SYSTEMD_UNIT_PREFIXES` (`rules.rs:118-122`):
```
/etc/systemd/system/
/lib/systemd/system/
/usr/lib/systemd/system/
```

On match → `Verdict { action: KillProcess, severity: High, reason: "Systemd unit file dropped or
modified — persistence indicator" }` (`:724-730`). (Note: `KillProcess`, not `KillProcessTree`.)

**Exemptions: NONE.** No writer/uid/comm condition, no allowlist, no carve-out, no escalation hook in
the rule. It fires on *any* `Created|Modified` under those three prefixes.

The only filtering is **upstream and family-scoped**: the agent + watchdog are in `PROTECTED_PIDS`, so
the C2 BPF `should_emit` suppresses *their* FimEvents before the rule layer ever sees them (the
parallel statement for FIM-010 is spelled out at `rules.rs:793-796`; the BPF caller-exemption is
`agent-ebpf/src/inode_protect.rs:250-263`). So the **agent writing its own unit won't trip FIM-009,
but any other PID will** — including `install.sh`'s `install`/`cp`/`dpkg`.

**Precedent for a carve-out (contrast).** FIM-009 has nothing like the carve-outs other FIM rules got:
- FIM-005 received a per-writer exemption for rsyslogd's own log appends (commit `171018a`; see the
  "carve-out" comment at `rules.rs:376`).
- FIM-007 got per-directory-bucket coalescing (FP-4, commit `dcbf32a`).
- Sibling **FIM-023** (`.timer`, `rules.rs:1499-1533`) shares `SYSTEMD_UNIT_PREFIXES` + same
  `KillProcess`/High and *also* has no allow logic (it has BUG-022 truncation handling, not an
  exemption).

So: adding a "trusted writer / trusted window" carve-out to FIM-009 is **greenfield** for this rule;
the FIM-005 rsyslogd exemption is the closest in-repo template for the *shape* of a per-writer carve.

**Known detection gaps (NOT exemptions), for awareness:** `BUG_CATALOG_DESIGN.md` notes the 4 unit
dirs are bare-inode, a dir path can fail the `…/system/` suffix check, and in-place unit edits were
historically blind (BUG-023 family). These are coverage bugs, not allow logic.

---

## 3. Existing allow/trust machinery — can it express "trusted upgrade"? **No (today it's network-only).**

### `posture/escalation_allow.rs` — COMBAT network count-filter
- Filters the two **network** COMBAT heuristics only: `AllowTrigger ∈ {Exfil, Lateral}` (`:63-70`,
  explicitly *"the file/process ones (persistence, confirmed-intrusion) are not destination-keyed"*).
- Entry shape: `<trigger> <comm|comm*> <dst-cidr> [port|*]` (`:42-49`, `AllowEntry` `:97-105`).
- Semantics: a match is **excluded from the threshold count**, it does **not** suppress the trigger
  wholesale (`:12-18`). Loaded fail-secure from `/etc/northnarrow/escalation-allow.local` (`:61`);
  the shipped config is all-commented examples (`configs/escalation-allow.local`).

### `anti_tamper/combat_allow.rs` — COMBAT management carve-out
- Loads CIDRs from `/etc/northnarrow/combat-allow.cidrs` (`:36`) and splices `iptables ACCEPT` rules
  ahead of COMBAT's catch-all DROP so SSH/management survives isolation (`:1-30`).
- Entry shape: bare IP or `IP/prefix`. Re-read at engage time (`:16-18`), fail-secure (`:19-22`),
  IPv4 ruleset (v6 validated but emits no rule).

**Neither is a writer/action allow-list, and neither touches FIM/persistence rules.** There is **no
existing mechanism that can express "this writer/action is exempt during an upgrade"** for FIM-009.

**But the *notion* of a trusted/signed operation exists** — just not as an allow-list:
- the Ed25519 admin-op framework (§4);
- the bootstrap relaxation gate `anti_tamper/bootstrap.rs` (§4) — the closest structural template for
  a *gated, one-shot relaxation of a normally-strict policy*, with layered anti-downgrade defences;
- the `FS_PROTECT_OVERRIDE` eBPF stub (§6) — explicitly intended as "Ed25519-signed override
  capability for FS modification."

---

## 4. Signing / verification primitives already present

**Crypto stack:** `ed25519-dalek` (sign + `verify_strict`), `sha2` (SHA-256/512), `hex`, CBOR for the
signed payload, `OsRng` for nonces.

**Trust root = `/etc/northnarrow/admin.pub`.** N Ed25519 verifying keys, each with a role allowlist.
Parsed by `AdminAuth::load` (`agent/src/anti_tamper/admin_auth.rs:240-278`; line parser
`parse_admin_line:1004-1037`). Line format: `<hex64-pubkey> [role,role,...]`. Roles
(`parse_role_keyword:1075-1098`): `unlock, shutdown, force-posture, rotate-keys, audit-read,
fim-manage, fim-read, canary-read, canary-manage, net-read, net-manage, all` (break-glass). Pubkey-only
lines default to `unlock,audit-read`. Hot-swappable via `RwLock` for `rotate-keys` (`:184-192`).

**Signed-OPERATION verification (the real "trusted operation" engine):**
- `verify_with_role` (`:458-540`) — single-sig over the 32-byte challenge nonce + role check;
  constant-time per-key scan (no short-circuit).
- `verify_quorum` (`:588-709`) — M-of-N **distinct-key** quorum over the nonce + per-role coverage.
- `verify_signed_payload_quorum` (`:769-965`) — the full path: signatures over
  `signing_digest(payload)` = `SHA-512(b"northnarrow.admin.v1" || cbor(SignedPayload))`
  (`common/src/wire/admin_signed_payload.rs:18,82,640-645`); enforces **op-tag match, nonce-binding,
  agent_id-binding** (anti cross-agent replay), **±60 s timestamp skew**, **distinct-key quorum**, and
  **per-role coverage**; returns `(UnlockToken, matched-key fingerprints)` for the audit log.
- `SignedPayload` carries `op + nonce + agent_id + ts + OperationExtra`. `OperationCode` variants
  (`admin_signed_payload.rs:96,551-567`): Unlock, Shutdown, ForcePosture, RotateKeysAdd,
  RotateKeysRevoke, AuditRead, FimBaseline, FimReport, FimStatus, CanaryDeploy, CanaryList, CanaryBurn,
  CanaryRefresh, NetFlows, NetListeners, NetResolve, NetFingerprint. **There is no upgrade/install op.**
- Entrance rate-limit (`issue_challenge`): 3 failures / 5 min; attack-signal failures increment the
  counter, operator-UX failures (quorum shortfall, role mismatch, clock skew) do not.

**Audit-log signature VERIFICATION exists** (proves verify, not just sign, is in the codebase):
`agent/src/canary/access_log.rs:289-335` `verify_chain` — Ed25519 hash-chain verify with
`VerifyingKey`/`Verifier`/`Signature::from_bytes`. XAI evidence-chain signing in
`common/src/xai_types.rs` (+ concrete signer `agent/src/xai/evidence.rs`).

**COMBAT release** is minted only through the admin-auth verify path: `UnlockToken` →
`NetworkIsolator::release` (`agent/src/combat/mod.rs:449`, `network_isolate::mint_unlock_token`).

**What `anti_tamper/bootstrap.rs` actually establishes** (the question asked specifically): **not** a
binary verifier. It is the **bootstrap-quorum relaxation gate (BUG-013)** — a one-shot 1-of-N
exception for the *first* `rotate-keys add` on a fresh single-key install, gated by **all** of:
(a) sentinel `/etc/northnarrow/.bootstrap` exists; (b) `admin.pub` has exactly one key; (c) sentinel
== `hex SHA-256(install_nonce || admin.pub bytes)`, where `install_nonce` is 32 CSPRNG bytes at
`/etc/northnarrow/.install_nonce` (written by install.sh, known only to agent + install-time operator).
See `bootstrap.rs:29-43`, `evaluate:146-245`, `compute_sentinel_content:265-270`. Anti-downgrade: ≥2
keys ⇒ ignore + scrub the sentinel; constant-time compare; after 2 keys, permanent 2-of-N. **This is
the in-repo template for "a filesystem-anchored, nonce-gated, one-shot relaxation of a strict
policy."**

**Is there any binary / unit / artifact signature verification? No.** All Ed25519 verification is over
(a) admin *commands* and (b) audit-log *chains*. Nothing verifies the signature of a binary, a systemd
unit, or any release artifact before trusting it.

**But a signed-artifact / signed-grant path would be cheap** — every block is present: `ed25519-dalek`
is already a dependency; `VerifyingKey::from_bytes` + `verify_strict` are already used; a pinned trust
root (`admin.pub`) with roles + quorum + replay defences is implemented; `OperationCode` / `Role` /
`OperationExtra` are explicit append-only extension points (every Tappa added ops/roles this way);
install.sh already provisions `admin.pub` + `admin.key` + `install_nonce`. An
`OperationCode::InstallMode` + a `Role` + a dispatcher arm calling `verify_signed_payload_quorum` would
reuse the existing engine verbatim.

---

## 5. Deploy model

- **install.sh does NOT `enable` or `start` the agent.** Header `deploy/install.sh:4-8`: *"Copies… then
  `daemon-reload`s. **Does NOT enable or start the units** — operators run that explicitly."* Confirmed
  in body: only `systemctl daemon-reload` (`:464`) + best-effort `restart systemd-journald@northnarrow`
  (`:468`). The operator runs `systemctl enable --now …` by hand (documented step 5, `:524-526`). (Once
  enabled, systemd starts it on boot — but that is an operator action, not install.sh.)
- **install.sh writes the unit file on every (re)install:** binaries → `/usr/local/bin` (`:219-221`);
  **unit files → `/etc/systemd/system/`** (`:224-225`) — i.e. `northnarrow-agent.service` is rewritten,
  and that path is the FIM-009 watch prefix. The unit copy at `:224` has **no** skip-if-identical guard
  (unlike the baits at `:386-404`); it is an unconditional overwrite.
- **FIM detection is event-driven; the baseline is not periodically re-scanned.**
  - Detection: eBPF FIM sensor → ringbuf → drain (`agent/src/fim/mod.rs` C4 "RingBuf drain";
    `agent/src/fim/drain.rs`). Live `FimOp` events are evaluated by the rules. No polling.
  - Baseline: computed at boot (first-boot TOFU when `fim_baseline.jsonl` is empty) and **recomputed
    only via the operator-signed `nn-admin fim baseline` admin op** (`agent/src/fim/recompute.rs:1-8`;
    `dispatch_fim_baseline` → `BaselineRecomputeChannel`). The "periodic-rebaseline" phrase at
    `baseline.rs:160` means *the operator re-runs that signed op*, **not** an agent-internal timer
    (grep of `agent/src/fim` for `interval|tokio::time|periodic` → none).
  - Honeypot baits: a **boot-time** integrity sweep only (`fim/honeypot.rs::check_and_restore`, called
    from `main.rs:1586`) recreates missing baits; not periodic.

---

## 6. Cross-cutting — the most design-relevant prior art

### 6.1 `FS_PROTECT_OVERRIDE` already exists; the kernel deny path already honours it
`agent-ebpf/src/inode_protect.rs:99-104`:
> *"Tappa 8 stub: Ed25519-signed override capability for FS modification. Non-zero slot 0 = active
> admin grant, hooks pass-through. Empty in Tappa 7. Pinned by-name; Tappa-8 caveat: slot 0 persists
> across restart and **must be zeroed on boot**."*  `FS_PROTECT_OVERRIDE: Array<u32> = Array::pinned(1, 0)`

`override_active()` (`:181-186`) reads slot 0 (non-zero = bypass). `deny_if_protected` (`:226-267`)
checks, in order: resolve inode → `is_protected?` → **`override_active()` ⇒ ALLOW** (`:246-249`) →
caller-in-`PROTECTED_PIDS` ⇒ allow (`:250-263`) → else emit denial + `-EPERM`.

**So the kernel half of "an admin grant suspends the FS pin" is in place.** What is **missing** is the
userland side: nothing arms it (no admin-key-gated write to slot 0) and nothing zeroes it on boot — a
grep shows `FS_PROTECT_OVERRIDE` referenced in `agent/src` only inside the pinned-by-name map list in
`anti_tamper/mod.rs`, never written. The "must be zeroed on boot" caveat is therefore unaddressed (in
practice harmless only because nothing ever sets it).

### 6.2 The sibling `KILL_OVERRIDE` is further along — a hardening template
`agent-ebpf/src/task_kill.rs` gates its override on a **session nonce** compared against
`AGENT_SESSION[0]`, so a leftover pinned override from a *prior* install isn't honoured — solving
exactly the "persists across restart" caveat `FS_PROTECT_OVERRIDE` still carries. Good pattern to copy
when the FS override's arming path is built.

### 6.3 `§15.1` of `docs/backlog/BUG_CATALOG_DESIGN.md` already designs the fix (`:859-895`)
The "Anti-tamper trust model gap" cluster — **BUG-010 (controller) / BUG-011 (observer) / BUG-013
(authority) / BUG-020 (installer)** — *"the V1 anti-tamper model has no concept of trusted local
controllers/observers/authorities."* Unified-fix table row (`:892`):
> `FS_PROTECT_OVERRIDE` (BPF map) **gated by admin-key presentation** — "a key-authorized local
> installer may suspend `inode_protect` bait/pin denial for the duration of an install. `install.sh`
> (or a small `nn-admin install-mode` helper) presents the Ed25519 admin key; agent arms a **TTL'd**
> override covering protected-inode writes, then clears it. **Closes BUG-020.**"

BUG-013's `bootstrap.rs` gate (§4) is the already-shipped instance of this "trusted authority" pattern.

### 6.4 BUG-020 (§18, `:1021-1054`) is the live operational pain
Reinstall is denied by the pinned anti-tamper hook on bait rewrite. Tactical fix = idempotent
skip-if-identical (`install.sh:386-404`). **Residual limit (`:1051`):** a release that ships *changed*
honeypot-bait bytes still EPERMs on a running host → needs a fresh boot **or** the structural
trusted-installer. *"The structural fix is therefore not optional forever: it is the ONLY mechanism
that can apply a bait-content update on a running host."*

### 6.5 Anti-tamper deny surface — precise (what self-upgrade actually collides with)
- `inode_protect` hooks: `inode_unlink`, `inode_rmdir`, `inode_rename`, `inode_setattr` —
  **no `inode_create`** (`inode_protect.rs:13-16`). `inode_unlink`/`rename` check **both** the parent
  dir inode and the target inode (`:289-303`), so unlink/rename *inside a protected dir* is denied.
- Protected **directory** (registered as a dir inode): `/var/lib/northnarrow` (`filesystem.rs:252-272`
  + `chattr +i` `:279-288`). `/etc/northnarrow` dir is **not** registered (operators legitimately add
  files; `:64`) — only the individual files are.
- Protected **files:** `ETC_PROTECTED_FILES` (`filesystem.rs:115-130`: `admin.pub`, `agent_id`,
  `audit.log`, `agent.sig.key`, `fim-paths.{v1,local}`, `netflow-blocklist.{v1,local}`,
  `netflow-ja3-blocklist.{v1,local}`, `process-comm-allowlist.{v1,local}`,
  `netflow-comm-allowlist.{v1,local}`); `STATE_PROTECTED_FILES` (`:175-182`, the 6 `.jsonl` chains);
  `ETC_PROTECTED_TEMPLATES` (`:204-210`, the 5 `.tmpl`).
- **The systemd unit files are in none of these lists, and `/etc/systemd/system/` is not a registered
  dir** ⇒ the anti-tamper pin does **not** write-protect the unit. An in-place unit rewrite is
  **detected by FIM-009 (a verdict), not prevented by EPERM** — the opposite of the bait case.
- The bait files are pin-protected only *transitively*: the `/var/lib/northnarrow` baits via the
  protected **parent dir** (the `inode_unlink`/`rename` parent check); the `/etc/northnarrow` baits are
  **not** individually registered (`HONEYPOT_PATHS` is referenced only by `fim::rules`/`fim::honeypot`,
  never by the anti-tamper registration code) — their pin coverage is weaker than install.sh's BUG-020
  comment implies. *(Worth confirming on a host in the design phase.)*
- Agent's own writes are exempt via the `PROTECTED_PIDS` caller check (`:250-263`), and that check runs
  **after** `override_active()` — so an armed override exempts *any* writer, the caller-PID path exempts
  only the agent family.
- Catalog note `:1202`: in-place `inode_setattr` content-rewrite of a protected file currently
  **succeeds** (only FIM-observed as drift); the deny is on unlink/rename/rmdir. Latent contract
  question, noted for context.

---

## Open questions to settle in the design phase (not answered here)
1. **Window scope:** does the upgrade window need to suppress only **FIM-009** (+ FIM-023/-024 if the
   release touches units/baits), or arm `FS_PROTECT_OVERRIDE` too, or both? (A) is detection-only; (B)
   is the EPERM/pin path — a full self-upgrade likely needs both.
2. **Agent-running vs stopped during the rewrite:** FIM-009 is a *live-event* rule. A unit rewrite
   while the agent is stopped produces a ringbuf event whose fate (drained on restart vs lost) depends
   on whether the FIM events ring is pinned — not traced here; verify before relying on either.
3. **Arming path + boot-zeroing + TTL + anti-replay** for `FS_PROTECT_OVERRIDE`: adopt the
   `KILL_OVERRIDE` session-nonce pattern (§6.2) and address the still-open "zeroed on boot" caveat.
4. **`Protect*` / `*Paths` regression check:** any unit-hardening change shipped by a self-upgrade must
   be re-checked against the FIM watch set + the runtime-state write set (BUG-009/BUG-019 cluster
   pattern — a hardening directive that silently disabled a subsystem).
5. **Bait-content updates** are the residual BUG-020 case that *only* the structural trusted-installer
   can apply on a running host (§6.4).
