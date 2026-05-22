# Tappa 9.5.1 — Anti-Tamper Honeypot Design

**Status:** RFC RESOLVED 2026-05-22 (all 5 items owner-accepted verbatim
+ implementation guidance — see §6). Step 3 (D1–D4) unblocked pending
go-ahead.
**Branch:** `tappa9-5-1-design` → `tappa9-5-1-rfc-resolution`.
**Sequencing:** ships between the T10.6 close and the T10.7 V2 Kali
execution, so honeypot trips during adversarial validation become
first-class validation data.

---

## 1. Scope & goals

### 1.1 Goals

Deploy a small set of **NN-internals honeypot files** — inert bait whose
*names* mimic NorthNarrow agent control points (kill switches, maintenance
flags, override tokens). They are never read by the agent and never
touched by any legitimate operator workflow, so **any** modify / delete /
create against them is, by construction, an adversary probing for a way
to disable NN. Such a tamper fires the new Critical rule
**NN-L-FIM-024 (AntiTamperHoneypotModified)** → `KillProcessTree` →
posture **COMBAT**.

This is a *transparent* honeypot pattern: the decoys, their paths, and
their behaviour are fully documented for the operator (§4). It is **not**
a hidden "ghost mode" — owner-confirmed scope.

### 1.2 Threat model

Mid-tier *targeted* attackers who have done homework on NorthNarrow and,
post–initial-access, go looking for the agent's off-switch: a config
flag, a kill-switch file, a maintenance/disable token, a legacy config
path. A real such control point would be a single point of failure; the
honeypot turns that reconnaissance step into a high-confidence detonation.
MITRE: **T1562.001** (Impair Defenses: Disable or Modify Tools).

Out of scope: attackers with kernel-level code-exec (already covered by
the T7 6-layer anti-tamper / LSM enforcement); insider operators with
the signed admin key; behavioural mimicry of NN beyond filename bait.

### 1.3 Builds on

- **T7 anti-tamper** — LSM enforcement, watchdog, heartbeat,
  tamper-evident logs; the agent + watchdog PIDs live in `PROTECTED_PIDS`.
- **T9.5 Deception Layer** — canary registry, `WATCHED_PATHS` FIM
  inode-watch plumbing, the Critical→COMBAT posture path, and the
  privileged-e2e harness for tamper reproduction.

Distinction from T9.5 canaries: T9.5 canaries bait *data* (credential
stores) and are operator-deployed, tracked rows. T9.5.1 honeypots bait
*NN's own control surface*, are install-time static, and are matched by a
dedicated FIM **path** rule (not the canary registry).

---

## 2. Honeypot file inventory

Filenames suggest an NN control function; contents are inert (§4).
The agent never opens these paths; no documented operator task writes them.

| Path | Suggested (fake) function |
|------|---------------------------|
| `/etc/northnarrow/agent.dev.lock` | "developer lock" preventing enforcement |
| `/etc/northnarrow/kill_switch.conf` | global kill switch |
| `/etc/northnarrow/maintenance.mode` | maintenance bypass |
| `/etc/northnarrow/debug_disable.flag` | disable-on-debug flag |
| `/etc/northnarrow/agent.legacy.conf` | "legacy" config path |
| `/var/lib/northnarrow/shutdown.signal` | graceful-shutdown signal file |
| `/var/lib/northnarrow/disable.token` | enforcement-disable token |
| `/var/lib/northnarrow/override.config` | policy override |
| `/run/northnarrow/pause.flag` | runtime pause |
| `/run/northnarrow/unload.signal` | LSM-unload signal |

10 baits across the three dirs an attacker would inspect for NN state
(`/etc` config, `/var/lib` state, `/run` runtime). The set is deliberately
small and high-signal; it can grow in a follow-up without a rule change
(the rule matches a path prefix set, §3).

**Naming discipline:** none of these collide with a *real* NN file. Real
control paths (e.g. the admin socket, `agent_id`, signing key, registry
files) are passed by explicit flags and live elsewhere; the honeypot
names are plausible-but-unused. A pre-merge check (§5) asserts no
honeypot path equals a real configured path.

---

## 3. Detection rule — NN-L-FIM-024

```
id:       NN-L-FIM-024_AntiTamperHoneypotModified
name:     Anti-tamper honeypot file tampered
category: fim_anti_tamper
severity: Critical
action:   KillProcessTree
posture:  → COMBAT   (FSM maps Critical → COMBAT, as FIM-021/022)
MITRE:    T1562.001 (Impair Defenses: Disable or Modify Tools)
```

Shape mirrors `NnLFim021PamModuleModified` (`agent/src/fim/rules.rs`):

```rust
fn evaluate(&self, event: &Event) -> Option<Verdict> {
    let fe = as_fim(event)?;
    // Create / Modify / Delete / Rename — ANY mutation is hostile.
    if !matches!(fe.op, FimOp::Created | FimOp::Modified
                       | FimOp::Deleted | FimOp::Renamed) {
        return None;
    }
    if !HONEYPOT_PATHS.iter().any(|p| fe.path == *p) {
        return None;
    }
    // Secondary self-guard (see "exclusion" below).
    if fe.modifier_pid == own_pid { return None; }
    Some(fim_verdict(self, fe, ResponseAction::KillProcessTree,
                     Severity::Critical,
                     "Anti-tamper honeypot file tampered — adversary \
                      probing for an NN off-switch (T1562.001); kill \
                      tree + posture → COMBAT"))
}
```

Note vs the other FIM rules: FIM-024 trips on **Deleted/Renamed too**, not
just Create/Modify — deleting a (fake) "lock" file is exactly the
disable attempt we want to catch.

**Exclusion — `modifier_pid == own_pid`.** Largely free already: the
agent + watchdog PIDs are in `PROTECTED_PIDS`, and the C2 BPF layer
exempts `PROTECTED_PIDS` callers from emitting adversary FimEvents
(`fim/drain.rs`, `fim/rules.rs:565`). The install/uninstall writes are
done by `install.sh` (a *separate*, pre-agent process) during deploy, not
in steady state. The rule-level `modifier_pid == own_pid` check is a
belt-and-suspenders guard for the only steady-state writer that could be
the agent itself: an optional startup integrity refresh (Q5). Requires
threading the agent's own PID to the rule (it is already known —
`std::process::id()` at boot, main.rs:555).

---

## 4. Deployment integration

- **Generation:** `deploy/install.sh` creates the 10 bait files (and the
  `/run/northnarrow` dir, tmpfs-backed → recreated each boot by a
  systemd `tmpfiles.d` entry or an `ExecStartPre`).
- **Contents:** realistic config-style — a header comment + dummy
  key=value lines — so a casual `cat` looks like a real NN control file
  (final style is **Q1**). Inert: parsed by nothing.
- **FIM paths:** the 10 paths are appended to `configs/fim-paths.v1`
  under a new `# Anti-tamper honeypots (NN-L-FIM-024 — T1562.001)`
  section, so they land in `WATCHED_PATHS` at boot (same plumbing as
  FIM-015..023).
- **Operator docs:** `docs/operator/` page documenting the pattern, the
  exact paths, "do not touch", and the expected COMBAT response
  (placement is **Q3**).

---

## 5. Testing strategy

**Unit (`agent/src/fim/rules.rs` tests):**
- FIM-024 fires (Critical + KillProcessTree) on Create / Modify / Delete /
  Rename of each of the 10 honeypot paths.
- Does **not** fire on a non-honeypot path under the same dirs.
- Does **not** fire when `modifier_pid == own_pid`.
- Static assertion: no honeypot path equals any real configured NN path.

**Startup integrity check (`HoneypotIntegrityCheck`, Q5):**
- All 10 present → `Honeypot integrity: 10/10 present` at Info, no alert.
- A missing bait → Medium alert + recreate-from-template; the recreate
  (agent in `PROTECTED_PIDS`) does NOT fire FIM-024.

**Privileged e2e (`detection_rules_at_scale_privileged_e2e.rs` family):**
- Tamper each honeypot file from an *external* process (not in
  `PROTECTED_PIDS`); assert the `NN-L-FIM-024` Critical verdict, the
  `KillProcessTree` action, and the `POSTURE TRANSITION COMBAT` line.
- Boot with a deleted bait → assert the Medium `HoneypotIntegrityCheck`
  alert + recreation, and that recreation does not self-trigger FIM-024.
- Reuse the existing `EniIptablesGuard` (COMBAT installs the
  `NORTHNARROW_COMBAT` chain) and the bounded-acceptor / off-`/tmp`
  install conventions established in T10.6 D9.

**Workspace impact:** engine 67 → 68 rules; FIM family 23 → 24.

---

## 6. RFC resolutions

All 5 RFC items resolved 2026-05-22 — owner accepted every engineering
recommendation verbatim, plus the implementation guidance folded in
below (bait content template, per-file content, the
`HoneypotIntegrityCheck` startup event). Step 3 (D1–D4) unblocked pending
go-ahead. Each block: **Decision**, **Rationale**, **Implementation
note** (where it manifests in this doc / commit plan), **Reversibility**.

### Q1 — Bait file content style

- **Decision:** REALISTIC CONFIG-STYLE. Each bait carries a header
  comment + dummy `key=value` lines whose fields *suggest its function*,
  per this template (values are inert — parsed by nothing):

  ```
  # NorthNarrow Agent - {Purpose} Configuration
  # {Plausible description}
  # WARNING: modifying this file requires admin authorization
  {key}={value}
  last_modified={timestamp}
  ```

  Content is **unique per file** and themed to the fake function — e.g.
  `kill_switch.conf` → `enabled=` / `signature_required=`;
  `maintenance.mode` → `scheduled_window=` / `disable_until=`;
  `disable.token` → a dummy token-shaped value; etc. The goal is to
  *incentivise the attacker to edit* it, believing they've found the
  kill mechanism — which detonates FIM-024.
- **Rationale:** plausible config invites the edit that detonates; random
  bytes or a magic header smell like a trap or fingerprint the decoy.
  No field may hint "honeypot".
- **Implementation note:** §4 content generation; templates live with
  `install.sh` (D2). A static test asserts no bait content leaks the
  word "honeypot"/"decoy"/"canary".
- **Reversibility:** easy — content is install-time only; restyling is a
  template edit + re-deploy, no rule change.

### Q2 — ADE second opinion for NN-L-FIM-024

- **Decision:** NO ADE second opinion. Deterministic
  Critical/KillProcessTree on the rule alone.
- **Rationale:** a honeypot path has **zero** legitimate writers by
  construction → false-positive rate ~0, so the deterministic action is
  both correct and faster than an ADE round-trip. (Contrast FIM-021: real
  package updates can touch PAM `.so`, where ADE adds nuance.) ADE may
  still annotate the emitted verdict post-hoc for the analyst, but must
  not gate the response.
- **Implementation note:** §3 — `evaluate` returns the verdict directly;
  no `process_template` / ADE hook on this rule (consistent with the
  T10.6 D7 process_template deferral rationale — ADE only where it
  changes the action).
- **Reversibility:** easy — adding an ADE annotation later is additive
  and non-gating.

### Q3 — Customer-visible documentation placement

- **Decision:** DEDICATED `docs/operator/anti-tamper-honeypots.md`,
  linked from the install README.
- **Rationale:** the "do not touch these paths / touching them triggers
  COMBAT + KillProcessTree" warning is operationally load-bearing and
  must be findable, not buried in a README paragraph. Transparency is
  the design's premise (§1).
- **Implementation note:** §4 + D4. Page lists all 10 paths, the inert
  nature, and the expected response; README gains a one-line link.
- **Reversibility:** trivial.

### Q4 — COMBAT on first trigger vs N-in-window

- **Decision:** COMBAT on the FIRST trigger.
- **Rationale:** no benign honeypot access exists to debounce — one
  tamper is already high-confidence hostile intent; an N-in-window gate
  only buys the attacker dwell time. Consistent with FIM-021/022
  first-trip COMBAT.
- **Implementation note:** §3 — the rule emits Critical on the first
  matching `FimEvent`; the posture FSM's existing Critical→COMBAT arm
  does the transition (no new windowing state).
- **Reversibility:** easy — a windowed variant could wrap the rule later
  via the correlation store if policy ever wants it.

### Q5 — Startup bait-file integrity check

- **Decision:** YES — verify-and-alert + auto-recreate. A new
  **`HoneypotIntegrityCheck`** event (Medium severity) runs in the agent
  startup sequence **after BPF programs attach**:
  - stat all 10 baits;
  - **missing** file → log + recreate from its template + emit a Medium
    alert (a pre-agent-boot deletion is itself a tamper signal);
  - **all present** → log `Honeypot integrity: 10/10 present` at Info.
  Auto-recreation is performed by the agent, which is in `PROTECTED_PIDS`
  → the recreate write does not emit an adversary `FimEvent` and cannot
  self-trigger FIM-024 (the §3 `own_pid` rule guard backstops it).
- **Rationale:** fire-and-forget would let an attacker who deletes a bait
  *before* the agent starts go unnoticed; the boot check converts that
  into a Medium signal while restoring the trap.
- **Implementation note:** §5 startup sequence; new event type +
  Medium-severity emit path (D1/D2). Distinct from the steady-state
  FIM-024 Critical rule — this is a one-shot boot baseline.
- **Reversibility:** easy — the check is self-contained at boot; can be
  gated behind a config flag if an operator ever wants it off.

---

## 7. Effort estimate (post-ruling, indicative)

| Step | Scope |
|------|-------|
| D1 | `NnLFim024` rule + `HONEYPOT_PATHS` + own-pid thread + unit tests |
| D2 | per-file bait templates + `install.sh` generation + tmpfiles.d for `/run`; `fim-paths.v1` section; `HoneypotIntegrityCheck` boot event (Medium, verify+recreate) |
| D3 | privileged-e2e (external tamper → Critical + KillProcessTree + COMBAT; deleted-bait boot → Medium alert + recreate) |
| D4 | `docs/operator/anti-tamper-honeypots.md` + install README link |

Each gated by the cardinal rule (no priv-e2e committed without a verified
PASS). Builds on T9.5 (`TAPPA9_5_DECEPTION_LAYER_DESIGN.md`).
