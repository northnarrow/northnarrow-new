# Tappa 9.5.1 — Anti-Tamper Honeypot Design

**Status:** RFC OPEN (Q1–Q5 await owner ruling — see §6).
**Branch:** `tappa9-5-1-design`.
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

**Privileged e2e (`detection_rules_at_scale_privileged_e2e.rs` family):**
- Tamper each honeypot file from an *external* process (not in
  `PROTECTED_PIDS`); assert the `NN-L-FIM-024` Critical verdict, the
  `KillProcessTree` action, and the `POSTURE TRANSITION COMBAT` line.
- Reuse the existing `EniIptablesGuard` (COMBAT installs the
  `NORTHNARROW_COMBAT` chain) and the bounded-acceptor / off-`/tmp`
  install conventions established in T10.6 D9.

**Workspace impact:** engine 67 → 68 rules; FIM family 23 → 24.

---

## 6. RFC items (await owner ruling — Step 2 resolves)

Each item lists the engineering recommendation; **not** a resolution.

### Q1 — Bait file content style
Realistic config-style (header comment + dummy `key=value`) **vs** random
bytes **vs** a magic header.
**Recommendation: realistic config-style.** A targeted attacker who
`cat`s `kill_switch.conf` and sees plausible config is more likely to
*edit* it (detonation) than one who sees random bytes (smells like a
trap). Magic headers risk fingerprinting the decoy. Keep contents inert
and free of any value that hints "honeypot".

### Q2 — ADE second opinion for NN-L-FIM-024
**Recommendation: NO ADE second opinion** (deterministic action
sufficient). Unlike FIM-021 (PAM `.so`, where a rare legitimate package
update can touch the path and ADE adds nuance), a honeypot path has
**zero** legitimate writers by construction — the false-positive rate is
~0, so a deterministic Critical/KillProcessTree is correct and faster.
ADE enrichment can still annotate the verdict post-hoc for the analyst,
but should not gate the response.

### Q3 — Customer-visible documentation placement
**Recommendation: dedicated `docs/operator/anti-tamper-honeypots.md`**,
linked from the install README. The "do not touch these paths / touching
them triggers COMBAT" warning is operationally load-bearing and deserves
a findable page rather than a buried README paragraph.

### Q4 — COMBAT on first trigger vs N-in-window
**Recommendation: COMBAT on the FIRST trigger.** There is no benign
honeypot access to debounce — a single tamper is already high-confidence
hostile intent. N-in-window only adds dwell time for the attacker.
(Consistent with FIM-021/022 first-trip COMBAT.)

### Q5 — Startup bait-file integrity check
**Recommendation: YES, verify-and-alert (not silent re-create).** On
agent boot, stat all 10 baits; if any is **missing**, that itself is a
tamper signal (an attacker who deleted a bait before the agent started),
so emit a Medium "honeypot baseline incomplete" alert and re-create it.
Re-creation is done by the agent (in `PROTECTED_PIDS`), so it cannot
self-trigger FIM-024 — this is the case the §3 `own_pid` guard backstops.
Fire-and-forget would let pre-boot deletion go unnoticed.

---

## 7. Effort estimate (post-ruling, indicative)

| Step | Scope |
|------|-------|
| D1 | `NnLFim024` rule + `HONEYPOT_PATHS` + own-pid thread + unit tests |
| D2 | `fim-paths.v1` section + `install.sh` bait generation + tmpfiles.d for `/run` |
| D3 | privileged-e2e (tamper → Critical + KillProcessTree + COMBAT) |
| D4 | `docs/operator/` page + install README link |

Each gated by the cardinal rule (no priv-e2e committed without a verified
PASS). Builds on T9.5 (`TAPPA9_5_DECEPTION_LAYER_DESIGN.md`).
