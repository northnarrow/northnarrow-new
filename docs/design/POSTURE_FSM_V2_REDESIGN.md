# POSTURE_FSM_V2 — Gradient Multi-Signal Posture + Fleet-Level Architecture

**Status:** Design document. NOT implemented as a whole; lot 282 (Tappa Prove P0,
04/11/2026) implemented the parts §10 describes — the mass-write arm's measure (§5.1),
the anti-tamper refusals of package transactions, and no kill on one heuristic arm
(Principle 2).
**Owner:** Phase B redesign track. Implementation scoped across beta → V1.0 → V2.0.
**Cross-refs:** `BUG-014`, `BUG-017`, `BUG-018` (see `docs/backlog/BUG_CATALOG_DESIGN.md` once
written); `Tappa 14.3` cloud-broker design (separate doc, pending).

---

## 1. Problem Statement

The current posture finite-state machine (V1) is structurally biased toward
**single-host network isolation as a first response to a single coarse
trigger**. Three classes of legitimate workload have empirically tripped the
COMBAT-tier path in this engineering cycle without the host being compromised.
Each one points at the same underlying design weakness: V1 decisions are
binary — one count crosses a threshold, one lineage walk fails to find a
binary on an allowlist — and the system has no graduated middle ground
between "watch quietly" and "isolate the box from the network."

### 1.1 V1 model as it actually exists (CURRENT)

States (`agent/src/posture/state.rs:29-44`):

```rust
pub enum PostureState {
    Observing,                                  // default
    Alerted    { since, last_trigger },
    Engaged    { since, last_trigger },
    Combat     { since, locked },
}
```

Transition rules (`agent/src/posture/transitions.rs`):

- `apply_trigger(state, trigger, now)` (line 37): only pushes posture UP.
  Trigger → target_level mapping in `common/src/posture_types.rs:79-98`.
- `Combat` branch (transitions.rs:41): explicitly terminal under automatic
  control — `// Combat is terminal under automatic control. Stay put.`
- Decay (`apply_decay`, line 96):
  - `Alerted → Observing` after `ALERTED_DECAY = 1 hour`
  - `Engaged → Alerted` after `ENGAGED_DECAY = 24 hours`
  - `Combat` does not decay — caller must invoke
    `PostureMachine::admin_release_combat_with_token` (Ed25519-signed admin
    request, single-sig today, see BUG-013).

Trigger types and their COMBAT-promotion path
(`common/src/posture_types.rs:79-98`):

- **→ Alerted**: `Reconnaissance`, `SuspiciousDns`, `SensitiveFileAccess`,
  `Lolbas`
- **→ Engaged**: `ExploitAttempt`, `AdjacentCompromise`,
  `HeavyReconnaissance`, `CriticalFileModification`
- **→ Combat**: `ConfirmedIntrusion`, `PersistenceMechanism`,
  `LateralMovement`, `ExfiltrationPattern`

Detection (`agent/src/posture/triggers.rs`):

- `ConfirmedIntrusion` fires from `confirmed_intrusion()` (line 517) on
  any of three conditions:
  1. `Event::FsProtectDenial` — any LSM-blocked tamper attempt.
  2. `Event::ProcessSpawn { filename }` or `ExecCheck` where filename
     starts with `/tmp/` or `/dev/shm/`.
  3. Mass-write: ≥ `MASS_WRITE_MIN = 20` FileOpen-with-write-flag events
     from the same PID inside a `MASS_WRITE_WINDOW_NS = 60 s` window
     (lines 50-51). (Lot 282: distinct existing files destroyed or
     replaced, not writes — §10.1.)
- The mass-write arm is gated by:
  - `ExemptPids::is_exempt` (the agent's own PID + verified watchdog PID)
  - `AuthSessionTracker::is_auth_mediated` (parent-chain walk hitting
    `AUTH_BINARY_EXES` at lineage.rs:62, e.g. `/bin/sudo`, `/usr/sbin/sshd`)
  - BUG-014 path-class carve-out (`MASS_WRITE_CARVEOUT_PREFIXES` at
    triggers.rs:82, plus operator-tunable overlay loaded from
    `/etc/northnarrow/mass-write-carveout.local`).

### 1.2 What's structurally wrong

**Bias toward COMBAT-as-first-response.** Any one of the three
`confirmed_intrusion` conditions, observed on a single event, takes posture
straight to Combat from Observing — no Alerted, no Engaged in between. The
`apply_trigger` function explicitly jumps to the trigger's `target_level`
without traversing intermediate states (transitions.rs:62-66).

**COMBAT has no automatic de-escalation.** Once isolated, the host stays
isolated until an Ed25519-signed admin release lands. On a fresh single-key
install (BUG-013) this is an unrecoverable state without operator
intervention. Combined with the bias above, a single false-positive
event can produce a single-host outage with no automatic recovery path.

**Binary heuristics are too coarse.** The mass-write arm counts file
opens. The lineage arm consults an exact-match allowlist of binary paths
(`AUTH_BINARY_EXES`). Both have already produced false positives on
legitimate workloads (Section 2). Neither has a confidence dimension —
they fire or they don't.

**Single-host worldview.** The detector decides locally with no
fleet-wide correlation. There is no mechanism to say "this signal is
seen on 1 host = possible FP; seen on 8 hosts in the same fleet = high
confidence threat." Every decision is made cold from one host's stream.

---

## 2. Evidence — Three Convergent False Positives From This Cycle

All three findings below were observed empirically and are reproducible.
Each one alone might be a single bug to patch; together they describe a
class of problem that allowlist-patching does not solve.

### 2.1 Mass-write threshold crudeness (BUG-014, fixed tactically)

PID 1 systemd, during early boot, writes to ~30+ cgroupfs control files
under `/sys/fs/cgroup/system.slice/<svc>/{memory,cpu,pids}.*` to configure
each service's resource limits. The `confirmed_intrusion` mass-write arm
counted these as ransomware-shape activity and escalated to COMBAT within
~3 seconds of agent attach.

Ground-truth attribution captured by the BUG-015 observability patch:

```
07:42:40.918  WARN POSTURE TRANSITION state=COMBAT trigger=Some(ConfirmedIntrusion)
07:42:40.775  WARN mass-write threshold crossed
              focal_pid=1  focal_comm=systemd
              focal_filename=/sys/fs/cgroup/system.slice/ssh.service/memory.zswap.max
              count_within_window=20  threshold=20
```

Tactical fix (commit `1c15300`): exclude four pseudo-FS prefixes (`/sys/`,
`/proc/`, `/run/systemd/`, `/run/log/journal/`) from the mass-write count.
This unblocks the immediate FP but does not address the root cause —
counting opens is the wrong heuristic, full stop. A different legitimate
workload (a Postgres bulk-load, an rsync, a build farm extracting a
tarball) will trip the same threshold on a different path class that is
not pseudo-FS. The exclusion list is a Band-Aid.

### 2.2 Heavy-IO dev workload — BUG-017 (mitigated by operator overlay)

The Claude Code runtime (Bun pool) writing subagent transcripts to
`/home/<user>/.claude/projects/.../subagents/*.jsonl` and tool output
streams to `/tmp/claude-1000/.../tasks/*.output` reliably exceeds
`MASS_WRITE_MIN=20` in ~3-5 seconds of agent attach during active
sessions.

```
WARN mass-write threshold crossed
     focal_pid=1112  focal_comm="Bun Pool 1"
     focal_filename=/home/<dev>/.claude/projects/.../subagents/agent-…jsonl
     count_within_window=20
```

This is benign development-tool I/O. Tactical mitigation in commit
`1c15300`: operator-tunable overlay at
`/etc/northnarrow/mass-write-carveout.local` lets the operator extend the
carve-out for trusted prefixes.

Why this generalizes: any application with bursty file I/O — Postgres,
RocksDB compaction, video encoders, `rsync`, `tar -x`, container image
unpacking — has the same shape as ransomware to a count-only detector.
The detector has no way to distinguish "20 writes of small varied
data to known dev-tool state paths by a process that has been alive
for 14 hours" from "20 writes of high-entropy 4 KB blobs to /home
documents by a freshly-spawned process that is a child of bash."

### 2.3 Lineage binary mismatch — BUG-018 (unmitigated, deferred)

SSH login of `uid=1000` user. PAM session activates `user@1000.service`
under PID 1 systemd. `systemd --user` (PID 974, `uid=1000`) is therefore
**a direct child of PID 1, NOT of sshd**. Its descendants (env
generators, dbus-daemon, xdg helpers, etc.) read `/etc/passwd` while
running as `uid=1000` during normal session setup.

The `AuthSessionTracker::is_auth_mediated` walk for any such helper
follows `helper → systemd-user (PID 974) → systemd (PID 1)`. None of
these binary paths are in `AUTH_BINARY_EXES`. Result: the read of
`/etc/passwd` is classified as "non-auth-mediated `uid=1000` sensitive
file access" → `SensitiveFileAccess` trigger → posture goes to Alerted
within ~5 s of every boot.

```
07:42:45.383  WARN POSTURE TRANSITION state=ALERTED trigger=Some(SensitiveFileAccess)
```

Naive fix — add `/usr/lib/systemd/systemd` to `AUTH_BINARY_EXES` — is
unsafe: PID 1 systemd is also at that path, so any process whose
lineage runs through PID 1 (i.e., every persistent service) would be
auth-mediated. The argv differentiator (`--user`) is not currently
plumbed into the lineage cache and is itself untrusted (argv can be
spoofed via `prctl`/`execve` setup tricks).

The deeper issue: **"is the parent in this allowlist of binaries?"** is
the wrong question. The right question is closer to **"did an
interactive operator authenticate, and is this process plausibly part of
that session's intended workflow?"** That requires more than a binary
match.

### 2.4 Convergence

All three FPs share a structure:

| | trigger | heuristic | what it actually measures | what it should measure |
|---|---|---|---|---|
| BUG-014 | ConfirmedIntrusion / mass-write | count of write-opens in 60 s | file-handle activity volume | data-mutation pattern resembling encryption |
| BUG-017 | ConfirmedIntrusion / mass-write | same | same | same |
| BUG-018 | SensitiveFileAccess | parent-walk hits a binary allowlist | "an allowlisted binary appears in ancestry" | "is this process part of an authenticated, intended session?" |

The fix for each FP individually is a list adjustment. The fix for the
*class* is to replace single-signal binary heuristics with multi-signal
confidence-scored detection, and to replace state-jumping with
graduated proportionate response.

---

## 3. Design Principles (PROPOSED — codified for V2)

These principles govern every detection/response decision in V2. They are
listed in priority order; earlier principles override later ones when in
conflict.

### Principle 1 — Gradient, not jump

V2 has four graduated states. Each higher state requires more evidence
than the previous and authorizes a more invasive response. **The system
must traverse intermediate states**; it should not jump from Observing to
Combat on a single event. Network isolation (COMBAT) is the **last
resort**, not the first response.

*Contrast with V1:* `apply_trigger` (transitions.rs:62-66) maps a single
trigger directly to its `target_level`, which can be `Combat`. V2's
transition function evaluates **accumulated multi-signal confidence**
before promoting.

### Principle 2 — Multi-signal, not single-threshold

Every escalation requires **correlation of multiple signals**, not a
single count crossing a threshold. Signals carry confidence scores; the
state machine consumes the score, not the raw boolean. (Evidence from
§2: a single count is too noisy; a single allowlist hit is too rigid.)

### Principle 3 — Proportionate response

Each state's response is **commensurate with the evidence available at
that state**:

- OBSERVING — baseline sampling. No special action.
- ENRICHED_LOGGING — *observe more* (entropy sample, process-tree track),
  no blocking action. **Buys time without harm.**
- TARGETED_RESPONSE — **kill/freeze the specific offending process and
  its file handles**, no network isolation. Hits the threat, not the host.
- COMBAT — full network isolation. Reserved for cases where targeted
  response is insufficient (e.g., the threat has spawned multiple
  processes, the agent is being actively tampered with, fleet broker
  has confirmed the IoC on N other hosts).

### Principle 4 — Automatic de-escalation

If accumulating signals do not confirm the threat within a state-specific
window, posture **drops back automatically**. V1 already does this for
Alerted (1 h) and Engaged (24 h); V2 extends the same model to **COMBAT**
(today: only admin-signed release; V2: auto-decay after a multi-signal
"all clear" window, with admin override still available for explicit
suppression).

The V1 stickiness that hurt: not Alerted (already decayed), but **Combat
locked, combined with first-event-jump-to-Combat**, which on a benign
boot produces an unrecoverable network outage. V2 closes both ends —
slower to enter Combat (Principles 1+2) and able to leave it (this
principle).

### Principle 5 — Fleet-aware (forward ref Tappa 14.3)

The local edge FSM is **informed by, but never solely dependent on**,
fleet-wide signals from the cloud broker. A signal seen on one host is
ambiguous; a signal confirmed on N hosts in the same fleet is high
confidence and reduces both detection time AND false-positive rate. This
principle is what mechanically enables "block the threat from the first
machine onward" — a CrowdStrike / SentinelOne-class capability that V1
does not provide.

Critically: **fleet-aware ≠ fleet-data-shared**. Only IoCs and behavioral
signals leave the edge; customer data does not. Section 7 details the
boundary.

---

## 4. V2 State Machine (PROPOSED)

### 4.1 States

| V1 (CURRENT) | V2 (PROPOSED) | Rationale for the rename |
|---|---|---|
| `Observing` | `Observing` | Unchanged. Baseline sampling. |
| `Alerted` | `EnrichedLogging` | V1 "Alerted" connoted a verdict; the state's actual job is **observe more** — sample entropy on writes, walk the process tree of suspects, raise sampling rate on the focal PID. The new name describes the action. |
| `Engaged` | `TargetedResponse` | V1 "Engaged" was vague. The actual response at this tier should be **specific to the offending process**: kill it, freeze its file handles, quarantine its writes. The new name says what happens. |
| `Combat` | `Combat` | Unchanged name. Semantically tightened: now last resort + de-escalable, not first response. |

### 4.2 State diagram

```
                ┌────────── timeout/no-confirmation ──────────┐
                │           (auto de-escalation)              │
                ▼                                             │
        ┌──────────────┐                                      │
        │  OBSERVING   │◀─────── timeout ──────┐              │
        │ (baseline)   │                       │              │
        └──────┬───────┘                       │              │
               │                               │              │
               │ multi-signal confidence       │              │
               │ ≥ ENRICH_THRESHOLD            │              │
               ▼                               │              │
        ┌──────────────────┐                   │              │
        │ ENRICHED_LOGGING │                   │              │
        │ (observe more —  │───── timeout ─────┘              │
        │  no blocking)    │                                  │
        └──────┬───────────┘                                  │
               │                                              │
               │ confidence ≥ TARGETED_THRESHOLD              │
               │ AND specific-process signals present         │
               ▼                                              │
        ┌────────────────────┐                                │
        │ TARGETED_RESPONSE  │                                │
        │ (kill/freeze the   │────── threat-contained ────────┘
        │  offending PID,    │       (verified absence
        │  no net isolation) │        of related signals)
        └──────┬─────────────┘
               │
               │ targeted action FAILED to contain
               │  OR multi-process/cross-host evidence
               │  OR fleet broker confirmed IoC on N peers
               ▼
        ┌──────────────────┐
        │     COMBAT       │
        │ (last resort:    │────── auto-decay after ──────────
        │  net isolation)  │       extended quiet window
        └──────────────────┘       (V2 NEW; V1 had no decay)
```

### 4.3 Up-transitions (CONCEPTUAL — thresholds in Open Questions)

| From → To | Triggering condition (V2 PROPOSED) |
|---|---|
| Observing → EnrichedLogging | Any single signal raises a `low` confidence (sensitive-file open, recon pattern, etc.). Not an escalation — a *signal to start watching closer*. |
| EnrichedLogging → TargetedResponse | Accumulated multi-signal confidence ≥ `TARGETED_THRESHOLD` AND signals attributable to a specific identified PID (or small set). E.g., entropy ≥ 7.5 bit/byte on N writes from PID P + extension-rename pattern + write target in `/home`. |
| TargetedResponse → Combat | Targeted action failed to contain (the killed PID respawned via persistence; siblings continuing the activity) OR multi-PID coordinated activity OR fleet broker corroborates the IoC on ≥ M peer hosts. |
| (any) → Combat (fast path) | Reserved for *explicit* indicators that single-host isolation is the proportionate response: confirmed anti-tamper denial of the agent's own protected files (Event::FsProtectDenial on agent state), explicit kernel-rootkit module-load completion, broker-broadcast "fleet-wide active intrusion." Single-event Combat is *exceptional*, not default. |

### 4.4 Down-transitions (CONCEPTUAL — windows in Open Questions)

| From → To | Triggering condition (V2 PROPOSED) |
|---|---|
| EnrichedLogging → Observing | No additional signals from the tracked process(es) within `ENRICH_DWELL` (proposed ≪ 1 h; V1 = 1 h is too slow for transient noise). |
| TargetedResponse → EnrichedLogging | Targeted action succeeded; tracked process and family terminated/quiescent for `TARGET_DWELL`. |
| Combat → TargetedResponse | NEW in V2: combined absence of related signals across multiple windows AND no broker-active "this fleet IoC is live." Configurable per-fleet whether Combat → TargetedResponse is automatic or requires admin co-sign. |
| Admin override | Always available: signed admin token can force any down-transition, including immediate Combat → Observing. (V1's `admin_release_combat` mechanism, unchanged shape.) |

---

## 5. Multi-Signal Detection Model (PROPOSED)

V2 replaces both V1's count-based and allowlist-based gates with confidence
scores combined from multiple signals.

### 5.1 Mass-write redesign (replaces V1 `confirmed_intrusion` mass-write arm)

V2 computes a `mass_write_confidence` ∈ [0, 1] from a weighted sum of:

| Signal | Weight (PROPOSED, see Open Questions) | Rationale |
|---|---|---|
| **Entropy of written bytes** | High | Ransomware encrypts → ~8 bit/byte. Legitimate code/text writes are far lower. A single entropy sample of a small write block is cheap. |
| **Extension-change / rename pattern** | High | `foo.docx → foo.docx.locked`, `bar.pdf → bar.pdf.<random>` are canonical ransomware shapes. `rename(2)` events feeding a per-PID extension-change-rate. |
| **Target-path class** | Medium | `/home/`, `/srv/`, `/var/`, mounted media = data targets. Pseudo-FS (`/sys/`, `/proc/`) = control, not data — currently the BUG-014 hardcoded carve-out. V2 generalizes this to a continuous "is-data-path" score. |
| **Shadow-copy / backup deletion** | High | `vssadmin delete shadows`, `wbadmin delete`, `rm` of `.snapshots/*` is a textbook ransomware precursor — preserved into Linux equivalents (BTRFS snapshot deletion, ZFS `zfs destroy`). Single-event high signal. |
| **Outbound C2-correlated** | High | Process has a recent outbound connect to a domain matching threat intel or DGA-shaped DNS. Cross-stream correlation. |
| **Process lineage trust score** | Negative weight (signal *against* threat) | Continuous score (§5.2) — a session-rooted, interactive, long-lived process is less likely to be ransomware than a fresh-spawned PID-1 child. |
| **Raw write count in window** | Low | What V1 used as its only signal. Demoted to a weak corroborator — still useful, just no longer the sole basis. |

The numeric thresholds are NOT specified in this doc — see Open Questions
§9.1.

### 5.2 Lineage redesign (replaces V1 `AuthSessionTracker::is_auth_mediated`)

V2 replaces the binary `is_auth_mediated() → bool` with a continuous
`lineage_trust_score(pid) → f32 ∈ [0, 1]`:

| Lineage shape | Score (PROPOSED) | Rationale |
|---|---|---|
| Interactive sshd → bash with controlling tty | 0.95 | Operator clearly present and authenticated. |
| `systemd-user` (uid ≥ 1000) PAM session ancestry | 0.7 | User authenticated via PAM (not necessarily via sshd directly — this is the BUG-018 case that V1 misclassifies as 0). PAM-attested. |
| `cron`/`systemd-timer` user job lineage | 0.5 | Scheduled, not interactive. Trusted by configuration, not by present operator. |
| Daemon/service with no tty, lineage rooted at PID 1 system slice | 0.3 | Could be legitimate, could be compromise persistence. Ambiguous. |
| Orphan PID, no parent, no tty | 0.1 | Suspicious; either short-lived helper or post-detach attacker code. |

This is consumed as a *signal in the mass-write confidence calculation*
(negative weight), not as a gate that suppresses the entire arm. V1's gate
behavior (suppress when auth-mediated) becomes the limit case
`mass_write_confidence(score = 1.0)` ≈ `mass_write_confidence(score = 0)
minus a constant` — never zero. This is what fixes BUG-018 without the
unsafe naive `AUTH_BINARY_EXES` widening: a `systemd-user`-rooted process
scores 0.7 (not 0), which suppresses *most* mass-write-shaped FPs but
allows the rule to still fire on genuine high-confidence multi-signal
ransomware activity from a PAM-session-rooted PID (if it ever happens).

### 5.3 Where today's R001-R017 rules fit

V1's process rules (R001 ExecFromTmp, R011 KernelModuleTooling, etc.) are
**individual signal sources**, not posture triggers in their own right.
In V2 they continue to fire as today (Kill verdicts, etc.) but they
ALSO contribute their signal to the multi-signal posture confidence. A
single R001 hit is itself low confidence at the FSM level (because exec
from /tmp is a real shape but also occurs in benign cases — pre-commit
hooks, container build helpers). Combined with high-entropy writes and
a low lineage trust score from the same PID, it pushes confidence over
the threshold.

---

## 6. Response Actions Per State (PROPOSED)

| State | Detection action | Response action | Reversibility |
|---|---|---|---|
| **Observing** | Baseline sampling: BPF tracepoints + LSM hooks at default rate. R001-R017 verdicts fire as today. | None at posture layer. (Individual rules can still emit KillProcess verdicts per their own design — orthogonal to posture. Since the decision of 03/11/2026, lot 278: R009's kill, and R001's/R003's of an exec by root, run in COMBAT only — `crates/nn-core/src/decision/posture_floor.rs`, `docs/operator/RULE_POLICY.md` §1.) | n/a |
| **EnrichedLogging** | Raise sampling rate on suspect PID(s); enable per-PID write entropy sampling; subscribe to that PID's process tree; record file handles for potential later freeze. **No blocking.** | None. Pure observability uplift. | Auto-decay to Observing after `ENRICH_DWELL`. |
| **TargetedResponse** | Continue enriched sampling on the wider tree. | Surgical, **per-process**: <br>– KillProcess (and KillProcessTree if the family is identified)<br>– Freeze file handles to prevent further writes (e.g., `kill -STOP` on the tree pending cleanup)<br>– Quarantine produced files (chattr +i / move to /var/lib/northnarrow/quarantine/)<br>– **No network isolation. No iptables.** | Auto-decay to EnrichedLogging when tracked tree is gone + quiet window. |
| **Combat** | Maximum sampling. Continuous broker push of every event signal. | Full network isolation via `NetworkIsolator::engage()` (existing V1 mechanism, unchanged shape — operator-tunable carve-out CIDRs already preserved). | Auto-decay to TargetedResponse after `COMBAT_QUIET_WINDOW` of broker-confirmed all-clear AND local quiescence. Admin override always available. |

Note: V2 explicitly **does not** auto-engage iptables on the first
high-severity rule hit. The Combat-tier action is reserved for cases
where the targeted response was insufficient OR fleet correlation has
confirmed an active threat at scale OR explicit agent-tamper signals
have fired (the cases where the host MUST be cut off because the threat
has demonstrably outrun process-level containment).

---

## 7. Fleet-Level Architecture (PROPOSED — substantial)

This section describes the cloud-broker (Tappa 14.3) component that
transforms the posture FSM from per-host to fleet-aware. The broker
itself is a separate design doc; this section covers only its
**interaction with the posture FSM** and the **data-boundary contract**.

### 7.1 Edge / cloud split

```
┌────────────────────────────────────────────────────────────────┐
│  CUSTOMER PREMISES (edge)                                      │
│                                                                │
│   Customer hosts (n)                                           │
│   ┌────────────────┐                                           │
│   │ northnarrow    │  per-host posture FSM                     │
│   │ -agent         │  local rules R001..R0NN                   │
│   │                │  in-process ADE (Foundation-Sec-8B Q4_K_M)│
│   │  uses ONLY     │  ─────────────────── boundary ────────────│
│   │  customer-     │  produces IoCs + behavioral signatures    │
│   │  local CPU     │  (hashes, IPs, TTPs) — NOT raw data       │
│   └───────┬────────┘                                           │
│           │                                                    │
└───────────┼────────────────────────────────────────────────────┘
            │
            ▼ TLS — IoCs + signals only
┌────────────────────────────────────────────────────────────────┐
│  CLOUD BROKER (EU-sovereign, operator-controlled, Tappa 14.3)  │
│                                                                │
│  - Cross-fleet IoC correlation                                 │
│  - Curated TI distribution (operator-vetted feeds)             │
│  - Per-fleet (per-customer) tenancy isolation                  │
│  - Optional deep-reasoning GPU pipeline on operator-uploaded   │
│    artifacts (NOT customer data)                               │
│                                                                │
│  Broadcasts: confirmed IoC set + recommended response level    │
│  back to all edges in the fleet                                │
└────────────────────────────────────────────────────────────────┘
```

### 7.2 Data-boundary contract (CRITICAL)

What MAY leave the edge to the broker:

- **Indicators of Compromise**: SHA-256 of suspected payload binaries,
  domains/IPs/ports of suspected C2, JA3/JA4 TLS fingerprints, mutex
  names, registry keys (where applicable), behavioral signature hashes.
- **TTPs**: MITRE ATT&CK tactic + technique IDs the local detector
  matched against.
- **Behavioral signatures**: structured digests of the posture FSM's
  observed sequence (e.g., "exec-from-tmp followed by 22-writes-high-
  entropy followed by .docx→.locked rename pattern"). These are
  hashes/labels of patterns, not contents.
- **Numeric counters**: per-trigger fire counts, per-rule verdict counts,
  posture-state dwell times.
- **Agent self-telemetry**: agent version, ADE backend ID, host_id (an
  opaque UUID generated per-install, NOT mapped to a human identifier).

What MUST NOT leave the edge:

- File contents (encrypted or otherwise).
- Process argv beyond pre-redacted IoC components (URLs/IPs OK; rest
  redacted at edge before send).
- File paths in customer-owned directories (`/home/`, `/srv/`, customer
  app data dirs) beyond the basename hash. The path's `inode-classification`
  (data vs config vs system) goes; the path string does not.
- Usernames, group names, full hostnames, IP addresses of the edge
  itself (the broker knows the edge by its host_id UUID + per-customer
  fleet ID).
- Any field whose data-protection classification per customer policy is
  "do not forward."

The edge SDK MUST enforce this boundary in code: an explicit allowlist
of fields that may be serialized into broker uplink payloads, not a
deny list. Compile-time check + runtime fuzz on the uplink path.

### 7.3 Sovereignty + legal boundary

- The broker is hosted in **EU-sovereign infrastructure** (specific
  jurisdiction TBD in Tappa 14.3). This is a positioning differentiator
  vs US-hosted EDR competitors (CrowdStrike, SentinelOne) for EU
  customers under GDPR + NIS2 + the upcoming Cyber Resilience Act.
- **Threat Intelligence Collection** (collecting IoCs/signals from the
  field for defensive purposes) is legal in IT/EU/US.
- **Hack-back** (probing/exploiting the attacker's infrastructure from
  the broker or edge) is **illegal** in IT/EU/US under unauthorized-
  access statutes (e.g., IT Codice Penale art. 615-ter; EU NIS2 doesn't
  authorize offensive action; US CFAA). The system MUST NOT perform any
  outbound interaction with attacker-attributed infrastructure beyond
  passive lookup/IOC matching.
- **Federated learning across customers** (training shared models on
  pooled customer behavioral data) is RESERVED for V2.0 as **explicit
  per-customer OPT-IN only**. V1.0 ships fleet correlation that is
  scoped to a single customer's own fleet. Cross-customer correlation
  (anonymized) is not a default — it requires written consent per
  customer.

### 7.4 How the broker informs the posture FSM

The local posture FSM consumes broker signals as additional inputs into
the multi-signal confidence calculation (§5.1), not as overrides:

- **Broker confirms IoC on N peer hosts**: contributes a positive
  weight proportional to `log(N)` peers — a signal seen on 1 host is
  ambiguous; seen on 10 hosts is high-confidence threat.
- **Broker broadcasts curated TI match**: contributes a high positive
  weight if a local observation matches an operator-vetted TI feed.
- **Broker says "fleet quiet on this IoC for T hours"**: contributes a
  *negative* weight, accelerating local de-escalation. If the rest of
  the fleet doesn't see what this host sees, it's more likely an FP.
- **Broker per-fleet posture aggregate**: visibility for operator
  dashboards; can drive operator-policy escalation (e.g., "if ≥ 30 %
  of fleet hits TargetedResponse, page on-call").

The posture FSM remains fully **operational with no broker connection**.
The broker is an *uplift*, not a dependency. Edge can detect and
respond autonomously to local threats; the broker reduces FPs and
shortens detection time at scale.

### 7.5 Impact on response policy

In V1, network isolation is per-host and reflexive. In V2 with broker:

- A signal confirmed across multiple hosts in the fleet authorizes
  **broadcast** of a *targeted* response (KillProcess of a specific
  binary hash, blocklist a specific IP) across the entire fleet —
  surgically, without isolating any single host.
- A signal confirmed on a single host triggers **escalated local
  enrichment + targeted response** on that host; other hosts go into
  EnrichedLogging proactively in case it spreads.
- Combat-tier isolation becomes one option among several: a per-host
  surgical response. Often it's not the right one — broker-coordinated
  fleet-wide IP blocklist + KillProcess on the matching binary hash is
  a stronger response that doesn't take any single host off the
  network.

This is the architectural step that delivers "block the threat from
the first machine onward" — the V1 model couldn't do this because each
edge made decisions in isolation. V2 + broker matches the
CrowdStrike/SentinelOne capability bar while keeping customer data on
the edge.

---

## 8. Migration Path (PROPOSED)

### 8.1 Ship schedule (PROPOSED — open to negotiation, see Open Questions §9.2)

**Beta (current cycle):** V1 FSM as-is, plus the BUG-014/017 tactical
fixes already in commit `1c15300`. Known issues — BUG-018, BUG-008'
TOCTOU — documented but not blocking beta acceptance. V1.0 design doc
(this) committed.

**V1.0:** V2 STATE NAMES land (rename V1 enum + serializable
`PostureKind`, behind a compatibility shim for older serialized records
— old "Alerted" deserializes to `EnrichedLogging`, etc.). V2 TRANSITION
LOGIC lands but conservatively configured: the multi-signal confidence
calculation runs and is *logged*, but the V1 single-threshold gates
are still the active arbiters. This gives a full release cycle of
ground-truth comparison data ("would V2 have escalated where V1
escalated? would it have avoided BUG-018?") before flipping the
arbiter to V2.

**V1.1:** V2 arbiter flips on. V1 gates kept as fallback for one
release in case of regression. Combat auto-decay enabled.

**V2.0:** Fleet broker (Tappa 14.3) lands. Federated learning OPT-IN
becomes available. V1 gates removed. Old `PostureKind` deserialization
shim removed (only relevant for serialized records from pre-V1.0
agents; by V2.0 those should be aged out).

### 8.2 Wire-format compatibility

`PostureKind` is serialized over the admin socket
(`common/src/posture_types.rs`, `serde::Deserialize`) and in the audit
log. V1.0 must accept old field names ("Alerted") and emit new ones
("EnrichedLogging") behind a `serde(alias = "Alerted")` for one release.
The audit log is hash-chained; existing records cannot be rewritten —
the verifier MUST handle both old and new names.

### 8.3 Operator-visible compatibility

- `nn-admin status --json` output: `posture` field accepts new names.
  Operator scripts that grep for "Alerted" need updating; provide a
  release-note migration table.
- `nn-admin force-posture`: argument names update; old names accepted
  as aliases for one release.
- The `combat-allow.cidrs` and `mass-write-carveout.local` overlay
  files are unchanged — they remain operator config, not in repo.

### 8.4 Internal API compatibility (Rust)

`PostureMachine::observe` already returns
`Option<(PostureState, Option<TriggerType>)>` (BUG-015 P-5 change). V2
extends this to surface the multi-signal confidence breakdown
(field-level, so callers can log per-signal contributions). Backward-
compatible additive change.

---

## 9. Open Questions

### 9.1 Numeric thresholds and windows

- `ENRICH_THRESHOLD`, `TARGETED_THRESHOLD`, `COMBAT_THRESHOLD` confidence
  cutoffs. Need empirical calibration on a fleet workload.
- `ENRICH_DWELL`, `TARGET_DWELL`, `COMBAT_QUIET_WINDOW` decay timers.
  V1 uses 1 h / 24 h / never; V2 windows should be shorter (minutes for
  EnrichedLogging, hours for TargetedResponse, low hours for Combat) but
  this needs to be tested against real-world quiet-after-attack data.
- Mass-write entropy threshold (~7.5 bit/byte for ransomware-shape, but
  AES-encrypted data tar.gz also hits that — need additional signals
  to disambiguate).

### 9.2 What ships when

- Beta vs V1.0 vs V2.0 division above is **proposed**; final ship
  schedule depends on Tappa-14.3 broker design timing and customer
  pilot feedback.

### 9.3 Edge CPU cost of entropy sampling

- Sampling write-block entropy is cheap per call, but if applied to
  every write event on a busy host (PostgreSQL, journald, build
  systems), it could exceed the agent's CPU budget. V1's per-event ADE
  inference budget is the comparable cost. Need a sampling strategy
  (e.g., entropy sample every Nth event per PID, with N adaptive to
  agent CPU pressure).

### 9.4 De-escalation interaction with admin acknowledgement

- Should automatic Combat → TargetedResponse decay require operator
  acknowledgement to silence (so the audit log records that an admin
  saw it)? Or is it fire-and-forget with a post-hoc dashboard
  notification? Different customers will want different defaults.

### 9.5 Broker protocol details

- Deferred to Tappa 14.3 design. Includes: uplink framing, TLS pinning,
  IoC schema, broker-to-edge broadcast format, per-fleet tenancy enforcement,
  operator dashboard schema. This doc only declares the interaction
  contract with the posture FSM (§7.4), not the wire protocol.

### 9.6 R011 PF_KTHREAD via BPF

- Already deferred to "Phase C" per session decisions. Not posture-FSM
  scope, but called out because the current P-7 fix's `/proc` TOCTOU
  surfaces as a posture-irrelevant noisy verdict — should still be
  cleaned up before V2.0 ships.

### 9.7 Federated cross-customer learning consent UX

- V2.0 OPT-IN architecture exists conceptually (§7.3). Open question:
  how customers express consent, how revocation works, how to handle
  signals already aggregated from a now-revoking customer. Legal +
  product question, separate from this design doc.

### 9.8 Backward compatibility window length

- §8.1 proposes one full release of V1-V2 dual-arbiter for empirical
  comparison. Could be shorter (one minor release) or longer (two
  releases) depending on confidence in the multi-signal calibration.

---

## 10. Implemented in lot 282 (Tappa Prove P0, 04/11/2026)

The lab of lot 279 (Ubuntu 22.04) found the ladder killing podman at a host's
first `podman pull`, and lot 282's measurement on `main` (same guest) gave the
chain, signed: `sudo podman run` (first pull) → podman's CNI firewall plugin
ran `iptables -t nat -F <its own chain>` → NN-L-EVA-002 recorded "`iptables
-F`" → `DefenseImpairment` (ENGAGED, execution evidence) in the
administrator's login scope → podman opened `bolt_state.db` 261 times in a
minute → the mass-write arm's overwrite crossing → `ConfirmedIntrusion`
(file-system evidence, root's write: privileged), corroborated by the
`DefenseImpairment` → COMBAT, locked → INVESTIGATE → jump-ahead (podman forks)
→ NEUTRALIZE killed podman's tree. On the same `main`, `apt purge podman`
reached locked COMBAT from an anti-tamper refusal of `deb-systemd-helper`
(its `rmdir` of a protected directory), and the ladder killed it. Three
changes, and one false positive of NN-L-EVA-002 fixed on the way (§10.4).

### 10.1 The mass-write arm measures what ransomware does to existing files

Ransomware rewrites or replaces many EXISTING files of a user; image, package
and build tools create many NEW files, and databases rewrite THE SAME file.
The arm counts distinct pre-existing files destroyed or replaced, never
writes. In the kernel (the file-open sensor on LSM `file_open`,
`inode_unlink`, `inode_rename`; `common/src/wire/open_sensor.rs`):

| counter | counts | once per |
|---|---|---|
| rewrites (`MASS_OVERWRITE`) | write-opens of an existing regular file of 4 KiB or more (no `FMODE_CREATED`; the size read before `O_TRUNC` empties it) | file (`OPEN_OVERWRITE_SEEN`: tgid, device, inode) per 60-s window |
| small rewrites (`MASS_OVERWRITE_SMALL`; the review of #500, C1) | the same, of any existing file that holds data: crosses when the distinct non-empty files rewritten reach the threshold before the files of 4 KiB or more alone do (a crossing of both is `MASS_OVERWRITE` alone) | file, per window |
| files written new (`MASS_WRITE`) | the first write-open of the window of a file that held no data: created by the open (`FMODE_CREATED`), or empty when opened — made by `mknod(S_IFREG)`, an `O_TMPFILE` linked in with `linkat`, an `O_RDONLY \| O_CREAT` open reopened to write (the review of #500, B1: `FMODE_CREATED` alone was evaded by all three) | file (`OPEN_OVERWRITE_SEEN`, the same map: a file counts once, as what its first write-open of the window found) |
| originals destroyed (`MASS_UNLINK`) | an unlink of a regular file that holds data (C1: it was 4 KiB or more), or held data within the window — seen non-empty at an `inode_setattr` that changes its size (`OPEN_HAD_DATA`, by inode: a `truncate` then an `unlink` is one original; the re-check of #500: a size change only, not a chmod or a `touch`) — or a rename onto the name of one (the target is destroyed); not a file the same process created within the window (`OPEN_CREATED`: its own temporary file, as `pip` and `npm` unpack), nor one in a directory whose writes do not count (the re-check of #500: a carve-out — a pseudo-filesystem, `/run/systemd`, the journal, `/run/udev` (see below), the operator's extras — or the destroyer's own runtime directory, read from the parent's `DIR_CLASS`: a daemon's atomic replacements there) | name (`OPEN_DESTROY_SEEN`: tgid, parent dentry, the name's `hash_len`) per window |

The re-check of #500 added `/run/udev/` to the carve-outs
(`triggers::MASS_WRITE_CARVEOUT_PREFIXES`), as measured: on Ubuntu 22.04
the boot's coldplug (`udevadm trigger --action=add` of every device) made
each systemd-udevd worker write 20 device database files new under
`/run/udev/data` and replace 20 old ones by a rename — the replacement
shape, ENGAGED on `systemd-udevd.service`. It is device state, not a
user's data; the udev rules that persist live in `/etc/udev` and
`/lib/udev`, which the FIM and persistence rules watch.

A repeat (the same file reopened, the same name destroyed again) is not
counted; an entry the LRU maps evicted counts again (more, never fewer). The
cgroup window (external audit EBPF-011) adds the processes' distinct rewrites.
The arm (`crates/nn-core/src/posture/triggers.rs`, `confirmed_intrusion`)
raises `ConfirmedIntrusion` on:

1. **rewrites** — at least 20 distinct existing files of 4 KiB or more
   rewritten in place by one process in 60 s, or 40 by one cgroup's
   processes (each with three or more): `MassWrite { overwrites: true }`.
   Inside an authenticated session too (external audit POS-002: encryption
   in place run from a shell). The review of #500 (C1): 20 distinct existing
   files that hold data, the smaller ones included (`MassWrite { overwrites:
   true, small_files: true }`), outside an authenticated session only —
   inside one, as before, only files of 4 KiB or more count: a build
   rewrites its own small outputs (cargo's fingerprints, `.d` files), and
   counted as ransomware in a session it reached COMBAT and the ladder
   killed cargo (lab PR 127, the reason of the 4 KiB floor).
2. **replacement** — at least 20 distinct originals destroyed and at least
   20 files written new, the two crossings within a window of each other, in
   either order (`FileBurst { kind: Unlink }` and `MassWrite { overwrites:
   false }`): the encrypted copy written and the original deleted, or the
   copy renamed onto it. The two halves pair within one process, or (the
   review of #500, C1) within one cgroup — the kernel's cgroup v2 id of each
   crossing (`OpenRecordRaw::cgroup`): an encryptor and a separate deleter (a
   helper, an `rm` it runs, a second worker of the unit or the container). A
   half of an exempt writer, or of a process of an authenticated session,
   pairs only within its own process; the root cgroup (no hierarchy in use)
   pairs nothing. Outside an authenticated session (a session's new files
   never counted, and a checkout or an archive extracted over a tree from a
   shell is this shape).

and never on files created alone (an image pulled, a clone, an archive
extracted, a build, a cache filled), one file rewritten again and again (a
database, a state file), or originals deleted alone (`rm -rf`, a purge, a
cache sweep). In tracepoint mode (no LSM sensor; every open reaches userland,
whether its file existed is unknown, and no unlink is seen) the arm counts
the distinct files a process opened to write — an open that must create its
file (`O_CREAT | O_EXCL`) included (the review of #500, C1: a copy-and-delete
encryptor's copies; tracepoint mode cannot tell them from an extraction, so
an extraction outside a session raises the arm there, ENGAGED, as on
`main`) — and inside a session no open that may create one does.
Every shape is file-system evidence (`triggers::evidence_class`): no shape of
the arm corroborates another, nor the ransomware tracker's
`RansomwareEncryption` (file-system evidence too).

The firing set stays within the old one: a rewrite crossing needs 20
distinct files where it needed 20 opens (and a small-file crossing 20
distinct files that `main` counted as 20 write-opens outside a session); a
replacement needs the crossing of files written new that alone used to fire
(each of them a write-open `main` counted). A replacement paired in a cgroup
raises the arm on the later half's process — the deleter's burst, say —
where `main` raised it on the encryptor's own crossing, within the same
window. One corner goes further (the review of #500, N4): the exempt writers
are judged on the path of the replacement's crossing, the destroyed file's
for a deletion, where `main` judged the written file's — a writer exempt in
its own storage and not outside it may raise the arm where `main` did not;
the safe direction. The ransomware simulation's shapes still fire it (in
place: 300 distinct files rewritten; copy-delete: 300 originals destroyed
beside 300 new files), and so do its variants of the review of #500 (§10.6).

The writers the arm exempts are kept, each for the shape that still counts
it (and an exempt crossing is now recorded at INFO with the exemption that
answered): a package transaction (it replaces the files it upgrades), the
man-db cache rebuild as a system account (it replaces each locale's
`index.db` by a rename), npm's CLI (`npm ci` deletes `node_modules` and
extracts it again) and a user's package manager in that user's container
storage. None is by name or path alone.

The kernel counters feed the ransomware tracker too (`crates/nn-core/src/impact`):
its (a) rewrites are distinct files of 4 KiB or more (a small-file crossing
is no shape (a): the tracker's verdict is decisive, and a build rewrites its
own small outputs), its (d) "deletion of originals after writing new files"
reads files written new (not every write-open; whatever made them: B1) —
and (the re-check of #500) the small-file rewrite crossing too: a copy
made by `mknod` and brought to one byte by `truncate(2)` before it is
written is a small rewrite to the kernel, a file written all the same;
the copies beside the deleted originals and their content decide — and
originals of any size that held data, and counts a rename onto an
original as its deletion. What it does not see is said in §10.5.

### 10.2 An anti-tamper refusal of a package transaction never corroborates

A refusal is signed (NN-L-AT-001) and the kernel already blocked it. When the
refused process belongs to a package transaction — a package manager proper
(`PACKAGE_MANAGER_EXES`: dpkg, apt, rpm, dnf, …) executed by root whose run
covers the refusal, judged as R009 and the FIM rules judge it
(`AuthSessionTracker::in_package_transaction`) — it raises
`PackageTamperRefusal`: ALERTED, kernel evidence, never written to the
corroboration ledger (an ALERTED-tier trigger never is), never decisive,
never locking — for the refused operations a maintainer script does on the
file namespace only (the review of #500, B2: `unlink`, `rmdir`, `rename`,
`setattr`, `create`, `link`, `symlink`, `mkdir`, `mknod`, an extended
attribute; `triggers::is_package_file_operation`). Any root process makes
itself a "transaction" without pretending anything — `apt-get -o
APT::Update::Pre-Invoke::=<cmd> update`, `DPkg::Pre-Invoke`, `rpm --eval
'%(cmd)'`, a dpkg run with `LD_PRELOAD`, and every child of `snapd` and
`packagekitd`, which run for as long as the host does — so a refused signal,
ptrace, BPF map or link handle, kexec, cgroup write, resource limit,
scheduling change, read of the signing key, write-open, `ioctl` or
`oom_score_adj` write keeps the weight it has outside one (`AntiTamperDenial`,
decisive, COMBAT locked; `DefenseImpairment` for a scheduling change;
`SensitiveFileAccess` for the read). A refusal of any other process keeps
today's weight; PID 1's relayed signal stays `RelayedTamperAttempt`.
Residual: a root process inside a package transaction — a malicious
package's maintainer script, or any root command run as an apt hook — whose
file operation on the agent's files is refused (the kernel blocks it, the
record is signed) no longer brings COMBAT by itself.

### 10.3 COMBAT never kills on one heuristic arm

Principle 2 at the point of the kill: the ladder's NEUTRALIZE does not kill,
quarantine or isolate when the episode's cause is a heuristic
(`Confidence::NeedsCorroboration`) that no signal of another kind of evidence
vouches for (`CombatCause::single_heuristic_arm`: nothing, or only repeats of
its own kind — the sustained knob). It signs a `combat_stage` row "NEUTRALIZE
held … one heuristic arm …" and does not escalate to ISOLATE (the offenders
were spared by choice, not found uncontainable). The posture already reaches
COMBAT on a heuristic only with a signal of another class in the actor's
scope (BUG-032, POS-001), so the hold is the ladder's own check of that rule:
the mass-write arm alone, however often and in whatever shape, stops at
ENGAGED and never reaches the ladder (golden case
`mass-write-arm-alone-engaged`). Corroboration stays per actor scope (§10.5).

### 10.4 NN-L-EVA-002: a container runtime flushing its own chain

What a flush of one named chain (`iptables -F <chain>`, `--flush`) is depends
on the chain's function and on who flushes it (the coordinator's review of the
design):

- the chains of the container runtimes and orchestrators — `CNI-…`,
  `DOCKER…`, `KUBE-…`, `cali-…`, `cilium_…`, `NETAVARK…` — but the filter
  chains they create (`DOCKER-USER` and, the review of #500, `CNI-ADMIN`:
  the administrator's rules for the containers' traffic; `KUBE-FIREWALL`:
  the drop of marked packets, the guard of `route_localnet`), which no
  runtime empties —
  flushed by the runtime itself are its own networking at work, not a
  firewall switched off: the `iptables`'s parent is a runtime program (a CNI
  plugin of `/usr/lib/cni` or `/usr/libexec/cni`, `dockerd`, `podman`,
  `netavark`, `containerd`, `crio`, `kubelet`, `kube-proxy`), judged on what
  the kernel executed, in a system tree and installed by a package — never a
  name or a path alone;
- the same chains flushed by any other process (a shell, an unpackaged
  plugin in `/opt/cni/bin`, k3s's bundled tools), the filter chains above
  flushed by anyone, and every other chain — the host firewall's (ufw's
  `ufw-…`, fail2ban's `f2b-…`, firewalld's zones), a built-in one, every
  chain of a table — stay the firewall switched off.

Residual: kube-proxy, Calico and Cilium run in containers on most clusters;
their executables are no package of the host, so their flushes stay records.
A root process can make a packaged runtime its parent (`LD_PRELOAD` into
dockerd or podman, a ptrace) and flush a runtime's chain without a record:
an accepted residual of a heuristic, the filter chains excluded.

### 10.5 What stays as it was, said explicitly

- **Copy then delete from a login session.** The replacement shape (§10.1,
  rule 2) counts outside an authenticated session only, as new files never
  counted inside one (POS-002). Ransomware run from an SSH shell that writes
  encrypted copies and deletes the originals does not pass through the
  mass-write arm: the ransomware tracker (lot 225, NN-L-IMP-001 and the
  posture's `RansomwareEncryption`) judges it, by the copies' content and
  names — copies written new, or (the re-check of #500) copies sized to
  one byte before they are written. Encryption in place from a session
  still raises the arm (rule 1), for files of 4 KiB or more: small
  documents encrypted in place from a session do not (as on `main`; the
  tracker sees them by their renames; a session threshold of its own for
  small rewrites is to be measured on a development corpus first: lot
  283).
- **What the arm does not see (the review of #500, C1), and who does.**
  - Originals deleted more than 60 s after the copies were written (the
    halves pair within one window, either order). NN-L-IMP-001 pairs its
    shapes within 120 s; past that, nothing.
  - An encryptor and a deleter in different cgroups (the deletion handed to
    another unit, a cron job, a `systemd-run`), or a deleter forked once per
    file (each process under 20 originals): the copies' crossing alone is no
    shape. `main` raised the arm on the encryptor's 20 write-opens; the
    tracker's (d) needs the deleter to descend from the encryptor.
  - Writers forked once per file (each under 20 files written new or
    rewritten) and a slow encryptor (under 20 files a minute): as on `main`,
    the counters are per process (the cgroup window adds rewrites of 4 KiB
    or more only).
  - A truncated original whose `OPEN_HAD_DATA` entry was evicted (more than
    4,096 files truncated in the window — since the re-check of #500 a
    chmod, a chown or a `touch` no longer marks a file): its unlink counts
    nothing, as it did.
  - Tracepoint mode: the arm counts files written, no replacement shape, and
    the tracker is blind (no `MassWrite`, no `FileBurst`).
  - NN-L-IMP-001 itself: (a) counts rewrites of files of 4 KiB or more only;
    (b) measures entropy over the bytes it reads, and a file of a few
    hundred bytes of random data measures under 7.5 bits per byte (the
    signal needs about 1 KiB of ciphertext); (d) needs the deleter to be the
    writer's actor (the nearest foreign program of its lineage). Small
    documents encrypted in place are the tracker's by (c), their renames to
    a new extension, with (b) where they hold a kilobyte or more.
- **The kernel windows evict.** The per-process windows (`OPEN_WRITES`,
  `OPEN_UNLINKS`: 4,096 processes, LRU, as before the lot) restart a
  process's counts when another 4,096 processes write or delete within its
  window: fewer, not more. The lot's maps evict the other way — a file or a
  name seen again counts again (`OPEN_OVERWRITE_SEEN`, `OPEN_DESTROY_SEEN`),
  a process's own temporary file forgotten counts as an original
  (`OPEN_CREATED`) — save `OPEN_HAD_DATA`, above. Documented, not changed:
  4,096 writers in a minute is a host under a fork storm, which other
  signals see.
- **Corroboration is per actor scope, not per process tree** (future work).
  A signal of one process of a login session or a workload vouches for
  another process of the same scope, as the lab's `iptables` (podman's CNI
  plugin, under `sudo`) vouched for rootless podman's mass write. The
  NEUTRALIZE hold of §10.3 judges the cause's evidence classes, not which
  process raised them.

### 10.6 The review of #500: the kernel's cost, and the variants measured

The counters' maps, LRU hashes preallocated by the kernel:
`OPEN_OVERWRITE_SEEN`, `OPEN_DESTROY_SEEN` and `OPEN_CREATED`, 16,384
entries each (key 24 bytes, value 8), and `OPEN_HAD_DATA`, 4,096 (key 16,
value 8). Per call, a write-open of a regular file now looks its file up in
`OPEN_OVERWRITE_SEEN` (and inserts it, once per window) whatever it found
— a file written new included — and a creation inserts into
`OPEN_CREATED`; an unlink, or a rename onto an existing name, reads the
inode's key and looks it up in `OPEN_CREATED` (and, for an empty file, in
`OPEN_HAD_DATA`), then its name in `OPEN_DESTROY_SEEN`; a setattr of a
regular file that holds data inserts into `OPEN_HAD_DATA`. The re-check of
#500 made three of these cheaper (measured below): a creation inserts into
`OPEN_OVERWRITE_SEEN` without looking it up (a new inode); an unlink or a
rename reads its directory's class first (`DIR_CLASS`, a lookup; the walk
on a miss) and stops in a carve-out; a setattr reads the `iattr`'s
`ia_valid` and marks a size change only. Measured on our
own lab guests (4 vCPU, QEMU; the kernel's BPF statistics on for the bench
only, `run_time_ns / run_cnt` of each program over 20,000 operations on
files of 1 KiB; `main` a97d5ff2 against the lot on the same Ubuntu 22.04
guest, 5.15):

| operation (program) | `main`, ns a call | the lot, ns a call | the bench's operation, `main` → the lot |
|---|---:|---:|---|
| a file created (`fim_file_open_sensor`) | 516 | 1,568 | 27.2 → 31.3 µs |
| an existing file rewritten, again (`fim_file_open_sensor`) | 320 | 347 | 3.26 → 3.16 µs |
| an unlink (`fim_unlink_observe`) | 270 | 1,147 | 8.9 → 10.1 µs |
| a rename onto an existing file (`fim_rename_observe`) | 2,728 | 5,657 | 102 → 115 µs |
| a chmod (`fim_setattr_observe`) | 115 | 351 | 2.13 → 2.35 µs |

`main`'s unlink of a file under 4 KiB returned at the size check; the lot
counts it. On Ubuntu 24.04 (6.8, the lot only): 1,859, 664, 1,990, 7,342
and 916 ns. Memory, as 6.8 accounts it (`bpftool map show`, `memlock`):
1,573,952 bytes for each map of 16,384 entries and 361,536 for
`OPEN_HAD_DATA` — about 5.1 MB together (5.15 reports page estimates, 512
KiB and 96 KiB). The LRU lists are the maps' common ones; a per-CPU list
(`BPF_F_NO_COMMON_LRU`) would take the lock off a creation burst's path,
not evaluated here. The verifier: on 5.15 `fim_file_open_sensor` 4,379
instructions, `fim_unlink_observe` 2,360, `fim_rename_observe` 6,270,
`fim_setattr_observe` 1,008; on 6.8 the same, with 104,758, 9,038, 129,370
and 1,220 instructions verified; every program loads on both. The
variants of the review — small documents encrypted in place, small
documents copied then deleted, an encryptor whose originals another
process of its unit deletes — reach ENGAGED on `main` and on the lot
(`ransom-check`, MS-23): on the lot the arm raises each (the small-file
crossing, the replacement, the replacement paired in the unit's cgroup).

After the re-check of #500 (the same bench; one round per guest, each
build installed in turn on the same guest — on 22.04 `main` b000a814, the
head the re-check read, dd870a16, and the lot's 79ca9ab3; on 24.04 the
latter two), ns a call:

| operation (program) | 22.04 `main` | 22.04 before → after | 24.04 before → after |
|---|---:|---:|---:|
| a file created (`fim_file_open_sensor`) | 500 | 1,158 → 1,144 | 2,838 → 1,799 |
| an existing file rewritten, again | 291 | 311 → 325 | 799 → 684 |
| an unlink (`fim_unlink_observe`) | 270 | 1,052 → 1,194 | 2,283 → 1,908 |
| a rename onto an existing file | 2,556 | 5,165 → 5,033 | 8,885 → 8,179 |
| a chmod (`fim_setattr_observe`) | 117 | 351 → 134 | 930 → 353 |

The chmod is back to `main`'s cost (a size change only marks a file). The
creation's skipped lookup is within the rounds' spread; the unlink in a
directory that is no carve-out pays the class lookup (about 140 ns on
5.15), and in a carve-out stops before every map (daemons' atomic
replacements under `/run/systemd`; not in the bench). 24.04's "before"
ran while the 22.04 guest was busy on the same host (its operations took
twice as long): its differences are no measure of the change. The
verifier after the re-check: `fim_unlink_observe` 3,331 instructions
(57,674 verified on 6.8: the directory's class, the walk on a miss),
`fim_rename_observe` 7,241 (178,006), `fim_setattr_observe` 1,072 (1,278),
`fim_file_open_sensor` 4,379 (104,801); every program loads on 5.15 and
6.8. MS-23 with the presized copies (made by `mknod`, truncated to one
byte, written, the originals deleted): ENGAGED and NN-L-IMP-001 on
`main` and on the lot, both guests.

---

**End of design doc.** This is the V2 contract — open questions are
explicitly carved out and will be answered in subsequent design notes
or implementation PRs. No code in this doc.
