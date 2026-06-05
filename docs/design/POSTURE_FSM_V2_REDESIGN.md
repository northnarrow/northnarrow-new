# POSTURE_FSM_V2 — Gradient Multi-Signal Posture + Fleet-Level Architecture

**Status:** Design document. NOT implemented. No code changes accompany this doc.
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
     (lines 50-51).
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
     focal_filename=/home/forty/.claude/projects/.../subagents/agent-…jsonl
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
| **Observing** | Baseline sampling: BPF tracepoints + LSM hooks at default rate. R001-R017 verdicts fire as today. | None at posture layer. (Individual rules can still emit KillProcess verdicts per their own design — orthogonal to posture.) | n/a |
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

**End of design doc.** This is the V2 contract — open questions are
explicitly carved out and will be answered in subsequent design notes
or implementation PRs. No code in this doc.
