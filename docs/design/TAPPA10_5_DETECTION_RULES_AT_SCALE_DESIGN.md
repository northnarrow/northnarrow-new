# Tappa 10.5 — Detection Rules at Scale Design

**Status:** RFC OPEN — 10 owner-ruling items in §13 (engineering
recommendation supplied for each, awaiting sign-off). NO
implementation begins until §13 is resolved.
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-21.
**Prerequisite track:** Tappe 2, 6, 7, 8, 9, 9.5, 10 are all SHIPPED
and 100% verified on northnarrowdev (kernel 6.8.0-117). Tappa 10.5
adds NO new sensors, NO new BPF programs, NO new wire types — it is a
**pure detection-content + false-positive-framework** tappa layered
on top of the five event channels already instrumented:

- The Tappa 2 decision engine + `Rule` trait
  (`agent/src/decision/mod.rs:30`) — every new rule implements the
  same `evaluate(&Event) -> Option<Verdict>` contract.
- The Tappa 9 FIM rule family + `Event::Fim` channel
  (`agent/src/fim/rules.rs`) — new FIM rules are path-pattern
  additions over the existing machinery.
- The Tappa 9.5 deception layer + `Event::CanaryTripped` channel.
- The Tappa 10 NetFlow / NetListener / DnsQuery channels +
  `net_critical/net_high/net_medium` category-tier scheme
  (`agent/src/decision/rules/net.rs:59`).
- The Tappa 9 C7 `.v1` + `.local` overlay loader
  (`agent/src/fim/paths_config.rs`) — the operator-allowlist
  framework for the new rule families generalises this verbatim.

This doc is reviewable as a PR. **Known scope dependency:** the
Tappa 4 DNS observability refit (Bug 2 connected-UDP `msg_name ==
NULL` early-return + Bug 3 QNAME never copied into
`query_name`, both in `agent-ebpf/src/dns_query.rs`, exposed
end-to-end by the Tappa 10 N9 priv-e2e) is **pending**. Until it
lands (tracked as **N9.2 / 10.1**), `Event::DnsQuery` does not fire
for real libc resolution and carries an empty qname — so every
DNS-payload-dependent rule in this doc is marked **BLOCKED on T4
refit** and gated out of the production engine (§13 Q6).

---

## 1. Purpose & scope

**Detection breadth is the Beta-credibility gate.** NorthNarrow
ships 37 production rules today. EU-regulated prospects run
acceptance suites with thousands of detection-coverage checkboxes
and benchmark against Wazuh (which advertises "thousands of rules").
37 rules is not a defensible Beta number in that conversation — not
because 37 good rules detect less than 3000 noisy ones, but because
the *breadth-of-coverage story* (which MITRE ATT&CK tactics can this
product see at all?) has visible holes a procurement checklist will
find.

Tappa 10.5 closes those holes by growing the curated rule set from
**37 → a target band of 50–80** (recommendation: **60–65**, see
§13 Q1), and — equally important — by shipping the **operator
false-positive framework** (per-family `.v1` + `.local` allowlist
overlays) that makes a larger rule set *deployable* without burying
operators in noise.

### 1.1 Goals

1. **MITRE ATT&CK breadth.** Reach ≥1 production detection in every
   host-relevant ATT&CK tactic (§2 matrix). Coverage *breadth* is
   the credibility metric, not raw count.
2. **Curated, false-positive-tuned rules.** Every new rule ships
   with explicit FP guards + an operator-tunable allowlist file.
3. **Operator allowlist framework.** Generalise the Tappa 9 C7
   `.v1`/`.local` overlay to the process + network rule families so
   operators silence site-specific noise without code changes.
4. **Zero new attack surface.** No new BPF programs, no new wire
   types, no new `Event` variants (§4 verifies this). All new rules
   consume the events the shipped sensors already emit.

### 1.2 Non-goals (explicit)

- **Rule-generation framework / DSL.** Tappa 10.5 ships a *curated
  hand-written set*, not a Sigma-importer or a YAML rule engine.
  Rules stay compiled Rust implementing the `Rule` trait (the
  immutable-ID + pure-function contract in
  `agent/src/decision/mod.rs:8`). A rule DSL is a post-Beta
  consideration.
- **Configuration / posture assessment** (CIS-benchmark-style host
  hardening checks) — defer post-Beta.
- **Compliance reporting** (PCI/SOC2/ISO control mapping export) —
  defer post-Beta. The MITRE matrix in §2 is for *engineering
  coverage tracking*, not a customer-facing compliance artifact.
- **argv / parent-comm-aware process detection.** `Event::ProcessSpawn`
  carries `comm` + `filename` + `pid`/`ppid`/`uid`/`gid` only — no
  command-line arguments and no resolved parent `comm` (§4.2). Many
  attractive process TTPs (e.g. `curl … | bash`, `systemctl enable`,
  history-clearing) need argv. Adding argv is a *wire + BPF* change
  and is therefore **out of Tappa 10.5 scope** (it would violate the
  "no new wire types" goal). Process rules in §6/§7 are scoped to
  what the current event shape supports; argv-enrichment is flagged
  as a future tappa.

### 1.3 Out of scope (deferred to named successors)

- **DNS-payload detection rules** (tunnelling refinements, fast-flux,
  qname-entropy) — **BLOCKED on the T4 DNS refit (N9.2 / 10.1)**.
  Rule logic may be authored but is register-gated out of the
  production engine until the refit lands (§13 Q6).
- **JA3/JA4 fingerprint rules beyond the shipped NN-L-NET-003** —
  the TLS capture trigger is dormant until **Tappa 11.5** (T10 §13
  Q2 lock-in). No new JA3-dependent rules in 10.5.
- **Correlation-engine-backed chain rules at scale** — the full
  `NN-L-CHAIN-*` family depends on a multi-event correlation pass
  the current single-event `Rule` trait does not provide (§3.5,
  §13 Q2). Recommendation: a small stateful subset ships in 10.5;
  the rest defers to **T10.6**.
- **Container-escape (`NN-L-CONTAINER-*`) + K8s-API-abuse
  (`NN-L-K8S-*`) families** — reserved for **T11+** (need cgroup /
  namespace / audit-API sensors not yet built).

### 1.4 Threat model delta

Same post-exec attacker as Tappa 10 §1.2 (code already running on
the host). Tappa 10.5 widens *what stage of the kill-chain we can
see*, not *how* we see it. The new rules light up tactics the
current 37 under-cover: **Discovery**, **Credential Access** (beyond
`/etc/shadow`), **Privilege Escalation** (beyond suid-FIM),
**Defense Evasion** (history/log-tamper breadth), and
**Persistence** (timers, `ld.so.preload`, PAM modules).

---

## 2. Current-state inventory + MITRE coverage matrix

### 2.1 The 37 production rules (verified)

`RuleEngine::with_default_rules().rule_count() == 10 + 14 + 4 + 9`
(`agent/src/decision/tests.rs`). Registration:
`agent/src/decision/rules/mod.rs:50` (`default_rules`) and `:78`
(`default_rules_with_net`, the production builder threading operator
blocklists into the net rules).

| Family | IDs | Count | Event channel | Registered |
|---|---|---|---|---|
| Process (Tappa 2) | `R001..R010` | 10 | `Event::ProcessSpawn` | `rules/mod.rs:51-62` |
| FIM (Tappa 9) | `NN-L-FIM-001..014` | 14 | `Event::Fim` | `fim/rules.rs` via `:63` |
| Canary (Tappa 9.5) | `NN-L-CANARY-001..004` | 4 | `Event::CanaryTripped` | `rules/canary.rs` via `:64` |
| Network (Tappa 10) | `NN-L-NET-001..009` | 9 | `NetFlow`/`NetListener`/`DnsQuery` | `rules/net.rs` via `:69` |

### 2.2 MITRE ATT&CK coverage — current vs target

Tactics ordered by the ATT&CK Enterprise matrix. "Current" = the 37
shipped rules; "Target (10.5)" = after this tappa at the recommended
60–65 count. Endpoint-sensor reality: **Initial Access**,
**Collection**, and **Reconnaissance** are intrinsically weak for a
host-resident post-exec sensor and are best-effort, not gap targets.

| MITRE Tactic | Current rules | Current verdict | Target (10.5) |
|---|---|---|---|
| Initial Access (TA0001) | — (payload exec lands in Execution) | **none** | best-effort only (non-goal) |
| Execution (TA0002) | R001-R008 (exec from tmp/shm/var-tmp/proc-fd, netcat, reverse-shell tooling), R005/R006 | **strong** | maintain + R013/R014/R019 tooling exec |
| Persistence (TA0003) | FIM-cron/systemd/authorized_keys paths | **medium** | + FIM-021 PAM, FIM-022 `ld.so.preload`, FIM-023 systemd `.timer` |
| Privilege Escalation (TA0004) | FIM suid-binary (NN-L-FIM-002) | **weak** | + R013 kmod tooling, R014 setcap tooling, R019 ns-escape tooling |
| Defense Evasion (TA0005) | R004 fileless, FIM log-tamper (auth/audit) | **medium** | + FIM-018 lastlog, FIM-019 wtmp/btmp, FIM-020 shell-history truncation |
| Credential Access (TA0006) | FIM `/etc/shadow`, CANARY cloud-cred files | **medium** | + FIM-015 browser cred stores, FIM-016 password-manager DBs, FIM-017 GPG keyrings |
| Discovery (TA0007) | CANARY trip (deception) | **weak** | + CHAIN recon-burst (stateful, §6.4) |
| Lateral Movement (TA0008) | NN-L-NET-007 (RFC1918 outbound) | **weak** | + NN-L-NET-018 lateral-movement ports (445/3389/5985/5900) |
| Collection (TA0009) | — | **none** | best-effort (canary-adjacent) |
| Command & Control (TA0011) | NN-L-NET-001/002/003/008, R006 | **strong** | + NN-L-NET-016 high-risk C2 ports |
| Exfiltration (TA0010) | NN-L-NET-009 (byte-count) | **weak** | + CHAIN-001 sensitive-read→egress; DNS-tunnel rules **BLOCKED** |
| Impact (TA0040) | R007 crypto-miner, NN-L-FIM-010 ransomware-ext | **medium** | maintain |

**Gap summary that drives §7 rule allocation:** Privilege
Escalation, Credential Access breadth, Defense Evasion breadth, and
Persistence breadth are the highest-leverage host-detectable gaps.
FIM path-pattern rules close most of them cheaply (the machinery
already exists). Discovery + Exfiltration improvements need
correlation (chain rules, §6.4 / §13 Q2). DNS-tunnel detection is
blocked on the T4 refit.

### 2.3 What already exists to build on (no new infrastructure)

- **`Rule` trait** (`decision/mod.rs:30`): `id()`, `name()`,
  `category()`, `evaluate(&self, &Event) -> Option<Verdict>`. Immutable
  IDs (`decision/mod.rs:12`). New rules slot into the existing
  `Vec<Box<dyn Rule>>` builders.
- **`Severity`** (`common/src/model.rs:372`): `Low/Medium/High/Critical`.
- **`ResponseAction`** (`common/src/model.rs:382`): `Log`, `KillProcess`,
  `KillProcessTree`, `BlockOutbound`, `FullNetworkIsolation`,
  `Quarantine`, `ThrottleProcess`.
- **`PostureKind`** (`common/src/posture_types.rs:23`):
  `Observing/Alerted/Engaged/Combat` + `TriggerType` transition enum.
- **`.v1`/`.local` overlay loader** (`fim/paths_config.rs`):
  `+entry`/`-entry` directives, boot-WARN on disabled defaults.
- **Tiered category tags** (`net.rs:59`): `net_critical` (never
  throttled) / `net_high` / `net_medium`.
- **Stateful-rule precedent**: NN-L-NET-005 holds
  `Arc<Mutex<DnsBurstWindow>>` (`net.rs:36`) — proof that a rule can
  carry rolling state behind `&self` + interior mutability.
- **`CorrelationBuffer`** (`correlation/mod.rs:28`):
  `get_correlated(focal, lookback_ns, max_hits)` time-windowed event
  ring — the substrate for chain rules.

---

## 3. Architecture

Tappa 10.5 adds **rule modules + allowlist config files**. No new
runtime components. The data flow is unchanged from Tappa 10:

```text
   sensors (Tappa 4/9/9.5/10 — UNCHANGED)
        │  Event::{ProcessSpawn|Fim|CanaryTripped|NetFlow|NetListener|DnsQuery}
        ▼
   ┌────────────────────────────────────────────────────┐
   │ RuleEngine (decision/engine.rs)                     │
   │   Vec<Box<dyn Rule>>  ← 37 today, 60-65 target      │
   │   first-match-wins per event channel                │
   │   NEW: per-family allowlist state injected at boot  │
   │        (mirrors net_rules_with_net blocklist inject)│
   └───────────────┬──────────────────────┬─────────────┘
                   │ Verdict              │ category tier
                   ▼                      ▼
        posture state machine     §6.5 rate-limit bucket
        (Observing→…→Combat)      (Critical NEVER throttled)
                   │
                   ▼
        ADE handoff (Critical + selected High) — §8
```

### 3.1 Rule registration pattern (new families)

New rules append to the existing builders. Process rules extend the
`default_rules` / `default_rules_with_net` vecs
(`rules/mod.rs:51`); FIM rules extend `fim::rules::fim_rules()`;
net rules extend `net::net_rules*`. Following the Tappa 10 N6
precedent (`net_rules` takes operator state as parameters,
`net_rules_empty` supplies empty state for boot/tests), each new
**stateful or allowlist-bearing family** gets a paired
`*_rules(state)` + `*_rules_empty()` factory so unit tests stay
state-free.

The immutable-ID contract (`decision/mod.rs:12`) is preserved: new
IDs only ever *append* (R011+, FIM-015+, NET-010+); no existing ID
changes meaning (§13 Q10).

### 3.2 Severity tiers + action mapping (review)

The shipped 4-tier `Severity` is retained (§13 Q5 — recommend
*against* adding an `Informational` tier; use `ResponseAction::Log`
at `Medium` for defense-in-depth logging without a wire-enum churn).
Action mapping convention, consistent across all families:

| Severity | Typical action | Posture transition |
|---|---|---|
| Critical | `KillProcessTree` | → Combat |
| High | `KillProcess` | → Engaged |
| Medium | `Log` (sometimes `ThrottleProcess`) | → Alerted (or none) |
| Low | `Log` | none |

New rules MUST justify any Critical assignment (Critical bypasses
rate-limiting, §3.4) — Critical is reserved for *documented,
low-FP, kill-worthy* indicators.

### 3.3 False-positive guard patterns (the deployability framework)

This is the load-bearing half of Tappa 10.5 — a 60-rule engine that
floods operators is worse than 37. Every new rule ships with FP
guards drawn from a fixed menu:

1. **Operator allowlist file per rule family** — flat `.v1`
   default + `.local` overlay with `+entry`/`-entry` directives,
   parsed by a generalised `paths_config.rs` loader (§3.6). Mirrors
   Tappa 9 C7 (`fim-paths.{v1,local}`) and the Tappa 10 N6
   blocklists. **This replaces the inline `const` allowlists**
   currently hard-coded in `net.rs:77-120`
   (`LISTENER_ALLOWLIST_COMMS`, `RFC1918_OUTBOUND_ALLOWLIST_COMMS`,
   etc.) — that file's own comment (`net.rs:69`) already names this
   as the planned V1.1 refit; 10.5 delivers it.
2. **Process-basename allowlists** — `comm`/`filename` basename
   sets (e.g. package managers, backup tooling).
3. **Path-glob allowlists** — for FIM rules, prefix/glob exclusions
   (the existing `fim-paths` machinery).
4. **Port/comm allowlists** — for net rules (the `LISTENER_*` /
   `RFC1918_*` sets, moved to config).
5. **`.v1` + `.local` overlay** — boot-WARN on every disabled
   default (the Tappa 9 C7 lock-in), so silencing a default rule is
   always visible in the agent log.

### 3.4 Rate-limit tier mapping

Reuse the Tappa 10 N6 category-string scheme
(`net.rs:59`) generalised to all families. Each rule's
`category()` carries a tier suffix the bucket-aware emitter reads:

| Tier | Category convention | Rate cap |
|---|---|---|
| Critical | `*_critical` | **NEVER throttled** |
| High | `*_high` | 200 / min |
| Medium | `*_medium` | 1000 / min |
| Low | `*_low` | 5000 / min |

`Critical NEVER throttled` is the documented-attack-indicator
lock-in (Tappa 9 §13 Q4 + Tappa 10 §13 Q4) — extends unchanged.
The Low tier (5000/min) is new in 10.5 to back the defense-in-depth
`Log`-only rules that replace an `Informational` severity (§13 Q5).

### 3.5 Chain / correlation rules — architectural note

The single-event `Rule::evaluate(&self, &Event)` trait cannot
express "FIM sensitive-file read **followed within N seconds by**
outbound egress". Two viable shapes:

- **(A) Stateful single-trigger rule** — the rule holds
  `Arc<CorrelationBuffer>` (or a purpose-built rolling window) and,
  on its *triggering* event, queries `get_correlated(focal,
  lookback_ns, max_hits)` for the *prior* event. Precedent:
  NN-L-NET-005's `DnsBurstWindow` (`net.rs:36`). Fits the existing
  trait; works for 2-event chains keyed on a shared PID. **This is
  what 10.5 ships** (a small subset, §6.4).
- **(B) Two-pass correlation engine** — a new post-rule aggregation
  module (foreshadowed in `decision/mod.rs:15`) that sees the full
  event stream and emits composite verdicts. Needed for N-event /
  cross-PID chains. **Out of 10.5 scope → T10.6** (§13 Q2).

### 3.6 Allowlist loader generalisation

`fim/paths_config.rs` parses absolute-path lists with `+`/`-`
overlay directives into a `WatchedPathsLoad { effective, added,
disabled, unknown_disable }`. Tappa 10.5 extracts the
directive-parsing core into a reusable
`config::overlay::load_flat_list(v1_path, local_path)` returning
`OverlayLoad { effective, added, disabled, unknown_disable }` over
arbitrary `String` entries (comms, ports-as-strings, paths), so the
process + net families reuse it without copy-paste. The FIM loader
becomes a thin typed wrapper over it (no behaviour change — the
existing FIM tests pin the contract).

---

## 4. Data model

### 4.1 No new wire types

Tappa 10.5 introduces **zero** new types in `common/src/wire/` or
`common/src/model.rs`. Every new rule consumes an existing decoded
event. `Verdict` (`common/src/model.rs:400`) is unchanged.

### 4.2 No new `Event` variants — verified

The `Event` enum (`common/src/model.rs:16-154`) already exposes
every channel the new rules need:

| New rule family | Consumes |
|---|---|
| Process R011+ | `Event::ProcessSpawn { pid, ppid, uid, gid, comm, filename, timestamp_ns }` |
| FIM-015+ | `Event::Fim(FimEvent)` |
| Net-010+ | `Event::NetFlow` / `Event::NetListener` / `Event::DnsQuery` |
| Chain (stateful) | combinations of the above via `CorrelationBuffer` |

**`ProcessSpawn` field constraint (load-bearing):** the variant
carries no argv and no resolved parent `comm` — only `ppid` as a
number. Process rules are therefore limited to *"this binary
(`comm`/`filename`) ran, from this path, as this `uid`"* predicates.
This is the documented reason (§1.2 non-goal) several attractive
process TTPs are deferred to a future argv-enrichment tappa rather
than forced into 10.5 with weak heuristics.

### 4.3 Allowlist config schema (on disk)

Flat-list files, one entry per line, `#` comments, `.local` overlay
with `+`/`-` (identical to `fim-paths`):

```
# /etc/northnarrow/process-comm-allowlist.v1  (default, agent-readable)
apt
dpkg
dnf
...
# /etc/northnarrow/process-comm-allowlist.local (operator overlay)
+my-deploy-tool       # allow our CI runner's exec helper
-dnf                  # we don't run dnf; re-enable detection on it
```

Files added (all `.v1` shipped, `.local` operator-curated, never
shipped):

- `process-comm-allowlist.{v1,local}` — process rule comm exclusions.
- `netflow-comm-allowlist.{v1,local}` — replaces the inline net
  `const` sets (`net.rs:77-120`).
- FIM additions reuse the existing `fim-paths.{v1,local}` (new
  default paths appended to `configs/fim-paths.v1`).

---

## 5. BPF programs

**NONE.** Tappa 10.5 attaches no kernel programs and modifies no
existing ones. The verifier surface, ringbuf budget, and attach
sequence are byte-for-byte the Tappa 10 state. (This is the single
biggest risk-reducer of the tappa — all change is userland Rust +
config text.)

---

## 6. Rule families — proposed allocation

Target band 50–80, recommendation **60–65**. Allocation below lands
**~63** when all non-blocked rules register. DNS-dependent and full
chain rules are listed but gated (§13 Q2/Q6) so the *live* engine
count is honest.

### 6.1 Process family — `R011..R0xx` (≈8–10 new)

Consumes `Event::ProcessSpawn`. Scoped to `comm`/`filename`/`uid`
predicates (no argv — §4.2). Each gated by
`process-comm-allowlist.{v1,local}`.

- **R011** kernel-module tooling exec (`insmod`/`modprobe`/`kmod`) by
  non-package-manager context — PrivEsc/Persistence.
- **R012** capability-set tooling exec (`setcap`) — PrivEsc.
- **R013** namespace/escape tooling exec (`nsenter`/`unshare`/`runc`)
  from a non-allowlisted path — PrivEsc/escape primitive.
- **R014** `at`/`batch` scheduling-binary exec — Persistence.
- **R015** encoding/encryption tooling (`base64`/`xxd`/`openssl`)
  exec by a service-class `uid` — Defense Evasion/exfil-prep
  (Medium; FP-prone, allowlist-gated).
- **R016** debugger/tracer exec (`gdb`/`strace`/`ltrace`) by a
  non-developer `uid` — Defense Evasion/credential-dump prep
  (Medium).
- **R017** suspicious shell basename from non-standard path
  (extends R001-R003 family to `comm ∈ {sh,bash,dash}` with
  `filename` outside `/bin`,`/usr/bin`).

(Final count tuned in D2; conservatively 7, headroom to 10.)

### 6.2 FIM family — `NN-L-FIM-015..025` (≈8 new — highest leverage)

Consumes `Event::Fim`. Pure path-pattern additions over the shipped
FIM rule machinery — cheapest, highest-confidence breadth.

- **FIM-015** browser stored-credential files (Chrome `Login Data`,
  Firefox `logins.json`/`key4.db`) — Credential Access. High.
- **FIM-016** password-manager DBs (`*.kdbx`, `~/.password-store/`)
  — Credential Access. High.
- **FIM-017** GPG keyring (`~/.gnupg/*`) — Credential Access. High.
- **FIM-018** `/var/log/lastlog` tamper — Defense Evasion. High.
- **FIM-019** `/var/log/wtmp` + `/var/log/btmp` tamper — Defense
  Evasion. High.
- **FIM-020** shell-history truncation/removal (`~/.bash_history`,
  `~/.zsh_history` delete/rename) — Defense Evasion. Medium.
- **FIM-021** PAM module modification (`/lib/security/*.so`,
  `/usr/lib/.../security/*.so`) — Persistence/Credential Access.
  Critical.
- **FIM-022** `/etc/ld.so.preload` modification (LD_PRELOAD rootkit)
  — Persistence/Defense Evasion. Critical.
- **FIM-023** systemd `.timer` unit creation — Persistence. High.

### 6.3 Network family — `NN-L-NET-010..025` (≈5 shippable now)

Consumes `NetFlow`/`NetListener`. **Shippable over current fields**
(`dst_port`, `dst_addr`, `comm`, `exe`, byte counts):

- **NN-L-NET-010** outbound to high-risk C2 port set
  (4444 Metasploit, 1080 SOCKS, 6667/6697 IRC, 9001 Tor-OR) from
  non-allowlisted comm — C2. High.
- **NN-L-NET-011** plaintext-credential service flow/listener
  (telnet 23, FTP 21) — C2/lateral. Medium.
- **NN-L-NET-018** RFC1918 outbound on lateral-movement ports
  (445 SMB, 3389 RDP, 5985 WinRM, 5900 VNC) — refines NN-L-NET-007;
  Lateral Movement. High.
- **NN-L-NET-019** new listener bound on `0.0.0.0` for a non-common
  port by non-allowlisted comm (refines NN-L-NET-006 for the
  wildcard-bind exposure case) — C2/backdoor. Medium.
- **NN-L-NET-013** flow-timing beacon detector (regular-interval
  outbound to same dst from same PID) — C2. High. *Stateful* (rolling
  window per §3.5-A; precedent NN-L-NET-005).

**BLOCKED on T4 DNS refit (gated out of engine, §13 Q6):**
- NN-L-NET-014 DNS-tunnelling qname-entropy refinement.
- NN-L-NET-015 fast-flux DNS (also needs DNS-response observation,
  not yet built).
- (NN-L-NET-004/005 already shipped also degrade on live kernels
  until the refit — documented, not regressed.)

### 6.4 Chain family — `NN-L-CHAIN-001..0xx` (≈3 stateful in 10.5)

Stateful single-trigger shape (§3.5-A) using `CorrelationBuffer`.
Keyed on shared PID + a lookback window. Ship a *small, high-signal*
subset; defer the N-event/cross-PID set to T10.6 (§13 Q2).

- **NN-L-CHAIN-001** credential-store FIM read/access (FIM-015/016/017
  path hit) **+** outbound flow from same PID within window —
  Credential Access → Exfiltration. Critical.
- **NN-L-CHAIN-002** exec from `/tmp` (R001 fire) **+** outbound C2
  flow from same PID within window — Execution → C2. Critical.
- **NN-L-CHAIN-003** canary trip **+** outbound flow from same PID
  within window — deception → Exfiltration. Critical.

### 6.5 Reserved (T11+)

`NN-L-CONTAINER-*` (cgroup/namespace sensors), `NN-L-K8S-*` (audit-API
sensor) — named, not designed here.

---

## 7. Detection rules — full specification

Each row: ID · MITRE TTP · severity · action · trigger · FP guard ·
allowlist file. **G** = gated/blocked (not registered in the live
engine for 10.5).

### 7.1 Process (`Event::ProcessSpawn`) — allowlist `process-comm-allowlist`

| ID | MITRE | Sev | Action | Trigger | FP guard |
|---|---|---|---|---|---|
| R011 | T1547.006 | High | KillProcess→Engaged | `comm ∈ {insmod,modprobe,kmod}` & uid≠pkg-mgr ctx | comm allowlist |
| R012 | T1548 | High | KillProcess→Engaged | `comm = setcap` | comm allowlist |
| R013 | T1611 | High | KillProcess→Engaged | `comm ∈ {nsenter,unshare,runc}` & filename ∉ std path | path + comm allowlist |
| R014 | T1053.002 | Medium | Log→Alerted | `comm ∈ {at,batch}` | comm allowlist |
| R015 | T1027/T1132 | Medium | Log→Alerted | `comm ∈ {base64,xxd,openssl}` & uid is service-class | comm + uid allowlist |
| R016 | T1622 | Medium | Log→Alerted | `comm ∈ {gdb,strace,ltrace}` & uid non-dev | comm + uid allowlist |
| R017 | T1059.004 | High | KillProcess→Engaged | `comm ∈ {sh,bash,dash}` & filename ∉ {/bin,/usr/bin} | path allowlist |

### 7.2 FIM (`Event::Fim`) — allowlist `fim-paths`

| ID | MITRE | Sev | Action | Trigger | FP guard |
|---|---|---|---|---|---|
| NN-L-FIM-015 | T1555.003 | High | KillProcess→Engaged | write/read of browser cred store paths | path allowlist + op filter |
| NN-L-FIM-016 | T1555.005 | High | KillProcess→Engaged | mod of `*.kdbx`/`~/.password-store` | path allowlist |
| NN-L-FIM-017 | T1552.004 | High | KillProcess→Engaged | mod of `~/.gnupg/*` | path allowlist |
| NN-L-FIM-018 | T1070 | High | KillProcess→Engaged | mod of `/var/log/lastlog` | modifier-comm allowlist |
| NN-L-FIM-019 | T1070 | High | KillProcess→Engaged | mod of `/var/log/wtmp`,`btmp` | modifier-comm allowlist |
| NN-L-FIM-020 | T1070.003 | Medium | Log→Alerted | truncate/delete `~/.bash_history`,`~/.zsh_history` | path allowlist |
| NN-L-FIM-021 | T1543/T1556 | Critical | KillProcessTree→Combat | mod of PAM `security/*.so` | path allowlist |
| NN-L-FIM-022 | T1574.006 | Critical | KillProcessTree→Combat | mod of `/etc/ld.so.preload` | none (Critical, low-FP) |
| NN-L-FIM-023 | T1053.006 | High | KillProcess→Engaged | create systemd `.timer` unit | path allowlist |

### 7.3 Network (`NetFlow`/`NetListener`) — allowlist `netflow-comm-allowlist`

| ID | MITRE | Sev | Action | Trigger | FP guard |
|---|---|---|---|---|---|
| NN-L-NET-010 | T1571 | High | KillProcess→Engaged | dst_port ∈ high-risk-C2 set & comm ∉ allowlist | comm allowlist |
| NN-L-NET-011 | T1071 | Medium | Log→Alerted | flow/listener on 21/23 plaintext | comm allowlist |
| NN-L-NET-013 | T1071/T1029 | High | →Engaged + Log | regular-interval beacon to same dst/PID (stateful) | per-PID window + comm allowlist |
| NN-L-NET-018 | T1021 | High | KillProcess→Engaged | RFC1918 dst on {445,3389,5985,5900} & comm ∉ allowlist | comm allowlist |
| NN-L-NET-019 | T1571 | Medium | Log→Alerted | `0.0.0.0` listener on uncommon port & comm ∉ allowlist | comm + port allowlist |
| NN-L-NET-014 **G** | T1071.004 | High | — | DNS qname entropy/length (tunnelling) | **BLOCKED on T4 refit** |
| NN-L-NET-015 **G** | T1568.001 | High | — | fast-flux (many IPs/qname) | **BLOCKED — needs DNS responses** |

### 7.4 Chain (stateful, `CorrelationBuffer`) — §3.5-A

| ID | MITRE | Sev | Action | Trigger |
|---|---|---|---|---|
| NN-L-CHAIN-001 | T1555→T1041 | Critical | KillProcessTree→Combat | cred-store FIM hit + same-PID outbound within window |
| NN-L-CHAIN-002 | T1059→T1571 | Critical | KillProcessTree→Combat | `/tmp` exec + same-PID outbound C2 within window |
| NN-L-CHAIN-003 | deception→T1041 | Critical | KillProcessTree→Combat | canary trip + same-PID outbound within window |

**Live-engine count after 10.5:** 37 + 7 (proc) + 9 (FIM) + 5 (net
shippable) + 3 (chain) = **61**. Gated (NET-014/015, T4-blocked) +
deferred (T10.6 chain set) are excluded from the count, keeping the
`rule_count()` assertion honest.

---

## 8. ADE handoff

Reuse the Tappa 6 / Tappa 9 C9 / Tappa 10 N10 pattern: **Critical +
selected High** rules route to the LLM second-opinion via the
per-domain `Ade*RateLimiter` (10 individual + 1 batched / min;
`agent/src/ade/fim_template.rs:207`). The deterministic kill +
posture transition is **never gated by ADE** — ADE is enrichment.

Promotion is by the same hardcoded-ID + category mechanism as
`is_critical_fim_rule()` (`fim_template.rs`): the new Critical rules
(FIM-021/022, all NN-L-CHAIN-*) extend the critical-ID set; selected
High net/process rules promote via their `*_high` category when the
operator enables net/process ADE.

**Prompt templates** (one per family, mirroring `fim_template.rs`
structure — `event` / source-context / `already-taken-action` /
`question` blocks):

- `ade/process_template.rs` — ProcessSpawn context + spawn ancestry
  (ppid chain from `/proc`) + recent same-PID FIM/net events.
- chain rules reuse the relevant family template + attach the
  `CorrelationBuffer` hits that fired the chain.

ADE budgets stay per-domain (FIM / Net / Process each 11/min). This
is **optional** for the 10.5 ship (§12 D8); the deterministic path is
complete without it.

---

## 9. Wire protocol

**No changes.** No new `AdminMessage` variants, `OperationCode`s, or
`Role`s. `nn-admin` rule-listing surfaces (if any) read the existing
engine introspection. Operators edit allowlist files directly on
disk (same as `fim-paths.local`); no new signed-op is required to
tune rules in 10.5.

---

## 10. Deploy

`deploy/install.sh` additions (idempotent, mirroring the existing
`fim-paths.v1` / `netflow-blocklist.v1` blocks):

1. Drop default allowlist files if absent (leave operator copies):
   - `configs/process-comm-allowlist.v1` → `/etc/northnarrow/`
   - `configs/netflow-comm-allowlist.v1` → `/etc/northnarrow/`
     (seeded from the current inline `net.rs` `const` sets so
     behaviour is unchanged on upgrade).
   - Append new FIM default paths to `configs/fim-paths.v1`
     (browser cred stores, GPG, lastlog/wtmp/btmp, PAM `.so`,
     `ld.so.preload`, systemd timer dir).
2. **LSM widening** — extend `ETC_PROTECTED_FILES`
   (`agent/src/anti_tamper/filesystem.rs`) to cover the two new
   `.v1` allowlist files **+ their `.local` overlays** (so an
   attacker can't silence detection by editing the allowlist —
   same protection `fim-paths.{v1,local}` + `netflow-blocklist.*`
   already get).
3. No new `STATE_PROTECTED_FILES` (no new audit logs — verdicts use
   the existing decision/audit path).

The new FIM rules watch paths that must be added to the FIM watch
set; those paths join `fim-paths.v1` (the FIM sensor already watches
the configured set — no sensor change, just config).

---

## 11. Testing strategy

### 11.1 Unit tests (~80–120 new)

Per-rule **positive + negative pair** (matches the shipped pattern:
`r001_exec_from_tmp.rs::tests`, `fim/rules.rs::tests`,
`net.rs::tests`), plus allowlist edge cases. **Hybrid with
table-driven** for the homogeneous FIM path-pattern family
(FIM-015..025 share machinery → a `(path, op, expect_fire)` table is
clearer than 9 near-identical pairs); keep bespoke pairs for the
stateful + chain rules where each needs distinct window setup
(§13 Q8).

- Process R011..R017: ~3 each ≈ 21.
- FIM-015..023: table-driven ≈ 20–25 cases.
- Net-010/011/013/018/019: ~4 each ≈ 20 (013 beacon needs window
  tests).
- Chain-001..003: ~4 each ≈ 12 (correlation-window + same-PID
  isolation + negative no-correlation cases).
- Allowlist overlay generalisation: reuse + extend the existing
  `paths_config.rs::tests`; add process/net comm-list cases ≈ 10.
- Engine-count + ID-pin updates (`decision/tests.rs`): the `==
  10+14+4+9` assertion becomes `== 61` with a per-family breakdown +
  the ID-pin list extended for every new rule.

### 11.2 Privileged e2e (~5–8 smoke tests)

One smoke per *live* new family, reusing the
`install_to_priv_bin` + `EniIptablesGuard` pattern from
`agent/tests/net_privileged_e2e.rs` (and the N9.1 loopback-flow
fixture):

1. Process: exec a benign `insmod`-named helper from a temp path →
   R011 fires.
2. FIM: touch a fixture browser-cred path under a temp watch root →
   FIM-015 fires; touch `/tmp` fixture `ld.so.preload` analog →
   FIM-022 fires.
3. Net: outbound connect to a high-risk port on loopback → NN-L-NET-010
   fires (builds on the N9.1 loopback-flow correlation now working).
4. Net listener: `0.0.0.0` bind on uncommon port → NN-L-NET-019.
5. Chain: `/tmp` exec + immediate loopback egress in one PID →
   NN-L-CHAIN-002 fires; assert *no* fire when the two events are
   outside the window (negative correlation).

**Stop condition preserved:** each net/chain priv-e2e must leave no
`NORTHNARROW_COMBAT` iptables debris (the N9.1 cleanup check).

---

## 12. Effort estimate — commit-by-commit plan

Total **~30–50 h** (band reflects the chain-rule + ADE swing).
Recommended single tappa T10.5 with the internal chain below; chain
rules' *full* set and ADE templates are the deferrable tail (§13 Q9).

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **D1** | `refactor(config): extract flat-list .v1/.local overlay loader from paths_config; add process/net comm-allowlist files + LSM widening` | Generalise loader, seed `.v1` from inline consts, ETC-protect. Tests: ~12. | 5 |
| **D2** | `feat(decision): process rules R011..R017 + process-comm-allowlist gating` | 7 process rules. Tests: ~21. | 6 |
| **D3** | `feat(fim): NN-L-FIM-015..023 path-pattern rules + fim-paths.v1 defaults` | 9 FIM rules (table-driven tests). Tests: ~25. | 6 |
| **D4** | `feat(decision): NN-L-NET-010/011/018/019 + stateful NN-L-NET-013 beacon detector` | 5 net rules. Tests: ~20. | 6 |
| **D5** | `feat(decision): NN-L-CHAIN-001..003 stateful correlation rules over CorrelationBuffer` | 3 chain rules (gated on §13 Q2 ruling). Tests: ~12. | 6 |
| **D6** | `feat(deploy): install.sh allowlist bootstrap + engine-count + ID-pin test updates` | Deploy + `decision/tests.rs` `== 61`. Tests: updated. | 3 |
| **D7** | `test(privileged_e2e): per-family smoke (process/fim/net/chain) reusing install_to_priv_bin` | ~5–8 priv-e2e. | 5 |
| **D8** *(optional)* | `feat(ade): process_template + chain enrichment + critical-ID set extension` | ADE for new Critical rules. Tests: ~8. | 5 |
| | **TOTAL** | | **~32–42 h** (D8 pushes upper) |

DNS-blocked rules (NN-L-NET-014/015) are authored only if the T4
refit lands first; otherwise they are not in this plan.

---

## 13. RFC items for owner ruling

Each: **Question**, **Recommendation** (engineering default),
**Rationale**, **Reversibility**.

### Q1 — Total rule-count target: 60 / 80 / 100?

- **Recommendation: 60–65 for V1.0 (the §7 plan lands ~61).**
- **Rationale:** the credibility metric is **MITRE tactic breadth**
  (§2.2), not raw count. Wazuh's "thousands" counts per-signature
  syscheck/log-decoder entries — not comparable to curated
  behavioural rules; matching that number invites FP-storm
  regressions that *lose* Beta trust. 60 well-tuned rules with ≥1
  detection per host-relevant tactic is the defensible story. Raw
  count past ~65 hits diminishing returns against the
  no-argv/DNS-blocked constraints without new sensors.
- **Reversibility:** easy — append more rules later; IDs are
  immutable so growth is purely additive.

### Q2 — Chain rules: V1.0 or V1.1? Correlation engine?

- **Recommendation: ship 3 *stateful single-trigger* chain rules in
  10.5 (§6.4, shape §3.5-A); defer the N-event/cross-PID set + the
  two-pass correlation engine to T10.6.**
- **Rationale:** the existing `Rule` trait + `CorrelationBuffer` +
  the NN-L-NET-005 `DnsBurstWindow` precedent already support
  2-event same-PID chains with no new module. A general correlation
  engine (shape §3.5-B) is real new architecture (the second pass
  foreshadowed in `decision/mod.rs:15`) and deserves its own tappa.
  T6.9 RAG-Local does **not** cover this — it's LLM enrichment, not
  deterministic multi-event correlation.
- **Reversibility:** medium — the 3 stateful rules are self-contained;
  T10.6's engine can subsume them or run alongside.

### Q3 — Allowlist format: per-rule vs per-family?

- **Recommendation: per-FAMILY flat `.v1`/`.local`, mirroring
  `fim-paths`. NOT per-rule.**
- **Rationale:** per-rule files explode operator surface (60+ files);
  per-family (`process-comm-allowlist`, `netflow-comm-allowlist`,
  `fim-paths`) matches the shipped C7 pattern operators already know,
  reuses one parser, and the `net.rs:69` comment already commits to
  exactly this shape. Rules that need finer scope encode it in their
  predicate (e.g. uid-class), not in a separate file.
- **Reversibility:** easy — a per-rule overlay can layer on top later
  if a specific rule proves to need it.

### Q4 — MITRE coverage minimum threshold for Beta?

- **Recommendation: ≥1 production detection in each of the 8
  host-relevant tactics** (Execution, Persistence, PrivEsc, Defense
  Evasion, Credential Access, Lateral Movement, C2, Impact).
  Discovery + Exfiltration = "covered via chain rules"; Initial
  Access + Collection = explicit best-effort (non-goal).
- **Rationale:** a percentage-of-techniques target is misleading
  (ATT&CK has 200+ techniques, most irrelevant to a Linux host
  post-exec sensor) and invites checkbox-gaming. "Every applicable
  tactic has a detection" is honest and defensible in a procurement
  review.
- **Reversibility:** easy — the §2.2 matrix is the living tracker.

### Q5 — Add an `Informational` severity tier?

- **Recommendation: NO. Keep the 4-tier `Severity`.** Use
  `ResponseAction::Log` at `Medium`/`Low` for defense-in-depth
  logging; add the `*_low` rate-limit category (§3.4) to back it.
- **Rationale:** `Severity` is a wire enum (`common/src/model.rs:372`)
  with a postcard discriminant; adding a variant ripples into
  posture-mapping, ADE gating, audit schema, and every match arm —
  high churn for a tier that `Log`-at-`Low` already expresses.
- **Reversibility:** medium — adding the variant later is a
  wire-compat exercise (append-last), so deferring costs nothing.

### Q6 — DNS-dependent rules: ship-logic-but-ignore, or defer entirely?

- **Recommendation: author logic if convenient but REGISTER-GATE out
  of the production engine until the T4 refit (N9.2/10.1) lands.**
  Mark `#[ignore]` on their priv-e2e; keep unit tests on the pure
  predicate.
- **Rationale:** a rule registered in the live engine that *cannot
  fire* (because `Event::DnsQuery` never arrives for real resolution
  — Bug 2/3) inflates `rule_count()` dishonestly and confuses
  operators reading the rule list. Gating keeps the count truthful;
  the predicate stays unit-tested so the refit lights it up with one
  registration line.
- **Reversibility:** easy — registration is one line behind the
  refit.

### Q7 — Rate-limit category assignment: same scheme or finer?

- **Recommendation: reuse the existing `*_critical/_high/_medium`
  category-string scheme (`net.rs:59`), add `*_low`. Critical NEVER
  throttled.**
- **Rationale:** the bucket-aware emitter already reads
  `Rule::category()`; generalising the existing convention to
  `proc_*`/`fim_*`/`chain_*` is zero new mechanism. Finer-grained
  per-rule caps add tuning surface with no demonstrated need.
- **Reversibility:** easy — runtime-tunable caps; categories are
  strings.

### Q8 — Test pattern: per-rule pairs or table-driven?

- **Recommendation: HYBRID.** Per-rule positive+negative pairs
  (shipped convention) for heterogeneous rules; table-driven
  `(input, expect)` for the homogeneous FIM path-pattern family
  (FIM-015..023) and the high-risk-port net set.
- **Rationale:** the FIM family is 9 near-identical path-match rules —
  a table is more readable + maintainable than 18 copy-paste tests;
  the stateful/chain rules each need bespoke window setup where a
  table obscures intent.
- **Reversibility:** easy — test-only choice, per-family.

### Q9 — One tappa or split T10.5 / T10.6 / T10.7?

- **Recommendation: ONE tappa T10.5** = process + FIM + shippable-net
  + allowlist framework + 3 stateful chain rules (D1–D7), with the
  **full chain-rule set deferred to T10.6** (gated on Q2's
  correlation engine) and **ADE templates as optional D8** (or folded
  into a later ADE tappa). Avoid a T10.7.
- **Rationale:** D1–D7 are one coherent deliverable (content + the
  framework that makes it deployable). The chain *engine* is the only
  genuine architectural fork → it earns the T10.6 split. Splitting
  ADE into its own tappa proliferates ceremony for ~5 h of work.
- **Reversibility:** easy — commit chain is internal; D8 can move.

### Q10 — Backward-compat: any current rule needs downgrade/split?

- **Recommendation: NO downgrades; NO ID changes** (immutable-ID
  contract, `decision/mod.rs:12`). One **additive refinement**:
  NN-L-NET-018 (RFC1918 lateral-movement ports) overlaps
  NN-L-NET-007 (RFC1918 outbound) — keep both; NET-007 stays the
  broad Medium catch-all, NET-018 is the High port-specific
  refinement. Document the intentional overlap so a future reviewer
  doesn't "dedupe" them.
- **Rationale:** stability of shipped IDs is a hard contract
  (telemetry/alert-dedup/correlation depend on it). The only real
  question is overlap, resolved by tiering not merging.
- **Reversibility:** easy — overlap is documented intent.

### Cross-cutting lock-ins

1. **Q2 (stateful chain subset) + Q9 (one tappa)** → the 3 chain
   rules ship in 10.5 D5; the engine + the rest defer to T10.6.
2. **Q3 (per-family allowlist) + Q7 (category scheme) + §3.6
   (generalised loader)** → one parser, one category convention,
   reused across all families. D1 is the shared-infrastructure
   commit everything else depends on.
3. **Q5 (no Info tier) + Q7 (`*_low` category)** → defense-in-depth
   logging expressed without a wire-enum change.
4. **Q6 (gate DNS rules) + §1.3 (JA3 deferred to 11.5)** → the live
   `rule_count()` reflects only rules that can actually fire on the
   current sensor stack; blocked/deferred rules are documented, not
   registered.
5. **§1.2 (no argv) + Q1 (60–65 target)** → process-family count is
   bounded by the current `ProcessSpawn` shape; argv-enrichment is a
   future tappa, not a 10.5 stretch.

---

## Appendix A — Cross-references

- `Rule` trait + immutable-ID contract — `agent/src/decision/mod.rs:8,30`.
- Rule registration builders — `agent/src/decision/rules/mod.rs:50,78`.
- Net category-tier scheme + inline allowlists (to be externalised) —
  `agent/src/decision/rules/net.rs:59,77-120`.
- FIM rules + family — `agent/src/fim/rules.rs`.
- `.v1`/`.local` overlay loader — `agent/src/fim/paths_config.rs`.
- `CorrelationBuffer` (chain-rule substrate) —
  `agent/src/correlation/mod.rs:28,79`.
- Stateful-rule precedent (`DnsBurstWindow`) —
  `agent/src/decision/rules/net.rs:36`.
- ADE rate limiter + template shape — `agent/src/ade/fim_template.rs:207`.
- Posture state machine — `common/src/posture_types.rs:23,59`.
- `Severity` / `ResponseAction` / `Verdict` — `common/src/model.rs:372,382,400`.
- `Event` enum (all channels) — `common/src/model.rs:16-154`.
- T4 DNS refit dependency (Bug 2/3) — `agent-ebpf/src/dns_query.rs`;
  documented in the Tappa 10 N9.1 commit (`fc53a7f`) + the
  `net_privileged_e2e.rs` test #1 docstring.

## Appendix B — MITRE tactic → rule index (target state)

| Tactic | Rules |
|---|---|
| Execution | R001-R008, R013, R017 |
| Persistence | FIM cron/systemd/keys, FIM-021, FIM-022, FIM-023, R011, R014 |
| Privilege Escalation | NN-L-FIM-002, R011, R012, R013 |
| Defense Evasion | R004, FIM log-tamper, FIM-018, FIM-019, FIM-020, R015, R016 |
| Credential Access | NN-L-FIM (shadow), CANARY, FIM-015, FIM-016, FIM-017 |
| Discovery | CANARY, (chain recon — T10.6) |
| Lateral Movement | NN-L-NET-007, NN-L-NET-018 |
| Command & Control | NN-L-NET-001/002/003/008, R006, NN-L-NET-010, NN-L-NET-013 |
| Exfiltration | NN-L-NET-009, NN-L-CHAIN-001/002/003; DNS-tunnel **BLOCKED** |
| Impact | R007, NN-L-FIM-010 |
