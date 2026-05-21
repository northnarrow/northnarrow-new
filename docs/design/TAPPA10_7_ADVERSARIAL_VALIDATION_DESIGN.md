# Tappa 10.7 — Adversarial Validation via Kali Linux Design

**Status:** RFC RESOLVED 2026-05-21 (§13 — all 10 owner-accepted
engineering recommendations applied verbatim as resolved decision
blocks). V1 (range setup automation) unblocked; sequenced per the §12
commit chain (V1 → V2 → … → V8). The 5 ADE Active Defender open
questions are tracked separately and do **not** gate T10.7.
**Author:** Claude Code (architecture), owner-signed-off 2026-05-21.
**Date:** 2026-05-21.
**Prerequisite track:** Tappe 2, 6, 7, 8, 9, 9.5, 10, **10.5** are all
SHIPPED and 100% verified on northnarrowdev (kernel 6.8.0-117). T10.5
closed on `main` (tip `6b5edf7`) with the **61-rule production engine**
and Critical-tier ADE routing. Tappa 10.7 adds **NO production code,
NO new sensors, NO new wire types** (§9) — it is a **pure validation +
evidence tappa**: it points industry-standard attacker tooling at the
already-shipped engine and records what fires.

This doc is reviewable as a PR. **Known scope dependencies carried in
from T10.5:**

- The **T4 DNS observability refit** (Bug 2 connected-UDP `msg_name ==
  NULL` early-return + Bug 3 QNAME never copied into `query_name`,
  `agent-ebpf/src/dns_query.rs`) is **still pending**. The two
  DNS-payload rules (NN-L-NET-014/015) remain register-gated out of
  the engine and are therefore **N/A** in the 61-rule validation
  surface (§4 marks them, §13 Q1 excludes them from the denominator).
- **argv / parent-comm enrichment** (the T10.6 Beta blocker) is not
  landed. Process rules validate only against the `comm + filename +
  pid/ppid/uid/gid` event shape they ship with; TTPs that *would* need
  argv (e.g. `curl … | bash`) are out of the validation surface, not
  counted as FAILs (§6 triage classifies these as **sensor gap →
  T10.6**, not rule-logic gaps).

---

## 1. Purpose & scope

**Adversarial validation is the Beta-credibility proof.** T10.5 closed
the *breadth* gap — ≥1 detection in 9 host-relevant MITRE tactics
across 61 curated rules. But every one of those rules was proven only
against **synthetic triggers**: unit tests that hand-construct an
`Event` and assert a `Verdict`, plus per-family privileged-e2e smoke
tests that fire fixture events under the `test-privileged` feature
flag. A procurement reviewer's first question is the one synthetic
tests cannot answer: *"Does it catch real attacker tools?"*

Tappa 10.7 answers it. We stand up an isolated two-VM range, point
**MITRE-mapped, industry-standard offensive tooling** (Atomic Red Team,
Sliver, Metasploit, LaZagne, Pupy, plus targeted manual exploitation)
at a **production-mode** NorthNarrow agent, and record — with captured
evidence — which of the 61 rules trigger correctly on real tool
execution. The output is a publishable **NorthNarrow Adversarial
Validation Report**: the Beta marketing + technical-credibility
artifact that converts "61 rules, all unit-tested" into "61 rules,
validated against the same tools Wazuh/CrowdStrike are benchmarked
with."

### 1.1 Goals

1. **Real-tool detection coverage.** ≥ a target fraction (§13 Q1
   recommends **80%**) of the **applicable** 61 rules trigger
   correctly — right severity, action, and posture transition — on
   the relevant Kali tool execution.
2. **Production-mode validation.** Run against the agent as a real
   deployment runs it: **no `test-privileged` flag**, real systemd
   service, real LSM attach, real iptables `NORTHNARROW_COMBAT` chain,
   real `.v1`/`.local` config files (§5). This is the first time the
   shipped binary is exercised end-to-end by a non-fixture adversary.
3. **Quantified detection quality.** Per-rule PASS/PARTIAL/FAIL/N-A,
   per-tactic coverage %, event→verdict latency distribution, and a
   **false-positive rate** measured against a baseline of legitimate
   (non-attack) Kali activity (§8).
4. **Publishable evidence.** Every result backed by a reproducible
   command, a log snippet, and a screen capture (§11), assembled into
   the final report (§8, V8).

### 1.2 Non-goals (explicit)

- **Full Red Team exercise.** No objective-driven, multi-stage,
  evasion-optimised campaign with a human operator improvising against
  defenses. T10.7 is **detection-coverage validation** against
  catalogued tooling, not an adversary-emulation engagement.
- **Zero-day / vulnerability discovery.** We are not fuzzing the agent
  or hunting exploitable bugs in NorthNarrow itself (that is a separate
  security-review track). We validate *detection*, not *robustness*.
- **Cloud / SaaS attack simulation.** No AWS/Azure/GCP control-plane,
  no IMDS abuse, no cloud-credential TTPs. The range has **no internet
  and no cloud** by construction (§2).
- **Windows / cross-platform TTPs.** Linux-only for V1.0 — NorthNarrow
  is a Linux host sensor. Tools are exercised only in their Linux
  attack modes; Windows payloads/TTPs are out of scope.
- **New detection content.** T10.7 ships **no new rules**. Rule-logic
  gaps discovered are triaged and either hot-fixed in a narrow
  refinement phase or deferred (§13 Q5) — the tappa's product is the
  *report*, not engine growth.

### 1.3 Out of scope (deferred to named successors)

- **DNS-payload rule validation** (NN-L-NET-014/015) — BLOCKED on the
  T4 DNS refit; marked **N/A** until it lands.
- **argv-dependent process TTPs** — deferred to **T10.6** (the
  argv+correlation refit). Discovered sensor gaps here feed the T10.6
  backlog, they are not T10.7 FAILs.
- **Cross-PID / N-event correlation attack chains** — the shipped
  `NN-L-CHAIN-*` rules are single-trigger same-PID (T10.5 §13 Q2);
  multi-hop chain validation waits on the T10.6 correlation engine.
- **Automated continuous adversarial CI** (re-running the range on
  every merge) — a post-Beta infrastructure consideration; T10.7 is a
  point-in-time validation campaign.

### 1.4 Threat model delta

No change to the **defended** threat model (post-exec attacker already
running code on the host — Tappa 10 §1.2). What changes is the
**validation method**: the trigger source moves from
`agent`-internal synthetic `Event` construction to **externally
generated kernel events produced by real attacker binaries** observed
through the production eBPF sensors. T10.7 proves the *sensor → event →
rule → verdict → response* path end-to-end against inputs the agent
did not author.

---

## 2. Environment architecture

A two-VM, fully isolated VirtualBox range. The target runs the agent
exactly as a customer would; the attacker runs Kali. No component can
reach the internet during attack execution.

```
        ┌─────────────────────────── VirtualBox host ───────────────────────────┐
        │                                                                        │
        │   intnet "intnet-adversarial"  (no DHCP, no NAT, no host route)        │
        │   ┌───────────────────────────┬──────────────────────────────────┐    │
        │   │                            │                                  │    │
        │  ┌┴───────────────┐      ┌─────┴──────────────┐                   │    │
        │  │  kalidev (VM2) │      │ northnarrowdev(VM1)│                   │    │
        │  │  Kali 2025.x   │─────▶│  TARGET            │                   │    │
        │  │  192.168.56.10 │ attk │  NN agent, PROD    │                   │    │
        │  │                │      │  192.168.56.20     │                   │    │
        │  └────────────────┘      └────────────────────┘                   │    │
        │   (eth0 = intnet only during runs)   (eth0 = intnet only)         │    │
        └────────────────────────────────────────────────────────────────────┘

   Provisioning lifecycle (NAT adapter present ONLY between runs):
   build/install tools ──▶ snapshot "armed" ──▶ DETACH NAT ──▶ attack runs ──▶ revert
```

### 2.1 Network isolation (the C2-containment invariant)

- **Transport:** a VirtualBox **Internal Network** named
  `intnet-adversarial`. Internal networks have no NAT engine and no
  host route — VMs on it can reach each other and nothing else. This
  is the hard guarantee that a C2 framework (Sliver/Metasploit/Pupy)
  cannot call out to real-world infrastructure even if a payload tries.
- **Addressing:** static, no DHCP. `192.168.56.10` (Kali, attacker),
  `192.168.56.20` (northnarrowdev, target). *(Note: `192.168.56.0/24`
  is conventionally VirtualBox's host-only range; here it is assigned
  statically on the **internal** network purely for operator
  familiarity — there is no host-only adapter and no host reachability
  during runs.)*
- **Provisioning seam:** tool download/build on Kali needs the
  internet *once*. A NAT adapter is attached to Kali **only** during
  the V1 provisioning step, the "armed" snapshot is taken, then the
  **NAT adapter is detached** before any attack run. The target VM
  never has a NAT adapter at any point.
- **Evidence egress:** logs/screencaps leave the range via a
  **VirtualBox shared folder** (read-only from guest where possible)
  or a post-run snapshot mount — never over the network during a run.

### 2.2 VM 1 — northnarrowdev (target), PRODUCTION mode

- Kernel 6.8.0-117 (the verified track baseline).
- NorthNarrow agent installed via `deploy/install.sh` as the **real
  systemd service**, built **without** `--features test-privileged`
  (§5). Real `/etc/northnarrow/*.v1` + operator `.local` files, real
  LSM/BPF attach, real `NORTHNARROW_COMBAT` iptables chain on posture
  escalation, real ENI cleanup guard.
- A baseline snapshot ("clean-prod") is captured after install +
  health check, before any attack.

### 2.3 VM 2 — kalidev (attacker)

- Kali Linux 2025.x, full offensive toolchain (§3) provisioned in V1.
- Reaches the target only over `intnet-adversarial`.
- Its own "armed" snapshot (tools installed, NAT detached) is the
  revert point for repeatable runs.

---

## 3. Tooling categories + selections

Tools are chosen for **MITRE traceability** (so each invocation maps to
a tactic/technique and thus to a rule) and for being the
free/industry-standard analogues of what commercial EDRs are
benchmarked against.

| Category | Tool | Role in validation | Primary rule families exercised |
|---|---|---|---|
| **Systematic coverage** | **Atomic Red Team** | MITRE-mapped atomic tests — the backbone; one technique per atomic, deterministic commands | Process (R0xx), FIM (NN-L-FIM-*), some NET |
| **C2 framework** | **Sliver** | Modern, maintained, free Cobalt-Strike alternative; implant beacon → exercises egress + chain | NET (C2 ports/egress), CHAIN-001/002/003 |
| **Exploitation** | **Metasploit** | Classic post-exploitation modules, meterpreter Linux, reverse shells | R001-R006 (exec/reverse-shell), NET |
| **Credential dumping** | **LaZagne** | Linux credential harvesting (browser/keyring/GPG reads) | FIM-015/016/017, CHAIN-001 |
| **RAT** | **Pupy** | Cross-platform RAT in Linux mode — in-memory exec + egress | R004 (fileless), NET, CHAIN |
| **Breach simulation** *(optional, §13 Q3)* | **Caldera** | MITRE orchestration over Atomic abilities — automates large coverage sweeps | All (orchestration layer) |
| **Targeted manual** | shell + utils | Precision triggers for rules no framework hits cleanly | as below |

**Manual exploitation tooling, mapped to the specific rules the owner
called out:**

| Rule | MITRE | Manual trigger (on target, post-exec) |
|---|---|---|
| **R011** kmod tooling | T1547.006 | `modprobe dummy` / `insmod ./x.ko` from a flagged path |
| **R012/R013** setcap / runc | T1548 / T1611 | `setcap cap_setuid+ep ./x`; `runc`-shape container-escape exec |
| **FIM-021** PAM module | T1543/T1556 | write a `.so` under `/lib/.../security/` |
| **FIM-022** ld.so.preload | T1574.006 | `echo /tmp/e.so > /etc/ld.so.preload` |
| **FIM-018/019** log tamper | T1070 | `shred -u /var/log/wtmp` analog; `logrotate`-foreign write to lastlog/wtmp/btmp |
| **NET-018** lateral ports | T1021 | connect to 445/3389/5985/5900 on the attacker IP (SMB/RDP-shape) |

Tool selection note: Sliver and Metasploit overlap on C2/reverse-shell;
§13 Q3 asks whether both add value or one suffices. LaZagne + the
manual cred-store reads both target FIM-015/016/017 — LaZagne proves
the *real-tool* path, the manual read proves the *rule predicate* in
isolation.

---

## 4. Test matrix structure

The validation surface is the **61 production rules**, minus the
**N/A** set (DNS-blocked NET-014/015 are already gated out, so the
denominator is the live 61; any rule whose only trigger needs argv is
marked N/A with a T10.6 pointer). Each rule is one matrix row.

### 4.1 Per-rule row schema

| Field | Description |
|---|---|
| `rule_id` | e.g. `NN-L-FIM-022_LdSoPreloadModified` |
| `mitre` | tactic + technique (e.g. TA0003 / T1574.006) |
| `tool` | Kali tool + exact command/atomic-id used |
| `expected` | severity + `ResponseAction` + posture transition |
| `result` | **PASS** / **PARTIAL** / **FAIL** / **N/A** |
| `latency_ms` | event timestamp → verdict timestamp |
| `evidence` | screencap filename + log-snippet anchor |
| `notes` | for PARTIAL/FAIL: triage classification (§6.3) |

**Result semantics:**
- **PASS** — fires with the exact expected severity, action, and
  posture transition.
- **PARTIAL** — fires but with a mismatch (e.g. detected as High when
  spec says Critical, or correct verdict but no posture transition).
- **FAIL** — the rule's trigger condition was genuinely met and
  nothing fired (a real detection gap).
- **N/A** — the rule cannot be exercised in this environment for a
  *known, documented* reason (DNS-blocked, argv-dependent, requires a
  sensor not in scope) — excluded from the coverage denominator per
  §13 Q1.

### 4.2 Aggregate metrics

- **Coverage %** = PASS / (PASS+PARTIAL+FAIL), per MITRE tactic and
  overall. (N/A excluded — §13 Q1.)
- **Detection latency** distribution (p50/p95/p99) — event→verdict,
  read from the audit chain timestamps.
- **False-positive rate** — verdicts fired during the legitimate-Kali
  baseline window (§8.3) that are *not* attacks, normalised per hour.

---

## 5. Production-mode vs privileged-test-mode delta

This is the central technical reason T10.7 matters: it validates a
code path the existing test suite **cannot** exercise.

| Dimension | T10.5 priv-e2e (`--features test-privileged`) | T10.7 production mode |
|---|---|---|
| Build flag | `test-privileged` ON | **OFF** (shipped binary) |
| Process model | test harness spawns agent | **real systemd unit** (`northnarrow.service`) |
| Event source | `install_to_priv_bin` fixtures, synthetic events | **real eBPF sensors** observing real tool syscalls |
| LSM attach | test scaffolding | **real BPF-LSM / fanotify attach** at boot |
| Response | assertions on `Verdict` | **real `NORTHNARROW_COMBAT` iptables chain** + real kill |
| ENI guard | `EniIptablesGuard` test fixture | **real cleanup guard** under real teardown |
| Config | test temp dirs | **real `/etc/northnarrow/*.{v1,local}`** |

T10.7 adds two things the test suite never measured:

1. **Real-deployment correctness** — does the systemd-managed,
   LSM-attached, real-iptables build actually fire and respond, or did
   a fixture mask a wiring gap? (e.g. does the COMBAT chain really drop
   egress, does the ENI guard really clean up after a real kill?)
2. **Performance overhead under attack load** — CPU/mem/event-loop
   latency on the target while a C2 beacon + an Atomic sweep run
   concurrently. Baseline (idle) vs under-load, captured for the
   report's "production readiness" section.

---

## 6. Test execution protocol

### 6.1 Isolation + snapshot cadence

- Target reverts to **`clean-prod`** between major TTP **families**
  (process / FIM / net / chain / C2) by default (§13 Q10 recommends
  **per-family**, with per-TTP revert reserved for any test that
  mutates persistent state — PAM/ld.so.preload writes, log tamper —
  so a prior write doesn't pre-trigger a later rule).
- Attacker reverts to **`armed`** to guarantee a clean toolchain state.
- Each run is timestamped and tied to the snapshot generation it ran
  against, for reproducibility in the report.

### 6.2 Per-result documentation template

Every executed test produces one record (the §4.1 row) plus:
`(a)` the exact command + Atomic-id, `(b)` agent log snippet around the
verdict, `(c)` a screen capture of the verdict/posture surface, `(d)`
the measured latency. Template lives in
`docs/validation/templates/result.md`.

### 6.3 Failed-detection triage workflow

A non-PASS is classified before it's logged as a verdict on the engine:

1. **Rule-logic gap** — the event reached the engine but the predicate
   missed it (wrong path fragment, wrong op, FP-guard too broad). →
   candidate hot-fix (§13 Q5).
2. **Sensor gap** — the event never reached the engine because the
   sensor doesn't emit it (argv missing, a syscall path not
   instrumented). → **T10.6 backlog**, not a T10.7 rule FAIL.
3. **Configuration gap** — the rule + sensor are fine but the
   `.v1`/`.local` allowlist or watch-path set excluded the test target.
   → config fix, re-run.

The triage class is recorded in the row's `notes` so the report
distinguishes "we have a detection hole" from "this needs T10.6".

---

## 7. Specific test plan — 61-rule × Kali-tool mapping

The full 61-row matrix is the **product of V2–V4** (it *is* a chunk of
the report). This section fixes the per-family scenario design and the
exact triggers for the high-value rules; the remaining rows follow the
same shape.

### 7.1 Process family (R001–R017) — Atomic Red Team + Metasploit + manual

- **R001–R004** (exec from `/tmp`,`/dev/shm`,`/var/tmp`, fileless
  memfd): Atomic T1059 / T1620 + Metasploit `exploit/multi/handler`
  dropping a payload to `/tmp` and executing → expect **Critical /
  KillProcessTree / COMBAT**.
- **R005/R006** (netcat, reverse-shell tooling): `nc -e`, bash
  `/dev/tcp` reverse shell from Metasploit → expect fire.
- **R007** (crypto-miner): xmrig-named benign binary exec.
- **R011** (kmod tooling): `modprobe dummy` / `insmod` from flagged
  path → T1547.006.
- **R012/R013** (setcap / container-escape): `setcap` + `runc`-shape
  exec → T1548 / T1611.
- **R014–R017**: per the D2 spec, mapped to nearest Atomic technique.
- Argv-dependent process TTPs → **N/A (T10.6)**.

### 7.2 FIM family (NN-L-FIM-001..023) — Atomic + LaZagne + manual writes

- **FIM-001/002/008** (system-binary / SUID / kmod-file modify):
  Atomic file-write techniques + manual `cp`/`chmod u+s`.
- **FIM-010** (ransomware ext rename): scripted mass-rename to a
  `.crypted` analog.
- **FIM-015/016/017** (browser / password-manager / GPG cred stores):
  **LaZagne** run on the target reads these stores → expect High +
  KillProcess; cross-check with a manual `cat` of a fixture cred file.
- **FIM-018/019** (lastlog / wtmp / btmp tamper): `shred`/foreign-write
  → T1070.
- **FIM-021** (PAM module): write `.so` under `/lib/.../security/` →
  **Critical**; ADE `fim_template` `rule-context` (D8) should attach
  the T1543/T1556 block — validated as part of the row evidence.
- **FIM-022** (ld.so.preload): `echo … > /etc/ld.so.preload` →
  **Critical** + D8 ADE T1574.006 context.
- **FIM-023** (systemd `.timer`): drop a `.timer` unit.

### 7.3 Network family (NN-L-NET-*) — Sliver / Metasploit / manual

- **NET-001/002/003/008** (C2 indicators, egress): a **Sliver** mTLS
  beacon from the target to `192.168.56.10` → expect the C2/egress
  rules; the beacon's periodicity also feeds the **NET-013 beacon
  detector** (stateful window).
- **NET-009** (byte-count exfil): stage a large outbound transfer over
  the Sliver session.
- **NET-010/011** (high-risk ports): connect to the flagged ports on
  the attacker.
- **NET-018** (lateral-movement ports 445/3389/5985/5900): manual
  connects → T1021.
- **NET-019** (uncommon-port listener / `0.0.0.0` bind): bind a
  listener on the target.
- **NET-014/015** (DNS payload): **N/A — BLOCKED on T4 refit.**

### 7.4 Chain family (NN-L-CHAIN-001..003) — the correlation showcase

These need a **two-event same-PID sequence inside the window** — the
hardest and most impressive to demonstrate with real tooling:

- **CHAIN-001** (cred read → egress): a single Sliver/Pupy implant
  process runs **LaZagne** (reads a cred store → records precursor) and
  then **beacons out** → expect **Critical / KillProcessTree / COMBAT**
  on the egress, with the D8 `chain_template` T1555→T1041 context.
- **CHAIN-002** (`/tmp` exec → non-DNS egress): drop a Metasploit
  payload to `/tmp`, execute, and have it connect to a non-53 port →
  T1059→T1571.
- **CHAIN-003** (canary trip → egress): the implant touches a deployed
  NN canary file, then beacons → deception→T1041.
- Negative control: run the precursor and the egress in **different
  PIDs** / **outside the window** → assert **no** chain fire (validates
  the §13-Q2 per-PID single-trigger semantics, not just the positive).

### 7.5 Canary family (NN-L-CANARY-001..004) — Pupy / manual

- Implant accesses deployed decoy credential/file canaries → expect the
  canary trip verdicts (and seeds CHAIN-003).

---

## 8. Metrics + reporting

### 8.1 Coverage matrix

The §2.2-style MITRE tactic table, but with **validated** columns: per
tactic, `rules / PASS / PARTIAL / FAIL / N-A` and a coverage %. This is
the report's headline figure and the §13-Q1 acceptance gate.

### 8.2 Detection-latency histogram

event→verdict p50/p95/p99 from the audit-chain timestamps, plus the
under-attack-load overhead numbers (§5). Establishes "real-time
detection" credibly with data.

### 8.3 False-positive analysis (baseline vs attack delta)

Run a window of **legitimate** Kali activity (browsing, package
installs, normal SSH, dev work — §13 Q4 recommends a defined baseline
duration) with **no attack**, count any verdicts. The FP rate is
`baseline verdicts / hour`. The report presents baseline-vs-attack as a
signal-to-noise delta — the number that proves the FP framework
(`.v1`/`.local` allowlists) works in practice.

### 8.4 EDR comparison framework (§13 Q7)

Recommendation: **descriptive, methodology-first** comparison vs Wazuh
for V1.0 — same tools, same tactics, "here is what each detects" —
**not** a head-to-head score we publish as a benchmark (a formal
benchmark invites methodology disputes and needs a tuned Wazuh install
to be fair). The report documents the comparison *method* so a reader
can reproduce it; a formal scored benchmark is a post-Beta exercise.

---

## 9. Wire protocol

**No changes.** T10.7 is testing + evidence only. No `AdminMessage`
variants, no `OperationCode`s, no `Event` variants, no rule changes
(refinement hot-fixes in §13-Q5 scope, if approved, are existing-rule
predicate tweaks, not wire changes). The agent binary under test is the
shipped T10.5 `main` build.

---

## 10. Deployment for the adversarial environment

New artifacts live under `deploy/adversarial/` (scripts) and
`docs/validation/` (templates, matrix, report) — no change to the
production `deploy/install.sh` path beyond invoking it in prod mode.

### 10.1 kalidev provisioning

`deploy/adversarial/provision-kali.sh` (idempotent, run once with NAT
attached): install Atomic Red Team (§13 Q2 method), Sliver, Metasploit,
LaZagne, Pupy, (optional Caldera); pin versions; verify; then prompt to
detach NAT and snapshot `armed`.

### 10.2 northnarrowdev production bootstrap

`deploy/adversarial/bootstrap-target-prod.sh`: run `deploy/install.sh`
**without** `test-privileged`, enable + start `northnarrow.service`,
seed `/etc/northnarrow/*.v1` defaults, deploy canary files, run a
health check (engine reports 61 rules, LSM attached, COMBAT chain
absent at rest), snapshot `clean-prod`.

---

## 11. Evidence capture

- **Screen capture:** per-result stills (and short clips for the chain
  demos) of the verdict/posture surface; filenames keyed to `rule_id`.
- **Log archival:** the agent audit chain + journald slice for each run
  window, pulled via the read-only shared folder, hashed (sha256) for
  integrity, archived under `docs/validation/evidence/<run-id>/`.
- **PCAP** (§13 Q6): recommendation **selective** — capture full PCAP
  only for the NET + CHAIN runs (where packet evidence matters);
  skip PCAP for pure FIM/process rows (the log + screencap suffice).
- **Report assembly:** `docs/validation/REPORT.md` is generated from
  the matrix + metrics + curated evidence; V8 produces the
  publication-ready version per the §13-Q8 scope ruling.

---

## 12. Effort estimate — commit-by-commit plan

Total **~30–50 h** across **8 commits** (V1–V8). Band reflects the
refinement-loop swing (§13 Q5) and whether Caldera (§13 Q3) is included.
These are **doc/test/evidence** commits — no production engine code
(§9).

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **V1** | `chore(adversarial): VirtualBox range + Kali provisioning + prod-mode target bootstrap` | intnet, both VMs, `provision-kali.sh` + `bootstrap-target-prod.sh`, snapshots, health check. | 6 |
| **V2** | `test(adversarial): Atomic Red Team systematic sweep — process + FIM families` | Atomic atomics mapped to R0xx + NN-L-FIM-*; matrix rows + evidence. | 8 |
| **V3** | `test(adversarial): C2 framework runs (Sliver/Metasploit) — NET + CHAIN families` | beacon/egress/lateral + chain correlation rows; PCAP for these. | 7 |
| **V4** | `test(adversarial): manual exploitation campaigns + cred-dump (LaZagne/Pupy)` | R011/012/013, FIM-021/022/018/019, NET-018, CHAIN-001 cred chain, canary. | 6 |
| **V5** | `test(adversarial): false-positive baseline — legitimate Kali activity window` | baseline run, FP-rate measurement, signal-to-noise delta. | 4 |
| **V6** | `docs(validation): coverage matrix + latency + FP analysis assembly` | aggregate metrics, EDR-comparison method, evidence linking. | 5 |
| **V7** | `fix(refinement): close rule-logic gaps discovered in validation` *(scope per §13 Q5)* | predicate hot-fixes + re-run of affected rows (or no-op if deferred). | 5 |
| **V8** | `docs(validation): publication-ready Adversarial Validation Report` | final report per §13-Q8 scope. | 4 |
| | **TOTAL** | | **~30–45 h** (Caldera + deep refinement push the upper band) |

Cadence (§13 Q9): recommendation **multi-day with refinement loops** —
V1→V6 then a triage gate before V7, not a single banner sprint, because
real-tool runs surface gaps that benefit from a fix-and-re-run cycle.

---

## 13. RFC resolutions

All 10 RFC items resolved **2026-05-21** (owner-accepted engineering
recommendations applied verbatim). V1 (range setup automation)
unblocked; sequenced per the §12 commit chain. Each block below:
**Decision**, **Rationale**, **Implementation note** (where in this doc
/ commit plan the decision manifests), **Reversibility**, **Date
resolved**. The 5 ADE Active Defender open questions
(`docs/strategy/ADE_ACTIVE_DEFENDER_VISION.md` §7) are tracked
separately and do **not** gate T10.7.

### Q1 — Coverage threshold acceptable for Beta: 80% / 90% / 100%?

- **Decision:** **80% of applicable rules** (N/A excluded), with
  **100% on the Critical tier** (FIM-001/002/008/010/021/022 + all
  CHAIN-*) as a **hard sub-gate**.
- **Rationale:** 100% overall is brittle — some rules are genuinely
  hard to trigger with catalogued tooling without argv (T10.6) and
  would force contrived tests that prove little. 80% overall is a
  defensible procurement number; making **Critical** detections
  non-negotiable is what actually matters for the security story.
- **Implementation note:** §8.1 coverage matrix is the gate; the
  Critical sub-gate is asserted explicitly in the V6 metrics + V8
  report.
- **Reversibility:** easy — threshold is a report gate, not code.
- **Date resolved:** 2026-05-21.

### Q2 — Atomic Red Team install: full git clone or curated subset?

- **Decision:** **full clone, curated Linux execution.** Clone the
  whole `atomics/` repo (provenance + reproducibility), run only a
  **curated index** of Linux atomics mapped to our 61 rules
  (`docs/validation/atomic-index.md`).
- **Rationale:** full clone is the honest, reproducible artifact and
  cheap; running everything wastes time on Windows/cloud atomics
  irrelevant to a Linux host sensor. Curate execution, not the install.
- **Implementation note:** `04_install_attack_toolkit.sh` (V1) clones
  the full repo; the curated index is authored in V2.
- **Reversibility:** easy — the curated index grows/shrinks freely.
- **Date resolved:** 2026-05-21.

### Q3 — Sliver vs Metasploit vs both for C2?

- **Decision:** **Sliver + Metasploit + Pupy, distinct roles.** Sliver
  = modern beacon/egress + chain showcase; Metasploit = classic
  reverse-shell/post-exploitation breadth (R005/R006 + exec rows);
  Pupy = fileless/in-memory angle.
- **Rationale:** they overlap on "reverse shell" but diverge on beacon
  modernity (Sliver mTLS/periodicity → NET-013 beacon detector) vs
  module breadth (Metasploit) vs in-memory (Pupy). Overlap is small
  relative to the coverage each uniquely unlocks.
- **Implementation note:** all three provisioned in
  `04_install_attack_toolkit.sh` (V1); exercised in V3 (Sliver/MSF) +
  V4 (Pupy).
- **Reversibility:** easy — drop one if V3 shows redundancy.
- **Date resolved:** 2026-05-21.

### Q4 — FP baseline: how many hours of legitimate Kali activity?

- **Decision:** **8h total — a 4-hour scripted legit-activity baseline,
  repeated twice** (separate steady-state noise from one-offs).
- **Rationale:** long enough to catch periodic/cron-driven FPs, short
  enough to fit the campaign; scripted so it's reproducible and the
  report states exactly what "legitimate" meant.
- **Implementation note:** §8.3 + the V5 baseline commit; the scripted
  activity set is authored in V5.
- **Reversibility:** easy — extend if the first window is noisy.
- **Date resolved:** 2026-05-21.

### Q5 — Refinement scope: fix discovered gaps here or defer?

- **Decision:** **fix rule-logic gaps in V7** (narrow predicate
  hot-fixes, hard-capped at the §12 5h estimate); **route sensor gaps
  to T10.6** and **config gaps to a separate config PR**. Anything
  bigger than the cap becomes a tracked backlog item, not scope creep.
- **Rationale:** a rule that *should* fire and doesn't, where the fix
  is a one-line predicate tweak, is cheap to close while the evidence
  is fresh. Architectural gaps (argv) are explicitly T10.6 and must not
  balloon T10.7.
- **Implementation note:** §6.3 triage workflow classifies each
  non-PASS into rule-logic / sensor / config before V7 acts.
- **Reversibility:** medium — hot-fixes are small, reversible PRs;
  deferral is the safe default if a fix looks risky.
- **Date resolved:** 2026-05-21.

### Q6 — Evidence retention: full PCAP or selective?

- **Decision:** **selective** — full PCAP for NET + CHAIN runs only;
  logs + screencaps for everything else; **hash all** evidence.
- **Rationale:** packet evidence matters where the detection *is* the
  network behaviour; for FIM/process rows the audit log is the
  authoritative evidence and PCAP just bloats the archive.
- **Implementation note:** §11 evidence-capture rules; PCAP scoped to
  the V3 NET/CHAIN runs.
- **Reversibility:** easy — capture-all is a one-flag change if a
  reviewer wants more.
- **Date resolved:** 2026-05-21.

### Q7 — Comparison framework: formal benchmark vs Wazuh, or descriptive?

- **Decision:** **descriptive, methodology-first** for V1.0 (§8.4).
  Document the comparable method; do **not** publish a head-to-head
  score.
- **Rationale:** a fair scored benchmark needs a tuned competitor
  install and invites "you misconfigured Wazuh" disputes that
  undermine credibility. Descriptive comparison is honest and
  defensible; a formal benchmark is a deliberate post-Beta project.
- **Implementation note:** §8.4 documents the method; V8 report carries
  the descriptive comparison only.
- **Reversibility:** easy — the descriptive method is the foundation a
  later formal benchmark would build on.
- **Date resolved:** 2026-05-21.

### Q8 — Report publication scope: internal / GitHub README / marketing?

- **Decision:** **tiered.** Full technical report in-repo
  (`docs/validation/REPORT.md`) → **summary linked from the GitHub
  README** → marketing-landing version held until **after owner
  review** of the in-repo report (no external publish pre-review).
- **Rationale:** the in-repo report is the source of truth and review
  surface; README linkage gives Beta evaluators immediate access;
  external marketing should follow, not lead, the reviewed artifact.
- **Implementation note:** V8 produces the in-repo report + README
  summary; marketing promotion is a post-review follow-up.
- **Reversibility:** easy — promotion is additive once reviewed.
- **Date resolved:** 2026-05-21.

### Q9 — Execution cadence: single sprint or multi-day with loops?

- **Decision:** **multi-day with refinement loops** — V1–V6, triage
  gate, V7 fixes + re-run, V8 report.
- **Rationale:** real-tool runs surface gaps cheapest to close in a
  fix-and-re-run rhythm; a single banner sprint forces either skipping
  fixes or uncontrolled scope creep.
- **Implementation note:** §12 cadence note + the V7 triage gate.
- **Reversibility:** easy — the phases are independent commits.
- **Date resolved:** 2026-05-21.

### Q10 — VM snapshot strategy: per-TTP revert or per-family?

- **Decision:** **per-family revert** as the default; **per-TTP revert
  mandatory** only for **state-mutating** tests (PAM / `ld.so.preload`
  writes, log tamper, persistence drops) so a prior write can't
  pre-satisfy or mask a later rule.
- **Rationale:** per-TTP revert for all 61 is slow and mostly
  unnecessary (read-only/process tests don't dirty state); targeted
  per-TTP revert where state persists keeps results clean without the
  full cost.
- **Implementation note:** §6.1 snapshot cadence; `06_baseline_snapshot.sh`
  (V1) creates the `v1-baseline` revert point both VMs roll back to.
- **Reversibility:** easy — snapshot cadence is an operator choice per
  run.
- **Date resolved:** 2026-05-21.

### Resolved cross-cutting notes (owner-confirmed 2026-05-21)

- **§2 network isolation:** the `intnet-adversarial` Internal Network +
  **NAT-only-during-provisioning** lifecycle is confirmed — Kali gets a
  NAT adapter only for the V1 tool download, then it is detached before
  the `armed`/`v1-baseline` snapshot; the target never has NAT.
- **§4 N/A denominator:** DNS-payload rules (NN-L-NET-014/015,
  T4-blocked) and argv-dependent process TTPs (T10.6-blocked) are
  explicitly **excluded** from the coverage denominator; **sensor gaps
  route to T10.6**, never counted as T10.7 FAILs.
- **§7 matrix scope:** the full 61-row matrix is the **progressive
  product of V2–V4** (it is a chunk of the report), not a pre-authored
  artifact.

---

## Appendix A — Cross-references

- **T10.5 design** (`docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md`)
  — the 61-rule allocation (§6/§7), the MITRE matrix (§2.2 / Appendix
  B) this validation scores against, and the ADE D8 templates
  (`fim_template` / `chain_template`) whose context blocks are checked
  as row evidence.
- **Engine rule-count pin**
  (`agent/src/decision/tests.rs::default_engine_has_sixtyone_rules_across_all_families`)
  — the authoritative 61-rule list = the validation surface.
- **T10.5 priv-e2e** (`agent/tests/*privileged_e2e.rs`, `EniIptablesGuard`,
  `install_to_priv_bin`) — the synthetic baseline T10.7 supersedes with
  real tooling (§5 delta).
- **Backlog:** T10.6 (argv + correlation refit — the Beta blocker that
  bounds the N/A set), T4 DNS refit (Bug 2/3 — NET-014/015 N/A).

## Appendix B — MITRE tactic → validation tooling index (target)

| Tactic | Rules in scope | Primary tool(s) |
|---|---|---|
| Execution (TA0002) | R001–R008 | Atomic, Metasploit |
| Persistence (TA0003) | FIM-021/022/023, FIM-cron/systemd | Atomic, manual writes |
| Privilege Escalation (TA0004) | FIM-002, R012/R013 | manual (setcap/runc) |
| Defense Evasion (TA0005) | R004, FIM-018/019/020 | Atomic, shred/manual |
| Credential Access (TA0006) | FIM-015/016/017 | **LaZagne**, manual |
| Discovery (TA0007) | canary-adjacent | Pupy, manual |
| Lateral Movement (TA0008) | NET-018 | manual (445/3389/…) |
| Command & Control (TA0011) | NET-001/002/003/008/013 | **Sliver**, Metasploit |
| Exfiltration (TA0010) | NET-009, CHAIN-001 | Sliver + LaZagne |
| Impact (TA0040) | R007, FIM-010 | Atomic, scripted |
| *Initial Access / Collection / Recon* | — | best-effort (non-goal) |
