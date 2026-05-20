# Tappa 9.5 — Deception Layer / Canary Tokens Design

**Status:** RFC RESOLVED 2026-05-19 (§12 — all 10 owner-accepted
decisions documented in-place). K1 implementation unblocked.
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-20.
**Prerequisite track:** Tappa 7 (anti-tamper LSM + watchdog),
Tappa 8 (signed admin overrides + audit chain), Tappa 9 (FIM
including C5.2 `fim_file_open_observe` + the WATCHED_PATHS
infrastructure) are all SHIPPED. Tappa 9.5 builds on three
Tappa-7/8/9 layers that already exist:

- The `fim_file_open_observe` LSM hook + `WATCHED_PATHS`
  HashMap (Tappa 9 C5.2 + C8) — Tappa 9.5 reuses the SAME
  kernel-side observation pipeline to detect canary
  reads/writes. No new BPF programs for file canaries.
- The Tappa 4 process-spawn sensor (`sched_process_exec`
  tracepoint) — Tappa 9.5 reuses for process-canary exec
  detection.
- The Tappa 9 polish-#2 `BaselineCache` + Tappa 8 B1
  chained-audit primitives — Tappa 9.5's canary registry +
  access log directly reuse the chained-log shape.

Tappa 9.5 is the **zero-FP detection primitive** that
complements the 14 heuristic FIM rules. Heuristic rules trade
precision for coverage; canaries trade coverage for precision.
Every canary trip is, by construction, an intrusion signal —
no operator workflow legitimately reads a `north-narrow-canary-
*` file or connects to a deception-port listener.

This doc is reviewable as a PR. All §12 RFC items resolved
2026-05-19; implementation begins at K1 (§11 commit-by-commit
plan).

---

## 1. Purpose & scope

**Deception is the second customer-visible Phase 1 detection
differentiator after FIM.** Operators of high-value targets
(financial / health / defence) want a zero-false-positive
signal alongside the heuristic engines — something that, when
it fires, is incontrovertible evidence of compromise. The
canary-token model (Thinkst Canary, AWS Honey-IAM, Microsoft
"honeypot files in OneDrive") is the proven shape; Tappa 9.5
ships the sovereign on-host implementation.

The Tappa 9.5 scope:

1. **Four canary types** — file, process, network listener,
   credential. Each has a distinct kernel-side detection
   surface but shares the same userland registry + the same
   tripped-signal flow into the posture state machine.
2. **Zero-false-positive contract** — any canary access is,
   by construction, an intrusion. The decision-engine rule
   (NN-L-CANARY-001..004) ALWAYS emits
   `Severity::Critical` + `KillProcessTree` + posture →
   COMBAT. No exceptions, no allowlists, no rate limiting.
3. **Operator-managed deployment** — `nn-admin canary
   deploy <type> <name>` (signed, audit-chained); `nn-admin
   canary list`; `nn-admin canary burn <id>` (manual
   retirement). NO operator-facing way to disable canary
   detection — once deployed, the only way to make a canary
   stop firing is to delete it via the signed admin op
   (which itself audit-rows).
4. **Chained, signed canary registry** at
   `/var/lib/northnarrow/canaries.jsonl` — the operator's
   complete deployment history, LSM-protected (same
   STATE_PROTECTED_FILES treatment as Tappa 9's
   fim_baseline.jsonl).
5. **Chained, signed access log** at
   `/var/lib/northnarrow/canary_access.jsonl` — every
   tripped canary writes one entry. The pair (registry +
   access log) is the audit-grade record an operator hands
   to incident-response.
6. **Single-trip semantics** — once a canary is accessed, it
   marks `tripped: true` in the registry and STAYS tripped
   until the operator manually `nn-admin canary refresh
   <id>` (which audits + resets). Re-firing the same canary
   on repeated reads would burn ringbuf + audit-chain
   budget for no additional signal (the first trip already
   told us "compromised"). The posture transition fires
   only on the FIRST trip per canary.

### 1.1 Out of scope for Tappa 9.5

- **Networked honeypot services** (full SSH service that
  accepts a connection, prompts for a password, logs the
  password) — Tappa 11+. Tappa 9.5 ships only LISTENER
  canaries (a port that listens but never responds; the
  CONNECT itself is the signal).
- **AWS / GCP / Azure honeytoken integration** (canary
  credentials that hit a SaaS console for verification) —
  Tappa 13 SaaS-Backend feature; sovereign deployments
  can't validate online tokens.
- **Random canary generation by the agent** (auto-deploy a
  rotating set of canaries based on host heuristics) —
  V1.1; operator-managed deployment is the V1.0 surface.
- **Decoy file CONTENT generation** (synthetic credit-card
  numbers, fake password lists) — V1.1 ergonomic; V1.0
  ships generators for the four canary types but
  delegates "what does the canary file CONTAIN" to the
  operator (template-driven via
  `/etc/northnarrow/canary-templates/`).

### 1.2 Threat model

The attacker has executed code on the host AND is doing
post-exploitation reconnaissance — looking for credentials,
checking for tooling, enumerating listening services, reading
sensitive-looking files. The canary types target each of
these reconnaissance behaviours:

- **File canary** — fake `~/.ssh/config_backup` or
  `aws_keys_old.txt` in plausible locations the attacker
  greps for after they've owned the box.
- **Process canary** — `northnarrow-sysadmin-helper` binary
  at `/usr/local/bin/` that LOOKS like a legitimate
  helper. Execution is the signal (no operator workflow
  ever runs it; legitimate operators use `nn-admin`).
- **Network listener canary** — a process that calls
  `bind() + listen()` on a port like 4444 (Metasploit
  default), 31337 (lan-monitoring), 9999 (custom backdoor
  shapes). Attacker scanning the host for backdoor
  remnants connects → trip.
- **Credential canary** — fake AWS access key, GCP service-
  account JSON, generic SSH private key in plausible
  `.aws/credentials` / `~/.ssh/id_rsa.bak` locations. The
  READ (via the Tappa 9 C5.2 `fim_file_open_observe`
  pipeline) is the signal. Useful complement to
  NN-L-FIM-011..014 cloud-cred rules: those fire on legit
  read paths too (CLI tools); canary creds NEVER have a
  legitimate read.

Tappa 9.5 does NOT prevent the attacker's reconnaissance
(by definition — the canary HAS to be readable to be
triggered). It surfaces the intrusion with zero-FP
certainty within MILLISECONDS of the first probe.

---

## 2. Current state inventory (IMPLEMENTED vs TODO)

### 2.1 IMPLEMENTED

- `fim_file_open_observe` LSM hook (Tappa 9 C5.2) — fires on
  every open of a watched inode. Tappa 9.5 reuses this
  pipeline by inserting canary file inodes into
  `WATCHED_PATHS` and discriminating canary-vs-fim in
  userland.
- `WATCHED_PATHS` BPF HashMap + `populate_watched_paths`
  helper (Tappa 9 C8) — Tappa 9.5 adds a parallel
  `CANARY_PATHS` map OR (Q4 lock-in dependent) extends
  WATCHED_PATHS with a discriminator byte.
- Tappa 4 process-spawn sensor (`sched_process_exec`
  tracepoint) — Tappa 9.5 process-canary detection
  reuses; the rule simply matches on
  `event.filename == canary.path`.
- Tappa 8 B1 chained audit log primitives + Tappa 9 C3
  `BaselineDb` shape — Tappa 9.5's `canaries.jsonl` +
  `canary_access.jsonl` chains directly reuse the
  prev_hash / entry_hash / agent_sig triple.
- Tappa 9 C6 signed admin pipeline (FimBaselineRequest +
  FimReportRequest patterns) — Tappa 9.5's
  CanaryDeployRequest / CanaryListResponse / CanaryBurnRequest
  are direct ports of the same shape.
- Tappa 9 C7 `STATE_PROTECTED_FILES` registry extension
  pattern + Tappa 9 polish #1 PHASE_D_003
  `install_to_priv_bin` for e2e tests — Tappa 9.5 reuses
  both.

### 2.2 TODO (gaps this design addresses)

- **No canary registry.** No on-disk record of which
  canaries are deployed, when, by which operator
  fingerprint.
- **No canary-vs-FIM discriminator in the drift pipeline.**
  A file read of a canary today would fire NN-L-FIM-011..014
  (cred-read rules) — High severity, NOT Critical. Tappa 9.5
  routes canary trips through a DEDICATED rule family with
  ALWAYS-Critical severity.
- **No process / network canary detection paths.** Tappa 4
  + Tappa 10 give us the sensors; no rule logic exists yet.
- **No `nn-admin canary` CLI subcommand surface.**
- **No tripped-state tracking** (single-trip semantics).
- **No canary-content templates** under `/etc/northnarrow/`.

### 2.3 Test surface that already exists

- `agent/src/fim/rules.rs::tests::fim004_*` and
  `nn_l_fim_011_*` — Tappa 9.5 rule tests will mirror this
  pattern (one positive + one negative per canary type +
  the path-allowlist edge cases).
- `agent/tests/fim_privileged_e2e.rs` (Tappa 9 C8 +
  polish #2) — the wipe-pin-tree fixture + AgentGuard +
  install_priv_bins infrastructure is reusable verbatim
  for Tappa 9.5's canary-trip e2e tests.
- `agent/src/admin_socket.rs::dispatch_fim_baseline` /
  `dispatch_fim_report` — Tappa 9.5's
  `dispatch_canary_deploy` / `dispatch_canary_list` are
  direct ports.

---

## 3. Architecture

```text
                  ┌──────────────────────────────────┐
                  │  Operator workstation            │
                  │  (nn-admin canary {deploy|list|  │
                  │              burn|refresh})      │
                  └──────────────┬───────────────────┘
                                 │  Unix socket
                                 │  (signed AdminMessage, Tappa 8)
                  ┌──────────────▼───────────────────┐
                  │  agent/src/admin_socket.rs       │
                  │  + dispatch_canary_deploy etc.   │
                  └──────┬──────────────┬────────────┘
                         │              │
        ┌────────────────▼──┐  ┌────────▼──────────┐
        │ agent/src/canary/ │  │ agent/src/audit.rs│
        │ registry.rs       │  │ (Tappa 8 B1)      │
        │   deploy()        │  │                   │
        │   list()/burn()   │  │ Reused for both   │
        │   mark_tripped()  │  │ canaries.jsonl +  │
        └────────┬──────────┘  │ canary_access.    │
                 │             │ jsonl.            │
                 │ writes      └───────────────────┘
                 ▼
        ┌───────────────────────┐
        │ /var/lib/northnarrow/ │
        │   canaries.jsonl      │  ← Tappa 7 LSM-protected
        │   canary_access.jsonl │  ← Tappa 7 LSM-protected
        └───────────────────────┘
                 ▲
                 │ append-on-trip
                 │
        ┌────────┴──────────┐
        │ agent/src/canary/ │   Consumes Event::FsProtectDenial,
        │ detector.rs       │   Event::ProcessSpawn, Event::Fim,
        │   process_event() │   Event::NetFlow (Tappa 10) →
        └────────┬──────────┘   matches against registry →
                 │               appends CanaryAccessEntry →
                 ▼               emits Event::CanaryTripped →
        ┌───────────────────┐    forces posture → COMBAT (always).
        │ Decision engine   │
        │ NN-L-CANARY-001.. │    Critical-always, no rate-limit,
        │ + posture machine │    KillProcessTree per rule §6.
        └───────────────────┘

   ┌──────────────────────────────────────────────────┐
   │ Kernel BPF programs                              │
   │                                                  │
   │  (REUSED) fim_file_open_observe → file canary    │
   │           detection (FIM C5.2 pipeline).         │
   │  (REUSED) sched_process_exec    → process canary │
   │           detection (Tappa 4 sensor).            │
   │  (REUSED, Tappa 10) inet_csk_listen + tcp_accept │
   │           → network listener canary detection.   │
   │                                                  │
   │  NO new BPF programs. Reuses the existing        │
   │  observation pipelines; canary-vs-non-canary     │
   │  discrimination happens in userland against the  │
   │  registry.                                       │
   └──────────────────────────────────────────────────┘
```

Tappa 9.5 introduces **zero new BPF programs**. The whole
deception layer rides on existing Tappa 4 + Tappa 9 + Tappa 10
sensor outputs; userland discriminates canary vs non-canary
events against the on-disk registry. This keeps the verifier
surface unchanged and the implementation cost low — most of
the work is the registry + dispatch + rule layer.

---

## 4. Data model

### 4.1 `CanaryToken` (registry row)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    /// Operator-supplied human-readable name —
    /// `"aws_creds_backup_in_root_home"`. Used as the primary
    /// reference in nn-admin output.
    pub name: String,
    /// Per-canary stable ID — `SHA-256(name || deployed_at_unix
    /// || random_salt)[..16]`. Used for `nn-admin canary burn
    /// <id>` operator addressing.
    pub canary_id: String,
    /// Canary type — see §4.2.
    pub canary_type: CanaryType,
    /// Type-specific deployment data (path / port / cred body).
    pub deployment: CanaryDeployment,
    /// Unix timestamp at deploy time.
    pub deployed_at_unix: u64,
    /// Operator key fingerprint that signed the deploy op.
    pub deployed_by_fp: String,
    /// True once any access has been observed. Once true,
    /// subsequent accesses do NOT re-fire the posture
    /// transition (single-trip semantics). The operator can
    /// `nn-admin canary refresh <id>` to reset.
    pub tripped: bool,
    /// Populated when `tripped = true`. The first-trip
    /// `CanaryAccessEntry`'s entry_hash, for chain
    /// cross-reference.
    pub first_trip_access_hash: Option<String>,
    /// Chain integrity (Tappa 8 B1 shape).
    pub agent_id: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}
```

### 4.2 `CanaryType` + `CanaryDeployment`

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CanaryType {
    /// File at a plausible path — the OPEN is the signal.
    /// Reuses Tappa 9 C5.2 fim_file_open_observe.
    File,
    /// Executable at a plausible path — the EXEC is the signal.
    /// Reuses Tappa 4 sched_process_exec.
    Process,
    /// TCP listener on a deception port — any CONNECT is the
    /// signal. Reuses Tappa 10 inet_csk_listen +
    /// tcp_accept (NEW Tappa 10 program — listed in
    /// Tappa 10 §5 but not yet implemented at the time
    /// Tappa 9.5 ships; if Tappa 10 hasn't merged yet, the
    /// network-canary type is feature-gated dormant).
    Network,
    /// Credential file (subtype of File but separately tracked
    /// because the deployment templates differ — `.aws/credentials`
    /// shape, ssh private key shape, etc.).
    Credential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CanaryDeployment {
    File { path: PathBuf, contents_hash: [u8; 32] },
    Process { path: PathBuf, fake_arg0: String },
    Network { bind_addr: IpAddr, bind_port: u16 },
    Credential {
        path: PathBuf,
        cred_family: CredFamily,
        contents_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CredFamily {
    Aws,
    Gcp,
    Azure,
    SshPrivKey,
    GitToken,
}
```

### 4.3 `CanaryAccessEntry` (access log row)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryAccessEntry {
    pub ts: String,
    /// References `CanaryToken.canary_id`.
    pub canary_id: String,
    pub canary_name: String,
    pub canary_type: CanaryType,
    /// What the agent saw the accessor doing.
    pub access_kind: CanaryAccessKind,
    /// Process triple at access time.
    pub accessor_pid: u32,
    pub accessor_uid: u32,
    pub accessor_comm: String,
    pub accessor_exe: Option<String>,
    /// The Verdict.action that fired in response (always
    /// KillProcessTree per §6; recorded for audit-grade
    /// completeness).
    pub response_action: String,
    /// Chain integrity.
    pub agent_id: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CanaryAccessKind {
    /// File or credential canary — open() observed.
    FileOpen,
    /// Process canary — exec() observed.
    ProcessExec,
    /// Network canary — accept() observed on the deception
    /// listener.
    NetworkConnect,
}
```

---

## 5. BPF integration (REUSE only)

### 5.1 File + Credential canaries

Reuse Tappa 9 C5.2 `fim_file_open_observe`. The canary's
`(dev, ino)` goes into `WATCHED_PATHS` at deploy time. When
the kernel hook fires, the userland drain (`agent/src/fim/
drain.rs::drain_loop`) checks against BOTH the FIM watched-
paths set AND the canary registry. A match in the canary
registry takes precedence: emits `Event::CanaryTripped`
INSTEAD OF `Event::Fim`, skips the FIM rule layer entirely.

**Q4 resolution (locked-in 2026-05-19):** SHARE the
WATCHED_PATHS map (single source of truth for "kernel cares
about this inode"); userland discriminates via a parallel
in-memory `Registry` lookup. NO new BPF map. The K3 detector
exposes `Registry::is_canary_inode((dev, ino)) -> bool` as the
hot-path discriminator that runs BEFORE the FIM rule layer
(§12 Q9 inline-filter lock-in).

### 5.2 Process canaries

Reuse Tappa 4 `sched_process_exec`. Every exec event already
fires; the K3 inline detector intercepts `Event::ProcessSpawn`
in `main::process_event` BEFORE the rule engine (§12 Q9
inline-filter lock-in) and checks `event.filename` against the
registry's `CanaryType::Process` entries.

### 5.3 Network canaries

Two phases:

- **Bind phase** — at deploy time, the agent spawns an
  in-process tokio TcpListener on the canary's
  `(bind_addr, bind_port)`. This is a real listening
  socket — `ss -tlnp` shows it as `northnarrow-agent`.
- **Trip phase** — the agent's accept() loop on that
  listener returns; the agent IMMEDIATELY records the
  trip + drops the connection (NEVER reads, NEVER writes).
  Same posture transition as the other types.

Network canaries are listed in the registry but the
listener-state lives in agent process memory (one tokio task
per network canary). At agent restart, the spawn loop in
main.rs re-creates each registered network listener.

If Tappa 10 hasn't shipped at Tappa 9.5 implementation time,
the network-canary type is feature-gated dormant
(`#[cfg(feature = "tappa10-net")]`); operators can deploy file
+ process + credential canaries today, and add network
canaries once Tappa 10 lands.

---

## 6. Detection rules — NN-L-CANARY-001 through NN-L-CANARY-004

Four rules, one per canary type. All Critical-always,
KillProcessTree, posture → COMBAT. NEVER throttled by any
rate-limit (the zero-FP contract trumps storm-protection —
a real canary trip is infrequent by definition).

| ID | Title | Match | Severity | Action |
|---|---|---|---|---|
| **NN-L-CANARY-001** | File canary opened | `Event::CanaryTripped` with `access_kind = FileOpen` AND `canary_type = File` | Critical | KillProcessTree + posture→COMBAT |
| **NN-L-CANARY-002** | Process canary executed | `Event::CanaryTripped` with `access_kind = ProcessExec` AND `canary_type = Process` | Critical | KillProcessTree + posture→COMBAT |
| **NN-L-CANARY-003** | Network canary connected | `Event::CanaryTripped` with `access_kind = NetworkConnect` AND `canary_type = Network` | Critical | KillProcessTree + posture→COMBAT |
| **NN-L-CANARY-004** | Credential canary read | `Event::CanaryTripped` with `access_kind = FileOpen` AND `canary_type = Credential` | Critical | KillProcessTree + posture→COMBAT |

The four rules are functionally near-identical (same severity,
same action, same posture transition); the distinct
`rule_id` exists so:

1. The audit chain row distinguishes canary types for
   operator triage (`grep canary_type=Credential`).
2. ADE prompt variation: Credential trips get a richer
   prompt (which cred family, what was the modifier
   process expecting to do with stolen creds); Network
   trips get the connecting peer's IP + JA3 from Tappa 10.
3. Future per-type response-action diversification (V1.1:
   credential canary trip → also rotate operator-managed
   keys in cloud control plane; file canary trip → also
   snapshot the host's process tree for forensics).

**Cross-cutting:** the canary detector is the SOLE consumer
of `Event::CanaryTripped`. The FIM rule layer does NOT see
these events (the detector filters them out before they
reach the FIM evaluation path). This prevents
NN-L-CANARY-001 + NN-L-FIM-011 firing in tandem on a
credential canary read (both would fire KillProcess; the
canary rule wins by happening first AND by being Critical
vs the FIM rule's High).

---

## 7. Canary deployment + lifecycle

### 7.1 Deploy

`nn-admin canary deploy <type> --name <name> [type-specific
flags]`:

- File: `--path /root/aws_keys_backup.txt --template aws`
- Process: `--path /usr/local/bin/sysadmin-helper
  --fake-arg0 "sysadmin-helper --serve"`
- Network: `--bind 0.0.0.0:4444`
- Credential: `--path /root/.aws/credentials.bak --cred-family
  aws`

Signed admin op (1-of-N quorum, `Role::CanaryManage`). Server-
side:

1. Renders the canary content from the template (V1.0
   templates ship in
   `/etc/northnarrow/canary-templates/<family>.tmpl`;
   operator can override via `.local`).
2. Writes the file / spawns the listener / installs the
   binary.
3. Registers the inode (for file/credential types) into
   `WATCHED_PATHS` BPF map.
4. Appends `CanaryToken` row to `canaries.jsonl` (signed,
   chained per Tappa 8 B1).
5. Emits info-log line + audit-row.

### 7.2 List

`nn-admin canary list`: signed admin op (1-of-N,
`Role::CanaryRead`). Returns the full registry as a JSONL
body (same shape as `nn-admin fim report`), one
CanaryToken per line. Operator pipes to `jq` for filtering.

### 7.3 Burn (retire)

`nn-admin canary burn <canary_id>`: signed admin op (1-of-N,
`Role::CanaryManage`). Server-side:

1. Removes the canary file / kills the listener task /
   removes the binary.
2. Removes the inode from `WATCHED_PATHS`.
3. Appends a `burn` row to `canaries.jsonl`.
4. The original deploy row stays in the chain (audit
   history); the burn row is the "this canary is no
   longer active" marker.

### 7.4 Refresh (reset tripped flag)

`nn-admin canary refresh <canary_id>`: signed admin op (1-of-N,
`Role::CanaryManage`). For operators who want to keep a
canary deployed after the first trip (e.g., during a
post-incident recovery, leaving the canary in place to
detect repeat attempts).

1. Sets `tripped: false` on the in-memory registry.
2. Appends a `refresh` row to `canaries.jsonl`.
3. Subsequent accesses re-fire the rule + posture
   transition.

### 7.5 Single-trip lockout window

Per §1 — single-trip semantics. The first access to a
deployed canary:

1. Fires NN-L-CANARY-00X + posture transition to COMBAT.
2. Marks the in-memory registry's `tripped: true`.
3. Appends `CanaryAccessEntry` to
   `canary_access.jsonl`.

Subsequent accesses to the SAME canary in the same agent
session:

1. STILL append `CanaryAccessEntry` to the chain (forensic
   completeness — the access log captures every access).
2. Do NOT re-fire the rule (the rule abstains when
   `canary.tripped == true`).
3. Do NOT re-trigger the posture transition (COMBAT is
   already engaged).

This is the right semantics because the deterministic
response (KillProcessTree + COMBAT) has ALREADY fired; the
attacker's process tree is being torn down + the host is
network-isolated. Re-firing would burn audit-chain budget
without operational value.

---

## 8. Wire protocol

NEW `AdminMessage` variants appended LAST (postcard
discriminant preservation per the §A7 wire-stability rule
in force since Tappa 8). Note: **OperationCode + Role
numbering is contested with Tappa 10's design RFC** — the
agreed final numbering is set at implementation-merge time;
this doc proposes the FIRST AVAILABLE op-codes after Tappa 9
C7's FimStatus = 9. If Tappa 10 lands first, these slide.

Proposed:
- `OperationCode::CanaryDeploy = 10`
- `OperationCode::CanaryList = 11`
- `OperationCode::CanaryBurn = 12`
- `OperationCode::CanaryRefresh = 13`
- `Role::CanaryManage = 8` (deploy + burn + refresh)
- `Role::CanaryRead = 9` (list)

The CLI flows mirror `nn-admin fim` exactly: challenge →
SignedPayload → submit → reply.

---

## 9. Systemd / deploy

No new systemd units. Canary listener tasks run inside the
agent's existing tokio runtime (one `tokio::spawn` per
deployed network canary, started in main.rs post-attach +
post-registry-load).

Install changes (`deploy/install.sh` additions):

1. Bootstrap `/var/lib/northnarrow/canaries.jsonl` +
   `canary_access.jsonl` as zero-byte placeholders.
2. Drop canary content templates at
   `/etc/northnarrow/canary-templates/`:
   - `aws-creds.tmpl` (fake `[default]` block with
     AKIA-prefixed key)
   - `gcp-creds.tmpl` (fake service-account JSON)
   - `azure-creds.tmpl` (fake `~/.azure/` config)
   - `ssh-priv.tmpl` (fake RSA private key shape)
   - `git-token.tmpl` (fake GitHub PAT)
3. `STATE_PROTECTED_FILES` extends to cover the two
   canary chains.
4. `ETC_PROTECTED_FILES` extends to cover
   `canary-templates/` directory (operator-readable,
   tamper would silently widen what content gets
   deployed).

V1.0 ships NO default canaries. Operators deploy explicitly
via `nn-admin canary deploy` — the deception strategy is
intentionally operator-controlled (placement defeats the
purpose if predictable from public defaults).

---

## 10. Testing strategy

### 10.1 Unit tests

- `agent/src/canary/registry.rs::tests` — deploy / list /
  burn / refresh state machine + chain integrity
  (~10 tests).
- `agent/src/canary/detector.rs::tests` — Event::Fim /
  Event::ProcessSpawn matching against registry + canary-vs-
  FIM precedence (~8 tests).
- `agent/src/canary/templates.rs::tests` — template
  rendering for the 5 credential families (~6 tests).
- `agent/src/decision/rules/canary.rs::tests` — 4 rules
  with positive + negative + tripped-no-refire (~12 tests).

### 10.2 Privileged e2e

Three privileged tests reusing the PHASE_D_003
`install_to_priv_bin` pattern (now ubiquitous post-Tappa 9
polish #1):

1. `canary_file_open_fires_combat_and_kills_modifier` —
   deploy a file canary, `cat` it from a subprocess,
   verify (a) `canary_access.jsonl` has the trip row,
   (b) the subprocess is killed (process gone within
   100ms), (c) `nn-admin status` shows posture = Combat
   + iptables NORTHNARROW_COMBAT chain present.
2. `canary_process_exec_fires_combat` — deploy a process
   canary, exec it, verify the same triad.
3. `canary_refresh_re_arms_the_token` — deploy + trip
   once, `nn-admin canary refresh <id>`, trip again, verify
   the second trip ALSO fires (the chain has 2 access
   rows + the registry's tripped flag is cleared then
   set again).

---

## 11. Effort estimate — commit-by-commit plan

Numbered against the §2.1/§2.2 inventory. Re-uses existing
`agent-ebpf` (no new BPF), `agent/src/fim/drain.rs`,
`agent/src/audit.rs`, `agent/src/admin_socket.rs`
infrastructure. Estimated commit-by-commit; total
**~28–35 hours**.

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **K1** | `feat(common): CanaryToken + CanaryAccessEntry + CanaryType wire types + Role::CanaryManage/CanaryRead + OperationCode::Canary* additions` | New wire types + role/op-code additions. Tests: 6 (round-trip + variant ordering + role parse). | 3 |
| **K2** | `feat(agent): canary/registry.rs — deploy + list + burn + refresh state machine + chained on-disk DB` | Pure userland registry + JSONL writer reusing audit.rs primitives. Tests: 10. | 5 |
| **K3** | `feat(agent): canary/detector.rs — Event::Fim/ProcessSpawn intercept + canary-vs-FIM precedence + Event::CanaryTripped emit` | Tokio task subscribed to the event bus; filters before the FIM rule layer sees it. Tests: 8. | 4 |
| **K4** | `feat(agent): canary/templates.rs + canary-templates/*.tmpl — 5 credential family templates + renderer` | Template-driven cred-canary content; operator override via .local. Tests: 6. | 3 |
| **K5** | `feat(decision): 4 canary rules NN-L-CANARY-001..004 + always-Critical + posture→Combat` | One rule per canary type. Tests: 12. | 3 |
| **K6** | `feat(admin_cli): nn-admin canary deploy / list / burn / refresh subcommands + signed-payload wiring + audit emission` | CLI surface + dispatch_canary_*. Mirrors Tappa 9 C6 audit CLI pattern. Tests: 10. | 5 |
| **K7** | `feat(deploy): canary-templates/ + install.sh bootstrap + LSM widening of canaries.jsonl + canary_access.jsonl + ETC widening for canary-templates/` | install.sh changes + STATE/ETC_PROTECTED_FILES extensions. Tests: 4. | 2 |
| **K8** | `test(privileged_e2e): canary file-open trip + process-exec trip + refresh re-arm` | New `agent/tests/canary_privileged_e2e.rs` file. Reuses install_to_priv_bin. Tests: 3 privileged. | 4 |
| | **TOTAL** | | **~28–35 hours** ≈ 1 working week with CC pair-programming. |

Phase-1 ships at K8 (CLI + 4 canary types + audit-grade
reporting + e2e proof). Tappa 9.5 is INTENTIONALLY scoped
small — it's the surgical zero-FP complement to the broad
FIM heuristics, not a full deception suite.

---

## 12. RFC resolutions

All 10 RFC items resolved 2026-05-19 (owner-accepted engineering
recommendations). K1 implementation now unblocked. Each block
below: **Decision**, **Rationale**, **Implementation note**
(where in this doc / commit plan the decision manifests),
**Reversibility cost**.

### Q1 — Canary placement strategy

- **Decision:** EXPLICIT PER-HOST DEPLOYMENT. V1.0 ships
  content templates (`canary-templates/*.tmpl`), NOT
  default deployments. Every canary placement is an
  operator-driven `nn-admin canary deploy` call.
- **Rationale:** default placements defeat deception —
  any attacker familiar with NorthNarrow checks those
  paths FIRST and avoids them. Operator-curated placement
  (informed by the host's actual workflow shape) is the
  irreducible-minimum-effort cost of a useful deception
  layer.
- **Implementation note:** §7 deploy/lifecycle + §9 deploy
  install.sh ships templates only; K6 CLI surfaces
  `nn-admin canary deploy <type> --path <...>`.
- **Reversibility:** medium — adding default deployment
  later forces operators to either trip-then-burn the
  defaults OR live with them; deferring keeps the option
  open.

### Q2 — Refresh policy (auto vs manual)

- **Decision:** MANUAL REFRESH ONLY. A tripped canary stays
  tripped until `nn-admin canary refresh <id>` (signed,
  audit-chained); subsequent accesses log to the chain but
  do NOT re-fire posture transitions.
- **Rationale:** auto-refresh would lose the "this host has
  been compromised" signal from subsequent agent boots.
  IR processes need the explicit operator decision —
  audit-chained, not magic state change.
- **Implementation note:** §7.4 + K2 `Registry::mark_tripped`
  / `Registry::refresh`; K5 rule abstains when
  `canary.tripped == true`.
- **Reversibility:** easy (operators can script
  `nn-admin canary refresh` as a cron job if policy wants
  auto-refresh).

### Q3 — Multi-canary correlation in audit chain

- **Decision:** NO V1.0 correlation. Each trip is an
  independent audit row; cross-canary correlation is
  operator post-hoc analysis via `jq` on the chain.
- **Rationale:** auto-correlation would add a correlation-
  window state machine + a new chain entry type + matching
  rules — complexity strictly additive over what V1.0's
  individual-trip records already provide.
- **Implementation note:** K2 registry stays single-trip-
  per-event; no `canary_campaign.jsonl` shipped in K2-K8.
- **Reversibility:** easy (V1.1 can add a separate
  `canary_campaign.jsonl` chain that references existing
  trip entries by entry_hash).

### Q4 — WATCHED_PATHS map sharing vs separate CANARY_PATHS

- **Decision:** SHARE the FIM `WATCHED_PATHS` BPF map for
  canary inode tracking. Userland discriminates via a
  parallel `Registry` lookup. NO new BPF map.
- **Rationale:** 8192-entry capacity of WATCHED_PATHS has
  plenty of headroom (~100 FIM + ~10-50 canaries = well
  under cap). Userland discrimination is a microsecond
  HashMap lookup. Separate map would double the BPF
  complexity for no operational benefit.
- **Implementation note:** §5.1 SHARE lock-in. K3 detector
  inspects `Registry::is_canary_inode((dev, ino))`
  BEFORE the FIM rule layer sees the event (race-free
  precedence per Q9).
- **Reversibility:** medium — if real-world deployments
  hit the cap, V1.1 can split into two maps. Migration:
  operators export registry → bump map size → re-deploy.
  No on-disk format change.

### Q5 — Credential canary content authenticity

- **Decision:** LEVEL A in V1.0 — valid format + valid
  checksum (AWS AKIA-prefixed key with correct format,
  GCP service-account JSON with valid structure, SSH
  RSA private key shape), no online verification.
- **Rationale:** Level B (online registration with a
  backend) is a Tappa 13 SaaS-Backend feature; sovereign
  deployments can't validate online tokens. Operators
  with online-verification budgets integrate via their
  own SIEM/SOAR feeding off `canary_access.jsonl`.
- **Implementation note:** §1 OUT OF SCOPE + K4 templates
  ship 5 cred families (AWS/GCP/Azure/SSH/Git) all at
  Level A. Tappa 13 adds the online-verify backend
  additively.
- **Reversibility:** easy (Level B is additive; V1.0
  Level A canaries stay valid Level A under Tappa 13).

### Q6 — Network canary connection handling

- **Decision:** IMMEDIATE CLOSE on connect. Zero data
  sent or received; the connect itself is the signal.
  `tokio::TcpListener::accept()` returns; the agent
  immediately records the trip + drops the socket
  without read/write.
- **Rationale:** banner-then-disconnect (Option B) leaks
  "this is deception" to a clever attacker via the
  fingerprintable banner+RST pattern. Honeypot-style
  (Option C) is Tappa 11+ territory + adds attacker-
  controlled-input attack surface. Immediate-close is
  the irreducible signal — KillProcessTree fires on the
  local accessor before any attacker payload arrives.
- **Implementation note:** §5.3 trip phase + K2 registry's
  network-canary task. NO `.read()` / `.write()` call on
  the accepted socket.
- **Reversibility:** easy (operator-tunable in V1.1; V1.0
  immediate-close is the safe default).

### Q7 — Operator key role allocation

- **Decision:** SPLIT into `Role::CanaryRead` (list-only,
  audit-grade read access) + `Role::CanaryManage` (deploy +
  burn + refresh). Same shape as Tappa 9 C6's `FimManage`
  + `FimRead`.
- **Rationale:** audit-only operators (IR, compliance)
  get read without deploy authority. Operational
  operators (sysadmins) get the full surface. Two roles
  at V1.0 means operators provision the right
  granularity from day one; adding roles later means
  re-issuing keys.
- **Implementation note:** K1 wire types + K6 CLI dispatch
  enforces `Role::CanaryManage` on deploy/burn/refresh,
  `Role::CanaryRead` on list. Same `verify_signed_payload_quorum`
  1-of-N pattern from Tappa 9 C6 (§13 Q6 workflow-gate
  precedent).
- **Reversibility:** easy (adding roles later is additive;
  splitting day one avoids the operator-key-migration
  cost).

### Q8 — Canary chain rotation policy

- **Decision:** V1.0 KEEPS FULL CHAIN. V1.1 ships signed
  `nn-admin canary rotate` op with chain-of-chains
  continuation (same shape as Tappa 8 §14 Q9 audit-rotate
  + Tappa 9 §13 Q8 baseline-rotate).
- **Rationale:** canary chains stay tiny (operator deploys
  ~10-50; trips are rare by zero-FP construction). Full
  retention is operationally trivial — a 100-entry chain
  is ~25 KB.
- **Implementation note:** no V1.0 implementation work;
  documented as deferred follow-up. V1.1 rotate joins
  Tappa 8 audit + Tappa 9 FIM rotations.
- **Reversibility:** easy (V1.1 rotate is additive; un-
  rotated chains stay verifiable forever).

### Q9 — Detector integration point

- **Decision:** OPTION B (inline filter) — the canary
  detector runs as a synchronous discriminator inside
  `main::process_event`, BEFORE the rule engine sees the
  `Event::Fim` / `Event::ProcessSpawn` / `Event::NetFlow`.
- **Rationale:** the canary lookup (registry HashMap query
  by inode/path/exe) is microseconds. Running it inline
  preserves the canary-vs-FIM precedence GUARANTEE (canary
  rule fires BEFORE the FIM rule layer sees the event).
  Option A (separate tokio task with channel clone) would
  race — NN-L-FIM-011 could fire alongside NN-L-CANARY-004.
- **Implementation note:** §3 architecture + K3 `detector.rs`
  exposes `process_event(event, registry) -> Option<Event::CanaryTripped>`;
  main.rs calls it inline pre-rule-engine. K3 returns
  `None` for non-canary events so the rule engine sees
  the original event unchanged.
- **Reversibility:** medium — refactor to Option A later
  is a self-contained change but invalidates the test
  fixtures' inline-filter assertions.

### Q10 — Tappa 13 backend mirror

- **Decision:** DEFER TO TAPPA 13. V1.0 local
  `canaries.jsonl` + `canary_access.jsonl` + signed
  `nn-admin canary list --json` export is the audit-
  grade primitive; remote mirroring is an additive
  future feature.
- **Rationale:** mirroring requires backend-SaaS
  architecture decisions out of Tappa 9.5 scope. The
  on-disk format Tappa 9.5 ships IS the streaming
  protocol Tappa 13 will consume (Tappa 9 §13 Q10
  precedent — same on-disk-IS-the-wire-format design).
- **Implementation note:** no V1.0 implementation work.
- **Reversibility:** easy (additive future feature; no
  V1.0 commitment to preclude).

### Cross-cutting consistency (lock-ins captured above)

1. **Q1 (no defaults) + Q5 (Level A content)** → V1.0
   ships TEMPLATES, not deployments. Operator does the
   placement; agent renders the content from the
   templates K4 installs.
2. **Q4 (shared map) + Q9 (inline filter)** → the canary
   detector intercepts Event::Fim BEFORE the FIM rule
   layer; one map, one lookup, race-free precedence.
   `Registry::is_canary_inode` is the K3 hot-path
   discriminator.
3. **Q2 (manual refresh) + Q6 (immediate close)** → both
   reflect the "tight, surgical, audit-chained" design
   philosophy. Avoid magic auto-state-changes. Operator
   intent + audit chain are the only state-transition
   triggers.
4. **Q7 (split roles) + Q3 (no correlation)** → the V1.0
   surface stays small; growing it (auto-correlation,
   more roles) is additive future work. `Role::CanaryRead`
   audit-grade access composes cleanly with future
   correlation views.
5. **Q8 (V1.0 keep) + Q10 (defer mirror)** → Tappa 9
   precedents adopted verbatim. Consistency reduces
   operator cognitive overhead across the chained-
   audit primitives (Tappa 8 audit / Tappa 9 FIM
   baseline+drift / Tappa 9.5 canary registry+access).

---

## Appendix A — Cross-references

- Tappa 4 process-spawn sensor — `agent-ebpf/src/exec_sensor.rs`
  (existing tracepoint Tappa 9.5 process canary reuses).
- Tappa 7 task 5 — `agent/src/anti_tamper/filesystem.rs`
  (STATE_PROTECTED_FILES + ETC_PROTECTED_FILES Tappa 9.5
  extends with canary files).
- Tappa 8 §9 — `agent/src/audit.rs` chain primitives the
  canary chains reuse.
- Tappa 9 C5.2 — `agent-ebpf/src/fim_watch.rs::fim_file_open_observe`
  (the kernel-side hook file + credential canaries
  consume).
- Tappa 9 C7 — `docs/operator/TAPPA9_FIM_TRUST_MODEL.md`
  (overlay-config + boot-WARN-on-disabled pattern Tappa
  9.5's canary-templates `.local` follows).
- Tappa 9 polish #1 — `agent/tests/privileged_e2e.rs`
  `install_priv_bins` (R009 avoidance pattern Tappa 9.5
  e2e tests directly reuse).
- Tappa 10 design — `docs/design/TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md`
  (the network-canary type depends on Tappa 10's
  `inet_csk_listen` BPF program; feature-gated dormant if
  Tappa 10 ships later).

## Appendix B — Threat-model recap

| Reconnaissance behaviour | Canary that catches it |
|---|---|
| `grep -r AKIA ~/` (search for AWS keys) | Credential canary `aws-creds.tmpl` in `.aws/credentials.bak` |
| `cat /root/.ssh/*` (enumerate SSH keys) | Credential canary `ssh-priv.tmpl` in `id_rsa.bak` |
| `ls /usr/local/bin/` then exec something interesting | Process canary `sysadmin-helper` |
| `nmap -p- <host>` (port scan) | Network canary on port 4444 / 31337 / 9999 |
| `find / -name "*backup*"` (file enum) | File canary `aws_keys_backup.txt` |
| Cobalt Strike `recon-credentials` module | Credential canary (multiple families) |

Every reconnaissance pattern in the table is detected within
MILLISECONDS of the canary access (file open / process exec /
network connect are kernel-immediate events). The
deterministic response (KillProcessTree + posture → COMBAT +
network isolation via Tappa 5's iptables ruleset) fires before
the attacker can complete the reconnaissance — and the
operator gets an audit-grade chain row pointing at the
attacker's process tree.

The zero-FP property means EVERY entry in
`canary_access.jsonl` is a real intrusion. There is no triage
noise. This is what makes deception complementary to (not
overlapping with) the heuristic engines in Tappa 9 (FIM) and
Tappa 10 (NetFlow).
