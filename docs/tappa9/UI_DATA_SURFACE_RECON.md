# Tappa 9 (Local GUI) — UI Data-Surface Recon

**Status:** Read-only recon. No code changed, no dependencies added, no UI scaffolding built.
**Date:** 2026-06-08
**Repo:** `/home/forty/dev/northnarrow-new` (workspace members: `agent`, `common`, `watchdog`, `cli`, `antitamper-bpf`, `ebpf-guard`, `xtask`)
**Goal:** Map the agent's existing UI-consumable data surface to the reference "threat-detection dashboard" layout, and identify what is MISSING for later Tappa 9 sub-steps.

> **Naming note:** "Tappa 9" is overloaded in this repo. `docs/design/TAPPA9_FIM_DESIGN.md` and `docs/operator/TAPPA9_FIM_TRUST_MODEL.md` use "Tappa 9" for the FIM work. This document uses "Tappa 9" per the current task brief = **the local native desktop GUI** (Tauri 2 + React/TS). Filed under `docs/tappa9/` to avoid colliding with the FIM design docs in `docs/design/`.

## Method

Four parallel read-only passes over the agent, common, and wire crates, plus direct verification by the author of the two load-bearing claims (§1 unauthenticated status, §3 non-persistence of verdicts). All `file:line` refs are against the current working tree. `~line` = approximate anchor.

## Legend

- **AVAILABLE** — exists today, a UI can consume it with no agent-side change.
- **PARTIAL** — some of the data exists but is incomplete, transient, root-gated, or needs glue (log scraping / a new read verb).
- **MISSING** — does not exist; must be built in a later Tappa 9 sub-step.

---

## Executive summary

| # | Surface | Verdict | One-line |
|---|---|---|---|
| 1 | Admin socket protocol & auth | **PARTIAL** | postcard/Unix-socket RPC, full command set mapped; only `Status`+`Challenge` are unauthenticated; socket is **0600 root-only**. |
| 2 | `status --json` | **PARTIAL** | Only **3 fields** (posture, net-isolation, last-admin-action-age). Hand-rolled JSON. No mode/sensors/rules/health/build_hash. |
| 3 | **Detection / alert representation** | **MISSING** ⛔ | **No detection store, no query, no stream.** Verdicts are `warn!`-logged + executed, then dropped. *This is the central Tappa 9 gap.* |
| 4 | Posture | **PARTIAL** | Current scalar posture is readable via `Status`. Transition **timeline** is in-memory only (cap 256), not externally readable. |
| 5 | ADE verdict + XAI | **MISSING** ⛔ | ADE verdict is transient (only `step_5_decision` logged). XAI `XaiEvidenceChain` exists but is **never invoked at runtime**. |
| 6 | Rules | **PARTIAL** | 69 rules compiled-in, enumerable in-process via builders; **no socket/CLI/file** exposes the catalog. No enable/disable bit. |
| 7 | Audit / chainlog | **AVAILABLE** | `/etc/northnarrow/audit.log` — 0644 signed JSONL, parseable directly, no auth. Domain chainlogs under `/var/lib` are 0700. |
| 8 | Logs | **PARTIAL** | journald-only, **free-text** (`LogNamespace=northnarrow`). No structured JSON log file, no tail socket. |
| 9 | Manual actions | **PARTIAL** | Full signed control set mapped. **No acknowledge/close-detection** and no trigger/cancel-response verb (only coarse `force-posture`/`unlock`). |
| 10 | Existing UI / frontend | **MISSING** | Nothing. Clean slate — no Tauri/web/egui/package.json anywhere. |

**The two questions the brief calls out explicitly:**

- **(§3) Is there a detection store a dashboard can read?** **No.** After a rule fires or ADE returns, the `Verdict`/`AdeVerdict` is logged to journald and handed to the response executor, then dropped. There is no in-memory ring buffer of detections, no on-disk detection log, no broadcast channel, and no "list detections" socket verb. A dashboard cannot list "the last N detections" or aggregate them for the Sankey through any existing interface. **An agent-side detection store + read/stream API is the prerequisite for the entire dashboard.**
- **(§1) Can a display UI poll state WITHOUT the COMBAT recovery key?** **Only barely.** Exactly two messages are unauthenticated: `ChallengeRequest` and `Status` (3 fields). Every richer read (FIM, canary, netflows, listeners) requires a **signed challenge with an admin.pub private key** carrying the relevant read role. And the socket itself is **mode 0600, root-owned** — so even the unauthenticated reads require the UI to run as root. Read-only telemetry is **not** cleanly separable from the privileged control plane today.

---

## §1 — Admin socket: wire protocol & auth — **PARTIAL**

### Socket, bind, framing

- **Path:** `/run/northnarrow/admin.sock`. `DEFAULT_SOCKET` at `agent/src/bin/nn_admin.rs:46`; documented `common/src/wire/admin_protocol.rs:4`, `common/src/wire/mod.rs:796`.
- **Server:** `serve_with_marker_path` `agent/src/admin_socket.rs:352` — unlinks stale socket (`:366`), `UnixListener::bind` (`:376`), **forces `chmod 0600`** (`:381`), accept loop (`:388-420`), one task per connection via `handle_connection` (`:438`). One-frame-request → one-frame-reply, looped to EOF (`:455-475`).
- **Permissions:** **mode 0600, owner root:root** (`:381`; comment `:378-380` notes "V1.1 will tighten to root:northnarrow 0660"). `SO_PEERCRED` is read (`peer_creds` `:523-554`) but used **only to populate audit `client_*` fields — never to gate access**.
- **Framing / serialization:** **`postcard`** (varint), **not** bincode/CBOR. `encode_frame`/`decode_frame` `admin_protocol.rs:790`,`:814`. **4-byte `u32` big-endian** length prefix + postcard body. **`MAX_FRAME_BODY = 64 KiB`** (`admin_protocol.rs:716`), enforced on encode/decode and in the agent reader (`admin_socket.rs:2070`).
- **Version handshake — dead code:** `PROTOCOL_VERSION=1`, `VersionedAdminMessage`, `encode_versioned_frame`/`decode_versioned_or_legacy_frame` exist (`admin_protocol.rs:726`,`:843-962`) but the live agent reader/writer (`admin_socket.rs:2062`,`:2087`) and the CLI both use the **bare** `decode_frame`/`encode_frame`. Production wire = unversioned bare `AdminMessage`. (Module doc admits A1 "does not rewire admin_socket.rs", `admin_protocol.rs:54-63`.)

### Complete command set + auth (the full `AdminMessage` enum, `admin_protocol.rs:586-710`)

| Command (request) | Reply | Auth model / Role | Read/Mutate |
|---|---|---|---|
| `ChallengeRequest` | `Challenge{nonce:[u8;32]}` | **UNAUTHENTICATED** (rate-limit only) | read (mints nonce) |
| `Status` | `StatusResponse` | **UNAUTHENTICATED** | **read** |
| `Unlock` | `UnlockResult` | Ed25519 over nonce, 1-of-N, `Role::Unlock` | mutate (release COMBAT) |
| `ShutdownRequest` | `ShutdownResult` | signed quorum **2-of-N**, `Role::Shutdown` | mutate |
| `ForcePostureRequest` | `ForcePostureResult` | quorum **1-of-N**, `Role::ForcePosture` | mutate |
| `RotateKeysAddRequest` | `RotateKeysAddResult` | quorum **2-of-N** (1-of-N if bootstrap-armed), `Role::RotateKeys` | mutate (rewrites admin.pub) |
| `RotateKeysRevokeRequest` | `RotateKeysRevokeResult` | quorum **2-of-N**, `Role::RotateKeys` | mutate |
| `FimBaselineRequest` | `FimBaselineResult` | quorum **1-of-N**, `Role::FimManage` | mutate |
| `FimReportRequest` | `FimReportResponse` | quorum **1-of-N**, `Role::FimRead` | **read** (dumps one JSONL) |
| `FimStatusRequest` | `FimStatusResponse` | quorum **1-of-N**, `Role::FimRead` | **read** (counts) |
| `CanaryDeployRequest` | `CanaryDeployResponse` | quorum **1-of-N**, `Role::CanaryManage` | mutate |
| `CanaryListRequest` | `CanaryListResponse` | quorum **1-of-N**, `Role::CanaryRead` | **read** |
| `CanaryBurnRequest` | `CanaryBurnResult` | quorum **1-of-N**, `Role::CanaryManage` | mutate |
| `CanaryRefreshRequest` | `CanaryRefreshResult` | quorum **1-of-N**, `Role::CanaryManage` | mutate |
| `NetFlowsRequest` | `NetFlowsResponse` | quorum **1-of-N**, `Role::NetRead` | **read** |
| `NetListenersRequest` | `NetListenersResponse` | quorum **1-of-N**, `Role::NetRead` | **read** |
| `NetResolveRequest` | `NetResolveResponse` | quorum **1-of-N**, `Role::NetRead` | **read** |
| `NetFingerprintRequest` | `NetFingerprintResponse` | quorum **1-of-N**, `Role::NetRead` | **read** |
| `TrustedInstallerGrantRequest` | `TrustedInstallerGrantResult` | quorum **1-of-N** (M=1), `Role::TrustedInstaller` | mutate (arms FS-pin) |
| `DebugForcePosture` *(cfg `debug-trigger` only)* | `DebugForcePostureAck` | **UNAUTH, bypasses verify** — not in prod builds | mutate |

Dispatch match: `admin_socket.rs:912-1128`. Roles: `common/src/wire/admin_signed_payload.rs:212-261` (`Unlock=1…TrustedInstaller=12, All=255`). `Role::AuditRead=5` and `Role::NetManage=11` exist but **no socket command requires them** (audit read is a local file op — §7; there is no net-mutate verb). Signed path = `AdminAuth::verify_signed_payload_quorum(...)` `agent/src/anti_tamper/admin_auth.rs:769` (nonce-binding + op-tag + agent_id + ±60s skew + per-sig verify + distinct-key tally + role check).

### CRITICAL: read-only telemetry vs privileged control

- **Unauthenticated reads = `Status` + `ChallengeRequest` only.** `Status` handler returns `posture.current_kind()`, `isolator.is_engaged()`, `posture.last_admin_action_secs_ago()` with **zero auth** (verified: `admin_socket.rs:999-1003`). `ChallengeRequest` mints a nonce with only a rate-limit check (`admin_auth.rs:396-417`).
- **Every richer read requires an admin private key** carrying a read role (`FimRead`/`CanaryRead`/`NetRead`). There is **no key-less path** to FIM drift, canary registry, netflows, listeners, rule count, sensor health, BTF, or build_hash.
- **Socket reachability requires root** (0600 root:root). No group carve-out yet.
- **Verdict:** a dashboard can poll the 3 `Status` fields key-lessly **but still must run as root**. For anything richer it must hold a real admin.pub key (a role-limited `FimRead,CanaryRead,NetRead` key is the closest "read-only" approximation, but it is still admin key material on the same control socket). **This is a design gap:** there is no read-only, non-root telemetry channel. *Recommendation for a later sub-step:* either (a) a dedicated unauthenticated/credential-light read socket scoped to display data, or (b) widen `StatusResponse` and add a `Role`-gated but read-only "telemetry" verb, plus tighten the socket to `root:northnarrow 0660` so a non-root GUI service account can connect.

---

## §2 — `status --json` schema — **PARTIAL**

`StatusResponse` (verbatim, `common/src/wire/admin_protocol.rs:538-543`) — verified:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub posture: PostureKind,                       // Observing|Alerted|Engaged|Combat
    pub network_isolation_engaged: bool,            // COMBAT network lockdown indicator
    pub last_admin_action_secs_ago: Option<u64>,
}
```

`nn-admin status --json` is **hand-rolled** (not serde) in `print_status` `agent/src/bin/nn_admin.rs:1445-1458`:

```json
{"posture":"Combat","network_isolation_engaged":true,"last_admin_action_secs_ago":42}
```

- `posture` = the `{:?}` Debug name of `PostureKind` (`"Observing"|"Alerted"|"Engaged"|"Combat"`). No serde renames involved.
- `last_admin_action_secs_ago` = integer or JSON `null`.
- Client round-trip `run_status` `agent/src/admin_cli.rs:209-221`; mirror type `StatusOutcome` `:104-109`.

**MISSING from status entirely** (not behind auth either — simply not on the wire): **mode (detect/enforce), sensors-up, rule count, health/BTF status, `build_hash`.** The dashboard's "Agent status panel" (brief item 3) needs all of these — only posture + COMBAT/net-isolation are obtainable today. (FIM watched-path/baseline/drift counts exist but only behind the authenticated `FimStatusResponse` `admin_protocol.rs:275-308`.)

---

## §3 — Detection / alert representation — **MISSING** ⛔ *(HIGHEST-PRIORITY FINDING)*

### There is no detection record, no store, no query, no stream.

**Verified terminal sink** (`agent/src/main.rs::process_event`): a rule verdict is `warn!("VERDICT (rule)")`-logged (`main.rs:2344-2354`) then `executor.execute(...)` then `return` (`:2356-2376`). The ADE path is identical: `warn!("VERDICT (ADE)")` (`:2408-2415`) → `posture.modulate_verdict` → execute → `return` (`:2417-2455`). **No `.append()`, `.push()`, `.send()`, or serialize of the verdict anywhere.** The struct is dropped at end of scope.

> Architectural nuance for the Sankey: **rule and ADE are mutually exclusive per event** — ADE only runs when *no rule matched* (`main.rs:2343` early-return vs `:2389` "no rule matched, escalating to ADE"). So a single event yields **either** a rule `Verdict` **or** an `AdeVerdict`, never both. Posture modulation applies to the **ADE path only** (`:2419`); rule verdicts execute unmodulated. A "Sensor → Rule → Severity → ADE Verdict → Posture" Sankey therefore models two distinct flows, not one linear pipeline.

### The "detection" types (all in-memory, none persisted as a unified record)

**(1) `Verdict`** — rule-engine output, `common/src/model.rs:549-560`:
```rust
pub struct Verdict {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,        // coarse string, e.g. "execution" — NOT a MITRE ID
    pub action: ResponseAction,
    pub severity: Severity,      // Low|Medium|High|Critical (model.rs:522)
    pub reasoning: String,
    pub event_pid: u32,
    pub event_filename: String,  // no uid, no comm, no ppid
    pub timestamp_ns: u64,       // CLOCK_MONOTONIC ns, not wall-clock
}
```
Built by `build_verdict` `agent/src/decision/rules/mod.rs:232-268`.

**(2) `AdeVerdict`** — LLM fallback, richest shape, `common/src/ade_types.rs:52-80`. Carries `confidence: f64`, `severity: AdeSeverity`, `verdict: AdeAction`, `threat_classification`, `reasoning: ReasoningSteps` (5 steps), `evidence`, `mitre_attack: MitreAttack{tactic:Vec<String>, technique:Vec<String>}` (`ade_types.rs:150-155`), `recommended_action`, `metadata`. **Computed only for non-rule-matched events; never persisted.**

**(3) Persisted on-disk records (raw per-domain events, NOT verdicts)** — these survive but are siloed and lack rule_id/verdict:
- `FimDriftEntry` — `agent/src/fim/drain.rs:381-440` (`ts,path,op,baseline_sha256,new_sha256,modifier_pid/uid/comm,severity:DriftSeverity,…`).
- `NetFlowPayload` — `agent/src/net/drain.rs:167`.
- `CanaryAccessEntry` — `agent/src/canary/access_log.rs:65-97`.
- `AuditEntry` — `agent/src/audit.rs:291` (admin ops only).

### Field-coverage table (what the reference detection table needs)

| UI field (brief item 2) | Exists? | Where | Notes |
|---|---|---|---|
| timestamp | PARTIAL | `Verdict.timestamp_ns` (monotonic); persisted records use ISO-8601 `ts` | verdict ts isn't wall-clock |
| severity pill | AVAILABLE (transient) | `Verdict.severity` / `AdeVerdict.severity` / `FimDriftEntry.severity` | **three different enums** |
| signal / rule name | AVAILABLE (transient) | `Verdict.rule_id`/`rule_name` | log-line only, never persisted |
| principal: pid | AVAILABLE | `Verdict.event_pid` | |
| principal: process name | **MISSING** on `Verdict` | comm exists on source `Event`, not copied into verdict | |
| principal: user/uid | **MISSING** on `Verdict` | uid on `Event::ProcessSpawn` (`model.rs:28`), not in verdict; FIM/canary records do carry uid | |
| ADE recommendation/verdict | AVAILABLE (transient) | `AdeVerdict.verdict:AdeAction` (`ade_types.rs:85-97`) + `ThreatClassification` | never persisted; ADE-path only |
| confidence | PARTIAL (transient) | `AdeVerdict.confidence:f64` | rule `Verdict` has **no** confidence |
| status (open/closed) | **MISSING everywhere** | — | no struct has open/closed/ack/resolved |
| MITRE tactic tags | PARTIAL (transient) | `AdeVerdict.mitre_attack` (structured); rule path = prose only in `reasoning`/doc-comments | no structured MITRE on rule path |
| source / sensor | PARTIAL | `Verdict.category` / `Event` variant | no explicit sensor tag |
| detection type | PARTIAL | free-string `category` | no enum taxonomy |

### Verdict: can a dashboard list "last N detections" + aggregate for a Sankey? **NO.**

What's missing, precisely: (1) a **unified detection record** joining {sensor, rule_id, severity, ADE verdict, posture-at-time, principal, status}; (2) **persistence** of that record (none today — verdicts are dropped); (3) a **query/stream interface** (the admin socket has only per-domain file-dump verbs — `read_fim_drift_jsonl` `admin_socket.rs:1967`, `read_jsonl_chain` `:2407` — and no "detections" verb). A UI today could only tail journald `"VERDICT (rule)"`/`"VERDICT (ADE)"` lines (lossy, unstructured) or union heterogeneous JSONL chainlogs — neither carries the rule+ADE+posture join a Sankey needs.

**This is the central Tappa 9 build item: an agent-side detection store (the reusable `RotatingChainLog<P>` primitive in `agent/src/chainlog.rs` is the natural foundation) + a read/stream API (new `AdminMessage` verb on `admin_socket.rs` dispatch `:900`).** The insertion point is `main.rs:2343-2455` (both verdict arms).

---

## §4 — Posture — **PARTIAL**

**Wire enum `PostureKind`** (`common/src/posture_types.rs:24-34`): `Observing | Alerted | Engaged | Combat` (derives `Serialize/Deserialize/Ord`; `as_str()` → uppercase `:38-45`). **Runtime `PostureState`** (`agent/src/posture/state.rs:28-44`) carries timing/`locked` fields; `kind()` projects to `PostureKind` (`state.rs:46-55`).

- **Held** as `Arc<Inner{ state: RwLock<PostureState> }>` (`agent/src/posture/mod.rs:79,102-103`); read via `current_kind()` (`:288-290`).
- **Exposed:** **YES** in `StatusResponse.posture` (`admin_socket.rs:1000`) → `nn-admin status [--json]`. **A dashboard can read the current posture today (key-lessly).**
- **Transitions as events:** **PARTIAL / poll-only.** On change, `log_transition()` pushes a `PostureTransition{from,to,trigger,unix_ts_secs,reason}` (`posture_types.rs:165-171`) into an **in-memory `RwLock<Vec<…>>` capped at 256** (`mod.rs:677-700`). **No channel, no socket verb, no audit/chainlog sink** — the only production surfacing is journald `warn!("POSTURE TRANSITION")` (`main.rs:2139-2143`) and `info!("posture decay transition")` (`:1917`). The in-memory log's only readers are an example + unit tests.
- *(Note: the signed `audit.log` records COMBAT **ladder-stage** transitions (INVESTIGATE→NEUTRALIZE→ISOLATE) and admin ops — `main.rs:1147-1162` — **not** the 4-tier posture transitions.)*

**Verdict:** current posture readable; a **structured transition timeline is MISSING** (would need a new read verb exposing `transition_log()`, or journald scraping).

---

## §5 — ADE verdict + XAI — **MISSING** ⛔

- **ADE classification:** `AdeAction` (`ade_types.rs:85-97`: `Allow,Monitor,Alert,Throttle,Kill,KillTree,Quarantine,BlockNetwork,Isolate,Escalate`) + `AdeSeverity` + `ThreatClassification{family,kind,novelty}`. There is **no literal Malicious/Suspicious/Benign enum** — that spectrum maps onto `AdeAction`/`AdeSeverity`.
- **ADE explanation** (`reasoning: ReasoningSteps` 5-step, `evidence`, `escalation_package`): produced transiently in `AdeEngine::evaluate` (`agent/src/ade/mod.rs:188-363`). In the main loop **only `reasoning.step_5_decision` reaches journald** (`main.rs:2413`); steps 1–4, evidence, mitre_attack, escalation_package are never logged or stored. **Not retrievable by a UI.**
- **XAI / Article-13 `XaiEvidenceChain`** (`common/src/xai_types.rs:77-136`): a full signed evidence-chain schema (`saliency_map: Vec<SaliencyEntry>`, `baseline_verdict`, `XaiSignature{sig,signer_pubkey}`, FK `ade_trace_id` → `AdeVerdict.trace_id`). **`XaiEngine::explain` (`agent/src/xai/engine.rs:217`) is never called outside tests/examples** — the entire XAI subsystem is **dead at runtime** (module doc: explainer for "future Tappa 10.5 synthesized rules"). **No Article-13 evidence is generated or persisted by the running agent.**

**Verdict:** the reference table's "ADE recommendation/verdict + confidence" and any XAI drill-down are **not** available from a persisted source. Both require the §3 detection store (to attach the verdict + explanation to a record) and, for XAI, **wiring `XaiEngine::explain` into the runtime** first.

---

## §6 — Rules — **PARTIAL**

**`Rule` trait** (`agent/src/decision/mod.rs:31-48`) exposes `id() -> &'static str`, `name() -> &'static str`, `category() -> &'static str`, `evaluate(&Event) -> Option<Verdict>`. Doc literally says id/name/category are "for dashboards and CLI output" — but nothing surfaces them externally.

- **Enumerable in-process** via builders returning `Vec<Box<dyn Rule>>`: production `default_rules_with_net(...)` `agent/src/decision/rules/mod.rs:120-161`, plus family builders `chain_rules()`, `process_rules()`, `module_load_rules()`, `fim::rules::fim_rules()` (`fim/rules.rs:1706-1749`), `canary_rules()`, `net_rules()`.
- **Per-rule metadata:**

| Field | Available? | How | Example |
|---|---|---|---|
| id | YES | `Rule::id()` | `"R001_ExecFromTmp"` (`r001_exec_from_tmp.rs:16`) |
| name | YES | `Rule::name()` | `"Netcat family launched"` (`r005_netcat_exec.rs:19`) |
| category | YES (coarse string) | `Rule::category()` | `"execution"`, `"lateral_movement"`, `"fim_persistence"`, … |
| severity | PARTIAL | **not on trait** — only on a firing `Verdict.severity` | `Severity::High` (`r005:33`) |
| response action | PARTIAL | only on firing `Verdict.action` | `KillProcess` (`r001:39`) |
| MITRE tactic/technique | **MISSING (structured)** | prose only in `reasoning`/doc-comments | `T1571` text `net.rs:~1090` |
| description | PARTIAL | no `description()`; doc-comments only | |
| enabled/disabled | **MISSING** | no toggle on trait/builder | |

- **External exposure:** **MISSING.** No `AdminMessage` "list rules" variant (full enum `admin_protocol.rs:587-710`), no `nn-admin rules` subcommand (`nn_admin.rs:71-305`), no on-disk rule manifest (operator config files are rule *inputs* — blocklists, comm-allowlists, fim-paths — not the catalog).
- **Count:** **69 rules** compiled into the production engine (chain 8 + process R001–R017 = 17 + module R018 = 1 + FIM 24 + canary 4 + net 15). Matches the "69 rules" memory note.
- **Enable/disable:** essentially none — rules are on iff the builder pushes them; the only "off" mechanisms are build-time omission (net 012/015/016/017) and operator allowlist carve-outs (visible only as FIM aggregate counts).

**Verdict:** the catalog (id/name/category for 69 rules) is friendly to exposure but **not obtainable by a UI today** — a `RuleList` verb (iterating `default_rules_with_net`) is a small, clean build item. Severity/action/MITRE would need to be lifted onto the trait or a side-table.

---

## §7 — Audit / chainlog — **AVAILABLE**

**`AuditEntry`** (`agent/src/audit.rs:291-333`):
```rust
pub struct AuditEntry {
    pub ts: String,              // ISO-8601 UTC, µs
    pub agent_id: String,        // hex of 16-byte install UUID
    pub op: String,              // "unlock","shutdown","force_posture",…
    pub extra: serde_json::Value,
    pub key_fp: String,          // 8-hex primary signer fp
    pub cosigner_fps: Vec<String>,
    pub result: String,          // "success" | "failure: <reason>"
    pub client_pid: u32,
    pub client_uid: u32,
    pub client_comm: String,
    pub prev_hash: String,       // hex of prior entry_hash (genesis = 64×'0')
    pub entry_hash: String,      // SHA-256(prev ‖ canonical_json(entry∖{entry_hash,agent_sig}))
    pub agent_sig: String,       // base64 Ed25519 over the 32 raw hash bytes
}
```
- **Chain:** per-entry SHA-256 over `prev_hash ‖ canonical-json`, signed by an **internal agent key** `AgentSigningKey` (`audit.rs:145`) — **not** an admin key; persisted `/etc/northnarrow/agent.sig.key` mode **0400**. Field declaration order = canonical byte order. No explicit seq field (ordering implicit by chain).
- **On-disk:** `/etc/northnarrow/audit.log` (`DEFAULT_AUDIT_LOG_PATH` `audit.rs:97`; default in `main.rs:215`), **JSONL** (one entry/line, `O_APPEND`+`fsync`), file mode **0644** (`audit.rs:122`), created at boot by `bootstrap_audit_log` (`anti_tamper/filesystem.rs:838-867`).
- **Read = direct file parse, NO socket, NO role:** `run_audit_read(log_path, since, json)` `admin_cli.rs:706-760` opens + `serde_json::from_str::<AuditEntry>` per line; `nn-admin audit read [--since][--json]` (`nn_admin.rs:353-373`) never touches the socket. `--json` re-emits canonical JSONL on stdout (summary to stderr). **A UI can parse `/etc/northnarrow/audit.log` directly** (0644).
- **Verify:** `run_audit_verify` `admin_cli.rs:772-804` → `audit::verify_chain` `audit.rs:556-606` (checks linkage, recomputes hash, verifies sigs; typed failures carry entry index; CLI exit 0 intact / 8 broken). Needs the agent **public** key (`--agent-pubkey <hex>` or root-read of the 0400 key file).
- **`chainlog.rs` vs `audit.rs`:** `agent/src/chainlog.rs` is a separate **generic rotating** hash-chain primitive (`RotatingChainLog<P>`, `ChainLine<P>` `:92`, 64 MiB×8 rotation, meta-chain manifest) reusing the same crypto + `AgentSigningKey`. It backs the **domain** logs under `/var/lib/northnarrow` (dir **0700**, files 0644): `fim_drift.jsonl`, `netflow.jsonl`, `netflow_listeners.jsonl`, `canaries.jsonl`, `canary_access.jsonl`, `combat-audit.jsonl`. These are **JSONL + `pub` types** (parseable) but **root-only (0700)** — a non-root UI must go through the role-gated socket `report` verbs.

**Verdict:** the admin `audit.log` is an **AVAILABLE**, directly-readable, signed forensic record for the "audit/chainlog timeline" panel — but it logs **operator/admin actions and COMBAT stages, not detections**. Detail discrepancy to fix later: `deploy/systemd/journald@northnarrow.conf:24` wrongly cites `/var/lib/northnarrow` for `audit.log` (code = `/etc/northnarrow`).

---

## §8 — Logs — **PARTIAL**

Logging init (`agent/src/main.rs:439-444`, watchdog identical `watchdog/src/main.rs:59-62`):
```rust
tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
    .with_target(false)
    .init();
```
- **Plain-text to stdout/stderr.** **No `tracing_journald` layer, no `.json()` formatter, no file log writer** anywhere. Logs reach journald indirectly via systemd capture, namespaced **`LogNamespace=northnarrow`** (`deploy/systemd/northnarrow-agent.service:37`, `…watchdog.service:30`; store `/var/log/journal/<machine-id>.northnarrow`, `SystemMaxUse=1G`). Filter = `RUST_LOG` (default `info`).
- **Realistic logs panel:** shell out to `journalctl --namespace=northnarrow -u northnarrow-agent -o json [-f]` — but journald's `MESSAGE` is **free text** (the agent emits no journald-native structured fields), so per-event fields must be regex-parsed. **No JSON log file to tail, no FIFO/log socket** (grep: none). For anything *filterable by field*, the JSONL chain files (§7) are the real structured source, not the journal.

**Verdict:** a free-text journald panel is achievable now; a structured, field-filterable log stream is **MISSING** (would need a journald-JSON layer or a structured log file).

---

## §9 — Manual actions — **PARTIAL**

**Mutating socket actions + role** (handlers in `agent/src/admin_socket.rs`):

| Action | nn-admin cmd | Quorum / Role |
|---|---|---|
| Unlock / release COMBAT | `unlock --key` | 1-of-N `Role::Unlock` (`:932`) |
| Shutdown | `shutdown --key --cosign-key` | 2-of-N `Role::Shutdown` (`:1153`) |
| Force posture | `force-posture <target> --key` | 1-of-N `Role::ForcePosture` (`:1292`) |
| Rotate keys add/revoke | `rotate-keys {add,revoke}` | 2-of-N `Role::RotateKeys` (`:1396`,`:1529`) |
| FIM baseline recompute | `fim baseline` | 1-of-N `Role::FimManage` (`:1622`) |
| Canary deploy/burn/refresh | `canary {deploy,burn,refresh}` | 1-of-N `Role::CanaryManage` |
| Trusted-installer grant | `trusted-installer-grant --key` | 1-of-N `Role::TrustedInstaller` (`:1691`) |

Key-less local CLI: `status`, `verify-keys`, `init`, `audit read/verify` (read the 0644 file). Read-but-key-required: `fim report/status`, `canary list`, `net flows/listeners/resolve/fingerprint`.

**MISSING manual actions the reference UI (brief item 4) implies:**
- **No acknowledge / close / dismiss a detection** — does not exist anywhere in `AdminMessage` or dispatch (there is no detection identity to ack — see §3).
- **No "trigger response" / "cancel response"** verb. Closest indirect controls: `force-posture <target>` (drive into/out of any posture incl. Combat) and `unlock` (release COMBAT net-isolation — the documented "cancel the response" path). `canary burn` retires a canary; `fim baseline` re-snapshots — neither acks an alert.

**Verdict:** the privileged control set is rich and well-mapped, but **per-detection lifecycle actions are entirely absent** — they depend on §3 (a detection must exist as an addressable record before it can be acknowledged/closed). All existing mutations require a signed admin key with the matching role.

---

## §10 — Existing UI / frontend — **MISSING (clean slate)**

Whole-repo search (excluding `target/`): **no** `package.json`, `*.tsx/jsx/vue/svelte`, `tauri.conf.json`, `index.html`; **no** Cargo dep on `tauri/wry/webview/egui/eframe/gtk/dioxus/iced/slint/leptos/yew`; **no** `ui/frontend/gui/desktop/webview/dashboard` directory. The only "interface" code is the `nn-admin` CLI (`agent/src/bin/nn_admin.rs`) and the admin socket. Tappa 9 starts from zero — no prior UI to integrate or migrate.

---

## GAPS — ordered by how blocking they are for Tappa 9

1. **⛔ BLOCKER — No detection store / query / stream (§3, §5).** Verdicts (`Verdict`/`AdeVerdict`) are logged + executed then dropped; nothing persists a unified detection record and no interface lists them. **Nothing on the reference detection table or the Sankey can be built until the agent persists detections and exposes a read/stream API.** Build: a detection record type (join sensor+rule+severity+ADE verdict+posture+principal+status) → persist via the existing `RotatingChainLog<P>` (`agent/src/chainlog.rs`) → new `AdminMessage` read verb (insertion points: `main.rs:2343-2455`, `admin_socket.rs:900`). This unblocks items 2 (detection table), 1 (Sankey aggregation), 4 (per-detection actions), and 5's ADE drill-down.

2. **⛔ BLOCKER — No detection-lifecycle state or actions (§3 status field, §9).** No struct has an open/closed/acknowledged field, and no socket verb acks/closes/dismisses a detection. The reference UI's acknowledge/close controls require both a persisted detection identity (gap 1) **and** new mutate verbs. Depends on gap 1.

3. **HIGH — Read-only telemetry is not separable from privileged control, and is root-only (§1).** Only `Status`(3 fields)+`Challenge` are unauthenticated, and the socket is 0600 root:root. A display GUI either runs as root with no rich data, or holds real admin.pub key material to read FIM/canary/net. **Design question for the team:** add a credential-light/read-only telemetry channel (or a read-scoped socket at `root:northnarrow 0660` + a `Role`-gated telemetry verb)? This shapes the GUI's privilege model and must be decided early.

4. **HIGH — Agent status panel is 3 fields; missing mode/sensors/rules/health/BTF/build_hash (§2).** `StatusResponse` must be widened (or a new status verb added) before the status panel (brief item 3) can be populated. Self-contained, no dependency on gap 1.

5. **MEDIUM — Rule catalog not externally enumerable (§6).** 69 rules are compiled-in with id/name/category on the trait but no socket/CLI/file exposes them; severity/action/MITRE aren't on the trait and MITRE is prose-only. Needed for the Sankey's "Rule" and "Severity" stages and any rule legend. Build: `RuleList` verb + lift severity/MITRE onto rule metadata.

6. **MEDIUM — Posture transition timeline not externally readable (§4).** Current posture is readable; the transition history is an in-memory cap-256 Vec with no socket/file exposure (journald free-text only). Needed for a posture timeline panel.

7. **MEDIUM — XAI/Article-13 evidence never generated at runtime (§5).** `XaiEngine::explain` is dead code; no signed evidence chain is produced or stored. Any XAI drill-down needs the runtime wired first (and then attached to the gap-1 detection record).

8. **LOW–MEDIUM — No structured/field-filterable log stream (§8).** journald is free-text; a filterable logs panel needs either a journald-JSON layer in the agent or a structured log file. A free-text `journalctl --namespace=northnarrow -o json` panel is achievable now as an interim.

9. **LOW — Domain chainlogs are root-only (0700) (§7).** FIM/net/canary JSONL under `/var/lib/northnarrow` are parseable but require root or the role-gated socket `report` verbs. The admin `audit.log` (0644) is directly readable and is the ready source for the audit-timeline panel — but it carries admin actions/COMBAT stages, not detections.

10. **LOW — Protocol hygiene.** The version-negotiation envelope exists but is unwired (bare frames in prod) — worth wiring before a long-lived GUI client couples to the wire. The `journald@northnarrow.conf` comment misstates the `audit.log` path (`/var/lib` vs code's `/etc`).

### What is genuinely ready to consume today (no agent change)
- Current **posture** + **COMBAT/network-isolation** flag + last-admin-action age — `nn-admin status --json` (key-less, but root socket).
- The signed **admin audit log** `/etc/northnarrow/audit.log` — 0644 JSONL, parse directly for the forensic/admin-action timeline.
- Free-text agent/watchdog logs via `journalctl --namespace=northnarrow -o json`.
- (With a role-scoped admin key) FIM drift report, canary list, netflows/listeners via the socket `report`/`list` verbs.

---

## Appendix — key files for the Tappa 9 build

- Detection sink / insertion point: `agent/src/main.rs:2343-2455` (`process_event`, rule arm + ADE arm).
- Detection types: `common/src/model.rs:549` (`Verdict`), `:522` (`Severity`), `:531` (`ResponseAction`); `common/src/ade_types.rs:52` (`AdeVerdict`), `:85` (`AdeAction`), `:150` (`MitreAttack`).
- XAI (built, unwired): `common/src/xai_types.rs:77` (`XaiEvidenceChain`), `agent/src/xai/engine.rs:217` (`explain`).
- Rules: `agent/src/decision/mod.rs:31` (`Rule` trait), `agent/src/decision/rules/mod.rs:120` (`default_rules_with_net`).
- Posture: `agent/src/posture/state.rs:28`, `agent/src/posture/mod.rs` (`current_kind`, `transition_log`), `common/src/posture_types.rs:24`.
- Persistence primitive: `agent/src/chainlog.rs` (`RotatingChainLog<P>`, `ChainLine<P>`); admin audit `agent/src/audit.rs:291`.
- Wire + dispatch: `common/src/wire/admin_protocol.rs:586` (`AdminMessage`), `:538` (`StatusResponse`); `agent/src/admin_socket.rs:900` (dispatch), `:352` (server/bind/0600).
- CLI: `agent/src/bin/nn_admin.rs` (subcommands), `agent/src/admin_cli.rs:209` (`run_status`), `:706` (`run_audit_read`).
