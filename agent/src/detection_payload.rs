//! The records of the detection log and of its status-event log, and what
//! they are made of: the sensor, the decision path and verdict, the
//! ATT&CK references, the acting principal, the exec policy's and the
//! exec quarantine's evidence. The signed lines of `detections.jsonl` and
//! `status_events.jsonl` are these types' JSON (SCHEMA FREEZE).
//!
//! Wave 4 restructure, R04a (lab PR 241): from `crate::detection_store`,
//! unchanged (plan R04a: "i tipi dei payload vanno in file propri"; the
//! payloads go to nn-evidence). `detection_store` re-exports them; the
//! constructors from the engine's decisions (`DetectionRecord::from_rule`,
//! `with_attack`, `RuleMatchRecord::of`) and the network text of a
//! detection stay there, as does the sink that writes the records.

use nn_model::posture_types::PostureKind;
use nn_model::{Event, ResponseAction, Severity};
use serde::{Deserialize, Serialize};

/// Which sensor surfaced the triggering event. Derived from the
/// [`Event`] variant via [`Sensor::from_event`]; the Sankey's left-most
/// "Sensor (eBPF)" column. (There is no pre-existing sensor enum in the
/// codebase — events are tagged only by `Event` variant — so this is a
/// thin projection of that, not a redefinition of an existing type.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensor {
    /// Process exec — `sched_process_exec` / `bprm_check_security`.
    Exec,
    /// File access / integrity — `file_open` LSM + FIM drift.
    File,
    /// Kernel module load — `kernel_read_file` / `kernel_load_data`.
    ModuleLoad,
    /// Network — TCP connect, DNS query, finalized flow, listener.
    Network,
    /// Anti-tamper LSM denial on a protected inode.
    AntiTamper,
    /// Canary token trip.
    Canary,
    /// io_uring ring creation / activity (asynchronous I/O channel).
    IoUring,
    /// Lab PR 219: the exploit post-condition guard (`raw_syscalls` +
    /// `commit_creds` / `switch_task_namespaces` / `set_fs_root`).
    ExploitGuard,
}

impl Sensor {
    /// Map a triggering [`Event`] to its originating sensor. Exhaustive
    /// (no wildcard) on purpose: a new `Event` variant should force an
    /// explicit decision here rather than be silently bucketed.
    pub fn from_event(event: &Event) -> Self {
        match event {
            Event::ProcessSpawn { .. } | Event::ExecCheck { .. } => Sensor::Exec,
            Event::FileOpen { .. }
            | Event::MassWrite { .. }
            | Event::FileBurst { .. }
            | Event::Fim(_) => Sensor::File,
            Event::ModuleLoad { .. } => Sensor::ModuleLoad,
            Event::IoUring { .. } => Sensor::IoUring,
            Event::BpfSyscall { .. } => Sensor::AntiTamper,
            Event::ExploitPostcondition { .. } => Sensor::ExploitGuard,
            Event::TcpConnect { .. }
            | Event::DnsQuery { .. }
            | Event::DnsFlood { .. }
            | Event::SensorFlood { .. }
            | Event::NetFlow(_)
            | Event::NetListener(_) => Sensor::Network,
            Event::FsProtectDenial { .. } | Event::DefenderSignal { .. } => Sensor::AntiTamper,
            Event::CanaryTripped { .. } => Sensor::Canary,
        }
    }
}

/// Which decision path produced the detection. `path: Rule` ⇒
/// `rule_id`/`rule_name` are `Some`; `path: Ade` ⇒ they are `None` and
/// the verdict carries an [`AdvisorAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionPath {
    /// A compiled `NN-L-*` / `R0*` rule fired.
    Rule,
    /// No rule matched and the on-host LLM advisor (ADE) returned a
    /// verdict. Written before Wave 4 only: the advisor was removed in lab
    /// PR 214. Kept so that older records still decode and chain-verify.
    Ade,
}

/// The decision itself. Kept as one field (rather than two `Option`s) so
/// a record always has exactly one verdict; the variant matches
/// [`DetectionRecord::path`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionVerdict {
    /// Rule-engine action ([`ResponseAction`]).
    Rule(ResponseAction),
    /// The removed advisor's recommendation, in a record written before
    /// Wave 4 (see [`DetectionPath::Ade`]).
    Ade(AdvisorAction),
}

/// The recommendation of the on-host LLM advisor in a record written
/// before Wave 4 (lab PR 214), when the advisor judged the execs no rule
/// matched (it was `common::ade_types::AdeAction`). Nothing writes it any
/// more; it stays so that those records still decode, re-serialise byte
/// for byte and chain-verify. The variant names are the on-disk form:
/// never rename one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvisorAction {
    Allow,
    Monitor,
    Alert,
    Throttle,
    Kill,
    KillTree,
    Quarantine,
    BlockNetwork,
    Isolate,
    Escalate,
}

/// The MITRE ATT&CK tags of a detection: tactic and technique ids (the
/// rule path records none today). It was the LLM advisor's
/// `common::ade_types::MitreAttack` until Wave 4 (lab PR 214); the fields,
/// their order and their serialised form are unchanged, so older records
/// keep verifying.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitreAttack {
    pub tactic: Vec<String>,
    #[serde(default)]
    pub technique: Vec<String>,
}

/// Triage lifecycle of a detection. A newly-recorded detection is
/// [`Open`](Self::Open); a triage operator walks it forward
/// `Open` → `Acknowledged` → `Investigating` → `Resolved` /
/// `FalsePositive` via the Tappa 9.0.c `DetectionSetStatus` verb.
///
/// IMPORTANT (wire stability): these variants are serde-serialised by
/// NAME into the event chain, so they are part of the on-disk +
/// on-wire contract — never rename an existing variant; append new
/// rungs only. `Open`'s repr is unchanged from 9.0.a/9.0.b.
///
/// NOTE: the 9.0.a/9.0.b `Closed` rung was replaced by the richer
/// `Investigating` / `Resolved` / `FalsePositive` triage lifecycle in
/// 9.0.c. This is safe because 9.0.a only ever persisted `Open` and
/// 9.0.b was read-only, so no on-disk `DetectionRecord` ever carried
/// `Closed` — removing it cannot break deserialisation of real data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionStatus {
    Open,
    Acknowledged,
    Investigating,
    Resolved,
    FalsePositive,
}

/// Process attribution for a detection. Best-effort: `comm` is always
/// present, `ppid` only when the source event carried it (process exec
/// events do; file / net / canary events do not). No `exe` lives HERE —
/// it is not uniformly available across sensors, and `comm` is the one
/// field every variant exposes; the executable path (exec sensors only)
/// is carried by the sibling [`DetectionRecord::exe`] (9.0.a.1), not the
/// principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub pid: u32,
    pub comm: String,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
}

impl Principal {
    /// Extract the acting principal from a triggering [`Event`].
    /// Exhaustive on purpose (see [`Sensor::from_event`]).
    pub fn from_event(event: &Event) -> Self {
        match event {
            Event::ProcessSpawn {
                pid,
                ppid,
                uid,
                comm,
                ..
            }
            | Event::ExecCheck {
                pid,
                ppid,
                uid,
                comm,
                ..
            } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: Some(*ppid),
            },
            Event::FileOpen { pid, uid, comm, .. }
            | Event::MassWrite { pid, uid, comm, .. }
            | Event::FileBurst { pid, uid, comm, .. }
            | Event::DefenderSignal { pid, uid, comm, .. }
            | Event::TcpConnect { pid, uid, comm, .. }
            | Event::DnsQuery { pid, uid, comm, .. }
            | Event::DnsFlood { pid, uid, comm, .. }
            | Event::SensorFlood { pid, uid, comm, .. }
            | Event::FsProtectDenial { pid, uid, comm, .. } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: None,
            },
            Event::ModuleLoad {
                loader_pid,
                loader_uid,
                loader_comm,
                ..
            } => Principal {
                pid: *loader_pid,
                comm: loader_comm.clone(),
                uid: *loader_uid,
                ppid: None,
            },
            Event::IoUring { pid, uid, comm, .. }
            | Event::BpfSyscall { pid, uid, comm, .. }
            | Event::ExploitPostcondition { pid, uid, comm, .. } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: None,
            },
            Event::CanaryTripped {
                accessor_pid,
                accessor_uid,
                accessor_comm,
                ..
            } => Principal {
                pid: *accessor_pid,
                comm: accessor_comm.clone(),
                uid: *accessor_uid,
                ppid: None,
            },
            Event::Fim(fe) => Principal {
                pid: fe.modifier_pid,
                comm: fe.modifier_comm.clone(),
                uid: fe.modifier_uid,
                ppid: None,
            },
            Event::NetFlow(nf) => Principal {
                pid: nf.pid,
                comm: nf.comm.clone(),
                uid: nf.uid,
                ppid: None,
            },
            Event::NetListener(nl) => Principal {
                pid: nl.pid,
                comm: nl.comm.clone(),
                uid: nl.uid,
                ppid: None,
            },
        }
    }
}

/// The full executable path that triggered a detection, when the
/// originating event names one. ONLY the two exec-sensor events carry
/// an executable: `ProcessSpawn` (post-exec) and `ExecCheck` (pre-exec
/// `bprm_check_security`). Tappa 10.9 step 2: the file the kernel
/// executed (`exe.path`, review 61), else the caller's `filename`, which
/// may be relative or name a symlink. Every other event names no
/// executable — `FileOpen`
/// carries the *opened* file (not an exe), `ModuleLoad` a `.ko` source
/// path, the net / canary / anti-tamper events nothing — so they map to
/// `None`. Exhaustive (no wildcard) on purpose, like [`Sensor::from_event`]
/// / [`Principal::from_event`]: a new exec-bearing `Event` variant must
/// force an explicit decision here rather than silently yield `None`.
pub(crate) fn exe_from_event(event: &Event) -> Option<String> {
    match event {
        Event::ProcessSpawn { filename, exe, .. } | Event::ExecCheck { filename, exe, .. } => {
            Some(exe.path_or(filename).to_string())
        }
        Event::FileOpen { .. }
        | Event::MassWrite { .. }
        | Event::FileBurst { .. }
        | Event::DefenderSignal { .. }
        | Event::ModuleLoad { .. }
        | Event::IoUring { .. }
        | Event::BpfSyscall { .. }
        | Event::ExploitPostcondition { .. }
        | Event::TcpConnect { .. }
        | Event::DnsQuery { .. }
        | Event::DnsFlood { .. }
        | Event::SensorFlood { .. }
        | Event::FsProtectDenial { .. }
        | Event::CanaryTripped { .. }
        | Event::Fim(_)
        | Event::NetFlow(_)
        | Event::NetListener(_) => None,
    }
}

/// The file a detection is about ([`DetectionRecord::file`]). Exhaustive
/// on purpose, like [`exe_from_event`].
pub(crate) fn file_from_event(event: &Event) -> Option<String> {
    match event {
        Event::Fim(fe) => Some(fe.path.clone()),
        Event::FileOpen { filename, .. }
        | Event::MassWrite { filename, .. }
        | Event::FileBurst { filename, .. } => (!filename.is_empty()).then(|| filename.clone()),
        Event::ModuleLoad { path, .. } => path.clone(),
        Event::ProcessSpawn { .. }
        | Event::ExecCheck { .. }
        | Event::IoUring { .. }
        | Event::BpfSyscall { .. }
        | Event::ExploitPostcondition { .. }
        | Event::TcpConnect { .. }
        | Event::DnsQuery { .. }
        | Event::DnsFlood { .. }
        | Event::SensorFlood { .. }
        | Event::DefenderSignal { .. }
        | Event::FsProtectDenial { .. }
        | Event::CanaryTripped { .. }
        | Event::NetFlow(_)
        | Event::NetListener(_) => None,
    }
}

/// The refused operation of an anti-tamper denial
/// ([`DetectionRecord::operation`]); lab PR 224: `connect` for a connect
/// the `socket_connect` deny refused; `None` for every other event.
pub(crate) fn operation_from_event(event: &Event) -> Option<String> {
    match event {
        Event::FsProtectDenial { operation, .. } => Some(operation.to_string()),
        Event::NetFlow(nf) if nf.phase == nn_model::telemetry::FlowPhase::Denied => {
            Some("connect".to_string())
        }
        _ => None,
    }
}

/// The subject of a detection for the per-rule budget's held report
/// ([`crate::detection_budget`]): `(key, text)`. The key is what the
/// detection is about — its file, else its executable, else the acting
/// `comm` — so a flood cannot crowd the report out by renaming itself.
pub fn held_sample(event: &Event) -> (String, String) {
    let p = Principal::from_event(event);
    match file_from_event(event).or_else(|| exe_from_event(event)) {
        Some(t) => {
            let text = format!("{} (pid {}) {}", p.comm, p.pid, t);
            (t, text)
        }
        None => {
            let text = format!("{} (pid {})", p.comm, p.pid);
            (p.comm, text)
        }
    }
}

/// One persisted detection. Serialised as a flattened JSONL line inside
/// the [`RotatingChainLog`] (the chain envelope adds `fmt_ver` /
/// `prev_hash` / `entry_hash` / `agent_sig`). No field collides with the
/// chainlog's reserved keys.
///
/// NOTE: this record does not duplicate `Verdict.timestamp_ns` (a
/// monotonic-clock value) — [`ts`](Self::ts) is the wall-clock instant
/// the detection was recorded, which is what a dashboard needs.
///
/// SCHEMA FREEZE: chain verification RE-SERIALISES the decoded record
/// and re-hashes it (see [`verify_log_set`](crate::chainlog::verify_log_set)),
/// so the recomputed pre-image must reproduce the stored bytes exactly —
/// every existing field's name, declaration order, and serialised type
/// is FROZEN once records exist on disk. The only safe schema change is
/// ADDING an `Option` field with `#[serde(default, skip_serializing_if =
/// "Option::is_none")]`: absent on old lines, it decodes to `None` and
/// re-serialises back to absent, so old records keep chain-verifying
/// (see [`exe`](Self::exe) for the worked example).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecord {
    /// Monotonic, restart-stable id (seeded from the persisted tail).
    /// Gaps are possible and meaningful — a gap means a record was
    /// dropped under backpressure (see [`DetectionSink`]).
    pub id: u64,
    /// Wall-clock UTC, microsecond resolution (matches the audit log).
    pub ts: String,
    pub sensor: Sensor,
    pub path: DetectionPath,
    /// `Some` on the rule path; `None` on the (pre-Wave 4) advisor path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    pub severity: Severity,
    pub verdict: DetectionVerdict,
    /// `1.0` on the (deterministic) rule path; the model's confidence on
    /// the advisor path of a record written before Wave 4.
    pub confidence: f64,
    pub mitre: MitreAttack,
    pub principal: Principal,
    /// Full path of the executable that triggered the detection — set
    /// for the two exec sensors (`ProcessSpawn` post-exec / `ExecCheck`
    /// pre-exec, both carrying the kernel `filename`), `None` for every
    /// non-exec sensor (file / module-load / network / anti-tamper /
    /// canary), which names no executable. Tappa 9.0.a.1: `comm` alone
    /// loses the world-writable path R001 ("Exec from /tmp") actually
    /// fired on; `exe` restores it. Mapped from the event's `filename`
    /// by [`exe_from_event`]. Absent-on-`None` (`skip_serializing_if`)
    /// so 9.0.a/b/c lines written before this field stay byte-identical
    /// on disk and still chain-verify, and re-serialising them (as the
    /// chain verifier does) omits `exe` exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Agent posture at the moment of detection.
    pub posture_at: PostureKind,
    /// What the response layer actually did: a [`ResponseAction`] name
    /// when the action was carried out, the name followed by the outcome
    /// when it was not (`"KillProcess (already gone)"`, see
    /// [`describe_response`]), `"suppressed (detect-only)"`, or `"none"`.
    pub response: String,
    /// Detection sub-type: the rule `category` (rule path) or, in a record
    /// written before Wave 4, the advisor's threat-classification `kind`.
    pub detection_type: String,
    pub status: DetectionStatus,
    // `explanation` (an XAI evidence chain, Tappa 9.0.e) stood here: it
    // was never written (always `None`, so absent from every line) and was
    // removed with the LLM advisor in Wave 4, lab PR 214.
    /// Detections of the same rule and uid acted on but not recorded
    /// since the previous report, because they exceeded the per-rule
    /// budget ([`crate::detection_budget`], review 75) or repeated an
    /// action their rule coalesced into an earlier record (NN-L-EVA-002,
    /// lab PR 225). Absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_before: Option<u64>,
    /// The file the detection is about, for the file sensors: the path
    /// of a FIM drift or of a file-open detection, the write that crossed
    /// a mass-write threshold, the `.ko` of a module load. Review 77: a
    /// record of NN-L-FIM-007 named the writer but not the cron drop-in
    /// it created, so a record could not be read without the drift log.
    /// Mapped from the event by [`file_from_event`]; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The operation an anti-tamper hook refused (`signal`, `ptrace`,
    /// `write`, `unlink`, `bpf_map`, …), for the NN-L-AT-001 records of a
    /// kernel denial; absent otherwise. External audit NN-AUD-413 (lab PR
    /// 167): the adversarial check reads what was refused from this signed
    /// record, not from the journal, where another user could write a line
    /// that looked like the agent's. Absent-on-`None`, like [`Self::file`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Lab PR 221 (capability C16): the ATT&CK Enterprise version
    /// ([`ATTACK_VERSION`], `"20.0"`) the ids of [`Self::mitre`] are from,
    /// on a rule-path record whose rule declares its ATT&CK references
    /// ([`Rule::attack`](crate::decision::Rule::attack), set by
    /// [`Self::with_attack`]). Version 19 renumbered techniques (T1562
    /// Impair Defenses is revoked, T1685 took its place), so an id is read
    /// with its version. Absent on records written before lab PR 221, whose
    /// rule-path `mitre` is empty, and on ADE-path records, whose ids are
    /// the model's and name no version; absent-on-`None`, like
    /// [`Self::file`], so those lines keep their bytes and still verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitre_version: Option<String>,
    /// Lab PR 223 (EXPERIMENTAL): the exec quarantine's evidence on its
    /// own records (`NN-L-EXECQ-001`) — the scan verdict and its reasons,
    /// the digest, the decision and how long the process was held. Absent
    /// on every other record (absent-on-`None`, like [`Self::file`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execq: Option<ExecqEvidence>,
    /// Lab PR 224: the network side of the detection ([`network_from_event`]):
    /// the flow and its phase — whether it was judged at the connect,
    /// while open, at the close, or refused in the kernel — the connect
    /// attempt of a fan-out record, the socket on a shell's standard
    /// streams. The lab reads a connect-time verdict from this signed
    /// record, not from the journal. Absent-on-`None`, like [`Self::file`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Lab PR 225: why a security-tool finding (NN-L-EVA-00x) was
    /// sanctioned and recorded Low — a package transaction, an
    /// administrator's interactive session, a configuration-management
    /// actor, or the valid signed trusted-installer window (its key id and
    /// deadline) inside which the agent's own units were stopped or
    /// restarted. Absent on every other record (absent-on-`None`, like
    /// [`Self::file`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanction: Option<String>,
    /// Lab PR 226 (EXPERIMENTAL): the exec policy's evidence on its own
    /// records (`NN-L-EXECPOL-001`, `NN-L-EXECENV-00x`) — the decision, the
    /// caller's lineage tier and its signals, the classes, the loader
    /// variables. Absent on every other record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execpol: Option<ExecPolEvidence>,
    /// Lab PR 236 (multi-match): every rule that matched the event, in the
    /// engine's order, when there are several, the per-rule policy gave the
    /// primary rule a mode, or the legacy ceiling held its response — [`Self::rule_id`] is the primary rule and
    /// [`Self::mitre`] the union of their ATT&CK references. Absent on a
    /// record of one rule under the built-in defaults (absent-on-`None`,
    /// like [`Self::file`], so those lines keep their bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<RuleMatchRecord>>,
}

/// Lab PR 236: one matched rule of a multi-match record
/// ([`DetectionRecord::matches`]). Frozen like the record: fields are only
/// ever appended as `Option`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchRecord {
    pub rule_id: String,
    /// The match's action after the policy (`Log` for a held, alert,
    /// audit or exempt match).
    pub action: ResponseAction,
    pub severity: Severity,
    /// `builtin`, `enforce`, `alert`, `audit` or `exempt`.
    pub mode: String,
    /// The process the rule's verdict names.
    pub pid: u32,
    pub mitre: MitreAttack,
    /// What still holds its response: a switch (its text, built-in
    /// defaults) or `legacy_ceiling` — the first-match engine would not have
    /// run it on this event, and no `enforce` lifts the ceiling for the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    /// The action held back (the rule's own), when `held` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_action: Option<ResponseAction>,
    /// The policy's exemption that covered the actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exempt: Option<String>,
}

/// Lab PR 226: what the exec policy saw and decided
/// ([`DetectionRecord::execpol`]). Frozen like the record: fields are only
/// ever appended as `Option`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPolEvidence {
    /// `exec` (an exec pass) or `map` (an executable mapping).
    pub kind: String,
    /// `deny`, `would deny`, `record`, `quarantine`.
    pub decision: String,
    /// `admin`, `session`, `service`, `unknown`.
    pub tier: String,
    /// What the tier rests on (`user.slice`, `tty`, `login_uid`…).
    pub tier_signals: Vec<String>,
    /// The file's classes.
    pub classes: Vec<String>,
    /// Environment findings (`LD_PRELOAD`, `preload_staging`…).
    pub environment: Vec<String>,
    /// The captured values (`LD_PRELOAD=/tmp/x.so`), journal-escaped.
    pub values: Vec<String>,
    /// The target is set-id: the kernel sets `AT_SECURE` and the loader
    /// ignores these variables itself.
    pub at_secure: bool,
    /// Where the policy came from (`server profile (built in)`,
    /// `/etc/northnarrow/exec-policy.local (signed)`).
    pub policy: String,
}

/// Lab PR 223: what the exec quarantine found and decided
/// ([`DetectionRecord::execq`]). Frozen like the record: fields are only
/// ever appended as `Option`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecqEvidence {
    /// `clean`, `trusted`, `suspicious`, `malicious`, `unscanned`, or
    /// `none` (no verdict: the decision was the default policy's).
    pub verdict: String,
    /// SHA-256 of the file, when it was scanned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// `elf64-x86_64-dyn`, `script:/bin/sh`…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// The scanner's reasons, `code (+weight): detail`, and the
    /// controller's notes.
    pub reasons: Vec<String>,
    /// `resume`, `kill`, or `would resume` / `would kill` in observe mode.
    pub decision: String,
    /// Why (`scanned clean`, `decision budget expired (…)`).
    pub basis: String,
    /// The guarded classes the file was executed from.
    pub classes: Vec<String>,
    /// The kernel held the process.
    pub held: bool,
    /// From the kernel's report to the decision (ms).
    pub held_ms: u64,
}

/// Tappa 9.0.c — one triage status-change event. Persisted as a
/// flattened JSONL line inside its OWN [`RotatingChainLog`]
/// (`status_events.jsonl`), separate from the detection chain so
/// `detections.jsonl` lines + hash chain stay byte-intact. The chain
/// envelope adds `fmt_ver` / `prev_hash` / `entry_hash` / `agent_sig`
/// around these fields, exactly like a [`DetectionRecord`] line.
///
/// "Current status" of a detection is the [`new_status`](Self::new_status)
/// of the LATEST `StatusEvent` carrying its [`detection_id`](Self::detection_id)
/// (see [`latest_status_for_ids`]); a detection with no status event
/// keeps its record's initial `Open`.
///
/// SCHEMA FREEZE: same constraint as [`DetectionRecord`] — the chain
/// verifier re-serialises decoded events, so existing field names,
/// declaration order and serialised types are frozen; only additive
/// `Option` fields with `#[serde(default, skip_serializing_if =
/// "Option::is_none")]` are safe to add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEvent {
    /// The [`DetectionRecord::id`] this event re-statuses.
    pub detection_id: u64,
    /// The status the detection transitions TO.
    pub new_status: DetectionStatus,
    /// Wall-clock UTC the change was recorded (same format as
    /// [`DetectionRecord::ts`]).
    pub ts: String,
    /// Who made the change — the admin caller's SO_PEERCRED identity
    /// (pid / comm / uid). Reuses [`Principal`] so the event records
    /// the acting local operator process, not just the signing key
    /// (the matched key fingerprint is in the audit log). Its `comm` is
    /// self-reported (external audit ASK-013): the name the peer gave
    /// itself; [`Self::principal_exe`] is the kernel's record.
    pub principal: Principal,
    /// Optional operator triage note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// External audit ASK-013 (NN-AUD-239, lab PR 179): the admin caller's
    /// executable, `/proc/<pid>/exe`, read while the caller was known to be
    /// alive. Absent on events written before lab PR 179 (their bytes and
    /// pre-image unchanged) and when the link could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_exe: Option<String>,
}

/// External audit EVD-008 (lab PR 204): the detection log's name in its v3
/// pre-images.
impl crate::chainlog::ChainPayload for DetectionRecord {
    const KIND: &'static str = "detections";
}

/// External audit EVD-008 (lab PR 204): the status-event log's name in its
/// v3 pre-images.
impl crate::chainlog::ChainPayload for StatusEvent {
    const KIND: &'static str = "status_events";
}
