//! The exec policy's records (lab PR 226): what one kernel report becomes —
//! one signed detection record per finding (the exec deny, the loader
//! variable, the environment trick, the mapping), through the per-rule
//! budget like every rule's. Pure functions; the [`SinkRecorder`] writes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::wire::execpol::{action, env_flags, kind, tier, ExecPolRaw};
use common::wire::execq::class;
use nn_model::{Event, ExeIdentity, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;
use tracing::warn;

use super::{
    CATEGORY, RULE_ENV, RULE_ENV_NAME, RULE_EXEC, RULE_EXEC_NAME, RULE_MAP, RULE_MAP_NAME,
    RULE_PRELOAD, RULE_PRELOAD_NAME,
};
use crate::decision::attack::{mitre_of, AttackRef, Tactic};
use crate::decision::bounded::RepeatWindow;
use crate::detection_payload::ExecPolEvidence;
use crate::detection_store::DetectionSink;

/// Lab PR 221's typed ATT&CK mapping (Enterprise 20.0) of the exec policy's
/// rules: every reference a record of each can carry; a record carries the
/// ones its finding names ([`exec_attack`], [`records_of`]).
/// NN-L-EXECPOL-001: Reflective Code Loading (memfd, deleted file), File
/// Deletion, User Execution: Malicious File (a staging location), Hidden
/// Files and Directories (a hidden name on the way).
pub const ATTACK_EXEC: &[AttackRef] = &[
    AttackRef::new(Tactic::Stealth, "T1620"),
    AttackRef::new(Tactic::Stealth, "T1070.004"),
    AttackRef::new(Tactic::Execution, "T1204.002"),
    AttackRef::new(Tactic::Stealth, "T1564.001"),
];
/// NN-L-EXECENV-001: Dynamic Linker Hijacking.
pub const ATTACK_PRELOAD: &[AttackRef] = &[
    AttackRef::new(Tactic::Stealth, "T1574.006"),
    AttackRef::new(Tactic::Execution, "T1574.006"),
];
/// NN-L-EXECENV-002: a set-id exploit's environment (Exploitation for
/// Privilege Escalation), a library path into staging, history disabled
/// (Clear Command History).
pub const ATTACK_ENV: &[AttackRef] = &[
    AttackRef::new(Tactic::PrivilegeEscalation, "T1068"),
    AttackRef::new(Tactic::Stealth, "T1574.006"),
    AttackRef::new(Tactic::Stealth, "T1070.003"),
];
/// NN-L-EXECENV-003: a staging file mapped executable (Dynamic Linker
/// Hijacking, Shared Modules; Reflective Code Loading for memfd / deleted).
pub const ATTACK_MAP: &[AttackRef] = &[
    AttackRef::new(Tactic::Stealth, "T1574.006"),
    AttackRef::new(Tactic::Execution, "T1129"),
    AttackRef::new(Tactic::Stealth, "T1620"),
];

/// The reference of `table` filed under `tactic` for `technique`.
fn pick(table: &[AttackRef], tactic: Tactic, technique: &str) -> AttackRef {
    *table
        .iter()
        .find(|r| r.tactic == tactic && r.technique.as_str() == technique)
        .expect("a reference of the rule's table")
}

/// `refs` once each, in order.
fn dedup(refs: Vec<AttackRef>) -> Vec<AttackRef> {
    let mut out: Vec<AttackRef> = Vec::new();
    for r in refs {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// One finding, ready for the detection chain.
#[derive(Debug, Clone)]
pub struct ExecPolRecord {
    pub event: Event,
    pub verdict: Verdict,
    pub response: String,
    /// Its ATT&CK references (lab PR 221: typed, of the rule's table).
    pub attack: Vec<AttackRef>,
    pub evidence: ExecPolEvidence,
}

impl ExecPolRecord {
    /// The tactic ids of [`Self::attack`], as the record's `mitre` has them.
    pub fn tactics(&self) -> Vec<String> {
        mitre_of(&self.attack).tactic
    }
    /// The technique ids of [`Self::attack`].
    pub fn techniques(&self) -> Vec<String> {
        mitre_of(&self.attack).technique
    }
}

/// Where records go (the detection sink in production, a vector in tests).
pub trait Recorder: Send {
    fn detection(&self, rec: ExecPolRecord);
}

/// A NUL-terminated buffer as text.
fn cstr(b: &[u8]) -> String {
    common::wire::cstr_lossy(b).into_owned()
}

/// The event the records describe: the exec (or the mapping) as the exec
/// sensor would name it, its path made absolute with the mount table.
pub fn event_of(raw: &ExecPolRaw) -> Event {
    let exe = ExeIdentity::from_raw(&raw.exe);
    let mut event = Event::ExecCheck {
        pid: raw.pid,
        ppid: raw.ppid,
        uid: raw.uid,
        comm: cstr(&raw.comm),
        filename: String::new(),
        timestamp_ns: raw.timestamp_ns,
        exe,
    };
    crate::sensors::exe_identity::resolve(&mut event);
    event
}

fn path_of(event: &Event) -> String {
    match event {
        Event::ExecCheck { exe, .. } => exe.path.clone(),
        _ => String::new(),
    }
}

/// ATT&CK for an exec deny, by class: references of [`ATTACK_EXEC`] (v20
/// identifiers of the pinned list, lab PR 221; T1204.002 pinned with lab PR
/// 223's mapping).
pub fn exec_attack(classes: u32, path: &str) -> Vec<AttackRef> {
    let mut refs = Vec::new();
    let t = |tactic, id| pick(ATTACK_EXEC, tactic, id);
    if classes & class::MEMFD != 0 {
        refs.push(t(Tactic::Stealth, "T1620"));
    }
    if classes & class::DELETED != 0 {
        refs.extend([t(Tactic::Stealth, "T1620"), t(Tactic::Stealth, "T1070.004")]);
    }
    if classes & !(class::MEMFD | class::DELETED) != 0 {
        refs.push(t(Tactic::Execution, "T1204.002"));
    }
    // A hidden name on the way (`/dev/shm/.x/kdmtmpflush`).
    if path
        .split('/')
        .any(|c| c.starts_with('.') && c != "." && c != "..")
    {
        refs.push(t(Tactic::Stealth, "T1564.001"));
    }
    dedup(refs)
}

/// [`exec_attack`] as the record's `mitre` lists it: (tactic ids,
/// technique ids).
pub fn exec_techniques(classes: u32, path: &str) -> (Vec<String>, Vec<String>) {
    let m = mitre_of(&exec_attack(classes, path));
    (m.tactic, m.technique)
}

/// Loader-variable values as the record shows them (escaped).
fn values(raw: &ExecPolRaw) -> Vec<String> {
    let mut out = Vec::new();
    let f = raw.env_flags;
    let mut push = |name: &str, bit: u32, buf: &[u8]| {
        if f & bit != 0 {
            out.push(format!(
                "{name}={}",
                nn_model::log_escape::Escaped(&cstr(buf))
            ));
        }
    };
    push("LD_PRELOAD", env_flags::LD_PRELOAD, &raw.preload);
    push("LD_AUDIT", env_flags::LD_AUDIT, &raw.audit);
    push("LD_LIBRARY_PATH", env_flags::LD_LIBRARY_PATH, &raw.libpath);
    push("HISTFILE", env_flags::HISTFILE, &raw.hist);
    if f & env_flags::GLIBC_TUNABLES != 0 {
        let v = cstr(&raw.tunables);
        let shown: String = v.chars().take(96).collect();
        out.push(format!(
            "GLIBC_TUNABLES={} ({} bytes read{})",
            nn_model::log_escape::Escaped(&shown),
            raw.tunables_len,
            if raw.tunables_len as usize >= common::wire::execpol::ENV_TUNABLES_LEN - 1 {
                ", cut"
            } else {
                ""
            }
        ));
    }
    out
}

/// The Looney Tunables shape (CVE-2023-4911): a tunable whose value holds
/// another assignment (`glibc.malloc.mxfast=glibc.malloc.mxfast=…`), or a
/// string as long as the buffer the kernel read.
pub fn tunables_exploit_shape(v: &str, len: u32) -> bool {
    v.split(':').any(|item| item.matches('=').count() > 1)
        || len as usize >= common::wire::execpol::ENV_TUNABLES_LEN - 1
}

/// Shells that read `HISTFILE` / `HISTSIZE` at start.
fn is_shell(path: &str) -> bool {
    matches!(
        path.rsplit('/').next().unwrap_or(""),
        "bash" | "sh" | "dash" | "zsh" | "ksh" | "mksh" | "ash" | "busybox" | "fish"
    )
}

fn decision_of(act: u32) -> &'static str {
    if act & action::DENY != 0 {
        "deny"
    } else if act & action::WOULD_DENY != 0 {
        "would deny"
    } else if act & action::QUARANTINE != 0 {
        "quarantine"
    } else {
        "record"
    }
}

fn evidence(raw: &ExecPolRaw, decision: &str, policy: &str) -> ExecPolEvidence {
    ExecPolEvidence {
        kind: if raw.kind == kind::MAP { "map" } else { "exec" }.to_string(),
        decision: decision.to_string(),
        tier: common::wire::execpol::tier_name(raw.tier).to_string(),
        tier_signals: common::wire::execpol::tier_signals(raw.tier)
            .into_iter()
            .map(str::to_string)
            .collect(),
        classes: common::wire::execq::class_names(raw.classes)
            .into_iter()
            .map(str::to_string)
            .collect(),
        environment: common::wire::execpol::env_names(raw.env_flags)
            .into_iter()
            .map(str::to_string)
            .collect(),
        values: values(raw),
        at_secure: raw.target_setid(),
        policy: policy.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    event: &Event,
    path: &str,
    rule: (&str, &str),
    severity: Severity,
    reasoning: String,
    response: String,
    attack: Vec<AttackRef>,
    evidence: ExecPolEvidence,
) -> ExecPolRecord {
    let (pid, ts) = match event {
        Event::ExecCheck {
            pid, timestamp_ns, ..
        } => (*pid, *timestamp_ns),
        _ => (0, 0),
    };
    ExecPolRecord {
        verdict: Verdict {
            rule_id: rule.0.to_string(),
            rule_name: rule.1.to_string(),
            category: CATEGORY.to_string(),
            action: ResponseAction::Log,
            severity,
            reasoning,
            event_pid: pid,
            event_filename: path.to_string(),
            timestamp_ns: ts,
        },
        event: event.clone(),
        response,
        attack,
        evidence,
    }
}

/// The records one report gives (`policy`: where the table came from).
pub fn records_of(raw: &ExecPolRaw, event: &Event, policy: &str) -> Vec<ExecPolRecord> {
    let path = path_of(event);
    let t = raw.tier_value();
    let tname = common::wire::execpol::tier_name(raw.tier);
    let classes = common::wire::execq::class_names(raw.classes).join(", ");
    let mut out = Vec::new();
    if raw.kind == kind::MAP {
        let act = raw.action;
        let (sev, resp) = if act & action::DENY != 0 {
            (Severity::High, "mapping refused (EACCES)".to_string())
        } else if act & action::WOULD_DENY != 0 {
            (
                Severity::Medium,
                "would refuse (audit): the mapping was made".to_string(),
            )
        } else {
            let s = if t == tier::SERVICE || t == tier::UNKNOWN {
                Severity::Medium
            } else {
                Severity::Low
            };
            (s, "recorded: the mapping was made".to_string())
        };
        let mut attack = vec![
            pick(ATTACK_MAP, Tactic::Stealth, "T1574.006"),
            pick(ATTACK_MAP, Tactic::Execution, "T1129"),
        ];
        if raw.classes & (class::MEMFD | class::DELETED) != 0 {
            attack.push(pick(ATTACK_MAP, Tactic::Stealth, "T1620"));
        }
        out.push(record(
            event,
            &path,
            (RULE_MAP, RULE_MAP_NAME),
            sev,
            format!(
                "executable mapping of a file from a staging location ({classes}) by a {tname} \
                 caller"
            ),
            resp,
            attack,
            evidence(raw, decision_of(act), policy),
        ));
        return out;
    }
    // The exec's classes.
    if raw.action & (action::DENY | action::WOULD_DENY) != 0 {
        let deny = raw.action & action::DENY != 0;
        let sev = if deny {
            Severity::High
        } else {
            Severity::Medium
        };
        let resp = if deny {
            "denied at exec (EACCES): the caller kept its image, nothing of the file ran"
        } else {
            "would deny (audit): the exec ran"
        };
        let attack = exec_attack(raw.classes, &path);
        out.push(record(
            event,
            &path,
            (RULE_EXEC, RULE_EXEC_NAME),
            sev,
            format!(
                "exec from a staging location ({classes}) by a {tname} caller: the exec policy \
                 {}",
                if deny { "denies it" } else { "would deny it" }
            ),
            resp.to_string(),
            attack,
            evidence(raw, decision_of(raw.action), policy),
        ));
    }
    let ef = raw.env_flags;
    let ea = raw.env_action;
    if ea == 0 {
        return out;
    }
    let setid = raw.target_setid();
    // The loader variable into a staging path.
    if ef & env_flags::DENYABLE != 0 {
        let (sev, resp) = if ea & action::DENY != 0 {
            (Severity::High, "denied at exec (EACCES)".to_string())
        } else if ea & action::WOULD_DENY != 0 {
            (
                Severity::Medium,
                "would deny (audit): the exec ran".to_string(),
            )
        } else if setid {
            (
                Severity::Medium,
                "recorded: the target is set-id, the kernel sets AT_SECURE and the loader \
                 ignores the entry"
                    .to_string(),
            )
        } else if t == tier::SERVICE || t == tier::UNKNOWN {
            (Severity::Medium, "recorded: the exec ran".to_string())
        } else {
            (Severity::Low, "recorded: the exec ran".to_string())
        };
        out.push(record(
            event,
            &path,
            (RULE_PRELOAD, RULE_PRELOAD_NAME),
            sev,
            format!(
                "a loader variable at exec names a staging path ({}) for a {tname} caller",
                values(raw)
                    .into_iter()
                    .filter(|v| v.starts_with("LD_PRELOAD=") || v.starts_with("LD_AUDIT="))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            resp,
            ATTACK_PRELOAD.to_vec(),
            evidence(raw, decision_of(ea), policy),
        ));
    }
    // The other environment tricks: recorded only.
    let tun = cstr(&raw.tunables);
    let tunables = setid && ef & env_flags::GLIBC_TUNABLES != 0;
    let history = ef & env_flags::HISTORY != 0 && is_shell(&path);
    let libpath = ef & env_flags::LIBPATH_STAGING != 0
        && (t == tier::SERVICE || t == tier::UNKNOWN || raw.uid == 0);
    if tunables || history || libpath {
        let mut why = Vec::new();
        let mut attack = Vec::new();
        let mut sev = Severity::Low;
        if tunables {
            let shape = tunables_exploit_shape(&tun, raw.tunables_len);
            sev = if shape {
                Severity::Critical
            } else {
                Severity::Medium
            };
            why.push(if shape {
                "GLIBC_TUNABLES in the shape of CVE-2023-4911 (Looney Tunables) at the exec of \
                 a set-id program"
            } else {
                "GLIBC_TUNABLES at the exec of a set-id program"
            });
            attack.push(pick(ATTACK_ENV, Tactic::PrivilegeEscalation, "T1068"));
        }
        if libpath {
            if sev == Severity::Low {
                sev = Severity::Medium;
            }
            why.push("LD_LIBRARY_PATH names a staging path");
            attack.push(pick(ATTACK_ENV, Tactic::Stealth, "T1574.006"));
        }
        if history {
            why.push("shell history disabled (HISTFILE, HISTSIZE, HISTFILESIZE or HISTCONTROL)");
            attack.push(pick(ATTACK_ENV, Tactic::Stealth, "T1070.003"));
        }
        out.push(record(
            event,
            &path,
            (RULE_ENV, RULE_ENV_NAME),
            sev,
            format!("{} ({tname} caller)", why.join("; ")),
            "recorded: the exec ran".to_string(),
            attack,
            evidence(raw, "record", policy),
        ));
    }
    out
}

/// Lot 314 (BUG-125): the record-only findings [`Repeats`] remembers; past
/// it the one admitted least recently is forgotten (it may be recorded once
/// more, within the per-rule budget). An unprivileged user makes a new
/// finding with every distinct value (`HISTFILE=/a/<n>`): the table had no
/// cap, and its sweep ran at every admit once it held 4096.
pub const REPEATS_CAP: usize = 4096;

/// Lot 314 (BUG-92): what makes two record-only findings the same — every
/// field the record shows of the finding, its severity and its caller's
/// tier among them; not the process (its pid, its time). The key was the
/// rule, the uid, the file, the shown values and the decision: a Critical
/// CVE-2023-4911 `GLIBC_TUNABLES` whose first 96 characters and length were
/// a Medium one's was held back as a repeat of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RepeatKey {
    rule: String,
    severity: Severity,
    uid: u32,
    path: String,
    kind: String,
    decision: String,
    tier: String,
    tier_signals: Vec<String>,
    classes: Vec<String>,
    environment: Vec<String>,
    values: Vec<String>,
    at_secure: bool,
}

impl RepeatKey {
    fn of(rec: &ExecPolRecord) -> Self {
        let e = &rec.evidence;
        RepeatKey {
            rule: rec.verdict.rule_id.clone(),
            severity: rec.verdict.severity,
            uid: crate::detection_payload::Principal::from_event(&rec.event).uid,
            path: rec.verdict.event_filename.clone(),
            kind: e.kind.clone(),
            decision: e.decision.clone(),
            tier: e.tier.clone(),
            tier_signals: e.tier_signals.clone(),
            classes: e.classes.clone(),
            environment: e.environment.clone(),
            values: e.values.clone(),
            at_secure: e.at_secure,
        }
    }
}

/// Holds back repeats of the same record-only finding (one shell's
/// `HISTFILE=/dev/null` is in every exec it makes) for a while. Lot 314: a
/// [`RepeatWindow`] keyed by [`RepeatKey`], capped at [`REPEATS_CAP`].
pub struct Repeats {
    seen: RepeatWindow<RepeatKey>,
}

impl Repeats {
    pub fn new(every: Duration) -> Self {
        Repeats {
            seen: RepeatWindow::new(every, REPEATS_CAP),
        }
    }

    /// Whether `rec` is new (or its last one is older than the window).
    /// Denies are never held back (each refusal is its own fact).
    pub fn admit(&mut self, rec: &ExecPolRecord, now: Instant) -> bool {
        if rec.evidence.decision == "deny" {
            return true;
        }
        self.seen.admit(RepeatKey::of(rec), now)
    }
}

/// The production recorder: the detection sink, through the per-rule
/// budget.
pub struct SinkRecorder {
    pub sink: Option<DetectionSink>,
    pub posture: Box<dyn Fn() -> nn_model::posture_types::PostureKind + Send>,
}

impl Recorder for SinkRecorder {
    fn detection(&self, rec: ExecPolRecord) {
        let Some(sink) = &self.sink else {
            return;
        };
        let uid = crate::detection_payload::Principal::from_event(&rec.event).uid;
        let admit = crate::detection_budget::admit(&rec.verdict.rule_id, uid, || {
            crate::detection_payload::held_sample(&rec.event)
        });
        if let crate::detection_budget::Admit::Record { suppressed_before } = admit {
            warn!(
                rule = %rec.verdict.rule_id,
                severity = ?rec.verdict.severity,
                target_pid = rec.verdict.event_pid,
                target_filename = %nn_model::log_escape::Escaped(&rec.verdict.event_filename),
                decision = %rec.evidence.decision,
                tier = %rec.evidence.tier,
                "VERDICT (exec policy)"
            );
            sink.record_execpol(
                &rec.event,
                &rec.verdict,
                (self.posture)(),
                rec.response,
                &rec.attack,
                rec.evidence,
                suppressed_before,
            );
        }
    }
}

/// A recorder that keeps what it is given (tests, and the lab's dry runs).
#[derive(Default, Clone)]
pub struct VecRecorder(pub Arc<Mutex<Vec<ExecPolRecord>>>);

impl Recorder for VecRecorder {
    fn detection(&self, rec: ExecPolRecord) {
        self.0.lock().push(rec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::execpol::tier_sig;

    fn put(buf: &mut [u8], s: &str) {
        buf[..s.len()].copy_from_slice(s.as_bytes());
    }

    fn raw_exec(classes: u32, act: u32, t: u32) -> ExecPolRaw {
        let mut r = ExecPolRaw::zeroed();
        r.kind = kind::EXEC;
        r.pid = 4242;
        r.uid = 33;
        r.classes = classes;
        r.action = act;
        r.tier = t;
        r.file_mode = 0o100755;
        put(&mut r.comm, "nn-ms");
        r
    }

    fn ev(path: &str) -> Event {
        Event::ExecCheck {
            pid: 4242,
            ppid: 1,
            uid: 33,
            comm: "nn-ms".into(),
            filename: String::new(),
            timestamp_ns: 7,
            exe: ExeIdentity {
                path: path.into(),
                ..Default::default()
            },
        }
    }

    /// MS-01: `/dev/shm` from a service, refused.
    #[test]
    fn a_denied_exec_is_one_high_record() {
        let raw = raw_exec(
            class::DEV_SHM | class::TMPFS | class::GUARDED_MOUNT,
            action::DENY,
            tier::SERVICE | tier_sig::SYSTEM_SLICE,
        );
        let recs = records_of(&raw, &ev("/dev/shm/nn-ms/id"), "server profile (built in)");
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.verdict.rule_id, RULE_EXEC);
        assert_eq!(r.verdict.severity, Severity::High);
        assert_eq!(r.verdict.event_filename, "/dev/shm/nn-ms/id");
        assert!(r.response.starts_with("denied at exec (EACCES)"));
        assert_eq!(r.evidence.decision, "deny");
        assert_eq!(r.evidence.tier, "service");
        assert_eq!(r.evidence.tier_signals, ["system.slice"]);
        assert!(r.evidence.classes.contains(&"dev_shm".to_string()));
        assert_eq!(r.techniques(), ["T1204.002"]);
        assert_eq!(r.tactics(), ["TA0002"]);
    }

    /// MS-02, MS-03: memfd and deleted files map to Reflective Code
    /// Loading (and File Deletion).
    #[test]
    fn memfd_and_deleted_techniques() {
        let (tac, tech) = exec_techniques(class::MEMFD, "/memfd:x (deleted)");
        assert_eq!(tech, ["T1620"]);
        assert_eq!(tac, ["TA0005"]);
        let (_, tech) = exec_techniques(class::DELETED | class::TMP, "/tmp/.x/a");
        assert_eq!(tech, ["T1620", "T1070.004", "T1204.002", "T1564.001"]);
        let raw = raw_exec(class::MEMFD, action::WOULD_DENY, tier::ADMIN);
        let r = &records_of(&raw, &ev(""), "p")[0];
        assert_eq!(r.verdict.severity, Severity::Medium);
        assert_eq!(r.evidence.decision, "would deny");
        assert!(r.response.contains("the exec ran"));
    }

    /// MS-32: `LD_PRELOAD` from `/tmp` into a service, refused; the same at
    /// a set-id target is recorded (the loader ignores it).
    #[test]
    fn the_preload_record() {
        let mut raw = raw_exec(0, 0, tier::SERVICE | tier_sig::SYSTEM_SLICE);
        raw.env_flags = env_flags::LD_PRELOAD | env_flags::PRELOAD_STAGING;
        raw.env_action = action::DENY | action::RECORD;
        put(&mut raw.preload, "/tmp/nn-ms/libnnms_noop.so");
        let recs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(recs.len(), 1, "{recs:?}");
        let r = &recs[0];
        assert_eq!(r.verdict.rule_id, RULE_PRELOAD);
        assert_eq!(r.verdict.severity, Severity::High);
        assert_eq!(r.techniques(), ["T1574.006"]);
        assert_eq!(r.evidence.values, ["LD_PRELOAD=/tmp/nn-ms/libnnms_noop.so"]);
        assert!(r.verdict.reasoning.contains("libnnms_noop.so"));
        raw.env_action = action::RECORD;
        raw.file_mode = 0o104755;
        let r = &records_of(&raw, &ev("/usr/bin/su"), "p")[0];
        assert!(r.response.contains("AT_SECURE"), "{}", r.response);
        assert!(r.evidence.at_secure);
        assert_eq!(r.verdict.severity, Severity::Medium);
    }

    #[test]
    fn tunables_history_and_library_path() {
        let mut raw = raw_exec(0, 0, tier::SESSION | tier_sig::LOGIN);
        raw.env_flags = env_flags::GLIBC_TUNABLES;
        raw.env_action = action::RECORD;
        raw.file_mode = 0o104755;
        let shape = "glibc.malloc.mxfast=glibc.malloc.mxfast=AAAA";
        put(&mut raw.tunables, shape);
        raw.tunables_len = shape.len() as u32;
        let r = &records_of(&raw, &ev("/usr/bin/su"), "p")[0];
        assert_eq!(r.verdict.rule_id, RULE_ENV);
        assert_eq!(r.verdict.severity, Severity::Critical);
        assert_eq!(r.techniques(), ["T1068"]);
        assert!(tunables_exploit_shape(shape, raw.tunables_len));
        assert!(!tunables_exploit_shape(
            "glibc.malloc.check=3:glibc.cpu.x86_ibt=off",
            40
        ));
        assert!(tunables_exploit_shape("glibc.a=b", 127));
        // the same at a plain target: nothing
        raw.file_mode = 0o100755;
        assert!(records_of(&raw, &ev("/usr/bin/id"), "p").is_empty());
        // history tricks count for a shell only
        let mut raw = raw_exec(0, 0, tier::SESSION);
        raw.env_flags = env_flags::HISTFILE | env_flags::HISTFILE_NULL;
        raw.env_action = action::RECORD;
        put(&mut raw.hist, "/dev/null");
        let r = &records_of(&raw, &ev("/usr/bin/bash"), "p")[0];
        assert_eq!(r.verdict.severity, Severity::Low);
        assert_eq!(r.techniques(), ["T1070.003"]);
        assert!(records_of(&raw, &ev("/usr/bin/id"), "p").is_empty());
        // a library path into /tmp, for a service
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::LD_LIBRARY_PATH | env_flags::LIBPATH_STAGING;
        raw.env_action = action::RECORD;
        put(&mut raw.libpath, "/tmp/lib");
        let r = &records_of(&raw, &ev("/usr/bin/id"), "p")[0];
        assert_eq!(r.verdict.severity, Severity::Medium);
        assert!(r
            .evidence
            .values
            .contains(&"LD_LIBRARY_PATH=/tmp/lib".to_string()));
    }

    #[test]
    fn a_mapping_record() {
        let mut raw = raw_exec(class::TMP, action::RECORD, tier::SERVICE);
        raw.kind = kind::MAP;
        let r = &records_of(&raw, &ev("/tmp/nn-ms/libnnms_noop.so"), "p")[0];
        assert_eq!(r.verdict.rule_id, RULE_MAP);
        assert_eq!(r.verdict.severity, Severity::Medium);
        assert_eq!(r.evidence.kind, "map");
        assert_eq!(r.evidence.decision, "record");
        raw.action = action::RECORD | action::DENY;
        let r = &records_of(&raw, &ev("/dev/shm/x.so"), "p")[0];
        assert_eq!(r.verdict.severity, Severity::High);
        assert!(r.response.contains("refused"));
    }

    #[test]
    fn repeats_are_held_back_but_denies_never() {
        let mut rep = Repeats::new(Duration::from_secs(600));
        let mut raw = raw_exec(0, 0, tier::SESSION);
        raw.env_flags = env_flags::HISTFILE | env_flags::HISTFILE_NULL;
        raw.env_action = action::RECORD;
        let r = records_of(&raw, &ev("/bin/sh"), "p").remove(0);
        let t0 = Instant::now();
        assert!(rep.admit(&r, t0));
        assert!(!rep.admit(&r, t0 + Duration::from_secs(1)));
        assert!(rep.admit(&r, t0 + Duration::from_secs(601)));
        let d = records_of(
            &raw_exec(class::MEMFD, action::DENY, tier::SERVICE),
            &ev(""),
            "p",
        )
        .remove(0);
        assert!(rep.admit(&d, t0));
        assert!(rep.admit(&d, t0));
    }
}

/// Bug hunt 3 (edition 1.4), BUG-92, BUG-125: tests that
/// assert the promised behaviour (they fail on 0cdfb6b where the defect is)
/// and guards that must keep passing.
#[cfg(test)]
mod bughunt3 {
    use super::*;
    use common::wire::execpol::tier_sig;

    fn su_event(uid: u32, path: &str) -> Event {
        Event::ExecCheck {
            pid: 5930,
            ppid: 1,
            uid,
            comm: "su".into(),
            filename: String::new(),
            timestamp_ns: 7,
            exe: ExeIdentity {
                path: path.into(),
                ..Default::default()
            },
        }
    }

    /// The kernel's report of `GLIBC_TUNABLES=<v>` at the exec of the
    /// set-uid-root `/usr/bin/su` by uid 1000 in a login session.
    fn tunables_at_su(v: &str) -> ExecPolRaw {
        let mut r = ExecPolRaw::zeroed();
        r.kind = kind::EXEC;
        r.pid = 5930;
        r.uid = 1000;
        r.file_uid = 0;
        r.file_mode = 0o104755;
        r.tier = tier::SESSION | tier_sig::LOGIN | tier_sig::TTY;
        r.env_flags = env_flags::GLIBC_TUNABLES;
        r.env_action = action::RECORD;
        r.tunables[..v.len()].copy_from_slice(v.as_bytes());
        r.tunables_len = v.len() as u32;
        r
    }

    /// BUG-92: a Critical Looney Tunables record is not a "repeat" of a
    /// Medium one whose first 96 shown characters and length are the same.
    #[test]
    fn bug92_critical_tunables_is_not_a_repeat_of_a_medium() {
        let prefix = "glibc.malloc.arena_max=1:".repeat(4);
        let benign = format!("{prefix}glibc.malloc.tcache_m=1");
        let exploit = format!("{prefix}glibc.malloc.mxfast=g=A");
        assert_eq!(benign.len(), exploit.len());
        assert!(benign.len() > 96 && benign.len() < 127);
        let medium = records_of(
            &tunables_at_su(&benign),
            &su_event(1000, "/usr/bin/su"),
            "p",
        )
        .remove(0);
        let critical = records_of(
            &tunables_at_su(&exploit),
            &su_event(1000, "/usr/bin/su"),
            "p",
        )
        .remove(0);
        assert_eq!(medium.verdict.rule_id, RULE_ENV);
        assert_eq!(medium.verdict.severity, Severity::Medium);
        assert_eq!(critical.verdict.severity, Severity::Critical);
        assert!(critical.verdict.reasoning.contains("CVE-2023-4911"));
        // what the repeat key reads is the same in both records
        assert_eq!(medium.evidence.values, critical.evidence.values);
        let mut rep = Repeats::new(Duration::from_secs(600));
        let t0 = Instant::now();
        assert!(rep.admit(&medium, t0), "the first record is new");
        assert!(
            rep.admit(&critical, t0 + Duration::from_secs(5)),
            "the Critical CVE-2023-4911 record was held back as a repeat of the Medium one \
             (key without severity; values cut at 96 characters)"
        );
    }

    /// BUG-92 guard: a true repeat (same record, same severity) is still
    /// held back within the window.
    #[test]
    fn bug92_guard_a_true_repeat_is_held_back() {
        let prefix = "glibc.malloc.arena_max=1:".repeat(4);
        let exploit = format!("{prefix}glibc.malloc.mxfast=g=A");
        let critical = records_of(
            &tunables_at_su(&exploit),
            &su_event(1000, "/usr/bin/su"),
            "p",
        )
        .remove(0);
        let mut rep = Repeats::new(Duration::from_secs(600));
        let t0 = Instant::now();
        assert!(rep.admit(&critical, t0));
        assert!(!rep.admit(&critical, t0 + Duration::from_secs(5)));
    }

    /// BUG-125: the repeat table stays bounded however many distinct
    /// record-only findings an unprivileged user makes in the window
    /// (`HISTSIZE=0 HISTFILE=/a/N sh -c :`, N always different).
    #[test]
    fn bug125_the_repeat_table_is_bounded() {
        let mut rep = Repeats::new(Duration::from_secs(600));
        let t0 = Instant::now();
        for n in 0..20_000u32 {
            let mut r = ExecPolRaw::zeroed();
            r.kind = kind::EXEC;
            r.pid = 7000 + n;
            r.uid = 1000;
            r.tier = tier::SESSION;
            r.env_flags = env_flags::HISTSIZE_ZERO | env_flags::HISTFILE;
            r.env_action = action::RECORD;
            let v = format!("/a/{n}");
            r.hist[..v.len()].copy_from_slice(v.as_bytes());
            let mut ev = su_event(1000, "/usr/bin/sh");
            if let Event::ExecCheck { pid, .. } = &mut ev {
                *pid = r.pid;
            }
            let rec = records_of(&r, &ev, "p").remove(0);
            assert!(rep.admit(&rec, t0 + Duration::from_millis(u64::from(n))));
        }
        assert!(
            rep.seen.len() <= 4097,
            "the repeat table has no ceiling: {} live keys after 20000 distinct findings in 20 s \
             (admit's own threshold is 4096)",
            rep.seen.len()
        );
    }

    /// Lot 314 (F3, `nn_core::model_check`): the repeat table as a state
    /// machine. A seeded generator draws record-only findings — a
    /// `GLIBC_TUNABLES` benign or of the CVE-2023-4911 shape behind the same
    /// shown characters, history disabled with a few `HISTFILE`s, by two
    /// users in two tiers, from two programs — and exec denies, at times a
    /// few minutes apart. After each: a record is admitted exactly when the
    /// oracle (its whole record — rule, severity, uid, file, every field of
    /// the evidence — last admitted at least a window ago, or never) says
    /// so, a deny always; the table within its cap.
    #[test]
    fn the_repeat_table_keeps_its_invariants() {
        use nn_core::model_check::{check, Rng, SEQUENCES};
        use std::collections::HashMap;
        let prefix = "glibc.malloc.arena_max=1:".repeat(4);
        let tunables = [
            format!("{prefix}glibc.malloc.tcache_m=1"),
            format!("{prefix}glibc.malloc.mxfast=g=A"),
            "glibc.malloc.arena_max=1".to_string(),
        ];
        let hist = ["/dev/null", "/a/1", "/a/2"];
        let window = Duration::from_secs(600);
        let draw = |rng: &mut Rng| -> (ExecPolRaw, Event) {
            let uid = *rng.pick(&[1000u32, 1001]);
            let session = rng.one_in(2);
            match rng.below(5) {
                0..=1 => {
                    let mut r = tunables_at_su(rng.pick::<String>(&tunables));
                    r.uid = uid;
                    if !session {
                        r.tier = tier::SERVICE;
                    }
                    (r, su_event(uid, "/usr/bin/su"))
                }
                2..=3 => {
                    let mut r = ExecPolRaw::zeroed();
                    r.kind = kind::EXEC;
                    r.pid = 7000;
                    r.uid = uid;
                    r.tier = if session {
                        tier::SESSION
                    } else {
                        tier::SERVICE
                    };
                    r.env_flags = env_flags::HISTSIZE_ZERO | env_flags::HISTFILE;
                    r.env_action = action::RECORD;
                    let v = rng.pick(&hist);
                    r.hist[..v.len()].copy_from_slice(v.as_bytes());
                    let path = rng.pick::<&str>(&["/usr/bin/sh", "/usr/bin/bash"]);
                    (r, su_event(uid, path))
                }
                _ => {
                    let mut r = ExecPolRaw::zeroed();
                    r.kind = kind::EXEC;
                    r.pid = 7001;
                    r.uid = uid;
                    r.classes = class::MEMFD;
                    r.action = action::DENY;
                    r.tier = tier::SERVICE;
                    r.file_mode = 0o100755;
                    (r, su_event(uid, "/memfd:x (deleted)"))
                }
            }
        };
        check("exec policy repeats", 0x3143_0000, SEQUENCES, |rng| {
            let mut rep = Repeats::new(window);
            let mut oracle: HashMap<String, Instant> = HashMap::new();
            let t0 = Instant::now();
            let mut now = t0;
            for step in 0..30 {
                now += Duration::from_secs(rng.below(400));
                let (raw, event) = draw(rng);
                for rec in records_of(&raw, &event, "p") {
                    let uid = match &rec.event {
                        Event::ExecCheck { uid, .. } => *uid,
                        _ => u32::MAX,
                    };
                    let key = format!(
                        "{}|{:?}|{uid}|{}|{:?}",
                        rec.verdict.rule_id,
                        rec.verdict.severity,
                        rec.verdict.event_filename,
                        rec.evidence
                    );
                    let deny = rec.evidence.decision == "deny";
                    let want = deny
                        || oracle
                            .get(&key)
                            .is_none_or(|t| now.duration_since(*t) >= window);
                    let got = rep.admit(&rec, now);
                    if got != want {
                        return Err(format!(
                            "step {step}: {} {:?} admitted {got}, the oracle says {want}",
                            rec.verdict.rule_id, rec.verdict.severity
                        ));
                    }
                    if got && !deny {
                        oracle.insert(key, now);
                    }
                }
                if rep.seen.len() > rep.seen.cap() {
                    return Err(format!("step {step}: the table past its cap"));
                }
            }
            Ok(())
        });
    }
}
