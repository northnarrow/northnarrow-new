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
        at_secure: raw.at_secure(),
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
                 {}{}",
                if deny { "denies it" } else { "would deny it" },
                if raw.action & action::UNWALKED != 0 {
                    UNWALKED_NOTE
                } else {
                    ""
                }
            ),
            resp.to_string(),
            attack,
            evidence(raw, decision_of(raw.action), policy),
        ));
    }
    // Lot 325 (the re-check of #546, R5): an exec judged without its walk
    // (the exec guards' per-task buffers full) and let through: recorded,
    // and the agent signs a degradation while it lasts.
    if raw.action & action::UNWALKED != 0
        && raw.action & (action::DENY | action::WOULD_DENY) == 0
        && raw.env_action & (action::DENY | action::WOULD_DENY) == 0
    {
        out.push(record(
            event,
            &path,
            (RULE_EXEC, RULE_EXEC_NAME),
            Severity::Low,
            format!(
                "exec by a {tname} caller judged without its walk ({}): no protected target, \
                 let through{UNWALKED_NOTE}",
                if classes.is_empty() {
                    "no class it can know without one"
                } else {
                    classes.as_str()
                }
            ),
            "recorded: the exec ran (the exec guards are past their capacity)".to_string(),
            exec_attack(raw.classes, &path),
            evidence(raw, "record", policy),
        ));
    }
    let ef = raw.env_flags;
    let ea = raw.env_action;
    if ea == 0 {
        return out;
    }
    let setid = raw.target_setid();
    // Lot 315 (BUG-101): whether the loader ignores the entry is whether
    // the exec changes the credentials, not the mode's set-id bits alone
    // (root running a set-uid-root file: the preload is honoured).
    let at_secure = raw.at_secure();
    // The loader variable into a staging path.
    if ef & env_flags::DENYABLE != 0 {
        let changed = ef & env_flags::CHANGED != 0;
        let (sev, resp) = if changed && ea & action::KILLED != 0 {
            (
                Severity::Critical,
                "killed (SIGKILL) before its first instruction: the exec was past its point \
                 of no return"
                    .to_string(),
            )
        } else if changed && ea & action::WOULD_DENY != 0 {
            (
                Severity::High,
                "would deny (audit): the exec ran with the entry".to_string(),
            )
        } else if changed {
            (
                Severity::High,
                "recorded: the exec ran with the entry".to_string(),
            )
        } else if ea & action::DENY != 0 {
            (Severity::High, "denied at exec (EACCES)".to_string())
        } else if ea & action::WOULD_DENY != 0 {
            (
                Severity::Medium,
                "would deny (audit): the exec ran".to_string(),
            )
        } else if at_secure {
            (
                Severity::Medium,
                "recorded: the target is set-id, the kernel sets AT_SECURE and the loader \
                 ignores the entry"
                    .to_string(),
            )
        } else if setid {
            (
                Severity::Medium,
                "recorded: the exec ran; the target is set-id, but the exec changes no \
                 credential, so the loader honours the entry"
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
                "a loader variable at exec names a staging path ({}) for a {tname} caller{}",
                values(raw)
                    .into_iter()
                    .filter(|v| v.starts_with("LD_PRELOAD=") || v.starts_with("LD_AUDIT="))
                    .collect::<Vec<_>>()
                    .join(", "),
                if changed {
                    // Lot 325 (TOCTOU): seen in the kernel's own copy only
                    "; it is in the kernel's own copy of the environment (the new image's) and \
                     was not in the caller's memory when the exec's first pass read it: the \
                     environment changed after the kernel's copy"
                } else {
                    ""
                }
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
    // Lot 322 (the review of #546, F1, F2): an environment the kernel could
    // not read whole — an entry or a string unreadable at the exec's first
    // pass (the caller's memory changed after the kernel's copy of it), an
    // exec entered through a call the scan does not know, or no stash.
    // Whatever loader variable it held was not judged: recorded, High,
    // never refused (a 32-bit runtime's exec reads normally).
    // Lot 325 (the re-check of #546, R2): an environment the scan could
    // not finish — more variables than any the kernel accepts, so its
    // array grew after the kernel's count. Recorded High, as an unread
    // one; refused at a protected target (the tier's rule refuses a
    // staging preload) or a set-id one.
    if ef & env_flags::UNFINISHED != 0
        && ea & (action::RECORD | action::DENY | action::WOULD_DENY) != 0
    {
        let resp = env_response(ea, "a protected or set-id target");
        out.push(record(
            event,
            &path,
            (RULE_ENV, RULE_ENV_NAME),
            Severity::High,
            if ef & env_flags::TRUNCATED != 0 {
                format!(
                    "the new environment could not be read whole at exec ({tname} caller): \
                     more than {} variables, more than any environment the kernel accepts — \
                     the array grew after the kernel counted it; a loader variable past them \
                     was not judged",
                    common::wire::execpol::ENV_SCAN_CAP
                )
            } else {
                // Lot 325 (the mini-hunt of R2; the review of #547, F7: the
                // value is judged whole up to about 4 KiB, a longer one
                // judged in the kernel's copy at the commit)
                format!(
                    "a loader variable's value at exec is longer than the check reads \
                     ({tname} caller; {} bytes): its entries past them were not judged",
                    common::wire::execpol::ENV_VALUE_READS
                        * (common::wire::execpol::ENV_REGION_READ - 1)
                )
            },
            resp,
            vec![pick(ATTACK_ENV, Tactic::Stealth, "T1574.006")],
            evidence(raw, decision_of(ea), policy),
        ));
    }
    // The review of #547 (F1): a relative loader path, or a bare name in a
    // staging or relative library path — where it resolves is not in the
    // string. Refused at a protected or set-id target, recorded elsewhere.
    if ef & env_flags::PRELOAD_RELATIVE != 0
        && ea & (action::RECORD | action::DENY | action::WOULD_DENY) != 0
    {
        let refused = ea & action::DENY != 0;
        out.push(record(
            event,
            &path,
            (RULE_PRELOAD, RULE_PRELOAD_NAME),
            if refused {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "a loader variable at exec names a path relative to the caller's directory, \
                 or a bare name in a staging or relative library path ({}), for a {tname} \
                 caller: where it resolves is not in the string",
                values(raw)
                    .into_iter()
                    .filter(|v| v.starts_with("LD_"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            env_response(ea, "a protected or set-id target"),
            ATTACK_PRELOAD.to_vec(),
            evidence(raw, decision_of(ea), policy),
        ));
    }
    if ef & env_flags::UNREADABLE != 0
        && ef & env_flags::UNFINISHED == 0
        && ea & (action::RECORD | action::DENY) != 0
    {
        // The review of #547 (F5): an unreadable environment is not refused
        // at the first pass (the post-commit check reads the kernel's copy);
        // killed there on it only at a protected or set-id target.
        let refused_on_it =
            ea & action::DENY != 0 && ef & (env_flags::DENYABLE | env_flags::PRELOAD_RELATIVE) == 0;
        out.push(record(
            event,
            &path,
            (RULE_ENV, RULE_ENV_NAME),
            Severity::High,
            format!(
                "the new environment could not be read whole at exec ({tname} caller): an \
                 entry or a string unreadable after the kernel's copy, or a call the check does \
                 not know; a loader variable in it was not judged"
            ),
            if refused_on_it {
                env_response(ea, "a protected or set-id target")
            } else if ea & action::DENY != 0 {
                "the exec was refused on another finding of its environment".to_string()
            } else {
                "recorded: the exec ran".to_string()
            },
            vec![pick(ATTACK_ENV, Tactic::Stealth, "T1574.006")],
            evidence(raw, if refused_on_it { "deny" } else { "record" }, policy),
        ));
    }
    out
}

/// What was done about an environment finding (`ea`, the report's
/// `env_action`); `why` names the target a refusal rests on.
fn env_response(ea: u32, why: &str) -> String {
    if ea & action::KILLED != 0 {
        format!(
            "killed (SIGKILL) before its first instruction: the kernel's own copy of the \
             environment, past the exec's point of no return ({why})"
        )
    } else if ea & action::DENY != 0 {
        format!("denied at exec (EACCES): {why}")
    } else if ea & action::WOULD_DENY != 0 {
        "would deny (audit): the exec ran".to_string()
    } else {
        "recorded: the exec ran".to_string()
    }
}

/// Lot 325 (R5): what a record of an exec judged without its walk adds.
const UNWALKED_NOTE: &str = " (judged without its walk: the exec guards' per-task buffers were \
     full — a flood of execs in flight — so only the tier, the set-id bits, memfd, deleted, \
     tmpfs, a world-writable directory and the environment were judged)";

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
    /// a set-id target the kernel only recorded (a tier whose rule does not
    /// deny: since lot 318 a denying tier refuses it there too) says the
    /// loader ignores it.
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

    /// Lot 322 (the review of #546, F1, F2): an environment the kernel
    /// could not read whole is one High record under NN-L-EXECENV-002, with
    /// the exec allowed; nothing without the record action.
    #[test]
    fn an_environment_not_read_whole_is_one_high_record() {
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::UNREADABLE;
        raw.env_action = action::RECORD;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_ENV);
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert_eq!(rs[0].techniques(), ["T1574.006"]);
        // with a staging preload read before the unreadable entry: both
        raw.env_flags = env_flags::UNREADABLE | env_flags::LD_PRELOAD | env_flags::PRELOAD_STAGING;
        raw.env_action = action::RECORD | action::DENY;
        put(&mut raw.preload, "/tmp/x.so");
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 2, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_PRELOAD);
        assert_eq!(rs[1].verdict.rule_id, RULE_ENV);
        // not recorded for that tier: nothing
        raw.env_flags = env_flags::UNREADABLE;
        raw.env_action = 0;
        assert!(records_of(&raw, &ev("/usr/bin/true"), "p").is_empty());
    }

    /// Lot 325 (the re-check of #546, R2): an environment the scan could not
    /// finish — more variables than any the kernel accepts — is one High
    /// record, refused at a protected target, recorded elsewhere. It was a
    /// count no one saw.
    #[test]
    fn an_environment_the_scan_could_not_finish_is_one_high_record() {
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::TRUNCATED;
        raw.env_action = action::RECORD | action::DENY;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_ENV);
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert!(
            rs[0].response.starts_with("denied at exec"),
            "{}",
            rs[0].response
        );
        assert!(rs[0]
            .verdict
            .reasoning
            .contains("grew after the kernel counted it"));
        assert_eq!(rs[0].evidence.decision, "deny");
        assert_eq!(rs[0].evidence.environment, ["truncated"]);
        // an admin's: recorded, the exec ran
        raw.tier = tier::ADMIN | tier_sig::TTY | tier_sig::ROOT;
        raw.env_action = action::RECORD;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert_eq!(rs[0].response, "recorded: the exec ran");
        // with an unreadable entry too: still one record
        raw.env_flags = env_flags::TRUNCATED | env_flags::UNREADABLE;
        assert_eq!(records_of(&raw, &ev("/usr/bin/true"), "p").len(), 1);
    }

    /// Lot 325 (the mini-hunt of R2): a loader variable's value longer than
    /// its capture — a staging entry after a long clean one passed — is an
    /// environment not judged to its end: one High record, refused at a
    /// protected target.
    #[test]
    fn a_loader_value_longer_than_its_capture_is_not_judged_whole() {
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::LD_PRELOAD | env_flags::VALUE_CUT | env_flags::LOADER_CUT;
        raw.env_action = action::RECORD | action::DENY;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_ENV);
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert!(rs[0]
            .verdict
            .reasoning
            .contains("longer than the check reads"));
        assert!(
            rs[0].response.starts_with("denied at exec"),
            "{}",
            rs[0].response
        );
        assert!(rs[0]
            .evidence
            .environment
            .contains(&"loader_value_cut".to_string()));
    }

    /// Lot 325 (TOCTOU): a staging preload in the kernel's own copy that the
    /// first pass did not see — killed before its first instruction where
    /// the tier refuses it (Critical), High where it is recorded.
    #[test]
    fn a_preload_seen_only_in_the_kernel_s_copy_is_the_environment_changed() {
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::LD_PRELOAD | env_flags::PRELOAD_STAGING | env_flags::CHANGED;
        raw.env_action = action::RECORD | action::DENY | action::KILLED;
        put(&mut raw.preload, "/tmp/x.so");
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_PRELOAD);
        assert_eq!(rs[0].verdict.severity, Severity::Critical);
        assert!(
            rs[0].response.starts_with("killed (SIGKILL)"),
            "{}",
            rs[0].response
        );
        assert!(rs[0]
            .verdict
            .reasoning
            .contains("the environment changed after the kernel's copy"));
        assert!(rs[0]
            .evidence
            .environment
            .contains(&"changed_after_the_kernel_s_copy".to_string()));
        raw.env_action = action::RECORD | action::WOULD_DENY;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert!(
            rs[0].response.starts_with("would deny"),
            "{}",
            rs[0].response
        );
        raw.tier = tier::ADMIN | tier_sig::TTY;
        raw.env_action = action::RECORD;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert_eq!(rs[0].response, "recorded: the exec ran with the entry");
    }

    /// Lot 325 (the re-check of #546, R5): an exec judged without its walk
    /// is recorded whatever the verdict — refused (a protected target) or
    /// let through (the exec guards past their capacity).
    #[test]
    fn an_exec_judged_without_its_walk_is_recorded() {
        // let through: one Low record
        let raw = raw_exec(
            0,
            action::UNWALKED | action::RECORD,
            tier::ADMIN | tier_sig::TTY,
        );
        let rs = records_of(&raw, &ev(""), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_EXEC);
        assert_eq!(rs[0].verdict.severity, Severity::Low);
        assert!(rs[0].verdict.reasoning.contains("judged without its walk"));
        assert!(
            rs[0].response.contains("past their capacity"),
            "{}",
            rs[0].response
        );
        // a memfd from a service: refused, one High record that says so
        let raw = raw_exec(
            class::MEMFD,
            action::UNWALKED | action::RECORD | action::DENY,
            tier::SERVICE,
        );
        let rs = records_of(&raw, &ev(""), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert!(rs[0].verdict.reasoning.contains("judged without its walk"));
        // the environment not read at a protected target: refused on it
        let mut raw = raw_exec(0, action::UNWALKED | action::RECORD, tier::SERVICE);
        raw.env_flags = env_flags::UNREADABLE;
        raw.env_action = action::RECORD | action::DENY;
        let rs = records_of(&raw, &ev(""), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_ENV);
        assert!(
            rs[0].response.starts_with("denied at exec"),
            "{}",
            rs[0].response
        );
        assert_eq!(rs[0].evidence.decision, "deny");
    }

    /// The review of #547 (F1, F2): a relative loader path is one record
    /// under the preload rule (High when refused); what the post-commit
    /// check could not clear in the kernel's copy, killed at a protected or
    /// set-id target, says so.
    #[test]
    fn a_relative_loader_path_and_a_kill_on_an_unjudged_copy_are_recorded() {
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::LD_PRELOAD | env_flags::PRELOAD_RELATIVE;
        raw.env_action = action::RECORD | action::DENY;
        put(&mut raw.preload, "./x.so");
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_PRELOAD);
        assert_eq!(rs[0].verdict.severity, Severity::High);
        assert!(rs[0]
            .verdict
            .reasoning
            .contains("relative to the caller's directory"));
        assert!(
            rs[0].response.starts_with("denied at exec"),
            "{}",
            rs[0].response
        );
        assert!(rs[0]
            .evidence
            .environment
            .contains(&"relative_loader_path".to_string()));
        raw.env_action = action::RECORD;
        assert_eq!(
            records_of(&raw, &ev("/usr/bin/true"), "p")[0]
                .verdict
                .severity,
            Severity::Medium
        );
        // a value past the scan's reads, killed at the commit
        let mut raw = raw_exec(0, 0, tier::SERVICE);
        raw.env_flags = env_flags::LD_PRELOAD | env_flags::LOADER_CUT;
        raw.env_action = action::RECORD | action::DENY | action::KILLED;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert_eq!(rs[0].verdict.rule_id, RULE_ENV);
        assert!(
            rs[0].response.starts_with("killed (SIGKILL)"),
            "{}",
            rs[0].response
        );
        // an unreadable copy, killed
        raw.env_flags = env_flags::UNREADABLE;
        let rs = records_of(&raw, &ev("/usr/bin/true"), "p");
        assert_eq!(rs.len(), 1, "{rs:?}");
        assert!(
            rs[0].response.starts_with("killed (SIGKILL)"),
            "{}",
            rs[0].response
        );
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

/// Lot 315 (external bug hunt 1.4, BUG-101, the record's half).
#[cfg(test)]
mod lot315 {
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

    fn preload_at(uid: u32, file_uid: u32, mode: u32, t: u32) -> ExecPolRaw {
        let mut r = ExecPolRaw::zeroed();
        r.kind = kind::EXEC;
        r.pid = 4242;
        r.uid = uid;
        r.file_uid = file_uid;
        r.file_mode = mode;
        r.tier = t;
        r.env_flags = env_flags::LD_PRELOAD | env_flags::PRELOAD_STAGING;
        // what the kernel reports for a set-id target: the deny is skipped
        // (agent-ebpf/src/execpol.rs, lot 318's half), recorded only
        r.env_action = action::RECORD;
        let v = "/tmp/x.so";
        r.preload[..v.len()].copy_from_slice(v.as_bytes());
        r
    }

    /// BUG-101: root running a set-uid-root binary changes no credential:
    /// no AT_SECURE, the loader honours the preload. The record must not
    /// say the loader ignored it (on main it did) — and stays Medium.
    #[test]
    fn bug101_root_running_setuid_root_is_not_at_secure() {
        for t in [
            tier::SERVICE | tier_sig::ROOT | tier_sig::SYSTEM_SLICE,
            tier::SESSION | tier_sig::ROOT | tier_sig::LOGIN | tier_sig::TTY,
        ] {
            let raw = preload_at(0, 0, 0o104755, t);
            let recs = records_of(&raw, &su_event(0, "/usr/bin/su"), "p");
            assert_eq!(recs.len(), 1, "{recs:?}");
            let r = &recs[0];
            assert_eq!(r.verdict.rule_id, RULE_PRELOAD);
            assert!(
                !r.evidence.at_secure,
                "at_secure = true for uid 0 running a set-uid-root file (no credential change)"
            );
            assert!(
                !r.response.contains("AT_SECURE") && !r.response.contains("ignores"),
                "false response: {}",
                r.response
            );
            assert!(r.response.contains("honours"), "{}", r.response);
            assert_eq!(r.verdict.severity, Severity::Medium, "{t:#x}");
        }
    }

    /// BUG-101 guard: an unprivileged caller of a set-uid-root binary does
    /// change credentials: AT_SECURE applies and the record says so.
    #[test]
    fn bug101_guard_user_running_setuid_root_stays_at_secure() {
        let raw = preload_at(33, 0, 0o104755, tier::SERVICE | tier_sig::SYSTEM_SLICE);
        let r = records_of(&raw, &su_event(33, "/usr/bin/su"), "p").remove(0);
        assert!(r.evidence.at_secure);
        assert!(r.response.contains("AT_SECURE"), "{}", r.response);
        assert_eq!(r.verdict.severity, Severity::Medium);
    }

    /// BUG-101: Looney Tunables (`GLIBC_TUNABLES` at a set-id target) is
    /// still reported for root running a set-uid-root file — the set-id
    /// bits decide that record, not the credential change.
    #[test]
    fn bug101_guard_tunables_at_a_setid_target_stay_reported_for_root() {
        let mut raw = preload_at(0, 0, 0o104755, tier::SESSION | tier_sig::ROOT);
        raw.env_flags = env_flags::GLIBC_TUNABLES;
        let v = "glibc.malloc.mxfast=glibc.malloc.mxfast=A";
        raw.tunables[..v.len()].copy_from_slice(v.as_bytes());
        raw.tunables_len = v.len() as u32;
        let recs = records_of(&raw, &su_event(0, "/usr/bin/su"), "p");
        assert!(
            recs.iter().any(|r| r.verdict.rule_id == RULE_ENV),
            "{recs:?}"
        );
    }
}
