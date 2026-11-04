//! Signed rows as OCSF 1.9.0 records (lot 276; `docs/operator/EXPORT.md`
//! §3, the mapping table). Runs in the export worker only.
//!
//! One row gives one record — two for a detection of the exec sensor (its
//! Detection Finding and the Process Activity it judged) — and every record
//! carries its row: `raw_data` is the row verbatim, as signed, and
//! `unmapped.northnarrow.row` its place (`chain`, `file`, `line`, `end`)
//! and links (`prev_hash`, `entry_hash`; on the first row after a rotation
//! the terminator, `rotate`), so a receiver verifies each record against
//! the agent's key (`nn-admin export verify`) and the chain's continuity
//! across them. A row this mapping does not know, or that does not parse,
//! is a Base Event (class 0) with its bytes: nothing the chain holds is
//! dropped by the mapping.
//!
//! The pinned schema is `ocsf/ocsf-1.9.0.json` (the classes' JSON Schema
//! and their enumerations' captions, from schema.ocsf.io, `profiles=host`);
//! the tests validate every record this module writes against it.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use nn_proto::ipc::ExportChain;
use serde_json::{json, Map, Value};

/// The OCSF version every record names (`metadata.version`).
pub const OCSF_VERSION: &str = "1.9.0";

/// What every record of this agent says about it.
#[derive(Debug, Clone)]
pub struct Context {
    pub agent_id: String,
    pub hostname: String,
    pub version: String,
}

/// A row to map, with its place.
#[derive(Debug, Clone)]
pub struct Row<'a> {
    pub chain: ExportChain,
    pub file: u64,
    pub line: u64,
    pub end: u64,
    pub raw: &'a [u8],
    pub rotate: Option<&'a [u8]>,
    /// Its signature verified with the agent's key (`row_verify`).
    pub verified: bool,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
}

#[derive(Clone, Copy)]
struct Class {
    uid: u32,
    caption: &'static str,
    category_uid: u32,
    category: &'static str,
}

const BASE_EVENT: Class = Class {
    uid: 0,
    caption: "Base Event",
    category_uid: 0,
    category: "Uncategorized",
};
const DETECTION_FINDING: Class = Class {
    uid: 2004,
    caption: "Detection Finding",
    category_uid: 2,
    category: "Findings",
};
const PROCESS_ACTIVITY: Class = Class {
    uid: 1007,
    caption: "Process Activity",
    category_uid: 1,
    category: "System Activity",
};
const FILE_ACTIVITY: Class = Class {
    uid: 1001,
    caption: "File System Activity",
    category_uid: 1,
    category: "System Activity",
};
const NETWORK_ACTIVITY: Class = Class {
    uid: 4001,
    caption: "Network Activity",
    category_uid: 4,
    category: "Network Activity",
};
const REMEDIATION: Class = Class {
    uid: 7001,
    caption: "Remediation Activity",
    category_uid: 7,
    category: "Remediation",
};
const FILE_REMEDIATION: Class = Class {
    uid: 7002,
    caption: "File Remediation Activity",
    category_uid: 7,
    category: "Remediation",
};
const PROCESS_REMEDIATION: Class = Class {
    uid: 7003,
    caption: "Process Remediation Activity",
    category_uid: 7,
    category: "Remediation",
};
const NETWORK_REMEDIATION: Class = Class {
    uid: 7004,
    caption: "Network Remediation Activity",
    category_uid: 7,
    category: "Remediation",
};

/// OCSF's severities (`severity_id`, the same in every class).
fn severity_caption(id: u8) -> &'static str {
    match id {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        6 => "Fatal",
        99 => "Other",
        _ => "Unknown",
    }
}

/// The agent's severities (`Low` … `Critical`, any case) as OCSF's.
fn severity_id(s: Option<&str>) -> u8 {
    match s.map(str::to_ascii_lowercase).as_deref() {
        Some("low") => 2,
        Some("medium") => 3,
        Some("high") => 4,
        Some("critical") => 5,
        _ => 0,
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` as milliseconds since the epoch.
pub fn time_ms(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = ts.get(r)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    if b.len() < 20
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
        || b.last() != Some(&b'Z')
    {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let ms = match b.get(19) {
        Some(b'Z') if b.len() == 20 => 0,
        Some(b'.') => {
            let frac = ts.get(20..b.len() - 1)?;
            if frac.is_empty() || !frac.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let mut ms = 0i64;
            for (i, c) in frac.bytes().take(3).enumerate() {
                ms += i64::from(c - b'0') * 10i64.pow(2 - i as u32);
            }
            ms
        }
        _ => return None,
    };
    // days from the civil date (Howard Hinnant's algorithm)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + h) * 60 + mi) * 60_000 + s * 1000 + ms)
}

fn text(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn uint(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

fn basename(path: &str) -> String {
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

/// An OCSF process from the agent's facts.
fn process(pid: Option<u64>, comm: Option<String>, exe: Option<String>, uid: Option<u64>) -> Value {
    let mut p = Map::new();
    if let Some(pid) = pid {
        p.insert("pid".into(), json!(pid));
    }
    if let Some(c) = comm.filter(|c| !c.is_empty()) {
        p.insert("name".into(), json!(c));
    }
    if let Some(e) = exe.filter(|e| !e.is_empty()) {
        p.insert(
            "file".into(),
            json!({"name": basename(&e), "path": e, "type_id": 1, "type": "Regular File"}),
        );
        p.insert("path".into(), json!(e));
    }
    if let Some(u) = uid {
        p.insert("user".into(), json!({"uid": u.to_string()}));
    }
    Value::Object(p)
}

fn file(path: &str, type_id: u8) -> Value {
    json!({
        "name": basename(path),
        "path": path,
        "type_id": type_id,
        "type": if type_id == 1 { "Regular File" } else { "Unknown" },
    })
}

fn endpoint(addr: &str, port: Option<u64>) -> Option<Value> {
    if addr.is_empty() {
        return None;
    }
    let mut e = Map::new();
    e.insert("ip".into(), json!(addr));
    if let Some(p) = port {
        e.insert("port".into(), json!(p));
    }
    Some(Value::Object(e))
}

/// The OCSF mapping's state: the actions chain's intents, so an outcome's
/// record carries what its intent said (bounded; a worker restarted
/// between them writes the outcome with what it has).
#[derive(Debug, Default)]
pub struct Mapper {
    intents: HashMap<(String, u64), Value>,
    order: VecDeque<(String, u64)>,
}

/// Intents kept for their outcomes.
pub const MAX_INTENTS: usize = 4096;

impl Mapper {
    pub fn new() -> Self {
        Self::default()
    }

    /// The records of one row (one or two; never none).
    pub fn map(&mut self, ctx: &Context, row: &Row<'_>) -> Vec<Value> {
        let parsed: Option<Value> = serde_json::from_slice(row.raw).ok();
        let Some(v) = parsed.filter(Value::is_object) else {
            return vec![base_event(ctx, row, None, "a row that does not parse", 0)];
        };
        match row.chain {
            ExportChain::Detections => detection(ctx, row, &v),
            ExportChain::FimDrift => vec![fim(ctx, row, &v)],
            ExportChain::Netflow => vec![flow(ctx, row, &v)],
            ExportChain::CanaryAccess => vec![canary(ctx, row, &v)],
            ExportChain::Actions => vec![self.action(ctx, row, &v)],
        }
    }

    fn action(&mut self, ctx: &Context, row: &Row<'_>, v: &Value) -> Value {
        let kind = text(v, "row").unwrap_or_default();
        let run = text(v, "run").unwrap_or_default();
        let action = uint(v, "action").unwrap_or(0);
        let key = (run.clone(), action);
        match kind.as_str() {
            "intent" | "interrupted" => {
                let intent = v.get("intent").cloned().unwrap_or(Value::Null);
                let rec = remediation(ctx, row, v, &intent, None, &kind);
                if kind == "intent" {
                    if self.order.len() >= MAX_INTENTS {
                        if let Some(old) = self.order.pop_front() {
                            self.intents.remove(&old);
                        }
                    }
                    let mut kept = intent;
                    if let Value::Object(m) = &mut kept {
                        m.insert("_row".into(), row_ref(row));
                    }
                    if self.intents.insert(key.clone(), kept).is_none() {
                        self.order.push_back(key);
                    }
                }
                rec
            }
            "outcome" => {
                // the intent stays: an outcome sent again (a connection
                // reset before its acknowledgement) maps the same way
                let intent = self.intents.get(&key).cloned();
                remediation(
                    ctx,
                    row,
                    v,
                    intent.as_ref().unwrap_or(&Value::Null),
                    v.get("outcome"),
                    &kind,
                )
            }
            other => {
                let (sev, what) = match other {
                    "overflow" => (3, "responses refused or displaced by a full queue"),
                    "stalled" => (3, "an action outlived its deadline"),
                    "run_started" => (1, "the actions chain's run started"),
                    "run_ended" => (1, "the actions chain's run ended"),
                    _ => (0, "an actions row this mapping does not know"),
                };
                base_event(ctx, row, Some(v), what, sev)
            }
        }
    }
}

/// `unmapped.northnarrow.row`: the row's place and links.
fn row_ref(row: &Row<'_>) -> Value {
    let mut r = Map::new();
    r.insert("chain".into(), json!(row.chain.name()));
    r.insert("file".into(), json!(row.file));
    r.insert("line".into(), json!(row.line));
    r.insert("end".into(), json!(row.end));
    if let Some(p) = &row.prev_hash {
        r.insert("prev_hash".into(), json!(p));
    }
    if let Some(h) = &row.entry_hash {
        r.insert("entry_hash".into(), json!(h));
    }
    r.insert("verified".into(), json!(row.verified));
    if let Some(t) = row.rotate {
        r.insert("rotate".into(), json!(String::from_utf8_lossy(t)));
    }
    Value::Object(r)
}

/// The fields every record has; `n` numbers the records of one row.
#[allow(clippy::too_many_arguments)]
fn frame(
    ctx: &Context,
    row: &Row<'_>,
    class: Class,
    activity: (u8, &str),
    severity: u8,
    time: Option<i64>,
    n: u8,
    extra: Map<String, Value>,
) -> Value {
    let mut m = Map::new();
    m.insert("class_uid".into(), json!(class.uid));
    m.insert("class_name".into(), json!(class.caption));
    m.insert("category_uid".into(), json!(class.category_uid));
    m.insert("category_name".into(), json!(class.category));
    m.insert("activity_id".into(), json!(activity.0));
    m.insert("activity_name".into(), json!(activity.1));
    m.insert(
        "type_uid".into(),
        json!(u64::from(class.uid) * 100 + u64::from(activity.0)),
    );
    m.insert(
        "type_name".into(),
        json!(format!("{}: {}", class.caption, activity.1)),
    );
    m.insert("severity_id".into(), json!(severity));
    m.insert("severity".into(), json!(severity_caption(severity)));
    m.insert("time".into(), json!(time.unwrap_or(0)));
    let mut uid = format!(
        "{}/{}/{}/{}",
        ctx.agent_id,
        row.chain.name(),
        row.file,
        row.line
    );
    if n > 0 {
        uid.push_str(&format!("/{n}"));
    }
    m.insert(
        "metadata".into(),
        json!({
            "version": OCSF_VERSION,
            "profiles": ["host"],
            "product": {
                "name": "NorthNarrow",
                "vendor_name": "NorthNarrow",
                "version": ctx.version,
            },
            "uid": uid,
            "log_name": row.chain.name(),
            "log_provider": "northnarrow-agent",
        }),
    );
    m.insert(
        "device".into(),
        json!({
            "type_id": 0,
            "type": "Unknown",
            "hostname": ctx.hostname,
            "uid": ctx.agent_id,
        }),
    );
    m.insert(
        "raw_data".into(),
        json!(String::from_utf8_lossy(row.raw).into_owned()),
    );
    m.insert(
        "unmapped".into(),
        json!({"northnarrow": {"row": row_ref(row)}}),
    );
    for (k, v) in extra {
        m.insert(k, v);
    }
    Value::Object(m)
}

fn base_event(ctx: &Context, row: &Row<'_>, v: Option<&Value>, what: &str, sev: u8) -> Value {
    let mut extra = Map::new();
    extra.insert("message".into(), json!(what));
    let time = v.and_then(|v| text(v, "ts")).and_then(|t| time_ms(&t));
    frame(ctx, row, BASE_EVENT, (99, "Other"), sev, time, 0, extra)
}

/// MITRE ATT&CK as OCSF attacks: one per technique (its sub-technique
/// split off), or one per tactic when there is none.
fn attacks(v: &Value) -> Vec<Value> {
    let list = |k: &str| -> Vec<String> {
        v.get("mitre")
            .and_then(|m| m.get(k))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let (tactics, techniques) = (list("tactic"), list("technique"));
    let version = text(v, "mitre_version");
    let tactic = |t: &str| {
        if t.len() == 6 && t.starts_with("TA") && t[2..].bytes().all(|b| b.is_ascii_digit()) {
            json!({"uid": t})
        } else {
            json!({"name": t})
        }
    };
    let mut out = Vec::new();
    for t in &techniques {
        let mut a = Map::new();
        match t.split_once('.') {
            Some((base, _)) => {
                a.insert("technique".into(), json!({"uid": base}));
                a.insert("sub_technique".into(), json!({"uid": t}));
            }
            None => {
                a.insert("technique".into(), json!({"uid": t}));
            }
        }
        if tactics.len() == 1 {
            a.insert("tactic".into(), tactic(&tactics[0]));
        }
        if let Some(ver) = &version {
            a.insert("version".into(), json!(ver));
        }
        out.push(Value::Object(a));
    }
    if techniques.is_empty() {
        for t in &tactics {
            let mut a = Map::new();
            a.insert("tactic".into(), tactic(t));
            if let Some(ver) = &version {
                a.insert("version".into(), json!(ver));
            }
            out.push(Value::Object(a));
        }
    }
    out
}

fn detection(ctx: &Context, row: &Row<'_>, v: &Value) -> Vec<Value> {
    let time = text(v, "ts").and_then(|t| time_ms(&t));
    let p = v.get("principal").cloned().unwrap_or(Value::Null);
    let pid = uint(&p, "pid");
    let ppid = uint(&p, "ppid");
    let proc = {
        let mut pr = process(pid, text(&p, "comm"), text(v, "exe"), uint(&p, "uid"));
        if let (Some(pp), Value::Object(m)) = (ppid, &mut pr) {
            m.insert("parent_process".into(), json!({"pid": pp}));
        }
        pr
    };
    let rule_id = text(v, "rule_id");
    let rule_name = text(v, "rule_name");
    let sev = severity_id(text(v, "severity").as_deref());
    let id = uint(v, "id").unwrap_or(0);
    let mut fi = Map::new();
    fi.insert(
        "uid".into(),
        json!(format!("{}/detection/{id}", ctx.agent_id)),
    );
    fi.insert(
        "title".into(),
        json!(rule_name
            .clone()
            .or_else(|| rule_id.clone())
            .unwrap_or_else(|| "detection".into())),
    );
    if let Some(t) = text(v, "detection_type") {
        fi.insert("types".into(), json!([t]));
    }
    if rule_id.is_some() || rule_name.is_some() {
        let mut a = Map::new();
        a.insert("type_id".into(), json!(1));
        a.insert("type".into(), json!("Rule"));
        if let Some(r) = &rule_id {
            a.insert("uid".into(), json!(r));
        }
        if let Some(n) = &rule_name {
            a.insert("name".into(), json!(n));
        }
        fi.insert("analytic".into(), Value::Object(a));
    }
    let atk = attacks(v);
    if !atk.is_empty() {
        fi.insert("attacks".into(), json!(atk));
    }
    if let Some(t) = time {
        fi.insert("created_time".into(), json!(t));
    }
    let mut ev = Map::new();
    ev.insert("process".into(), proc.clone());
    if let Some(f) = text(v, "file").filter(|f| !f.is_empty()) {
        ev.insert("file".into(), file(&f, 0));
    }
    if let Some(dst) = text(v, "network").as_deref().and_then(network_dst) {
        ev.insert("dst_endpoint".into(), dst);
    }
    let (status_id, status) = match text(v, "status").as_deref() {
        Some("Open") => (1, "New"),
        Some("Acknowledged") | Some("Investigating") => (2, "In Progress"),
        Some("Resolved") => (4, "Resolved"),
        Some("FalsePositive") => (99, "Other"),
        _ => (0, "Unknown"),
    };
    let response = text(v, "response").unwrap_or_default();
    let mut extra = Map::new();
    extra.insert("finding_info".into(), Value::Object(fi));
    extra.insert("evidences".into(), json!([Value::Object(ev)]));
    extra.insert("actor".into(), json!({"process": proc.clone()}));
    extra.insert("is_alert".into(), json!(true));
    extra.insert("status_id".into(), json!(status_id));
    extra.insert("status".into(), json!(status));
    if status_id == 99 {
        extra.insert("status_detail".into(), json!("false positive"));
    }
    if let Some(c) = v.get("confidence").and_then(Value::as_f64) {
        extra.insert(
            "confidence_score".into(),
            json!((c.clamp(0.0, 1.0) * 100.0).round() as u64),
        );
    }
    extra.insert(
        "message".into(),
        json!(format!(
            "{}{} ({})",
            rule_id.as_deref().unwrap_or("detection"),
            rule_name.map(|n| format!(": {n}")).unwrap_or_default(),
            if response.is_empty() { "-" } else { &response }
        )),
    );
    let mut nn = Map::new();
    nn.insert("row".into(), row_ref(row));
    for k in [
        "id",
        "sensor",
        "response",
        "posture_at",
        "suppressed_before",
        "operation",
    ] {
        if let Some(x) = v.get(k) {
            nn.insert(k.into(), x.clone());
        }
    }
    extra.insert("unmapped".into(), json!({"northnarrow": Value::Object(nn)}));
    let mut out = vec![frame(
        ctx,
        row,
        DETECTION_FINDING,
        (1, "Create"),
        sev,
        time,
        0,
        extra,
    )];
    // the exec sensor's detections judged a launch: its Process Activity
    if text(v, "sensor").as_deref() == Some("Exec") {
        let mut pa = Map::new();
        pa.insert("process".into(), proc);
        pa.insert(
            "actor".into(),
            match ppid {
                Some(pp) => json!({"process": {"pid": pp}}),
                None => json!({"user": {"uid": uint(&p, "uid").unwrap_or(0).to_string()}}),
            },
        );
        pa.insert(
            "message".into(),
            json!(format!(
                "exec judged by {}",
                rule_id.as_deref().unwrap_or("a detection")
            )),
        );
        out.push(frame(
            ctx,
            row,
            PROCESS_ACTIVITY,
            (1, "Launch"),
            1,
            time,
            1,
            pa,
        ));
    }
    out
}

/// A detection's `network` (`tcp 1.2.3.4:443 connect`) as its destination.
fn network_dst(s: &str) -> Option<Value> {
    let addr: SocketAddr = s.split_whitespace().nth(1)?.parse().ok()?;
    endpoint(&addr.ip().to_string(), Some(u64::from(addr.port())))
}

fn fim(ctx: &Context, row: &Row<'_>, v: &Value) -> Value {
    let time = text(v, "ts").and_then(|t| time_ms(&t));
    let path = text(v, "path").unwrap_or_default();
    let activity = match uint(v, "op") {
        Some(1) => (3, "Update"),
        Some(2) => (1, "Create"),
        Some(3) => (4, "Delete"),
        Some(4) => (5, "Rename"),
        Some(5) => (1, "Create"),
        Some(6) => (14, "Open"),
        Some(7) => (7, "Set Security"),
        Some(8) => (6, "Set Attributes"),
        _ => (0, "Unknown"),
    };
    let mut f = file(if path.is_empty() { "-" } else { &path }, 1);
    if let (Some(h), Value::Object(m)) = (text(v, "new_sha256"), &mut f) {
        m.insert(
            "hashes".into(),
            json!([{"algorithm_id": 3, "algorithm": "SHA-256", "value": h}]),
        );
    }
    let mut extra = Map::new();
    extra.insert("file".into(), f);
    extra.insert(
        "actor".into(),
        json!({"process": process(
            uint(v, "modifier_pid"),
            text(v, "modifier_comm"),
            None,
            uint(v, "modifier_uid"),
        )}),
    );
    extra.insert(
        "message".into(),
        json!(format!("{} {path}", activity.1.to_ascii_lowercase())),
    );
    let sev = severity_id(text(v, "severity").as_deref()).max(1);
    frame(ctx, row, FILE_ACTIVITY, activity, sev, time, 0, extra)
}

fn flow(ctx: &Context, row: &Row<'_>, v: &Value) -> Value {
    let time = text(v, "ts").and_then(|t| time_ms(&t));
    let proto = uint(v, "proto").unwrap_or(0);
    // lot 275: an inbound connection's row (`"inbound": true`) has the peer
    // that connected as `src_*`, the local listener as `dst_*`; the byte
    // counters stay the local socket's
    let inbound = v.get("inbound").and_then(Value::as_bool) == Some(true);
    let mut ci = Map::new();
    if inbound {
        ci.insert("direction_id".into(), json!(1));
        ci.insert("direction".into(), json!("Inbound"));
    } else {
        ci.insert("direction_id".into(), json!(0));
        ci.insert("direction".into(), json!("Unknown"));
    }
    ci.insert("protocol_num".into(), json!(proto));
    if let Some(n) = match proto {
        6 => Some("tcp"),
        17 => Some("udp"),
        _ => None,
    } {
        ci.insert("protocol_name".into(), json!(n));
    }
    match uint(v, "family") {
        Some(2) => {
            ci.insert("protocol_ver_id".into(), json!(4));
            ci.insert(
                "protocol_ver".into(),
                json!("Internet Protocol version 4 (IPv4)"),
            );
        }
        Some(10) => {
            ci.insert("protocol_ver_id".into(), json!(6));
            ci.insert(
                "protocol_ver".into(),
                json!("Internet Protocol version 6 (IPv6)"),
            );
        }
        _ => {}
    }
    let sent = uint(v, "bytes_sent").unwrap_or(0);
    let recv = uint(v, "bytes_recv").unwrap_or(0);
    // OCSF's `bytes_out` is the source's to the destination, `bytes_in` the
    // destination's to the source: the local socket's sent bytes are `out`
    // when the host connected, `in` when the peer did
    let (bytes_out, bytes_in) = if inbound { (recv, sent) } else { (sent, recv) };
    let mut extra = Map::new();
    if let Some(e) = endpoint(
        &text(v, "src_addr").unwrap_or_default(),
        uint(v, "src_port"),
    ) {
        extra.insert("src_endpoint".into(), e);
    }
    if let Some(mut e) = endpoint(
        &text(v, "dst_addr").unwrap_or_default(),
        uint(v, "dst_port"),
    ) {
        if let (Some(h), Value::Object(m)) = (text(v, "resolved_hostname"), &mut e) {
            m.insert("hostname".into(), json!(h));
        }
        extra.insert("dst_endpoint".into(), e);
    }
    extra.insert("connection_info".into(), Value::Object(ci));
    extra.insert(
        "traffic".into(),
        json!({"bytes_in": bytes_in, "bytes_out": bytes_out, "bytes": sent.saturating_add(recv)}),
    );
    extra.insert(
        "actor".into(),
        json!({"process": process(uint(v, "pid"), text(v, "comm"), text(v, "exe"), uint(v, "uid"))}),
    );
    if let (Some(s), Some(e)) = (uint(v, "start_ns"), uint(v, "end_ns")) {
        extra.insert("duration".into(), json!(e.saturating_sub(s) / 1_000_000));
    }
    match uint(v, "close_reason") {
        Some(0) => {
            extra.insert("status_id".into(), json!(1));
            extra.insert("status".into(), json!("Success"));
        }
        Some(r) => {
            extra.insert("status_id".into(), json!(2));
            extra.insert("status".into(), json!("Failure"));
            extra.insert("status_code".into(), json!(r.to_string()));
        }
        None => {}
    }
    let mut nn = Map::new();
    nn.insert("row".into(), row_ref(row));
    for k in ["flow_id", "ja3", "ja4", "sni", "inbound"] {
        if let Some(x) = v.get(k).filter(|x| !x.is_null()) {
            nn.insert(k.into(), x.clone());
        }
    }
    extra.insert("unmapped".into(), json!({"northnarrow": Value::Object(nn)}));
    frame(
        ctx,
        row,
        NETWORK_ACTIVITY,
        (6, "Traffic"),
        1,
        time,
        0,
        extra,
    )
}

fn canary(ctx: &Context, row: &Row<'_>, v: &Value) -> Value {
    let time = text(v, "ts").and_then(|t| time_ms(&t));
    let name = text(v, "canary_name").unwrap_or_else(|| "canary".into());
    let id = text(v, "canary_id").unwrap_or_default();
    let actor = json!({"process": process(
        uint(v, "accessor_pid"),
        text(v, "accessor_comm"),
        text(v, "accessor_exe"),
        uint(v, "accessor_uid"),
    )});
    let sev = if v.get("first_trip").and_then(Value::as_bool) == Some(true) {
        4
    } else {
        3
    };
    let mut extra = Map::new();
    extra.insert("actor".into(), actor);
    extra.insert(
        "message".into(),
        json!(format!("canary {name} ({id}) touched")),
    );
    match text(v, "access_kind").as_deref() {
        Some("ProcessExec") => {
            extra.insert("process".into(), json!({"uid": id, "name": name}));
            frame(
                ctx,
                row,
                PROCESS_ACTIVITY,
                (1, "Launch"),
                sev,
                time,
                0,
                extra,
            )
        }
        Some("NetworkConnect") => {
            extra.insert("dst_endpoint".into(), json!({"uid": id, "name": name}));
            frame(ctx, row, NETWORK_ACTIVITY, (1, "Open"), sev, time, 0, extra)
        }
        _ => {
            let mut f = file(&name, 0);
            if let Value::Object(m) = &mut f {
                m.insert("uid".into(), json!(id));
            }
            extra.insert("file".into(), f);
            frame(ctx, row, FILE_ACTIVITY, (14, "Open"), sev, time, 0, extra)
        }
    }
}

/// The class and activity of a response (its name in the intent: the
/// rule's `ResponseAction`, the COMBAT ladder's step, the exec
/// quarantine's).
fn response_class(response: &str) -> (Class, (u8, &'static str)) {
    let r = response.to_ascii_lowercase();
    if r.contains("kill") {
        (PROCESS_REMEDIATION, (2, "Evict"))
    } else if r.contains("throttle") {
        (PROCESS_REMEDIATION, (99, "Other"))
    } else if r.contains("quarantine") {
        (FILE_REMEDIATION, (1, "Isolate"))
    } else if r.contains("strip") {
        (FILE_REMEDIATION, (4, "Harden"))
    } else if r.contains("release") {
        (NETWORK_REMEDIATION, (3, "Restore"))
    } else if r.contains("block") || r.contains("isolat") {
        (NETWORK_REMEDIATION, (1, "Isolate"))
    } else {
        (REMEDIATION, (99, "Other"))
    }
}

fn remediation(
    ctx: &Context,
    row: &Row<'_>,
    v: &Value,
    intent: &Value,
    outcome: Option<&Value>,
    kind: &str,
) -> Value {
    let time = text(v, "ts").and_then(|t| time_ms(&t));
    let run = text(v, "run").unwrap_or_default();
    let action = uint(v, "action").unwrap_or(0);
    let response = text(intent, "response").unwrap_or_default();
    let (mut class, mut activity) = response_class(&response);
    let pid = uint(intent, "pid").filter(|p| *p > 0);
    let target = text(intent, "file").filter(|f| !f.is_empty());
    let mut extra = Map::new();
    // each specific class has its required target, or the record is the
    // generic class's
    match class.uid {
        7003 => match pid {
            Some(p) => {
                extra.insert("process".into(), json!({"pid": p}));
            }
            None => class = REMEDIATION,
        },
        7002 => match &target {
            Some(f) => {
                extra.insert("file".into(), file(f, 0));
            }
            None => class = REMEDIATION,
        },
        7004 => {
            let outbound = response.to_ascii_lowercase().contains("block");
            extra.insert(
                "connection_info".into(),
                json!({
                    "direction_id": if outbound { 2 } else { 0 },
                    "direction": if outbound { "Outbound" } else { "Unknown" },
                }),
            );
        }
        _ => {}
    }
    if class.uid == 7001 && intent.is_null() {
        activity = (0, "Unknown");
    }
    extra.insert("command_uid".into(), json!(format!("{run}/{action}")));
    let why: Vec<String> = intent
        .get("why")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if !why.is_empty() {
        extra.insert("remediation".into(), json!({"desc": why.join(", ")}));
    }
    let (status_id, status, detail): (u8, &str, Option<String>) = match (kind, outcome) {
        ("outcome", Some(o)) => {
            let what = text(o, "outcome");
            let reason = text(o, "reason");
            let detail = match (what, reason) {
                (Some(w), Some(r)) => Some(format!("{w}: {r}")),
                (w, r) => w.or(r),
            };
            if let Some(us) = uint(o, "elapsed_us") {
                extra.insert("duration".into(), json!(us / 1000));
            }
            match text(o, "result").as_deref() {
                Some("success") => (1, "Success", detail),
                Some("failure") => (2, "Failure", detail),
                Some("partial") => (4, "Partial", detail),
                Some("would_execute") => (
                    99,
                    "Other",
                    Some(format!("would execute (detect-only){}", tail(detail))),
                ),
                Some("not_run") => (99, "Other", Some(format!("not run{}", tail(detail)))),
                Some("abandoned") => (6, "Error", Some(format!("abandoned{}", tail(detail)))),
                _ => (0, "Unknown", detail),
            }
        }
        ("interrupted", _) => (
            6,
            "Error",
            Some("interrupted: the agent stopped between the intent and its outcome".into()),
        ),
        _ => (
            99,
            "Other",
            Some("intended: the outcome follows in its own row".into()),
        ),
    };
    extra.insert("status_id".into(), json!(status_id));
    extra.insert("status".into(), json!(status));
    if let Some(d) = detail {
        extra.insert("status_detail".into(), json!(d));
    }
    extra.insert(
        "message".into(),
        json!(format!(
            "{} {}{}",
            text(intent, "source").unwrap_or_else(|| "action".into()),
            if response.is_empty() { "?" } else { &response },
            pid.map(|p| format!(" pid {p}")).unwrap_or_default()
        )),
    );
    let mut nn = Map::new();
    nn.insert("row".into(), row_ref(row));
    nn.insert("kind".into(), json!(kind));
    if let Some(r @ Value::Object(_)) = intent.get("_row") {
        nn.insert("intent_row".into(), r.clone());
    }
    extra.insert(
        "metadata_correlation".into(),
        json!(format!("{}/actions/{run}/{action}", ctx.agent_id)),
    );
    extra.insert("unmapped".into(), json!({"northnarrow": Value::Object(nn)}));
    let sev = severity_id(text(intent, "severity").as_deref());
    let mut rec = frame(ctx, row, class, activity, sev, time, 0, extra);
    // the intent and its outcome share one correlation id
    if let Value::Object(m) = &mut rec {
        if let Some(c) = m.remove("metadata_correlation") {
            if let Some(Value::Object(md)) = m.get_mut("metadata") {
                md.insert("correlation_uid".into(), c);
            }
        }
    }
    rec
}

fn tail(detail: Option<String>) -> String {
    detail.map(|d| format!(": {d}")).unwrap_or_default()
}

/// A record as one line: JSON in ASCII only (every other character as its
/// `\u` escape), so a syslog message is plain ASCII and a file line too.
pub fn to_line(v: &Value) -> Vec<u8> {
    let s = v.to_string();
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c as u8);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.extend_from_slice(format!("\\u{u:04x}").as_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests;
