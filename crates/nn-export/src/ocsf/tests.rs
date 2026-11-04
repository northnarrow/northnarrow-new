//! Lot 276: the OCSF validator — every record the mapping writes checked
//! against the pinned schema (`ocsf/ocsf-1.9.0.json`): the class's JSON
//! Schema (types, required attributes, enumerations, no attribute the class
//! does not have), and what JSON Schema does not say — `type_uid` is
//! `class_uid × 100 + activity_id`, every `*_name` and caption is its id's
//! in the schema, `metadata.version` is the pinned one.

use super::*;
use crate::schema::{check_record, schema};
use serde_json::Value;

fn ctx() -> Context {
    Context {
        agent_id: "0123456789abcdef0123456789abcdef".into(),
        hostname: "lab-host".into(),
        version: "0.0.1".into(),
    }
}

const SEAL: &str = concat!(
    ",\"prev_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"",
    ",\"entry_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"",
    ",\"agent_sig\":\"AAAA\"}"
);

fn sealed(body: &str) -> String {
    let body = body.strip_suffix('}').expect("an object");
    format!("{body},\"fmt_ver\":3{SEAL}")
}

/// One row of each kind the mapping knows, as the agent writes them (the
/// agent's own test, `agent/src/export/tests.rs`, maps rows its writers
/// produce from the real types).
pub(crate) fn fixtures() -> Vec<(ExportChain, String)> {
    vec![
        (
            ExportChain::Detections,
            sealed(
                r#"{"id":7,"ts":"2026-06-08T12:00:00.123456Z","sensor":"Exec","path":"Rule","rule_id":"R001_ExecFromTmp","rule_name":"Exec from /tmp/","severity":"Medium","verdict":{"Rule":"KillProcess"},"confidence":0.9,"mitre":{"tactic":["TA0002"],"technique":["T1059.004"]},"principal":{"pid":4242,"comm":"évil","uid":0,"ppid":1},"exe":"/tmp/payload","posture_at":"Engaged","response":"KillProcess","detection_type":"execution","status":"Open","mitre_version":"v18"}"#,
            ),
        ),
        (
            ExportChain::Detections,
            sealed(
                r#"{"id":8,"ts":"2026-06-08T12:00:01.000000Z","sensor":"Network","path":"Rule","rule_id":"NN-L-NET-007","severity":"High","verdict":{"Rule":"Log"},"confidence":1.0,"mitre":{"tactic":["Command and Control"],"technique":[]},"principal":{"pid":77,"comm":"curl","uid":1000},"posture_at":"Calm","response":"Log","detection_type":"network","status":"FalsePositive","network":"tcp 10.0.0.9:4444 connect","file":"/etc/hosts"}"#,
            ),
        ),
        (
            ExportChain::Detections,
            sealed(
                r#"{"id":9,"ts":"2026-06-08T12:00:02Z","sensor":"AntiTamper","path":"Ade","severity":"Critical","verdict":{"Ade":"Alert"},"confidence":0.5,"mitre":{"tactic":[]},"principal":{"pid":1,"comm":"systemd","uid":0},"posture_at":"Combat","response":"Log","detection_type":"tamper","status":"Investigating"}"#,
            ),
        ),
        (
            ExportChain::FimDrift,
            sealed(
                r#"{"ts":"2026-06-08T12:00:03.000000Z","path":"/etc/passwd","op":1,"baseline_sha256":"aa","new_sha256":"bb","modifier_pid":900,"modifier_uid":0,"modifier_comm":"vipw","severity":"Critical","decision_engine_skipped":false,"skip_reason":"","agent_id":"0123456789abcdef0123456789abcdef"}"#,
            ),
        ),
        (
            ExportChain::FimDrift,
            sealed(
                r#"{"ts":"2026-06-08T12:00:04.000000Z","path":"/usr/bin/x","op":7,"baseline_sha256":null,"new_sha256":null,"modifier_pid":1,"modifier_uid":0,"modifier_comm":"setcap","severity":"High","decision_engine_skipped":true,"skip_reason":"budget","agent_id":"0123456789abcdef0123456789abcdef"}"#,
            ),
        ),
        (
            ExportChain::Netflow,
            sealed(
                r#"{"ts":"2026-06-08T12:00:05.000000Z","flow_id":"f-1","start_ns":1000000,"end_ns":51000000,"family":2,"src_addr":"10.0.0.2","src_port":40000,"dst_addr":"93.184.216.34","dst_port":443,"proto":6,"pid":321,"uid":1000,"comm":"curl","exe":"/usr/bin/curl","bytes_sent":512,"bytes_recv":4096,"resolved_hostname":"example.org","ja3":"0123456789abcdef0123456789abcdef","ja4":null,"sni":"example.org","close_reason":0,"agent_id":"0123456789abcdef0123456789abcdef"}"#,
            ),
        ),
        (
            ExportChain::Netflow,
            sealed(
                r#"{"ts":"2026-06-08T12:00:06.000000Z","flow_id":"f-2","start_ns":5,"end_ns":4,"family":10,"src_addr":"::1","src_port":1,"dst_addr":"::1","dst_port":2,"proto":17,"pid":3,"uid":0,"comm":"x","exe":null,"bytes_sent":0,"bytes_recv":0,"resolved_hostname":null,"ja3":null,"ja4":null,"sni":null,"close_reason":104,"agent_id":"0123456789abcdef0123456789abcdef"}"#,
            ),
        ),
        (
            ExportChain::CanaryAccess,
            format!(
                "{}{SEAL}",
                r#"{"ts":"2026-06-08T12:00:07.000000Z","canary_id":"c-1","canary_name":"/home/u/.aws/credentials","canary_type":"Credential","access_kind":"FileOpen","accessor_pid":55,"accessor_uid":1000,"accessor_comm":"cat","accessor_exe":"/usr/bin/cat","first_trip":true,"agent_id":"0123456789abcdef0123456789abcdef","seq":3"#
            ),
        ),
        (
            ExportChain::CanaryAccess,
            format!(
                "{}{SEAL}",
                r#"{"ts":"2026-06-08T12:00:08.000000Z","canary_id":"c-2","canary_name":"decoy_helper","canary_type":"Process","access_kind":"ProcessExec","accessor_pid":56,"accessor_uid":0,"accessor_comm":"sh","first_trip":false,"agent_id":"0123456789abcdef0123456789abcdef""#
            ),
        ),
        (
            ExportChain::CanaryAccess,
            format!(
                "{}{SEAL}",
                r#"{"ts":"2026-06-08T12:00:09.000000Z","canary_id":"c-3","canary_name":"10.9.9.9:22","canary_type":"Network","access_kind":"NetworkConnect","accessor_pid":57,"accessor_uid":0,"accessor_comm":"nc","first_trip":true,"agent_id":"0123456789abcdef0123456789abcdef""#
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"intent","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.000000Z","intent":{"source":"rule","response":"KillProcessTree","pid":4242,"start_ns":1000000,"severity":"critical","why":["NN-L-CANARY-001"],"queued_us":120}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"outcome","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.010000Z","outcome":{"result":"success","outcome":"killed 3 processes","elapsed_us":9000}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"intent","run":"00112233aabbccdd","action":8,"ts":"2026-10-31T23:59:01.000000Z","intent":{"source":"combat","response":"Quarantine","pid":4243,"start_ns":0,"file":"/tmp/payload","severity":"high","why":["NEUTRALIZE"],"queued_us":0}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"intent","run":"00112233aabbccdd","action":9,"ts":"2026-10-31T23:59:02.000000Z","intent":{"source":"combat","response":"BlockOutbound","pid":4244,"start_ns":0,"severity":"high","why":["INVESTIGATE: soft egress block"],"queued_us":0}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"intent","run":"00112233aabbccdd","action":10,"ts":"2026-10-31T23:59:03.000000Z","intent":{"source":"combat","response":"Isolate","pid":0,"start_ns":0,"severity":"critical","why":["ISOLATE"],"queued_us":0}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"outcome","run":"00112233aabbccdd","action":99,"ts":"2026-10-31T23:59:04.000000Z","outcome":{"result":"would_execute","outcome":"detect-only","elapsed_us":1}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"interrupted","run":"00112233aabbccdd","action":11,"ts":"2026-10-31T23:59:05.000000Z","intent":{"source":"rule","response":"StripFileCapability","pid":5,"start_ns":0,"file":"/usr/bin/ping","severity":"medium","why":[],"queued_us":0},"noted_by":"ffeeddccbbaa0099"}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"overflow","run":"00112233aabbccdd","action":12,"ts":"2026-10-31T23:59:06.000000Z","overflow":{"displaced":[1],"refused":[2],"queued_at_stop":0,"samples":["x"],"total":2}}"#,
            ),
        ),
        (
            ExportChain::Actions,
            sealed(
                r#"{"row":"run_started","run":"00112233aabbccdd","action":0,"ts":"2026-10-31T23:58:00.000000Z"}"#,
            ),
        ),
        (ExportChain::Detections, "not json at all".to_string()),
        (ExportChain::Netflow, "[1,2,3]".to_string()),
    ]
}

fn map_all() -> Vec<(ExportChain, String, Vec<Value>)> {
    let mut m = Mapper::new();
    fixtures()
        .into_iter()
        .enumerate()
        .map(|(i, (chain, raw))| {
            let row = Row {
                chain,
                file: 3,
                line: i as u64 + 1,
                end: 1000 * (i as u64 + 1),
                raw: raw.as_bytes(),
                rotate: (i == 0).then_some(&b"{\"rotate\":{\"fmt_ver\":3}}"[..]),
                verified: true,
                prev_hash: Some("0".repeat(64)),
                entry_hash: Some("1".repeat(64)),
            };
            let recs = m.map(&ctx(), &row);
            (chain, raw, recs)
        })
        .collect()
}

#[test]
fn the_validator_knows_every_keyword_of_the_pinned_schema() {
    fn walk(v: &Value, names: bool, out: &mut std::collections::BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if !names {
                        out.insert(k.clone());
                    }
                    walk(x, !names && (k == "properties" || k == "$defs"), out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, false, out)),
            _ => {}
        }
    }
    let sc = schema();
    let mut used = std::collections::BTreeSet::new();
    for c in sc["classes"].as_object().unwrap().values() {
        walk(&c["schema"], false, &mut used);
    }
    walk(&sc["$defs"], true, &mut used);
    let unknown: Vec<_> = used
        .iter()
        .filter(|k| !crate::schema::KEYWORDS.contains(&k.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "keywords the validator would skip: {unknown:?}"
    );
    // the classes this mapping writes, pinned
    for (name, uid) in [
        ("base_event", 0),
        ("detection_finding", 2004),
        ("process_activity", 1007),
        ("file_activity", 1001),
        ("network_activity", 4001),
        ("remediation_activity", 7001),
        ("file_remediation_activity", 7002),
        ("process_remediation_activity", 7003),
        ("network_remediation_activity", 7004),
    ] {
        assert_eq!(sc["classes"][name]["uid"], uid, "{name}");
    }
}

/// The validator itself refuses what the schema refuses.
#[test]
fn the_validator_refuses_a_bent_record() {
    let (_, _, recs) = map_all().remove(0);
    let good = recs[0].clone();
    assert_eq!(check_record(&good), Vec::<String>::new());
    type Bend = fn(&mut Value);
    let cases: Vec<(&str, Bend)> = vec![
        ("an unknown attribute", |r| r["colour"] = json!("blue")),
        ("a required one missing", |r| {
            r.as_object_mut().unwrap().remove("finding_info");
        }),
        ("a wrong type", |r| r["time"] = json!("now")),
        ("an enum", |r| r["severity_id"] = json!(42)),
        ("a constant", |r| r["category_uid"] = json!(1)),
        ("type_uid", |r| r["type_uid"] = json!(200402)),
        ("a caption", |r| r["activity_name"] = json!("Make")),
        ("severity's caption", |r| r["severity"] = json!("Loud")),
        ("a nested unknown", |r| r["metadata"]["colour"] = json!(1)),
        ("anyOf", |r| {
            r["evidences"] = json!([{"name": "x"}]);
        }),
        ("the version", |r| r["metadata"]["version"] = json!("1.8.0")),
        ("device type", |r| r["device"]["type"] = json!("Server")),
    ];
    for (what, f) in cases {
        let mut r = good.clone();
        f(&mut r);
        assert!(!check_record(&r).is_empty(), "{what}");
    }
}

/// Every record of every fixture validates, carries its row verbatim and
/// its place, and is ASCII on its line.
#[test]
fn every_record_validates_against_the_pinned_schema() {
    let mut uids = std::collections::BTreeSet::new();
    for (chain, raw, recs) in map_all() {
        assert!(
            !recs.is_empty() && recs.len() <= 2,
            "{chain:?}: {} records",
            recs.len()
        );
        for r in &recs {
            let errs = check_record(r);
            assert!(
                errs.is_empty(),
                "{chain:?} {raw}:\n{}\n{r:#}",
                errs.join("\n")
            );
            assert_eq!(r["raw_data"], raw.as_str());
            let at = &r["unmapped"]["northnarrow"]["row"];
            assert_eq!(at["chain"], chain.name());
            assert_eq!(at["file"], 3);
            assert!(at["line"].as_u64().unwrap() >= 1);
            assert_eq!(at["verified"], true);
            assert!(uids.insert(r["metadata"]["uid"].as_str().unwrap().to_string()));
            let line = to_line(r);
            assert!(line.is_ascii() && !line.contains(&b'\n'));
            let back: Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(&back, r, "the ASCII line decodes to the record");
        }
    }
}

/// The mapping table (`docs/operator/EXPORT.md` §3), as it is.
#[test]
fn each_row_takes_its_class() {
    let got: Vec<Vec<(u64, u64)>> = map_all()
        .into_iter()
        .map(|(_, _, recs)| {
            recs.iter()
                .map(|r| {
                    (
                        r["class_uid"].as_u64().unwrap(),
                        r["activity_id"].as_u64().unwrap(),
                    )
                })
                .collect()
        })
        .collect();
    assert_eq!(
        got,
        vec![
            vec![(2004, 1), (1007, 1)], // an exec detection: its finding, the launch
            vec![(2004, 1)],
            vec![(2004, 1)],
            vec![(1001, 3)], // FIM modified: Update
            vec![(1001, 7)], // a capability set: Set Security
            vec![(4001, 6)], // a flow: Traffic
            vec![(4001, 6)],
            vec![(1001, 14)], // a canary file opened
            vec![(1007, 1)],  // a canary process executed
            vec![(4001, 1)],  // a canary connect
            vec![(7003, 2)],  // KillProcessTree: Evict
            vec![(7003, 2)],  // its outcome, with the intent's facts
            vec![(7002, 1)],  // Quarantine: Isolate
            vec![(7004, 1)],  // BlockOutbound: Isolate, outbound
            vec![(7004, 1)],  // Isolate: the host
            vec![(7001, 0)],  // an outcome without its intent: the generic class
            vec![(7002, 4)],  // StripFileCapability, interrupted: Harden
            vec![(0, 99)],    // an overflow: a base event
            vec![(0, 99)],
            vec![(0, 99)], // a row that does not parse: a base event with its bytes
            vec![(0, 99)],
        ]
    );
}

#[test]
fn an_outcome_carries_its_intent() {
    let all = map_all();
    let outcome = &all[11].2[0];
    assert_eq!(outcome["process"]["pid"], 4242);
    assert_eq!(outcome["status_id"], 1);
    assert_eq!(outcome["status_detail"], "killed 3 processes");
    assert_eq!(outcome["duration"], 9);
    assert_eq!(outcome["severity_id"], 5);
    assert_eq!(outcome["command_uid"], "00112233aabbccdd/7");
    let intent = &all[10].2[0];
    assert_eq!(
        outcome["metadata"]["correlation_uid"],
        intent["metadata"]["correlation_uid"]
    );
    assert_eq!(
        intent["metadata"]["correlation_uid"],
        format!("{}/actions/00112233aabbccdd/7", ctx().agent_id)
    );
    assert_eq!(
        outcome["unmapped"]["northnarrow"]["intent_row"]["line"], 11,
        "the intent's row"
    );
    // the third check of #499: the intent's signed row whole, verbatim
    assert_eq!(
        outcome["unmapped"]["northnarrow"]["intent_raw"],
        fixtures()[10].1.as_str()
    );
    assert!(intent["unmapped"]["northnarrow"]
        .get("intent_raw")
        .is_none());
    assert_eq!(intent["status_id"], 99);
    // the detection's facts
    let det = &all[0].2[0];
    assert_eq!(det["finding_info"]["analytic"]["uid"], "R001_ExecFromTmp");
    assert_eq!(
        det["finding_info"]["attacks"][0],
        json!({"technique": {"uid": "T1059"}, "sub_technique": {"uid": "T1059.004"},
               "tactic": {"uid": "TA0002"}, "version": "v18"})
    );
    assert_eq!(det["time"], 1_780_920_000_123i64);
    assert_eq!(det["confidence_score"], 90);
    assert_eq!(det["evidences"][0]["process"]["parent_process"]["pid"], 1);
    assert!(det["unmapped"]["northnarrow"]["row"]["rotate"].is_string());
    let net = &all[1].2[0];
    assert_eq!(
        net["evidences"][0]["dst_endpoint"],
        json!({"ip": "10.0.0.9", "port": 4444})
    );
    assert_eq!(net["status"], "Other");
    assert_eq!(
        net["finding_info"]["attacks"][0]["tactic"]["name"],
        "Command and Control"
    );
    let flow = &all[5].2[0];
    assert_eq!(flow["traffic"]["bytes"], 4608);
    assert_eq!(flow["duration"], 50);
    assert_eq!(flow["unmapped"]["northnarrow"]["sni"], "example.org");
}

/// At least once: an outcome delivered again (a connection reset before
/// its acknowledgement) maps as the first time — its intent is kept.
#[test]
fn an_outcome_sent_again_maps_the_same_way() {
    let fx = fixtures();
    let mut m = Mapper::new();
    let row = |i: usize| Row {
        chain: fx[i].0,
        file: 3,
        line: i as u64 + 1,
        end: 1000 * (i as u64 + 1),
        raw: fx[i].1.as_bytes(),
        rotate: None,
        verified: true,
        prev_hash: Some("0".repeat(64)),
        entry_hash: Some("1".repeat(64)),
    };
    m.map(&ctx(), &row(10));
    let first = m.map(&ctx(), &row(11));
    let again = m.map(&ctx(), &row(11));
    assert_eq!(first[0]["class_uid"], 7003);
    assert_eq!(first, again);
}

/// A process remediation names its process: an intent without a pid (0,
/// or none) is the generic class's, no `process` invented.
#[test]
fn a_kill_without_its_pid_is_the_generic_remediation() {
    let mut m = Mapper::new();
    for pid in [", \"pid\": 0", ""] {
        let raw = sealed(&format!(
            r#"{{"row":"intent","run":"r","action":1,"ts":"2026-10-31T23:59:00Z","intent":{{"source":"rule","response":"KillProcess"{pid},"severity":"low","why":[]}}}}"#
        ));
        let row = Row {
            chain: ExportChain::Actions,
            file: 1,
            line: 1,
            end: 1,
            raw: raw.as_bytes(),
            rotate: None,
            verified: true,
            prev_hash: None,
            entry_hash: None,
        };
        let r = m.map(&ctx(), &row);
        assert_eq!(r[0]["class_uid"], 7001, "{pid}");
        assert!(r[0].get("process").is_none(), "{pid}");
        assert_eq!(check_record(&r[0]), Vec::<String>::new());
    }
}

/// Each result of an outcome row takes its status.
#[test]
fn an_outcome_s_result_takes_its_status() {
    for (result, id, status, detail) in [
        ("success", 1, "Success", "done"),
        ("failure", 2, "Failure", "done"),
        ("partial", 4, "Partial", "done"),
        (
            "would_execute",
            99,
            "Other",
            "would execute (detect-only): done",
        ),
        ("not_run", 99, "Other", "not run: done"),
        ("abandoned", 6, "Error", "abandoned: done"),
        ("whatever", 0, "Unknown", "done"),
    ] {
        let raw = sealed(&format!(
            r#"{{"row":"outcome","run":"r","action":1,"ts":"2026-10-31T23:59:00Z","outcome":{{"result":"{result}","outcome":"done"}}}}"#
        ));
        let row = Row {
            chain: ExportChain::Actions,
            file: 1,
            line: 2,
            end: 2,
            raw: raw.as_bytes(),
            rotate: None,
            verified: true,
            prev_hash: None,
            entry_hash: None,
        };
        let r = Mapper::new().map(&ctx(), &row);
        assert_eq!(
            (&r[0]["status_id"], &r[0]["status"], &r[0]["status_detail"]),
            (&json!(id), &json!(status), &json!(detail)),
            "{result}"
        );
    }
}

/// The agent's severities as OCSF's, in any case, and their captions.
#[test]
fn severities_map_one_to_one() {
    for (s, id, caption) in [
        ("low", 2, "Low"),
        ("Medium", 3, "Medium"),
        ("HIGH", 4, "High"),
        ("critical", 5, "Critical"),
        ("severe", 0, "Unknown"),
    ] {
        assert_eq!(severity_id(Some(s)), id, "{s}");
        assert_eq!(severity_caption(id), caption, "{s}");
    }
    assert_eq!(severity_id(None), 0);
}

#[test]
fn intents_are_bounded() {
    let mut m = Mapper::new();
    for a in 0..(MAX_INTENTS as u64 + 10) {
        let raw = sealed(&format!(
            r#"{{"row":"intent","run":"r","action":{a},"ts":"2026-10-31T23:59:00Z","intent":{{"source":"rule","response":"KillProcess","pid":9,"start_ns":0,"severity":"low","why":[],"queued_us":0}}}}"#
        ));
        let row = Row {
            chain: ExportChain::Actions,
            file: 1,
            line: a + 1,
            end: a + 1,
            raw: raw.as_bytes(),
            rotate: None,
            verified: true,
            prev_hash: None,
            entry_hash: None,
        };
        m.map(&ctx(), &row);
    }
    assert_eq!(m.intents.len(), MAX_INTENTS);
    assert_eq!(m.order.len(), MAX_INTENTS);
    assert!(!m.intents.contains_key(&("r".to_string(), 0)));
}

#[test]
fn times_are_read_strictly() {
    assert_eq!(time_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(time_ms("1970-01-01T00:00:01.5Z"), Some(1500));
    assert_eq!(
        time_ms("2000-03-01T00:00:00.000000Z"),
        Some(951_868_800_000)
    );
    assert_eq!(
        time_ms("2026-06-08T12:00:00.123456Z"),
        Some(1_780_920_000_123)
    );
    for bad in [
        "",
        "2026-06-08",
        "2026-06-08T12:00:00",
        "2026-13-08T12:00:00Z",
        "2026-06-08T25:00:00Z",
        "2026-06-08T12:00:00.Z",
        "2026-06-08T12:00:00+01:00",
        "2026-06-08x12:00:00Z",
        "20a6-06-08T12:00:00Z",
    ] {
        assert_eq!(time_ms(bad), None, "{bad}");
    }
}

#[test]
fn lines_are_ascii_with_escapes() {
    let v = json!({"a": "é\u{1F600}\n"});
    let l = to_line(&v);
    assert_eq!(l, b"{\"a\":\"\\u00e9\\ud83d\\ude00\\n\"}".to_vec());
    assert_eq!(serde_json::from_slice::<Value>(&l).unwrap(), v);
}

/// Lot 275's inbound connections in the netflow chain (`"inbound": true`:
/// the peer that connected as `src_*`, the local listener as `dst_*`, the
/// byte counters the local socket's): direction Inbound, OCSF's `bytes_out`
/// (source to destination) the bytes the host received; every other row
/// (no such field: a connection the host made) Outbound.
#[test]
fn an_inbound_flow_is_inbound_with_its_traffic_from_the_peer() {
    let body = |extra: &str| {
        sealed(&format!(
            r#"{{"ts":"2026-06-08T12:00:05.000000Z","flow_id":"f-9","start_ns":1000000,"end_ns":51000000,"family":2,"src_addr":"198.51.100.9","src_port":51000,"dst_addr":"10.0.0.2","dst_port":22,"proto":6,"pid":700,"uid":0,"comm":"sshd","exe":"/usr/sbin/sshd","bytes_sent":4000,"bytes_recv":300,"resolved_hostname":null,"ja3":null,"ja4":null,"sni":null,"close_reason":0,"agent_id":"0123456789abcdef0123456789abcdef"{extra}}}"#
        ))
    };
    let map = |raw: &str| {
        let row = Row {
            chain: ExportChain::Netflow,
            file: 1,
            line: 1,
            end: 100,
            raw: raw.as_bytes(),
            rotate: None,
            verified: true,
            prev_hash: Some("0".repeat(64)),
            entry_hash: Some("1".repeat(64)),
        };
        let recs = Mapper::new().map(&ctx(), &row);
        assert_eq!(recs.len(), 1);
        let errs = check_record(&recs[0]);
        assert!(errs.is_empty(), "{}", errs.join("\n"));
        recs[0].clone()
    };
    let inbound = map(&body(r#","inbound":true"#));
    assert_eq!(inbound["class_uid"], 4001);
    assert_eq!(inbound["connection_info"]["direction_id"], 1);
    assert_eq!(inbound["connection_info"]["direction"], "Inbound");
    assert_eq!(inbound["src_endpoint"]["ip"], "198.51.100.9");
    assert_eq!(inbound["dst_endpoint"]["port"], 22);
    assert_eq!(
        inbound["traffic"],
        json!({"bytes_in": 4000, "bytes_out": 300, "bytes": 4300})
    );
    assert_eq!(inbound["unmapped"]["northnarrow"]["inbound"], true);
    assert_eq!(inbound["actor"]["process"]["name"], "sshd");
    for outbound in [map(&body("")), map(&body(r#","inbound":false"#))] {
        assert_eq!(outbound["connection_info"]["direction_id"], 2);
        assert_eq!(outbound["connection_info"]["direction"], "Outbound");
        assert_eq!(
            outbound["traffic"],
            json!({"bytes_in": 300, "bytes_out": 4000, "bytes": 4300})
        );
    }
    assert!(map(&body(""))["unmapped"]["northnarrow"]
        .get("inbound")
        .is_none());
}
