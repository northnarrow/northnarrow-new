//! Lot 276: the OCSF validator — a record checked against the pinned
//! schema (`ocsf/ocsf-1.9.0.json`): the class's JSON Schema (types,
//! required attributes, enumerations, no attribute the class does not
//! have), and what JSON Schema does not say — `type_uid` is `class_uid ×
//! 100 + activity_id`, every `*_name` and caption is its id's in the
//! schema, `metadata.version` is the pinned one. The tests' (nn-export's
//! own, and the agent's with the `schema-check` feature): not in a
//! production build.

use serde_json::Value;

use crate::ocsf::OCSF_VERSION;

/// The pinned schema.
pub fn schema() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-export/ocsf/ocsf-1.9.0.json"
    )))
    .expect("the pinned schema")
}

/// The JSON Schema keywords the validator knows.
pub const KEYWORDS: &[&str] = &[
    "$ref",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "anyOf",
    "oneOf",
    "not",
];

fn type_ok(v: &Value, t: &str) -> bool {
    match t {
        "string" => v.is_string(),
        "integer" => v.is_i64() || v.is_u64(),
        "number" => v.is_number(),
        "boolean" => v.is_boolean(),
        "object" => v.is_object(),
        "array" => v.is_array(),
        "null" => v.is_null(),
        _ => false,
    }
}

/// `v` against the schema `s` (the pinned file's subset of JSON Schema);
/// every failure with its path.
pub fn validate(v: &Value, s: &Value, defs: &Value, path: &str, errs: &mut Vec<String>) {
    let Some(s) = s.as_object() else {
        // `{}`-like schemas (an attribute of any type)
        return;
    };
    for k in s.keys() {
        if !KEYWORDS.contains(&k.as_str()) {
            errs.push(format!("{path}: the validator does not know `{k}`"));
        }
    }
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        let name = r.strip_prefix("#/$defs/").expect("a local reference");
        let target = defs
            .get(name)
            .unwrap_or_else(|| panic!("{path}: no $defs/{name}"));
        validate(v, target, defs, path, errs);
    }
    match s.get("type") {
        Some(Value::String(t)) if !type_ok(v, t) => {
            errs.push(format!("{path}: {v} is not a {t}"));
            return;
        }
        Some(Value::Array(ts)) if !ts.iter().filter_map(Value::as_str).any(|t| type_ok(v, t)) => {
            errs.push(format!("{path}: {v} is none of {ts:?}"));
            return;
        }
        _ => {}
    }
    if let Some(c) = s.get("const") {
        if c != v {
            errs.push(format!("{path}: {v}, the class's constant is {c}"));
        }
    }
    if let Some(Value::Array(e)) = s.get("enum") {
        if !e.contains(v) {
            errs.push(format!("{path}: {v} is not one of {e:?}"));
        }
    }
    if let Some(obj) = v.as_object() {
        if let Some(Value::Array(req)) = s.get("required") {
            for r in req.iter().filter_map(Value::as_str) {
                if !obj.contains_key(r) {
                    errs.push(format!("{path}: `{r}` is required"));
                }
            }
        }
        if let Some(Value::Array(any)) = s.get("anyOf") {
            let ok = any.iter().any(|alt| {
                let mut e = Vec::new();
                validate(v, alt, defs, path, &mut e);
                e.is_empty()
            });
            if !ok {
                errs.push(format!("{path}: none of anyOf {any:?}"));
            }
        }
        let passes = |alt: &Value| {
            let mut e = Vec::new();
            validate(v, alt, defs, path, &mut e);
            e.is_empty()
        };
        if let Some(Value::Array(one)) = s.get("oneOf") {
            let n = one.iter().filter(|alt| passes(alt)).count();
            if n != 1 {
                errs.push(format!("{path}: {n} of oneOf {one:?}"));
            }
        }
        if let Some(not) = s.get("not") {
            if passes(not) {
                errs.push(format!("{path}: matches not {not}"));
            }
        }
        let props = s.get("properties").and_then(Value::as_object);
        for (k, x) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(ps) => validate(x, ps, defs, &format!("{path}.{k}"), errs),
                None if s.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    errs.push(format!("{path}: `{k}` is not an attribute here"))
                }
                None => {}
            }
        }
    }
    if let (Some(arr), Some(items)) = (v.as_array(), s.get("items")) {
        for (i, x) in arr.iter().enumerate() {
            validate(x, items, defs, &format!("{path}[{i}]"), errs);
        }
    }
}

/// Every check of one record: the schema and the rules around it.
pub fn check_record(rec: &Value) -> Vec<String> {
    let sc = schema();
    let mut errs = Vec::new();
    let class_uid = rec["class_uid"].as_u64().expect("class_uid");
    let Some((name, class)) = sc["classes"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, c)| c["uid"].as_u64() == Some(class_uid))
    else {
        return vec![format!("class {class_uid} is not one the schema pins")];
    };
    validate(rec, &class["schema"], &sc["$defs"], name, &mut errs);
    let caption = |table: &Value, id: &Value| -> Option<String> {
        table
            .get(id.as_u64()?.to_string())
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let activity = rec["activity_id"].as_u64().unwrap_or(999);
    if rec["type_uid"].as_u64() != Some(class_uid * 100 + activity) {
        errs.push(format!(
            "type_uid {} for class {class_uid}, activity {activity}",
            rec["type_uid"]
        ));
    }
    let want = |what: &str, got: &Value, want: Option<String>| {
        if got.as_str().map(str::to_string) != want {
            Some(format!("{what} {got}, the schema's caption is {want:?}"))
        } else {
            None
        }
    };
    let enums = &class["enums"];
    errs.extend(want(
        "class_name",
        &rec["class_name"],
        class["caption"].as_str().map(str::to_string),
    ));
    errs.extend(want(
        "category_name",
        &rec["category_name"],
        caption(&sc["categories"], &rec["category_uid"]),
    ));
    errs.extend(want(
        "activity_name",
        &rec["activity_name"],
        caption(&enums["activity_id"], &rec["activity_id"]),
    ));
    errs.extend(want(
        "type_name",
        &rec["type_name"],
        Some(format!(
            "{}: {}",
            class["caption"].as_str().unwrap(),
            caption(&enums["activity_id"], &rec["activity_id"]).unwrap_or_default()
        )),
    ));
    errs.extend(want(
        "severity",
        &rec["severity"],
        caption(&enums["severity_id"], &rec["severity_id"]),
    ));
    if rec.get("status_id").is_some() {
        errs.extend(want(
            "status",
            &rec["status"],
            caption(&enums["status_id"], &rec["status_id"]),
        ));
    }
    if rec["metadata"]["version"] != OCSF_VERSION {
        errs.push(format!("metadata.version {}", rec["metadata"]["version"]));
    }
    if sc["ocsf_version"] != OCSF_VERSION {
        errs.push("the pinned schema is another version".into());
    }
    // the objects' enumerations this mapping writes, by their captions
    let oe = &sc["object_enums"];
    let mut objects: Vec<(&str, &Value)> = vec![("device.type_id", &rec["device"])];
    let mut files = vec![&rec["file"]];
    for e in rec["evidences"].as_array().into_iter().flatten() {
        files.push(&e["file"]);
        files.push(&e["process"]["file"]);
    }
    files.push(&rec["actor"]["process"]["file"]);
    files.push(&rec["process"]["file"]);
    for f in files {
        objects.push(("file.type_id", f));
    }
    for (table, obj) in objects {
        if obj.is_null() {
            continue;
        }
        let (_, key) = table.split_once('.').unwrap();
        let name = key.trim_end_matches("_id");
        errs.extend(want(table, &obj[name], caption(&oe[table], &obj[key])));
    }
    if let Some(a) = rec["finding_info"].get("analytic") {
        errs.extend(want(
            "analytic.type",
            &a["type"],
            caption(&oe["analytic.type_id"], &a["type_id"]),
        ));
    }
    for h in rec["file"]["hashes"].as_array().into_iter().flatten() {
        errs.extend(want(
            "fingerprint.algorithm",
            &h["algorithm"],
            caption(&oe["fingerprint.algorithm_id"], &h["algorithm_id"]),
        ));
    }
    let ci = &rec["connection_info"];
    if !ci.is_null() {
        errs.extend(want(
            "connection_info.direction",
            &ci["direction"],
            caption(
                &oe["network_connection_info.direction_id"],
                &ci["direction_id"],
            ),
        ));
        if ci.get("protocol_ver_id").is_some() {
            errs.extend(want(
                "connection_info.protocol_ver",
                &ci["protocol_ver"],
                caption(
                    &oe["network_connection_info.protocol_ver_id"],
                    &ci["protocol_ver_id"],
                ),
            ));
        }
    }
    errs
}

/// Lot 364 (pre-alpha, the export to a real receiver): the records a
/// receiver wrote — the lab's rsyslog or OpenSSL listener, one message a
/// line after its syslog header, or the JSONL sink's files — checked
/// against the pinned schema, as the mapping's own records are above.
#[cfg(test)]
mod received {
    use super::*;

    /// The OCSF record of one received line: the JSON object after the
    /// syslog header (a JSONL line is the object itself); `None` for an
    /// empty line, which the file sink writes at a start (EXPORT.md §8).
    pub(super) fn record_of(line: &str) -> Option<Result<Value, String>> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let Some(i) = line.find('{') else {
            return Some(Err("no JSON object on the line".into()));
        };
        Some(serde_json::from_str(&line[i..]).map_err(|e| format!("not one JSON object ({e})")))
    }

    /// The problems of one received record (a record with no class is one).
    pub(super) fn problems_of(rec: &Value) -> Vec<String> {
        if rec["class_uid"].as_u64().is_none() {
            return vec!["no class_uid".into()];
        }
        check_record(rec)
    }

    #[test]
    fn a_received_line_gives_its_record() {
        let rec = r#"{"class_uid":2004,"activity_id":1}"#;
        let syslog =
            format!("<107>1 2026-11-16T10:00:00.000Z host northnarrow - DETECTION - {rec}");
        for line in [rec.to_string(), syslog, format!("  {rec}\n")] {
            let v = record_of(&line).expect("a record").expect("JSON");
            assert_eq!(v["class_uid"], 2004);
        }
        assert!(record_of("").is_none());
        assert!(record_of("   \n").is_none());
        assert!(record_of("<107>1 cut before the record").unwrap().is_err());
        assert!(record_of("<107>1 - - - {\"class_uid\":20")
            .unwrap()
            .is_err());
        assert_eq!(problems_of(&serde_json::json!({})), ["no class_uid"]);
        assert!(problems_of(&serde_json::json!({"class_uid": 1}))
            .iter()
            .any(|p| p.contains("not one the schema pins")));
    }

    /// `NN_OCSF_RECEIVED=<file>[:<file>…]`: every record of each file
    /// passes the pinned schema and its rules; a no-op without it.
    #[test]
    #[ignore = "lab: NN_OCSF_RECEIVED names the files a receiver wrote"]
    fn received_records_match_the_pinned_schema() {
        let Ok(files) = std::env::var("NN_OCSF_RECEIVED") else {
            return;
        };
        let mut problems = Vec::new();
        for f in files.split(':').filter(|f| !f.is_empty()) {
            let text = std::fs::read_to_string(f).expect("a received file");
            let mut by_class = std::collections::BTreeMap::<u64, usize>::new();
            let mut records = 0;
            for (n, line) in text.lines().enumerate() {
                let Some(rec) = record_of(line) else { continue };
                records += 1;
                match rec {
                    Ok(v) => {
                        *by_class
                            .entry(v["class_uid"].as_u64().unwrap_or(0))
                            .or_default() += 1;
                        for p in problems_of(&v) {
                            problems.push(format!("{f}:{}: {p}", n + 1));
                        }
                    }
                    Err(e) => problems.push(format!("{f}:{}: {e}", n + 1)),
                }
            }
            println!("{f}: {records} records, by class {by_class:?}");
            assert!(records > 0, "{f}: no record");
        }
        assert!(
            problems.is_empty(),
            "{} problems, the first:\n  {}",
            problems.len(),
            problems
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }
}
