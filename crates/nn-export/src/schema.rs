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
