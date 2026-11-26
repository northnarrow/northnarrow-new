//! Lot M3 (OpenSSF Scorecard, Vulnerabilities): the tests' YAML reader
//! (`support/yaml.rs`, serde-saphyr in safe Rust) reads the committed YAML
//! as serde_yaml_ng did before it. Each point where a YAML reader may read
//! otherwise, and that a test of the workflows would then read wrong, is
//! pinned here: the trigger key `on`, YAML 1.1's booleans, numbers spelled
//! with a leading zero or an underscore, key order, a key given twice, a
//! merge key, and the YAML written back (a job's text, for `contains`).
//!
//! Lot M3's parity run read every input of the xtask tests with both
//! readers (164 parses, the same trees; 19 nodes written back, the same
//! but the quotes of 2: `'it''s'` before, `"it's"` now).

mod support;

use support::yaml::{self, Number, Value};

fn parse(text: &str) -> Value {
    yaml::from_str(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

/// `on:` is a workflow's triggers; a YAML 1.1 reader reads `on` as
/// `true`, and a test that looks up "on" then finds nothing.
#[test]
fn only_true_and_false_are_booleans() {
    let v = parse("on:\n  push: {}\n");
    let keys: Vec<&Value> = v.as_mapping().unwrap().keys().collect();
    assert_eq!(keys, [&Value::String("on".into())]);
    assert!(v.get("on").is_some_and(Value::is_mapping));
    for word in ["yes", "no", "on", "off", "y", "n", "Yes", "NO", "On", "OFF"] {
        assert_eq!(parse(&format!("k: {word}\n"))["k"], Value::String(word.into()), "{word}");
    }
    for (word, b) in [("true", true), ("True", true), ("TRUE", true), ("false", false)] {
        assert_eq!(parse(&format!("k: {word}\n"))["k"], Value::Bool(b), "{word}");
    }
}

#[test]
fn numbers_read_as_serde_yaml_ng_read_them() {
    let v = parse("a: 0755\nb: 1_000\nc: 8\nd: -3\ne: 3.10\nf: 1.0\ng: '8'\nh: 0x1f\n");
    assert_eq!(v["a"], Value::String("0755".into()));
    assert_eq!(v["b"], Value::String("1_000".into()));
    assert_eq!(v["c"], Value::Number(Number::PosInt(8)));
    assert_eq!(v["d"], Value::Number(Number::NegInt(-3)));
    assert_eq!(v["g"], Value::String("8".into()));
    assert_eq!(v["h"], Value::Number(Number::PosInt(31)));
    let shown: Vec<String> = ["c", "d", "e", "f"]
        .iter()
        .map(|k| match &v[*k] {
            Value::Number(n) => n.to_string(),
            other => panic!("{k}: {other:?}"),
        })
        .collect();
    assert_eq!(shown, ["8", "-3", "3.1", "1.0"]);
}

#[test]
fn a_mapping_keeps_its_order_and_refuses_a_key_given_twice() {
    let v = parse("z: 1\na: 2\nm: 3\n");
    let keys: Vec<&str> = v
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(keys, ["z", "a", "m"]);
    assert!(yaml::from_str("a: 1\nb: 2\na: 3\n").is_err());
    assert!(yaml::from_str("jobs:\n  x: {}\n  x: {}\n").is_err());
}

/// serde_yaml_ng kept `<<` as an ordinary key (a tree no runner reads):
/// the reader refuses it, and no committed file has one.
#[test]
fn a_merge_key_refuses_the_file() {
    let text = "base: &b\n  runs-on: x\njob:\n  <<: *b\n  name: y\n";
    assert!(yaml::from_str(text).is_err());
    // an alias alone is read as the node it names
    let v = parse("base: &b\n  runs-on: x\njob: *b\n");
    assert_eq!(v["job"]["runs-on"], Value::String("x".into()));
}

#[test]
fn a_missing_key_or_index_is_null_and_a_mapping_can_be_changed() {
    let mut v = parse("jobs:\n  a:\n    steps: [x]\n");
    assert!(v["nope"].is_null() && v["jobs"]["a"]["steps"][3].is_null());
    assert_eq!(v["jobs"]["a"]["steps"][0], Value::String("x".into()));
    let jobs = v.get_mut("jobs").and_then(Value::as_mapping_mut).unwrap();
    assert_eq!(jobs.insert("b".into(), Value::Null), None);
    assert_eq!(jobs.insert("a".into(), Value::Bool(true)), Some(parse("steps: [x]\n")));
    let keys: Vec<&str> = jobs.keys().map(|k| k.as_str().unwrap()).collect();
    assert_eq!(keys, ["a", "b"]);
}

/// A job's text, for the tests that look for a line in it: a script as a
/// literal block, its lines as they are; a long line not folded.
#[test]
fn a_node_written_back_keeps_each_line_whole() {
    let long = format!("if: {}\n", "needs.a.result == 'success' && ".repeat(6) + "true");
    let text = format!("{long}run: |\n  sign.sh \"$fpr\" dist/SUMS\n  echo 'done'\n");
    let v = parse(&text);
    let back = yaml::to_string(&v).unwrap();
    assert!(back.contains("sign.sh \"$fpr\" dist/SUMS\n"), "{back}");
    assert!(back.contains("echo 'done'"), "{back}");
    let cond = v["if"].as_str().unwrap();
    assert!(back.lines().any(|l| l.contains(cond)), "{back}");
    assert_eq!(parse(&back), v);
}

/// Every YAML file git tracks is read (a file the reader refused would
/// fail its own test, but one no test reads yet would not).
#[test]
fn every_committed_yaml_file_is_read() {
    let root = support::repo_root();
    let files: Vec<String> = support::tracked_files()
        .into_iter()
        .filter(|f| f.ends_with(".yml") || f.ends_with(".yaml"))
        .collect();
    assert!(files.len() >= 10, "{files:?}");
    for f in &files {
        let text = std::fs::read_to_string(root.join(f)).unwrap();
        let v = yaml::from_str(&text).unwrap_or_else(|e| panic!("{f}: {e}"));
        if f.starts_with(".github/workflows/") {
            assert!(v.get("on").is_some(), "{f}: no `on` key");
            assert!(v.get("jobs").is_some_and(Value::is_mapping), "{f}: no jobs");
        }
    }
}
