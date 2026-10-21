//! The performance baseline (lab PR 228, `docs/PERFORMANCE.md` §2): the gate
//! `cargo xtask perf-compare` on made-up result files — a regression, an
//! improvement, a change inside the noise, the per-metric threshold and
//! floor, a missing metric, runs from different hosts, another schema —
//! the contract between the guest's writer (`deploy/lab/perf/perf_lib.py
//! assemble`) and the gate, the writer's self-test, the scripts' syntax,
//! and the committed baseline: its A/A partner passes the gate with the
//! committed thresholds, which sit above that pair's spread with a margin
//! (`docs/validation/PERF_BASELINE.md`). Offline: committed files, `bash`,
//! `python3 -I` and the xtask binary only; nothing privileged, nothing
//! written outside the target directory, no guest.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

const PERF_RUN: &str = "deploy/lab/perf/perf-run.sh";
const PERF_LIB: &str = "deploy/lab/perf/perf_lib.py";
const PROBE: &str = "deploy/lab/perf/nn-perf-probe.c";
const NN_BENCH: &str = "deploy/lab/overhead/nn-bench.c";
const NN_LAB: &str = "deploy/lab/nn-lab.sh";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

fn case_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("perf-baseline")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn have(tool: &str) -> bool {
    Command::new("bash")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A result file as perf_lib.py writes it, with only what the gate reads.
fn run_doc(metrics: Value) -> Value {
    json!({
        "schema": "northnarrow-perf/1",
        "created_utc": "2026-10-21T00:00:00Z",
        "status": "complete",
        "tree": {"commit": "0123456789abcdef0123456789abcdef01234567"},
        "host": {"kernel": "6.8.0-45-generic", "cpu_model": "Lab CPU", "vcpus": 4,
                 "mem_total_kib": 8_000_000, "virt": "kvm", "clocksource": "tsc"},
        "method": {"reps": 5, "warmup": 1, "scale": 1.0, "quick": false},
        "metrics": metrics,
    })
}

fn metric(samples: &[f64]) -> Value {
    json!({"unit": "ns/op", "better": "lower", "kind": "ratio", "gate": true,
           "group": "micro", "order": 0, "samples": samples})
}

fn scaled(xs: &[f64], f: f64) -> Vec<f64> {
    xs.iter().map(|x| x * f).collect()
}

const TIGHT: [f64; 5] = [100.0, 101.0, 99.0, 100.0, 102.0];

fn write(dir: &Path, name: &str, v: &Value) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, serde_json::to_string_pretty(v).unwrap()).unwrap();
    p
}

/// The gate on made-up files, with the defaults only: no thresholds file
/// (the committed one is for the committed baseline's metrics, tested
/// below).
fn compare(base: &Path, new: &Path, extra: &[&str]) -> Output {
    compare_with(base, new, &[&["--no-thresholds"][..], extra].concat())
}

fn compare_with(base: &Path, new: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("perf-compare")
        .arg(base)
        .arg(new)
        .args(extra)
        .output()
        .expect("xtask runs")
}

fn pair(name: &str, base: Value, new: Value) -> (PathBuf, PathBuf) {
    let dir = case_dir(name);
    (
        write(&dir, "base.json", &run_doc(base)),
        write(&dir, "new.json", &run_doc(new)),
    )
}

/// The line of `name` in the table.
fn row<'a>(out: &'a str, name: &str) -> &'a str {
    out.lines()
        .find(|l| l.split_whitespace().next() == Some(name))
        .unwrap_or_else(|| panic!("no row for {name}:\n{out}"))
}

// ── the gate ─────────────────────────────────────────────────────────────

/// 15 % worse on a series that moves ±1 %: beyond the 10 % default and the
/// noise, exit 1; the same file against itself passes.
#[test]
fn a_change_beyond_threshold_and_noise_fails_the_gate() {
    let (b, n) = pair(
        "regression",
        json!({"open_watched_ns": metric(&TIGHT), "exec_true_ns": metric(&TIGHT)}),
        json!({"open_watched_ns": metric(&scaled(&TIGHT, 1.15)), "exec_true_ns": metric(&TIGHT)}),
    );
    let out = compare(&b, &n, &[]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(row(&t, "open_watched_ns").ends_with("REGRESSION"), "{t}");
    assert!(row(&t, "exec_true_ns").ends_with("ok"), "{t}");
    assert!(t.contains("result: 1 regression(s) (open_watched_ns)") && t.contains("FAIL"));
    let same = compare(&b, &b, &[]);
    assert_eq!(same.status.code(), Some(0), "{}", text(&same));
}

#[test]
fn an_improvement_passes_and_is_reported() {
    let (b, n) = pair(
        "improvement",
        json!({"udp_send_ns": metric(&TIGHT)}),
        json!({"udp_send_ns": metric(&scaled(&TIGHT, 0.8))}),
    );
    let out = compare(&b, &n, &[]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(row(&t, "udp_send_ns").ends_with("improved"), "{t}");
    assert!(t.contains("1 improved — PASS"), "{t}");
}

/// A 12 % move of the median on a series spread ±17 %: beyond the
/// threshold, not beyond the noise — not a regression.
#[test]
fn a_change_inside_the_noise_passes() {
    let noisy = [80.0, 100.0, 120.0, 100.0, 90.0, 110.0, 100.0];
    let moved: Vec<f64> = noisy.iter().map(|x| x + 12.0).collect();
    let (b, n) = pair(
        "noise",
        json!({"tcp_connect_close_ns": metric(&noisy)}),
        json!({"tcp_connect_close_ns": metric(&moved)}),
    );
    let out = compare(&b, &n, &[]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(
        row(&t, "tcp_connect_close_ns").ends_with("within noise"),
        "{t}"
    );
    // the same move on a quiet series fails
    let (b, n) = pair(
        "noise-quiet",
        json!({"tcp_connect_close_ns": metric(&TIGHT)}),
        json!({"tcp_connect_close_ns": metric(&scaled(&TIGHT, 1.12))}),
    );
    assert_eq!(compare(&b, &n, &[]).status.code(), Some(1));
}

/// Thresholds per metric and globally; a misspelt metric is an error.
#[test]
fn thresholds_are_configurable_per_metric() {
    let (b, n) = pair(
        "per-metric",
        json!({"exec_true_ns": metric(&TIGHT), "udp_send_ns": metric(&TIGHT)}),
        json!({"exec_true_ns": metric(&scaled(&TIGHT, 1.15)),
               "udp_send_ns": metric(&scaled(&TIGHT, 1.15))}),
    );
    let out = compare(&b, &n, &["--metric-threshold", "exec_true_ns=20"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(
        row(&t, "exec_true_ns").ends_with("ok") && row(&t, "udp_send_ns").ends_with("REGRESSION")
    );
    assert_eq!(
        compare(&b, &n, &["--threshold", "20"]).status.code(),
        Some(0)
    );
    let bad = compare(&b, &n, &["--metric-threshold", "exec_ture_ns=20"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(text(&bad).contains("no such metric"), "{}", text(&bad));
    let bad = compare(&b, &n, &["--metric-threshold", "exec_true_ns=-5"]);
    assert_eq!(bad.status.code(), Some(2));
}

/// A loss counter has one total per run: from 0 any loss fails, unless it
/// is below the counter's floor.
#[test]
fn a_loss_counter_fails_from_zero_unless_below_its_floor() {
    let counter = |v: f64| {
        json!({"unit": "events", "better": "lower", "kind": "count", "gate": true,
               "group": "loss", "order": 1, "samples": [v]})
    };
    let (b, n) = pair(
        "counter",
        json!({"burst_ring_drops": counter(0.0)}),
        json!({"burst_ring_drops": counter(3.0)}),
    );
    let out = compare(&b, &n, &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(row(&text(&out), "burst_ring_drops").contains("+inf"));
    assert_eq!(
        compare(&b, &n, &["--abs-floor", "burst_ring_drops=5"])
            .status
            .code(),
        Some(0)
    );
}

/// The default floors are in the metric's unit: 0.3 percentage points of
/// idle CPU is +30 % of 1 %, and below the 0.5 floor.
#[test]
fn default_floors_keep_resolution_out_of_the_gate() {
    let cpu = |xs: &[f64]| {
        json!({"unit": "% of one CPU", "better": "lower", "kind": "ratio", "gate": true,
               "group": "resources", "order": 2, "samples": xs})
    };
    let (b, n) = pair(
        "floor",
        json!({"agent_cpu_idle_pct": cpu(&[1.0, 1.0, 1.0, 1.0])}),
        json!({"agent_cpu_idle_pct": cpu(&[1.3, 1.3, 1.3, 1.3])}),
    );
    let out = compare(&b, &n, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        compare(&b, &n, &["--abs-floor", "agent_cpu_idle_pct=0.1"])
            .status
            .code(),
        Some(1)
    );
}

/// A gated metric the baseline has and the new run lacks fails; one only
/// the new run has is not gated yet; a metric that is not gated never
/// fails, and an agent-off reference that moves is a warning.
#[test]
fn missing_new_and_reference_metrics() {
    let mut reference = metric(&TIGHT);
    reference["gate"] = json!(false);
    reference["group"] = json!("reference");
    let mut moved = metric(&scaled(&TIGHT, 1.3));
    moved["gate"] = json!(false);
    moved["group"] = json!("reference");
    let (b, n) = pair(
        "missing",
        json!({"boot_to_ready_ms": metric(&TIGHT), "exec_true_ns_off": reference}),
        json!({"dns_send_ns": metric(&TIGHT), "exec_true_ns_off": moved}),
    );
    let out = compare(&b, &n, &[]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(row(&t, "boot_to_ready_ms").ends_with("MISSING"), "{t}");
    assert!(row(&t, "exec_true_ns_off").ends_with("worse"), "{t}");
    assert!(
        t.contains("the agent-off reference moved (exec_true_ns_off)"),
        "{t}"
    );
    assert!(t.contains("dns_send_ns: new in this run"), "{t}");
}

/// Higher-is-better metrics regress downwards.
#[test]
fn a_higher_is_better_metric_regresses_when_it_drops() {
    let mut m = metric(&TIGHT);
    m["better"] = json!("higher");
    let mut d = metric(&scaled(&TIGHT, 0.8));
    d["better"] = json!("higher");
    let (b, n) = pair("higher", json!({"throughput": m}), json!({"throughput": d}));
    assert_eq!(compare(&b, &n, &[]).status.code(), Some(1));
}

/// Runs from different hosts are not compared, unless asked.
#[test]
fn runs_from_different_hosts_are_refused() {
    let dir = case_dir("host");
    let m = json!({"exec_true_ns": metric(&TIGHT)});
    let b = write(&dir, "base.json", &run_doc(m.clone()));
    let mut other = run_doc(m);
    other["host"]["kernel"] = json!("6.8.0-47-generic");
    let n = write(&dir, "new.json", &other);
    let out = compare(&b, &n, &[]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(
        t.contains("kernel: 6.8.0-45-generic → 6.8.0-47-generic") && t.contains("not comparable"),
        "{t}"
    );
    assert_eq!(
        compare(&b, &n, &["--allow-host-mismatch"]).status.code(),
        Some(0)
    );
}

#[test]
fn unreadable_input_is_an_error_not_a_verdict() {
    let dir = case_dir("bad-input");
    let good = write(&dir, "good.json", &run_doc(json!({})));
    let mut other = run_doc(json!({}));
    other["schema"] = json!("northnarrow-perf/0");
    let schema = write(&dir, "schema.json", &other);
    let garbage = dir.join("garbage.json");
    fs::write(&garbage, "{not json").unwrap();
    let nan = write(
        &dir,
        "nan.json",
        &run_doc(json!({"m": {"samples": ["NaN"], "better": "lower"}})),
    );
    for bad in [&schema, &garbage, &nan, &dir.join("absent.json")] {
        let out = compare(&good, bad, &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}: {}",
            bad.display(),
            text(&out)
        );
    }
}

// ── the writer and the gate agree ────────────────────────────────────────

fn perf_lib(args: &[&str]) -> Output {
    Command::new("python3")
        .arg("-I")
        .arg(repo_root().join(PERF_LIB))
        .args(args)
        .output()
        .expect("python3 runs (the lab helpers need it)")
}

#[test]
fn perf_lib_self_test_passes() {
    let out = perf_lib(&["--selftest"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains(", 0 failed"), "{}", text(&out));
}

/// What `assemble` writes is what the gate reads: a made-up run assembled
/// by perf_lib.py passes against itself, and fails once one gated metric's
/// samples are 25 % worse.
#[test]
fn the_assembled_result_is_what_the_gate_reads() {
    let dir = case_dir("contract");
    let (raw, env) = (dir.join("raw.jsonl"), dir.join("env.json"));
    let (json_out, md) = (dir.join("perf.json"), dir.join("perf.md"));
    let out = perf_lib(&["synthetic", raw.to_str().unwrap(), env.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let out = perf_lib(&[
        "assemble",
        "--raw",
        raw.to_str().unwrap(),
        "--env",
        env.to_str().unwrap(),
        "--json",
        json_out.to_str().unwrap(),
        "--md",
        md.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let doc: Value = serde_json::from_str(&fs::read_to_string(&json_out).unwrap()).unwrap();
    for name in [
        "syscall_getppid_ns",
        "syscall_read_devzero_ns",
        "open_watched_ns",
        "open_unwatched_ns",
        "write_open_ns",
        "exec_true_ns",
        "tcp_connect_close_ns",
        "udp_send_ns",
        "dns_resolver_query_ns",
        "event_to_record_ms",
        "burst_ring_drops",
        "agent_cpu_idle_pct",
        "agent_rss_load_kib",
        "boot_to_ready_ms",
    ] {
        let m = &doc["metrics"][name];
        assert_eq!(m["gate"], json!(true), "{name} is gated");
        assert!(
            !m["samples"].as_array().unwrap().is_empty(),
            "{name} has raw samples"
        );
    }
    assert_eq!(doc["metrics"]["exec_true_ns_off"]["gate"], json!(false));
    let mdtext = fs::read_to_string(&md).unwrap();
    assert!(
        mdtext.contains("## Hooked operations (agent off → on)"),
        "{mdtext}"
    );

    let same = compare(&json_out, &json_out, &[]);
    assert_eq!(same.status.code(), Some(0), "{}", text(&same));
    let mut worse = doc.clone();
    let s: Vec<f64> = worse["metrics"]["exec_true_ns"]["samples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_f64().unwrap() * 1.25)
        .collect();
    worse["metrics"]["exec_true_ns"]["samples"] = json!(s);
    let worse_path = write(&dir, "worse.json", &worse);
    let out = compare(&json_out, &worse_path, &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(row(&text(&out), "exec_true_ns").ends_with("REGRESSION"));
}

// ── the scripts ──────────────────────────────────────────────────────────

#[test]
fn the_perf_scripts_parse() {
    for rel in [PERF_RUN, NN_LAB, "deploy/lab/soak/generate.sh"] {
        let out = Command::new("bash")
            .arg("-n")
            .arg(repo_root().join(rel))
            .output()
            .unwrap();
        assert!(out.status.success(), "bash -n {rel}: {}", text(&out));
    }
}

/// perf-run.sh refuses bad arguments before it checks or touches anything,
/// and refuses to run as anyone but root.
#[test]
fn perf_run_refuses_before_touching_anything() {
    let script = repo_root().join(PERF_RUN);
    for (args, want) in [
        (&["--reps", "1"][..], "--reps below 3"),
        (&["--reps", "x"][..], "takes a whole number"),
        (&["--scale", "fast"][..], "--scale takes a number"),
        (&["--nope"][..], "unknown argument"),
    ] {
        let out = Command::new("bash")
            .arg(&script)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        assert!(text(&out).contains(want), "{args:?}: {}", text(&out));
    }
    let euid = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&euid.stdout).trim() == "0" {
        eprintln!("SKIP the not-root case: the tests run as root");
        return;
    }
    let out = Command::new("bash").arg(&script).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("run as root"), "{}", text(&out));
}

/// `nn-lab.sh perf` is dispatched and documented, ships what perf-run.sh
/// needs, and fetches the JSON into the reports directory.
#[test]
fn nn_lab_perf_ships_runs_and_fetches() {
    let text = fs::read_to_string(repo_root().join(NN_LAB)).unwrap();
    assert!(text.contains("\n    perf)          shift; cmd_perf \"$@\" ;;\n"));
    assert!(text.contains("#   deploy/lab/nn-lab.sh perf [--fresh]"));
    let start = text.find("\ncmd_perf() {").expect("cmd_perf");
    let body = &text[start..start + text[start..].find("\n}\n").unwrap()];
    for needle in [
        "deploy/lab/perf/perf-run.sh",
        "deploy/lab/perf/perf_lib.py",
        "deploy/lab/perf/nn-perf-probe.c",
        "deploy/lab/overhead/nn-bench.c",
        "deploy/lab/soak/generate.sh",
        "deploy/lab/lib/lab-records.py",
        "$LAB_DIR/reports/perf-$stamp.json",
        "NN_PERF_TREE_COMMIT",
    ] {
        assert!(body.contains(needle), "cmd_perf lacks {needle}");
    }
}

/// The probes and the benchmark compile cleanly (getppid and rdzero, lab
/// PR 219, are in the benchmark).
#[test]
fn the_probes_compile() {
    let bench = fs::read_to_string(repo_root().join(NN_BENCH)).unwrap();
    assert!(bench.contains("\"getppid\"") && bench.contains("\"rdzero\""));
    if !have("cc") {
        eprintln!("SKIP the compile check: no cc on this host");
        return;
    }
    for rel in [PROBE, NN_BENCH] {
        let out = Command::new("cc")
            .args(["-fsyntax-only", "-Wall", "-Wextra", "-Werror"])
            .arg(repo_root().join(rel))
            .output()
            .unwrap();
        assert!(out.status.success(), "cc {rel}: {}", text(&out));
    }
}

// ── the committed baseline ───────────────────────────────────────────────

const RESULTS: &str = "docs/validation/results";
const THRESHOLDS: &str = "deploy/lab/perf/thresholds.tsv";

fn quantile(xs: &[f64], p: f64) -> f64 {
    let mut s = xs.to_vec();
    s.sort_by(f64::total_cmp);
    let h = (s.len() - 1) as f64 * p;
    let (lo, hi) = (h.floor() as usize, h.ceil() as usize);
    s[lo] + (h - lo as f64) * (s[hi] - s[lo])
}

/// metric → (threshold %, floor), from the committed file.
fn committed_thresholds() -> std::collections::BTreeMap<String, (f64, f64)> {
    let text = fs::read_to_string(repo_root().join(THRESHOLDS)).unwrap();
    let mut out = std::collections::BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 4, "{THRESHOLDS}: {line:?}");
        assert!(
            !f[3].trim().is_empty(),
            "{THRESHOLDS}: {} has no reason",
            f[0]
        );
        out.insert(
            f[0].to_string(),
            (f[1].parse().unwrap(), f[2].parse().unwrap()),
        );
    }
    out
}

/// The committed baselines (`perf-….json`), each with its A/A partners
/// (`perf-…-aa.json`, `perf-…-aa2.json`, …): one pair per partner.
fn committed_baselines() -> Vec<(PathBuf, PathBuf)> {
    let dir = repo_root().join(RESULTS);
    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().to_string())
        .filter(|n| n.starts_with("perf-") && n.ends_with(".json"))
        .collect();
    let is_partner = |n: &str| {
        n.rsplit_once("-aa").is_some_and(|(_, rest)| {
            rest.trim_end_matches(".json")
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
    };
    let mut out = Vec::new();
    for base in names.iter().filter(|n| !is_partner(n)) {
        let stem = base.trim_end_matches(".json");
        let partners: Vec<&String> = names
            .iter()
            .filter(|n| is_partner(n) && n.starts_with(&format!("{stem}-aa")))
            .collect();
        assert!(
            !partners.is_empty(),
            "{base}: no A/A partner ({stem}-aa.json)"
        );
        for p in partners {
            out.push((dir.join(base), dir.join(p)));
        }
    }
    for p in names.iter().filter(|n| is_partner(n)) {
        assert!(
            out.iter().any(|(_, aa)| aa.ends_with(p)),
            "{p}: an A/A partner without its baseline"
        );
    }
    out.sort();
    out
}

/// Lab PR 228: the committed baseline is a complete, full run (not
/// `--quick`) of an agent whose build inputs are its branch point's, with
/// its summary beside it; it and its A/A partner pass the gate with the
/// committed thresholds; every gated metric of the baseline has a reasoned
/// line there; and each threshold sits above that pair's spread with a
/// margin — at least twice the move of the medians and five points above
/// it — unless the move is within the metric's floor.
#[test]
fn the_committed_baseline_passes_its_aa_check_with_margin() {
    let pairs = committed_baselines();
    assert!(!pairs.is_empty(), "no committed baseline in {RESULTS}");
    let thresholds = committed_thresholds();
    for (base, aa) in &pairs {
        let b: Value = serde_json::from_str(&fs::read_to_string(base).unwrap()).unwrap();
        let a: Value = serde_json::from_str(&fs::read_to_string(aa).unwrap()).unwrap();
        for (doc, path) in [(&b, base), (&a, aa)] {
            assert_eq!(doc["status"], "complete", "{}", path.display());
            assert_eq!(doc["method"]["quick"], false, "{}", path.display());
            assert_eq!(
                doc["tree"]["build_inputs_changed"],
                "none",
                "{}: the agent measured is its branch point's",
                path.display()
            );
            for k in ["kernel", "cpu_model", "vcpus", "mem_total_kib"] {
                assert!(!doc["host"][k].is_null(), "{}: host.{k}", path.display());
            }
        }
        assert!(
            base.with_extension("md").exists(),
            "{}: no .md",
            base.display()
        );
        assert_eq!(
            b["agent"]["files"]["binaries"]["agent"]["sha256"],
            a["agent"]["files"]["binaries"]["agent"]["sha256"],
            "the A/A pair measured the same agent binary"
        );
        let out = compare_with(base, aa, &[]);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(0), "the A/A check fails:\n{t}");
        assert!(t.contains("thresholds: ") && t.contains(THRESHOLDS), "{t}");
        for (name, m) in b["metrics"].as_object().unwrap() {
            if m["gate"] != json!(true) {
                continue;
            }
            let (pct, floor) = *thresholds
                .get(name)
                .unwrap_or_else(|| panic!("{THRESHOLDS}: no line for the gated {name}"));
            let xs: Vec<f64> = m["samples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap())
                .collect();
            let ys: Vec<f64> = a["metrics"][name]["samples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap())
                .collect();
            let (mb, ma) = (quantile(&xs, 0.5), quantile(&ys, 0.5));
            if (ma - mb).abs() <= floor || mb == 0.0 {
                continue;
            }
            let moved = 100.0 * (ma - mb).abs() / mb.abs();
            assert!(
                pct >= 2.0 * moved && pct >= moved + 5.0,
                "{name}: threshold {pct} % is not above the A/A move {moved:.1} % with margin"
            );
        }
    }
}

/// The committed thresholds name only metrics a baseline has.
#[test]
fn the_committed_thresholds_name_baseline_metrics() {
    let pairs = committed_baselines();
    let thresholds = committed_thresholds();
    for name in thresholds.keys() {
        assert!(
            pairs.iter().any(|(b, _)| {
                let v: Value = serde_json::from_str(&fs::read_to_string(b).unwrap()).unwrap();
                v["metrics"][name]["gate"] == json!(true)
            }),
            "{THRESHOLDS}: {name} is no gated metric of a committed baseline"
        );
    }
}
