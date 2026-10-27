//! `cargo xtask perf-compare BASE.json NEW.json` — the regression gate of the
//! performance baseline (lab PR 228, `docs/PERFORMANCE.md` §2.4).
//!
//! The two files are what `deploy/lab/perf/perf-run.sh` writes
//! (`nn-lab.sh perf`): per metric its unit, which way is better, whether it
//! is gated, and every raw sample. The statistics are computed here from the
//! samples (the ones in the file are for reading), with the definitions of
//! `deploy/lab/perf/perf_lib.py`: quantiles by linear interpolation between
//! closest ranks, noise = (p95 − p5) / 2 over the median.
//!
//! A gated metric regresses when the new median is worse than the base
//! median by more than its threshold **and** by more than the noise of the
//! two runs (the larger of the two, at least `--noise-floor`, 1 %), **and**
//! by more than its absolute floor in its own unit. The thresholds and
//! floors are the committed file [`THRESHOLDS_FILE`] (`--thresholds FILE`
//! for another, `--no-thresholds` for none): one line per gated metric, set
//! above the spread of the baseline's A/A check with a margin
//! (`docs/validation/PERF_BASELINE.md`). A metric the file does not list
//! gets `--threshold` (10 %) and the built-in floor ([`DEFAULT_ABS_FLOORS`],
//! the measurement's resolution); `--metric-threshold NAME=PCT` and
//! `--abs-floor NAME=VALUE` override both.
//! A gated metric the base measured and the new run did not is missing.
//! Exit 0: no regression and nothing missing; 1: a regression or a missing
//! metric; 2: unreadable input, another schema, or runs from different hosts
//! (kernel, CPU model, vCPUs, memory, virtualisation, clocksource) without
//! `--allow-host-mismatch`. The host fields must be equal, but for MemTotal,
//! which moves by a few KiB between boots of one guest (lab PR 248): within
//! ±[`MEM_TOTAL_DRIFT_PCT`] % of the base's or ±[`MEM_TOTAL_DRIFT_MIN_KIB`]
//! KiB, whichever is larger, it is the same host, and the report notes the
//! drift.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

/// The schema `perf_lib.py` writes.
pub const SCHEMA: &str = "northnarrow-perf/1";
/// The committed thresholds, relative to the repository root.
pub const THRESHOLDS_FILE: &str = "deploy/lab/perf/thresholds.tsv";
/// Default threshold, percent worse.
pub const DEFAULT_THRESHOLD_PCT: f64 = 10.0;
/// Noise below this is not taken for the runs' noise.
pub const DEFAULT_NOISE_FLOOR_PCT: f64 = 1.0;
/// The smallest change, in the metric's own unit, that can count: below it
/// a relative change is the measurement's resolution, not the agent. CPU
/// comes from 10 ms ticks over 10 s windows, RSS moves with the allocator,
/// the disk latency is polled every 2 ms, a boot moves with the BPF load.
/// The loss counters have none: the design target is no loss (review 45).
pub const DEFAULT_ABS_FLOORS: &[(&str, f64)] = &[
    ("agent_cpu_idle_pct", 0.5),
    ("agent_cpu_load_pct", 2.0),
    ("agent_rss_idle_kib", 2048.0),
    ("agent_rss_load_kib", 4096.0),
    ("agent_rss_after_load_kib", 4096.0),
    ("event_to_record_ms", 1.0),
    ("event_to_disk_ms", 2.0),
    ("boot_to_ready_ms", 100.0),
];
/// MemTotal drifts between boots of the same guest (what the kernel
/// reserves at boot: 8,131,760 and 8,131,764 KiB on the lab's 8 GiB guest):
/// a new run's MemTotal within this share of the base's, percent, or within
/// [`MEM_TOTAL_DRIFT_MIN_KIB`] when that is more, is the same host's.
pub const MEM_TOTAL_DRIFT_PCT: f64 = 0.1;
/// The smallest MemTotal drift tolerated, KiB (1 MiB).
pub const MEM_TOTAL_DRIFT_MIN_KIB: f64 = 1024.0;
/// The host field that may drift by [`mem_total_tolerance_kib`].
const MEM_TOTAL_KEY: &str = "mem_total_kib";
/// The host fields two runs must share to be compared.
pub const HOST_KEYS: &[&str] = &[
    "kernel",
    "cpu_model",
    "vcpus",
    "mem_total_kib",
    "virt",
    "clocksource",
];
/// The method fields that should match; a difference is reported, not fatal.
pub const METHOD_KEYS: &[&str] = &[
    "reps",
    "warmup",
    "rounds",
    "scale",
    "quick",
    "pin_cpu",
    "idle_secs",
    "burst_secs",
    "burst_rates",
    "latency_samples",
    "boot_cycles",
    "resolver",
];

/// `cargo xtask perf-compare`.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// The baseline (perf-<stamp>.json of `nn-lab.sh perf`).
    pub base: PathBuf,
    /// The run to judge against it.
    pub new: PathBuf,
    /// Threshold of every gated metric, percent worse (median vs median).
    #[arg(long, default_value_t = DEFAULT_THRESHOLD_PCT)]
    pub threshold: f64,
    /// Threshold of one metric, `NAME=PCT` (repeatable).
    #[arg(long = "metric-threshold", value_name = "NAME=PCT")]
    pub metric_threshold: Vec<String>,
    /// Smallest change that can count for one metric, `NAME=VALUE` in its
    /// unit (repeatable; replaces the default floor).
    #[arg(long = "abs-floor", value_name = "NAME=VALUE")]
    pub abs_floor: Vec<String>,
    /// Smallest noise, percent, whatever the samples show.
    #[arg(long = "noise-floor", default_value_t = DEFAULT_NOISE_FLOOR_PCT)]
    pub noise_floor: f64,
    /// Compare runs taken on different hosts (kernel, CPU, vCPUs, memory
    /// beyond a boot's drift, virtualisation, clocksource) anyway.
    #[arg(long)]
    pub allow_host_mismatch: bool,
    /// The per-metric thresholds and floors (default: the committed
    /// `deploy/lab/perf/thresholds.tsv`).
    #[arg(long, value_name = "FILE", conflicts_with = "no_thresholds")]
    pub thresholds: Option<PathBuf>,
    /// Use no thresholds file: `--threshold` and the built-in floors only.
    #[arg(long)]
    pub no_thresholds: bool,
}

/// One line of a thresholds file.
#[derive(Debug, Clone, PartialEq)]
pub struct Threshold {
    pub threshold_pct: f64,
    pub abs_floor: f64,
    pub why: String,
}

/// Parse a thresholds file: `metric<TAB>threshold %<TAB>floor<TAB>why`, one
/// per line; `#` starts a comment line. A metric listed twice, a value that
/// is not a finite number ≥ 0 or a line without its reason is an error.
pub fn parse_thresholds(text: &str) -> Result<BTreeMap<String, Threshold>> {
    let mut out = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let [name, pct, floor, why] = f[..] else {
            bail!("line {n}: metric, threshold %, floor and reason, tab-separated: {line:?}");
        };
        let num = |v: &str, what: &str| -> Result<f64> {
            match v.trim().parse::<f64>() {
                Ok(x) if x.is_finite() && x >= 0.0 => Ok(x),
                _ => bail!("line {n}: {what} {v:?} is not a finite number ≥ 0"),
            }
        };
        let t = Threshold {
            threshold_pct: num(pct, "the threshold")?,
            abs_floor: num(floor, "the floor")?,
            why: why.trim().to_string(),
        };
        if name.trim().is_empty() || t.why.is_empty() {
            bail!("line {n}: a metric name and a reason: {line:?}");
        }
        if out.insert(name.trim().to_string(), t).is_some() {
            bail!("line {n}: {name} listed twice");
        }
    }
    Ok(out)
}

/// One metric of a run.
#[derive(Debug, Clone)]
pub struct Metric {
    pub unit: String,
    pub lower_is_better: bool,
    pub gate: bool,
    pub group: String,
    pub order: u64,
    pub samples: Vec<f64>,
}

/// One run (one perf JSON).
#[derive(Debug, Clone)]
pub struct Run {
    pub label: String,
    pub status: String,
    pub host: BTreeMap<String, Value>,
    pub method: BTreeMap<String, Value>,
    pub metrics: BTreeMap<String, Metric>,
}

/// What a metric is judged by.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    pub threshold_pct: f64,
    pub abs_floor: f64,
    pub noise_floor_pct: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Worse beyond the threshold, the noise and the floor.
    Regression,
    /// Better beyond the threshold, the noise and the floor.
    Improved,
    /// Beyond the threshold, but not beyond the runs' noise.
    WithinNoise,
    Ok,
    /// Measured in the base, not in the new run.
    Missing,
    /// Not measured in the base: nothing to compare with.
    Unmeasured,
}

impl Verdict {
    /// How the row reads: a metric that is not gated only moves.
    fn label(self, gated: bool) -> &'static str {
        match (self, gated) {
            (Verdict::Regression, true) => "REGRESSION",
            (Verdict::Regression, false) => "worse",
            (Verdict::Improved, true) => "improved",
            (Verdict::Improved, false) => "better",
            (Verdict::WithinNoise, _) => "within noise",
            (Verdict::Ok, _) => "ok",
            (Verdict::Missing, true) => "MISSING",
            (Verdict::Missing, false) => "absent",
            (Verdict::Unmeasured, _) => "not in base",
        }
    }
}

/// The judgement of one metric.
#[derive(Debug, Clone, Copy)]
pub struct Judgement {
    pub base_median: Option<f64>,
    pub new_median: Option<f64>,
    /// Positive = worse. Infinite when the base median is 0.
    pub worse_pct: Option<f64>,
    pub noise_pct: f64,
    pub limit_pct: f64,
    pub verdict: Verdict,
}

/// Quantile by linear interpolation between closest ranks (Hyndman–Fan
/// type 7), as `perf_lib.py` computes it.
pub fn quantile(xs: &[f64], p: f64) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let mut s = xs.to_vec();
    s.sort_by(f64::total_cmp);
    let h = (s.len() - 1) as f64 * p;
    let (lo, hi) = (h.floor() as usize, h.ceil() as usize);
    Some(s[lo] + (h - lo as f64) * (s[hi] - s[lo]))
}

/// (p95 − p5) / 2 over the median, percent; `None` below three samples or
/// for a zero median.
pub fn noise_pct(xs: &[f64]) -> Option<f64> {
    if xs.len() < 3 {
        return None;
    }
    let med = quantile(xs, 0.5)?;
    if med == 0.0 {
        return None;
    }
    Some(100.0 * (quantile(xs, 0.95)? - quantile(xs, 0.05)?) / (2.0 * med.abs()))
}

/// Judge one metric's samples.
pub fn judge(base: &[f64], new: &[f64], lower_is_better: bool, gate: &Gate) -> Judgement {
    let base_median = quantile(base, 0.5);
    let new_median = quantile(new, 0.5);
    let noise = noise_pct(base)
        .unwrap_or(0.0)
        .max(noise_pct(new).unwrap_or(0.0))
        .max(gate.noise_floor_pct);
    let limit = gate.threshold_pct.max(noise);
    let (Some(mb), Some(mn)) = (base_median, new_median) else {
        return Judgement {
            base_median,
            new_median,
            worse_pct: None,
            noise_pct: noise,
            limit_pct: limit,
            verdict: if base_median.is_none() {
                Verdict::Unmeasured
            } else {
                Verdict::Missing
            },
        };
    };
    let delta = mn - mb;
    let signed = if lower_is_better { delta } else { -delta };
    // `+ 0.0` turns a negated zero into zero
    let worse = signed + 0.0;
    let worse_pct = if mb != 0.0 {
        100.0 * worse / mb.abs()
    } else if worse > 0.0 {
        f64::INFINITY
    } else if worse < 0.0 {
        f64::NEG_INFINITY
    } else {
        0.0
    };
    let big = delta.abs() > gate.abs_floor;
    let verdict = if big && worse_pct > limit {
        Verdict::Regression
    } else if big && -worse_pct > limit {
        Verdict::Improved
    } else if big && worse_pct.abs() > gate.threshold_pct {
        Verdict::WithinNoise
    } else {
        Verdict::Ok
    };
    Judgement {
        base_median,
        new_median,
        worse_pct: Some(worse_pct),
        noise_pct: noise,
        limit_pct: limit,
        verdict,
    }
}

fn object(v: Option<&Value>) -> BTreeMap<String, Value> {
    match v {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => BTreeMap::new(),
    }
}

/// Parse one perf JSON.
pub fn parse_run(text: &str, label: &str) -> Result<Run> {
    let v: Value = serde_json::from_str(text).with_context(|| format!("{label}: not JSON"))?;
    match v.get("schema").and_then(Value::as_str) {
        Some(SCHEMA) => {}
        other => bail!("{label}: schema {other:?}, expected {SCHEMA:?}"),
    }
    let Some(Value::Object(ms)) = v.get("metrics") else {
        bail!("{label}: no `metrics` object");
    };
    let mut metrics = BTreeMap::new();
    for (name, m) in ms {
        let better = m.get("better").and_then(Value::as_str).unwrap_or("lower");
        let lower_is_better = match better {
            "lower" => true,
            "higher" => false,
            other => bail!("{label}: metric {name}: `better` is {other:?} (lower or higher)"),
        };
        let mut samples = Vec::new();
        for s in m
            .get("samples")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("{label}: metric {name}: no `samples` array"))?
        {
            match s.as_f64() {
                Some(x) if x.is_finite() => samples.push(x),
                _ => bail!("{label}: metric {name}: a sample is not a finite number: {s}"),
            }
        }
        metrics.insert(
            name.clone(),
            Metric {
                unit: m
                    .get("unit")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                lower_is_better,
                gate: m.get("gate").and_then(Value::as_bool).unwrap_or(true),
                group: m
                    .get("group")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                order: m.get("order").and_then(Value::as_u64).unwrap_or(u64::MAX),
                samples,
            },
        );
    }
    let tree = object(v.get("tree"));
    let commit = tree
        .get("commit")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let short = commit.get(..12).unwrap_or(commit);
    Ok(Run {
        label: format!(
            "{label} ({short}, {})",
            v.get("created_utc").and_then(Value::as_str).unwrap_or("?")
        ),
        status: v
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string(),
        host: object(v.get("host")),
        method: object(v.get("method")),
        metrics,
    })
}

/// The gate's settings, defaults and overrides resolved.
#[derive(Debug, Clone)]
pub struct Config {
    pub threshold_pct: f64,
    pub per_metric_threshold: BTreeMap<String, f64>,
    pub abs_floor: BTreeMap<String, f64>,
    pub noise_floor_pct: f64,
}

impl Config {
    pub fn new(threshold_pct: f64, noise_floor_pct: f64) -> Self {
        Config {
            threshold_pct,
            per_metric_threshold: BTreeMap::new(),
            abs_floor: DEFAULT_ABS_FLOORS
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            noise_floor_pct,
        }
    }

    fn gate(&self, name: &str) -> Gate {
        Gate {
            threshold_pct: *self
                .per_metric_threshold
                .get(name)
                .unwrap_or(&self.threshold_pct),
            abs_floor: *self.abs_floor.get(name).unwrap_or(&0.0),
            noise_floor_pct: self.noise_floor_pct,
        }
    }
}

fn name_value(s: &str, what: &str) -> Result<(String, f64)> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("{what} takes NAME=VALUE, got {s:?}"))?;
    let x: f64 = v
        .trim()
        .parse()
        .map_err(|_| anyhow!("{what} {s:?}: not a number"))?;
    if k.is_empty() || !x.is_finite() || x < 0.0 {
        bail!("{what} {s:?}: a metric name and a finite value ≥ 0");
    }
    Ok((k.to_string(), x))
}

/// One row of the comparison.
#[derive(Debug, Clone)]
pub struct Row {
    pub name: String,
    pub unit: String,
    pub gated: bool,
    pub group: String,
    pub order: u64,
    pub judgement: Judgement,
}

/// The comparison of two runs.
#[derive(Debug, Clone)]
pub struct Report {
    pub base: String,
    pub new: String,
    pub rows: Vec<Row>,
    pub host_mismatch: Vec<String>,
    pub notes: Vec<String>,
}

fn show(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "—".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The MemTotal drift, KiB, either way, that a run of the base's host may
/// show: [`MEM_TOTAL_DRIFT_PCT`] of the base's MemTotal, at least
/// [`MEM_TOTAL_DRIFT_MIN_KIB`].
pub fn mem_total_tolerance_kib(base_kib: f64) -> f64 {
    (base_kib.abs() * MEM_TOTAL_DRIFT_PCT / 100.0).max(MEM_TOTAL_DRIFT_MIN_KIB)
}

/// Whether one host field tells two hosts apart: `Err` with the mismatch
/// line, `Ok(Some(note))` for a MemTotal drift within the tolerance,
/// `Ok(None)` for equal values. MemTotal is compared as a number only when
/// both runs recorded one; otherwise, and for every other field, the values
/// must be equal.
fn host_field(key: &str, b: Option<&Value>, n: Option<&Value>) -> Result<Option<String>, String> {
    if b == n {
        return Ok(None);
    }
    if key == MEM_TOTAL_KEY {
        if let (Some(x), Some(y)) = (b.and_then(Value::as_f64), n.and_then(Value::as_f64)) {
            let tolerance = mem_total_tolerance_kib(x);
            if (y - x).abs() <= tolerance {
                return Ok(Some(format!(
                    "host: {key} {} → {} ({:+} KiB), within the drift between boots of one \
                     host (±{tolerance:.0} KiB: {MEM_TOTAL_DRIFT_PCT} % of the base or \
                     {MEM_TOTAL_DRIFT_MIN_KIB:.0} KiB, whichever is larger): the same host",
                    show(b),
                    show(n),
                    y - x
                )));
            }
        }
    }
    Err(format!("{key}: {} → {}", show(b), show(n)))
}

/// Compare `new` with `base`.
pub fn compare(base: &Run, new: &Run, cfg: &Config) -> Report {
    let mut host_mismatch = Vec::new();
    let mut notes = Vec::new();
    for k in HOST_KEYS {
        match host_field(k, base.host.get(*k), new.host.get(*k)) {
            Ok(None) => {}
            Ok(Some(note)) => notes.push(note),
            Err(line) => host_mismatch.push(line),
        }
    }
    for k in METHOD_KEYS {
        let (b, n) = (base.method.get(*k), new.method.get(*k));
        if b != n {
            notes.push(format!("method differs, {k}: {} → {}", show(b), show(n)));
        }
    }
    for (run, which) in [(base, "base"), (new, "new")] {
        if run.status != "complete" {
            notes.push(format!(
                "the {which} run is {} (not every gated metric was measured)",
                run.status
            ));
        }
        if run.method.get("quick") == Some(&Value::Bool(true)) {
            notes.push(format!(
                "the {which} run is a --quick smoke run, not a baseline"
            ));
        }
    }
    let mut rows = Vec::new();
    for (name, bm) in &base.metrics {
        let gate = cfg.gate(name);
        let empty = Vec::new();
        let ns = new.metrics.get(name).map_or(&empty, |m| &m.samples);
        rows.push(Row {
            name: name.clone(),
            unit: bm.unit.clone(),
            gated: bm.gate,
            group: bm.group.clone(),
            order: bm.order,
            judgement: judge(&bm.samples, ns, bm.lower_is_better, &gate),
        });
    }
    for (name, nm) in &new.metrics {
        if !base.metrics.contains_key(name) && nm.gate {
            notes.push(format!(
                "{name}: new in this run, not gated until a baseline has it"
            ));
        }
    }
    rows.sort_by(|a, b| (!a.gated, a.order, &a.name).cmp(&(!b.gated, b.order, &b.name)));
    Report {
        base: base.label.clone(),
        new: new.label.clone(),
        rows,
        host_mismatch,
        notes,
    }
}

impl Report {
    pub fn regressions(&self) -> Vec<&str> {
        self.rows
            .iter()
            .filter(|r| r.gated && r.judgement.verdict == Verdict::Regression)
            .map(|r| r.name.as_str())
            .collect()
    }

    pub fn missing(&self) -> Vec<&str> {
        self.rows
            .iter()
            .filter(|r| r.gated && r.judgement.verdict == Verdict::Missing)
            .map(|r| r.name.as_str())
            .collect()
    }

    /// The reference metrics (agent off) that moved beyond their limit.
    pub fn reference_moved(&self) -> Vec<&str> {
        self.rows
            .iter()
            .filter(|r| {
                !r.gated
                    && r.group == "reference"
                    && matches!(r.judgement.verdict, Verdict::Regression | Verdict::Improved)
            })
            .map(|r| r.name.as_str())
            .collect()
    }

    /// 0 pass, 1 a regression or a gated metric missing.
    pub fn exit_code(&self) -> u8 {
        u8::from(!self.regressions().is_empty() || !self.missing().is_empty())
    }

    pub fn render(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "perf-compare: base {}", self.base);
        let _ = writeln!(o, "              new  {}", self.new);
        let _ = writeln!(
            o,
            "a gated metric regresses when its median is worse by more than its threshold, by more \
             than the noise (the larger run's (p95 − p5) / 2 over the median, at least the floor) \
             and by more than its absolute floor"
        );
        let header = format!(
            "{:<32} {:<13} {:>14} {:>14} {:>10} {:>8} {:>8}  {}",
            "metric", "unit", "base median", "new median", "delta", "noise", "limit", "verdict"
        );
        let mut section = None;
        for r in &self.rows {
            let s = if r.gated {
                "gated"
            } else {
                "not gated (reference: agent off; informational)"
            };
            if section != Some(s) {
                let _ = writeln!(o, "\n{s}:\n{header}");
                section = Some(s);
            }
            let j = &r.judgement;
            let _ = writeln!(
                o,
                "{:<32} {:<13} {:>14} {:>14} {:>10} {:>7.1}% {:>7.1}%  {}",
                r.name,
                r.unit,
                num(j.base_median),
                num(j.new_median),
                pct(j.worse_pct),
                j.noise_pct,
                j.limit_pct,
                r.judgement.verdict.label(r.gated)
            );
        }
        let _ = writeln!(o, "(delta: positive = worse)");
        if !self.host_mismatch.is_empty() {
            let _ = writeln!(o, "\nhost differs: {}", self.host_mismatch.join("; "));
        }
        let moved = self.reference_moved();
        if !moved.is_empty() {
            let _ = writeln!(
                o,
                "\nwarning: the agent-off reference moved ({}): the host or the kernel changed under \
                 the comparison, and the gated figures may have moved with it",
                moved.join(", ")
            );
        }
        for n in &self.notes {
            let _ = writeln!(o, "note: {n}");
        }
        let regressions = self.regressions();
        let missing = self.missing();
        let improved = self
            .rows
            .iter()
            .filter(|r| r.gated && r.judgement.verdict == Verdict::Improved)
            .count();
        let _ = writeln!(
            o,
            "\nresult: {} regression(s){}, {} missing{}, {} improved — {}",
            regressions.len(),
            list(&regressions),
            missing.len(),
            list(&missing),
            improved,
            if self.exit_code() == 0 {
                "PASS"
            } else {
                "FAIL"
            }
        );
        o
    }
}

fn list(names: &[&str]) -> String {
    if names.is_empty() {
        String::new()
    } else {
        format!(" ({})", names.join(", "))
    }
}

fn num(v: Option<f64>) -> String {
    match v {
        None => "—".to_string(),
        Some(x) if x.abs() >= 100.0 => format!("{x:.1}"),
        Some(x) if x.abs() >= 1.0 => format!("{x:.3}"),
        Some(x) => format!("{x:.4}"),
    }
}

fn pct(v: Option<f64>) -> String {
    match v {
        None => "—".to_string(),
        Some(x) if x == f64::INFINITY => "+inf".to_string(),
        Some(x) if x == f64::NEG_INFINITY => "-inf".to_string(),
        Some(x) => format!("{x:+.1}%"),
    }
}

fn read_run(path: &Path, label: &str) -> Result<Run> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_run(&text, label)
}

fn run(args: &Args) -> Result<u8> {
    for (v, what) in [
        (args.threshold, "--threshold"),
        (args.noise_floor, "--noise-floor"),
    ] {
        if !v.is_finite() || v < 0.0 {
            bail!("{what} takes a finite value ≥ 0");
        }
    }
    let base = read_run(&args.base, &args.base.display().to_string())?;
    let new = read_run(&args.new, &args.new.display().to_string())?;
    let mut cfg = Config::new(args.threshold, args.noise_floor);
    let known = |n: &str| base.metrics.contains_key(n) || new.metrics.contains_key(n);
    let file = match (&args.thresholds, args.no_thresholds) {
        (_, true) => None,
        (Some(p), false) => Some(p.clone()),
        (None, false) => Some(crate::repo_root()?.join(THRESHOLDS_FILE)),
    };
    let mut file_note = "thresholds: none (--threshold and the built-in floors)".to_string();
    if let Some(path) = file {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading the thresholds {}", path.display()))?;
        let table = parse_thresholds(&text).with_context(|| format!("in {}", path.display()))?;
        file_note = format!("thresholds: {} ({} metrics)", path.display(), table.len());
        for (name, t) in table {
            if !known(&name) {
                file_note.push_str(&format!("; {name} is in neither run"));
                continue;
            }
            cfg.per_metric_threshold
                .insert(name.clone(), t.threshold_pct);
            cfg.abs_floor.insert(name, t.abs_floor);
        }
    }
    for s in &args.metric_threshold {
        let (k, v) = name_value(s, "--metric-threshold")?;
        if !known(&k) {
            bail!("--metric-threshold {k}: no such metric in either file");
        }
        cfg.per_metric_threshold.insert(k, v);
    }
    for s in &args.abs_floor {
        let (k, v) = name_value(s, "--abs-floor")?;
        if !known(&k) {
            bail!("--abs-floor {k}: no such metric in either file");
        }
        cfg.abs_floor.insert(k, v);
    }
    let mut report = compare(&base, &new, &cfg);
    report.notes.insert(0, file_note);
    print!("{}", report.render());
    if !report.host_mismatch.is_empty() && !args.allow_host_mismatch {
        eprintln!(
            "perf-compare: the runs come from different hosts ({}): not comparable; take a new \
             baseline on this host with the base tree, or pass --allow-host-mismatch",
            report.host_mismatch.join("; ")
        );
        return Ok(2);
    }
    Ok(report.exit_code())
}

/// The sub-command: 0 pass, 1 fail, 2 error.
pub fn main(args: &Args) -> ExitCode {
    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("perf-compare: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(threshold: f64, floor: f64) -> Gate {
        Gate {
            threshold_pct: threshold,
            abs_floor: floor,
            noise_floor_pct: DEFAULT_NOISE_FLOOR_PCT,
        }
    }

    #[test]
    fn quantiles_match_perf_lib() {
        // the cases of perf_lib.py's self-test
        assert_eq!(quantile(&[1.0, 2.0, 3.0, 4.0], 0.5), Some(2.5));
        assert!((quantile(&[10.0, 20.0, 30.0, 40.0, 50.0], 0.95).unwrap() - 48.0).abs() < 1e-9);
        assert_eq!(quantile(&[7.0], 0.95), Some(7.0));
        assert_eq!(quantile(&[], 0.5), None);
        // order does not matter
        assert_eq!(quantile(&[3.0, 1.0, 2.0], 0.5), Some(2.0));
        let n = noise_pct(&[100.0, 102.0, 98.0, 101.0, 99.0]).unwrap();
        assert!(n > 1.5 && n < 2.0, "{n}");
        assert_eq!(noise_pct(&[5.0, 5.0]), None);
        assert_eq!(noise_pct(&[0.0, 0.0, 0.0]), None);
    }

    #[test]
    fn worse_beyond_threshold_and_noise_is_a_regression() {
        let base = [100.0, 101.0, 99.0, 100.0, 102.0];
        let new = [115.0, 116.0, 114.0, 115.0, 117.0];
        let j = judge(&base, &new, true, &gate(10.0, 0.0));
        assert_eq!(j.verdict, Verdict::Regression, "{j:?}");
        assert!((j.worse_pct.unwrap() - 15.0).abs() < 1e-9);
        // a higher threshold for the metric lets it through
        assert_eq!(
            judge(&base, &new, true, &gate(20.0, 0.0)).verdict,
            Verdict::Ok
        );
        // so does an absolute floor above the change
        assert_eq!(
            judge(&base, &new, true, &gate(10.0, 20.0)).verdict,
            Verdict::Ok
        );
    }

    #[test]
    fn better_beyond_the_limit_is_an_improvement() {
        let base = [100.0, 101.0, 99.0, 100.0, 102.0];
        let new = [85.0, 86.0, 84.0, 85.0, 87.0];
        assert_eq!(
            judge(&base, &new, true, &gate(10.0, 0.0)).verdict,
            Verdict::Improved
        );
    }

    #[test]
    fn a_change_inside_the_noise_is_not_a_regression() {
        // ±20 % spread: a 12 % move of the median is within it
        let base = [80.0, 100.0, 120.0, 100.0, 90.0, 110.0, 100.0];
        let new = [92.0, 112.0, 132.0, 112.0, 102.0, 122.0, 112.0];
        let j = judge(&base, &new, true, &gate(10.0, 0.0));
        assert_eq!(j.verdict, Verdict::WithinNoise, "{j:?}");
        assert!(j.noise_pct > 12.0 && j.limit_pct == j.noise_pct);
    }

    #[test]
    fn higher_is_better_metrics_regress_downwards() {
        let base = [50.0, 51.0, 49.0];
        let new = [40.0, 41.0, 39.0];
        assert_eq!(
            judge(&base, &new, false, &gate(10.0, 0.0)).verdict,
            Verdict::Regression
        );
        assert_eq!(
            judge(&new, &base, false, &gate(10.0, 0.0)).verdict,
            Verdict::Improved
        );
    }

    #[test]
    fn counters_from_zero_regress_beyond_their_floor() {
        // a single total per run: no noise but the floor
        let j = judge(&[0.0], &[3.0], true, &gate(10.0, 0.0));
        assert_eq!(j.verdict, Verdict::Regression);
        assert_eq!(j.worse_pct, Some(f64::INFINITY));
        assert_eq!(
            judge(&[0.0], &[3.0], true, &gate(10.0, 5.0)).verdict,
            Verdict::Ok
        );
        assert_eq!(
            judge(&[0.0], &[0.0], true, &gate(10.0, 0.0)).verdict,
            Verdict::Ok
        );
        assert_eq!(
            judge(&[4.0], &[0.0], true, &gate(10.0, 0.0)).verdict,
            Verdict::Improved
        );
    }

    #[test]
    fn a_metric_measured_once_and_not_again_is_missing() {
        assert_eq!(
            judge(&[1.0, 2.0, 3.0], &[], true, &gate(10.0, 0.0)).verdict,
            Verdict::Missing
        );
        assert_eq!(
            judge(&[], &[1.0], true, &gate(10.0, 0.0)).verdict,
            Verdict::Unmeasured
        );
    }

    #[test]
    fn parse_refuses_another_schema_and_bad_samples() {
        assert!(parse_run(r#"{"schema":"other","metrics":{}}"#, "x").is_err());
        assert!(parse_run(r#"{"metrics":{}}"#, "x").is_err());
        assert!(parse_run(
            r#"{"schema":"northnarrow-perf/1","metrics":{"m":{"samples":[1,"x"]}}}"#,
            "x"
        )
        .is_err());
        assert!(parse_run(
            r#"{"schema":"northnarrow-perf/1","metrics":{"m":{"better":"up","samples":[1]}}}"#,
            "x"
        )
        .is_err());
        let r = parse_run(
            r#"{"schema":"northnarrow-perf/1","metrics":{"m":{"samples":[1,2],"gate":false}}}"#,
            "x",
        )
        .unwrap();
        assert!(!r.metrics["m"].gate && r.metrics["m"].lower_is_better);
    }

    #[test]
    fn a_thresholds_file_is_one_reasoned_line_per_metric() {
        let t = parse_thresholds(
            "# comment\n\nexec_true_ns\t15\t0\tA/A 4 %, twice that plus 5\n\
             agent_rss_idle_kib\t10\t2048\tthe allocator\n",
        )
        .unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t["exec_true_ns"].threshold_pct, 15.0);
        assert_eq!(t["agent_rss_idle_kib"].abs_floor, 2048.0);
        for bad in [
            "exec_true_ns\t15\t0\n",
            "exec_true_ns\t15\t0\t\n",
            "exec_true_ns\t-1\t0\twhy\n",
            "exec_true_ns\tx\t0\twhy\n",
            "exec_true_ns 15 0 why\n",
            "a\t1\t0\twhy\na\t2\t0\twhy\n",
        ] {
            assert!(parse_thresholds(bad).is_err(), "{bad:?}");
        }
    }

    /// A run with only a `host` object (no metrics).
    fn run_on(host: Value) -> Run {
        let doc = serde_json::json!({"schema": SCHEMA, "host": host, "metrics": {}});
        parse_run(&doc.to_string(), "x").unwrap()
    }

    /// The host of the committed baseline (lab PR 228).
    fn lab_host() -> Value {
        serde_json::json!({
            "kernel": "6.8.0-147-generic",
            "cpu_model": "AMD Ryzen 9 3900XT 12-Core Processor",
            "vcpus": 4,
            "mem_total_kib": 8_131_764,
            "virt": "microsoft",
            "clocksource": "hyperv_clocksource_tsc_page",
        })
    }

    fn with(key: &str, value: Value) -> Run {
        let mut h = lab_host();
        h[key] = value;
        run_on(h)
    }

    fn mem(base_kib: u64, new_kib: u64) -> Report {
        let cfg = Config::new(DEFAULT_THRESHOLD_PCT, DEFAULT_NOISE_FLOOR_PCT);
        compare(
            &with("mem_total_kib", base_kib.into()),
            &with("mem_total_kib", new_kib.into()),
            &cfg,
        )
    }

    /// Lab PR 248: the guest's MemTotal was 8,131,760 KiB on one boot and
    /// 8,131,764 on another, and the gate refused the pair as two hosts
    /// (exit 2), so every comparison needed --allow-host-mismatch. A drift
    /// within ±0.1 % of the base's MemTotal, or ±1 MiB when that is more, is
    /// the same host now — noted, not a mismatch.
    #[test]
    fn a_memtotal_drift_between_boots_is_the_same_host() {
        let r = mem(8_131_764, 8_131_760);
        assert!(r.host_mismatch.is_empty(), "{:?}", r.host_mismatch);
        assert!(
            r.notes.iter().any(
                |n| n.starts_with("host: mem_total_kib 8131764 → 8131760 (-4 KiB)")
                    && n.contains("±8132 KiB")
                    && n.ends_with("the same host")
            ),
            "{:?}",
            r.notes
        );
        assert!(r
            .render()
            .contains("note: host: mem_total_kib 8131764 → 8131760"));
        // 0.1 % of the base (8,131.8 KiB here), at least 1 MiB
        assert!((mem_total_tolerance_kib(8_131_764.0) - 8_131.764).abs() < 1e-9);
        assert_eq!(mem_total_tolerance_kib(524_288.0), 1024.0);
        for (b, n) in [
            (8_131_764, 8_131_764 + 8_131),
            (8_131_764, 8_131_764 - 8_131),
            (524_288, 524_288 + 1024),
            (524_288, 524_288 - 1024),
        ] {
            let r = mem(b, n);
            assert!(
                r.host_mismatch.is_empty(),
                "{b} → {n}: {:?}",
                r.host_mismatch
            );
        }
        // the same MemTotal: nothing to note
        let r = mem(8_131_764, 8_131_764);
        assert!(r.host_mismatch.is_empty() && r.notes.iter().all(|n| !n.contains("mem_total")));
    }

    /// A host that did change still fails the comparison: another CPU model
    /// or count, another kernel, a MemTotal beyond the drift (a smaller
    /// guest, or just past the tolerance either way), one not recorded, the
    /// virtualisation or the clocksource.
    #[test]
    fn a_real_host_change_is_still_another_host() {
        let cfg = Config::new(DEFAULT_THRESHOLD_PCT, DEFAULT_NOISE_FLOOR_PCT);
        let base = run_on(lab_host());
        for (key, value, line) in [
            (
                "cpu_model",
                serde_json::json!("AMD EPYC 7763 64-Core Processor"),
                "cpu_model: AMD Ryzen 9 3900XT 12-Core Processor → AMD EPYC 7763 64-Core Processor",
            ),
            ("vcpus", serde_json::json!(8), "vcpus: 4 → 8"),
            (
                "kernel",
                serde_json::json!("6.8.0-149-generic"),
                "kernel: 6.8.0-147-generic → 6.8.0-149-generic",
            ),
            (
                "mem_total_kib",
                serde_json::json!(6_093_644),
                "mem_total_kib: 8131764 → 6093644",
            ),
            (
                "mem_total_kib",
                serde_json::json!(8_131_764 + 8_132),
                "mem_total_kib: 8131764 → 8139896",
            ),
            (
                "mem_total_kib",
                serde_json::json!(8_131_764 - 8_132),
                "mem_total_kib: 8131764 → 8123632",
            ),
            ("mem_total_kib", Value::Null, "mem_total_kib: 8131764 → —"),
            ("virt", serde_json::json!("kvm"), "virt: microsoft → kvm"),
            (
                "clocksource",
                serde_json::json!("tsc"),
                "clocksource: hyperv_clocksource_tsc_page → tsc",
            ),
        ] {
            let r = compare(&base, &with(key, value), &cfg);
            assert_eq!(r.host_mismatch, vec![line.to_string()], "{key}");
            assert!(
                r.render().contains(&format!("host differs: {line}")),
                "{key}"
            );
        }
        // beyond the 1 MiB floor of a small guest
        assert_eq!(
            mem(524_288, 524_288 + 1025).host_mismatch,
            vec!["mem_total_kib: 524288 → 525313".to_string()]
        );
    }

    #[test]
    fn option_values_are_name_and_non_negative_number() {
        assert_eq!(
            name_value("open_watched_ns=15", "--metric-threshold").unwrap(),
            ("open_watched_ns".to_string(), 15.0)
        );
        for bad in ["x", "=3", "x=-1", "x=abc", "x=inf"] {
            assert!(name_value(bad, "--abs-floor").is_err(), "{bad}");
        }
    }
}
