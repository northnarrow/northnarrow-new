//! Lab PR 228: the golden replay.
//!
//! Recorded event streams (`agent/tests/golden/cases/*.json`) go through
//! the decision path of `process_event` (`pipeline`), on an engine built the
//! way the start (`boot`) builds it — the shipped lists of `configs/`, every
//! per-rule policy switch at its production value (`response_policy`: off)
//! — over host state of the case's own, so nothing of the machine running
//! the test is read: an empty `/proc`, the package database of the fixture
//! root `agent/tests/golden/host`, an entropy sampler that answers from the
//! case, the case's resolvers and files. What each item of a stream gives
//! is one line of `agent/tests/golden/expected/<case>.jsonl`: the verdict —
//! rule, action, severity, reasoning, target pid and file, time, ATT&CK —
//! or `null`. The test compares those files byte for byte, replays every
//! case several times and on several threads at once, and requires the
//! same bytes each time.
//!
//! The decision path of one item, as `process_event` runs it:
//! - an exec event is first ingested into the lineage cache (the posture's
//!   trigger detector does it before the rules see the event);
//! - an anti-tamper denial is NN-L-AT-001's and an exploit post-condition
//!   NN-L-EPG-001/002's, outside the engine (lab PR 219);
//! - every other event goes to the engine: every rule judges it and the
//!   decision is computed from all the matches (lab PR 236, multi-match) —
//!   a line names every matched rule — under the case's per-rule policy
//!   (`policy`, none: the built-in defaults, a held response an alert);
//! - an exec-policy report of the kernel (lab PR 226) becomes the exec
//!   policy's records (`execpol::record::records_of`), outside the engine.
//!
//! Not replayed, said so: the posture and the COMBAT ladder (they act on
//! verdicts, they are not verdicts), the canary registry (no case deploys a
//! canary), the per-rule budget (it decides what is stored, never the
//! verdict), the exec sensor's path resolution (a case's paths are
//! absolute), the exec quarantine's scanner (lab PR 223: a process, not a
//! rule over events).
//!
//! State that is the process's, not the engine's: NN-L-FIM-010's
//! two-record dedup (one engine per agent, by design). The cases use their
//! own paths and pids, so replays running at once never share an entry.
//!
//! `cargo xtask golden` runs these tests; `cargo xtask golden --update`
//! rewrites the golden files (`NN_GOLDEN_UPDATE=1`), to be read as a diff
//! and committed with the change that moved them. CI never writes them:
//! with `CI` set an update is refused, and a stale file fails the test
//! (`docs/validation/GOLDEN_REPLAY.md`).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::wire::execpol::{self as wpol, ExecPolRaw};
use nn_model::{Event, ExeIdentity};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{replay, response_policy, rule_policy, RuleEngine};
use crate::impact::entropy::{Sample, Sampler};
use crate::impact::trust::ProgramOwners;
use crate::impact::RansomTracker;
use crate::posture::lineage::AuthSessionTracker;

/// The cases, the golden files and the fixture root.
const GOLDEN_DIR: &str = concat!(env!("NN_REPO_ROOT"), "/agent/tests/golden");
/// The repository's shipped lists (`configs/`), as install.sh lays them.
const CONFIGS: &str = concat!(env!("NN_REPO_ROOT"), "/configs");
/// `1`: write the golden files instead of comparing (`cargo xtask golden
/// --update`).
const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";
/// Stands for the replay's own file root in a case and in its golden file
/// (the directory is made for each replay, and the case's text read with
/// it in place of the token).
const ROOT_TOKEN: &str = "@ROOT@";
/// The golden file's format; a change of the line shape bumps it.
/// Lab PR 236: 2 — a decision of several rules lists its `matches` and
/// `responses`, the header names the policy.
const FORMAT: &str = "northnarrow-golden/2";
/// Replays of each case in the determinism test, and threads at once.
const RUNS: usize = 3;
const THREADS: usize = 4;

/// One recorded stream.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    /// What the stream is (the lab scenario it is shaped on) and what its
    /// golden file must show.
    about: String,
    /// The host's configured resolvers (the port-53 exemption, lab PR 224).
    #[serde(default)]
    resolvers: Vec<IpAddr>,
    /// Files there before the stream, under `@ROOT@` (what a copy-delete
    /// left beside the originals, read by the ransomware tracker).
    #[serde(default)]
    files: Vec<String>,
    /// The entropy sampler's answers, by path prefix (the first that
    /// matches); any other path samples as plain content.
    #[serde(default)]
    entropy: Vec<EntropyAnswer>,
    /// The rules the stream must fire, and those whose response it must
    /// show held (action `Log`, its reasoning naming what was held): an
    /// update of the golden file that loses one fails
    /// `every_case_shows_what_it_says`.
    #[serde(default)]
    fires: Vec<String>,
    #[serde(default)]
    held: Vec<String>,
    /// Lab PR 236: a per-rule policy (`rule-policy.local` text) the engine
    /// reads; none = the built-in defaults.
    #[serde(default)]
    policy: Option<String>,
    /// Rules the stream must show enforced by that policy (an action other
    /// than `Log`, mode `enforce`), and rules it must show exempt.
    #[serde(default)]
    enforced: Vec<String>,
    #[serde(default)]
    exempt: Vec<String>,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntropyAnswer {
    prefix: String,
    examined: u32,
    high: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Item {
    /// One event as the agent serialises it (`nn_model::Event`).
    Event(Box<Event>),
    /// A connect sweep of one process: `count` `TcpConnect` events, the
    /// destination address counting up from `first` and wrapping after
    /// `hosts`, the ports in turn, `step_ns` apart.
    TcpSweep(Sweep),
    /// One report of the exec policy's kernel half (lab PR 226).
    Execpol(Box<ExecPolInput>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sweep {
    pid: u32,
    uid: u32,
    comm: String,
    first: Ipv4Addr,
    hosts: u32,
    ports: Vec<u16>,
    count: u32,
    start_ns: u64,
    step_ns: u64,
}

impl Sweep {
    fn events(&self) -> Vec<Event> {
        let base = u32::from(self.first);
        (0..self.count)
            .map(|i| {
                let mut dst = [0u8; 16];
                dst[..4].copy_from_slice(&(base + i % self.hosts.max(1)).to_be_bytes());
                let mut src = [0u8; 16];
                src[..4].copy_from_slice(&[10, 0, 2, 15]);
                Event::TcpConnect {
                    pid: self.pid,
                    uid: self.uid,
                    comm: self.comm.clone(),
                    family: 2,
                    src_addr: src,
                    src_port: 40_000 + (i % 20_000) as u16,
                    dst_addr: dst,
                    dst_port: self.ports[i as usize % self.ports.len()],
                    timestamp_ns: self.start_ns + u64::from(i) * self.step_ns,
                }
            })
            .collect()
    }
}

/// An exec-policy report, by name (`common::wire::execpol`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecPolInput {
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: String,
    timestamp_ns: u64,
    /// `exec` or `map`.
    kind: String,
    /// `admin`, `session`, `service`, `unknown`.
    tier: String,
    /// What the tier rests on (`tier_signals` names).
    #[serde(default)]
    tier_signals: Vec<String>,
    /// The file the kernel executed or mapped.
    path: String,
    /// `execq::class_names` names.
    #[serde(default)]
    classes: Vec<String>,
    /// `deny`, `would_deny`, `quarantine`, `quarantine_inactive`,
    /// `record`, `exempted`.
    #[serde(default)]
    action: Vec<String>,
    /// `env_names` names.
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    env_action: Vec<String>,
    #[serde(default)]
    preload: String,
    #[serde(default)]
    audit: String,
    #[serde(default)]
    tunables: String,
    #[serde(default)]
    libpath: String,
    #[serde(default)]
    hist: String,
    /// The file's mode (set-id bits).
    #[serde(default)]
    file_mode: u32,
    /// Where the policy came from.
    policy: String,
}

/// The bits whose names `namer` gives for `names`; an unknown name is an
/// error of the case.
fn bits(names: &[String], namer: impl Fn(u32) -> Vec<&'static str>, what: &str) -> u32 {
    let mut v = 0;
    for n in names {
        let bit = (0..32)
            .map(|b| 1u32 << b)
            .find(|b| namer(*b).contains(&n.as_str()))
            .unwrap_or_else(|| panic!("{what}: unknown name {n:?}"));
        v |= bit;
    }
    v
}

fn action_names(bit: u32) -> Vec<&'static str> {
    use wpol::action as a;
    [
        (a::DENY, "deny"),
        (a::WOULD_DENY, "would_deny"),
        (a::QUARANTINE, "quarantine"),
        (a::QUARANTINE_INACTIVE, "quarantine_inactive"),
        (a::RECORD, "record"),
        (a::EXEMPTED, "exempted"),
    ]
    .into_iter()
    .filter(|(b, _)| bit & b != 0)
    .map(|(_, n)| n)
    .collect()
}

fn fill(dst: &mut [u8], s: &str) {
    assert!(s.len() < dst.len(), "{s:?} longer than its field");
    dst[..s.len()].copy_from_slice(s.as_bytes());
}

impl ExecPolInput {
    fn raw(&self) -> ExecPolRaw {
        let mut r = ExecPolRaw::zeroed();
        r.pid = self.pid;
        r.tid = self.pid;
        r.ppid = self.ppid;
        r.uid = self.uid;
        r.gid = self.uid;
        r.loginuid = u32::MAX;
        r.timestamp_ns = self.timestamp_ns;
        r.kind = match self.kind.as_str() {
            "exec" => wpol::kind::EXEC,
            "map" => wpol::kind::MAP,
            k => panic!("execpol kind {k:?}: exec or map"),
        };
        let t = (0..wpol::tier::COUNT)
            .find(|t| wpol::tier_name(*t) == self.tier)
            .unwrap_or_else(|| panic!("execpol tier {:?}", self.tier));
        r.tier = t | bits(&self.tier_signals, wpol::tier_signals, "tier_signals");
        r.classes = bits(&self.classes, common::wire::execq::class_names, "classes");
        r.action = bits(&self.action, action_names, "action");
        r.env_flags = bits(&self.env, wpol::env_names, "env");
        r.env_action = bits(&self.env_action, action_names, "env_action");
        r.file_mode = self.file_mode;
        r.tunables_len = self.tunables.len() as u32;
        fill(&mut r.comm, &self.comm);
        fill(&mut r.preload, &self.preload);
        fill(&mut r.audit, &self.audit);
        fill(&mut r.tunables, &self.tunables);
        fill(&mut r.libpath, &self.libpath);
        fill(&mut r.hist, &self.hist);
        r
    }

    /// The event the records describe, as `execpol::record::event_of`
    /// builds it once the path is absolute.
    fn event(&self) -> Event {
        Event::ExecCheck {
            pid: self.pid,
            ppid: self.ppid,
            uid: self.uid,
            comm: self.comm.clone(),
            filename: String::new(),
            timestamp_ns: self.timestamp_ns,
            exe: ExeIdentity {
                path: self.path.clone(),
                ..Default::default()
            },
        }
    }
}

/// The entropy sampler of a case.
struct Answers(Vec<EntropyAnswer>);

impl Sampler for Answers {
    fn sample(&self, path: &str, _since: Duration) -> Sample {
        match self.0.iter().find(|a| path.starts_with(&a.prefix)) {
            Some(a) => Sample {
                examined: a.examined,
                high: a.high,
                containers: 0,
            },
            None => Sample {
                examined: 4,
                high: 0,
                containers: 0,
            },
        }
    }
    fn sample_copies(&self, copy: &str, _suffix: &str, since: Duration) -> Sample {
        self.sample(copy, since)
    }
}

/// The host a replay runs on: its own `/proc` (empty) and file root, the
/// engine the start builds over them (`replay::engine`).
struct Host {
    _proc: tempfile::TempDir,
    root: tempfile::TempDir,
    lineage: AuthSessionTracker,
    engine: RuleEngine,
}

impl Host {
    /// The host of one replay of `case`, read with `root` for its
    /// [`ROOT_TOKEN`].
    fn new(case: &Case, root: tempfile::TempDir) -> Self {
        let proc = tempfile::TempDir::new().unwrap();
        for f in &case.files {
            let p = PathBuf::from(f);
            assert!(
                p.starts_with(root.path()),
                "{f}: a case's file lies under {ROOT_TOKEN}"
            );
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"golden fixture").unwrap();
        }
        let fixture = Path::new(GOLDEN_DIR).join("host");
        let lineage = AuthSessionTracker::new(proc.path()).with_host_root(&fixture);
        let entropy: Vec<EntropyAnswer> = case
            .entropy
            .iter()
            .map(|a| EntropyAnswer {
                prefix: a.prefix.clone(),
                examined: a.examined,
                high: a.high,
            })
            .collect();
        let ransom = Arc::new(RansomTracker::with(
            lineage.clone(),
            ProgramOwners::new(&fixture),
            Arc::new(Answers(entropy)),
        ));
        let policy = match &case.policy {
            Some(text) => {
                rule_policy::parse(text).unwrap_or_else(|e| panic!("the case's policy: {e}"))
            }
            None => rule_policy::RulePolicy::builtin(),
        };
        let engine = replay::engine(replay::HostParts {
            configs: Path::new(CONFIGS),
            proc_root: proc.path(),
            lineage: lineage.clone(),
            ransom,
            resolvers: case.resolvers.clone(),
            policy,
        });
        Self {
            _proc: proc,
            root,
            lineage,
            engine,
        }
    }

    /// The decision on one event, as `process_event` takes it.
    fn decide(&self, event: &Event) -> Value {
        replay::decide(&self.engine, &self.lineage, event)
    }

    fn replay(&self, case: &Case) -> Vec<Value> {
        let mut out = Vec::new();
        for item in &case.items {
            out.push(match item {
                Item::Event(e) => self.decide(e),
                Item::TcpSweep(s) => {
                    let events = s.events();
                    let fired: Vec<Value> = events
                        .iter()
                        .enumerate()
                        .filter_map(|(i, e)| match self.decide(e) {
                            Value::Null => None,
                            v => Some(json!({"at": i, "decision": v})),
                        })
                        .collect();
                    json!({"sweep": events.len(), "decisions": fired})
                }
                Item::Execpol(p) => execpol_lines(p),
            });
        }
        out
    }
}

/// The exec policy's records of one kernel report, as decision lines.
fn execpol_lines(p: &ExecPolInput) -> Value {
    let records = crate::execpol::record::records_of(&p.raw(), &p.event(), &p.policy);
    Value::Array(
        records
            .iter()
            .map(|r| {
                let mut v = replay::outside_line(
                    Some(r.verdict.clone()),
                    r.attack.as_slice(),
                    Some(r.response.clone()),
                );
                v["execpol"] = serde_json::to_value(&r.evidence).unwrap();
                v
            })
            .collect(),
    )
}

/// The golden text of one replay: a header naming the case and the policy
/// switches, then one line per item.
fn render(name: &str, case: &Case, host: &Host, lines: &[Value]) -> String {
    let switches: Vec<Value> = response_policy::ALL
        .iter()
        .map(|s| json!({"held": s.held, "on": s.on}))
        .collect();
    let policy = host.engine.policy().current();
    let mut text = serde_json::to_string(&json!({
        "format": FORMAT,
        "case": name,
        "about": case.about,
        "rules": host.engine.rule_count(),
        "switches": switches,
        "policy": if policy.is_builtin() { "built-in defaults".to_string() } else { policy.render() },
    }))
    .unwrap();
    text.push('\n');
    for (seq, l) in lines.iter().enumerate() {
        text.push_str(&serde_json::to_string(&json!({"seq": seq, "decision": l})).unwrap());
        text.push('\n');
    }
    text.replace(host.root.path().to_str().unwrap(), ROOT_TOKEN)
}

/// A case's text, read with `root` in place of [`ROOT_TOKEN`].
fn parse(name: &str, text: &str, root: &Path) -> Case {
    let root = root.to_str().unwrap();
    // Put in a JSON string as it is, and taken out of the golden text the
    // same way: no character JSON would escape.
    assert!(
        !root.contains(['"', '\\']) && !root.chars().any(char::is_control),
        "the temporary directory {root:?} cannot stand in for {ROOT_TOKEN}"
    );
    let text = text.replace(ROOT_TOKEN, root);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("case {name}: {e}"))
}

/// The case files, by name (`cases/<name>.json`, sorted), as text.
fn cases() -> Vec<(String, String)> {
    let dir = Path::new(GOLDEN_DIR).join("cases");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_str().unwrap().to_string();
            (name, std::fs::read_to_string(&p).unwrap())
        })
        .collect()
}

/// One fresh replay of a case: the case as read for it, and its decisions.
fn replay(name: &str, text: &str) -> (Case, Host, Vec<Value>) {
    let root = tempfile::TempDir::new().unwrap();
    let case = parse(name, text, root.path());
    let host = Host::new(&case, root);
    let lines = host.replay(&case);
    (case, host, lines)
}

/// One fresh replay of a case, as golden text.
fn golden_text(name: &str, text: &str) -> String {
    let (case, host, lines) = replay(name, text);
    render(name, &case, &host, &lines)
}

fn expected_path(name: &str) -> PathBuf {
    Path::new(GOLDEN_DIR)
        .join("expected")
        .join(format!("{name}.jsonl"))
}

fn updating() -> bool {
    let on = std::env::var(UPDATE_ENV).is_ok_and(|v| v == "1");
    if on && std::env::var_os("CI").is_some() {
        panic!(
            "{UPDATE_ENV}=1 with CI set: the golden files are written by a maintainer \
             (`cargo xtask golden --update`) and reviewed, never by CI"
        );
    }
    on
}

/// Every committed case gives its committed golden file, byte for byte;
/// every golden file has its case. `cargo xtask golden --update` rewrites
/// them.
#[test]
fn golden_replay_matches_the_committed_files() {
    let update = updating();
    let cases = cases();
    assert!(!cases.is_empty(), "no golden case in {GOLDEN_DIR}/cases");
    let mut stale = Vec::new();
    for (name, source) in &cases {
        let text = golden_text(name, source);
        let path = expected_path(name);
        if update {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                std::fs::write(&path, &text).unwrap();
                eprintln!("golden: wrote {}", path.display());
            }
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(committed) if committed == text => {}
            Ok(committed) => {
                let first = committed
                    .lines()
                    .zip(text.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| committed.lines().count().min(text.lines().count()));
                stale.push(format!(
                    "{name}: line {} differs\n  committed: {}\n  replayed:  {}",
                    first + 1,
                    committed.lines().nth(first).unwrap_or("(none)"),
                    text.lines().nth(first).unwrap_or("(none)")
                ));
            }
            Err(_) => stale.push(format!("{name}: no golden file {}", path.display())),
        }
    }
    let names: BTreeSet<&str> = cases.iter().map(|(n, _)| n.as_str()).collect();
    for e in std::fs::read_dir(Path::new(GOLDEN_DIR).join("expected")).unwrap() {
        let p = e.unwrap().path();
        let stem = p.file_stem().unwrap().to_str().unwrap().to_string();
        if !names.contains(stem.as_str()) {
            if update {
                std::fs::remove_file(&p).unwrap();
                eprintln!("golden: removed {} (no case)", p.display());
            } else {
                stale.push(format!("{}: a golden file without a case", p.display()));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "the golden replay differs from the committed files — a change of the decision \
         path; if it is intended, `cargo xtask golden --update` and review the diff \
         (docs/validation/GOLDEN_REPLAY.md):\n{}",
        stale.join("\n")
    );
}

/// The same input gives the same bytes: every case replayed again on this
/// thread, and on several threads at once, each replay on its own engine.
#[test]
fn golden_replay_is_deterministic_across_runs_and_threads() {
    let cases = Arc::new(cases());
    let first: Vec<String> = cases.iter().map(|(n, c)| golden_text(n, c)).collect();
    for _ in 1..RUNS {
        let again: Vec<String> = cases.iter().map(|(n, c)| golden_text(n, c)).collect();
        assert_eq!(again, first, "a second replay on one thread differs");
    }
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let cases = Arc::clone(&cases);
            std::thread::spawn(move || {
                cases
                    .iter()
                    .map(|(n, c)| golden_text(n, c))
                    .collect::<Vec<String>>()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(
            h.join().unwrap(),
            first,
            "a replay on another thread differs"
        );
    }
}

fn decisions(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Null => {}
        Value::Array(a) => a.iter().for_each(|x| decisions(x, out)),
        Value::Object(o) if o.contains_key("sweep") => {
            for d in o["decisions"].as_array().unwrap() {
                decisions(&d["decision"], out);
            }
        }
        Value::Object(_) => out.push(v.clone()),
        _ => unreachable!("{v}"),
    }
}

/// One matched rule of a decision line: its id, action, mode, whether a
/// switch still holds its response, and its exemption. A line of one match
/// carries no `matches`: the line is the match.
struct RuleView {
    rule: String,
    action: String,
    mode: String,
    held: bool,
    exempt: bool,
}

fn rule_views(d: &Value) -> Vec<RuleView> {
    match d.get("matches").and_then(Value::as_array) {
        Some(ms) => ms
            .iter()
            .map(|m| RuleView {
                rule: m["rule"].as_str().unwrap().to_string(),
                action: m["action"].as_str().unwrap().to_string(),
                mode: m["mode"].as_str().unwrap().to_string(),
                held: m.get("held").is_some(),
                exempt: m.get("exempt").is_some(),
            })
            .collect(),
        None => vec![RuleView {
            rule: d["rule"].as_str().unwrap().to_string(),
            action: d["action"].as_str().unwrap().to_string(),
            mode: "builtin".to_string(),
            held: d["action"] == "Log" && d["reasoning"].as_str().unwrap().contains("[held back: "),
            exempt: false,
        }],
    }
}

/// The cases cover the rules lots 219–226 added, and every response those
/// lots hold behind a switch shows as an alert: action `Log`, the reasoning
/// naming what was held — unless the case's own test policy enforces it.
#[test]
fn golden_cases_cover_the_rules_of_lots_219_to_226() {
    let mut all = Vec::new();
    let mut builtin = Vec::new();
    for (name, text) in cases() {
        let (case, _, lines) = replay(&name, &text);
        for l in &lines {
            decisions(l, &mut all);
            if case.policy.is_none() {
                decisions(l, &mut builtin);
            }
        }
    }
    let fired: BTreeSet<String> = all
        .iter()
        .flat_map(|d| rule_views(d).into_iter().map(|v| v.rule))
        .collect();
    for want in [
        "NN-L-EPG-001_CredentialPostcondition",
        "NN-L-NET-026_ScanFanOut",
        "NN-L-NET-027_OutboundAuthBruteforce",
        "R020_ShellWithSocketStdio",
        "NN-L-IMP-001_RansomwareEncryption",
        "NN-L-IMP-002_RenameExtensionBurst",
        "NN-L-EVA-001_SecurityServiceStopped",
        "NN-L-FIM-010_RansomwareExtensionRename",
        "NN-L-EXECPOL-001_StagingExecDenied",
    ] {
        assert!(
            fired.contains(want),
            "no golden case fires {want}: {fired:?}"
        );
    }
    // A held kill is an alert in the golden output.
    let held: Vec<RuleView> = builtin
        .iter()
        .flat_map(rule_views)
        .filter(|v| v.held)
        .collect();
    for v in &held {
        assert_eq!(v.action, "Log", "{}", v.rule);
    }
    let held_rules: BTreeSet<&str> = held.iter().map(|v| v.rule.as_str()).collect();
    for want in [
        "R020_ShellWithSocketStdio",
        "NN-L-NET-026_ScanFanOut",
        "NN-L-NET-027_OutboundAuthBruteforce",
        "NN-L-IMP-001_RansomwareEncryption",
        "NN-L-EVA-001_SecurityServiceStopped",
        "NN-L-FIM-010_RansomwareExtensionRename",
    ] {
        assert!(
            held_rules.contains(want),
            "no golden case shows the held kill of {want}: {held_rules:?}"
        );
    }
    // Without a policy no response a switch holds runs in the golden
    // output: no response is a held rule's, and a single-match line that
    // acts names nothing held.
    for d in &builtin {
        let views = rule_views(d);
        for r in d
            .get("responses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let rule = r["rule"].as_str().unwrap();
            assert!(!views.iter().any(|v| v.rule == rule && v.held), "{d}");
        }
        if d.get("matches").is_none() && d["action"] != "Log" {
            let r = d["reasoning"].as_str().unwrap();
            assert!(!r.contains("[held back: "), "{d}");
        }
    }
}

/// Each case fires the rules it names in `fires`, shows held the
/// responses it names in `held`, enforced by its policy those in
/// `enforced` and exempt those in `exempt`.
#[test]
fn every_case_shows_what_it_says() {
    for (name, text) in cases() {
        let (case, _, lines) = replay(&name, &text);
        assert!(!case.fires.is_empty(), "case {name}: `fires` names no rule");
        let mut all = Vec::new();
        for l in &lines {
            decisions(l, &mut all);
        }
        let views: Vec<RuleView> = all.iter().flat_map(rule_views).collect();
        for want in &case.fires {
            assert!(
                views.iter().any(|v| v.rule == *want),
                "case {name}: {want} does not fire"
            );
        }
        for want in &case.held {
            assert!(
                views
                    .iter()
                    .any(|v| v.rule == *want && v.action == "Log" && v.held),
                "case {name}: no held response of {want}"
            );
        }
        for want in &case.enforced {
            assert!(
                views
                    .iter()
                    .any(|v| v.rule == *want && v.action != "Log" && v.mode == "enforce"),
                "case {name}: no response of {want} enforced by the policy"
            );
        }
        for want in &case.exempt {
            assert!(
                views
                    .iter()
                    .any(|v| v.rule == *want && v.action == "Log" && v.exempt),
                "case {name}: {want} is not exempt"
            );
        }
        assert!(
            case.policy.is_some() || (case.enforced.is_empty() && case.exempt.is_empty()),
            "case {name}: `enforced` / `exempt` need a `policy`"
        );
    }
}

// ── Lab PR 267 (R12a): the priority bus does not change a verdict ────────
//
// R12a gives each class of events a queue of its own, taken by strict
// priority with aging and FIFO inside a class (`nn_core::bus`): two events
// of different classes can reach `process_event` in another order than the
// kernel saw them — today's pumps already interleave them as they are
// scheduled, the bus can hold a lower class back for longer. The property:
// every order of a stream's events that keeps each class's own order gives
// the same verdicts — for each rule and process, the strongest verdict the
// rule gave the process, and the responses run on each process ([`Judged`];
// not which event's line carried them, nor how often). The stream's order
// is the order the events reached the bus: an event is judged on the
// lineage of every exec that arrived before it, as the bus gives it
// (`nn_linux::sensors::bus`: the execs an event of a higher class
// overtakes are ingested first). Checked on every golden case: all such
// orders while they are few (`EXHAUSTIVE_MAX`), else every class-major
// order (each class whole, the classes in every order), the bus's own take
// order with the consumer behind by 1 to all of the stream, and a fixed
// sample of random merges.
//
// What it found (lab PR 267), fixed in the stores, not in this test: the
// process lineage and the chains' ancestry tree learned an exec only when
// it was judged, so a tamper event taken before the exec of its process,
// or a fan-out counted before the execs of the children, was judged
// without them (NN-L-EVA-003 lost its target, NN-L-NET-026/027 their
// parent) — the bus now hands them the execs it overtakes, and an exec
// ingested twice, or after a newer one of its pid, changes nothing; the
// chain store let one chain keep another off a flow and a late exec pick a
// held port-53 egress over the flow its kill is for — each chain now
// answers a flow once, in any order.

/// The lane of an exec policy report: not the bus — its own ring, read by
/// the exec policy apart from the event loop.
const OUTSIDE_BUS: usize = nn_core::bus::QUEUES;
const LANES: usize = OUTSIDE_BUS + 1;
/// Up to this many orders, every order is replayed.
const EXHAUSTIVE_MAX: u128 = 2_000;
/// Random merges replayed per case when not every order is.
const RANDOM_ORDERS: u64 = 256;

/// One item of a stream as the bus carries it: an event (a sweep is its
/// events, each queued on its own) or an exec policy report.
enum Unit<'a> {
    Event(Box<Event>),
    Execpol(&'a ExecPolInput),
}

/// A case's units in stream order, with their lanes.
fn units(case: &Case) -> Vec<(usize, Unit<'_>)> {
    let mut out = Vec::new();
    for item in &case.items {
        match item {
            Item::Event(e) => out.push((
                nn_core::bus::Priority::of_event(e).index(),
                Unit::Event(e.clone()),
            )),
            Item::TcpSweep(s) => {
                for e in s.events() {
                    out.push((
                        nn_core::bus::Priority::of_event(&e).index(),
                        Unit::Event(Box::new(e)),
                    ));
                }
            }
            Item::Execpol(p) => out.push((OUTSIDE_BUS, Unit::Execpol(p))),
        }
    }
    out
}

/// What a replay of a stream decided, whichever event carried each
/// judgment: for every rule and process it judged, the rule's verdict —
/// action, severity, policy mode, whether its response was held or the
/// rule exempt, ATT&CK — the strongest when it judged the process more than
/// once; and the responses that run, per process. Not compared: a decision
/// line's composition (one line per event, so a correlation is combined
/// with the matches of the event that completed it), the text and time a
/// line carries (a chain completed late names the order it was processed
/// in, by design: review 70, lab PRs 235 and 244), and how often a rule
/// judged a process (in order a chain answers each flow of the process; a
/// precursor processed late completes the chain once).
#[derive(Debug, PartialEq, Eq)]
struct Judged {
    /// (rule, pid) → the strongest verdict, as text.
    verdicts: std::collections::BTreeMap<(String, u64), String>,
    /// pid → the actions run on it (a tree kill includes the process's).
    effects: std::collections::BTreeMap<u64, BTreeSet<String>>,
}

/// The rule verdicts of one decision line: (rule, pid, strength, text).
fn rule_verdicts(line: &Value, out: &mut Vec<(String, u64, (bool, u8), String)>) {
    let view = |rule: &Value,
                action: &Value,
                severity: &Value,
                pid: &Value,
                mitre: &Value,
                mode: &str,
                held: bool,
                exempt: bool| {
        let text = serde_json::to_string(&json!({
            "rule": rule, "action": action, "severity": severity, "pid": pid,
            "mitre": mitre, "mode": mode, "held": held, "exempt": exempt,
        }))
        .unwrap();
        let rank = match action.as_str().unwrap_or("Log") {
            "Log" => 0,
            "KillProcess" => 2,
            "KillProcessTree" => 3,
            _ => 1,
        };
        (
            rule.as_str().unwrap_or("").to_string(),
            pid.as_u64().unwrap_or(0),
            (!held && !exempt, rank),
            text,
        )
    };
    match line.get("matches").and_then(Value::as_array) {
        Some(ms) => {
            for m in ms {
                out.push(view(
                    &m["rule"],
                    &m["action"],
                    &m["severity"],
                    &m["pid"],
                    &m["mitre"],
                    m["mode"].as_str().unwrap(),
                    m.get("held").is_some(),
                    m.get("exempt").is_some(),
                ));
            }
        }
        None => out.push(view(
            &line["rule"],
            &line["action"],
            &line["severity"],
            &line["pid"],
            &line["mitre"],
            "builtin",
            line["reasoning"]
                .as_str()
                .is_some_and(|r| r.contains("[held back: ")),
            false,
        )),
    }
    // An exec policy record carries its evidence and its response: outside
    // the bus, they are compared whole.
    if let Some(e) = line.get("execpol") {
        let text = serde_json::to_string(&json!({"execpol": e, "response": line.get("response")}))
            .unwrap();
        out.push((format!("execpol {text}"), 0, (true, 0), text));
    }
}

/// The responses one decision line runs, `(pid, action)`.
fn line_effects(line: &Value) -> Vec<(u64, String)> {
    if let Some(rs) = line.get("responses").and_then(Value::as_array) {
        return rs
            .iter()
            .map(|r| {
                (
                    r["pid"].as_u64().unwrap(),
                    r["action"].as_str().unwrap().to_string(),
                )
            })
            .collect();
    }
    let pid = line["pid"].as_u64().unwrap_or(0);
    let mut out = Vec::new();
    if let Some(a) = line["action"].as_str().filter(|a| *a != "Log") {
        out.push((pid, a.to_string()));
    }
    if let Some(r) = line.get("response").and_then(Value::as_str) {
        out.push((pid, r.to_string()));
    }
    out
}

/// A fresh replay of a case with its units in `order`, the bus's way: an
/// event is judged on the lineage of every exec that reached the bus
/// before it (the units before it in the stream; `nn_linux::sensors::bus`
/// ingests the execs an event of a higher class overtakes), and an exec
/// judged after a newer one of its process changes nothing there.
fn judged_in(name: &str, text: &str, order: &[usize]) -> Judged {
    let root = tempfile::TempDir::new().unwrap();
    let case = parse(name, text, root.path());
    let host = Host::new(&case, root);
    let units = units(&case);
    assert_eq!(
        order.len(),
        units.len(),
        "case {name}: an order of every unit"
    );
    let root_text = host.root.path().to_str().unwrap().to_string();
    let mut arrived = vec![false; units.len()];
    let mut lines = Vec::new();
    for &i in order {
        for (j, (_, u)) in units.iter().enumerate().take(i) {
            if let (false, Unit::Event(e)) = (arrived[j], u) {
                replay::arrive(&host.engine, &host.lineage, e);
                arrived[j] = true;
            }
        }
        arrived[i] = true;
        let v = match &units[i].1 {
            Unit::Event(e) => host.decide(e),
            Unit::Execpol(p) => execpol_lines(p),
        };
        decisions(&v, &mut lines);
    }
    let lines: Vec<Value> = lines
        .iter()
        .map(|l| {
            serde_json::from_str(
                &serde_json::to_string(l)
                    .unwrap()
                    .replace(&root_text, ROOT_TOKEN),
            )
            .unwrap()
        })
        .collect();
    let mut all = Vec::new();
    let mut effects: std::collections::BTreeMap<u64, BTreeSet<String>> = Default::default();
    for l in &lines {
        rule_verdicts(l, &mut all);
        for (pid, a) in line_effects(l) {
            effects.entry(pid).or_default().insert(a);
        }
    }
    for actions in effects.values_mut() {
        if actions.contains("KillProcessTree") {
            actions.remove("KillProcess");
        }
    }
    let mut verdicts: std::collections::BTreeMap<(String, u64), ((bool, u8), String)> =
        Default::default();
    for (rule, pid, strength, text) in all {
        let e = verdicts
            .entry((rule, pid))
            .or_insert((strength, text.clone()));
        if (strength, &text) > (e.0, &e.1) {
            *e = (strength, text);
        }
    }
    Judged {
        verdicts: verdicts.into_iter().map(|(k, (_, t))| (k, t)).collect(),
        effects,
    }
}

/// A small deterministic generator (xorshift64*), for the random merges.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The units of each lane, in stream order.
fn lane_queues(lanes: &[usize]) -> [Vec<usize>; LANES] {
    let mut q: [Vec<usize>; LANES] = Default::default();
    for (i, &l) in lanes.iter().enumerate() {
        q[l].push(i);
    }
    q
}

/// The order a sequence of lane picks gives (each pick the lane's next unit).
fn order_of_picks(q: &[Vec<usize>; LANES], picks: &[usize]) -> Vec<usize> {
    let mut next = [0usize; LANES];
    picks
        .iter()
        .map(|&l| {
            let u = q[l][next[l]];
            next[l] += 1;
            u
        })
        .collect()
}

/// How many orders keep each lane's order: n! / Π kᵢ! (saturating).
fn fifo_order_count(q: &[Vec<usize>; LANES]) -> u128 {
    let mut count: u128 = 1;
    let mut placed: u128 = 0;
    for lane in q {
        for k in 1..=lane.len() as u128 {
            placed += 1;
            count = count.saturating_mul(placed) / k;
        }
    }
    count
}

/// Every order that keeps each lane's order.
fn all_fifo_orders(q: &[Vec<usize>; LANES]) -> Vec<Vec<usize>> {
    fn go(
        q: &[Vec<usize>; LANES],
        left: &mut [usize; LANES],
        picks: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if left.iter().all(|&n| n == 0) {
            out.push(order_of_picks(q, picks));
            return;
        }
        for l in 0..LANES {
            if left[l] > 0 {
                left[l] -= 1;
                picks.push(l);
                go(q, left, picks, out);
                picks.pop();
                left[l] += 1;
            }
        }
    }
    let mut left = [0usize; LANES];
    for (l, lane) in q.iter().enumerate() {
        left[l] = lane.len();
    }
    let mut out = Vec::new();
    go(q, &mut left, &mut Vec::new(), &mut out);
    out
}

/// Every class-major order: each non-empty lane whole, the lanes in every
/// order.
fn class_major_orders(q: &[Vec<usize>; LANES]) -> Vec<Vec<usize>> {
    fn perms(items: &[usize]) -> Vec<Vec<usize>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut out = Vec::new();
        for i in 0..items.len() {
            let mut rest = items.to_vec();
            let first = rest.remove(i);
            for mut p in perms(&rest) {
                p.insert(0, first);
                out.push(p);
            }
        }
        out
    }
    let lanes: Vec<usize> = (0..LANES).filter(|&l| !q[l].is_empty()).collect();
    perms(&lanes)
        .into_iter()
        .map(|p| p.into_iter().flat_map(|l| q[l].iter().copied()).collect())
        .collect()
}

/// The bus's own take order: the units arrive in stream order, one per
/// tick; the consumer takes one each time more than `lag` wait, then
/// drains the queues. An exec policy report is not queued.
fn bus_order(lanes: &[usize], lag: usize) -> Vec<usize> {
    let mut queues = nn_core::bus::ClassQueues::new([usize::MAX; nn_core::bus::QUEUES]);
    let mut out = Vec::new();
    let mut queued = 0usize;
    for (i, &l) in lanes.iter().enumerate() {
        let now = i as u64;
        if l == OUTSIDE_BUS {
            out.push(i);
            continue;
        }
        queues.push(nn_core::bus::Priority::ALL[l], now, i).unwrap();
        queued += 1;
        while queued > lag {
            out.push(queues.take(now).unwrap().item);
            queued -= 1;
        }
    }
    let end = lanes.len() as u64;
    while let Some(t) = queues.take(end) {
        out.push(t.item);
    }
    out
}

/// Random merges: at each step one non-empty lane, uniformly, for one unit
/// or (every other merge) a run of up to 16.
fn random_orders(q: &[Vec<usize>; LANES], seed: u64, n: u64) -> Vec<Vec<usize>> {
    let total: usize = q.iter().map(Vec::len).sum();
    (0..n)
        .map(|k| {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (k + 1));
            let mut left: Vec<usize> = q.iter().map(Vec::len).collect();
            let mut picks = Vec::with_capacity(total);
            while picks.len() < total {
                let open: Vec<usize> = (0..LANES).filter(|&l| left[l] > 0).collect();
                let l = open[rng.below(open.len())];
                let run = if k % 2 == 1 { 1 + rng.below(16) } else { 1 };
                for _ in 0..run.min(left[l]) {
                    picks.push(l);
                    left[l] -= 1;
                }
            }
            order_of_picks(q, &picks)
        })
        .collect()
}

/// The orders a case is replayed in, each with what it is.
fn orders_for(lanes: &[usize], seed: u64) -> Vec<(String, Vec<usize>)> {
    let q = lane_queues(lanes);
    if fifo_order_count(&q) <= EXHAUSTIVE_MAX {
        return all_fifo_orders(&q)
            .into_iter()
            .enumerate()
            .map(|(i, o)| (format!("order {i} of all"), o))
            .collect();
    }
    let mut out: Vec<(String, Vec<usize>)> = class_major_orders(&q)
        .into_iter()
        .map(|o| ("class-major".to_string(), o))
        .collect();
    for lag in [1, 2, 4, 8, 32, 128, usize::MAX] {
        out.push((
            format!("the bus, consumer behind by {lag}"),
            bus_order(lanes, lag),
        ));
    }
    for (k, o) in random_orders(&q, seed, RANDOM_ORDERS)
        .into_iter()
        .enumerate()
    {
        out.push((format!("random merge {k}"), o));
    }
    out
}

/// The orders keep each lane's order and hold every unit once.
fn assert_fifo_order(lanes: &[usize], order: &[usize]) {
    let mut seen = vec![false; lanes.len()];
    let mut last = [None::<usize>; LANES];
    for &u in order {
        assert!(!seen[u], "unit {u} twice");
        seen[u] = true;
        if let Some(prev) = last[lanes[u]] {
            assert!(prev < u, "lane {} out of its order", lanes[u]);
        }
        last[lanes[u]] = Some(u);
    }
    assert!(seen.iter().all(|&s| s), "a unit left out");
}

/// Review #471 M4b, M5c: the event loop does what the property test below
/// models, and what the bus's own tests cannot see — the engine's rules
/// learn the execs an event overtook (`Received::overtaken`) before the
/// event is judged, and when the loop ends the bus is stopped: what it
/// still holds counted and signed, every drop signed. The loop needs the
/// whole agent to run, so its source is pinned (comments left out).
#[test]
fn the_event_loop_wires_the_bus_as_modelled() {
    let src = include_str!("../run_loop.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let at = |what: &str, from: usize| {
        code[from..]
            .find(what)
            .map(|i| from + i)
            .unwrap_or_else(|| panic!("run_loop.rs: `{what}` not found after byte {from}"))
    };
    let arm = at("Some(received) => {", 0);
    let each = at("for exec in &received.overtaken {", arm);
    let teach = at("engine.observe_arrival(exec);", each);
    assert!(
        !code[each..teach].contains('}'),
        "observe_arrival is the loop over the overtaken execs"
    );
    let event = at("let e = received.event;", arm);
    let judge = at("process_event(", arm);
    assert!(
        teach < event && event < judge,
        "taught before the event is judged"
    );
    let stop = at("sensor.stop_bus();", judge);
    let reported = at("Stopped {", stop);
    assert!(
        code[judge..stop].contains("break;") && !code[stop..reported].contains("break;"),
        "the bus is stopped after the loop, before the stop is reported"
    );
    assert_eq!(code.matches("sensor.stop_bus();").count(), 1);
}

/// Lab PR 267 (R12a): every order of a golden case's events that keeps
/// each class's own order gives the verdicts of the stream's order.
#[test]
fn golden_verdicts_survive_every_per_class_fifo_interleaving() {
    let cases = cases();
    let mut failures = Vec::new();
    let mut replays = 0usize;
    let mut exhaustive = 0usize;
    for (ci, (name, text)) in cases.iter().enumerate() {
        let lanes: Vec<usize> = {
            let root = tempfile::TempDir::new().unwrap();
            let case = parse(name, text, root.path());
            units(&case).iter().map(|(l, _)| *l).collect()
        };
        let in_order: Vec<usize> = (0..lanes.len()).collect();
        let want = judged_in(name, text, &in_order);
        let orders = orders_for(&lanes, ci as u64 + 1);
        if fifo_order_count(&lane_queues(&lanes)) <= EXHAUSTIVE_MAX {
            exhaustive += 1;
        }
        for (what, order) in &orders {
            assert_fifo_order(&lanes, order);
            replays += 1;
            let got = judged_in(name, text, order);
            if got != want {
                let missing: Vec<&String> = want
                    .verdicts
                    .iter()
                    .filter(|(k, v)| got.verdicts.get(*k) != Some(*v))
                    .map(|(_, v)| v)
                    .collect();
                let extra: Vec<&String> = got
                    .verdicts
                    .iter()
                    .filter(|(k, v)| want.verdicts.get(*k) != Some(*v))
                    .map(|(_, v)| v)
                    .collect();
                let picks: Vec<String> = order.iter().map(|&u| lanes[u].to_string()).collect();
                failures.push(format!(
                    "case {name}, {what} (lanes in order: {}):\n  verdicts missing: {missing:?}\n  verdicts extra: {extra:?}\n  effects: {:?} -> {:?}",
                    picks.join(""),
                    want.effects,
                    got.effects
                ));
                break;
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a verdict depends on the order between classes ({replays} replays):\n{}",
        failures.join("\n")
    );
    assert!(replays > cases.len(), "no interleaving replayed");
    eprintln!(
        "bus property: {} cases, {replays} interleavings replayed, {exhaustive} cases with every order",
        cases.len()
    );
}

/// The generators keep each lane's order, and the bus's take order is a
/// per-class FIFO order too.
#[test]
fn the_interleavings_keep_each_class_s_order() {
    let lanes = [1, 2, 3, 2, 0, 1, 4, 3, 3, 0, 2];
    let q = lane_queues(&lanes);
    let all = all_fifo_orders(&q);
    assert_eq!(all.len() as u128, fifo_order_count(&q));
    let unique: BTreeSet<&Vec<usize>> = all.iter().collect();
    assert_eq!(unique.len(), all.len());
    for o in all.iter().chain(class_major_orders(&q).iter()) {
        assert_fifo_order(&lanes, o);
    }
    for lag in [0, 1, 3, usize::MAX] {
        assert_fifo_order(&lanes, &bus_order(&lanes, lag));
    }
    assert_eq!(bus_order(&lanes, 0), (0..lanes.len()).collect::<Vec<_>>());
    for o in random_orders(&q, 7, 10) {
        assert_fifo_order(&lanes, &o);
    }
    assert_eq!(class_major_orders(&q).len(), 120, "5 lanes, 5! orders");
}
