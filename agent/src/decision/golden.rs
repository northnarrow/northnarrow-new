//! Lab PR 228: the golden replay.
//!
//! Recorded event streams (`agent/tests/golden/cases/*.json`) go through
//! the decision path of `process_event` (`main.rs`), on an engine built the
//! way `main.rs` builds it — the shipped lists of `configs/`, every
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
//! - every other event goes to the engine: first match wins, a held
//!   response is an alert (`response_policy`);
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
use common::{Event, ExeIdentity};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};

use super::attack::{mitre_of, AttackRef};
use super::correlation::{AncestryTree, CorrelationStore};
use super::rules::{epg, net::NetRuleConfig, net_fanout::FanoutConfig};
use super::{response_policy, Rule, RuleEngine};
use crate::config::comm_allowlist::{
    load_comm_allowlist, NETFLOW_COMM_ALLOWLIST_SHIPPED, PROCESS_COMM_ALLOWLIST_SHIPPED,
};
use crate::config::overlay_auth::Verified;
use crate::impact::entropy::{Sample, Sampler};
use crate::impact::trust::ProgramOwners;
use crate::impact::RansomTracker;
use crate::impair::{DefenseDetector, SecurityTools};
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
use crate::posture::lineage::AuthSessionTracker;

/// The cases, the golden files and the fixture root.
const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");
/// The repository's shipped lists (`configs/`), as install.sh lays them.
const CONFIGS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../configs");
/// `1`: write the golden files instead of comparing (`cargo xtask golden
/// --update`).
const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";
/// Stands for the replay's own file root in a case and in its golden file
/// (the directory is made for each replay, and the case's text read with
/// it in place of the token).
const ROOT_TOKEN: &str = "@ROOT@";
/// The golden file's format; a change of the line shape bumps it.
const FORMAT: &str = "northnarrow-golden/1";
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
    /// One event as the agent serialises it (`common::Event`).
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
/// engine `main.rs` builds over them.
struct Host {
    _proc: tempfile::TempDir,
    root: tempfile::TempDir,
    lineage: AuthSessionTracker,
    engine: RuleEngine,
}

fn configs(file: &str) -> PathBuf {
    Path::new(CONFIGS).join(file)
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
        let process_allowlist = Arc::new(
            load_comm_allowlist(
                "process-comm-allowlist",
                &configs("process-comm-allowlist.v1"),
                PROCESS_COMM_ALLOWLIST_SHIPPED,
                &Verified::Missing,
            )
            .unwrap(),
        );
        let netflow_allowlist = Arc::new(
            load_comm_allowlist(
                "netflow-comm-allowlist",
                &configs("netflow-comm-allowlist.v1"),
                NETFLOW_COMM_ALLOWLIST_SHIPPED,
                &Verified::Missing,
            )
            .unwrap(),
        );
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
        let (tools, _) = SecurityTools::load(&configs("security-tools.v1"));
        let defense = Arc::new(DefenseDetector::with_proc_root(
            Arc::new(tools),
            lineage.clone(),
            Some(Arc::new(
                process_allowlist
                    .as_ref()
                    .clone()
                    .with_identity(lineage.clone()),
            )),
            proc.path(),
        ));
        let correlation = Arc::new(Mutex::new(CorrelationStore::with_tree(
            AncestryTree::with_proc_root(
                proc.path(),
                super::correlation::ancestry::MAX_TRACKED_EDGES,
            ),
        )));
        let net_config = NetRuleConfig {
            resolvers: crate::net::resolvers::HostResolvers::fixed(case.resolvers.iter().copied()),
            fanout: Arc::new(FanoutConfig::default()),
        };
        let engine = RuleEngine::with_default_rules_and_net(
            Arc::new(
                NetBlocklist::load(&configs("netflow-blocklist.v1"), &Verified::Missing).unwrap(),
            ),
            Arc::new(
                Ja3Blocklist::load(&configs("netflow-ja3-blocklist.v1"), &Verified::Missing)
                    .unwrap(),
            ),
            Arc::new(Mutex::new(super::rules::net::DnsBurstWindow::new())),
            process_allowlist,
            netflow_allowlist,
            Arc::new(Mutex::new(super::rules::net::BeaconWindow::new())),
            Arc::new(crate::net::dns_cache::DnsCache::default()),
            crate::anti_tamper::trusted_installer::TrustedInstallerOverride::inert_arc(),
            lineage.clone(),
            crate::canary::readers::CanaryReaders::default(),
            correlation,
            net_config,
            ransom,
            defense,
        );
        Self {
            _proc: proc,
            root,
            lineage,
            engine,
        }
    }

    /// The decision on one event, as `process_event` takes it.
    fn decide(&self, event: &Event) -> Value {
        if let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            filename,
            argv,
            timestamp_ns,
            exe,
            start_ns,
            ..
        } = event
        {
            self.lineage.ingest_exec(
                *pid,
                *ppid,
                exe.path_or(filename),
                argv,
                *timestamp_ns,
                *start_ns,
                *uid,
            );
        }
        match event {
            Event::FsProtectDenial { .. } => {
                let at001 = super::rules::anti_tamper::NnLAt001AntiTamperDenial;
                verdict_line(at001.evaluate(event).map(|v| (v, at001.attack())), None)
            }
            Event::ExploitPostcondition { .. } => {
                let found =
                    epg::rule_for(event).and_then(|r| r.evaluate(event).map(|v| (v, r.attack())));
                let response = found.as_ref().map(|_| epg::response_line(event));
                verdict_line(found, response)
            }
            _ => verdict_line(self.engine.evaluate_with_attack(event), None),
        }
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
                Item::Execpol(p) => {
                    let records =
                        crate::execpol::record::records_of(&p.raw(), &p.event(), &p.policy);
                    Value::Array(
                        records
                            .iter()
                            .map(|r| {
                                let mut v = verdict_line(
                                    Some((r.verdict.clone(), r.attack.as_slice())),
                                    Some(r.response.clone()),
                                );
                                v["execpol"] = serde_json::to_value(&r.evidence).unwrap();
                                v
                            })
                            .collect(),
                    )
                }
            });
        }
        out
    }
}

/// One decision as a golden line: the verdict and its ATT&CK record field,
/// and the response line of a record made outside the engine.
fn verdict_line(found: Option<(common::Verdict, &[AttackRef])>, response: Option<String>) -> Value {
    let Some((v, attack)) = found else {
        return Value::Null;
    };
    let mut line = json!({
        "rule": v.rule_id,
        "name": v.rule_name,
        "category": v.category,
        "action": format!("{:?}", v.action),
        "severity": format!("{:?}", v.severity),
        "pid": v.event_pid,
        "file": v.event_filename,
        "ts": v.timestamp_ns,
        "reasoning": v.reasoning,
        "mitre": serde_json::to_value(mitre_of(attack)).unwrap(),
    });
    if let Some(r) = response {
        line["response"] = Value::String(r);
    }
    line
}

/// The golden text of one replay: a header naming the case and the policy
/// switches, then one line per item.
fn render(name: &str, case: &Case, host: &Host, lines: &[Value]) -> String {
    let switches: Vec<Value> = response_policy::ALL
        .iter()
        .map(|s| json!({"held": s.held, "on": s.on}))
        .collect();
    let mut text = serde_json::to_string(&json!({
        "format": FORMAT,
        "case": name,
        "about": case.about,
        "rules": host.engine.rule_count(),
        "switches": switches,
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

/// The cases cover the rules lots 219–226 added, and every response those
/// lots hold behind a switch shows as an alert: action `Log`, the reasoning
/// naming what was held.
#[test]
fn golden_cases_cover_the_rules_of_lots_219_to_226() {
    let mut all = Vec::new();
    for (name, text) in cases() {
        let (_, _, lines) = replay(&name, &text);
        for l in &lines {
            decisions(l, &mut all);
        }
    }
    let fired: BTreeSet<&str> = all.iter().map(|d| d["rule"].as_str().unwrap()).collect();
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
    let held: Vec<&Value> = all
        .iter()
        .filter(|d| d["reasoning"].as_str().unwrap().contains("[held back: "))
        .collect();
    for d in &held {
        assert_eq!(d["action"], "Log", "{d}");
    }
    let held_rules: BTreeSet<&str> = held.iter().map(|d| d["rule"].as_str().unwrap()).collect();
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
    // No response a switch holds runs in the golden output.
    for d in &all {
        if d["action"] != "Log" {
            let r = d["reasoning"].as_str().unwrap();
            assert!(!r.contains("[held back: "), "{d}");
        }
    }
}

/// Each case fires the rules it names in `fires` and shows held the
/// responses it names in `held`.
#[test]
fn every_case_shows_what_it_says() {
    for (name, text) in cases() {
        let (case, _, lines) = replay(&name, &text);
        assert!(!case.fires.is_empty(), "case {name}: `fires` names no rule");
        let mut all = Vec::new();
        for l in &lines {
            decisions(l, &mut all);
        }
        for want in &case.fires {
            assert!(
                all.iter().any(|d| d["rule"] == want.as_str()),
                "case {name}: {want} does not fire"
            );
        }
        for want in &case.held {
            assert!(
                all.iter().any(|d| d["rule"] == want.as_str()
                    && d["action"] == "Log"
                    && d["reasoning"].as_str().unwrap().contains("[held back: ")),
                "case {name}: no held response of {want}"
            );
        }
    }
}
